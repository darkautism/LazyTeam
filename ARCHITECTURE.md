# LazyTeam Architecture

This document is the engineering companion to the [README](README.md). The README is the human front door; this file describes how LazyTeam is actually built: process boundaries, the Git broker, review/merge lifecycle, sessions and affinity, OAuth/security, storage/migrations, and operations.

## System overview and current MVP

- Rust control plane (`lazyteam-server`) and Rust worker daemon (`lazyteam-worker`).
- Multiple first-class projects, each bound to a Git repository and default branch.
- Shared worker pool with project access rules and key/value capability tags.
- Workers connect outbound: enroll, heartbeat, claim, renew leases, and report results.
- Task dependencies, execution attempts, stale-execution rejection, and lease-expiry requeue.
- Pi RPC is the first worker runtime; an execution is considered finished only after Pi emits `agent_settled`.
- Persistent SQLite state (default `/app/data/lazyteam.db`).
- MCP Streamable HTTP at `/mcp` for ChatGPT and other MCP clients.
- OAuth compatibility modeled after MCPX: RFC 9728 protected-resource metadata, RFC 8414 authorization-server metadata, PKCE S256, Dynamic Client Registration, HTTPS Client ID Metadata Documents (CIMD), authorization-code and rotating refresh-token grants, plus path-qualified discovery aliases.

## Host / worker / reviewer boundaries

Three roles exist:

- **Host (control plane).** The only upstream Git principal. Owns SQLite state, the project mirrors and per-execution bare broker repositories, lease capabilities, review/merge gating, MCP/OAuth serving, and the private management REST + `/ui`.
- **Worker agents** claim implementation tasks (`assigned`/`running`), edit code in the task workspace, and publish a stable review ref when the execution finishes.
- **Reviewer agents (protocol 6)** claim pinned review leases for tasks in `review`, verify the exact candidate commit independently from the Host broker, and return an approve/retry JSON verdict. They never modify source, commit, push, or merge.

The **main agent** (typically ChatGPT over MCP) owns the merge decision but holds no Git credential. A reviewer-role worker's approve verdict moves the task directly `review -> merge_pending`; `tasks_approve` remains only a fallback for main-agent self-review. From `merge_pending`, the main agent calls `tasks_merge(task_id)`, and the Host performs the upstream publish.

Workers and reviewer workers never receive the project's GitHub/Gitea token, SSH private key, credential helper, or upstream `Authorization` header. They only ever see Host broker URLs such as `https://lazyteam.example.com/git/task/<execution-id>/repo.git` plus a per-claim lease capability.

The worker image (`ghcr.io/darkautism/lazyteam-worker:latest`, `linux/amd64` + `linux/arm64`) pins Pi `@earendil-works/pi-coding-agent@0.85.1` and the host tools needed to build the per-capability Ubuntu agent rootfs. Worker identity, its LazyTeam worker credential, Pi credentials, agent rootfs generations, and sessions live under `/app/state`; trusted broker-backed Git workspaces live under `/app/workspaces`.

## Public deployment and operational detail

Do not publish LazyTeam port `8787` directly to the internet. The production profile (`docker-compose.public.yml`) places Caddy in front of LazyTeam and exposes only MCP/OAuth, health, and the worker runtime endpoints. Management REST and the Web UI stay loopback-only.

```sh
export LAZYTEAM_PUBLIC_URL=https://lazyteam.example.com
export LAZYTEAM_OAUTH_PASSWORD="$(openssl rand -base64 32)"
export LAZYTEAM_ADMIN_TOKEN="$(openssl rand -hex 32)"
export LAZYTEAM_WORKER_TOKEN="$(openssl rand -hex 32)"

docker compose -f docker-compose.public.yml up -d --build
```

The canonical public MCP endpoint is `https://lazyteam.example.com/mcp`. For client UIs that normalize the configured server URL to the site root, LazyTeam also serves an OAuth-protected MCP alias at `https://lazyteam.example.com/`. Both endpoints publish RFC 9728 metadata for their own resource identifier. The private dashboard moved to `/ui` and is not exposed by the public Caddy profile.

Caddy obtains and renews the public TLS certificate. LazyTeam itself remains reachable on the host only through `127.0.0.1:8787` for local administration.

The container layout is intentionally rooted at `/app`:

```text
/app
├── data/        # persistent control-plane state (SQLite; future Pi/session state)
└── workspaces/  # project / planner / execution workspaces
```

The process working directory is `/app`. Persistent server state is stored in `/app/data` (the `lazyteam-data` Docker volume), and workspace storage is `/app/workspaces` (the `lazyteam-workspaces` volume). The default database is `/app/data/lazyteam.db`. For NAS deployments, bind-mount host datasets to `/app/data` and `/app/workspaces` if you prefer explicit host paths over Docker named volumes.

No manual `chown`, PUID, or PGID setting is required in the normal case. The container entrypoint starts with only the capabilities needed to initialize the mounts, detects an existing non-root owner, and then drops privileges before starting LazyTeam:

- TrueNAS datasets owned by `568:568` are automatically run as `568:568`.
- Arbitrary non-root bind-mount owners are adopted the same way.
- Root-owned empty bind mounts are initialized to the default runtime identity `10001:10001`.
- Docker named volumes work without extra settings.
- If an older root-run image left a root-owned database inside a non-root dataset, the dataset owner wins and the database ownership is repaired.

After initialization, the LazyTeam server itself runs non-root and its effective Linux capabilities are cleared. The root filesystem remains read-only and `no-new-privileges` is enabled. For unusual environments, `PUID`/`PGID` (or `LAZYTEAM_PUID`/`LAZYTEAM_PGID`) may explicitly override the automatic identity selection, but they are not required for TrueNAS or ordinary Docker deployments.

### Required production settings

```text
LAZYTEAM_PRODUCTION=true
LAZYTEAM_PUBLIC_URL=https://lazyteam.example.com
LAZYTEAM_OAUTH_PASSWORD=<strong human authorization password>
LAZYTEAM_ADMIN_TOKEN=<strong local management bearer>
LAZYTEAM_WORKER_TOKEN=<strong worker enrollment secret>
LAZYTEAM_ALLOWED_OAUTH_CLIENT_HOSTS=chatgpt.com,*.chatgpt.com
LAZYTEAM_ALLOWED_REDIRECT_HOSTS=chatgpt.com,*.chatgpt.com
```

`LAZYTEAM_PUBLIC_URL` is the single public-origin setting used by both LazyTeam and the bundled Caddy profile. Loopback development may use `http://127.0.0.1:8787` or `http://localhost:8787`; any non-loopback hostname requires HTTPS even if `LAZYTEAM_PRODUCTION` was accidentally omitted. Production additionally requires the URL to be HTTPS and all required credentials/host allowlists to be present.

The ChatGPT host values are defaults, not a universal trust rule. If the actual MCP client metadata or callback host changes, update the allowlists explicitly instead of opening them to `*`.

### Public route boundary

The provided Caddy configuration (`deploy/Caddyfile`) publishes only:

```text
/
/health
/mcp
/mcp/*
/.well-known/*
/api/workers/register
/api/workers/*
/api/executions/*
```

(see also `/git/*` and `/api/reviews/*` worker paths in the Caddyfile). Everything else receives `404` at the public reverse proxy. In particular, Project/Task CRUD, review approval/retry, the Worker registry listing, and the Web UI are not publicly routed.

## Security model

LazyTeam separates three identities:

1. **ChatGPT / MCP clients** use OAuth Bearer tokens scoped to the `/mcp` protected resource.
2. **Local administrators** use `LAZYTEAM_ADMIN_TOKEN` on management REST requests through the loopback-bound port.
3. **Workers** use an enrollment secret only when joining, then receive an independent worker-specific credential.

Worker-specific credentials are generated by the control plane, returned once in the `X-LazyTeam-Worker-Credential` response header, and stored in SQLite only as a SHA-256 hash. The Rust worker persists its credential in its state directory and uses it for heartbeat, claim, lease renewal, and completion. On Unix the credential file is set to mode `0600`.

The shared `LAZYTEAM_WORKER_TOKEN` is therefore an **enrollment credential**, not the normal runtime worker identity. After workers are enrolled, it can be rotated without invalidating already-enrolled workers. Supplying a new enrollment secret to a worker is only needed for first enrollment or recovery after the server has lost/replaced its worker credential state.

Execution renew/finish requests are checked against the worker that owns the execution, so a credential issued to Worker B cannot operate Worker A's execution.

OAuth/CIMD hardening includes:

- PKCE S256 required.
- Exact registered redirect URI matching.
- OAuth client metadata and redirect host allowlists.
- Access tokens bound to the MCP resource and stored only as hashes.
- One-time authorization codes and rotating refresh tokens.
- CIMD HTTPS-only fetching with size/time limits.
- DNS resolution before CIMD fetches and rejection of loopback, RFC1918, CGNAT, link-local, ULA, multicast, documentation and other special-use addresses.
- Redirect-by-redirect URL/DNS validation and DNS pinning to close the validation/connect rebinding window.
- Rate limits on DCR, authorization, token exchange, worker enrollment, and worker claiming.
- 1 MiB request-body limit, request timeout, CSP, HSTS, `nosniff`, frame denial, `no-referrer`, and `no-store` response headers.

The domain allowlists above protect OAuth client/callback identity. CORS or an HTTP `Origin` header is deliberately not treated as an authentication boundary because non-browser clients can forge those headers.

## Local management

Production management requests go through the loopback-bound port and require the admin bearer:

```sh
curl -X POST http://127.0.0.1:8787/api/projects \
  -H "Authorization: Bearer $LAZYTEAM_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "slug":"lazyteam",
    "name":"LazyTeam",
    "repo_url":"git@github.com:darkautism/LazyTeam.git",
    "default_branch":"main",
    "required_worker_tags":{}
  }'
```

A task stores a `project_id`. Workers remain a shared fleet and may allow all projects (`*`) or an explicit set of project slugs.

The Web UI is intentionally not part of the public Caddy route set. Open the loopback/private UI at `http://127.0.0.1:8787/ui`, click **Connect**, paste `LAZYTEAM_ADMIN_TOKEN`, and connect. The token is kept only in browser `sessionStorage`; the compact header shows only **Connected** while it is valid.

For non-production local development, the security middleware keeps the original unauthenticated local REST workflow unless credentials/production mode are enabled.

## Project Git access and Git broker / auth

Each project chooses how the Host reaches upstream:

- **Host environment / public repository** (default): the Host uses anonymous access or Git/SSH configuration already present in the Host runtime.
- **Host SSH private key**: store a project-scoped private key in LazyTeam. The Host materializes it only for the upstream Git command and removes the temporary key afterward.
- **Host HTTPS username + token/password**: store a project-scoped HTTPS credential. The Host applies it only to its upstream fetch/publish command.

### GitHub fine-grained PAT: least privilege

For normal LazyTeam Host fetch/publish over HTTPS, a GitHub fine-grained personal access token should be restricted to the required repository or repositories and needs only:

- **Repository permissions → Contents: Read and write** — required to fetch and push Git objects/refs.
- **Metadata: Read-only** — GitHub adds this required permission automatically.
- **Workflows: Read and write** — add this only if LazyTeam must publish commits that modify files under `.github/workflows/`.

**Administration is not required** for ordinary Git fetch/push. It controls repository settings and does not replace `Contents: Read and write`. Actions, Pull requests, Issues, and other repository permissions are also unnecessary unless a separate LazyTeam feature explicitly uses those APIs. Repository rules or branch protection can still reject a push independently of token permissions.

Stored project secrets are write-only from the Project UI/API and encrypted at rest with AES-256-GCM. On first boot LazyTeam generates a random master key at `LAZYTEAM_GIT_ROOT/credential.key` (normally `/app/data/git/credential.key` in the container) with private permissions and reuses it across restarts. `LAZYTEAM_GIT_CREDENTIAL_KEY` remains only as an optional compatibility override; normal deployments do not need to provide it.

Each stored Host credential also has an opaque `credential_revision`. It is not derived from the secret and does not reveal any token material. The revision changes when a new secret is submitted and remains stable when an edit leaves the secret blank, so operators can verify that a replacement credential reached persistent storage without exposing the credential itself.

The Project **Git Probe** validates both directions. It fetches the configured default branch into a temporary Host bare repository, then runs a `git push --dry-run` of the same ref back to upstream. The dry run exercises upstream receive/write authorization without changing any upstream ref. The UI distinguishes **Git R/W OK**, **Git read-only**, and **Git failed**, and reports the credential revision used for the probe.

For execution, the Host maintains a project mirror and creates a bare repository scoped to the execution. Assignments contain a Host URL such as `https://lazyteam.example.com/git/task/<execution-id>/repo.git`, never the upstream URL plus credentials. Every implementation or review claim also mints a fresh opaque **lease capability**. Broker access and lease renew/finish calls require both the worker identity credential and that exact lease capability, so two slots on the same worker cannot authorize each other's execution/review. Only a hash of the lease capability is stored by the Host. The capability is revoked immediately when the execution/review finishes or is marked lost, and an expired lease cannot be renewed. Workers may push only the stable task ref allowed by the Host pre-receive hook; reviewer broker endpoints are read-only. After approval, `tasks_merge` makes the Host re-fetch upstream, verifies that the reviewed base and candidate have not moved, and publishes the exact reviewed candidate upstream with the Host-only project credential.

## Worker runtime, sandbox, and configuration

For a containerized worker, generate a join code in the private UI and run:

```sh
export LAZYTEAM_WORKER_JOIN_CODE='<ltj1...>'
export LAZYTEAM_WORKER_NAME='worker-01'
export LAZYTEAM_WORKER_SLOTS=1
docker compose -f docker-compose.worker.yml up -d
```

The worker container is outbound-only and exposes no port. Its embedded agent sandbox needs Linux user/mount namespaces; the supplied Compose profile keeps the daemon non-root after volume initialization and relaxes the outer Docker seccomp/AppArmor filters so the worker can create its **inner** rootless namespace sandbox. LazyTeam still fails closed if that inner filesystem/seccomp sandbox cannot be established. Hosts that disable unprivileged user namespaces must enable them before using the worker container.

For a native worker, `git`, Pi, and the rootfs-builder host tools must be installed on the machine. The preferred bootstrap path does **not** require the remote machine to know `LAZYTEAM_PUBLIC_URL` or the shared enrollment secret in advance:

1. Open the private `/ui`, enter the admin token, and click **Generate join code**.
2. Copy the generated 10-minute `ltj1...` code to the worker machine.
3. Start the worker with the join code:

```sh
cargo run -p lazyteam-worker -- \
  --join-code '<ltj1...>' \
  --name worker-01 \
  --project '*' \
  --tag rust=true \
  --slots 1
```

The signed join code contains the canonical public LazyTeam endpoint and acts as a short-lived enrollment capability. The server verifies its signature, endpoint binding, and expiry before registration. After successful enrollment, the worker persists `server-url`, `worker-id`, and its independent `worker-credential` under `LAZYTEAM_WORKER_STATE_DIR` (default `.lazyteam-worker`); the credential file is mode `0600` on Unix. Subsequent starts discover the persisted endpoint and credential automatically, so neither the join code nor `LAZYTEAM_WORKER_TOKEN` is needed again.

The legacy/manual bootstrap remains available when needed:

```sh
export LAZYTEAM_WORKER_TOKEN='<enrollment secret>'
cargo run -p lazyteam-worker -- --server https://lazyteam.example.com --name worker-01 --project '*'
```

There is intentionally no implicit `127.0.0.1:8787` fallback: a fresh worker must receive either a join code or an explicit server URL, preventing accidental attempts to register against itself.

### Embedded agent sandbox

On Linux, `lazyteam-worker` runs Pi inside an embedded sandbox implemented in the same Rust executable; Docker and a separate sandbox binary are not required. It prefers a fully enforced Landlock filesystem policy; kernels without Landlock use a rootless user+mount namespace with a tmpfs root and explicit bind-mount allowlist. Startup is **fail-closed**: if neither filesystem backend can be established or the seccomp filter cannot be installed, the worker refuses to run agents instead of falling back to an unsandboxed process. Check a machine without contacting the control plane with:

```sh
lazyteam-worker --sandbox-diagnose
```

The trusted worker daemon keeps the real Git checkout and `.git` metadata outside the agent view. Before each implementation/review turn it materializes a source-only mirror with no `.git`; implementation changes are synchronized back by the daemon and committed/pushed by the daemon. An agent-created `.git` entry is always discarded during synchronization. Pi gets an isolated `PI_CODING_AGENT_DIR`, HOME, Cargo cache/target directory, temp directory, and persistent task session. A fresh worker's isolated Pi directory always starts empty: LazyTeam never imports `~/.pi`, `PI_CODING_AGENT_DIR`, `auth.json`, settings, model caches, or provider sessions from the host user. Provider credentials must be configured explicitly for that worker. The worker credential, worker state root, host `~/.ssh`, and trusted Git metadata are not included in the sandbox allowlist or inherited agent environment. Upstream Git credentials never exist on the worker at all.

The initial seccomp policy deliberately stays small to preserve normal Node/Pi/Cargo behavior while denying mount/namespace escape and process-inspection primitives such as `mount`, `pivot_root`, `chroot`, `setns`, `unshare`, `ptrace`, `bpf`, and `perf_event_open`. Network access remains available because Pi and package managers need outbound access.

### Worker and agent configuration

After a worker is enrolled, open **Workers → Configure** in the private UI. The server becomes the source of truth for the worker name, role, tags, allowed projects, slots, agent selection, provider/model selection, and initial prompt. A running worker fetches this configuration before claiming work, so changes apply to subsequent tasks without re-enrollment. The worker list shows each worker's role (`worker` or `reviewer`) as a pill next to its name.

The **Role** selector switches a registered agent between Worker and Reviewer. Changing the role replaces the **Initial prompt** with that role's default prompt: the Worker default (`lazyteam_core::DEFAULT_WORKER_PROMPT`) or the Reviewer default (`lazyteam_core::DEFAULT_REVIEWER_PROMPT`). If the current prompt has been customized, the UI asks for explicit confirmation that changing role will overwrite the customized prompt; cancelling keeps both the previous role selection and the prompt unchanged. Saving the dialog PATCHes `role` together with the existing agent/provider/model/prompt fields. Assigning the Reviewer role requires a protocol 6 worker; older workers must be updated/restarted first.

Agent integrations are capability-driven instead of assuming every CLI exposes the same controls. Each worker reports whether its agent supports model discovery, what login mode it exposes (`unsupported`, `local_interactive`, or `remote`), and the provider/model catalog it can discover. The UI adapts to those capabilities.

Pi is the only agent backend currently implemented. A protocol-4 worker queries Pi's public `ModelRuntime` API for the **real provider registry and auth metadata**, so a fresh worker can show providers even before authentication; no static/mock provider list exists in LazyTeam. Available models still come from Pi RPC `get_available_models` and refresh after credential changes and periodically. In **Workers → Configure**, choose a provider and enter its API key. The admin server keeps that key only in a volatile one-shot handoff until the authenticated worker polls it; the key is never written to SQLite or returned by worker/project APIs. The worker stores it only in its isolated Pi `auth.json` with private permissions, then refreshes Pi's real model catalog. Until Pi reports at least one usable model, the worker stays idle and does not claim tasks. OAuth-capable providers are reported by Pi too, but remote OAuth UI is not implemented yet.

The default worker initial prompt is deliberately agent-independent:

```text
You are an autonomous LazyTeam coding worker. Execute only the assigned task in the provided repository workspace. Treat the task description and acceptance criteria as the contract. Inspect before editing, make the smallest correct change, preserve unrelated behavior, and follow repository instructions. Run relevant validation and never wait for interactive input. Do not broaden scope. If blocked, stop and report the concrete blocker. Do not expose secrets or modify external systems unless the task explicitly requires it. Finish with a concise summary of what changed, validation performed, and any remaining risks.
```

### Reviewer configuration

Reviewer policy belongs to the **reviewer worker**, not the Project. Open **Workers → Configure**, set Role to Reviewer, and edit that worker's **Initial prompt**. There is no separate Project-level review prompt. The Home board keeps review work in two lanes: **Review** contains tasks awaiting/under reviewer-worker review, while **MergePending** contains approved candidates waiting for the main agent to invoke Host publish.

`reviews_get(task_id)` exposes pinned execution metadata and evidence for the main agent: implementation worker, candidate SHA, base SHA, stable review ref, patch/summary, and Host repository metadata. The actual reviewer worker gets a worker-authenticated read-only Host broker checkout and performs its independent inspection there; no upstream credential is involved.

A review retry requires a reason. LazyTeam stores that reason as `review_feedback`, reserves implementation return work for the worker that owns the logical implementation session, and injects the feedback into that retained session. Review work follows the same rule: the latest reviewer owns the logical review session and receives return review work first. Busy/full owners keep the reservation without holding a physical slot; another eligible worker may take over only when the owner is unavailable/ineligible or the affinity window expires. Affinity never reuses authority: every execution/review claim receives a fresh lease capability, and the previous capability stays revoked.

A reviewer-role worker's approve verdict moves the task directly `review -> merge_pending`; `tasks_approve` is only the fallback when the main agent reviews the candidate itself. Neither path releases dependencies or deletes worker state. The main agent then calls `tasks_merge(task_id)`. The Host re-fetches upstream and refuses to publish if the default branch no longer equals the reviewed `base_sha` or if the task ref no longer equals the reviewed candidate SHA. On success the Host pushes that exact candidate, marks the task `done`, unlocks dependencies, and queues cleanup. The worker deletes only its local task workspace/session; the Host owns broker-repository cleanup.

The worker also captures up to 256 KiB of textual patch evidence and marks truncated patches explicitly. Full-context reviewer validation uses the worker-authenticated Host review broker rather than an upstream review branch.

## Sessions and affinity

Each task has backend-neutral logical agent sessions keyed by `(task_id, role)`: one implementation session and one review session. The worker maps that logical session to the backend-specific handle (Pi today; other backends can supply their own session IDs later). A retained session does not consume a running slot: workers may fill the rest of their slots with new tasks/sessions. If implementation or review work returns, LazyTeam reserves it for the live owner and gives it first claim priority when that worker has a free slot. Ownership is not transferred merely because the worker is currently full. The default affinity window is 15 minutes (`LAZYTEAM_SESSION_AFFINITY_SECS` can override it); dead/paused/retired/ineligible workers release affinity immediately. Backend session data is retained until the task is merged or explicitly abandoned, then the Host queues cleanup to every implementation/reviewer worker that owned a session.

## Task and review/merge lifecycle

```text
queued -> assigned -> running -> review -> merge_pending -> done
   ^                         |                         |
   |---- review retry -------|                         |
   |                                                   |
   +---- failed/blocked retry -------------------------+
```

- Completed worker executions enter `review` and publish a stable review ref.
- Review retry requires feedback and is sticky to the same worker so workspace/session state is reused.
- A reviewer approve verdict moves `review -> merge_pending` directly (`tasks_approve` is only the main-agent self-review fallback); dependencies remain blocked.
- `tasks_merge` performs Host-side upstream publish of the exact reviewed candidate, moves `merge_pending -> done`, releases dependencies, and queues worker cleanup. It refuses the publish if upstream or the candidate moved after review.
- Every execution still gets its own UUID/attempt record, but attempts share the task workspace/session until merge.

## MCP and OAuth detail

Current MCP tools:

```text
projects_list
projects_create
tasks_list
tasks_create
reviews_get
tasks_approve
tasks_merge
tasks_retry
workers_list
```

The intended flow is that a strong planner such as ChatGPT talks to the OAuth-protected MCP control plane, creates project-scoped work, and lets idle workers claim matching tasks automatically. The authorization page uses `LAZYTEAM_OAUTH_PASSWORD` for the human approval step. See [Security model](#security-model) for PKCE, DCR, CIMD, token, DNS, and rate-limit hardening.

## Storage, migrations, and operations

- SQLite via `sqlx`, with migrations in `crates/lazyteam-server/migrations/` (`0001_init` through `0015_git_auth_revision` covering OAuth tokens, worker credentials, agent config, reviewer roles, retry affinity/cleanup, Git auth, capabilities, retirement, and session cleanup).
- Add the public MCP endpoint to ChatGPT as `https://lazyteam.example.com/mcp`.
- CI boots real LazyTeam servers and gates the public deployment on: `cargo check --workspace` and `cargo test --workspace`; OAuth discovery and RFC 9728 protected-resource metadata; DCR, PKCE authorization-code exchange, and refresh-token rotation; authenticated MCP `server/discover` and `tools/list`; unauthenticated MCP challenge metadata; multi-project worker matching, lease renewal, review retry affinity, explicit merge gating, and post-merge cleanup/dependency release; anonymous/admin/worker role separation; per-worker credential isolation and cross-worker execution rejection; OAuth callback/client host policy and private CIMD rejection; OAuth rate limiting; rejection of insecure HTTP public URLs for every non-loopback hostname, including when production mode is omitted; production Docker image build; local and public Docker Compose configuration validation.
