# LazyTeam

LazyTeam is a self-hosted Rust control plane for coordinating AI coding workers across multiple projects.

## Current MVP

- Rust control plane and Rust worker daemon.
- Multiple first-class projects, each bound to a Git repository and default branch.
- Shared worker pool with project access rules and key/value capability tags.
- Workers connect outbound: enroll, heartbeat, claim, renew leases, and report results.
- Task dependencies, execution attempts, stale-execution rejection, and lease-expiry requeue.
- Pi RPC is the first worker runtime; an execution is considered finished only after Pi emits `agent_settled`.
- Persistent SQLite state.
- MCP Streamable HTTP at `/mcp` for ChatGPT and other MCP clients.
- OAuth compatibility modeled after MCPX: RFC 9728 protected-resource metadata, RFC 8414 authorization-server metadata, PKCE S256, Dynamic Client Registration, HTTPS Client ID Metadata Documents (CIMD), authorization-code and rotating refresh-token grants, plus path-qualified discovery aliases.

## Public deployment

Do not publish LazyTeam port `8787` directly to the Internet. The production profile places Caddy in front of LazyTeam and exposes only MCP/OAuth, health, and the worker runtime endpoints. Management REST and the current Web UI stay loopback-only.

Set a DNS name that points at the host, then generate strong secrets:

```sh
export LAZYTEAM_PUBLIC_URL=https://lazyteam.example.com
export LAZYTEAM_OAUTH_PASSWORD="$(openssl rand -base64 32)"
export LAZYTEAM_ADMIN_TOKEN="$(openssl rand -hex 32)"
export LAZYTEAM_WORKER_TOKEN="$(openssl rand -hex 32)"

docker compose -f docker-compose.public.yml up -d --build
```

The canonical public MCP endpoint is:

```text
https://lazyteam.example.com/mcp
```

For client UIs that normalize the configured server URL to the site root, LazyTeam also serves an OAuth-protected MCP alias at:

```text
https://lazyteam.example.com/
```

Both endpoints publish RFC 9728 metadata for their own resource identifier. The private dashboard moved to `/ui` and is not exposed by the public Caddy profile.

Caddy obtains and renews the public TLS certificate. LazyTeam itself remains reachable on the host only through `127.0.0.1:8787` for local administration.

The container layout is intentionally rooted at `/app`:

```text
/app
├── data/        # persistent control-plane state (SQLite; future Pi/session state)
└── workspaces/  # project / planner / execution workspaces
```

The process working directory is `/app`. Persistent server state is stored in `/app/data` (the `lazyteam-data` Docker volume), and workspace storage is `/app/workspaces` (the `lazyteam-workspaces` volume). The default database is `/app/data/lazyteam.db`.

For NAS deployments, bind-mount host datasets to `/app/data` and `/app/workspaces` if you prefer explicit host paths over Docker named volumes.

No manual `chown`, PUID or PGID setting is required in the normal case. The container entrypoint starts with only the capabilities needed to initialize the mounts, detects an existing non-root owner, and then drops privileges before starting LazyTeam:

- TrueNAS datasets owned by `568:568` are automatically run as `568:568`.
- Arbitrary non-root bind-mount owners are adopted the same way.
- Root-owned empty bind mounts are initialized to the default runtime identity `10001:10001`.
- Docker named volumes work without extra settings.
- If an older root-run image left a root-owned database inside a non-root dataset, the dataset owner wins and the database ownership is repaired.

After initialization, the LazyTeam server itself runs non-root and its effective Linux capabilities are cleared. The root filesystem remains read-only and `no-new-privileges` is enabled.

For unusual environments, `PUID`/`PGID` (or `LAZYTEAM_PUID`/`LAZYTEAM_PGID`) may explicitly override the automatic identity selection, but they are not required for TrueNAS or ordinary Docker deployments.

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

The provided Caddy configuration publishes only:

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

Everything else receives `404` at the public reverse proxy. In particular, Project/Task CRUD, review approval/retry, the Worker registry listing, and the current Web UI are not publicly routed.

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

## Run a worker

The worker needs `git`, access to the project repositories it may execute, and Pi on `PATH` (or `LAZYTEAM_PI_BIN`). The preferred bootstrap path does **not** require the remote machine to know `LAZYTEAM_PUBLIC_URL` or the shared enrollment secret in advance:

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

There is intentionally no implicit `127.0.0.1:8787` fallback anymore: a fresh worker must receive either a join code or an explicit server URL, preventing accidental attempts to register against itself.

### Worker and agent configuration

After a worker is enrolled, open **Workers → Configure** in the private UI. The server becomes the source of truth for the worker name, tags, allowed projects, slots, agent selection, provider/model selection, and initial prompt. A running worker fetches this configuration before claiming work, so changes apply to subsequent tasks without re-enrollment.

Agent integrations are capability-driven instead of assuming every CLI exposes the same controls. Each worker reports whether its agent supports model discovery, what login mode it exposes (`unsupported`, `local_interactive`, or `remote`), and the provider/model catalog it can discover. The UI adapts to those capabilities.

Pi is the only agent backend currently implemented. The worker probes Pi through RPC `get_available_models` and refreshes the catalog every 60 seconds. The provider/model dropdowns are populated only from models reported by that worker. Pi authentication is currently treated as **local interactive**: if the catalog cannot be loaded because Pi needs authentication, run Pi on that worker and use `/login`; the worker will discover the models after the next refresh. LazyTeam does not pretend a remote-login API exists when an agent backend does not expose one.

The default initial prompt is deliberately agent-independent:

```text
You are an autonomous LazyTeam coding worker. Execute only the assigned task in the provided repository workspace. Treat the task description and acceptance criteria as the contract. Inspect before editing, make the smallest correct change, preserve unrelated behavior, and follow repository instructions. Run relevant validation and never wait for interactive input. Do not broaden scope. If blocked, stop and report the concrete blocker. Do not expose secrets or modify external systems unless the task explicitly requires it. Finish with a concise summary of what changed, validation performed, and any remaining risks.
```

A task keeps one stable worker workspace and one stable agent session across review retries. Pi sessions are keyed by task ID, and review retries are pinned to the same worker so the existing conversation/cache and repository state can be reused. The worker publishes a stable `lazyteam/task-<task-id>` review branch after every successful attempt. The workspace and agent session are retained through review and merge; they are deleted only after LazyTeam receives an explicit merged signal.

### Reviewer configuration

Review policy is project-scoped because different repositories can require different standards. The current UI exposes **ChatGPT / MCP** review only; there are intentionally no Approve/Retry buttons in the board and no temporary manual-review workflow. Projects still have an independent reviewer prompt.

Before deciding, an MCP reviewer calls `reviews_get(task_id)`. The response is designed for an actual review machine, not a patch-only judgment: it contains the project/task contract, full worker execution environment, latest execution, reviewer prompt, and a structured checkout bundle with repository URL, default branch, published review ref, commit SHA, and base SHA. The patch/summary/validation fields remain useful evidence, but the reviewer should fetch the review ref into an execution environment and run appropriate inspection/tests whenever practical.

A review retry requires a reason. LazyTeam stores that reason as `review_feedback`, pins the task back to the worker that produced the reviewed attempt, and injects the feedback into the same persistent task session. The task workspace and Pi session are reused instead of being recreated, improving continuity and provider prompt-cache reuse.

Approval is only a review verdict: `tasks_approve` moves the task to `merge_pending`. It does **not** release dependencies or delete worker state. After the reviewed ref is actually merged into the default branch, the merger calls `tasks_merged(task_id, merge_commit_sha)`. Only then does the task become `done`, dependencies unlock, and the original worker receive a cleanup item. The worker then deletes the task workspace, Pi session directory, and best-effort deletes the temporary review branch.

The worker also captures up to 256 KiB of textual patch evidence and marks truncated patches explicitly, but the pullable review ref is the primary path for full-context review.

## Task lifecycle

```text
queued -> assigned -> running -> review -> merge_pending -> done
   ^                         |                         |
   |---- review retry -------|                         |
   |                                                   |
   +---- failed/blocked retry -------------------------+
```

- Completed worker executions enter `review` and publish a stable review ref.
- Review retry requires feedback and is sticky to the same worker so workspace/session state is reused.
- `tasks_approve` moves `review -> merge_pending`; dependencies remain blocked.
- `tasks_merged` requires a merge commit SHA, moves `merge_pending -> done`, releases dependencies, and queues worker cleanup.
- Every execution still gets its own UUID/attempt record, but attempts share the task workspace/session until merge.

## Connect ChatGPT through MCP

Add the public MCP endpoint to ChatGPT:

```text
https://lazyteam.example.com/mcp
```

The server exposes OAuth discovery, Dynamic Client Registration, HTTPS Client ID Metadata Documents, PKCE authorization, token refresh, and the RFC 9728 `resource_metadata` challenge. The authorization page uses `LAZYTEAM_OAUTH_PASSWORD` for the human approval step.

Current MCP tools:

```text
projects_list
projects_create
tasks_list
tasks_create
reviews_get
tasks_approve
tasks_merged
tasks_retry
workers_list
```

The intended flow is that a strong planner such as ChatGPT talks to the OAuth-protected MCP control plane, creates project-scoped work, and lets idle workers claim matching tasks automatically.

## Development

For non-production local development, the security middleware keeps the original unauthenticated local REST workflow unless credentials/production mode are enabled:

```sh
cargo check --workspace
cargo test --workspace
cargo run -p lazyteam-server
```

CI boots real LazyTeam servers and gates the public deployment on:

- `cargo check --workspace` and `cargo test --workspace`.
- OAuth discovery and RFC 9728 protected-resource metadata.
- DCR, PKCE authorization-code exchange, and refresh-token rotation.
- Authenticated MCP `server/discover` and `tools/list`.
- Unauthenticated MCP challenge metadata.
- Multi-project worker matching, lease renewal, review retry affinity, explicit merge gating, and post-merge cleanup/dependency release.
- Anonymous/admin/worker role separation.
- Per-worker credential isolation and cross-worker execution rejection.
- OAuth callback/client host policy and private CIMD rejection.
- OAuth rate limiting.
- Rejection of insecure HTTP public URLs for every non-loopback hostname, including when production mode is omitted.
- Production Docker image build.
- Local and public Docker Compose configuration validation.
