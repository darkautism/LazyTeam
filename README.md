# LazyTeam

It started the way all great infrastructure starts: with too many subscriptions. One ChatGPT plan, one Gemini plan, some dumb models you bought at 2 a.m., plus a pile of free tokens that expire at the end of the month. You stare at the pile and think: *I should use them all up.* Then the next thought arrives, uninvited: *is GPT hallucinating new skills worse than Gemini, or is it the other way around?* LazyTeam exists so you don't have to answer that alone — point every model you have at one task list and let them prove it.

## Why use LazyTeam?

You have coding work spread across several Git projects and a drawer full of AI models, subscriptions, and tokens. LazyTeam gives you one place to drop off tasks ("fix this bug", "add that feature") and one shared crew of workers that picks the work up and does it.

You don't babysit checkouts, copy-paste diffs between chat windows, or wonder which model did what. You describe the job in plain words, a worker claims it, writes the code, and another worker double-checks it before anything lands in your real repository.

## What problem does it solve?

Without LazyTeam, using many AI coders looks like this: five browser tabs, three API keys, copy-pasted code, lost context, and mystery merges.

LazyTeam fixes that by being the patient middle-manager:

- **One task list for all your projects.** Each project points at a Git repo and a default branch.
- **One shared pool of workers.** Workers are small programs running on your machines or servers. Each one knows which projects it may touch and what it is good at.
- **Safe hands on your code.** Workers never get your GitHub token or SSH key. Only the central LazyTeam server (the "Host") can push to your real repo, and only after a review passes.
- **Talk to it from ChatGPT.** LazyTeam speaks the MCP protocol, so a strong planner like ChatGPT can create and track tasks for you over a secure login.

In short: you bring the ideas and the model subscriptions; LazyTeam brings the discipline.

## How the workflow feels

1. **You describe a job.** In ChatGPT (connected to LazyTeam) or in the small private web dashboard, you say something like: "In project *my-blog*, fix the broken RSS feed. It must validate and existing tests must pass."
2. **A worker picks it up.** The next free worker that is allowed to work on *my-blog* claims the task, gets its own clean copy of the code, and starts editing — using whatever model and API key you assigned to that worker. That is how you burn through all those subscriptions: give each worker a different one.
3. **The work gets reviewed.** When the worker finishes, the task moves to a *review* lane. A second worker (a "reviewer") reads the proposed change independently and says *approve* or *try again, because…*. If it asks for changes, the feedback goes back to the original worker, which already remembers the context.
4. **The Host merges it.** Once approved, the Host re-checks that nobody moved the goalposts, then pushes exactly the reviewed change to your real Git repo using its own stored credential. Your main branch moves forward; dependencies unlock; everyone cleans up.

You can watch all of this on the Home board: queued → being worked on → in review → waiting to merge → done.

> **Settle the bet:** give one worker your GPT key and another your Gemini key, assign them similar tasks, and compare the review verdicts. May the least-hallucinated skills win.

## Install / deploy it

You need two things: the **server** (one copy, reachable on the internet) and at least one **worker** (as many as you like, anywhere that can reach the server).

### 1. Deploy the server

Pick a machine with Docker (a VPS, home server, or NAS), point a DNS name at it, e.g. `lazyteam.example.com`, and run:

```sh
export LAZYTEAM_PUBLIC_URL=https://lazyteam.example.com
export LAZYTEAM_OAUTH_PASSWORD="$(openssl rand -base64 32)"
export LAZYTEAM_ADMIN_TOKEN="$(openssl rand -hex 32)"
export LAZYTEAM_WORKER_TOKEN="$(openssl rand -hex 32)"

docker compose -f docker-compose.public.yml up -d --build
```

That starts LazyTeam plus Caddy, which automatically gets and renews your public TLS (HTTPS) certificate — you don't need to buy or install one. Your AI entry point is then:

```text
https://lazyteam.example.com/mcp
```

Connect that URL in ChatGPT as an MCP server and log in with your OAuth password when asked. Local administration (creating projects, generating worker join codes) happens on the server itself at `http://127.0.0.1:8787/ui` with your admin token — that dashboard is never exposed to the internet.

Published images are `ghcr.io/darkautism/lazyteam:latest` (server) and `ghcr.io/darkautism/lazyteam-worker:latest` (worker, includes Pi `@earendil-works/pi-coding-agent@0.85.1`), both for `linux/amd64` and `linux/arm64`.

### 2. Add a worker

**Easiest (container worker):** in the private dashboard (`/ui`), click **Generate join code**, then on the worker machine run:

```sh
export LAZYTEAM_WORKER_JOIN_CODE='<ltj1...>'
export LAZYTEAM_WORKER_NAME='worker-01'
export LAZYTEAM_WORKER_SLOTS=1
docker compose -f docker-compose.worker.yml up -d
```

The supplied worker Compose file always refreshes the published `latest` image before recreating the worker, so a restart cannot silently reuse an older local image. The join code is a short-lived (10-minute) invite — after the worker joins once, it remembers its own credential and you can throw the code away.

**Native worker (from source):**

```sh
cargo run -p lazyteam-worker -- \
  --join-code '<ltj1...>' \
  --name worker-01 \
  --project '*' \
  --tag rust=true \
  --slots 1
```

Then open **Workers → Configure** in the private dashboard to pick that worker's role (Worker or Reviewer), agent, provider/model, API key, and starting instructions. Until its AI provider reports at least one usable model, the worker politely stays idle instead of claiming work it can't do.

### 3. Create a project and a task

In the private dashboard or via ChatGPT, create a project pointing at your Git repo and default branch, then create a task with a plain-language description plus what "done" looks like. Idle matching workers claim it automatically.

## What credentials, tokens, and certificates do you need?

| What | Where you set it | What it does |
|---|---|---|
| `LAZYTEAM_PUBLIC_URL` | Server environment | Your public address, e.g. `https://lazyteam.example.com`. Used for login callbacks and worker connections. |
| `LAZYTEAM_OAUTH_PASSWORD` | Server environment | The human password you type when ChatGPT asks LazyTeam for permission. This is how you approve the connection. |
| `LAZYTEAM_ADMIN_TOKEN` | Server environment; pasted into `/ui` | Master key for local management (projects, tasks, workers). Never exposed to the internet; kept in browser session storage only. |
| `LAZYTEAM_WORKER_TOKEN` | Server environment | One-time enrollment secret for new workers. After a worker joins it gets its own credential, so you can rotate this without breaking existing workers. |
| Worker **join code** (`ltj1…`) | Generated in `/ui`, valid 10 minutes | Short-lived invite that bundles the server address + enrollment permission, so a new worker doesn't need the raw token. |
| Project Git credential (SSH key or HTTPS token) | Per project, in `/ui` or API | How the *server only* reads/writes your Git repo (e.g. a GitHub fine-grained token with **Contents: Read and write** on just that repo). Workers never see it. |
| Provider API keys (OpenAI, Gemini, etc.) | Per worker, in **Workers → Configure** | Pays for that worker's brain. Handed once to the worker over an encrypted handoff; never stored in the server database. Free tokens welcome — this is the place to burn them. |
| TLS certificate | Automatic | Caddy obtains and renews a public HTTPS certificate for your domain. You provide nothing except the DNS name. |

**Safety in one paragraph:** keep the admin token and enrollment secret strong and private, never publish port `8787` directly (always go through the included Caddy setup, which only exposes the chat, login, health, and worker endpoints), and give each project Git credential access to only the repo it needs. Full details — identities, token storage, sandboxing, and the public route boundary — live in [ARCHITECTURE.md](ARCHITECTURE.md#security-model).

## Go deeper

Technical reader? The engineering details — Host/worker/reviewer boundaries, the Git broker, the review-and-merge lifecycle, sessions and affinity, OAuth hardening, storage, and operations — live in **[ARCHITECTURE.md](ARCHITECTURE.md)**.

Local development quick check: `cargo check --workspace`, `cargo test --workspace`, `cargo run -p lazyteam-server`.
