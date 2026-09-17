# LazyTeam

LazyTeam is a self-hosted control plane for coordinating AI coding workers across multiple projects.

## Current MVP

- Rust control plane and Rust worker daemon.
- Multiple first-class projects, each bound to a Git repository and default branch.
- Shared worker pool with project access rules and key/value capability tags.
- Workers connect outbound: register, heartbeat, claim, renew leases, and report results.
- Task dependencies, execution attempts, stale-execution rejection, and lease-expiry requeue.
- Pi RPC is the first worker runtime; an execution is considered finished only after Pi emits `agent_settled`.
- Persistent SQLite state.
- Web control board at `/` for projects, tasks, workers, approval, and retry.
- MCP Streamable HTTP at `/mcp` for ChatGPT and other MCP clients.
- OAuth compatibility modeled after MCPX: RFC 9728 protected-resource metadata, RFC 8414 authorization-server metadata, PKCE S256, Dynamic Client Registration, authorization-code and rotating refresh-token grants, plus path-qualified discovery aliases.

## Run the control plane

Set a public URL that resolves to the server when connecting a remote MCP client. For local development, localhost is fine.

```sh
export LAZYTEAM_PUBLIC_URL=https://lazyteam.example.com
export LAZYTEAM_OAUTH_PASSWORD='replace-with-a-strong-password'
docker compose up --build
```

Persistent data is stored in the `lazyteam-data` Docker volume. The server listens on port `8787` by default.

Useful endpoints:

```text
/                                      Web UI
/health                                Health check
/api/projects                          Project API
/api/tasks                             Task API
/api/workers                           Worker registry
/mcp                                   MCP Streamable HTTP
/.well-known/oauth-protected-resource/mcp
/.well-known/oauth-authorization-server
/mcp/oauth/register
/mcp/oauth/authorize
/mcp/oauth/token
```

## Add a project

```sh
curl -X POST http://127.0.0.1:8787/api/projects \
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

## Run a worker

The worker needs `git`, access to the project repositories it may execute, and Pi on `PATH` (or `LAZYTEAM_PI_BIN`).

```sh
cargo run -p lazyteam-worker -- \
  --server http://127.0.0.1:8787 \
  --name worker-01 \
  --project '*' \
  --tag os=linux \
  --tag arch=x86_64 \
  --tag rust=true
```

The worker persists its identity locally, actively registers with the control plane, and claims only tasks whose project access and required tags match. Each execution gets a separate checkout and branch.

## Task lifecycle

```text
queued -> assigned -> running -> review -> done
   ^                                 |
   |---- lease loss / retry ---------|
```

- Completed worker executions enter `review`.
- Approval moves a task to `done` and releases dependent tasks.
- Review/failed/blocked tasks can be retried.
- Every execution has its own UUID and attempt number; an old worker cannot finish over a newer attempt.

## Connect ChatGPT through MCP

Expose the control plane over HTTPS, set `LAZYTEAM_PUBLIC_URL` to that externally reachable origin, then add this MCP endpoint to the client:

```text
https://lazyteam.example.com/mcp
```

The server exposes OAuth discovery, Dynamic Client Registration, PKCE authorization, token refresh, and the RFC 9728 `resource_metadata` challenge used by MCP clients. The current authorization screen uses `LAZYTEAM_OAUTH_PASSWORD` as the human approval credential.

Current MCP tools:

```text
projects_list
projects_create
tasks_list
tasks_create
tasks_approve
tasks_retry
workers_list
```

The intent is that a strong planner such as ChatGPT talks only to the control plane, creates project-scoped work through MCP, and lets idle workers claim matching tasks automatically.

## Development

```sh
cargo check --workspace
cargo test --workspace
```

CI also boots a real LazyTeam server and exercises OAuth discovery, DCR, PKCE authorization-code exchange, refresh-token rotation, and the unauthenticated MCP challenge.
