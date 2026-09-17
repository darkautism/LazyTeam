# LazyTeam

LazyTeam is a self-hosted control plane for coordinating AI coding workers across multiple projects.

## MVP goals

- Multi-project task queue.
- Workers register outbound, heartbeat, claim work, renew leases, and report results.
- Deterministic project/capability matching.
- Persistent SQLite state.
- Rust server and Rust worker daemon.
- Pi as the first agent runtime behind an abstraction.
- MCP over Streamable HTTP so ChatGPT and other MCP clients can CRUD projects/tasks/workers/executions.
- OAuth compatibility modeled after MCPX: RFC 9728 protected-resource metadata, RFC 8414 authorization-server metadata, PKCE S256, Dynamic Client Registration, authorization-code and refresh-token grants, and ChatGPT-compatible discovery aliases.

This repository is being bootstrapped as a dogfood project: once the control plane is usable, LazyTeam should be able to schedule work on itself.
