# LocalVault Docs Index

## Start Here

- [PILLARS.md](PILLARS.md) — project pillar lock
- `plans/00-delivery-sequence.md` — implementation order; local and Kuickr only
- `plans/01-contextual-cli-help.md` — CLI help and group design, released in 1.8.0
- `plans/02-mcp-safe-secret-use.md` — MCP safety and setup design, released in 1.8.0
- `plans/03-contextual-cli-help-implementation.md` — implemented CLI plan
- `plans/04-mcp-safe-secret-use-implementation.md` — implemented MCP plan
- `plans/06-safe-secret-input-and-fingerprints.md` — safe stdin writes and versioned secret comparison, targeted for 1.9.0
- `plans/07-agent-plaintext-containment.md` — TTY gate and guard hooks so agents cannot expose plaintext, released in 1.9.0

The shared documentation rules and templates live in `../../74-dev-docs`.
Project plans and session records are internal: both are intentionally ignored
by Git and published only to private Kuickr folders —
<https://kuickr.co/dev-docs-74/localvault-plans> and
<https://kuickr.co/dev-docs-74/localvault-sessions>.

## Product Documentation

- [organizing-secrets.md](organizing-secrets.md) — naming and grouping secrets
- [RELEASING.md](RELEASING.md) — release workflow
- `backlog/` — feature backlogs and PRDs
- `sessions/` — dated implementation and release records; internal, ignored by
  Git and published only to <https://kuickr.co/dev-docs-74/localvault-sessions>

## Coordination

- `agents/00-roster.md` — stable agent aliases and roles
- `threads/` — living agent-to-agent conversations
