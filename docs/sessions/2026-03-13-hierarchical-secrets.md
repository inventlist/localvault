# 2026-03-13 Hierarchical Secrets + Release Autopilot (v0.9.0)

## What Was Done

### Hierarchical secrets (dot-notation)

Vault secrets now support one level of nesting: `project.KEY`.

- `set("platepose.DATABASE_URL", val)` — creates group hash
- `get("platepose.DATABASE_URL")` — digs into group
- `delete("platepose.DATABASE_URL")` — cleans up empty groups
- `list` — returns `platepose.DATABASE_URL` style strings
- `export_env(project: "platepose")` — exports raw KEY=val (no prefix)
- `export_env` without project — exports `PLATEPOSE__DATABASE_URL`
- `env_hash(project:)` — flat hash for exec injection
- CLI: `--project / -p` flag on `env`, `exec`, `show`
- `show` auto-renders nested structure without needing `--group`

### MCP logging to stderr

`[localvault-mcp] started  v0.9.0  vault=default` on start, `stopped` on EOF.

### GitHub Actions release autopilot

`.github/workflows/release.yml` — push `v*` tag → tests → gem push → tap update.
Requires secrets: `RUBYGEMS_API_KEY`, `HOMEBREW_TAP_TOKEN`.

## Tests

195 total, 370 assertions, 0 failures. 14 new vault tests for nested behavior.
