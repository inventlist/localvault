---
title: LocalVault MCP — Secrets for AI Agents
description: How to give Claude Code, Cursor, and Windsurf access to your secrets without ever exposing your passphrase or hardcoding keys.
type: doc
---

# LocalVault MCP — Secrets for AI Agents

AI coding agents need your API keys to do useful work — call your APIs, deploy your code, interact with services. But you don't want to paste secrets into chat, hardcode them in config files, or give your agent a plaintext credential store.

LocalVault solves this with a built-in MCP (Model Context Protocol) server. Your secrets stay encrypted. The agent gets controlled read/write access. Your passphrase never leaves your machine.

## One-time setup

```bash
localvault install-mcp
```

This registers localvault as a user-scope MCP server in Claude Code globally — works across all your projects without per-project configuration.

For Cursor or Windsurf:

```bash
localvault install-mcp cursor
localvault install-mcp windsurf
```

## How it works

When you run `eval $(localvault unlock)` or `localvault show`, the derived master key is cached for the active vault. MCP uses the same default-vault and session-cache rules as the CLI, so `localvault switch`, `LOCALVAULT_VAULT`, and `localvault lock` affect what the agent can access.

The agent never sees your passphrase. It gets access to individual secrets only when it calls the MCP tools.

## Tools available to the agent

| Tool | What it does |
|------|-------------|
| `localvault_whoami` | Diagnose active vault, session, and unlocked state |
| `get_secret` | Retrieve an exact secret key |
| `list_secrets` | List/search secret keys (values hidden) |
| `set_secret` | Store a new secret |
| `delete_secret` | Delete a secret |

All tools accept an optional `vault` parameter to target a specific named vault.

## Multiple vaults

The agent can work with any unlocked vault:

```
get_secret(key: "DATABASE_URL", vault: "production")
set_secret(key: "NEW_TOKEN", value: "...", vault: "staging")
list_secrets(vault: "intellectaco")
list_secrets(vault: "intellectaco", prefix: "AWS_IAM.")
```

If no vault is specified, MCP uses the same active vault as the CLI: explicit vault, then `LOCALVAULT_VAULT`, then `localvault switch` / configured default.

## Manual config (without install-mcp)

If you prefer manual setup, add to your MCP config:

```json
{
  "mcpServers": {
    "localvault": {
      "command": "localvault",
      "args": ["mcp"]
    }
  }
}
```

The server picks up the active default vault and any cached unlock state automatically.

## Security model

- Your passphrase never touches the MCP protocol
- The session token (`LOCALVAULT_SESSION`) is a derived key — it can decrypt your vault but cannot reconstruct your passphrase
- Cached unlocks expire by TTL or immediately when you run `localvault lock`
- The MCP server only runs when invoked — there is no background daemon
