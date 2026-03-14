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
localvault install-mcp --cursor
localvault install-mcp --windsurf
```

## How it works

When you run `eval $(localvault unlock)`, the derived master key is cached in your shell session. The MCP server inherits this session and can decrypt your vault for the duration of your terminal session.

The agent never sees your passphrase. It gets access to individual secrets only when it calls the MCP tools.

## Tools available to the agent

| Tool | What it does |
|------|-------------|
| `get_secret` | Retrieve a secret by key |
| `list_secrets` | List all secret keys (values hidden) |
| `set_secret` | Store a new secret |
| `delete_secret` | Delete a secret |

All tools accept an optional `vault` parameter to target a specific named vault.

## Multiple vaults

The agent can work with any unlocked vault:

```
get_secret(key: "DATABASE_URL", vault: "production")
set_secret(key: "NEW_TOKEN", value: "...", vault: "staging")
list_secrets(vault: "intellectaco")
```

If no vault is specified, it uses whichever vault is currently unlocked in your session.

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

The server picks up your active session automatically if you've run `eval $(localvault unlock)` in the same terminal.

## Security model

- Your passphrase never touches the MCP protocol
- The session token (`LOCALVAULT_SESSION`) is a derived key — it can decrypt your vault but cannot reconstruct your passphrase
- Session expires when your terminal closes
- The MCP server only runs when invoked — there is no background daemon
