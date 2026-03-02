# MCP Server Setup

LocalVault includes an MCP (Model Context Protocol) server so AI coding agents can read and manage vault secrets over stdio — without ever seeing your passphrase.

## How it works

1. You unlock your vault once: `eval $(localvault unlock)`
2. The session token (`LOCALVAULT_SESSION`) is passed to the MCP server
3. The agent calls tools like `get_secret` and `list_secrets` via JSON-RPC
4. Secrets are decrypted in-process and returned to the agent

## Get your session token

```bash
eval $(localvault unlock)
echo $LOCALVAULT_SESSION
```

Copy the token value for the config below.

## Claude Code

Add to your project's `.mcp.json` (or global `~/.claude.json`):

```json
{
  "mcpServers": {
    "localvault": {
      "command": "localvault",
      "args": ["mcp"],
      "env": {
        "LOCALVAULT_SESSION": "<paste-token-here>"
      }
    }
  }
}
```

Or if you've already run `eval $(localvault unlock)` in your terminal, Claude Code inherits the env var automatically:

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

## Cursor

Add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "localvault": {
      "command": "localvault",
      "args": ["mcp"],
      "env": {
        "LOCALVAULT_SESSION": "<paste-token-here>"
      }
    }
  }
}
```

## Available tools

| Tool | Description | Arguments |
|------|-------------|-----------|
| `get_secret` | Retrieve a secret by key | `key` (string, required) |
| `list_secrets` | List all secret keys | none |
| `set_secret` | Store a key-value pair | `key`, `value` (strings, required) |
| `delete_secret` | Delete a secret by key | `key` (string, required) |

## Example: agent reads a secret

Once configured, the agent can call:

```
get_secret({ "key": "DATABASE_URL" })
→ "postgres://user:pass@host/db"
```

Or list all available keys:

```
list_secrets({})
→ "API_KEY\nDATABASE_URL\nSTRIPE_SECRET"
```

## Security notes

- The session token contains the derived master key (not the passphrase)
- It's equivalent to having the vault unlocked — treat it like a credential
- Tokens live in memory only; they're not written to disk by LocalVault
- Rotate by re-running `eval $(localvault unlock)` with a new passphrase
- The MCP server only accesses the vault specified in the session token
