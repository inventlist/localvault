---
title: LocalVault CLI Reference
description: Complete reference for all LocalVault commands — secrets management, MCP, sync, and sharing.
type: doc
---

# LocalVault CLI Reference

## Secrets

| Command | Description |
|---------|-------------|
| `localvault init [NAME]` | Create a new vault |
| `localvault set KEY VALUE` | Store a secret |
| `localvault get KEY` | Retrieve a secret value |
| `localvault list` | List all secret keys |
| `localvault delete KEY` | Remove a secret or project group |
| `localvault show` | Display secrets in a table (masked) |
| `localvault show --reveal` | Show full values |
| `localvault show -p PROJECT` | Filter to one project group |
| `localvault env` | Print `export KEY=value` lines |
| `localvault env -p PROJECT` | Export one project group |
| `localvault exec -- CMD` | Run command with secrets in env |
| `localvault import FILE` | Bulk-import from .env/.json/.yml |
| `localvault rename OLD NEW` | Rename a key |
| `localvault copy KEY --to VAULT` | Copy a secret to another vault |

## Vault management

| Command | Description |
|---------|-------------|
| `localvault vaults` | List all vaults with secret counts |
| `localvault switch [NAME]` | Switch default vault (or show current) |
| `localvault unlock` | Export session token for passphrase-free access |
| `localvault lock [NAME]` | Clear cached session (or all sessions) |
| `localvault rekey [NAME]` | Change vault passphrase |
| `localvault reset [NAME]` | Wipe and reinitialize a vault |

## Cloud sync

| Command | Description |
|---------|-------------|
| `localvault keygen` | Generate your X25519 identity keypair |
| `localvault keygen --show` | Print your existing public key |
| `localvault keygen --force` | Regenerate keypair (overwrites existing) |
| `localvault login TOKEN` | Log in to InventList, publish public key |
| `localvault login --status` | Show current login status |
| `localvault logout` | Log out of InventList |
| `localvault sync push [NAME]` | Push vault to cloud |
| `localvault sync pull [NAME]` | Pull vault from cloud |
| `localvault sync pull [NAME] --force` | Overwrite existing local vault |
| `localvault sync status` | Show local/remote status for all vaults |

## Team access

| Command | Description |
|---------|-------------|
| `localvault team list [VAULT]` | Show who has access to a vault |
| `localvault team remove @HANDLE` | Remove a person's access to a vault |
| `localvault share VAULT --with @handle` | Share vault with an InventList user |
| `localvault share VAULT --with team:HANDLE` | Share with a team |
| `localvault receive` | Import vaults shared with you |
| `localvault revoke SHARE_ID` | Revoke a share by ID |

## MCP (AI tool integration)

| Command | Description |
|---------|-------------|
| `localvault mcp` | Start MCP server (stdio) |
| `localvault install-mcp` | Install MCP in Claude Code (default) |
| `localvault install-mcp cursor` | Install in Cursor |
| `localvault install-mcp windsurf` | Install in Windsurf |

## Global options

| Flag | Description |
|------|-------------|
| `--vault NAME` / `-v NAME` | Use a specific vault (overrides default) |

## Dot-notation for team vaults

When you have many projects in one vault, prefix keys with `project.key`:

```bash
localvault set platepose.DATABASE_URL postgres://...   -v intellectaco
localvault set inventlist.STRIPE_KEY sk_live_...        -v intellectaco

# Show one project only
localvault show -p platepose -v intellectaco

# Inject one project's secrets into a command
localvault exec -p platepose -v intellectaco -- rails server
```

## Dot-notation for vault name

Named vault as a positional argument (sync commands) vs global flag (secrets commands):

```bash
# Secrets commands use --vault / -v flag
localvault show -v production
localvault set KEY VAL -v staging

# Sync commands use a positional argument
localvault sync push production
localvault sync pull staging
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `LOCALVAULT_HOME` | Override default `~/.localvault` directory |
| `LOCALVAULT_SESSION` | Session token from `localvault unlock` |
