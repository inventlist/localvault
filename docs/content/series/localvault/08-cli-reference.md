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
| `localvault demo` | Create demo vaults with fake data for learning (passphrase: `demo`) |
| `localvault set KEY VALUE` | Store a secret |
| `localvault get KEY` | Retrieve a secret value |
| `localvault list` | List all secret keys |
| `localvault delete KEY` | Remove a secret or project group |
| `localvault show` | Display secrets in a table (masked) |
| `localvault show --reveal` | Show full values |
| `localvault show --group` | Group flat keys by common prefix (`STRIPE_KEY` + `STRIPE_SECRET` → `STRIPE`) |
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
| `localvault unlock [NAME]` | Cache passphrase for the session and export `LOCALVAULT_SESSION` |
| `localvault lock [NAME]` | Clear cached session (or all sessions) |
| `localvault rekey [NAME]` | Change vault passphrase |
| `localvault reset [NAME]` | Wipe and reinitialize a vault |

## Login

| Command | Description |
|---------|-------------|
| `localvault login [TOKEN]` | Log in to InventList — auto-generates keypair + publishes public key |
| `localvault login --status` | Show current login status |
| `localvault logout` | Log out of InventList |

## Identity keys

The `keys` namespace manages your X25519 keypair. `localvault login` auto-generates and publishes for you, so you only need these commands when rotating, inspecting, or recovering your identity.

| Command | Description |
|---------|-------------|
| `localvault keys generate` | Generate an X25519 keypair (no-op if one already exists) |
| `localvault keys generate --force` | Regenerate the keypair, overwriting the existing one |
| `localvault keys publish` | Upload your public key to InventList |
| `localvault keys show` | Print your base64-encoded public key |
| `localvault keygen` | Legacy alias — same as `keys generate` (also supports `--show` and `--force`) |

## Cloud sync

| Command | Description |
|---------|-------------|
| `localvault sync push [NAME]` | Push vault to cloud |
| `localvault sync pull [NAME]` | Pull vault from cloud (auto-unlocks if you have a key slot) |
| `localvault sync pull [NAME] --force` | Overwrite existing local vault |
| `localvault sync status` | Show local/remote status for all vaults |

## Team sharing

The leading `@` in a handle already signals a person operation, so `add`/`remove`/`verify` are top-level commands. The `team` namespace holds the vault-level operations (`init`, `list`, `rotate`).

| Command | Description |
|---------|-------------|
| `localvault verify @HANDLE` | Check if a person has a published public key (dry-run before adding) |
| `localvault add @HANDLE` | Add a teammate to a synced team vault via key slot |
| `localvault add @HANDLE --scope KEY...` | Add teammate with access to specific keys only |
| `localvault remove @HANDLE` | Remove a person's access to a vault |
| `localvault remove @HANDLE --scope KEY` | Remove specific scopes only (keeps other scopes) |
| `localvault remove @HANDLE --rotate` | Full revocation + re-encrypt with new master key |
| `localvault team init [VAULT]` | Convert a vault to a team vault (sets you as owner — required before `add`) |
| `localvault team list [VAULT]` | Show who has access to a vault |
| `localvault team rotate [VAULT]` | Re-key a team vault, keep all members |

The aliases `localvault team add @HANDLE`, `localvault team remove @HANDLE`, and `localvault team verify @HANDLE` still work for backward compatibility but the top-level forms are preferred.

## Legacy direct sharing (pre-v1.2)

These pre-v1.2 commands still work as a fallback when a vault isn't a team vault. For active team vaults, prefer `add` / `remove` above.

| Command | Description |
|---------|-------------|
| `localvault share VAULT --with @handle` | Share vault with an InventList user (one-shot copy) |
| `localvault share VAULT --with team:HANDLE` | Share with a team |
| `localvault share VAULT --with crew:SLUG` | Share with a crew |
| `localvault receive` | Import vaults shared with you |
| `localvault revoke SHARE_ID` | Revoke a direct share by ID |

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
