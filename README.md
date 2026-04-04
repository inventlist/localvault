# LocalVault

Encrypted local secrets vault with MCP server for AI agents. Zero infrastructure, zero cloud dependency.

> **[Try the interactive demo](https://inventlist.com/tools/localvault/cli)** — explore every command in your browser.

Part of [InventList Tools](https://inventlist.com/tools/localvault) — free, open-source developer utilities for indie builders.

---

## Install

### Homebrew (macOS / Linux)

```bash
brew install inventlist/tap/localvault
```

### RubyGems

```bash
gem install localvault
```

**Requires libsodium:**

```bash
# macOS
brew install libsodium

# Ubuntu/Debian
sudo apt-get install libsodium-dev

# Fedora
sudo dnf install libsodium-devel
```

## Quick Start

```bash
# Create a vault (prompts for passphrase)
localvault init

# Store secrets
localvault set OPENAI_API_KEY "sk-proj-..."
localvault set STRIPE_SECRET_KEY "sk_live_..."
localvault set DATABASE_URL "postgres://localhost/myapp"

# Retrieve a secret (raw, pipeable)
localvault get OPENAI_API_KEY

# View all secrets (masked by default)
localvault show

# Reveal values
localvault show --reveal

# Export as shell variables
eval $(localvault env)

# Run a command with secrets injected
localvault exec -- rails server
```

## Commands

### Secrets

| Command | Description |
|---------|-------------|
| `init [NAME]` | Create a vault (Argon2id key derivation) |
| `set KEY VALUE` | Store a secret (supports dot-notation: `project.KEY`) |
| `get KEY` | Retrieve a secret (raw, pipeable) |
| `show` | Display all secrets in a table (masked by default) |
| `show --reveal` | Display with values visible |
| `show --group` | Group by dot-notation prefix (one table per project) |
| `list` | List key names only |
| `delete KEY` | Remove a secret |
| `rename OLD NEW` | Rename a secret key |
| `copy KEY --to VAULT` | Copy a secret to another vault |
| `import FILE` | Bulk-import from .env / .json / .yml |
| `env` | Export as `export KEY="value"` lines |
| `exec -- CMD` | Run a command with secrets injected as env vars |

### Vault Management

| Command | Description |
|---------|-------------|
| `vaults` | List all vaults with secret counts |
| `switch [VAULT]` | Switch default vault |
| `unlock` | Cache passphrase for the session |
| `lock [NAME]` | Clear cached passphrase |
| `rekey [NAME]` | Change vault passphrase (re-encrypts all secrets) |
| `reset [NAME]` | Destroy and reinitialize a vault |

### Sync & Login

| Command | Description |
|---------|-------------|
| `login [TOKEN]` | Log in to InventList — auto-generates X25519 keypair + publishes public key |
| `login --status` | Show current login status |
| `logout` | Clear stored credentials |
| `sync push [NAME]` | Push encrypted vault to cloud |
| `sync pull [NAME]` | Pull vault from cloud (auto-unlocks if you have a key slot) |
| `sync status` | Show sync state for all vaults |
| `config set server URL` | Point at a custom server (default: inventlist.com) |

### Team Sharing (v1.2.0)

| Command | Description |
|---------|-------------|
| `team init` | Convert vault to team vault (sets you as owner, SyncBundle v3) |
| `team verify @handle` | Check if a user has a published public key (dry-run) |
| `team add @handle` | Add teammate with full vault access |
| `team add @handle --scope KEY...` | Add teammate with access to specific keys only |
| `team remove @handle` | Remove teammate's access |
| `team remove @handle --scope KEY` | Remove one scoped key (keeps other scopes) |
| `team remove @handle --rotate` | Full revocation + re-encrypt with new passphrase |
| `team list` | List vault members |
| `team rotate` | Re-key vault with new passphrase, keep all members |

### Keys

| Command | Description |
|---------|-------------|
| `keys generate` | Generate X25519 identity keypair |
| `keys show` | Display your public key |
| `keys publish` | Upload public key to InventList (required before others can add you) |

### AI / MCP

| Command | Description |
|---------|-------------|
| `install-mcp [CLIENT]` | Configure MCP server in claude-code, cursor, windsurf, or zed |
| `mcp` | Start MCP server (stdio transport) |

All commands accept `--vault NAME` (or `-v NAME`) to target a specific vault. Default vault is `default`.

## Personal Sync

Sync your vaults between machines — same passphrase, no team features needed:

```bash
# Machine A: push your vault
localvault sync push

# Machine B: install, login, pull
brew install inventlist/tap/localvault
localvault login YOUR_TOKEN
localvault sync pull
localvault show  # enter your passphrase — same secrets
```

Check what's synced:

```bash
localvault sync status
# default        synced        2 minutes ago
# production     local only    —
```

## Team Sharing

Share vault access with teammates using X25519 asymmetric encryption. The server never sees plaintext.

```bash
# 1. Convert to team vault (required first)
localvault team init -v production

# 2. Verify teammate has a published key
localvault team verify @alice

# 3. Add with full access
localvault team add @alice -v production

# 4. Or scoped — they only see specific keys
localvault team add @bob -v production --scope STRIPE_KEY WEBHOOK_SECRET

# 5. When Alice pulls, auto-unlocks via her identity key
# (on Alice's machine)
localvault sync pull production
# => Unlocked via your identity key.

# 6. Scoped members can't push
# (on Bob's machine)
localvault sync push production
# => Error: You have scoped access. Only the owner can push.

# 7. Rotate without removing anyone
localvault team rotate -v production

# 8. Full revocation + re-key
localvault team remove @alice -v production --rotate
```

**Prerequisites:** Teammates must have a published public key. `localvault login` does this automatically, or: `localvault keys generate && localvault keys publish`.

## MCP Server (AI Agents)

Give AI agents safe secret access. Keys never appear in agent context or config files.

```bash
# One-command install for Claude Code
localvault install-mcp claude-code
# Also supports: cursor, windsurf, zed

# Unlock your vault for the session
localvault unlock

# MCP tools available to the agent:
#   get_secret(key, vault?)      — read a secret
#   list_secrets(vault?, prefix?) — list key names
#   set_secret(key, value, vault?) — store a secret
#   delete_secret(key, vault?)   — remove a secret
```

**exec_action** — agent declares intent, LocalVault executes with secrets injected. The agent never sees the key:

```bash
localvault exec_action -- curl -s https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

## Multi-Project Vaults

One vault, many projects. Dot-notation keeps secrets organized:

```bash
# Store with project prefix
localvault set myapp.DATABASE_URL postgres://localhost/myapp -v work
localvault set api.DATABASE_URL postgres://localhost/api -v work

# View grouped by project
localvault show --group -v work

# Filter to one project
localvault show -p myapp -v work

# Export one project
eval $(localvault env -p myapp -v work)

# Bulk import
localvault import .env --prefix myapp -v work
```

## Session Caching

Avoid typing your passphrase repeatedly:

```bash
eval $(localvault unlock)

# All subsequent commands skip the passphrase prompt
localvault get API_KEY
localvault exec -- rails server
```

Session lives in `LOCALVAULT_SESSION` — disappears when the terminal closes.

## Security

### Crypto Stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key derivation | **Argon2id** (64 MB, 3 iterations) | Passphrase → master key |
| Encryption | **XSalsa20-Poly1305** | Authenticated encryption |
| Key exchange | **X25519** | Team key slots + vault sharing |

- Random 24-byte nonce per encryption
- Poly1305 authentication prevents tampering
- Argon2id is memory-hard (GPU/ASIC resistant)
- All crypto via [libsodium](https://doc.libsodium.org/) (RbNaCl bindings)
- SyncBundle v3 for team vaults (owner field + per-member key slots)

### Storage Layout

```
~/.localvault/
├── config.yml              # Default vault, server URL, token
├── identity.key            # X25519 private key (encrypted at rest)
├── identity.pub            # X25519 public key (safe to share)
├── vaults/
│   ├── default/
│   │   ├── meta.yml        # Salt, creation date, version
│   │   └── secrets.enc     # Encrypted JSON blob
│   └── production/
│       ├── meta.yml
│       └── secrets.enc
```

## Server Independence

LocalVault is server-agnostic. It ships configured for `inventlist.com` but works with any host that implements the protocol (4 endpoints):

```bash
# Use a different server
localvault config set server https://vaulthost.example

# Or override per-login
localvault login --server https://vaulthost.example
```

## Development

```bash
git clone https://github.com/inventlist/localvault.git
cd localvault
bundle install
bundle exec rake test  # 463 tests, 918 assertions
```

## Used by

Powers credentials management at [InventList](https://inventlist.com) — where indie builders ship, share, and get discovered.

## License

Apache 2.0 — see [LICENSE](LICENSE).
Built by the [InventList](https://inventlist.com) team.
