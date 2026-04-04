# LocalVault

Zero-infrastructure secrets manager. Encrypted secrets stored locally, unlocked with a passphrase.

No servers. No cloud. No config files to leak. Just encrypted files on disk.

Part of [InventList Tools](https://inventlist.com/tools/localvault) — free, open-source developer utilities for indie builders.

## Install

### Homebrew (macOS)

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

# Store any sensitive values — API keys, tokens, credentials, database URLs
localvault set OPENAI_API_KEY "sk-proj-..."
localvault set STRIPE_SECRET_KEY "sk_live_..."
localvault set GITHUB_TOKEN "ghp_..."

# Retrieve a secret (pipeable)
localvault get OPENAI_API_KEY

# List all keys
localvault list

# Export as shell variables
localvault env
# => export GITHUB_TOKEN="ghp_..."
# => export OPENAI_API_KEY="sk-proj-..."
# => export STRIPE_SECRET_KEY="sk_live_..."

# Run a command with secrets injected
localvault exec -- rails server
localvault exec -- node app.js
```

## Commands

| Command | Description |
|---------|-------------|
| `init [NAME]` | Create a vault (prompts for passphrase with confirmation) |
| `set KEY VALUE` | Store a secret |
| `get KEY` | Retrieve a secret (raw value, pipeable) |
| `list` | List all keys |
| `delete KEY` | Remove a secret |
| `env` | Export all secrets as `export KEY="value"` lines |
| `exec -- CMD` | Run a command with all secrets as env vars |
| `vaults` | List all vaults |
| `unlock` | Output a session token for passphrase-free access |
| `reset [NAME]` | Destroy all secrets and reinitialize with a new passphrase |
| `login TOKEN` | Log in to InventList (auto-keygen + publish public key) |
| `sync push` | Push vault to InventList cloud |
| `sync pull` | Pull vault from InventList cloud |
| `sync status` | Show sync state for all vaults |
| `team init` | Initialize a vault as a team vault (sets you as owner) |
| `team add @handle` | Add a teammate (with optional `--scope`) |
| `team remove @handle` | Remove a teammate (with optional `--rotate` or `--scope`) |
| `team list` | Show who has access to a synced vault |
| `team rotate` | Re-encrypt vault with new passphrase (no member changes) |
| `version` | Print version |

All vault commands accept `--vault NAME` (or `-v NAME`) to target a specific vault. Defaults to `default`.

## Session Caching

Avoid typing your passphrase repeatedly:

```bash
# Unlock once per terminal session
eval $(localvault unlock)

# All subsequent commands skip the passphrase prompt
localvault get API_KEY
localvault list
localvault exec -- rails server
```

The session token is stored in `LOCALVAULT_SESSION` and contains the derived master key (base64-encoded). It lives only in your shell's memory and disappears when the terminal closes.

## Multiple Vaults

Separate secrets by project, environment, or service — each vault has its own passphrase and encryption:

```bash
# Create separate vaults
localvault init production
localvault init staging
localvault init x          # all X / Twitter API credentials

# Use --vault to target a specific vault
localvault set API_KEY "sk-prod-xxx" --vault production
localvault set API_KEY "sk-staging-xxx" --vault staging

# Store multiple X accounts in one vault using handle-prefixed keys
localvault set MYHANDLE_API_KEY        "..." --vault x
localvault set MYHANDLE_API_SECRET     "..." --vault x
localvault set MYHANDLE_ACCESS_TOKEN   "..." --vault x
localvault set MYHANDLE_ACCESS_SECRET  "..." --vault x
localvault set MYHANDLE_BEARER_TOKEN   "..." --vault x

localvault set MYBRAND_API_KEY         "..." --vault x
localvault set MYBRAND_ACCESS_TOKEN    "..." --vault x

# List all vaults
localvault vaults
# => default (default)
# => production
# => staging
# => x

# Unlock a specific vault for a session
eval $(localvault unlock --vault x)
localvault exec --vault x -- ruby scripts/post.rb
```

## Resetting a Vault

Forgot your passphrase? Use `reset` to destroy all secrets and start fresh with a new one:

```bash
localvault reset
# WARNING: This will permanently delete all secrets in vault 'default'.
# This cannot be undone.
# Type 'default' to confirm: default
# New passphrase:
# Confirm passphrase:
# Vault 'default' has been reset.
```

Works on named vaults too: `localvault reset production`. All secrets are gone — there is no recovery.

## Cloud Sync

Sync vaults across devices via [InventList](https://inventlist.com). Your secrets stay encrypted — the server never sees plaintext.

```bash
# Log in (auto-generates keypair + publishes public key)
localvault login YOUR_TOKEN

# Push a vault to the cloud
localvault sync push

# Pull on another device
localvault sync pull

# Check sync status
localvault sync status
```

## Team Sharing

Share vault access with teammates using X25519 key slots. Three modes: personal sync (just you), direct share (one-time handoff), and team sync (ongoing shared access with scoping).

```bash
# Initialize a vault as a team vault (you become the owner)
localvault team init -v production

# Add a teammate with full access
localvault team add @bob -v production

# Add a teammate with scoped access (only specific keys)
localvault team add @carol -v production --scope platepose DATABASE_URL

# See who has access
localvault team list -v production
# => @alice  (owner)
# => @bob    (full vault)
# => @carol  (scopes: platepose, DATABASE_URL)

# Remove access
localvault team remove @bob -v production

# Remove a specific scope (keeps other scopes)
localvault team remove @carol -v production --scope DATABASE_URL

# Remove + re-encrypt with new passphrase (full revocation)
localvault team remove @bob -v production --rotate

# Re-key without removing anyone (periodic rotation)
localvault team rotate -v production
```

When a teammate pulls a vault they have a key slot for, it auto-unlocks via their identity key. Scoped members see only their authorized keys — they don't know other keys exist.

## MCP Server (AI Agents)

LocalVault includes an MCP server so AI coding agents can read and manage secrets via the Model Context Protocol — without ever seeing your passphrase.

```bash
# Unlock your vault first
eval $(localvault unlock)
```

Then add to your MCP config (`.mcp.json`, `.cursor/mcp.json`, etc.):

```json
{
  "mcpServers": {
    "localvault": {
      "command": "localvault",
      "args": ["mcp"],
      "env": {
        "LOCALVAULT_SESSION": "<your-session-token>"
      }
    }
  }
}
```

If you've already run `eval $(localvault unlock)` in your terminal, the agent inherits the session automatically — no need to paste the token.

**Available tools:** `get_secret`, `list_secrets`, `set_secret`, `delete_secret`

See [MCP for AI Agents](https://inventlist.com/sites/localvault/series/localvault/mcp-for-ai-agents) for Claude Code and Cursor configuration details.

## Security

### Crypto Stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key derivation | **Argon2id** (64 MB, 2 iterations) | Passphrase to master key |
| Encryption | **XSalsa20-Poly1305** | Authenticated encryption of secrets |
| Key exchange | **X25519** | Team key slots + vault sharing |

- Every encryption uses a random 24-byte nonce
- Authentication tag prevents tampering (Poly1305)
- Argon2id is memory-hard, resistant to GPU/ASIC attacks
- All crypto via [libsodium](https://doc.libsodium.org/) (RbNaCl bindings)

### Storage Layout

```
~/.localvault/
├── config.yml              # Default vault name
├── vaults/
│   ├── default/
│   │   ├── meta.yml        # Salt, creation date, version
│   │   └── secrets.enc     # Encrypted JSON blob
│   └── production/
│       ├── meta.yml
│       └── secrets.enc
└── keys/                   # X25519 identity keypair for sync + team access
```

- Secrets are stored as a single encrypted JSON blob per vault
- Atomic writes (temp file + rename) prevent corruption
- Salt is stored in plaintext metadata (this is standard and safe)
- The master key is never written to disk

## Development

```bash
git clone https://github.com/inventlist/localvault.git
cd localvault
bundle install
bundle exec rake test
```

## Used by

Powers credentials management at [InventList](https://inventlist.com) — where indie builders ship, share, and get discovered.

## License

MIT
