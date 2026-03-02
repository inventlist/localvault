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

```bash
# Create separate vaults for different environments
localvault init production
localvault init staging

# Use --vault to target a specific vault
localvault set API_KEY "sk-prod-xxx" --vault production
localvault set API_KEY "sk-staging-xxx" --vault staging

# List all vaults
localvault vaults
# => default (default)
# => production
# => staging
```

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

See [MCP Setup Guide](docs/site-docs/mcp-setup.md) for Claude Code and Cursor configuration details.

## Security

### Crypto Stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key derivation | **Argon2id** (64 MB, 2 iterations) | Passphrase to master key |
| Encryption | **XSalsa20-Poly1305** | Authenticated encryption of secrets |
| Key exchange | **X25519** | Future: shared vaults |

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
└── keys/                   # Future: shared vault keys
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

## License

MIT
