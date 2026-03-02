# Getting Started with LocalVault

## Install

### Homebrew (macOS)

```bash
brew install inventlist/tap/localvault
```

### RubyGems

```bash
gem install localvault
```

LocalVault requires **libsodium** for encryption:

```bash
# macOS
brew install libsodium

# Ubuntu/Debian
sudo apt-get install libsodium-dev

# Fedora
sudo dnf install libsodium-devel
```

## Create a vault

```bash
localvault init
```

You'll be prompted for a passphrase (with confirmation). This creates a vault called `default` at `~/.localvault/vaults/default/`.

To create a named vault:

```bash
localvault init production
```

## Store and retrieve secrets

```bash
# Store a secret
localvault set DATABASE_URL "postgres://localhost/mydb"
localvault set API_KEY "sk-1234567890"

# Retrieve a secret (raw value, pipeable)
localvault get DATABASE_URL

# List all keys
localvault list

# Delete a secret
localvault delete API_KEY
```

## Session caching

Typing your passphrase every time gets old. Unlock once per terminal session:

```bash
eval $(localvault unlock)
```

This stores the derived master key in `LOCALVAULT_SESSION` — it lives only in your shell's memory and disappears when the terminal closes. All subsequent commands skip the passphrase prompt.

## Inject secrets into commands

```bash
# Export as shell variables
localvault env
# => export API_KEY="sk-1234567890"
# => export DATABASE_URL="postgres://localhost/mydb"

# Run a command with secrets injected as env vars
localvault exec -- rails server
localvault exec -- node app.js
localvault exec -- docker compose up
```

## Multiple vaults

```bash
# Create separate vaults
localvault init production
localvault init staging

# Target a specific vault
localvault set API_KEY "sk-prod-xxx" --vault production
localvault get API_KEY --vault staging

# List all vaults
localvault vaults
# => default (default)
# => production
# => staging
```

## What's next

- [MCP Setup](mcp-setup.md) — let AI agents access your secrets
