---
title: Getting Started with LocalVault
description: Install LocalVault, create your first vault, and store secrets encrypted on your machine. No servers, no cloud, no subscriptions.
type: doc
---

# Getting Started with LocalVault

LocalVault is a free, open-source secrets manager. Store API keys, tokens, credentials, and any sensitive values encrypted on your machine. No servers, no cloud, no subscriptions.

**Source code:** [github.com/inventlist/localvault](https://github.com/inventlist/localvault) (MIT licensed)

## Install

**macOS (Homebrew):**

```bash
brew install inventlist/tap/localvault
```

**Linux / RubyGems:**

```bash
# Install libsodium first
apt-get install libsodium-dev   # Ubuntu/Debian
brew install libsodium          # macOS

gem install localvault
```

## Create a vault

```bash
localvault init
```

You'll be prompted for a passphrase (with confirmation). This creates a vault called `default` at `~/.localvault/vaults/default/`.

## Store and retrieve secrets

```bash
# API keys
localvault set OPENAI_API_KEY "sk-proj-..."
localvault set STRIPE_SECRET_KEY "sk_live_..."

# Tokens and credentials
localvault set GITHUB_TOKEN "ghp_..."
localvault set AWS_SECRET_ACCESS_KEY "wJalr..."

# Database URLs, webhook secrets, anything sensitive
localvault set DATABASE_URL "postgres://user:pass@host/db"
localvault set WEBHOOK_SECRET "whsec_..."

# Retrieve a single secret
localvault get OPENAI_API_KEY

# List all keys
localvault list

# Delete a secret
localvault delete OLD_KEY
```

## Unlock once per session

Typing your passphrase every time gets old. Unlock once and all subsequent commands skip the prompt:

```bash
eval $(localvault unlock)
```

This stores the derived master key in `LOCALVAULT_SESSION` in your shell's memory. It disappears when the terminal closes — it's never written to disk.

## Inject secrets into commands

```bash
# Export as shell variables
localvault env

# Run any command with secrets injected as env vars
localvault exec -- rails server
localvault exec -- node app.js
localvault exec -- docker compose up
localvault exec -- python manage.py runserver
```

## Multiple vaults

Separate secrets by project, environment, or service. Each vault has its own passphrase:

```bash
localvault init production
localvault init staging

localvault set API_KEY "sk-prod-xxx" --vault production
localvault set API_KEY "sk-staging-xxx" --vault staging

localvault vaults
# => default (default)
# => production
# => staging

# Switch default vault
localvault switch production

# Unlock a specific vault
eval $(localvault unlock --vault production)
```

## Reset a vault

Forgot your passphrase? Use `reset` to wipe and start fresh:

```bash
localvault reset
# WARNING: This will permanently delete all secrets in vault 'default'.
# Type 'default' to confirm: default
# New passphrase: ••••••••
```

**All secrets are permanently deleted. There is no recovery — that's the point.**

## Sync to the cloud (optional)

Back up and sync your vault across machines via InventList — free, zero-knowledge:

```bash
# Log in with your InventList API token
localvault login <your-token>

# Push your vault to the cloud
localvault sync push

# Pull it on another machine
localvault sync pull

# Check sync status across all vaults
localvault sync status
```

See [LocalVault Sync — How It Works](06-sync-how-it-works.md) for the full guide.
