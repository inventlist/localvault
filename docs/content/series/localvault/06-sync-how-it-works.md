---
title: LocalVault Sync — How It Works
description: Technical reference for vault sync across devices. Keypair generation, InventList API, R2 storage, push/pull/status commands, and team key slots.
type: doc
---

# LocalVault Sync — How It Works

> This feature is in development. See the [backlog](../../backlog/vault-sync/backlog.md) for status.

LocalVault sync stores your encrypted vault on Cloudflare R2 via InventList. Your secrets are encrypted before they leave your machine. InventList stores opaque encrypted bytes — it cannot read your secrets.

## Setup

```bash
# 1. Generate your keypair (one time per user)
localvault keygen

# 2. Login to InventList — publishes your public key to your profile
localvault login <your-inventlist-api-token>
```

Get your API token from inventlist.com/settings.

## Sync commands

```bash
# Push default vault to the cloud
localvault sync push

# Push a named vault
localvault sync push -v intellectaco

# Pull to this machine
localvault sync pull
localvault sync pull -v intellectaco

# Check sync state across all vaults
localvault sync status
```

### Sync status output

```
Vault            Status      Last synced
──────────────   ─────────   ─────────────────────
default          synced      2 hours ago
intellectaco     ahead       never pushed
staging          behind      3 days ago
```

States:
- **synced** — local and remote checksums match
- **ahead** — local is newer than remote (needs push)
- **behind** — remote is newer than local (needs pull)
- **local-only** — exists locally, never pushed
- **remote-only** — exists in cloud, not pulled yet

## What gets stored

Each vault sync in R2:
- **Key**: `<user_id>/<vault_name>.vault`
- **Content**: the encrypted vault blob (already encrypted by libsodium — no double-encryption)

Each vault sync in the database (metadata only):
- vault name, checksum (sha256), size, last synced time

InventList never stores your passphrase or private key.

## Team access

Add a teammate by their InventList handle. LocalVault looks up their public key from their profile and creates an encrypted key slot for them:

```bash
localvault team add @teammate -v intellectaco
```

The teammate can then pull and unlock the vault with their own private key — no passphrase sharing required.

```bash
# List who has access
localvault team list -v intellectaco

# Remove access
localvault team remove @teammate -v intellectaco

# Remove + rotate master key (full revocation)
localvault team remove @teammate -v intellectaco --rotate
```

## Key slot format

The vault file uploaded to R2 has a small header prepended:

```
[header length: 4 bytes]
[key slots: JSON, one entry per authorized user]
  {
    "handle": "@nauman",
    "key_id": "...",
    "encrypted_master_key": "base64..."  // master key encrypted with user's public key
  }
[vault blob: libsodium encrypted secrets]
```

When you pull, LocalVault finds your key slot, decrypts the master key with your private key, then uses the master key to decrypt the vault blob.

## Security properties

| Property | Guarantee |
|----------|-----------|
| Server access | InventList cannot read your secrets — ever |
| Transport | HTTPS only, Bearer token auth |
| Revocation | Remove key slot — user cannot pull new versions |
| Full revocation | `--rotate` re-encrypts with new master key |
| Passphrase | Never transmitted, never stored server-side |
| Private key | Never leaves your machine |

## Conflict handling

Last-write-wins for v1. If the remote is newer than local, push and pull both warn:

```
Remote vault 'intellectaco' is newer than local (pushed 1 hour ago).
Use --force to overwrite, or run: localvault sync pull first.
```
