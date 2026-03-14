---
title: LocalVault Sync — How It Works
description: Sync your encrypted vaults across machines via InventList. Zero-knowledge — your secrets are encrypted before they leave your machine.
type: doc
---

# LocalVault Sync — How It Works

LocalVault sync stores your encrypted vault on Cloudflare R2 via InventList. Your secrets are encrypted before they leave your machine. InventList stores opaque encrypted bytes — it cannot read your secrets.

## Setup (one time)

```bash
# 1. Generate your keypair — creates your X25519 identity
localvault keygen

# 2. Log in with your InventList API token
#    This validates your token and publishes your public key to your profile
localvault login <your-token>
```

Get your API token at inventlist.com/settings.

## Push a vault to the cloud

```bash
# Push default vault
localvault sync push

# Push a named vault
localvault sync push production
localvault sync push intellectaco
```

The encrypted vault is bundled (meta + encrypted secrets) and uploaded to R2. InventList stores the blob, a SHA256 checksum, and the timestamp. It never decrypts anything.

## Pull to another machine

```bash
# Pull default vault (will error if it exists locally — use --force to overwrite)
localvault sync pull

# Pull a named vault
localvault sync pull production

# Overwrite existing local vault
localvault sync pull production --force
```

After pulling, unlock the vault with your passphrase:

```bash
eval $(localvault unlock -v production)
```

## Check sync status

```bash
localvault sync status
```

Output:

```
Vault        Status       Synced At
──────────   ──────────   ─────────
default      synced       2026-03-15
production   local only   —
staging      remote only  2026-03-12
```

Status values:
- **synced** — exists locally and in cloud
- **local only** — exists locally, never pushed
- **remote only** — in cloud, not pulled yet

## What gets stored

On R2 (encrypted blob):
- Path: `<user_id>/<vault_name>.vault`
- Content: JSON bundle with base64-encoded `meta.yml` + `secrets.enc` — both already encrypted

In the database (metadata only — never sensitive):
- Vault name, SHA256 checksum, file size, last synced timestamp

InventList never stores your passphrase, private key, or unencrypted secrets.

## Security properties

| Property | Guarantee |
|----------|-----------|
| Server access | InventList cannot read your secrets |
| Transport | HTTPS only, Bearer token auth |
| Encryption | libsodium (Argon2id + XSalsa20-Poly1305) |
| Passphrase | Never transmitted, never stored server-side |
| Private key | Never leaves your machine |

## Team access (coming soon)

Team vaults will let you add collaborators by InventList handle. LocalVault will look up their public key from their profile and create an encrypted key slot — no passphrase sharing required. See [VS-009/010/011](../../backlog/vault-sync/backlog.md) in the backlog.
