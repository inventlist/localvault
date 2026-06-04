---
title: LocalVault Sync — How It Works
description: Sync your encrypted vaults across machines via InventList. Zero-knowledge — your secrets are encrypted before they leave your machine.
type: doc
---

# LocalVault Sync — How It Works

LocalVault sync stores your encrypted vault on Cloudflare R2 via InventList. Your secrets are encrypted before they leave your machine. InventList stores opaque encrypted bytes — it cannot read your secrets.

## Setup (one time)

```bash
# Log in with your InventList API token. This validates your token,
# generates your X25519 identity keypair if you don't have one yet,
# and publishes your public key to your profile.
localvault login <your-token>
```

Get your API token at `inventlist.com/@YOUR_HANDLE/edit#developer`. (If you'd
rather create the keypair ahead of time, `localvault keys generate` does that;
`login` will use the existing key.)

## Sync everything in one command

Most of the time you just run:

```bash
localvault sync            # push local changes, pull remote changes, for every vault
localvault sync --dry-run  # preview the plan without making any changes
```

For each vault it compares local and remote and picks a direction:

```
  Vault         Action  Reason
  ────────────  ──────  ──────
  production    push    local only
  staging       pull    remote changes
  default       skip    up to date
  agpages       adopt   in sync — recording baseline
  notes         CONFLICT  both local and remote changed since last sync
```

- **push** / **pull** — only one side changed since the last sync, so the direction is unambiguous.
- **skip** — nothing changed on either side.
- **adopt** — both sides already hold identical secrets but there was no sync baseline yet (e.g. a vault pushed before sync tracking existed); LocalVault records a baseline so future syncs can detect drift. No data moves.
- **CONFLICT** — both sides changed independently, or both exist with no baseline and the secrets genuinely differ. LocalVault never overwrites either side here; resolve it explicitly with `sync push <vault>` (keep local) or `sync pull <vault> --force` (keep remote).

The summary line reports the counts, e.g. `Summary: 1 pushed, 1 pulled, 1 baselined, 1 up to date`.

The sections below cover the single-vault `sync push` / `sync pull` commands that the bidirectional sync is built on.

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

## Team access

Team vaults let you add collaborators by InventList handle. LocalVault looks up their public key from their profile and creates an encrypted key slot — no passphrase sharing required. Run `localvault team init` to convert a vault, then `localvault add @handle` to grant access (optionally `--scope KEY...` for access to specific keys only). See the team-sharing articles later in this series for the full flow.
