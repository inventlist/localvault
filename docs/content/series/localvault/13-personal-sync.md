---
title: "Personal Sync: Your Vaults On Every Machine"
description: "Sync your encrypted vaults between devices with one command. Same passphrase, same secrets — no team features needed."
type: doc
---

# Personal Sync: Your Vaults On Every Machine

You have a MacBook at your desk and a laptop for the couch. Both need your API keys. Personal sync solves this without team features, key slots, or any ceremony.

## The Setup

### Machine A (where your vaults already live)

```bash
# Log in (once)
localvault login YOUR_TOKEN

# Push your vaults
localvault sync push
localvault sync push production
localvault sync push x
```

Each vault uploads as an encrypted blob. The server stores only ciphertext — it never sees your passphrase or secrets.

### Machine B (new machine)

```bash
# Install
brew install inventlist/tap/localvault

# Log in with the same InventList token
localvault login YOUR_TOKEN

# Pull your vaults
localvault sync pull
localvault sync pull production
localvault sync pull x

# Unlock with your passphrase
localvault show
# Passphrase: ••••••••
# Vault: default (12 secrets)
```

That's it. Same passphrase, same secrets. No key slots, no team init, no public keys.

## How It Works

Personal sync uses SyncBundle v1 — the simplest format:

```
Upload (push):
  vault.enc → Argon2id(passphrase, salt) → encrypted blob → R2 storage

Download (pull):
  R2 storage → encrypted blob → your machine → enter passphrase → secrets
```

The blob is tied to your InventList account. Only you can push or pull it. The passphrase never leaves your machine.

## Check What's Synced

```bash
localvault sync status
# Vault          Status        Last synced
# default        synced        2 minutes ago
# production     synced        1 hour ago
# x              local only    —
# staging        local only    —
```

**"local only"** means the vault exists on this machine but hasn't been pushed. Push it:

```bash
localvault sync push x
localvault sync push staging
```

## When You Change Secrets

Sync is manual — push after changes, pull to update:

```bash
# Machine A: add a new secret
localvault set NEW_KEY "value" -v production
localvault sync push production

# Machine B: pull the update
localvault sync pull production
```

There's no auto-sync or conflict resolution. The last push wins. For solo use this is fine — you know what you changed.

## Personal Sync vs Team Sync

| | Personal sync | Team sync |
|---|---|---|
| Users | Just you | You + teammates |
| Format | SyncBundle v1 | SyncBundle v3 |
| Auth | Same passphrase | X25519 key slots |
| Setup | `sync push` / `sync pull` | `team init` → `team add` |
| Who can push | You | Owner (or all full-access members) |
| Unlock | Enter passphrase | Auto-unlock via identity key |

Start with personal sync. If you need to share a vault with someone else, upgrade it with `team init`.

## Try It

The Getting Started tab in the [interactive demo](https://inventlist.com/tools/localvault/cli) covers personal sync in steps 8-10.
