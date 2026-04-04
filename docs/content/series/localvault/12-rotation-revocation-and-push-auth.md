---
title: "Rotation, Revocation, and Push Auth"
description: "When teammates leave or keys rotate: team remove --rotate, team rotate, and why scoped members can't push."
type: doc
---

# Rotation, Revocation, and Push Auth

Giving someone access is easy. Taking it away — and being confident they can't read future secrets — is the hard part. v1.2.0 adds three mechanisms: full revocation with rotation, standalone rotation, and push authorization.

## Revoking a Teammate

### Simple removal

```bash
localvault team remove @alice -v production
# Removed @alice from vault 'production'.
```

This deletes Alice's key slot. She can no longer pull the vault. But if she cached a copy locally, she could still decrypt it with the key she already has.

### Removal + rotation (recommended for departures)

```bash
localvault team remove @alice -v production --rotate
# New passphrase for vault 'production': ••••••••
# Removed @alice from vault 'production'.
# Vault re-encrypted with new master key (rotated).
# 2 member(s) updated.
```

This does three things:
1. Removes Alice's key slot
2. Prompts for a new passphrase and re-derives the master key
3. Re-encrypts every secret and rebuilds all remaining key slots

Alice's cached copy is now useless — it was encrypted with the old master key, which no longer exists.

Use `--rotate` whenever someone leaves the team, gets a compromised machine, or when you want to be certain old copies can't decrypt future data.

## Standalone Rotation

Sometimes you want to re-key a vault without changing who has access. Periodic rotation, policy compliance, or just good hygiene:

```bash
localvault team rotate -v production
# New passphrase for vault 'production': ••••••••
# Vault 'production' re-encrypted with new master key.
# 2 member(s) updated.
```

All members keep access. All secrets are re-encrypted under a new master key. The old passphrase no longer works.

**When to use `team rotate` vs `rekey`:**

| Command | Use when |
|---------|----------|
| `team rotate` | Team vault — rebuilds all key slots |
| `rekey` | Personal vault — just you, no key slots |

## Push Authorization

v1.2.0 introduces push authorization rules based on member type:

| Vault type | Who can push |
|-----------|-------------|
| Personal (v1) | Owner only |
| Team — all full-access members | Any member |
| Team — has scoped members | Owner only |

The logic: if you've given someone scoped access (they can only see specific keys), you don't want another scoped member pushing changes that could overwrite the vault. Only the owner pushes.

### What Bob sees when he tries:

```bash
# Bob has scoped access
localvault sync push production
# Error: You have scoped access to vault 'production'.
# Only the owner (@nauman) can push.
```

### What Alice (full access) sees:

If the vault has only full-access members (no scoped members), Alice can push. If any scoped member exists, only the owner can push — even full-access members are blocked.

This prevents conflicts. The owner is the source of truth for scoped vaults.

## Partial Scope Removal

You can strip specific keys from a scoped member without fully removing them:

```bash
localvault team remove @bob -v production --scope STRIPE_KEY
# Removed scope(s) STRIPE_KEY from @bob.
# Remaining: WEBHOOK_SECRET
```

Bob's per-member blob is rebuilt with only the remaining keys. He loses access to `STRIPE_KEY` immediately on next pull.

If you remove all scopes, Bob is fully removed from the vault.

## Putting It All Together

A typical team lifecycle:

```bash
# Initial setup
localvault team init -v production
localvault team add @alice -v production
localvault team add @bob -v production --scope STRIPE_KEY WEBHOOK_SECRET

# Quarterly rotation (no member changes)
localvault team rotate -v production

# Bob's contract ends — remove + rotate
localvault team remove @bob -v production --rotate

# Alice leaves the company — full revocation
localvault team remove @alice -v production --rotate
```

After both removals with rotation, you're the only one with access, and the vault has been re-encrypted twice. No old cached copies can decrypt it.

## Try It

Walk through the full revocation flow in the [interactive demo](https://inventlist.com/tools/localvault/cli) — Team Sharing tab, steps 8-10.
