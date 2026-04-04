---
title: "Team Init and Scoped Sharing: Give Your Team Exactly the Keys They Need"
description: "v1.2.0 introduces team init, scoped access, and per-member encrypted blobs. Give teammates access to specific keys — not your entire vault."
type: doc
---

# Team Init and Scoped Sharing

v1.2.0 changes how team vaults work. You now explicitly opt a vault into team mode, and you can scope exactly which keys each teammate sees.

## Why the Change

In v1.1, `team add` worked on any synced vault. This was convenient but created ambiguity — who owns the vault? Can anyone push? What happens when you remove someone?

v1.2.0 makes ownership explicit. You run `team init` once to declare yourself as the owner. The vault gets upgraded to SyncBundle v3, which adds an owner field and per-member key slots. No more guessing.

## The Flow

### Step 1: Push your vault

Start with a vault you already use locally:

```bash
localvault sync push production
# Synced vault 'production' (4821 bytes)
```

This is still a personal vault (SyncBundle v1). Only you can access it.

### Step 2: Initialize as a team vault

```bash
localvault team init -v production
# Vault 'production' is now a team vault.
# Owner: @nauman
#
# Next: localvault team add @handle -v production
```

This does three things:
1. Creates your owner key slot (master key encrypted to your X25519 public key)
2. Re-pushes as SyncBundle v3 with the `owner_handle` field
3. Enables the `team add`, `team remove`, `team list`, and `team rotate` commands

### Step 3: Verify your teammate

Before adding someone, check they have a published public key:

```bash
localvault team verify @alice
# @alice — public key published
#   Fingerprint: aBcDeFgH...efgh
#   Ready for: localvault team add @alice -v VAULT
```

If they don't have a key, they need to run `localvault login` (which auto-generates and publishes one).

### Step 4: Add with full access

```bash
localvault team add @alice -v production
# Added @alice to vault 'production'.
```

Alice gets the vault's master key encrypted to her public key. When she pulls, it auto-unlocks — no passphrase needed.

### Step 5: Add with scoped access

This is the big v1.2.0 feature. Instead of giving someone your entire vault, give them specific keys:

```bash
localvault team add @bob -v production --scope STRIPE_KEY WEBHOOK_SECRET
# Added @bob to vault 'production' (scopes: STRIPE_KEY, WEBHOOK_SECRET).
```

What happens under the hood:
- LocalVault filters the vault to only those keys
- Encrypts the filtered blob with Bob's public key
- Stores it as a per-member encrypted blob alongside the vault

Bob sees only `STRIPE_KEY` and `WEBHOOK_SECRET`. He doesn't know `DATABASE_URL`, `OPENAI_API_KEY`, or any other keys exist.

## How Scoped Access Works

```
SyncBundle v3:
┌────────────────────────────────────┐
│ meta: { owner: @nauman, v: 3 }    │
│ secrets.enc (full vault, encrypted)│
│ key_slots:                         │
│   @nauman: enc(master_key, nauman) │ ← owner: full vault
│   @alice:  enc(master_key, alice)  │ ← full: same master key
│ scoped_blobs:                      │
│   @bob:    enc(filtered, bob)      │ ← scoped: only their keys
└────────────────────────────────────┘
```

Full-access members decrypt the master key and read the whole vault. Scoped members decrypt their personal blob, which contains only the keys listed in `--scope`.

## Partial Scope Removal

Remove one key from someone's scope without revoking entirely:

```bash
localvault team remove @bob -v production --scope STRIPE_KEY
# Removed scope(s) STRIPE_KEY from @bob.
# Remaining: WEBHOOK_SECRET
```

Bob's blob is rebuilt with only the remaining keys.

## What Scoped Members Can't Do

- **Push:** Only the owner can push when scoped members exist
- **See other keys:** The filtered blob contains no information about keys outside their scope
- **Modify the vault:** Scoped access is read-only pull

This separation matters. Your contractor needs the Stripe webhook secret to test payment flows. They don't need your database credentials, your OpenAI key, or your AWS root token. Scoped sharing gives them exactly what they need — nothing more.

## Try It

```bash
localvault team init -v production
localvault team verify @teammate
localvault team add @teammate -v production --scope STRIPE_KEY WEBHOOK_SECRET
```

Or explore the full flow in the [interactive demo](https://inventlist.com/tools/localvault/cli) — Team Sharing tab.
