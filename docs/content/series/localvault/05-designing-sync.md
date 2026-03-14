---
title: Designing Zero-Knowledge Sync
description: How I designed encrypted vault sync across devices — from shared passphrases to PGP-style per-user keys. The thinking behind making InventList profiles a public key directory.
type: journey
---

# Designing Zero-Knowledge Sync

When I started thinking about sync for LocalVault, the first instinct was the obvious one: just upload the encrypted vault file to a server. It's already encrypted — store the blob somewhere, download it on the other machine, done.

That mostly works. But it has a problem once teams enter the picture.

## The shared passphrase problem

The simplest sync model is: your vault has one passphrase, you know it, you type it on both machines. Secure enough for personal use.

For teams, you'd share that passphrase out of band — a Slack message, a 1Password note, something. And that works too, for a while. But then someone leaves the team. Now what? You rotate the passphrase, re-encrypt everything, and send the new one to everyone still on the team. It's manual, error-prone, and easy to forget.

The bigger issue is this: a shared passphrase means the passphrase itself is a liability. The more people who know it, the less secure it is.

## What PGP got right

PGP-style encryption has been around for decades and it's ugly in a lot of ways — the tooling, the web of trust, the key management UX. But the underlying idea is right: instead of sharing a secret, you share a *public key*. Anyone can encrypt for you. Only you can decrypt.

For vault sharing, this translates to:
- Each user has a keypair (public + private)
- The vault master key (the thing that actually decrypts your secrets) is encrypted *separately* for each authorized user
- When you add a teammate, you encrypt the vault master key with their public key and add it as a "key slot"
- When they pull the vault, they decrypt their key slot with their private key — getting the master key — then decrypt the vault

When someone leaves: delete their key slot. They can no longer pull new versions. Rotate the master key if you need to lock them out of anything they already have locally.

No passphrase sharing. No rotation complexity. Clean revocation.

## Where do public keys live?

PGP's big failure was always key distribution. How do you get someone's public key? You hope they published it to a keyserver, or you ask them to paste it somewhere, or you use Keybase. It's always friction.

The insight here was that InventList profiles are already a trusted identity for indie makers. If a user's public key is on their profile, then `localvault team add @teammate` can look it up automatically. No asking, no pasting, no key exchange dance.

```bash
localvault team add @teammate -v intellectaco
# looks up @teammate's public key from inventlist.com
# encrypts vault master key with their key
# adds as a new key slot
# pushes updated vault
```

The InventList profile becomes a public key directory — the same role GitHub plays for SSH keys, but purpose-built for vault sharing.

## The storage layer

The encrypted vault files are tiny — a few kilobytes at most. Storing them in a database blob column would work, but Cloudflare R2 is a better fit: object storage, globally distributed, already used in the stack.

A dedicated bucket (`localvault-sync`) with keys like `<user_id>/<vault_name>.vault` keeps things simple. The Rails API proxies all access — the CLI never touches R2 directly, which keeps auth and rate limiting centralized.

## What InventList actually stores

This is the part that matters for the security story:

- R2 stores: an encrypted blob. Random bytes to anyone without the private key.
- The database stores: user_id, vault name, checksum, synced_at. No secrets, no keys, no passphrases.
- The server never has: your passphrase, your private key, or the vault master key in plaintext.

Even if R2 was breached, the attacker gets encrypted blobs with no way to decrypt them. Even if the InventList database was breached, the attacker gets metadata with nothing sensitive.

This is what "zero-knowledge" actually means — not a marketing claim, but a cryptographic property. The server literally cannot read your secrets because it was never given the means to do so.

## How personal sync works (same user, two machines)

For your own machines, you don't need key slots. You are the only user. Your public key is the same on both machines (since you generated it once and synced it, or derived it consistently).

```
Mac 1:  localvault keygen    # generates your keypair
        localvault login     # publishes public key to your InventList profile
        localvault sync push # uploads encrypted vault to R2

Mac 2:  localvault login     # pulls your public key from InventList
        localvault sync pull # downloads vault from R2
        localvault show      # enter passphrase, work normally
```

The vault file is encrypted with your passphrase as always. Sync is just transport — the passphrase requirement doesn't go away. What you gain is not having to manually copy files between machines.

## What's still to build

This is all planned, not yet shipped. The current version of LocalVault is local-only. The sync work (keypair generation, InventList API, R2 storage, push/pull commands, team sharing) is the next major phase.

The backlog is in `docs/backlog/vault-sync/` — 11 items across three phases. Phase 1 is the identity layer (keygen + login + InventList API endpoint). Phase 2 is single-user sync. Phase 3 is teams.

I wanted to write about the design before the code, because the security model is the interesting part — and it's easier to see the shape of it before it's buried in implementation details.
