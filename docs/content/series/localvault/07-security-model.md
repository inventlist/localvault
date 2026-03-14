---
title: LocalVault Security Model
description: How LocalVault encrypts your secrets, what algorithms it uses, what the threat model is, and what "zero-knowledge" actually means.
type: doc
---

# LocalVault Security Model

## Encryption stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key derivation | Argon2id (64 MB, 2 iterations) | Passphrase → master key |
| Secret encryption | XSalsa20-Poly1305 | Authenticated encryption of each secret |
| Key exchange | Curve25519 (X25519) | Per-user key slots for team sharing |
| Session cache | macOS Keychain / file (0600) | Master key cached per-session |

All crypto via [libsodium](https://doc.libsodium.org/) through the `rbnacl` gem.

## How a vault works

A vault is a directory at `~/.localvault/vaults/<name>/`. Each secret is stored as an individual encrypted file. There is no single flat database — this makes partial reads and concurrent writes safer.

When you unlock:
1. You type your passphrase
2. Argon2id derives the master key (slow by design — resists brute force)
3. The master key decrypts individual secret files on demand
4. The master key is optionally cached in Keychain / session file

The master key is **never written to disk** in plaintext. It lives in memory for the duration of the session.

## Session caching

`eval $(localvault unlock)` exports `LOCALVAULT_SESSION` — a base64-encoded master key cached in memory.

On macOS, the session is also stored in Keychain with an 8-hour TTL. This avoids re-prompting on new terminal windows during the same working session.

On Linux, the session is stored as a file in `~/.localvault/.sessions/<vault_name>` with mode 0600. Not as secure as Keychain but reasonable for developer machines.

## Sync and zero-knowledge

When vault sync is enabled:

- Your vault file is already encrypted before upload
- InventList / R2 receives an opaque blob — random bytes without your private key
- InventList stores: vault name, checksum, file size, timestamp. Nothing sensitive.
- For team vaults: the vault master key is encrypted with each user's Curve25519 public key. InventList stores these encrypted key slots — it cannot decrypt them because it doesn't have any private key.

**Zero-knowledge means:** even with full access to InventList's database and R2 bucket, an attacker cannot read your secrets. The cryptographic keys to decrypt them never exist on the server.

## Threat model

**Protects against:**
- Stolen laptop (vault file is encrypted at rest)
- Compromised cloud storage (R2 breach — attacker gets encrypted blobs only)
- Compromised sync server (InventList DB breach — attacker gets metadata only)
- Malicious actor added to team then removed (key slot deleted = no new pulls; `--rotate` for full revocation)

**Does not protect against:**
- Attacker with access to your unlocked terminal session
- Keylogger capturing your passphrase
- Attacker with your private key file (protect this like an SSH key)
- Weak passphrases (Argon2id is slow but not magic)

## Private key storage

Your Curve25519 private key is stored in:
- **macOS**: Keychain under service `localvault-identity`
- **Linux**: `~/.localvault/.keys/private_key` (mode 0600)

Treat it like an SSH private key. Back it up. If you lose it, you lose access to any vault where you're the only authorized user.

## Open source

All crypto code is in `lib/localvault/crypto.rb`. The vault format, encryption scheme, and key derivation parameters are public and auditable. There are no proprietary algorithms, no security through obscurity.
