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

A vault is a directory at `~/.localvault/vaults/<name>/`. Secrets are stored together in an encrypted JSON blob plus metadata.

When you unlock:
1. You type your passphrase
2. Argon2id derives the master key (slow by design — resists brute force)
3. The master key decrypts the vault blob on demand
4. The master key is optionally cached in Keychain / session file

The vault data is encrypted at rest. The derived master key may be cached in Keychain or LocalVault's file fallback with a TTL so CLI and MCP calls can reuse the unlock.

## Session caching

`eval $(localvault unlock)` exports `LOCALVAULT_SESSION` — a base64-encoded session token for the active shell.

On macOS, the session is also stored in Keychain. This avoids re-prompting on new terminal windows during the same working session.

On Linux, the session is stored as a 0600 file. When `$XDG_RUNTIME_DIR` exists it goes in `$XDG_RUNTIME_DIR/localvault/`, a per-user tmpfs cleared at logout, so the cached key never lands on persistent disk. Otherwise it falls back to `~/.localvault/.sessions/`.

Sessions last 8 hours by default. Change it with `localvault config set session-ttl HOURS` (1–24), or `LOCALVAULT_SESSION_TTL_HOURS` for one process. `localvault lock` forgets every vault and the identity key at once.

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
- Keylogger or malware running as you (it sees what you see)
- Attacker with your private key file **and** its identity passphrase
- Weak passphrases. New passphrases must be at least 12 characters and not a common one, but Argon2id is slow, not magic.

## Private key storage

Your X25519 identity private key lives in `~/.localvault/keys/identity.priv` (mode 0600), **encrypted with an identity passphrase**: Argon2id derives a key, XSalsa20-Poly1305 seals the private key. The file is a small JSON envelope carrying the salt and the Argon2id parameters, so they can be raised later.

This arrives in the next release. Earlier versions store the private key as plain base64, protected only by the `0600` file permission ([why we changed it](https://localvault.kuickr.co/the-key-we-forgot-to-lock.md)).

The identity passphrase is separate from your vault passphrases, because this one key unlocks the key slots of every vault shared with you.

- `localvault keys unlock` opens it once per session.
- `localvault keys protect` upgrades a key from an older install, or changes the passphrase.
- `localvault keys status` tells you which state you are in, without printing key material.

Back the file up like an SSH key. If you lose it, you lose access to any vault where you're the only authorized user.

## Open source

All crypto code is in `lib/localvault/crypto.rb`. The vault format, encryption scheme, and key derivation parameters are public and auditable. There are no proprietary algorithms, no security through obscurity.
