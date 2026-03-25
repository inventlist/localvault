# Team Sync and Key Slots

How LocalVault enables multi-user vault access without sharing passphrases.

## The Problem

You have a production vault with 20 API keys. Your co-founder needs access. The naive approach:

1. Tell them your passphrase (bad — now two people know it)
2. Email them the secrets (bad — plaintext in transit)
3. Set up a shared password manager (overkill for a CLI tool)

## The Solution: Key Slots

LocalVault uses **per-user key slots** — the vault's master key encrypted once for each authorized user's X25519 public key.

```
Vault blob on InventList cloud:
┌─────────────────────────────────┐
│ meta.yml (salt, name, version)  │ ← plaintext metadata
│ secrets.enc                     │ ← XSalsa20-Poly1305 encrypted
│ key_slots:                      │
│   alice: encrypt(master_key,    │ ← X25519 Box for Alice
│          alice_pub_key)         │
│   bob:   encrypt(master_key,    │ ← X25519 Box for Bob
│          bob_pub_key)           │
└─────────────────────────────────┘
```

The server stores only ciphertext. It never sees the master key, the secrets, or who can decrypt what.

## How It Works

### Setup (once per user)

```bash
localvault login YOUR_TOKEN   # auto-generates X25519 keypair
                               # publishes public key to InventList
```

### Owner pushes vault

```bash
localvault sync push -v production
```

This creates the owner's key slot automatically — encrypts the master key to their own public key.

### Add a teammate

```bash
localvault team add @bob -v production
```

This:
1. Fetches Bob's public key from InventList
2. Encrypts the vault's master key for Bob's public key
3. Adds Bob's key slot to the bundle
4. Pushes the updated blob

### Teammate pulls

```bash
localvault sync pull -v production
# "Pulled vault 'production'."
# "Unlocked via your identity key."
```

Bob's pull detects a matching key slot, decrypts the master key using his private key, and caches it locally. No passphrase needed.

### Remove access

```bash
# Stop future pulls (Bob keeps his local copy)
localvault team remove @bob -v production

# Full revocation — re-encrypt everything with a new master key
localvault team remove @bob -v production --rotate
```

With `--rotate`, the vault gets a new master key. All secrets are re-encrypted. New key slots are created for remaining members. Bob's cached copy becomes useless.

## Crypto Details

- **Key slots** use X25519 Box with ephemeral sender keypairs (same as direct sharing)
- **Bundle format** is versioned (v2 adds key_slots to the v1 meta+secrets format)
- **v1 bundles** (no key slots) are fully backward compatible
- **Master key** is never transmitted — only encrypted copies in key slots
- **Rotation** generates a fresh master key via `SecureRandom.hex(32)` + Argon2id

## What the Server Sees

| Data | Server sees? |
|------|-------------|
| Vault name | Yes (routing) |
| Blob size / checksum | Yes (metadata) |
| Encrypted secrets | Yes (opaque ciphertext) |
| Key slot ciphertexts | Yes (opaque ciphertext) |
| Master key | **Never** |
| Plaintext secrets | **Never** |
| Who can decrypt | **Never** (can't read key slots) |
