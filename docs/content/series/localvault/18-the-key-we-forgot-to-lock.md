---
title: "The Key We Forgot to Lock"
description: "A source review found LocalVault's identity private key sitting on disk as plain base64, while our own security page said it was in the Keychain. Here is why that one file matters, how we encrypted it, and why libsodium carries the whole design."
type: journey
---

# The Key We Forgot to Lock

I asked an agent a simple question: read LocalVault's source and tell me, in plain words, why nobody can just take the files and use them.

The answer was mostly reassuring. Then it got to one file.

`~/.localvault/keys/identity.priv` held my X25519 private key as **plain base64**. Nothing encrypted it. A `0600` file permission was all that stood between that file and anyone who could copy my home directory.

Worse, our own [security model page](07-security-model.md) said the key lived in the macOS Keychain under `localvault-identity`. It never did. The docs described the design I meant to ship, not the one I shipped.

This post is about fixing that. It covers why one small file matters so much, how we designed the fix, and why libsodium carries the whole thing.

## The simple idea behind LocalVault

Before the bug, the concept. It fits in one line:

**Your passphrase is the only key, and LocalVault never stores it.**

```
passphrase + random salt ──Argon2id (64 MB)──► 32-byte key   (only ever in memory)
secrets ──XSalsa20-Poly1305 + random nonce──► secrets.enc   (random-looking bytes)
```

Steal `secrets.enc` and you get noise. Guessing the 256-bit key directly is out of reach. Guessing the passphrase instead costs 64 MB of memory per attempt, which is exactly what makes GPU farms slow and expensive. Flip one byte and Poly1305 refuses to decrypt, so nobody can quietly edit a secret either. The sync server only ever stores that sealed blob.

That part was solid. The identity key was the gap in it.

## Why one key matters more than any vault

Vault passphrases protect one vault each. The identity key is different.

When a teammate shares a vault with you, LocalVault doesn't send the secrets. It takes that vault's master key and seals it to your X25519 public key, in what we call a key slot. Only your private key opens it.

So your private key is the key to every key slot ever made for you.

Copy `identity.priv`, pull the key slots from the sync server, and every vault shared with you opens. No passphrase needed. That's the file we left unlocked.

## The design

The fix uses the same two primitives that already protect your vaults. Nothing new to trust.

```json
{ "v": 2, "kdf": "argon2id", "opslimit": 2, "memlimit": 67108864,
  "salt": "…", "box": "nonce + XSalsa20-Poly1305 ciphertext" }
```

Your identity passphrase goes through Argon2id with a fresh salt. The 32-byte result seals the private key with XSalsa20-Poly1305. The file stores the Argon2id parameters alongside the salt, so we can raise them later without breaking anyone's key.

A few decisions mattered more than the code.

**A separate identity passphrase.** I considered reusing a vault passphrase. It was tempting, with one fewer thing to remember. But the identity key outranks any single vault, and tying it to one vault's passphrase would make that vault a skeleton key. So it gets its own.

**No passphrase in an environment variable.** It would have been convenient for scripts. It's also how secrets end up in `ps` output and crash logs. Vaults already avoid this, and the identity key follows the same rule. You unlock it once with `localvault keys unlock`, and it's cached for the session like a vault.

**Old keys keep working.** Breaking every existing install to force an upgrade is a bad trade. A legacy key still decrypts. It prints one line asking you to run `localvault keys protect`, which seals the same key in place. Your public key doesn't change, so nothing you've already shared breaks. The new file is written atomically and decrypted once to verify it before it replaces the old one. A failure leaves you with the key you had, never with nothing.

**`lock` means everything.** `localvault lock` now forgets every vault and the identity key in one go.

## The other three limits

The same review listed three more weaknesses. They're smaller, and we fixed what code can fix.

**Weak passphrases.** Argon2id makes guessing slow, but it can't save `password123`. Every new passphrase now has to be at least 12 characters, can't be one character repeated, and can't come from a short list of the first things attackers try. That covers vault passphrases and the identity passphrase. Existing vaults still open with whatever you chose before.

**The 8-hour session.** Unlocked keys sit in the macOS Keychain for 8 hours, and on Linux they fell back to a file on persistent disk. The default stays 8 hours, because agent workflows depend on it. But `localvault config set session-ttl 2` now shortens it. On Linux the cache moves to `$XDG_RUNTIME_DIR`, a per-user tmpfs that is cleared at logout.

While fixing this I found that the test suite was writing to the same Keychain entries as my real vaults. Each `LOCALVAULT_HOME` now gets its own Keychain service. Tests can't see real keys, and two homes can't read each other's.

**A compromised machine.** This one has no fix, and I'd rather say so than pretend. Malware running as you sees what you type and reads what you've unlocked. Encryption protects data at rest and in transit. It doesn't protect a machine that's already taken.

## Why libsodium is the backbone

Every security-critical step goes through one library:

| Job | libsodium primitive |
|---|---|
| Passphrase → key | Argon2id |
| Sealing vaults and the identity key | XSalsa20-Poly1305 (`SecretBox`) |
| Identity keypairs | X25519 |
| Key slots and shares | `Box`: X25519 + XSalsa20-Poly1305, with a throwaway sender key |
| Salts and nonces | the operating system's secure random generator |

It's not about libsodium being clever. It's about what it won't let you do.

It has no unauthenticated mode to pick by accident. Comparisons don't leak timing. Nonces come from a source that's actually random. If you combine its primitives the documented way, you get the documented guarantees. I didn't write any cryptography for this fix. I reused two calls the vault already trusted.

LocalVault also refuses to start without libsodium. There's no weaker fallback to slip into when it's missing.

## What to run

These commands arrived in LocalVault 1.16.0. Once you've upgraded:

```bash
localvault keys status     # protected, locked, or legacy?
localvault keys protect    # seal an older key (or change its passphrase)
localvault keys unlock     # open it for this session
localvault lock            # forget everything
```

`localvault doctor` also tells you when your identity key is still in the old format.

The lesson I keep relearning: a security page is a claim, and claims drift. The only proof is the code, read by someone who isn't trying to agree with you. This time that was an agent I asked the obvious question. The answer was uncomfortable, and that was useful.
