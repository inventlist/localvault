# Session: Vault Sync — Phase 1 (Identity)
**Date:** 2026-03-15
**Feature:** vault-sync
**Phase:** 1 — Identity (keypair + login)

## Context

Building zero-knowledge vault sync via InventList. Encrypted blobs stored on Cloudflare R2.
PGP-style per-user key slots — InventList never has the passphrase or master key.

Full design: `docs/content/series/localvault/05-designing-sync.md`
Backlog: `docs/backlog/vault-sync/backlog.md`

## What already existed (no need to build)

- `Identity` module — `generate!`, `public_key`, `private_key_bytes` (Curve25519 keypair, file store)
- `Crypto.generate_keypair` — RbNaCl Box keypair
- `ShareCrypto` — `encrypt_for` / `decrypt_from` (ephemeral Box encryption for sharing)
- `Config` — `token`, `inventlist_handle`, `api_url`
- `ApiClient` — `publish_public_key`, `get_public_key`
- InventList: `PUT /api/v1/profile/public_key` — `PublicKeysController#update` ✓
- InventList: `GET /api/v1/users/:handle/public_key` — `PublicKeysController#show` ✓
- InventList: `GET /api/v1/me` — `MeController#show` ✓
- `connect` command — stores token + handle (legacy, replaced by `login`)

## What was built this session

### VS-001: `localvault keygen` command
- Wraps `Identity.generate!`
- `--force` flag to regenerate
- `--show` flag to print public key
- Prints public key after generation for easy copy

### VS-002: `localvault login TOKEN` command
- Calls `GET /api/v1/me` to validate token + fetch handle (no need to pass handle manually)
- Stores token + handle in `Config`
- Calls `Identity.generate!` if no keypair exists (auto-keygen on first login)
- Calls `ApiClient#publish_public_key` to publish to InventList profile
- `localvault logout` — clears token + handle from config
- `localvault login --status` — shows current login state

### VS-003: InventList API (already done)
- No code changes needed — endpoints and routes already existed

## Tests

- `test/cli_test.rb` — `test_keygen_*`, `test_login_*`
- Updated `test/identity_test.rb` — already had good coverage

## Files changed

**LocalVault:**
- `lib/localvault/cli.rb` — added `keygen`, `login`, `logout` commands
- `lib/localvault/api_client.rb` — added `me` method

## Status

- [x] VS-001: keygen
- [x] VS-002: login
- [x] VS-003: InventList API (pre-existing)
- [ ] VS-004: R2 bucket + VaultSync model (Phase 2)
- [ ] VS-005: push/pull API endpoints (Phase 2)
- [ ] VS-006: sync push CLI (Phase 2)
- [ ] VS-007: sync pull CLI (Phase 2)
- [ ] VS-008: sync status CLI (Phase 2)
