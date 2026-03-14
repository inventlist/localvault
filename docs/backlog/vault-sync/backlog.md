# Vault Sync Backlog

Zero-knowledge vault sync across devices via InventList. PGP-style per-user encryption.
Public keys on InventList profiles act as a key directory — no passphrase sharing ever needed.

---

## Phase 1 — Identity (keypair + profile)

### VS-001: localvault keygen command
**Scope:** CLI (localvault)
**Context:** Generate a Curve25519 keypair. Private key stored in Keychain (macOS) or ~/.localvault/.keys/ (Linux, mode 0600). Public key stored in ~/.localvault/config alongside the InventList API token.
**Acceptance:**
- `localvault keygen` generates keypair and stores both
- Running again warns "keypair already exists, use --force to regenerate"
- `localvault keygen --show` prints the public key
- Private key never printed or logged
**Constraints:**
- Use rbnacl Box keypair (Curve25519) — already a dependency
- If keypair exists and --force not given, abort with clear message
**Verify:** `localvault keygen` then `localvault keygen --show` prints a base64 public key

---

### VS-002: localvault login command
**Scope:** CLI (localvault)
**Context:** Authenticate against InventList API. Stores token in ~/.localvault/config. After login, publish public key to InventList profile automatically.
**Acceptance:**
- `localvault login <token>` stores token and publishes public key to InventList
- `localvault login --show` prints current token (masked)
- `localvault logout` removes token from config
- Login fails gracefully if token is invalid (401 from API)
- Login fails gracefully if no keypair exists (prompt to run keygen first)
**Constraints:**
- Token stored in config file, not Keychain (it's an API credential, not a secret)
- HTTPS only for all API calls
**Verify:** `localvault login <token>` then check inventlist.com/@handle shows LocalVault badge

---

### VS-003: InventList API — publish public key endpoint
**Scope:** InventList Rails (inventlist.com)
**Context:** CLI needs to publish its public key to the user's profile. New API endpoint accepts the public key and stores it on the user record. Public key already has a field (vault_public_key or public_key).
**Acceptance:**
- `PUT /api/v1/profile/public_key` with `{ public_key: "..." }` updates user's public key
- Returns 200 on success, 422 on invalid key format
- Requires Bearer token auth
- `GET /api/v1/profile` returns current user info including public key
**Constraints:**
- Validate public key is valid base64 (32 bytes decoded = Curve25519 public key)
- Existing public key is overwritten (each device regeneration updates it)
**Verify:** After `localvault login`, GET /api/v1/profile returns the public key

---

## Phase 2 — Sync (single user, two devices)

### VS-004: InventList infrastructure — R2 bucket + VaultSync model
**Scope:** InventList Rails + Cloudflare R2
**Context:** New dedicated R2 bucket (localvault-sync). Rails model tracks metadata. R2 stores encrypted blobs.
**Acceptance:**
- New R2 bucket created: `localvault-sync`
- R2 credentials in Rails credentials: `r2_vault_sync.access_key_id / secret_access_key / endpoint`
- `VaultSync` model: user_id, name (vault name), checksum (sha256), size_bytes, synced_at, r2_key
- `VaultSync` validates: name format (alphanumeric + dash/underscore), size_bytes <= 5MB
**Constraints:**
- R2 key pattern: `<user_id>/<vault_name>.vault`
- One VaultSync record per user+name combination (upsert on push)
**Verify:** Can create VaultSync record and upload/download blob from R2 in console

---

### VS-005: InventList API — vault push/pull endpoints
**Scope:** InventList Rails
**Context:** CLI proxies all R2 access through Rails. Two endpoints: upload (PUT) and download (GET).
**Acceptance:**
- `PUT /api/v1/vaults/:name` — accepts raw encrypted blob (binary), upserts VaultSync record + uploads to R2
- `GET /api/v1/vaults/:name` — downloads blob from R2, streams to client
- `GET /api/v1/vaults` — list all synced vaults for user (name, checksum, synced_at, size_bytes)
- `DELETE /api/v1/vaults/:name` — removes from R2 + deletes VaultSync record
- All require Bearer token auth
- Returns 404 if vault not found on pull
**Constraints:**
- Max blob size: 5MB (encrypted vault files are tiny, this is generous)
- Checksum (sha256) computed server-side and stored for sync status comparison
**Verify:** curl PUT then GET returns identical bytes

---

### VS-006: localvault sync push command
**Scope:** CLI (localvault)
**Context:** Encrypt vault master key with user's own public key (key slot), attach to vault blob, upload to InventList API.
**Acceptance:**
- `localvault sync push` pushes default vault
- `localvault sync push -v <name>` pushes named vault
- Requires active session (prompts to unlock if not)
- Requires login (prompts if no token)
- Shows progress: "Pushing vault 'intellectaco'... done (2.3 KB)"
- Warns if remote is newer than local (checksum mismatch): "Remote is newer. Use --force to overwrite."
**Constraints:**
- The vault file is already encrypted — push as-is (no re-encryption needed for sync)
- Key slots stored as a separate header prepended to the blob (see VS-011 for team slots)
**Verify:** `localvault sync push` then verify file exists in R2 bucket

---

### VS-007: localvault sync pull command
**Scope:** CLI (localvault)
**Context:** Download encrypted blob from InventList, write to ~/.localvault/vaults/<name>.vault. User then unlocks normally with their passphrase.
**Acceptance:**
- `localvault sync pull` pulls default vault
- `localvault sync pull -v <name>` pulls named vault
- Warns if local is newer than remote (checksum mismatch): "Local is newer. Use --force to overwrite."
- Creates vault file if it doesn't exist locally
- Shows: "Pulling vault 'intellectaco'... done. Run: localvault show to unlock."
**Constraints:**
- Does NOT prompt for passphrase — user unlocks separately
- Does NOT overwrite local without warning if local is newer
**Verify:** Pull on second Mac, then `localvault show` works with correct passphrase

---

### VS-008: localvault sync status command
**Scope:** CLI (localvault)
**Context:** Compare local vault checksums against remote. Show which vaults are in sync, ahead, behind, or not yet synced.
**Acceptance:**
- `localvault sync status` shows all vaults with sync state
- States: `synced`, `ahead` (local newer), `behind` (remote newer), `local-only`, `remote-only`
- Shows last synced time
**Constraints:**
- Checksum computed from local vault file (sha256)
- Does not push or pull — status only
**Verify:** Push from Mac 1, check status on Mac 2 shows "behind"

---

## Phase 3 — Teams (shared vault access)

### VS-009: localvault team add command
**Scope:** CLI (localvault)
**Context:** Add a teammate's public key as an authorized reader of a vault. Looks up their public key from InventList profile by @handle. Encrypts vault master key with their public key, adds as a new key slot.
**Acceptance:**
- `localvault team add @handle -v <vault>` adds teammate
- Fetches @handle's public key from `GET /api/v1/users/@handle/public_key`
- Fails gracefully if @handle has no public key ("@handle has no LocalVault key published")
- Re-encrypts vault with updated key slots, pushes to R2
- Shows: "Added @handle to vault 'intellectaco'"
**Constraints:**
- Requires vault to be unlocked (needs master key to create new key slot)
- Only vault owner / existing authorized members can add others
**Verify:** `localvault team add @teammate -v shared` then teammate can `localvault sync pull -v shared`

---

### VS-010: InventList API — public key lookup by handle
**Scope:** InventList Rails
**Context:** CLI needs to look up another user's public key to add them to a vault.
**Acceptance:**
- `GET /api/v1/users/@handle/public_key` returns `{ handle: "...", public_key: "..." }`
- Returns 404 if user not found or has no public key
- Requires Bearer token auth (authenticated users only — not public)
**Constraints:**
- Only return public_key field — no other user data
**Verify:** curl with valid handle returns public key; invalid handle returns 404

---

### VS-011: localvault team remove command
**Scope:** CLI (localvault)
**Context:** Remove a teammate's key slot from the vault. They can no longer pull new versions. Optionally rotate the vault master key to revoke access to existing data.
**Acceptance:**
- `localvault team remove @handle -v <vault>` removes their key slot
- `--rotate` flag re-encrypts vault with a new master key (full revocation)
- Without --rotate: they can no longer pull new versions but still have their local copy
- Shows list of current authorized users: `localvault team list -v <vault>`
**Constraints:**
- Cannot remove yourself if you are the only authorized user
- --rotate requires vault to be unlocked and re-prompts passphrase to confirm
**Verify:** After remove, `localvault sync pull -v shared` fails for removed user

---

## Deferred

- Auto-sync after every write (nice-to-have, v2)
- Conflict merge (last-write-wins is fine for v1)
- Audit log of who accessed what (v2)
- Web UI on InventList to manage vault access (v2)
