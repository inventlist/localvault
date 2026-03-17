# LocalVault Security Hardening & Refactor — 2026-03-16

**Status:** Complete (uncommitted)
**Version:** 0.9.9 → pending bump
**Suite:** 319 tests, 607 assertions, 0 failures

---

## Context

Full security audit of the LocalVault gem (16 source files, ~2200 LOC). Three audit rounds with verified reproduction of every finding before fix. All changes follow TDD — failing tests written and confirmed red before implementation.

## Round 1 — Critical/High Findings (7 items)

### R1-1 (Critical): Path traversal via vault names
**File:** `store.rb`
**Vuln:** `Store.new("../../../tmp/owned").vault_path` resolved outside `~/.localvault/vaults/`.
**Fix:** `Store::InvalidVaultName` exception. Regex `[a-zA-Z0-9][a-zA-Z0-9_-]*`, max 64 chars. Validated in constructor.
**Test:** `test/security_test.rb` — 9 tests (traversal, slashes, dots, empty, nil, spaces, leading dash, valid names, path containment).

### R1-2 (High): Shell injection via secret key names in export_env
**File:** `vault.rb:77-86`
**Vuln:** `vault.set("$(touch /tmp/pwned)", "x")` then `eval $(localvault env)` executes the command.
**Fix:** `Vault::InvalidKeyName` on `set`. Regex `[A-Za-z_][A-Za-z0-9_]*` per segment. Dot-notation: both group and subkey validated.
**Test:** `test/security_test.rb` — 7 tests (metacharacters, semicolons, spaces, empty, dotted edge cases, valid keys, shell safety of output).

### R1-3 (High): Nested vault corruption on team share receive
**File:** `cli.rb:638`
**Vuln:** `secrets.each { |k, v| vault.set(k, v.to_s) }` stringified nested hashes: `{"DB" => "pg"}` became `'{"DB"=>"pg"}'`.
**Fix:** New `Vault#merge(hash)` — single decrypt/encrypt cycle, preserves nested structure. Used in `receive`, `import`, `demo`.
**Test:** `test/security_test.rb` — 3 tests (nested preservation, no stringification, single encrypt cycle).

### R1-4 (Medium): macOS Keychain `-A` flag + silent failures
**File:** `session_cache.rb:74-84`
**Vuln:** `-A` grants all apps access. Keychain failure silently ignored.
**Fix:** Removed `-A`. Added file fallback when Keychain fails. Unified get/delete to check both backends. Tests went from 3 failures to 0.

### R1-5 (Medium): Config file written 0644
**File:** `config.rb:31`
**Vuln:** API bearer token readable by other local users.
**Fix:** `File.chmod(0o600, config_path)` after write. `ensure_directories!` uses `mode: 0o700`.
**Test:** `test/security_test.rb` — 1 test.

### R1-6 (Medium): Malformed share/sync payloads crash CLI
**File:** `share_crypto.rb:33`, `sync_bundle.rb:23`
**Vuln:** `ArgumentError` from invalid base64 escapes unhandled.
**Fix:** `ShareCrypto` catches `ArgumentError` → `DecryptionError`. `SyncBundle::UnpackError` wraps JSON, KeyError, ArgumentError.
**Test:** `test/security_test.rb` — 5 tests.

### R1-7 (Low): O(n²) bulk operations
**File:** `cli.rb:421,638,705`
**Vuln:** `import`, `receive`, `demo` called `vault.set` per key — each call decrypts + re-encrypts the full blob.
**Fix:** `Vault#merge` does one decrypt/encrypt cycle for any number of keys.

---

## Round 2 — Remaining Findings (5 items from user verification)

### R2-1 (High): Legacy/synced blobs bypass key validation on output
**File:** `vault.rb:78,98`
**Vuln:** `export_env`/`env_hash` trust decrypted JSON keys blindly. A crafted persistent payload like `{"BAD;KEY":"evil"}` produces `export BAD;KEY=evil`. `sync pull` restores remote blobs directly.
**Fix:** `shell_safe_key?` private method filters keys at output time. Unsafe keys silently skipped in `export_env` and `env_hash`.
**Test:** `test/audit_round2_test.rb` — 3 tests (flat, nested, env_hash).

### R2-2 (High): sync pull --force leaves old secrets.enc when remote is empty
**File:** `cli/sync.rb:47`
**Vuln:** `store.write_encrypted(data[:secrets]) unless data[:secrets].empty?` — the `unless` skips the write, leaving old `secrets.enc` on disk. A forced pull of an emptied remote vault still has the old secrets.
**Fix:** When `data[:secrets].empty?`, explicitly `FileUtils.rm_f(store.secrets_path)`.
**Test:** `test/audit_round2_test.rb` — 1 test.

### R2-3 (Medium): Vault storage permissions too loose
**File:** `store.rb:39,47,69,78,99`
**Vuln:** Default umask → vault dir 0755, meta.yml 0644, secrets.enc 0644. Exposes salt, ciphertext, and vault inventory.
**Fix:** All `mkdir_p` calls use `mode: 0o700`. New `write_meta` private helper with `chmod 0o600`. `write_encrypted` adds `chmod 0o600` after rename. `cli/sync.rb` pull path also hardened.
**Test:** `test/audit_round2_test.rb` — 5 tests (create dir, create meta, update_count, create_meta!, write_encrypted).

### R2-4 (Medium): MCP server crash on invalid set_secret
**File:** `mcp/tools.rb:94`
**Vuln:** `Vault::InvalidKeyName` propagates unrescued through `Tools.call` → `handle_message`. No JSON-RPC error returned; server process crashes.
**Fix:** `Tools.set_secret` rescues `InvalidKeyName` → `error_result("Invalid key name: ...")`.
**Test:** `test/audit_round2_test.rb` — 2 tests (invalid key error, valid key still works).

### R2-5 (Low): No HTTP timeouts
**File:** `api_client.rb:121,151,174`
**Vuln:** `Net::HTTP` defaults (60s). Slow/hung server blocks CLI indefinitely.
**Fix:** `open_timeout = 10`, `read_timeout = 30` on all three request methods.

---

## Additional Fixes (from audit notes)

### API path injection
**File:** `api_client.rb:30,61,66,70,75`
**Vuln:** `get_public_key(handle)`, `team_public_keys`, `crew_public_keys`, `accept_share(id)`, `revoke_share(id)` interpolated params raw into URL paths. A handle like `../admin` → path traversal.
**Fix:** `URI.encode_uri_component` on all 5 endpoints. Vault name endpoints (push/pull/delete) already had this.

### Dead code in Crypto.generate_keypair
**File:** `crypto.rb:46`
**Removed:** Unused `RbNaCl::GroupElements::Curve25519.base.mult(...)` line.

### create_meta! local variable shadow
**File:** `store.rb:92-99`
**Bug:** `meta = { "created_at" => meta&.dig("created_at") ... }` — right-hand `meta` was the method, not the local. Works by accident.
**Fix:** Renamed to `existing = meta; new_meta = { ... }`. Extracted `write_meta` helper.

### SyncBundle version validation
**File:** `sync_bundle.rb:24`
**Gap:** `unpack` never checked bundle version.
**Fix:** Raises `UnpackError` if version is present and != 1.

### Unused `require "digest"`
**File:** `sync_bundle.rb:3`
**Removed.**

### Vault#get returns Hash for group names
**File:** `vault.rb:25`
**Bug:** `vault.get("myapp")` when `myapp` is a nested group returned the raw Hash.
**Fix:** Returns `nil` for Hash values (groups are accessed via dot-notation only).

### Duplicate vault-opening logic
**File:** `cli.rb:1034-1068`
**Smell:** `open_vault!` was a 34-line copy of `open_vault_by_name!`.
**Fix:** `open_vault!` now delegates: `open_vault_by_name!(resolve_vault_name)`.

### Identity pub key explicit permissions
**File:** `identity.rb:21`
**Fix:** Added `File.chmod(0o644, pub_key_path)` for consistency (explicit, not umask-dependent).

### receive accept_share error handling
**File:** `cli.rb:641`
**Bug:** `client.accept_share(share["id"]) rescue nil` — silent failure.
**Fix:** Explicit `rescue ApiClient::ApiError` with warning to stderr.

---

## Files Changed (12 files)

| File | Changes |
|------|---------|
| `lib/localvault/store.rb` | +40 — vault name validation, write_meta helper, 0700/0600 permissions |
| `lib/localvault/vault.rb` | +78 — key validation, merge, shell_safe_key?, get returns nil for groups |
| `lib/localvault/cli.rb` | +68/-84 — merge in receive/import/demo, open_vault! delegates, accept_share error handling |
| `lib/localvault/cli/sync.rb` | +9/-2 — pull clears empty secrets, permissions on pulled files |
| `lib/localvault/api_client.rb` | +16/-3 — URI encoding on 5 endpoints, timeouts on 3 methods |
| `lib/localvault/config.rb` | +7/-2 — chmod 0600 on config, 0700 on directories |
| `lib/localvault/session_cache.rb` | +21/-8 — removed -A, file fallback, unified cleanup |
| `lib/localvault/share_crypto.rb` | +2 — catch ArgumentError |
| `lib/localvault/sync_bundle.rb` | +11/-1 — UnpackError, version validation, removed unused digest |
| `lib/localvault/mcp/tools.rb` | +2 — rescue InvalidKeyName in set_secret |
| `lib/localvault/crypto.rb` | -2 — removed dead code |
| `lib/localvault/identity.rb` | +1 — explicit pub key chmod |

## New Test Files (2 files, 50 tests)

| File | Tests | Coverage |
|------|-------|----------|
| `test/security_test.rb` | 27 | Round 1: path traversal, key validation, merge, permissions, malformed payloads |
| `test/audit_round2_test.rb` | 23 | Round 2+3: output sanitization, sync pull empty, store perms, MCP crash, API encoding, bundle version, roundtrip |

## Not Fixed (deferred)

| Item | Reason |
|------|--------|
| CLI god object (1179 lines) | Large refactor, low risk — extracted what could be done (open_vault! dedup) |
| abort_with doesn't exit | Intentional for testability |
| Config re-reads YAML per accessor | Fine for CLI; MCP server impact is negligible |
| No file locking for concurrent writes | Needs design (flock vs lockfile); low real-world risk for single-user CLI |
| No `localvault destroy` command | Feature request, not a bug |
| Vault#all not cached | Needs careful invalidation design; current perf is acceptable |
