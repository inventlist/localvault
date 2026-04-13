# v1.7.0 — Key-Level Merge for Bidirectional Sync

## Problem

v1.6.0's checksum-based sync detects conflicts but can't resolve them.
If you add `NEW_KEY=foo` locally and someone adds `OTHER_KEY=bar`
remotely, those are non-conflicting changes — but v1.6.0 flags it as
CONFLICT and forces you to pick a side, losing one set of changes.

## Solution: 3-way key-level merge

When both local and remote have changed since the baseline:

1. Decrypt local secrets → `local_hash`
2. Decrypt remote secrets → `remote_hash` (pull blob, decrypt with master key or key slot)
3. Load baseline → `baseline_hash` (store the plaintext hash at sync time, encrypted with the master key, in `.sync_baseline`)
4. 3-way diff:
   - Keys added locally (in local, not in baseline) → keep
   - Keys added remotely (in remote, not in baseline) → keep
   - Keys deleted locally → delete (unless remote also changed the value)
   - Keys deleted remotely → delete (unless local also changed the value)
   - Keys changed on one side only → take that side's value
   - Keys changed on BOTH sides to DIFFERENT values → **true conflict** — prompt user
   - Keys changed on both sides to the SAME value → no conflict (convergent edit)
5. Merge result → re-encrypt → push merged bundle
6. Update local secrets.enc + .sync_state + .sync_baseline

## Baseline storage

New file: `~/.localvault/vaults/<name>/.sync_baseline`
- Encrypted with the vault's master key
- Contains the JSON plaintext secrets hash as it was at last successful sync
- Written by `sync push`, `sync pull`, and `sync all` on success
- Read only during the 3-way merge (conflict resolution)

## Conflict UX

For true conflicts (same key, different values):

```
CONFLICT in vault 'production':
  DATABASE_URL:
    local:  postgres://new-local-host/prod
    remote: postgres://new-remote-host/prod

  Keep [l]ocal, [r]emote, or [s]kip this vault? 
```

Per-key resolution for small numbers of conflicts. If > 5 conflicts,
offer "keep all local" / "keep all remote" shortcuts.

## Stories

- [ ] SYNC-MERGE-001: Store encrypted baseline on every successful sync
- [ ] SYNC-MERGE-002: 3-way diff engine (operate on plain Hash, no crypto)
- [ ] SYNC-MERGE-003: Wire merge into `localvault sync` conflict path
- [ ] SYNC-MERGE-004: Per-key conflict prompt UX
- [ ] SYNC-MERGE-005: Handle group (nested hash) merges (dot-notation keys)
- [ ] SYNC-MERGE-006: Tests — 15+ cases covering additions, deletions,
      edits, convergent edits, true conflicts, group merges

## Dependencies

- v1.6.0 sync infrastructure (SyncState, perform_push/pull, classify_vault)
- Vault must be unlockable to decrypt both sides
