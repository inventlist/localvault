# Organizing Secrets in LocalVault

LocalVault supports two ways to organize secrets depending on how complex your setup is.

---

## Flat keys with `--group` (simple projects)

For a single project or personal use, just store secrets as plain keys:

```bash
localvault set DATABASE_URL postgres://localhost/myapp
localvault set REDIS_URL    redis://localhost
localvault set STRIPE_KEY   sk_live_abc123
localvault set STRIPE_SECRET whsec_xyz
```

Run `localvault show --group` and LocalVault automatically groups them by their prefix:

```
Vault: default  (4 secrets)

  STRIPE  (2)
  ╭──────────────────┬────────────╮
  │ STRIPE_KEY       │ ••••• 123  │
  │ STRIPE_SECRET    │ ••••• xyz  │
  ╰──────────────────┴────────────╯

  ungrouped
  ╭──────────────────┬────────────╮
  │ DATABASE_URL     │ ••••• app  │
  │ REDIS_URL        │ ••••• st   │
  ╰──────────────────┴────────────╯
```

`localvault exec -- rails s` injects all keys as-is.

**Best for:** personal machines, single-project vaults.

---

## Dot-notation (team vaults with multiple projects)

For a team vault that holds secrets for several projects, use dot-notation:

```bash
localvault set platepose.SECRET_KEY_BASE  abc123   -v intellectaco
localvault set platepose.RAILS_MASTER_KEY 703d11af -v intellectaco
localvault set platepose.DATABASE_URL     postgres://... -v intellectaco

localvault set inventlist.SECRET_KEY_BASE  xyz789   -v intellectaco
localvault set inventlist.DATABASE_URL     postgres://... -v intellectaco
```

`localvault show -v intellectaco` renders each project as its own group:

```
Vault: intellectaco  (5 secrets)

  platepose  (3)
  ╭──────────────────────┬────────────╮
  │ DATABASE_URL         │ ••••• 2aa  │
  │ RAILS_MASTER_KEY     │ ••••• f42  │
  │ SECRET_KEY_BASE      │ ••••• 123  │
  ╰──────────────────────┴────────────╯

  inventlist  (2)
  ╭──────────────────────┬────────────╮
  │ DATABASE_URL         │ ••••• 1aa  │
  │ SECRET_KEY_BASE      │ ••••• 789  │
  ╰──────────────────────┴────────────╯
```

### Scoped commands

View or inject only one project at a time:

```bash
# Show only platepose secrets
localvault show -v intellectaco --project platepose

# Start platepose app with its secrets (no other project's keys leak in)
localvault exec --project platepose -v intellectaco -- rails s

# Export as shell vars for a specific project
eval $(localvault env --project platepose -v intellectaco)
```

When no `--project` is given and you run `env`/`exec`, nested secrets are
exported with a `GROUP__KEY` prefix to avoid collisions:

```bash
# PLATEPOSE__DATABASE_URL=postgres://...
# INVENTLIST__DATABASE_URL=postgres://...
eval $(localvault env -v intellectaco)
```

### Sharing a team vault

```bash
# Share all projects at once with a team member
localvault share intellectaco --with @bob

# Or share with everyone on a team
localvault share intellectaco --with team:intellectaco
```

The recipient runs `localvault receive` — they get the full vault including
all project groups.

---

## Bulk import

Instead of setting keys one by one, import from an existing file:

```bash
# From a .env file
localvault import .env -v intellectaco --project platepose

# From JSON
localvault import secrets.json -v intellectaco --project platepose

# From YAML
localvault import secrets.yml -v intellectaco --project platepose

# Nested JSON imports structure directly
localvault import all-secrets.json -v intellectaco
```

Supported formats:

**.env** — `KEY=value` lines, comments and blanks ignored:
```
SECRET_KEY_BASE=abc123
DATABASE_URL=postgres://...
# this is ignored
```

**.json** — flat or nested:
```json
{ "SECRET_KEY_BASE": "abc", "DATABASE_URL": "postgres://..." }
```
```json
{ "platepose": { "SECRET_KEY_BASE": "abc" }, "inventlist": { "API_KEY": "xyz" } }
```

**.yml / .yaml**:
```yaml
SECRET_KEY_BASE: abc123
DATABASE_URL: postgres://...
```

---

## Moving secrets around

```bash
# Rename a key
localvault rename OLD_KEY NEW_KEY -v intellectaco

# Copy a key to another vault (great for promoting staging → production)
localvault copy platepose.DATABASE_URL --to production -v intellectaco

# Delete one key
localvault delete platepose.SECRET_KEY_BASE -v intellectaco

# Delete an entire project group
localvault delete platepose -v intellectaco
```

---

## Switching vaults

```bash
localvault switch              # show current vault + all available
localvault switch intellectaco # make intellectaco the default
localvault switch default      # switch back
```

---

## Quick reference

| Goal | Command |
|------|---------|
| Simple key | `localvault set KEY value` |
| Nested key | `localvault set project.KEY value -v vault` |
| Import from file | `localvault import file.env -v vault --project app` |
| Rename key | `localvault rename OLD NEW` |
| Copy to vault | `localvault copy KEY --to other-vault` |
| Delete group | `localvault delete project -v vault` |
| View all grouped | `localvault show --group` |
| View one project | `localvault show -p platepose -v vault` |
| Inject all (flat) | `localvault exec -- cmd` |
| Inject one project | `localvault exec -p platepose -v vault -- cmd` |
| Export one project | `eval $(localvault env -p platepose -v vault)` |
| Switch vault | `localvault switch intellectaco` |
