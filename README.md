# LocalVault

Encrypted local secrets vault with MCP server for AI agents. Zero infrastructure, zero cloud dependency.

> **[Try the interactive demo](https://inventlist.com/tools/localvault/cli)** — explore every command in your browser.

Part of [InventList Tools](https://inventlist.com/tools/localvault) — free, open-source developer utilities for indie builders.

---

## Install

### Homebrew (macOS / Linux)

```bash
brew install inventlist/tap/localvault
```

### Install script (no Homebrew)

```bash
curl -sSL https://raw.githubusercontent.com/inventlist/localvault/main/install.sh | sh
```

Installs into an isolated prefix (`~/.localvault/runtime`) and writes a wrapper
to your PATH that pins its own Ruby. It never adds a version-manager shim and
never touches your project gems, so `localvault` keeps working when you switch
Ruby versions. Override with `LOCALVAULT_BIN_DIR`, `LOCALVAULT_PREFIX`,
`LOCALVAULT_VERSION`, or `LOCALVAULT_RUBY`.

### RubyGems

```bash
gem install localvault
```

A plain `gem install` under asdf/rbenv creates a shim that can shadow your
Homebrew build and silently pin you to an old version. If `localvault version`
disagrees with what you installed, run `localvault doctor` — it lists every
copy on your PATH.

**Requires libsodium:**

```bash
# macOS
brew install libsodium

# Ubuntu/Debian
sudo apt-get install libsodium-dev

# Fedora
sudo dnf install libsodium-devel
```

## Quick Start

```bash
# Create a vault (prompts for passphrase)
localvault init

# Store secrets without putting values in shell history / process args
printf '%s' "$OPENAI_API_KEY" | localvault set OPENAI_API_KEY --stdin
printf '%s' "$STRIPE_SECRET_KEY" | localvault set STRIPE_SECRET_KEY --stdin
printf '%s' "$DATABASE_URL" | localvault set DATABASE_URL --stdin

# Retrieve a secret (raw, pipeable)
localvault get OPENAI_API_KEY

# View all secrets (masked by default)
localvault show

# Reveal values
localvault show --reveal

# Export as shell variables
eval $(localvault env)

# Run a command with secrets injected
localvault exec -- rails server
```

## Commands

### Secrets

| Command | Description |
|---------|-------------|
| `init [NAME]` | Create a vault (Argon2id key derivation) |
| `set KEY --stdin` | Store a secret from stdin without argv/history exposure |
| `set KEY [VALUE]` | Store a secret (positional value kept for compatibility) |
| `set --group GROUP KEY --stdin` | Store a secret in a named group from stdin |
| `get KEY` | Retrieve a secret (raw, pipeable) |
| `show` | Display all secrets in a table (masked by default) |
| `show --reveal` | Display with values visible |
| `show --group` | Group by dot-notation prefix (one table per project) |
| `show --group QUERY` | Show one exact or uniquely matching group |
| `groups [QUERY]` | List/search group names and key counts without values |
| `list` | List key names only |
| `delete KEY` | Remove a secret |
| `rename OLD NEW` | Rename a secret key |
| `copy KEY --to VAULT` | Copy a secret to another vault |
| `import FILE` | Bulk-import from .env / .json / .yml |
| `env` | Export as `export KEY="value"` lines |
| `exec -- CMD` | Run a command with secrets injected as env vars |

### Vault Management

| Command | Description |
|---------|-------------|
| `vaults` | List all vaults with secret counts |
| `switch [VAULT]` | Switch default vault |
| `unlock` | Cache passphrase for the session |
| `lock [NAME]` | Clear cached passphrase |
| `rekey [NAME]` | Change vault passphrase (re-encrypts all secrets) |
| `reset [NAME]` | Destroy and reinitialize a vault |

### Sync & Login

| Command | Description |
|---------|-------------|
| `login [TOKEN]` | Log in to InventList — auto-generates X25519 keypair + publishes public key |
| `login --status` | Show current login status |
| `logout` | Clear stored credentials |
| `sync` | Sync all vaults bidirectionally (push local, pull remote, detect conflicts) |
| `sync --dry-run` | Preview what sync would do without making changes |
| `sync push [NAME]` | Push one vault to cloud |
| `sync pull [NAME]` | Pull one vault from cloud (auto-unlocks if you have a key slot) |
| `sync status` | Show sync state for all vaults |

### Team Sharing (v1.3.0)

Vault-level operations live under `team`. Person operations (the `@handle`
already signals a person) are top-level.

| Command | Description |
|---------|-------------|
| `team init` | Convert vault to team vault (sets you as owner, SyncBundle v3) |
| `team list` | List vault members |
| `team rotate` | Re-key vault with new passphrase, keep all members |
| `verify @handle` | Check if a user has a published public key (dry-run) |
| `add @handle` | Add teammate with full vault access |
| `add @handle --scope KEY...` | Add teammate with access to specific keys only |
| `remove @handle` | Remove teammate's access |
| `remove @handle --scope KEY` | Remove one scoped key (keeps other scopes) |
| `remove @handle --rotate` | Full revocation + re-encrypt with new passphrase |

The `team add`, `team remove`, and `team verify` aliases still work for
backward compatibility but the top-level forms are preferred.

### Keys

| Command | Description |
|---------|-------------|
| `keys generate` | Generate X25519 identity keypair |
| `keys show` | Display your public key |
| `keys publish` | Upload public key to InventList (required before others can add you) |

### AI / MCP

| Command | Description |
|---------|-------------|
| `install-mcp [CLIENT]` | Configure MCP server in claude-code, cursor, or windsurf |
| `mcp` | Start MCP server (stdio transport) |
| `doctor` | Check install and PATH readiness, including brew/asdf shadowing |
| `guard install` | Install Claude Code hooks that block secrets in agent commands (v1.9.0) |
| `guard status` | Show guard hook installation state |
| `guard hook` | Hook entrypoint (reads hook JSON on stdin; not run by hand) |

All commands accept `--vault NAME` (or `-v NAME`) to target a specific vault. Default vault is `default`.

## Personal Sync

Sync your vaults between machines — same passphrase, no team features needed:

```bash
# Machine A: push all your vaults at once
localvault sync

# Machine B: install, login, sync
brew install inventlist/tap/localvault
localvault login YOUR_TOKEN
localvault sync                # pulls everything, pushes local-only vaults
localvault show                # enter your passphrase — same secrets
```

Or push/pull individual vaults:

```bash
localvault sync push production    # push one vault
localvault sync pull production    # pull one vault
localvault sync status             # check what's synced vs local-only
```

Preview before syncing:

```bash
localvault sync --dry-run
#   Vault         Action    Reason
#   default       skip      up to date
#   production    push      local changes
#   staging       pull      remote changes
```

## Team Sharing

Share vault access with teammates using X25519 asymmetric encryption. The server never sees plaintext.

```bash
# 1. Convert to team vault (required first)
localvault team init -v production

# 2. Verify teammate has a published key
localvault verify @alice

# 3. Add with full access
localvault add @alice -v production

# 4. Or scoped — they only see specific keys
localvault add @bob -v production --scope STRIPE_KEY WEBHOOK_SECRET

# 5. When Alice pulls, auto-unlocks via her identity key
# (on Alice's machine)
localvault sync pull production
# => Unlocked via your identity key.

# 6. Scoped members can't push
# (on Bob's machine)
localvault sync push production
# => Error: You have scoped access. Only the owner can push.

# 7. Rotate without removing anyone
localvault team rotate -v production

# 8. Full revocation + re-key
localvault remove @alice -v production --rotate
```

**Prerequisites:** Teammates must have a published public key. `localvault login` does this automatically, or: `localvault keys generate && localvault keys publish`.

## MCP Server (AI Agents)

Give AI agents controlled secret access without hardcoding credentials in MCP
config. The default workflow keeps values out of model context: discover names,
build a `localvault exec` command, then run it with process-scoped injection.

```bash
# One-command install for Claude Code
localvault install-mcp claude-code
# Also supports: cursor, windsurf

# Unlock your vault for the session
localvault unlock

# Verify setup without starting the blocking stdio server
localvault mcp --check

# Diagnose brew/asdf PATH shadowing after upgrades
localvault doctor

# MCP tools available to the agent:
#   localvault_whoami             — diagnose active vault/session state
#   list_secrets(vault?, prefix?, query?) — list/search key names
#   localvault_build_exec(command, ...) — build safe injection (does not execute)
#   get_secret(key, allow_plaintext: true, vault?) — explicit plaintext reveal
#   set_secret(key, value, vault?) — store a secret
#   delete_secret(key, vault?)    — remove a secret
```

Agents should prefer `localvault_build_exec` for commands, evaluation, API calls,
and configuration checks. It returns both argv and a shell-safe command without
opening a vault or reading a value. `get_secret` rejects calls unless
`allow_plaintext: true` is explicit.

Use selectors, mappings, and profiles to keep subprocess envs scoped:

```bash
localvault exec --profile aws -- aws sts get-caller-identity
localvault exec --only AWS_IAM.*,AWS_SES.* --except AWS_SES.smtp_password -- your-script
localvault env --map AWS_IAM.access_key_id=AWS_ACCESS_KEY_ID
```

## Multi-Project Vaults

One vault, many projects. Dot-notation keeps secrets organized:

```bash
# Store with project prefix
localvault set myapp.DATABASE_URL postgres://localhost/myapp -v work
localvault set api.DATABASE_URL postgres://localhost/api -v work

# Or use the guided group form
localvault set --group myapp DATABASE_URL postgres://localhost/myapp -v work

# Search groups without revealing values
localvault groups app -v work

# View grouped by project
localvault show --group -v work

# Show one group by exact or unique prefix
localvault show --group my -v work

# Filter to one project
localvault show -p myapp -v work

# Export one project
eval $(localvault env -p myapp -v work)

# Export all projects with project.key transformed to PROJECT__key
localvault env -v work
# → MYAPP__DATABASE_URL, API__DATABASE_URL

# Bulk import
localvault import .env --prefix myapp -v work
```

## Session Caching

Avoid typing your passphrase repeatedly:

```bash
eval $(localvault unlock)

# All subsequent commands skip the passphrase prompt
localvault get API_KEY
localvault exec -- rails server
```

Unlocking writes a derived key to `LOCALVAULT_SESSION` and also caches it with an 8-hour TTL in Keychain or LocalVault's file fallback so MCP and new terminals can reuse it until `localvault lock`.

## Security

### Agent Plaintext Containment (v1.9.0)

Two layers keep secrets out of AI agent context and transcripts:

**1. Plaintext refuses captured streams.** `get`, `env`, and `show --reveal`
print values to an interactive terminal as always. When stdout is captured
(a pipe or an agent's shell), a human confirms with one keypress on `/dev/tty`;
an agent's shell has no `/dev/tty`, so it is refused and pointed at injection:

```bash
localvault get STRIPE_KEY              # human at a terminal: prints
localvault get STRIPE_KEY | pbcopy     # human piping: "Print plaintext? [y/N]"
# agent shell: refused → use localvault exec --map STRIPE_KEY=STRIPE_KEY -- CMD
```

There is deliberately no flag or environment variable to bypass this — the only
override is a keypress on a real terminal. Headless automation uses
`localvault exec` injection.

**2. Guard hooks block secrets in agent commands.** `localvault guard install`
wires Claude Code hooks that scan every Bash tool call against your unlocked
vaults. A command containing a stored secret value is blocked before it runs,
naming the key by fingerprint — never by value:

```text
LocalVault guard: blocked — this tool input contains the plaintext value of
default/STRIPE.private_key (sha256:1a2b3c4d5e6f). Inject it instead:
  localvault exec --map STRIPE.private_key=PRIVATE_KEY -- your-command
```

The installed hook fails open: locked vaults, an old binary, or a missing
install allow the call rather than breaking your session.

### Crypto Stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key derivation | **Argon2id** (64 MB, 3 iterations) | Passphrase → master key |
| Encryption | **XSalsa20-Poly1305** | Authenticated encryption |
| Key exchange | **X25519** | Team key slots + vault sharing |

- Random 24-byte nonce per encryption
- Poly1305 authentication prevents tampering
- Argon2id is memory-hard (GPU/ASIC resistant)
- All crypto via [libsodium](https://doc.libsodium.org/) (RbNaCl bindings)
- SyncBundle v3 for team vaults (owner field + per-member key slots)

### Storage Layout

```
~/.localvault/
├── config.yml              # Default vault, server URL, token
├── identity.key            # X25519 private key (encrypted at rest)
├── identity.pub            # X25519 public key (safe to share)
├── vaults/
│   ├── default/
│   │   ├── meta.yml        # Salt, creation date, version
│   │   └── secrets.enc     # Encrypted JSON blob
│   └── production/
│       ├── meta.yml
│       └── secrets.enc
```

## Server Independence

LocalVault is server-agnostic. It ships configured for `inventlist.com` but works with any host that implements the protocol (4 endpoints):

```bash
# Use a different server
localvault config set server https://vaulthost.example

# Or override per-login
localvault login --server https://vaulthost.example
```

## Development

```bash
git clone https://github.com/inventlist/localvault.git
cd localvault
bundle install
bundle exec rake test
```

## Used by

Powers credentials management at [InventList](https://inventlist.com) — where indie builders ship, share, and get discovered.

## License

Apache 2.0 — see [LICENSE](LICENSE).
Built by the [InventList](https://inventlist.com) team.
