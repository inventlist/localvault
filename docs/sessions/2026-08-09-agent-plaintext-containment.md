# 2026-08-09 · Agent Plaintext Containment (1.9.0 / 1.9.1)

Release digest. Nodepad capture was unavailable (connector internal error), so
this file carries the trace.

## What shipped

**Layer 1 — TTY gate.** `get`, `env`, and `show --reveal` refuse to print
plaintext to a captured stream. A human at a terminal is unaffected; a human
piping confirms with one keypress on `/dev/tty`; an agent shell has no
`/dev/tty` and is refused with a pointer to `exec --map`. No flag, env var, or
config bypass — anything discoverable in `--help` would be discovered by an
agent.

**Layer 2 — `localvault guard`.** Claude Code `PreToolUse`/`PostToolUse` hooks
scan tool traffic against session-unlocked vaults. A Bash command containing a
stored secret is blocked (exit 2) before it runs; keys are named by vault/key
and SHA-256 fingerprint, never by value. Secrets appearing in tool *output*
trigger a rotate-now warning. Fails open on locked vaults, malformed events,
and — via a wrapper in the installed settings entry — old or missing binaries.

## Trace

- Commits: `7566f8f..ad24578`; tags `v1.9.0`, `v1.9.1`
- Plan: `docs/plans/07-agent-plaintext-containment.md` (Kuickr: dev-docs-74/localvault-plans)
- Series post: `docs/content/series/localvault/17-when-guidance-is-not-enough.md`
- Tests: 633 runs, 1644 assertions, 0 failures (both releases)

## Why 1.9.1 followed immediately

End-to-end verification against the *installed* binary found three defects that
unit tests could not see, because they stubbed the seams involved:

1. A stale `gem install localvault` (1.8.0) under asdf shadowed the Homebrew
   1.9.0 build — `localvault version` reported 1.8.0 after a successful
   upgrade. Fixed locally by uninstalling the gem; fixed for users by adding
   `install.sh` (isolated prefix + PATH wrapper, never a version-manager shim)
   and a README warning.
2. `guard` was missing from the curated top-level help (`CLI.help` is
   hand-written, so registering a Thor subcommand does not list it).
3. `guard install` probed for support by grepping that help text, so it always
   warned "does not support guard hook". Now it runs `guard status` against the
   PATH binary and checks the exit status.

Lesson worth keeping: for a feature whose whole purpose is enforcement, verify
against the shipped artifact, not only the test harness.

## Pending human action

- Ship draft **1158** is unpublished — the public changelog entry.
- Tweet draft **3840** (`@Invent_List`) awaits approval; the ritual forbids
  announcing before the Ship is live.
- Rotate the shared Stripe `sk_live` (`STRIPE_INVENT_LIST.private_key`).
  Consumers: inventlist, calm.page, shorttags, inventlist-rails-upgrade.
  kuickr is on its own key and is unaffected.
