---
title: "LocalVault 1.8.1: Stop Putting Secrets In Your Shell History"
description: "LocalVault 1.8.1 adds set --stdin and localvault doctor, fixing two real audit findings: argv secret exposure and brew/asdf PATH confusion."
type: journey
---

# LocalVault 1.8.1: Stop Putting Secrets In Your Shell History

The original LocalVault write path was simple:

```bash
localvault set DEPLOY_WEBHOOK_SECRET "real-secret-here"
```

It worked, but it had the same flaw as every positional secret CLI: the value can
land in shell history, process listings, terminal scrollback, and screenshots.

LocalVault 1.8.1 adds the safer path:

```bash
printf '%s' "$SECRET" | localvault set DEPLOY_WEBHOOK_SECRET --stdin
```

The secret is read from stdin, stored encrypted, and never echoed back.

## Grouped Secrets Work Too

Dot-notation and group saving still work:

```bash
printf '%s' "$SECRET" | localvault set app.DEPLOY_WEBHOOK_SECRET --stdin

printf '%s' "$SECRET" | localvault set \
  --group app \
  DEPLOY_WEBHOOK_SECRET \
  --stdin \
  -v production
```

Use `printf '%s'`, not `echo`, when exact bytes matter. `echo` can add a newline
or interpret flags depending on the shell.

## What LocalVault Refuses

`--stdin` is intentionally strict.

This fails because it has two value sources:

```bash
localvault set KEY "argv-secret" --stdin
```

This fails before reading because interactive stdin is not a safe secret prompt:

```bash
localvault set KEY --stdin
# when run directly in a terminal without a pipe
```

Invalid UTF-8 also fails before storage. LocalVault stores secrets in encrypted
JSON, so rejecting invalid text keeps the vault format predictable.

## Compatibility Stays Intact

The old form still works:

```bash
localvault set KEY VALUE
```

It is now the compatibility path, not the recommended path.

Two edge cases remain literal values:

```bash
localvault set DASH -
localvault set FLAG -- --stdin
```

The first stores `-`. The second stores `--stdin`. LocalVault does not overload
`-` as stdin, because that would change behavior for existing users.

## The Other Real Bug: PATH Confusion

The same audit found a second problem: after installing through Homebrew, a
stale asdf shim could still be the `localvault` that actually runs.

That looks like this:

```bash
which -a localvault
# /Users/you/.asdf/shims/localvault
# /opt/homebrew/bin/localvault
```

You think you upgraded LocalVault. Your shell still runs the shim. The error you
see is an asdf error, not a LocalVault error.

LocalVault 1.8.1 adds:

```bash
localvault doctor
```

It prints:

- selected executable
- every `localvault` executable on PATH
- warning when an asdf shim shadows Homebrew
- repair checks: `asdf reshim ruby`, `hash -r`, and `which -a localvault`

On a healthy Homebrew-first setup, it still warns if multiple executables exist,
because duplicate secret tooling is worth noticing.

## Upgrade

```bash
brew update
brew upgrade inventlist/tap/localvault

localvault version
# localvault 1.8.1

localvault doctor
```

If you install with RubyGems:

```bash
gem install localvault
localvault version
```

## The Baseline Going Forward

Use stdin for writes:

```bash
printf '%s' "$SECRET" | localvault set KEY --stdin
```

Use `exec` for commands:

```bash
localvault exec --profile aws -- aws sts get-caller-identity
```

Use MCP to discover names and build injection commands, not to copy plaintext
values by default.

That combination keeps secrets out of config files, shell history, and model
context unless you explicitly choose otherwise.
