---
title: "LocalVault 1.8: MCP First, CLI Honest"
description: "LocalVault 1.8 makes the MCP server a first-class interface: same vault resolution as the CLI, whoami diagnostics, safer exact reads, and process injection by default."
type: journey
---

# LocalVault 1.8: MCP First, CLI Honest

LocalVault started as a local CLI. Then AI agents arrived and the CLI was no
longer the only user.

The uncomfortable lesson from using it every day: an MCP server cannot be a
thin afterthought. If the agent sees a different vault than the CLI, or if it
cannot explain which vault it is bound to, every debugging session becomes
guesswork.

LocalVault 1.8 is the release that makes MCP a first-class interface.

## The Bug That Made This Obvious

The CLI could see a key:

```bash
localvault get AWS_IAM.access_key_id -v intellectaco
```

But an MCP call from the agent said the same key did not exist. In another
case, listing secrets through MCP showed a locked or unrelated vault while the
CLI had an unlocked session.

That is the worst kind of secrets bug: not a crypto failure, but a coordination
failure. The value is present. The user is authorized. The tools disagree.

## The New Rule

MCP now uses the same vault resolution rules as the CLI:

1. Explicit vault argument
2. `LOCALVAULT_VAULT`
3. Configured default from `localvault switch`

`LOCALVAULT_SESSION` only applies when it belongs to the resolved vault. If your
shell has a session token for `devops` but the active vault is `intellectaco`,
MCP does not silently bind to `devops`.

Every MCP call re-checks session state. If you run:

```bash
localvault lock
```

the agent loses access without restarting the MCP server.

## `localvault_whoami`

The new diagnostic tool answers the question that should never require
guessing:

```
localvault_whoami
```

It reports:

- LocalVault version
- LocalVault home directory
- active vault and where it came from
- whether the active vault is unlocked
- session vault
- unlocked vaults visible to MCP

When an agent says a key is missing, the first move is no longer another blind
lookup. It is `localvault_whoami`.

## Names First, Values Last

The safe MCP workflow is:

1. Discover names with `list_secrets`
2. Build a command with `localvault_build_exec`
3. Run the command through the normal CLI path

`list_secrets` can now filter by prefix or query:

```
list_secrets(prefix: "AWS_IAM.")
list_secrets(query: "smtp")
```

The tool returns names only. No values, no accidental paste into model context.

## Exact Reads Only

`get_secret` is still available, but it is deliberately strict:

- exact key match can return a value
- partial or fuzzy match returns candidate names only
- plaintext requires `allow_plaintext: true`

If the agent asks for `AWS_IAM`, and the vault contains both
`AWS_IAM.access_key_id` and `AWS_IAM.secret_access_key`, MCP returns the
candidates. It does not guess and it does not reveal either value.

That mirrors the CLI's helpful fuzzy-match behavior without making fuzzy reads
unsafe.

## Process Injection Is The Default

Most agent tasks do not need the secret in chat. They need a subprocess to have
the right environment.

Instead of asking for an AWS key, the agent can build:

```bash
localvault exec --profile aws -- aws sts get-caller-identity
```

The value goes from the encrypted vault into the child process environment. It
does not need to be copied into the prompt, a config file, or a shell history
entry.

## Try It

```bash
brew upgrade inventlist/tap/localvault

localvault install-mcp
localvault unlock
localvault mcp --check
```

Then ask your agent to diagnose LocalVault before reading anything:

```
Call localvault_whoami, then list the AWS_IAM key names.
Do not retrieve plaintext values unless I explicitly ask.
```

That is the new baseline: the agent starts from the same vault state as the
CLI, can explain what it sees, and prefers safe injection over plaintext reads.
