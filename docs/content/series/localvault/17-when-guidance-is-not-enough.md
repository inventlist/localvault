---
title: "When Guidance Is Not Enough: Making Secrets Agent-Proof"
description: "An AI agent put a live Stripe key on a command line despite every safety instruction we had shipped. Here is the two-layer containment design that makes that class of mistake impossible instead of discouraged."
type: journey
---

# When Guidance Is Not Enough: Making Secrets Agent-Proof

LocalVault 1.8 shipped a whole guidance layer for AI agents: MCP server
instructions that tell agents not to retrieve plaintext, a `build_exec` tool
that constructs injected commands for them, an `allow_plaintext` gate on
`get_secret`, and stdin-based writes so values never touch argv.

Then an agent leaked a live Stripe secret key anyway.

Not through any of the gated paths. The value was already in the agent's
context, and the agent interpolated it into a command line. The command — and
the key — landed in the session transcript. Every safety instruction we had
written was technically followed or simply not applicable, and the secret still
got out.

That incident taught us the lesson this post is about:

**Guidance shapes behavior. Only enforcement bounds it.**

## Why the Guidance Layer Could Not Catch This

All of LocalVault's 1.8-era protections sit on the *read path*. They make it
harder for an agent to pull a plaintext value into its context in the first
place. That is worth doing, and it works — in the session after the incident,
every secret moved by env-injection or stdin pipe, and nothing leaked.

But the read path is only half the problem:

- An agent can hold a secret it *generated* — fresh encryption keys, random
  tokens — which never passed any LocalVault gate.
- An agent that legitimately retrieved a value for one step can misuse it in
  the next.
- Once a value is in model context, nothing on the vault side can stop it from
  being written into a command, a file, or a reply.

A secrets manager that only guards retrieval is a door with a lock on one side.

## The Design: Two Layers, Zero Human Friction

The fix we designed has two independent layers. Either one alone would have
gaps; together they cover both directions.

### Layer 1: Plaintext refuses to enter a captured stream

`localvault get` and `localvault env` will check whether stdout is an
interactive terminal before printing a plaintext value.

A human in a real terminal has a TTY, so nothing changes:

```bash
localvault get STRIPE_KEY        # works exactly as today
```

An agent's shell captures output — no TTY — so the same command is refused,
and the refusal teaches the safe path:

```text
Refusing to print plaintext to a captured stream.
Use: localvault exec --map KEY=ENV_NAME -- your-command
```

The elegant part is what happens with pipes. A human piping to the clipboard
gets a one-keystroke confirmation on `/dev/tty`:

```bash
localvault get STRIPE_KEY | pbcopy
# Print plaintext? [y/N]
```

An agent's shell has no `/dev/tty` to answer on. There is no flag to discover,
no argument to pass, nothing to talk itself into. The boundary is physical:
if you can press a key on the terminal, you are a human.

### Layer 2: A guard at the harness boundary

Layer 1 cannot stop the incident that actually happened, because that value
was already in context. For that we designed `localvault guard`, a hook for
the agent harness (Claude Code first).

Before every shell command an agent runs, the guard compares the outgoing
command against the decrypted values in the session-cached vault. If any
stored secret appears in the command line, the call is denied before it
executes, and the agent is told — by key fingerprint, never by value — what it
tried to do and how to do it safely:

```text
Blocked: command contains the value of STRIPE.private_key (fp:1a2b3c…).
Inject it instead: localvault exec --map STRIPE.private_key=STRIPE_KEY -- …
```

This is the layer that would have caught the Stripe key. It does not matter
how the value reached the agent's context — retrieved, generated, or pasted —
if it is in the vault, it cannot pass through a command line.

The guard fails open when the vault is locked: a locked vault cannot have fed
values into the session anyway, and a security tool that blocks all work when
it cannot check anything gets uninstalled.

## What We Deliberately Did Not Build

- **File-write scanning.** A file on your own disk is not an exposure; the
  transcript is. Scanning every write buys little and costs trust in the tool.
- **Git-push scanning.** Tools like gitleaks already own that boundary well.
- **Removing plaintext access.** Some tasks genuinely need the value. The goal
  is that *getting* plaintext requires a human at a keyboard, and *misusing*
  it gets caught at the boundary.

## The Principle

Every secrets tool for the agent era will go through this same arc: first you
write instructions, then an agent ignores or sidesteps them, then you build
walls. The instructions still matter — they route the agent to the right path
ninety-nine times out of a hundred. But the wall is what makes the hundredth
time a denied tool call instead of a rotated production key.

Rotate your keys anyway. We are.
