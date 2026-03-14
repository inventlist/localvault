---
title: Why I Built LocalVault
description: The maker journey behind a zero-infrastructure secrets manager — from frustration with existing tools to building something I actually want to use.
type: journey
---

# Why I Built LocalVault

I build a lot of side projects. Each one has a pile of secrets — API keys, database URLs, tokens for services I've integrated. After a while you end up with the same problem everyone has: where do you actually keep these things?

The options I tried, and why they didn't stick:

**1Password / Bitwarden** — great for passwords, awkward for developer secrets. Not built for `export STRIPE_KEY=...` workflows. Can't inject into a process.

**Doppler / Infisical / Vault** — genuinely good tools, but they all require a server running somewhere, or a subscription, or both. For a solo indie maker, standing up a secrets server for a side project feels like more infrastructure than the project itself.

**`.env` files in the repo** — everyone does this and everyone knows it's bad. Secrets end up in git history, shared in Slack, pasted into CI configs.

**System Keychain directly** — you can store things there, but there's no coherent interface for developer workflows. No `exec`, no `env`, no team sharing.

So I built what I actually wanted: a CLI that stores secrets encrypted on disk, gives you a clean interface, injects them into processes, and has zero infrastructure requirements. No server. No subscription. Open source.

## The AI agents angle

The shift that made LocalVault much more useful was when AI coding agents became a daily tool. Claude Code, Cursor, Windsurf — these agents write and run code, and they need your secrets to do anything real.

The naive solution is to paste your keys into the conversation. That's obviously bad. Some tools have their own secret management, but it's per-tool and none of them talk to each other.

MCP (Model Context Protocol) changed this. You can expose a controlled interface to the agent — it can ask for specific secrets by name, and your vault handles the rest. The agent never sees your passphrase. You don't have to paste anything. The session expires when your terminal closes.

Running `localvault install-mcp` now wires this up globally for Claude Code in one command. The agent just calls `get_secret("OPENAI_API_KEY")` and gets what it needs.

## The thing I didn't expect to build

When I started, I thought LocalVault was a personal tool. One machine, one person, local-only.

Then I started working across two Macs, and immediately hit the obvious limitation: if the vault is local-only, you can't get to it from another machine without manually copying files around.

The obvious answer is cloud sync. But cloud sync for secrets is a loaded problem — you're trusting whatever service stores them to not read them. Most sync solutions don't make strong guarantees here.

So I started thinking about how to do sync in a way where the answer to "can the server read my secrets?" is genuinely, cryptographically, *no* — not just a policy promise.

That led to the sync design, which is the most interesting part of building this. I'll write about that next.
