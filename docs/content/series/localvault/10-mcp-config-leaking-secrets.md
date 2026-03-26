---
title: Your MCP Config Is Leaking Secrets. Here's Proof.
description: 24,008 secrets found in MCP configs in the wild. The setup guides tell you to do it. Here's what's actually at risk and how to fix it in 60 seconds.
type: journey
---

# Your MCP Config Is Leaking Secrets. Here's Proof.

Go open your Claude Desktop config right now. On macOS:

```bash
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

If it looks anything like this, keep reading:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_a1b2c3d4e5f6g7h8i9j0..."
      }
    },
    "slack": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-slack"],
      "env": {
        "SLACK_BOT_TOKEN": "xoxb-1234567890-abcdefghij...",
        "SLACK_TEAM_ID": "T01ABCDEF"
      }
    },
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"],
      "env": {
        "DATABASE_URL": "postgresql://admin:s3cretpassword@prod-db.example.com:5432/myapp"
      }
    }
  }
}
```

That file is sitting on your disk in plaintext. Every secret you've wired up to every MCP server is right there, readable by any process running as your user.

## The numbers

GitGuardian's 2026 State of Secrets Sprawl report found **24,008 secrets hardcoded in MCP configuration files** across public repositories and scanned environments. That's not a rounding error. That's twenty-four thousand API keys, database credentials, and service tokens sitting in JSON files.

The broader picture is worse. AI-service-related secret leaks surged 81% year over year. OWASP's MCP Top 10 — published specifically for the Model Context Protocol — lists **Token Mismanagement** as the number one risk.

This is not a theoretical concern. It's happening at scale, right now.

## Why this happens

Because the setup guides tell you to do it.

Open the README for almost any MCP server. The installation instructions look like this:

```json
{
  "mcpServers": {
    "some-service": {
      "command": "npx",
      "args": ["-y", "@example/mcp-server"],
      "env": {
        "API_KEY": "your-api-key-here"
      }
    }
  }
}
```

You copy the block, paste in your real key, save the file, and move on. The README doesn't warn you. There's no "by the way, this file is plaintext and any process on your machine can read it" caveat.

Every MCP server you add puts another secret into that same file. After a few months of daily use, your config becomes a collection of every important credential you have — GitHub tokens, database URLs, payment processor keys, cloud provider credentials.

## What's actually at risk

That config file has several properties that make it dangerous:

**Any process can read it.** It's a regular file with standard permissions. Any application, script, or malware running as your user can open it and read every secret.

**It gets synced.** If you use iCloud, Dropbox, or any backup service that covers your home directory or Application Support folder, your secrets are now in the cloud. In someone else's infrastructure. In plaintext.

**It gets committed.** People share dotfiles. People commit config directories. GitGuardian didn't find 24,008 secrets by accident — those files ended up in repositories.

**It's a single point of failure.** Compromise this one file and an attacker has everything. Not just one service — every service you've connected via MCP.

## The fix

The root problem is that MCP config files were designed to hold environment variables, and people use environment variables to pass secrets. The fix is to stop putting secrets in that file entirely.

LocalVault has a built-in MCP server. Your config looks like this:

```json
{
  "mcpServers": {
    "localvault": {
      "command": "localvault",
      "args": ["mcp"]
    }
  }
}
```

That's it. No `env` block. No secrets. Nothing sensitive in the file at all.

When your AI agent needs an API key, it calls `get_secret("GITHUB_TOKEN")` through the MCP protocol. LocalVault decrypts the value from your vault on the fly and returns it. The secret exists in memory for the duration of the call.

Your vault is encrypted with Argon2id key derivation (64 MB memory cost, 2 iterations) and XSalsa20-Poly1305 authenticated encryption. The config file an attacker would find is a JSON object with the word "localvault" in it. Nothing else.

## Setup in 60 seconds

Install:

```bash
brew install inventlist/tap/localvault
```

Or if you prefer gems:

```bash
gem install localvault
```

Create a vault and add your secrets:

```bash
localvault init
localvault set GITHUB_TOKEN ghp_a1b2c3d4e5...
localvault set SLACK_BOT_TOKEN xoxb-1234567890...
localvault set DATABASE_URL postgresql://admin:s3cret@prod-db:5432/myapp
```

Unlock your session (one prompt, then cached):

```bash
eval $(localvault unlock)
```

Register the MCP server:

```bash
localvault install-mcp
```

Done. Your AI agent now has access to your secrets through a controlled, encrypted interface. Your MCP config contains zero credentials. Your vault is encrypted at rest. The session expires when your terminal closes.

On macOS, the session is also cached in Keychain with an 8-hour TTL — so opening a new terminal window doesn't reprompt you during your working day.

## For teams

If you work with collaborators, the problem is worse. Sharing an MCP config means sharing every secret in it. People end up pasting tokens in Slack or committing shared configs to private repos.

LocalVault handles this with key slots. Each team member has their own Curve25519 key pair. The vault's master key is encrypted separately for each authorized user. You add a collaborator by their public key — they can decrypt the vault with their own passphrase. Nobody shares a passphrase. Nobody pastes tokens. Revoking access is deleting their key slot.

```bash
localvault team add @colleague -v production
localvault sync push -v production
```

Your colleague pulls the vault and it auto-unlocks via their identity key — no passphrase needed. Their MCP config is the same zero-secret JSON block. The secrets travel encrypted, decrypted only on their machine.

## The baseline

You wouldn't commit your SSH private key to a repo. You wouldn't paste your database password into a README. But right now, thousands of developers are doing the equivalent with their MCP configs — because the tooling told them to.

Check your config. Count the secrets. Then decide if a plaintext JSON file is where you want to keep them.

```bash
# See what's in your config right now
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json | grep -c "env"
```

If the answer is more than zero, you have work to do.
