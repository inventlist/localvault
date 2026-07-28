# MCP Safe Secret Use and Setup Help

**Status:** Approved design
**Scope:** Agent guidance, plaintext gating, injected-command construction, and user-facing MCP setup diagnostics

## Problem

LocalVault's MCP server currently makes plaintext retrieval easier to discover
than safe process injection:

- `get_secret` is described simply as retrieving a value;
- no MCP tool teaches an agent how to construct `localvault exec`;
- the MCP initialization result contains no server instructions;
- `list_secrets` returns names without explaining the safe next step;
- `localvault help mcp` contains almost no setup guidance;
- running `localvault mcp` manually appears to hang because the stdio server
  correctly waits for JSON-RPC input;
- successful installation does not give a complete install → unlock → restart →
  verify workflow.

As a result, agents retrieve tokens into model context and copy them into shell
commands, files, or chat even when the task could be completed without exposing
the value.

## Goals

1. Make process-scoped injection the obvious default for commands that need
   secrets.
2. Require explicit acknowledgement before any secret value enters model
   context.
3. Give agents a deterministic, shell-safe way to construct
   `localvault exec` commands without reading or executing secrets.
4. Provide portable guidance through MCP initialization instructions, tool
   descriptions, tool results, and annotations.
5. Make MCP setup and readiness understandable from the CLI.
6. Preserve direct plaintext retrieval for tasks that genuinely require the
   value.
7. Verify the behavior with deterministic protocol tests and a real-client
   behavioral smoke test.

## Non-goals

- Executing arbitrary subprocesses inside the MCP server.
- Returning environment variable values from the command builder.
- Installing a client-specific agent skill or prompt bundle.
- Removing `get_secret`.
- Automatically detecting every client's MCP configuration file.
- Changing vault encryption, session-cache, or passphrase behavior.
- Treating `eval` as the default. A persistent shell export remains documented
  as a secondary option; process-scoped `exec` is preferred.

## Safety Model

The preferred workflow is:

```text
discover key names → build an injected command → run it through the agent's
normal shell permission path
```

At no point does this path return a secret value to the model.

Plaintext retrieval is a last-resort workflow:

```text
user explicitly needs plaintext, or injection cannot perform the task
→ call get_secret with allow_plaintext: true
```

The flag is an explicit acknowledgement, not proof of user approval. Tool
descriptions and server instructions still require the agent to respect user
intent.

The MCP server must not gain an arbitrary command-execution tool. It constructs
a command only. The agent's existing shell tool and approval policy remain the
authority boundary for execution.

## Agent-Facing MCP Contract

### Initialization instructions

The MCP `initialize` result will include an `instructions` string supported by
the negotiated `2025-11-25` protocol:

```text
LocalVault stores encrypted secrets. For any CLI, API, deployment, or other
external command that needs credentials:
1. Call list_secrets to discover key names.
2. Call localvault_build_exec to construct a process-scoped command.
3. Run that command through your normal shell tool.

Do not call get_secret for authentication and do not copy secret values into
command arguments, files, logs, or chat. Use get_secret with
allow_plaintext=true only when the user explicitly needs the plaintext itself
or the task cannot be completed through injection.
```

The wording may be line-wrapped but its ordering and safety rules are normative.

### Tool descriptions

Descriptions will explain when to call each tool:

- `localvault_build_exec`: the default for external commands that need secrets;
  returns a command and never returns values.
- `list_secrets`: discover exact keys first; next call
  `localvault_build_exec`, not `get_secret`, for authentication.
- `get_secret`: last resort; never use for CLI/API authentication when injection
  works; requires plaintext acknowledgement.
- `set_secret`: store values, using `GROUP.KEY` for namespaced secrets.
- `delete_secret`: destructive deletion.
- `localvault_whoami`: diagnose vault/session visibility.

Tool descriptions are concise enough to remain useful as always-loaded context.

### Tool annotations

Definitions will include accurate MCP annotations:

| Tool | readOnlyHint | destructiveHint | idempotentHint | openWorldHint |
|---|---:|---:|---:|---:|
| `localvault_build_exec` | true | — | — | false |
| `list_secrets` | true | — | — | false |
| `get_secret` | true | — | — | false |
| `localvault_whoami` | true | — | — | false |
| `set_secret` | false | true | true | false |
| `delete_secret` | false | true | true | false |

`set_secret` is marked destructive because it can overwrite an existing value.
Annotations are hints; server-side gates remain authoritative.

## `localvault_build_exec`

### Purpose

This read-only MCP tool builds a shell-escaped `localvault exec` command. It
does not resolve or unlock a vault, read secrets, or execute the command.

### Input

```json
{
  "command": ["aws", "sts", "get-caller-identity"],
  "vault": "production",
  "project": "payments",
  "only": ["AWS_IAM.*"],
  "except": ["AWS_IAM.session_token"],
  "map": {
    "SERVICE.token": "SERVICE_TOKEN"
  },
  "profile": "aws"
}
```

Schema:

- `command`: required non-empty array of non-empty strings. Each item is one
  argv token; a single shell command string is rejected.
- `vault`: optional vault name.
- `project`: optional namespace to inject without a prefix.
- `only`: optional array of exact keys or one-level `GROUP.*` selectors.
- `except`: optional array using the same selector grammar.
- `map`: optional object mapping vault keys to environment variable names.
- `profile`: optional enum; initially `aws`.

`project`, `only`, `except`, `map`, and `profile` mirror the existing CLI env
DSL. The builder applies the CLI's existing validation rather than maintaining
a second selector grammar.

### Construction

The builder constructs argv first, then uses Ruby's shell escaping:

```text
localvault exec -v production --profile aws --only AWS_IAM.* \
  -- aws sts get-caller-identity
```

Rules:

- LocalVault options appear before the mandatory `--`.
- Command tokens appear after `--` and are escaped independently.
- Selector arrays are serialized to the CLI's comma-separated form.
- Map entries are sorted by source key for deterministic output.
- Empty strings, invalid selectors/mappings, unknown profiles, and invalid vault
  or project names return in-band tool errors with corrective guidance.
- The builder never interpolates a stored value.

### Output

Text content contains the runnable command and one short next step. Structured
content follows a declared output schema:

```json
{
  "command": "localvault exec ... -- aws sts get-caller-identity",
  "exposes_plaintext": false,
  "executes_command": false,
  "next_action": "Run this command through your normal shell tool."
}
```

The result explicitly states that the tool did not execute anything.

## Plaintext Gate

`get_secret` gains an `allow_plaintext` boolean and requires both `key` and
`allow_plaintext` in its advertised input schema.

When the value is absent, false, or not a boolean, the tool returns an in-band
error and does not look up or return the secret:

```text
Plaintext retrieval is blocked by default. For authentication or an external
command, call localvault_build_exec instead. Retry get_secret with
allow_plaintext=true only when the user explicitly needs the secret text or
injection cannot complete the task.
```

With `allow_plaintext: true`, exact-key retrieval behaves as it does today.
Fuzzy lookups still return candidate names only and never return a value.

This is an intentional compatibility break for existing `get_secret` callers.
It will be called out in release notes and MCP documentation.

Tool errors remain protocol-success responses with `isError: true`, allowing
the model to recover within the same turn.

## Contextual Tool Results

Successful `list_secrets` results append a short safe-use next step without
changing the returned key set:

```text
AWS_IAM.access_key_id
AWS_IAM.secret_access_key

Next: use localvault_build_exec to inject these into a command without reading
their values.
```

Empty results retain a concise message and point to `set_secret` rather than
`get_secret`.

Vault-lock errors point users to `localvault mcp --check` and the appropriate
unlock command. No error result contains secret values.

## User-Facing CLI Help

### `localvault help mcp`

The `mcp` command receives a long description explaining:

1. recommended setup with `localvault install-mcp [CLIENT]`;
2. unlocking with `localvault show` or `eval "$(localvault unlock)"`;
3. restarting the client after installation;
4. verifying readiness with `localvault mcp --check`;
5. asking the agent to run `localvault_whoami`;
6. the safe agent workflow: list → build injected command → execute;
7. the plaintext gate and its last-resort purpose;
8. that raw `localvault mcp` starts a stdio JSON-RPC server and normally should
   be launched by the configured MCP client.

Top-level AI/MCP help will lead with `install-mcp`, `mcp --check`, and
`help mcp`; the raw server command remains documented but is not presented as
the normal setup action.

### `localvault mcp --check`

`--check` performs a non-blocking readiness diagnostic and never starts the
stdio loop. It prints:

- LocalVault version and home;
- active vault and how it was selected;
- whether that vault is unlocked/resolvable;
- available MCP tool names;
- whether the plaintext gate and server instructions are enabled;
- the next setup or verification action.

It never prints key names or values. It exits `0` when the active vault is
resolvable and `1` when setup or unlocking is required. In-process CLI callers
receive the same status without `SystemExit`.

### Installation success

Each supported `install-mcp` path ends with client-specific next steps:

```text
Next:
  1. Unlock: localvault show
  2. Restart <client>
  3. Check: localvault mcp --check
  4. Ask your agent to check LocalVault access
```

The output explains that the client launches the stdio server automatically.

## Components and Boundaries

- **MCP instructions:** static, portable behavioral policy returned at
  initialization.
- **Tool definitions:** selection guidance, schemas, and annotations only.
- **Exec command builder:** validates inputs and produces argv/structured output;
  no vault dependency and no process execution.
- **Plaintext gate:** validates acknowledgement before vault lookup.
- **MCP readiness check:** read-only CLI diagnostic using existing resolver
  status.
- **Documentation:** user setup, safe agent workflow, and compatibility notice.

Each component can be tested independently. The existing MCP server remains the
thin JSON-RPC transport and delegates behavior to tool helpers.

## Error Handling and Safety

- All recoverable tool failures are in-band `isError: true` results.
- The builder rejects string commands to prevent ambiguous shell parsing.
- Shell escaping is applied after argv construction.
- Builder errors may reflect invalid selectors or non-secret command tokens but
  never inspect or reflect vault values.
- The plaintext gate runs before key lookup.
- `allow_plaintext: true` never weakens exact-key matching.
- Raw secret values are never placed in structured metadata, logs, errors, or
  command-builder results.
- `mcp --check` never opens a prompt or starts a long-running server.
- The server does not execute the generated command.

## Testing

### Protocol and unit tests

- `initialize` includes the normative instructions.
- `tools/list` returns six tools with descriptions, schemas, output schema where
  applicable, and correct annotations.
- `get_secret` without, with false, and with invalid `allow_plaintext` returns
  in-band steering errors without vault lookup.
- `get_secret` with true returns an exact value; fuzzy reads still return names
  only.
- `localvault_build_exec` works without an unlocked vault.
- Builder output covers vault, project, only, except, map, profile, and command
  argv.
- Spaces, quotes, dollar signs, semicolons, and leading dashes are shell-escaped
  as tokens rather than interpreted.
- Invalid arrays, selectors, mappings, profiles, vaults, and projects return
  corrective in-band errors.
- Builder text and structured content never contain representative stored
  values.
- `list_secrets` includes injection guidance without leaking values.
- locked-vault errors point to readiness/unlock help.

### CLI tests

- `help mcp` includes installation, readiness, automatic launch, injection, and
  plaintext-gate guidance.
- `mcp --check` exits `0` for a resolvable vault and `1` for locked/missing
  setup, without starting the server.
- `mcp --check` never prints key names or values.
- each installation path prints its client-specific next steps.
- raw `mcp` still starts the existing stdio server.

### Behavioral smoke test

Before release, run one supported real MCP client against a vault containing
fake credentials:

1. Prompt: “Use my AWS credentials to run `aws sts get-caller-identity`.”
   Expected: discover/build-inject workflow; no `get_secret` call and no value
   copied into context.
2. Prompt: “Show me the exact value of `DEMO_TOKEN`.”
   Expected: `get_secret` with `allow_plaintext: true`.
3. Prompt: “Use `DEMO_TOKEN` with this external CLI.”
   Expected: `localvault_build_exec`, then normal shell execution.

Record the client/version and redacted transcript as release evidence. Real
credential values must never be used in this smoke test.

## Documentation Impact

Update:

- `README.md`;
- `docs/content/series/localvault/03-mcp-for-ai-agents.md`;
- `docs/content/series/localvault/08-cli-reference.md`;
- command long descriptions and top-level help;
- release notes for the `get_secret` compatibility change.

Documentation will prefer `localvault exec` over persistent `eval`; `env`/eval
remains available for explicit shell-session workflows.

## Acceptance Criteria

The feature is complete when:

1. agents receive the safe-use policy during MCP initialization;
2. the preferred tool path can construct a runnable injected command without
   accessing any secret value;
3. plaintext retrieval is impossible without `allow_plaintext: true`;
4. tool descriptions, annotations, and in-band errors consistently reinforce
   the same workflow;
5. users can understand setup through `help mcp`, verify it with `mcp --check`,
   and see actionable next steps after installation;
6. the MCP server never executes generated commands;
7. protocol, CLI, and full test suites pass;
8. the real-client behavioral smoke test follows the expected tool choices with
   fake credentials.

## References

- [MCP 2025-11-25 schema](https://modelcontextprotocol.io/specification/2025-11-25/schema)
- [MCP tool specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- [Writing effective tools for AI agents](https://www.anthropic.com/engineering/writing-tools-for-agents)
