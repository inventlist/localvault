# MCP Safe Secret Use and Help Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Steer agents to process-scoped secret injection, gate plaintext reads, and make MCP setup/readiness obvious to users.

**Architecture:** Extend the thin stdio server with portable initialization instructions and a read-only command builder. Share pure env-DSL validators, keep plaintext gating before vault lookup, and expose bounded readiness through the typed CLI status boundary from the contextual-help plan.

**Tech Stack:** Ruby 3.4, MCP protocol 2025-11-25, Thor 1.5, Minitest, Shellwords, Open3

**Spec:** `docs/localvault/plans/02-mcp-safe-secret-use.md`

**Dependency:** Execute `2026-07-28-contextual-cli-help.md` first.

---

## File Structure

- Create `lib/localvault/input_validation.rb`: pure vault/project/selector/mapping/argv validators.
- Create `lib/localvault/mcp/exec_command_builder.rb`: argv construction and structured result.
- Create `test/input_validation_test.rb`: shared grammar.
- Create `test/mcp/exec_command_builder_test.rb`: construction and leak-safety tests.
- Modify `lib/localvault/env_projection.rb`: delegate parsing validation to shared helpers.
- Modify `lib/localvault/mcp/tools.rb`: descriptions, annotations, builder tool, plaintext gate, guidance.
- Modify `lib/localvault/mcp/server.rb`: initialization instructions.
- Modify `lib/localvault/session_cache.rb`: bounded Keychain runner.
- Modify `lib/localvault/vault_resolver.rb`: active-vault-only bounded readiness status.
- Modify `lib/localvault/cli.rb`: MCP help/check and installation next steps.
- Modify MCP/CLI tests and user docs.

### Task 1: Pure Shared Input Validation

**Files:**
- Create: `lib/localvault/input_validation.rb`
- Create: `test/input_validation_test.rb`
- Modify: `lib/localvault/env_projection.rb`
- Test: `test/vault_filter_test.rb`
- Test: `test/cli_test.rb`

- [ ] **Step 1: Write failing validator tests**

Specify pure methods:

```ruby
InputValidation.selector!("AWS_IAM.*")       # => string
InputValidation.mapping!("A.B", "ENV_NAME") # => pair
InputValidation.project!("payments")
InputValidation.vault_name!("production")
InputValidation.argv!(["ruby", "-e", "puts 1"])
```

Reject empty/extra segments, wildcard mapping sources, commas/equals
delimiters, unsafe env names, invalid vault/project names, non-arrays, empty
argv, empty tokens, non-string tokens, and NUL bytes.

- [ ] **Step 2: Run and verify RED**

Run `bundle exec ruby -Itest -Ilib test/input_validation_test.rb`; expect missing module.

- [ ] **Step 3: Implement validators and reuse them**

Use anchored regexes and raise a single `InputValidation::InvalidInput` carrying
safe corrective text. Refactor `EnvProjection.parse_selectors` and `parse_map`
to call the pure helpers. Translate invalid selectors/mappings back to
`EnvProjection::InvalidMapping`; preserve `EnvProjection::UnknownProfile`
unchanged so `CLI#env` and `CLI#exec` retain their public rescue contract.

- [ ] **Step 4: Run and verify GREEN/regression**

```bash
bundle exec ruby -Itest -Ilib test/input_validation_test.rb
bundle exec ruby -Itest -Ilib test/vault_filter_test.rb
bundle exec ruby -Itest -Ilib test/cli_test.rb
```

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/input_validation.rb lib/localvault/env_projection.rb test/input_validation_test.rb test/vault_filter_test.rb test/cli_test.rb
git commit -m "refactor: share env input validation"
```

### Task 2: Read-Only Injected Command Builder

**Files:**
- Create: `lib/localvault/mcp/exec_command_builder.rb`
- Create: `test/mcp/exec_command_builder_test.rb`

- [ ] **Step 1: Write failing builder tests**

Cover minimal argv, every supported option, deterministic map ordering,
POSIX escaping for spaces/quotes/dollar/semicolon/leading dash, invalid input
errors, no vault access, and absence of representative stored values.

Desired result:

```ruby
result = ExecCommandBuilder.call("command" => ["aws", "sts", "get-caller-identity"],
                                 "only" => ["AWS_IAM.*"], "profile" => "aws")
assert_equal false, result.fetch("exposes_plaintext")
assert_equal false, result.fetch("executes_command")
assert_match(/localvault exec .* -- aws sts/, result.fetch("command"))
```

- [ ] **Step 2: Run and verify RED**

Expect missing builder.

- [ ] **Step 3: Implement argv-first construction**

Build:

```ruby
argv = ["localvault", "exec"]
argv.concat(["-v", vault]) if vault
...
argv << "--"
argv.concat(command)
Shellwords.join(argv)
```

Join validated selectors with commas and sorted mappings as `KEY=ENV`. Return
only command/exposure/execution/next-action fields. Never call resolver, vault,
session cache, or `Kernel.exec`.

- [ ] **Step 4: Run and verify GREEN**

Run builder tests; expect zero failures.

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/mcp/exec_command_builder.rb test/mcp/exec_command_builder_test.rb
git commit -m "feat: build secret-injected commands over MCP"
```

### Task 3: Plaintext Gate and Agent-Oriented Tool Definitions

**Files:**
- Modify: `lib/localvault/mcp/tools.rb`
- Modify: `test/mcp/server_test.rb`

- [ ] **Step 1: Write failing protocol tests**

Assert six tools, exact descriptions/annotations, builder output/outputSchema,
and `get_secret` required fields. Use a resolver spy to prove missing/false/
invalid `allow_plaintext` returns `isError: true` before resolver lookup.
Assert `allow_plaintext: true` exact reads work and fuzzy reads remain names-only.

- [ ] **Step 2: Run and verify RED**

Run `test/mcp/server_test.rb`; expect five-tool and ungated-read behavior.

- [ ] **Step 3: Implement definitions and dispatch**

Add `localvault_build_exec` before vault resolution. Gate `get_secret` before
resolver lookup. Return the normative in-band steering message. Add annotations:
read-only/closed-world for builder/list/get/whoami; destructive/non-idempotent
for set; destructive/idempotent for delete.

- [ ] **Step 4: Run and verify GREEN**

Run MCP server and builder tests; expect zero failures.

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/mcp/tools.rb test/mcp/server_test.rb
git commit -m "feat: gate plaintext MCP reads"
```

### Task 4: Initialization and Result Steering

**Files:**
- Modify: `lib/localvault/mcp/server.rb`
- Modify: `lib/localvault/mcp/tools.rb`
- Modify: `test/mcp/server_test.rb`

- [ ] **Step 1: Write failing guidance tests**

Assert initialize instructions contain ordered list → build → shell guidance and
forbid get-for-auth behavior. Assert successful/empty `list_secrets` and
locked-vault errors provide the specified next actions without values.

- [ ] **Step 2: Run and verify RED**

Expect missing instructions/guidance.

- [ ] **Step 3: Implement static instructions and contextual results**

Add one frozen instructions constant returned in initialize. Append guidance
after the key list; keep key lines unchanged and sorted. Locked errors reference
`mcp --check` and unlock.

- [ ] **Step 4: Run and verify GREEN**

Run MCP tests; expect zero failures.

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/mcp/server.rb lib/localvault/mcp/tools.rb test/mcp/server_test.rb
git commit -m "feat: steer agents toward secret injection"
```

### Task 5: Bounded Keychain Readiness

**Files:**
- Modify: `lib/localvault/session_cache.rb`
- Modify: `lib/localvault/vault_resolver.rb`
- Modify: `test/session_cache_test.rb`
- Modify: `test/mcp/server_test.rb`

- [ ] **Step 1: Write failing timeout/readiness tests**

Use the exact seams:

```ruby
SessionCache.get(name, keychain_runner: runner, keychain_timeout: seconds)
VaultResolver.readiness_status(name = nil, deadline_seconds: 3,
  clock: monotonic_clock, session_cache: cache)
```

Inject a fake runner/cache/clock to test success, timeout, TERM→KILL→reap, file
fallback, and remaining-deadline propagation without sleeping. Assert active
readiness never scans other vaults.

- [ ] **Step 2: Run and verify RED**

Expect no injectable/bounded runner.

- [ ] **Step 3: Implement bounded subprocess access**

Add `SessionCache::KeychainRunner.read(vault_name, timeout_seconds:,
popen3: Open3.method(:popen3), clock:)`. Compute one monotonic deadline, close
child stdin, and drain stdout/stderr on reader threads so the caller never
blocks on `IO#read` before checking process state. Wait with
`wait_thread.join(remaining_time)`. If still alive, send TERM, wait only the
remaining deadline budget, then send KILL. Close pipes to unblock readers and
reap the child in `ensure`; every join/wait duration is recomputed from the same
deadline, so signal cleanup cannot add an unbounded grace period. Return a typed
timeout result so `SessionCache.get` falls back to the session file.

`VaultResolver.readiness_status` computes one monotonic deadline with
`Process.clock_gettime(Process::CLOCK_MONOTONIC)`, passes
`min(2, deadline - clock.call)` to `SessionCache.get`, checks only the active
vault, and returns a typed timed-out/not-ready status when no budget remains.
Normal `SessionCache.get(name)` uses the same two-second default runner and
existing file fallback; no API scans every vault.

Runner tests exercise this actual `popen3` seam with fake pipes, reader threads,
wait thread, signals, and monotonic clock; they do not bypass the runner with a
higher-level timeout stub.

- [ ] **Step 4: Run and verify GREEN**

Run session-cache and MCP resolver tests; expect zero failures and no real waits.

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/session_cache.rb lib/localvault/vault_resolver.rb test/session_cache_test.rb test/mcp/server_test.rb
git commit -m "feat: bound MCP readiness checks"
```

### Task 6: MCP CLI Help, Check, and Installation Next Steps

**Files:**
- Modify: `lib/localvault/cli.rb`
- Modify: `test/cli_test.rb`
- Modify: `test/mcp/server_test.rb`

- [ ] **Step 1: Write failing CLI tests**

Cover `help mcp`, ready/locked `mcp --check` output and status, no stdio loop,
no keys/values, top-level help ordering, and next-step output for Claude Code,
Cursor, and Windsurf installers.

- [ ] **Step 2: Run and verify RED**

Expect missing option/help/status.

- [ ] **Step 3: Implement check/help**

Add `method_option :check, type: :boolean`. If set, render readiness fields and
return typed `CommandStatus.success/failure`; otherwise start the existing
server. Add the approved long description and concise top-level entries. Route
all installer success paths through one client-aware next-steps helper.

- [ ] **Step 4: Run and verify GREEN**

Run focused CLI/MCP tests; expect zero failures.

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/cli.rb test/cli_test.rb test/mcp/server_test.rb
git commit -m "feat: add MCP setup diagnostics"
```

### Task 7: Documentation, Release Notice, Real-Client Smoke, and Full Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/content/series/localvault/03-mcp-for-ai-agents.md`
- Modify: `docs/content/series/localvault/08-cli-reference.md`
- Modify: `test/cli_test.rb`
- Create: `docs/localvault/release-notes/next.md`
- Create: `docs/localvault/mcp-smoke-2026-07-28.md`

- [ ] **Step 1: Write doc/help regression assertions**

Add assertions that user docs prefer exec, explain the plaintext flag, builder,
automatic client launch, check, and last-resort eval/plaintext behavior.

- [ ] **Step 2: Run and verify RED**

Expect missing documentation strings.

- [ ] **Step 3: Update docs, release notice, and smoke evidence skeleton**

Document the breaking `allow_plaintext` requirement in
`docs/localvault/release-notes/next.md`. Prepare the dated smoke evidence file
with client/model/LocalVault/OS fields, clean-session procedure, exact three
prompts, allowed retry rule, expected tool calls, redaction rules, and pass/fail.

- [ ] **Step 4: Execute the real-client smoke test**

Use the installed Claude Code client with a temporary `LOCALVAULT_HOME`, a demo
vault containing only fake values, and temporary MCP configuration so the test
does not mutate persistent client settings. Start a fresh conversation for each
approved prompt. Record redacted tool calls and outcomes in
`docs/localvault/mcp-smoke-2026-07-28.md`.

If a transport failure occurs before a relevant tool choice, allow one
documented retry. A plaintext tool choice on an injection prompt is an immediate
failure requiring implementation changes and a full rerun.

- [ ] **Step 5: Run all automated verification**

```bash
bundle exec ruby -Itest -Ilib test/input_validation_test.rb
bundle exec ruby -Itest -Ilib test/mcp/exec_command_builder_test.rb
bundle exec ruby -Itest -Ilib test/mcp/server_test.rb
bundle exec ruby -Itest -Ilib test/session_cache_test.rb
bundle exec ruby -Itest -Ilib test/cli_test.rb
bundle exec rake test
git diff --check
```

Expected: every command exits `0`; zero failures/errors.

- [ ] **Step 6: Commit**

```bash
git add README.md docs/content/series/localvault/03-mcp-for-ai-agents.md docs/content/series/localvault/08-cli-reference.md test/cli_test.rb docs/localvault/release-notes/next.md docs/localvault/mcp-smoke-2026-07-28.md
git commit -m "docs: teach safe MCP secret workflows"
```
