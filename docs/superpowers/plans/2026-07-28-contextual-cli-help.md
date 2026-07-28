# Contextual CLI Help and Groups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every LocalVault usage failure actionable and add searchable, writable secret groups without breaking legacy `--group` forms.

**Architecture:** Add a central Thor error boundary with typed command statuses, metadata-driven context/suggestion helpers, and a standalone `GroupCatalog`. Keep `CLI` as orchestration/rendering while pure helpers own matching, safety, and formatting.

**Tech Stack:** Ruby 3.4, Thor 1.5, Minitest, Lipgloss, Shellwords

**Spec:** `docs/localvault/plans/01-contextual-cli-help.md`

---

## File Structure

- Create `lib/localvault/cli/command_status.rb`: explicit process-status value.
- Create `lib/localvault/cli/command_context.rb`: resolve top-level/nested Thor command metadata from argv.
- Create `lib/localvault/cli/suggestion_builder.rb`: extract curated examples and metadata fallbacks.
- Create `lib/localvault/cli/error_presenter.rb`: classify safe usage errors and render stderr.
- Create `lib/localvault/group_catalog.rb`: derive, search, and resolve namespace/prefix groups.
- Create `test/cli/contextual_help_test.rb`: pure and CLI integration coverage for error help.
- Create `test/group_catalog_test.rb`: catalog semantics and collision coverage.
- Modify `lib/localvault/cli.rb`: central start boundary, legacy normalization, group commands/options/rendering.
- Modify `bin/localvault`: exit with normalized CLI status.
- Modify `README.md` and `docs/content/series/localvault/08-cli-reference.md`: new syntax and contextual errors.

### Task 1: Typed CLI Status and Central Error Boundary

**Files:**
- Create: `lib/localvault/cli/command_status.rb`
- Modify: `lib/localvault/cli.rb`
- Modify: `bin/localvault`
- Test: `test/cli/contextual_help_test.rb`

- [ ] **Step 1: Write failing status-boundary tests**

Cover:

```ruby
assert_equal 0, LocalVault::CLI.start(%w[help show])
assert_equal 1, LocalVault::CLI.start(%w[set only_one_arg])
assert_raises(SystemExit) { load bin_path } # subprocess coverage belongs below
```

Use a subprocess test for `bin/localvault set only_one_arg` and assert exit `1`;
in-process calls must return an integer without raising.
Also pass a custom `config[:shell]` and assert it receives errors, and verify
both `config[:debug]` and `THOR_DEBUG=1` re-raise the original `Thor::Error`.

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
bundle exec ruby -Itest -Ilib test/cli/contextual_help_test.rb
```

Expected: failures because usage errors still call Thor's exit path and successful calls do not normalize status.

- [ ] **Step 3: Implement the typed boundary**

Implement:

```ruby
module LocalVault
  class CLI
    CommandStatus = Struct.new(:code, keyword_init: true) do
      def self.success = new(code: 0)
      def self.failure = new(code: 1)
    end
  end
end
```

Override `CLI.start` to call `dispatch`, map only `CommandStatus` to its code,
map every other successful return to `0`, rescue `Thor::Error` for the presenter
added in Task 3, and return `1`. Preserve `THOR_DEBUG` re-raise and EPIPE success.
Preserve the caller-supplied shell and honor `config[:debug]`.
Change `bin/localvault` to `exit(LocalVault::CLI.start(ARGV))`.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run the same command; expect zero failures.

- [ ] **Step 5: Commit**

```bash
git add bin/localvault lib/localvault/cli.rb lib/localvault/cli/command_status.rb test/cli/contextual_help_test.rb
git commit -m "feat: normalize CLI command statuses"
```

### Task 2: Command Context and Safe Suggestions

**Files:**
- Create: `lib/localvault/cli/command_context.rb`
- Create: `lib/localvault/cli/suggestion_builder.rb`
- Test: `test/cli/contextual_help_test.rb`

- [ ] **Step 1: Write failing pure-helper tests**

Specify:

```ruby
context = CommandContext.resolve(LocalVault::CLI, %w[sync pull extra])
assert_equal LocalVault::CLI::Sync, context.command_class
assert_equal "pull", context.command.name

suggestions = SuggestionBuilder.new(context).suggestions
assert_operator suggestions.size, :<=, 6
assert_includes suggestions, "localvault sync pull [NAME]"
```

Cover top-level commands, registered subcommands, class/method option values,
`--` passthrough, long-description marker cleanup, deduplication, fallback
generation, and no positional-value reflection.

- [ ] **Step 2: Run and verify RED**

Run the contextual-help test and expect missing constants.

- [ ] **Step 3: Implement minimal pure helpers**

`CommandContext.resolve(root_class, argv)` returns a struct containing command
class, command metadata, command path, unresolved token, and valid options.
Traverse `CLI`'s `subcommands`/registered classes without invoking command code.
Skip recognized option values and stop semantic parsing after `--`.

`SuggestionBuilder` extracts lines containing `localvault <active path>` from
`long_description`, strips Thor's `\x05` marker and trailing comments, then
deduplicates and caps at six. Fall back to `formatted_usage` plus individual
options with placeholders. Unknown/ambiguous commands use names plus one-line
descriptions.

- [ ] **Step 4: Run and verify GREEN**

Run the focused test; expect zero failures.

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/cli/command_context.rb lib/localvault/cli/suggestion_builder.rb test/cli/contextual_help_test.rb
git commit -m "feat: derive contextual CLI suggestions"
```

### Task 3: Error Classification and Safe Rendering

**Files:**
- Create: `lib/localvault/cli/error_presenter.rb`
- Modify: `lib/localvault/cli.rb`
- Test: `test/cli/contextual_help_test.rb`

- [ ] **Step 1: Write failing integration tests**

Cover exact stderr for:

- `set group`: safe missing-value explanation and group-saving examples.
- `show --group-by`: nearest `--group` suggestion.
- `sh`: `share` and `show` candidates.
- invalid `sync`, `team`, and `keys` subcommands.
- extra positional values after `set`, using a sentinel secret and asserting it
  is absent from stderr.
- generic fallback that does not reuse Thor's argument-embedding message.

- [ ] **Step 2: Run and verify RED**

Expected: current terse Thor output and secret-reflection failures.

- [ ] **Step 3: Implement `ErrorPresenter`**

Classify by `Thor::UndefinedCommandError`, `Thor::AmbiguousCommandError`,
unknown switch-shaped argv, and arity mismatch. Build error text from command
metadata, never `error.message` for invocation errors. Render:

```text
Error: ...
Usage: ...

Did you mean ...?

Try:
  ...
```

Allow only command/option names in usage errors. Wire it into `CLI.start`.

- [ ] **Step 4: Run and verify GREEN**

Run focused tests plus:

```bash
bundle exec ruby -Ilib bin/localvault show --group-by
```

Expect safe actionable stderr and exit `1`.

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/cli.rb lib/localvault/cli/error_presenter.rb test/cli/contextual_help_test.rb
git commit -m "feat: render safe actionable CLI errors"
```

### Task 4: Group Catalog

**Files:**
- Create: `lib/localvault/group_catalog.rb`
- Test: `test/group_catalog_test.rb`

- [ ] **Step 1: Write failing catalog tests**

Exercise:

- namespace groups from hash values;
- first-underscore flat prefixes;
- omission of ungrouped scalar keys;
- same-spelling namespace/prefix merge with kind `mixed`;
- exact-case precedence;
- case-insensitive exact unique/ambiguous;
- case-insensitive prefix unique/ambiguous/absent;
- entry labels and counts for namespace, prefix, and mixed groups.

Desired API:

```ruby
catalog = LocalVault::GroupCatalog.new(secrets)
result = catalog.resolve("str")
assert_equal :ambiguous, result.kind
assert_equal %w[STRATUS STRIPE], result.groups.map(&:name)
```

- [ ] **Step 2: Run and verify RED**

Run `bundle exec ruby -Itest -Ilib test/group_catalog_test.rb`; expect missing class.

- [ ] **Step 3: Implement the catalog**

Use immutable structs for `Entry(label, value, source_kind)`,
`Group(name, kind, entries)`, and `Match(kind, query, groups)`. Sort groups and
entries deterministically. Merge only exact spelling into `mixed`; preserve
case-distinct names. Namespace entries use inner key labels and source
`:namespace`; prefix entries retain full flat-key labels and source `:prefix`.
Implement the five-step resolution order from the spec.

- [ ] **Step 4: Run and verify GREEN**

Run the catalog test; expect zero failures.

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/group_catalog.rb test/group_catalog_test.rb
git commit -m "feat: add searchable secret group catalog"
```

### Task 5: Group Listing and Filtered Show

**Files:**
- Modify: `lib/localvault/cli.rb`
- Modify: `lib/localvault/cli/error_presenter.rb`
- Modify: `test/cli_test.rb`
- Test: `test/group_catalog_test.rb`

- [ ] **Step 1: Write failing CLI tests**

Cover `groups`, `groups str`, empty search, exact/unique `show --group QUERY`,
ambiguous/absent stderr with status `1`, mixed rendering, masked/reveal values,
and bare `show --group` retaining named and ungrouped sections.

Add legacy compatibility cases for all true/false spellings, `--no-group`,
`--skip-group`, unique `show` prefixes, non-show commands, and `--` cutoff.

- [ ] **Step 2: Run and verify RED**

Run selected `cli_test.rb` names; expect missing command/string option failures.

- [ ] **Step 3: Implement group CLI behavior**

Add `groups [QUERY]`. Change show's `:group` option to optional string with a
private sentinel lazy default. Add a pre-dispatch normalizer scoped only to argv
whose first command resolves exactly/uniquely to `show`; normalize legacy
boolean spellings and stop at `--`.

For filtered show, use `GroupCatalog#resolve`; exact/unique renders.
Ambiguous/absent raises a structured `GroupSelectionError < Thor::Error`
containing only match kind, query, and catalog candidates. Extend
`ErrorPresenter` to format that error on stderr; the central boundary returns
`1`. Keep all values masked unless `--reveal`.

- [ ] **Step 4: Run and verify GREEN**

Run `test/cli_test.rb` and `test/group_catalog_test.rb`; expect zero failures.

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/cli.rb lib/localvault/cli/error_presenter.rb test/cli_test.rb test/group_catalog_test.rb
git commit -m "feat: search and display secret groups"
```

### Task 6: Guided Group Saving

**Files:**
- Modify: `lib/localvault/cli.rb`
- Modify: `lib/localvault/cli/error_presenter.rb`
- Modify: `test/cli_test.rb`
- Modify: `test/cli/contextual_help_test.rb`

- [ ] **Step 1: Write failing group-save tests**

Cover:

```ruby
LocalVault::CLI.start(%w[set --group STRIPE API_KEY value])
assert_equal "value", vault.get("STRIPE.API_KEY")
```

Also cover dotted-form equivalence, case-insensitive exact canonicalization, no
partial resolution, case ambiguity, invalid segments, scalar-name collision,
missing value help, and absence of supplied values from stderr.

The incomplete `set --group GROUP KEY` case fails in Thor before `set`
executes. `ErrorPresenter` must detect the group option in argv and render the
group-specific usage plus both save forms without reflecting argv values.

- [ ] **Step 2: Run and verify RED**

Expect unknown option or incorrect storage failures.

- [ ] **Step 3: Implement minimal save alias**

Add `method_option :group, type: :string` to `set`. Validate group and key as
single `Vault::KEY_SEGMENT_PATTERN` segments. Resolve only exact
case-sensitive/case-insensitive existing catalog names. Join `GROUP.KEY` and
delegate to `Vault#set`. Convert invalid/collision cases to structured safe
`GroupSaveError < Thor::Error` values containing only failure kind and catalog
candidates. Extend `ErrorPresenter` to render them centrally. Never print a
group, key, or value supplied to a failing save.

- [ ] **Step 4: Run and verify GREEN**

Run focused CLI tests; expect zero failures.

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/cli.rb lib/localvault/cli/error_presenter.rb test/cli_test.rb test/cli/contextual_help_test.rb
git commit -m "feat: save secrets into named groups"
```

### Task 7: Help, Documentation, and Verification

**Files:**
- Modify: `lib/localvault/cli.rb`
- Modify: `README.md`
- Modify: `docs/content/series/localvault/08-cli-reference.md`
- Modify: `test/cli_test.rb`

- [ ] **Step 1: Write failing help assertions**

Assert top-level and command help include `groups [QUERY]`,
`show --group [GROUP]`, `set --group GROUP KEY VALUE`, and contextual-error
examples.

- [ ] **Step 2: Run and verify RED**

Run focused help tests; expect missing text.

- [ ] **Step 3: Update help and docs**

Keep top-level help concise. Add curated long-description examples that the
suggestion builder can reuse.

- [ ] **Step 4: Run focused and full verification**

```bash
bundle exec ruby -Itest -Ilib test/cli/contextual_help_test.rb
bundle exec ruby -Itest -Ilib test/group_catalog_test.rb
bundle exec ruby -Itest -Ilib test/cli_test.rb
bundle exec rake test
git diff --check
```

Expected: all commands exit `0`; test output has zero failures/errors.

- [ ] **Step 5: Commit**

```bash
git add lib/localvault/cli.rb README.md docs/content/series/localvault/08-cli-reference.md test/cli_test.rb
git commit -m "docs: explain contextual group workflows"
```
