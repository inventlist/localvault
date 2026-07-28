# Contextual CLI Help

**Status:** Draft revision — awaiting user review
**Scope:** LocalVault CLI-wide usage help and group discovery

## Problem

LocalVault has useful command descriptions and examples, but Thor discards most
of that context when invocation fails. Incomplete or nearly correct commands
therefore produce terse output such as:

```text
ERROR: "localvault set" was called with arguments ["group"]
Usage: "localvault set KEY VALUE"
```

The user must already know to run a separate help command and translate its
contents back to the failed invocation. This is especially awkward for:

- missing positional arguments, such as `localvault set group`;
- discovering stored group names before showing or adding secrets;
- saving into a group without already knowing the dot-notation convention;
- misspelled flags, such as `localvault show --group-by`;
- partial or misspelled commands and subcommands;
- nested namespaces such as `team`, `keys`, and `sync`.

## Goals

1. Make every CLI usage error explain the next useful action in the same output.
2. Suggest runnable, context-specific command forms rather than only a bare
   usage signature.
3. Cover top-level commands and every registered subcommand through one shared
   mechanism.
4. Reuse Thor command metadata and existing long-description examples so help
   does not become a second hand-maintained command registry.
5. Preserve secret safety by never reflecting positional values in usage-error
   output.
6. Return a nonzero process status for CLI usage errors without forcing
   `SystemExit` on callers that invoke `LocalVault::CLI.start` in-process.
7. Make stored groups discoverable by partial name and make saving into a group
   obvious without requiring users to know dot notation in advance.

## Non-goals

- Rewriting the normal top-level help page.
- Adding shell completion scripts or an interactive command picker.
- Removing or breaking existing command forms, including `show --group` and
  `set GROUP.KEY VALUE`.
- Reformatting domain errors produced after a valid command begins execution,
  such as authentication, network, decryption, or missing-vault failures.
- Generating every possible option permutation. Suggestions must remain short
  and intentional.

## User Experience

Usage failures use one consistent structure:

```text
Error: <concise explanation>
Usage: <correct command signature>

Try:
  <runnable or placeholder-based example>
  <runnable or placeholder-based example>
```

The `Try:` block is capped at six suggestion lines and ordered by relevance.
They use placeholders such as `VALUE`, `PROJECT`, and `VAULT` when the CLI
cannot know a real value.

### Missing arguments

```console
$ localvault set group
Error: `set` needs both a key and a value.
Usage: localvault set KEY VALUE

Try:
  localvault set API_KEY VALUE
  localvault set project.API_KEY VALUE
  localvault set project.DATABASE_URL postgres://...
```

The error must not echo any supplied secret value.

### Find stored groups

```console
$ localvault groups str
Groups matching `str` in vault `default`:

  Group         Keys   Kind
  STRIPE        4      namespace
  STRATUS       2      flat prefix
```

Group search uses case-insensitive prefix matching, not substring matching. With
no query, `groups` lists every group. It lists names, key counts, and whether
each group is a dot-notation namespace or an inferred flat-key prefix; it never
prints values. A query with no matches prints `No groups match QUERY` on stdout
and exits `0`, because an empty search result is not a command failure.

`localvault show --group QUERY` uses the same catalog. An exact or unique match
shows that group's masked table. Multiple matches list candidates and runnable
`show --group GROUP` forms. No match reports the query and points to
`localvault groups`.

Resolution order is deterministic:

1. an exact case-sensitive name wins;
2. otherwise, one case-insensitive exact match wins;
3. multiple case-insensitive exact matches are ambiguous;
4. otherwise, case-insensitive prefix matches are considered;
5. one prefix match wins, multiple are ambiguous, and zero are absent.

An exact or unique match prints the normal table on stdout and exits `0`.
Ambiguous or absent `show` queries print candidate/help output on stderr and
exit `1`.

`localvault show --group` with no query preserves its current behavior of
rendering all groups.

If namespace and flat-prefix keys have the exact same group name, the catalog
returns one group with kind `mixed` and a combined key count. Namespace keys
keep their inner labels in the table; flat keys keep their full labels. If
groups differ only by letter case, an exact-case query wins; a non-exact query
lists both matches rather than guessing.

### Save into a group

```console
$ localvault set --group STRIPE API_KEY sk_live_...
Set API_KEY in group `STRIPE` in vault `default`.

Stored as:
  STRIPE.API_KEY
```

This is a discoverable alias for the existing
`localvault set STRIPE.API_KEY VALUE` form. Incomplete group saves show both
forms and point to `localvault groups [QUERY]`:

```console
$ localvault set --group STRIPE API_KEY
Error: saving in a group needs GROUP, KEY, and VALUE.
Usage: localvault set --group GROUP KEY VALUE

Try:
  localvault set --group GROUP KEY VALUE
  localvault set GROUP.KEY VALUE
  localvault groups [QUERY]
```

The error output does not repeat the supplied group, key, or value.

Saving does not resolve partial group names. An exact case-sensitive group name
is used as written; otherwise, one case-insensitive exact catalog match is
canonicalized to its stored spelling. Multiple case-insensitive exact matches
are rejected with candidates. When no exact match exists, the supplied spelling
creates a new namespace. Invalid group or key segments print a safe error on
stderr and exit `1`; the secret value is never reflected.

If a scalar secret already occupies the exact proposed top-level group name,
the command cannot create that namespace. It prints
`Cannot create group: that name is already used by a secret key` on stderr and
exits `1`, without reflecting the group, key, or value.

### Misspelled option

```console
$ localvault show --group-by
Error: unknown option `--group-by`.
Usage: localvault show

Did you mean `--group`?

Try:
  localvault show --group GROUP
  localvault groups [QUERY]
  localvault show --project PROJECT
```

### Partial command

```console
$ localvault sh
Error: `sh` matches more than one command.
Usage: localvault COMMAND

Try:
  localvault share [VAULT]   Share a vault with a user, team, or crew
  localvault show            Display secrets in a formatted table
```

The same behavior applies within registered namespaces, for example
`localvault sync unknown` and `localvault team rotate one two`.

Thor accepts a unique command prefix as valid syntax. This feature preserves that
behavior: a unique prefix continues to dispatch normally, while ambiguous or
unknown prefixes receive contextual suggestions. It does not introduce a new
pre-dispatch rejection policy.

## Design

### 1. Central usage-error boundary

`LocalVault::CLI.start` will own dispatch instead of allowing
`Thor::Base.start` to print usage errors directly. It will:

1. dispatch the original argument vector through Thor;
2. return success status on normal completion;
3. rescue only `Thor::Error`;
4. send the error and original arguments to the contextual error presenter;
5. return status `1`;
6. retain Thor's existing broken-pipe behavior.

`bin/localvault` will exit with the returned status. In-process test and library
callers may inspect or ignore that integer without having to rescue
`SystemExit`.

Runtime exceptions outside the Thor usage-error family continue to propagate as
they do today.

### 2. Command-context resolver

A small resolver maps the original argument vector to the deepest known Thor
command class and command:

```text
["show", "--group-by"]       -> LocalVault::CLI / show
["sync", "pull", "extra"]    -> LocalVault::CLI::Sync / pull
["team", "unknown"]          -> LocalVault::CLI::Team / unknown subcommand
```

The resolver reads Thor's registered commands, subcommands, positional usage,
class options, and method options. It does not open a vault, read configuration,
or execute command code.

Option values and `--` passthrough arguments are skipped while resolving
context. This prevents values that happen to match command names from changing
the diagnosis.

### 3. Group catalog

A shared group catalog derives groups from decrypted vault keys using the same
rules as the current grouped table:

- a top-level hash is a dot-notation namespace;
- flat keys containing `_` are grouped by their first underscore-delimited
  prefix;
- flat keys without `_` remain ungrouped and are not returned as groups.

The catalog exposes group name, key count, kind, and case-insensitive matching.
It is used by both `groups [QUERY]` and `show --group [QUERY]`, keeping search
and display semantics consistent.

The catalog returns an explicit match result: `exact`, `unique`, `ambiguous`, or
`absent`. Callers format that result for their command rather than reimplementing
matching rules.

`groups` and group-filtered `show` are valid vault-reading commands, so they use
the normal vault-opening/session flow. The parse-error presenter does not open a
vault or attempt to discover dynamic group names.

Thor's `--group` option becomes an optional string with a lazy default sentinel:
no supplied value means “all groups,” preserving the existing boolean form;
a supplied value is a group query.

Before Thor dispatch, a narrow compatibility normalizer preserves every legacy
boolean spelling for the `show` command:

- `--group`, `--group=true`, `--group true`, `--group=TRUE`, and the existing
  `t`/`T` variants mean “show all groups”;
- `--group=false`, `--group false`, `--group=FALSE`, the existing `f`/`F`
  variants, `--no-group`, and `--skip-group` mean “do not group.”

Those boolean words are reserved and cannot be used as a group query through
`show --group`; `groups QUERY` can still discover them. All other supplied
values are group queries.

The normalizer runs only when Thor resolves the top-level command exactly or by
a unique prefix to `show`, and it stops processing at `--`. It never rewrites
`set --group ...`, another command's arguments, or passthrough arguments.

`set --group GROUP KEY VALUE` validates `GROUP` and `KEY` as individual vault
key segments, joins them as `GROUP.KEY`, then uses the existing `Vault#set`
path. The existing dotted form remains unchanged.

Group display/save failures use a structured `Thor::Error` subclass containing
only the failure kind and safe group metadata, never a secret value. It reaches
the same central boundary as usage errors, which formats stderr and returns
status `1`. This avoids incidental Ruby method return values controlling the
process status.

### 4. Error classifier

The presenter classifies a rescued error and resolved context into:

- unknown command or subcommand;
- ambiguous command or subcommand;
- unknown or misspelled option;
- missing positional argument;
- extra positional argument;
- ambiguous or absent group selection;
- invalid or case-ambiguous group save target;
- generic Thor usage error fallback.

Classification may improve Thor's wording but must not broaden the accepted
syntax. When a special case cannot be diagnosed confidently, the presenter uses
the generic error, correct usage, and safe suggestions.

For parse and usage failures, only command and option names may be reflected;
supplied positional and option values are never reflected. Valid group
discovery commands may display the user's group query and catalog-derived group
names, because those are the requested discovery result. Structured
`show --group` failures may display the query and catalog candidates, but never
secret keys or values. Structured `set --group` failures may display catalog
candidates, but never reflect the raw supplied group, key, or value.

### 5. Suggestion builder

Suggestions come from two sources:

1. Existing curated `localvault ...` examples in the active command's long
   description.
2. Thor metadata-derived fallbacks: the command usage, corrected command or
   option names, and individual valid option forms.

Curated examples are preferred because they encode meaningful combinations.
Metadata fallbacks ensure commands without a long description still receive
useful output.

The builder normalizes Thor's formatting markers, removes comments and duplicate
forms, keeps only examples for the active command path, and caps output at six
suggestions. It does not compute the full power set of options.

For unknown or ambiguous commands, suggestions instead show matching command
names with their one-line Thor descriptions.

### 6. Boundaries

The implementation will keep four responsibilities independently testable:

- **Context resolver:** arguments and Thor metadata in, resolved command context
  out.
- **Group catalog:** a vault key structure in, searchable group metadata out.
- **Suggestion builder:** resolved context and error category in, safe ordered
  suggestions out.
- **Error presenter:** error and original arguments in, formatted stderr output
  out.

The CLI start override only coordinates these units and returns the status.

## Error Handling and Safety

- Contextual help itself must never open or decrypt a vault.
- Positional and option-value contents are not printed in parse/usage failures,
  because `set` values and command passthrough arguments may be secrets.
- Valid `groups` output and structured group-selection failures may print the
  group query and catalog group names under the narrower discovery rules above;
  they never print secret keys or values.
- Unknown option names may be printed; attached option values must be stripped
  before display.
- The presenter constructs safe error text from the error category and command
  metadata. It must not reuse Thor's native invocation message because that
  message embeds the full positional argument array.
- Suggestion extraction failures fall back to Thor metadata and must never mask
  the original usage failure.
- Normal help and successful command output remain on stdout. Usage errors and
  their suggestions remain on stderr.
- Parsing/invocation errors, ambiguous or absent `show --group` lookups, and
  invalid or case-ambiguous `set --group` targets return status `1` from
  in-process `CLI.start` and from the executable. Empty `groups` searches are
  successful and return `0`.
- Existing post-dispatch domain-error behavior outside the new group commands is
  unchanged by this feature.

## Testing

### Unit coverage

- Resolve top-level and nested command contexts.
- Ignore option values and `--` passthrough content during resolution.
- Extract, normalize, deduplicate, order, and cap curated examples.
- Generate metadata fallback suggestions for commands without examples.
- Correct close command and option misspellings.
- Redact positional and attached option values.
- Search namespace and flat-prefix groups case-insensitively.
- Preserve all-groups behavior when `--group` has no value.
- Resolve exact-case, case-insensitive exact, unique-prefix, ambiguous, and
  absent group matches.
- Merge same-spelling namespace and flat-prefix groups as `mixed`.
- Prefer an exact-case group when case-distinct names otherwise collide, and
  report ambiguous non-exact case collisions.
- Build `GROUP.KEY` safely for the group-saving alias.
- Canonicalize only case-insensitive exact group names on save; never resolve a
  partial group name while writing.
- Reject group creation when a scalar secret already occupies the top-level
  name.
- Normalize legacy boolean spellings only for exact or uniquely prefixed
  `show`, and stop normalization at `--`.

### CLI integration coverage

- `set` with a missing value prints safe contextual examples.
- `groups`, `groups str`, and a no-match query list safe group metadata.
- `show --group`, exact, unique-prefix, ambiguous-prefix, absent, mixed-source,
  exact-case collision, and non-exact case-collision queries behave consistently
  with the group catalog.
- bare `show --group` continues rendering ungrouped keys after named groups.
- legacy `--group=true`, `--group true`, `t`/`T`, `--group=false`,
  `--group false`, `f`/`F`, `--no-group`, and `--skip-group` forms preserve
  their current behavior.
- legacy normalization works through a unique `show` prefix but never rewrites
  another command or content after `--`.
- `set --group STRIPE API_KEY VALUE` stores the same key as
  `set STRIPE.API_KEY VALUE`.
- `set --group stripe ...` canonicalizes an existing unique `STRIPE` name,
  rejects case-ambiguous names, and creates a literal namespace only when no
  exact case-insensitive group exists.
- invalid `GROUP` and `KEY` segments fail safely without reflecting the value.
- a scalar/group-name collision fails safely without replacing the scalar.
- an incomplete `set --group` invocation explains both group-saving forms
  without reflecting supplied values.
- `show --group-by` suggests `--group`.
- ambiguous and misspelled top-level commands suggest valid commands while
  unique prefixes retain Thor's existing dispatch behavior.
- ambiguous and invalid `team`, `keys`, and `sync` subcommands suggest valid
  forms.
- valid commands and existing `help COMMAND` output remain unchanged.
- usage failures produce process status `1`; valid help produces status `0`.
- no usage-error output contains a representative secret value supplied on the
  command line.
- generic fallback output does not contain positional values from Thor's native
  invocation message.

The focused CLI tests run first, followed by the complete test suite.

## Documentation Impact

The CLI reference will gain a short “contextual errors” example. Existing
per-command examples remain the source material for suggestions, so commands
that add or change syntax should continue updating their long descriptions and
tests as they do today.

The command reference and top-level help will also document `groups [QUERY]`,
`show --group [GROUP]`, and `set --group GROUP KEY VALUE`.

## Acceptance Criteria

The feature is complete when:

1. every Thor usage error at the top level or in a registered namespace includes
   a concise explanation and safe next-step suggestions;
2. `show`, `set`, `team`, `keys`, and `sync` demonstrate the expected contextual
   behavior in integration tests;
3. suggestion output is relevant, deduplicated, and never exceeds six entries;
4. usage failures exit `1` in the executable while in-process callers receive a
   return status;
5. successful invocations and existing normal help remain behaviorally
   compatible;
6. stored groups can be searched and shown by partial name without revealing
   secret values;
7. users can save into a group through either the guided `--group` form or the
   existing dotted-key form;
8. the full test suite passes.
