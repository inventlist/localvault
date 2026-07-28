# Contextual CLI Help

**Status:** Approved design
**Scope:** LocalVault CLI-wide usage and discovery errors

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
- extra words after boolean flags, such as `localvault show --group by`;
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

## Non-goals

- Rewriting the normal top-level help page.
- Adding shell completion scripts or an interactive command picker.
- Changing command names, argument shapes, or existing option semantics.
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

Suggestions are capped at six lines and ordered by relevance. They use
placeholders such as `VALUE`, `PROJECT`, and `VAULT` when the CLI cannot know a
real value.

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

### Boolean flag followed by an extra word

```console
$ localvault show --group by
Error: `--group` is already a complete flag and does not take a value; remove `by`.
Usage: localvault show

Try:
  localvault show --group
  localvault show --group --reveal
  localvault show --project PROJECT
```

### Misspelled option

```console
$ localvault show --group-by
Error: unknown option `--group-by`.

Did you mean `--group`?

Try:
  localvault show --group
  localvault show --project PROJECT
```

### Partial command

```console
$ localvault sh
Error: `sh` matches more than one command.

Try:
  localvault share [VAULT]   Share a vault with a user, team, or crew
  localvault show            Display secrets in a formatted table
```

The same behavior applies within registered namespaces, for example
`localvault sync pu` and `localvault team rotate unexpected`.

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
["team", "ro"]               -> LocalVault::CLI::Team / partial subcommand "ro"
```

The resolver reads Thor's registered commands, subcommands, positional usage,
class options, and method options. It does not open a vault, read configuration,
or execute command code.

Option values and `--` passthrough arguments are skipped while resolving
context. This prevents values that happen to match command names from changing
the diagnosis.

### 3. Error classifier

The presenter classifies a rescued error and resolved context into:

- unknown command or subcommand;
- ambiguous command or subcommand;
- unknown or misspelled option;
- missing positional argument;
- extra positional argument;
- boolean option incorrectly followed by a value;
- generic Thor usage error fallback.

Classification may improve Thor's wording but must not broaden the accepted
syntax. When a special case cannot be diagnosed confidently, the presenter uses
the generic error, correct usage, and safe suggestions.

Only command names, option names, and explicitly identified unexpected syntax
may be reflected. Supplied positional values are redacted from messages.

### 4. Suggestion builder

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

### 5. Boundaries

The implementation will keep three responsibilities independently testable:

- **Context resolver:** arguments and Thor metadata in, resolved command context
  out.
- **Suggestion builder:** resolved context and error category in, safe ordered
  suggestions out.
- **Error presenter:** error and original arguments in, formatted stderr output
  out.

The CLI start override only coordinates these units and returns the status.

## Error Handling and Safety

- Contextual help itself must never open or decrypt a vault.
- Positional argument contents are not printed, because `set` values and command
  passthrough arguments may be secrets.
- Unknown option names may be printed; attached option values must be stripped
  before display.
- Suggestion extraction failures fall back to Thor metadata and must never mask
  the original usage failure.
- Normal help and successful command output remain on stdout. Usage errors and
  their suggestions remain on stderr.
- Only parsing and invocation errors return the new status `1`; existing
  post-dispatch domain-error behavior is unchanged by this feature.

## Testing

### Unit coverage

- Resolve top-level and nested command contexts.
- Ignore option values and `--` passthrough content during resolution.
- Extract, normalize, deduplicate, order, and cap curated examples.
- Generate metadata fallback suggestions for commands without examples.
- Correct close command and option misspellings.
- Redact positional and attached option values.
- Diagnose boolean flags followed by extra words.

### CLI integration coverage

- `set` with a missing value prints safe contextual examples.
- `show --group by` explains boolean flag semantics.
- `show --group-by` suggests `--group`.
- partial and misspelled top-level commands suggest valid commands.
- partial and invalid `team`, `keys`, and `sync` subcommands suggest valid forms.
- valid commands and existing `help COMMAND` output remain unchanged.
- usage failures produce process status `1`; valid help produces status `0`.
- no usage-error output contains a representative secret value supplied on the
  command line.

The focused CLI tests run first, followed by the complete test suite.

## Documentation Impact

The CLI reference will gain a short “contextual errors” example. Existing
per-command examples remain the source material for suggestions, so commands
that add or change syntax should continue updating their long descriptions and
tests as they do today.

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
6. the full test suite passes.
