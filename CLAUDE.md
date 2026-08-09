# LocalVault Agent Instructions

> This file mirrors [AGENTS.md](AGENTS.md). Keep both files aligned when
> changing branch rules, boot order, or docs-harness routing.

This project inherits its shared documentation harness from
`../74-dev-docs`.

## Boot Order

1. Read this file and `AGENTS.md`.
2. Run `../74-dev-docs/scripts/agent-skill-router.sh .`.
3. Read `docs/INDEX.md`, `docs/agents/00-roster.md`, and `docs/PILLARS.md`.
4. Run `../74-dev-docs/scripts/agent-thread-status.sh docs --me <alias> --me <role>`.
5. Read `docs/plans/00-delivery-sequence.md` and the numbered plan being changed.

## Git and Plans

- Work on `main` unless the operator explicitly asks for a branch.
- `docs/plans/` and `docs/sessions/` are internal. Both are intentionally
  ignored by Git and published only to private Kuickr folders.
- Publish from the isolated bindings with:
  `kuickr push --dir docs/plans` and `kuickr push --dir docs/sessions`.
- The Kuickr destinations are
  `https://kuickr.co/dev-docs-74/localvault-plans` (numbered plans) and
  `https://kuickr.co/dev-docs-74/localvault-sessions` (session and release
  records). Both are private; keep them that way.
- Never commit session notes or plans to this repo, and do not copy
  LocalVault-specific plans into the shared `74-dev-docs` repo.

## Verification

- Run `bundle exec rake test` for the Ruby suite.
- Run `../74-dev-docs/scripts/docs-harness-doctor.sh docs` for docs shape.
- Run `kuickr status --dir docs/plans` and `kuickr status --dir docs/sessions`
  before and after publishing.
