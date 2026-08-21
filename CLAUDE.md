# LocalVault Agent Instructions

> This file mirrors [AGENTS.md](AGENTS.md). Keep both files aligned when
> changing branch rules, boot order, or docs-harness routing.

This project inherits its shared documentation harness from
`../74-dev-docs`.

## Boot Order

1. Read this file and `AGENTS.md`.
2. Run `../74-dev-docs/scripts/agent-skill-router.sh .`.
3. Read `docs/INDEX.md` and `docs/PILLARS.md`.
4. Internal coordination (agent roster, threads, plans, sessions, backlog)
   lives in the private `../101.2-localvault-docs` repo, not here — this repo
   is public. Read `../101.2-localvault-docs/agents/00-roster.md` and run
   `../74-dev-docs/scripts/agent-thread-status.sh threads --me <alias> --me <role>`
   from inside `../101.2-localvault-docs`.
5. Read `../101.2-localvault-docs/plans/00-delivery-sequence.md` and the
   numbered plan being changed.

## Git and Plans — this repo is public

- Work on `main` unless the operator explicitly asks for a branch.
- **This repo (`inventlist/localvault`) is public.** All internal planning —
  `plans/`, `sessions/`, `backlog/`, `agents/`, `threads/` — lives in the
  private `inventlist/101.2-localvault-docs` repo instead, not here.
  `docs/plans/`, `docs/sessions/`, `docs/backlog/`, `docs/agents/`, and
  `docs/threads/` are gitignored in this repo for exactly that reason — if a
  tool is about to write into one of those paths, stop and write into
  `../101.2-localvault-docs` instead.
- Publish from `../101.2-localvault-docs` with the isolated bindings:
  `kuickr push --dir plans`, `kuickr push --dir sessions`,
  `kuickr push --dir backlog`, `kuickr push --dir ships`.
- The Kuickr destination is the dedicated `localvault` space —
  `kuickr.co/localvault/plans`, `.../sessions`, `.../backlog`, `.../ships`
  (all private) and `.../guide`, `.../series` (public showcase docs). The
  older `dev-docs-74/localvault-plans` and `localvault-sessions` folders
  predate this space and are superseded — do not publish to them.
- Never commit session notes, plans, backlog, or agent-coordination files to
  this repo, and do not copy LocalVault-specific plans into the shared
  `74-dev-docs` repo.

## Verification

- Run `bundle exec rake test` for the Ruby suite.
- Run `../74-dev-docs/scripts/docs-harness-doctor.sh docs` for docs shape.
- Run `kuickr status --dir plans` and `kuickr status --dir sessions` from
  inside `../101.2-localvault-docs` before and after publishing.
