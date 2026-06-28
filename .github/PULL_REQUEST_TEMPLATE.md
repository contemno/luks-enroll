<!--
PR base should be `dev` (feature → dev → main). The dev → main PR is the release
promotion. Keep the diff scoped so the right CI checks run.
-->

## What & why

<!-- What does this change, and why now? Link the issue. -->

Closes #

## How it was verified

<!-- Commands run, tests added, manual checks. "Trust me" is not verification. -->

- [ ] Tests added or updated for the new behavior (and for any reconciled conflict)
- [ ] Lint/format pass locally
- [ ] Required CI checks reported green (a required check that never *ran* is not a pass)

## Re-sync with base

<!-- A clean diff against a STALE base hides regressions. See CONTRIBUTING.md. -->

- [ ] Rebased on the latest `dev`
- [ ] Checked `git log <branch-point>..origin/dev -- <changed files>`; if another PR
      touched these files, reconciled *intent* against the current `dev` version

## Docs moved (Done = docs updated)

- [ ] Updated the matching docs for this change, **or** N/A because: ___

## Project invariants

<!-- TODO: replace with YOUR must-not-break guarantees. Examples below. -->

- [ ] Does **not** change a frozen interface contract — or it does, and the
      contract + both sides + a test move together
- [ ] Preserves the project's core safety guarantee (or notes how it's affected)
