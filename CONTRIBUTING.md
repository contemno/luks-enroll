# Contributing

> Template — adjust names/links for your project. The flow below is the standard's
> default; the rationale is in [`STANDARD.md`](STANDARD.md) → *Process*.

## Branching & promotion

Promotion flow: **`feature branch → dev → main`**.

- Branch from `dev`; name `<topic>` (or `claude/<topic>` for agent work).
- **Open every PR against `dev`.** `main` is release-only; `dev → main` is the
  release promotion step.
- Releases are auto-tagged. The version is `max(patch-bump, ./VERSION)`. Patch
  releases are automatic — to cut a **minor/major**, bump `VERSION` in the `dev` PR.

## Work loop

1. Pick or open an issue (use the forms in `.github/ISSUE_TEMPLATE/`).
2. Branch from `dev`.
3. Open a PR with **base `dev`**, body containing `Closes #<issue>`.
4. On merge, the issue closes and the release pipeline runs on `dev`.

## Before a PR is ready (and after each conflict resolution)

A clean diff against a *stale* base hides regressions. Before marking ready — and
again after resolving any conflict:

1. **Re-sync with base.** `git fetch origin dev` and rebase.
2. **Check what else touched your files:**
   `git log --oneline <branch-point>..origin/dev -- <file>`. If another PR changed
   it, read the **current `dev` version** of the functions you're editing and
   reconcile *intent* — don't just re-apply your hunks.
3. **Treat the conflict resolution as authored code** — pin each side's intent
   with a test.
4. **Confirm the gates are green** locally and that the PR's required checks
   actually reported (a required check that never ran is not a pass).
5. **Move the docs** (see below).

## Done = docs updated

Every change moves its matching artifact, or explicitly notes N/A. The PR template
has a checkbox for this — keep it honest.

## Local hooks

Run `./scripts/install-hooks.sh` once to install the fast pre-push lint hook.
