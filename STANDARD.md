# The Standard — rationale

Why each piece is shaped the way it is. These are the non-obvious lessons; the
mechanics live in the files themselves (read alongside this). Skim the headings;
read the box only when you're about to change that piece.

---

## CI

### Classify the diff once, gate jobs with `if:`

A single `changes` job diffs the PR against its base and emits one boolean output
per area (`backend`, `frontend`, …). Every downstream job runs `if:
needs.changes.outputs.<area> == 'true'`. Docs-only PRs run nothing; a backend-only
PR skips the frontend suite. Anything unrecognized (build infra, CI itself) flips
*every* area on — misclassification fails safe toward running more, not less.

### Skip, don't ignore (the most important lesson)

The intuitive way to skip CI on docs is `paths-ignore` on the trigger. **Do not do
this for jobs that are required status checks.** A required check that never runs
never *reports*, and GitHub leaves the PR stuck "Expected — waiting for status"
forever. You cannot merge.

A **skipped** job is different: it reports a neutral result that branch protection
treats as satisfied. So keep required jobs reachable (no `paths-ignore`) and skip
them with `if:`. Same green PR on docs changes, without wedging the merge.

### The aggregator gate

When you split a required check into parallel jobs for speed (e.g. `build` +
`integration`), branch protection still points at one check name. Recreate that
name as a tiny aggregator job:

```yaml
gate:
  needs: [changes, build, integration]
  if: always() && needs.changes.outputs.area == 'true'
  steps:
    - run: |
        [ "${{ needs.build.result }}" = "success" ] || exit 1
        [ "${{ needs.integration.result }}" = "success" ] || exit 1
```

Two subtleties:
- **`if: always()`** is mandatory. Without it, when an upstream job fails the
  aggregator is reported *skipped* — which branch protection reads as **passing**.
  `always()` forces it to run and fail. (The `&& area == 'true'` keeps it a clean
  skip on PRs that don't touch the area at all.)
- This lets you reshape the job graph (add jobs, split, parallelize) without ever
  editing branch-protection settings — they only know the aggregator's name.

### One build definition (reusable workflow)

The build/package logic lives once in `build-release.yml` (`on: workflow_call`).
Both the manual path (`release.yml`, on a pushed tag) and the automated path
(`autotag.yml`) `uses:` it. There is exactly one place that knows how to build the
artifact, so the "manual release" and "auto release" can never produce different
outputs.

### Caching that actually helps

- **`shared-key`** across parallel jobs so they restore *one* warm cache instead of
  N cold ones (dependencies are identical across jobs that share a lockfile).
- **Distinct keys for distinct profiles.** Debug (PR) and release builds have
  different artifacts; one key would thrash. Key on the lockfile hash + profile.
- **Don't let `clean` wipe the cache.** Package builders often run a `clean` step
  first that deletes the very `target/`/cache dir you just restored. Use the
  builder's no-clean flag (`dpkg-buildpackage -nc`, `--no-clean`, etc.) on CI,
  where the checkout is already pristine.

### Concurrency intent differs by purpose

- **CI:** `cancel-in-progress: true`. New push supersedes the old run — don't pay
  for stale results.
- **Releases:** `cancel-in-progress: false`. Aborting a half-created tag or a
  half-published release leaves a mess. Let it finish; serialize per branch.

### Least privilege

`permissions: contents: read` at the top of every workflow. Elevate (`contents:
write`) only on the specific job that tags or publishes. Never grant write at the
workflow level "just in case".

---

## Releases

### Version floor: automatic patches, deliberate minors

`next = max(patch-bump-of-latest-release-tag, ./VERSION)`.

- Routine merges bump the **patch** automatically — no human touches a version.
- To cut a **minor/major**, bump the one-line `VERSION` file in the PR. The `max()`
  means that floor wins for exactly one release; afterward the patch-bump catches
  up and resumes. A stale floor never re-cuts or lowers a version.

This decouples "ship a fix" from "decide the version number" — the second is a
deliberate, reviewable one-line diff, the first is free.

### Two GitHub platform gotchas (documented because they cost real time)

1. **A tag pushed with the default `GITHUB_TOKEN` does not trigger
   `on: push: tags`.** GitHub suppresses this to prevent workflow loops. So
   `autotag.yml` can't rely on `release.yml` firing — it calls the reusable build
   workflow *directly* after creating the tag. (The alternative, a PAT/App token,
   adds a secret and risks the loop. Not worth it.)
2. **Immutable releases only accept assets while a draft.** Create the release as a
   *draft* with the assets attached, then flip `draft=false` in a second step.
   Attaching after publish fails.

### Trigger hygiene

The release trigger uses `paths-ignore` for changes that can't affect the shipped
artifact (`**.md`, `LICENSE`, `.github/**`, test-only dirs) so docs/CI commits
don't cut pointless releases and inflate the version. Carve-outs matter: package
metadata and the `VERSION` file are deliberately **not** ignored, so a lone version
bump still releases. (Note `paths-ignore` is all-or-nothing per push — a docs file
bundled with real code still releases.)

---

## Supply chain

- **Actions pinned to full commit SHAs**, with a trailing `# vX.Y.Z` comment for
  human readability. A moved tag can't swap the code under you.
- **Application/tooling deps hash-pinned** (`pip install --require-hashes`, lockfiles
  committed). Install fails if a published artifact changes.
- **Dependabot bumps both**, grouped (one PR per ecosystem, not per package) and
  targeting the integration branch (`dev`) so bumps flow through the normal gate.
  Dependabot understands the SHA-`# comment` convention and rewrites both together.

---

## Templates

### Issue *forms*, not markdown

YAML issue forms give you `validations: required`, dropdowns, and checkboxes —
structured intake instead of a blank box. The payoff: triagable fields (component,
version, environment) are present every time.

### `config.yml` routes the things that shouldn't be issues

- **Security → a private advisory.** Never let a vulnerability land as a public
  issue. This is the single most important contact link.
- **Questions → Discussions.** Keeps the tracker for actual defects/work.
- **Roadmap pointer** so contributors find planned work before re-proposing it.
- `blank_issues_enabled: true` so maintainers can still open planning/epic issues
  that fit no form.

### Invariants at intake (the idea most worth stealing)

Every project has a core guarantee it must not break. Put it as a checkbox on the
relevant form so the author confirms it the moment they propose the work:

- a frozen interface contract ("this may change `<contract file>` — both sides +
  a test must move together"),
- a safety property ("this preserves the *you-can-never-lock-yourself-out*
  guarantee, or I've noted how it affects it").

Replace the placeholders with *your* invariants. This catches contract/safety
regressions at proposal time, not in review.

### Log scrubbing reminders

If issues will carry logs, the form should both ask for the exact command
(`journalctl -u … --no-pager`) and warn, inline, never to paste secrets. Make the
safe path the easy path.

---

## Process (see CONTRIBUTING.md)

- **Promotion flow `feature → dev → main`.** PRs target `dev`; `main` is
  release-only. `dev → main` is the release promotion.
- **Re-sync with base before "ready" — and after every conflict resolution.** A
  clean diff against a *stale* base hides regressions: if another PR changed the
  same code on `dev` after you branched, your hunks can silently revert it.
  Rebase, check what else touched your files, and treat the conflict resolution as
  authored code that needs its own test. (This rule exists because of a real
  near-miss where two PRs silently reverted each other's change to shared code.)
- **Done = docs moved.** Every change moves its matching doc/test or explicitly
  notes N/A — enforced by a line in the PR template.
- **Fast local pre-push hook.** Lint + syntax only (~seconds); full tests run in
  CI. Fast enough that nobody disables it.
