# Repo Standard

A portable, drop-in baseline for new projects: GitHub Actions CI/release, issue
& PR templates, dependency hardening, and the process conventions behind them.

It is distilled from a real project (an unprivileged GTK4 client + privileged
Rust D-Bus service shipping as a `.deb`). The **patterns** here are
language-agnostic; the language-specific bits are marked as fill-in placeholders.

> This branch is an **orphan** — it shares no history with the project it was
> extracted from. Copy the tree into a new repository (or a GitHub `.github`
> template repo) and work through [`ADOPTING.md`](ADOPTING.md).

## What's in the box

```
.github/
  dependabot.yml                  # SHA/hash-pinned deps, auto-bumped, grouped
  PULL_REQUEST_TEMPLATE.md        # re-sync checklist + "docs moved?" gate
  ISSUE_TEMPLATE/
    config.yml                    # security → advisory, questions → discussions
    bug_report.yml                # form: pre-flight, validations, log scrubbing
    feature_request.yml           # form: includes a project-invariant checkbox
    task.yml                      # form: roadmap/maintainer task
    documentation.yml             # form: docs fix
  workflows/
    ci.yml                        # classify diff → skip-not-ignore → aggregator
    build-release.yml             # reusable build (the ONE build definition)
    autotag.yml                   # auto tag + release on push to dev/main
    release.yml                   # manual tag → release (same reusable build)
scripts/
  next-version.sh                 # next = max(patch-bump, ./VERSION floor)
  install-hooks.sh                # fast pre-push lint hook
VERSION                           # release-version floor (X.Y.Z)
STANDARD.md                       # the WHY — rationale for every non-obvious choice
ADOPTING.md                       # step-by-step adoption checklist
CONTRIBUTING.md                   # promotion flow + work loop
```

## The ideas worth keeping

- **Skip, don't ignore.** Required checks stay reachable and *skip* when their
  area is untouched — a skipped required job satisfies branch protection, a
  never-reported one wedges the PR.
- **Aggregator gate.** Fan a required check out into parallel jobs, then re-assert
  it with a one-line `if: always()` aggregator — refactor the job graph without
  touching branch-protection settings.
- **One build definition.** A reusable `workflow_call` workflow is shared by the
  manual and automated release paths so they can't drift.
- **Pin everything, bot the bumps.** Actions pinned to commit SHAs, app deps
  hash-pinned, Dependabot configured to bump both in lockstep.
- **Version floor.** Patch releases are automatic; a one-line `VERSION` bump cuts
  a minor/major. No human in the routine release loop.
- **Invariants at intake.** Surface your project's core guarantees as a checkbox
  on the issue/PR forms, where work is proposed.

See [`STANDARD.md`](STANDARD.md) for the reasoning behind each, including the
GitHub platform gotchas that motivated them.
