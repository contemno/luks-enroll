<!--
PR base should be `dev` (feature branches → dev → main; see CLAUDE.md). Never
open a PR or push directly against `main` — that branch is release-only and
is promoted from `dev` via a merge commit, not a rebase or squash.
-->

## What & why

<!-- Summary of the change and the problem it solves. Link the issue: Closes #___ -->

## Re-sync with base

- [ ] Rebased/merged onto current `origin/dev` — a branch behind `dev` hasn't
      been tested against the code it will merge into.
- [ ] For each changed file, checked `git log <branch-point>..origin/dev -- <file>`:
      if another PR touched it, I read the **current `dev` version** of the
      functions I'm editing and reconciled *intent*, not just re-applied my hunks
      (see the #29/#35 near-miss in CLAUDE.md for why this matters).
- [ ] Any conflict resolution is treated as authored code: a test from each
      side's intent passes, and any reconciled behavior not already pinned by
      a test has one added.

## Docs moved

- [ ] Service behavior / token JSON / D-Bus surface → the
      [parity & design](https://github.com/contemno/luks-enroll/wiki/Rust-Service-Parity-and-Design)
      wiki page + a Rust test updated, or N/A
- [ ] Dependencies / architecture / project layout → **README.md** updated, or N/A
- [ ] New long-horizon work → an issue under a milestone + a line in
      [#28](https://github.com/contemno/luks-enroll/issues/28), or N/A
- [ ] Notable decision or divergence → the parity page's *Accepted
      divergences* / *Implementation findings*, or N/A

## Project invariants

- [ ] Does **not** break the frozen D-Bus contract
      (`dbus/net.contemno.LuksEnroll1.xml`) without updating client + service
      + a test together, or N/A
- [ ] Does not hand-edit `debian/luks-enroll/` (the `dh` build directory) or
      other generated files (e.g. `debian/changelog`)
- [ ] Build / test / lint gates ran locally and are green (client:
      `ruff check .`, `ruff format --check .`, `pytest tests/`; service, from
      `rust/`: `cargo fmt --all --check`, `cargo clippy --workspace
      --all-targets -- -D warnings`, `cargo build --workspace`, `cargo test
      --workspace`), and the PR's required checks actually reported
