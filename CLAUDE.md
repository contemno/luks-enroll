# CLAUDE.md

Operating guide for Claude Code sessions (and humans) in this repo. It points to the
living sources instead of duplicating them, so it doesn't drift.

## The project

An unprivileged **Python GTK4 client** (`dist/usr/bin/luks-enroll`) talks over a **frozen
D-Bus contract** (`dbus/net.contemno.LuksEnroll1.xml`) to a privileged **Rust service**
(`rust/`, ships as `/usr/sbin/luks-enroll-service`). It enrolls FIDO2 tokens, TPM2 chips,
and recovery keys into LUKS2 volumes.

## Roadmap = GitHub (read before starting work)

- Source of truth: **[Roadmap issue #28](https://github.com/contemno/luks-enroll/issues/28)**
  plus milestones #1 (Rust client), #2 (arm64), #3 (crash-atomicity). Don't invent scope —
  check these first.
- Long-horizon work lives as an **issue under a milestone**, linked from #28 (its checklist
  auto-updates as issues close).
- New idea → open an issue under the right milestone and add a line to #28.

## Branching & promotion — PRs target `dev`

- Promotion flow: **`feature branch → dev → main`**.
- **Open every PR against `dev`. Never PR or push directly to `main`.** `main` is
  release-only; `dev → main` is the release promotion step.
- Branch from `dev`; name `claude/<topic>`. Reach `dev` through a PR, not a direct push.

## Work loop

1. Check #28 / the relevant milestone; pick or open the issue.
2. Branch from `dev`.
3. Open a PR with **base `dev`**, body containing `Closes #<issue>`.
4. On merge, GitHub closes the issue and ticks #28.

## Done = docs updated

Every change moves the matching artifact (or explicitly notes N/A):

| Change | Update |
|---|---|
| Service behavior / token JSON / D-Bus surface | the **parity & design** wiki page + a Rust test |
| Dependencies / architecture / project layout | **README.md** |
| New long-horizon work | an issue under a milestone + a line in **#28** |
| Notable decision or divergence | the parity page's *Accepted divergences* / *Implementation findings* |

## Reference docs (in the wiki, not this clone — fetch when relevant)

These are public wiki pages, not files in the repo, so a fresh session must fetch them
(WebFetch) when the work touches them:

- **Read before changing the service:**
  [Rust service — parity & design](https://github.com/contemno/luks-enroll/wiki/Rust-Service-Parity-and-Design)
  — systemd-cryptenroll parity contract, accepted divergences, testing strategy.
- [Rust Migration](https://github.com/contemno/luks-enroll/wiki/Rust-Migration) — why/how the
  service became Rust.
- [Refactor Plan](https://github.com/contemno/luks-enroll/wiki/Refactor-Plan) *(archived)* —
  the client-shrink plan; Phase 4 lives on as issue #24.

## Layout

- `rust/` — Cargo workspace: `service/` (D-Bus service + cryptsetup/TPM2/FIDO2/format) and
  `fido2-sys/` (bindgen FFI to libfido2). Service tests in `rust/service/tests/`.
- `dist/` — the non-Rust install tree (Python client, systemd unit, polkit/D-Bus/dracut config).
- `dbus/net.contemno.LuksEnroll1.xml` — **frozen** client↔service contract; change both sides
  together, deliberately.
- `tests/` — Python GUI-client tests (`conftest.py` is the GTK-shim importer).
- `debian/` — packaging; `debian/rules` builds the Rust service. `debian/changelog` is
  generated, not tracked.

## Build / test / lint

- Client: `ruff check .` · `ruff format --check .` · `python3 -m pytest tests/ -v`
- Service (from `rust/`): `cargo fmt --all --check` · `cargo clippy --workspace --all-targets
  -- -D warnings` · `cargo build --workspace` · `cargo test --workspace`
- Package: `make package` (builds the Rust service and assembles the `.deb`).

## CI

- `ci.yml` validates PRs and **classifies the diff** so unrelated jobs skip: `*.md`/LICENSE →
  docs (lint/test/rust skip); `rust/**` → Rust job; `*.py` / `tests/**` → Python jobs;
  anything else → both. Keep diffs scoped so the right checks run.
- The release pipeline (`autotag.yml` → `build-release.yml`) runs on push to `dev` (prerelease)
  and `main` (release).
- Note: `ci.yml`'s PR trigger currently keys on base `main`, so PRs into `dev` are validated
  post-merge by the release pipeline rather than at PR time.

## Don't

- Break the frozen D-Bus XML without updating client + service + a test.
- Hand-edit `debian/luks-enroll/` (the `dh` build directory) or generated files.
