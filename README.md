# LUKS Enroll Wizard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A GTK4/libadwaita wizard for managing LUKS2 disk encryption on Linux. Enrolls FIDO2 tokens, TPM2 chips, and recovery keys into a LUKS-encrypted root volume, then optionally removes the original password keyslot.

Designed to run on first login, from a normal desktop session, or inside an installer chroot with `/dev`, `/sys`, and `/proc` bind-mounted.

## Features

- **FIDO2 enrollment** with PIN, multiple tokens per device, hotplug detection
- **TPM2 enrollment** with optional PIN and configurable PCR selection
- **Recovery keys** — generate one or more high-entropy passphrases per device
- **Passphrase management** — add, remove, change keyslots
- **Encrypted USB formatting** — GPT + LUKS2 in a single workflow
- **Encrypted image files** — create and enroll loop-mounted LUKS containers
- **Auto-detection** of all LUKS devices, FIDO2 tokens, and TPM2 chips
- **Per-enrollment wipe controls** with auth-keyslot protection so you can never lock yourself out
- **systemd-cryptsetup compatible token format** — the same keyslots work for initramfs unlock
- **In-process crypto** against libcryptsetup, libfido2, and libtss2 — zero subprocess calls into the cryptsetup CLI

## Architecture

The application is split between an unprivileged GTK client (Python) and a privileged D-Bus system service (Rust):

```
┌─────────────────────┐  D-Bus system bus   ┌──────────────────────────┐
│  luks-enroll        │ ──────────────────► │  luks-enroll-service     │
│  (user, GTK4 GUI)   │  net.contemno       │  (root, bus-activated)   │
│  Python, ~2,400 LOC │  .LuksEnroll1       │  Rust                    │
│                     │ ◄────────────────── │                          │
└─────────────────────┘                     └──────────────────────────┘
                                                       │
                                                       │ typed crates
                                                       ▼
                                       libcryptsetup-rs, fido2-sys,
                                       tss-esapi, libblkid-rs, gpt
```

- **`/usr/bin/luks-enroll`** — unprivileged GTK4/libadwaita client, written in Python. Talks to the service over the system bus, runs all blocking calls in background threads, and updates the UI via `GLib.idle_add()`.
- **`/usr/sbin/luks-enroll-service`** — bus-activated D-Bus service running as root, written in Rust and built from the [`rust/`](rust/) workspace. All crypto runs in-process through typed crates: `libcryptsetup-rs` (with the `mutex` feature serializing the not-thread-safe library), `tss-esapi` for TPM2, an in-repo `fido2-sys` bindgen crate for libfido2, and `libblkid-rs` + the pure-Rust `gpt` crate for formatting. Volume-key material is held in `zeroize`-backed buffers.
- **D-Bus name:** `net.contemno.LuksEnroll`, object `/net/contemno/LuksEnroll`, interface `net.contemno.LuksEnroll1`. The contract is frozen in [`dbus/net.contemno.LuksEnroll1.xml`](dbus/net.contemno.LuksEnroll1.xml) so the client and service evolve independently.
- **Polkit actions:** `net.contemno.luks-enroll.read` (auth-cached for inspection), `net.contemno.luks-enroll.manage` (required for any destructive change).
- **systemd hardening:** the service unit runs with `ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_UNIX`, a minimal capability bounding set, and explicit `DeviceAllow` rules for block, hidraw, tpm, and tpmrm device classes.
- **File-descriptor passing:** operations on encrypted *file* containers under `$HOME` use the `*Fd` D-Bus methods — the unprivileged client opens the container it owns and passes the descriptor over the bus, so the header write goes through the user's writable mount while the service keeps `ProtectHome=read-only`. Block devices keep the path-based methods (the client cannot open a `/dev` descriptor).

## Initramfs unlock

The package ships [`/etc/dracut.conf.d/luks-enroll.conf`](dist/etc/dracut.conf.d/luks-enroll.conf), which conditionally adds the `fido2` and `tpm2-tss` dracut modules and pulls in the matching `libcryptsetup-token-systemd-*.so` plugins. The conf file is sourced as shell, so it is a no-op on systems without the relevant libraries — and a no-op entirely if dracut is not installed.

After enrolling a token, regenerate the initramfs (`dracut --force` or `update-initramfs -u`) and add the appropriate `crypttab` options:

```
crypt-root  UUID=...  none  tpm2-device=auto,fido2-device=auto,luks,discard
```

## Project layout

```
rust/                              Privileged service (Rust workspace)
  service/                         luks-enroll-service crate
    src/                           D-Bus service + cryptsetup/TPM2/FIDO2/format logic
    tests/                         LUKS2 image-file, D-Bus e2e, fd-passing, config-parity integration tests
      common/mod.rs                Shared test harness (temp-dir, LUKS-image factory, passphrase)
  fido2-sys/                       bindgen FFI to libfido2 (built against system headers)

dist/                              Mirrors the install hierarchy for the non-Rust files:
  usr/bin/luks-enroll              GTK4 client (Python)
  usr/share/dbus-1/                Bus policy + activation
  usr/share/polkit-1/actions/      Polkit policy
  usr/share/applications/          Desktop launcher
  etc/dracut.conf.d/               Initramfs module config
  etc/luks-enroll.conf             Runtime config (writable)
  lib/systemd/system/              Hardened systemd unit

dbus/
  net.contemno.LuksEnroll1.xml     Frozen D-Bus interface contract (client ⇄ service)

debian/                            Debian packaging
  luks-enroll.install              Install map: dist/* + the compiled service binary -> /
  rules                            Builds the Rust workspace (cargo build --release --locked)
  postinst / prerm                 Reload D-Bus; stop the service on upgrade/removal
  control / copyright              changelog is generated, not tracked

tests/
  test_luks_enroll.py              GUI client unit tests (Python)
  conftest.py                      Shared GTK-shim test importer

VERSION                            Release-version floor (X.Y.Z); bump for a minor/major release
scripts/                           Developer tooling (git hooks, changelog + next-version)
.github/workflows/                 CI (Python lint+tests, Rust fmt/clippy/build/test) and releases
.github/actions/                   Reusable composite actions (install-c-deps, python-setup)
```

[`debian/rules`](debian/rules) compiles the Rust service (`cargo build --release --locked`) and `dh_install` copies `dist/*` plus the built binary into place per [`debian/luks-enroll.install`](debian/luks-enroll.install). The service tests live in the Rust workspace ([`rust/service/tests/`](rust/service/tests/)); the Python suite under [`tests/`](tests/) covers the GUI client.

## Dependencies

**Runtime (required):**

- Python 3, PyGObject (`python3-gi`)
- GTK 4 (`gir1.2-gtk-4.0`), libadwaita (`gir1.2-adw-1`)
- systemd (>= 248)
- `libcryptsetup12`, `libblkid1`
- `libfido2-1` (FIDO2)
- `libtss2-esys`, `libtss2-mu` (TPM2)
- polkit (`polkitd` or `policykit-1`)

**Runtime (optional):**

- `tpm2-tools` (recommended)
- `dracut` (suggested — for initramfs unlock)

**Build (from source):**

- Rust toolchain (`cargo`/`rustc`) — install via rustup; the workspace's `Cargo.lock` is v4 and some crate MSRVs exceed the rustc shipped by stable Debian/Ubuntu
- `pkg-config`, `clang`, `libclang-dev` (the last two drive `fido2-sys`'s bindgen build script)
- `libcryptsetup-dev`, `libblkid-dev`, `libfido2-dev`, `libtss2-dev`

## Install

### From .deb

```sh
sudo apt install ./luks-enroll_*.deb
```

The package is `Architecture: any` — it ships the compiled Rust service, so install a build that matches your CPU architecture (releases are currently amd64-only).

### Build from source

```sh
make package                              # compiles rust/ and assembles the .deb under target/
sudo apt install ./target/luks-enroll_*.deb
```

`make package` runs `dpkg-buildpackage`, which builds the Rust workspace (`cargo build --release --locked`) and installs both the Python client and the compiled service.

## Usage

```sh
luks-enroll                 # management view
```

## Development

The repository is two codebases behind one frozen D-Bus contract: a Python GTK client (`dist/usr/bin/luks-enroll`, tested by `tests/`) and a Rust service (`rust/`).

```sh
# Install git hooks (pre-push lint + checks)
./scripts/install-hooks.sh

# Python client: lint + tests
ruff check .
ruff format --check .
python3 -m pytest tests/ -v

# Rust service: format, lint, build, test (from rust/)
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
cargo test --workspace
```

The Rust suite includes LUKS2 image-file integration tests and a D-Bus end-to-end suite that both run without root or hardware; TPM2 seal/unseal roundtrips run against `swtpm` in CI.

### Building the .deb

```sh
make package
# or directly:
dpkg-buildpackage -us -uc -b
```

The build regenerates [`debian/changelog`](debian/changelog) from git history (see [`scripts/gen-changelog.sh`](scripts/gen-changelog.sh)) — the changelog is not tracked in git.

## Releases

Tags trigger GitHub Actions builds. Version scheme:

| Tag             | Debian version  | Type                                             |
|-----------------|-----------------|--------------------------------------------------|
| `v1.0.0`        | `1.0.0-1`       | Production                                       |
| `v1.0.0-dev.1`  | `1.0.0~dev1-1`  | Development (sorts lower, won't overwrite prod)  |

Tagging is automatic ([`autotag.yml`](.github/workflows/autotag.yml)): a push to `dev` cuts a prerelease and a push to `main` cuts the release. The version is `max(patch-bump of the latest release tag, the ./VERSION floor)` (see [`scripts/next-version.sh`](scripts/next-version.sh)) — so patch releases need no edit, and to cut a minor/major release you bump [`VERSION`](VERSION) (e.g. `0.2.0`) in the `dev` PR; merging `dev → main` then releases it.

## Design notes, reference & roadmap

Longer-form documentation lives in the [project wiki](https://github.com/contemno/luks-enroll/wiki):

- **[Rust service — parity & design](https://github.com/contemno/luks-enroll/wiki/Rust-Service-Parity-and-Design)** — reference for the as-built service: the systemd-cryptenroll parity contract (token JSON shapes, recovery-key format, auth caching), accepted divergences, implementation findings, and testing strategy.
- **[Rust Migration](https://github.com/contemno/luks-enroll/wiki/Rust-Migration)** — why and how the privileged service was ported to Rust, and the C-library → crate mapping.
- **[Refactor Plan](https://github.com/contemno/luks-enroll/wiki/Refactor-Plan)** *(archived)* — the plan that slimmed the Python client (wizard removal, page consolidation, `.ui` templates).

The living roadmap is tracked as GitHub [milestones](https://github.com/contemno/luks-enroll/milestones) and the [Roadmap issue](https://github.com/contemno/luks-enroll/issues/28).

## License

[MIT](LICENSE)
