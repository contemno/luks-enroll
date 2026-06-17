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
- **Native ctypes bindings** to libcryptsetup, libfido2, and libtss2 — zero subprocess calls into the cryptsetup CLI

## Architecture

The application is split between an unprivileged GTK client and a privileged D-Bus system service:

```
┌─────────────────────┐  D-Bus system bus   ┌──────────────────────────┐
│  luks-enroll        │ ──────────────────► │  luks-enroll-service     │
│  (user, GTK4 GUI)   │  net.contemno       │  (root, bus-activated)   │
│                     │  .LuksEnroll1       │                          │
│  ~3900 LOC          │ ◄────────────────── │  ~3400 LOC               │
└─────────────────────┘                     └──────────────────────────┘
                                                       │
                                                       │ ctypes
                                                       ▼
                                          libcryptsetup, libfido2,
                                          libtss2-esys, libtss2-mu
```

- **`/usr/bin/luks-enroll`** — unprivileged GTK4/libadwaita client. Talks to the service over the system bus, runs all blocking calls in background threads, and updates the UI via `GLib.idle_add()`.
- **`/usr/sbin/luks-enroll-service`** — bus-activated D-Bus service running as root, implemented in Rust. Performs all crypto operations against libcryptsetup/libfido2/libtss2.
- **D-Bus name:** `net.contemno.LuksEnroll`, object `/net/contemno/LuksEnroll`, interface `net.contemno.LuksEnroll1`
- **Polkit actions:** `net.contemno.luks-enroll.read` (auth-cached for inspection), `net.contemno.luks-enroll.manage` (required for any destructive change)
- **systemd hardening:** the service unit runs with `ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_UNIX`, a minimal capability bounding set, and explicit `DeviceAllow` rules for block, hidraw, tpm, and tpmrm device classes.

## Rust port (Phase A, in progress)

The privileged service is being ported to Rust — see [RUST_MIGRATION.md](RUST_MIGRATION.md)
for the plan and status. The Rust workspace lives in [`rust/`](rust/); the D-Bus interface
contract is frozen in [`dbus/net.contemno.LuksEnroll1.xml`](dbus/net.contemno.LuksEnroll1.xml),
so the Python client and service remain the shipped implementation until the swap (Phase A6).

## Initramfs unlock

The package ships [`/etc/dracut.conf.d/luks-enroll.conf`](dist/etc/dracut.conf.d/luks-enroll.conf), which conditionally adds the `fido2` and `tpm2-tss` dracut modules and pulls in the matching `libcryptsetup-token-systemd-*.so` plugins. The conf file is sourced as shell, so it is a no-op on systems without the relevant libraries — and a no-op entirely if dracut is not installed.

After enrolling a token, regenerate the initramfs (`dracut --force` or `update-initramfs -u`) and add the appropriate `crypttab` options:

```
crypt-root  UUID=...  none  tpm2-device=auto,fido2-device=auto,luks,discard
```

## Project layout

```
dist/                              Mirrors the install hierarchy:
  usr/bin/luks-enroll              GTK4 client
  usr/sbin/luks-enroll-service     Privileged D-Bus service
  usr/share/dbus-1/                Bus policy + activation
  usr/share/polkit-1/actions/      Polkit policy
  usr/share/applications/          Desktop launcher
  etc/xdg/autostart/               First-login autostart entry
  etc/dracut.conf.d/               Initramfs module config
  etc/luks-enroll.conf             Runtime config (writable)
  lib/systemd/system/              Hardened systemd unit

debian/                            Debian packaging
  luks-enroll.install              Single-file install map: dist/* -> /
  rules                            Trivial — no manual install lines
  control / copyright / changelog

tests/
  test_luks_enroll.py              GUI client unit tests

scripts/                           Developer tooling (git hooks)
.github/workflows/                 CI (lint, tests) and tagged releases
```

The `dist/` layout is what makes [`debian/rules`](debian/rules) trivial — `dh_install` reads [`debian/luks-enroll.install`](debian/luks-enroll.install) and copies the three top-level directories to `/`.

## Dependencies

**Required:**

- Python 3, PyGObject (`python3-gi`)
- GTK 4 (`gir1.2-gtk-4.0`), libadwaita (`gir1.2-adw-1`)
- systemd (>= 248)
- `libcryptsetup12`, `libblkid1`, `libfdisk1`
- polkit (`polkitd` or `policykit-1`)

**For FIDO2 support:** `libfido2-1`

**For TPM2 support:** `libtss2-esys`, `libtss2-mu`, `tpm2-tools`

**For initramfs unlock (optional):** `dracut`

## Install

### From .deb

```sh
sudo apt install ./luks-enroll_*.deb
```

### Manual

```sh
sudo ./install              # live system
sudo ./install /mnt/chroot  # into a chroot
```

## Usage

```sh
luks-enroll                 # management view
```

## Development

```sh
# Install git hooks (pre-push lint + syntax check)
./scripts/install-hooks.sh

# Run tests
python3 -m pytest tests/ -v

# Lint
pip install ruff
ruff check .
```

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

## License

[MIT](LICENSE)
