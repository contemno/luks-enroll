# LUKS Enroll Wizard

A GTK4/libadwaita wizard that enrolls FIDO2 tokens, TPM2 chips, and recovery keys into a LUKS2-encrypted root volume, then optionally removes the original password keyslot.

Designed to run on first login or inside a chroot with `/dev`, `/sys`, and `/proc` bind-mounted.

## Features

- FIDO2 enrollment with PIN (supports multiple tokens)
- TPM2 enrollment with PIN and configurable PCR selection
- Recovery key generation (multiple keys supported)
- Passphrase management (add/remove keyslots)
- Encrypted USB formatting (GPT + LUKS2)
- Encrypted image file creation
- Auto-detection of all LUKS devices, FIDO2 tokens (hotplug), and TPM2 chips
- Empty passphrase auto-unlock
- Per-enrollment wipe controls with auth keyslot protection
- Autostart via XDG desktop entry with polkit elevation

All cryptographic operations use native ctypes bindings (libcryptsetup, libfido2, libtss2) — no subprocess calls.

## Project Layout

```
src/        Python source (GUI client + D-Bus service)
data/       D-Bus, polkit, and desktop config files
tests/      Unit and integration tests
debian/     Debian packaging
scripts/    Developer tooling (git hooks)
```

## Dependencies

**Required:**
- Python 3, PyGObject (`python3-gi`)
- GTK 4 (`gir1.2-gtk-4.0`), libadwaita (`gir1.2-adw-1`)
- systemd (>= 248)
- `libcryptsetup12`, `libblkid1`, `libfdisk1`
- polkit (`polkitd`)

**For FIDO2 support:** `libfido2-1`

**For TPM2 support:** `libtss2-esys`, `libtss2-mu`

## Install

### From .deb

```sh
sudo apt install ./luks-enroll_*.deb
```

### Manual

```sh
sudo ./install.sh              # live system
sudo ./install.sh /mnt/chroot  # into a chroot
```

## Usage

```sh
luks-enroll                  # open the management view (default)
luks-enroll --first-login    # run the first-login enrollment wizard
```

The wizard launches automatically on first login via XDG autostart.

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

## Releases

Tags trigger builds. Version scheme:

| Tag | Debian version | Type |
|---|---|---|
| `v1.0.0` | `1.0.0-1` | Production |
| `v1.0.0-dev.1` | `1.0.0~dev1-1` | Development (sorts lower, won't overwrite prod) |

## License

See [debian/copyright](debian/copyright).
