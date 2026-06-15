# Rust Migration Plan

Status: **Phase A in progress** (backend service). Phase B (GTK client) not started.

## Verdict

- **Backend service: migrate to Rust.** A root daemon handling disk-encryption secrets and
  untrusted D-Bus input through ~1,400 LOC of hand-written ctypes FFI across five C libraries
  is exactly the profile where Rust pays off. Mature, institutionally backed crates exist for
  every binding.
- **Frontend client: optional, second.** Unprivileged UI code — the win is operational
  (drop the python3-gi/GIR dependency chain, one language, compile-checked D-Bus surface),
  not safety. Decide after the Rust service ships.
- **The D-Bus interface is the migration seam.** It is frozen (see
  `dbus/net.contemno.LuksEnroll1.xml`); each side swaps independently. The Python client keeps
  working against the Rust service unchanged.

## Why the backend case is strong

1. The ctypes layer is the riskiest code in the project and it evaporates: a wrong `argtypes`
   declaration is silent UB in a root process, and the TPM2 code hand-packs TPM wire structures
   with `struct.pack`. Typed crates replace all of it.
2. Latent thread-safety bug today: libcryptsetup is not thread-safe, ctypes releases the GIL
   during C calls, and the service runs blocking methods on multiple threads. `libcryptsetup-rs`
   makes this sound explicitly (`mutex` feature serializes library access).
3. Real secret hygiene: Python bytes are immutable and GC-managed — the volume-key cache cannot
   be zeroized. Rust + `zeroize` gives actual control over key-material lifetime.
4. Testing gets better: the service treats regular files as devices, so the Rust port is tested
   black-box against real LUKS2 loopback images (no root needed for keyslot/token ops on files),
   plus swtpm for TPM2.
5. The OS integration surface (D-Bus policy, polkit policy, systemd unit + hardening, bus
   activation, dracut conf, systemd-compatible token format) is config files — all unchanged.
   Binary paths stay `/usr/sbin/luks-enroll-service` and `/usr/bin/luks-enroll`.

## Library mapping

| Today (ctypes)                          | Rust replacement                                | Backing |
|-----------------------------------------|--------------------------------------------------|---------|
| libcryptsetup.so.12                      | `libcryptsetup-rs` (`mutex` feature)             | Stratis / Red Hat |
| libtss2-esys/-mu + hand-rolled marshaling| `tss-esapi` (typed structures, `Marshall` trait) | Parsec (CNCF) |
| libfido2.so.1                            | in-repo `fido2-sys` (bindgen vs system headers)  | exact parity with systemd's library; pure-Rust `ctap-hid-fido2` is a later option |
| libblkid.so.1                            | `libblkid-rs` (probe API)                        | Stratis / Red Hat |
| libfdisk.so.1                            | pure-Rust `gpt` crate + `nix` BLKRRPART ioctl    | usage is only "GPT label + one typed partition" |
| Gio D-Bus + manual polkit calls          | `zbus` + `zbus_polkit::AuthorityProxy`           | zbus project |

## Phase plan

### Phase 0 — Seam and safety net
- [x] Freeze the D-Bus interface as `dbus/net.contemno.LuksEnroll1.xml` (extracted verbatim from
      the Python service's `INTROSPECTION_XML`).
- [x] Cargo workspace under `rust/` (service now, client later as a second member).
- [x] Rust CI (fmt, clippy, build, test) alongside the existing Python CI.
- [ ] Black-box conformance suite that talks to either implementation over a private bus
      (extend over time; image-file integration tests in the Rust crate cover the cryptsetup
      core today).

### Phase A — Rust service (in progress)
- [x] A1: zbus skeleton — bus activation, `--replace`, idle timeout (5 min), polkit via
      `zbus_polkit` with the two auth caches (read 30 s / manage 300 s), ownership-based polkit
      skip, input-validation parity (realpath + S_ISBLK/S_ISREG, 10 MiB length caps),
      read-only methods.
- [x] A2: cryptsetup core via `libcryptsetup-rs`: VerifyPassphrase, UnlockWithToken (vk extract),
      EnrollPassphrase, EnrollRecoveryKey, WipeSlot, volume-key cache (120 s TTL, zeroized).
- [x] A3: TPM2 via `tss-esapi`: persistent SRK 0x81000001 → transient ECC-P256 fallback,
      trial-session policy digest (PolicyPCR [+ PolicyAuthValue with PIN]), seal/unseal,
      blob = TPM2B_PRIVATE ‖ TPM2B_PUBLIC marshaled, SRK `tr_serialize` for `tpm2_srk`.
- [x] A4: FIDO2 via in-repo bindgen sys crate: enroll (ES256 + hmac-secret, rp
      `io.systemd.cryptsetup`), three-phase unlock (probe w/o PIN → touch-select → assert),
      duplicate-token rejection, CheckFido2Enrolled.
- [x] A5: formatting paths — wipefs via libblkid probe loop, GPT via `gpt` crate
      (type GUID CA7D7CCB-63ED-4C53-861C-1742536059CC), partprobe ioctl, FormatPartition,
      CreateEncryptedImage (+ chown to caller).
- [ ] A6: packaging swap — debian `Architecture: all` → `any`, dh-cargo or vendored crates,
      Build-Depends on C `-dev` packages + libclang, per-arch release builds (amd64/arm64).
      Ship Rust binary at `/usr/sbin/luks-enroll-service`; keep the Python service in-tree for
      one release as rollback.
- [ ] Hardware validation gate before A6 lands: real FIDO2 token (with and without PIN),
      real TPM2 (PCR 7 and 7+11, with and without PIN), enroll-with-Rust → boot-unlock via
      dracut initramfs, and cross-validation (Python-enrolled volume managed by Rust service
      and vice versa).

### Phase B — Rust GTK client (optional; decide after A ships)
- B0: execute PLAN.md Phases 1–3 deletions in Python first (wizard + first-login, collapse
  Manage pages — ~35 % of the port surface), then PLAN.md Phase 4 (`.ui` templates); the XML is
  reused verbatim by gtk4-rs composite templates.
- B1: shell — `Adw.Application`, ManagementWindow, DeviceListPage; threads+`idle_add` becomes
  `MainContext::spawn_local` + async Gio D-Bus calls.
- B2: detail + enroll pages on the `.ui` templates; udev hotplug via `gudev`/`udev` crate.
- B3: replace `/usr/bin/luks-enroll`, drop all Python runtime deps from debian/control.

### Interaction with PLAN.md
- PLAN.md Phases 1–3 (client deletions): still worth doing regardless.
- PLAN.md Phase 4 (.ui templates): only as the precursor to Phase B.
- PLAN.md Phases 5–7 (ctypes regen, service consolidation): **mooted by the Rust service — skip.**

## Behavioral-parity contract

The Rust service replicates the Python service bug-for-bug where the wire format is observable:

- Token JSONs match systemd-cryptenroll conventions, including the duplicate
  `tpm2-blob`/`tpm2_blob` fields and string keyslot ids.
- Operation failures return `(false, "", "Operation failed")`-style tuples, never D-Bus errors;
  D-Bus errors are reserved for authorization (`org.freedesktop.PolicyKit1.Error.NotAuthorized`)
  and argument validation (`org.freedesktop.DBus.Error.InvalidArgs`).
- `GetSystemdVersion` returns 999.
- Auth caching: read 30 s, manage 300 s, keyed by D-Bus sender; idle exit after 5 min,
  reset only by privileged methods.
- Recovery keys are 64 modhex chars in 8 dash-separated groups (256-bit), like
  `systemd-cryptenroll --recovery-key`.
- FIDO2/TPM2 keyslots are added with minimal PBKDF (pbkdf2/sha512/1000 iters) since the
  passphrase is high-entropy; recovery/passphrase keyslots use the device default (argon2id).

### Accepted divergences (documented decisions)
1. **Hard linking instead of dlopen.** Python `CDLL`s libfido2/libtss2 lazily so they could be
   Recommends. The Rust binary links them; A6 moves them to Depends. (apt installs Recommends
   by default, so the practical delta is small.)
2. **LUKS discovery scans /sys/class/block + per-device blkid probe** instead of the libblkid
   cache API — same results, no dependency on /run/blkid cache state.
3. **GPT creation uses the pure-Rust `gpt` crate** rather than libfdisk: protective MBR + GPT,
   single partition, type GUID 8309. The partition starts at the first usable LBA (34) rather
   than sgdisk's 1 MiB-aligned 2048 — visible in `fdisk -l`, functionally irrelevant for a
   single LUKS partition on removable media.
4. **Tokio** for the async runtime; blocking crypto/hardware work runs on `spawn_blocking`
   threads, libcryptsetup access serialized by the crate's `mutex` feature.
5. **Two FIDO2 error constants corrected.** The Python service hand-defined
   `FIDO_ERR_UP_REQUIRED = 0x11` and `FIDO_ERR_PIN_NOT_SET = 0x2B`; `fido/err.h` says 0x3B and
   0x35. The Rust port takes all constants from bindgen against the system header, which fixes
   credential-probe classification for devices returning those codes — exactly the FFI-drift
   bug class the migration was meant to eliminate.

### Implementation findings (Phase A, recorded for posterity)
- tss-esapi 7.7.0 wraps neither `Esys_TR_Serialize` nor `Private` marshaling, and
  `Public::marshall()` emits the bare TPMT_PUBLIC (no size prefix). The TPM2 module therefore
  drives the ESYS command layer through the `tss_esapi::tss2_esys` sys re-export
  (call-for-call with the Python ctypes flow, explicit flush bookkeeping) and produces the
  token blob with `Tss2_MU_TPM2B_PRIVATE_Marshal` ‖ `Tss2_MU_TPM2B_PUBLIC_Marshal` — the
  size-prefixed TPM2B forms systemd expects. Templates and PCR selections still use the typed
  builders, with the wire layout pinned by unit tests.
- The systemd cryptsetup token plugins (`libcryptsetup-token-systemd-*.so`), when installed,
  validate token JSON on `crypt_token_json_set`. The integration suite exploits this: writing
  the service's own token shapes through a validating libcryptsetup doubles as a conformance
  check against systemd's validator. The lenient read-side parsing quirks (chunked array
  blobs, scalar pcrs, `tpm2_blob` vs `tpm2-blob`) are unit-tested against the pure parsers.
- The Python `_wipefs` sets a partitions-flags value of `1<<1` labeled PARTS_MAGIC; on current
  util-linux that bit is `BLKID_PARTS_FORCE_GPT` and PARTS_MAGIC is `1<<3`. Either way only
  `SBMAGIC*` values are consumed, so the wiped set is identical; the Rust port passes the real
  header constant and preserves the PTMAGIC-not-wiped quirk.

## Testing strategy (implemented)

- Unit tests: modhex recovery keys, PCR selection encoding/wire layout, crypttab/sysfs/device-
  name parsing (including the mmcblk quirk), probe-code classification, token-JSON parser
  quirks, hidraw path validation.
- Integration tests (no root, no hardware): real libcryptsetup against LUKS2 image files in
  /tmp — image creation, format, keyslot add/destroy (normal and minimal PBKDF), token
  set/get with golden systemd token shapes, passphrase verify, volume-key extract, wipe-slot
  semantics including last-keyslot protection.
- D-Bus end-to-end: the real binary on a private dbus-daemon — bus-name acquisition,
  ownership-based polkit bypass, read-auth caching, fresh-sender denial with the exact
  `org.freedesktop.PolicyKit1.Error.NotAuthorized` name, InvalidArgs on bad device paths.
- TPM2: seal/unseal roundtrips (PIN and no-PIN, wrong-PIN rejection) against swtpm in CI via
  `TCTI=swtpm:host=127.0.0.1,port=2321`, `--ignored`-gated elsewhere.
- FIDO2: orchestration decisions (probe classification, candidate ordering) are pure,
  unit-tested functions; hardware behavior is validated per the A-phase gate checklist.
- The Python test suite continues to run against the Python implementations until A6.

## Effort and risks

- Service ≈ 2,500–3,500 LOC Rust (FFI prototypes and TPM2 wire-packing move into crates).
- Top risks: token-format parity with systemd (mitigated: golden tests + initramfs boot gate),
  FIDO2/TPM2 hardware behavior (mitigated: same C libraries underneath, trait mocks),
  Debian Rust packaging friction (vendoring, MSRV vs target distro rustc).
