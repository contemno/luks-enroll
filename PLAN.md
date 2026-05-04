# LUKS Enroll Wizard — Refactor Plan

## Top-line shape

- **Total source today:** ~7,364 LOC (3,941 client + 3,423 service), ~1,822 LOC of tests.
- **Total source after plan:** ~3,200–3,500 LOC of hand-written Python + ~600–800 LOC of `.ui` XML + ~3,000–6,000 LOC of *generated* ctypes (excluded from the "lines of Python you maintain" budget). Net hand-maintained Python drops by **~50–60%**.
- **Risk profile:** the refactor is heavily client-side (low risk) and library-binding-side (medium risk). The atomic, in-process enrollment path on the service is touched only twice (Phase 5 ctypes regen, Phase 7 transactional helper). Both phases are gated on the workflow tests in `tests/test_workflows.py`, which are already structured around the service surface and require no GTK.

## Pre-flight observation that affects the plan

The "in-process atomicity" property is currently implemented through **`_volume_key_cache`** ([dist/usr/sbin/luks-enroll-service](dist/usr/sbin/luks-enroll-service) around line 643) plus `_clear_volume_key_cache(device)` calls on the boundaries — *not* through a long-lived `crypt_device *cd` handle. Every helper does its own `crypt_init` / `crypt_load` / `crypt_free` cycle (see `_add_keyslot_by_volume_key`, `_set_luks_token`, `_destroy_keyslot`, `_get_volume_key`). So the "single auth → multiple keyslot ops" property is real but is delivered by caching the volume key, not by holding the device open.

Implications:
- Phase 5 (ctypes regeneration) only changes how prototypes are declared — it does not need to touch this caching pattern.
- Phase 7 (the optional `with luks_session(device, vk) as s:` context manager) is the right phase to *also* hold the `cd` handle for the duration if we want, but doing so is independent of the deletions and can ship later or never.

---

## Phase ordering rationale

Lowest-risk-first, **client-side deletions before service-side rewrites**. The wizard removal is pure deletion and only affects code already decided to be discarded — it shrinks the file by ~1,000 lines and produces no new bugs because the deleted code path has no callers after the autostart entry is removed. The collapsing of the four `Manage*` pages and the `.ui` migration ride on top of that flat ground. Only once the client is small and stable do we touch the privileged service: first the ctypes prototype regeneration (mechanical, covered by `test_workflows.py`), then the optional helper-deduplication / transactional context manager (semantic, the only real risk to atomicity).

```
Phase 0  — repo prep / test scaffolding             (nothing user-facing)
Phase 1  — delete autostart + --first-login         (smallest, ships independently)
Phase 2  — delete WizardWindow & wizard pages       (~1,025 LOC out of client)
Phase 3  — collapse 4 Manage*EnrollPages → 1        (~400 LOC out of client)
Phase 4  — migrate to .ui templates                 (~800 LOC of imperative widget code → XML)
Phase 5  — clang2py ctypes regeneration             (~666 LOC of prototypes leave the source tree)
Phase 6  — service helper consolidation & dead code (~300 LOC)
Phase 7  — OPTIONAL transactional luks_session ctx  (atomicity hardening, no LOC delta)
```

Each phase is independently shippable and reverts cleanly. Phases 1–4 are entirely client-side and can never break the privileged service or the LUKS header. Phases 5–7 are service-side and are staged carefully.

---

# Phase 0 — Repo prep and test scaffolding

**Why first.** Two small things make every later phase faster and safer.

**File changes.**
- New `tests/conftest.py` — extract the duplicated `_load_module(...)` / `fake_gi` shim from `tests/test_luks_enroll.py:35-50` and `tests/test_workflows.py:32-50` so both test files share one importer. This is also what subsequent phases will plug into when the GUI code splits into multiple modules.
- New `Makefile` targets: `test` (runs pytest), `lint` (existing tools if any), `regen-ctypes` (placeholder, populated in Phase 5). Keep `package` and `changelog` exactly as they are.
- Audit whether `debian/luks-enroll/` is gitignored. The duplicate paths under `debian/luks-enroll/usr/...` and `debian/luks-enroll/etc/...` are populated by `dh_install` from `debian/luks-enroll.install` and should not be hand-edited. If they're tracked, fix the gitignore.

**Test work.** Run the full existing suite once to capture a green baseline before touching anything: `python3 -m pytest tests/ -v`. Record the pass count.

**LOC delta.** ~+30 (new conftest), ~−30 (deduped from the two test files). Net zero.

**Rollback.** `git revert` of the conftest commit. Test files keep working with their own `_load_module` if needed.

**Subagents.** None. Single trivial commit.

---

# Phase 1 — Delete first-login autostart and `--first-login` mode

**Why now.** Smallest user-visible change. Decouples the wizard deletion (Phase 2) from any "but how does the user get into the wizard at first login?" surprise. After Phase 1, the only entry point is the management UI; Phase 2 then drops the wizard with no remaining caller.

**File changes (deletions).**
- `dist/etc/xdg/autostart/luks-enroll-firstlogin.desktop` — delete.
- `debian/luks-enroll/etc/xdg/autostart/luks-enroll-firstlogin.desktop` — delete (build artifact; will regenerate empty).
- `install:34` — delete the `install -Dm644 .../luks-enroll-firstlogin.desktop` line.
- `dist/usr/bin/luks-enroll`: delete the `--first-login` argparse flag and the `mode == "first-login"` branch (lines 3919–3937). Simplify `LuksEnrollApp.__init__` to drop `mode`. The `WizardWindow` import disappears in Phase 2; for now leave it referenced only inside the dead branch you're deleting.

**Files to verify aren't broken.** `debian/control` (no change needed; package still ships everything), `debian/rules` (no change needed). The `Suggests: dracut` line and dracut config in `dist/etc/dracut.conf.d/luks-enroll.conf` are *not* affected — they're about libcryptsetup token plugins in the initramfs, not about the GUI wizard. Keep them as-is.

**Test work.**
- *Before code change:* add a regression test in `tests/test_luks_enroll.py` asserting that `LuksEnrollApp` no longer accepts a `mode="first-login"` kwarg and `argparse` no longer accepts `--first-login`. (Test will fail.)
- Make the change; test passes.
- *After green:* delete any test that asserted the wizard launches at first login (search for `first-login`, `firstlogin`, `WelcomePage` references — verify none exist).

**LOC delta.** ~−30 (client), ~−10 (autostart desktop), ~−1 (install script).

**Rollback.** Single git revert. The autostart .desktop is recovered, argparse flag is back. No state to migrate.

**Subagents.** None. One commit.

---

# Phase 2 — Delete `WizardWindow` and the seven wizard pages

**Why now.** Largest single deletion. After Phase 1, nothing references these classes.

**File changes (all in `dist/usr/bin/luks-enroll`, deletions only).**
- Lines 382–711: `WelcomePage`
- Lines 712–1038: `EnrollStepPage`
- Lines 1039–1070: `RecoveryKeyPage`
- Lines 1071–1291: `FIDO2Page`
- Lines 1292–1331: `TPM2Page`
- Lines 1332–1346: `PasswordDeletePage`
- Lines 1347–1406: `DonePage`
- Lines 1412–1905: `WizardWindow`
- Top of file: drop the `DeviceContext` dataclass at lines 28–33 *only if* nothing else uses it. The management UI doesn't (it uses instance attributes on `DeviceDetailPage`); confirm with grep before removing.

**Possibly-shared helpers to keep.** `detect_fido2_devices()` (line 309) and `detect_tpm2_device()` (line 352) are unprivileged hardware-detection functions used by `ManageFido2EnrollPage` and `ManageTpm2EnrollPage` (see luks-enroll:3322 and luks-enroll:3487). Keep them. Don't accidentally delete them with the wizard block.

**Test work.**
- *Before code change:* update import-time assertions. `tests/test_luks_enroll.py` does not reference any wizard classes by name (verified — it only checks recovery-key format, format-size helpers, parent-device parsing, etc., all of which live in the service). So nothing to update on the test side beforehand.
- *After green:* search for any test referencing `WelcomePage|EnrollStepPage|RecoveryKeyPage|FIDO2Page|TPM2Page|PasswordDeletePage|DonePage|WizardWindow|DeviceContext` and delete them. Verify none exist before removing the grep step from the checklist.

**LOC delta.** ~−1,025 client.

**Rollback.** Single git revert. The wizard returns intact.

**Subagents.**
- **Explore agent (parallel × 2)** — fan out two reads in parallel:
  1. "Find every cross-reference to the deleted class names from elsewhere in the client and tests."
  2. "Confirm `detect_fido2_devices`/`detect_tpm2_device` are only used by the management Manage*EnrollPage classes, not by anything inside the wizard block we're deleting."
  Both run before the deletion commit; their outputs are checklists for the implementer.

---

# Phase 3 — Collapse `ManageFido2EnrollPage`, `ManageTpm2EnrollPage`, `ManageRecoveryEnrollPage`, `ManagePassphraseEnrollPage` into one parametrized class

**Why now.** With the wizard gone, these four classes (luks-enroll:3195–3831) are the most obvious remaining duplication. They share an identical lifecycle: build a header bar + scroll + prefs page → collect inputs → call `self.svc.enroll_*` on a worker thread → display result → call `self.detail_page.refresh_after_enroll()`. Today this scaffold is duplicated four times (~640 lines).

| page | unique inputs | service call | result widget |
|------|---------------|--------------|---------------|
| FIDO2 | hidraw dropdown + PIN | `enroll_fido2(device, pp, pin, fido2_dev, unlock_method, unlock_pin)` | none (success label) |
| TPM2 | PCR checkbox grid + optional PIN + confirm | `enroll_tpm2(device, pp, pin, pcrs, unlock_method, unlock_pin)` | none |
| Recovery | (no input) | `enroll_recovery_key(device, pp, unlock_method, unlock_pin)` | monospace key label populated from `stdout` |
| Passphrase | new pp + confirm | `enroll_passphrase(device, existing_pp, new_pp, unlock_method, unlock_pin)` | none |

**Design.** A single `EnrollPage(Adw.NavigationPage)` parametrized by an `EnrollSpec` (or constructor args): `title`, `inputs_factory(group) -> dict-of-widget-getters`, `service_method_name`, `args_builder(ctx, inputs) -> tuple`, `result_handler(stdout)`. The four current classes become four small spec factories. The FIDO2-specific GUdev hidraw subscription lives in the FIDO2 spec; the rest don't need it.

**File changes.**
- `dist/usr/bin/luks-enroll`: replace lines 3195–3831 with one ~150–200-line `EnrollPage` plus four ~30-line spec factories. Update `DeviceDetailPage._push_enroll_page` (luks-enroll:3182–3187) to take an `EnrollSpec` instead of a class.

**Test work.**
- *Write first, in the same commit:* one parametrized test in `tests/test_luks_enroll.py` (does not require GTK runtime — assert the spec list is well-formed, that each spec maps to a real proxy method on `LuksEnrollProxy`, and that `args_builder` produces a tuple matching the D-Bus signature for that method as declared in `INTROSPECTION_XML`). This extends the existing `TestProxyServiceConsistency` and `TestDBusInvariant` with a parametrized "specs are consistent" check.
- *After green:* find and delete any test that referenced `ManageFido2EnrollPage|ManageTpm2EnrollPage|ManageRecoveryEnrollPage|ManagePassphraseEnrollPage` by name (check first; based on the earlier grep, there appear to be none, but the check is mandatory).

**LOC delta.** ~−400 client.

**Rollback.** Single git revert. The four classes return.

**Subagents.**
- **Explore agent (parallel × 4, fan-out on classes).** One agent per `Manage*EnrollPage`. Each produces:
  1. A list of widget-getter signatures the spec must expose.
  2. The exact tuple the service call expects.
  3. Any class-specific lifecycle (FIDO2's GUdev subscription is the only one).
  Their outputs converge into the `EnrollSpec` design.
- **Plan agent (sequential, after the four explores).** Synthesize the four reports into the unified `EnrollSpec` shape and the migration mapping. Output a one-page "do these renames" diff for the implementer.

---

# Phase 4 — Migrate widget construction to `.ui` XML templates with `Gtk.Template`

**Why now.** With the management UI down to ~5 page classes (DeviceList, EncryptDevice, CreateImage, DeviceDetail, EnrollPage), each class is now a candidate for a `.ui` template. `DeviceDetailPage` (lines 2591–3193, ~604 lines) is mostly widget tree assembly; it's the biggest win. `DeviceListPage` (lines 1906–2319, ~414 lines) is second-biggest.

**File changes.**
- New directory: `dist/usr/share/luks-enroll/ui/` containing one `.ui` per page:
  - `device-list-page.ui`
  - `device-detail-page.ui`
  - `encrypt-device-page.ui`
  - `create-image-page.ui`
  - `enroll-page.ui` (the unified one from Phase 3, with named child slots that each spec fills in)
- `dist/usr/bin/luks-enroll`: each page class declares `__gtype_name__` and `@Gtk.Template(filename=...)`, then declares `Gtk.Template.Child()` for each widget it touches. The body of `__init__` shrinks from "create 40 widgets and pack them" to "wire up signal handlers and start initial fetch."
- `debian/luks-enroll.install`: add `dist/usr/share/luks-enroll/ /` so the .ui files ship in the package.
- The CSS block at luks-enroll:3886–3896 should also move to `dist/usr/share/luks-enroll/style.css` and be loaded via `Gtk.CssProvider().load_from_path(...)`. Tiny but consistent.

**Hidden risk to manage.** `Gtk.Template(filename=...)` resolves the filename at class-definition time, which means the .ui must exist on disk at module-import time. For unit tests that import the GUI module (as `tests/test_luks_enroll.py` does), the test importer has to point the templates at the in-repo `dist/usr/share/luks-enroll/ui/` directory rather than the installed `/usr/share/...` path. Concretely: introduce a `_UI_DIR` module-level constant in the client, defaulting to `/usr/share/luks-enroll/ui` but overridable via env var `LUKS_ENROLL_UI_DIR`. The test conftest sets that env var before importing the GUI module. This is the only non-trivial integration concern in this phase.

**Test work.**
- *Write first:* a test that asserts every `.ui` file parses as well-formed XML and that every `Gtk.Template.Child` declared on a Python class corresponds to an `<object>` with a matching `id=` in the .ui file. Purely textual/XML — no GTK runtime needed.
- *Update:* the existing `_load_module` shim in conftest needs to set `LUKS_ENROLL_UI_DIR` before the GUI module is imported.
- *After green:* delete tests that assert specific widget construction sequences (none currently exist; verify).

**LOC delta.** ~−800 hand-written Python; +600–800 .ui XML (XML lines are not "Python LOC" for the budget). Net Python-LOC reduction: ~−800.

**Rollback.** Per-page revert is possible because each page is in its own .ui file. If `DeviceDetailPage` migration goes sideways, revert just that class + its .ui — others stay migrated.

**Strategic note.** `.ui` files are language-neutral. If the project ever moves to Rust (`gtk4-rs`), the `.ui` markup ports unchanged — only the controller logic needs translating. This phase preserves that optionality at no extra cost.

**Subagents.**
- **General-purpose agent (parallel × 5, fan-out on pages).** One per page (DeviceList, DeviceDetail, EncryptDevice, CreateImage, EnrollPage). Each agent's job: read the existing `__init__` widget-construction code, produce the `.ui` XML and the new template-binding `__init__`. They run in parallel because each page is self-contained.
- **Plan agent (after, sequential).** One pass to verify a consistent set of `Gtk.Template.Child` declarations and consistent CSS class usage across the migrated files.

---

# Phase 5 — Generate ctypes prototypes via `clang2py`

**Why now.** With the client down from 3,941 to ~1,700 LOC, all attention is on the service. The single biggest source of code in `luks-enroll-service` is hand-written ctypes prototypes:
- `_load_libblkid()` lines 95–172 (~78 LOC)
- `_load_libfdisk()` lines 265–349 (~85 LOC)
- `_load_libcryptsetup()` lines 430–543 (~114 LOC)
- `_load_libfido2()` lines 950–1106 (~157 LOC)
- `_load_libtss2()` lines 1442–1673 (~232 LOC)

Total: ~666 LOC of `restype = ...; argtypes = [...]` declarations, plus the `_CryptPbkdfType` ctypes.Structure and various TPM2 wire-format structs.

**Strategy.** Use `clang2py` (`ctypeslib2`) to produce one generated module per library, **check the output into git**, and wire regeneration into the Makefile. Build-time has no libclang dependency; only contributors who edit the generated bindings need it.

**File changes.**
- New directory `dist/usr/lib/luks-enroll/_ctypes/` (Python package):
  - `__init__.py`
  - `cryptsetup.py` — generated from `libcryptsetup.h`
  - `blkid.py` — generated from `blkid/blkid.h`
  - `fdisk.py` — generated from `libfdisk/libfdisk.h`
  - `fido2.py` — generated from `fido2.h` (and the subset of fido_err.h, etc., needed)
  - `tss2_esys.py` — generated from `tss2/tss2_esys.h`
  - `tss2_mu.py` — generated from `tss2/tss2_mu.h`
- `Makefile`: new `regen-ctypes` target that runs `clang2py -l <so-name> <header.h> -o <output.py>` for each, with the explicit `-c -d` flags for constants/defines as needed. The target requires `ctypeslib2` and libclang on the contributor's machine; running `make regen-ctypes` is documented in `README.md`.
- `dist/usr/sbin/luks-enroll-service`: replace each `_load_libXXX()` with `from luks_enroll._ctypes import cryptsetup as cs_lib; cs_lib._libraries['libcryptsetup.so.12'] = ctypes.CDLL("libcryptsetup.so.12")`. Internal call sites change from `lib.crypt_init(...)` to `cs_lib.crypt_init(...)`. Each `_load_libXXX` function becomes ~3 lines (load lib, register handle, return module-as-namespace) or disappears entirely if loading is at module top.
- `debian/luks-enroll.install`: add `dist/usr/lib/luks-enroll/ /` so the generated package ships.
- `debian/control`: `Depends: python3` is enough — no new runtime deps. Generated files are pure Python ctypes.

**Hidden risks that have to be handled.**
1. **Constant naming.** `clang2py` emits constants with their original C names (e.g., `FIDO_OK = 0`). The current code defines a few of these manually (luks-enroll-service:937–947). Use the generated names; remove the duplicates. If `clang2py` doesn't pick up a constant (e.g., a `#define` it can't resolve without a full preprocessor invocation), keep it in a small `_ctypes/_extra.py` to avoid scattering.
2. **Versioning of headers.** Different distros ship slightly different `tss2/*.h`. Generated bindings depend on the headers used at regeneration time. Document which headers (and which Debian package versions) were used to produce the checked-in output. The `Makefile regen-ctypes` target should preflight-check those package versions and refuse to run on a different version, to keep the checked-in output reproducible.
3. **The TPM2 wire-format helpers.** `_tpm2_build_*` functions (luks-enroll-service:1676–1796) and the manual struct construction are *not* ctypes prototypes — they're handcrafted wire-format builders that don't use the TPM2B_* C structs at all. They must stay as-is. clang2py will produce ctypes definitions for the TPM2B_* structs but the wire builders will continue to ignore them (correctly, because the wire format is platform-/endian-defined and using `struct.pack` is more reliable than `ctypes.Structure` with packed fields).
4. **systemd token format quirks.** The dual `tpm2-blob`/`tpm2_blob` field naming and the `tpm2_srk` base64 wrapping in `_handle_EnrollTpm2` (luks-enroll-service:3181–3195) are *not* in the C bindings — they're string keys in the LUKS2 token JSON. Untouched by this phase.

**Test work.**
- *Write first:* a test in `tests/test_luks_enroll.py` that asserts every function the service code calls on a generated module exists with the expected `restype` and `argtypes` (introspect the generated module and compare to a small whitelist). Catches regen drift.
- *Verify:* `tests/test_workflows.py` uses a `FakeLuksDevice` and a `ServiceHarness` (lines 74–192) that patches the service's library loaders. This phase changes how those loaders are structured. The `ServiceHarness._patch_all` (line 192) needs to be updated to patch the new `_ctypes` modules instead of patching `_load_libcryptsetup` etc. **This is the single highest-touch test change in the whole plan.**
- *After green:* delete `_load_libblkid`, `_load_libfdisk`, `_load_libcryptsetup`, `_load_libfido2`, `_load_libtss2` and the local constant declarations they replace. Verify the test suite still passes and `pytest tests/test_workflows.py -v` shows no new failures.

**LOC delta.** ~−666 hand-written service Python (the prototype declarations). The generated modules add ~3,000–6,000 LOC each but live in `_ctypes/` and are auto-generated; they don't count against the "code I maintain" budget.

**Rollback.** Per-library revert is possible — each `_load_libXXX` and its replacement are independent. If clang2py output for libtss2 produces an unusable binding, keep `_load_libtss2()` and migrate the others. The `regen-ctypes` Makefile target is independent.

**Subagents.**
- **Explore agent (parallel × 5, fan-out on libraries).** One per library: scan `luks-enroll-service` for every symbol it references on that library (`lib.crypt_*`, `lib.fido_*`, `lib.Esys_*`, `mu.Tss2_MU_*`, `lib.blkid_*`, `lib.fdisk_*`). Output a per-library symbol manifest. This is the input to the next step.
- **General-purpose agent (parallel × 5).** One per library: run `clang2py` against the library's headers, diff the symbol manifest against the generated module's exports, identify any missing symbol that needs to live in `_extra.py`, and produce the import-rewriting patch for `luks-enroll-service`.
- **Plan agent (sequential, after).** Verify all five migrations are consistent in style and that the test harness patching strategy works against all five. This is the synthesis step.

This phase is where the biggest parallelism win sits. Five independent fan-outs, each ~1 hour of work, condensed into one wall-clock hour.

---

# Phase 6 — Service helper consolidation and dead-code sweep

**Why now.** Whatever's left after Phase 5 is the actual business logic. Now you can see duplication that was hidden by ctypes verbosity:
- The `crypt_init` → `crypt_load` → `try` → `crypt_free` boilerplate appears in `_get_luks_json`, `verify_luks_passphrase`, `verify_luks_token`, `_get_volume_key`, `_add_keyslot_by_volume_key`, `_set_luks_token`, `_destroy_keyslot`, `_luks_format_device`. Eight sites of identical 10-line boilerplate (~80 LOC). One context manager (`with _opened_luks(device) as cd:`) collapses them to ~30 LOC.
- The TPM2 wire-format builders `_tpm2_build_empty_*` (lines 1774–1795) are tiny one-liners that get inlined.
- Each `_handle_*` enrollment method has identical try/except → `invocation.return_value(GLib.Variant("(bss)", ...))` shape; a small decorator drops 5–8 LOC per handler.
- Some print-debugging in `_handle_CheckFido2Enrolled` (luks-enroll-service:3109–3148) — replace with `logging` and configurable level.

**File changes.** All inside `dist/usr/sbin/luks-enroll-service`. New private helpers:
- `_opened_luks(device) -> contextmanager` yielding the `cd` handle.
- `_dbus_handler(reply_signature)` decorator wrapping the try/except + `return_value` / `return_dbus_error` pattern.

**Test work.** No new behavior — every change must keep `tests/test_workflows.py` green. Add one test that asserts `_opened_luks` raises `RuntimeError` cleanly on a non-LUKS path (covers the new helper).

**LOC delta.** ~−250 to −350 service.

**Rollback.** Each helper introduction is its own commit; revert any single one if it breaks atomicity invariants.

**Subagents.** None. Single engineer, sequential commits.

---

# Phase 7 — OPTIONAL: transactional `luks_session` for in-process atomicity hardening

**Why optional.** "Preserve in-process atomicity guarantees" is satisfied by the existing volume-key cache. The current code does *not* hold a `cd` handle across calls and does *not* snapshot the LUKS header — multi-step `_handle_*` methods (`_add_keyslot_by_volume_key` → `_set_luks_token` → `_clear_volume_key_cache`) have no rollback. If you want to *strengthen* the guarantee while you're already in the file, this is the phase to do it; if you don't, skip it.

**Design (if pursued).**
- `with luks_session(device, vk_bytes) as s: s.add_keyslot(...); s.set_token(...)` — the context manager opens the device once, snapshots the LUKS header (`luksHeaderBackup` to a `tmpfs` file under `PrivateTmp=yes`), runs the body, restores the header on exception, deletes the snapshot on success.
- Net reduction: enroll handlers each shrink ~15 LOC because they no longer manage `_clear_volume_key_cache` themselves.
- Net guarantee improvement: a crash in the middle of `EnrollFido2` — between the `crypt_keyslot_add_by_volume_key` and the `crypt_token_json_set` — now leaves the header recoverable instead of leaving an orphan keyslot with no token.

**Test work.** New tests in `tests/test_workflows.py` that simulate failure between add-keyslot and set-token, then assert the header was rolled back. Use `mock.patch` on `_set_luks_token` to raise.

**LOC delta.** ~−100 service (handler simplification) +60 (`luks_session`). Net ~−40, but the *atomicity guarantee* genuinely gets stronger.

**Rollback.** Self-contained; revert this phase alone.

**Subagents.** None. Carefully reviewed single commit.

---

## Hidden risks not anticipated in the original framing

1. **D-Bus interface compatibility** — *Currently safe to break*, but verify before assuming. The XML at `luks-enroll-service:2652–2778` defines 21 methods. Today, the only registered consumer is `LuksEnrollProxy` in `dist/usr/bin/luks-enroll`. There is no third-party D-Bus client documented in `README.md`. **However**, the bus name `net.contemno.LuksEnroll` is published and a system service. If the package is already deployed anywhere, downstreams may script against it. Verify with the project owner; otherwise, treat the D-Bus surface as removable. After Phase 3, `GetSystemdVersion` (which always returns 999) is dead — remove it from the XML and from the proxy. After Phase 7, `_handle_Authenticate` is also questionable — it's a no-op that just triggers the polkit cache via `handle_method_call`. Leave it in case external clients use it for the polkit prompt side-effect.

2. **Polkit action IDs are stable, but the conf files are inconsistent.** The repo ships *both* `com.contemno.luks-enroll.policy` (in `debian/luks-enroll/usr/share/polkit-1/actions/`) and `net.contemno.luks-enroll.policy` (in `dist/`). The `com.contemno` files appear to be stale build artifacts from a renaming pass. They will be regenerated on `dpkg-buildpackage`. Verify they are not actually shipped — if they are, that's a packaging bug to fix in Phase 0 (move them out of `debian/luks-enroll/` which is the dh build directory).

3. **Dracut/initrd is independent of the GUI deletion.** The dracut config (`dist/etc/dracut.conf.d/luks-enroll.conf`) installs `libcryptsetup-token-systemd-fido2.so` and `libcryptsetup-token-systemd-tpm2.so` into the initramfs so the *kernel* can unlock at boot via the LUKS2 tokens this code writes. Deleting the wizard does not affect this. Removing the autostart entry does not affect this. The initramfs unlock path uses systemd's plugins, not our service. Phase 1's deletions are safe.

4. **`PrivateTmp=yes` and Phase 7's header snapshot.** The systemd unit at `dist/lib/systemd/system/net.contemno.LuksEnroll.service:13` enables `PrivateTmp=yes`, so a header snapshot in `/tmp/luks-header-XXX` is invisible to the rest of the system and cleaned up on service exit — exactly what we want. But the unit also has `ProtectSystem=strict` and only `/etc/luks-enroll.conf` in `ReadWritePaths`. Adding `/tmp` to `ReadWritePaths` is *not needed* (PrivateTmp creates a writable namespace), but if Phase 7 ever wants to write the snapshot somewhere else, the unit needs updating.

5. **`Gtk.Template` and unit-test importability** (called out in Phase 4). This is the single most likely cause of "the refactor broke pytest" surprise. Mitigated by the env-var indirection but worth highlighting at PR review.

6. **`debian/luks-enroll/` is a build directory.** Many of the duplicate paths (`debian/luks-enroll/etc/...`, `debian/luks-enroll/usr/...`) are populated by `dh_install` from `debian/luks-enroll.install`. Don't edit those by hand; they get clobbered. Edit the source files in `dist/` and let dh regenerate. Phase 0 should add a quick `git status --ignored` audit to confirm `debian/luks-enroll/` is gitignored or at least not the hand-edited canonical copy.

7. **Removing `--first-login` doesn't change `Suggests: dracut`.** The package still benefits from dracut for initramfs LUKS unlock; the wizard removal is purely a userspace UI change. `debian/control` line 24 stays.

---

## Critical Files for Implementation

- `dist/usr/bin/luks-enroll`
- `dist/usr/sbin/luks-enroll-service`
- `tests/test_luks_enroll.py`
- `tests/test_workflows.py`
- `Makefile`
- `debian/luks-enroll.install`
