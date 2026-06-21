//! FIDO2 enrollment and unlock via libfido2 (fido2-sys bindgen bindings).
//!
//! Port of the Python service's libfido2 ctypes code. Credentials are
//! systemd-cryptenroll compatible: rp "io.systemd.cryptsetup", ES256,
//! hmac-secret extension, rk=false, uv=false, clientdata hash = 32 zero
//! bytes, random 32-byte user id and salt.
//!
//! All unsafe FFI is contained in this module (and the sys crate); the
//! public functions are safe. libfido2 handles are held in small RAII
//! wrappers ([`Dev`], [`Cred`], [`Assert`], [`DevInfoList`]) so they are
//! closed/freed on every path, mirroring the Python `finally` blocks.

use std::ffi::{CStr, CString};
use std::os::raw::c_int;
use std::ptr;
use std::slice;
use std::sync::Once;

use fido2_sys::{
    fido_opt_t_FIDO_OPT_FALSE as FIDO_OPT_FALSE, fido_opt_t_FIDO_OPT_OMIT as FIDO_OPT_OMIT,
    fido_opt_t_FIDO_OPT_TRUE as FIDO_OPT_TRUE,
};

use crate::bail;
use crate::error::{Error, Result};
use crate::luks::Fido2TokenRef;

// libfido2 status codes and flags, taken from the generated bindings
// (fido/err.h, fido/param.h). bindgen types them `u32` while the libfido2
// functions return/take `c_int`, so cast once here.
//
// NOTE: the Python reference hand-defines FIDO_ERR_UP_REQUIRED = 0x11 and
// FIDO_ERR_PIN_NOT_SET = 0x2B, which do not match fido/err.h (0x3B and
// 0x35). The header values, via bindgen, are authoritative; using them
// fixes the probe classification of those two codes.
const FIDO_OK: c_int = fido2_sys::FIDO_OK as c_int;
const FIDO_ERR_UP_REQUIRED: c_int = fido2_sys::FIDO_ERR_UP_REQUIRED as c_int;
const FIDO_ERR_NO_CREDENTIALS: c_int = fido2_sys::FIDO_ERR_NO_CREDENTIALS as c_int;
const FIDO_ERR_PIN_NOT_SET: c_int = fido2_sys::FIDO_ERR_PIN_NOT_SET as c_int;
const FIDO_ERR_PIN_REQUIRED: c_int = fido2_sys::FIDO_ERR_PIN_REQUIRED as c_int;
const FIDO_ERR_PIN_INVALID: c_int = fido2_sys::FIDO_ERR_PIN_INVALID as c_int;
/// COSE algorithm for credential creation (already `i32` in the bindings).
const COSE_ES256: c_int = fido2_sys::COSE_ES256;
const FIDO_EXT_HMAC_SECRET: c_int = fido2_sys::FIDO_EXT_HMAC_SECRET as c_int;

/// FIDO2 RP ID (matches systemd-cryptenroll).
pub const FIDO2_RP_ID: &str = "io.systemd.cryptsetup";

/// `FIDO2_RP_ID` as a C string for libfido2 calls (equality with the
/// public constant is asserted by a unit test).
const FIDO2_RP_ID_C: &CStr = c"io.systemd.cryptsetup";

pub struct Fido2Enrollment {
    pub cred_id: Vec<u8>,
    pub salt: Vec<u8>,
    pub hmac_secret: Vec<u8>,
}

/// Create a credential on the token at `fido2_device` (a /dev/hidrawN
/// path; validated against the canonical path) and derive the hmac-secret
/// for LUKS enrollment.
pub fn enroll(fido2_device: &str, pin: Option<&str>) -> Result<Fido2Enrollment> {
    // Python truthiness: an empty PIN behaves like no PIN.
    let pin = pin.filter(|p| !p.is_empty());

    let real_path = std::fs::canonicalize(fido2_device)
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .filter(|p| is_hidraw_path(p))
        .ok_or_else(|| Error(format!("Invalid FIDO2 device path: {fido2_device}")))?;

    fido_init_once();

    let mut dev = Dev::new()?;
    let real_c = CString::new(real_path).expect("canonical path contains no NUL");
    let ret = dev.open(&real_c);
    if ret != FIDO_OK {
        bail!("fido_dev_open({fido2_device}) failed: {ret}");
    }

    // Create the credential with the hmac-secret extension. Setter return
    // codes are not checked, matching the Python; a bad setting surfaces
    // as a fido_dev_make_cred failure.
    let cred_id = {
        let cred = Cred::new()?;
        let mut user_id = [0u8; 32];
        getrandom::fill(&mut user_id).expect("OS RNG unavailable");
        let zeroes = [0u8; 32];
        unsafe {
            fido2_sys::fido_cred_set_type(cred.0, COSE_ES256);
            fido2_sys::fido_cred_set_rp(
                cred.0,
                FIDO2_RP_ID_C.as_ptr(),
                c"Encrypted Volume".as_ptr(),
            );
            fido2_sys::fido_cred_set_user(
                cred.0,
                user_id.as_ptr(),
                user_id.len(),
                c"user".as_ptr(),
                c"user".as_ptr(),
                ptr::null(),
            );
            fido2_sys::fido_cred_set_clientdata_hash(cred.0, zeroes.as_ptr(), zeroes.len());
            fido2_sys::fido_cred_set_extensions(cred.0, FIDO_EXT_HMAC_SECRET);
            fido2_sys::fido_cred_set_rk(cred.0, FIDO_OPT_FALSE);
            fido2_sys::fido_cred_set_uv(cred.0, FIDO_OPT_FALSE);
        }

        let pin_c = pin_cstring(pin)?;
        let pin_ptr = pin_c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        let ret = unsafe { fido2_sys::fido_dev_make_cred(dev.0, cred.0, pin_ptr) };
        if ret == FIDO_ERR_PIN_REQUIRED && pin_c.is_none() {
            bail!("FIDO2 device requires a PIN");
        }
        if ret != FIDO_OK {
            bail!("fido_dev_make_cred failed: {ret}");
        }

        let cid_ptr = unsafe { fido2_sys::fido_cred_id_ptr(cred.0) };
        let cid_len = unsafe { fido2_sys::fido_cred_id_len(cred.0) };
        if cid_ptr.is_null() || cid_len == 0 {
            bail!("Credential ID is empty");
        }
        unsafe { slice::from_raw_parts(cid_ptr, cid_len) }.to_vec()
        // `cred` freed here (also on the error paths above).
    };

    // Generate a random salt and run the hmac-secret assertion.
    let mut salt = vec![0u8; 32];
    getrandom::fill(&mut salt).expect("OS RNG unavailable");
    let hmac_secret = get_hmac_secret(&dev, &cred_id, &salt, pin)?;

    Ok(Fido2Enrollment {
        cred_id,
        salt,
        hmac_secret,
    })
    // `dev` closed and freed here (also on every error path).
}

/// Derive the passphrase secret from one of the device's enrolled FIDO2
/// tokens, in three phases to avoid burning PIN retries on the wrong
/// token: (1) probe each connected device per credential with UP=false /
/// no PIN, (2) touch-select when several match, (3) real hmac-secret
/// assertion with PIN on the selected device only.
pub fn unlock_from_tokens(tokens: &[Fido2TokenRef], pin: &str) -> Result<Vec<u8>> {
    if tokens.is_empty() {
        bail!("No systemd-fido2 token found");
    }

    fido_init_once();
    let dev_paths = list_devices()?;

    // Open all devices up front; reused across all phases. Devices that
    // fail to open are skipped (and freed by Drop).
    let mut open_devs: Vec<Dev> = Vec::new();
    for path in &dev_paths {
        let Ok(mut dev) = Dev::new() else { continue };
        if dev.open(path) == FIDO_OK {
            open_devs.push(dev);
        }
    }
    if open_devs.is_empty() {
        bail!("No FIDO2 device could be opened");
    }

    // --- Phase 1: Probe (no PIN, no touch) ---
    // Keep a token in the running unless the probe definitively said the
    // credential is absent ("is not False" in the Python).
    let mut dev_creds: Vec<(usize, Vec<usize>)> = Vec::new(); // (dev idx, token idxs)
    for (di, dev) in open_devs.iter().enumerate() {
        let matching: Vec<usize> = tokens
            .iter()
            .enumerate()
            .filter(|(_, tok)| probe_credential(dev, &tok.cred_id) != Some(false))
            .map(|(ti, _)| ti)
            .collect();
        if !matching.is_empty() {
            dev_creds.push((di, matching));
        }
    }
    if dev_creds.is_empty() {
        bail!("No matching FIDO2 device/credential found");
    }

    // --- Phase 2: Select (touch-to-pick if multiple matches) ---
    let selected = if dev_creds.len() == 1 {
        0
    } else {
        touch_select(&open_devs, &dev_creds)
    };
    let (dev_idx, token_idxs) = &dev_creds[selected];
    let dev = &open_devs[*dev_idx];

    // --- Phase 3: Unlock with PIN on selected device only ---
    unsafe {
        fido2_sys::fido_dev_set_timeout(dev.0, 30000);
    }
    let pin = if pin.is_empty() { None } else { Some(pin) };
    let mut last_err: Option<Error> = None;
    for &ti in token_idxs {
        match get_hmac_secret(dev, &tokens[ti].cred_id, &tokens[ti].salt, pin) {
            Ok(secret) => return Ok(secret),
            Err(e) => last_err = Some(e),
        }
    }
    let last = last_err.map_or_else(|| "unknown error".to_string(), |e| e.to_string());
    bail!("FIDO2 unlock failed on selected device: {last}")
    // All `open_devs` closed and freed here (also on every error path).
}

/// Of `dev_paths` (hidraw paths), return those that strictly confirm one
/// of `cred_ids` (probe result definitively true; used by
/// CheckFido2Enrolled and the duplicate-enrollment rejection).
pub fn enrolled_paths(dev_paths: &[String], cred_ids: &[Vec<u8>]) -> Vec<String> {
    let mut enrolled = Vec::new();
    // Mirrors the Python's `if existing_creds and fido2_dev_paths` guard:
    // nothing is initialized or opened when either list is empty.
    if dev_paths.is_empty() || cred_ids.is_empty() {
        return enrolled;
    }

    fido_init_once();
    for dev_path in dev_paths {
        let Some(real_c) = canonical_cstring(dev_path) else {
            eprintln!("  {dev_path}: canonicalize failed");
            continue;
        };
        let Ok(mut dev) = Dev::new() else {
            eprintln!("  {dev_path}: fido_dev_new failed");
            continue;
        };
        let ret = dev.open(&real_c);
        if ret != FIDO_OK {
            eprintln!("  {dev_path}: fido_dev_open failed ret={ret:#x}");
            continue;
        }
        for cred_id in cred_ids {
            let result = probe_credential(&dev, cred_id);
            eprintln!("  {dev_path}: probe result={result:?}");
            if result == Some(true) {
                // Report the path as given by the caller, not canonicalized.
                enrolled.push(dev_path.clone());
                break;
            }
        }
        // `dev` closed and freed here.
    }
    enrolled
}

/// `fido_init(0)` exactly once per process. (The Python re-inits before
/// every operation; libfido2 only needs it once.)
fn fido_init_once() {
    static INIT: Once = Once::new();
    INIT.call_once(|| unsafe { fido2_sys::fido_init(0) });
}

/// True iff `path` is exactly `/dev/hidraw<digits>` — the hand-parsed
/// equivalent of the Python's `^/dev/hidraw\d+$` check (ASCII digits
/// only). Called on the canonicalized path.
fn is_hidraw_path(path: &str) -> bool {
    match path.strip_prefix("/dev/hidraw") {
        Some(num) => !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// Classify a `fido_dev_get_assert` return code from a UP=false / no-PIN
/// probe (the decision table of `_fido2_probe_credential`):
///
/// - `Some(false)` — credential definitely not on this device
///   (NO_CREDENTIALS).
/// - `Some(true)` — credential confirmed (OK, UP_REQUIRED, PIN_NOT_SET,
///   PIN_REQUIRED, PIN_INVALID — per CTAP2, allowList matching happens
///   before PIN verification, so these all imply the credential exists).
/// - `None` — ambiguous (transport error, unknown code, etc.).
fn classify_probe_ret(ret: c_int) -> Option<bool> {
    match ret {
        FIDO_ERR_NO_CREDENTIALS => Some(false),
        FIDO_OK
        | FIDO_ERR_UP_REQUIRED
        | FIDO_ERR_PIN_NOT_SET
        | FIDO_ERR_PIN_REQUIRED
        | FIDO_ERR_PIN_INVALID => Some(true),
        _ => None,
    }
}

/// Assert setup shared by both `fido_dev_get_assert` paths: bind the RP and
/// the all-zero 32-byte clientdata hash. Each caller then adds its own
/// allow_cred / up / uv (and, for unlock, the hmac-secret extension + salt).
fn setup_assert_common(assert: &Assert) {
    let zeroes = [0u8; 32];
    unsafe {
        fido2_sys::fido_assert_set_rp(assert.0, FIDO2_RP_ID_C.as_ptr());
        fido2_sys::fido_assert_set_clientdata_hash(assert.0, zeroes.as_ptr(), zeroes.len());
    }
}

/// Check if `dev` holds `cred_id` without consuming a touch or a PIN
/// retry (mirrors `_fido2_probe_credential`): assertion with UP=false,
/// UV=omit, no PIN, no hmac-secret extension. Callers use `== Some(true)`
/// for strict checks and `!= Some(false)` for optimistic ones.
fn probe_credential(dev: &Dev, cred_id: &[u8]) -> Option<bool> {
    let Ok(assert) = Assert::new() else {
        return None;
    };
    setup_assert_common(&assert);
    unsafe {
        fido2_sys::fido_assert_allow_cred(assert.0, cred_id.as_ptr(), cred_id.len());
        fido2_sys::fido_assert_set_up(assert.0, FIDO_OPT_FALSE);
        fido2_sys::fido_assert_set_uv(assert.0, FIDO_OPT_OMIT);
    }
    let ret = unsafe { fido2_sys::fido_dev_get_assert(dev.0, assert.0, ptr::null()) };
    eprintln!("    _fido2_probe_credential: ret={ret:#x}");
    classify_probe_ret(ret)
}

/// Perform a FIDO2 assertion with the hmac-secret extension and return
/// the secret bytes (mirrors `_fido2_get_hmac_secret`). UP=true so the
/// user must touch the token; `None`/empty pin sends no PIN.
fn get_hmac_secret(dev: &Dev, cred_id: &[u8], salt: &[u8], pin: Option<&str>) -> Result<Vec<u8>> {
    let assert = Assert::new()?;
    setup_assert_common(&assert);
    unsafe {
        fido2_sys::fido_assert_set_extensions(assert.0, FIDO_EXT_HMAC_SECRET);
        fido2_sys::fido_assert_set_hmac_salt(assert.0, salt.as_ptr(), salt.len());
        fido2_sys::fido_assert_allow_cred(assert.0, cred_id.as_ptr(), cred_id.len());
        fido2_sys::fido_assert_set_up(assert.0, FIDO_OPT_TRUE);
        fido2_sys::fido_assert_set_uv(assert.0, FIDO_OPT_FALSE);
    }

    let pin_c = pin_cstring(pin)?;
    let pin_ptr = pin_c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
    let ret = unsafe { fido2_sys::fido_dev_get_assert(dev.0, assert.0, pin_ptr) };
    if ret != FIDO_OK {
        bail!("fido_dev_get_assert failed: {ret}");
    }

    let secret_ptr = unsafe { fido2_sys::fido_assert_hmac_secret_ptr(assert.0, 0) };
    let secret_len = unsafe { fido2_sys::fido_assert_hmac_secret_len(assert.0, 0) };
    if secret_ptr.is_null() || secret_len == 0 {
        bail!("hmac-secret output is empty");
    }
    Ok(unsafe { slice::from_raw_parts(secret_ptr, secret_len) }.to_vec())
    // `assert` freed here (also on every error path).
}

/// Discover connected FIDO2 device paths via `fido_dev_info_manifest`
/// (mirrors `_fido2_list_devices`).
fn list_devices() -> Result<Vec<CString>> {
    const MAX_DEVS: usize = 16;
    let devlist = DevInfoList::new(MAX_DEVS)?;
    let mut found: usize = 0;
    let rc = unsafe { fido2_sys::fido_dev_info_manifest(devlist.ptr, MAX_DEVS, &mut found) };
    if rc != FIDO_OK || found == 0 {
        bail!("No FIDO2 device found");
    }
    let mut paths = Vec::new();
    for i in 0..found {
        let di = unsafe { fido2_sys::fido_dev_info_ptr(devlist.ptr, i) };
        if di.is_null() {
            continue;
        }
        let path = unsafe { fido2_sys::fido_dev_info_path(di) };
        if !path.is_null() {
            paths.push(unsafe { CStr::from_ptr(path) }.to_owned());
        }
    }
    if paths.is_empty() {
        bail!("No FIDO2 device found");
    }
    Ok(paths)
    // `devlist` freed here.
}

/// Make every candidate device blink and return the index into
/// `candidates` of the first one touched, cancelling the rest (mirrors
/// `_fido2_touch_select`). Polls each device round-robin with a 200 ms
/// timeout, looping until a touch arrives. No credentials or PINs are
/// involved.
fn touch_select(devs: &[Dev], candidates: &[(usize, Vec<usize>)]) -> usize {
    for (di, _) in candidates {
        unsafe {
            fido2_sys::fido_dev_get_touch_begin(devs[*di].0);
        }
    }
    loop {
        for (pos, (di, _)) in candidates.iter().enumerate() {
            let mut touched: c_int = 0;
            let ret =
                unsafe { fido2_sys::fido_dev_get_touch_status(devs[*di].0, &mut touched, 200) };
            if ret == FIDO_OK && touched != 0 {
                for (other, _) in candidates {
                    if other != di {
                        unsafe {
                            fido2_sys::fido_dev_cancel(devs[*other].0);
                        }
                    }
                }
                return pos;
            }
        }
    }
}

/// Convert an optional PIN for `fido_dev_make_cred`/`fido_dev_get_assert`:
/// `None` or empty → no PIN (NULL), mirroring the Python's
/// `pin.encode() if pin else None` truthiness.
fn pin_cstring(pin: Option<&str>) -> Result<Option<CString>> {
    match pin {
        Some(p) if !p.is_empty() => Ok(Some(
            CString::new(p).map_err(|_| Error::from("PIN contains a NUL byte"))?,
        )),
        _ => Ok(None),
    }
}

/// Canonicalize a device path and convert it to a C string for
/// `fido_dev_open`. `None` if the path does not resolve.
fn canonical_cstring(path: &str) -> Option<CString> {
    use std::os::unix::ffi::OsStringExt;
    let real = std::fs::canonicalize(path).ok()?;
    CString::new(real.into_os_string().into_vec()).ok()
}

// ---------------------------------------------------------------------------
// RAII wrappers for libfido2 handles
// ---------------------------------------------------------------------------

/// Define a newtype owning a `*mut fido2_sys::$ty`: `new()` allocates via
/// `$new` (null-checked) and `Drop` frees via `$free(&mut self.0)`. The
/// optional `close = $close` runs `$close(self.0)` before the free.
macro_rules! fido_raii {
    ($name:ident, $ty:ident, $new:ident, $free:ident $(, close = $close:ident)?) => {
        struct $name(*mut fido2_sys::$ty);

        impl $name {
            fn new() -> Result<Self> {
                let ptr = unsafe { fido2_sys::$new() };
                if ptr.is_null() {
                    bail!(concat!(stringify!($new), " failed"));
                }
                Ok(Self(ptr))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe {
                    $( fido2_sys::$close(self.0); )?
                    fido2_sys::$free(&mut self.0);
                }
            }
        }
    };
}

// Owned `fido_cred_t` / `fido_assert_t`, freed on drop.
fido_raii!(Cred, fido_cred_t, fido_cred_new, fido_cred_free);
fido_raii!(Assert, fido_assert_t, fido_assert_new, fido_assert_free);

// Owned `fido_dev_t`. Drop closes then frees; `fido_dev_close` on a
// never-opened device just returns FIDO_ERR_INVALID_ARGUMENT, so the
// unconditional close is harmless (the Python's `finally` blocks rely on
// the same behavior).
fido_raii!(
    Dev,
    fido_dev_t,
    fido_dev_new,
    fido_dev_free,
    close = fido_dev_close
);

impl Dev {
    /// `fido_dev_open`; returns the raw libfido2 code (`FIDO_OK` on
    /// success).
    fn open(&mut self, path: &CStr) -> c_int {
        unsafe { fido2_sys::fido_dev_open(self.0, path.as_ptr()) }
    }
}

/// Owned `fido_dev_info_t` list of capacity `cap`, freed on drop.
struct DevInfoList {
    ptr: *mut fido2_sys::fido_dev_info_t,
    cap: usize,
}

impl DevInfoList {
    fn new(cap: usize) -> Result<Self> {
        let ptr = unsafe { fido2_sys::fido_dev_info_new(cap) };
        if ptr.is_null() {
            bail!("fido_dev_info_new failed");
        }
        Ok(Self { ptr, cap })
    }
}

impl Drop for DevInfoList {
    fn drop(&mut self) {
        unsafe {
            fido2_sys::fido_dev_info_free(&mut self.ptr, self.cap);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raii_wrappers_construct_and_drop() {
        // The `*_new` allocators need no hardware, and Drop's close/free on an
        // unopened/empty handle is safe (`fido_dev_close` on a never-opened
        // device is a harmless no-op; `fido_dev_info_free` frees an empty list).
        // This is the only direct coverage of the `fido_raii!`-generated
        // new()/Drop; each value is dropped at the end of its statement.
        Cred::new().expect("fido_cred_new");
        Assert::new().expect("fido_assert_new");
        Dev::new().expect("fido_dev_new");
        DevInfoList::new(64).expect("fido_dev_info_new");
    }

    #[test]
    fn rp_id_cstring_matches_rp_id() {
        assert_eq!(FIDO2_RP_ID_C.to_str(), Ok(FIDO2_RP_ID));
    }

    #[test]
    fn hidraw_path_accepts_valid() {
        assert!(is_hidraw_path("/dev/hidraw0"));
        assert!(is_hidraw_path("/dev/hidraw12"));
        assert!(is_hidraw_path("/dev/hidraw7"));
        assert!(is_hidraw_path("/dev/hidraw007"));
        assert!(is_hidraw_path("/dev/hidraw9999"));
    }

    #[test]
    fn hidraw_path_rejects_invalid() {
        assert!(!is_hidraw_path("/dev/hidraw")); // no number
        assert!(!is_hidraw_path("/dev/hidraw1x")); // trailing junk
        assert!(!is_hidraw_path("/dev/hidrawx1"));
        assert!(!is_hidraw_path("/dev/hidraw0 ")); // trailing space
        assert!(!is_hidraw_path("/dev/hidraw0\n")); // trailing newline
        assert!(!is_hidraw_path("/dev/hidraw0/")); // trailing slash
        assert!(!is_hidraw_path("/dev/hidraw-1")); // sign is not a digit
        assert!(!is_hidraw_path("/dev/sda"));
        assert!(!is_hidraw_path("/tmp/evil"));
        assert!(!is_hidraw_path("/dev/HIDRAW0"));
        assert!(!is_hidraw_path("dev/hidraw0")); // not absolute
        assert!(!is_hidraw_path(" /dev/hidraw0")); // leading space
        assert!(!is_hidraw_path(""));
    }

    #[test]
    fn probe_ret_classification() {
        // Definitive miss.
        assert_eq!(classify_probe_ret(FIDO_ERR_NO_CREDENTIALS), Some(false));
        // Credential confirmed (allowList is matched before PIN checks).
        assert_eq!(classify_probe_ret(FIDO_OK), Some(true));
        assert_eq!(classify_probe_ret(FIDO_ERR_UP_REQUIRED), Some(true));
        assert_eq!(classify_probe_ret(FIDO_ERR_PIN_NOT_SET), Some(true));
        assert_eq!(classify_probe_ret(FIDO_ERR_PIN_REQUIRED), Some(true));
        assert_eq!(classify_probe_ret(FIDO_ERR_PIN_INVALID), Some(true));
        // Ambiguous: unknown CTAP codes and libfido2 internal (negative)
        // transport errors.
        assert_eq!(classify_probe_ret(0x7f), None); // FIDO_ERR_INTERNAL
        assert_eq!(classify_probe_ret(0x27), None); // CREDENTIAL_EXCLUDED
        assert_eq!(classify_probe_ret(-1), None); // FIDO_ERR_TX
        assert_eq!(classify_probe_ret(-2), None); // FIDO_ERR_RX
    }

    /// Pin the bindgen constants to the fido/err.h values. The Python
    /// reference hand-defines UP_REQUIRED = 0x11 and PIN_NOT_SET = 0x2B,
    /// which are wrong per the header; this documents the intentional
    /// difference.
    #[test]
    fn bindgen_constants_match_fido_err_h() {
        assert_eq!(FIDO_OK, 0);
        assert_eq!(FIDO_ERR_UP_REQUIRED, 0x3b);
        assert_eq!(FIDO_ERR_NO_CREDENTIALS, 0x2e);
        assert_eq!(FIDO_ERR_PIN_NOT_SET, 0x35);
        assert_eq!(FIDO_ERR_PIN_REQUIRED, 0x36);
        assert_eq!(FIDO_ERR_PIN_INVALID, 0x31);
        assert_eq!(COSE_ES256, -7);
        assert_eq!(FIDO_EXT_HMAC_SECRET, 0x01);
        assert_eq!(FIDO_OPT_OMIT, 0);
        assert_eq!(FIDO_OPT_FALSE, 1);
        assert_eq!(FIDO_OPT_TRUE, 2);
    }

    #[test]
    fn pin_cstring_truthiness() {
        assert_eq!(pin_cstring(None).unwrap(), None);
        assert_eq!(pin_cstring(Some("")).unwrap(), None);
        assert_eq!(
            pin_cstring(Some("1234")).unwrap(),
            Some(CString::new("1234").unwrap())
        );
        assert!(pin_cstring(Some("12\u{0}34")).is_err());
    }

    #[test]
    fn enroll_rejects_bad_paths() {
        // Not `.unwrap_err()`: Fido2Enrollment carries a secret and
        // deliberately has no Debug impl.
        fn expect_err(r: Result<Fido2Enrollment>) -> Error {
            match r {
                Ok(_) => panic!("expected enroll to fail"),
                Err(e) => e,
            }
        }
        // Nonexistent path: canonicalize fails -> invalid (original path
        // in the message).
        let err = expect_err(enroll("/tmp/no-such-fido2-device", None));
        assert_eq!(
            err.to_string(),
            "Invalid FIDO2 device path: /tmp/no-such-fido2-device"
        );
        // Exists but is not a hidraw node.
        let err = expect_err(enroll("/dev/null", None));
        assert_eq!(err.to_string(), "Invalid FIDO2 device path: /dev/null");
    }

    #[test]
    fn unlock_with_no_tokens_errors() {
        let err = unlock_from_tokens(&[], "").unwrap_err();
        assert_eq!(err.to_string(), "No systemd-fido2 token found");
    }

    #[test]
    fn enrolled_paths_empty_inputs() {
        // Either list empty -> no devices touched, empty result (mirrors
        // the Python's `if existing_creds and fido2_dev_paths` guard).
        assert!(enrolled_paths(&[], &[]).is_empty());
        assert!(enrolled_paths(&["/dev/hidraw0".to_string()], &[]).is_empty());
        assert!(enrolled_paths(&[], &[vec![1, 2, 3]]).is_empty());
    }
}
