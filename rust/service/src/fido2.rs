//! FIDO2 enrollment and unlock via libfido2 (fido2-sys bindgen bindings).
//!
//! Port of the Python service's libfido2 ctypes code. Credentials are
//! systemd-cryptenroll compatible: rp "io.systemd.cryptsetup", ES256,
//! hmac-secret extension, rk=false, uv=false, clientdata hash = 32 zero
//! bytes, random 32-byte user id and salt.

use crate::error::Result;
use crate::luks::Fido2TokenRef;

/// FIDO2 RP ID (matches systemd-cryptenroll).
pub const FIDO2_RP_ID: &str = "io.systemd.cryptsetup";

pub struct Fido2Enrollment {
    pub cred_id: Vec<u8>,
    pub salt: Vec<u8>,
    pub hmac_secret: Vec<u8>,
}

/// Create a credential on the token at `fido2_device` (a /dev/hidrawN
/// path; validated against the canonical path) and derive the hmac-secret
/// for LUKS enrollment.
pub fn enroll(_fido2_device: &str, _pin: Option<&str>) -> Result<Fido2Enrollment> {
    todo!("implemented in Phase A4")
}

/// Derive the passphrase secret from one of the device's enrolled FIDO2
/// tokens, in three phases to avoid burning PIN retries on the wrong
/// token: (1) probe each connected device per credential with UP=false /
/// no PIN, (2) touch-select when several match, (3) real hmac-secret
/// assertion with PIN on the selected device only.
pub fn unlock_from_tokens(_tokens: &[Fido2TokenRef], _pin: &str) -> Result<Vec<u8>> {
    todo!("implemented in Phase A4")
}

/// Of `dev_paths` (hidraw paths), return those that strictly confirm one
/// of `cred_ids` (probe result definitively true; used by
/// CheckFido2Enrolled and the duplicate-enrollment rejection).
pub fn enrolled_paths(_dev_paths: &[String], _cred_ids: &[Vec<u8>]) -> Vec<String> {
    todo!("implemented in Phase A4")
}
