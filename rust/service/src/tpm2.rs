//! TPM2 seal/unseal via tss-esapi.
//!
//! Port of the Python service's libtss2 ctypes code (see
//! dist/usr/sbin/luks-enroll-service, "libtss2 ctypes bindings" section).
//! Produces systemd-tpm2-compatible token material:
//!   - blob   = TPM2B_PRIVATE ‖ TPM2B_PUBLIC (Tss2_MU marshaled)
//!   - SRK    = persistent 0x81000001 if present, else transient ECC-P256
//!              primary (TCG SRK template, matches systemd), serialized
//!              with Esys_TR_Serialize for the `tpm2_srk` field
//!   - policy = trial-session PolicyPCR (+ PolicyAuthValue when a PIN is
//!              set); PIN auth value is SHA-256(pin) per systemd.

use crate::error::Result;
use crate::luks::Tpm2TokenRef;

pub struct SealResult {
    /// Marshaled TPM2B_PRIVATE + TPM2B_PUBLIC of the sealed object.
    pub blob: Vec<u8>,
    /// Policy digest the object is sealed to.
    pub policy_hash: Vec<u8>,
    /// Primary key algorithm name for the token JSON (always "ecc").
    pub primary_alg: &'static str,
    /// Esys_TR_Serialize output for the SRK (token `tpm2_srk` field).
    pub srk_blob: Vec<u8>,
}

/// Seal `secret` to the TPM bound to the given PCRs ("7" or "7+11" form,
/// SHA-256 bank). With a non-empty `pin`, additionally requires
/// PolicyAuthValue with auth = SHA-256(pin).
pub fn seal(_secret: &[u8], _pcrs: &str, _pin: &str) -> Result<SealResult> {
    todo!("implemented in Phase A3")
}

/// Unseal the secret from one of the device's systemd-tpm2 tokens.
///
/// Token preference order matches Python: with a PIN, PIN-required tokens
/// first; without, PIN-less first and PIN-required tokens are skipped.
/// Tries each candidate until one unseals; returns the raw secret bytes.
pub fn unseal_from_tokens(_tokens: &[Tpm2TokenRef], _pin: &str) -> Result<Vec<u8>> {
    todo!("implemented in Phase A3")
}
