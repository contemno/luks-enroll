//! TPM2 seal/unseal via tss-esapi.
//!
//! Port of the Python service's libtss2 ctypes code (see
//! dist/usr/sbin/luks-enroll-service, "libtss2 ctypes bindings" section).
//! Produces systemd-tpm2-compatible token material:
//!   - blob = TPM2B_PRIVATE ‖ TPM2B_PUBLIC (Tss2_MU marshaled)
//!   - SRK = persistent 0x81000001 if present, else a transient ECC-P256
//!     primary (TCG SRK template, matches systemd), serialized with
//!     Esys_TR_Serialize for the `tpm2_srk` field
//!   - policy = trial-session PolicyPCR (+ PolicyAuthValue when a PIN is
//!     set); PIN auth value is SHA-256(pin) per systemd.
//!
//! Implementation note: tss-esapi 7.7.0 does not wrap `Esys_TR_Serialize`
//! (it is listed as a missing function in context/general_esys_tr.rs) and
//! does not expose the raw `ESYS_CONTEXT` pointer of its safe `Context`,
//! so the ESYS command layer below talks to libtss2-esys directly through
//! the tss-esapi-sys bindings (re-exported as `tss_esapi::tss2_esys`),
//! mirroring the Python ctypes implementation call-for-call. tss-esapi's
//! typed builders are still used to construct the public templates and
//! PCR selections, which are converted to their TSS wire structs.
//!
//! Blob wire format: `Public`'s `Marshall` impl emits the bare TPMT_PUBLIC
//! (no size prefix), so it is NOT used for the blob; the blob parts are
//! produced with `Tss2_MU_TPM2B_PRIVATE_Marshal` / `Tss2_MU_TPM2B_PUBLIC_-
//! Marshal`, i.e. the TPM2B forms with the u16 size prefix, exactly like
//! the Python service and systemd-cryptenroll.

use std::convert::TryFrom;
use std::ffi::CString;
use std::ptr::{null, null_mut};

use sha2::{Digest as Sha2Digest, Sha256};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme, PcrSelectSize,
    PcrSelectionList, PcrSelectionListBuilder, PcrSlot, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyedHashParameters, SymmetricDefinitionObject,
};
use tss_esapi::tss2_esys as sys;
use zeroize::Zeroize;

use crate::bail;
use crate::error::{Error, Result};
use crate::luks::Tpm2TokenRef;

// ---------------------------------------------------------------------------
// TPM2 wire constants (kept as literals; parity with the Python service)
// ---------------------------------------------------------------------------

// SHA-1/384/512 ids are referenced by the unit tests only (the run-time
// bank mapping goes through HashingAlgorithm); kept for parity with the
// Python constant block.
#[allow(dead_code)]
const TPM2_ALG_SHA1: u16 = 0x0004;
const TPM2_ALG_SHA256: u16 = 0x000B;
#[allow(dead_code)]
const TPM2_ALG_SHA384: u16 = 0x000C;
#[allow(dead_code)]
const TPM2_ALG_SHA512: u16 = 0x000D;
const TPM2_ALG_NULL: u16 = 0x0010;
const TPM2_SE_POLICY: u8 = 0x01;
const TPM2_SE_TRIAL: u8 = 0x03;
/// Standard TCG persistent SRK handle (also what systemd uses).
const TPM2_PERSISTENT_SRK: u32 = 0x8100_0001;
/// Scratch buffer size for Tss2_MU_* marshaling (Python: _MARSHAL_BUF_MAX).
const MARSHAL_BUF_MAX: usize = 4096;

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
pub fn seal(secret: &[u8], pcrs: &str, pin: &str) -> Result<SealResult> {
    let pcr_list = build_pcr_selection_list(HashingAlgorithm::Sha256, pcrs)?;
    let ctx = EsysContext::new()?;
    let mut flusher = HandleFlusher::new(&ctx);
    seal_inner(&ctx, &mut flusher, secret, &pcr_list, pin)
}

/// Unseal the secret from one of the device's systemd-tpm2 tokens.
///
/// Token preference order matches Python: with a PIN, PIN-required tokens
/// first; without, PIN-less first and PIN-required tokens are skipped.
/// Tries each candidate until one unseals; returns the raw secret bytes.
pub fn unseal_from_tokens(tokens: &[Tpm2TokenRef], pin: &str) -> Result<Vec<u8>> {
    if tokens.is_empty() {
        bail!("No systemd-tpm2 token found");
    }
    let pin_provided = !pin.is_empty();
    let mut last_error = Error::from("No systemd-tpm2 token could be unsealed");
    for token in candidate_tokens(tokens, pin_provided) {
        match try_unseal_token(token, pin) {
            Ok(secret) => return Ok(secret),
            Err(e) => last_error = Error(format!("Token {}: {}", token.token_id, e)),
        }
    }
    Err(last_error)
}

// ---------------------------------------------------------------------------
// Pure helpers (no TPM access; unit-tested below)
// ---------------------------------------------------------------------------

/// Parse a "7+11" style PCR string into validated indices.
///
/// Mirrors the Python `_tpm2_build_pcr_selection` parsing: empty segments
/// are ignored, each index must be in 0..=23 and the resulting selection
/// must not be empty.
fn parse_pcr_indices(pcrs: &str) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    for part in pcrs.split('+') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let n: i64 = part
            .parse()
            .map_err(|_| Error(format!("Invalid PCR index '{part}'")))?;
        if !(0..=23).contains(&n) {
            bail!("PCR index {n} out of range (0-23)");
        }
        let n = n as u8;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    if out.is_empty() {
        bail!("PCR selection must not be empty");
    }
    Ok(out)
}

/// Map a token's PCR bank name to the hash algorithm, defaulting to
/// SHA-256 for unknown names (parity with Python's dict .get default).
fn pcr_bank_to_alg(bank: &str) -> HashingAlgorithm {
    match bank {
        "sha1" => HashingAlgorithm::Sha1,
        "sha256" => HashingAlgorithm::Sha256,
        "sha384" => HashingAlgorithm::Sha384,
        "sha512" => HashingAlgorithm::Sha512,
        _ => HashingAlgorithm::Sha256,
    }
}

/// Build a single-bank PCR selection list (sizeofSelect = 3, like the
/// Python wire builder and systemd).
fn build_pcr_selection_list(bank: HashingAlgorithm, pcrs: &str) -> Result<PcrSelectionList> {
    let indices = parse_pcr_indices(pcrs)?;
    let mut slots: Vec<PcrSlot> = Vec::with_capacity(indices.len());
    for n in indices {
        let slot = PcrSlot::try_from(1u32 << n)
            .map_err(|e| Error(format!("PCR slot conversion failed: {e}")))?;
        slots.push(slot);
    }
    PcrSelectionListBuilder::new()
        .with_size_of_select(PcrSelectSize::ThreeOctets)
        .with_selection(bank, &slots)
        .build()
        .map_err(|e| Error(format!("Failed to build PCR selection: {e}")))
}

/// Order the unseal candidates and drop tokens that cannot be tried.
///
/// Stable sort by `pin_required != pin_provided` (Python parity): with a
/// PIN, PIN-required tokens come first; without one, PIN-less tokens come
/// first and PIN-required tokens are skipped entirely.
fn candidate_tokens(tokens: &[Tpm2TokenRef], pin_provided: bool) -> Vec<&Tpm2TokenRef> {
    let mut candidates: Vec<&Tpm2TokenRef> = tokens.iter().collect();
    candidates.sort_by_key(|t| t.pin_required != pin_provided);
    // Skip PIN-required tokens when no PIN was provided.
    candidates.retain(|t| !t.pin_required || pin_provided);
    candidates
}

// ---------------------------------------------------------------------------
// Templates (tss-esapi typed builders)
// ---------------------------------------------------------------------------

/// TCG ECC SRK template, identical to the Python `_tpm2_build_ecc_srk_template`
/// (and systemd): ECC NIST-P256, nameAlg SHA-256, AES-128-CFB symmetric,
/// NULL scheme/KDF, empty unique, attributes FIXEDTPM | FIXEDPARENT |
/// SENSITIVEDATAORIGIN | USERWITHAUTH | NODA | RESTRICTED | DECRYPT.
fn ecc_srk_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| Error(format!("SRK attributes build failed: {e}")))?;
    let ecc_parameters = PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .build()
        .map_err(|e| Error(format!("SRK ECC parameters build failed: {e}")))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| Error(format!("SRK template build failed: {e}")))
}

/// Sealed-object template, identical to the Python `_tpm2_build_seal_template`
/// (and systemd): KEYEDHASH, nameAlg SHA-256, NULL scheme, empty unique,
/// authPolicy = `policy_digest`, attributes FIXEDTPM | FIXEDPARENT
/// (+ USERWITHAUTH only with a PIN; deliberately no NODA and no
/// SENSITIVEDATAORIGIN).
fn seal_template(policy_digest: &[u8], use_pin: bool) -> Result<Public> {
    let mut attributes_builder = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true);
    if use_pin {
        attributes_builder = attributes_builder.with_user_with_auth(true);
    }
    let object_attributes = attributes_builder
        .build()
        .map_err(|e| Error(format!("Seal attributes build failed: {e}")))?;
    let auth_policy = Digest::try_from(policy_digest.to_vec())
        .map_err(|e| Error(format!("Policy digest conversion failed: {e}")))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_auth_policy(auth_policy)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|e| Error(format!("Seal template build failed: {e}")))
}

/// TPM2B_SENSITIVE_CREATE with data = `secret` and userAuth = SHA-256(pin)
/// when a PIN is set (Python `_tpm2_build_sensitive_create`).
fn build_sensitive_create(secret: &[u8], pin: &str) -> Result<sys::TPM2B_SENSITIVE_CREATE> {
    // The TPM2B size field is recomputed by Tss2_MU during command
    // marshaling; mirror tss-esapi's create() and fill in the struct size.
    let mut sensitive_create = sys::TPM2B_SENSITIVE_CREATE {
        size: std::mem::size_of::<sys::TPMS_SENSITIVE_CREATE>() as u16,
        ..Default::default()
    };
    if !pin.is_empty() {
        let pin_auth = Sha256::digest(pin.as_bytes());
        sensitive_create.sensitive.userAuth.size = pin_auth.len() as u16;
        sensitive_create.sensitive.userAuth.buffer[..pin_auth.len()].copy_from_slice(&pin_auth);
    }
    let data_max = sensitive_create.sensitive.data.buffer.len();
    if secret.len() > data_max {
        bail!(
            "Secret too large to seal ({} > {} bytes)",
            secret.len(),
            data_max
        );
    }
    sensitive_create.sensitive.data.size = secret.len() as u16;
    sensitive_create.sensitive.data.buffer[..secret.len()].copy_from_slice(secret);
    Ok(sensitive_create)
}

// ---------------------------------------------------------------------------
// Raw ESYS context (tss-esapi-sys; see module docs for why this is raw)
// ---------------------------------------------------------------------------

/// Owned ESYS context + TCTI context, finalized on drop.
struct EsysContext {
    esys: *mut sys::ESYS_CONTEXT,
    tcti: *mut sys::TSS2_TCTI_CONTEXT,
}

/// TCTI configuration string: honor the same environment variables as
/// tss-esapi's `TctiNameConf::from_environment_variable` (TPM2TOOLS_TCTI,
/// TCTI, TEST_TCTI in that order), else default to the kernel resource
/// manager device. This enables swtpm-based testing.
fn tcti_conf() -> String {
    for var in ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"] {
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                return value;
            }
        }
    }
    String::from("device:/dev/tpmrm0")
}

impl EsysContext {
    fn new() -> Result<Self> {
        let conf = CString::new(tcti_conf())
            .map_err(|_| Error::from("TCTI configuration contains a NUL byte"))?;
        let mut tcti: *mut sys::TSS2_TCTI_CONTEXT = null_mut();
        let rc = unsafe { sys::Tss2_TctiLdr_Initialize(conf.as_ptr(), &mut tcti) };
        if rc != 0 {
            bail!("Tss2_TctiLdr_Initialize failed: 0x{rc:08x}");
        }
        let mut esys: *mut sys::ESYS_CONTEXT = null_mut();
        let rc = unsafe { sys::Esys_Initialize(&mut esys, tcti, null_mut()) };
        if rc != 0 {
            unsafe { sys::Tss2_TctiLdr_Finalize(&mut tcti) };
            bail!("Esys_Initialize failed: 0x{rc:08x}");
        }
        Ok(EsysContext { esys, tcti })
    }

    /// Flush a TPM handle, ignoring errors (cleanup path; Python parity).
    fn flush_quiet(&self, handle: sys::ESYS_TR) {
        let _ = unsafe { sys::Esys_FlushContext(self.esys, handle) };
    }
}

impl Drop for EsysContext {
    fn drop(&mut self) {
        unsafe {
            sys::Esys_Finalize(&mut self.esys);
            sys::Tss2_TctiLdr_Finalize(&mut self.tcti);
        }
    }
}

/// Tracks ESYS transient handles and flushes any still held when dropped, so
/// seal/unseal free their handles on success and on every error path.
struct HandleFlusher<'a> {
    ctx: &'a EsysContext,
    handles: Vec<sys::ESYS_TR>,
}

impl<'a> HandleFlusher<'a> {
    fn new(ctx: &'a EsysContext) -> Self {
        Self {
            ctx,
            handles: Vec::new(),
        }
    }

    /// Track a handle to be flushed on drop.
    fn track(&mut self, handle: sys::ESYS_TR) {
        self.handles.push(handle);
    }

    /// Flush now and stop tracking — for a handle that must be freed before a
    /// later TPM op (the trial session and the transient SRK in `seal_inner`).
    fn flush_now(&mut self, handle: sys::ESYS_TR) {
        self.ctx.flush_quiet(handle);
        self.handles.retain(|&h| h != handle);
    }
}

impl Drop for HandleFlusher<'_> {
    fn drop(&mut self) {
        for &handle in &self.handles {
            self.ctx.flush_quiet(handle);
        }
    }
}

/// Free an ESYS-allocated output pointer (no-op for NULL).
fn esys_free<T>(ptr: *mut T) {
    if !ptr.is_null() {
        unsafe { sys::Esys_Free(ptr.cast()) };
    }
}

/// Esys_TR_Serialize the handle (token `tpm2_srk` field format).
fn tr_serialize(ctx: &EsysContext, handle: sys::ESYS_TR) -> Result<Vec<u8>> {
    let mut buffer: *mut u8 = null_mut();
    let mut buffer_size: sys::size_t = 0;
    let rc = unsafe { sys::Esys_TR_Serialize(ctx.esys, handle, &mut buffer, &mut buffer_size) };
    if rc != 0 {
        bail!("Esys_TR_Serialize failed: 0x{rc:08x}");
    }
    let out = if buffer.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(buffer, buffer_size as usize) }.to_vec()
    };
    esys_free(buffer);
    Ok(out)
}

/// Get the SRK, preferring the persistent SRK at 0x81000001 and creating
/// a transient ECC primary under the owner hierarchy otherwise (Python
/// `_tpm2_get_srk`). Returns (handle, caller-must-flush, serialized SRK).
fn get_srk(ctx: &EsysContext) -> Result<(sys::ESYS_TR, bool, Vec<u8>)> {
    let mut srk: sys::ESYS_TR = sys::ESYS_TR_NONE;

    // Try the persistent SRK first (standard TCG handle).
    let rc = unsafe {
        sys::Esys_TR_FromTPMPublic(
            ctx.esys,
            TPM2_PERSISTENT_SRK,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            &mut srk,
        )
    };
    if rc == 0 {
        let srk_blob = tr_serialize(ctx, srk)?;
        return Ok((srk, false, srk_blob));
    }

    // No persistent SRK — create a transient one with empty owner auth.
    let empty_auth = sys::TPM2B_AUTH::default();
    // Python ignores the Esys_TR_SetAuth return code here; do the same.
    let _ = unsafe { sys::Esys_TR_SetAuth(ctx.esys, sys::ESYS_TR_RH_OWNER, &empty_auth) };

    let in_public = sys::TPM2B_PUBLIC::try_from(ecc_srk_template()?)
        .map_err(|e| Error(format!("SRK template conversion failed: {e}")))?;
    let in_sensitive = sys::TPM2B_SENSITIVE_CREATE {
        size: std::mem::size_of::<sys::TPMS_SENSITIVE_CREATE>() as u16,
        ..Default::default()
    };
    let outside_info = sys::TPM2B_DATA::default();
    let creation_pcr = sys::TPML_PCR_SELECTION::default();

    let mut out_public: *mut sys::TPM2B_PUBLIC = null_mut();
    let mut creation_data: *mut sys::TPM2B_CREATION_DATA = null_mut();
    let mut creation_hash: *mut sys::TPM2B_DIGEST = null_mut();
    let mut creation_ticket: *mut sys::TPMT_TK_CREATION = null_mut();

    let rc = unsafe {
        sys::Esys_CreatePrimary(
            ctx.esys,
            sys::ESYS_TR_RH_OWNER,
            sys::ESYS_TR_PASSWORD,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            &in_sensitive,
            &in_public,
            &outside_info,
            &creation_pcr,
            &mut srk,
            &mut out_public,
            &mut creation_data,
            &mut creation_hash,
            &mut creation_ticket,
        )
    };
    if rc != 0 {
        bail!("Esys_CreatePrimary failed: 0x{rc:08x}");
    }
    esys_free(out_public);
    esys_free(creation_data);
    esys_free(creation_hash);
    esys_free(creation_ticket);

    let srk_blob = tr_serialize(ctx, srk)?;
    Ok((srk, true, srk_blob))
}

/// Start an unbound/unsalted auth session (SHA-256, symmetric NULL).
/// `kind` is "trial" or "policy" (used in the error message, Python parity).
fn start_session(ctx: &EsysContext, session_type: u8, kind: &str) -> Result<sys::ESYS_TR> {
    let sym_def = sys::TPMT_SYM_DEF {
        algorithm: TPM2_ALG_NULL,
        ..Default::default()
    };
    let mut session: sys::ESYS_TR = sys::ESYS_TR_NONE;
    let rc = unsafe {
        sys::Esys_StartAuthSession(
            ctx.esys,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            null(),
            session_type,
            &sym_def,
            TPM2_ALG_SHA256,
            &mut session,
        )
    };
    if rc != 0 {
        bail!("Esys_StartAuthSession ({kind}) failed: 0x{rc:08x}");
    }
    Ok(session)
}

/// PolicyPCR with an empty expected digest (the TPM reads current values).
fn policy_pcr(ctx: &EsysContext, session: sys::ESYS_TR, pcr_list: &PcrSelectionList) -> Result<()> {
    let pcr_selection: sys::TPML_PCR_SELECTION = pcr_list.clone().into();
    let empty_digest = sys::TPM2B_DIGEST::default();
    let rc = unsafe {
        sys::Esys_PolicyPCR(
            ctx.esys,
            session,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            &empty_digest,
            &pcr_selection,
        )
    };
    if rc != 0 {
        bail!("Esys_PolicyPCR failed: 0x{rc:08x}");
    }
    Ok(())
}

fn policy_auth_value(ctx: &EsysContext, session: sys::ESYS_TR) -> Result<()> {
    let rc = unsafe {
        sys::Esys_PolicyAuthValue(
            ctx.esys,
            session,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
        )
    };
    if rc != 0 {
        bail!("Esys_PolicyAuthValue failed: 0x{rc:08x}");
    }
    Ok(())
}

fn policy_get_digest(ctx: &EsysContext, session: sys::ESYS_TR) -> Result<Vec<u8>> {
    let mut digest_ptr: *mut sys::TPM2B_DIGEST = null_mut();
    let rc = unsafe {
        sys::Esys_PolicyGetDigest(
            ctx.esys,
            session,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            &mut digest_ptr,
        )
    };
    if rc != 0 {
        bail!("Esys_PolicyGetDigest failed: 0x{rc:08x}");
    }
    let digest = unsafe { &*digest_ptr };
    let len = (digest.size as usize).min(digest.buffer.len());
    let out = digest.buffer[..len].to_vec();
    esys_free(digest_ptr);
    Ok(out)
}

/// Marshal a TPM2B_PRIVATE to its wire form (u16 size prefix + bytes).
fn marshal_tpm2b_private(private: &sys::TPM2B_PRIVATE) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; MARSHAL_BUF_MAX];
    let mut offset: sys::size_t = 0;
    let rc = unsafe {
        sys::Tss2_MU_TPM2B_PRIVATE_Marshal(
            private,
            buf.as_mut_ptr(),
            MARSHAL_BUF_MAX as sys::size_t,
            &mut offset,
        )
    };
    if rc != 0 {
        bail!("Marshal failed: 0x{rc:08x}");
    }
    buf.truncate(offset as usize);
    Ok(buf)
}

/// Marshal a TPM2B_PUBLIC to its wire form (u16 size prefix + TPMT_PUBLIC).
fn marshal_tpm2b_public(public: &sys::TPM2B_PUBLIC) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; MARSHAL_BUF_MAX];
    let mut offset: sys::size_t = 0;
    let rc = unsafe {
        sys::Tss2_MU_TPM2B_PUBLIC_Marshal(
            public,
            buf.as_mut_ptr(),
            MARSHAL_BUF_MAX as sys::size_t,
            &mut offset,
        )
    };
    if rc != 0 {
        bail!("Marshal failed: 0x{rc:08x}");
    }
    buf.truncate(offset as usize);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Seal
// ---------------------------------------------------------------------------

fn seal_inner(
    ctx: &EsysContext,
    flusher: &mut HandleFlusher,
    secret: &[u8],
    pcr_list: &PcrSelectionList,
    pin: &str,
) -> Result<SealResult> {
    // --- Get SRK (persistent at 0x81000001, or create transient) ---
    let (srk, srk_need_flush, srk_blob) = get_srk(ctx)?;
    if srk_need_flush {
        flusher.track(srk);
    }

    // --- Compute policy digest via trial session ---
    let trial_session = start_session(ctx, TPM2_SE_TRIAL, "trial")?;
    flusher.track(trial_session);

    policy_pcr(ctx, trial_session, pcr_list)?;
    if !pin.is_empty() {
        policy_auth_value(ctx, trial_session)?;
    }
    let policy_hash = policy_get_digest(ctx, trial_session)?;

    // Flush the trial session.
    flusher.flush_now(trial_session);

    // --- Seal the secret ---
    let in_public = sys::TPM2B_PUBLIC::try_from(seal_template(&policy_hash, !pin.is_empty())?)
        .map_err(|e| Error(format!("Seal template conversion failed: {e}")))?;
    let mut in_sensitive = build_sensitive_create(secret, pin)?;
    let outside_info = sys::TPM2B_DATA::default();
    let creation_pcr = sys::TPML_PCR_SELECTION::default();

    let mut out_private: *mut sys::TPM2B_PRIVATE = null_mut();
    let mut out_public: *mut sys::TPM2B_PUBLIC = null_mut();
    let mut creation_data: *mut sys::TPM2B_CREATION_DATA = null_mut();
    let mut creation_hash: *mut sys::TPM2B_DIGEST = null_mut();
    let mut creation_ticket: *mut sys::TPMT_TK_CREATION = null_mut();

    let rc = unsafe {
        sys::Esys_Create(
            ctx.esys,
            srk,
            sys::ESYS_TR_PASSWORD,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            &in_sensitive,
            &in_public,
            &outside_info,
            &creation_pcr,
            &mut out_private,
            &mut out_public,
            &mut creation_data,
            &mut creation_hash,
            &mut creation_ticket,
        )
    };
    // Scrub the in-memory copy of the secret (and PIN hash) regardless of rc.
    in_sensitive.sensitive.userAuth.buffer.zeroize();
    in_sensitive.sensitive.data.buffer.zeroize();
    if rc != 0 {
        bail!("Esys_Create (seal) failed: 0x{rc:08x}");
    }

    // Marshal sealed private + public into the token blob.
    let blob = (|| -> Result<Vec<u8>> {
        let mut blob = marshal_tpm2b_private(unsafe { &*out_private })?;
        blob.extend_from_slice(&marshal_tpm2b_public(unsafe { &*out_public })?);
        Ok(blob)
    })();
    esys_free(out_private);
    esys_free(out_public);
    esys_free(creation_data);
    esys_free(creation_hash);
    esys_free(creation_ticket);
    let blob = blob?;

    // Flush the SRK (only if we created a transient one).
    if srk_need_flush {
        flusher.flush_now(srk);
    }

    Ok(SealResult {
        blob,
        policy_hash,
        primary_alg: "ecc",
        srk_blob,
    })
}

// ---------------------------------------------------------------------------
// Unseal
// ---------------------------------------------------------------------------

/// Attempt to unseal a single token. Errors are step-tagged like the
/// Python implementation ("Esys_Load failed: 0x..."); the caller adds the
/// "Token {id}: " prefix.
fn try_unseal_token(token: &Tpm2TokenRef, pin: &str) -> Result<Vec<u8>> {
    let pcr_list = build_pcr_selection_list(pcr_bank_to_alg(&token.pcr_bank), &token.pcrs)?;
    let ctx = EsysContext::new()?;
    let mut flusher = HandleFlusher::new(&ctx);
    unseal_inner(&ctx, &mut flusher, token, &pcr_list, pin)
}

fn unseal_inner(
    ctx: &EsysContext,
    flusher: &mut HandleFlusher,
    token: &Tpm2TokenRef,
    pcr_list: &PcrSelectionList,
    pin: &str,
) -> Result<Vec<u8>> {
    // --- Get SRK (persistent at 0x81000001, or create transient) ---
    let (srk, srk_need_flush, _srk_blob) = get_srk(ctx)?;
    if srk_need_flush {
        flusher.track(srk);
    }

    // Unmarshal the sealed private + public from the blob at a running offset.
    let blob = &token.blob;
    let mut offset: sys::size_t = 0;
    let mut seal_private = sys::TPM2B_PRIVATE::default();
    let rc = unsafe {
        sys::Tss2_MU_TPM2B_PRIVATE_Unmarshal(
            blob.as_ptr(),
            blob.len() as sys::size_t,
            &mut offset,
            &mut seal_private,
        )
    };
    if rc != 0 {
        bail!("Unmarshal TPM2B_PRIVATE failed: 0x{rc:08x}");
    }
    let mut seal_public = sys::TPM2B_PUBLIC::default();
    let rc = unsafe {
        sys::Tss2_MU_TPM2B_PUBLIC_Unmarshal(
            blob.as_ptr(),
            blob.len() as sys::size_t,
            &mut offset,
            &mut seal_public,
        )
    };
    if rc != 0 {
        bail!("Unmarshal TPM2B_PUBLIC failed: 0x{rc:08x}");
    }

    // Load the sealed object under the SRK (password session, empty auth).
    let mut loaded: sys::ESYS_TR = sys::ESYS_TR_NONE;
    let rc = unsafe {
        sys::Esys_Load(
            ctx.esys,
            srk,
            sys::ESYS_TR_PASSWORD,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            &seal_private,
            &seal_public,
            &mut loaded,
        )
    };
    if rc != 0 {
        bail!("Esys_Load failed: 0x{rc:08x}");
    }
    flusher.track(loaded);

    // If a PIN is used, set auth = SHA-256(pin) on the loaded object.
    if token.pin_required && !pin.is_empty() {
        let pin_auth = Sha256::digest(pin.as_bytes());
        let mut auth = sys::TPM2B_AUTH {
            size: pin_auth.len() as u16,
            ..Default::default()
        };
        auth.buffer[..pin_auth.len()].copy_from_slice(&pin_auth);
        // Python ignores the Esys_TR_SetAuth return code; do the same.
        let _ = unsafe { sys::Esys_TR_SetAuth(ctx.esys, loaded, &auth) };
        auth.buffer.zeroize();
    }

    // Start the policy session and replay the policy.
    let policy_session = start_session(ctx, TPM2_SE_POLICY, "policy")?;
    flusher.track(policy_session);

    policy_pcr(ctx, policy_session, pcr_list)?;
    if token.pin_required {
        policy_auth_value(ctx, policy_session)?;
    }

    // Unseal.
    let mut out_data: *mut sys::TPM2B_SENSITIVE_DATA = null_mut();
    let rc = unsafe {
        sys::Esys_Unseal(
            ctx.esys,
            loaded,
            policy_session,
            sys::ESYS_TR_NONE,
            sys::ESYS_TR_NONE,
            &mut out_data,
        )
    };
    if rc != 0 {
        bail!("Esys_Unseal failed: 0x{rc:08x}");
    }
    let sensitive = unsafe { &*out_data };
    let len = (sensitive.size as usize).min(sensitive.buffer.len());
    let secret = sensitive.buffer[..len].to_vec();
    esys_free(out_data);
    Ok(secret)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn token(id: &str, pin_required: bool) -> Tpm2TokenRef {
        Tpm2TokenRef {
            token_id: id.to_string(),
            blob: Vec::new(),
            pcrs: "7".to_string(),
            pcr_bank: "sha256".to_string(),
            pin_required,
        }
    }

    fn ids(tokens: Vec<&Tpm2TokenRef>) -> Vec<String> {
        tokens.iter().map(|t| t.token_id.clone()).collect()
    }

    // --- PCR string parsing -------------------------------------------------

    #[test]
    fn parse_pcr_valid() {
        assert_eq!(parse_pcr_indices("7").unwrap(), vec![7]);
        assert_eq!(parse_pcr_indices("7+11").unwrap(), vec![7, 11]);
        assert_eq!(parse_pcr_indices("0+23").unwrap(), vec![0, 23]);
        // Whitespace and empty segments are tolerated, like Python's
        // strip()/filter in _tpm2_build_pcr_selection.
        assert_eq!(parse_pcr_indices(" 7 + 11 ").unwrap(), vec![7, 11]);
        assert_eq!(parse_pcr_indices("7++11").unwrap(), vec![7, 11]);
    }

    #[test]
    fn parse_pcr_empty_selection() {
        for s in ["", "+", "  "] {
            let err = parse_pcr_indices(s).unwrap_err();
            assert_eq!(
                err.to_string(),
                "PCR selection must not be empty",
                "input {s:?}"
            );
        }
    }

    #[test]
    fn parse_pcr_out_of_range() {
        let err = parse_pcr_indices("24").unwrap_err();
        assert_eq!(err.to_string(), "PCR index 24 out of range (0-23)");
        let err = parse_pcr_indices("7+99").unwrap_err();
        assert_eq!(err.to_string(), "PCR index 99 out of range (0-23)");
        let err = parse_pcr_indices("-1").unwrap_err();
        assert_eq!(err.to_string(), "PCR index -1 out of range (0-23)");
    }

    #[test]
    fn parse_pcr_not_a_number() {
        assert!(parse_pcr_indices("abc").is_err());
        assert!(parse_pcr_indices("7+abc").is_err());
    }

    // --- Bank name mapping --------------------------------------------------

    #[test]
    fn bank_name_mapping() {
        // Wire algorithm ids: sha1 0x4, sha256 0xB, sha384 0xC, sha512 0xD.
        let alg_id = |bank: &str| -> u16 { pcr_bank_to_alg(bank).into() };
        assert_eq!(alg_id("sha1"), TPM2_ALG_SHA1);
        assert_eq!(alg_id("sha256"), TPM2_ALG_SHA256);
        assert_eq!(alg_id("sha384"), TPM2_ALG_SHA384);
        assert_eq!(alg_id("sha512"), TPM2_ALG_SHA512);
        // Unknown bank names fall back to SHA-256.
        assert_eq!(alg_id("sm3_256"), TPM2_ALG_SHA256);
        assert_eq!(alg_id(""), TPM2_ALG_SHA256);
    }

    #[test]
    fn pcr_selection_wire_layout() {
        // Verify the typed builder produces the same TPML_PCR_SELECTION the
        // Python wire builder packs: count=1, hash=0xB, sizeofSelect=3,
        // bitmask byte n/8 bit n%8.
        let list = build_pcr_selection_list(HashingAlgorithm::Sha256, "7+11").unwrap();
        let tpml: sys::TPML_PCR_SELECTION = list.into();
        assert_eq!(tpml.count, 1);
        assert_eq!(tpml.pcrSelections[0].hash, TPM2_ALG_SHA256);
        assert_eq!(tpml.pcrSelections[0].sizeofSelect, 3);
        assert_eq!(tpml.pcrSelections[0].pcrSelect[0], 0x80); // PCR 7
        assert_eq!(tpml.pcrSelections[0].pcrSelect[1], 0x08); // PCR 11
        assert_eq!(tpml.pcrSelections[0].pcrSelect[2], 0x00);

        let list = build_pcr_selection_list(HashingAlgorithm::Sha1, "0+23").unwrap();
        let tpml: sys::TPML_PCR_SELECTION = list.into();
        assert_eq!(tpml.pcrSelections[0].hash, TPM2_ALG_SHA1);
        assert_eq!(tpml.pcrSelections[0].pcrSelect[0], 0x01); // PCR 0
        assert_eq!(tpml.pcrSelections[0].pcrSelect[2], 0x80); // PCR 23
    }

    // --- Token sort/skip ordering -------------------------------------------

    #[test]
    fn candidate_order_with_pin_prefers_pin_tokens() {
        let tokens = vec![
            token("0", false),
            token("1", true),
            token("2", false),
            token("3", true),
        ];
        // PIN-required tokens first, original order preserved within groups
        // (stable sort), nothing skipped.
        assert_eq!(ids(candidate_tokens(&tokens, true)), ["1", "3", "0", "2"]);
    }

    #[test]
    fn candidate_order_without_pin_skips_pin_tokens() {
        let tokens = vec![
            token("0", true),
            token("1", false),
            token("2", true),
            token("3", false),
        ];
        // PIN-required tokens are dropped entirely when no PIN is provided.
        assert_eq!(ids(candidate_tokens(&tokens, false)), ["1", "3"]);
    }

    #[test]
    fn candidate_order_all_pinless() {
        let tokens = vec![token("a", false), token("b", false)];
        assert_eq!(ids(candidate_tokens(&tokens, false)), ["a", "b"]);
        assert_eq!(ids(candidate_tokens(&tokens, true)), ["a", "b"]);
    }

    // --- unseal_from_tokens edge cases (no TPM needed) -----------------------

    #[test]
    fn unseal_no_tokens() {
        let err = unseal_from_tokens(&[], "").unwrap_err();
        assert_eq!(err.to_string(), "No systemd-tpm2 token found");
    }

    #[test]
    fn unseal_all_tokens_skipped_without_pin() {
        // Only PIN-required tokens and no PIN: every candidate is skipped,
        // so the default last_error is returned (Python parity).
        let tokens = vec![token("0", true), token("1", true)];
        let err = unseal_from_tokens(&tokens, "").unwrap_err();
        assert_eq!(err.to_string(), "No systemd-tpm2 token could be unsealed");
    }

    // --- Full roundtrip against a real TPM (swtpm or hardware) ---------------

    /// Serializes the roundtrip tests: cargo runs tests on parallel
    /// threads, but a raw swtpm socket TCTI has no resource manager, and
    /// two concurrent seal/unseal flows need more transient object slots
    /// than the reference TPM's three (-> TPM_RC_OBJECT_MEMORY, 0x902).
    /// Note: repeated wrong-PIN runs against one long-lived swtpm also
    /// accumulate dictionary-attack failures (the sealed object has no
    /// NODA, like systemd's); restart swtpm with a fresh state dir if
    /// unseals start failing with TPM_RC_LOCKOUT (0x921).
    static TPM_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// True when some TCTI is configured or the kernel resource manager
    /// device exists; the roundtrip tests are additionally #[ignore]d so
    /// they only run on demand (cargo test -- --ignored) with e.g.:
    ///   TCTI=swtpm:host=127.0.0.1,port=2321 cargo test ... -- --ignored
    fn tpm_available() -> bool {
        for var in ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"] {
            if std::env::var(var).map(|v| !v.is_empty()).unwrap_or(false) {
                return true;
            }
        }
        std::path::Path::new("/dev/tpmrm0").exists()
    }

    #[test]
    #[ignore = "requires a TPM (set TCTI, e.g. to a running swtpm)"]
    fn roundtrip_seal_unseal_no_pin() {
        if !tpm_available() {
            eprintln!("skipping: no TCTI configured and no /dev/tpmrm0");
            return;
        }
        let _serial = TPM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let secret = b"correct horse battery staple";
        let sealed = seal(secret, "7", "").expect("seal failed");
        assert_eq!(sealed.primary_alg, "ecc");
        assert_eq!(sealed.policy_hash.len(), 32);
        assert!(!sealed.srk_blob.is_empty());

        // Blob layout: TPM2B_PRIVATE ‖ TPM2B_PUBLIC, both with a big-endian
        // u16 size prefix (systemd-tpm2 compatible).
        let priv_len = u16::from_be_bytes([sealed.blob[0], sealed.blob[1]]) as usize;
        let pub_off = 2 + priv_len;
        assert!(pub_off + 2 < sealed.blob.len(), "no room for TPM2B_PUBLIC");
        let pub_len = u16::from_be_bytes([sealed.blob[pub_off], sealed.blob[pub_off + 1]]) as usize;
        assert_eq!(
            pub_off + 2 + pub_len,
            sealed.blob.len(),
            "trailing bytes in blob"
        );

        let tok = Tpm2TokenRef {
            token_id: "0".to_string(),
            blob: sealed.blob,
            pcrs: "7".to_string(),
            pcr_bank: "sha256".to_string(),
            pin_required: false,
        };
        let out = unseal_from_tokens(&[tok], "").expect("unseal failed");
        assert_eq!(out, secret);
    }

    #[test]
    #[ignore = "requires a TPM (set TCTI, e.g. to a running swtpm)"]
    fn roundtrip_seal_unseal_with_pin() {
        if !tpm_available() {
            eprintln!("skipping: no TCTI configured and no /dev/tpmrm0");
            return;
        }
        let _serial = TPM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let secret = b"pin protected secret";
        let sealed = seal(secret, "7+11", "hunter2").expect("seal failed");
        assert_eq!(sealed.policy_hash.len(), 32);

        let mk_token = |blob: Vec<u8>| Tpm2TokenRef {
            token_id: "1".to_string(),
            blob,
            pcrs: "7+11".to_string(),
            pcr_bank: "sha256".to_string(),
            pin_required: true,
        };

        // Correct PIN unseals.
        let out = unseal_from_tokens(&[mk_token(sealed.blob.clone())], "hunter2")
            .expect("unseal with pin failed");
        assert_eq!(out, secret);

        // Wrong PIN fails with a step-tagged, token-prefixed error.
        let err = unseal_from_tokens(&[mk_token(sealed.blob.clone())], "wrong").unwrap_err();
        assert!(
            err.to_string().starts_with("Token 1: "),
            "unexpected error: {err}"
        );

        // No PIN: the PIN-required token is skipped entirely.
        let err = unseal_from_tokens(&[mk_token(sealed.blob)], "").unwrap_err();
        assert_eq!(err.to_string(), "No systemd-tpm2 token could be unsealed");
    }
}
