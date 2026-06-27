//! LUKS2 operations via libcryptsetup-rs.
//!
//! Mirrors the Python service's helpers: every operation opens its own
//! crypt device handle (init + load LUKS2), and the single-auth →
//! multiple-keyslot-ops property is delivered by a TTL'd volume-key cache,
//! not by holding the device open. libcryptsetup calls are serialized by
//! the crate's `mutex` feature (libcryptsetup is not thread-safe).

use std::collections::{BTreeMap, HashMap};
use std::os::raw::c_uint;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use libcryptsetup_rs::consts::flags::{CryptPbkdf, CryptVolumeKey};
use libcryptsetup_rs::consts::vals::{CryptKdf, EncryptionFormat};
use libcryptsetup_rs::{CryptDevice, CryptInit, CryptPbkdfType, Either, LibcryptErr, TokenInput};
use zeroize::Zeroizing;

use crate::constants::{TOKEN_TYPE_FIDO2, TOKEN_TYPE_TPM2};
use crate::error::{Error, Result};
use crate::{bail, fido2, tpm2};

/// Scoped timer that logs elapsed wall-clock for an operation when
/// `LUKS_ENROLL_TIMING` is set in the environment. Off by default (zero
/// overhead beyond one env lookup). Logging on drop covers every return
/// path. Used to quantify where unlock latency goes (argon2 vs. reads).
pub(crate) struct Timer {
    label: &'static str,
    start: std::time::Instant,
    enabled: bool,
}

impl Timer {
    pub(crate) fn new(label: &'static str) -> Self {
        Timer {
            label,
            start: std::time::Instant::now(),
            enabled: std::env::var_os("LUKS_ENROLL_TIMING").is_some(),
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if self.enabled {
            eprintln!(
                "[timing] {}: {} ms",
                self.label,
                self.start.elapsed().as_millis()
            );
        }
    }
}

/// A LUKS volume key. Zeroized on drop.
#[derive(Clone)]
pub struct VolumeKey(Zeroizing<Vec<u8>>);

impl VolumeKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        VolumeKey(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// FIDO2 token fields needed for unlock (from the LUKS2 header).
pub struct Fido2TokenRef {
    pub cred_id: Vec<u8>,
    pub salt: Vec<u8>,
}

/// TPM2 token fields needed for unlock (from the LUKS2 header).
pub struct Tpm2TokenRef {
    pub token_id: String,
    pub blob: Vec<u8>,
    /// PCR list in "7+11" string form.
    pub pcrs: String,
    /// PCR bank name, e.g. "sha256".
    pub pcr_bank: String,
    pub pin_required: bool,
}

// ---------------------------------------------------------------------------
// Volume key cache
// ---------------------------------------------------------------------------

// Cache volume keys extracted during token unlock to avoid requiring a
// second FIDO2 touch or TPM2 unseal for subsequent operations.
// Keyed by canonicalized device path.
const VOLUME_KEY_CACHE_TTL: Duration = Duration::from_secs(120);

static VOLUME_KEY_CACHE: LazyLock<Mutex<HashMap<String, (VolumeKey, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn realpath(device: &str) -> String {
    std::fs::canonicalize(device)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| device.to_string())
}

pub fn clear_volume_key_cache(device: &str) {
    VOLUME_KEY_CACHE.lock().unwrap().remove(&realpath(device));
}

fn cache_volume_key(device: &str, vk: VolumeKey) {
    VOLUME_KEY_CACHE
        .lock()
        .unwrap()
        .insert(realpath(device), (vk, Instant::now()));
}

fn cached_volume_key(device: &str) -> Option<VolumeKey> {
    let key = realpath(device);
    let mut cache = VOLUME_KEY_CACHE.lock().unwrap();
    match cache.get(&key) {
        Some((vk, ts)) if ts.elapsed() < VOLUME_KEY_CACHE_TTL => Some(vk.clone()),
        Some(_) => {
            cache.remove(&key);
            None
        }
        None => None,
    }
}

// ---------------------------------------------------------------------------
// Device open helpers
// ---------------------------------------------------------------------------

fn open_luks2(device: &str) -> Result<CryptDevice> {
    let mut dev =
        CryptInit::init(Path::new(device)).map_err(|_| Error::from("Failed to open device"))?;
    dev.context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)
        .map_err(|_| Error::from("Failed to load LUKS2 header"))?;
    Ok(dev)
}

/// Parsed LUKS2 JSON metadata (crypt_dump_json), or None on any failure.
pub fn metadata_json(device: &str) -> Option<serde_json::Value> {
    let _t = Timer::new("metadata_json");
    let mut dev = open_luks2(device).ok()?;
    dev.status_handle().dump_json().ok()
}

// ---------------------------------------------------------------------------
// Read-only metadata queries
// ---------------------------------------------------------------------------

/// Map of keyslot number -> keyslot type (e.g. "luks2").
pub fn list_keyslots(device: &str) -> BTreeMap<i32, String> {
    let mut out = BTreeMap::new();
    let Some(meta) = metadata_json(device) else {
        return out;
    };
    if let Some(slots) = meta.get("keyslots").and_then(|v| v.as_object()) {
        for (slot, info) in slots {
            if let Ok(n) = slot.parse::<i32>() {
                let type_ = info
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("unknown");
                out.insert(n, type_.to_string());
            }
        }
    }
    out
}

/// List of (token_id, keyslots) for tokens of the given type
/// (e.g. "systemd-fido2", "systemd-tpm2", "systemd-recovery").
pub fn tokens_by_type(device: &str, token_type: &str) -> Vec<(i32, Vec<i32>)> {
    let mut out = Vec::new();
    let Some(meta) = metadata_json(device) else {
        return out;
    };
    for (tid, tinfo) in tokens_iter(&meta) {
        if token_type_is(tinfo, token_type) {
            let Ok(tid) = tid.parse::<i32>() else {
                continue;
            };
            let slots = token_keyslots(tinfo);
            out.push((tid, slots));
        }
    }
    out.sort();
    out
}

fn token_keyslots(tinfo: &serde_json::Value) -> Vec<i32> {
    tinfo
        .get("keyslots")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().and_then(|s| s.parse().ok()))
                .collect()
        })
        .unwrap_or_default()
}

/// Iterate the LUKS2 `tokens` object as (token-id, token-info) pairs. Empty
/// when the section is absent or not an object — the *absent = empty, not
/// error* contract the token walkers and parsers rely on.
fn tokens_iter(meta: &serde_json::Value) -> impl Iterator<Item = (&String, &serde_json::Value)> {
    meta.get("tokens")
        .and_then(|v| v.as_object())
        .into_iter()
        .flatten()
}

/// Whether a token-info object's `type` field equals `token_type`.
fn token_type_is(tinfo: &serde_json::Value, token_type: &str) -> bool {
    tinfo.get("type").and_then(|t| t.as_str()) == Some(token_type)
}

/// A string field of a token-info object, or None if absent / not a string.
fn token_str<'a>(tinfo: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    tinfo.get(field).and_then(|v| v.as_str())
}

/// Ordered, de-duplicated keyslots bound to tokens of `token_type` in the
/// given LUKS2 metadata. Empty when the type has no tokens / no recorded
/// keyslots — the signal for `extract_token_volume_key` to try every slot.
fn token_type_keyslots(meta: &serde_json::Value, token_type: &str) -> Vec<i32> {
    let mut slots = Vec::new();
    for (_, tinfo) in tokens_iter(meta) {
        if token_type_is(tinfo, token_type) {
            for s in token_keyslots(tinfo) {
                if !slots.contains(&s) {
                    slots.push(s);
                }
            }
        }
    }
    slots
}

/// Keyslot numbers not referenced by any token (i.e. plain password slots).
pub fn password_keyslots(device: &str) -> Vec<i32> {
    let Some(meta) = metadata_json(device) else {
        return Vec::new();
    };
    let mut managed = std::collections::HashSet::new();
    for (_, tinfo) in tokens_iter(&meta) {
        managed.extend(token_keyslots(tinfo));
    }
    let mut out: Vec<i32> = meta
        .get("keyslots")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.keys()
                .filter_map(|s| s.parse().ok())
                .filter(|n| !managed.contains(n))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Token ID associated with a keyslot, or -1 if none.
pub fn find_token_for_keyslot(device: &str, slot: i32) -> i32 {
    let Some(meta) = metadata_json(device) else {
        return -1;
    };
    for (tid, tinfo) in tokens_iter(&meta) {
        if token_keyslots(tinfo).contains(&slot) {
            if let Ok(tid) = tid.parse() {
                return tid;
            }
        }
    }
    -1
}

/// Parse systemd-fido2 tokens from the LUKS2 header.
pub fn fido2_token_refs(device: &str) -> Result<Vec<Fido2TokenRef>> {
    let meta = metadata_json(device).ok_or(Error::from("Failed to read LUKS2 metadata"))?;
    fido2_refs_from_meta(&meta)
}

/// Decode standard base64 into bytes, mapping a decode failure to the service
/// error string the token parsers have always produced.
fn decode_b64(s: &str) -> Result<Vec<u8>> {
    B64.decode(s).map_err(|e| Error(format!("bad base64: {e}")))
}

/// Pure parser for systemd-fido2 tokens in LUKS2 metadata JSON.
fn fido2_refs_from_meta(meta: &serde_json::Value) -> Result<Vec<Fido2TokenRef>> {
    let mut out = Vec::new();
    for (_, tinfo) in tokens_iter(meta) {
        if !token_type_is(tinfo, TOKEN_TYPE_FIDO2) {
            continue;
        }
        let cred = token_str(tinfo, "fido2-credential")
            .ok_or(Error::from("fido2 token missing fido2-credential"))?;
        let salt =
            token_str(tinfo, "fido2-salt").ok_or(Error::from("fido2 token missing fido2-salt"))?;
        out.push(Fido2TokenRef {
            cred_id: decode_b64(cred)?,
            salt: decode_b64(salt)?,
        });
    }
    Ok(out)
}

/// Parse systemd-tpm2 tokens from the LUKS2 header.
///
/// Accepts both `tpm2_blob` and `tpm2-blob` spellings (preferring the
/// former, like the Python service), blob as string or list of strings
/// (concatenated), and pcrs as list or scalar.
pub fn tpm2_token_refs(device: &str) -> Result<Vec<Tpm2TokenRef>> {
    let meta = metadata_json(device).ok_or(Error::from("Failed to read LUKS2 metadata"))?;
    tpm2_refs_from_meta(&meta)
}

/// Pure parser for systemd-tpm2 tokens in LUKS2 metadata JSON. The lenient
/// shapes (array blobs, scalar pcrs) appear only when reading headers
/// written by other tools — the systemd token plugins validate what *we*
/// write through crypt_token_json_set, so these forms are read-side only.
fn tpm2_refs_from_meta(meta: &serde_json::Value) -> Result<Vec<Tpm2TokenRef>> {
    let mut out = Vec::new();
    for (tid, tinfo) in tokens_iter(meta) {
        if !token_type_is(tinfo, TOKEN_TYPE_TPM2) {
            continue;
        }
        let blob_val = tinfo
            .get("tpm2_blob")
            .filter(|v| !v.is_null())
            .or_else(|| tinfo.get("tpm2-blob"))
            .ok_or(Error::from("tpm2 token missing tpm2-blob"))?;
        let blob = match blob_val {
            serde_json::Value::Array(parts) => {
                let mut buf = Vec::new();
                for p in parts {
                    let s = p.as_str().ok_or(Error::from("bad tpm2-blob entry"))?;
                    buf.extend(decode_b64(s)?);
                }
                buf
            }
            serde_json::Value::String(s) => decode_b64(s)?,
            _ => bail!("bad tpm2-blob field"),
        };
        let pcrs = match tinfo.get("tpm2-pcrs") {
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .map(|p| match p {
                    serde_json::Value::Number(n) => n.to_string(),
                    other => other.as_str().unwrap_or_default().to_string(),
                })
                .collect::<Vec<_>>()
                .join("+"),
            Some(other) => other
                .as_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| other.to_string()),
            None => String::new(),
        };
        out.push(Tpm2TokenRef {
            token_id: tid.clone(),
            blob,
            pcrs,
            pcr_bank: token_str(tinfo, "tpm2-pcr-bank")
                .unwrap_or("sha256")
                .to_string(),
            pin_required: tinfo
                .get("tpm2-pin")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Unlock / verify
// ---------------------------------------------------------------------------

/// Verify a passphrase. Returns the matching keyslot, or an error message.
pub fn verify_passphrase(device: &str, passphrase: &str) -> std::result::Result<i32, String> {
    let _t = Timer::new("verify_passphrase");
    let mut dev = open_luks2(device).map_err(|e| e.0)?;
    // Extract (and thereby verify) the volume key without activating dm-crypt
    // (name=None), then cache it so follow-up enroll/wipe ops run from this
    // single unlock -- mirroring verify_token.
    let key_size = dev.status_handle().get_volume_key_size().max(0) as usize;
    let mut vk_buf = Zeroizing::new(vec![0u8; key_size.max(1)]);
    match dev
        .volume_key_handle()
        .get(None, &mut vk_buf, Some(passphrase.as_bytes()))
    {
        Ok((slot, size)) => {
            vk_buf.truncate(size);
            cache_volume_key(device, VolumeKey::new(vk_buf.to_vec()));
            Ok(slot)
        }
        Err(_) => Err("Incorrect passphrase or recovery key".to_string()),
    }
}

/// Derive the LUKS passphrase bytes from a token (FIDO2 assertion or TPM2
/// unseal), base64-encoded per the systemd token-plugin convention.
fn derive_passphrase_from_token(
    device: &str,
    token_type: &str,
    pin: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let raw = match token_type {
        TOKEN_TYPE_FIDO2 => fido2::unlock_from_tokens(&fido2_token_refs(device)?, pin)?,
        TOKEN_TYPE_TPM2 => tpm2::unseal_from_tokens(&tpm2_token_refs(device)?, pin)?,
        other => bail!("Unknown token type: {other}"),
    };
    let encoded = Zeroizing::new(B64.encode(&raw).into_bytes());
    drop(Zeroizing::new(raw)); // zeroize the raw secret
    Ok(encoded)
}

/// Extract the volume key for a token-derived passphrase `pw`, querying the
/// keyslot(s) the token unlocks before falling back to "try all keyslots".
///
/// crypt_volume_key_get with keyslot -1 (None) tries every keyslot in turn,
/// and each non-matching slot still runs its full KDF before failing — the
/// argon2id passphrase slot alone costs 1–2 s. Token keyslots use fast
/// pbkdf2, so targeting them directly avoids that cost (issue #16: 2–4 s
/// in-app unlock). Falls back to None (-1, try all) when the token records
/// no keyslots or the targeted slots don't match, so correctness is never
/// worse than before. Returns (keyslot, volume key).
pub fn extract_token_volume_key(
    device: &str,
    token_type: &str,
    pw: &[u8],
) -> Result<(i32, VolumeKey)> {
    let mut dev = open_luks2(device)?;
    let meta = dev
        .status_handle()
        .dump_json()
        .unwrap_or(serde_json::Value::Null);
    let key_size = dev.status_handle().get_volume_key_size().max(0) as usize;

    // Targeted token keyslots first, then None (-1, try all) as a safety net.
    let mut candidates: Vec<Option<c_uint>> = token_type_keyslots(&meta, token_type)
        .into_iter()
        .map(|s| Some(s as c_uint))
        .collect();
    candidates.push(None);

    let mut last_err: Option<LibcryptErr> = None;
    for slot in candidates {
        let mut vk_buf = Zeroizing::new(vec![0u8; key_size.max(1)]);
        match dev.volume_key_handle().get(slot, &mut vk_buf, Some(pw)) {
            Ok((found, size)) => {
                vk_buf.truncate(size);
                return Ok((found, VolumeKey::new(vk_buf.to_vec())));
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .map(Error::from)
        .unwrap_or_else(|| Error::from("volume key extraction failed")))
}

/// Verify unlock via a LUKS2 token (FIDO2/TPM2) and cache the volume key so
/// follow-up enrollment operations don't need a second touch/unseal.
/// Returns the keyslot, or an error message.
pub fn verify_token(device: &str, token_type: &str, pin: &str) -> std::result::Result<i32, String> {
    let _t = Timer::new("verify_token");
    const VALID: [&str; 2] = [TOKEN_TYPE_FIDO2, TOKEN_TYPE_TPM2];
    if !VALID.contains(&token_type) {
        // Parity: Python raises here (caller turns it into a D-Bus failure).
        return Err("Unsupported token type".to_string());
    }
    let pw = derive_passphrase_from_token(device, token_type, pin).map_err(|e| e.0)?;

    match extract_token_volume_key(device, token_type, &pw) {
        Ok((slot, vk)) => {
            cache_volume_key(device, vk);
            Ok(slot)
        }
        Err(e) => Err(format!("Token unlock failed ({})", e.0)),
    }
}

/// Get the volume key for a device using the given unlock method
/// ("passphrase", "systemd-fido2" or "systemd-tpm2").
///
/// All methods consult the volume-key cache first (populated here, by
/// `verify_token`, or by `verify_passphrase`) so a sequence of ops runs from a
/// single extraction -- avoiding a second FIDO2 touch / TPM2 unseal, or a
/// repeated argon2id pass for a passphrase.
pub fn get_volume_key(
    device: &str,
    unlock_method: &str,
    passphrase: &str,
    unlock_pin: &str,
) -> Result<VolumeKey> {
    let _t = Timer::new("get_volume_key");
    const VALID: [&str; 3] = ["passphrase", TOKEN_TYPE_FIDO2, TOKEN_TYPE_TPM2];
    if !VALID.contains(&unlock_method) {
        bail!("Invalid unlock method: {unlock_method:?}");
    }
    let token_based = unlock_method != "passphrase";
    // Reuse a cached volume key (from a prior unlock or op) for any unlock
    // method, so a sequence of enroll/wipe ops runs from a single extraction.
    if let Some(vk) = cached_volume_key(device) {
        return Ok(vk);
    }

    let vk = if token_based {
        // Target the token's own keyslot(s) to skip slow KDF attempts against
        // unrelated keyslots (issue #16).
        let pw = derive_passphrase_from_token(device, unlock_method, unlock_pin)?;
        let (_slot, vk) = extract_token_volume_key(device, unlock_method, &pw)
            .map_err(|e| Error(format!("Failed to get volume key ({})", e.0)))?;
        vk
    } else {
        let mut dev = open_luks2(device)?;
        let pw = Zeroizing::new(passphrase.as_bytes().to_vec());
        let key_size = dev.status_handle().get_volume_key_size().max(0) as usize;
        let mut vk_buf = Zeroizing::new(vec![0u8; key_size.max(1)]);
        let (_slot, size) = dev
            .volume_key_handle()
            .get(None, &mut vk_buf, Some(&pw))
            .map_err(|e| Error(format!("Failed to get volume key ({e})")))?;
        vk_buf.truncate(size);
        VolumeKey::new(vk_buf.to_vec())
    };
    // Prime the cache for every unlock method so a sequence of enroll/wipe ops
    // runs from a single extraction -- one FIDO2 tap / TPM2 unseal, or one
    // argon2id pass for a passphrase. Entries expire after VOLUME_KEY_CACHE_TTL.
    cache_volume_key(device, vk.clone());
    Ok(vk)
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/// Add a keyslot using the volume key. Returns the new keyslot number.
///
/// With `minimal_pbkdf`, uses pbkdf2/sha512 with minimal cost — for
/// high-entropy random passphrases (FIDO2 hmac-secret, TPM2-sealed
/// secrets), matching systemd-cryptenroll.
pub fn add_keyslot_by_volume_key(
    device: &str,
    vk: &VolumeKey,
    new_passphrase: &[u8],
    minimal_pbkdf: bool,
) -> Result<i32> {
    let _t = Timer::new("add_keyslot_by_volume_key");
    let mut dev = open_luks2(device)?;
    if minimal_pbkdf {
        let pbkdf = CryptPbkdfType {
            type_: CryptKdf::Pbkdf2,
            hash: Some("sha512".to_string()),
            time_ms: 1,
            iterations: 1000,
            max_memory_kb: 0,
            parallel_threads: 0,
            flags: CryptPbkdf::empty(),
        };
        dev.settings_handle()
            .set_pbkdf_type(&pbkdf)
            .map_err(|e| Error(format!("set_pbkdf_type failed: {e}")))?;
    }
    let slot = dev
        .keyslot_handle()
        .add_by_key(
            None,
            Some(Either::Left(vk.as_bytes())),
            new_passphrase,
            CryptVolumeKey::empty(),
        )
        .map_err(|e| Error(format!("crypt_keyslot_add_by_key failed: {e}")))?;
    Ok(slot as i32)
}

/// Set or remove a LUKS2 token. `token_json=None` removes the token;
/// `token_id=-1` auto-allocates. Returns the token ID.
pub fn set_token(device: &str, token_id: i32, token_json: Option<&str>) -> Result<i32> {
    let mut dev = open_luks2(device)?;
    let result = match token_json {
        None => dev
            .token_handle()
            .json_set(TokenInput::RemoveToken(token_id as u32)),
        Some(json) => {
            let value: serde_json::Value = serde_json::from_str(json)?;
            if token_id < 0 {
                dev.token_handle().json_set(TokenInput::AddToken(&value))
            } else {
                dev.token_handle()
                    .json_set(TokenInput::ReplaceToken(token_id as u32, &value))
            }
        }
    };
    match result {
        Ok(id) => Ok(id as i32),
        // RemoveToken returns the errno-style result of token_json_set with
        // NULL json; libcryptsetup returns the token id which the crate maps
        // through errno_int_success — treat success uniformly.
        Err(e) => Err(Error(format!("crypt_token_json_set failed: {e}"))),
    }
}

/// Destroy a LUKS2 keyslot.
pub fn destroy_keyslot(device: &str, slot: i32) -> Result<()> {
    let mut dev = open_luks2(device)?;
    dev.keyslot_handle()
        .destroy(slot as u32)
        .map_err(|e| Error(format!("crypt_keyslot_destroy failed: {e}")))
}

/// LUKS2-format a device or image file (aes-xts-plain64, 512-bit volume
/// key) and add the passphrase. Returns the keyslot number.
pub fn format_luks2(path: &str, passphrase: &str) -> Result<i32> {
    let _t = Timer::new("format_luks2");
    let mut dev = CryptInit::init(Path::new(path)).map_err(|_| Error::from("crypt_init failed"))?;
    dev.context_handle()
        .format::<()>(
            EncryptionFormat::Luks2,
            ("aes", "xts-plain64"),
            None,
            Either::Right(64),
            None,
        )
        .map_err(|e| Error(format!("crypt_format failed: {e}")))?;
    let slot = dev
        .keyslot_handle()
        .add_by_key(None, None, passphrase.as_bytes(), CryptVolumeKey::empty())
        .map_err(|e| Error(format!("crypt_keyslot_add_by_key failed: {e}")))?;
    Ok(slot as i32)
}

/// LUKS2-format a freshly created container with a generated volume key but
/// **no keyslot**, caching the VK so the first enrollment can wrap it with a
/// real method (FIDO2/TPM2/recovery/passphrase) without the user ever typing
/// a throwaway passphrase (issue #58).
///
/// We generate the 512-bit VK ourselves and pass it to `crypt_format`, then
/// cache it directly -- no need to read it back out of the context. The
/// on-disk header commits to this VK via its digest, but with zero keyslots
/// the VK is recoverable *only* from the in-process cache until a keyslot is
/// enrolled. That is safe precisely because the caller has just created the
/// container: it holds no committed data and cannot be mounted through the
/// normal (keyslot) path, so an abandoned, never-enrolled volume is an empty
/// throwaway, not a lock-out. The caller MUST make the next step a
/// keyslot-adding enrollment (which `get_volume_key` serves from this cache).
pub fn format_luks2_keyless(path: &str) -> Result<()> {
    let _t = Timer::new("format_luks2_keyless");
    let mut vk = Zeroizing::new(vec![0u8; 64]);
    getrandom::fill(vk.as_mut_slice()).expect("OS RNG unavailable");
    let mut dev = CryptInit::init(Path::new(path)).map_err(|_| Error::from("crypt_init failed"))?;
    dev.context_handle()
        .format::<()>(
            EncryptionFormat::Luks2,
            ("aes", "xts-plain64"),
            None,
            Either::Left(&vk[..]),
            None,
        )
        .map_err(|e| Error(format!("crypt_format failed: {e}")))?;
    // No keyslot is added: the VK lives only in the cache until the first
    // enrollment wraps it. Keyed by canonical path, so the subsequent enroll
    // call (path- or fd-based) resolves to the same entry.
    cache_volume_key(path, VolumeKey::new(vk.to_vec()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_b64_decodes_and_reports_bad_input() {
        assert_eq!(decode_b64("aGk=").unwrap(), b"hi");
        let err = decode_b64("@@not base64@@").unwrap_err();
        assert!(err.0.starts_with("bad base64"), "unexpected: {}", err.0);
    }

    #[test]
    fn token_helpers_walk_and_getters() {
        // tokens_iter yields each (id, info) pair...
        let meta = serde_json::json!({
            "tokens": {
                "0": { "type": "systemd-fido2", "fido2-salt": "AAAA" },
                "1": { "type": "systemd-tpm2" },
            }
        });
        let ids: Vec<&String> = tokens_iter(&meta).map(|(tid, _)| tid).collect();
        assert_eq!(ids, vec!["0", "1"]);

        // ...and is empty (not a panic) when the section is absent or non-object.
        assert_eq!(tokens_iter(&serde_json::json!({"keyslots": {}})).count(), 0);
        assert_eq!(tokens_iter(&serde_json::json!({"tokens": 7})).count(), 0);

        let (_, fido) = tokens_iter(&meta).next().unwrap();
        // token_type_is matches the `type` field exactly.
        assert!(token_type_is(fido, "systemd-fido2"));
        assert!(!token_type_is(fido, "systemd-tpm2"));
        // token_str returns Some for a present string, None for missing /
        // non-string fields.
        assert_eq!(token_str(fido, "fido2-salt"), Some("AAAA"));
        assert_eq!(token_str(fido, "fido2-credential"), None);
        assert_eq!(token_str(fido, "type"), Some("systemd-fido2"));
    }

    #[test]
    fn tpm2_refs_parse_quirks() {
        // Old-style header written by another tool: only "tpm2-blob"
        // (dash), blob split into base64 chunks, pcrs as a number list.
        let meta = serde_json::json!({
            "tokens": {
                "3": {
                    "type": "systemd-tpm2",
                    "keyslots": ["1"],
                    "tpm2-blob": [B64.encode([0x01, 0x02]), B64.encode([0x03])],
                    "tpm2-pcrs": [7, 11],
                    "tpm2-pin": true,
                },
                "4": {
                    "type": "systemd-fido2",
                    "keyslots": ["2"],
                },
            }
        });
        let refs = tpm2_refs_from_meta(&meta).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].token_id, "3");
        assert_eq!(refs[0].blob, vec![0x01, 0x02, 0x03]);
        assert_eq!(refs[0].pcrs, "7+11");
        assert_eq!(refs[0].pcr_bank, "sha256"); // default when absent
        assert!(refs[0].pin_required);
    }

    #[test]
    fn tpm2_refs_prefer_underscore_blob_and_scalar_pcrs() {
        let meta = serde_json::json!({
            "tokens": {
                "0": {
                    "type": "systemd-tpm2",
                    "tpm2_blob": B64.encode([0xAA]),
                    "tpm2-blob": B64.encode([0xBB]),
                    "tpm2-pcrs": "7",
                    "tpm2-pcr-bank": "sha1",
                }
            }
        });
        let refs = tpm2_refs_from_meta(&meta).unwrap();
        assert_eq!(refs[0].blob, vec![0xAA], "tpm2_blob wins over tpm2-blob");
        assert_eq!(refs[0].pcrs, "7");
        assert_eq!(refs[0].pcr_bank, "sha1");
        assert!(!refs[0].pin_required); // default when absent
    }

    #[test]
    fn tpm2_refs_missing_blob_is_error() {
        let meta = serde_json::json!({
            "tokens": { "0": { "type": "systemd-tpm2" } }
        });
        assert!(tpm2_refs_from_meta(&meta).is_err());
    }

    #[test]
    fn fido2_refs_parse_and_skip_other_types() {
        let meta = serde_json::json!({
            "tokens": {
                "1": {
                    "type": "systemd-fido2",
                    "fido2-credential": B64.encode([9u8; 4]),
                    "fido2-salt": B64.encode([7u8; 4]),
                },
                "2": { "type": "systemd-recovery", "keyslots": ["5"] },
            }
        });
        let refs = fido2_refs_from_meta(&meta).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].cred_id, vec![9u8; 4]);
        assert_eq!(refs[0].salt, vec![7u8; 4]);
    }

    #[test]
    fn no_tokens_section_is_empty_not_error() {
        let meta = serde_json::json!({"keyslots": {}});
        assert!(tpm2_refs_from_meta(&meta).unwrap().is_empty());
        assert!(fido2_refs_from_meta(&meta).unwrap().is_empty());
    }

    // Regression for issue #15: a single token unlock must serve a *sequence*
    // of enroll/wipe ops without re-prompting. The cache is therefore not
    // consumed by a read and is only dropped by an explicit clear or the TTL —
    // never eagerly after each op.
    #[test]
    fn volume_key_cache_serves_repeated_reads_until_cleared() {
        // Unique key so parallel tests don't touch the same global entry.
        let dev = "/dev/luks-enroll-vk-cache-test-repeat";
        clear_volume_key_cache(dev);
        assert!(cached_volume_key(dev).is_none(), "starts empty");

        cache_volume_key(dev, VolumeKey::new(vec![1, 2, 3, 4]));

        // Multiple reads all hit: this is what lets two enrollments run from
        // one FIDO2 tap. A read does not consume the entry.
        for _ in 0..3 {
            let got = cached_volume_key(dev).expect("cache hit");
            assert_eq!(got.as_bytes(), &[1, 2, 3, 4]);
        }

        clear_volume_key_cache(dev);
        assert!(cached_volume_key(dev).is_none(), "cleared explicitly");
    }

    #[test]
    fn volume_key_cache_expires_after_ttl() {
        let dev = "/dev/luks-enroll-vk-cache-test-ttl";
        clear_volume_key_cache(dev);

        // Insert with a timestamp already older than the TTL.
        let stale = Instant::now()
            .checked_sub(VOLUME_KEY_CACHE_TTL + Duration::from_secs(1))
            .expect("instant in range");
        VOLUME_KEY_CACHE
            .lock()
            .unwrap()
            .insert(realpath(dev), (VolumeKey::new(vec![9, 9]), stale));

        assert!(
            cached_volume_key(dev).is_none(),
            "stale entry is treated as a miss"
        );
        // And the expired entry is evicted on access.
        assert!(!VOLUME_KEY_CACHE
            .lock()
            .unwrap()
            .contains_key(&realpath(dev)));
    }

    #[test]
    fn token_type_keyslots_targets_matching_type() {
        // tpm2 token bound to slot 1, fido2 token bound to slot 2: a query
        // for one type returns only that type's slot (issue #16 targeting).
        let meta = serde_json::json!({
            "tokens": {
                "0": { "type": "systemd-tpm2", "keyslots": ["1"] },
                "1": { "type": "systemd-fido2", "keyslots": ["2"] },
            }
        });
        assert_eq!(token_type_keyslots(&meta, "systemd-tpm2"), vec![1]);
        assert_eq!(token_type_keyslots(&meta, "systemd-fido2"), vec![2]);
    }

    #[test]
    fn token_type_keyslots_dedups_across_tokens() {
        let meta = serde_json::json!({
            "tokens": {
                "0": { "type": "systemd-fido2", "keyslots": ["1", "2"] },
                "1": { "type": "systemd-fido2", "keyslots": ["2", "3"] },
            }
        });
        assert_eq!(token_type_keyslots(&meta, "systemd-fido2"), vec![1, 2, 3]);
    }

    #[test]
    fn token_type_keyslots_empty_when_type_absent() {
        // No token of the queried type -> empty -> caller falls back to -1.
        let meta = serde_json::json!({
            "tokens": { "0": { "type": "systemd-tpm2", "keyslots": ["1"] } }
        });
        assert!(token_type_keyslots(&meta, "systemd-recovery").is_empty());
        // A missing tokens section is empty too, not a panic.
        let empty = serde_json::json!({ "keyslots": {} });
        assert!(token_type_keyslots(&empty, "systemd-tpm2").is_empty());
    }
}
