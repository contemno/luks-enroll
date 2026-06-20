//! LUKS2 operations via libcryptsetup-rs.
//!
//! Mirrors the Python service's helpers: every operation opens its own
//! crypt device handle (init + load LUKS2), and the single-auth →
//! multiple-keyslot-ops property is delivered by a TTL'd volume-key cache,
//! not by holding the device open. libcryptsetup calls are serialized by
//! the crate's `mutex` feature (libcryptsetup is not thread-safe).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use libcryptsetup_rs::consts::flags::{CryptPbkdf, CryptVolumeKey};
use libcryptsetup_rs::consts::vals::{CryptKdf, EncryptionFormat};
use libcryptsetup_rs::{CryptDevice, CryptInit, CryptPbkdfType, Either, TokenInput};
use zeroize::Zeroizing;

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
    if let Some(tokens) = meta.get("tokens").and_then(|v| v.as_object()) {
        for (tid, tinfo) in tokens {
            if tinfo.get("type").and_then(|t| t.as_str()) == Some(token_type) {
                let Ok(tid) = tid.parse::<i32>() else {
                    continue;
                };
                let slots = token_keyslots(tinfo);
                out.push((tid, slots));
            }
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

/// Keyslot numbers not referenced by any token (i.e. plain password slots).
pub fn password_keyslots(device: &str) -> Vec<i32> {
    let Some(meta) = metadata_json(device) else {
        return Vec::new();
    };
    let mut managed = std::collections::HashSet::new();
    if let Some(tokens) = meta.get("tokens").and_then(|v| v.as_object()) {
        for tinfo in tokens.values() {
            managed.extend(token_keyslots(tinfo));
        }
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
    if let Some(tokens) = meta.get("tokens").and_then(|v| v.as_object()) {
        for (tid, tinfo) in tokens {
            if token_keyslots(tinfo).contains(&slot) {
                if let Ok(tid) = tid.parse() {
                    return tid;
                }
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

/// Pure parser for systemd-fido2 tokens in LUKS2 metadata JSON.
fn fido2_refs_from_meta(meta: &serde_json::Value) -> Result<Vec<Fido2TokenRef>> {
    let mut out = Vec::new();
    if let Some(tokens) = meta.get("tokens").and_then(|v| v.as_object()) {
        for tinfo in tokens.values() {
            if tinfo.get("type").and_then(|t| t.as_str()) != Some("systemd-fido2") {
                continue;
            }
            let cred = tinfo
                .get("fido2-credential")
                .and_then(|v| v.as_str())
                .ok_or(Error::from("fido2 token missing fido2-credential"))?;
            let salt = tinfo
                .get("fido2-salt")
                .and_then(|v| v.as_str())
                .ok_or(Error::from("fido2 token missing fido2-salt"))?;
            out.push(Fido2TokenRef {
                cred_id: B64
                    .decode(cred)
                    .map_err(|e| Error(format!("bad base64: {e}")))?,
                salt: B64
                    .decode(salt)
                    .map_err(|e| Error(format!("bad base64: {e}")))?,
            });
        }
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
    if let Some(tokens) = meta.get("tokens").and_then(|v| v.as_object()) {
        for (tid, tinfo) in tokens {
            if tinfo.get("type").and_then(|t| t.as_str()) != Some("systemd-tpm2") {
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
                        buf.extend(
                            B64.decode(s)
                                .map_err(|e| Error(format!("bad base64: {e}")))?,
                        );
                    }
                    buf
                }
                serde_json::Value::String(s) => B64
                    .decode(s)
                    .map_err(|e| Error(format!("bad base64: {e}")))?,
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
                pcr_bank: tinfo
                    .get("tpm2-pcr-bank")
                    .and_then(|v| v.as_str())
                    .unwrap_or("sha256")
                    .to_string(),
                pin_required: tinfo
                    .get("tpm2-pin")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            });
        }
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
        "systemd-fido2" => fido2::unlock_from_tokens(&fido2_token_refs(device)?, pin)?,
        "systemd-tpm2" => tpm2::unseal_from_tokens(&tpm2_token_refs(device)?, pin)?,
        other => bail!("Unknown token type: {other}"),
    };
    let encoded = Zeroizing::new(B64.encode(&raw).into_bytes());
    drop(Zeroizing::new(raw)); // zeroize the raw secret
    Ok(encoded)
}

/// Verify unlock via a LUKS2 token (FIDO2/TPM2) and cache the volume key so
/// follow-up enrollment operations don't need a second touch/unseal.
/// Returns the keyslot, or an error message.
pub fn verify_token(device: &str, token_type: &str, pin: &str) -> std::result::Result<i32, String> {
    let _t = Timer::new("verify_token");
    const VALID: [&str; 2] = ["systemd-fido2", "systemd-tpm2"];
    if !VALID.contains(&token_type) {
        // Parity: Python raises here (caller turns it into a D-Bus failure).
        return Err("Unsupported token type".to_string());
    }
    let pw = derive_passphrase_from_token(device, token_type, pin).map_err(|e| e.0)?;

    let mut dev = open_luks2(device).map_err(|e| e.0)?;
    let key_size = dev.status_handle().get_volume_key_size().max(0) as usize;
    let mut vk_buf = Zeroizing::new(vec![0u8; key_size.max(1)]);
    match dev.volume_key_handle().get(None, &mut vk_buf, Some(&pw)) {
        Ok((slot, size)) => {
            vk_buf.truncate(size);
            cache_volume_key(device, VolumeKey::new(vk_buf.to_vec()));
            Ok(slot)
        }
        Err(e) => Err(format!("Token unlock failed ({e})")),
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
    const VALID: [&str; 3] = ["passphrase", "systemd-fido2", "systemd-tpm2"];
    if !VALID.contains(&unlock_method) {
        bail!("Invalid unlock method: {unlock_method:?}");
    }
    let token_based = unlock_method != "passphrase";
    // Reuse a cached volume key (from a prior unlock or op) for any unlock
    // method, so a sequence of enroll/wipe ops runs from a single extraction.
    if let Some(vk) = cached_volume_key(device) {
        return Ok(vk);
    }

    let mut dev = open_luks2(device)?;
    let pw: Zeroizing<Vec<u8>> = if token_based {
        derive_passphrase_from_token(device, unlock_method, unlock_pin)?
    } else {
        Zeroizing::new(passphrase.as_bytes().to_vec())
    };

    let key_size = dev.status_handle().get_volume_key_size().max(0) as usize;
    let mut vk_buf = Zeroizing::new(vec![0u8; key_size.max(1)]);
    let (_slot, size) = dev
        .volume_key_handle()
        .get(None, &mut vk_buf, Some(&pw))
        .map_err(|e| Error(format!("Failed to get volume key ({e})")))?;
    vk_buf.truncate(size);
    let vk = VolumeKey::new(vk_buf.to_vec());
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
