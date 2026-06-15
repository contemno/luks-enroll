//! Integration tests: real libcryptsetup operations against LUKS2 image
//! files — no root, no hardware, no D-Bus.
//!
//! This is the conformance safety net for the Rust port: the same
//! operation layer the D-Bus handlers call is exercised end-to-end, and
//! the resulting LUKS2 token JSON is asserted against the shapes the
//! Python service produced (and systemd-cryptsetup consumes).

use luks_enroll_service::{luks, service};

const PASSPHRASE: &str = "test-passphrase-123";

/// 32 MiB image: LUKS2 reserves 16 MiB for metadata by default.
fn new_luks_image(dir: &tempfile::TempDir) -> String {
    let path = dir.path().join("test.img").to_string_lossy().into_owned();
    let (ok, keyslot, err) = service::op_create_encrypted_image(&path, 32, PASSPHRASE, None);
    assert!(ok, "op_create_encrypted_image failed: {err}");
    assert_eq!(keyslot, 0, "first keyslot should be 0");
    path
}

fn tmpdir() -> tempfile::TempDir {
    // Keep images under /tmp so op_create_encrypted_image's path
    // allowlist (/home/ or /tmp/) accepts them.
    tempfile::tempdir_in("/tmp").expect("tempdir")
}

#[test]
fn create_image_format_and_verify() {
    let dir = tmpdir();
    let img = new_luks_image(&dir);

    // Metadata is valid LUKS2 with exactly one keyslot.
    let slots = luks::list_keyslots(&img);
    assert_eq!(slots.len(), 1);
    assert_eq!(slots.get(&0).map(String::as_str), Some("luks2"));

    // Right passphrase verifies against slot 0; wrong one fails.
    assert_eq!(luks::verify_passphrase(&img, PASSPHRASE), Ok(0));
    assert!(luks::verify_passphrase(&img, "wrong").is_err());

    // No tokens yet: every keyslot is a password slot.
    assert_eq!(luks::password_keyslots(&img), vec![0]);
    assert!(luks::tokens_by_type(&img, "systemd-recovery").is_empty());
}

#[test]
fn create_image_rejects_bad_paths_and_sizes() {
    // Outside the allowlist.
    let (ok, slot, err) = service::op_create_encrypted_image("/var/evil.img", 32, PASSPHRASE, None);
    assert!(!ok);
    assert_eq!(slot, -1);
    assert_eq!(err, "Path must be under /home/ or /tmp/");

    // Existing non-regular file.
    let (ok, _, err) = service::op_create_encrypted_image("/tmp", 32, PASSPHRASE, None);
    assert!(!ok);
    assert_eq!(err, "Path must be a regular file");

    // Bad sizes (validated inside create_image_file).
    let dir = tmpdir();
    let p = dir.path().join("x.img").to_string_lossy().into_owned();
    let (ok, _, err) = service::op_create_encrypted_image(&p, 0, PASSPHRASE, None);
    assert!(!ok);
    assert_eq!(err, "Operation failed");
    let (ok, _, _) = service::op_create_encrypted_image(&p, 9000, PASSPHRASE, None);
    assert!(!ok);
}

#[test]
fn enroll_recovery_key_golden_token() {
    let dir = tmpdir();
    let img = new_luks_image(&dir);

    let (ok, recovery_key, err) =
        service::op_enroll_recovery_key(&img, PASSPHRASE, "passphrase", "");
    assert!(ok, "recovery enrollment failed: {err}");

    // Key format: 64 modhex chars in 8 dash-separated groups.
    assert_eq!(recovery_key.len(), 71);
    assert_eq!(recovery_key.split('-').count(), 8);

    // The recovery key opens the volume.
    assert!(luks::verify_passphrase(&img, &recovery_key).is_ok());

    // Golden token shape (what systemd-cryptsetup and the GUI expect).
    let tokens = luks::tokens_by_type(&img, "systemd-recovery");
    assert_eq!(tokens.len(), 1);
    let (tid, slots) = &tokens[0];
    assert_eq!(slots.len(), 1);
    let meta = luks::metadata_json(&img).expect("metadata");
    let tok = &meta["tokens"][tid.to_string()];
    assert_eq!(tok["type"], "systemd-recovery");
    // Keyslot ids are strings, like the Python service wrote them.
    assert_eq!(tok["keyslots"][0], slots[0].to_string());

    // The new slot is token-managed: not a password slot anymore.
    assert_eq!(luks::password_keyslots(&img), vec![0]);
    assert_eq!(luks::find_token_for_keyslot(&img, slots[0]), *tid);
}

#[test]
fn enroll_passphrase_and_wipe_slot() {
    let dir = tmpdir();
    let img = new_luks_image(&dir);

    let (ok, _, err) =
        service::op_enroll_passphrase(&img, PASSPHRASE, "second-passphrase", "passphrase", "");
    assert!(ok, "passphrase enrollment failed: {err}");
    assert_eq!(luks::verify_passphrase(&img, "second-passphrase"), Ok(1));
    assert_eq!(luks::list_keyslots(&img).len(), 2);

    // Wipe the new slot, authenticating with the original passphrase.
    let (ok, _, err) = service::op_wipe_slot(&img, PASSPHRASE, "passphrase", "", 1);
    assert!(ok, "wipe failed: {err}");
    assert_eq!(luks::list_keyslots(&img).len(), 1);
    assert!(luks::verify_passphrase(&img, "second-passphrase").is_err());
    assert_eq!(luks::verify_passphrase(&img, PASSPHRASE), Ok(0));
}

#[test]
fn wipe_refuses_last_keyslot() {
    let dir = tmpdir();
    let img = new_luks_image(&dir);

    let (ok, _, msg) = service::op_wipe_slot(&img, PASSPHRASE, "passphrase", "", 0);
    assert!(!ok);
    assert_eq!(msg, "Cannot wipe the last remaining keyslot");
    assert_eq!(luks::list_keyslots(&img).len(), 1);
}

#[test]
fn wipe_slot_removes_associated_token() {
    let dir = tmpdir();
    let img = new_luks_image(&dir);

    let (ok, _, _) = service::op_enroll_recovery_key(&img, PASSPHRASE, "passphrase", "");
    assert!(ok);
    let tokens = luks::tokens_by_type(&img, "systemd-recovery");
    let (_tid, slots) = &tokens[0];

    let (ok, _, err) = service::op_wipe_slot(&img, PASSPHRASE, "passphrase", "", slots[0]);
    assert!(ok, "wipe failed: {err}");
    assert!(luks::tokens_by_type(&img, "systemd-recovery").is_empty());
    assert_eq!(luks::list_keyslots(&img).len(), 1);
}

#[test]
fn wrong_unlock_method_rejected() {
    let dir = tmpdir();
    let img = new_luks_image(&dir);

    let (ok, _, err) = service::op_enroll_recovery_key(&img, PASSPHRASE, "bogus-method", "");
    assert!(!ok);
    assert_eq!(err, "Operation failed");
}

#[test]
fn keyslots_and_tokens_json_shapes() {
    let dir = tmpdir();
    let img = new_luks_image(&dir);

    // GetKeyslots JSON: object with string keys.
    let ks: serde_json::Value =
        serde_json::from_str(&service::keyslots_json(&img)).expect("valid json");
    assert_eq!(ks["0"], "luks2");

    // GetTokensByType JSON: [[tid, [slots]], ...].
    let (ok, _, _) = service::op_enroll_recovery_key(&img, PASSPHRASE, "passphrase", "");
    assert!(ok);
    let tj: serde_json::Value =
        serde_json::from_str(&service::tokens_json(&img, "systemd-recovery")).expect("json");
    let arr = tj.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert!(arr[0][0].is_i64());
    assert!(arr[0][1].is_array());
}

/// Simulated FIDO2/TPM2 keyslot: what the enroll paths do after deriving
/// the secret — minimal-PBKDF keyslot keyed by the base64 secret, plus a
/// token entry. Covers add_keyslot_by_volume_key(minimal_pbkdf=true) and
/// set_token with an explicit systemd-fido2 style payload.
#[test]
fn token_style_keyslot_with_minimal_pbkdf() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let dir = tmpdir();
    let img = new_luks_image(&dir);

    let vk = luks::get_volume_key(&img, "passphrase", PASSPHRASE, "").expect("volume key");
    let secret_b64 = B64.encode([0xAB; 32]);
    let slot = luks::add_keyslot_by_volume_key(&img, &vk, secret_b64.as_bytes(), true)
        .expect("add keyslot");

    let token_json = serde_json::json!({
        "type": "systemd-fido2",
        "keyslots": [slot.to_string()],
        "fido2-credential": B64.encode([1u8; 32]),
        "fido2-salt": B64.encode([2u8; 32]),
        "fido2-rp": "io.systemd.cryptsetup",
        "fido2-clientPin-required": false,
        "fido2-up-required": true,
        "fido2-uv-required": false,
    })
    .to_string();
    let tid = luks::set_token(&img, -1, Some(&token_json)).expect("set token");

    // Round-trip through the header.
    let refs = luks::fido2_token_refs(&img).expect("refs");
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].cred_id, vec![1u8; 32]);
    assert_eq!(refs[0].salt, vec![2u8; 32]);

    // The minimal-PBKDF slot uses pbkdf2 (visible in the LUKS2 metadata).
    let meta = luks::metadata_json(&img).expect("metadata");
    assert_eq!(
        meta["keyslots"][slot.to_string()]["kdf"]["type"],
        "pbkdf2",
        "token keyslot should use minimal pbkdf2"
    );
    // And the base64 secret unlocks it.
    assert_eq!(luks::verify_passphrase(&img, &secret_b64), Ok(slot));

    // Token removal via set_token(None).
    luks::set_token(&img, tid, None).expect("remove token");
    assert!(luks::fido2_token_refs(&img).expect("refs").is_empty());
}

/// A fully-formed systemd-tpm2 token — the exact shape op_enroll_tpm2
/// writes — must pass libcryptsetup's token validation (the systemd token
/// plugins are installed in CI and validate on crypt_token_json_set; this
/// is a real conformance check against systemd's own validator) and parse
/// back through tpm2_token_refs. The lenient read-side parsing quirks
/// (array blobs, scalar pcrs) are covered by unit tests in luks.rs, since
/// those shapes can't be *written* through a validating plugin.
#[test]
fn tpm2_token_full_shape_roundtrip() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let dir = tmpdir();
    let img = new_luks_image(&dir);
    let vk = luks::get_volume_key(&img, "passphrase", PASSPHRASE, "").expect("vk");
    let slot = luks::add_keyslot_by_volume_key(&img, &vk, b"tpm2-secret", true).expect("slot");

    let blob_b64 = B64.encode(vec![0x5A; 96]);
    let token_json = serde_json::json!({
        "type": "systemd-tpm2",
        "keyslots": [slot.to_string()],
        "tpm2-blob": blob_b64,
        "tpm2_blob": blob_b64,
        "tpm2-pcrs": [7, 11],
        "tpm2-pcr-bank": "sha256",
        "tpm2-primary-alg": "ecc",
        "tpm2-policy-hash": "ab".repeat(32),
        "tpm2-pin": true,
        "tpm2_pubkey_pcrs": [],
        "tpm2_pcr_hash": "sha256",
        "tpm2_pcrlock": false,
        "tpm2_srk": B64.encode([0x11; 32]),
    })
    .to_string();
    luks::set_token(&img, -1, Some(&token_json)).expect("set token");

    let refs = luks::tpm2_token_refs(&img).expect("refs");
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].blob, vec![0x5A; 96]);
    assert_eq!(refs[0].pcrs, "7+11");
    assert_eq!(refs[0].pcr_bank, "sha256");
    assert!(refs[0].pin_required);
}
