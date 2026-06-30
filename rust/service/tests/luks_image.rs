//! Integration tests: real libcryptsetup operations against LUKS2 image
//! files — no root, no hardware, no D-Bus.
//!
//! This is the conformance safety net for the Rust port: the same
//! operation layer the D-Bus handlers call is exercised end-to-end, and
//! the resulting LUKS2 token JSON is asserted against the shapes the
//! Python service produced (and systemd-cryptsetup consumes).

use luks_enroll_service::{luks, service};

mod common;
use common::{new_luks_image, tmpdir, PASSPHRASE};

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
fn keyless_create_caches_vk_and_first_enroll_needs_no_passphrase() {
    // Issue #58: creating a container with an empty passphrase formats a
    // keyslot-less LUKS2 header and caches the volume key, so the first
    // enrollment authenticates from the cache -- the user never types a
    // throwaway passphrase.
    let dir = tmpdir();
    let path = dir
        .path()
        .join("keyless.img")
        .to_string_lossy()
        .into_owned();
    luks::clear_volume_key_cache(&path);

    let (ok, keyslot, err) = service::op_create_encrypted_image(&path, 32, "", None);
    assert!(ok, "keyless create failed: {err}");
    assert_eq!(keyslot, -1, "no keyslot is created up front");

    // Valid LUKS2 header, but zero keyslots / zero password slots on disk.
    assert!(
        luks::list_keyslots(&path).is_empty(),
        "no keyslots persisted"
    );
    assert!(luks::password_keyslots(&path).is_empty());

    // The first enrollment passes an empty passphrase; it can only succeed by
    // serving the volume key from the cache (there is no keyslot to unwrap).
    let (ok, recovery_key, err) = service::op_enroll_recovery_key(&path, "", "passphrase", "");
    assert!(ok, "first enroll via cached VK failed: {err}");

    // Now exactly one keyslot exists and the recovery key unlocks it.
    assert_eq!(luks::list_keyslots(&path).len(), 1);
    assert!(luks::verify_passphrase(&path, &recovery_key).is_ok());
}

#[test]
fn keyless_volume_has_no_recovery_path_once_cache_is_gone() {
    // Pins the safety reasoning behind the keyless create: with no keyslot,
    // the cached VK is the *only* way in. Dropping the cache before the first
    // enrollment leaves an empty, unrecoverable throwaway -- which is sound
    // precisely because no data has been committed yet (the container was
    // just created and was never mountable through the keyslot path).
    let dir = tmpdir();
    let path = dir.path().join("orphan.img").to_string_lossy().into_owned();
    luks::clear_volume_key_cache(&path);

    let (ok, _, err) = service::op_create_encrypted_image(&path, 32, "", None);
    assert!(ok, "keyless create failed: {err}");

    luks::clear_volume_key_cache(&path);

    // No cached VK and no keyslot: enrollment can't get a volume key.
    let (ok, _, _) = service::op_enroll_recovery_key(&path, "", "passphrase", "");
    assert!(!ok, "without the cached VK there is no way to enroll");
    // And no passphrase (not even empty) unlocks a keyslot-less header.
    assert!(luks::verify_passphrase(&path, "").is_err());
}

#[test]
fn create_refuses_existing_file_instead_of_clobbering() {
    // Issue #58: never reformat in place. A second create at the same path is
    // refused rather than truncating whatever (possibly a LUKS container) is
    // already there.
    let dir = tmpdir();
    let path = dir.path().join("exists.img").to_string_lossy().into_owned();

    let (ok, _, err) = service::op_create_encrypted_image(&path, 32, PASSPHRASE, None);
    assert!(ok, "initial create failed: {err}");

    let (ok, slot, err) = service::op_create_encrypted_image(&path, 32, PASSPHRASE, None);
    assert!(!ok, "second create must refuse the existing file");
    assert_eq!(slot, -1);
    assert_eq!(err, "A file already exists at this path");

    // The original is untouched: still a valid one-keyslot LUKS2 container.
    assert_eq!(luks::list_keyslots(&path).len(), 1);
    assert_eq!(luks::verify_passphrase(&path, PASSPHRASE), Ok(0));
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
fn recovery_keyslot_uses_minimal_pbkdf() {
    // Regression for issue #57: the recovery key is 256 bits of OS-RNG
    // entropy, so its keyslot must use the fast pbkdf2 KDF (like the
    // FIDO2/TPM2 secret slots and systemd-cryptenroll), not the slow
    // argon2id pass reserved for low-entropy user passphrases. Running
    // argon2id here cost ~8 s for no security benefit.
    let dir = tmpdir();
    let img = new_luks_image(&dir);

    let (ok, _recovery_key, err) =
        service::op_enroll_recovery_key(&img, PASSPHRASE, "passphrase", "");
    assert!(ok, "recovery enrollment failed: {err}");

    let rk_slot = luks::tokens_by_type(&img, "systemd-recovery")[0].1[0];
    let meta = luks::metadata_json(&img).expect("metadata");
    let kdf = &meta["keyslots"][rk_slot.to_string()]["kdf"]["type"];
    assert_eq!(
        kdf, "pbkdf2",
        "recovery keyslot must use minimal pbkdf2, got {kdf}"
    );

    // Sanity: the original low-entropy password slot is still argon2-hardened,
    // so this is a targeted choice, not a global KDF downgrade.
    assert_eq!(meta["keyslots"]["0"]["kdf"]["type"], "argon2id");
}

#[test]
fn token_volume_key_targets_keyslot_and_falls_back() {
    // Regression for issue #16: token unlock must query the token's own
    // keyslot instead of every keyslot (which runs the slow argon2id
    // password slot first). A systemd-recovery token stands in for a
    // FIDO2/TPM2 token — its recovery key unlocks its keyslot as an
    // ordinary passphrase, so the targeted path is exercised without
    // real hardware.
    let dir = tmpdir();
    let img = new_luks_image(&dir);

    let (ok, recovery_key, err) =
        service::op_enroll_recovery_key(&img, PASSPHRASE, "passphrase", "");
    assert!(ok, "recovery enrollment failed: {err}");

    let tokens = luks::tokens_by_type(&img, "systemd-recovery");
    assert_eq!(tokens.len(), 1);
    let rk_slot = tokens[0].1[0];

    // Targeted path: the recovery token records its keyslot, so extraction
    // unlocks via that exact slot.
    let (slot, vk_targeted) =
        luks::extract_token_volume_key(&img, "systemd-recovery", recovery_key.as_bytes())
            .expect("targeted extraction");
    assert_eq!(slot, rk_slot, "should unlock via the token's own keyslot");

    // Fallback path: no systemd-fido2 token exists, so there are no targeted
    // slots and extraction falls back to -1 (try all). Still correct, and it
    // yields the same volume key.
    let (_slot, vk_fallback) =
        luks::extract_token_volume_key(&img, "systemd-fido2", recovery_key.as_bytes())
            .expect("fallback extraction");
    assert_eq!(
        vk_targeted.as_bytes(),
        vk_fallback.as_bytes(),
        "targeted and fallback paths must yield the same volume key"
    );
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

/// The volume-key cache is no longer gated on token-based unlock: a passphrase
/// extraction primes the cache (write gate gone) and a subsequent call is
/// served from it (read gate gone). Proven by a second call with a *wrong*
/// passphrase succeeding and returning the same key.
#[test]
fn passphrase_volume_key_is_cached_and_reused() {
    let dir = tmpdir();
    let img = new_luks_image(&dir);
    luks::clear_volume_key_cache(&img);

    let vk1 = luks::get_volume_key(&img, "passphrase", PASSPHRASE, "").expect("vk");
    let vk2 = luks::get_volume_key(&img, "passphrase", "definitely-wrong", "")
        .expect("served from cache, not re-validated");
    assert_eq!(vk1.as_bytes(), vk2.as_bytes());
}

/// verify_passphrase now primes the cache (mirroring verify_token), so a
/// follow-up get_volume_key is served even with a wrong passphrase.
#[test]
fn verify_passphrase_primes_volume_key_cache() {
    let dir = tmpdir();
    let img = new_luks_image(&dir);
    luks::clear_volume_key_cache(&img);

    let slot = luks::verify_passphrase(&img, PASSPHRASE).expect("verify");
    assert!(slot >= 0);
    assert!(luks::get_volume_key(&img, "passphrase", "definitely-wrong", "").is_ok());
}

/// GetDeviceInfo must surface the LUKS2 UUID so the client can build the
/// `luks-<UUID>` mapper name. Regression for the #70 review: the underlying
/// blkid probe only requested LABEL/TYPE, so the UUID came back empty and the
/// Open button fell back to the device-basename name.
#[test]
fn device_info_reports_luks_uuid() {
    use luks_enroll_service::devices;

    let dir = tmpdir();
    let img = new_luks_image(&dir);

    let info = devices::get_device_info(&img);
    let uuid = info.get("uuid").and_then(|v| v.as_str()).unwrap_or("");
    assert!(!uuid.is_empty(), "GetDeviceInfo should report a LUKS UUID");
    // Canonical UUID shape: 36 chars, 8-4-4-4-12 hex groups.
    let groups: Vec<&str> = uuid.split('-').collect();
    assert_eq!(
        groups.len(),
        5,
        "UUID should have five dash-separated groups"
    );
    assert_eq!(
        groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "UUID groups should be 8-4-4-4-12"
    );
    assert!(
        uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
        "UUID should be hex digits and dashes only"
    );
}

/// OpenVolume must reject a mapper name that could escape /dev/mapper before
/// it ever touches dm-crypt — the validation happens up front, so this needs
/// no root and asserts the security boundary at the op entry point.
#[test]
fn open_volume_rejects_invalid_mapper_name() {
    let dir = tmpdir();
    let img = new_luks_image(&dir);

    let (ok, mapper, _err) =
        service::op_open_volume(&img, "../escape", PASSPHRASE, "passphrase", "");
    assert!(!ok, "a path-escaping mapper name must be refused");
    assert!(mapper.is_empty());

    // An empty name is refused too (it would be an invalid dm node).
    let (ok, _, _) = service::op_open_volume(&img, "", PASSPHRASE, "passphrase", "");
    assert!(!ok);
}

/// Closing a mapping that does not exist is a success (idempotent) and refuses
/// an invalid name. Guarded behind root because `crypt_status` needs access to
/// the device-mapper control node.
#[test]
fn close_volume_is_idempotent_and_validates_name() {
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("not root; skipping CloseVolume idempotency test (needs dm control node)");
        return;
    }
    // Never-mapped name -> already closed -> ok.
    let (ok, err) = service::op_close_volume("luks-enroll-test-nonexistent-mapping");
    assert!(ok, "closing a non-existent mapping should succeed: {err}");

    // Invalid name -> refused.
    let (ok, _) = service::op_close_volume("../escape");
    assert!(!ok);
}

/// Full activate -> verify mapping -> deactivate roundtrip against a real
/// LUKS2 image. Requires root (loop-device + dm-crypt setup), so it is
/// `#[ignore]`d in the default run; CI's privileged leg runs it explicitly:
///   sudo -E cargo test -p luks-enroll-service --test luks_image -- \
///     --ignored open_close_volume_roundtrip
#[test]
#[ignore = "requires root: loop-device + dm-crypt activation"]
fn open_close_volume_roundtrip() {
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("not root; skipping open/close roundtrip");
        return;
    }
    let dir = tmpdir();
    let img = new_luks_image(&dir);
    // Unique, valid mapper name for this test run.
    let name = format!("luks-enroll-test-{}", std::process::id());
    let mapper_path = format!("/dev/mapper/{name}");

    // Open: activates /dev/mapper/<name> from the volume key.
    let (ok, mapper, err) = service::op_open_volume(&img, &name, PASSPHRASE, "passphrase", "");
    assert!(ok, "open failed: {err}");
    assert_eq!(mapper, name);
    assert!(luks::mapping_is_active(&name), "mapping should be active");
    assert!(
        std::path::Path::new(&mapper_path).exists(),
        "{mapper_path} should exist after open"
    );
    // Freshly opened, nothing mounted on it -> close is allowed.
    assert!(
        !luks::mapping_is_mounted(&name),
        "a freshly opened mapping has no mounted filesystem"
    );

    // Re-open is idempotent: still ok, still one mapping.
    let (ok, _, err) = service::op_open_volume(&img, &name, PASSPHRASE, "passphrase", "");
    assert!(ok, "idempotent re-open failed: {err}");

    // Close: tears the mapping down.
    let (ok, err) = service::op_close_volume(&name);
    assert!(ok, "close failed: {err}");
    assert!(!luks::mapping_is_active(&name), "mapping should be gone");
    assert!(
        !std::path::Path::new(&mapper_path).exists(),
        "{mapper_path} should be removed after close"
    );
}
