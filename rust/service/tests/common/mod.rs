//! Shared harness for the integration tests. Lives in a `common/` subdirectory
//! so Cargo does not compile it as its own test binary; each `tests/*.rs`
//! pulls it in with `mod common;`.

// Each `tests/*.rs` is a separate crate and uses only some of these helpers,
// so unused-in-one-binary items would otherwise trip `dead_code`.
#![allow(dead_code)]

/// LUKS images live under /tmp so `op_create_encrypted_image`'s path allowlist
/// (/home/ or /tmp/) accepts them.
pub fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir_in("/tmp").expect("tempdir")
}

pub const PASSPHRASE: &str = "test-passphrase-123";

/// 32 MiB image: LUKS2 reserves 16 MiB for metadata by default.
pub fn new_luks_image(dir: &tempfile::TempDir) -> String {
    let path = dir.path().join("test.img").to_string_lossy().into_owned();
    let (ok, keyslot, err) =
        luks_enroll_service::service::op_create_encrypted_image(&path, 32, PASSPHRASE, None);
    assert!(ok, "op_create_encrypted_image failed: {err}");
    assert_eq!(keyslot, 0, "first keyslot should be 0");
    path
}
