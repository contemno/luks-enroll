//! Config drift-guard: the packaging files under `dist/` (systemd unit, D-Bus
//! policy + activation, polkit policy) duplicate identifiers that live in the
//! Rust single source of truth (`luks_enroll_service::constants`). These tests
//! assert they agree, so a rename in one place can't silently desync the
//! installed config. (B1 froze the constants; this ties the config to them.)
//!
//! The `dist/` tree is read relative to this crate's manifest dir, so it works
//! from any cwd under CI's `cargo test`.

use std::fs;
use std::path::{Path, PathBuf};

use luks_enroll_service::constants::{
    BUS_NAME, POLKIT_ACTION_MANAGE, POLKIT_ACTION_READ, SERVICE_BINARY_PATH,
};

/// `dist/<rel>` resolved from CARGO_MANIFEST_DIR (`.../rust/service`).
fn dist(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../dist")
        .join(rel)
}

fn read(rel: &str) -> String {
    let path = dist(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Assert `hay` contains `needle`, naming the file + expected value on failure.
fn assert_has(file: &str, hay: &str, needle: &str) {
    assert!(
        hay.contains(needle),
        "{file}: expected to contain `{needle}` (drift from luks_enroll_service::constants)"
    );
}

#[test]
fn systemd_unit_matches_constants() {
    let f = "lib/systemd/system/net.contemno.LuksEnroll.service";
    let s = read(f);
    assert_has(f, &s, &format!("BusName={BUS_NAME}"));
    assert_has(f, &s, &format!("ExecStart={SERVICE_BINARY_PATH}"));
}

#[test]
fn dbus_activation_matches_constants() {
    let f = "usr/share/dbus-1/system-services/net.contemno.LuksEnroll.service";
    let s = read(f);
    assert_has(f, &s, &format!("Name={BUS_NAME}"));
    assert_has(f, &s, &format!("Exec={SERVICE_BINARY_PATH}"));
    // The activation entry must point at the systemd unit, named after the bus.
    assert_has(f, &s, &format!("SystemdService={BUS_NAME}.service"));
}

#[test]
fn dbus_policy_matches_constants() {
    let f = "usr/share/dbus-1/system.d/net.contemno.luks_enroll.conf";
    let s = read(f);
    assert_has(f, &s, &format!("own=\"{BUS_NAME}\""));
    assert_has(f, &s, &format!("send_destination=\"{BUS_NAME}\""));
}

#[test]
fn polkit_policy_matches_constants() {
    let f = "usr/share/polkit-1/actions/net.contemno.luks-enroll.policy";
    let s = read(f);
    assert_has(f, &s, &format!("action id=\"{POLKIT_ACTION_READ}\""));
    assert_has(f, &s, &format!("action id=\"{POLKIT_ACTION_MANAGE}\""));
}
