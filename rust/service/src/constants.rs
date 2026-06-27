//! Single source of truth for identifiers that recur across the crate (and in
//! external config): the D-Bus name triple, the polkit action IDs, and the
//! systemd-cryptenroll token-type strings.
//!
//! These are a frozen external contract — the D-Bus name triple must match
//! `dbus/net.contemno.LuksEnroll1.xml` and the `dist/` systemd/D-Bus/polkit
//! files, and the token-type strings must match systemd-cryptenroll's on-disk
//! LUKS2 token `type` field. They previously appeared as bare literals in many
//! places; centralizing them removes the drift/typo risk. `constants_match_…`
//! below freezes the values so any edit here is a deliberate, reviewed change.

/// Well-known D-Bus bus name the service owns.
pub const BUS_NAME: &str = "net.contemno.LuksEnroll";
/// Object path the service is served at.
pub const OBJECT_PATH: &str = "/net/contemno/LuksEnroll";
/// D-Bus interface name.
///
/// NOTE: `#[zbus::interface(name = ...)]` in `service.rs` needs a string
/// *literal* (attribute macros can't take a `const`), so that one site repeats
/// the value; the `dbus_e2e` test connects via this constant, and the contract
/// test below guards both against drift.
pub const INTERFACE: &str = "net.contemno.LuksEnroll1";

/// polkit action gating read-only methods.
pub const POLKIT_ACTION_READ: &str = "net.contemno.luks-enroll.read";
/// polkit action gating mutating methods.
pub const POLKIT_ACTION_MANAGE: &str = "net.contemno.luks-enroll.manage";

/// Absolute path the service binary installs to; the systemd unit's
/// `ExecStart=` and the D-Bus activation `Exec=` must match it (pinned by the
/// `config_parity` integration test). Not referenced by the service at runtime
/// — it's the install-location single source of truth for the packaging files.
pub const SERVICE_BINARY_PATH: &str = "/usr/sbin/luks-enroll-service";

/// LUKS2 token `type` for a FIDO2 enrollment (systemd-cryptenroll compatible).
pub const TOKEN_TYPE_FIDO2: &str = "systemd-fido2";
/// LUKS2 token `type` for a TPM2 enrollment.
pub const TOKEN_TYPE_TPM2: &str = "systemd-tpm2";
/// LUKS2 token `type` for a recovery-key enrollment.
pub const TOKEN_TYPE_RECOVERY: &str = "systemd-recovery";

#[cfg(test)]
mod tests {
    use super::*;

    /// Tripwire, not a tautology: these strings are a frozen external contract
    /// (the D-Bus name triple, the polkit action IDs, and systemd-cryptenroll's
    /// token-type field). Freezing them here forces any change to be a
    /// two-place, deliberate edit rather than a silent break.
    #[test]
    fn constants_match_frozen_contract() {
        assert_eq!(BUS_NAME, "net.contemno.LuksEnroll");
        assert_eq!(OBJECT_PATH, "/net/contemno/LuksEnroll");
        assert_eq!(INTERFACE, "net.contemno.LuksEnroll1");
        assert_eq!(POLKIT_ACTION_READ, "net.contemno.luks-enroll.read");
        assert_eq!(POLKIT_ACTION_MANAGE, "net.contemno.luks-enroll.manage");
        assert_eq!(TOKEN_TYPE_FIDO2, "systemd-fido2");
        assert_eq!(TOKEN_TYPE_TPM2, "systemd-tpm2");
        assert_eq!(TOKEN_TYPE_RECOVERY, "systemd-recovery");
        assert_eq!(SERVICE_BINARY_PATH, "/usr/sbin/luks-enroll-service");
    }
}
