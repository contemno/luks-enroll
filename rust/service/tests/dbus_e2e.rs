//! End-to-end D-Bus test: boots the real service binary on a private bus
//! and talks to it like the GTK client would.
//!
//! A throwaway dbus-daemon stands in for the system bus via
//! DBUS_SYSTEM_BUS_ADDRESS. There is no polkitd on it, so:
//!   - methods on caller-owned image files succeed through the
//!     ownership-based polkit skip (the real fast path for image files),
//!   - methods that need polkit fail with the exact error name the
//!     Python service used (org.freedesktop.PolicyKit1.Error.NotAuthorized).
//!
//! Skips (with a notice) when dbus-daemon isn't installed.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BUS_NAME: &str = "net.contemno.LuksEnroll";
const OBJECT_PATH: &str = "/net/contemno/LuksEnroll";
const INTERFACE: &str = "net.contemno.LuksEnroll1";

struct Procs {
    daemon: Child,
    service: Child,
}

impl Drop for Procs {
    fn drop(&mut self) {
        let _ = self.service.kill();
        let _ = self.service.wait();
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

fn start_private_bus_and_service() -> Option<(Procs, String)> {
    // Private session-type daemon; same-uid default policy allows
    // everything we need (name ownership, method calls).
    let mut daemon = match Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address"])
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            eprintln!("dbus-daemon not available; skipping e2e test");
            return None;
        }
    };
    let stdout = daemon.stdout.take().expect("daemon stdout");
    let mut address = String::new();
    BufReader::new(stdout)
        .read_line(&mut address)
        .expect("daemon address");
    let address = address.trim().to_string();
    assert!(!address.is_empty(), "empty bus address");

    let service = Command::new(env!("CARGO_BIN_EXE_luks-enroll-service"))
        .env("DBUS_SYSTEM_BUS_ADDRESS", &address)
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn service");

    Some((Procs { daemon, service }, address))
}

async fn connect(address: &str) -> zbus::Connection {
    // The service connects to the same address via DBUS_SYSTEM_BUS_ADDRESS;
    // the client connects explicitly.
    zbus::connection::Builder::address(address)
        .expect("address")
        .build()
        .await
        .expect("client connection")
}

async fn wait_for_name(conn: &zbus::Connection) {
    let dbus = zbus::fdo::DBusProxy::new(conn).await.expect("fdo proxy");
    for _ in 0..100 {
        let names = dbus.list_names().await.expect("list names");
        if names.iter().any(|n| n.as_str() == BUS_NAME) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("service never acquired {BUS_NAME}");
}

async fn proxy(conn: &zbus::Connection) -> zbus::Proxy<'_> {
    zbus::Proxy::new(conn, BUS_NAME, OBJECT_PATH, INTERFACE)
        .await
        .expect("proxy")
}

#[tokio::test]
async fn e2e_over_private_bus() {
    let Some((_procs, address)) = start_private_bus_and_service() else {
        return; // skipped
    };
    let conn = connect(&address).await;
    wait_for_name(&conn).await;
    let proxy = proxy(&conn).await;

    // --- Unprivileged method ---
    let version: i32 = proxy
        .call("GetSystemdVersion", &())
        .await
        .expect("GetSystemdVersion");
    assert_eq!(version, 999);

    // --- Privileged read on a caller-owned image file: the ownership
    //     check must bypass polkit and succeed end-to-end. ---
    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let img = dir.path().join("e2e.img").to_string_lossy().into_owned();
    let (ok, keyslot, err) =
        luks_enroll_service::service::op_create_encrypted_image(&img, 32, "pw-e2e", None);
    assert!(ok, "image creation failed: {err}");
    assert_eq!(keyslot, 0);

    let keyslots_json: String = proxy
        .call("GetKeyslots", &(img.as_str(),))
        .await
        .expect("GetKeyslots over the bus");
    let parsed: serde_json::Value = serde_json::from_str(&keyslots_json).expect("json");
    assert_eq!(parsed["0"], "luks2");

    // Auth is now cached for the read action: a second read also works.
    let slots: Vec<i32> = proxy
        .call("FindPasswordKeyslots", &(img.as_str(),))
        .await
        .expect("FindPasswordKeyslots");
    assert_eq!(slots, vec![0]);

    // --- Manage-action method on the owned file (VerifyPassphrase). ---
    let (ok, slot): (bool, i32) = proxy
        .call("VerifyPassphrase", &(img.as_str(), "pw-e2e"))
        .await
        .expect("VerifyPassphrase");
    assert!(ok);
    assert_eq!(slot, 0);
    let (ok, slot): (bool, i32) = proxy
        .call("VerifyPassphrase", &(img.as_str(), "wrong"))
        .await
        .expect("VerifyPassphrase wrong");
    assert!(!ok);
    assert_eq!(slot, -1);

    // --- Bad device argument: exact InvalidArgs error. ---
    let err = proxy
        .call::<_, _, String>("GetKeyslots", &("/nonexistent/nope",))
        .await
        .expect_err("missing device must fail");
    assert_eq!(
        error_name(&err),
        Some("org.freedesktop.DBus.Error.InvalidArgs")
    );

    // --- No polkitd on this bus: a method without an ownership path must
    //     fail with the exact polkit error name. ---
    let err = proxy
        .call::<_, _, Vec<String>>("DetectDevices", &())
        .await
        .expect_err("DetectDevices must fail without polkit");
    assert_eq!(
        error_name(&err),
        Some("org.freedesktop.PolicyKit1.Error.NotAuthorized")
    );
}

fn error_name(e: &zbus::Error) -> Option<&str> {
    match e {
        zbus::Error::MethodError(name, _, _) => Some(name.as_str()),
        _ => None,
    }
}
