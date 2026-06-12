//! D-Bus system service daemon for privileged LUKS enrollment operations.
//!
//! Bus name:  net.contemno.LuksEnroll
//! Object:    /net/contemno/LuksEnroll
//! Interface: net.contemno.LuksEnroll1
//!
//! Rust port of dist/usr/sbin/luks-enroll-service (Python). The D-Bus
//! interface is frozen in dbus/net.contemno.LuksEnroll1.xml; behavior is
//! intentionally parity-preserving (see RUST_MIGRATION.md).

use futures_util::StreamExt;
use luks_enroll_service::service;
use zbus::fdo::{DBusProxy, RequestNameFlags, RequestNameReply};
use zbus::names::WellKnownName;

const BUS_NAME: &str = "net.contemno.LuksEnroll";
const OBJECT_PATH: &str = "/net/contemno/LuksEnroll";

/// Idle timeout: exit when no privileged method has been called for this
/// long. The service is bus-activated, so exiting is cheap.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let replace = std::env::args().any(|a| a == "--replace");

    let (idle_tx, mut idle_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let svc = service::LuksEnrollService::new(idle_tx);

    let connection = zbus::connection::Builder::system()?
        .serve_at(OBJECT_PATH, svc)?
        .build()
        .await?;

    let mut flags = RequestNameFlags::AllowReplacement | RequestNameFlags::DoNotQueue;
    if replace {
        flags |= RequestNameFlags::ReplaceExisting;
    }
    let dbus = DBusProxy::new(&connection).await?;
    let name = WellKnownName::try_from(BUS_NAME)?;
    match dbus.request_name(name.clone(), flags).await? {
        RequestNameReply::PrimaryOwner => eprintln!("Acquired bus name: {BUS_NAME}"),
        reply => {
            eprintln!("Could not acquire bus name {BUS_NAME}: {reply:?}");
            std::process::exit(1);
        }
    }
    eprintln!("Object registered at {OBJECT_PATH}");

    // Exit if we lose the bus name (e.g. replaced by a --replace instance).
    let mut name_lost = dbus.receive_name_lost().await?;
    let lost = async {
        while let Some(sig) = name_lost.next().await {
            match sig.args() {
                Ok(args) if *args.name() == name => return,
                _ => continue,
            }
        }
    };

    // Idle timeout: every privileged method call pings idle_tx; exit after
    // IDLE_TIMEOUT with no pings.
    let idle = async {
        while let Ok(Some(())) = tokio::time::timeout(IDLE_TIMEOUT, idle_rx.recv()).await {}
    };

    tokio::select! {
        _ = lost => eprintln!("Lost bus name: {BUS_NAME}"),
        _ = idle => eprintln!("Idle timeout reached, exiting."),
    }
    Ok(())
}
