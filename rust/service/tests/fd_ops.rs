//! File-descriptor operation tests.
//!
//! The *Fd D-Bus methods route every operation through /proc/self/fd/N
//! instead of a path, so the sandboxed service can manage user-owned
//! container files under ProtectHome without relaxing the sandbox. These
//! tests cover the two things that matter:
//!   1. functional parity — the op layer behaves identically when handed a
//!      /proc/self/fd path instead of a real path;
//!   2. the sandbox bypass itself — a child in a read-only mount namespace,
//!      holding a read-write fd opened by the parent, can still LUKS-format
//!      and enroll through /proc/self/fd (the EROFS-on-/home case).

use std::os::fd::AsRawFd;

use luks_enroll_service::{luks, service};

mod common;
use common::{tmpdir, PASSPHRASE};

fn fd_path<F: AsRawFd>(f: &F) -> String {
    format!("/proc/self/fd/{}", f.as_raw_fd())
}

/// op_create_image_fd + enroll + verify, all via /proc/self/fd — proves
/// libcryptsetup operates correctly on the magic-symlink path.
#[test]
fn fd_create_enroll_verify_roundtrip() {
    let dir = tmpdir();
    let path = dir.path().join("c.img");
    // Client side: create + size the file it owns, then hand over the fd.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("create");
    file.set_len(32 * 1024 * 1024).expect("size");
    let fdp = fd_path(&file);

    // Service side: format via the fd path.
    let (ok, keyslot, err) = service::op_create_image_fd(&fdp, PASSPHRASE);
    assert!(ok, "create via fd failed: {err}");
    assert_eq!(keyslot, 0);

    // Header is valid and the passphrase verifies — addressed by either the
    // fd path or the real path (same inode).
    assert_eq!(luks::verify_passphrase(&fdp, PASSPHRASE), Ok(0));
    assert_eq!(
        luks::verify_passphrase(&path.to_string_lossy(), PASSPHRASE),
        Ok(0)
    );

    // Enrolling a recovery key through the fd path writes the header.
    let (ok, rkey, err) = service::op_enroll_recovery_key(&fdp, PASSPHRASE, "passphrase", "");
    assert!(ok, "recovery enroll via fd failed: {err}");
    assert!(luks::verify_passphrase(&fdp, &rkey).is_ok());
    assert_eq!(
        luks::tokens_by_type(&fdp, "systemd-recovery").len(),
        1,
        "token must be readable back through the fd path"
    );
}

/// The sandbox bypass: reproduce ProtectHome=read-only in a child mount
/// namespace and prove the fd path still works where a direct path open
/// would get EROFS. This is the exact failure the user hit, in miniature.
///
/// `#[ignore]` by default for two reasons: it needs root + mount-namespace
/// support, and it `fork()`s — which is only safe when no sibling test is
/// running argon2/malloc in another libtest worker thread. Run it alone:
///   sudo -E cargo test -p luks-enroll-service --test fd_ops -- \
///     --ignored --test-threads=1 fd_writes_through_readonly_mount_namespace
#[test]
#[ignore = "requires root; forks, so must run single-threaded and alone"]
fn fd_writes_through_readonly_mount_namespace() {
    use nix::mount::{mount, MsFlags};
    use nix::sched::{unshare, CloneFlags};
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};
    use std::os::fd::AsFd;

    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("not root; skipping mount-namespace bypass test");
        return;
    }

    let dir = tmpdir();
    let path = dir.path().join("sandboxed.img");
    let dir_path = dir.path().to_path_buf();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("create");
    file.set_len(32 * 1024 * 1024).expect("size");

    // SAFETY: the child only performs async-signal-safe-ish work and exits
    // via _exit; it shares the parent's already-open fd (inherited).
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            let run = || -> Result<(), String> {
                unshare(CloneFlags::CLONE_NEWNS).map_err(|e| format!("unshare: {e}"))?;
                mount(
                    None::<&str>,
                    "/",
                    None::<&str>,
                    MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                    None::<&str>,
                )
                .map_err(|e| format!("make-private: {e}"))?;
                // Re-bind the temp dir read-only: the service's view of /home.
                mount(
                    Some(&dir_path),
                    &dir_path,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )
                .map_err(|e| format!("bind: {e}"))?;
                mount(
                    None::<&str>,
                    &dir_path,
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                    None::<&str>,
                )
                .map_err(|e| format!("remount-ro: {e}"))?;

                // A direct path open RW must now fail (sandbox is active).
                match std::fs::OpenOptions::new().write(true).open(&path) {
                    Ok(_) => return Err("direct RW open unexpectedly succeeded".into()),
                    Err(e) if e.raw_os_error() == Some(libc::EROFS) => {}
                    Err(e) => return Err(format!("unexpected direct-open error: {e}")),
                }

                // But operating through the inherited fd writes through.
                let fdp = fd_path(&file);
                let (ok, _slot, err) = service::op_create_image_fd(&fdp, PASSPHRASE);
                if !ok {
                    return Err(format!("create via fd in sandbox failed: {err}"));
                }
                let (ok, _rk, err) =
                    service::op_enroll_recovery_key(&fdp, PASSPHRASE, "passphrase", "");
                if !ok {
                    return Err(format!("enroll via fd in sandbox failed: {err}"));
                }
                // Keep the fd alive until here.
                let _ = file.as_fd();
                Ok(())
            };
            match run() {
                Ok(()) => unsafe { libc::_exit(0) },
                Err(e) => {
                    eprintln!("sandbox child: {e}");
                    unsafe { libc::_exit(1) }
                }
            }
        }
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).expect("waitpid");
            assert!(
                matches!(status, WaitStatus::Exited(_, 0)),
                "child failed: {status:?}"
            );
            // Parent (outside the namespace) reads back what the child wrote.
            assert_eq!(
                luks::verify_passphrase(&path.to_string_lossy(), PASSPHRASE),
                Ok(0)
            );
            assert_eq!(
                luks::tokens_by_type(&path.to_string_lossy(), "systemd-recovery").len(),
                1
            );
        }
    }
}
