//! The net.contemno.LuksEnroll1 D-Bus interface.
//!
//! Mirrors the Python service's central dispatch exactly:
//!   1. authorization (cache -> ownership-based skip -> polkit), per-kind
//!      caches: read 30 s, manage 300 s, keyed by D-Bus sender
//!   2. idle-timer reset (privileged methods only)
//!   3. device-path canonicalization + block/regular-file validation
//!      (after auth, to prevent TOCTOU between check and handler)
//!   4. 10 MiB length cap on every string argument
//!   5. dispatch; blocking crypto/hardware work on spawn_blocking threads
//!
//! Operation failures return (false, "", "Operation failed")-style tuples
//! with the real error logged to stderr; D-Bus errors are reserved for
//! authorization and argument validation, with the same error names the
//! Python service used.

use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use zbus::message::Header;
use zbus::zvariant::OwnedFd;
use zbus::Connection;
use zbus_polkit::policykit1::{AuthorityProxy, CheckAuthorizationFlags, Subject};

use crate::{devices, fido2, format, luks, recovery, settings};

pub const POLKIT_ACTION_READ: &str = "net.contemno.luks-enroll.read";
pub const POLKIT_ACTION_MANAGE: &str = "net.contemno.luks-enroll.manage";

const AUTH_CACHE_TTL: Duration = Duration::from_secs(30);
const MANAGE_AUTH_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Input size limit applied to every string parameter.
const MAX_STRING_LEN: usize = 10 * 1024 * 1024; // 10 MiB

/// D-Bus errors with the exact names the Python service emitted.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop")]
pub enum SvcError {
    #[zbus(name = "PolicyKit1.Error.NotAuthorized")]
    NotAuthorized(String),
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
}

type MethodResult<T> = Result<T, SvcError>;

#[derive(Clone, Copy, PartialEq)]
enum AuthKind {
    Read,
    Manage,
}

pub struct LuksEnrollService {
    idle_tx: tokio::sync::mpsc::UnboundedSender<()>,
    read_auth: Mutex<HashMap<String, Instant>>,
    manage_auth: Mutex<HashMap<String, Instant>>,
}

impl LuksEnrollService {
    pub fn new(idle_tx: tokio::sync::mpsc::UnboundedSender<()>) -> Self {
        LuksEnrollService {
            idle_tx,
            read_auth: Mutex::new(HashMap::new()),
            manage_auth: Mutex::new(HashMap::new()),
        }
    }

    /// os.path.realpath equivalent: resolve as far as possible, never fail.
    fn realpath(path: &str) -> String {
        if let Ok(p) = std::fs::canonicalize(path) {
            return p.to_string_lossy().into_owned();
        }
        // Path doesn't exist: resolve the parent and re-append the file name
        // (enough for CreateEncryptedImage's not-yet-created files).
        let p = Path::new(path);
        if let (Some(parent), Some(name)) = (p.parent(), p.file_name()) {
            if let Ok(rp) = std::fs::canonicalize(parent) {
                return rp.join(name).to_string_lossy().into_owned();
            }
        }
        path.to_string()
    }

    async fn caller_uid(conn: &Connection, hdr: &Header<'_>) -> Option<u32> {
        let sender = hdr.sender()?.to_owned();
        let dbus = zbus::fdo::DBusProxy::new(conn).await.ok()?;
        dbus.get_connection_unix_user(sender.into()).await.ok()
    }

    /// Authorization gate. `owned_path` is the first parameter for methods
    /// operating on a device/file (polkit is skipped when the caller owns
    /// the file); `create_image` switches the ownership test to the parent
    /// directory (the file doesn't exist yet).
    async fn gate(
        &self,
        conn: &Connection,
        hdr: &Header<'_>,
        kind: AuthKind,
        owned_path: Option<&str>,
        create_image: bool,
    ) -> MethodResult<()> {
        let sender = hdr.sender().map(|s| s.to_string()).unwrap_or_default();

        let is_cached = {
            let (cache, ttl) = match kind {
                AuthKind::Read => (&self.read_auth, AUTH_CACHE_TTL),
                AuthKind::Manage => (&self.manage_auth, MANAGE_AUTH_CACHE_TTL),
            };
            let map = cache.lock().unwrap();
            map.get(&sender).is_some_and(|t| t.elapsed() < ttl)
        };

        if !is_cached {
            // Skip polkit if the caller owns the (resolved) file they're
            // operating on; symlinks are resolved first so a user can't
            // point the service at files they don't own.
            let mut needs_polkit = true;
            if let Some(arg0) = owned_path {
                if let Some(uid) = Self::caller_uid(conn, hdr).await {
                    let real = Self::realpath(arg0);
                    let target: Option<PathBuf> = if create_image {
                        Path::new(&real).parent().map(|p| p.to_path_buf())
                    } else {
                        Some(PathBuf::from(&real))
                    };
                    if let Some(target) = target {
                        if let Ok(md) = std::fs::metadata(&target) {
                            let type_ok = if create_image {
                                md.is_dir()
                            } else {
                                md.is_file()
                            };
                            if type_ok && md.uid() == uid {
                                needs_polkit = false;
                            }
                        }
                    }
                }
            }

            if needs_polkit {
                let action = match kind {
                    AuthKind::Read => POLKIT_ACTION_READ,
                    AuthKind::Manage => POLKIT_ACTION_MANAGE,
                };
                if !check_polkit(conn, hdr, action).await {
                    return Err(SvcError::NotAuthorized(
                        "Authorization required for LUKS enrollment operations".into(),
                    ));
                }
            }

            let cache = match kind {
                AuthKind::Read => &self.read_auth,
                AuthKind::Manage => &self.manage_auth,
            };
            cache.lock().unwrap().insert(sender, Instant::now());
        }

        // Reset the idle timeout on every authorized privileged call.
        let _ = self.idle_tx.send(());
        Ok(())
    }

    /// Canonicalize a device argument and require it to be a block device
    /// or regular file (TOCTOU guard between the auth check and handler).
    fn validate_device(path: &str) -> MethodResult<String> {
        let real = Self::realpath(path);
        let md = std::fs::metadata(&real)
            .map_err(|_| SvcError::InvalidArgs("Device path does not exist".into()))?;
        let is_blk = (md.mode() & libc::S_IFMT) == libc::S_IFBLK;
        if !(is_blk || md.is_file()) {
            return Err(SvcError::InvalidArgs(
                "Path is not a block device or regular file".into(),
            ));
        }
        Ok(real)
    }

    fn check_lens(args: &[&str]) -> MethodResult<()> {
        for a in args {
            if a.len() > MAX_STRING_LEN {
                return Err(SvcError::InvalidArgs(
                    "Parameter exceeds maximum length".into(),
                ));
            }
        }
        Ok(())
    }

    /// Validate a file descriptor received over D-Bus for an *Fd method.
    ///
    /// The descriptor must refer to a regular file (or a block device,
    /// unless `regular_only`) and, for write operations, must be opened
    /// read-write. Possession of the descriptor *is* the authorization:
    /// the caller could only have obtained it by holding the access it
    /// represents, which is strictly stronger than the path-based
    /// ownership skip — so no polkit check is consulted (and a round-trip
    /// is saved). Operating on the file through /proc/self/fd also lets the
    /// sandboxed, privileged service reach user-owned container files under
    /// `ProtectHome=read-only` without relaxing the sandbox: the descriptor
    /// carries the client's writable mount, so the reopen writes through.
    fn check_fd<Fd: AsFd>(fd: Fd, need_write: bool, regular_only: bool) -> MethodResult<()> {
        let st = nix::sys::stat::fstat(&fd)
            .map_err(|_| SvcError::InvalidArgs("Invalid file descriptor".into()))?;
        let typ = (st.st_mode as u32) & libc::S_IFMT;
        let is_reg = typ == libc::S_IFREG;
        let is_blk = typ == libc::S_IFBLK;
        if !(is_reg || (!regular_only && is_blk)) {
            return Err(SvcError::InvalidArgs(
                "Descriptor is not a regular file".into(),
            ));
        }
        let flags = nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_GETFL)
            .map_err(|_| SvcError::InvalidArgs("Invalid file descriptor".into()))?;
        let acc = nix::fcntl::OFlag::from_bits_truncate(flags) & nix::fcntl::OFlag::O_ACCMODE;
        if need_write {
            if acc != nix::fcntl::OFlag::O_RDWR {
                return Err(SvcError::InvalidArgs(
                    "File descriptor is not writable".into(),
                ));
            }
        } else if acc == nix::fcntl::OFlag::O_WRONLY {
            return Err(SvcError::InvalidArgs(
                "File descriptor is not readable".into(),
            ));
        }
        Ok(())
    }

    /// Keep the bus-activated service alive while work is in flight.
    /// (The *Fd methods skip the polkit gate, so they reset the idle timer
    /// here instead of through `gate`.)
    fn touch_idle(&self) {
        let _ = self.idle_tx.send(());
    }
}

/// Path libcryptsetup can open for an fd received over D-Bus. The fd table
/// is process-wide, so /proc/self/fd is valid from the blocking thread.
fn fd_path<Fd: AsRawFd>(fd: &Fd) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

async fn check_polkit(conn: &Connection, hdr: &Header<'_>, action: &str) -> bool {
    let result = async {
        let authority = AuthorityProxy::new(conn).await?;
        let subject = Subject::new_for_message_header(hdr)
            .map_err(|e| zbus::Error::Failure(format!("polkit subject: {e}")))?;
        let auth = authority
            .check_authorization(
                &subject,
                action,
                &HashMap::new(),
                CheckAuthorizationFlags::AllowUserInteraction.into(),
                "",
            )
            .await?;
        Ok::<bool, zbus::Error>(auth.is_authorized)
    }
    .await;
    match result {
        Ok(authorized) => authorized,
        Err(e) => {
            eprintln!("Polkit check failed: {e}");
            false
        }
    }
}

/// Run a blocking operation off the async executor.
async fn blocking<T, F>(f: F) -> MethodResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(f).await.map_err(|e| {
        eprintln!("Method failed: {e}");
        SvcError::Failed("Operation failed".into())
    })
}

// ---------------------------------------------------------------------------
// Operation layer: free functions so integration tests can exercise the
// orchestration (token JSON construction, keyslot bookkeeping) against
// LUKS2 image files without D-Bus. Each mirrors a Python _handle_* body.
// ---------------------------------------------------------------------------

type Triple = (bool, String, String);

fn op_failed(op: &str, e: impl std::fmt::Display) -> Triple {
    eprintln!("{op} failed: {e}");
    (false, String::new(), "Operation failed".to_string())
}

pub fn op_enroll_fido2(
    device: &str,
    passphrase: &str,
    pin: &str,
    fido2_device: &str,
    unlock_method: &str,
    unlock_pin: &str,
) -> Triple {
    let run = || -> crate::error::Result<Triple> {
        // Reject if this physical token is already enrolled on this volume.
        let existing_creds: Vec<Vec<u8>> = luks::fido2_token_refs(device)
            .map(|refs| refs.into_iter().map(|r| r.cred_id).collect())
            .unwrap_or_default();
        if !existing_creds.is_empty()
            && !fido2::enrolled_paths(&[fido2_device.to_string()], &existing_creds).is_empty()
        {
            return Ok((
                false,
                String::new(),
                "This FIDO2 token is already enrolled on this volume".to_string(),
            ));
        }

        let enrollment = fido2::enroll(fido2_device, (!pin.is_empty()).then_some(pin))?;
        let vk = luks::get_volume_key(device, unlock_method, passphrase, unlock_pin)?;

        // systemd convention: the token plugin base64-encodes the secret.
        let secret_b64 = B64.encode(&enrollment.hmac_secret);
        let keyslot = luks::add_keyslot_by_volume_key(device, &vk, secret_b64.as_bytes(), true)?;

        let token_json = serde_json::json!({
            "type": "systemd-fido2",
            "keyslots": [keyslot.to_string()],
            "fido2-credential": B64.encode(&enrollment.cred_id),
            "fido2-salt": B64.encode(&enrollment.salt),
            "fido2-rp": fido2::FIDO2_RP_ID,
            "fido2-clientPin-required": !pin.is_empty(),
            "fido2-up-required": true,
            "fido2-uv-required": false,
        });
        luks::set_token(device, -1, Some(&token_json.to_string()))?;
        luks::clear_volume_key_cache(device);
        Ok((true, String::new(), String::new()))
    };
    run().unwrap_or_else(|e| op_failed("EnrollFido2", e))
}

pub fn op_enroll_tpm2(
    device: &str,
    passphrase: &str,
    pin: &str,
    pcrs: &str,
    unlock_method: &str,
    unlock_pin: &str,
) -> Triple {
    let run = || -> crate::error::Result<Triple> {
        // Random 32-byte secret to seal.
        let mut secret = zeroize::Zeroizing::new(vec![0u8; 32]);
        getrandom::fill(&mut secret).map_err(|e| crate::error::Error(e.to_string()))?;

        let sealed = crate::tpm2::seal(&secret, pcrs, pin)?;
        let vk = luks::get_volume_key(device, unlock_method, passphrase, unlock_pin)?;

        // systemd convention: token plugin base64-encodes the unsealed bytes.
        let secret_b64 = B64.encode(&*secret);
        let keyslot = luks::add_keyslot_by_volume_key(device, &vk, secret_b64.as_bytes(), true)?;

        let pcr_list: Vec<i64> = pcrs
            .split('+')
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| {
                p.parse()
                    .map_err(|_| crate::error::Error(format!("bad PCR: {p}")))
            })
            .collect::<crate::error::Result<_>>()?;

        let blob_b64 = B64.encode(&sealed.blob);
        let token_json = serde_json::json!({
            "type": "systemd-tpm2",
            "keyslots": [keyslot.to_string()],
            // Both spellings, exactly like the Python service.
            "tpm2-blob": blob_b64,
            "tpm2_blob": blob_b64,
            "tpm2-pcrs": pcr_list,
            "tpm2-pcr-bank": "sha256",
            "tpm2-primary-alg": sealed.primary_alg,
            "tpm2-policy-hash": hex_encode(&sealed.policy_hash),
            "tpm2-pin": !pin.is_empty(),
            "tpm2_pubkey_pcrs": [],
            "tpm2_pcr_hash": "sha256",
            "tpm2_pcrlock": false,
            "tpm2_srk": B64.encode(&sealed.srk_blob),
        });
        luks::set_token(device, -1, Some(&token_json.to_string()))?;
        luks::clear_volume_key_cache(device);
        Ok((true, String::new(), String::new()))
    };
    run().unwrap_or_else(|e| op_failed("EnrollTpm2", e))
}

pub fn op_enroll_recovery_key(
    device: &str,
    passphrase: &str,
    unlock_method: &str,
    unlock_pin: &str,
) -> Triple {
    let run = || -> crate::error::Result<Triple> {
        let recovery_key = recovery::make_recovery_key();
        let vk = luks::get_volume_key(device, unlock_method, passphrase, unlock_pin)?;
        let keyslot = luks::add_keyslot_by_volume_key(device, &vk, recovery_key.as_bytes(), false)?;
        let token_json = serde_json::json!({
            "type": "systemd-recovery",
            "keyslots": [keyslot.to_string()],
        });
        luks::set_token(device, -1, Some(&token_json.to_string()))?;
        luks::clear_volume_key_cache(device);
        // The GUI parses the recovery key from the stdout field.
        Ok((true, recovery_key, String::new()))
    };
    run().unwrap_or_else(|e| op_failed("EnrollRecoveryKey", e))
}

pub fn op_enroll_passphrase(
    device: &str,
    existing_passphrase: &str,
    new_passphrase: &str,
    unlock_method: &str,
    unlock_pin: &str,
) -> Triple {
    let run = || -> crate::error::Result<Triple> {
        let vk = luks::get_volume_key(device, unlock_method, existing_passphrase, unlock_pin)?;
        luks::add_keyslot_by_volume_key(device, &vk, new_passphrase.as_bytes(), false)?;
        luks::clear_volume_key_cache(device);
        Ok((true, String::new(), String::new()))
    };
    run().unwrap_or_else(|e| op_failed("EnrollPassphrase", e))
}

pub fn op_wipe_slot(
    device: &str,
    passphrase: &str,
    unlock_method: &str,
    pin: &str,
    slot: i32,
) -> Triple {
    let run = || -> crate::error::Result<Triple> {
        // Verify the caller can unlock the device at all.
        luks::get_volume_key(device, unlock_method, passphrase, pin)?;

        // Refuse to wipe the last remaining keyslot.
        let slots = luks::list_keyslots(device);
        if slots.len() <= 1 && slots.contains_key(&slot) {
            return Ok((
                false,
                String::new(),
                "Cannot wipe the last remaining keyslot".to_string(),
            ));
        }

        // Remove the associated token first, if any.
        let token_id = luks::find_token_for_keyslot(device, slot);
        if token_id >= 0 {
            luks::set_token(device, token_id, None)?;
        }
        luks::destroy_keyslot(device, slot)?;
        luks::clear_volume_key_cache(device);
        Ok((true, String::new(), String::new()))
    };
    run().unwrap_or_else(|e| op_failed("WipeSlot", e))
}

pub fn op_create_encrypted_image(
    real_path: &str,
    size_mb: i32,
    passphrase: &str,
    owner: Option<(u32, u32)>,
) -> (bool, i32, String) {
    // Reject block devices / non-regular existing paths.
    let p = Path::new(real_path);
    if p.exists() && !p.is_file() {
        return (false, -1, "Path must be a regular file".to_string());
    }
    // Allowlist: only under /home/ or /tmp/.
    if !(real_path.starts_with("/home/") || real_path.starts_with("/tmp/")) {
        return (false, -1, "Path must be under /home/ or /tmp/".to_string());
    }
    let run = || -> crate::error::Result<i32> {
        format::create_image_file(real_path, size_mb)?;
        let keyslot = luks::format_luks2(real_path, passphrase)?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(real_path, Some(uid), Some(gid))?;
        }
        Ok(keyslot)
    };
    match run() {
        Ok(keyslot) => (true, keyslot, String::new()),
        Err(e) => {
            eprintln!("CreateEncryptedImage failed: {e}");
            (false, -1, "Operation failed".to_string())
        }
    }
}

/// Create-image variant for fd-passing: the client created and owns the
/// file, so there is no path allowlist, no parent-directory ownership
/// check, and no chown — the descriptor is the capability. The handler
/// sizes the file via ftruncate before calling this.
pub fn op_create_image_fd(path: &str, passphrase: &str) -> (bool, i32, String) {
    match luks::format_luks2(path, passphrase) {
        Ok(keyslot) => (true, keyslot, String::new()),
        Err(e) => {
            eprintln!("CreateEncryptedImage(fd) failed: {e}");
            (false, -1, "Operation failed".to_string())
        }
    }
}

pub fn op_format_partition(device: &str, passphrase: &str) -> Triple {
    match format::format_removable_partition(device, passphrase) {
        Ok(partition) => (true, partition, String::new()),
        Err(e) => {
            eprintln!("FormatPartition failed: {e}");
            (false, String::new(), "Operation failed".to_string())
        }
    }
}

pub fn op_check_fido2_enrolled(device: &str, fido2_dev_paths: &[String]) -> Vec<String> {
    let existing_creds: Vec<Vec<u8>> = luks::fido2_token_refs(device)
        .map(|refs| refs.into_iter().map(|r| r.cred_id).collect())
        .unwrap_or_default();
    eprintln!(
        "CheckFido2Enrolled: device={device}, fido2_paths={fido2_dev_paths:?}, existing_creds={}",
        existing_creds.len()
    );
    let enrolled = if existing_creds.is_empty() || fido2_dev_paths.is_empty() {
        Vec::new()
    } else {
        fido2::enrolled_paths(fido2_dev_paths, &existing_creds)
    };
    eprintln!("CheckFido2Enrolled result: {enrolled:?}");
    enrolled
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// JSON for GetKeyslots: {"0": "luks2", ...} (string keys like Python's
/// json.dumps of an int-keyed dict).
pub fn keyslots_json(device: &str) -> String {
    let map: serde_json::Map<String, serde_json::Value> = luks::list_keyslots(device)
        .into_iter()
        .map(|(k, v)| (k.to_string(), serde_json::Value::String(v)))
        .collect();
    serde_json::Value::Object(map).to_string()
}

/// JSON for GetTokensByType: [[token_id, [keyslots]], ...].
pub fn tokens_json(device: &str, token_type: &str) -> String {
    serde_json::to_string(&luks::tokens_by_type(device, token_type)).unwrap_or_else(|_| "[]".into())
}

// ---------------------------------------------------------------------------
// D-Bus interface
// ---------------------------------------------------------------------------

#[zbus::interface(name = "net.contemno.LuksEnroll1")]
impl LuksEnrollService {
    #[zbus(name = "DetectDevices")]
    async fn detect_devices(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
    ) -> Result<Vec<String>, SvcError> {
        self.gate(conn, &hdr, AuthKind::Read, None, false).await?;
        Ok(devices::detect_luks_devices())
    }

    #[zbus(name = "GetKeyslots")]
    async fn get_keyslots(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
    ) -> Result<String, SvcError> {
        self.gate(conn, &hdr, AuthKind::Read, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[&device])?;
        Ok(keyslots_json(&device))
    }

    #[zbus(name = "GetTokensByType")]
    async fn get_tokens_by_type(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
        token_type: String,
    ) -> Result<String, SvcError> {
        self.gate(conn, &hdr, AuthKind::Read, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[&device, &token_type])?;
        Ok(tokens_json(&device, &token_type))
    }

    #[zbus(name = "FindPasswordKeyslots")]
    async fn find_password_keyslots(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
    ) -> Result<Vec<i32>, SvcError> {
        self.gate(conn, &hdr, AuthKind::Read, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[&device])?;
        Ok(luks::password_keyslots(&device))
    }

    #[zbus(name = "VerifyPassphrase")]
    async fn verify_passphrase(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
        passphrase: String,
    ) -> Result<(bool, i32), SvcError> {
        self.gate(conn, &hdr, AuthKind::Manage, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[&device, &passphrase])?;
        blocking(
            move || match luks::verify_passphrase(&device, &passphrase) {
                Ok(slot) => (true, slot),
                Err(_) => (false, -1),
            },
        )
        .await
    }

    #[zbus(name = "UnlockWithToken")]
    async fn unlock_with_token(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
        token_type: String,
        pin: String,
    ) -> Result<(bool, i32), SvcError> {
        self.gate(conn, &hdr, AuthKind::Manage, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[&device, &token_type, &pin])?;
        // Parity: an unsupported token type raised out of the Python
        // handler and surfaced as a generic D-Bus failure.
        if token_type != "systemd-fido2" && token_type != "systemd-tpm2" {
            eprintln!("Method UnlockWithToken failed: Unsupported token type");
            return Err(SvcError::Failed("Operation failed".into()));
        }
        blocking(
            move || match luks::verify_token(&device, &token_type, &pin) {
                Ok(slot) => (true, slot),
                Err(e) => {
                    eprintln!("UnlockWithToken: {e}");
                    (false, -1)
                }
            },
        )
        .await
    }

    #[zbus(name = "EnrollFido2")]
    #[allow(clippy::too_many_arguments)]
    async fn enroll_fido2(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
        passphrase: String,
        pin: String,
        fido2_device: String,
        unlock_method: String,
        unlock_pin: String,
    ) -> Result<Triple, SvcError> {
        self.gate(conn, &hdr, AuthKind::Manage, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[
            &device,
            &passphrase,
            &pin,
            &fido2_device,
            &unlock_method,
            &unlock_pin,
        ])?;
        blocking(move || {
            op_enroll_fido2(
                &device,
                &passphrase,
                &pin,
                &fido2_device,
                &unlock_method,
                &unlock_pin,
            )
        })
        .await
    }

    #[zbus(name = "EnrollTpm2")]
    #[allow(clippy::too_many_arguments)]
    async fn enroll_tpm2(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
        passphrase: String,
        pin: String,
        pcrs: String,
        unlock_method: String,
        unlock_pin: String,
    ) -> Result<Triple, SvcError> {
        self.gate(conn, &hdr, AuthKind::Manage, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[
            &device,
            &passphrase,
            &pin,
            &pcrs,
            &unlock_method,
            &unlock_pin,
        ])?;
        blocking(move || {
            op_enroll_tpm2(
                &device,
                &passphrase,
                &pin,
                &pcrs,
                &unlock_method,
                &unlock_pin,
            )
        })
        .await
    }

    #[zbus(name = "EnrollRecoveryKey")]
    async fn enroll_recovery_key(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
        passphrase: String,
        unlock_method: String,
        unlock_pin: String,
    ) -> Result<Triple, SvcError> {
        self.gate(conn, &hdr, AuthKind::Manage, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[&device, &passphrase, &unlock_method, &unlock_pin])?;
        blocking(move || op_enroll_recovery_key(&device, &passphrase, &unlock_method, &unlock_pin))
            .await
    }

    #[zbus(name = "WipeSlot")]
    #[allow(clippy::too_many_arguments)]
    async fn wipe_slot(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
        passphrase: String,
        unlock_method: String,
        pin: String,
        slot: i32,
    ) -> Result<Triple, SvcError> {
        self.gate(conn, &hdr, AuthKind::Manage, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[&device, &passphrase, &unlock_method, &pin])?;
        blocking(move || op_wipe_slot(&device, &passphrase, &unlock_method, &pin, slot)).await
    }

    #[zbus(name = "CreateEncryptedImage")]
    async fn create_encrypted_image(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        path: String,
        size_mb: i32,
        passphrase: String,
    ) -> Result<(bool, i32, String), SvcError> {
        self.gate(conn, &hdr, AuthKind::Manage, Some(&path), true)
            .await?;
        let real_path = Self::realpath(&path);
        Self::check_lens(&[&real_path, &passphrase])?;
        // Caller uid/gid so the image ends up owned by the requester.
        let owner = match Self::caller_uid(conn, &hdr).await {
            Some(uid) => nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
                .ok()
                .flatten()
                .map(|u| (uid, u.gid.as_raw())),
            None => None,
        };
        blocking(move || {
            if owner.is_none() {
                // Parity: a failed uid/gid lookup fails the operation.
                eprintln!("CreateEncryptedImage failed: cannot resolve caller uid/gid");
                return (false, -1, "Operation failed".to_string());
            }
            op_create_encrypted_image(&real_path, size_mb, &passphrase, owner)
        })
        .await
    }

    #[zbus(name = "DetectRemovableDevices")]
    async fn detect_removable_devices(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
    ) -> Result<String, SvcError> {
        self.gate(conn, &hdr, AuthKind::Read, None, false).await?;
        Ok(devices::detect_removable_devices().to_string())
    }

    #[zbus(name = "GetDeviceInfo")]
    async fn get_device_info(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
    ) -> Result<String, SvcError> {
        self.gate(conn, &hdr, AuthKind::Read, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[&device])?;
        Ok(devices::get_device_info(&device).to_string())
    }

    #[zbus(name = "FormatPartition")]
    async fn format_partition(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
        passphrase: String,
    ) -> Result<Triple, SvcError> {
        self.gate(conn, &hdr, AuthKind::Manage, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[&device, &passphrase])?;
        blocking(move || op_format_partition(&device, &passphrase)).await
    }

    #[zbus(name = "EnrollPassphrase")]
    #[allow(clippy::too_many_arguments)]
    async fn enroll_passphrase(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
        existing_passphrase: String,
        new_passphrase: String,
        unlock_method: String,
        unlock_pin: String,
    ) -> Result<Triple, SvcError> {
        self.gate(conn, &hdr, AuthKind::Manage, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[
            &device,
            &existing_passphrase,
            &new_passphrase,
            &unlock_method,
            &unlock_pin,
        ])?;
        blocking(move || {
            op_enroll_passphrase(
                &device,
                &existing_passphrase,
                &new_passphrase,
                &unlock_method,
                &unlock_pin,
            )
        })
        .await
    }

    #[zbus(name = "GetSetting")]
    async fn get_setting(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        key: String,
    ) -> Result<String, SvcError> {
        self.gate(conn, &hdr, AuthKind::Read, None, false).await?;
        Self::check_lens(&[&key])?;
        Ok(settings::load_setting(&key))
    }

    #[zbus(name = "SetSetting")]
    async fn set_setting(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        key: String,
        value: String,
    ) -> Result<bool, SvcError> {
        self.gate(conn, &hdr, AuthKind::Manage, None, false).await?;
        Self::check_lens(&[&key, &value])?;
        Ok(settings::save_setting(&key, &value))
    }

    #[zbus(name = "CheckFido2Enrolled")]
    async fn check_fido2_enrolled(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
        device: String,
        fido2_dev_paths: Vec<String>,
    ) -> Result<Vec<String>, SvcError> {
        self.gate(conn, &hdr, AuthKind::Read, Some(&device), false)
            .await?;
        let device = Self::validate_device(&device)?;
        Self::check_lens(&[&device])?;
        blocking(move || op_check_fido2_enrolled(&device, &fido2_dev_paths)).await
    }

    #[zbus(name = "Authenticate")]
    async fn authenticate(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] hdr: Header<'_>,
    ) -> Result<bool, SvcError> {
        // No-op: the polkit auth already happened in the gate.
        self.gate(conn, &hdr, AuthKind::Manage, None, false).await?;
        Ok(true)
    }

    #[zbus(name = "GetSystemdVersion")]
    async fn get_systemd_version(&self) -> i32 {
        // All token operations are handled natively; return a high value
        // so existing GUI version checks always pass.
        999
    }

    // -----------------------------------------------------------------
    // File-descriptor variants
    //
    // For encrypted-container files the client opens the file itself
    // (it owns it) and passes the descriptor; the service operates on
    // /proc/self/fd/N. This lets the hardened, sandboxed service write a
    // user-owned container's LUKS header under ProtectHome=read-only
    // without relaxing the sandbox, and removes the path allowlist,
    // TOCTOU window, and polkit round-trip. Block devices keep using the
    // path-based methods above (the unprivileged client cannot open a
    // /dev descriptor; the service opens those by path, which the sandbox
    // permits).
    // -----------------------------------------------------------------

    #[zbus(name = "GetKeyslotsFd")]
    async fn get_keyslots_fd(&self, fd: OwnedFd) -> Result<String, SvcError> {
        Self::check_fd(&fd, false, false)?;
        self.touch_idle();
        blocking(move || keyslots_json(&fd_path(&fd))).await
    }

    #[zbus(name = "GetTokensByTypeFd")]
    async fn get_tokens_by_type_fd(
        &self,
        fd: OwnedFd,
        token_type: String,
    ) -> Result<String, SvcError> {
        Self::check_fd(&fd, false, false)?;
        Self::check_lens(&[&token_type])?;
        self.touch_idle();
        blocking(move || tokens_json(&fd_path(&fd), &token_type)).await
    }

    #[zbus(name = "FindPasswordKeyslotsFd")]
    async fn find_password_keyslots_fd(&self, fd: OwnedFd) -> Result<Vec<i32>, SvcError> {
        Self::check_fd(&fd, false, false)?;
        self.touch_idle();
        blocking(move || luks::password_keyslots(&fd_path(&fd))).await
    }

    #[zbus(name = "GetDeviceInfoFd")]
    async fn get_device_info_fd(&self, fd: OwnedFd) -> Result<String, SvcError> {
        Self::check_fd(&fd, false, false)?;
        self.touch_idle();
        blocking(move || devices::get_device_info(&fd_path(&fd)).to_string()).await
    }

    #[zbus(name = "CheckFido2EnrolledFd")]
    async fn check_fido2_enrolled_fd(
        &self,
        fd: OwnedFd,
        fido2_dev_paths: Vec<String>,
    ) -> Result<Vec<String>, SvcError> {
        Self::check_fd(&fd, false, false)?;
        self.touch_idle();
        blocking(move || op_check_fido2_enrolled(&fd_path(&fd), &fido2_dev_paths)).await
    }

    #[zbus(name = "VerifyPassphraseFd")]
    async fn verify_passphrase_fd(
        &self,
        fd: OwnedFd,
        passphrase: String,
    ) -> Result<(bool, i32), SvcError> {
        // Verify only reads the header, so a read-only descriptor suffices.
        Self::check_fd(&fd, false, false)?;
        Self::check_lens(&[&passphrase])?;
        self.touch_idle();
        blocking(
            move || match luks::verify_passphrase(&fd_path(&fd), &passphrase) {
                Ok(slot) => (true, slot),
                Err(_) => (false, -1),
            },
        )
        .await
    }

    #[zbus(name = "UnlockWithTokenFd")]
    async fn unlock_with_token_fd(
        &self,
        fd: OwnedFd,
        token_type: String,
        pin: String,
    ) -> Result<(bool, i32), SvcError> {
        Self::check_fd(&fd, false, false)?;
        Self::check_lens(&[&token_type, &pin])?;
        if token_type != "systemd-fido2" && token_type != "systemd-tpm2" {
            eprintln!("Method UnlockWithTokenFd failed: Unsupported token type");
            return Err(SvcError::Failed("Operation failed".into()));
        }
        self.touch_idle();
        blocking(
            move || match luks::verify_token(&fd_path(&fd), &token_type, &pin) {
                Ok(slot) => (true, slot),
                Err(e) => {
                    eprintln!("UnlockWithTokenFd: {e}");
                    (false, -1)
                }
            },
        )
        .await
    }

    #[zbus(name = "EnrollFido2Fd")]
    async fn enroll_fido2_fd(
        &self,
        fd: OwnedFd,
        passphrase: String,
        pin: String,
        fido2_device: String,
        unlock_method: String,
        unlock_pin: String,
    ) -> Result<Triple, SvcError> {
        Self::check_fd(&fd, true, false)?;
        Self::check_lens(&[
            &passphrase,
            &pin,
            &fido2_device,
            &unlock_method,
            &unlock_pin,
        ])?;
        self.touch_idle();
        blocking(move || {
            op_enroll_fido2(
                &fd_path(&fd),
                &passphrase,
                &pin,
                &fido2_device,
                &unlock_method,
                &unlock_pin,
            )
        })
        .await
    }

    #[zbus(name = "EnrollTpm2Fd")]
    async fn enroll_tpm2_fd(
        &self,
        fd: OwnedFd,
        passphrase: String,
        pin: String,
        pcrs: String,
        unlock_method: String,
        unlock_pin: String,
    ) -> Result<Triple, SvcError> {
        Self::check_fd(&fd, true, false)?;
        Self::check_lens(&[&passphrase, &pin, &pcrs, &unlock_method, &unlock_pin])?;
        self.touch_idle();
        blocking(move || {
            op_enroll_tpm2(
                &fd_path(&fd),
                &passphrase,
                &pin,
                &pcrs,
                &unlock_method,
                &unlock_pin,
            )
        })
        .await
    }

    #[zbus(name = "EnrollRecoveryKeyFd")]
    async fn enroll_recovery_key_fd(
        &self,
        fd: OwnedFd,
        passphrase: String,
        unlock_method: String,
        unlock_pin: String,
    ) -> Result<Triple, SvcError> {
        Self::check_fd(&fd, true, false)?;
        Self::check_lens(&[&passphrase, &unlock_method, &unlock_pin])?;
        self.touch_idle();
        blocking(move || {
            op_enroll_recovery_key(&fd_path(&fd), &passphrase, &unlock_method, &unlock_pin)
        })
        .await
    }

    #[zbus(name = "EnrollPassphraseFd")]
    async fn enroll_passphrase_fd(
        &self,
        fd: OwnedFd,
        existing_passphrase: String,
        new_passphrase: String,
        unlock_method: String,
        unlock_pin: String,
    ) -> Result<Triple, SvcError> {
        Self::check_fd(&fd, true, false)?;
        Self::check_lens(&[
            &existing_passphrase,
            &new_passphrase,
            &unlock_method,
            &unlock_pin,
        ])?;
        self.touch_idle();
        blocking(move || {
            op_enroll_passphrase(
                &fd_path(&fd),
                &existing_passphrase,
                &new_passphrase,
                &unlock_method,
                &unlock_pin,
            )
        })
        .await
    }

    #[zbus(name = "WipeSlotFd")]
    async fn wipe_slot_fd(
        &self,
        fd: OwnedFd,
        passphrase: String,
        unlock_method: String,
        pin: String,
        slot: i32,
    ) -> Result<Triple, SvcError> {
        Self::check_fd(&fd, true, false)?;
        Self::check_lens(&[&passphrase, &unlock_method, &pin])?;
        self.touch_idle();
        blocking(move || op_wipe_slot(&fd_path(&fd), &passphrase, &unlock_method, &pin, slot)).await
    }

    #[zbus(name = "CreateEncryptedImageFd")]
    async fn create_encrypted_image_fd(
        &self,
        fd: OwnedFd,
        size_mb: i32,
        passphrase: String,
    ) -> Result<(bool, i32, String), SvcError> {
        // Sizing only makes sense for a fresh regular file the client made.
        Self::check_fd(&fd, true, true)?;
        Self::check_lens(&[&passphrase])?;
        if !(1..=8192).contains(&size_mb) {
            return Ok((false, -1, "size_mb must be between 1 and 8192".to_string()));
        }
        self.touch_idle();
        blocking(move || {
            if let Err(e) = nix::unistd::ftruncate(&fd, size_mb as libc::off_t * 1024 * 1024) {
                eprintln!("CreateEncryptedImageFd ftruncate failed: {e}");
                return (false, -1, "Operation failed".to_string());
            }
            op_create_image_fd(&fd_path(&fd), &passphrase)
        })
        .await
    }
}
