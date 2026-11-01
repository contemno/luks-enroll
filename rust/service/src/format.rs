//! Destructive formatting paths: signature wiping, GPT partitioning,
//! LUKS formatting of removable media and image files.
//!
//! Port of the Python service's _wipefs / _sgdisk_zap_and_partition /
//! _format_removable_partition / format_luks_image. GPT creation uses the
//! pure-Rust `gpt` crate instead of libfdisk (documented divergence):
//! protective MBR + fresh GPT + one partition covering the disk with the
//! Linux LUKS type GUID.

use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use gpt::disk::LogicalBlockSize;
use gpt::mbr::ProtectiveMBR;
use gpt::{partition_types, GptConfig};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use udev::{EventType, MonitorBuilder};

use crate::error::{cstring, Error, Result};
use crate::luks::Timer;
use crate::{bail, devices, luks};

/// Linux LUKS partition type GUID (sgdisk shortcode 8309).
pub const LUKS_PARTITION_TYPE_GUID: &str = "CA7D7CCB-63ED-4C53-861C-1742536059CC";

/// Erase all filesystem/partition-table signatures (wipefs equivalent):
/// libblkid probe loop over SBMAGIC/SBMAGIC_OFFSET, zeroing each magic.
///
/// Uses libblkid-rs-sys directly: the high-level crate exposes neither
/// `blkid_probe_set_partitions_flags` nor raw (length-carrying) value
/// lookups, and SBMAGIC bytes are not guaranteed to be UTF-8/NUL-
/// terminated. Like the Python original, only SBMAGIC* values are read,
/// so partition-table magics reported by the partitions chain (PTMAGIC*)
/// are probed but not wiped.
pub fn wipefs(device: &str) -> Result<()> {
    let dev_c = cstring(device, "device path")?;
    let raw = unsafe { libblkid_rs_sys::blkid_new_probe_from_filename(dev_c.as_ptr()) };
    if raw.is_null() {
        bail!("blkid_new_probe_from_filename failed for {device}");
    }
    let probe = RawProbe(raw);

    // Python sets BLKID_SUBLKS_MAGIC (1<<9) and a partitions-flags value
    // of 1<<1, which it labels PARTS_MAGIC. We pass the header constants;
    // on current util-linux BLKID_PARTS_MAGIC is 1<<3 (1<<1 is
    // BLKID_PARTS_FORCE_GPT there). Either way the loop below only
    // consumes SBMAGIC values, so the wiped set is identical.
    unsafe {
        libblkid_rs_sys::blkid_probe_enable_superblocks(probe.0, 1);
        libblkid_rs_sys::blkid_probe_set_superblocks_flags(
            probe.0,
            libblkid_rs_sys::BLKID_SUBLKS_MAGIC as libc::c_int,
        );
        libblkid_rs_sys::blkid_probe_enable_partitions(probe.0, 1);
        libblkid_rs_sys::blkid_probe_set_partitions_flags(
            probe.0,
            libblkid_rs_sys::BLKID_PARTS_MAGIC as libc::c_int,
        );
    }

    loop {
        let rc = unsafe { libblkid_rs_sys::blkid_do_probe(probe.0) };
        if rc < 0 {
            bail!("blkid_do_probe error");
        }
        if rc != 0 {
            break; // rc == 1: no more signatures
        }

        // Skip this hit if either lookup fails or the magic is empty.
        let Some(offset) =
            probe_lookup_string(&probe, "SBMAGIC_OFFSET").and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        let Some(length) = probe_lookup_len(&probe, "SBMAGIC") else {
            continue;
        };
        if length == 0 {
            continue;
        }

        let mut fp = OpenOptions::new().read(true).write(true).open(device)?;
        fp.seek(SeekFrom::Start(offset))?;
        fp.write_all(&vec![0u8; length])?;
    }

    Ok(())
}

/// Wipe the partition table and create a single GPT LUKS partition
/// spanning the disk (sgdisk --zap-all && sgdisk -n 1:0:0 -t 1:8309).
///
/// Writes a protective MBR to LBA0 and builds a fresh GPT (which ignores
/// and overwrites any previous table), then adds one partition covering
/// the largest free span: type GUID CA7D7CCB-63ED-4C53-861C-1742536059CC,
/// empty name, no flags. Everything is flushed and fsync'd before return.
pub fn gpt_zap_and_partition(device: &str) -> Result<()> {
    // Logical block size from sysfs when the kernel knows the device;
    // 512 for image files and anything unreported. The gpt crate only
    // models 512/4096.
    let base = devices::basename(device);
    let lb_bytes = devices::read_sysfs(&format!("/sys/block/{base}/queue/logical_block_size"))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(512);
    let lb_size = LogicalBlockSize::try_from(lb_bytes).unwrap_or(LogicalBlockSize::Lb512);

    let mut file = OpenOptions::new().read(true).write(true).open(device)?;
    let disk_len = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;
    let total_lba = disk_len / lb_size.as_u64();

    // Protective MBR: one 0xEE partition from LBA1 covering the disk
    // (clamped to u32::MAX like sgdisk for >2 TiB disks).
    let pmbr =
        ProtectiveMBR::with_lb_size(u32::try_from(total_lba.saturating_sub(1)).unwrap_or(u32::MAX));
    pmbr.overwrite_lba0(&mut file)
        .map_err(|e| Error(format!("writing protective MBR failed: {e}")))?;

    // Fresh GPT; existing headers/tables are not read and get overwritten.
    let mut disk = GptConfig::new()
        .writable(true)
        .logical_block_size(lb_size)
        .create_from_device(file, None)
        .map_err(|e| Error(format!("creating GPT failed: {e}")))?;

    let &(first_lba, length_lba) = disk
        .find_free_sectors()
        .iter()
        .max_by_key(|(_, length)| *length)
        .ok_or_else(|| Error(format!("no usable space on {device}")))?;
    disk.add_partition_at("", 1, first_lba, length_lba, partition_types::LINUX_LUKS, 0)
        .map_err(|e| Error(format!("adding LUKS partition failed: {e}")))?;

    let file = disk
        .write()
        .map_err(|e| Error(format!("writing GPT failed: {e}")))?;
    file.sync_all()?;
    Ok(())
}

/// Ask the kernel to re-read the partition table (BLKRRPART ioctl).
/// Best-effort; errors ignored.
pub fn partprobe(device: &str) {
    if let Ok(file) = File::open(device) {
        // BLKRRPART takes no argument; failures (regular file, busy
        // device, ...) are deliberately ignored.
        let _ = unsafe { ioctls::blkrrpart(file.as_raw_fd()) };
    }
}

/// Worst-case fallback poll budget, matching the pre-existing behavior:
/// up to 20 x 500ms = 10s.
const FALLBACK_POLL_ITERATIONS: u32 = 20;
const FALLBACK_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Bound on the event-driven udev wait, matching the same 10s worst case.
const UDEV_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Wait for a partition device node to appear after (re)partitioning.
/// Prefers an in-process udev netlink monitor (reacting to the kernel's
/// "add" uevent for the new partition the moment it fires) over
/// sleep-polling; falls back to the fixed-interval poll if a udev
/// monitor can't be set up on this system.
fn wait_for_partition_node(device: &str, partition: &str) -> bool {
    wait_for_node(
        partition,
        || udev_wait_for_partition(device, partition, UDEV_WAIT_TIMEOUT),
        || partprobe(device),
        FALLBACK_POLL_ITERATIONS,
        FALLBACK_POLL_INTERVAL,
    )
}

/// Subscribe directly to the kernel's "block" uevents (not udevd's
/// re-broadcast socket — devtmpfs creates the device node the instant
/// the kernel processes the partition table, independent of and
/// earlier than udevd's own rule processing/blkid probing, so waiting
/// on udevd here would reintroduce the same latency `udevadm settle`
/// had) *before* triggering a `partprobe`, so the new partition's "add"
/// event can't fire before we're listening, then wait up to `timeout`
/// for it. Returns true once the wait completed one way or another
/// (event seen, or timeout) — the caller checks the node's existence
/// afterward, which is authoritative either way. Returns false only if
/// the monitor itself couldn't be created (e.g. insufficient
/// privilege), signaling the caller to fall back to polling.
fn udev_wait_for_partition(device: &str, partition: &str, timeout: Duration) -> bool {
    let Ok(socket) = MonitorBuilder::new_kernel()
        .and_then(|b| b.match_subsystem("block"))
        .and_then(|b| b.listen())
    else {
        eprintln!(
            "udev kernel-uevent monitor unavailable (falling back to polling): \
             is AF_NETLINK in the service unit's RestrictAddressFamilies?"
        );
        return false;
    };

    let sysname = devices::basename(partition);
    partprobe(device);

    let deadline = Instant::now() + timeout;
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return true;
        };
        let Ok(timeout_ms) = PollTimeout::try_from(remaining) else {
            return true;
        };
        let mut fds = [PollFd::new(socket.as_fd(), PollFlags::POLLIN)];
        if poll(&mut fds, timeout_ms).is_err() {
            return true;
        }
        for event in socket.iter() {
            if event.event_type() == EventType::Add && event.sysname().to_str() == Some(sysname) {
                return true;
            }
        }
    }
}

/// Testable core of `wait_for_partition_node`: `settle` attempts the
/// event-driven wait (true if it ran, false if unavailable); on `false`,
/// `reprobe` is called between up to `fallback_iterations` existence
/// checks spaced `fallback_interval` apart.
fn wait_for_node(
    partition: &str,
    settle: impl FnOnce() -> bool,
    mut reprobe: impl FnMut(),
    fallback_iterations: u32,
    fallback_interval: Duration,
) -> bool {
    if settle() {
        return Path::new(partition).exists();
    }
    for _ in 0..fallback_iterations {
        if Path::new(partition).exists() {
            return true;
        }
        reprobe();
        thread::sleep(fallback_interval);
    }
    Path::new(partition).exists()
}

/// Why `format_removable_partition` refused or failed. The D-Bus layer
/// surfaces the one case the user can act on (`InUse`: unmount, then retry)
/// and keeps everything else the logged, generic "Operation failed" of the
/// parity contract. `From<String>` lets the stage-wrapping
/// `map_err(|e| format!(..))?` lines produce `Failed` unchanged.
#[derive(Debug, PartialEq, Eq)]
pub enum FormatError {
    /// Something holds the device (or a partition of it) open exclusively:
    /// a mounted filesystem, an active dm-crypt mapping, a swap area, ...
    /// `mounts` lists the `(source, mount_point)` pairs found in
    /// /proc/mounts; empty when the holder is not a mount.
    InUse {
        mounts: Vec<(String, String)>,
    },
    Failed(String),
}

impl From<String> for FormatError {
    fn from(msg: String) -> Self {
        FormatError::Failed(msg)
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::InUse { mounts } if mounts.is_empty() => f.write_str(
                "Device is in use (opened exclusively by another program); \
                 release it before encrypting",
            ),
            FormatError::InUse { mounts } => {
                let listed: Vec<String> = mounts
                    .iter()
                    .map(|(src, mp)| format!("{src} is mounted at {mp}"))
                    .collect();
                write!(
                    f,
                    "Device is in use: {}. Unmount it before encrypting",
                    listed.join(", ")
                )
            }
            FormatError::Failed(msg) => f.write_str(msg),
        }
    }
}

/// Refuse to touch a device that something else holds open exclusively: the
/// kernel's own definition of "in use", which covers a mounted filesystem on
/// the device *or on any of its partitions* (claiming a partition claims the
/// whole disk too), an active dm-crypt/LVM/RAID member, and a swap area. The
/// probe is the same `O_EXCL` open that wipefs, mkfs and libcryptsetup use.
///
/// It runs before the first destructive write. Without it, the signature
/// wipe went through (the kernel allows raw writes to a mounted device) and
/// only the later luksFormat's exclusive open failed, leaving the user with
/// a wiped-but-unencrypted device and a generic error. Regular files (image
/// containers) ignore `O_EXCL` without `O_CREAT`, so they pass.
fn check_not_in_use(device: &str) -> std::result::Result<(), FormatError> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_EXCL)
        .open(device)
    {
        Ok(_claim) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
            let mounts = std::fs::read_to_string("/proc/mounts")
                .map(|table| devices::device_mounts(&table, device))
                .unwrap_or_default();
            Err(FormatError::InUse { mounts })
        }
        Err(e) => Err(FormatError::Failed(format!("cannot open {device}: {e}"))),
    }
}

/// Format a removable device with LUKS2. Whole disks get GPT + one LUKS
/// partition first; existing partitions are wiped and formatted directly.
/// Refuses non-removable devices and devices in use (see `check_not_in_use`).
/// Returns the LUKS partition path, or a `FormatError` (logged; only the
/// in-use refusal is relayed to clients).
///
/// An empty passphrase means "no passphrase keyslot": the partition is
/// formatted with a cached volume key and the first enrollment wraps it, so
/// the user is never asked for a throwaway passphrase (mirrors the
/// `CreateEncryptedImage` keyless path from issue #58, extended to removable
/// media by #82). A non-empty passphrase keeps the classic behavior of
/// seeding a password keyslot.
pub fn format_removable_partition(
    device: &str,
    passphrase: &str,
) -> std::result::Result<String, FormatError> {
    // Per-stage timing (LUKS_ENROLL_TIMING gated, like luks::Timer's other
    // users): the whole-disk delay (#84) survived three fixes to the
    // partition-node wait before per-stage timing pinned it on the
    // crypt_format keyslots-area wipe, so keep the stages measurable.

    // Safety: refuse non-removable.
    if !devices::is_removable(device) {
        return Err(FormatError::Failed(
            "Refusing to format non-removable device".to_string(),
        ));
    }

    // Safety: refuse anything mounted or otherwise held, before the wipe.
    check_not_in_use(device)?;

    if devices::is_partition(device) {
        // Existing partition: wipefs + luksFormat it directly.
        {
            let _t = Timer::new("format_removable_partition: wipefs");
            wipefs(device).map_err(|e| format!("wipefs failed: {e}"))?;
        }
        let _t = Timer::new("format_removable_partition: luksFormat");
        format_luks2(device, passphrase).map_err(|e| format!("luksFormat failed: {e}"))?;
        return Ok(device.to_string());
    }

    // Whole disk: wipe signatures, then GPT + single LUKS partition.
    {
        let _t = Timer::new("format_removable_partition: wipefs");
        wipefs(device).map_err(|e| format!("wipefs failed: {e}"))?;
    }
    {
        let _t = Timer::new("format_removable_partition: GPT partitioning");
        gpt_zap_and_partition(device).map_err(|e| format!("GPT partitioning failed: {e}"))?;
    }

    // Partition node naming: nvme whole disks get a "p" separator.
    let base = devices::basename(device);
    let partition = if is_nvme_whole_disk(base) {
        format!("{device}p1")
    } else {
        format!("{device}1")
    };

    // Wait for the partition device node to appear.
    {
        let _t = Timer::new("format_removable_partition: partition-node wait");
        if !wait_for_partition_node(device, &partition) {
            return Err(format!("Partition {partition} did not appear after formatting").into());
        }
    }

    let _t = Timer::new("format_removable_partition: luksFormat");
    format_luks2(&partition, passphrase).map_err(|e| format!("luksFormat failed: {e}"))?;
    Ok(partition)
}

/// Format `path` as LUKS2: keyless (cached volume key, no keyslot) when
/// `passphrase` is empty, otherwise the classic passphrase-keyslot format.
/// Removable media always get the compact keyslots area: `crypt_format`
/// zero-wipes the whole area, and on slow USB flash the default 16 MiB
/// wipe was the dominant cost of whole-disk encryption (#84).
fn format_luks2(path: &str, passphrase: &str) -> Result<()> {
    if passphrase.is_empty() {
        luks::format_luks2_keyless(path, luks::KeyslotsArea::Compact)
    } else {
        luks::format_luks2(path, passphrase, luks::KeyslotsArea::Compact).map(|_| ())
    }
}

/// Create a filesystem on the open dm-crypt mapping `/dev/mapper/<name>` of
/// `device`, so a freshly encrypted removable volume is usable without a
/// trip through another tool (`MakeFilesystem`). Policy, all checked before
/// anything is written:
///   * `fstype` is `ext4`, the only type offered so far;
///   * `device` is removable, the only kind `FormatPartition` creates;
///   * the mapping is a LUKS mapping whose backing device is `device`, as
///     read back from the device-mapper table, so the authorization the
///     handler obtained for `device` is the one exercised: a mapping of some
///     other volume is refused;
///   * `device` has zero keyslots. That is this codebase's definition of a
///     freshly (keyless-)formatted volume (#58/#82/#88); an enrolled volume
///     can carry data, and this is for new volumes only, never a reformat;
///   * the mapping is not mounted.
///
/// `owner` is the caller's (uid, gid): mke2fs creates the root directory
/// owned by them (`-E root_owner`), so the mounted volume is writable by the
/// user who asked for it without a chown.
pub fn make_filesystem(
    device: &str,
    name: &str,
    fstype: &str,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    if fstype != "ext4" {
        bail!("Unsupported filesystem type {fstype:?}; only ext4 is supported");
    }
    if !devices::is_removable(device) {
        bail!("Refusing to create a filesystem on a non-removable device");
    }
    let backing = luks::mapping_backing_device(name)?;
    if devices::canonicalize_lossy(Path::new(&backing))
        != devices::canonicalize_lossy(Path::new(device))
    {
        bail!("Mapping /dev/mapper/{name} is backed by {backing}, not {device}");
    }
    if !luks::list_keyslots(device).is_empty() {
        bail!(
            "Refusing to create a filesystem on a volume with enrolled keyslots; \
             only a freshly encrypted volume qualifies"
        );
    }
    if luks::mapping_is_mounted(name) {
        bail!("The volume's filesystem is mounted");
    }
    mkfs_ext4(&format!("/dev/mapper/{name}"), owner)
}

/// Run mke2fs on `target`. Kept apart from the policy in `make_filesystem`
/// so tests can exercise the real mkfs against an image file (no root) and a
/// loop-backed mapping (root), neither of which is "removable".
///
/// `-F` once: a brand-new volume's plaintext is random, and a chance match
/// against one of blkid's weak two-byte signatures would otherwise stall
/// mke2fs on a "Proceed anyway?" prompt nobody can answer (stdin is
/// /dev/null, so it would abort). A single `-F` skips only that
/// plausibility prompt; mke2fs still refuses a mounted or busy target.
pub fn mkfs_ext4(target: &str, owner: Option<(u32, u32)>) -> Result<()> {
    let _t = Timer::new("mkfs_ext4");
    let mut cmd = Command::new(mkfs_ext4_binary()?);
    cmd.arg("-q").arg("-F");
    if let Some((uid, gid)) = owner {
        cmd.arg("-E").arg(format!("root_owner={uid}:{gid}"));
    }
    cmd.arg(target).stdin(Stdio::null());
    let out = cmd
        .output()
        .map_err(|e| Error(format!("could not run mkfs.ext4: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stderr = stderr.trim();
        bail!(
            "mkfs.ext4 failed ({}): {}",
            out.status,
            if stderr.is_empty() {
                "no error output"
            } else {
                stderr
            }
        );
    }
    Ok(())
}

/// e2fsprogs' mkfs.ext4, by `$PATH` (systemd's default service PATH includes
/// the sbin directories) with the two conventional absolute locations as
/// fallbacks for a minimal environment.
fn mkfs_ext4_binary() -> Result<PathBuf> {
    const FALLBACKS: [&str; 2] = ["/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"];
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|dir| dir.join("mkfs.ext4"))
        .chain(FALLBACKS.iter().map(PathBuf::from))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| Error("mkfs.ext4 not found (is e2fsprogs installed?)".into()))
}

/// Create a sparse image file of `size_mb` MiB (1..=8192) at `path`,
/// ready for LUKS formatting.
pub fn create_image_file(path: &str, size_mb: i32) -> Result<()> {
    if !(1..=8192).contains(&size_mb) {
        bail!("size_mb must be between 1 and 8192, got {size_mb}");
    }
    let mut f = File::create(path)?;
    f.seek(SeekFrom::Start(size_mb as u64 * 1024 * 1024 - 1))?;
    f.write_all(&[0u8])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

mod ioctls {
    // BLKRRPART = _IO(0x12, 95) = 0x125F: re-read partition table.
    nix::ioctl_none!(blkrrpart, 0x12, 95);
}

/// Owned raw libblkid probe, freed on every exit path.
struct RawProbe(libblkid_rs_sys::blkid_probe);

impl Drop for RawProbe {
    fn drop(&mut self) {
        unsafe { libblkid_rs_sys::blkid_free_probe(self.0) }
    }
}

/// blkid_probe_lookup_value as a string (for NUL-terminated decimal
/// values like SBMAGIC_OFFSET). None when the lookup fails.
fn probe_lookup_string(probe: &RawProbe, name: &str) -> Option<String> {
    let name_c = CString::new(name).ok()?;
    let mut data: *const libc::c_char = std::ptr::null();
    let rc = unsafe {
        libblkid_rs_sys::blkid_probe_lookup_value(
            probe.0,
            name_c.as_ptr(),
            &mut data,
            std::ptr::null_mut(),
        )
    };
    if rc != 0 || data.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(data) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Byte length of a probe value (the value itself may be arbitrary,
/// non-UTF-8 magic bytes). None when the lookup fails.
fn probe_lookup_len(probe: &RawProbe, name: &str) -> Option<usize> {
    let name_c = CString::new(name).ok()?;
    let mut data: *const libc::c_char = std::ptr::null();
    let mut len: usize = 0;
    let rc = unsafe {
        libblkid_rs_sys::blkid_probe_lookup_value(probe.0, name_c.as_ptr(), &mut data, &mut len)
    };
    if rc != 0 {
        return None;
    }
    Some(len)
}

/// Hand-rolled `^nvme[0-9]+n[0-9]+$` (whole-disk nvme name).
fn is_nvme_whole_disk(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("nvme") else {
        return false;
    };
    let b = rest.as_bytes();
    let mut i = 0;
    let ctrl_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == ctrl_start || i >= b.len() || b[i] != b'n' {
        return false;
    }
    i += 1;
    let ns_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    i > ns_start && i == b.len()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;

    #[test]
    fn luks_type_guid_matches_gpt_constant() {
        assert!(partition_types::LINUX_LUKS
            .guid
            .to_string()
            .eq_ignore_ascii_case(LUKS_PARTITION_TYPE_GUID));
    }

    #[test]
    fn nvme_whole_disk_names() {
        assert!(is_nvme_whole_disk("nvme0n1"));
        assert!(is_nvme_whole_disk("nvme12n34"));
        assert!(!is_nvme_whole_disk("nvme0n1p1"));
        assert!(!is_nvme_whole_disk("nvme0"));
        assert!(!is_nvme_whole_disk("sda"));
    }

    #[test]
    fn create_image_file_sets_apparent_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img.bin");
        create_image_file(path.to_str().unwrap(), 4).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 4 * 1024 * 1024);
    }

    #[test]
    fn create_image_file_rejects_bad_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img.bin");
        let err = create_image_file(path.to_str().unwrap(), 0).unwrap_err();
        assert_eq!(err.to_string(), "size_mb must be between 1 and 8192, got 0");
        let err = create_image_file(path.to_str().unwrap(), 9000).unwrap_err();
        assert_eq!(
            err.to_string(),
            "size_mb must be between 1 and 8192, got 9000"
        );
        // Rejected before any file I/O.
        assert!(!path.exists());
    }

    #[test]
    fn partition_wait_returns_once_node_appears_via_settle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("part1");
        File::create(&path).unwrap();
        // settle "ran" (true) and the node already exists: no polling.
        assert!(wait_for_node(
            path.to_str().unwrap(),
            || true,
            || panic!("reprobe should not be called when settle succeeds"),
            0,
            Duration::from_millis(0),
        ));
    }

    #[test]
    fn partition_wait_errors_on_timeout_via_settle() {
        // settle "ran" (true) but the node never shows up: no fallback
        // poll is attempted, so this returns immediately.
        assert!(!wait_for_node(
            "/nonexistent/luks-enroll-partition",
            || true,
            || panic!("reprobe should not be called when settle succeeds"),
            0,
            Duration::from_millis(0),
        ));
    }

    #[test]
    fn partition_wait_falls_back_to_polling_when_settle_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("part1");
        // Node appears only after the first reprobe.
        let mut reprobed = false;
        assert!(wait_for_node(
            path.to_str().unwrap(),
            || false,
            || {
                reprobed = true;
                File::create(&path).unwrap();
            },
            FALLBACK_POLL_ITERATIONS,
            Duration::from_millis(0),
        ));
        assert!(reprobed);
    }

    #[test]
    fn partition_wait_fallback_poll_errors_on_timeout() {
        assert!(!wait_for_node(
            "/nonexistent/luks-enroll-partition",
            || false,
            || {},
            2,
            Duration::from_millis(0),
        ));
    }

    #[test]
    fn format_removable_partition_refuses_non_removable() {
        let err = format_removable_partition("/nonexistent/luks-enroll-dev", "pw").unwrap_err();
        assert_eq!(
            err,
            FormatError::Failed("Refusing to format non-removable device".into())
        );
    }

    #[test]
    fn in_use_check_passes_a_regular_file_and_reports_a_missing_path() {
        // O_EXCL without O_CREAT is a no-op on regular files, so image
        // containers (and every existing image-based test) pass the guard.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img.bin");
        File::create(&path).unwrap().set_len(1024 * 1024).unwrap();
        assert_eq!(check_not_in_use(path.to_str().unwrap()), Ok(()));

        let err = check_not_in_use("/nonexistent/luks-enroll-dev").unwrap_err();
        assert!(matches!(err, FormatError::Failed(ref m) if m.starts_with("cannot open")));
    }

    #[test]
    fn in_use_refusal_names_the_mounts_for_the_user() {
        let with_mounts = FormatError::InUse {
            mounts: vec![
                ("/dev/sdb1".into(), "/media/josh/USB STICK".into()),
                ("/dev/sdb2".into(), "/mnt/data".into()),
            ],
        };
        assert_eq!(
            with_mounts.to_string(),
            "Device is in use: /dev/sdb1 is mounted at /media/josh/USB STICK, \
             /dev/sdb2 is mounted at /mnt/data. Unmount it before encrypting"
        );
        let held = FormatError::InUse { mounts: vec![] };
        assert!(held
            .to_string()
            .starts_with("Device is in use (opened exclusively"));
        // Stage failures convert via From<String> and display verbatim.
        let failed: FormatError = "wipefs failed: boom".to_string().into();
        assert_eq!(failed.to_string(), "wipefs failed: boom");
    }

    #[test]
    fn make_filesystem_checks_type_then_removability_before_touching_anything() {
        let err =
            make_filesystem("/nonexistent/luks-enroll-dev", "luks-x", "btrfs", None).unwrap_err();
        assert_eq!(
            err.0,
            "Unsupported filesystem type \"btrfs\"; only ext4 is supported"
        );
        let err =
            make_filesystem("/nonexistent/luks-enroll-dev", "luks-x", "ext4", None).unwrap_err();
        assert_eq!(
            err.0,
            "Refusing to create a filesystem on a non-removable device"
        );
    }

    #[test]
    fn mkfs_ext4_formats_an_image_and_sets_the_root_owner() {
        // The real mke2fs against a regular file (no root needed): pins the
        // command line, -F for the non-block-device plausibility prompt, and
        // root_owner. The root-only roundtrip in tests/luks_image.rs covers
        // the same call on a live dm-crypt mapping, mounted.
        if mkfs_ext4_binary().is_err() {
            eprintln!("mkfs.ext4 not installed; skipping mkfs coverage");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fs.img").to_string_lossy().into_owned();
        File::create(&path)
            .unwrap()
            .set_len(32 * 1024 * 1024)
            .unwrap();

        mkfs_ext4(&path, Some((1234, 5678))).unwrap();

        assert_eq!(devices::blkid_tag(&path, "TYPE").as_deref(), Some("ext4"));
        // debugfs (also e2fsprogs) reads the root inode's owner back.
        let out = Command::new("debugfs")
            .args(["-R", "stat /", &path])
            .stderr(Stdio::null())
            .output();
        let Ok(out) = out else {
            eprintln!("debugfs not installed; skipping root_owner check");
            return;
        };
        let stat = String::from_utf8_lossy(&out.stdout);
        let after = |key: &str| -> Option<String> {
            let tokens: Vec<&str> = stat.split_whitespace().collect();
            tokens
                .iter()
                .position(|t| *t == key)
                .and_then(|i| tokens.get(i + 1))
                .map(|t| t.to_string())
        };
        assert_eq!(after("User:").as_deref(), Some("1234"), "{stat}");
        assert_eq!(after("Group:").as_deref(), Some("5678"), "{stat}");
    }

    // `format_removable_partition` itself can't be exercised end-to-end here
    // (it gates on a real sysfs "removable" device), so these pin the
    // passphrase-vs-keyless branch in its `format_luks2` dispatch helper
    // directly -- the same logic `format_removable_partition` calls at both
    // of its call sites (issue #82).

    #[test]
    fn format_luks2_dispatch_seeds_a_keyslot_for_a_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.img").to_string_lossy().into_owned();
        File::create(&path)
            .unwrap()
            .set_len(32 * 1024 * 1024)
            .unwrap();

        format_luks2(&path, "correcthorse").unwrap();

        assert_eq!(luks::password_keyslots(&path), vec![0]);
        assert_eq!(luks::verify_passphrase(&path, "correcthorse"), Ok(0));
    }

    #[test]
    fn format_luks2_dispatch_is_keyless_and_caches_vk_for_an_empty_passphrase() {
        // Mirrors the CreateEncryptedImage keyless path (issue #58): an empty
        // passphrase must create no keyslot and instead cache the volume key
        // so the first enrollment can wrap it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("keyless.img")
            .to_string_lossy()
            .into_owned();
        File::create(&path)
            .unwrap()
            .set_len(32 * 1024 * 1024)
            .unwrap();
        luks::clear_volume_key_cache(&path);

        format_luks2(&path, "").unwrap();

        assert!(
            luks::list_keyslots(&path).is_empty(),
            "no keyslots persisted"
        );
        // The only way to get a volume key back with no keyslot is the cache.
        assert!(luks::get_volume_key(&path, "passphrase", "", "").is_ok());
    }

    #[test]
    fn removable_format_uses_compact_keyslots_area() {
        // The removable dispatch must format with the shrunken keyslots
        // area: crypt_format wipes the whole area and the default 16 MiB
        // wipe was the dominant whole-disk encryption cost on USB flash
        // (#84). Pin the on-disk size so a refactor can't silently revert
        // to the slow default.
        use libcryptsetup_rs::consts::vals::EncryptionFormat;
        use libcryptsetup_rs::CryptInit;

        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("compact.img")
            .to_string_lossy()
            .into_owned();
        File::create(&path)
            .unwrap()
            .set_len(32 * 1024 * 1024)
            .unwrap();
        luks::clear_volume_key_cache(&path);

        format_luks2(&path, "").unwrap();

        let mut dev = CryptInit::init(Path::new(&path)).unwrap();
        dev.context_handle()
            .load::<()>(Some(EncryptionFormat::Luks2), None)
            .unwrap();
        let (_, keyslots_size) = dev.settings_handle().get_metadata_size().unwrap();
        assert_eq!(*keyslots_size, luks::COMPACT_KEYSLOTS_SIZE);
    }

    #[test]
    fn gpt_zap_and_partition_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.img");
        File::create(&path)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();

        gpt_zap_and_partition(path.to_str().unwrap()).unwrap();

        // Protective MBR in LBA0: 0x55AA signature, type-0xEE partition.
        let mut lba0 = [0u8; 512];
        File::open(&path).unwrap().read_exact(&mut lba0).unwrap();
        assert_eq!(&lba0[510..], &[0x55, 0xAA]);
        assert_eq!(lba0[446 + 4], 0xEE);

        // Exactly one partition with the LUKS type GUID, spanning the
        // whole usable area.
        let disk = GptConfig::new().open(&path).unwrap();
        let used: Vec<_> = disk.partitions().values().filter(|p| p.is_used()).collect();
        assert_eq!(used.len(), 1);
        let part = used[0];
        assert!(part
            .part_type_guid
            .guid
            .to_string()
            .eq_ignore_ascii_case(LUKS_PARTITION_TYPE_GUID));
        assert_eq!(part.part_type_guid, partition_types::LINUX_LUKS);
        assert_eq!(part.name, "");
        assert_eq!(part.flags, 0);
        let header = disk.primary_header().unwrap();
        assert_eq!(part.first_lba, header.first_usable);
        assert_eq!(part.last_lba, header.last_usable);
    }

    #[test]
    fn wipefs_ok_on_file_without_signatures() {
        // No signatures -> the probe loop finds nothing and succeeds.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zeros.img");
        File::create(&path).unwrap().set_len(1024 * 1024).unwrap();
        wipefs(path.to_str().unwrap()).unwrap();
    }

    #[test]
    fn wipefs_erases_swap_signature() {
        // Minimal swap-v1 signature libblkid recognizes: version=1 and
        // last_page!=0 (le32 at offsets 1024/1028) plus "SWAPSPACE2" at
        // offset 4086 (PAGE_SIZE - 10 for 4 KiB pages).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swap.img");
        let mut f = File::create(&path).unwrap();
        f.set_len(1024 * 1024).unwrap();
        f.seek(SeekFrom::Start(1024)).unwrap();
        f.write_all(&1u32.to_le_bytes()).unwrap();
        f.write_all(&255u32.to_le_bytes()).unwrap();
        f.seek(SeekFrom::Start(4086)).unwrap();
        f.write_all(b"SWAPSPACE2").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let path_str = path.to_str().unwrap();
        if devices::blkid_tag(path_str, "TYPE").as_deref() != Some("swap") {
            // This environment's libblkid does not detect the synthetic
            // signature; the zeroed-file test above still covers the
            // no-signature path.
            eprintln!("skipping deeper wipefs coverage: synthetic swap signature not detected");
            return;
        }

        wipefs(path_str).unwrap();

        // Signature gone for blkid, magic bytes zeroed on disk.
        assert_eq!(devices::blkid_tag(path_str, "TYPE"), None);
        let mut magic = [0u8; 10];
        let mut f = File::open(&path).unwrap();
        f.seek(SeekFrom::Start(4086)).unwrap();
        f.read_exact(&mut magic).unwrap();
        assert_eq!(magic, [0u8; 10]);
    }
}
