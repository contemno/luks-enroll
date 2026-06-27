//! Block-device discovery and inspection: crypttab parsing, libblkid
//! probing, sysfs metadata.
//!
//! Port of the Python service's detection helpers. One documented
//! divergence: system-wide LUKS discovery scans /sys/class/block and
//! probes each device with libblkid instead of using the libblkid cache
//! API — same results, no dependency on /run/blkid cache state.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use libblkid_rs::{BlkidProbe, BlkidSafeprobeRet, BlkidSublks, BlkidSublksFlags};
use serde_json::{json, Value};

/// LUKS block devices on the system: /etc/crypttab sources first, then a
/// system-wide scan, deduplicated by canonical path.
pub fn detect_luks_devices() -> Vec<String> {
    let mut found = crypttab_devices(Path::new("/etc/crypttab"), Path::new("/dev/disk/by-uuid"));
    let mut seen: HashSet<String> = found.iter().cloned().collect();

    // Also scan for any LUKS devices not in crypttab.
    for dev in find_luks_block_devices() {
        let real = canonicalize_lossy(Path::new(&dev));
        if seen.insert(real.clone()) {
            found.push(real);
        }
    }

    found
}

/// All block devices with TYPE=crypto_LUKS (canonical paths not required;
/// caller dedups). Used by detect_luks_devices and removable scanning.
///
/// Divergence from the Python reference (libblkid cache API): scan
/// /sys/class/block, skip virtual devices, and safeprobe each /dev node.
/// Devices that cannot be opened/probed are skipped silently. Results are
/// sorted by kernel name for determinism.
pub fn find_luks_block_devices() -> Vec<String> {
    let mut devices = Vec::new();
    for name in sorted_dir_names("/sys/class/block") {
        if is_virtual_block_name(&name) {
            continue;
        }
        let dev = format!("/dev/{name}");
        if blkid_tag(&dev, "TYPE").as_deref() == Some("crypto_LUKS") {
            devices.push(dev);
        }
    }
    devices
}

/// Removable devices with their partitions, as the JSON structure the
/// client expects from DetectRemovableDevices:
/// [{device, partitions: [{device, size, label, encrypted, luks_device?}],
///   size, label}]
pub fn detect_removable_devices() -> Value {
    // Get all LUKS devices in one scan for efficiency.
    let luks_devices: HashSet<String> = find_luks_block_devices().into_iter().collect();

    let mut results: Vec<Value> = Vec::new();
    for dev_name in sorted_dir_names("/sys/block") {
        // Skip virtual devices.
        if is_virtual_block_name(&dev_name) {
            continue;
        }
        if read_sysfs(&format!("/sys/block/{dev_name}/removable")).as_deref() != Some("1") {
            continue;
        }

        let dev_path = format!("/dev/{dev_name}");
        let size_bytes = sysfs_size_bytes(&format!("/sys/block/{dev_name}/size"));
        let label = blkid_tag(&dev_path, "LABEL").unwrap_or_default();

        // Enumerate partitions: sysfs entries named after the parent disk.
        let mut partitions: Vec<Value> = Vec::new();
        for entry in sorted_dir_names(&format!("/sys/block/{dev_name}")) {
            if !entry.starts_with(dev_name.as_str()) {
                continue;
            }
            let part_path = format!("/dev/{entry}");
            let part_size_bytes = sysfs_size_bytes(&format!("/sys/block/{dev_name}/{entry}/size"));
            let part_label = blkid_tag(&part_path, "LABEL").unwrap_or_default();
            let part_encrypted = luks_devices.contains(&part_path);
            let mut part_info = json!({
                "device": part_path,
                "size": format_size(part_size_bytes),
                "label": part_label,
                "encrypted": part_encrypted,
            });
            if part_encrypted {
                part_info["luks_device"] = Value::String(part_path);
            }
            partitions.push(part_info);
        }

        results.push(json!({
            "device": dev_path,
            "partitions": partitions,
            "size": format_size(size_bytes),
            "label": label,
        }));
    }

    Value::Array(results)
}

/// Detailed info for one device, as the JSON structure the client expects
/// from GetDeviceInfo: {device, size, label, removable, mount_point,
/// filesystem}.
pub fn get_device_info(device: &str) -> Value {
    // Size: file length for regular files, sysfs sector count otherwise.
    let mut size = String::new();
    match fs::metadata(device) {
        Ok(md) if md.is_file() => size = format_size(md.len()),
        _ => {
            let parent = parent_device_name(device);
            let base = basename(device);
            // Prefer the parent-qualified sysfs `size` (a partition under its
            // disk), falling back to the bare basename (a whole disk).
            // sysfs_size_bytes does the read -> parse -> *512, returning 0 for
            // a missing/unparseable file.
            let bytes = match sysfs_size_bytes(&format!("/sys/block/{parent}/{base}/size")) {
                0 => sysfs_size_bytes(&format!("/sys/block/{base}/size")),
                n => n,
            };
            if bytes > 0 {
                size = format_size(bytes);
            }
        }
    }

    // Mount point: second field of the first /proc/mounts line whose
    // first field is exactly this device path.
    let mut mount_point = String::new();
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let mut fields = line.split_whitespace();
            if let (Some(dev), Some(mp)) = (fields.next(), fields.next()) {
                if dev == device {
                    mount_point = mp.to_string();
                    break;
                }
            }
        }
    }

    json!({
        "device": device,
        "size": size,
        "label": blkid_tag(device, "LABEL").unwrap_or_default(),
        "removable": is_removable(device),
        "mount_point": mount_point,
        "filesystem": blkid_tag(device, "TYPE").unwrap_or_default(),
    })
}

/// Whether the device (or its parent disk) is removable per sysfs.
pub fn is_removable(device: &str) -> bool {
    let parent = parent_device_name(device);
    read_sysfs(&format!("/sys/block/{parent}/removable")).as_deref() == Some("1")
}

/// Whether the device node is a partition (vs whole disk) per sysfs.
pub fn is_partition(device: &str) -> bool {
    let base = basename(device);
    Path::new(&format!("/sys/class/block/{base}/partition")).exists()
}

/// Kernel name of the parent disk: sdb1 -> sdb, nvme0n1p2 -> nvme0n1.
///
/// Mirrors the Python regexes `^(nvme\d+n\d+)p\d+$` and `^([a-z]+)[0-9]+$`,
/// including the quirk that names like "mmcblk0p1" match neither pattern
/// and are returned unchanged.
pub fn parent_device_name(device: &str) -> String {
    let base = basename(device);
    if let Some(parent) = nvme_partition_parent(base) {
        return parent.to_string();
    }
    if let Some(parent) = letters_then_digits_parent(base) {
        return parent.to_string();
    }
    base.to_string()
}

/// Human-readable size, decimal units: "32.0 GB", "1.5 TB", "512 B".
pub fn format_size(size_bytes: u64) -> String {
    const TB: u64 = 1_000_000_000_000;
    const GB: u64 = 1_000_000_000;
    const MB: u64 = 1_000_000;
    const KB: u64 = 1_000;
    if size_bytes >= TB {
        format!("{:.1} TB", size_bytes as f64 / TB as f64)
    } else if size_bytes >= GB {
        format!("{:.1} GB", size_bytes as f64 / GB as f64)
    } else if size_bytes >= MB {
        format!("{:.1} MB", size_bytes as f64 / MB as f64)
    } else if size_bytes >= KB {
        format!("{:.1} KB", size_bytes as f64 / KB as f64)
    } else {
        format!("{size_bytes} B")
    }
}

/// A blkid tag (LABEL, TYPE, ...) for a device, via libblkid safeprobe.
///
/// Returns None when the device cannot be opened, nothing was detected,
/// the probe was ambiguous, or the tag is absent/empty (matches the
/// Python helper, which treats an empty value as None).
pub fn blkid_tag(device: &str, tag: &str) -> Option<String> {
    let mut probe = BlkidProbe::new_from_filename(Path::new(device)).ok()?;
    probe
        .set_superblock_flags(BlkidSublksFlags::new(vec![
            BlkidSublks::Label,
            BlkidSublks::Type,
        ]))
        .ok()?;
    if !matches!(probe.do_safeprobe(), Ok(BlkidSafeprobeRet::Success)) {
        return None;
    }
    probe.lookup_value(tag).ok().filter(|v| !v.is_empty())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a crypttab file: skip blanks/comments, take the source (second)
/// field of every entry, resolve `UUID=<uuid>` sources against
/// `by_uuid_dir` (normally /dev/disk/by-uuid) and plain sources as paths,
/// keeping only those that exist. Canonicalized, deduplicated, file order.
/// A missing crypttab (or missing by-uuid dir) yields no entries.
fn crypttab_devices(crypttab: &Path, by_uuid_dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let Ok(content) = fs::read_to_string(crypttab) else {
        return found;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let src = fields[1];
        let dev = if let Some(uuid) = src.strip_prefix("UUID=") {
            let path = by_uuid_dir.join(uuid);
            path.exists().then(|| canonicalize_lossy(&path))
        } else if Path::new(src).exists() {
            Some(canonicalize_lossy(Path::new(src)))
        } else {
            None
        };
        if let Some(dev) = dev {
            if seen.insert(dev.clone()) {
                found.push(dev);
            }
        }
    }
    found
}

/// Like Python's os.path.realpath: canonicalize, falling back to the
/// input path when resolution fails. Accepts `&Path` or `&str` so the
/// device-path callers in `luks` share this one implementation.
pub(crate) fn canonicalize_lossy(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

/// Final path component, like Python's os.path.basename.
pub(crate) fn basename(device: &str) -> &str {
    device.rsplit('/').next().unwrap_or(device)
}

/// Read a sysfs file and return its trimmed content, or None.
pub(crate) fn read_sysfs(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Sector count from a sysfs `size` file, in bytes (0 if missing/bad).
fn sysfs_size_bytes(path: &str) -> u64 {
    read_sysfs(path)
        .and_then(|s| s.parse::<u64>().ok())
        .map(|sectors| sectors * 512)
        .unwrap_or(0)
}

/// Directory entry names, sorted; empty when unreadable.
fn sorted_dir_names(dir: &str) -> Vec<String> {
    let mut names: Vec<String> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => return Vec::new(),
    };
    names.sort();
    names
}

/// Virtual block devices that are never interesting for LUKS scans.
fn is_virtual_block_name(name: &str) -> bool {
    name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram")
}

/// Parse an `nvme<ctrl>n<ns>` device name (the whole-disk shape). Returns the
/// byte offset just past the namespace -- the end of the whole-disk name --
/// and the remaining suffix after it, or None when the name isn't a
/// well-formed nvme namespace. `nvme0n1` -> Some((7, "")); `nvme0n1p2` ->
/// Some((7, "p2")). Shared by `nvme_partition_parent` here and
/// `format::is_nvme_whole_disk`.
pub(crate) fn parse_nvme(name: &str) -> Option<(usize, &str)> {
    let rest = name.strip_prefix("nvme")?;
    let b = rest.as_bytes();
    let mut i = 0;
    let ctrl_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == ctrl_start || i >= b.len() || b[i] != b'n' {
        return None;
    }
    i += 1;
    let ns_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == ns_start {
        return None;
    }
    let end = "nvme".len() + i;
    Some((end, &name[end..]))
}

/// Hand-rolled `^(nvme[0-9]+n[0-9]+)p[0-9]+$` -> group 1.
fn nvme_partition_parent(name: &str) -> Option<&str> {
    let (parent_end, suffix) = parse_nvme(name)?;
    // The suffix must be exactly `p` followed by one or more digits.
    let digits = suffix.strip_prefix('p')?;
    if !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit()) {
        Some(&name[..parent_end])
    } else {
        None
    }
}

/// Hand-rolled `^([a-z]+)[0-9]+$` -> the letters. Lowercase ASCII only,
/// like the Python regex.
fn letters_then_digits_parent(name: &str) -> Option<&str> {
    let b = name.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_lowercase() {
        i += 1;
    }
    if i == 0 || i == b.len() {
        return None;
    }
    let letters_end = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i != b.len() {
        return None;
    }
    Some(&name[..letters_end])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_goldens() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(999), "999 B");
        assert_eq!(format_size(1000), "1.0 KB");
        assert_eq!(format_size(1_500_000), "1.5 MB");
        assert_eq!(format_size(32_000_000_000), "32.0 GB");
        assert_eq!(format_size(2_000_000_000_000), "2.0 TB");
    }

    #[test]
    fn parse_nvme_shared() {
        // Whole disk: namespace runs to the end, empty suffix.
        assert_eq!(parse_nvme("nvme0n1"), Some((7, "")));
        assert_eq!(parse_nvme("nvme12n34"), Some((9, "")));
        // Partition: suffix is the trailing `p<part>`.
        assert_eq!(parse_nvme("nvme0n1p2"), Some((7, "p2")));
        // Not a well-formed namespace.
        assert_eq!(parse_nvme("nvme0"), None); // no `n<ns>`
        assert_eq!(parse_nvme("nvme0n"), None); // empty namespace
        assert_eq!(parse_nvme("sda"), None); // not nvme
    }

    #[test]
    fn sysfs_size_bytes_reads_sectors() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("size");
        fs::write(&ok, "2048\n").unwrap();
        // sectors * 512.
        assert_eq!(sysfs_size_bytes(ok.to_str().unwrap()), 2048 * 512);
        // Missing or non-numeric -> 0 (the fallback signal in get_device_info).
        assert_eq!(
            sysfs_size_bytes(dir.path().join("absent").to_str().unwrap()),
            0
        );
        let bad = dir.path().join("bad");
        fs::write(&bad, "not-a-number").unwrap();
        assert_eq!(sysfs_size_bytes(bad.to_str().unwrap()), 0);
    }

    #[test]
    fn parent_device_name_cases() {
        assert_eq!(parent_device_name("sda1"), "sda");
        assert_eq!(parent_device_name("sdb"), "sdb");
        assert_eq!(parent_device_name("nvme0n1p2"), "nvme0n1");
        assert_eq!(parent_device_name("nvme0n1"), "nvme0n1");
        assert_eq!(parent_device_name("vda3"), "vda");
        // Documented Python quirk: "mmcblk0p1" matches neither
        // `^(nvme\d+n\d+)p\d+$` nor `^([a-z]+)[0-9]+$` (the digits are
        // interrupted by 'p'), so the name is returned unchanged.
        assert_eq!(parent_device_name("mmcblk0p1"), "mmcblk0p1");
        // Full paths reduce to their basename first.
        assert_eq!(parent_device_name("/dev/sda1"), "sda");
        assert_eq!(parent_device_name("/dev/nvme0n1p2"), "nvme0n1");
    }

    #[test]
    fn canonicalize_lossy_str_and_path() {
        // A nonexistent path resolves to nothing, so the input is returned
        // verbatim -- and the &str overload (the luks cache call site) yields
        // the same string as the original input.
        assert_eq!(
            canonicalize_lossy("/nonexistent/luks-enroll-canon-test"),
            "/nonexistent/luks-enroll-canon-test"
        );

        // A real path resolves the same whether passed as &str or &Path.
        let f = tempfile::NamedTempFile::new().unwrap();
        let want = fs::canonicalize(f.path())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(canonicalize_lossy(f.path()), want);
        assert_eq!(canonicalize_lossy(f.path().to_str().unwrap()), want);
    }

    #[test]
    fn crypttab_parsing_with_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let dev_a = dir.path().join("deva");
        let dev_b = dir.path().join("devb");
        fs::write(&dev_a, b"a").unwrap();
        fs::write(&dev_b, b"b").unwrap();
        let canon_a = fs::canonicalize(&dev_a)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let canon_b = fs::canonicalize(&dev_b)
            .unwrap()
            .to_string_lossy()
            .into_owned();

        // by-uuid dir intentionally absent: UUID= sources must be
        // tolerated (skipped) when the symlink dir does not exist.
        let by_uuid = dir.path().join("by-uuid");

        let crypttab = dir.path().join("crypttab");
        let content = format!(
            "# a comment\n\
             \n\
             \t  \n\
             root {a} none luks\n\
             dup {a} none luks\n\
             other {b} none\n\
             gone /nonexistent/luks-enroll-test-dev none luks\n\
             uuid UUID=does-not-exist none luks\n\
             shortline\n",
            a = dev_a.display(),
            b = dev_b.display()
        );
        fs::write(&crypttab, content).unwrap();

        let devs = crypttab_devices(&crypttab, &by_uuid);
        assert_eq!(devs, vec![canon_a.clone(), canon_b]);

        // UUID= sources resolve through the by-uuid dir (symlink) and
        // dedup against plain-path entries for the same device.
        fs::create_dir_all(&by_uuid).unwrap();
        std::os::unix::fs::symlink(&dev_a, by_uuid.join("1234-ABCD")).unwrap();
        let content = format!(
            "luks-root UUID=1234-ABCD none luks\n\
             plain {a} none luks\n",
            a = dev_a.display()
        );
        fs::write(&crypttab, content).unwrap();
        let devs = crypttab_devices(&crypttab, &by_uuid);
        assert_eq!(devs, vec![canon_a]);

        // Missing crypttab: empty result.
        let devs = crypttab_devices(&dir.path().join("no-such-crypttab"), &by_uuid);
        assert!(devs.is_empty());
    }
}
