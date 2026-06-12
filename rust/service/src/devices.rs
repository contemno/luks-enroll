//! Block-device discovery and inspection: crypttab parsing, libblkid
//! probing, sysfs metadata.
//!
//! Port of the Python service's detection helpers. One documented
//! divergence: system-wide LUKS discovery scans /sys/class/block and
//! probes each device with libblkid instead of using the libblkid cache
//! API — same results, no dependency on /run/blkid cache state.

use serde_json::Value;

/// LUKS block devices on the system: /etc/crypttab sources first, then a
/// system-wide scan, deduplicated by canonical path.
pub fn detect_luks_devices() -> Vec<String> {
    todo!("implemented in Phase A1/A5")
}

/// All block devices with TYPE=crypto_LUKS (canonical paths not required;
/// caller dedups). Used by detect_luks_devices and removable scanning.
pub fn find_luks_block_devices() -> Vec<String> {
    todo!("implemented in Phase A1/A5")
}

/// Removable devices with their partitions, as the JSON structure the
/// client expects from DetectRemovableDevices:
/// [{device, partitions: [{device, size, label, encrypted, luks_device?}],
///   size, label}]
pub fn detect_removable_devices() -> Value {
    todo!("implemented in Phase A1/A5")
}

/// Detailed info for one device, as the JSON structure the client expects
/// from GetDeviceInfo: {device, size, label, removable, mount_point,
/// filesystem}.
pub fn get_device_info(device: &str) -> Value {
    todo!("implemented in Phase A1/A5")
}

/// Whether the device (or its parent disk) is removable per sysfs.
pub fn is_removable(device: &str) -> bool {
    todo!("implemented in Phase A1/A5")
}

/// Whether the device node is a partition (vs whole disk) per sysfs.
pub fn is_partition(device: &str) -> bool {
    todo!("implemented in Phase A1/A5")
}

/// Kernel name of the parent disk: sdb1 -> sdb, nvme0n1p2 -> nvme0n1.
pub fn parent_device_name(device: &str) -> String {
    todo!("implemented in Phase A1/A5")
}

/// Human-readable size, decimal units: "32.0 GB", "1.5 TB", "512 B".
pub fn format_size(size_bytes: u64) -> String {
    todo!("implemented in Phase A1/A5")
}

/// A blkid tag (LABEL, TYPE, ...) for a device, via libblkid safeprobe.
pub fn blkid_tag(device: &str, tag: &str) -> Option<String> {
    todo!("implemented in Phase A1/A5")
}
