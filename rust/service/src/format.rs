//! Destructive formatting paths: signature wiping, GPT partitioning,
//! LUKS formatting of removable media and image files.
//!
//! Port of the Python service's _wipefs / _sgdisk_zap_and_partition /
//! _format_removable_partition / format_luks_image. GPT creation uses the
//! pure-Rust `gpt` crate instead of libfdisk (documented divergence):
//! protective MBR + fresh GPT + one partition covering the disk with the
//! Linux LUKS type GUID.

use crate::error::Result;

/// Linux LUKS partition type GUID (sgdisk shortcode 8309).
pub const LUKS_PARTITION_TYPE_GUID: &str = "CA7D7CCB-63ED-4C53-861C-1742536059CC";

/// Erase all filesystem/partition-table signatures (wipefs equivalent):
/// libblkid probe loop over SBMAGIC/SBMAGIC_OFFSET, zeroing each magic.
pub fn wipefs(device: &str) -> Result<()> {
    todo!("implemented in Phase A5")
}

/// Wipe the partition table and create a single GPT LUKS partition
/// spanning the disk (sgdisk --zap-all && sgdisk -n 1:0:0 -t 1:8309).
pub fn gpt_zap_and_partition(device: &str) -> Result<()> {
    todo!("implemented in Phase A5")
}

/// Ask the kernel to re-read the partition table (BLKRRPART ioctl).
/// Best-effort; errors ignored.
pub fn partprobe(device: &str) {
    todo!("implemented in Phase A5")
}

/// Format a removable device with LUKS2. Whole disks get GPT + one LUKS
/// partition first; existing partitions are wiped and formatted directly.
/// Refuses non-removable devices. Returns the LUKS partition path, or an
/// error message (logged, not sent to clients).
pub fn format_removable_partition(
    device: &str,
    passphrase: &str,
) -> std::result::Result<String, String> {
    todo!("implemented in Phase A5")
}

/// Create a sparse image file of `size_mb` MiB (1..=8192) at `path`,
/// ready for LUKS formatting.
pub fn create_image_file(path: &str, size_mb: i32) -> Result<()> {
    todo!("implemented in Phase A5")
}
