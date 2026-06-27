//! luks-enroll-service library: privileged LUKS enrollment operations.
//!
//! Exposed as a library so integration tests can exercise the operation
//! layer directly (against LUKS2 image files) without D-Bus.

pub mod constants;
pub mod devices;
pub mod error;
pub mod fido2;
pub mod format;
pub mod luks;
pub mod recovery;
pub mod service;
pub mod settings;
pub mod tpm2;
