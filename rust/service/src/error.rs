//! Service-internal error type.
//!
//! The Python service raises RuntimeError(message) and handlers catch all
//! exceptions, log the real message to stderr, and return a generic
//! "Operation failed" over D-Bus. This type mirrors that: it carries the
//! detailed message for logging; the D-Bus layer decides what leaks out.

use std::fmt;

#[derive(Debug)]
pub struct Error(pub String);

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error(s.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error(format!("JSON error: {e}"))
    }
}

impl From<libcryptsetup_rs::LibcryptErr> for Error {
    fn from(e: libcryptsetup_rs::LibcryptErr) -> Self {
        Error(format!("libcryptsetup: {e}"))
    }
}

impl From<tss_esapi::Error> for Error {
    fn from(e: tss_esapi::Error) -> Self {
        Error(format!("tss-esapi: {e}"))
    }
}

/// Shorthand: `return err!("Esys_Load failed: {rc:#x}")`.
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::error::Error(format!($($arg)*)))
    };
}
