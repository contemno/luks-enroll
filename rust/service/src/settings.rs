//! Runtime settings stored in /etc/luks-enroll.conf (INI, [defaults] section).
//!
//! Parity note: the Python service defines an empty SETTINGS_ALLOWED_KEYS
//! set ("Add valid keys here as features are added"), so GetSetting always
//! returns "" and SetSetting always returns false. We preserve that exactly;
//! the INI plumbing gets added together with the first real key.

pub const SETTINGS_FILE: &str = "/etc/luks-enroll.conf";

/// Keys that may be read/written. Empty until features need it.
const ALLOWED_KEYS: &[&str] = &[];

pub fn load_setting(key: &str) -> String {
    if !ALLOWED_KEYS.contains(&key) {
        return String::new();
    }
    unreachable!("no allowed settings keys defined yet");
}

pub fn save_setting(key: &str, _value: &str) -> bool {
    if !ALLOWED_KEYS.contains(&key) {
        return false;
    }
    unreachable!("no allowed settings keys defined yet");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_keys_rejected() {
        assert_eq!(load_setting("nope"), "");
        assert!(!save_setting("nope", "value"));
    }
}
