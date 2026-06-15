//! Recovery key generation (modhex format, matches systemd-cryptenroll).

const MODHEX: &[u8; 16] = b"cbdefghijklnrtuv";

/// Generate a 256-bit recovery key in modhex dash-separated format.
///
/// Matches the format produced by `systemd-cryptenroll --recovery-key`:
/// 64 modhex characters in 8 groups of 8, e.g.
/// "cbdefghi-jklnrtuv-...". Panics only if the OS RNG is unavailable.
pub fn make_recovery_key() -> String {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).expect("OS RNG unavailable");

    let chars: Vec<u8> = raw
        .iter()
        .flat_map(|b| [MODHEX[(b >> 4) as usize], MODHEX[(b & 0x0f) as usize]])
        .collect();
    chars
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_key_format() {
        let key = make_recovery_key();
        // 64 chars + 7 dashes
        assert_eq!(key.len(), 71);
        let groups: Vec<&str> = key.split('-').collect();
        assert_eq!(groups.len(), 8);
        for g in groups {
            assert_eq!(g.len(), 8);
            assert!(g.bytes().all(|b| MODHEX.contains(&b)), "non-modhex in {g}");
        }
    }

    #[test]
    fn recovery_keys_are_unique() {
        assert_ne!(make_recovery_key(), make_recovery_key());
    }
}
