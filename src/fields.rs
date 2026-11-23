//! The fixed byte strings halti signs and hands between machines and the hub: a run of fields,
//! each its length, two bytes big-endian, then its bytes. A request's record and every byte string
//! the hub checks a signature over are made this way, and the names in them follow one rule.

/// The longest name in a record.
pub const NAME_MAX: usize = 32;

/// Whether `name` may stand in a record: 1 to 32 bytes of a-z, 0-9, `-` and `_`, starting with a
/// letter or a digit. Machines, devices, workspaces and boxes are all named by it.
pub fn is_name(name: &str) -> bool {
    let ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let bytes = name.as_bytes();
    (1..=NAME_MAX).contains(&bytes.len()) && ok(bytes[0]) && bytes.iter().all(|&c| ok(c) || c == b'-' || c == b'_')
}

/// Adds `field` to `bytes`, after its length. Every field is far below 64 KiB; one that isn't is a
/// bug.
pub fn push(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend_from_slice(&u16::try_from(field.len()).expect("a field under 64 KiB").to_be_bytes());
    bytes.extend_from_slice(field);
}

/// `parts` run together, each after its length.
pub fn join(parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in parts {
        push(&mut bytes, part);
    }
    bytes
}

/// The fields `bytes` is a run of, each without its length; None if the last one is cut short.
pub fn split(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let mut fields = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let (length, after) = rest.split_first_chunk::<2>()?;
        let (field, after) = after.split_at_checked(usize::from(u16::from_be_bytes(*length)))?;
        fields.push(field);
        rest = after;
    }
    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_of_fields_splits_back_into_them_or_not_at_all() {
        assert_eq!(split(&join(&[b"ab", b"", b"c"])), Some(vec![&b"ab"[..], b"", b"c"]));
        assert_eq!(split(&[]), Some(Vec::new()));
        let bytes = join(&[b"ab", b"c"]);
        for end in [1, 3, bytes.len() - 1] {
            assert_eq!(split(&bytes[..end]), None, "cut at {end}");
        }
    }

    #[test]
    fn fields_are_length_prefixed_and_nothing_else() {
        assert_eq!(join(&[b"ab", b""]), [0x00, 0x02, b'a', b'b', 0x00, 0x00]);
        assert_eq!(join(&[]), Vec::<u8>::new());
        // A byte moved from one field to the next makes other bytes.
        assert_ne!(join(&[b"ab", b"c"]), join(&[b"a", b"bc"]));
        let mut pushed = join(&[b"ab"]);
        push(&mut pushed, b"c");
        assert_eq!(pushed, join(&[b"ab", b"c"]));
    }

    #[test]
    fn names_follow_the_one_rule() {
        for good in ["acme", "server-1", "build_box", "a-", "0", "9z", &"x".repeat(32)] {
            assert!(is_name(good), "{good}");
        }
        for bad in ["", "-x", "_x", "Acme", "a b", "a.b", "a/b", "é", &"x".repeat(33)] {
            assert!(!is_name(bad), "{bad}");
        }
    }
}
