//! Who a workspace is. Its id is 16 random bytes that never change and say nothing of the client;
//! everything stored for the workspace is keyed by it. Its name is what a person types, checked
//! once, here: a `WsName` in hand is always well formed, wherever it was read from.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::refusal::Refusal;

/// Lowercase hex, two characters a byte.
pub(crate) fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
}

/// A workspace's permanent id: 16 bytes drawn at random when the workspace was made.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WsId([u8; 16]);

impl WsId {
    /// From 16 bytes. Core draws no randomness of its own: whoever makes the workspace does.
    pub const fn from_bytes(bytes: [u8; 16]) -> WsId {
        WsId(bytes)
    }

    /// The bytes, for adapters and for tying sealed data to the workspace.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// From exactly 32 lowercase hex characters, as `Display` writes them (in a folder's name,
    /// say). Anything else is refused, so text that parses can't hold a path.
    pub fn parse(hex: &str) -> Result<WsId, Refusal> {
        let text = hex.as_bytes();
        if text.len() != 32 {
            return Err(Refusal::BadId);
        }
        let mut bytes = [0; 16];
        for (byte, pair) in bytes.iter_mut().zip(text.chunks(2)) {
            *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(WsId(bytes))
    }
}

fn nibble(c: u8) -> Result<u8, Refusal> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(Refusal::BadId),
    }
}

impl fmt::Display for WsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for WsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

/// A workspace's name as a person types it: 1 to 32 of a-z, 0-9 and `-`, starting with a letter
/// or digit. No `/` (it separates a workspace from what is in it, as in `acme/linear`), no
/// `.`, and nothing a terminal could draw as something else.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WsName(String);

impl WsName {
    /// The longest name.
    pub const MAX: usize = 32;

    /// Checks the text. The only way to make a name: reading one from a file goes through here too.
    pub fn parse(s: &str) -> Result<WsName, Refusal> {
        let ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        let text = s.as_bytes();
        if text.is_empty() || text.len() > Self::MAX || !ok(text[0]) || !text.iter().all(|&c| ok(c) || c == b'-') {
            return Err(Refusal::BadName);
        }
        Ok(WsName(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for WsName {
    type Error = Refusal;

    fn try_from(s: String) -> Result<WsName, Refusal> {
        WsName::parse(&s)
    }
}

impl From<WsName> for String {
    fn from(name: WsName) -> String {
        name.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_lowercase_letters_digits_and_dashes() {
        for name in ["acme", "a", "9lives", "north-lake-2", &"x".repeat(WsName::MAX)] {
            assert_eq!(WsName::parse(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn a_name_with_a_dot_a_slash_or_a_space_is_refused() {
        for name in ["globex.linear", "acme/linear", "ac me", "Acme", "ac_me", "..", "a/../b"] {
            assert_eq!(WsName::parse(name), Err(Refusal::BadName), "{name}");
        }
    }

    #[test]
    fn a_name_starting_with_a_dash_or_empty_or_too_long_is_refused() {
        for name in ["", "-", "-rf", "--all", &"x".repeat(WsName::MAX + 1)] {
            assert_eq!(WsName::parse(name), Err(Refusal::BadName), "{name}");
        }
    }

    #[test]
    fn control_and_bidi_characters_never_make_a_name() {
        for name in ["ac\nme", "ac\x1b[2Kme", "acme\0", "ac\u{202e}em", "ac\u{200b}me", "acmé", "аcme"] {
            assert_eq!(WsName::parse(name), Err(Refusal::BadName), "{name:?}");
        }
    }

    #[test]
    fn a_refused_name_is_not_echoed() {
        let said = WsName::parse("\x1b[2Jowned").unwrap_err().to_string();
        assert!(!said.contains("owned") && !said.contains('\x1b'), "{said}");
    }

    #[test]
    fn a_name_read_from_a_file_is_checked_the_same_way() {
        assert_eq!(serde_json::from_str::<WsName>("\"acme\"").unwrap().as_str(), "acme");
        assert!(serde_json::from_str::<WsName>("\"Ac/me\"").is_err());
        assert_eq!(serde_json::to_string(&WsName::parse("acme").unwrap()).unwrap(), "\"acme\"");
    }

    #[test]
    fn an_id_prints_as_32_hex_characters_and_reads_back() {
        let id = WsId::from_bytes([0x00, 0x01, 0x0a, 0x10, 0x7f, 0x80, 0xfe, 0xff, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(id.to_string(), "00010a107f80feff0102030405060708");
        assert_eq!(format!("{id:?}"), id.to_string());
        assert_eq!(WsId::parse(&id.to_string()), Ok(id));
    }

    #[test]
    fn an_id_of_another_length_or_with_other_characters_is_refused() {
        let hex = "00010a107f80feff0102030405060708";
        for text in [
            "",
            "..",
            &hex[1..],
            &format!("{hex}0"),
            &hex.to_uppercase(),
            &hex.replace('7', "/"),
            &hex.replace("00", ".."),
            &hex.replace('a', "g"),
            &hex.replace('a', "é"),
            &hex.replace("0a", "é"),
        ] {
            assert_eq!(WsId::parse(text), Err(Refusal::BadId), "{text}");
        }
    }
}
