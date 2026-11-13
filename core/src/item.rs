//! A stored secret: what a person calls it, its value, and how both are kept.
//!
//! ```text
//! name  = HMAC-SHA-384(item_names key, VERSION ‖ "ITEM\x01" ‖ "name" ‖ resource ‖ "/" ‖ field)[..32]
//! aad   = VERSION (12) ‖ "ITEM\x01" (5) ‖ ws (16) ‖ name (32) ‖ version (8, big-endian)
//! blob  = aead::seal(secrets key, nonce, aad, value)
//! ```
//!
//! The name is what the keystore keeps the blob under: 32 bytes that spell nothing, and differ in
//! every workspace, since each has its own names key. The blob holds only the value; its workspace,
//! name and version are bound by the associated data, so a blob copied from another workspace or
//! name, or put back from before its last change, does not open. The version is the pin version
//! of the change that stored it, and pin versions only rise, so no name and version is sealed for
//! twice in a workspace's life.

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::aead;
use crate::crypto::kdf::{ITEM_ID, ITEM_NAME, VERSION, labeled_extract};
use crate::ids::WsId;
use crate::refusal::Refusal;
use crate::store::ItemName;

/// What a person calls a stored secret: a resource and one of its fields, shown as
/// `github/token`. Checked once, here: one in hand is always well formed.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ItemKey {
    resource: String,
    field: String,
}

impl ItemKey {
    /// The longest resource, and the longest field.
    pub const MAX: usize = 32;

    /// The resource: 1 to 32 of a-z, 0-9 and `-`, starting with a letter or digit. The field: 1
    /// to 32 of a-z, 0-9 and `_`, starting with a letter. Anything else is
    /// `Refusal::BadSecretName`, which echoes neither.
    pub fn parse(resource: &str, field: &str) -> Result<ItemKey, Refusal> {
        ItemKey::check_resource(resource)?;
        let text = field.as_bytes();
        let ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_';
        if text.is_empty() || text.len() > ItemKey::MAX || !text[0].is_ascii_lowercase() || !text.iter().all(|&c| ok(c)) {
            return Err(Refusal::BadSecretName);
        }
        Ok(ItemKey { resource: resource.to_string(), field: field.to_string() })
    }

    /// The resource rule alone, for naming every field of one resource.
    pub fn check_resource(resource: &str) -> Result<(), Refusal> {
        let text = resource.as_bytes();
        let ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        if text.is_empty() || text.len() > ItemKey::MAX || !ok(text[0]) || !text.iter().all(|&c| ok(c) || c == b'-') {
            return Err(Refusal::BadSecretName);
        }
        Ok(())
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn field(&self) -> &str {
        &self.field
    }
}

/// `resource/field`. A resource holds no `/`, so the text names one key only.
impl fmt::Display for ItemKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.resource, self.field)
    }
}

/// A secret's value: UTF-8 text of 1 to 65536 bytes, with no control character but tab and line
/// feed, so no value can split a header, cut a variable or redraw a terminal. Wiped on drop, as
/// far as the language allows; it can't be cloned, and printing it shows nothing of it.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// The longest value, in bytes.
    pub const MAX: usize = 65536;

    /// Checks the bytes. Anything else is `Refusal::BadSecret`, which echoes none of them.
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Result<Secret, Refusal> {
        let allowed = |c: char| !c.is_control() || c == '\t' || c == '\n';
        let text = (1..=Secret::MAX).contains(&bytes.len()) && str::from_utf8(&bytes).is_ok_and(|text| text.chars().all(allowed));
        if text { Ok(Secret(bytes)) } else { Err(Refusal::BadSecret) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// The name a secret is kept under in a workspace whose names key is `names`.
pub(crate) fn item_name(names: &[u8; 32], key: &ItemKey) -> ItemName {
    let prk = labeled_extract(names, ITEM_ID, ITEM_NAME, &[key.resource.as_bytes(), b"/", key.field.as_bytes()]);
    let mut name = [0; 32];
    name.copy_from_slice(&prk[..32]);
    ItemName::from_bytes(name)
}

/// Seals `value` for `ws`, under `name`, at `version`, with the workspace's secrets key. `nonce`
/// is 12 fresh random bytes the caller drew, never used twice under one key.
pub(crate) fn seal_value(secrets: &[u8; 32], ws: WsId, name: &ItemName, version: u64, value: &Secret, nonce: &[u8; 12]) -> Vec<u8> {
    aead::seal(secrets, nonce, &aad(ws, name, version), value.as_bytes())
}

/// Opens what `seal_value` made for the same workspace, name and version. Every failure, a value
/// that is not a secret's included, is `Refusal::Unreadable`.
pub(crate) fn open_value(secrets: &[u8; 32], ws: WsId, name: &ItemName, version: u64, blob: &[u8]) -> Result<Secret, Refusal> {
    let plain = aead::open(secrets, &aad(ws, name, version), blob)?;
    Secret::new(plain).map_err(|_| Refusal::Unreadable)
}

/// The associated data of a value's seal: 73 bytes.
fn aad(ws: WsId, name: &ItemName, version: u64) -> Vec<u8> {
    [VERSION, ITEM_ID, ws.as_bytes().as_slice(), name.as_bytes().as_slice(), version.to_be_bytes().as_slice()].concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vectors::{
        ITEM_VALUE, KAT_ITEM_AAD, KAT_ITEM_NAME, KAT_ITEM_NAME_GITHUB_USER, KAT_ITEM_NAME_GLOBEX, KAT_ITEM_NAME_LINEAR_TOKEN, KAT_ITEM_VALUE, KAT_KEY_ITEM_NAMES, KAT_KEY_SECRETS,
        arr, hex, value_nonce, ws_bytes,
    };
    use crate::key::InnerKey;

    const GLOBEX: WsId = WsId::from_bytes([2; 16]);

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn key(resource: &str, field: &str) -> ItemKey {
        ItemKey::parse(resource, field).unwrap()
    }

    fn names() -> [u8; 32] {
        arr(&hex(KAT_KEY_ITEM_NAMES))
    }

    fn secrets() -> [u8; 32] {
        arr(&hex(KAT_KEY_SECRETS))
    }

    fn secret(text: &[u8]) -> Result<Secret, Refusal> {
        Secret::new(Zeroizing::new(text.to_vec()))
    }

    /// The known answers' name of github/token in acme.
    fn token() -> ItemName {
        ItemName::from_bytes(arr(&hex(KAT_ITEM_NAME)))
    }

    #[test]
    fn a_secrets_name_is_a_resource_then_a_field() {
        let longest = "a".repeat(ItemKey::MAX);
        for (resource, field) in [("github", "token"), ("a", "b"), ("9lives", "x_1"), ("north-lake-2", "api_key"), (longest.as_str(), longest.as_str())] {
            let key = key(resource, field);
            assert_eq!((key.resource(), key.field()), (resource, field));
            assert_eq!(ItemKey::check_resource(resource), Ok(()));
        }
        assert_eq!(key("github", "token").to_string(), "github/token");
        let longer = "a".repeat(ItemKey::MAX + 1);
        let refused_resources = ["", "Git", "-x", "a/b", "git hub", "git_hub", "gité", "\x1b[2J", longer.as_str()];
        for resource in refused_resources {
            assert_eq!(ItemKey::parse(resource, "token"), Err(Refusal::BadSecretName), "{resource:?}");
            assert_eq!(ItemKey::check_resource(resource), Err(Refusal::BadSecretName), "{resource:?}");
        }
        for field in ["", "Token", "1x", "_x", "x-y", "a/b", "é", "\x1b[2J", longer.as_str()] {
            assert_eq!(ItemKey::parse("github", field), Err(Refusal::BadSecretName), "{field:?}");
        }
        // The refusal echoes nothing that was typed.
        let said = ItemKey::parse("\x1b[2Jowned", "token").unwrap_err().to_string();
        assert!(!said.contains("owned") && !said.contains('\x1b'), "{said}");
    }

    #[test]
    fn an_item_name_is_unchanged() {
        let (token, user, linear) = (item_name(&names(), &key("github", "token")), item_name(&names(), &key("github", "user")), item_name(&names(), &key("linear", "token")));
        assert_eq!(token, ItemName::from_bytes(arr(&hex(KAT_ITEM_NAME))));
        assert_eq!(user.as_bytes().as_slice(), hex(KAT_ITEM_NAME_GITHUB_USER));
        assert_eq!(linear.as_bytes().as_slice(), hex(KAT_ITEM_NAME_LINEAR_TOKEN));
        assert!(token != user && user != linear && token != linear);
        // Under globex's own names key, the same text has another name.
        let globex = InnerKey::from_bytes(Zeroizing::new([0x22; 32])).open_keys();
        let theirs = item_name(globex.item_names(), &key("github", "token"));
        assert_eq!(theirs.as_bytes().as_slice(), hex(KAT_ITEM_NAME_GLOBEX));
        assert_ne!(theirs, token);
        // Names sort by their bytes, not by their text.
        let mut sorted = [token, user, linear];
        sorted.sort();
        assert_eq!(sorted, [token, linear, user]);
    }

    #[test]
    fn a_sealed_value_is_unchanged() {
        let value = secret(ITEM_VALUE.as_bytes()).unwrap();
        assert_eq!(aad(acme(), &token(), 2), hex(KAT_ITEM_AAD));
        assert_eq!(aad(acme(), &token(), 2).len(), 73);
        let blob = seal_value(&secrets(), acme(), &token(), 2, &value, &value_nonce());
        assert_eq!(blob.len(), ITEM_VALUE.len() + 29);
        assert_eq!(blob[1..13], value_nonce(), "the nonce, as given");
        assert_eq!(blob, hex(KAT_ITEM_VALUE));
        assert_eq!(open_value(&secrets(), acme(), &token(), 2, &blob).unwrap().as_bytes(), ITEM_VALUE.as_bytes());
    }

    #[test]
    fn a_value_opens_only_for_its_workspace_name_version_and_key() {
        let blob = hex(KAT_ITEM_VALUE);
        let user = ItemName::from_bytes(arr(&hex(KAT_ITEM_NAME_GITHUB_USER)));
        let globex = InnerKey::from_bytes(Zeroizing::new([0x22; 32])).open_keys();
        let opened = |secrets: &[u8; 32], ws: WsId, name: &ItemName, version: u64, blob: &[u8]| open_value(secrets, ws, name, version, blob).map(|_| ());
        assert_eq!(opened(&secrets(), acme(), &token(), 2, &blob), Ok(()));
        assert_eq!(opened(&secrets(), GLOBEX, &token(), 2, &blob), Err(Refusal::Unreadable), "globex's id");
        assert_eq!(opened(&secrets(), acme(), &user, 2, &blob), Err(Refusal::Unreadable), "github/user's name");
        for version in [1, 3] {
            assert_eq!(opened(&secrets(), acme(), &token(), version, &blob), Err(Refusal::Unreadable), "version {version}");
        }
        assert_eq!(opened(globex.secrets(), acme(), &token(), 2, &blob), Err(Refusal::Unreadable), "globex's secrets key");
        for i in 0..blob.len() {
            let mut changed = blob.clone();
            changed[i] ^= 0x01;
            assert_eq!(opened(&secrets(), acme(), &token(), 2, &changed), Err(Refusal::Unreadable), "byte {i}");
        }
        for len in 0..blob.len() {
            assert_eq!(opened(&secrets(), acme(), &token(), 2, &blob[..len]), Err(Refusal::Unreadable), "cut to {len} bytes");
        }
        let mut longer = blob.clone();
        longer.push(0);
        assert_eq!(opened(&secrets(), acme(), &token(), 2, &longer), Err(Refusal::Unreadable), "one byte more");
        // A blob that opens and holds no secret, as anyone with the key could seal, is refused the same way.
        let control = aead::seal(&secrets(), &value_nonce(), &aad(acme(), &token(), 2), b"a\x1b[2J");
        assert_eq!(opened(&secrets(), acme(), &token(), 2, &control), Err(Refusal::Unreadable), "a value with an escape");
    }

    #[test]
    fn a_secret_is_text_of_1_to_65536_bytes() {
        let longest = "a".repeat(Secret::MAX);
        for text in ["a\tb\nc", "x", "ключ 🔑", ITEM_VALUE, "-----BEGIN KEY-----\nabc\n-----END KEY-----\n", longest.as_str()] {
            assert_eq!(secret(text.as_bytes()).unwrap().as_bytes(), text.as_bytes(), "{} bytes", text.len());
        }
        let longer = "a".repeat(Secret::MAX + 1);
        for bytes in [b"".as_slice(), longer.as_bytes(), b"a\0b", b"a\rb", b"line\r\n", b"a\x1b[2J", b"a\x7f", b"\xc2\x85", b"a\xffb", b"\xff"] {
            assert_eq!(secret(bytes).unwrap_err(), Refusal::BadSecret, "{:02x?}", &bytes[..bytes.len().min(8)]);
        }
        assert_eq!(Refusal::BadSecret.to_string(), "that value can't be stored: a secret is text of up to 65536 bytes");
    }

    #[test]
    fn a_secret_prints_nothing_of_itself() {
        let value = secret(ITEM_VALUE.as_bytes()).unwrap();
        assert_eq!((format!("{value:?}"), format!("{value:#?}")), ("Secret(..)".to_string(), "Secret(..)".to_string()));
        // Nor does a refusal of one, or of its name.
        for said in [secret(b"acme github token\0").unwrap_err().to_string(), ItemKey::parse("github", "Token").unwrap_err().to_string()] {
            assert!(!said.contains("acme github") && !said.contains("Token"), "{said}");
        }
    }
}
