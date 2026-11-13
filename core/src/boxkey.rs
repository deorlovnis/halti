//! A box's store key, kept as an item of the workspace in a namespace of its own.
//!
//! ```text
//! name  = HMAC-SHA-384(item_names key, VERSION ‖ "BOX\x01" ‖ "name" ‖ box)[..32]
//! aad   = VERSION (12) ‖ "BOX\x01" (4) ‖ ws (16) ‖ name (32) ‖ version (8, big-endian)
//! blob  = aead::seal(store key, nonce, aad, key (32))
//! ```
//!
//! The key is 32 random bytes the binary draws; the disk layer is given them as 64 lowercase hex
//! characters. Its name is derived under its own id, so no secret's name is ever a box key's, and a
//! secret removed by resource never takes a box with it. The blob is sealed under the workspace's
//! store key, the key the disk layer encrypts with, and binds the workspace, the name and the pin
//! version of the change that stored it, as a secret's value does (`item`).

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::aead;
use crate::crypto::kdf::{BOX_ID, BOX_NAME, VERSION, labeled_extract};
use crate::ids::WsId;
use crate::item::ItemKey;
use crate::refusal::Refusal;
use crate::store::ItemName;

/// A box's store key: 32 random bytes. Wiped on drop, as far as the language allows; it can't be
/// cloned, and printing it shows nothing of it.
pub struct BoxKey(Zeroizing<[u8; 32]>);

impl BoxKey {
    /// From 32 random bytes the caller drew.
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> BoxKey {
        BoxKey(bytes)
    }

    /// As the disk layer is given it: 64 lowercase hex characters.
    pub fn hex(&self) -> Zeroizing<String> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut text = Zeroizing::new(String::with_capacity(64));
        for byte in self.0.iter() {
            text.push(char::from(DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        text
    }
}

impl fmt::Debug for BoxKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoxKey(..)")
    }
}

/// Refuses, with `Refusal::BadBox`, a name that isn't a box's: 1 to 32 of a-z, 0-9 and `-`,
/// starting with a letter or digit, as a resource is.
pub fn check_box(name: &str) -> Result<(), Refusal> {
    ItemKey::check_resource(name).map_err(|_| Refusal::BadBox)
}

/// The name box `name`'s key is kept under in a workspace whose names key is `names`.
pub(crate) fn box_name(names: &[u8; 32], name: &str) -> ItemName {
    let prk = labeled_extract(names, BOX_ID, BOX_NAME, &[name.as_bytes()]);
    let mut out = [0; 32];
    out.copy_from_slice(&prk[..32]);
    ItemName::from_bytes(out)
}

/// Seals `key` for `ws`, under `name`, at `version`, with the workspace's store key. `nonce` is 12
/// fresh random bytes the caller drew, never used twice under one key.
pub(crate) fn seal_box_key(store: &[u8; 32], ws: WsId, name: &ItemName, version: u64, key: &BoxKey, nonce: &[u8; 12]) -> Vec<u8> {
    aead::seal(store, nonce, &aad(ws, name, version), key.0.as_slice())
}

/// Opens what `seal_box_key` made for the same workspace, name and version. Every failure, a key
/// of another length included, is `Refusal::Unreadable`.
pub(crate) fn open_box_key(store: &[u8; 32], ws: WsId, name: &ItemName, version: u64, blob: &[u8]) -> Result<BoxKey, Refusal> {
    let plain = aead::open(store, &aad(ws, name, version), blob)?;
    let bytes: &[u8; 32] = plain.as_slice().try_into().map_err(|_| Refusal::Unreadable)?;
    Ok(BoxKey(Zeroizing::new(*bytes)))
}

/// The associated data of a box key's seal: 72 bytes.
fn aad(ws: WsId, name: &ItemName, version: u64) -> Vec<u8> {
    [VERSION, BOX_ID, ws.as_bytes().as_slice(), name.as_bytes().as_slice(), version.to_be_bytes().as_slice()].concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vectors::{
        KAT_BOX_AAD, KAT_BOX_KEY, KAT_BOX_NAME, KAT_BOX_NAME_GLOBEX, KAT_ITEM_NAME, KAT_KEY_ITEM_NAMES, KAT_KEY_SECRETS, KAT_KEY_STORE, arr, box_key_bytes, box_key_nonce, hex,
        ws_bytes,
    };
    use crate::item::item_name;
    use crate::key::InnerKey;

    const GLOBEX: WsId = WsId::from_bytes([2; 16]);

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn names() -> [u8; 32] {
        arr(&hex(KAT_KEY_ITEM_NAMES))
    }

    fn store() -> [u8; 32] {
        arr(&hex(KAT_KEY_STORE))
    }

    fn key() -> BoxKey {
        BoxKey::from_bytes(Zeroizing::new(box_key_bytes()))
    }

    /// The known answers' name of box dev's key in acme.
    fn dev() -> ItemName {
        ItemName::from_bytes(arr(&hex(KAT_BOX_NAME)))
    }

    #[test]
    fn a_box_key_s_name_is_unchanged() {
        assert_eq!(box_name(&names(), "dev"), dev());
        // No secret's name is it: not the item `dev/…` under the same names key, of any field, nor github/token.
        for field in ["name", "key", "token"] {
            assert_ne!(item_name(&names(), &ItemKey::parse("dev", field).unwrap()), dev(), "dev/{field}");
        }
        assert_ne!(dev().as_bytes().as_slice(), hex(KAT_ITEM_NAME));
        // Another box, and the same box under globex's own names key, have other names.
        assert_ne!(box_name(&names(), "test"), dev());
        let globex = InnerKey::from_bytes(Zeroizing::new([0x22; 32])).open_keys();
        let theirs = box_name(globex.item_names(), "dev");
        assert_eq!(theirs.as_bytes().as_slice(), hex(KAT_BOX_NAME_GLOBEX));
        assert_ne!(theirs, dev());
    }

    #[test]
    fn a_sealed_box_key_is_unchanged() {
        assert_eq!(aad(acme(), &dev(), 2), hex(KAT_BOX_AAD));
        assert_eq!(aad(acme(), &dev(), 2).len(), 72);
        let blob = seal_box_key(&store(), acme(), &dev(), 2, &key(), &box_key_nonce());
        assert_eq!(blob.len(), 61);
        assert_eq!(blob[1..13], box_key_nonce(), "the nonce, as given");
        assert_eq!(blob, hex(KAT_BOX_KEY));
        assert_eq!(*open_box_key(&store(), acme(), &dev(), 2, &blob).unwrap().0, box_key_bytes());
        // Given to the disk layer as today's keys are: 64 lowercase hex characters.
        assert_eq!(key().hex().as_str(), "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
    }

    #[test]
    fn a_box_key_opens_only_for_its_workspace_name_version_and_key() {
        let blob = hex(KAT_BOX_KEY);
        let opened = |store: &[u8; 32], ws: WsId, name: &ItemName, version: u64, blob: &[u8]| open_box_key(store, ws, name, version, blob).map(|_| ());
        assert_eq!(opened(&store(), acme(), &dev(), 2, &blob), Ok(()));
        assert_eq!(opened(&store(), GLOBEX, &dev(), 2, &blob), Err(Refusal::Unreadable), "globex's id");
        assert_eq!(opened(&store(), acme(), &box_name(&names(), "test"), 2, &blob), Err(Refusal::Unreadable), "box test's name");
        for version in [1, 3] {
            assert_eq!(opened(&store(), acme(), &dev(), version, &blob), Err(Refusal::Unreadable), "version {version}");
        }
        let globex = InnerKey::from_bytes(Zeroizing::new([0x22; 32])).open_keys();
        assert_eq!(opened(globex.store(), acme(), &dev(), 2, &blob), Err(Refusal::Unreadable), "globex's store key");
        assert_eq!(opened(&arr(&hex(KAT_KEY_SECRETS)), acme(), &dev(), 2, &blob), Err(Refusal::Unreadable), "acme's secrets key");
        for i in 0..blob.len() {
            let mut changed = blob.clone();
            changed[i] ^= 0x01;
            assert_eq!(opened(&store(), acme(), &dev(), 2, &changed), Err(Refusal::Unreadable), "byte {i}");
        }
        for len in 0..blob.len() {
            assert_eq!(opened(&store(), acme(), &dev(), 2, &blob[..len]), Err(Refusal::Unreadable), "cut to {len} bytes");
        }
        let mut longer = blob.clone();
        longer.push(0);
        assert_eq!(opened(&store(), acme(), &dev(), 2, &longer), Err(Refusal::Unreadable), "one byte more");
        // A blob that opens and holds a key of another length, as anyone with the store key could seal, is refused the same way.
        for len in [0, 31, 33, 64] {
            let other = aead::seal(&store(), &box_key_nonce(), &aad(acme(), &dev(), 2), &vec![0x30; len]);
            assert_eq!(opened(&store(), acme(), &dev(), 2, &other), Err(Refusal::Unreadable), "{len} bytes");
        }
    }

    #[test]
    fn a_box_key_prints_nothing_of_itself() {
        assert_eq!((format!("{:?}", key()), format!("{:#?}", key())), ("BoxKey(..)".to_string(), "BoxKey(..)".to_string()));
    }

    #[test]
    fn a_box_is_named_as_a_resource_is() {
        let longest = "a".repeat(32);
        for name in ["dev", "a", "0", "x-browser", longest.as_str()] {
            assert_eq!(check_box(name), Ok(()), "{name}");
        }
        let longer = "a".repeat(33);
        for name in ["", "Dev", "-x", "a/b", "a.b", "a_b", "dév", "\x1b[2J", longer.as_str()] {
            assert_eq!(check_box(name), Err(Refusal::BadBox), "{name:?}");
        }
        assert_eq!(Refusal::BadBox.to_string(), "that isn't a box: 1 to 32 of a-z, 0-9 and -");
    }
}
