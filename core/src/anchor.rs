//! Where a workspace's pin is kept: three hashes of what the workspace is on disk, and a version
//! that only rises. Opening checks the files against the pin before the key holder is asked.
//!
//! ```text
//! pin  = 0x01 (format) ‖ version (8, big-endian) ‖ key_ref (48) ‖ public_key (48) ‖ state (48)
//! hash = SHA-384(VERSION ‖ PIN_ID ‖ length of the label (1) ‖ label ‖ ws (16) ‖ each part as its length (4, big-endian) ‖ part)
//! ```
//!
//! The pin protects as much as its anchor does. One that a program running as the user can write
//! keeps out accidents and other users, and nothing that program does: it rewrites the pin to match
//! whatever it put down. Against it, a wrap is refused only by the key holder's commitment
//! (`holder`).

use anyhow::Result;
use sha2::{Digest, Sha384};

use crate::crypto::kdf::{PIN_ID, PIN_KEY_REF, PIN_PUBLIC_KEY, PIN_STATE, VERSION};
use crate::holder::{KeyKind, KeyRef};
use crate::ids::{WsId, WsName};
use crate::key::PublicKey;
use crate::platform::Adapter;
use crate::refusal::Refusal;

/// The one pin format so far: the last byte of `PIN_ID`.
const FORMAT: u8 = 0x01;

/// What the anchor keeps for a workspace. Hashes, not secrets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pin {
    pub version: u64,
    /// Of the key holder's kind and its key ref.
    pub key_ref: [u8; 48],
    /// Of the public key the holder gives.
    pub public_key: [u8; 48],
    /// Of the name, the wrap, the manifest and the policy.
    pub state: [u8; 48],
}

impl Pin {
    /// The length of its bytes.
    pub const LEN: usize = 153;

    pub fn to_bytes(self) -> [u8; Pin::LEN] {
        let mut bytes = [0; Pin::LEN];
        bytes[0] = FORMAT;
        bytes[1..9].copy_from_slice(&self.version.to_be_bytes());
        bytes[9..57].copy_from_slice(&self.key_ref);
        bytes[57..105].copy_from_slice(&self.public_key);
        bytes[105..].copy_from_slice(&self.state);
        bytes
    }

    /// Refuses any other length or format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Pin, Refusal> {
        let [FORMAT, rest @ ..] = bytes else { return Err(Refusal::Unreadable) };
        let Some((version, rest)) = rest.split_first_chunk::<8>() else { return Err(Refusal::Unreadable) };
        let Some((key_ref, rest)) = rest.split_first_chunk::<48>() else { return Err(Refusal::Unreadable) };
        let Some((public_key, state)) = rest.split_first_chunk::<48>() else { return Err(Refusal::Unreadable) };
        let state: [u8; 48] = state.try_into().map_err(|_| Refusal::Unreadable)?;
        Ok(Pin { version: u64::from_be_bytes(*version), key_ref: *key_ref, public_key: *public_key, state })
    }
}

/// Where pins are kept. An anchor that a program running as the user can write lacks rollback-proof
/// and says so in its label: against that program it proves nothing. Core only ever advances a pin
/// by exactly one.
pub trait Anchor: Adapter {
    /// The workspace's pin, or none if it has none.
    fn read(&self, ws: WsId) -> Result<Option<Pin>>;

    /// Keeps `pin` in place of the one kept. Refuses a version that is not greater than the one
    /// kept, or than zero when none is.
    fn advance(&self, ws: WsId, pin: &Pin) -> Result<()>;

    /// Deletes the pin; a missing one is not an error.
    fn forget(&self, ws: WsId) -> Result<()>;
}

/// The hash of the key holder's kind and key ref.
pub(crate) fn key_ref_hash(ws: WsId, kind: KeyKind, key: &KeyRef) -> [u8; 48] {
    hash(PIN_KEY_REF, ws, &[[kind.tag()].as_slice(), key.0.as_slice()])
}

/// The hash of the public key.
pub(crate) fn public_key_hash(ws: WsId, public: &PublicKey) -> [u8; 48] {
    hash(PIN_PUBLIC_KEY, ws, &[public.to_bytes().as_slice()])
}

/// The hash of the name, the wrap, the manifest and the policy. A file that is not there counts as
/// empty.
pub(crate) fn state_hash(ws: WsId, name: &WsName, wrap: &[u8], manifest: &[u8], policy: &[u8]) -> [u8; 48] {
    hash(PIN_STATE, ws, &[name.as_str().as_bytes(), wrap, manifest, policy])
}

/// SHA-384 over the version string, the pin's id, the label, the workspace and each part with its
/// length, so no two lists of parts give the same bytes.
///
/// Panics if a part is 4 GiB or longer.
fn hash(label: &[u8], ws: WsId, parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(VERSION);
    hasher.update(PIN_ID);
    hasher.update([u8::try_from(label.len()).expect("a label is shorter than 256 bytes")]);
    hasher.update(label);
    hasher.update(ws.as_bytes());
    for part in parts {
        hasher.update(u32::try_from(part.len()).expect("a part is shorter than 4 GiB").to_be_bytes());
        hasher.update(part);
    }
    let mut out = [0; 48];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::crypto::kem::DecapKey;
    use crate::crypto::vectors::{
        KAT_HARDWARE_WRAP, KAT_PASSPHRASE_RECORD, KAT_PIN, KAT_PIN_KEY_REF, KAT_PIN_PUBLIC_KEY, KAT_PIN_STATE, hardware_seed, hex, recovery_seed, ws_bytes,
    };

    const GLOBEX: WsId = WsId::from_bytes([2; 16]);

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn name(text: &str) -> WsName {
        WsName::parse(text).unwrap()
    }

    fn public_of(seed: [u8; 96]) -> PublicKey {
        DecapKey::from_seed(Zeroizing::new(seed)).public()
    }

    /// The known answers' passphrase record, as the key holder's key ref.
    fn record() -> KeyRef {
        KeyRef(hex(KAT_PASSPHRASE_RECORD))
    }

    #[test]
    fn the_pin_of_a_new_workspace_is_unchanged() {
        let pin = Pin {
            version: 1,
            key_ref: key_ref_hash(acme(), KeyKind::Passphrase, &record()),
            public_key: public_key_hash(acme(), &public_of(hardware_seed())),
            state: state_hash(acme(), &name("acme"), &hex(KAT_HARDWARE_WRAP), b"", b""),
        };
        assert_eq!(pin.key_ref.as_slice(), hex(KAT_PIN_KEY_REF));
        assert_eq!(pin.public_key.as_slice(), hex(KAT_PIN_PUBLIC_KEY));
        assert_eq!(pin.state.as_slice(), hex(KAT_PIN_STATE));
        assert_eq!(pin.to_bytes().as_slice(), hex(KAT_PIN));
        // The public key hashed is the one the record carries in clear.
        assert_eq!(public_key_hash(acme(), &PublicKey::from_bytes(&record().0[2..1636]).unwrap()), pin.public_key);
    }

    #[test]
    fn a_pin_reads_back_from_its_153_bytes() {
        let pin = Pin { version: 0x0102030405060708, key_ref: [0x11; 48], public_key: [0x22; 48], state: [0x33; 48] };
        let bytes = pin.to_bytes();
        assert_eq!(bytes.len(), 153);
        assert_eq!(bytes[..9], [0x01, 1, 2, 3, 4, 5, 6, 7, 8], "the format, then the version");
        assert_eq!(bytes[9..57], [0x11; 48], "the key ref's hash");
        assert_eq!(bytes[57..105], [0x22; 48], "the public key's");
        assert_eq!(bytes[105..], [0x33; 48], "the state's");
        assert_eq!(Pin::from_bytes(&bytes), Ok(pin));
        let last = Pin { version: u64::MAX, ..pin };
        assert_eq!(Pin::from_bytes(&last.to_bytes()), Ok(last));
        let known = hex(KAT_PIN);
        assert_eq!(Pin::from_bytes(&known).unwrap().to_bytes().as_slice(), known);
    }

    #[test]
    fn a_pin_of_another_format_or_length_is_refused() {
        let bytes = Pin { version: 1, key_ref: [1; 48], public_key: [2; 48], state: [3; 48] }.to_bytes();
        for len in 0..bytes.len() {
            assert_eq!(Pin::from_bytes(&bytes[..len]), Err(Refusal::Unreadable), "cut to {len} bytes");
        }
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(Pin::from_bytes(&longer), Err(Refusal::Unreadable), "one byte more");
        for format in [0x00, 0x02, 0xff] {
            let mut other = bytes;
            other[0] = format;
            assert_eq!(Pin::from_bytes(&other), Err(Refusal::Unreadable), "format {format}");
        }
    }

    #[test]
    fn each_pin_hash_changes_with_its_workspace_and_each_input() {
        let (key, wrap, public) = (record(), hex(KAT_HARDWARE_WRAP), public_of(hardware_seed()));
        let hashes = |ws: WsId| [key_ref_hash(ws, KeyKind::Passphrase, &key), public_key_hash(ws, &public), state_hash(ws, &name("acme"), &wrap, b"", b"")];
        let base = hashes(acme());
        let mut all = base.to_vec();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 3, "the three hashes differ, though two of them cover the same public key");
        for (one, other) in base.iter().zip(hashes(GLOBEX)) {
            assert_ne!(*one, other, "another workspace");
        }

        // The key ref's hash: the kind, and any change to the key ref.
        let mut changed = key.clone();
        changed.0[1700] ^= 0x01;
        let cut = KeyRef(key.0[..1854].to_vec());
        for other in [key_ref_hash(acme(), KeyKind::Soft, &key), key_ref_hash(acme(), KeyKind::Passphrase, &changed), key_ref_hash(acme(), KeyKind::Passphrase, &cut)] {
            assert_ne!(other, base[0]);
        }
        // The public key's hash: another key.
        assert_ne!(public_key_hash(acme(), &public_of(recovery_seed())), base[1]);
        // The state's: the name, the wrap, a manifest or a policy where there was none.
        let mut other_wrap = wrap.clone();
        other_wrap[1682] ^= 0x01;
        for other in [
            state_hash(acme(), &name("globex"), &wrap, b"", b""),
            state_hash(acme(), &name("acme"), &other_wrap, b"", b""),
            state_hash(acme(), &name("acme"), &wrap, b"manifest", b""),
            state_hash(acme(), &name("acme"), &wrap, b"", b"policy"),
        ] {
            assert_ne!(other, base[2]);
        }
        // Each part carries its length, so moving bytes from one part to the next is a change too.
        assert_ne!(state_hash(acme(), &name("acme"), &wrap, b"ab", b""), state_hash(acme(), &name("acme"), &wrap, b"a", b"b"));
        assert_ne!(state_hash(acme(), &name("acme"), &wrap, b"policy", b""), state_hash(acme(), &name("acme"), &wrap, b"", b"policy"));
    }
}
