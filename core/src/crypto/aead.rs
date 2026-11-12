//! Sealing under a key both sides already hold: AES-256-GCM in a blob that names its format.
//!
//! ```text
//! blob = 0x01 ‖ nonce (12) ‖ ciphertext ‖ tag (16)
//! ```
//!
//! The format byte is authenticated too: it is put in front of the caller's associated data. The
//! shortest blob is 29 bytes.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use zeroize::Zeroizing;

use crate::refusal::Refusal;

/// The one blob format so far.
const FORMAT: u8 = 0x01;

/// Seals `plaintext` under `key`, bound to `aad`, into a blob that names its format.
///
/// `nonce` is 12 fresh random bytes, never used twice under one key: a repeat gives away the
/// plaintexts and lets blobs be forged. One key seals at most 2^32 times with random nonces
/// (NIST SP 800-38D section 8.3). Neither is checked here; both are the caller's to keep.
///
/// Panics if `plaintext` is over the cipher's limit of about 64 GiB.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(1 + nonce.len() + plaintext.len() + 16);
    blob.push(FORMAT);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&raw_seal(key, nonce, &framed(aad), plaintext));
    blob
}

/// Opens a blob `seal` made, or refuses without saying why: a wrong key, other associated data, an
/// unknown format, a cut or a changed byte all look the same.
pub fn open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    let [FORMAT, rest @ ..] = blob else { return Err(Refusal::Unreadable) };
    let Some((nonce, sealed)) = rest.split_first_chunk::<12>() else { return Err(Refusal::Unreadable) };
    raw_open(key, nonce, &framed(aad), sealed)
}

/// The associated data as it is authenticated: the format byte, then the caller's.
fn framed(aad: &[u8]) -> Vec<u8> {
    [[FORMAT].as_slice(), aad].concat()
}

/// AES-256-GCM itself: the ciphertext, then its 16-byte tag.
///
/// Panics if `plaintext` is over the cipher's limit of about 64 GiB.
pub(super) fn raw_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    Aes256Gcm::new(key.into()).encrypt(nonce.into(), Payload { msg: plaintext, aad }).expect("the plaintext is within the cipher's limit")
}

/// Checks the tag, then decrypts. Nothing is decrypted if the tag is wrong.
pub(super) fn raw_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    Aes256Gcm::new(key.into()).decrypt(nonce.into(), Payload { msg: sealed, aad }).map(Zeroizing::new).map_err(|_| Refusal::Unreadable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vectors::{AES_256_GCM, KAT_AEAD_BLOB, arr, hex, seq};

    fn key() -> [u8; 32] {
        arr(&seq(0x40, 32))
    }

    fn nonce() -> [u8; 12] {
        arr(&seq(0x70, 12))
    }

    #[test]
    fn aes_256_gcm_matches_wycheproof() {
        for v in AES_256_GCM {
            let (key, iv, aad, msg, ct, tag) = (arr(&hex(v.key)), arr(&hex(v.iv)), hex(v.aad), hex(v.msg), hex(v.ct), hex(v.tag));
            let sealed = [ct.as_slice(), tag.as_slice()].concat();
            let made = raw_seal(&key, &iv, &aad, &msg);
            let opened = raw_open(&key, &iv, &aad, &sealed);
            if v.valid {
                assert_eq!(made, sealed, "tcId {}", v.tc);
                assert_eq!(*opened.unwrap(), msg, "tcId {}", v.tc);
            } else {
                // The ciphertext is right and the tag is not.
                assert_eq!(made[..ct.len()], ct, "tcId {}", v.tc);
                assert_ne!(made[ct.len()..], tag, "tcId {}", v.tc);
                assert_eq!(opened.unwrap_err(), Refusal::Unreadable, "tcId {}", v.tc);
            }
        }
    }

    #[test]
    fn a_sealed_blob_is_unchanged() {
        let blob = seal(&key(), &nonce(), b"acme", b"a secret");
        assert_eq!(blob, hex(KAT_AEAD_BLOB));
        assert_eq!(blob.len(), 1 + 12 + 8 + 16);
        assert_eq!(blob[0], 0x01, "the format");
        assert_eq!(blob[1..13], nonce(), "the nonce, as given");
        assert_eq!(open(&key(), b"acme", &blob).unwrap().as_slice(), b"a secret");
    }

    #[test]
    fn a_sealed_blob_opens_with_its_key_and_associated_data() {
        for len in [0, 1, 4096] {
            let plaintext = seq(0x01, len);
            for aad in [b"".as_slice(), b"globex".as_slice()] {
                let blob = seal(&key(), &nonce(), aad, &plaintext);
                assert_eq!(blob.len(), 29 + len);
                assert_eq!(*open(&key(), aad, &blob).unwrap(), plaintext, "{len} bytes");
            }
        }
    }

    #[test]
    fn any_changed_byte_or_length_of_a_sealed_blob_is_refused() {
        let blob = seal(&key(), &nonce(), b"acme", b"a secret");
        assert!(open(&key(), b"acme", &blob).is_ok());
        for i in 0..blob.len() {
            for bit in [0x01, 0x80] {
                let mut changed = blob.clone();
                changed[i] ^= bit;
                assert_eq!(open(&key(), b"acme", &changed).unwrap_err(), Refusal::Unreadable, "byte {i}");
            }
        }
        for len in 0..blob.len() {
            assert_eq!(open(&key(), b"acme", &blob[..len]).unwrap_err(), Refusal::Unreadable, "cut to {len} bytes");
        }
        let mut longer = blob.clone();
        longer.push(0);
        assert_eq!(open(&key(), b"acme", &longer).unwrap_err(), Refusal::Unreadable, "one byte more");
        // A format this does not know is refused whatever follows it.
        for format in [0x00, 0x02, 0xff] {
            let mut other = blob.clone();
            other[0] = format;
            assert_eq!(open(&key(), b"acme", &other).unwrap_err(), Refusal::Unreadable, "format {format}");
        }
    }

    #[test]
    fn wrong_associated_data_or_key_does_not_open() {
        let blob = seal(&key(), &nonce(), b"acme", b"a secret");
        for aad in ["globex", "", "acm", "acme ", "\x01acme"] {
            assert_eq!(open(&key(), aad.as_bytes(), &blob).unwrap_err(), Refusal::Unreadable, "{aad:?}");
        }
        let mut other = key();
        other[31] ^= 0x01;
        assert_eq!(open(&other, b"acme", &blob).unwrap_err(), Refusal::Unreadable);
        assert_eq!(open(&[0; 32], b"acme", &blob).unwrap_err(), Refusal::Unreadable);
        // What `seal` makes is not the cipher's bare output under the caller's associated data: the format byte is bound in too.
        assert_eq!(raw_open(&key(), &nonce(), b"acme", &blob[13..]).unwrap_err(), Refusal::Unreadable);
        assert_eq!(raw_open(&key(), &nonce(), b"\x01acme", &blob[13..]).unwrap().as_slice(), b"a secret");
    }
}
