//! Sealed text between a machine and a phone: what an agent asks and the answer it gets,
//! hidden from the hub. The hub carries the sealed bytes and can read none of them; text it makes
//! up, or a record whose clear fields it changed, does not open.
//!
//! - A question, a notice and a receipt are sealed by the machine key to one device's second key.
//!   Only that device opens it, and only under the machine key it compared.
//! - An answer is sealed by the device's second key to the question's reply key: a key the keeper
//!   makes for that one question and holds in memory only, so a later copy of the machine key's
//!   file opens no answer.
//!
//! This layer knows no record. The record hands it its clear fields as associated data and its
//! secret fields as the plaintext.
//!
//! The construction is HPKE (RFC 9180, `crypto::hpke`): mode_auth, DHKEM(P-256, HKDF-SHA256),
//! HKDF-SHA256, AES-256-GCM, one message per seal. Byte for byte:
//!
//! ```text
//! info   = the kind's label, its ASCII bytes and nothing else:
//!          halti-sealed-question-v1, halti-sealed-notice-v1, halti-sealed-receipt-v1 or
//!          halti-sealed-answer-v1
//! aad    = the record's clear fields, exactly the bytes the record carries them as
//! sealed = enc (65: the ephemeral public key, 0x04 ‖ x ‖ y) ‖ ciphertext ‖ tag (16)
//! ```
//!
//! The label in the info keeps the kinds apart: a question never opens as a notice, nor an answer
//! as a question. A public key travels and is stored as its 91-byte SubjectPublicKeyInfo
//! (`device::SPKI_PREFIX`), as at pairing; inside HPKE it is the 65-byte point.
//!
//! The known answers both the machine's tests and the app's check are in
//! tests/fixtures/sealed-text-vectors.json in this repository.

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::hpke::{self, ENC_LEN, TAG_LEN};
use crate::device::{self, SPKI_LEN, SPKI_PREFIX};
use crate::refusal::Refusal;

/// What a sealed text is. Its label is the HPKE info.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A question from an agent, machine to phone.
    Question,
    /// A notice that an agent waits, machine to phone.
    Notice,
    /// The machine's receipt for an answer, machine to phone.
    Receipt,
    /// The answer, phone to the question's reply key.
    Answer,
}

impl Kind {
    /// The label, which is the whole HPKE info.
    pub const fn label(self) -> &'static str {
        match self {
            Kind::Question => "halti-sealed-question-v1",
            Kind::Notice => "halti-sealed-notice-v1",
            Kind::Receipt => "halti-sealed-receipt-v1",
            Kind::Answer => "halti-sealed-answer-v1",
        }
    }
}

/// The public half of a P-256 key for key agreement: a device's second key, the machine key, or a
/// question's reply key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AgreementKey([u8; ENC_LEN]);

impl AgreementKey {
    /// From its 91 bytes, in the one encoding taken at pairing (`device::check_agreement_key`).
    pub fn from_spki(der: &[u8]) -> Result<AgreementKey, Refusal> {
        device::check_agreement_key(der)?;
        Ok(AgreementKey(der[SPKI_PREFIX.len()..].try_into().expect("a checked key ends in its 65-byte point")))
    }

    /// Its 91 bytes.
    pub fn spki(&self) -> [u8; SPKI_LEN] {
        let mut der = [0; SPKI_LEN];
        der[..SPKI_PREFIX.len()].copy_from_slice(&SPKI_PREFIX);
        der[SPKI_PREFIX.len()..].copy_from_slice(&self.0);
        der
    }
}

/// The PKCS#8 DER of a P-256 private key, in the one form taken, up to its scalar: version 0, the
/// algorithm (id-ecPublicKey, prime256v1), then an ECPrivateKey of version 1 with the 32-byte
/// scalar.
const PKCS8_PREFIX: [u8; 36] = [
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d,
    0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
];

/// What comes between the scalar and the public point: the head of the `[1]` public key.
const PKCS8_MIDDLE: [u8; 5] = [0xa1, 0x44, 0x03, 0x42, 0x00];

/// The length of the whole: prefix, scalar, middle, point.
const PKCS8_LEN: usize = 36 + 32 + 5 + ENC_LEN;

/// A P-256 private key for key agreement, held in software: the machine key, or a reply key. Wiped
/// on drop, as far as the language allows; it can't be cloned, and printing it shows nothing.
pub struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    /// The machine key as its file holds it: PKCS#8 DER with the curve named and the public key
    /// included, as `halti hub join` writes it. Refuses any other form, a scalar out of range, and a
    /// public key that isn't the scalar's.
    pub fn from_pkcs8(der: &[u8]) -> Result<SecretKey, Refusal> {
        if der.len() != PKCS8_LEN || der[..36] != PKCS8_PREFIX || der[68..73] != PKCS8_MIDDLE {
            return Err(Refusal::Unreadable);
        }
        let key = SecretKey::from_scalar(&Zeroizing::new(der[36..68].try_into().expect("32 bytes")))?;
        if key.public().0 != der[73..] {
            return Err(Refusal::Unreadable);
        }
        Ok(key)
    }

    /// From the 32 bytes of its scalar, big-endian. Refuses zero and anything not below the order.
    pub fn from_scalar(bytes: &[u8; 32]) -> Result<SecretKey, Refusal> {
        hpke::public_of(bytes)?;
        Ok(SecretKey(Zeroizing::new(*bytes)))
    }

    /// The key that 32 random bytes the caller drew make: DeriveKeyPair of RFC 9180 section 7.1.3.
    pub fn derive(ikm: &[u8; 32]) -> SecretKey {
        SecretKey(hpke::derive_key_pair(ikm))
    }

    /// Its public half.
    pub fn public(&self) -> AgreementKey {
        AgreementKey(hpke::public_of(&self.0).expect("a held key is in range"))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// The key one question's answer is sealed to. The keeper makes it as it makes the question, puts
/// its public half in the question's sealed fields, holds it in memory only and drops it when the
/// question closes. It opens answers and nothing else.
#[derive(Debug)]
pub struct ReplyKey(SecretKey);

impl ReplyKey {
    /// A new reply key from 32 fresh random bytes the caller drew.
    pub fn make(ikm: &[u8; 32]) -> ReplyKey {
        ReplyKey(SecretKey::derive(ikm))
    }

    /// Its public half, for the question.
    pub fn public(&self) -> AgreementKey {
        self.0.public()
    }

    /// Opens an answer sealed to this key by the device whose second key is `device`, over the
    /// answer's clear fields `aad`.
    pub fn open(&self, device: &AgreementKey, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Refusal> {
        open(Kind::Answer, &self.0, device, aad, sealed)
    }
}

/// Seals `plaintext` as `kind`, by `from` to `to`, bound to `aad`. The machine seals a question, a
/// notice or a receipt by its machine key to a device's second key; the phone seals an answer by
/// its second key to the reply key.
///
/// `ikm_e` is 32 fresh random bytes, never used twice: they make the ephemeral key. Refuses a key
/// that is not a key.
pub fn seal(kind: Kind, from: &SecretKey, to: &AgreementKey, aad: &[u8], plaintext: &[u8], ikm_e: &[u8; 32]) -> Result<Vec<u8>, Refusal> {
    let (enc, ct) = hpke::seal_auth(&to.0, &from.0, ikm_e, kind.label().as_bytes(), aad, plaintext)?;
    Ok([enc.as_slice(), &ct].concat())
}

/// Opens what `seal` sealed as `kind`, by `from` to `to`'s public half, over `aad`. Refuses,
/// without saying why, another kind, sender, recipient or clear field, and any changed byte.
pub fn open(kind: Kind, to: &SecretKey, from: &AgreementKey, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    let Some((enc, ct)) = sealed.split_first_chunk::<ENC_LEN>() else { return Err(Refusal::Unreadable) };
    if ct.len() < TAG_LEN {
        return Err(Refusal::Unreadable);
    }
    hpke::open_auth(enc, &to.0, &from.0, kind.label().as_bytes(), aad, ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (SecretKey, SecretKey) {
        (SecretKey::derive(&[0x10; 32]), SecretKey::derive(&[0x30; 32]))
    }

    #[test]
    fn the_labels_are_unchanged_and_apart() {
        let all = [Kind::Question, Kind::Notice, Kind::Receipt, Kind::Answer];
        let labels: Vec<&str> = all.iter().map(|kind| kind.label()).collect();
        assert_eq!(labels, ["halti-sealed-question-v1", "halti-sealed-notice-v1", "halti-sealed-receipt-v1", "halti-sealed-answer-v1"]);
        // Nor is any the label of a record or of a signed answer.
        for label in labels {
            assert!(!["halti-question-v1", "halti-answer-v1", "halti-approval-v1"].contains(&label));
        }
    }

    #[test]
    fn a_key_reads_back_in_its_one_encoding() {
        let (machine, _) = keys();
        let public = machine.public();
        assert_eq!(AgreementKey::from_spki(&public.spki()), Ok(public));
        assert_eq!(public.spki()[..SPKI_PREFIX.len()], SPKI_PREFIX);
        let mut off_curve = public.spki();
        off_curve[90] ^= 0x01;
        for bad in [&public.spki()[..90], &public.spki()[SPKI_PREFIX.len()..], &off_curve[..], b"".as_slice()] {
            assert_eq!(AgreementKey::from_spki(bad), Err(Refusal::Unreadable));
        }
    }

    #[test]
    fn a_machine_key_reads_only_in_the_form_halti_writes() {
        let (machine, _) = keys();
        let der = [PKCS8_PREFIX.as_slice(), machine.0.as_slice(), &PKCS8_MIDDLE, &machine.public().0].concat();
        assert_eq!(der.len(), PKCS8_LEN);
        assert_eq!(der[2] as usize, PKCS8_LEN - 3, "the outer length");
        assert_eq!(SecretKey::from_pkcs8(&der).unwrap().public(), machine.public());
        // Another key's point, a scalar out of range, a byte more or less, and a changed head.
        let mut other_point = der.clone();
        other_point[73..].copy_from_slice(&SecretKey::derive(&[0x20; 32]).public().0);
        let mut zero = der.clone();
        zero[36..68].fill(0);
        let mut head = der.clone();
        head[34] = 0x05;
        for bad in [other_point, zero, head, der[..PKCS8_LEN - 1].to_vec(), [der.as_slice(), &[0]].concat()] {
            assert_eq!(SecretKey::from_pkcs8(&bad).unwrap_err(), Refusal::Unreadable);
        }
        assert_eq!(SecretKey::from_scalar(&[0; 32]).unwrap_err(), Refusal::Unreadable);
        assert_eq!(SecretKey::from_scalar(&[0xff; 32]).unwrap_err(), Refusal::Unreadable);
        assert_eq!(format!("{machine:?}"), "SecretKey(..)");
    }

    #[test]
    fn sealed_text_is_the_ephemeral_key_then_the_ciphertext() {
        let (machine, device) = keys();
        let sealed = seal(Kind::Notice, &machine, &device.public(), b"clear", b"", &[0x70; 32]).unwrap();
        assert_eq!(sealed.len(), ENC_LEN + TAG_LEN);
        assert_eq!(sealed[0], 0x04);
        assert_eq!(open(Kind::Notice, &device, &machine.public(), b"clear", &sealed).unwrap().as_slice(), b"");
        for len in [0, 1, ENC_LEN, ENC_LEN + TAG_LEN - 1] {
            assert_eq!(open(Kind::Notice, &device, &machine.public(), b"clear", &sealed[..len]).unwrap_err(), Refusal::Unreadable, "{len} bytes");
        }
    }
}
