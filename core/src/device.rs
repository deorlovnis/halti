//! The public keys and signatures of a paired device, in the forms a phone's keystore gives them.
//! No workspace key is among them: these only check what a device says.
//!
//! - A public key is a P-256 key's SubjectPublicKeyInfo in DER, with the curve named and the point
//!   uncompressed: always `SPKI_LEN` bytes, `SPKI_PREFIX` then the 65 bytes of the point (0x04, x,
//!   y). Every other encoding of the same key is refused, so a key has one encoding, and its
//!   fingerprint one value.
//! - A signature is ECDSA over P-256 with SHA-256, as DER `SEQUENCE { r INTEGER, s INTEGER }`, in
//!   strict DER. Either s of a pair is accepted: a keystore gives whichever its algorithm made, and
//!   what a device signs is never compared as a signature, only checked.
//! - A fingerprint is the SHA-256 of the key's 91 bytes.

use p256::ecdsa::signature::Verifier;
use sha2::{Digest, Sha256};

use crate::refusal::Refusal;

/// The DER of a P-256 public key's SubjectPublicKeyInfo up to its point: the algorithm
/// (id-ecPublicKey), the curve (prime256v1), and the head of the 66-byte bit string.
pub const SPKI_PREFIX: [u8; 26] =
    [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];

/// The length of a public key: the prefix and the uncompressed point.
pub const SPKI_LEN: usize = 91;

/// The longest DER signature: two 33-byte integers and their heads.
pub const SIGNATURE_MAX: usize = 72;

/// A device's signing key: checks what the device signed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceKey(p256::ecdsa::VerifyingKey);

impl DeviceKey {
    /// From the key's 91 bytes. Refuses any other length, prefix or point form, and a point not on
    /// the curve.
    pub fn from_spki(der: &[u8]) -> Result<DeviceKey, Refusal> {
        let point = point(der)?;
        p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map(DeviceKey).map_err(|_| Refusal::Unreadable)
    }

    /// Holds for exactly this message and a signature this key made over it.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Refusal> {
        if signature.len() > SIGNATURE_MAX {
            return Err(Refusal::Unreadable);
        }
        let signature = p256::ecdsa::Signature::from_der(signature).map_err(|_| Refusal::Unreadable)?;
        self.0.verify(message, &signature).map_err(|_| Refusal::Unreadable)
    }
}

/// Checks a key that only agrees on keys, a device's second key or a machine's: the same 91 bytes,
/// with a point on the curve.
pub fn check_agreement_key(der: &[u8]) -> Result<(), Refusal> {
    p256::PublicKey::from_sec1_bytes(point(der)?).map(drop).map_err(|_| Refusal::Unreadable)
}

/// The SHA-256 of the key's bytes, whatever they are.
pub fn fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// The uncompressed point at the end of a key in the one encoding taken.
fn point(der: &[u8]) -> Result<&[u8], Refusal> {
    match der.split_at_checked(SPKI_PREFIX.len()) {
        Some((prefix, point)) if der.len() == SPKI_LEN && prefix == SPKI_PREFIX && point[0] == 0x04 => Ok(point),
        _ => Err(Refusal::Unreadable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vectors::{RFC6979_P256_SHA256, hex};

    /// RFC 6979 A.2.5's key, as a device would give it: the prefix, then its published point.
    fn rfc_key() -> Vec<u8> {
        [SPKI_PREFIX.as_slice(), &hex(RFC6979_P256_SHA256[0].public)].concat()
    }

    /// DER of one integer: a 0x00 first when the high bit is set, no leading zeros otherwise.
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let mut value: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
        if value.first().is_none_or(|b| b & 0x80 != 0) {
            value.insert(0, 0);
        }
        [vec![0x02, value.len() as u8], value].concat()
    }

    fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let body = [integer(r), integer(s)].concat();
        [vec![0x30, body.len() as u8], body].concat()
    }

    #[test]
    fn the_prefix_is_the_standard_head_of_a_p256_key() {
        assert_eq!(SPKI_PREFIX.as_slice(), hex("3059301306072a8648ce3d020106082a8648ce3d030107034200"));
        assert_eq!(SPKI_PREFIX.len() + 65, SPKI_LEN);
        // A key's fingerprint, as `openssl pkey -pubin -outform DER | sha256sum` gives it for this key.
        assert_eq!(fingerprint(&rfc_key()).as_slice(), hex("5a7a78cca4a0f420d9bc62bb669c3c2759e39f723d3ae10dcbe0f0815a07ecd4"));
    }

    #[test]
    fn the_published_signatures_verify_in_der() {
        let key = DeviceKey::from_spki(&rfc_key()).unwrap();
        for v in RFC6979_P256_SHA256 {
            let signature = der(&hex(v.r), &hex(v.s));
            assert_eq!(key.verify(&hex(v.msg), &signature), Ok(()), "message {}", v.msg);
            // Another message, or any changed byte, fails.
            assert_eq!(key.verify(b"other", &signature), Err(Refusal::Unreadable));
            for i in 0..signature.len() {
                let mut changed = signature.clone();
                changed[i] ^= 0x01;
                assert_eq!(key.verify(&hex(v.msg), &changed), Err(Refusal::Unreadable), "byte {i}");
            }
        }
        // The first of them is DER exactly as written here: 72 bytes, both integers with a 0x00 first.
        let first = der(&hex(RFC6979_P256_SHA256[0].r), &hex(RFC6979_P256_SHA256[0].s));
        assert_eq!((first.len(), &first[..5]), (72, [0x30, 0x46, 0x02, 0x21, 0x00].as_slice()));
    }

    #[test]
    fn a_signature_that_is_not_strict_der_is_refused() {
        let key = DeviceKey::from_spki(&rfc_key()).unwrap();
        let v = &RFC6979_P256_SHA256[1];
        let (r, s, msg) = (hex(v.r), hex(v.s), hex(v.msg));
        assert_eq!(key.verify(&msg, &der(&r, &s)), Ok(()));
        // The 64 bytes of r and s with no DER around them.
        assert_eq!(key.verify(&msg, &[r.clone(), s.clone()].concat()), Err(Refusal::Unreadable));
        // s with a zero byte it doesn't need: BER, not DER.
        let padded = [vec![0x30, 0x46], integer(&r), vec![0x02, 0x21, 0x00], s.clone()].concat();
        assert_eq!(key.verify(&msg, &padded), Err(Refusal::Unreadable));
        // Bytes after the sequence, and a sequence that claims more than there is.
        assert_eq!(key.verify(&msg, &[der(&r, &s), vec![0]].concat()), Err(Refusal::Unreadable));
        let mut long = der(&r, &s);
        long[1] += 1;
        assert_eq!(key.verify(&msg, &long), Err(Refusal::Unreadable));
        assert_eq!(key.verify(&msg, &[]), Err(Refusal::Unreadable));
        assert_eq!(key.verify(&msg, &[0x30; 80]), Err(Refusal::Unreadable));
    }

    #[test]
    fn either_s_of_a_pair_is_accepted() {
        let key = DeviceKey::from_spki(&rfc_key()).unwrap();
        let v = &RFC6979_P256_SHA256[0];
        // The order of the group less s: the other signature with the same r.
        let order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let s = hex(v.s);
        let (mut twin, mut borrow) = (vec![0u8; 32], 0i16);
        for i in (0..32).rev() {
            let digit = i16::from(order[i]) - i16::from(s[i]) - borrow;
            borrow = i16::from(digit < 0);
            twin[i] = digit.rem_euclid(256) as u8;
        }
        assert_ne!(twin, s);
        assert_eq!(key.verify(&hex(v.msg), &der(&hex(v.r), &twin)), Ok(()));
    }

    #[test]
    fn a_key_in_another_encoding_is_refused() {
        let good = rfc_key();
        assert!(DeviceKey::from_spki(&good).is_ok());
        assert_eq!(check_agreement_key(&good), Ok(()));
        let point = &good[SPKI_PREFIX.len()..];
        // The bare point, the key with a byte more or less, and the compressed form.
        let mut compressed = [SPKI_PREFIX.as_slice(), &[0x02 | (point[64] & 1)], &point[1..33]].concat();
        compressed[1] = 0x39;
        let mut off_curve = good.clone();
        off_curve[90] ^= 0x01;
        let mut other_curve = good.clone();
        other_curve[24] ^= 0x01;
        for bad in [point.to_vec(), [good.as_slice(), &[0]].concat(), good[..90].to_vec(), compressed, off_curve, other_curve, vec![], vec![0; SPKI_LEN]] {
            assert_eq!(DeviceKey::from_spki(&bad), Err(Refusal::Unreadable), "{bad:02x?}");
            assert_eq!(check_agreement_key(&bad), Err(Refusal::Unreadable), "{bad:02x?}");
        }
    }
}
