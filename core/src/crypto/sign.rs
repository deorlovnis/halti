//! Policy signatures: ECDSA over P-256 with SHA-256 and the deterministic nonce of RFC 6979
//! (FIPS 186-5 section 6.3.2), as 64 bytes, r then s.
//!
//! SHA-256, where the rest of this crate hashes with SHA-384, because the curve bounds the
//! strength of a signature either way and the published test vectors cover this exact pairing.
//! A signature here is always the low-s one of its pair, so each signed policy has one encoding.
//!
//! The types wrap the curve crate's, which keeps that crate out of this one's public surface.

use std::fmt;

use p256::ecdsa::signature::{Signer, Verifier};

use crate::crypto::kdf::VERSION;
use crate::ids::{WsId, write_hex};
use crate::refusal::Refusal;

/// What marks a signed message as a policy.
const POLICY: &[u8] = b"policy";

/// Signs one workspace's policies and nothing else. Wiped on drop by its crate, as far as the
/// language allows; it can't be cloned, and printing it shows nothing of it.
pub struct SigningKey(p256::ecdsa::SigningKey);

/// Checks policy signatures.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifyingKey(p256::ecdsa::VerifyingKey);

/// A policy signature: r then s, 32 bytes each, big-endian.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// From the 64 bytes. They are checked when the signature is.
    pub const fn from_bytes(bytes: [u8; 64]) -> Signature {
        Signature(bytes)
    }

    /// The 64 bytes, for storing beside the policy.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// 128 lowercase hex characters.
impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl SigningKey {
    /// From a scalar that `kdf::derive_scalar` made. Refuses bytes that are no scalar.
    pub(crate) fn from_scalar(bytes: &[u8; 32]) -> Result<SigningKey, Refusal> {
        p256::ecdsa::SigningKey::from_slice(bytes).map(SigningKey).map_err(|_| Refusal::Unreadable)
    }

    /// Its public half.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(*self.0.verifying_key())
    }

    /// Signs `policy` as version `version` of `ws`. It takes no randomness: the same key and
    /// message always give the same signature, and always the low-s one.
    pub fn sign_policy(&self, ws: WsId, version: u64, policy: &[u8]) -> Signature {
        let raw = sign_raw(&self.0, &message(ws, version, policy));
        let signature = parse(&raw).expect("a signature just made has both scalars in range");
        Signature(signature.normalize_s().to_bytes().0)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

impl VerifyingKey {
    /// 65 bytes: 0x04, then x and y (SEC1, uncompressed).
    pub fn to_bytes(self) -> [u8; 65] {
        let mut bytes = [0; 65];
        bytes.copy_from_slice(self.0.to_sec1_point(false).as_bytes());
        bytes
    }

    /// Refuses anything but an uncompressed point on the curve.
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<VerifyingKey, Refusal> {
        if bytes[0] != 0x04 {
            return Err(Refusal::Unreadable);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes).map(VerifyingKey).map_err(|_| Refusal::Unreadable)
    }

    /// Holds for exactly this workspace, version and policy. A signature whose s is in the upper
    /// half of the range is refused, though the plain algorithm would accept it: `sign_policy`
    /// never makes one.
    pub fn verify_policy(&self, ws: WsId, version: u64, policy: &[u8], sig: &Signature) -> Result<(), Refusal> {
        let signature = parse(&sig.0)?;
        if signature.normalize_s() != signature {
            return Err(Refusal::Unreadable);
        }
        verify_raw(&self.0, &message(ws, version, policy), &sig.0)
    }
}

/// What is signed: VERSION ‖ "policy" ‖ ws (16) ‖ version (8, big-endian) ‖ policy. Every part but
/// the last has a fixed length, so no two triples give the same bytes.
fn message(ws: WsId, version: u64, policy: &[u8]) -> Vec<u8> {
    [VERSION, POLICY, ws.as_bytes().as_slice(), version.to_be_bytes().as_slice(), policy].concat()
}

/// The two scalars of a signature: 64 bytes, neither scalar zero nor out of range.
fn parse(sig: &[u8]) -> Result<p256::ecdsa::Signature, Refusal> {
    p256::ecdsa::Signature::from_slice(sig).map_err(|_| Refusal::Unreadable)
}

/// ECDSA as published, with no rule about s: `sign_policy` goes through it, and so do the RFC 6979
/// vectors.
fn sign_raw(key: &p256::ecdsa::SigningKey, msg: &[u8]) -> [u8; 64] {
    let signature: p256::ecdsa::Signature = key.sign(msg);
    signature.to_bytes().0
}

/// ECDSA verification as published: either s of a pair is accepted. `verify_policy` goes through
/// it, and so do the published vectors.
fn verify_raw(key: &p256::ecdsa::VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<(), Refusal> {
    key.verify(msg, &parse(sig)?).map_err(|_| Refusal::Unreadable)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::crypto::vectors::{
        ECDSA_P256_SHA256, KAT_POLICY_8_RAW, KAT_POLICY_8_SIGNATURE, KAT_POLICY_MESSAGE, KAT_POLICY_SIGNATURE, KAT_POLICY_VERIFY, RFC6979_P256_SHA256, arr, hex, inner_bytes,
        ws_bytes,
    };
    use crate::key::InnerKey;

    const GLOBEX: WsId = WsId::from_bytes([2; 16]);
    const ALLOW_NOTHING: &[u8] = b"allow nothing";

    /// The order of P-256's group, big-endian (FIPS 186-4 D.1.2.3).
    const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn signer() -> SigningKey {
        InnerKey::from_bytes(Zeroizing::new(inner_bytes())).policy_signer()
    }

    /// The other signature of the pair: the same r, and the order less s.
    fn twin(sig: &[u8; 64]) -> [u8; 64] {
        let order = hex(ORDER);
        let (mut out, mut borrow) = (*sig, 0);
        for i in (0..32).rev() {
            let digit = i16::from(order[i]) - i16::from(sig[32 + i]) - borrow;
            borrow = i16::from(digit < 0);
            out[32 + i] = u8::try_from(digit.rem_euclid(256)).expect("a remainder below 256");
        }
        out
    }

    /// Whether s is in the upper half of its range.
    fn is_high(sig: &[u8; 64]) -> bool {
        let parsed = parse(sig).unwrap();
        parsed.normalize_s() != parsed
    }

    #[test]
    fn ecdsa_p256_matches_wycheproof() {
        for v in ECDSA_P256_SHA256 {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&hex(v.public)).unwrap();
            let checked = verify_raw(&key, &hex(v.msg), &hex(v.sig));
            assert_eq!(checked, if v.valid { Ok(()) } else { Err(Refusal::Unreadable) }, "tcId {}", v.tc);
        }
    }

    #[test]
    fn ecdsa_p256_matches_rfc_6979() {
        let mut high = Vec::new();
        for v in RFC6979_P256_SHA256 {
            let key = p256::ecdsa::SigningKey::from_slice(&hex(v.x)).unwrap();
            assert_eq!(key.verifying_key().to_sec1_point(false).as_bytes(), hex(v.public));
            let (msg, expected) = (hex(v.msg), [hex(v.r), hex(v.s)].concat());
            let made = sign_raw(&key, &msg);
            assert_eq!(made.as_slice(), expected, "message {}", v.msg);
            assert_eq!(sign_raw(&key, &msg), made, "the same each time");
            assert_eq!(verify_raw(key.verifying_key(), &msg, &made), Ok(()));
            high.push(is_high(&made));
        }
        // The plain algorithm gives either s as it comes: the RFC's first has it in the upper half, its second in the lower.
        assert_eq!(high, [true, false]);
    }

    #[test]
    fn a_policy_signature_is_unchanged() {
        assert_eq!(message(acme(), 7, ALLOW_NOTHING), hex(KAT_POLICY_MESSAGE));
        assert_eq!(signer().verifying_key().to_bytes().as_slice(), hex(KAT_POLICY_VERIFY));
        let sig = signer().sign_policy(acme(), 7, ALLOW_NOTHING);
        assert_eq!(sig.as_bytes().as_slice(), hex(KAT_POLICY_SIGNATURE));
        assert_eq!(format!("{sig:?}"), KAT_POLICY_SIGNATURE, "a signature prints as its hex");
        assert_eq!(signer().sign_policy(acme(), 7, ALLOW_NOTHING), sig, "the same each time");
        // Version 7's s is in the lower half as it comes; version 8's is not, so it shows the change `sign_policy` makes.
        assert_eq!(sign_raw(&signer().0, &message(acme(), 7, ALLOW_NOTHING)).as_slice(), hex(KAT_POLICY_SIGNATURE));
        assert_eq!(sign_raw(&signer().0, &message(acme(), 8, ALLOW_NOTHING)).as_slice(), hex(KAT_POLICY_8_RAW));
        assert_eq!(signer().sign_policy(acme(), 8, ALLOW_NOTHING).as_bytes().as_slice(), hex(KAT_POLICY_8_SIGNATURE));
        assert_eq!(twin(&arr(&hex(KAT_POLICY_8_RAW))).as_slice(), hex(KAT_POLICY_8_SIGNATURE));
    }

    #[test]
    fn a_signed_policy_verifies() {
        let key = signer();
        let long = vec![0x5a; 4096];
        for ws in [acme(), GLOBEX] {
            for version in [0, 1, 7, u64::MAX] {
                for policy in [b"".as_slice(), ALLOW_NOTHING, long.as_slice()] {
                    let sig = key.sign_policy(ws, version, policy);
                    assert_eq!(key.verifying_key().verify_policy(ws, version, policy, &sig), Ok(()), "version {version}");
                    assert_eq!(Signature::from_bytes(*sig.as_bytes()), sig, "and it reads back from its bytes");
                }
            }
        }
    }

    #[test]
    fn a_policy_signature_is_low_s_and_its_high_s_twin_is_refused() {
        let key = signer();
        let verifier = key.verifying_key();
        for version in [7, 8] {
            let sig = key.sign_policy(acme(), version, ALLOW_NOTHING);
            assert!(!is_high(sig.as_bytes()), "version {version}");
            assert_eq!(verifier.verify_policy(acme(), version, ALLOW_NOTHING, &sig), Ok(()));
            let high = twin(sig.as_bytes());
            assert!(is_high(&high) && high[..32] == sig.as_bytes()[..32], "version {version}");
            assert_eq!(twin(&high), *sig.as_bytes());
            // The plain algorithm takes either of the pair; a policy's check takes only the one `sign_policy` makes.
            assert_eq!(verify_raw(&verifier.0, &message(acme(), version, ALLOW_NOTHING), &high), Ok(()), "version {version}");
            assert_eq!(verifier.verify_policy(acme(), version, ALLOW_NOTHING, &Signature::from_bytes(high)), Err(Refusal::Unreadable), "version {version}");
        }
    }

    #[test]
    fn a_signature_fails_for_another_workspace_version_policy_or_key() {
        let key = signer();
        let verifier = key.verifying_key();
        let sig = key.sign_policy(acme(), 7, ALLOW_NOTHING);
        assert_eq!(verifier.verify_policy(acme(), 7, ALLOW_NOTHING, &sig), Ok(()));
        for (ws, version, policy) in [
            (GLOBEX, 7, ALLOW_NOTHING),
            (acme(), 6, ALLOW_NOTHING),
            (acme(), 8, ALLOW_NOTHING),
            (acme(), 7, b"allow everything".as_slice()),
            (acme(), 7, b"allow nothing ".as_slice()),
            (acme(), 7, b"".as_slice()),
        ] {
            assert_eq!(verifier.verify_policy(ws, version, policy, &sig), Err(Refusal::Unreadable), "{ws} {version} {policy:?}");
        }
        let initech = InnerKey::from_bytes(Zeroizing::new([0x21; 32])).policy_signer();
        assert_ne!(initech.verifying_key(), verifier);
        assert_eq!(initech.verifying_key().verify_policy(acme(), 7, ALLOW_NOTHING, &sig), Err(Refusal::Unreadable));
        assert_eq!(verifier.verify_policy(acme(), 7, ALLOW_NOTHING, &initech.sign_policy(acme(), 7, ALLOW_NOTHING)), Err(Refusal::Unreadable));
        for i in 0..64 {
            let mut changed = *sig.as_bytes();
            changed[i] ^= 0x01;
            assert_eq!(verifier.verify_policy(acme(), 7, ALLOW_NOTHING, &Signature::from_bytes(changed)), Err(Refusal::Unreadable), "byte {i}");
        }
        // Scalars of zero, and scalars at or over the order, are no signature at all.
        for bytes in [[0; 64], [0xff; 64]] {
            assert_eq!(verifier.verify_policy(acme(), 7, ALLOW_NOTHING, &Signature::from_bytes(bytes)), Err(Refusal::Unreadable));
        }
    }

    #[test]
    fn a_verifying_key_is_only_an_uncompressed_point_on_the_curve() {
        let verifier = signer().verifying_key();
        let bytes = verifier.to_bytes();
        assert_eq!(bytes[0], 0x04);
        assert_eq!(VerifyingKey::from_bytes(&bytes), Ok(verifier));
        // Another first byte: 0x02 and 0x03 mark the compressed form, which is shorter and is not taken at this length either.
        for first in [0x00, 0x02, 0x03, 0x05] {
            let mut other = bytes;
            other[0] = first;
            assert_eq!(VerifyingKey::from_bytes(&other), Err(Refusal::Unreadable), "first byte {first}");
        }
        // A y that does not belong to the x, and the zeros that stand for no point.
        let (mut off, mut zeros) = (bytes, [0; 65]);
        off[64] ^= 0x01;
        zeros[0] = 0x04;
        for point in [off, zeros, [0; 65]] {
            assert_eq!(VerifyingKey::from_bytes(&point), Err(Refusal::Unreadable));
        }
        assert_eq!(SigningKey::from_scalar(&[0; 32]).map(|_| ()), Err(Refusal::Unreadable), "zero is no scalar");
        assert_eq!(SigningKey::from_scalar(&arr(&hex(ORDER))).map(|_| ()), Err(Refusal::Unreadable), "nor is the order");
    }
}
