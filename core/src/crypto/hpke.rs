//! HPKE (RFC 9180) in one suite and one mode: mode_auth with DHKEM(P-256, HKDF-SHA256),
//! HKDF-SHA256 and AES-256-GCM, single-shot (section 6.1). The sender's own key is bound in, so
//! a message opens only under the key pair it was sealed by. One seal is one message: it is
//! sealed at sequence number 0, so its nonce is base_nonce.
//!
//! Unlike `kem` and `kdf`, which borrow the RFC's layout under this crate's own labels, this is
//! HPKE itself, with the RFC's labels and suite ids, so another implementation of the suite opens
//! what this seals. Each function follows the RFC's pseudocode, named in its comment, and the tests
//! check it against the RFC's own vectors.
//!
//! Keys are P-256 scalars of 32 bytes (SerializePrivateKey) and uncompressed points of 65
//! (SerializePublicKey). Every public key taken is checked as section 7.1.4 asks: uncompressed, on
//! the curve, not the point at infinity.

use hkdf::{Hkdf, HkdfExtract};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{raw_open, raw_seal};
use crate::crypto::kdf::in_range;
use crate::crypto::kem::{ecdh_x, p256_public};
use crate::refusal::Refusal;

/// First in every labelled input (section 4).
const VERSION: &[u8] = b"HPKE-v1";
/// The suite id inside the KEM: "KEM", then kem_id 0x0010 (section 4.1).
const KEM_SUITE: &[u8] = b"KEM\x00\x10";
/// The suite id everywhere else: "HPKE", then kem_id 0x0010, kdf_id 0x0001 and aead_id 0x0002
/// (section 5.1).
const HPKE_SUITE: &[u8] = b"HPKE\x00\x10\x00\x01\x00\x02";
/// mode_auth (section 5, table 1).
const MODE_AUTH: u8 = 0x02;

/// Nenc: an encapsulated key is the ephemeral public key, 0x04 then x and y.
pub const ENC_LEN: usize = 65;
/// Nt: what AES-256-GCM adds to a plaintext.
pub const TAG_LEN: usize = 16;

/// HKDF-Extract with SHA-256. The parts of `ikm` are fed in order, as if joined. An empty salt is
/// 32 zero bytes (RFC 5869 section 2.2).
fn extract(salt: &[u8], ikm: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut state = HkdfExtract::<Sha256>::new(Some(salt));
    for part in ikm {
        state.input_ikm(part);
    }
    let (mut prk, _) = state.finalize();
    let mut out = Zeroizing::new([0; 32]);
    out.copy_from_slice(&prk);
    prk.as_mut_slice().zeroize();
    out
}

/// HKDF-Expand with SHA-256. The parts of `info` are fed in order, as if joined.
///
/// Panics if `out` is longer than 255 * 32 bytes.
fn expand(prk: &[u8; 32], info: &[&[u8]], out: &mut [u8]) {
    let keyed = Hkdf::<Sha256>::from_prk(prk).expect("a key of the hash's length is long enough");
    keyed.expand_multi_info(info, out).expect("at most 255 * 32 bytes are asked for");
}

/// LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" ‖ suite_id ‖ label ‖ ikm).
fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut parts: Vec<&[u8]> = vec![VERSION, suite, label];
    parts.extend_from_slice(ikm);
    extract(salt, &parts)
}

/// LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖
/// info, L), where L is the length of `out`.
fn labeled_expand(suite: &[u8], prk: &[u8; 32], label: &[u8], info: &[&[u8]], out: &mut [u8]) {
    let len = u16::try_from(out.len()).expect("at most 255 * 32 bytes are asked for").to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![len.as_slice(), VERSION, suite, label];
    parts.extend_from_slice(info);
    expand(prk, &parts, out);
}

/// DeriveKeyPair(ikm) for P-256 (section 7.1.3): candidates under a counter until one is a scalar
/// above zero and below the order. P-256's bitmask is 0xff, so no bit of a candidate is cleared.
/// The private half; its public half is `public_of`.
///
/// Panics if 256 candidates in a row are out of range (DeriveKeyPairError). Each is with a chance
/// of about 2^-32, so that is unreachable.
pub(crate) fn derive_key_pair(ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let prk = labeled_extract(KEM_SUITE, &[], b"dkp_prk", &[ikm]);
    for counter in 0..=255u8 {
        let mut bytes = Zeroizing::new([0; 32]);
        labeled_expand(KEM_SUITE, &prk, b"candidate", &[[counter].as_slice()], bytes.as_mut_slice());
        if in_range(&bytes) {
            return bytes;
        }
    }
    panic!("256 candidates gave no scalar in range");
}

/// The public key of a private one, SerializePublicKey'd: 0x04, then x and y. Refuses a scalar
/// that is zero or not below the order.
pub(crate) fn public_of(sk: &[u8; 32]) -> Result<[u8; ENC_LEN], Refusal> {
    p256_public(sk)
}

/// ExtractAndExpand(dh, kem_context) of DHKEM (section 4.1): the KEM's shared secret, Nsecret = 32.
fn extract_and_expand(dh: &[u8; 64], kem_context: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let eae_prk = labeled_extract(KEM_SUITE, &[], b"eae_prk", &[dh.as_slice()]);
    let mut shared = Zeroizing::new([0; 32]);
    labeled_expand(KEM_SUITE, &eae_prk, b"shared_secret", kem_context, shared.as_mut_slice());
    shared
}

/// AuthEncap(pkR, skS) (section 4.1), with the ephemeral key given: the shared secret, and enc.
///
/// ```text
/// dh = DH(skE, pkR) ‖ DH(skS, pkR)
/// kem_context = enc ‖ pkRm ‖ pkSm
/// ```
pub(crate) fn auth_encap(pk_r: &[u8; ENC_LEN], sk_s: &[u8; 32], sk_e: &[u8; 32]) -> Result<(Zeroizing<[u8; 32]>, [u8; ENC_LEN]), Refusal> {
    let mut dh = Zeroizing::new([0; 64]);
    dh[..32].copy_from_slice(ecdh_x(sk_e, pk_r)?.as_slice());
    dh[32..].copy_from_slice(ecdh_x(sk_s, pk_r)?.as_slice());
    let enc = public_of(sk_e)?;
    let pk_s = public_of(sk_s)?;
    Ok((extract_and_expand(&dh, &[enc.as_slice(), pk_r, &pk_s]), enc))
}

/// AuthDecap(enc, skR, pkS) (section 4.1): the shared secret.
///
/// ```text
/// dh = DH(skR, pkE) ‖ DH(skR, pkS)
/// kem_context = enc ‖ pkRm ‖ pkSm
/// ```
pub(crate) fn auth_decap(enc: &[u8; ENC_LEN], sk_r: &[u8; 32], pk_s: &[u8; ENC_LEN]) -> Result<Zeroizing<[u8; 32]>, Refusal> {
    let mut dh = Zeroizing::new([0; 64]);
    dh[..32].copy_from_slice(ecdh_x(sk_r, enc)?.as_slice());
    dh[32..].copy_from_slice(ecdh_x(sk_r, pk_s)?.as_slice());
    let pk_r = public_of(sk_r)?;
    Ok(extract_and_expand(&dh, &[enc.as_slice(), &pk_r, pk_s]))
}

/// key_schedule_context of mode_auth (section 5.1): mode ‖ psk_id_hash ‖ info_hash, with the
/// default psk_id "".
fn schedule_context(info: &[u8]) -> [u8; 65] {
    let psk_id_hash = labeled_extract(HPKE_SUITE, &[], b"psk_id_hash", &[]);
    let info_hash = labeled_extract(HPKE_SUITE, &[], b"info_hash", &[info]);
    let mut context = [0; 65];
    context[0] = MODE_AUTH;
    context[1..33].copy_from_slice(psk_id_hash.as_slice());
    context[33..].copy_from_slice(info_hash.as_slice());
    context
}

/// secret = LabeledExtract(shared_secret, "secret", psk), with the default psk "" (section 5.1).
fn schedule_secret(shared: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    labeled_extract(HPKE_SUITE, shared, b"secret", &[])
}

/// KeySchedule(mode_auth, shared_secret, info, "", "") (section 5.1): the AEAD's key (Nk = 32) and
/// base_nonce (Nn = 12). The exporter secret is not made: nothing here exports.
fn key_schedule(shared: &[u8; 32], info: &[u8]) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
    let context = schedule_context(info);
    let secret = schedule_secret(shared);
    let mut key = Zeroizing::new([0; 32]);
    labeled_expand(HPKE_SUITE, &secret, b"key", &[context.as_slice()], key.as_mut_slice());
    let mut base_nonce = [0; 12];
    labeled_expand(HPKE_SUITE, &secret, b"base_nonce", &[context.as_slice()], &mut base_nonce);
    (key, base_nonce)
}

/// SealAuth(pkR, info, aad, pt, skS) (section 6.1): enc, and the ciphertext with its tag.
///
/// The ephemeral key is DeriveKeyPair(`ikm_e`): 32 fresh random bytes the caller drew, never used
/// twice, as GenerateKeyPair is DeriveKeyPair(random(Nsk)) (section 4). The same `ikm_e` with
/// another plaintext to the same key repeats the AEAD's key and nonce. Refuses a `pk_r` that is not
/// an uncompressed point on the curve, and an `sk_s` that is not a scalar.
pub(crate) fn seal_auth(pk_r: &[u8; ENC_LEN], sk_s: &[u8; 32], ikm_e: &[u8; 32], info: &[u8], aad: &[u8], pt: &[u8]) -> Result<([u8; ENC_LEN], Vec<u8>), Refusal> {
    let sk_e = derive_key_pair(ikm_e);
    let (shared, enc) = auth_encap(pk_r, sk_s, &sk_e)?;
    let (key, base_nonce) = key_schedule(&shared, info);
    Ok((enc, raw_seal(&key, &base_nonce, aad, pt)))
}

/// OpenAuth(enc, skR, info, aad, ct, pkS) (section 6.1): the plaintext, or a refusal that says
/// nothing of why: another sender, recipient, info or aad, a bad point, or any changed byte.
pub(crate) fn open_auth(enc: &[u8; ENC_LEN], sk_r: &[u8; 32], pk_s: &[u8; ENC_LEN], info: &[u8], aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    let shared = auth_decap(enc, sk_r, pk_s)?;
    let (key, base_nonce) = key_schedule(&shared, info);
    raw_open(&key, &base_nonce, aad, ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vectors::{HPKE_AUTH_P256_KEM, HPKE_AUTH_P256_SHA256_AES256, arr, hex, seq};

    #[test]
    fn the_kem_matches_the_rfc_vectors_of_every_p256_suite() {
        for v in HPKE_AUTH_P256_KEM {
            for (ikm, sk, pk) in [(v.ikm_e, v.sk_e, v.pk_e), (v.ikm_r, v.sk_r, v.pk_r), (v.ikm_s, v.sk_s, v.pk_s)] {
                let derived = derive_key_pair(&hex(ikm));
                assert_eq!(derived.as_slice(), hex(sk), "{} DeriveKeyPair", v.section);
                assert_eq!(public_of(&derived).unwrap().as_slice(), hex(pk), "{} pk", v.section);
            }
            let (pk_r, pk_s) = (arr(&hex(v.pk_r)), arr(&hex(v.pk_s)));
            let (shared, enc) = auth_encap(&pk_r, &arr(&hex(v.sk_s)), &arr(&hex(v.sk_e))).unwrap();
            assert_eq!(enc.as_slice(), hex(v.pk_e), "{} enc", v.section);
            assert_eq!(shared.as_slice(), hex(v.shared), "{} AuthEncap", v.section);
            assert_eq!(auth_decap(&enc, &arr(&hex(v.sk_r)), &pk_s).unwrap().as_slice(), hex(v.shared), "{} AuthDecap", v.section);
        }
    }

    #[test]
    fn the_whole_suite_matches_the_rfc_vector() {
        let v = &HPKE_AUTH_P256_SHA256_AES256;
        let (sk_r, sk_s) = (derive_key_pair(&hex(v.ikm_r)), derive_key_pair(&hex(v.ikm_s)));
        let (pk_r, pk_s): ([u8; 65], [u8; 65]) = (arr(&hex(v.pk_r)), arr(&hex(v.pk_s)));
        assert_eq!((public_of(&sk_r).unwrap(), public_of(&sk_s).unwrap()), (pk_r, pk_s));
        let (shared, enc) = auth_encap(&pk_r, &sk_s, &derive_key_pair(&hex(v.ikm_e))).unwrap();
        assert_eq!((enc.as_slice(), shared.as_slice()), (hex(v.enc).as_slice(), hex(v.shared).as_slice()));
        let info = hex(v.info);
        assert_eq!(schedule_context(&info).as_slice(), hex(v.context));
        assert_eq!(schedule_secret(&shared).as_slice(), hex(v.secret));
        let (key, base_nonce) = key_schedule(&shared, &info);
        assert_eq!((key.as_slice(), base_nonce.as_slice()), (hex(v.key).as_slice(), hex(v.base_nonce).as_slice()));
        // The single-shot calls give the first message's ciphertext, and open it.
        let (sealed_enc, ct) = seal_auth(&pk_r, &sk_s, &arr(&hex(v.ikm_e)), &info, &hex(v.aad), &hex(v.pt)).unwrap();
        assert_eq!((sealed_enc, ct.as_slice()), (enc, hex(v.ct).as_slice()));
        assert_eq!(open_auth(&enc, &sk_r, &pk_s, &info, &hex(v.aad), &ct).unwrap().as_slice(), hex(v.pt));
    }

    #[test]
    fn the_suite_ids_and_mode_are_the_rfcs() {
        assert_eq!(VERSION, b"HPKE-v1");
        assert_eq!(KEM_SUITE, [b"KEM".as_slice(), &0x0010u16.to_be_bytes()].concat());
        assert_eq!(HPKE_SUITE, [b"HPKE".as_slice(), &0x0010u16.to_be_bytes(), &0x0001u16.to_be_bytes(), &0x0002u16.to_be_bytes()].concat());
        assert_eq!(MODE_AUTH, 0x02);
    }

    #[test]
    fn a_message_opens_only_with_its_keys_info_and_aad() {
        let v = &HPKE_AUTH_P256_SHA256_AES256;
        let (sk_r, sk_s) = (derive_key_pair(&hex(v.ikm_r)), derive_key_pair(&hex(v.ikm_s)));
        let (pk_r, pk_s) = (public_of(&sk_r).unwrap(), public_of(&sk_s).unwrap());
        let (enc, ct) = seal_auth(&pk_r, &sk_s, &arr(&seq(0x40, 32)), b"info", b"aad", b"a message").unwrap();
        assert_eq!(ct.len(), b"a message".len() + TAG_LEN);
        assert_eq!(open_auth(&enc, &sk_r, &pk_s, b"info", b"aad", &ct).unwrap().as_slice(), b"a message");
        let other = derive_key_pair(&seq(0x60, 32));
        let other_pk = public_of(&other).unwrap();
        let refused = [
            open_auth(&enc, &other, &pk_s, b"info", b"aad", &ct),
            open_auth(&enc, &sk_r, &other_pk, b"info", b"aad", &ct),
            open_auth(&enc, &sk_r, &pk_r, b"info", b"aad", &ct),
            open_auth(&enc, &sk_r, &pk_s, b"other", b"aad", &ct),
            open_auth(&enc, &sk_r, &pk_s, b"info", b"other", &ct),
            open_auth(&enc, &sk_r, &pk_s, b"info", b"aad", &ct[..ct.len() - 1]),
        ];
        for (i, result) in refused.into_iter().enumerate() {
            assert_eq!(result.unwrap_err(), Refusal::Unreadable, "case {i}");
        }
        for i in 0..ct.len() {
            let mut changed = ct.clone();
            changed[i] ^= 0x01;
            assert_eq!(open_auth(&enc, &sk_r, &pk_s, b"info", b"aad", &changed).unwrap_err(), Refusal::Unreadable, "byte {i}");
        }
        // Another enc that is a point gives another secret; one that is not a point is refused.
        let mut moved = enc;
        moved[1..].copy_from_slice(&other_pk[1..]);
        assert_eq!(open_auth(&moved, &sk_r, &pk_s, b"info", b"aad", &ct).unwrap_err(), Refusal::Unreadable);
        let mut off_curve = enc;
        off_curve[64] ^= 0x01;
        assert_eq!(open_auth(&off_curve, &sk_r, &pk_s, b"info", b"aad", &ct).unwrap_err(), Refusal::Unreadable);
    }

    #[test]
    fn a_public_key_that_is_not_an_uncompressed_point_is_refused() {
        let sk = derive_key_pair(&seq(0x00, 32));
        let pk = public_of(&sk).unwrap();
        let mut bad = Vec::new();
        for first in [0x00, 0x02, 0x03, 0x05] {
            let mut other = pk;
            other[0] = first;
            bad.push(other);
        }
        let (mut off, mut zeros) = (pk, [0; 65]);
        off[64] ^= 0x01;
        zeros[0] = 0x04;
        bad.extend([off, zeros, [0; 65]]);
        for point in bad {
            assert_eq!(seal_auth(&point, &sk, &[7; 32], b"", b"", b"x").unwrap_err(), Refusal::Unreadable, "{point:02x?}");
            assert_eq!(auth_decap(&pk, &sk, &point).unwrap_err(), Refusal::Unreadable, "{point:02x?}");
            assert_eq!(auth_decap(&point, &sk, &pk).unwrap_err(), Refusal::Unreadable, "{point:02x?}");
        }
        // A private key must be a scalar.
        assert_eq!(seal_auth(&pk, &[0; 32], &[7; 32], b"", b"", b"x").unwrap_err(), Refusal::Unreadable);
        assert_eq!(auth_decap(&pk, &[0xff; 32], &pk).unwrap_err(), Refusal::Unreadable);
    }
}
