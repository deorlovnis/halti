//! Key derivation: HKDF-SHA-384 (RFC 5869), always under a label. The labelled forms are those of
//! RFC 9180 section 4 with this crate's own version string and ids in place of HPKE's, so no
//! derivation here can produce the bytes of another, or of HPKE.
//!
//! The version string, the ids and the labels are part of every key and every sealed blob: to
//! change one is to change them all.

use hkdf::{Hkdf, HkdfExtract};
use sha2::Sha384;
use zeroize::{Zeroize, Zeroizing};

/// First in every labelled input.
pub(crate) const VERSION: &[u8] = b"workspace-v1";

/// The id of the key pair and its combined key. Its last byte is the suite's tag.
pub(crate) const KEM_ID: &[u8] = b"KEM\x01";
/// The id of sealing to a public key. Its last byte is the suite's tag.
pub(crate) const SEAL_ID: &[u8] = b"SEAL\x01";
/// The id of a workspace's working keys. Its last byte is the version of their derivation.
pub(crate) const KEYS_ID: &[u8] = b"KEYS\x01";
/// The id of a pin's hashes. Its last byte is the pin's format.
pub(crate) const PIN_ID: &[u8] = b"PIN\x01";
/// The id of a stored secret's name and seal. Its last byte is their format.
pub(crate) const ITEM_ID: &[u8] = b"ITEM\x01";

// Under any id: a scalar from 32 bytes.
const DKP_PRK: &[u8] = b"dkp_prk";
const CANDIDATE: &[u8] = b"candidate";

// Under `KEM_ID`: the combined key.
pub(crate) const EAE_PRK: &[u8] = b"eae_prk";
pub(crate) const SHARED_SECRET: &[u8] = b"shared_secret";

// Under `SEAL_ID`: the key schedule of a seal.
pub(crate) const PSK_ID_HASH: &[u8] = b"psk_id_hash";
pub(crate) const INFO_HASH: &[u8] = b"info_hash";
pub(crate) const SECRET: &[u8] = b"secret";
pub(crate) const KEY: &[u8] = b"key";
pub(crate) const BASE_NONCE: &[u8] = b"base_nonce";

// Under `KEYS_ID`: the working keys.
pub(crate) const INNER: &[u8] = b"inner";
pub(crate) const SECRETS: &[u8] = b"secrets";
pub(crate) const LOGS: &[u8] = b"logs";
pub(crate) const SESSIONS: &[u8] = b"sessions";
pub(crate) const STORE: &[u8] = b"store";
pub(crate) const ITEM_NAMES: &[u8] = b"item_names";
// Also under `KEYS_ID`, and never one of the working keys: the key the manifest is sealed under.
pub(crate) const MANIFEST: &[u8] = b"manifest";

// Under `PIN_ID`: what each of a pin's hashes covers. They are SHA-384s, not derivations (`anchor`).
pub(crate) const PIN_KEY_REF: &[u8] = b"key_ref";
pub(crate) const PIN_PUBLIC_KEY: &[u8] = b"public_key";
pub(crate) const PIN_STATE: &[u8] = b"state";

// Under `ITEM_ID`: a secret's name, from the workspace's names key and the secret's text (`item`).
pub(crate) const ITEM_NAME: &[u8] = b"name";

/// HKDF-Extract. The parts of `ikm` are fed in order, as if joined. An empty salt is 48 zero bytes
/// (RFC 5869 section 2.2).
fn extract(salt: &[u8], ikm: &[&[u8]]) -> Zeroizing<[u8; 48]> {
    let mut state = HkdfExtract::<Sha384>::new(Some(salt));
    for part in ikm {
        state.input_ikm(part);
    }
    let (mut prk, _) = state.finalize();
    let mut out = Zeroizing::new([0; 48]);
    out.copy_from_slice(&prk);
    prk.as_mut_slice().zeroize();
    out
}

/// HKDF-Expand. The parts of `info` are fed in order, as if joined.
///
/// Panics if `out` is longer than 255 * 48 bytes.
fn expand(prk: &[u8; 48], info: &[&[u8]], out: &mut [u8]) {
    let keyed = Hkdf::<Sha384>::from_prk(prk).expect("a key of the hash's length is long enough");
    keyed.expand_multi_info(info, out).expect("at most 255 * 48 bytes are asked for");
}

/// HKDF-SHA-384 as RFC 5869 writes it: extract, then expand. The labelled forms are built from the
/// same two steps; the published vectors are checked through this.
///
/// Panics if `out` is longer than 255 * 48 bytes.
#[cfg(test)]
fn hkdf(salt: &[u8], ikm: &[&[u8]], info: &[&[u8]], out: &mut [u8]) {
    expand(&extract(salt, ikm), info, out);
}

/// Extract under a label: HKDF-Extract(salt, VERSION ‖ id ‖ label ‖ ikm). The parts of `ikm` are
/// fed in order, not copied.
pub(crate) fn labeled_extract(salt: &[u8], id: &[u8], label: &[u8], ikm: &[&[u8]]) -> Zeroizing<[u8; 48]> {
    let mut parts: Vec<&[u8]> = vec![VERSION, id, label];
    parts.extend_from_slice(ikm);
    extract(salt, &parts)
}

/// Expand under a label: HKDF-Expand(prk, length of `out` in two bytes ‖ VERSION ‖ id ‖ label ‖
/// info), filling `out`.
///
/// Panics if `out` is longer than 255 * 48 bytes.
pub(crate) fn labeled_expand(prk: &[u8; 48], id: &[u8], label: &[u8], info: &[&[u8]], out: &mut [u8]) {
    let len = u16::try_from(out.len()).expect("at most 255 * 48 bytes are asked for").to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![len.as_slice(), VERSION, id, label];
    parts.extend_from_slice(info);
    expand(prk, &parts, out);
}

/// A P-256 scalar from 32 secret bytes, as RFC 9180 section 7.1.3 derives a key pair for P-256:
/// candidates are expanded under a counter until one is in range. The software private key, the
/// ephemeral key of an encapsulation and the policy signing key are all made this way.
///
/// Panics if 256 candidates in a row are out of range. Each is out of range with a chance of about
/// 2^-32, so that is unreachable.
pub(crate) fn derive_scalar(id: &[u8], ikm: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let prk = labeled_extract(&[], id, DKP_PRK, &[ikm.as_slice()]);
    for counter in 0..=255u8 {
        let mut bytes = Zeroizing::new([0; 32]);
        labeled_expand(&prk, id, CANDIDATE, &[[counter].as_slice()], bytes.as_mut_slice());
        if in_range(&bytes) {
            return bytes;
        }
    }
    panic!("256 candidates gave no scalar in range");
}

/// Whether the bytes, read big-endian, are a P-256 private scalar: above zero and below the
/// curve's order. The curve's own check decides, in constant time.
fn in_range(bytes: &[u8; 32]) -> bool {
    p256::NonZeroScalar::try_from(bytes.as_slice()).map(Zeroizing::new).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vectors::{HKDF_SHA384, KAT_SCALAR, arr, hex, seq};
    use crate::key::Suite;
    use crate::refusal::Refusal;

    /// The order of P-256's group, big-endian (FIPS 186-4 D.1.2.3).
    const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    #[test]
    fn hkdf_sha384_matches_wycheproof() {
        for v in HKDF_SHA384 {
            let (ikm, salt, info, okm) = (hex(v.ikm), hex(v.salt), hex(v.info), hex(v.okm));
            let mut whole = vec![0; okm.len()];
            hkdf(&salt, &[ikm.as_slice()], &[info.as_slice()], &mut whole);
            assert_eq!(whole, okm, "tcId {}", v.tc);
            // Again with each in two parts, which is how the labelled forms feed them.
            let (ikm, info) = (ikm.split_at(ikm.len() / 2), info.split_at(info.len() / 2));
            let mut parted = vec![0; okm.len()];
            hkdf(&salt, &[ikm.0, ikm.1], &[info.0, info.1], &mut parted);
            assert_eq!(parted, okm, "tcId {} in parts", v.tc);
        }
    }

    #[test]
    fn the_labels_are_unchanged() {
        let pinned: [(&[u8], &str); 16] = [
            (VERSION, "workspace-v1"),
            (KEM_ID, "KEM\x01"),
            (SEAL_ID, "SEAL\x01"),
            (KEYS_ID, "KEYS\x01"),
            (DKP_PRK, "dkp_prk"),
            (CANDIDATE, "candidate"),
            (EAE_PRK, "eae_prk"),
            (SHARED_SECRET, "shared_secret"),
            (PSK_ID_HASH, "psk_id_hash"),
            (INFO_HASH, "info_hash"),
            (SECRET, "secret"),
            (KEY, "key"),
            (BASE_NONCE, "base_nonce"),
            (INNER, "inner"),
            (SECRETS, "secrets"),
            (LOGS, "logs"),
        ];
        for (label, text) in pinned {
            assert_eq!(label, text.as_bytes());
        }
        assert_eq!((SESSIONS, STORE, ITEM_NAMES, MANIFEST), (b"sessions".as_slice(), b"store".as_slice(), b"item_names".as_slice(), b"manifest".as_slice()));
        // A pin's hashes: its id ends in the pin's format, 0x01.
        assert_eq!((PIN_ID, PIN_KEY_REF, PIN_PUBLIC_KEY, PIN_STATE), (b"PIN\x01".as_slice(), b"key_ref".as_slice(), b"public_key".as_slice(), b"state".as_slice()));
        assert_eq!(PIN_ID.last(), Some(&0x01));
        // A secret's name and seal: its id ends in their format, 0x01.
        assert_eq!((ITEM_ID, ITEM_NAME), (b"ITEM\x01".as_slice(), b"name".as_slice()));
        assert_eq!(ITEM_ID.last(), Some(&0x01));

        // The one suite's tag, which the ids of the key pair and of sealing end in.
        let tag = Suite::MlKem1024P256V1.tag();
        assert_eq!(tag, 0x01);
        assert_eq!((KEM_ID.last(), SEAL_ID.last()), (Some(&tag), Some(&tag)));
        for byte in 0..=255 {
            assert_eq!(Suite::from_tag(byte), if byte == tag { Ok(Suite::MlKem1024P256V1) } else { Err(Refusal::Unreadable) }, "tag {byte}");
        }

        // No id and label, joined, starts another: no two derivations or hashes can be fed the same bytes.
        let used: [(&[u8], &[&[u8]]); 5] = [
            (KEM_ID, &[DKP_PRK, CANDIDATE, EAE_PRK, SHARED_SECRET]),
            (SEAL_ID, &[PSK_ID_HASH, INFO_HASH, SECRET, KEY, BASE_NONCE]),
            (KEYS_ID, &[DKP_PRK, CANDIDATE, INNER, SECRETS, LOGS, SESSIONS, STORE, ITEM_NAMES, MANIFEST]),
            (PIN_ID, &[PIN_KEY_REF, PIN_PUBLIC_KEY, PIN_STATE]),
            (ITEM_ID, &[ITEM_NAME]),
        ];
        let joined: Vec<Vec<u8>> = used.iter().flat_map(|(id, labels)| labels.iter().map(move |label| [*id, *label].concat())).collect();
        assert_eq!(joined.len(), 22);
        for (i, one) in joined.iter().enumerate() {
            for (j, other) in joined.iter().enumerate() {
                assert!(i == j || !other.starts_with(one), "{one:?} starts {other:?}");
            }
        }
    }

    #[test]
    fn a_scalar_from_fixed_bytes_is_unchanged() {
        let ikm: [u8; 32] = arr(&seq(0x00, 32));
        assert_eq!(derive_scalar(KEM_ID, &ikm).as_slice(), hex(KAT_SCALAR));
        assert!(in_range(&derive_scalar(KEM_ID, &ikm)));
        assert_ne!(derive_scalar(KEYS_ID, &ikm), derive_scalar(KEM_ID, &ikm), "the id is part of it");
        assert_ne!(derive_scalar(KEM_ID, &arr(&seq(0x01, 32))), derive_scalar(KEM_ID, &ikm));
    }

    #[test]
    fn a_scalar_is_in_range_only_between_one_and_the_order_less_one() {
        let order: [u8; 32] = arr(&hex(ORDER));
        let (mut one, mut below, mut above) = ([0; 32], order, order);
        one[31] = 1;
        below[31] -= 1;
        above[31] += 1;
        assert!(!in_range(&[0; 32]), "zero");
        assert!(in_range(&one), "one");
        assert!(in_range(&below), "the order less one");
        assert!(!in_range(&order), "the order");
        assert!(!in_range(&above), "the order and one");
        assert!(!in_range(&[0xff; 32]), "all ones");
    }

    #[test]
    fn a_labelled_expansion_carries_its_length() {
        // The length asked for is the first part of the info, so a shorter output is not the start of a longer one.
        let prk = labeled_extract(&[], KEYS_ID, INNER, &[b"acme".as_slice()]);
        let (mut short, mut long) = ([0; 16], [0; 32]);
        labeled_expand(&prk, KEYS_ID, STORE, &[], &mut short);
        labeled_expand(&prk, KEYS_ID, STORE, &[], &mut long);
        assert_ne!(short, long[..16]);
    }
}
