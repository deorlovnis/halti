//! A key pair anyone can seal to, and only its holder can open: ML-KEM-1024 (FIPS 203) and ECDH
//! over P-256 together, so a sealed value stays secret while either of the two holds.
//!
//! Encapsulating gives a ciphertext for the key holder and two shared secrets, one from each
//! algorithm. The holder (a hardware key, or a `DecapKey` in software) gets the same two secrets
//! back from the ciphertext. `combine` turns the pair into one key, and sealing derives a cipher
//! key and nonce from that key and a context:
//!
//! ```text
//! blob = 0x01 (format) ‖ suite (1) ‖ ML-KEM ciphertext (1568) ‖ P-256 point (65) ‖ AES-256-GCM
//! ```
//!
//! The combiner is this crate's own composition from standard parts: the extract-and-expand
//! layout of RFC 9180 section 4.1 over the two shared secrets, with both ciphertexts and both
//! public keys in the expansion. The seal's key schedule is that of RFC 9180 section 5.1 in base
//! mode, used for one message. Neither is HPKE and neither works with it.
//!
//! Randomness is an argument. The ML-KEM step is the standard's internal, deterministic form on
//! purpose (FIPS 203 algorithms 16 and 17), fed with bytes the caller drew.

use std::fmt;

use ml_kem::{Decapsulate, DecapsulationKey1024, EncapsulationKey1024, KeyExport, Seed};
use p256::elliptic_curve::sec1::ToSec1Point;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{raw_open, raw_seal};
use crate::crypto::kdf::{BASE_NONCE, EAE_PRK, INFO_HASH, KEM_ID, KEY, PSK_ID_HASH, SEAL_ID, SECRET, SHARED_SECRET, derive_scalar, labeled_expand, labeled_extract};
use crate::key::{KemCiphertext, KemShares, PublicKey, Suite};
use crate::refusal::Refusal;

/// The one format of a sealed blob so far.
const FORMAT: u8 = 0x01;

/// What a value sealed to a public key is for. The tag is the first byte of the seal's context,
/// so a blob sealed for one purpose never opens as another.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Purpose {
    /// A workspace's inner key, wrapped to its hardware key.
    HardwareWrap,
    /// A workspace's inner key, wrapped to its recovery key.
    RecoveryWrap,
}

impl Purpose {
    /// The byte that stands for it. Every other value is reserved.
    const fn tag(self) -> u8 {
        match self {
            Purpose::HardwareWrap => 0x01,
            Purpose::RecoveryWrap => 0x02,
        }
    }
}

/// The private half of a key pair held in software, as its 96-byte seed: 64 bytes for ML-KEM
/// (d, then z), then 32 from which the P-256 scalar is derived. Holding one proves nobody's
/// presence. Wiped on drop, as far as the language allows; it can't be cloned, and printing it
/// shows nothing of it.
pub struct DecapKey(Zeroizing<[u8; 96]>);

impl DecapKey {
    /// From 96 random bytes the caller drew.
    pub fn from_seed(seed: Zeroizing<[u8; 96]>) -> DecapKey {
        DecapKey(seed)
    }

    /// The seed, for an adapter that stores it wrapped.
    pub fn seed(&self) -> &[u8; 96] {
        &self.0
    }

    /// Its public half.
    pub fn public(&self) -> PublicKey {
        let (seed, ikm) = self.halves();
        let p256 = p256_public(&derive_scalar(KEM_ID, ikm)).expect("a derived scalar is in range");
        PublicKey { suite: Suite::MlKem1024P256V1, mlkem: mlkem_public(seed), p256 }
    }

    /// Both shared secrets of a ciphertext. Refuses one whose point is not an uncompressed point
    /// on the curve. A changed ML-KEM ciphertext is not refused: it gives another secret, as the
    /// standard has it, and what was sealed then fails to open.
    pub fn decapsulate(&self, ct: &KemCiphertext) -> Result<KemShares, Refusal> {
        // A seed is a key of this one suite. A second suite has to be told apart here.
        let Suite::MlKem1024P256V1 = ct.suite;
        let (seed, ikm) = self.halves();
        let p256 = ecdh_x(&derive_scalar(KEM_ID, ikm), &ct.p256_eph)?;
        Ok(KemShares { mlkem: mlkem_decaps(seed, &ct.mlkem), p256 })
    }

    /// The ML-KEM seed, and the bytes the P-256 scalar is derived from.
    fn halves(&self) -> (&[u8; 64], &[u8; 32]) {
        (self.0.first_chunk().expect("a seed starts with 64 bytes"), self.0.last_chunk().expect("a seed ends with 32 bytes"))
    }
}

impl fmt::Debug for DecapKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DecapKey(..)")
    }
}

/// Encapsulates to `to`: a ciphertext for its holder, and the two shared secrets. Refuses a
/// public key that is malformed: an ML-KEM key that fails the standard's check, or a P-256 value
/// that is not an uncompressed point on the curve.
///
/// `rand` is 64 fresh random bytes, never reused: 32 for ML-KEM, then 32 from which the ephemeral
/// P-256 key is derived. They are secret, and the caller keeps them in `Zeroizing`.
pub fn encapsulate(to: &PublicKey, rand: &[u8; 64]) -> Result<(KemCiphertext, KemShares), Refusal> {
    let Suite::MlKem1024P256V1 = to.suite;
    let (Some(m), Some(ikm)) = (rand.first_chunk::<32>(), rand.last_chunk::<32>()) else { return Err(Refusal::Unreadable) };
    let (mlkem, mlkem_share) = mlkem_encaps(&to.mlkem, m)?;
    let ephemeral = derive_scalar(KEM_ID, ikm);
    let p256_share = ecdh_x(&ephemeral, &to.p256)?;
    let ct = KemCiphertext { suite: to.suite, mlkem, p256_eph: p256_public(&ephemeral)? };
    Ok((ct, KemShares { mlkem: mlkem_share, p256: p256_share }))
}

/// One 32-byte key from both shared secrets, both ciphertexts and both public keys: it changes
/// if any of the six does. This is the value to compare with a hardware key's. Refuses a
/// ciphertext of another suite than the key's.
///
/// The composition is this crate's own, from standard parts (RFC 9180 section 4.1's layout):
///
/// ```text
/// prk = LabeledExtract("", KEM_ID, "eae_prk", ML-KEM secret ‖ P-256 secret)
/// key = LabeledExpand(prk, KEM_ID, "shared_secret", ML-KEM ciphertext ‖ P-256 point ‖ ML-KEM key ‖ P-256 key, 32)
/// ```
///
/// It binds the suite and nothing else: the workspace and the purpose enter when sealing.
pub fn combine(shares: &KemShares, ct: &KemCiphertext, to: &PublicKey) -> Result<Zeroizing<[u8; 32]>, Refusal> {
    if ct.suite != to.suite {
        return Err(Refusal::Unreadable);
    }
    // `KEM_ID` ends in this suite's tag. A second suite needs its own id here.
    let Suite::MlKem1024P256V1 = to.suite;
    let prk = labeled_extract(&[], KEM_ID, EAE_PRK, &[shares.mlkem.as_slice(), shares.p256.as_slice()]);
    let mut key = Zeroizing::new([0; 32]);
    let context = [ct.mlkem.as_slice(), ct.p256_eph.as_slice(), to.mlkem.as_slice(), to.p256.as_slice()];
    labeled_expand(&prk, KEM_ID, SHARED_SECRET, &context, key.as_mut_slice());
    Ok(key)
}

/// The ciphertext inside a sealed blob: what to hand the key holder. Refuses a blob of an unknown
/// format or suite, or one too short to hold a ciphertext.
pub fn ciphertext_of(blob: &[u8]) -> Result<KemCiphertext, Refusal> {
    Ok(parse(blob)?.0)
}

/// Seals `plaintext` to `to`, for `purpose` and `context`: only the holder of `to`'s private half
/// can open it, and only as that purpose and context.
///
/// The cipher's key and nonce are both derived from the encapsulation, so each is used once.
/// `rand` is 64 fresh random bytes as for `encapsulate`: the same `rand` with another plaintext
/// repeats key and nonce.
pub(crate) fn seal_to(to: &PublicKey, purpose: Purpose, context: &[u8], plaintext: &[u8], rand: &[u8; 64]) -> Result<Vec<u8>, Refusal> {
    let (ct, shares) = encapsulate(to, rand)?;
    let shared = combine(&shares, &ct, to)?;
    let (key, nonce) = schedule(&shared, purpose, context);
    let header = [FORMAT, ct.suite.tag()];
    let mut blob = Vec::with_capacity(header.len() + ct.mlkem.len() + ct.p256_eph.len() + plaintext.len() + 16);
    blob.extend_from_slice(&header);
    blob.extend_from_slice(ct.mlkem.as_slice());
    blob.extend_from_slice(&ct.p256_eph);
    blob.extend_from_slice(&raw_seal(&key, &nonce, &header, plaintext));
    Ok(blob)
}

/// Opens a blob `seal_to` made, with the shares its key holder returned for `ciphertext_of` it.
/// Refuses, without saying why, a blob of another format, suite, key, purpose or context, wrong
/// shares, or any changed byte.
pub(crate) fn open_with(blob: &[u8], to: &PublicKey, purpose: Purpose, context: &[u8], shares: &KemShares) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    let (ct, body) = parse(blob)?;
    // `combine` refuses a blob whose suite is not the key's, before any secret is used.
    let shared = combine(shares, &ct, to)?;
    let (key, nonce) = schedule(&shared, purpose, context);
    raw_open(&key, &nonce, &[FORMAT, ct.suite.tag()], body)
}

/// A sealed blob's ciphertext and what follows it. The two header bytes are checked here and
/// authenticated by the cipher.
fn parse(blob: &[u8]) -> Result<(KemCiphertext, &[u8]), Refusal> {
    let [FORMAT, suite, rest @ ..] = blob else { return Err(Refusal::Unreadable) };
    let suite = Suite::from_tag(*suite)?;
    let Some((mlkem, rest)) = rest.split_first_chunk::<1568>() else { return Err(Refusal::Unreadable) };
    let Some((p256_eph, body)) = rest.split_first_chunk::<65>() else { return Err(Refusal::Unreadable) };
    Ok((KemCiphertext { suite, mlkem: Box::new(*mlkem), p256_eph: *p256_eph }, body))
}

/// The cipher key and nonce of one seal: the key schedule of RFC 9180 section 5.1 in base mode
/// (no pre-shared key), with `purpose ‖ context` as its info. The nonce is the one for the first
/// message, and a seal has no second.
fn schedule(shared: &[u8; 32], purpose: Purpose, context: &[u8]) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
    let psk_id_hash = labeled_extract(&[], SEAL_ID, PSK_ID_HASH, &[]);
    let info_hash = labeled_extract(&[], SEAL_ID, INFO_HASH, &[[purpose.tag()].as_slice(), context]);
    let secret = labeled_extract(shared, SEAL_ID, SECRET, &[]);
    let mode = [0x00];
    let schedule_context = [mode.as_slice(), psk_id_hash.as_slice(), info_hash.as_slice()];
    let mut key = Zeroizing::new([0; 32]);
    labeled_expand(&secret, SEAL_ID, KEY, &schedule_context, key.as_mut_slice());
    let mut nonce = [0; 12];
    labeled_expand(&secret, SEAL_ID, BASE_NONCE, &schedule_context, &mut nonce);
    (key, nonce)
}

/// The ML-KEM-1024 public key of a 64-byte seed (FIPS 203 algorithm 16, d then z).
fn mlkem_public(seed: &[u8; 64]) -> Box<[u8; 1568]> {
    let key = DecapsulationKey1024::from_seed(Seed::from(*seed));
    Box::new(key.encapsulation_key().to_bytes().0)
}

/// An ML-KEM ciphertext and the shared secret it carries.
type Encapsulated = (Box<[u8; 1568]>, Zeroizing<[u8; 32]>);

/// ML-KEM-1024 encapsulation with the given 32 bytes in place of drawn ones (FIPS 203 algorithm
/// 17): the ciphertext and the shared secret. Refuses a key that fails the standard's check.
fn mlkem_encaps(ek: &[u8; 1568], m: &[u8; 32]) -> Result<Encapsulated, Refusal> {
    let key = EncapsulationKey1024::new(ek.into()).map_err(|_| Refusal::Unreadable)?;
    let (ct, mut shared) = key.encapsulate_deterministic(m.into());
    let out = (Box::new(ct.0), Zeroizing::new(shared.0));
    shared.as_mut_slice().zeroize();
    Ok(out)
}

/// ML-KEM-1024 decapsulation with the key of a 64-byte seed. It never fails: a ciphertext that
/// was not made for this key gives a secret that matches nothing.
fn mlkem_decaps(seed: &[u8; 64], ct: &[u8; 1568]) -> Zeroizing<[u8; 32]> {
    let key = DecapsulationKey1024::from_seed(Seed::from(*seed));
    let mut shared = key.decapsulate(ct.into());
    let out = Zeroizing::new(shared.0);
    shared.as_mut_slice().zeroize();
    out
}

/// A P-256 private scalar from its 32 bytes, or a refusal if they are zero or not below the order.
fn scalar_of(bytes: &[u8; 32]) -> Result<Zeroizing<p256::NonZeroScalar>, Refusal> {
    p256::NonZeroScalar::try_from(bytes.as_slice()).map(Zeroizing::new).map_err(|_| Refusal::Unreadable)
}

/// The public point of a private scalar: 0x04, then x and y.
fn p256_public(scalar: &[u8; 32]) -> Result<[u8; 65], Refusal> {
    let scalar = scalar_of(scalar)?;
    let point = p256::PublicKey::from_secret_scalar(&scalar).to_sec1_point(false);
    let mut bytes = [0; 65];
    bytes.copy_from_slice(point.as_bytes());
    Ok(bytes)
}

/// ECDH over P-256: the x coordinate of scalar times point, 32 bytes big-endian (NIST SP 800-56A
/// section 5.7.1.2). The point must be 65 bytes starting 0x04 and on the curve, which also rules
/// out the point at infinity; a compressed point is refused though the curve crate would take it.
fn ecdh_x(scalar: &[u8; 32], point: &[u8]) -> Result<Zeroizing<[u8; 32]>, Refusal> {
    if point.len() != 65 || point[0] != 0x04 {
        return Err(Refusal::Unreadable);
    }
    let point = p256::PublicKey::from_sec1_bytes(point).map_err(|_| Refusal::Unreadable)?;
    let scalar = scalar_of(scalar)?;
    let shared = p256::ecdh::diffie_hellman::<p256::NistP256>(&*scalar, point.as_affine());
    Ok(Zeroizing::new(shared.raw_secret_bytes().0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vectors::{
        ECDH_P256, KAT_COMBINED, KAT_EPHEMERAL_SCALAR, KAT_HARDWARE_EK_FIRST, KAT_HARDWARE_EK_LAST, KAT_HARDWARE_P256, KAT_HARDWARE_SCALAR, KAT_HARDWARE_WRAP, KAT_P256_EPH,
        KAT_RECOVERY_EK_FIRST, KAT_RECOVERY_EK_LAST, KAT_RECOVERY_P256, KAT_RECOVERY_SCALAR, KAT_SS_M, KAT_SS_P, KAT_WRAP_KEY, KAT_WRAP_NONCE, ML_KEM_1024_BAD_KEY,
        ML_KEM_1024_DECAP, ML_KEM_1024_ENCAP, ML_KEM_1024_KEYGEN, arr, hardware_rand, hardware_seed, hex, recovery_seed, seq, ws_bytes,
    };

    fn hardware() -> DecapKey {
        DecapKey::from_seed(Zeroizing::new(hardware_seed()))
    }

    fn recovery() -> DecapKey {
        DecapKey::from_seed(Zeroizing::new(recovery_seed()))
    }

    /// The same two secrets again: shares can't be cloned.
    fn copy(shares: &KemShares) -> KemShares {
        KemShares { mlkem: Zeroizing::new(*shares.mlkem), p256: Zeroizing::new(*shares.p256) }
    }

    /// A value sealed to the hardware key for acme, and the shares its holder gives for it. The same random bytes every
    /// time, which only a test may do.
    fn sealed(plaintext: &[u8]) -> (Vec<u8>, KemShares) {
        let blob = seal_to(&hardware().public(), Purpose::HardwareWrap, b"acme", plaintext, &hardware_rand()).unwrap();
        let shares = hardware().decapsulate(&ciphertext_of(&blob).unwrap()).unwrap();
        (blob, shares)
    }

    /// Values of the right length that are not an uncompressed point of the curve, made from one that is.
    fn not_points(point: [u8; 65]) -> Vec<[u8; 65]> {
        let mut bad = Vec::new();
        // Another first byte: 0x02 and 0x03 mark the compressed form, 0x00 the point at infinity.
        for first in [0x00, 0x02, 0x03, 0x05] {
            let mut other = point;
            other[0] = first;
            bad.push(other);
        }
        // A y that does not belong to the x, and the zeros that stand for no point.
        let (mut off, mut zeros) = (point, [0; 65]);
        off[64] ^= 0x01;
        zeros[0] = 0x04;
        bad.extend([off, zeros, [0; 65]]);
        bad
    }

    #[test]
    fn ecdh_p256_matches_wycheproof() {
        for v in ECDH_P256 {
            let shared = ecdh_x(&arr(&hex(v.private)), &hex(v.public));
            if v.valid {
                assert_eq!(shared.unwrap().as_slice(), hex(v.shared), "tcId {}", v.tc);
            } else {
                assert_eq!(shared.unwrap_err(), Refusal::Unreadable, "tcId {}", v.tc);
            }
        }
    }

    #[test]
    fn ml_kem_1024_matches_the_nist_vectors() {
        for v in ML_KEM_1024_KEYGEN {
            let seed: [u8; 64] = arr(&[hex(v.d), hex(v.z)].concat());
            assert_eq!(mlkem_public(&seed).as_slice(), hex(v.ek), "tcId {}", v.tc);
        }
        for v in ML_KEM_1024_ENCAP {
            let (c, k) = mlkem_encaps(&arr(&hex(v.ek)), &arr(&hex(v.m))).unwrap();
            assert_eq!(c.as_slice(), hex(v.c), "tcId {}", v.tc);
            assert_eq!(k.as_slice(), hex(v.k), "tcId {}", v.tc);
        }
    }

    #[test]
    fn ml_kem_1024_matches_wycheproof() {
        for v in ML_KEM_1024_DECAP {
            let (seed, mut c): ([u8; 64], [u8; 1568]) = (arr(&hex(v.seed)), arr(&hex(v.c)));
            assert_eq!(mlkem_decaps(&seed, &c).as_slice(), hex(v.k), "tcId {}", v.tc);
            // A changed ciphertext is not an error: it gives a secret that matches nothing.
            c[0] ^= 0x01;
            assert_ne!(mlkem_decaps(&seed, &c).as_slice(), hex(v.k), "tcId {}", v.tc);
        }
        for v in ML_KEM_1024_BAD_KEY {
            let ek: [u8; 1568] = arr(&hex(v.ek));
            assert_eq!(mlkem_encaps(&ek, &arr(&hex(v.m))).unwrap_err(), Refusal::Unreadable, "tcId {}", v.tc);
            let to = PublicKey { mlkem: Box::new(ek), ..hardware().public() };
            assert_eq!(encapsulate(&to, &hardware_rand()).unwrap_err(), Refusal::Unreadable, "tcId {}", v.tc);
            assert_eq!(seal_to(&to, Purpose::HardwareWrap, b"acme", b"a secret", &hardware_rand()).unwrap_err(), Refusal::Unreadable, "tcId {}", v.tc);
        }
    }

    #[test]
    fn a_seed_gives_the_same_public_key() {
        for (key, seed, scalar, point, first, last) in [
            (hardware(), hardware_seed(), KAT_HARDWARE_SCALAR, KAT_HARDWARE_P256, KAT_HARDWARE_EK_FIRST, KAT_HARDWARE_EK_LAST),
            (recovery(), recovery_seed(), KAT_RECOVERY_SCALAR, KAT_RECOVERY_P256, KAT_RECOVERY_EK_FIRST, KAT_RECOVERY_EK_LAST),
        ] {
            assert_eq!(*key.seed(), seed);
            assert_eq!(derive_scalar(KEM_ID, key.halves().1).as_slice(), hex(scalar));
            let public = key.public();
            assert_eq!(public.suite, Suite::MlKem1024P256V1);
            assert_eq!(public.p256.as_slice(), hex(point));
            assert_eq!(public.mlkem[..16], hex(first));
            assert_eq!(public.mlkem[1552..], hex(last));
            assert_eq!(key.public(), public, "the same each time");
        }
        assert_ne!(hardware().public(), recovery().public());
    }

    #[test]
    fn the_combined_key_is_unchanged() {
        let to = hardware().public();
        let rand = hardware_rand();
        assert_eq!(derive_scalar(KEM_ID, rand.last_chunk::<32>().unwrap()).as_slice(), hex(KAT_EPHEMERAL_SCALAR), "the last 32 bytes make the ephemeral key");
        let (ct, shares) = encapsulate(&to, &rand).unwrap();
        assert_eq!(ct.suite, to.suite);
        assert_eq!(ct.mlkem.as_slice(), &hex(KAT_HARDWARE_WRAP)[2..1570]);
        assert_eq!(ct.p256_eph.as_slice(), hex(KAT_P256_EPH));
        assert_eq!(shares.mlkem.as_slice(), hex(KAT_SS_M));
        assert_eq!(shares.p256.as_slice(), hex(KAT_SS_P));
        assert_eq!(combine(&shares, &ct, &to).unwrap().as_slice(), hex(KAT_COMBINED));
        // The key's holder gets the same two secrets from the ciphertext, and so the same key.
        let back = hardware().decapsulate(&ct).unwrap();
        assert_eq!((&back.mlkem, &back.p256), (&shares.mlkem, &shares.p256));
        assert_eq!(combine(&back, &ct, &to).unwrap().as_slice(), hex(KAT_COMBINED));
    }

    #[test]
    fn the_cipher_key_and_nonce_of_a_wrap_are_unchanged() {
        assert_eq!((Purpose::HardwareWrap.tag(), Purpose::RecoveryWrap.tag()), (0x01, 0x02));
        let combined: [u8; 32] = arr(&hex(KAT_COMBINED));
        let (key, nonce) = schedule(&combined, Purpose::HardwareWrap, &ws_bytes());
        assert_eq!(key.as_slice(), hex(KAT_WRAP_KEY));
        assert_eq!(nonce.as_slice(), hex(KAT_WRAP_NONCE));
        // Another purpose, context or combined key gives another key and another nonce.
        let mut other = combined;
        other[0] ^= 0x01;
        let changed =
            [schedule(&combined, Purpose::RecoveryWrap, &ws_bytes()), schedule(&combined, Purpose::HardwareWrap, b"globex"), schedule(&other, Purpose::HardwareWrap, &ws_bytes())];
        for (changed_key, changed_nonce) in changed {
            assert_ne!(changed_key, key);
            assert_ne!(changed_nonce, nonce);
        }
    }

    #[test]
    fn a_value_sealed_to_a_key_opens_with_its_shares() {
        let to = hardware().public();
        let long = seq(0x00, 300);
        for plaintext in [b"".as_slice(), b"a secret".as_slice(), long.as_slice()] {
            let (blob, shares) = sealed(plaintext);
            assert_eq!(blob.len(), 2 + 1568 + 65 + plaintext.len() + 16);
            assert_eq!(open_with(&blob, &to, Purpose::HardwareWrap, b"acme", &shares).unwrap().as_slice(), plaintext);
            // Only as what it was sealed for.
            assert_eq!(open_with(&blob, &to, Purpose::RecoveryWrap, b"acme", &shares).unwrap_err(), Refusal::Unreadable);
            assert_eq!(open_with(&blob, &to, Purpose::HardwareWrap, b"globex", &shares).unwrap_err(), Refusal::Unreadable);
            assert_eq!(open_with(&blob, &to, Purpose::HardwareWrap, b"", &shares).unwrap_err(), Refusal::Unreadable);
        }
    }

    #[test]
    fn the_combined_key_changes_with_either_share_ciphertext_or_key() {
        let to = hardware().public();
        let (ct, shares) = encapsulate(&to, &hardware_rand()).unwrap();
        let (mut mlkem_share, mut p256_share) = (copy(&shares), copy(&shares));
        let (mut mlkem_ct, mut p256_ct, mut mlkem_key, mut p256_key) = (ct.clone(), ct.clone(), to.clone(), to.clone());
        mlkem_share.mlkem[0] ^= 0x01;
        p256_share.p256[0] ^= 0x01;
        mlkem_ct.mlkem[0] ^= 0x01;
        p256_ct.p256_eph[64] ^= 0x01;
        mlkem_key.mlkem[0] ^= 0x01;
        p256_key.p256[64] ^= 0x01;
        let mut keys = vec![
            combine(&shares, &ct, &to).unwrap(),
            combine(&mlkem_share, &ct, &to).unwrap(),
            combine(&p256_share, &ct, &to).unwrap(),
            combine(&shares, &mlkem_ct, &to).unwrap(),
            combine(&shares, &p256_ct, &to).unwrap(),
            combine(&shares, &ct, &mlkem_key).unwrap(),
            combine(&shares, &ct, &p256_key).unwrap(),
        ];
        assert_eq!(*keys[0], *combine(&shares, &ct, &to).unwrap(), "the same each time");
        keys.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        keys.dedup();
        assert_eq!(keys.len(), 7, "one change, another key");
    }

    #[test]
    fn an_unknown_format_or_suite_byte_is_refused() {
        let to = hardware().public();
        let (blob, shares) = sealed(b"a secret");
        assert_eq!(blob[..2], [FORMAT, Suite::MlKem1024P256V1.tag()]);
        assert_eq!(blob[..2], [0x01, 0x01]);
        for (at, byte) in [(0, 0x00), (0, 0x02), (0, 0xff), (1, 0x00), (1, 0x02), (1, 0xff)] {
            let mut changed = blob.clone();
            changed[at] = byte;
            assert_eq!(ciphertext_of(&changed).unwrap_err(), Refusal::Unreadable, "byte {at} as {byte}");
            assert_eq!(open_with(&changed, &to, Purpose::HardwareWrap, b"acme", &shares).unwrap_err(), Refusal::Unreadable, "byte {at} as {byte}");
        }
        // Too short to hold a ciphertext; and with one but nothing sealed after it.
        for len in [0, 1, 2, 1634] {
            assert_eq!(ciphertext_of(&blob[..len]).unwrap_err(), Refusal::Unreadable, "{len} bytes");
            assert_eq!(open_with(&blob[..len], &to, Purpose::HardwareWrap, b"acme", &shares).unwrap_err(), Refusal::Unreadable, "{len} bytes");
        }
        assert_eq!(ciphertext_of(&blob[..1635]), ciphertext_of(&blob));
        assert_eq!(open_with(&blob[..1635], &to, Purpose::HardwareWrap, b"acme", &shares).unwrap_err(), Refusal::Unreadable);
    }

    #[test]
    fn a_compressed_or_off_curve_point_is_refused() {
        let key = hardware();
        let to = key.public();
        let (ct, _) = encapsulate(&to, &hardware_rand()).unwrap();
        for point in not_points(to.p256) {
            let bad = PublicKey { p256: point, ..to.clone() };
            assert_eq!(encapsulate(&bad, &hardware_rand()).unwrap_err(), Refusal::Unreadable, "{point:?}");
            assert_eq!(seal_to(&bad, Purpose::HardwareWrap, b"acme", b"a secret", &hardware_rand()).unwrap_err(), Refusal::Unreadable, "{point:?}");
        }
        for point in not_points(ct.p256_eph) {
            let bad = KemCiphertext { p256_eph: point, ..ct.clone() };
            assert_eq!(key.decapsulate(&bad).unwrap_err(), Refusal::Unreadable, "{point:?}");
        }
        // The helper itself takes a slice: the true compressed form (33 bytes) and other lengths are refused there.
        let scalar = derive_scalar(KEM_ID, &[7; 32]);
        assert!(ecdh_x(&scalar, &to.p256).is_ok());
        let compressed = [[0x02 | (to.p256[64] & 0x01)].as_slice(), &to.p256[1..33]].concat();
        let mut longer = to.p256.to_vec();
        longer.push(0);
        for point in [compressed.as_slice(), &to.p256[..64], longer.as_slice(), b"".as_slice()] {
            assert_eq!(ecdh_x(&scalar, point).unwrap_err(), Refusal::Unreadable, "{} bytes", point.len());
        }
        // And a scalar must be one: zero is refused.
        assert_eq!(ecdh_x(&[0; 32], &to.p256).unwrap_err(), Refusal::Unreadable);
    }

    #[test]
    fn a_wrong_share_of_either_kind_does_not_open() {
        let to = hardware().public();
        let (blob, shares) = sealed(b"a secret");
        assert_eq!(open_with(&blob, &to, Purpose::HardwareWrap, b"acme", &copy(&shares)).unwrap().as_slice(), b"a secret");
        let (mut mlkem, mut p256) = (copy(&shares), copy(&shares));
        mlkem.mlkem[31] ^= 0x01;
        p256.p256[31] ^= 0x01;
        // What another key's holder gives for the same ciphertext.
        let others = recovery().decapsulate(&ciphertext_of(&blob).unwrap()).unwrap();
        let swapped = KemShares { mlkem: Zeroizing::new(*shares.p256), p256: Zeroizing::new(*shares.mlkem) };
        for wrong in [mlkem, p256, others, swapped] {
            assert_eq!(open_with(&blob, &to, Purpose::HardwareWrap, b"acme", &wrong).unwrap_err(), Refusal::Unreadable);
        }
    }

    #[test]
    fn a_blob_sealed_to_one_key_does_not_open_as_sealed_to_another() {
        let (blob, shares) = sealed(b"a secret");
        let initech = recovery();
        // The right shares under the wrong public key, and the wrong key's own shares under either.
        let theirs = initech.decapsulate(&ciphertext_of(&blob).unwrap()).unwrap();
        assert_eq!(open_with(&blob, &initech.public(), Purpose::HardwareWrap, b"acme", &shares).unwrap_err(), Refusal::Unreadable);
        assert_eq!(open_with(&blob, &initech.public(), Purpose::HardwareWrap, b"acme", &theirs).unwrap_err(), Refusal::Unreadable);
        assert_eq!(open_with(&blob, &hardware().public(), Purpose::HardwareWrap, b"acme", &theirs).unwrap_err(), Refusal::Unreadable);
    }
}
