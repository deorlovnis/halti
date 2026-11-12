//! A workspace's keys. One random inner key is the root of everything the workspace encrypts or
//! signs: the working keys and the policy signing key are derived from it and from nothing else.
//! It rests wrapped to public keys (the workspace's hardware key, and a recovery key), and core
//! never returns it unwrapped.
//!
//! Opening a workspace is: take the ciphertext out of a wrap, have the key holder turn it into
//! shares, unwrap, and derive `OpenKeys`. What an open workspace holds can check a policy's
//! signature but cannot make one: signing a policy needs the inner key again, and so its holder.

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::kdf::{INNER, ITEM_NAMES, KEYS_ID, LOGS, SECRETS, SESSIONS, STORE, derive_scalar, labeled_expand, labeled_extract};
use crate::crypto::kem::{Purpose, open_with, seal_to};
use crate::crypto::sign::{SigningKey, VerifyingKey};
use crate::ids::WsId;
use crate::refusal::Refusal;

/// Which algorithms a key or ciphertext is for. A new scheme is a new value, never a new meaning
/// for this one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Suite {
    /// ML-KEM-1024 with ECDH over P-256, combined as `crypto::kem::combine` does.
    MlKem1024P256V1,
}

impl Suite {
    /// The byte that names it in a blob.
    pub const fn tag(self) -> u8 {
        match self {
            Suite::MlKem1024P256V1 => 0x01,
        }
    }

    /// Refuses a byte that names no suite.
    pub fn from_tag(tag: u8) -> Result<Suite, Refusal> {
        match tag {
            0x01 => Ok(Suite::MlKem1024P256V1),
            _ => Err(Refusal::Unreadable),
        }
    }
}

/// The public half of a workspace's key or of a recovery key. Anyone may seal to it. The fields
/// are bytes as an adapter has them, so they are checked when used, not when set: `mlkem` is a
/// FIPS 203 encapsulation key, `p256` an uncompressed SEC1 point.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    pub suite: Suite,
    pub mlkem: Box<[u8; 1568]>,
    pub p256: [u8; 65],
}

/// What the key holder decapsulates: an ML-KEM ciphertext and an ephemeral P-256 point.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KemCiphertext {
    pub suite: Suite,
    pub mlkem: Box<[u8; 1568]>,
    pub p256_eph: [u8; 65],
}

/// Both shared secrets, as a key holder returns them. Wiped on drop, as far as the language
/// allows; it can't be cloned, and printing it shows nothing of it.
pub struct KemShares {
    pub mlkem: Zeroizing<[u8; 32]>,
    pub p256: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for KemShares {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KemShares(..)")
    }
}

/// Which wrap of the inner key a blob is. One never opens as the other, even under one key pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WrapKind {
    /// To the workspace's own key: what opening the workspace unwraps.
    Hardware,
    /// To the recovery key, whose private half is kept offline.
    Recovery,
}

impl WrapKind {
    /// What a wrap of this kind is sealed for.
    fn purpose(self) -> Purpose {
        match self {
            WrapKind::Hardware => Purpose::HardwareWrap,
            WrapKind::Recovery => Purpose::RecoveryWrap,
        }
    }
}

/// A workspace's root secret. Wiped on drop, as far as the language allows; it can't be cloned,
/// compared or written out, and printing it shows nothing of it.
///
/// Only this crate can get the key that signs policies from it:
///
/// ```compile_fail
/// let _ = halti_core::key::InnerKey::policy_signer;
/// ```
///
/// (That fails because `policy_signer` is private, as this, which is public, does not.)
///
/// ```
/// let _ = halti_core::key::InnerKey::open_keys;
/// ```
pub struct InnerKey(Zeroizing<[u8; 32]>);

impl InnerKey {
    /// From 32 random bytes the caller drew.
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> InnerKey {
        InnerKey(bytes)
    }

    /// The keys an open workspace holds. The workspace's id is no part of the derivation: two
    /// workspaces have different keys because each has its own random inner key.
    pub fn open_keys(&self) -> OpenKeys {
        let prk = labeled_extract(&[], KEYS_ID, INNER, &[self.0.as_slice()]);
        let key = |label: &[u8]| {
            let mut out = Zeroizing::new([0; 32]);
            labeled_expand(&prk, KEYS_ID, label, &[], out.as_mut_slice());
            out
        };
        OpenKeys { secrets: key(SECRETS), logs: key(LOGS), sessions: key(SESSIONS), store: key(STORE), item_names: key(ITEM_NAMES), policy_verify: self.signer().verifying_key() }
    }

    /// The key that signs this workspace's policies. Never part of `OpenKeys`.
    #[cfg_attr(not(test), expect(dead_code, reason = "approving a change is its first caller outside tests"))]
    pub(crate) fn policy_signer(&self) -> SigningKey {
        self.signer()
    }

    /// The signing key, derived as a scalar from the inner key under the working keys' id.
    fn signer(&self) -> SigningKey {
        SigningKey::from_scalar(&derive_scalar(KEYS_ID, &self.0)).expect("a derived scalar is in range")
    }

    /// Wraps this key to `to` for `ws`: 1683 bytes that only the holder of `to`'s private half can
    /// open, and only as this workspace's wrap of this kind. Refuses a malformed public key.
    ///
    /// `rand` is 64 fresh random bytes, never reused. They are secret, and the caller keeps them
    /// in `Zeroizing`.
    ///
    /// Anyone holding the public key can make a wrap, of any inner key: a wrap proves nothing
    /// about who made it.
    pub fn wrap_to(&self, to: &PublicKey, ws: WsId, kind: WrapKind, rand: &[u8; 64]) -> Result<Vec<u8>, Refusal> {
        seal_to(to, kind.purpose(), ws.as_bytes(), self.0.as_slice(), rand)
    }

    /// Opens a wrap with the shares its key holder returned for `crypto::kem::ciphertext_of` it.
    /// Refuses, without saying why, a wrap for another workspace, kind or key, wrong shares, or
    /// any changed byte.
    pub fn unwrap_with(blob: &[u8], to: &PublicKey, ws: WsId, kind: WrapKind, shares: &KemShares) -> Result<InnerKey, Refusal> {
        let plain = open_with(blob, to, kind.purpose(), ws.as_bytes(), shares)?;
        if plain.len() != 32 {
            return Err(Refusal::Unreadable);
        }
        let mut inner = Zeroizing::new([0; 32]);
        inner.copy_from_slice(&plain);
        Ok(InnerKey(inner))
    }
}

impl fmt::Debug for InnerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InnerKey(..)")
    }
}

/// What an open workspace holds. There is deliberately no policy signing key here. Wiped on drop,
/// as far as the language allows; it can't be cloned, and printing it shows nothing of it.
pub struct OpenKeys {
    secrets: Zeroizing<[u8; 32]>,
    logs: Zeroizing<[u8; 32]>,
    sessions: Zeroizing<[u8; 32]>,
    store: Zeroizing<[u8; 32]>,
    item_names: Zeroizing<[u8; 32]>,
    policy_verify: VerifyingKey,
}

impl OpenKeys {
    /// The key accepted items are sealed under.
    pub fn secrets(&self) -> &[u8; 32] {
        &self.secrets
    }

    /// The key the workspace's log is chained with.
    pub fn logs(&self) -> &[u8; 32] {
        &self.logs
    }

    /// The key for the door's sessions.
    pub fn sessions(&self) -> &[u8; 32] {
        &self.sessions
    }

    /// The key the disk layer encrypts the store with.
    pub fn store(&self) -> &[u8; 32] {
        &self.store
    }

    /// The key item names are derived with.
    pub fn item_names(&self) -> &[u8; 32] {
        &self.item_names
    }

    /// Checks this workspace's policies; it cannot sign them.
    pub fn policy_verify(&self) -> &VerifyingKey {
        &self.policy_verify
    }
}

impl fmt::Debug for OpenKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenKeys(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead;
    use crate::crypto::kem::{DecapKey, ciphertext_of, combine, encapsulate};
    use crate::crypto::sign::Signature;
    use crate::crypto::vectors::{
        KAT_HARDWARE_WRAP, KAT_KEY_ITEM_NAMES, KAT_KEY_LOGS, KAT_KEY_SECRETS, KAT_KEY_SESSIONS, KAT_KEY_STORE, KAT_POLICY_SCALAR, KAT_POLICY_VERIFY, KAT_RECOVERY_COMBINED,
        KAT_RECOVERY_P256_EPH, KAT_RECOVERY_SS_M, KAT_RECOVERY_SS_P, KAT_RECOVERY_WRAP_BODY, hardware_rand, hardware_seed, hex, inner_bytes, recovery_rand, recovery_seed,
        ws_bytes,
    };

    const GLOBEX: WsId = WsId::from_bytes([2; 16]);

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn inner() -> InnerKey {
        InnerKey::from_bytes(Zeroizing::new(inner_bytes()))
    }

    fn hardware() -> DecapKey {
        DecapKey::from_seed(Zeroizing::new(hardware_seed()))
    }

    fn recovery() -> DecapKey {
        DecapKey::from_seed(Zeroizing::new(recovery_seed()))
    }

    /// What the holder of `key` does with a wrap: takes the ciphertext out and decapsulates it.
    fn shares_for(key: &DecapKey, blob: &[u8]) -> Result<KemShares, Refusal> {
        key.decapsulate(&ciphertext_of(blob)?)
    }

    /// Everything an open workspace holds, to compare two of them by.
    fn held(keys: &OpenKeys) -> ([&[u8; 32]; 5], [u8; 65]) {
        ([keys.secrets(), keys.logs(), keys.sessions(), keys.store(), keys.item_names()], keys.policy_verify().to_bytes())
    }

    /// The inner key wrapped to the hardware key as acme's hardware wrap, and the shares that open it.
    fn wrapped() -> (Vec<u8>, KemShares) {
        let blob = inner().wrap_to(&hardware().public(), acme(), WrapKind::Hardware, &hardware_rand()).unwrap();
        let shares = shares_for(&hardware(), &blob).unwrap();
        (blob, shares)
    }

    #[test]
    fn a_wrapped_inner_key_is_unchanged() {
        let (blob, _) = wrapped();
        let known = hex(KAT_HARDWARE_WRAP);
        assert_eq!(blob.len(), 1683);
        assert_eq!(blob[..2], [0x01, 0x01], "the format, then the suite");
        // Piece by piece first, so that a difference says where it is.
        assert_eq!(blob[1570..1635], known[1570..1635], "the ephemeral point");
        assert_eq!(blob[1635..], known[1635..], "the sealed key and its tag");
        assert!(blob[2..1570] == known[2..1570], "the ML-KEM ciphertext");
        assert!(blob == known);

        let to = recovery().public();
        let blob = inner().wrap_to(&to, acme(), WrapKind::Recovery, &recovery_rand()).unwrap();
        assert_eq!(blob.len(), 1683);
        assert_eq!(blob[..2], [0x01, 0x01]);
        assert_eq!(blob[1570..1635], hex(KAT_RECOVERY_P256_EPH));
        assert_eq!(blob[1635..], hex(KAT_RECOVERY_WRAP_BODY));
        let given = shares_for(&recovery(), &blob).unwrap();
        assert_eq!(given.mlkem.as_slice(), hex(KAT_RECOVERY_SS_M));
        assert_eq!(given.p256.as_slice(), hex(KAT_RECOVERY_SS_P));
        assert_eq!(combine(&given, &ciphertext_of(&blob).unwrap(), &to).unwrap().as_slice(), hex(KAT_RECOVERY_COMBINED));
    }

    #[test]
    fn the_working_keys_are_unchanged() {
        let keys = inner().open_keys();
        assert_eq!(keys.secrets().as_slice(), hex(KAT_KEY_SECRETS));
        assert_eq!(keys.logs().as_slice(), hex(KAT_KEY_LOGS));
        assert_eq!(keys.sessions().as_slice(), hex(KAT_KEY_SESSIONS));
        assert_eq!(keys.store().as_slice(), hex(KAT_KEY_STORE));
        assert_eq!(keys.item_names().as_slice(), hex(KAT_KEY_ITEM_NAMES));
        assert_eq!(derive_scalar(KEYS_ID, &inner_bytes()).as_slice(), hex(KAT_POLICY_SCALAR));
        assert_eq!(keys.policy_verify().to_bytes().as_slice(), hex(KAT_POLICY_VERIFY));
    }

    #[test]
    fn an_inner_key_wrapped_to_the_hardware_key_and_to_the_recovery_key_opens_as_the_same_key() {
        let (hardware, recovery, key) = (hardware(), recovery(), inner());
        let first = key.wrap_to(&hardware.public(), acme(), WrapKind::Hardware, &hardware_rand()).unwrap();
        let second = key.wrap_to(&recovery.public(), acme(), WrapKind::Recovery, &recovery_rand()).unwrap();
        assert_ne!(first, second);
        let from_hardware = InnerKey::unwrap_with(&first, &hardware.public(), acme(), WrapKind::Hardware, &shares_for(&hardware, &first).unwrap()).unwrap();
        let from_recovery = InnerKey::unwrap_with(&second, &recovery.public(), acme(), WrapKind::Recovery, &shares_for(&recovery, &second).unwrap()).unwrap();
        assert_eq!(held(&from_hardware.open_keys()), held(&key.open_keys()));
        assert_eq!(held(&from_recovery.open_keys()), held(&key.open_keys()));
        assert_eq!(from_recovery.policy_signer().verifying_key(), key.policy_signer().verifying_key());
    }

    #[test]
    fn open_keys_hold_the_verifier_of_the_signer() {
        let key = inner();
        assert_eq!(*key.open_keys().policy_verify(), key.policy_signer().verifying_key());
        let sig = key.policy_signer().sign_policy(acme(), 1, b"allow nothing");
        assert_eq!(key.open_keys().policy_verify().verify_policy(acme(), 1, b"allow nothing", &sig), Ok(()));
        let initech = InnerKey::from_bytes(Zeroizing::new([0x21; 32]));
        assert_eq!(initech.open_keys().policy_verify().verify_policy(acme(), 1, b"allow nothing", &sig), Err(Refusal::Unreadable));
    }

    #[test]
    fn wrapping_needs_only_the_public_key() {
        // The public half as it travels: bytes, with no private half anywhere near.
        let public = hardware().public();
        let to = PublicKey { suite: Suite::from_tag(public.suite.tag()).unwrap(), mlkem: Box::new(*public.mlkem), p256: public.p256 };
        let blob = inner().wrap_to(&to, acme(), WrapKind::Hardware, &hardware_rand()).unwrap();
        // Opening it takes the holder of the private half.
        let opened = InnerKey::unwrap_with(&blob, &to, acme(), WrapKind::Hardware, &shares_for(&hardware(), &blob).unwrap()).unwrap();
        assert_eq!(held(&opened.open_keys()), held(&inner().open_keys()));
        // So a wrap says nothing of who made it: one of any other inner key opens just as well.
        let planted = InnerKey::from_bytes(Zeroizing::new([0x21; 32]));
        let blob = planted.wrap_to(&to, acme(), WrapKind::Hardware, &recovery_rand()).unwrap();
        let opened = InnerKey::unwrap_with(&blob, &to, acme(), WrapKind::Hardware, &shares_for(&hardware(), &blob).unwrap()).unwrap();
        assert_eq!(held(&opened.open_keys()), held(&planted.open_keys()));
    }

    #[test]
    fn open_keys_are_the_same_each_time() {
        let key = inner();
        assert_eq!(held(&key.open_keys()), held(&key.open_keys()));
        assert_eq!(held(&key.open_keys()), held(&inner().open_keys()));
        let sig = key.policy_signer().sign_policy(acme(), 1, b"allow nothing");
        assert_eq!(inner().policy_signer().sign_policy(acme(), 1, b"allow nothing"), sig);
    }

    #[test]
    fn any_changed_byte_or_length_of_a_wrap_is_refused() {
        let key = hardware();
        let to = key.public();
        let (blob, good) = wrapped();
        // Tried two ways: with the shares of the wrap as it was, and with those its key holder gives for it as it is now.
        let tried = |changed: &[u8]| {
            let with_old = InnerKey::unwrap_with(changed, &to, acme(), WrapKind::Hardware, &good).map(|_| ());
            let with_new = shares_for(&key, changed).and_then(|new| InnerKey::unwrap_with(changed, &to, acme(), WrapKind::Hardware, &new)).map(|_| ());
            (with_old, with_new)
        };
        let refused = (Err(Refusal::Unreadable), Err(Refusal::Unreadable));
        assert_eq!(tried(&blob), (Ok(()), Ok(())), "unchanged, it opens");
        // Every byte: the two of the header, all 1568 of the ML-KEM ciphertext, the 65 of the point, the 48 sealed. None is skipped.
        for i in 0..blob.len() {
            let mut changed = blob.clone();
            changed[i] ^= 0x01;
            assert_eq!(tried(&changed), refused, "byte {i}");
        }
        for len in 0..blob.len() {
            assert_eq!(tried(&blob[..len]), refused, "cut to {len} bytes");
        }
        let mut longer = blob.clone();
        longer.push(0);
        assert_eq!(tried(&longer), refused, "one byte more");
        // A blob that opens but holds something other than 32 bytes: anyone with the public key can make one.
        for len in [0, 31, 33] {
            let other = seal_to(&to, Purpose::HardwareWrap, acme().as_bytes(), &vec![0x20; len], &hardware_rand()).unwrap();
            assert_eq!(tried(&other), refused, "a sealed value of {len} bytes");
        }
    }

    #[test]
    fn a_wrap_for_acme_does_not_open_as_globex() {
        let to = hardware().public();
        let (blob, shares) = wrapped();
        assert!(InnerKey::unwrap_with(&blob, &to, acme(), WrapKind::Hardware, &shares).is_ok());
        assert_eq!(InnerKey::unwrap_with(&blob, &to, GLOBEX, WrapKind::Hardware, &shares).unwrap_err(), Refusal::Unreadable);
        // Made for globex with everything else the same, it is another blob, and it does not open as acme's.
        let globex = inner().wrap_to(&to, GLOBEX, WrapKind::Hardware, &hardware_rand()).unwrap();
        assert_eq!(globex[..1635], blob[..1635], "the same encapsulation");
        assert_ne!(globex[1635..], blob[1635..]);
        assert!(InnerKey::unwrap_with(&globex, &to, GLOBEX, WrapKind::Hardware, &shares).is_ok());
        assert_eq!(InnerKey::unwrap_with(&globex, &to, acme(), WrapKind::Hardware, &shares).unwrap_err(), Refusal::Unreadable);
    }

    #[test]
    fn a_hardware_wrap_does_not_open_as_a_recovery_wrap() {
        let to = hardware().public();
        let (blob, shares) = wrapped();
        assert_eq!(InnerKey::unwrap_with(&blob, &to, acme(), WrapKind::Recovery, &shares).unwrap_err(), Refusal::Unreadable);
        // Nor the other way round, though the key pair, the workspace and the random bytes are the same.
        let recovery = inner().wrap_to(&to, acme(), WrapKind::Recovery, &hardware_rand()).unwrap();
        assert_ne!(recovery[1635..], blob[1635..]);
        assert!(InnerKey::unwrap_with(&recovery, &to, acme(), WrapKind::Recovery, &shares).is_ok());
        assert_eq!(InnerKey::unwrap_with(&recovery, &to, acme(), WrapKind::Hardware, &shares).unwrap_err(), Refusal::Unreadable);
    }

    #[test]
    fn another_key_does_not_open_a_wrap() {
        let (blob, good) = wrapped();
        let (hardware, initech) = (hardware(), recovery());
        // What initech's holder gives for the ciphertext, under either public key; and the right shares under the wrong key.
        let theirs = shares_for(&initech, &blob).unwrap();
        assert_eq!(InnerKey::unwrap_with(&blob, &initech.public(), acme(), WrapKind::Hardware, &theirs).unwrap_err(), Refusal::Unreadable);
        assert_eq!(InnerKey::unwrap_with(&blob, &hardware.public(), acme(), WrapKind::Hardware, &theirs).unwrap_err(), Refusal::Unreadable);
        assert_eq!(InnerKey::unwrap_with(&blob, &initech.public(), acme(), WrapKind::Hardware, &good).unwrap_err(), Refusal::Unreadable);
    }

    #[test]
    fn each_working_key_is_different_and_two_inner_keys_share_none() {
        let every = |bytes: [u8; 32]| {
            let keys = InnerKey::from_bytes(Zeroizing::new(bytes)).open_keys();
            let mut all: Vec<Vec<u8>> = held(&keys).0.iter().map(|key| key.to_vec()).collect();
            // The signing scalar is one more secret from the same root, and the root itself must be none of them.
            all.push(derive_scalar(KEYS_ID, &bytes).to_vec());
            all.push(bytes.to_vec());
            (all, keys.policy_verify().to_bytes())
        };
        let ((mut all, verifier), (others, other_verifier)) = (every(inner_bytes()), every([0x21; 32]));
        all.extend(others);
        assert_eq!(all.len(), 14);
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 14, "no two are the same");
        assert_ne!(verifier, other_verifier);
    }

    #[test]
    fn secret_types_print_nothing_of_themselves() {
        let key = InnerKey::from_bytes(Zeroizing::new([0xab; 32]));
        let shares = KemShares { mlkem: Zeroizing::new([0xab; 32]), p256: Zeroizing::new([0xab; 32]) };
        let decap = DecapKey::from_seed(Zeroizing::new([0xab; 96]));
        let plain = [format!("{key:?}"), format!("{:?}", key.open_keys()), format!("{:?}", key.policy_signer()), format!("{shares:?}"), format!("{decap:?}")];
        assert_eq!(plain, ["InnerKey(..)", "OpenKeys(..)", "SigningKey(..)", "KemShares(..)", "DecapKey(..)"]);
        let pretty = [format!("{key:#?}"), format!("{:#?}", key.open_keys()), format!("{:#?}", key.policy_signer()), format!("{shares:#?}"), format!("{decap:#?}")];
        assert_eq!(pretty, plain);
        // Nor does a field of the one secret type whose fields are public.
        let field = format!("{:?}", shares.mlkem);
        assert!(!field.contains("ab") && !field.contains("171"), "{field}");
    }

    #[test]
    fn every_refusal_is_the_same() {
        let to = hardware().public();
        let (blob, good) = wrapped();
        let (ct, _) = encapsulate(&to, &hardware_rand()).unwrap();
        let sig = inner().policy_signer().sign_policy(acme(), 1, b"allow nothing");
        let mut cut = blob.clone();
        cut.truncate(100);
        let refusals = [
            Suite::from_tag(0x02).unwrap_err(),
            ciphertext_of(&cut).unwrap_err(),
            InnerKey::unwrap_with(&cut, &to, acme(), WrapKind::Hardware, &good).unwrap_err(),
            InnerKey::unwrap_with(&blob, &to, GLOBEX, WrapKind::Hardware, &good).unwrap_err(),
            InnerKey::unwrap_with(&blob, &to, acme(), WrapKind::Recovery, &good).unwrap_err(),
            inner().wrap_to(&PublicKey { p256: [0; 65], ..to.clone() }, acme(), WrapKind::Hardware, &hardware_rand()).unwrap_err(),
            encapsulate(&PublicKey { mlkem: Box::new([0xff; 1568]), ..to.clone() }, &hardware_rand()).unwrap_err(),
            hardware().decapsulate(&KemCiphertext { p256_eph: [0; 65], ..ct }).unwrap_err(),
            aead::open(&[0; 32], b"acme", &aead::seal(&[1; 32], &[0; 12], b"acme", b"a secret")).unwrap_err(),
            aead::open(&[0; 32], b"acme", b"").unwrap_err(),
            inner().open_keys().policy_verify().verify_policy(GLOBEX, 1, b"allow nothing", &sig).unwrap_err(),
            inner().open_keys().policy_verify().verify_policy(acme(), 1, b"allow nothing", &Signature::from_bytes([0; 64])).unwrap_err(),
            VerifyingKey::from_bytes(&[0; 65]).unwrap_err(),
        ];
        for refusal in refusals {
            assert_eq!(refusal, Refusal::Unreadable);
            assert_eq!(refusal.to_string(), "that can't be opened (wrong key, or it was changed)");
        }
    }
}
