//! A workspace's private key sealed under a passphrase: the key holder of a machine with no key in
//! hardware. The record keeps the public key in clear, and the key's seed and the holder's
//! commitment sealed with AES-256-GCM under a key that Argon2id (RFC 9106) derives from the
//! passphrase and a salt drawn for each seal:
//!
//! ```text
//! record = 0x01 (format) ‖ 0x05 (kind) ‖ public key (1634) ‖ 0x01 (Argon2id, version 0x13)
//!          ‖ m_kib (4) ‖ t (4) ‖ p (4) ‖ salt (16) ‖ aead::seal(kek, nonce, aad, seed (96) ‖ commitment (65))
//! kek    = Argon2id(passphrase, salt, m_kib, t, p), 32 bytes, with no secret and no associated data
//! aad    = ws (16) ‖ length of the name (1) ‖ name ‖ the record up to the sealed part (1665)
//! ```
//!
//! The record is 1855 bytes. The workspace, its name, the kind, the public key, the parameters and
//! the salt are all bound by the seal, so a record changed in any of them, or read for another
//! workspace or name, does not open.
//!
//! The record alone is enough to guess passphrases offline: Argon2id only slows that. And AES-GCM
//! does not commit to its key, so a crafted record could open under more than one passphrase; what
//! refuses one is the check that the opened seed gives the public key in clear.
//!
//! Argon2id's 64 MiB of memory, the key it derives and the opened seed are wiped when dropped, but
//! not kept out of swap: only the process as a whole can be.

use std::fmt;

use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
use zeroize::Zeroizing;

use crate::crypto::aead;
use crate::crypto::kem::DecapKey;
use crate::holder::{Change, Commitment, KeyKind, KeyRef, Prompt, Released};
use crate::ids::{WsId, WsName};
use crate::key::{KemCiphertext, PublicKey};
use crate::platform::{Grade, Label, Lacks, Property};
use crate::refusal::Refusal;

/// The one record format so far.
const FORMAT: u8 = 0x01;

/// The one derivation so far: Argon2id, version 0x13.
const ARGON2ID: u8 = 0x01;

/// What any adapter built on this record says of itself.
pub const LABEL: Label = Label {
    adapter: "passphrase-key",
    grade: Grade::Weaker,
    lacks: Lacks::of(&[Property::KeyInHardware, Property::PresenceProof, Property::TrustedPrompt]),
    why: "passphrase key (no hardware): a passphrase proves knowledge, not presence; a program running as you can capture it, or copy the key file \
          and guess offline, until the workspace is re-keyed",
};

/// A passphrase as typed: at least 14 characters and at most 1024 bytes of UTF-8 text with no
/// control characters, taken as it is, with no normalising. Wiped on drop, as far as the language
/// allows; it can't be cloned, and printing it shows nothing of it.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    /// The fewest characters (not bytes) a passphrase has.
    pub const MIN_CHARS: usize = 14;
    /// The most bytes a passphrase has.
    pub const MAX_BYTES: usize = 1024;

    /// Refuses one that is too long or holds a control character with `Refusal::Unreadable`, and
    /// then one with too few characters with `Refusal::ShortPassphrase`. Neither echoes it.
    pub fn new(text: Zeroizing<String>) -> Result<Passphrase, Refusal> {
        if text.len() > Passphrase::MAX_BYTES || text.chars().any(char::is_control) {
            return Err(Refusal::Unreadable);
        }
        if text.chars().count() < Passphrase::MIN_CHARS {
            return Err(Refusal::ShortPassphrase);
        }
        Ok(Passphrase(text))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(..)")
    }
}

/// Argon2id's cost, recorded with the key so it can be raised. Only `new` and `DEFAULT` make one,
/// so it is always within these bounds:
///
/// | | floor | ceiling |
/// |---|---|---|
/// | `m_kib`, memory in KiB | 65536 | 1048576 |
/// | `t`, passes | 3 | 16 |
/// | `p`, lanes | 1 | 4 |
/// | `m_kib` × `t` | | 4194304 |
///
/// The ceilings stop a planted record from asking for a huge allocation or a long run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KdfParams {
    m_kib: u32,
    t: u32,
    p: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passes, 1 lane: also the floor.
    pub const DEFAULT: KdfParams = KdfParams { m_kib: 65536, t: 3, p: 1 };

    /// Refuses anything outside the bounds with `Refusal::Unreadable`.
    pub fn new(m_kib: u32, t: u32, p: u32) -> Result<KdfParams, Refusal> {
        let within = (65536..=1048576).contains(&m_kib) && (3..=16).contains(&t) && (1..=4).contains(&p) && u64::from(m_kib) * u64::from(t) <= 4194304;
        if !within {
            return Err(Refusal::Unreadable);
        }
        Ok(KdfParams { m_kib, t, p })
    }

    pub const fn m_kib(&self) -> u32 {
        self.m_kib
    }

    pub const fn t(&self) -> u32 {
        self.t
    }

    pub const fn p(&self) -> u32 {
        self.p
    }
}

/// A workspace's private key, sealed under a passphrase. Not secret on its own: whoever copies it
/// can guess passphrases offline, and Argon2id only slows that.
#[derive(Clone, PartialEq, Eq)]
pub struct PassphraseRecord {
    public: PublicKey,
    params: KdfParams,
    salt: [u8; 16],
    /// `aead::seal`'s blob: 190 bytes.
    sealed: Vec<u8>,
}

impl PassphraseRecord {
    /// The length of its bytes.
    pub const LEN: usize = 1855;

    /// Seals `key`'s seed and `commitment` for the workspace and name `prompt` gives. Refuses a
    /// prompt for any change but `Change::Create`.
    ///
    /// `salt` and `nonce` are fresh random bytes the caller drew, never reused: each seal derives
    /// its own key, and uses it once.
    pub fn seal(
        prompt: &Prompt,
        passphrase: &Passphrase,
        key: &DecapKey,
        commitment: &Commitment,
        params: KdfParams,
        salt: &[u8; 16],
        nonce: &[u8; 12],
    ) -> Result<PassphraseRecord, Refusal> {
        if prompt.change() != Change::Create {
            return Err(Refusal::Unreadable);
        }
        let mut record = PassphraseRecord { public: key.public(), params, salt: *salt, sealed: Vec::new() };
        let kek = record.kek(passphrase)?;
        let plain = Zeroizing::new([key.seed().as_slice(), commitment.as_bytes().as_slice()].concat());
        record.sealed = aead::seal(&kek, nonce, &record.aad(prompt.ws(), prompt.name()), &plain);
        Ok(record)
    }

    /// `seal` of the key a seed gives, for a key holder that draws the seed and never holds the key
    /// itself. `seed` is 96 fresh random bytes, as `DecapKey::from_seed` takes them.
    pub fn seal_seed(
        prompt: &Prompt,
        passphrase: &Passphrase,
        seed: Zeroizing<[u8; 96]>,
        commitment: &Commitment,
        params: KdfParams,
        salt: &[u8; 16],
        nonce: &[u8; 12],
    ) -> Result<PassphraseRecord, Refusal> {
        PassphraseRecord::seal(prompt, passphrase, &DecapKey::from_seed(seed), commitment, params, salt, nonce)
    }

    /// Refuses any other length, format, kind, suite or derivation, and parameters outside the
    /// bounds. Derives nothing.
    pub fn from_key_ref(key: &KeyRef) -> Result<PassphraseRecord, Refusal> {
        let bytes = key.0.as_slice();
        if bytes.len() != PassphraseRecord::LEN {
            return Err(Refusal::Unreadable);
        }
        let [FORMAT, kind, rest @ ..] = bytes else { return Err(Refusal::Unreadable) };
        if *kind != KeyKind::Passphrase.tag() {
            return Err(Refusal::Unreadable);
        }
        let Some((public, rest)) = rest.split_first_chunk::<{ PublicKey::LEN }>() else { return Err(Refusal::Unreadable) };
        let [ARGON2ID, rest @ ..] = rest else { return Err(Refusal::Unreadable) };
        let Some((m_kib, rest)) = rest.split_first_chunk::<4>() else { return Err(Refusal::Unreadable) };
        let Some((t, rest)) = rest.split_first_chunk::<4>() else { return Err(Refusal::Unreadable) };
        let Some((p, rest)) = rest.split_first_chunk::<4>() else { return Err(Refusal::Unreadable) };
        let Some((salt, sealed)) = rest.split_first_chunk::<16>() else { return Err(Refusal::Unreadable) };
        let params = KdfParams::new(u32::from_be_bytes(*m_kib), u32::from_be_bytes(*t), u32::from_be_bytes(*p))?;
        Ok(PassphraseRecord { public: PublicKey::from_bytes(public)?, params, salt: *salt, sealed: sealed.to_vec() })
    }

    /// Its 1855 bytes, as a key holder keeps them.
    pub fn to_key_ref(&self) -> KeyRef {
        let mut bytes = self.clear();
        bytes.extend_from_slice(&self.sealed);
        KeyRef(bytes)
    }

    /// The public key, in clear. Trusted only once a decapsulation under it has been checked.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn params(&self) -> KdfParams {
        self.params
    }

    /// Derives the key, opens the seed under the workspace and name `prompt` gives, checks the
    /// seed against the clear public key, decapsulates `ct` and wipes the seed. Refuses a prompt
    /// for `Change::Create`. A wrong passphrase is `Refusal::Unreadable`; a seed that does not
    /// match is `Refusal::Tampered`.
    pub fn decapsulate(&self, prompt: &Prompt, passphrase: &Passphrase, ct: &KemCiphertext) -> Result<Released, Refusal> {
        if prompt.change() == Change::Create {
            return Err(Refusal::Unreadable);
        }
        let kek = self.kek(passphrase)?;
        let (key, commitment) = self.open_with_kek(prompt.ws(), prompt.name(), &kek)?;
        Ok(Released { shares: key.decapsulate(ct)?, commitment })
    }

    /// The record's bytes before the sealed part: all in clear, and all bound by the seal.
    fn clear(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PassphraseRecord::LEN);
        bytes.extend_from_slice(&[FORMAT, KeyKind::Passphrase.tag()]);
        bytes.extend_from_slice(&self.public.to_bytes());
        bytes.push(ARGON2ID);
        bytes.extend_from_slice(&self.params.m_kib.to_be_bytes());
        bytes.extend_from_slice(&self.params.t.to_be_bytes());
        bytes.extend_from_slice(&self.params.p.to_be_bytes());
        bytes.extend_from_slice(&self.salt);
        bytes
    }

    /// The associated data of the seal: the workspace, its name, and everything in clear.
    fn aad(&self, ws: WsId, name: &WsName) -> Vec<u8> {
        let name = name.as_str().as_bytes();
        let len = u8::try_from(name.len()).expect("a workspace name is at most 32 bytes");
        let clear = self.clear();
        [ws.as_bytes().as_slice(), [len].as_slice(), name, clear.as_slice()].concat()
    }

    /// The key the seed is sealed under: Argon2id of the passphrase under this record's salt and
    /// parameters.
    fn kek(&self, passphrase: &Passphrase) -> Result<Zeroizing<[u8; 32]>, Refusal> {
        let mut kek = Zeroizing::new([0; 32]);
        argon2id(passphrase.as_bytes(), &self.salt, &[], &[], self.params.m_kib, self.params.t, self.params.p, &mut kek)?;
        Ok(kek)
    }

    /// Opens the seed and the commitment with a derived key, and checks the seed gives the public
    /// key in clear. Past the tag, every failure is `Refusal::Tampered`.
    fn open_with_kek(&self, ws: WsId, name: &WsName, kek: &[u8; 32]) -> Result<(DecapKey, Commitment), Refusal> {
        let plain = aead::open(kek, &self.aad(ws, name), &self.sealed)?;
        let Some((seed, commitment)) = plain.split_first_chunk::<96>() else { return Err(Refusal::Tampered) };
        let commitment: [u8; 65] = commitment.try_into().map_err(|_| Refusal::Tampered)?;
        let key = DecapKey::from_seed(Zeroizing::new(*seed));
        if key.public() != self.public {
            return Err(Refusal::Tampered);
        }
        Ok((key, Commitment::from_bytes(commitment)))
    }
}

impl fmt::Debug for PassphraseRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PassphraseRecord(..)")
    }
}

/// Argon2id as RFC 9106 writes it, with its secret and associated data, into 32 bytes. The
/// published case is checked through this. It holds no floor: the bounds are `KdfParams`'.
///
/// The memory is allocated here, not in the crate, so that it is wiped before it is freed: the
/// crate frees its own without wiping it. A failed allocation is a refusal.
#[expect(clippy::too_many_arguments, reason = "the inputs of RFC 9106, in its order")]
fn argon2id(password: &[u8], salt: &[u8], secret: &[u8], data: &[u8], m_kib: u32, t: u32, p: u32, out: &mut [u8; 32]) -> Result<(), Refusal> {
    let data = AssociatedData::new(data).map_err(|_| Refusal::Unreadable)?;
    let params = ParamsBuilder::new().m_cost(m_kib).t_cost(t).p_cost(p).data(data).output_len(out.len()).build().map_err(|_| Refusal::Unreadable)?;
    let mut memory: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    memory.try_reserve_exact(params.block_count()).map_err(|_| Refusal::Unreadable)?;
    memory.resize(params.block_count(), Block::new());
    let argon2 = Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params).map_err(|_| Refusal::Unreadable)?;
    argon2.hash_password_into_with_memory(password, salt, out, memory.as_mut_slice()).map_err(|_| Refusal::Unreadable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::ciphertext_of;
    use crate::crypto::vectors::{
        ARGON2ID_RFC9106, KAT_HARDWARE_EK_FIRST, KAT_HARDWARE_EK_LAST, KAT_HARDWARE_P256, KAT_HARDWARE_WRAP, KAT_PASSPHRASE_KEK, KAT_PASSPHRASE_RECORD, KAT_PASSPHRASE_SEALED,
        KAT_POLICY_VERIFY, PASSPHRASE, hardware_seed, hex, inner_bytes, passphrase_nonce, passphrase_salt, recovery_seed, ws_bytes,
    };
    use crate::fakes::FixedPassphrase;
    use crate::holder::KeyHolder;
    use crate::key::{InnerKey, WrapKind};
    use crate::platform::Build;

    // Each test that derives a key at 64 MiB does so once, eight in all here. Only the known answer of the record seals one; the
    // others read `KAT_PASSPHRASE_RECORD`.

    const GLOBEX: WsId = WsId::from_bytes([2; 16]);

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn name(text: &str) -> WsName {
        WsName::parse(text).unwrap()
    }

    fn prompt(ws: WsId, text: &str, change: Change) -> Prompt {
        Prompt::new(ws, &name(text), change, Build::Release)
    }

    fn typed(text: &str) -> Result<Passphrase, Refusal> {
        Passphrase::new(Zeroizing::new(text.to_string()))
    }

    fn passphrase() -> Passphrase {
        typed(PASSPHRASE).unwrap()
    }

    fn hardware() -> DecapKey {
        DecapKey::from_seed(Zeroizing::new(hardware_seed()))
    }

    /// The commitment of the known answers' inner key.
    fn commitment() -> Commitment {
        InnerKey::from_bytes(Zeroizing::new(inner_bytes())).commitment()
    }

    /// The known answers' record, read as a key holder reads it: nothing is derived.
    fn record() -> PassphraseRecord {
        PassphraseRecord::from_key_ref(&KeyRef(hex(KAT_PASSPHRASE_RECORD))).unwrap()
    }

    /// What opening asks the record's holder to decapsulate: the ciphertext of the known answers' wrap.
    fn ct() -> KemCiphertext {
        ciphertext_of(&hex(KAT_HARDWARE_WRAP)).unwrap()
    }

    #[test]
    fn argon2id_matches_rfc_9106() {
        for v in ARGON2ID_RFC9106 {
            let (password, salt, secret, data) = (hex(v.password), hex(v.salt), hex(v.secret), hex(v.data));
            let mut tag = [0; 32];
            argon2id(&password, &salt, &secret, &data, v.m_kib, v.t, v.p, &mut tag).unwrap();
            assert_eq!(tag.as_slice(), hex(v.tag));
            // The secret and the associated data are both taken: without either, the tag is another.
            let (mut without_secret, mut without_data) = ([0; 32], [0; 32]);
            argon2id(&password, &salt, &[], &data, v.m_kib, v.t, v.p, &mut without_secret).unwrap();
            argon2id(&password, &salt, &secret, &[], v.m_kib, v.t, v.p, &mut without_data).unwrap();
            assert_ne!(without_secret, tag);
            assert_ne!(without_data, tag);
        }
    }

    #[test]
    fn the_passphrase_key_is_unchanged() {
        let record = record();
        assert_eq!((record.params(), record.salt), (KdfParams::DEFAULT, passphrase_salt()));
        assert_eq!(record.kek(&passphrase()).unwrap().as_slice(), hex(KAT_PASSPHRASE_KEK));
    }

    #[test]
    fn a_passphrase_record_is_unchanged() {
        let create = prompt(acme(), "acme", Change::Create);
        let seed = Zeroizing::new(hardware_seed());
        let sealed = PassphraseRecord::seal_seed(&create, &passphrase(), seed, &commitment(), KdfParams::DEFAULT, &passphrase_salt(), &passphrase_nonce()).unwrap();
        let bytes = sealed.to_key_ref().0;
        assert_eq!((bytes.len(), PassphraseRecord::LEN), (1855, 1855));
        // Piece by piece first, so that a difference says where it is.
        assert_eq!(bytes[..2], [0x01, 0x05], "the format, then the kind");
        assert_eq!(bytes[2], 0x01, "the public key's suite");
        assert_eq!(bytes[3..19], hex(KAT_HARDWARE_EK_FIRST), "its ML-KEM key");
        assert_eq!(bytes[1555..1571], hex(KAT_HARDWARE_EK_LAST));
        assert_eq!(bytes[1571..1636], hex(KAT_HARDWARE_P256), "its P-256 point");
        assert_eq!(bytes[1636..1649], hex("01 00010000 00000003 00000001"), "Argon2id, then m, t and p");
        assert_eq!(bytes[1649..1665], passphrase_salt(), "the salt");
        assert_eq!(bytes[1665..], hex(KAT_PASSPHRASE_SEALED), "the seed and the commitment, sealed");
        assert!(bytes == hex(KAT_PASSPHRASE_RECORD));
        // The seal is bound to the workspace, its name and everything in clear before it.
        let aad = [ws_bytes().as_slice(), [0x04].as_slice(), b"acme".as_slice(), &bytes[..1665]].concat();
        assert!(sealed.aad(acme(), &name("acme")) == aad);
        assert_eq!(record(), sealed, "and it reads back as it was made");
    }

    #[test]
    fn a_passphrase_record_opens_with_its_passphrase_and_gives_the_seeds_shares() {
        let released = record().decapsulate(&prompt(acme(), "acme", Change::Open), &passphrase(), &ct()).unwrap();
        let expected = hardware().decapsulate(&ct()).unwrap();
        assert_eq!((&released.shares.mlkem, &released.shares.p256), (&expected.mlkem, &expected.p256));
        assert_eq!(released.commitment.as_bytes().as_slice(), hex(KAT_POLICY_VERIFY), "the commitment it was sealed with");
        // Those shares open the wrap, to the inner key the commitment is of.
        let inner = InnerKey::unwrap_with(&hex(KAT_HARDWARE_WRAP), record().public(), acme(), WrapKind::Hardware, &released.shares).unwrap();
        assert_eq!(inner.commitment(), released.commitment);
    }

    #[test]
    fn a_wrong_passphrase_is_refused_like_any_other_failure() {
        let wrong = typed("acme passphrase two").unwrap();
        let refusal = record().decapsulate(&prompt(acme(), "acme", Change::Open), &wrong, &ct()).unwrap_err();
        assert_eq!(refusal, Refusal::Unreadable);
        assert_eq!(refusal.to_string(), "that can't be opened (wrong key, or it was changed)");
    }

    #[test]
    fn a_passphrase_of_thirteen_characters_is_refused_and_fourteen_is_not() {
        assert_eq!(typed(&"a".repeat(13)).unwrap_err(), Refusal::ShortPassphrase);
        assert!(typed(&"a".repeat(14)).is_ok());
        // Characters, not bytes: 13 of two bytes each are 26 bytes and still too few.
        assert_eq!("é".len(), 2);
        assert_eq!(typed(&"é".repeat(13)).unwrap_err(), Refusal::ShortPassphrase);
        assert!(typed(&"é".repeat(14)).is_ok());
        assert_eq!(typed("").unwrap_err(), Refusal::ShortPassphrase);
        // The refusal says how long one must be, and nothing of what was typed.
        assert_eq!(typed("acme pass").unwrap_err().to_string(), "a passphrase has at least 14 characters");
    }

    #[test]
    fn a_passphrase_with_a_control_character_or_over_1024_bytes_is_refused() {
        let controls = ["passphrase one\n", "pass\tphrase one", "passphrase\0one", "\x1b[2Jpassphrase", "passphrase one\u{7f}", "passphrase\u{85}one", "a\n"];
        // A control character is refused before the length is counted: a short one with a newline is refused the same way.
        for text in controls {
            assert_eq!(typed(text).unwrap_err(), Refusal::Unreadable, "{text:?}");
        }
        // 1024 bytes are the most, however many characters they are.
        assert!(typed(&"a".repeat(1024)).is_ok());
        assert_eq!(typed(&"a".repeat(1025)).unwrap_err(), Refusal::Unreadable);
        assert!(typed(&"é".repeat(512)).is_ok());
        assert_eq!(typed(&format!("{}a", "é".repeat(512))).unwrap_err(), Refusal::Unreadable);
        // Spaces and letters of any script are taken as they are.
        assert!(typed("correct horse battery staple").is_ok());
        assert!(typed("пароль пароль пароль").is_ok());
    }

    #[test]
    fn any_changed_byte_or_length_of_a_record_is_refused() {
        let known = hex(KAT_PASSPHRASE_RECORD);
        let kek = record().kek(&passphrase()).unwrap();
        let acme_name = name("acme");
        let opened = |bytes: &[u8]| PassphraseRecord::from_key_ref(&KeyRef(bytes.to_vec())).and_then(|record| record.open_with_kek(acme(), &acme_name, &kek)).map(|_| ());
        assert_eq!(opened(&known), Ok(()), "unchanged, it opens");
        // Every byte: the header, the public key, the derivation's id, its parameters and salt, the nonce, the sealed seed and
        // commitment, and the tag. Each is refused as it is read, or by the tag; none is skipped.
        for i in 0..known.len() {
            let mut changed = known.clone();
            changed[i] ^= 0x01;
            assert_eq!(opened(&changed), Err(Refusal::Unreadable), "byte {i}");
        }
        for len in 0..known.len() {
            assert_eq!(PassphraseRecord::from_key_ref(&KeyRef(known[..len].to_vec())), Err(Refusal::Unreadable), "cut to {len} bytes");
        }
        let mut longer = known.clone();
        longer.push(0);
        assert_eq!(PassphraseRecord::from_key_ref(&KeyRef(longer)), Err(Refusal::Unreadable), "one byte more");
    }

    #[test]
    fn a_record_for_acme_does_not_open_as_globex() {
        let record = record();
        let kek = record.kek(&passphrase()).unwrap();
        assert!(record.open_with_kek(acme(), &name("acme"), &kek).is_ok());
        assert_eq!(record.open_with_kek(GLOBEX, &name("acme"), &kek).unwrap_err(), Refusal::Unreadable, "the right key, for another workspace");
    }

    #[test]
    fn a_record_for_acme_does_not_open_under_another_name() {
        let record = record();
        let kek = record.kek(&passphrase()).unwrap();
        assert!(record.open_with_kek(acme(), &name("acme"), &kek).is_ok());
        for other in ["globex", "acm", "acme0", "acme-2"] {
            assert_eq!(record.open_with_kek(acme(), &name(other), &kek).unwrap_err(), Refusal::Unreadable, "{other}");
        }
    }

    #[test]
    fn a_record_whose_seed_does_not_match_its_public_key_is_tampered() {
        // Under the right passphrase, with a valid tag, over another clear public key than its seed's: a record made to open under
        // more than one key would look like this, since AES-GCM does not commit to its key.
        let mut crafted = record();
        crafted.public = DecapKey::from_seed(Zeroizing::new(recovery_seed())).public();
        let kek = crafted.kek(&passphrase()).unwrap();
        let plain = [hardware_seed().as_slice(), commitment().as_bytes().as_slice()].concat();
        crafted.sealed = aead::seal(&kek, &passphrase_nonce(), &crafted.aad(acme(), &name("acme")), &plain);
        let crafted = PassphraseRecord::from_key_ref(&crafted.to_key_ref()).unwrap();
        // Its tag holds; only the check of the opened seed against the key in clear refuses it.
        assert_eq!(*aead::open(&kek, &crafted.aad(acme(), &name("acme")), &crafted.sealed).unwrap(), plain);
        let refusal = crafted.open_with_kek(acme(), &name("acme"), &kek).unwrap_err();
        assert_eq!(refusal, Refusal::Tampered);
        assert_eq!(refusal.to_string(), "this workspace's files were changed by something other than halti");
    }

    #[test]
    fn parameters_outside_the_bounds_are_refused() {
        let known = hex(KAT_PASSPHRASE_RECORD);
        let with = |m_kib: u32, t: u32, p: u32| {
            let mut bytes = known.clone();
            bytes[1637..1641].copy_from_slice(&m_kib.to_be_bytes());
            bytes[1641..1645].copy_from_slice(&t.to_be_bytes());
            bytes[1645..1649].copy_from_slice(&p.to_be_bytes());
            PassphraseRecord::from_key_ref(&KeyRef(bytes))
        };
        let outside = [(65535, 3, 1), (1048577, 3, 1), (65536, 2, 1), (65536, 17, 1), (65536, 3, 0), (65536, 3, 5), (1048576, 5, 1), (u32::MAX, u32::MAX, 1)];
        for (m_kib, t, p) in outside {
            assert_eq!(KdfParams::new(m_kib, t, p), Err(Refusal::Unreadable), "m {m_kib}, t {t}, p {p}");
            assert_eq!(with(m_kib, t, p), Err(Refusal::Unreadable), "m {m_kib}, t {t}, p {p} in a record");
        }
        // The bounds themselves are inside, the product's too.
        for (m_kib, t, p) in [(65536, 3, 1), (1048576, 4, 4), (262144, 16, 4), (65536, 16, 1)] {
            let params = KdfParams::new(m_kib, t, p).unwrap();
            assert_eq!((params.m_kib(), params.t(), params.p()), (m_kib, t, p));
            assert_eq!(with(m_kib, t, p).unwrap().params(), params);
        }
        assert_eq!(KdfParams::new(65536, 3, 1), Ok(KdfParams::DEFAULT));
        // A derivation this build does not know.
        let mut other = known.clone();
        other[1636] = 0x02;
        assert_eq!(PassphraseRecord::from_key_ref(&KeyRef(other)), Err(Refusal::Unreadable));
    }

    #[test]
    fn a_record_is_sealed_and_opened_only_for_its_change() {
        // Each checks the change first, before any key is derived.
        let open = prompt(acme(), "acme", Change::Open);
        let sealed = PassphraseRecord::seal(&open, &passphrase(), &hardware(), &commitment(), KdfParams::DEFAULT, &passphrase_salt(), &passphrase_nonce());
        assert_eq!(sealed.unwrap_err(), Refusal::Unreadable);
        let create = prompt(acme(), "acme", Change::Create);
        assert_eq!(record().decapsulate(&create, &passphrase(), &ct()).unwrap_err(), Refusal::Unreadable);
    }

    #[test]
    fn the_public_key_reads_without_the_passphrase() {
        assert_eq!(*record().public(), hardware().public());
        // A key holder gives it without asking, whatever passphrase it would answer.
        let holder = FixedPassphrase::new("not the passphrase at all", hardware_seed(), passphrase_salt(), passphrase_nonce());
        assert_eq!(KeyHolder::public(&holder, &KeyRef(hex(KAT_PASSPHRASE_RECORD))).unwrap(), hardware().public());
        assert_eq!(holder.asks(), 0);
        // A key ref that is no passphrase record is refused.
        let refusal = KeyHolder::public(&holder, &KeyRef(vec![KeyKind::Soft.tag()])).unwrap_err();
        assert_eq!(refusal.downcast::<Refusal>().unwrap(), Refusal::Unreadable);
    }

    #[test]
    fn a_record_keeps_its_parameters() {
        let record = record();
        assert_eq!(record.params(), KdfParams::DEFAULT);
        assert_eq!((record.params().m_kib(), record.params().t(), record.params().p()), (65536, 3, 1));
        // Raised parameters are written into the record and read back from it, and the bytes come back whole.
        let raised = PassphraseRecord { params: KdfParams::new(262144, 4, 2).unwrap(), ..record.clone() };
        let bytes = raised.to_key_ref();
        assert_eq!(bytes.0[1636..1649], hex("01 00040000 00000004 00000002"));
        assert_eq!(PassphraseRecord::from_key_ref(&bytes).unwrap().params(), raised.params);
        assert!(record.to_key_ref().0 == hex(KAT_PASSPHRASE_RECORD));
    }

    #[test]
    fn a_passphrase_key_is_labelled_weaker_and_says_what_it_lacks() {
        assert_eq!((LABEL.adapter, LABEL.grade), ("passphrase-key", Grade::Weaker));
        assert_eq!(LABEL.lacks.iter().collect::<Vec<_>>(), [Property::KeyInHardware, Property::PresenceProof, Property::TrustedPrompt]);
        assert!(LABEL.why.starts_with("passphrase key (no hardware): "));
    }
}
