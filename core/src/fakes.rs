//! Adapters in memory, for tests: they keep what they are given and remember what they were asked.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::anchor::{Anchor, Pin};
use crate::crypto::kem::DecapKey;
use crate::holder::{Change, Commitment, KeyHolder, KeyKind, KeyRef, Prompt, Released};
use crate::ids::{WsId, WsName};
use crate::key::{KemCiphertext, KemShares, PublicKey};
use crate::passphrase::{KdfParams, Passphrase, PassphraseRecord};
use crate::platform::{Adapter, Grade, Label, Lacks, Property};
use crate::refusal::Refusal;
use crate::store::{FileKey, Files, Held, ItemName, KeystoreBackend};

fn label(adapter: &'static str) -> Label {
    Label { adapter, grade: Grade::Dev, lacks: Lacks::of(&Property::ALL), why: "kept in memory, for tests" }
}

/// A keystore in memory that remembers which workspace every call named.
#[derive(Default)]
pub struct MemKeystore {
    items: RefCell<BTreeMap<(WsId, ItemName), Vec<u8>>>,
    calls: RefCell<Vec<WsId>>,
}

impl MemKeystore {
    pub fn new() -> MemKeystore {
        MemKeystore::default()
    }

    /// The workspace of every call so far, in order.
    pub fn calls(&self) -> Vec<WsId> {
        self.calls.borrow().clone()
    }
}

impl Adapter for MemKeystore {
    fn label(&self) -> Label {
        label("mem-keystore")
    }
}

impl KeystoreBackend for MemKeystore {
    fn put(&self, ws: WsId, name: &ItemName, blob: &[u8]) -> Result<()> {
        self.calls.borrow_mut().push(ws);
        self.items.borrow_mut().insert((ws, *name), blob.to_vec());
        Ok(())
    }

    fn get(&self, ws: WsId, name: &ItemName) -> Result<Option<Vec<u8>>> {
        self.calls.borrow_mut().push(ws);
        Ok(self.items.borrow().get(&(ws, *name)).cloned())
    }

    fn delete(&self, ws: WsId, name: &ItemName) -> Result<bool> {
        self.calls.borrow_mut().push(ws);
        Ok(self.items.borrow_mut().remove(&(ws, *name)).is_some())
    }

    fn list(&self, ws: WsId) -> Result<Vec<ItemName>> {
        self.calls.borrow_mut().push(ws);
        Ok(self.items.borrow().keys().filter(|(owner, _)| *owner == ws).map(|(_, name)| *name).collect())
    }
}

/// Halti's files in memory, with a lock that excludes.
#[derive(Default)]
pub struct MemFiles {
    files: RefCell<BTreeMap<FileKey, Vec<u8>>>,
    locks: Rc<RefCell<BTreeSet<WsId>>>,
    calls: Cell<usize>,
    reads: RefCell<Vec<FileKey>>,
}

impl MemFiles {
    pub fn new() -> MemFiles {
        MemFiles::default()
    }

    /// How many calls it has had.
    pub fn calls(&self) -> usize {
        self.calls.get()
    }

    /// The file of every `read` so far, in order.
    pub fn reads(&self) -> Vec<FileKey> {
        self.reads.borrow().clone()
    }

    fn called(&self) {
        self.calls.set(self.calls.get() + 1);
    }
}

impl Adapter for MemFiles {
    fn label(&self) -> Label {
        label("mem-files")
    }
}

struct MemHeld {
    locks: Rc<RefCell<BTreeSet<WsId>>>,
    ws: WsId,
}

impl Held for MemHeld {}

impl Drop for MemHeld {
    fn drop(&mut self) {
        self.locks.borrow_mut().remove(&self.ws);
    }
}

impl Files for MemFiles {
    fn read(&self, k: &FileKey) -> Result<Option<Vec<u8>>> {
        self.called();
        self.reads.borrow_mut().push(k.clone());
        Ok(self.files.borrow().get(k).cloned())
    }

    fn write_atomic(&self, k: &FileKey, bytes: &[u8]) -> Result<()> {
        self.called();
        self.files.borrow_mut().insert(k.clone(), bytes.to_vec());
        Ok(())
    }

    fn append(&self, k: &FileKey, line: &[u8]) -> Result<()> {
        self.called();
        let mut files = self.files.borrow_mut();
        let file = files.entry(k.clone()).or_default();
        file.extend_from_slice(line);
        file.push(b'\n');
        Ok(())
    }

    fn remove(&self, k: &FileKey) -> Result<()> {
        self.called();
        self.files.borrow_mut().remove(k);
        Ok(())
    }

    fn names(&self) -> Result<Vec<WsName>> {
        self.called();
        Ok(self
            .files
            .borrow()
            .keys()
            .filter_map(|k| match k {
                FileKey::DirRecord(name) => Some(name.clone()),
                _ => None,
            })
            .collect())
    }

    fn lock(&self, ws: WsId) -> Result<Box<dyn Held>> {
        self.called();
        if !self.locks.borrow_mut().insert(ws) {
            bail!("workspace {ws} is locked");
        }
        Ok(Box::new(MemHeld { locks: self.locks.clone(), ws }))
    }
}

/// A software key in memory that counts how often it is asked for shares. As a key holder it keeps
/// the commitment it is given, counts the keys it makes, and remembers every prompt it is shown
/// (the prompt itself can't be kept: it can't be cloned). Its key ref is the one byte of its kind.
pub struct SoftKey {
    key: DecapKey,
    decapsulations: Cell<u32>,
    creates: Cell<u32>,
    commitment: Cell<Option<Commitment>>,
    asked: RefCell<Vec<(WsId, WsName, Change, String)>>,
    decline: Cell<bool>,
}

impl SoftKey {
    /// From a 96-byte seed, as `DecapKey` takes it.
    pub fn from_seed(seed: [u8; 96]) -> SoftKey {
        SoftKey {
            key: DecapKey::from_seed(Zeroizing::new(seed)),
            decapsulations: Cell::new(0),
            creates: Cell::new(0),
            commitment: Cell::new(None),
            asked: RefCell::new(Vec::new()),
            decline: Cell::new(false),
        }
    }

    /// Its public half.
    pub fn public(&self) -> PublicKey {
        self.key.public()
    }

    /// Counts the call, then decapsulates.
    pub fn shares_for(&self, ct: &KemCiphertext) -> Result<KemShares, Refusal> {
        self.decapsulations.set(self.decapsulations.get() + 1);
        self.key.decapsulate(ct)
    }

    /// How many times it has been asked for shares.
    pub fn decapsulations(&self) -> u32 {
        self.decapsulations.get()
    }

    /// How many keys it has been asked to make.
    pub fn creates(&self) -> u32 {
        self.creates.get()
    }

    /// The workspace, name, change and text of every prompt it was shown, in order.
    pub fn asked(&self) -> Vec<(WsId, WsName, Change, String)> {
        self.asked.borrow().clone()
    }

    /// From now on, says no to every prompt (or, given false, stops saying no).
    pub fn decline(&self, no: bool) {
        self.decline.set(no);
    }

    /// Remembers the prompt, then answers it.
    fn ask(&self, prompt: &Prompt) -> Result<(), Refusal> {
        self.asked.borrow_mut().push((prompt.ws(), prompt.name().clone(), prompt.change(), prompt.text()));
        if self.decline.get() {
            return Err(Refusal::Declined);
        }
        Ok(())
    }
}

impl Adapter for SoftKey {
    fn label(&self) -> Label {
        label("soft-key")
    }
}

impl KeyHolder for SoftKey {
    fn kind(&self) -> KeyKind {
        KeyKind::Soft
    }

    fn create(&self, prompt: &Prompt, commitment: &Commitment) -> Result<(KeyRef, PublicKey)> {
        self.creates.set(self.creates.get() + 1);
        self.ask(prompt)?;
        self.commitment.set(Some(*commitment));
        Ok((KeyRef(vec![KeyKind::Soft.tag()]), self.key.public()))
    }

    fn public(&self, key: &KeyRef) -> Result<PublicKey> {
        if key.0 != [KeyKind::Soft.tag()] {
            return Err(Refusal::Unreadable.into());
        }
        Ok(self.key.public())
    }

    /// Goes through `shares_for`, so it counts. With no commitment kept (it never made a key), it
    /// refuses after decapsulating.
    fn decapsulate(&self, key: &KeyRef, prompt: &Prompt, ct: &KemCiphertext) -> Result<Released> {
        KeyHolder::public(self, key)?;
        self.ask(prompt)?;
        let shares = self.shares_for(ct)?;
        let commitment = self.commitment.get().ok_or(Refusal::Unreadable)?;
        Ok(Released { shares, commitment })
    }

    fn destroy(&self, _key: &KeyRef) -> Result<()> {
        self.commitment.set(None);
        Ok(())
    }
}

/// An anchor in memory that counts its reads, and can be told to fail its next write.
#[derive(Default)]
pub struct MemAnchor {
    pins: RefCell<BTreeMap<WsId, Pin>>,
    reads: Cell<u32>,
    fail_next_advance: Cell<bool>,
}

impl MemAnchor {
    pub fn new() -> MemAnchor {
        MemAnchor::default()
    }

    /// How many times a pin was read.
    pub fn reads(&self) -> u32 {
        self.reads.get()
    }

    /// The next `advance` fails, as a disk would, and keeps nothing.
    pub fn fail_next_advance(&self) {
        self.fail_next_advance.set(true);
    }
}

impl Adapter for MemAnchor {
    fn label(&self) -> Label {
        label("mem-anchor")
    }
}

impl Anchor for MemAnchor {
    fn read(&self, ws: WsId) -> Result<Option<Pin>> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.pins.borrow().get(&ws).copied())
    }

    fn advance(&self, ws: WsId, pin: &Pin) -> Result<()> {
        if self.fail_next_advance.replace(false) {
            bail!("the anchor could not be written");
        }
        let mut pins = self.pins.borrow_mut();
        let kept = pins.get(&ws).map_or(0, |old| old.version);
        if pin.version <= kept {
            bail!("pin version {} is not above {kept}", pin.version);
        }
        pins.insert(ws, *pin);
        Ok(())
    }

    fn forget(&self, ws: WsId) -> Result<()> {
        self.pins.borrow_mut().remove(&ws);
        Ok(())
    }
}

/// A passphrase key holder whose passphrase is already typed: the terminal's adapter without the
/// terminal or the randomness. Its seed, salt and nonce are given, and it counts every time it
/// asks for the passphrase.
pub struct FixedPassphrase {
    answer: RefCell<String>,
    seed: [u8; 96],
    salt: [u8; 16],
    nonce: [u8; 12],
    asks: Cell<u32>,
}

impl FixedPassphrase {
    /// Answers `text` when asked, and makes the key of `seed`, sealed under `salt` and `nonce`.
    pub fn new(text: &str, seed: [u8; 96], salt: [u8; 16], nonce: [u8; 12]) -> FixedPassphrase {
        FixedPassphrase { answer: RefCell::new(text.to_string()), seed, salt, nonce, asks: Cell::new(0) }
    }

    /// Answers `text` from now on.
    pub fn answer(&self, text: &str) {
        *self.answer.borrow_mut() = text.to_string();
    }

    /// How many times it asked for the passphrase.
    pub fn asks(&self) -> u32 {
        self.asks.get()
    }

    /// Asks for the passphrase: counts, then checks what was typed.
    fn typed(&self) -> Result<Passphrase, Refusal> {
        self.asks.set(self.asks.get() + 1);
        Passphrase::new(Zeroizing::new(self.answer.borrow().clone()))
    }
}

impl Adapter for FixedPassphrase {
    fn label(&self) -> Label {
        label("fixed-passphrase")
    }
}

impl KeyHolder for FixedPassphrase {
    fn kind(&self) -> KeyKind {
        KeyKind::Passphrase
    }

    fn create(&self, prompt: &Prompt, commitment: &Commitment) -> Result<(KeyRef, PublicKey)> {
        let passphrase = self.typed()?;
        let key = DecapKey::from_seed(Zeroizing::new(self.seed));
        let record = PassphraseRecord::seal(prompt, &passphrase, &key, commitment, KdfParams::DEFAULT, &self.salt, &self.nonce)?;
        Ok((record.to_key_ref(), record.public().clone()))
    }

    fn public(&self, key: &KeyRef) -> Result<PublicKey> {
        Ok(PassphraseRecord::from_key_ref(key)?.public().clone())
    }

    fn decapsulate(&self, key: &KeyRef, prompt: &Prompt, ct: &KemCiphertext) -> Result<Released> {
        let record = PassphraseRecord::from_key_ref(key)?;
        let passphrase = self.typed()?;
        Ok(record.decapsulate(prompt, &passphrase, ct)?)
    }

    /// The record is the key ref itself, so there is nothing else to forget.
    fn destroy(&self, _key: &KeyRef) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::encapsulate;
    use crate::crypto::vectors::{KAT_HARDWARE_P256, hardware_rand, hardware_seed, hex};

    #[test]
    fn the_soft_key_counts_each_decapsulation() {
        let key = SoftKey::from_seed(hardware_seed());
        assert_eq!(key.public().p256.as_slice(), hex(KAT_HARDWARE_P256), "the key of its seed");
        let (ct, shares) = encapsulate(&key.public(), &hardware_rand()).unwrap();
        assert_eq!(key.decapsulations(), 0, "giving its public half is no decapsulation");
        for asked in 1..=3 {
            let back = key.shares_for(&ct).unwrap();
            assert_eq!((&back.mlkem, &back.p256), (&shares.mlkem, &shares.p256));
            assert_eq!(key.decapsulations(), asked);
        }
        // A ciphertext it refuses was still asked about.
        let mut compressed = ct.clone();
        compressed.p256_eph[0] = 0x02;
        assert_eq!(key.shares_for(&compressed).unwrap_err(), Refusal::Unreadable);
        assert_eq!(key.decapsulations(), 4);
    }
}
