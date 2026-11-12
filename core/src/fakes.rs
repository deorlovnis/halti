//! Adapters in memory, for tests: they keep what they are given and remember what they were asked.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::crypto::kem::DecapKey;
use crate::ids::{WsId, WsName};
use crate::key::{KemCiphertext, KemShares, PublicKey};
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

/// A software key in memory that counts how often it is asked for shares.
pub struct SoftKey {
    key: DecapKey,
    decapsulations: Cell<u32>,
}

impl SoftKey {
    /// From a 96-byte seed, as `DecapKey` takes it.
    pub fn from_seed(seed: [u8; 96]) -> SoftKey {
        SoftKey { key: DecapKey::from_seed(Zeroizing::new(seed)), decapsulations: Cell::new(0) }
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
