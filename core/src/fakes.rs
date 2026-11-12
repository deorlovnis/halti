//! Adapters in memory, for tests: they keep what they are given and remember what they were asked.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use anyhow::{Result, bail};

use crate::ids::{WsId, WsName};
use crate::platform::{Adapter, Grade, Label, Lacks, Property};
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
