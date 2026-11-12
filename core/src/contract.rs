//! What every adapter must do, whatever it is made of. Run here against the adapters in memory;
//! an adapter over real files or a real keystore is held to the same.

use crate::anchor::{Anchor, Pin};
use crate::fakes::{MemFiles, MemKeystore};
use crate::ids::{WsId, WsName};
use crate::platform::Grade;
use crate::store::{FileKey, Files, ItemName, KeystoreBackend};

const A: WsId = WsId::from_bytes([0xa; 16]);
const B: WsId = WsId::from_bytes([0xb; 16]);

/// A keystore keeps each workspace's items apart and does what its four calls say. Give it an
/// empty one.
pub fn keystore_contract(store: &dyn KeystoreBackend) {
    let (one, two) = (ItemName::from_bytes([1; 32]), ItemName::from_bytes([2; 32]));
    assert_eq!(store.get(A, &one).unwrap(), None);
    assert!(!store.delete(A, &one).unwrap(), "nothing was there");
    assert!(store.list(A).unwrap().is_empty());

    store.put(A, &one, b"first").unwrap();
    store.put(A, &one, b"second").unwrap();
    assert_eq!(store.get(A, &one).unwrap().unwrap(), b"second", "put replaces");
    store.put(A, &two, b"").unwrap();
    assert_eq!(store.get(A, &two).unwrap().unwrap(), b"", "an empty value is a value");

    assert_eq!(store.get(B, &one).unwrap(), None, "another workspace's item");
    assert!(store.list(B).unwrap().is_empty());
    assert!(!store.delete(B, &one).unwrap(), "and it can't be deleted from there");
    store.put(B, &one, b"b's").unwrap();
    assert_eq!(store.get(A, &one).unwrap().unwrap(), b"second");

    let mut listed = store.list(A).unwrap();
    listed.sort();
    assert_eq!(listed, [one, two]);
    assert!(store.delete(A, &one).unwrap());
    assert_eq!(store.list(A).unwrap(), [two]);
    assert_eq!(store.get(B, &one).unwrap().unwrap(), b"b's");
}

/// Halti's files are kept by what they are, one workspace's apart from another's, and a
/// workspace's lock excludes. Give it one with no files.
pub fn files_contract(files: &dyn Files) {
    let name = |s: &str| WsName::parse(s).unwrap();
    assert!(files.names().unwrap().is_empty());
    assert_eq!(files.read(&FileKey::Manifest(A)).unwrap(), None);

    files.write_atomic(&FileKey::Policy(A), b"old").unwrap();
    files.write_atomic(&FileKey::Policy(A), b"new").unwrap();
    assert_eq!(files.read(&FileKey::Policy(A)).unwrap().unwrap(), b"new", "a write replaces the file whole");

    files.append(&FileKey::Log(A), b"one").unwrap();
    files.append(&FileKey::Log(A), b"two").unwrap();
    assert_eq!(files.read(&FileKey::Log(A)).unwrap().unwrap(), b"one\ntwo\n");
    assert_eq!(files.read(&FileKey::Log(B)).unwrap(), None, "one workspace's log isn't another's");
    assert_eq!(files.read(&FileKey::Policy(B)).unwrap(), None);
    assert_eq!(files.read(&FileKey::Manifest(A)).unwrap(), None, "nor is its policy its manifest");

    assert!(files.names().unwrap().is_empty(), "only a directory record gives a name");
    files.write_atomic(&FileKey::DirRecord(name("acme")), b"record").unwrap();
    files.write_atomic(&FileKey::DirRecord(name("globex")), b"record").unwrap();
    let mut names = files.names().unwrap();
    names.sort();
    assert_eq!(names, [name("acme"), name("globex")]);
    files.remove(&FileKey::DirRecord(name("acme"))).unwrap();
    assert_eq!(files.names().unwrap(), [name("globex")]);
    assert_eq!(files.read(&FileKey::DirRecord(name("acme"))).unwrap(), None);
    assert_eq!(files.read(&FileKey::Policy(A)).unwrap().unwrap(), b"new", "removing one file removes that file");
    files.remove(&FileKey::Manifest(B)).unwrap();

    let held = files.lock(A).unwrap();
    assert!(files.lock(A).is_err(), "a held lock can't be had again");
    let other = files.lock(B).unwrap();
    drop(held);
    let again = files.lock(A).unwrap();
    assert!(files.lock(B).is_err(), "and another workspace's is its own");
    drop((other, again));
}

/// An anchor keeps one pin per workspace, only lets its version rise, and forgets. Give it an
/// empty one.
///
/// It refuses only a version that does not rise: that core advances by exactly one is core's rule,
/// not the anchor's.
pub fn anchor_contract(anchor: &dyn Anchor) {
    let pin = |version: u64| Pin { version, key_ref: [1; 48], public_key: [2; 48], state: [3; 48] };
    assert_eq!(anchor.read(A).unwrap(), None);
    assert!(anchor.advance(A, &pin(0)).is_err(), "a first pin is version 1 or more");
    assert_eq!(anchor.read(A).unwrap(), None);

    anchor.advance(A, &pin(1)).unwrap();
    assert_eq!(anchor.read(A).unwrap(), Some(pin(1)));
    assert!(anchor.advance(A, &pin(1)).is_err(), "the same version again");
    assert!(anchor.advance(A, &pin(0)).is_err(), "a lower one");
    assert_eq!(anchor.read(A).unwrap(), Some(pin(1)), "a refused pin changes nothing");

    let second = Pin { state: [4; 48], ..pin(2) };
    anchor.advance(A, &second).unwrap();
    assert_eq!(anchor.read(A).unwrap(), Some(second), "the whole pin is replaced");
    anchor.advance(A, &pin(7)).unwrap();
    assert_eq!(anchor.read(A).unwrap(), Some(pin(7)), "any rise is kept");

    assert_eq!(anchor.read(B).unwrap(), None, "another workspace's");
    anchor.advance(B, &pin(1)).unwrap();
    assert_eq!(anchor.read(A).unwrap(), Some(pin(7)));
    assert_eq!(anchor.read(B).unwrap(), Some(pin(1)));

    anchor.forget(A).unwrap();
    assert_eq!(anchor.read(A).unwrap(), None);
    anchor.forget(A).unwrap();
    assert_eq!(anchor.read(B).unwrap(), Some(pin(1)), "forgetting one workspace's pin leaves another's");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::{FixedPassphrase, MemAnchor, SoftKey};
    use crate::platform::{Adapter, Property};

    #[test]
    fn the_keystore_in_memory_keeps_the_contract() {
        keystore_contract(&MemKeystore::new());
    }

    #[test]
    fn the_files_in_memory_keep_the_contract() {
        files_contract(&MemFiles::new());
    }

    #[test]
    fn the_memory_anchor_keeps_the_anchor_contract() {
        anchor_contract(&MemAnchor::new());
    }

    /// An adapter for tests says so: nothing may mistake it for one that protects anything.
    #[test]
    fn the_adapters_in_memory_are_labelled_dev_and_lack_everything() {
        let soft = SoftKey::from_seed([0; 96]);
        let passphrase = FixedPassphrase::new("acme passphrase one", [0; 96], [0; 16], [0; 12]);
        for label in [MemKeystore::new().label(), MemFiles::new().label(), MemAnchor::new().label(), soft.label(), passphrase.label()] {
            assert_eq!(label.grade, Grade::Dev, "{}", label.adapter);
            assert!(Property::ALL.iter().all(|p| label.lacks.contains(*p)), "{}", label.adapter);
            assert!(!label.why.is_empty());
        }
    }
}
