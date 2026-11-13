//! Where a workspace's things are kept, as core sees it: stored values in a keystore and halti's
//! own files, both behind traits the binary implements for each OS.
//!
//! The keystore is where one workspace is kept apart from another. A backend takes the workspace
//! on every call, so equal names in two workspaces are two items. Code that works for a workspace
//! is handed a `Keystore`, which is bound to that workspace when it is made and has no way to name
//! another: whatever such code is tricked into asking for, it asks its own workspace.
//!
//! Values that core's verbs put are sealed (`item`): a backend sees only sealed blobs and 32-byte
//! names that spell nothing. What this does not yet do: a holder of the raw backend or of `Files`
//! can still name any workspace. Only adapters and the code that opens a workspace should hold
//! those.

use std::fmt;

use anyhow::Result;

use crate::ids::{WsId, WsName, write_hex};
use crate::platform::Adapter;
use crate::refusal::Refusal;

/// The name a stored value goes by: 32 opaque bytes. Core's verbs derive it from the secret's
/// text under the workspace's names key (`item::item_name`), so it never spells a client's name.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemName([u8; 32]);

impl ItemName {
    pub const fn from_bytes(bytes: [u8; 32]) -> ItemName {
        ItemName(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 64 lowercase hex characters, for an adapter that keeps one file or one entry per item.
impl fmt::Display for ItemName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for ItemName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

/// What kind of keystore keeps a workspace's items. Tags are written into records, so they are
/// fixed: 0x03 is kept for the Keychain, and 0x04 and up for vaults.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum KeystoreKind {
    /// In memory, for tests.
    Memory,
    /// One file per item.
    Files,
}

impl KeystoreKind {
    /// The byte that names it in a record: 0x01 memory, 0x02 files.
    pub const fn tag(self) -> u8 {
        match self {
            KeystoreKind::Memory => 0x01,
            KeystoreKind::Files => 0x02,
        }
    }

    /// Refuses a byte that names no kind this build knows.
    pub fn from_tag(tag: u8) -> Result<KeystoreKind, Refusal> {
        match tag {
            0x01 => Ok(KeystoreKind::Memory),
            0x02 => Ok(KeystoreKind::Files),
            _ => Err(Refusal::Unreadable),
        }
    }
}

/// Where stored values are kept. Every call names its workspace. Only `Keystore`, the adapters and
/// their contract should call it; nothing enforces that yet (see the top of this file).
pub trait KeystoreBackend: Adapter {
    /// What kind of keystore it is: written into each workspace's directory record and manifest.
    fn kind(&self) -> KeystoreKind;
    /// Stores the blob, replacing any under that name in that workspace.
    fn put(&self, ws: WsId, name: &ItemName, blob: &[u8]) -> Result<()>;
    fn get(&self, ws: WsId, name: &ItemName) -> Result<Option<Vec<u8>>>;
    /// Removes it; false if it wasn't there.
    fn delete(&self, ws: WsId, name: &ItemName) -> Result<bool>;
    /// Every name that workspace has, in any order.
    fn list(&self, ws: WsId) -> Result<Vec<ItemName>>;
}

/// Bound to one workspace for its whole life: the only way new code reaches stored values.
///
/// Nothing outside this crate can bind one, so no caller picks the workspace a handle reads:
///
/// ```compile_fail
/// let _ = halti_core::store::Keystore::bind;
/// ```
///
/// (That fails because `bind` is private, as this, which is public, does not.)
///
/// ```
/// let _ = halti_core::store::Keystore::ws;
/// ```
pub struct Keystore<'p> {
    ws: WsId,
    backend: &'p dyn KeystoreBackend,
}

impl<'p> Keystore<'p> {
    /// Binds a backend to one workspace. Nothing rebinds it.
    pub(crate) fn bind(ws: WsId, backend: &'p dyn KeystoreBackend) -> Keystore<'p> {
        Keystore { ws, backend }
    }

    pub fn ws(&self) -> WsId {
        self.ws
    }

    pub fn get(&self, item: &ItemName) -> Result<Option<Vec<u8>>> {
        self.backend.get(self.ws, item)
    }

    /// Stores the blob in this workspace, replacing any under that name.
    pub fn put(&self, item: &ItemName, blob: &[u8]) -> Result<()> {
        self.backend.put(self.ws, item, blob)
    }

    /// Removes it from this workspace; false if it wasn't there.
    pub fn delete(&self, item: &ItemName) -> Result<bool> {
        self.backend.delete(self.ws, item)
    }

    /// Every name this workspace has.
    pub fn list(&self) -> Result<Vec<ItemName>> {
        self.backend.list(self.ws)
    }
}

/// One file of halti's own: named by what it is, never by a path. A workspace is found by its
/// name (the directory record) and everything else of it by its id.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum FileKey {
    DirRecord(WsName),
    Manifest(WsId),
    /// A manifest written to replace the one there, kept only until it is put in its place: the
    /// pin moves on to it in between, so a crash leaves one of the two covered.
    NextManifest(WsId),
    Policy(WsId),
    Log(WsId),
    /// What the key holder needs to find the workspace's key again (`holder::KeyRef`).
    KeyRef(WsId),
    /// The inner key, wrapped to the workspace's key.
    Wrap(WsId),
}

/// Holds a workspace's lock until it is dropped.
pub trait Held {}

/// Halti's own files, outside any folder a box sees.
pub trait Files: Adapter {
    fn read(&self, k: &FileKey) -> Result<Option<Vec<u8>>>;
    /// Replaces the file whole, or not at all.
    fn write_atomic(&self, k: &FileKey, bytes: &[u8]) -> Result<()>;
    /// Writes the file whole, only if there is none, and says whether it did: false if one was
    /// there, which is left as it is. Two calls for one file at once never both return true.
    fn create_new(&self, k: &FileKey, bytes: &[u8]) -> Result<bool>;
    /// Adds `line` and a newline to the end, making the file if it isn't there. `line` holds no
    /// newline of its own.
    fn append(&self, k: &FileKey, line: &[u8]) -> Result<()>;
    /// Removes the file; one that isn't there is not an error.
    fn remove(&self, k: &FileKey) -> Result<()>;
    /// Every name that has a directory record, or an error: never part of the list. A caller counts
    /// these to tell whether there is only one workspace, so a record that can't be read must fail
    /// the call, not be left out.
    fn names(&self) -> Result<Vec<WsName>>;
    /// Takes the workspace's lock, or fails at once if it is held: it never waits. Dropping what
    /// it returns lets the lock go.
    fn lock(&self, ws: WsId) -> Result<Box<dyn Held>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::MemKeystore;

    const ACME: WsId = WsId::from_bytes([1; 16]);
    const GLOBEX: WsId = WsId::from_bytes([2; 16]);
    /// The same name in both workspaces, as `linear/token` would be once names are derived.
    const TOKEN: ItemName = ItemName::from_bytes([7; 32]);
    const OTHER: ItemName = ItemName::from_bytes([8; 32]);

    #[test]
    fn the_same_item_name_in_two_workspaces_is_two_items() {
        let backend = MemKeystore::new();
        let (acme, globex) = (Keystore::bind(ACME, &backend), Keystore::bind(GLOBEX, &backend));
        acme.put(&TOKEN, b"acme's").unwrap();
        globex.put(&TOKEN, b"globex's").unwrap();
        assert_eq!(acme.get(&TOKEN).unwrap().unwrap(), b"acme's");
        assert_eq!(globex.get(&TOKEN).unwrap().unwrap(), b"globex's");
    }

    #[test]
    fn a_handle_cannot_read_another_workspaces_item() {
        let backend = MemKeystore::new();
        Keystore::bind(ACME, &backend).put(&TOKEN, b"acme's").unwrap();
        let globex = Keystore::bind(GLOBEX, &backend);
        assert_eq!(globex.ws(), GLOBEX);
        assert_eq!(globex.get(&TOKEN).unwrap(), None, "the name is right and the workspace isn't");
    }

    #[test]
    fn a_handle_lists_only_its_own_items() {
        let backend = MemKeystore::new();
        let (acme, globex) = (Keystore::bind(ACME, &backend), Keystore::bind(GLOBEX, &backend));
        acme.put(&TOKEN, b"a").unwrap();
        acme.put(&OTHER, b"b").unwrap();
        globex.put(&OTHER, b"c").unwrap();
        let mut listed = acme.list().unwrap();
        listed.sort();
        assert_eq!(listed, [TOKEN, OTHER]);
        assert_eq!(globex.list().unwrap(), [OTHER]);
        assert_eq!(Keystore::bind(WsId::from_bytes([3; 16]), &backend).list().unwrap(), []);
    }

    #[test]
    fn deleting_through_one_handle_leaves_the_other_workspace_alone() {
        let backend = MemKeystore::new();
        let (acme, globex) = (Keystore::bind(ACME, &backend), Keystore::bind(GLOBEX, &backend));
        acme.put(&TOKEN, b"acme's").unwrap();
        globex.put(&TOKEN, b"globex's").unwrap();
        assert!(acme.delete(&TOKEN).unwrap());
        assert!(!acme.delete(&TOKEN).unwrap(), "it was gone already");
        assert_eq!(acme.get(&TOKEN).unwrap(), None);
        assert_eq!(globex.get(&TOKEN).unwrap().unwrap(), b"globex's");
    }

    #[test]
    fn every_backend_call_carries_the_handles_own_workspace() {
        let backend = MemKeystore::new();
        let globex = Keystore::bind(GLOBEX, &backend);
        globex.put(&TOKEN, b"x").unwrap();
        globex.get(&TOKEN).unwrap();
        globex.list().unwrap();
        globex.delete(&TOKEN).unwrap();
        assert_eq!(backend.calls(), [GLOBEX; 4]);
    }

    /// Byte for byte: these go into a workspace's directory record and manifest.
    #[test]
    fn a_keystore_kind_is_written_as_its_fixed_tag() {
        assert_eq!((KeystoreKind::Memory.tag(), KeystoreKind::Files.tag()), (0x01, 0x02));
        for tag in 0..=255 {
            let known = match tag {
                0x01 => Ok(KeystoreKind::Memory),
                0x02 => Ok(KeystoreKind::Files),
                _ => Err(Refusal::Unreadable),
            };
            assert_eq!(KeystoreKind::from_tag(tag), known, "tag {tag}");
        }
        assert_eq!(MemKeystore::new().kind(), KeystoreKind::Memory);
    }

    #[test]
    fn an_item_name_prints_as_64_hex_characters() {
        assert_eq!(TOKEN.to_string(), "07".repeat(32));
        assert_eq!(format!("{TOKEN:?}"), TOKEN.to_string());
        assert_eq!(ItemName::from_bytes(*TOKEN.as_bytes()), TOKEN);
    }
}
