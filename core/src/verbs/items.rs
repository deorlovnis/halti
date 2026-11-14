//! The verbs on a workspace's secrets: store one, list them, remove some. Each starts as opening a
//! workspace does: admission, the record and its kinds, one approval naming its change, and the
//! manifest's checks. Then every name the manifest lists is checked against the secret it says it
//! is, under the workspace's names key: a list whose names and secrets disagree was changed, and
//! is `Refusal::Tampered`.
//!
//! The working keys are derived inside the unlock and wiped before it returns, so neither the key
//! values are sealed under nor the one they are named with leaves core. Values are reached only
//! through a `Keystore` bound to the workspace.
//!
//! A store puts the value's blob, then replaces the manifest; a remove replaces the manifest, then
//! deletes the blobs. Either cut short before the pin moves leaves the list as it was: at worst the
//! one secret being stored is unreadable until it is stored again, and a blob no list names is
//! never read and goes when the workspace is deleted.

use anyhow::Result;

use super::sequence::{Unlocked, unlock};
use super::ws::{Machine, kinds_match, opened_manifest, read_record};
use crate::boxkey::box_name;
use crate::holder::Change;
use crate::ids::{WsId, WsName};
use crate::item::{ItemKey, Secret, item_name, open_value, seal_value};
use crate::key::OpenKeys;
use crate::manifest::{Entry, Manifest};
use crate::policy::{Edit, Kind, apply};
use crate::refusal::Refusal;
use crate::store::Keystore;

/// Fresh random bytes the caller drew for one `ws_set`, never reused: the value's nonce and the new
/// manifest's.
pub struct Nonces {
    pub value: [u8; 12],
    pub manifest: [u8; 12],
}

/// What a store did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Put {
    /// The workspace had no secret of that name.
    Added,
    /// It had one, and the value stored replaced it.
    Replaced,
}

/// Whether a listed secret's value opens.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Readable,
    /// Its value is missing, or is not the one the list names: removed, put back from before, or
    /// changed. Which, it does not say.
    Unreadable,
}

/// One secret as a listing gives it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Stored {
    pub key: ItemKey,
    pub state: State,
}

/// What `ws_remove` removes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Which {
    /// One field of a resource.
    Field(ItemKey),
    /// Every field of a resource. It is checked as a resource is before anything is read.
    Resource(String),
}

impl Which {
    fn names(&self, key: &ItemKey) -> bool {
        match self {
            Which::Field(field) => field == key,
            Which::Resource(resource) => key.resource() == resource,
        }
    }

    /// As the person typed it: `github/token`, or `github`.
    fn text(&self) -> String {
        match self {
            Which::Field(field) => field.to_string(),
            Which::Resource(resource) => resource.clone(),
        }
    }
}

/// Stores a secret: one approval (`Change::Store`), then `value`, called once and only after the
/// approval and every check of the manifest. The value is sealed for the pin version this change
/// moves to, and replaces any value of that name.
///
/// A refusal, a "no", or a failure of `value` changes nothing. A failure after the value is put and
/// before the pin moves leaves that one secret unreadable, and storing it again mends it.
pub fn ws_set(machine: &Machine<'_>, name: &WsName, key: &ItemKey, value: impl FnOnce() -> Result<Secret>, nonces: Nonces) -> Result<Put> {
    with_list(machine, name, Change::Store, |ws, unlocked, manifest, keys| {
        let value = value()?;
        let version = unlocked.next()?;
        let item = item_name(keys.item_names(), key);
        let entry = Entry { name: item, version, key: key.clone() };
        let mut items = manifest.items;
        let put = match items.binary_search_by(|listed| listed.name.cmp(&item)) {
            Ok(at) => {
                items[at] = entry;
                Put::Replaced
            }
            Err(at) => {
                items.insert(at, entry);
                Put::Added
            }
        };
        // Sealed before anything is written, so a list that can't be sealed writes nothing.
        let sealed = Manifest { items, ..manifest }.seal(unlocked.inner, ws, name, &nonces.manifest)?;
        let blob = seal_value(keys.secrets(), ws, &item, version, &value, &nonces.value);
        Keystore::bind(ws, machine.keystore).put(&item, &blob)?;
        unlocked.replace_manifest(&sealed)?;
        Ok(put)
    })
}

/// Lists a workspace's secrets: one approval (`Change::Open`). Every listed secret, sorted by its
/// text, and whether its value opens; each value opened is wiped at once. Writes nothing, and
/// leaves the pin where it was.
pub fn ws_items(machine: &Machine<'_>, name: &WsName) -> Result<Vec<Stored>> {
    with_list(machine, name, Change::Open, |ws, _, manifest, keys| {
        let items = Keystore::bind(ws, machine.keystore);
        let mut stored = Vec::with_capacity(manifest.items.len());
        for entry in manifest.items {
            let opens = items.get(&entry.name)?.is_some_and(|blob| open_value(keys.secrets(), ws, &entry.name, entry.version, &blob).is_ok());
            stored.push(Stored { key: entry.key, state: if opens { State::Readable } else { State::Unreadable } });
        }
        // As text, not by resource and then field: `github-ee/token` comes before `github/token`.
        stored.sort_by_cached_key(|stored| stored.key.to_string());
        Ok(stored)
    })
}

/// Removes one field, or every field of a resource: one approval (`Change::Remove`). What it
/// removed, sorted by its text. A whole resource also loses its policy's approval, in the same
/// change. Naming none, and no approval, is `Refusal::NoSecret`, after the approval and with
/// nothing written.
///
/// The list is replaced first; then each value is deleted. Once the list is replaced the secrets
/// are gone from it, so a value that can't be deleted is left, sealed and named by no list, and
/// goes when the workspace is deleted.
pub fn ws_remove(machine: &Machine<'_>, name: &WsName, which: &Which, manifest_nonce: [u8; 12]) -> Result<Vec<ItemKey>> {
    if let Which::Resource(resource) = which {
        ItemKey::check_resource(resource)?;
    }
    with_list(machine, name, Change::Remove, |ws, unlocked, manifest, _| {
        let (gone, kept): (Vec<Entry>, Vec<Entry>) = manifest.items.into_iter().partition(|entry| which.names(&entry.key));
        let approvals = match which {
            Which::Field(_) => manifest.approvals.clone(),
            Which::Resource(resource) => apply(&manifest.approvals, [Edit::Drop(Kind::Resource, resource)]),
        };
        if gone.is_empty() && approvals == manifest.approvals {
            return Err(Refusal::NoSecret { ws: name.clone(), what: which.text() }.into());
        }
        let sealed = Manifest { items: kept, approvals, ..manifest }.seal(unlocked.inner, ws, name, &manifest_nonce)?;
        unlocked.replace_manifest(&sealed)?;
        let items = Keystore::bind(ws, machine.keystore);
        for entry in &gone {
            let _ = items.delete(&entry.name);
        }
        let mut removed: Vec<ItemKey> = gone.into_iter().map(|entry| entry.key).collect();
        removed.sort_by_cached_key(ToString::to_string);
        Ok(removed)
    })
}

/// Opens the workspace for `change` as `ws_open` does, checks every listed name against its
/// secret or box, and hands `then` the workspace's id, the unlock, the manifest and the working
/// keys, which are wiped when it returns.
pub(super) fn with_list<T>(machine: &Machine<'_>, name: &WsName, change: Change, then: impl FnOnce(WsId, &Unlocked<'_>, Manifest, &OpenKeys) -> Result<T>) -> Result<T> {
    machine.admit()?;
    let record = read_record(machine.host.files, name)?;
    kinds_match(machine, &record)?;
    unlock(&machine.host, record.id, name, machine.build, change, |unlocked| {
        let manifest = opened_manifest(machine, &record, name, unlocked)?;
        let keys = unlocked.inner.open_keys();
        if !names_hold(&manifest, keys.item_names()) {
            return Err(Refusal::Tampered.into());
        }
        then(record.id, unlocked, manifest, &keys)
    })
}

/// Whether every item and box the manifest lists is kept under the name its text gives under the
/// workspace's names key `names`. A list where one isn't was changed.
pub(super) fn names_hold(manifest: &Manifest, names: &[u8; 32]) -> bool {
    manifest.items.iter().all(|entry| item_name(names, &entry.key) == entry.name) && manifest.boxes.iter().all(|entry| box_name(names, &entry.name) == entry.item)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use anyhow::bail;
    use zeroize::Zeroizing;

    use super::*;
    use crate::anchor::{Anchor, Pin, state_hash};
    use crate::crypto::vectors::{
        ITEM_VALUE, KAT_HARDWARE_WRAP, KAT_ITEM_NAME, KAT_ITEM_NAME_GLOBEX, KAT_ITEM_VALUE, hardware_rand, hardware_seed, hex, inner_bytes, item_manifest_nonce, manifest_nonce,
        recovery_rand, recovery_seed, value_nonce, ws_bytes,
    };
    use crate::fakes::{MemAnchor, MemFiles, MemKeystore, SoftKey};
    use crate::holder::{KeyHolder, KeyKind};
    use crate::key::InnerKey;
    use crate::manifest::{LogHead, Recorded};
    use crate::platform::{Build, Grade, Lacks, Os, Property, Role};
    use crate::store::{FileKey, Files, ItemName, KeystoreBackend, KeystoreKind};
    use crate::verbs::{Deleted, Draws, Fresh, Host, ws_delete, ws_new, ws_open};

    // Every key here is held in software: nothing is derived at 64 MiB.

    const GLOBEX: WsId = WsId::from_bytes([2; 16]);
    /// globex's inner key.
    const GLOBEX_INNER: [u8; 32] = [0x22; 32];

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn ws_name(text: &str) -> WsName {
        WsName::parse(text).unwrap()
    }

    fn key(resource: &str, field: &str) -> ItemKey {
        ItemKey::parse(resource, field).unwrap()
    }

    fn field(resource: &str, field: &str) -> Which {
        Which::Field(key(resource, field))
    }

    /// The name `key` is kept under in the workspace of this inner key.
    fn name_under(inner: [u8; 32], key: &ItemKey) -> ItemName {
        item_name(InnerKey::from_bytes(Zeroizing::new(inner)).open_keys().item_names(), key)
    }

    /// Its name in acme.
    fn in_acme(key: &ItemKey) -> ItemName {
        name_under(inner_bytes(), key)
    }

    /// The refusal a verb failed with. Panics if it did not fail, or failed some other way.
    fn refused<T>(result: Result<T>) -> Refusal {
        result.err().expect("it fails").downcast::<Refusal>().expect("with a refusal")
    }

    fn secret(text: &str) -> Secret {
        Secret::new(Zeroizing::new(text.as_bytes().to_vec())).unwrap()
    }

    /// Each listed secret's text and whether it opens.
    fn shown(stored: &[Stored]) -> Vec<(String, State)> {
        stored.iter().map(|stored| (stored.key.to_string(), stored.state)).collect()
    }

    /// What a debug build on macOS records for acme, made with the adapters in memory and a key held in software.
    fn dev_manifest() -> Manifest {
        let recorded = |role: Role, adapter: &str| Recorded { role, adapter: adapter.to_string(), grade: Grade::Dev, lacks: Lacks::of(&Property::ALL) };
        Manifest {
            built_by: Build::Dev,
            origin: Os::Macos,
            key: KeyKind::Soft,
            keystore: KeystoreKind::Memory,
            trial: true,
            adapters: vec![
                recorded(Role::KeyHolder, "soft-key"),
                recorded(Role::Anchor, "mem-anchor"),
                recorded(Role::Files, "mem-files"),
                recorded(Role::Keystore, "mem-keystore"),
            ],
            pin_version: 0,
            log_head: LogHead::NONE,
            store: Vec::new(),
            keystore_ref: Vec::new(),
            items: Vec::new(),
            approvals: Vec::new(),
            boxes: Vec::new(),
        }
    }

    /// Everything of a workspace a secret verb could change: its manifest, any manifest beside it, its pin, and every value
    /// its keystore holds.
    type Kept = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Pin>, Vec<(ItemName, Vec<u8>)>);

    /// One machine's files, anchor and keystore, which acme and globex share, and a key held in software for each.
    struct World {
        files: MemFiles,
        anchor: MemAnchor,
        keystore: MemKeystore,
        acme: SoftKey,
        globex: SoftKey,
        drawn: Cell<u8>,
    }

    impl World {
        /// acme made, with the known answers' draws.
        fn new() -> World {
            let world = World {
                files: MemFiles::new(),
                anchor: MemAnchor::new(),
                keystore: MemKeystore::new(),
                acme: SoftKey::from_seed(hardware_seed()),
                globex: SoftKey::from_seed(recovery_seed()),
                drawn: Cell::new(0),
            };
            let fresh = Fresh { id: ws_bytes(), key: Draws { inner: Zeroizing::new(inner_bytes()), wrap: Zeroizing::new(hardware_rand()) }, manifest: manifest_nonce() };
            ws_new(&world.machine(&world.acme, Build::Dev), &ws_name("acme"), fresh).unwrap();
            world
        }

        /// And globex beside it, with its own draws.
        fn with_globex(self) -> World {
            let fresh = Fresh { id: *GLOBEX.as_bytes(), key: Draws { inner: Zeroizing::new(GLOBEX_INNER), wrap: Zeroizing::new(recovery_rand()) }, manifest: [0x33; 12] };
            ws_new(&self.machine(&self.globex, Build::Dev), &ws_name("globex"), fresh).unwrap();
            self
        }

        fn machine<'a>(&'a self, holder: &'a dyn KeyHolder, build: Build) -> Machine<'a> {
            Machine { host: Host { files: &self.files, holder, anchor: &self.anchor }, keystore: &self.keystore, build, os: Os::Macos }
        }

        /// The holder of the workspace of this name.
        fn holder(&self, text: &str) -> &SoftKey {
            if text == "globex" { &self.globex } else { &self.acme }
        }

        /// Nonces never drawn before in this world.
        fn nonces(&self) -> Nonces {
            let n = self.drawn.get() + 1;
            self.drawn.set(n);
            Nonces { value: [n; 12], manifest: [0x80 | n; 12] }
        }

        /// Each verb, in a debug build.
        fn set(&self, text: &str, key: &ItemKey, value: &str) -> Result<Put> {
            ws_set(&self.machine(self.holder(text), Build::Dev), &ws_name(text), key, || Ok(secret(value)), self.nonces())
        }

        fn items(&self, text: &str) -> Result<Vec<Stored>> {
            ws_items(&self.machine(self.holder(text), Build::Dev), &ws_name(text))
        }

        fn remove(&self, text: &str, which: &Which) -> Result<Vec<ItemKey>> {
            ws_remove(&self.machine(self.holder(text), Build::Dev), &ws_name(text), which, self.nonces().manifest)
        }

        fn file(&self, key: &FileKey) -> Option<Vec<u8>> {
            self.files.read(key).unwrap()
        }

        fn pin(&self, ws: WsId) -> Pin {
            self.anchor.read(ws).unwrap().unwrap()
        }

        fn blob(&self, ws: WsId, name: &ItemName) -> Option<Vec<u8>> {
            self.keystore.get(ws, name).unwrap()
        }

        /// The workspace's manifest, opened.
        fn manifest(&self, ws: WsId, text: &str, inner: [u8; 32]) -> Manifest {
            Manifest::open(&InnerKey::from_bytes(Zeroizing::new(inner)), ws, &ws_name(text), &self.file(&FileKey::Manifest(ws)).unwrap()).unwrap()
        }

        fn kept(&self, ws: WsId) -> Kept {
            let mut blobs: Vec<(ItemName, Vec<u8>)> = self.keystore.list(ws).unwrap().into_iter().map(|name| (name, self.blob(ws, &name).unwrap())).collect();
            blobs.sort();
            (self.file(&FileKey::Manifest(ws)), self.file(&FileKey::NextManifest(ws)), self.anchor.read(ws).unwrap(), blobs)
        }

        /// Seals `manifest` as acme's under acme's inner key, and moves the pin over it: what a program holding the inner
        /// key could write.
        fn plant(&self, manifest: &Manifest, nonce: [u8; 12]) {
            let sealed = manifest.seal(&InnerKey::from_bytes(Zeroizing::new(inner_bytes())), acme(), &ws_name("acme"), &nonce).unwrap();
            self.files.write_atomic(&FileKey::Manifest(acme()), &sealed).unwrap();
            let pin = self.pin(acme());
            let state = state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), &sealed, b"");
            self.anchor.advance(acme(), &Pin { version: pin.version + 1, state, ..pin }).unwrap();
        }

        /// acme with github/token, linear/token and github/user stored, in that order.
        fn three(self) -> World {
            for (resource, field) in [("github", "token"), ("linear", "token"), ("github", "user")] {
                assert_eq!(self.set("acme", &key(resource, field), &format!("acme {resource} {field}")).unwrap(), Put::Added);
            }
            self
        }
    }

    #[test]
    fn storing_takes_one_approval_and_seals_the_value() {
        let world = World::new();
        let (called, decapsulated) = (Cell::new(0), Cell::new(0));
        let value = || {
            called.set(called.get() + 1);
            decapsulated.set(world.acme.decapsulations());
            Ok(secret(ITEM_VALUE))
        };
        let nonces = Nonces { value: value_nonce(), manifest: item_manifest_nonce() };
        let put = ws_set(&world.machine(&world.acme, Build::Dev), &ws_name("acme"), &key("github", "token"), value, nonces).unwrap();
        assert_eq!(put, Put::Added);
        let asked: Vec<(Change, String)> = world.acme.asked().into_iter().map(|(.., change, text)| (change, text)).collect();
        assert_eq!(asked[1..], [(Change::Store, "[DEV, not protected] store a secret in workspace acme".to_string())]);
        assert_eq!((asked[0].0, world.acme.decapsulations()), (Change::Create, 1));
        assert_eq!((called.get(), decapsulated.get()), (1, 1), "called once, after the one decapsulation");
        // One value, under its known name, sealed as the independent implementation seals it.
        let name = ItemName::from_bytes(hex(KAT_ITEM_NAME).try_into().unwrap());
        assert_eq!(world.keystore.list(acme()).unwrap(), [name]);
        assert_eq!(world.blob(acme(), &name).unwrap(), hex(KAT_ITEM_VALUE));
        // The manifest is acme's with that one entry, at version 2, sealed with the nonce given.
        let listed = Manifest { items: vec![Entry { name, version: 2, key: key("github", "token") }], ..dev_manifest() };
        assert_eq!(world.manifest(acme(), "acme", inner_bytes()), listed);
        let sealed = world.file(&FileKey::Manifest(acme())).unwrap();
        assert_eq!(sealed, listed.seal(&InnerKey::from_bytes(Zeroizing::new(inner_bytes())), acme(), &ws_name("acme"), &item_manifest_nonce()).unwrap());
        assert_eq!(world.file(&FileKey::NextManifest(acme())), None);
        // The pin moved on by one, over that manifest.
        let pin = world.pin(acme());
        assert_eq!(pin.version, 2);
        assert_eq!(pin.state, state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), &sealed, b""));
    }

    #[test]
    fn storing_again_replaces_it_at_the_next_version() {
        let world = World::new();
        world.set("acme", &key("github", "token"), "first").unwrap();
        assert_eq!(world.set("acme", &key("github", "token"), "second").unwrap(), Put::Replaced);
        let name = in_acme(&key("github", "token"));
        assert_eq!(world.manifest(acme(), "acme", inner_bytes()).items, [Entry { name, version: 3, key: key("github", "token") }]);
        assert_eq!(world.keystore.list(acme()).unwrap(), [name]);
        assert_eq!(world.pin(acme()).version, 3);
        let secrets = *InnerKey::from_bytes(Zeroizing::new(inner_bytes())).open_keys().secrets();
        let blob = world.blob(acme(), &name).unwrap();
        assert_eq!(open_value(&secrets, acme(), &name, 3, &blob).unwrap().as_bytes(), b"second");
        assert_eq!(shown(&world.items("acme").unwrap()), [("github/token".to_string(), State::Readable)]);
    }

    #[test]
    fn the_list_gives_names_in_order_and_whether_each_opens() {
        let world = World::new().with_globex().three();
        let readable = [("github/token", State::Readable), ("github/user", State::Readable), ("linear/token", State::Readable)].map(|(text, state)| (text.to_string(), state));
        assert_eq!(shown(&world.items("acme").unwrap()), readable);
        assert_eq!(world.acme.asked().last().unwrap().2, Change::Open);
        let (token, linear) = (in_acme(&key("github", "token")), in_acme(&key("linear", "token")));

        // Lists github/token as unreadable and the rest as readable, writing nothing and with one decapsulation.
        let only_token_unreadable = |what: &str| {
            let (kept, decapsulations) = (world.kept(acme()), world.acme.decapsulations());
            let mut expected = readable.clone();
            expected[0].1 = State::Unreadable;
            assert_eq!(shown(&world.items("acme").unwrap()), expected, "{what}");
            assert!(world.kept(acme()) == kept, "{what}: nothing was written");
            assert_eq!(world.acme.decapsulations(), decapsulations + 1, "{what}");
        };
        // Its file removed.
        let first = world.blob(acme(), &token).unwrap();
        world.keystore.delete(acme(), &token).unwrap();
        only_token_unreadable("removed");
        // Stored again at a later version, then its version 2 file put back.
        world.set("acme", &key("github", "token"), "acme github token again").unwrap();
        let current = world.blob(acme(), &token).unwrap();
        assert_eq!(shown(&world.items("acme").unwrap()), readable, "stored again, it opens");
        world.keystore.put(acme(), &token, &first).unwrap();
        only_token_unreadable("put back from before");
        // Copied from globex, where the same secret is stored under globex's own name and key.
        world.set("globex", &key("github", "token"), "globex github token").unwrap();
        let theirs = world.blob(GLOBEX, &name_under(GLOBEX_INNER, &key("github", "token"))).unwrap();
        world.keystore.put(acme(), &token, &theirs).unwrap();
        only_token_unreadable("copied from globex");
        world.keystore.put(acme(), &token, &current).unwrap();
        assert_eq!(shown(&world.items("acme").unwrap()), readable, "put back as it was, it opens");

        // Two swapped: neither opens, and the third does.
        let linear_blob = world.blob(acme(), &linear).unwrap();
        world.keystore.put(acme(), &token, &linear_blob).unwrap();
        world.keystore.put(acme(), &linear, &current).unwrap();
        let pin = world.pin(acme());
        let swapped = [("github/token", State::Unreadable), ("github/user", State::Readable), ("linear/token", State::Unreadable)].map(|(text, state)| (text.to_string(), state));
        assert_eq!(shown(&world.items("acme").unwrap()), swapped);
        assert_eq!(world.pin(acme()), pin, "listing leaves the pin where it was");
    }

    #[test]
    fn the_list_is_in_the_order_of_its_text() {
        let world = World::new();
        for (resource, field) in [("github", "user"), ("github-ee", "token"), ("github", "token")] {
            world.set("acme", &key(resource, field), "a value").unwrap();
        }
        // `-` comes before `/`, so github-ee's fields come before github's.
        let listed = ["github-ee/token", "github/token", "github/user"].map(|text| (text.to_string(), State::Readable));
        assert_eq!(shown(&world.items("acme").unwrap()), listed);
    }

    #[test]
    fn removing_a_field_or_a_resource() {
        let world = World::new().three();
        let version = world.pin(acme()).version;
        assert_eq!(world.remove("acme", &field("github", "user")).unwrap(), [key("github", "user")]);
        assert_eq!(world.acme.asked().last().unwrap().3, "[DEV, not protected] remove secrets from workspace acme");
        assert_eq!(world.pin(acme()).version, version + 1);
        assert_eq!(world.blob(acme(), &in_acme(&key("github", "user"))), None);
        assert_eq!(shown(&world.items("acme").unwrap()), [("github/token".to_string(), State::Readable), ("linear/token".to_string(), State::Readable)]);

        // Naming nothing stored: refused after one ask, with everything as it was.
        for (which, said) in [(field("github", "user"), "there is no github/user in acme"), (Which::Resource("gitlab".to_string()), "there is no gitlab in acme")] {
            let (kept, asked) = (world.kept(acme()), world.acme.asked().len());
            let refusal = refused(world.remove("acme", &which));
            assert_eq!(refusal, Refusal::NoSecret { ws: ws_name("acme"), what: which.text() });
            assert_eq!(refusal.to_string(), said);
            assert_eq!(world.acme.asked().len(), asked + 1);
            assert!(world.kept(acme()) == kept, "{said}");
        }
        // A resource that can't be one: refused before anything is asked.
        let asked = world.acme.asked().len();
        assert_eq!(refused(world.remove("acme", &Which::Resource("Git".to_string()))), Refusal::BadSecretName);
        assert_eq!(world.acme.asked().len(), asked);

        // A resource removes all its fields, and only those.
        world.set("acme", &key("github", "user"), "acme github user").unwrap();
        assert_eq!(world.remove("acme", &Which::Resource("github".to_string())).unwrap(), [key("github", "token"), key("github", "user")]);
        assert_eq!(shown(&world.items("acme").unwrap()), [("linear/token".to_string(), State::Readable)]);
        assert_eq!(world.keystore.list(acme()).unwrap(), [in_acme(&key("linear", "token"))]);
    }

    #[test]
    fn a_refused_or_declined_store_changes_nothing() {
        let world = World::new();
        world.set("acme", &key("linear", "token"), "acme linear token").unwrap();
        let kept = world.kept(acme());
        let machine = world.machine(&world.acme, Build::Dev);
        // Declined: the value is never asked for.
        world.acme.decline(true);
        let called = Cell::new(false);
        let value = || {
            called.set(true);
            Ok(secret("never"))
        };
        assert_eq!(refused(ws_set(&machine, &ws_name("acme"), &key("github", "token"), value, world.nonces())), Refusal::Declined);
        assert!(!called.get());
        assert!(world.kept(acme()) == kept);
        world.acme.decline(false);
        // The value could not be had, or is not one a secret can hold.
        let error = ws_set(&machine, &ws_name("acme"), &key("github", "token"), || bail!("no value was given"), world.nonces()).unwrap_err();
        assert!(error.to_string().contains("no value"), "{error}");
        assert!(world.kept(acme()) == kept);
        let control = || Ok(Secret::new(Zeroizing::new(b"a\x1b[2J".to_vec()))?);
        assert_eq!(refused(ws_set(&machine, &ws_name("acme"), &key("github", "token"), control, world.nonces())), Refusal::BadSecret);
        assert!(world.kept(acme()) == kept);
        // A workspace that is not there is refused before anything is asked.
        let asked = world.acme.asked().len();
        assert_eq!(refused(world.set("initech", &key("github", "token"), "x")), Refusal::Unknown(ws_name("initech")));
        assert_eq!(world.acme.asked().len(), asked);
    }

    #[test]
    fn a_store_cut_short_leaves_only_that_secret_unreadable() {
        let world = World::new();
        world.set("acme", &key("github", "token"), "acme github token").unwrap();
        world.set("acme", &key("linear", "token"), "acme linear token").unwrap();
        let pin = world.pin(acme());
        // The value is put, and the pin is not moved.
        world.anchor.fail_next_advance();
        assert!(world.set("acme", &key("github", "token"), "acme github token two").unwrap_err().to_string().contains("could not be written"));
        assert_eq!(world.pin(acme()), pin);
        ws_open(&world.machine(&world.acme, Build::Dev), &ws_name("acme")).unwrap();
        assert_eq!(shown(&world.items("acme").unwrap()), [("github/token".to_string(), State::Unreadable), ("linear/token".to_string(), State::Readable)]);
        // A new one cut short is not listed at all.
        world.anchor.fail_next_advance();
        assert!(world.set("acme", &key("github", "user"), "acme github user").is_err());
        assert_eq!(shown(&world.items("acme").unwrap()).len(), 2);
        // Stored again, it opens.
        assert_eq!(world.set("acme", &key("github", "token"), "acme github token two").unwrap(), Put::Replaced);
        assert_eq!(shown(&world.items("acme").unwrap()), [("github/token".to_string(), State::Readable), ("linear/token".to_string(), State::Readable)]);
    }

    #[test]
    fn a_remove_cut_short_removes_nothing() {
        let world = World::new().three();
        let (manifest, _, pin, blobs) = world.kept(acme());
        // The list is not replaced, so no value is deleted.
        world.anchor.fail_next_advance();
        assert!(world.remove("acme", &field("github", "token")).unwrap_err().to_string().contains("could not be written"));
        let (after, _, pin_after, blobs_after) = world.kept(acme());
        assert!((after, pin_after, blobs_after) == (manifest, pin, blobs), "only a manifest beside the old may be left");
        let readable = [("github/token", State::Readable), ("github/user", State::Readable), ("linear/token", State::Readable)].map(|(text, state)| (text.to_string(), state));
        assert_eq!(shown(&world.items("acme").unwrap()), readable);
    }

    #[test]
    fn the_manifest_is_checked_before_the_value_is_asked_for() {
        let world = World::new();
        world.set("acme", &key("github", "token"), "acme github token").unwrap();
        let machine = world.machine(&world.acme, Build::Dev);
        let made = world.manifest(acme(), "acme", inner_bytes());
        // Recorded as lacking nothing, where the adapters in memory lack everything.
        let lacking_nothing: Vec<Recorded> = made.adapters.iter().map(|recorded| Recorded { lacks: Lacks::NONE, ..recorded.clone() }).collect();
        let cases = [
            (Manifest { adapters: lacking_nothing.clone(), ..made.clone() }, [0x45; 12], Refusal::Downgraded(Lacks::of(&Property::ALL))),
            (Manifest { built_by: Build::Release, ..made.clone() }, [0x46; 12], Refusal::OtherBuild(Build::Release)),
            // Both: which build made it is checked first.
            (Manifest { built_by: Build::Release, adapters: lacking_nothing, ..made }, [0x47; 12], Refusal::OtherBuild(Build::Release)),
        ];
        for (manifest, nonce, refusal) in cases {
            world.plant(&manifest, nonce);
            let kept = world.kept(acme());
            let called = Cell::new(false);
            let value = || {
                called.set(true);
                Ok(secret("x"))
            };
            assert_eq!(refused(ws_set(&machine, &ws_name("acme"), &key("github", "user"), value, world.nonces())), refusal);
            assert!(!called.get(), "{refusal}: the value is not asked for");
            assert_eq!(refused(world.items("acme")), refusal);
            assert_eq!(refused(world.remove("acme", &field("github", "token"))), refusal);
            assert!(world.kept(acme()) == kept, "{refusal}: nothing was written");
        }
    }

    #[test]
    fn secrets_of_one_workspace_never_reach_another() {
        let world = World::new().with_globex();
        world.set("acme", &key("github", "token"), "acme github token").unwrap();
        let calls = world.keystore.calls().len();
        world.set("globex", &key("github", "token"), "globex github token").unwrap();
        assert!(world.keystore.calls()[calls..].iter().all(|ws| *ws == GLOBEX), "storing in globex touched only globex's values");
        // The same secret has another name in each, the known answers' own.
        let (ours, theirs) = (in_acme(&key("github", "token")), name_under(GLOBEX_INNER, &key("github", "token")));
        assert_eq!((ours.as_bytes().as_slice(), theirs.as_bytes().as_slice()), (hex(KAT_ITEM_NAME).as_slice(), hex(KAT_ITEM_NAME_GLOBEX).as_slice()));
        assert_eq!((world.keystore.list(acme()).unwrap(), world.keystore.list(GLOBEX).unwrap()), (vec![ours], vec![theirs]));
        // Removing it from acme leaves globex's, which still opens.
        let globex = world.kept(GLOBEX);
        world.remove("acme", &field("github", "token")).unwrap();
        assert!(world.kept(GLOBEX) == globex);
        assert!(world.items("acme").unwrap().is_empty());
        assert_eq!(shown(&world.items("globex").unwrap()), [("github/token".to_string(), State::Readable)]);
    }

    #[test]
    fn a_list_whose_names_and_secrets_disagree_is_tampered() {
        let world = World::new();
        world.set("acme", &key("github", "token"), "acme github token").unwrap();
        // github/token listed under linear/token's name.
        let mut manifest = world.manifest(acme(), "acme", inner_bytes());
        manifest.items[0].name = in_acme(&key("linear", "token"));
        world.plant(&manifest, [0x44; 12]);
        let kept = world.kept(acme());
        let called = Cell::new(false);
        let value = || {
            called.set(true);
            Ok(secret("x"))
        };
        assert_eq!(refused(ws_set(&world.machine(&world.acme, Build::Dev), &ws_name("acme"), &key("github", "user"), value, world.nonces())), Refusal::Tampered);
        assert!(!called.get(), "the value is not asked for");
        assert_eq!(refused(world.items("acme")), Refusal::Tampered);
        assert_eq!(refused(world.remove("acme", &field("github", "token"))), Refusal::Tampered);
        assert!(world.kept(acme()) == kept);
    }

    #[test]
    fn a_release_build_refuses_dev_adapters_before_anything_is_read() {
        let world = World::new();
        let (reads, anchor_reads, asked) = (world.files.calls(), world.anchor.reads(), world.acme.asked().len());
        let keystore = world.keystore.calls().len();
        let release = world.machine(&world.acme, Build::Release);
        let soft = Refusal::NotAdmitted { adapter: "soft-key", grade: Grade::Dev };
        let called = Cell::new(false);
        let value = || {
            called.set(true);
            Ok(secret("x"))
        };
        assert_eq!(refused(ws_set(&release, &ws_name("acme"), &key("github", "token"), value, world.nonces())), soft);
        assert_eq!(refused(ws_items(&release, &ws_name("acme"))), soft);
        assert_eq!(refused(ws_remove(&release, &ws_name("acme"), &field("github", "token"), [0; 12])), soft);
        assert_eq!(refused(ws_remove(&release, &ws_name("acme"), &Which::Resource("github".to_string()), [0; 12])), soft);
        // Nothing was read, written or asked.
        assert!(!called.get());
        assert_eq!((world.files.calls(), world.anchor.reads(), world.acme.asked().len()), (reads, anchor_reads, asked));
        assert_eq!(world.keystore.calls().len(), keystore);
    }

    #[test]
    fn deleting_a_workspace_removes_its_secrets_and_any_next_manifest() {
        let world = World::new().with_globex().three();
        world.set("globex", &key("github", "token"), "globex github token").unwrap();
        let globex = world.kept(GLOBEX);
        world.files.write_atomic(&FileKey::NextManifest(acme()), b"left").unwrap();
        assert_eq!(ws_delete(&world.machine(&world.acme, Build::Dev), &ws_name("acme")).unwrap(), Deleted::Whole);
        assert_eq!(world.kept(acme()), (None, None, None, Vec::new()));
        assert!(world.kept(GLOBEX) == globex);
        assert_eq!(shown(&world.items("globex").unwrap()), [("github/token".to_string(), State::Readable)]);
    }
}
