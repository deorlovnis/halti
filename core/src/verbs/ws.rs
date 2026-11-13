//! The workspace verbs: make, open, delete and list. Each admits first, reads the workspace's
//! directory record, and reaches its key only through the sequences, so nothing is made without
//! its record and manifest or opened without their checks.

use anyhow::{Result, bail};

use super::sequence::{Draws, Host, Opened, create_key, opened, unlock};
use crate::anchor::Anchor;
use crate::directory::DirRecord;
use crate::holder::{Change, KeyKind};
use crate::ids::{WsId, WsName};
use crate::manifest::{LogHead, Manifest, Recorded};
use crate::platform::{Build, Label, Lacks, Os, Role, admit};
use crate::refusal::Refusal;
use crate::store::{FileKey, Files, Keystore, KeystoreBackend};

/// Every workspace is marked trial while its formats may still change.
const TRIAL: bool = true;

/// What this machine is, for the workspace verbs: the sequences' adapters, the keystore, how the
/// binary was built and the system it runs on. The binary fills it; core never works any of it
/// out for itself.
pub struct Machine<'a> {
    pub host: Host<'a>,
    pub keystore: &'a dyn KeystoreBackend,
    pub build: Build,
    pub os: Os,
}

impl Machine<'_> {
    /// Each adapter in use, with the part it plays.
    fn adapters(&self) -> [(Role, Label); 4] {
        [(Role::KeyHolder, self.host.holder.label()), (Role::Anchor, self.host.anchor.label()), (Role::Files, self.host.files.label()), (Role::Keystore, self.keystore.label())]
    }

    /// Admission: a release build never runs a key held in software, whatever its label says,
    /// then `platform::admit`.
    fn admit(&self) -> Result<(), Refusal> {
        let holder = self.host.holder.label();
        if self.build == Build::Release && self.host.holder.kind() == KeyKind::Soft {
            return Err(Refusal::NotAdmitted { adapter: holder.adapter, grade: holder.grade });
        }
        admit(&self.adapters().map(|(_, label)| label), self.build, self.os)
    }
}

/// Fresh random bytes the caller drew for a new workspace, never reused: its id, its key's draws,
/// and the nonce its first manifest is sealed under.
pub struct Fresh {
    pub id: [u8; 16],
    pub key: Draws,
    pub manifest: [u8; 12],
}

/// What opening hands out: the working keys, split, and what the workspace was made with.
#[derive(Debug)]
pub struct Workspace {
    pub id: WsId,
    pub keys: Opened,
    pub manifest: Manifest,
}

/// One workspace as the directory lists it, without opening it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Listed {
    pub name: WsName,
    /// What its record says, or none if it can't be read.
    pub record: Option<DirRecord>,
    /// Whether the record's id has a pin. One without never finished, and `ws_delete` clears its
    /// files with no approval. Read through the record in clear, so it says what the record claims.
    pub pinned: bool,
}

/// Which way a delete went, so the binary can say what was left.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Deleted {
    /// With one approval: the items, the pin, the key, the files and the record.
    Whole,
    /// With none, since the workspace had no pin: its files and record only. Any items, and a key
    /// its holder keeps, are left.
    FilesOnly,
}

/// Makes a workspace: one approval, no decapsulation. Refuses adapters this build does not admit,
/// an id in use, a manifest that would not read back and a taken name, all before the key holder
/// is asked.
///
/// The record is written first, and only if the name has none, so every failure after it leaves a
/// workspace `ws_delete` finds by name. The pin is written last, so none of them opens. If the
/// holder made no key this sequence recorded, the record goes again and the name is free.
pub fn ws_new(machine: &Machine<'_>, name: &WsName, fresh: Fresh) -> Result<WsId> {
    machine.admit()?;
    let Fresh { id, key, manifest: nonce } = fresh;
    let (files, ws) = (machine.host.files, WsId::from_bytes(id));
    if machine.host.anchor.read(ws)?.is_some() {
        bail!("workspace id {ws} is already in use");
    }
    for file in [FileKey::KeyRef(ws), FileKey::Wrap(ws), FileKey::Manifest(ws)] {
        if files.read(&file)?.is_some() {
            bail!("workspace id {ws} is already in use");
        }
    }
    let record = DirRecord { id: ws, key: machine.host.holder.kind(), keystore: machine.keystore.kind() };
    let manifest = Manifest {
        built_by: machine.build,
        origin: machine.os,
        key: record.key,
        keystore: record.keystore,
        trial: TRIAL,
        adapters: machine.adapters().iter().map(|(role, label)| Recorded::of(*role, label)).collect(),
        pin_version: 0,
        log_head: LogHead::NONE,
        store: Vec::new(),
        keystore_ref: Vec::new(),
        items: Vec::new(),
    };
    manifest.check()?;
    if !files.create_new(&FileKey::DirRecord(name.clone()), &record.to_bytes())? {
        return Err(Refusal::Taken(name.clone()).into());
    }
    let made = create_key(&machine.host, ws, name, machine.build, key, |inner| files.write_atomic(&FileKey::Manifest(ws), &manifest.seal(inner, ws, name, &nonce)?));
    if let Err(error) = made {
        // No key ref was written: the holder made no key, or one this sequence never recorded. The name is free again. Past
        // that, the record stays for `ws_delete` to find.
        if matches!(files.read(&FileKey::KeyRef(ws)), Ok(None)) {
            let _ = files.remove(&FileKey::DirRecord(name.clone()));
        }
        return Err(error);
    }
    Ok(ws)
}

/// Opens a workspace: the checks that need no answer, one decapsulation, then the manifest.
/// Nothing is handed out unless every check passes.
///
/// The record's kinds are checked before the key holder is asked; what the manifest says, after,
/// since only the inner key opens it: that it agrees with the record, that a build of this kind
/// made it, and that nothing is lacking now that was not lacking then.
pub fn ws_open(machine: &Machine<'_>, name: &WsName) -> Result<Workspace> {
    machine.admit()?;
    let record = read_record(machine.host.files, name)?;
    kinds_match(machine, &record)?;
    unlock(&machine.host, record.id, name, machine.build, Change::Open, |unlocked| {
        let manifest = checked(Manifest::open(unlocked.inner, record.id, name, unlocked.manifest)?, &record, machine.build)?;
        not_weaker(&manifest, &machine.adapters())?;
        Ok(Workspace { id: record.id, keys: opened(unlocked.inner), manifest })
    })
}

/// Deletes a workspace: one approval naming the deletion, then its items, its pin, its key, its
/// files and its record, in that order. One with no pin loses its files and record with no
/// approval, and keeps any items and key. It says which of the two it did.
///
/// A workspace that fails a check is refused, and nothing of it is removed. The key destroyed is
/// the key ref the pin was checked against, never one read again.
pub fn ws_delete(machine: &Machine<'_>, name: &WsName) -> Result<Deleted> {
    machine.admit()?;
    let record = read_record(machine.host.files, name)?;
    kinds_match(machine, &record)?;
    let (files, ws) = (machine.host.files, record.id);
    if machine.host.anchor.read(ws)?.is_none() {
        let _held = files.lock(ws)?;
        if machine.host.anchor.read(ws)?.is_some() {
            bail!("workspace {name} is being made; try again");
        }
        // Nothing proves this one never finished, so only the files go: never its items or a key.
        remove_files(files, ws, name)?;
        return Ok(Deleted::FilesOnly);
    }
    unlock(&machine.host, ws, name, machine.build, Change::Delete, |unlocked| {
        checked(Manifest::open(unlocked.inner, ws, name, unlocked.manifest)?, &record, machine.build)?;
        // The items first: a crash here leaves a pinned workspace, whose items need the approval again.
        let items = Keystore::bind(ws, machine.keystore);
        for item in items.list()? {
            items.delete(&item)?;
        }
        // From here nothing opens, and a delete cut short is finished by the path with no pin.
        machine.host.anchor.forget(ws)?;
        machine.host.holder.destroy(unlocked.key_ref)?;
        remove_files(files, ws, name)?;
        Ok(Deleted::Whole)
    })
}

/// Every workspace in the directory, by name. Nothing secret is read and nothing is asked: a
/// program that only starts runs may call it.
///
/// A record that can't be read, or is gone since the names were listed, is listed with none. An
/// adapter's error fails the whole call, so no workspace is left out.
pub fn ws_list(files: &dyn Files, anchor: &dyn Anchor) -> Result<Vec<Listed>> {
    let mut names = files.names()?;
    names.sort();
    let mut listed = Vec::with_capacity(names.len());
    for name in names {
        let record = files.read(&FileKey::DirRecord(name.clone()))?.and_then(|bytes| DirRecord::from_bytes(&bytes).ok());
        let pinned = match record {
            Some(record) => anchor.read(record.id)?.is_some(),
            None => false,
        };
        listed.push(Listed { name, record, pinned });
    }
    Ok(listed)
}

/// The workspace's directory record: `Refusal::Unknown` if it has none, `Refusal::Unreadable` if
/// it is not one.
fn read_record(files: &dyn Files, name: &WsName) -> Result<DirRecord> {
    let Some(bytes) = files.read(&FileKey::DirRecord(name.clone()))? else { return Err(Refusal::Unknown(name.clone()).into()) };
    Ok(DirRecord::from_bytes(&bytes)?)
}

/// Before anything is asked: the record names the kinds of key holder and keystore this machine
/// has. Another would be found only after the holder had answered, or not at all.
fn kinds_match(machine: &Machine<'_>, record: &DirRecord) -> Result<(), Refusal> {
    if record.key == machine.host.holder.kind() && record.keystore == machine.keystore.kind() { Ok(()) } else { Err(Refusal::Unreadable) }
}

/// After the holder has answered: the manifest agrees with the record, and a build of this kind
/// made it.
fn checked(manifest: Manifest, record: &DirRecord, build: Build) -> Result<Manifest, Refusal> {
    if manifest.key != record.key || manifest.keystore != record.keystore {
        return Err(Refusal::Tampered);
    }
    if manifest.built_by != build {
        return Err(Refusal::OtherBuild(manifest.built_by));
    }
    Ok(manifest)
}

/// Refuses an open where any adapter in use lacks something its recorded one did not, naming all
/// of it. Grades are not compared: what is lacking is the rule.
fn not_weaker(manifest: &Manifest, now: &[(Role, Label)]) -> Result<(), Refusal> {
    let mut more = Lacks::NONE;
    for (role, label) in now {
        let Some(recorded) = manifest.adapters.iter().find(|recorded| recorded.role == *role) else { return Err(Refusal::Tampered) };
        for property in label.lacks.beyond(recorded.lacks).iter() {
            more = more.with(property);
        }
    }
    if more.is_empty() { Ok(()) } else { Err(Refusal::Downgraded(more)) }
}

/// Removes the workspace's files, then its record last, so a run cut short is found by name again.
fn remove_files(files: &dyn Files, ws: WsId, name: &WsName) -> Result<()> {
    for file in [FileKey::Wrap(ws), FileKey::KeyRef(ws), FileKey::Manifest(ws), FileKey::NextManifest(ws), FileKey::Policy(ws), FileKey::Log(ws)] {
        files.remove(&file)?;
    }
    files.remove(&FileKey::DirRecord(name.clone()))
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::anchor::{Pin, key_ref_hash, public_key_hash, state_hash};
    use crate::crypto::vectors::{
        KAT_DEV_MANIFEST, KAT_DEV_PIN_STATE, KAT_HARDWARE_WRAP, KAT_KEY_ITEM_NAMES, KAT_KEY_STORE, KAT_PASSPHRASE_RECORD, PASSPHRASE, hardware_rand, hardware_seed, hex,
        inner_bytes, manifest_nonce, passphrase_nonce, passphrase_salt, recovery_rand, recovery_seed, ws_bytes,
    };
    use crate::fakes::{FixedPassphrase, MemAnchor, MemFiles, MemKeystore, SoftKey};
    use crate::holder::{KeyHolder, KeyRef};
    use crate::key::InnerKey;
    use crate::platform::{Adapter, Grade, Property};
    use crate::store::{ItemName, KeystoreKind};

    // Only `a_new_workspace_with_a_passphrase_takes_one_ask_to_make_and_one_to_open` derives a key at 64 MiB, once to make and
    // once to open. Every other test here holds its key in software and derives nothing.

    const GLOBEX: WsId = WsId::from_bytes([2; 16]);
    /// An id nothing was made under.
    const FRESH: WsId = WsId::from_bytes([5; 16]);
    /// The same item name in every workspace.
    const ITEM: ItemName = ItemName::from_bytes([7; 32]);

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn ws_name(text: &str) -> WsName {
        WsName::parse(text).unwrap()
    }

    /// The known answers' inner key.
    fn inner() -> InnerKey {
        InnerKey::from_bytes(Zeroizing::new(inner_bytes()))
    }

    /// What the caller draws for acme: the known answers' id, inner key, wrap randomness and manifest nonce.
    fn acme_fresh() -> Fresh {
        Fresh { id: ws_bytes(), key: Draws { inner: Zeroizing::new(inner_bytes()), wrap: Zeroizing::new(hardware_rand()) }, manifest: manifest_nonce() }
    }

    /// And for globex: other bytes for each.
    fn globex_fresh() -> Fresh {
        Fresh { id: *GLOBEX.as_bytes(), key: Draws { inner: Zeroizing::new([0x22; 32]), wrap: Zeroizing::new(recovery_rand()) }, manifest: [0x33; 12] }
    }

    /// The refusal a verb failed with. Panics if it did not fail, or failed some other way.
    fn refused<T>(result: Result<T>) -> Refusal {
        result.err().expect("it fails").downcast::<Refusal>().expect("with a refusal")
    }

    /// What a debug build on macOS records for a workspace made with the adapters in memory and a key of `key`, whose holder is
    /// labelled `holder`: each adapter dev and lacking everything, and every place kept for later empty.
    fn dev_manifest(key: KeyKind, holder: &str) -> Manifest {
        let recorded = |role: Role, adapter: &str| Recorded { role, adapter: adapter.to_string(), grade: Grade::Dev, lacks: Lacks::of(&Property::ALL) };
        Manifest {
            built_by: Build::Dev,
            origin: Os::Macos,
            key,
            keystore: KeystoreKind::Memory,
            trial: true,
            adapters: vec![recorded(Role::KeyHolder, holder), recorded(Role::Anchor, "mem-anchor"), recorded(Role::Files, "mem-files"), recorded(Role::Keystore, "mem-keystore")],
            pin_version: 0,
            log_head: LogHead::NONE,
            store: Vec::new(),
            keystore_ref: Vec::new(),
            items: Vec::new(),
        }
    }

    /// What acme's record says when a debug build makes it with a key held in software.
    fn acme_record() -> DirRecord {
        DirRecord { id: acme(), key: KeyKind::Soft, keystore: KeystoreKind::Memory }
    }

    /// Whether the soft key was shown a prompt for this change.
    fn asked_to(holder: &SoftKey, change: Change) -> bool {
        holder.asked().iter().any(|(.., asked, _)| *asked == change)
    }

    /// What `World::everything` gathers: the six files, the pin and the item.
    type Everything = (Vec<Option<Vec<u8>>>, Option<Pin>, Option<Vec<u8>>);

    /// One machine's files, anchor and keystore, which acme and globex share, and a key held in software for each: a
    /// `SoftKey` keeps the commitment of one workspace only.
    struct World {
        files: MemFiles,
        anchor: MemAnchor,
        keystore: MemKeystore,
        acme: SoftKey,
        globex: SoftKey,
    }

    impl World {
        fn new() -> World {
            World {
                files: MemFiles::new(),
                anchor: MemAnchor::new(),
                keystore: MemKeystore::new(),
                acme: SoftKey::from_seed(hardware_seed()),
                globex: SoftKey::from_seed(recovery_seed()),
            }
        }

        /// This machine with `holder`, as a binary of `build` on macOS fills it.
        fn machine<'a>(&'a self, holder: &'a dyn KeyHolder, build: Build) -> Machine<'a> {
            Machine { host: Host { files: &self.files, holder, anchor: &self.anchor }, keystore: &self.keystore, build, os: Os::Macos }
        }

        /// Each verb, in a debug build.
        fn make(&self, holder: &dyn KeyHolder, text: &str, fresh: Fresh) -> Result<WsId> {
            ws_new(&self.machine(holder, Build::Dev), &ws_name(text), fresh)
        }

        fn open(&self, holder: &dyn KeyHolder, text: &str) -> Result<Workspace> {
            ws_open(&self.machine(holder, Build::Dev), &ws_name(text))
        }

        fn delete(&self, holder: &dyn KeyHolder, text: &str) -> Result<Deleted> {
            ws_delete(&self.machine(holder, Build::Dev), &ws_name(text))
        }

        /// acme, made with its own key and the known answers' draws.
        fn made(self) -> World {
            assert_eq!(self.make(&self.acme, "acme", acme_fresh()).unwrap(), acme());
            self
        }

        fn file(&self, key: &FileKey) -> Option<Vec<u8>> {
            self.files.read(key).unwrap()
        }

        /// Everything of one workspace: its record, key ref, wrap, manifest, policy and log, its pin and its item.
        fn everything(&self, ws: WsId, text: &str) -> Everything {
            let files = [FileKey::DirRecord(ws_name(text)), FileKey::KeyRef(ws), FileKey::Wrap(ws), FileKey::Manifest(ws), FileKey::Policy(ws), FileKey::Log(ws)];
            let files = files.map(|key| self.file(&key));
            (files.to_vec(), self.anchor.read(ws).unwrap(), self.keystore.get(ws, &ITEM).unwrap())
        }

        /// Advances the workspace's pin to match its files as they are: what a program running as the user can do where the
        /// pin is kept in a file.
        fn repin(&self, ws: WsId, text: &str, holder: &dyn KeyHolder) {
            let file = |key: FileKey| self.file(&key).unwrap_or_default();
            let key_ref = KeyRef(file(FileKey::KeyRef(ws)));
            let public = holder.public(&key_ref).unwrap();
            let version = self.anchor.read(ws).unwrap().map_or(1, |pin| pin.version + 1);
            let state = state_hash(ws, &ws_name(text), &file(FileKey::Wrap(ws)), &file(FileKey::Manifest(ws)), &file(FileKey::Policy(ws)));
            self.anchor.advance(ws, &Pin { version, key_ref: key_ref_hash(ws, holder.kind(), &key_ref), public_key: public_key_hash(ws, &public), state }).unwrap();
        }

        /// Seals `manifest` under acme's inner key for `ws` and `text`, puts it in place of acme's, and rewrites acme's pin to
        /// match: what that program can do once it has the inner key. The nonce is fixed: nothing a test seals is secret.
        fn plant(&self, manifest: &Manifest, ws: WsId, text: &str) {
            let sealed = manifest.seal(&inner(), ws, &ws_name(text), &[0x44; 12]).unwrap();
            self.files.write_atomic(&FileKey::Manifest(acme()), &sealed).unwrap();
            self.repin(acme(), "acme", &self.acme);
        }
    }

    #[test]
    fn a_new_workspace_takes_one_approval_and_opens_to_its_manifest_and_keys() {
        let world = World::new().made();
        assert_eq!((world.acme.creates(), world.acme.decapsulations()), (1, 0));
        assert_eq!(world.acme.asked(), [(acme(), ws_name("acme"), Change::Create, "[DEV, not protected] create workspace acme".to_string())]);
        // The record: its format, the id and the two kinds, and nothing of the name.
        let record = world.file(&FileKey::DirRecord(ws_name("acme"))).unwrap();
        assert_eq!(record, [[0x01].as_slice(), ws_bytes().as_slice(), [0x04, 0x01].as_slice()].concat());
        assert!(!record.windows(4).any(|four| four == b"acme"));
        // The manifest a debug build on macOS records, sealed under the inner key, as the independent implementation seals it.
        let sealed = world.file(&FileKey::Manifest(acme())).unwrap();
        assert_eq!(sealed, dev_manifest(KeyKind::Soft, "soft-key").seal(&inner(), acme(), &ws_name("acme"), &manifest_nonce()).unwrap());
        assert_eq!(sealed, hex(KAT_DEV_MANIFEST));
        // The first pin covers the manifest actually written.
        let pin = world.anchor.read(acme()).unwrap().unwrap();
        assert_eq!(pin.version, 1);
        assert_eq!(pin.state, state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), &sealed, b""));
        assert_eq!(pin.state.as_slice(), hex(KAT_DEV_PIN_STATE));

        let workspace = world.open(&world.acme, "acme").unwrap();
        assert_eq!((world.acme.creates(), world.acme.decapsulations()), (1, 1));
        assert_eq!(world.acme.asked()[1], (acme(), ws_name("acme"), Change::Open, "[DEV, not protected] open workspace acme".to_string()));
        assert_eq!(workspace.id, acme());
        assert_eq!(workspace.manifest, dev_manifest(KeyKind::Soft, "soft-key"));
        assert_eq!(workspace.keys.store.as_bytes().as_slice(), hex(KAT_KEY_STORE));
        assert_eq!(workspace.keys.names.as_bytes().as_slice(), hex(KAT_KEY_ITEM_NAMES));
    }

    #[test]
    fn a_new_workspace_with_a_passphrase_takes_one_ask_to_make_and_one_to_open() {
        let world = World::new();
        let holder = FixedPassphrase::new(PASSPHRASE, hardware_seed(), passphrase_salt(), passphrase_nonce());
        world.make(&holder, "acme", acme_fresh()).unwrap();
        assert_eq!(holder.asks(), 1);
        // The key ref is the known answers' passphrase record; the record names a passphrase key.
        assert!(world.file(&FileKey::KeyRef(acme())).unwrap() == hex(KAT_PASSPHRASE_RECORD));
        assert_eq!(world.file(&FileKey::DirRecord(ws_name("acme"))).unwrap(), [[0x01].as_slice(), ws_bytes().as_slice(), [0x05, 0x01].as_slice()].concat());

        let workspace = world.open(&holder, "acme").unwrap();
        assert_eq!(holder.asks(), 2);
        assert_eq!(workspace.manifest, dev_manifest(KeyKind::Passphrase, "fixed-passphrase"));
        assert_eq!(workspace.keys.store.as_bytes().as_slice(), hex(KAT_KEY_STORE));
    }

    #[test]
    fn creating_writes_the_record_first_and_the_pin_last() {
        let world = World::new();
        world.anchor.fail_next_advance();
        let error = world.make(&world.acme, "acme", acme_fresh()).unwrap_err();
        assert!(error.to_string().contains("could not be written"), "{error}");
        let made = [FileKey::DirRecord(ws_name("acme")), FileKey::KeyRef(acme()), FileKey::Wrap(acme()), FileKey::Manifest(acme())];
        for file in &made {
            assert!(world.file(file).is_some(), "{file:?}");
        }
        assert_eq!(world.anchor.read(acme()).unwrap(), None, "no pin");
        // It does not open, and nothing is asked.
        assert_eq!(refused(world.open(&world.acme, "acme")), Refusal::Unreadable);
        assert_eq!(world.acme.decapsulations(), 0);
        assert!(!asked_to(&world.acme, Change::Open));
        // It is listed, as never finished.
        assert_eq!(ws_list(&world.files, &world.anchor).unwrap(), [Listed { name: ws_name("acme"), record: Some(acme_record()), pinned: false }]);
        // Its name is taken, whatever id is drawn.
        assert_eq!(refused(world.make(&world.acme, "acme", Fresh { id: *FRESH.as_bytes(), ..acme_fresh() })), Refusal::Taken(ws_name("acme")));
        // Deleting it clears everything with no prompt, and the name can be made again.
        assert_eq!(world.delete(&world.acme, "acme").unwrap(), Deleted::FilesOnly);
        assert_eq!(world.acme.asked().len(), 1, "only the first create");
        for file in &made {
            assert_eq!(world.file(file), None, "{file:?}");
        }
        let world = world.made();
        assert_eq!(world.acme.creates(), 2);
        world.open(&world.acme, "acme").unwrap();
    }

    #[test]
    fn a_taken_name_or_an_id_in_use_is_refused_before_the_key_holder_is_asked() {
        let world = World::new().made();
        let refusal = refused(world.make(&world.globex, "acme", Fresh { id: *FRESH.as_bytes(), ..globex_fresh() }));
        assert_eq!(refusal, Refusal::Taken(ws_name("acme")));
        assert_eq!(refusal.to_string(), "there is already a workspace named acme");
        // acme's id under another name: its pin is there.
        let error = world.make(&world.globex, "globex", Fresh { id: ws_bytes(), ..globex_fresh() }).unwrap_err();
        assert!(error.downcast_ref::<Refusal>().is_none() && error.to_string().contains("already in use"), "{error}");
        // So is an id that has any one of the files a key leaves, and no pin.
        for file in [FileKey::KeyRef(FRESH), FileKey::Wrap(FRESH), FileKey::Manifest(FRESH)] {
            world.files.write_atomic(&file, b"left").unwrap();
            let error = world.make(&world.globex, "globex", Fresh { id: *FRESH.as_bytes(), ..globex_fresh() }).unwrap_err();
            assert!(error.to_string().contains("already in use"), "{file:?}: {error}");
            world.files.remove(&file).unwrap();
        }
        assert_eq!(world.file(&FileKey::DirRecord(ws_name("globex"))), None, "no record was written");
        assert_eq!((world.acme.creates(), world.globex.creates()), (1, 0));
        assert!(world.globex.asked().is_empty());
    }

    #[test]
    fn a_manifest_that_would_not_read_back_is_refused_before_the_key_holder_is_asked() {
        let world = World::new();
        // A name a manifest can't record: it holds a capital.
        world.files.label_as("Mem-Files", Lacks::of(&Property::ALL));
        assert_eq!(refused(world.make(&world.acme, "acme", acme_fresh())), Refusal::Unreadable);
        assert_eq!(world.acme.creates(), 0);
        assert!(world.acme.asked().is_empty());
        assert_eq!((world.file(&FileKey::DirRecord(ws_name("acme"))), world.file(&FileKey::KeyRef(acme()))), (None, None));
    }

    #[test]
    fn a_declined_create_leaves_no_record_and_frees_the_name() {
        let world = World::new();
        world.acme.decline(true);
        assert_eq!(refused(world.make(&world.acme, "acme", acme_fresh())), Refusal::Declined);
        assert_eq!((world.file(&FileKey::DirRecord(ws_name("acme"))), world.file(&FileKey::KeyRef(acme()))), (None, None));
        assert!(ws_list(&world.files, &world.anchor).unwrap().is_empty());
        // Once the holder says yes, the name is made and opens.
        world.acme.decline(false);
        let world = world.made();
        world.open(&world.acme, "acme").unwrap();
    }

    #[test]
    fn an_edited_directory_record_is_refused_before_any_prompt() {
        let world = World::new().made();
        world.make(&world.globex, "globex", globex_fresh()).unwrap();
        let record = |id: [u8; 16], key: u8, keystore: u8| [[0x01].as_slice(), id.as_slice(), [key, keystore].as_slice()].concat();
        let kept = world.file(&FileKey::DirRecord(ws_name("acme"))).unwrap();
        assert_eq!(kept, record(ws_bytes(), 0x04, 0x01));
        // Another key kind or keystore kind than this machine's; globex's id, which globex's pin covers with another public key;
        // an id with nothing under it; and no record at all.
        let edits = [record(ws_bytes(), 0x05, 0x01), record(ws_bytes(), 0x04, 0x02), record(*GLOBEX.as_bytes(), 0x04, 0x01), record(*FRESH.as_bytes(), 0x04, 0x01), vec![0xff; 19]];
        for edited in edits {
            world.files.write_atomic(&FileKey::DirRecord(ws_name("acme")), &edited).unwrap();
            let refusal = refused(world.open(&world.acme, "acme"));
            assert_eq!(refusal, Refusal::Unreadable, "{edited:02x?}");
            let said = refusal.to_string();
            assert!(!said.contains("globex") && !said.contains(&acme().to_string()) && !said.contains(&GLOBEX.to_string()), "{said}");
        }
        assert_eq!((world.acme.decapsulations(), world.globex.decapsulations()), (0, 0));
        assert!(!asked_to(&world.acme, Change::Open) && !asked_to(&world.globex, Change::Open));
        // Put back, it opens; removed, the name is unknown.
        world.files.write_atomic(&FileKey::DirRecord(ws_name("acme")), &kept).unwrap();
        world.open(&world.acme, "acme").unwrap();
        world.files.remove(&FileKey::DirRecord(ws_name("acme"))).unwrap();
        assert_eq!(refused(world.open(&world.acme, "acme")), Refusal::Unknown(ws_name("acme")));
        assert_eq!(world.acme.decapsulations(), 1);
    }

    #[test]
    fn a_manifest_for_another_workspace_or_name_is_tampered_after_one_decapsulation() {
        let world = World::new().made();
        // Sealed under acme's own inner key, for globex's id under acme's name, then for acme's id under globex's name.
        for (ws, text) in [(GLOBEX, "acme"), (acme(), "globex")] {
            let opened = world.acme.decapsulations();
            world.plant(&dev_manifest(KeyKind::Soft, "soft-key"), ws, text);
            assert_eq!(refused(world.open(&world.acme, "acme")), Refusal::Tampered, "{ws} {text}");
            assert_eq!(world.acme.decapsulations(), opened + 1, "{ws} {text}");
        }
        // Sealed for acme under its name, the same manifest opens.
        world.plant(&dev_manifest(KeyKind::Soft, "soft-key"), acme(), "acme");
        world.open(&world.acme, "acme").unwrap();
    }

    #[test]
    fn a_manifest_that_disagrees_with_the_directory_record_is_tampered() {
        let world = World::new().made();
        // Properly sealed, under a rewritten pin, and saying another keystore kind or key kind than the record.
        let disagreeing = [Manifest { keystore: KeystoreKind::Files, ..dev_manifest(KeyKind::Soft, "soft-key") }, dev_manifest(KeyKind::Passphrase, "soft-key")];
        for manifest in &disagreeing {
            world.plant(manifest, acme(), "acme");
            assert_eq!(refused(world.open(&world.acme, "acme")), Refusal::Tampered, "{manifest:?}");
        }
        assert_eq!(world.acme.decapsulations(), 2);
    }

    #[test]
    fn a_workspace_made_by_the_other_kind_of_build_does_not_open() {
        let world = World::new().made();
        world.plant(&Manifest { built_by: Build::Release, ..dev_manifest(KeyKind::Soft, "soft-key") }, acme(), "acme");
        let refusal = refused(world.open(&world.acme, "acme"));
        assert_eq!(refusal, Refusal::OtherBuild(Build::Release));
        assert_eq!(refusal.to_string(), "this workspace was made by a release build");
        assert_eq!(world.acme.decapsulations(), 1);
        // And the other way round: what a debug build made, a release build refuses.
        assert_eq!(checked(dev_manifest(KeyKind::Soft, "soft-key"), &acme_record(), Build::Release), Err(Refusal::OtherBuild(Build::Dev)));
        assert_eq!(checked(dev_manifest(KeyKind::Soft, "soft-key"), &acme_record(), Build::Dev), Ok(dev_manifest(KeyKind::Soft, "soft-key")));
    }

    #[test]
    fn an_open_where_more_is_lacking_than_was_recorded_is_refused() {
        let world = World::new();
        world.files.label_as("mem-files", Lacks::of(&[Property::RollbackProof]));
        let world = world.made();
        world.files.label_as("mem-files", Lacks::of(&[Property::RollbackProof, Property::OthersCantTouch]));
        let refusal = refused(world.open(&world.acme, "acme"));
        assert_eq!(refusal, Refusal::Downgraded(Lacks::of(&[Property::OthersCantTouch])));
        assert_eq!(refusal.to_string(), "this machine lacks what this workspace was made with: others-cant-touch");
        assert_eq!(world.acme.decapsulations(), 1);
        // Lacking less than it did is no downgrade.
        world.files.label_as("mem-files", Lacks::NONE);
        let workspace = world.open(&world.acme, "acme").unwrap();
        assert_eq!(workspace.manifest.adapters[2].lacks, Lacks::of(&[Property::RollbackProof]), "what was recorded is unchanged");

        // Every role is compared and all that is more is named; a role in use that the manifest does not record is tampered with.
        let label = |adapter: &'static str, lacks: Lacks| Label { adapter, grade: Grade::Dev, lacks, why: "for the test" };
        let lacking_nothing: Vec<Recorded> = dev_manifest(KeyKind::Soft, "soft-key").adapters.into_iter().map(|recorded| Recorded { lacks: Lacks::NONE, ..recorded }).collect();
        let made = Manifest { adapters: lacking_nothing, ..dev_manifest(KeyKind::Soft, "soft-key") };
        let now = [(Role::KeyHolder, label("soft-key", Lacks::of(&[Property::KeyInHardware]))), (Role::Keystore, label("mem-keystore", Lacks::of(&[Property::NetApart])))];
        assert_eq!(not_weaker(&made, &now), Err(Refusal::Downgraded(Lacks::of(&[Property::KeyInHardware, Property::NetApart]))));
        assert_eq!(not_weaker(&made, &now[..1]), Err(Refusal::Downgraded(Lacks::of(&[Property::KeyInHardware]))));
        let three = Manifest { adapters: made.adapters[..3].to_vec(), ..made.clone() };
        assert_eq!(not_weaker(&three, &now), Err(Refusal::Tampered));
        assert_eq!(not_weaker(&made, &[(Role::Files, label("mem-files", Lacks::NONE))]), Ok(()));
    }

    #[test]
    fn a_release_build_refuses_dev_adapters_before_anything_is_read() {
        let world = World::new();
        let release = world.machine(&world.acme, Build::Release);
        let soft = Refusal::NotAdmitted { adapter: "soft-key", grade: Grade::Dev };
        assert_eq!(refused(ws_new(&release, &ws_name("acme"), acme_fresh())), soft);
        assert_eq!(refused(ws_open(&release, &ws_name("acme"))), soft);
        assert_eq!(refused(ws_delete(&release, &ws_name("acme"))), soft);
        // A key holder of another kind is refused by its label, dev as every adapter in memory is.
        let holder = FixedPassphrase::new(PASSPHRASE, hardware_seed(), passphrase_salt(), passphrase_nonce());
        let release = world.machine(&holder, Build::Release);
        let fixed = Refusal::NotAdmitted { adapter: "fixed-passphrase", grade: Grade::Dev };
        assert_eq!(refused(ws_new(&release, &ws_name("acme"), acme_fresh())), fixed);
        assert_eq!(refused(ws_open(&release, &ws_name("acme"))), fixed);
        assert_eq!(refused(ws_delete(&release, &ws_name("acme"))), fixed);
        // Labelled as the passphrase holder a release build admits, it passes, and the next adapter, the anchor, is judged and refused.
        holder.label_as("passphrase-key", Grade::Weaker);
        assert_eq!(admit(&[holder.label()], Build::Release, Os::Macos), Ok(()));
        let anchor = Refusal::NotAdmitted { adapter: "mem-anchor", grade: Grade::Dev };
        assert_eq!(refused(ws_new(&release, &ws_name("acme"), acme_fresh())), anchor);
        assert_eq!(refused(ws_open(&release, &ws_name("acme"))), anchor);
        assert_eq!(refused(ws_delete(&release, &ws_name("acme"))), anchor);
        // Nothing was read, written or asked.
        assert_eq!((world.files.calls(), world.anchor.reads()), (0, 0));
        assert!(world.keystore.calls().is_empty());
        assert_eq!((world.acme.creates(), world.acme.asked().len(), holder.asks()), (0, 0, 0));
    }

    #[test]
    fn a_release_build_never_runs_a_soft_key_whatever_its_label_says() {
        let world = World::new();
        world.acme.label_grade(Grade::Production);
        // By its label alone it would be let in.
        assert_eq!(admit(&[world.acme.label()], Build::Release, Os::Macos), Ok(()));
        let release = world.machine(&world.acme, Build::Release);
        let expected = Refusal::NotAdmitted { adapter: "soft-key", grade: Grade::Production };
        assert_eq!(refused(ws_new(&release, &ws_name("acme"), acme_fresh())), expected);
        assert_eq!(refused(ws_open(&release, &ws_name("acme"))), expected);
        assert_eq!(refused(ws_delete(&release, &ws_name("acme"))), expected);
        assert_eq!((world.files.calls(), world.anchor.reads()), (0, 0));
        assert_eq!((world.acme.creates(), world.acme.asked().len()), (0, 0));
    }

    #[test]
    fn deleting_takes_one_approval_and_removes_that_workspace_only() {
        let world = World::new().made();
        world.make(&world.globex, "globex", globex_fresh()).unwrap();
        world.keystore.put(acme(), &ITEM, b"acme's").unwrap();
        world.keystore.put(GLOBEX, &ITEM, b"globex's").unwrap();
        // Each has a policy, under a pin advanced to cover it, and a log line.
        for (ws, text, holder) in [(acme(), "acme", &world.acme), (GLOBEX, "globex", &world.globex)] {
            world.files.write_atomic(&FileKey::Policy(ws), format!("{text}'s policy").as_bytes()).unwrap();
            world.repin(ws, text, holder);
            world.files.append(&FileKey::Log(ws), format!("{text}'s log").as_bytes()).unwrap();
        }
        let globex = world.everything(GLOBEX, "globex");
        let calls = world.keystore.calls().len();

        assert_eq!(world.delete(&world.acme, "acme").unwrap(), Deleted::Whole);
        assert_eq!(world.acme.asked().len(), 2);
        assert_eq!(world.acme.asked()[1], (acme(), ws_name("acme"), Change::Delete, "[DEV, not protected] delete workspace acme".to_string()));
        assert_eq!(world.acme.decapsulations(), 1);
        // acme's item, pin, key ref, wrap, manifest, policy, log and record are gone, and its key with them: its holder was told to
        // destroy the key ref it made, once, and globex's holder was told nothing.
        assert_eq!(world.everything(acme(), "acme"), (vec![None; 6], None, None));
        assert_eq!(world.acme.destroyed(), [KeyRef(vec![KeyKind::Soft.tag()])]);
        assert!(world.globex.destroyed().is_empty());
        assert!(world.keystore.calls()[calls..].iter().all(|ws| *ws == acme()), "only acme's items were touched");
        assert_eq!(refused(world.open(&world.acme, "acme")), Refusal::Unknown(ws_name("acme")));
        // globex's are as they were, and it opens.
        assert_eq!(world.everything(GLOBEX, "globex"), globex);
        world.open(&world.globex, "globex").unwrap();
        assert_eq!(ws_list(&world.files, &world.anchor).unwrap().iter().map(|listed| listed.name.as_str()).collect::<Vec<_>>(), ["globex"]);
    }

    #[test]
    fn deleting_a_workspace_removes_any_next_manifest() {
        // Left beside the manifest by a replacement cut short.
        let world = World::new().made();
        world.files.write_atomic(&FileKey::NextManifest(acme()), b"left").unwrap();
        assert_eq!(world.delete(&world.acme, "acme").unwrap(), Deleted::Whole);
        assert_eq!(world.file(&FileKey::NextManifest(acme())), None);
        assert_eq!(world.everything(acme(), "acme"), (vec![None; 6], None, None));
        // With no pin, so nothing is unlocked: the files go, that one with them.
        let world = World::new().made();
        world.files.write_atomic(&FileKey::NextManifest(acme()), b"left").unwrap();
        world.anchor.forget(acme()).unwrap();
        assert_eq!(world.delete(&world.acme, "acme").unwrap(), Deleted::FilesOnly);
        assert_eq!(world.file(&FileKey::NextManifest(acme())), None);
        assert_eq!(world.everything(acme(), "acme"), (vec![None; 6], None, None));
    }

    #[test]
    fn a_declined_or_refused_delete_removes_nothing() {
        let world = World::new().made();
        world.keystore.put(acme(), &ITEM, b"acme's").unwrap();
        let before = world.everything(acme(), "acme");
        world.acme.decline(true);
        assert_eq!(refused(world.delete(&world.acme, "acme")), Refusal::Declined);
        assert!(asked_to(&world.acme, Change::Delete), "it was asked, and said no");
        assert!(world.everything(acme(), "acme") == before);
        world.acme.decline(false);

        // A record of a kind this machine does not hold, or one that does not read: refused before the pin is looked at.
        let record = world.file(&FileKey::DirRecord(ws_name("acme"))).unwrap();
        for edited in [[[0x01].as_slice(), ws_bytes().as_slice(), [0x05, 0x01].as_slice()].concat(), vec![0xff; 19]] {
            world.files.write_atomic(&FileKey::DirRecord(ws_name("acme")), &edited).unwrap();
            assert_eq!(refused(world.delete(&world.acme, "acme")), Refusal::Unreadable, "{edited:02x?}");
        }
        world.files.write_atomic(&FileKey::DirRecord(ws_name("acme")), &record).unwrap();
        assert!(world.everything(acme(), "acme") == before);

        // One changed byte of the wrap: refused before the holder is asked.
        let asked = world.acme.asked().len();
        let mut wrap = hex(KAT_HARDWARE_WRAP);
        wrap[1682] ^= 0x01;
        world.files.write_atomic(&FileKey::Wrap(acme()), &wrap).unwrap();
        let before = world.everything(acme(), "acme");
        assert_eq!(refused(world.delete(&world.acme, "acme")), Refusal::Unreadable);
        assert_eq!((world.acme.asked().len(), world.acme.decapsulations()), (asked, 0));
        assert!(world.everything(acme(), "acme") == before);

        // One made by the other kind of build: found once the holder has answered, and refused all the same.
        world.files.write_atomic(&FileKey::Wrap(acme()), &hex(KAT_HARDWARE_WRAP)).unwrap();
        world.plant(&Manifest { built_by: Build::Release, ..dev_manifest(KeyKind::Soft, "soft-key") }, acme(), "acme");
        let before = world.everything(acme(), "acme");
        assert_eq!(refused(world.delete(&world.acme, "acme")), Refusal::OtherBuild(Build::Release));
        assert_eq!(world.acme.decapsulations(), 1);
        assert!(world.everything(acme(), "acme") == before);
        // In none of them was the holder told to destroy its key.
        assert!(world.acme.destroyed().is_empty());
    }

    #[test]
    fn a_workspace_with_no_pin_loses_only_its_files_without_approval() {
        // Its record edited to an id with no pin: only that id's files, which there are none of, and the name's record go.
        let world = World::new().made();
        world.keystore.put(acme(), &ITEM, b"acme's").unwrap();
        // A policy, under a pin advanced to cover it, and a log line.
        world.files.write_atomic(&FileKey::Policy(acme()), b"acme's policy").unwrap();
        world.repin(acme(), "acme", &world.acme);
        world.files.append(&FileKey::Log(acme()), b"acme's log").unwrap();
        let record = world.file(&FileKey::DirRecord(ws_name("acme"))).unwrap();
        let mut kept = world.everything(acme(), "acme");
        let mut edited = record.clone();
        edited[1..17].copy_from_slice(FRESH.as_bytes());
        world.files.write_atomic(&FileKey::DirRecord(ws_name("acme")), &edited).unwrap();
        assert_eq!(world.delete(&world.acme, "acme").unwrap(), Deleted::FilesOnly);
        assert_eq!(world.acme.asked().len(), 1, "only the create");
        // The record, the first of the files, is the only one gone.
        kept.0[0] = None;
        assert!(world.everything(acme(), "acme") == kept, "acme's pin, key ref, wrap, manifest, policy, log and item are untouched");
        // The holder was not told to destroy its key, and written back, the record opens.
        assert!(world.acme.destroyed().is_empty());
        world.files.write_atomic(&FileKey::DirRecord(ws_name("acme")), &record).unwrap();
        world.open(&world.acme, "acme").unwrap();

        // Its pin removed, as a program can where pins are kept in files: the files and the record go, and the item stays.
        let world = World::new().made();
        world.keystore.put(acme(), &ITEM, b"acme's").unwrap();
        world.files.write_atomic(&FileKey::Policy(acme()), b"acme's policy").unwrap();
        world.files.append(&FileKey::Log(acme()), b"acme's log").unwrap();
        world.anchor.forget(acme()).unwrap();
        assert_eq!(world.delete(&world.acme, "acme").unwrap(), Deleted::FilesOnly);
        assert_eq!((world.acme.asked().len(), world.acme.decapsulations()), (1, 0));
        assert_eq!(world.everything(acme(), "acme"), (vec![None; 6], None, Some(b"acme's".to_vec())));
        assert!(world.acme.destroyed().is_empty());
    }

    #[test]
    fn listing_shows_each_workspace_without_reading_a_secret_or_asking() {
        let world = World::new().made();
        world.make(&world.globex, "globex", globex_fresh()).unwrap();
        world.files.write_atomic(&FileKey::DirRecord(ws_name("initech")), &[0xff; 19]).unwrap();
        let reads = world.files.reads().len();
        let listed = ws_list(&world.files, &world.anchor).unwrap();
        let globex = DirRecord { id: GLOBEX, ..acme_record() };
        assert_eq!(
            listed,
            [
                Listed { name: ws_name("acme"), record: Some(acme_record()), pinned: true },
                Listed { name: ws_name("globex"), record: Some(globex), pinned: true },
                Listed { name: ws_name("initech"), record: None, pinned: false },
            ]
        );
        // Only the three records were read: no key ref, wrap or manifest.
        let read = world.files.reads()[reads..].to_vec();
        assert_eq!(read, ["acme", "globex", "initech"].map(|text| FileKey::DirRecord(ws_name(text))));
        assert_eq!((world.acme.asked().len(), world.globex.asked().len()), (1, 1));
        assert_eq!((world.acme.decapsulations(), world.globex.decapsulations()), (0, 0));
    }
}
