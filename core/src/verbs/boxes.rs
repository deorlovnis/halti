//! The verbs on a workspace's boxes: make one, remove one. Each starts as the verbs on secrets do
//! (`items`): admission, the record and its kinds, one approval naming its change, and the
//! manifest's checks, item and box names included.
//!
//! A box is the approval of its policy (`policy::Kind::Box`) and, for one that keeps a store, its
//! store key: a sealed item in a namespace of its own (`boxkey`), listed in the manifest's box
//! section. Both are written in one change, so a box is never approved without its key or kept
//! without its approval. Removing a resource never touches a box of the same name, nor the reverse.

use anyhow::Result;

use super::items::with_list;
use super::ws::Machine;
use crate::boxkey::{BoxKey, box_name, check_box, seal_box_key};
use crate::holder::Change;
use crate::ids::WsName;
use crate::manifest::{BoxEntry, Manifest};
use crate::policy::{Approval, Edit, Kind, Proposal, apply};
use crate::refusal::Refusal;
use crate::store::Keystore;

/// Fresh random bytes the caller drew for one `ws_box_new`, never reused: the key's nonce and the
/// new manifest's.
pub struct BoxNonces {
    pub key: [u8; 12],
    pub manifest: [u8; 12],
}

/// What removing a box removed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BoxGone {
    /// Its key was listed, and is gone.
    pub key: bool,
    /// Its policy was approved, and is no longer.
    pub approval: bool,
}

/// Makes a box: one approval (`Change::MakeBox`). `policy` is the box's policy, of `Kind::Box`,
/// named as the box; `key` is its store key, or none for a box that keeps nothing between runs.
///
/// A bad name is `Refusal::BadBox`, and a text that can't be approved, or a policy of another kind,
/// `Refusal::BadPolicy`, before anything is asked. After the approval and the checks: a box whose
/// key is listed already is `Refusal::BoxExists`, and a base that doesn't hold is
/// `Refusal::NotTheBase`, with nothing written. Then `made` is called once (the binary makes the
/// store there); then the key, if any, is sealed for the pin version this change moves to and put,
/// and the manifest is replaced once, with the box listed and its policy approved. `made` failing
/// writes nothing. A failure after the key is put and before the pin moves leaves a blob no list
/// names, which goes when the workspace is deleted.
pub fn ws_box_new(machine: &Machine<'_>, name: &WsName, key: Option<&BoxKey>, policy: &Proposal<'_>, made: impl FnOnce() -> Result<()>, nonces: BoxNonces) -> Result<()> {
    check_box(policy.name)?;
    if policy.kind != Kind::Box {
        return Err(Refusal::BadPolicy.into());
    }
    let approval = Approval::of(Kind::Box, policy.name, policy.text)?;
    with_list(machine, name, Change::MakeBox, |ws, unlocked, manifest, keys| {
        if manifest.boxes.iter().any(|entry| entry.name == policy.name) {
            return Err(Refusal::BoxExists { ws: name.clone(), name: policy.name.to_string() }.into());
        }
        if !policy.base_holds(&manifest.approvals) {
            return Err(Refusal::NotTheBase { name: policy.name.to_string() }.into());
        }
        made()?;
        let version = unlocked.next()?;
        let item = box_name(keys.item_names(), policy.name);
        let mut boxes = manifest.boxes.clone();
        if key.is_some() {
            let at = boxes.partition_point(|entry| entry.name.as_str() < policy.name);
            boxes.insert(at, BoxEntry { name: policy.name.to_string(), item, version });
        }
        let approvals = apply(&manifest.approvals, [Edit::Set(approval)]);
        // Sealed before anything is written, so a list that can't be sealed writes nothing.
        let sealed = Manifest { approvals, boxes, ..manifest }.seal(unlocked.inner, ws, name, &nonces.manifest)?;
        if let Some(key) = key {
            Keystore::bind(ws, machine.keystore).put(&item, &seal_box_key(keys.store(), ws, &item, version, key, &nonces.key))?;
        }
        unlocked.replace_manifest(&sealed)
    })
}

/// Removes a box: one approval (`Change::RemoveBox`). Drops its key from the list and its policy's
/// approval in one manifest replacement, then deletes the key's blob. A resource of the same name
/// keeps its approval. With neither listed, nothing is written and both are false. A bad name is
/// `Refusal::BadBox`, before anything is asked.
///
/// Once the list is replaced the box is gone from it, so a blob that can't be deleted is left,
/// sealed and named by no list, and goes when the workspace is deleted.
pub fn ws_box_rm(machine: &Machine<'_>, name: &WsName, box_name: &str, manifest_nonce: [u8; 12]) -> Result<BoxGone> {
    check_box(box_name)?;
    with_list(machine, name, Change::RemoveBox, |ws, unlocked, manifest, _| {
        let (gone, kept): (Vec<BoxEntry>, Vec<BoxEntry>) = manifest.boxes.iter().cloned().partition(|entry| entry.name == box_name);
        let approvals = apply(&manifest.approvals, [Edit::Drop(Kind::Box, box_name)]);
        let removed = BoxGone { key: !gone.is_empty(), approval: approvals != manifest.approvals };
        if removed == (BoxGone { key: false, approval: false }) {
            return Ok(removed);
        }
        let sealed = Manifest { approvals, boxes: kept, ..manifest }.seal(unlocked.inner, ws, name, &manifest_nonce)?;
        unlocked.replace_manifest(&sealed)?;
        let items = Keystore::bind(ws, machine.keystore);
        for entry in &gone {
            let _ = items.delete(&entry.item);
        }
        Ok(removed)
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use anyhow::bail;
    use zeroize::Zeroizing;

    use super::*;
    use crate::anchor::{Anchor, Pin, state_hash};
    use crate::crypto::vectors::{
        KAT_BOX_KEY, KAT_BOX_NAME, KAT_BOX_NAME_GLOBEX, KAT_HARDWARE_WRAP, POLICY_TEXT, box_key_bytes, box_key_nonce, hardware_rand, hardware_seed, hex, inner_bytes,
        manifest_nonce, recovery_rand, recovery_seed, ws_bytes,
    };
    use crate::fakes::{MemAnchor, MemFiles, MemKeystore, SoftKey};
    use crate::holder::KeyHolder;
    use crate::ids::WsId;
    use crate::item::{ItemKey, Secret};
    use crate::key::InnerKey;
    use crate::platform::{Build, Grade, Os};
    use crate::policy::Base;
    use crate::store::{FileKey, Files, ItemName, KeystoreBackend};
    use crate::verbs::{Draws, Fresh, Host, Nonces, Which, ws_approve, ws_new, ws_open, ws_remove, ws_set};

    // Every key here is held in software: nothing is derived at 64 MiB.

    const GLOBEX: WsId = WsId::from_bytes([2; 16]);
    /// globex's inner key.
    const GLOBEX_INNER: [u8; 32] = [0x22; 32];
    /// A box policy.
    const BOX_TEXT: &[u8] = b"run = [\"claude\"]\nsites = [\"github\"]\nkeep = true\n";

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn ws_name(text: &str) -> WsName {
        WsName::parse(text).unwrap()
    }

    /// The refusal a verb failed with. Panics if it did not fail, or failed some other way.
    fn refused<T>(result: Result<T>) -> Refusal {
        result.err().expect("it fails").downcast::<Refusal>().expect("with a refusal")
    }

    fn key(byte: u8) -> BoxKey {
        BoxKey::from_bytes(Zeroizing::new([byte; 32]))
    }

    /// Box `name`'s policy, shown as `base`.
    fn policy<'a>(name: &'a str, text: &'a [u8], base: Base<'a>) -> Proposal<'a> {
        Proposal { kind: Kind::Box, name, text, base }
    }

    /// The name of box `name`'s key in the workspace of this inner key.
    fn name_under(inner: [u8; 32], name: &str) -> ItemName {
        box_name(InnerKey::from_bytes(Zeroizing::new(inner)).open_keys().item_names(), name)
    }

    /// Everything of a workspace a box verb could change: its manifest, any manifest beside it, its pin, and every blob its
    /// keystore holds.
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
        fn nonces(&self) -> BoxNonces {
            let n = self.drawn.get() + 1;
            self.drawn.set(n);
            BoxNonces { key: [n; 12], manifest: [0x80 | n; 12] }
        }

        /// Makes box `name` in `text` with `key`, its policy new; `made` does nothing.
        fn make(&self, text: &str, name: &str, key: Option<&BoxKey>) -> Result<()> {
            ws_box_new(&self.machine(self.holder(text), Build::Dev), &ws_name(text), key, &policy(name, BOX_TEXT, Base::New), || Ok(()), self.nonces())
        }

        fn rm(&self, text: &str, name: &str) -> Result<BoxGone> {
            ws_box_rm(&self.machine(self.holder(text), Build::Dev), &ws_name(text), name, self.nonces().manifest)
        }

        fn file(&self, key: &FileKey) -> Option<Vec<u8>> {
            self.files.read(key).unwrap()
        }

        fn pin(&self, ws: WsId) -> Pin {
            self.anchor.read(ws).unwrap().unwrap()
        }

        /// The workspace's manifest, opened.
        fn manifest(&self, ws: WsId, text: &str, inner: [u8; 32]) -> Manifest {
            Manifest::open(&InnerKey::from_bytes(Zeroizing::new(inner)), ws, &ws_name(text), &self.file(&FileKey::Manifest(ws)).unwrap()).unwrap()
        }

        fn kept(&self, ws: WsId) -> Kept {
            let mut blobs: Vec<(ItemName, Vec<u8>)> = self.keystore.list(ws).unwrap().into_iter().map(|name| (name, self.keystore.get(ws, &name).unwrap().unwrap())).collect();
            blobs.sort();
            (self.file(&FileKey::Manifest(ws)), self.file(&FileKey::NextManifest(ws)), self.anchor.read(ws).unwrap(), blobs)
        }

        /// How many times acme's holder was asked.
        fn asks(&self) -> usize {
            self.acme.asked().len()
        }
    }

    #[test]
    fn making_a_box_takes_one_approval_and_seals_its_key_and_policy() {
        let world = World::new();
        let (called, decapsulated) = (Cell::new(0), Cell::new(0));
        let made = || {
            called.set(called.get() + 1);
            decapsulated.set(world.acme.decapsulations());
            Ok(())
        };
        let known = BoxKey::from_bytes(Zeroizing::new(box_key_bytes()));
        let nonces = BoxNonces { key: box_key_nonce(), manifest: [0x81; 12] };
        ws_box_new(&world.machine(&world.acme, Build::Dev), &ws_name("acme"), Some(&known), &policy("dev", BOX_TEXT, Base::New), made, nonces).unwrap();
        let asked: Vec<(Change, String)> = world.acme.asked().into_iter().map(|(.., change, text)| (change, text)).collect();
        assert_eq!(asked[1..], [(Change::MakeBox, "[DEV, not protected] make a box in workspace acme".to_string())]);
        assert_eq!(world.acme.decapsulations(), 1);
        assert_eq!((called.get(), decapsulated.get()), (1, 1), "made once, after the one decapsulation");
        // One blob, under the box's known name, sealed as the independent implementation seals it at version 2.
        let dev = ItemName::from_bytes(hex(KAT_BOX_NAME).try_into().unwrap());
        assert_eq!(world.keystore.list(acme()).unwrap(), [dev]);
        assert_eq!(world.keystore.get(acme(), &dev).unwrap().unwrap(), hex(KAT_BOX_KEY));
        // The manifest lists the box at version 2 and approves its policy, in one change.
        let manifest = world.manifest(acme(), "acme", inner_bytes());
        assert_eq!(manifest.boxes, [BoxEntry { name: "dev".to_string(), item: dev, version: 2 }]);
        assert_eq!(manifest.approvals, [Approval::of(Kind::Box, "dev", BOX_TEXT).unwrap()]);
        assert!(manifest.items.is_empty());
        let pin = world.pin(acme());
        assert_eq!(pin.version, 2);
        assert_eq!(pin.state, state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), &world.file(&FileKey::Manifest(acme())).unwrap(), b""));
        // Opened, the key is the one made, as the disk layer is given it.
        let reader = ws_open(&world.machine(&world.acme, Build::Dev), &ws_name("acme")).unwrap();
        assert_eq!(reader.box_key(&world.keystore, "dev").unwrap().unwrap().hex().as_str(), "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        assert!(reader.approval(Kind::Box, "dev").unwrap().approves(BOX_TEXT));
        assert!(reader.approval(Kind::Resource, "dev").is_none(), "a box's approval is no resource's");
    }

    #[test]
    fn a_box_without_a_key_is_only_an_approval() {
        let world = World::new();
        world.make("acme", "scratch", None).unwrap();
        let manifest = world.manifest(acme(), "acme", inner_bytes());
        assert!(manifest.boxes.is_empty(), "no key is listed");
        assert_eq!(manifest.approvals, [Approval::of(Kind::Box, "scratch", BOX_TEXT).unwrap()]);
        assert!(world.keystore.list(acme()).unwrap().is_empty(), "nor put");
        assert_eq!(world.pin(acme()).version, 2);
        let reader = ws_open(&world.machine(&world.acme, Build::Dev), &ws_name("acme")).unwrap();
        assert!(reader.box_key(&world.keystore, "scratch").unwrap().is_none());
        // Made again as new, its approval is the base that doesn't hold; shown against what was approved, it is approved again.
        let kept = world.kept(acme());
        assert_eq!(refused(world.make("acme", "scratch", None)), Refusal::NotTheBase { name: "scratch".to_string() });
        assert!(world.kept(acme()) == kept);
        let machine = world.machine(&world.acme, Build::Dev);
        ws_box_new(&machine, &ws_name("acme"), Some(&key(0x41)), &policy("scratch", BOX_TEXT, Base::Copy(BOX_TEXT)), || Ok(()), world.nonces()).unwrap();
        assert_eq!(world.manifest(acme(), "acme", inner_bytes()).boxes.len(), 1, "now with a key");
    }

    #[test]
    fn making_a_listed_box_again_writes_nothing() {
        let world = World::new();
        world.make("acme", "dev", Some(&key(0x41))).unwrap();
        let (kept, asks) = (world.kept(acme()), world.asks());
        let called = Cell::new(false);
        let made = || {
            called.set(true);
            Ok(())
        };
        let machine = world.machine(&world.acme, Build::Dev);
        // Whatever it is shown against, and with or without a key.
        for (base, with) in [(Base::New, Some(key(0x42))), (Base::Shown, None), (Base::Copy(BOX_TEXT), Some(key(0x42)))] {
            let refusal = refused(ws_box_new(&machine, &ws_name("acme"), with.as_ref(), &policy("dev", BOX_TEXT, base), made, world.nonces()));
            assert_eq!(refusal, Refusal::BoxExists { ws: ws_name("acme"), name: "dev".to_string() });
            assert_eq!(refusal.to_string(), "box acme/dev exists already");
        }
        assert!(!called.get(), "the store is never made");
        assert_eq!(world.asks(), asks + 3, "refused after the ask, each time");
        assert!(world.kept(acme()) == kept);
    }

    #[test]
    fn a_failed_made_writes_nothing() {
        let world = World::new();
        let kept = world.kept(acme());
        let machine = world.machine(&world.acme, Build::Dev);
        let error =
            ws_box_new(&machine, &ws_name("acme"), Some(&key(0x41)), &policy("dev", BOX_TEXT, Base::New), || bail!("the store could not be made"), world.nonces()).unwrap_err();
        assert!(error.to_string().contains("could not be made"), "{error}");
        assert!(world.kept(acme()) == kept);
        // A change cut short after the key is put: a blob no list names, and the box is not made.
        world.anchor.fail_next_advance();
        assert!(world.make("acme", "dev", Some(&key(0x41))).unwrap_err().to_string().contains("could not be written"));
        assert_eq!(world.pin(acme()), kept.2.unwrap());
        let reader = ws_open(&machine, &ws_name("acme")).unwrap();
        assert!(reader.manifest().boxes.is_empty() && reader.manifest().approvals.is_empty());
        // Made again, it is.
        world.make("acme", "dev", Some(&key(0x41))).unwrap();
        assert_eq!(world.manifest(acme(), "acme", inner_bytes()).boxes.len(), 1);
    }

    #[test]
    fn a_declined_or_refused_make_never_calls_made() {
        let world = World::new();
        world.make("acme", "dev", Some(&key(0x41))).unwrap();
        let kept = world.kept(acme());
        let called = Cell::new(false);
        let made = || {
            called.set(true);
            Ok(())
        };
        let machine = world.machine(&world.acme, Build::Dev);
        let new = |name: &str, text: &[u8], kind: Kind| -> Refusal {
            let proposal = Proposal { kind, name, text, base: Base::New };
            refused(ws_box_new(&machine, &ws_name("acme"), Some(&key(0x42)), &proposal, made, world.nonces()))
        };
        // Refused before anything is asked: a bad name, a text that can't be approved, a policy of a resource.
        let asks = world.asks();
        let too_long = vec![b'x'; Approval::MAX_TEXT + 1];
        assert_eq!(new("Dev", BOX_TEXT, Kind::Box), Refusal::BadBox);
        assert_eq!(new("a.b", BOX_TEXT, Kind::Box), Refusal::BadBox);
        assert_eq!(new("test", b"", Kind::Box), Refusal::BadPolicy);
        assert_eq!(new("test", &too_long, Kind::Box), Refusal::BadPolicy);
        assert_eq!(new("test", BOX_TEXT, Kind::Resource), Refusal::BadPolicy);
        assert_eq!(world.asks(), asks);
        // Declined: asked once, and nothing made.
        world.acme.decline(true);
        assert_eq!(new("test", BOX_TEXT, Kind::Box), Refusal::Declined);
        assert_eq!(world.asks(), asks + 1);
        world.acme.decline(false);
        // A workspace that is not there: refused before anything is asked.
        assert_eq!(refused(world.make("initech", "dev", None)), Refusal::Unknown(ws_name("initech")));
        assert_eq!(world.asks(), asks + 1);
        assert!(!called.get());
        assert!(world.kept(acme()) == kept);
    }

    #[test]
    fn removing_a_box_drops_its_key_and_approval_then_its_blob() {
        let world = World::new();
        world.make("acme", "dev", Some(&key(0x41))).unwrap();
        world.make("acme", "test", Some(&key(0x42))).unwrap();
        world.make("acme", "scratch", None).unwrap();
        let version = world.pin(acme()).version;
        assert_eq!(world.rm("acme", "dev").unwrap(), BoxGone { key: true, approval: true });
        assert_eq!(world.acme.asked().last().unwrap().3, "[DEV, not protected] remove a box from workspace acme");
        assert_eq!(world.pin(acme()).version, version + 1, "one change");
        let manifest = world.manifest(acme(), "acme", inner_bytes());
        assert_eq!(manifest.boxes.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>(), ["test"]);
        assert_eq!(manifest.approvals.iter().map(Approval::name).collect::<Vec<_>>(), ["scratch", "test"]);
        assert_eq!(world.keystore.list(acme()).unwrap(), [name_under(inner_bytes(), "test")], "its blob is deleted");
        // A box with only an approval loses that; one with neither is no refusal, and writes nothing.
        assert_eq!(world.rm("acme", "scratch").unwrap(), BoxGone { key: false, approval: true });
        let (kept, asks) = (world.kept(acme()), world.asks());
        assert_eq!(world.rm("acme", "dev").unwrap(), BoxGone { key: false, approval: false });
        assert_eq!(world.asks(), asks + 1);
        assert!(world.kept(acme()) == kept);
        // A bad name is refused before anything is asked.
        assert_eq!(refused(world.rm("acme", "Dev")), Refusal::BadBox);
        assert_eq!(world.asks(), asks + 1);
        // Removed, dev can be made again as new, with a fresh key.
        world.make("acme", "dev", Some(&key(0x43))).unwrap();
        let reader = ws_open(&world.machine(&world.acme, Build::Dev), &ws_name("acme")).unwrap();
        assert_eq!(reader.box_key(&world.keystore, "dev").unwrap().unwrap().hex().as_str(), "43".repeat(32));
    }

    #[test]
    fn removing_a_resource_of_the_same_name_leaves_the_box() {
        let world = World::new();
        world.make("acme", "dev", Some(&key(0x41))).unwrap();
        let machine = world.machine(&world.acme, Build::Dev);
        let value = || Ok(Secret::new(Zeroizing::new(b"a value".to_vec()))?);
        ws_set(&machine, &ws_name("acme"), &ItemKey::parse("dev", "token").unwrap(), value, Nonces { value: [0x70; 12], manifest: [0x71; 12] }).unwrap();
        ws_approve(&machine, &ws_name("acme"), &[Proposal { kind: Kind::Resource, name: "dev", text: POLICY_TEXT.as_bytes(), base: Base::New }], [0x72; 12]).unwrap();
        assert_eq!(ws_remove(&machine, &ws_name("acme"), &Which::Resource("dev".to_string()), [0x73; 12]).unwrap(), [ItemKey::parse("dev", "token").unwrap()]);
        let manifest = world.manifest(acme(), "acme", inner_bytes());
        assert_eq!(manifest.boxes.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>(), ["dev"]);
        assert_eq!(manifest.approvals, [Approval::of(Kind::Box, "dev", BOX_TEXT).unwrap()], "only the resource's approval went");
        assert_eq!(world.keystore.list(acme()).unwrap(), [name_under(inner_bytes(), "dev")]);
        // And removing the box leaves a resource of its name.
        ws_approve(&machine, &ws_name("acme"), &[Proposal { kind: Kind::Resource, name: "dev", text: POLICY_TEXT.as_bytes(), base: Base::New }], [0x74; 12]).unwrap();
        world.rm("acme", "dev").unwrap();
        assert_eq!(world.manifest(acme(), "acme", inner_bytes()).approvals, [Approval::of(Kind::Resource, "dev", POLICY_TEXT.as_bytes()).unwrap()]);
    }

    #[test]
    fn boxes_of_one_workspace_never_reach_another() {
        let world = World::new().with_globex();
        world.make("acme", "dev", Some(&key(0x41))).unwrap();
        let calls = world.keystore.calls().len();
        world.make("globex", "dev", Some(&key(0x42))).unwrap();
        assert!(world.keystore.calls()[calls..].iter().all(|ws| *ws == GLOBEX), "making globex's touched only globex's keystore");
        // The same box has another name in each, the known answers' own.
        let (ours, theirs) = (name_under(inner_bytes(), "dev"), name_under(GLOBEX_INNER, "dev"));
        assert_eq!((ours.as_bytes().as_slice(), theirs.as_bytes().as_slice()), (hex(KAT_BOX_NAME).as_slice(), hex(KAT_BOX_NAME_GLOBEX).as_slice()));
        // A blob copied from globex does not open in acme.
        let globex_blob = world.keystore.get(GLOBEX, &theirs).unwrap().unwrap();
        let ours_blob = world.keystore.get(acme(), &ours).unwrap().unwrap();
        world.keystore.put(acme(), &ours, &globex_blob).unwrap();
        let reader = ws_open(&world.machine(&world.acme, Build::Dev), &ws_name("acme")).unwrap();
        assert_eq!(refused(reader.box_key(&world.keystore, "dev")), Refusal::Unreadable);
        world.keystore.put(acme(), &ours, &ours_blob).unwrap();
        assert_eq!(reader.box_key(&world.keystore, "dev").unwrap().unwrap().hex().as_str(), "41".repeat(32));
        // Removing acme's leaves globex's.
        let globex = world.kept(GLOBEX);
        world.rm("acme", "dev").unwrap();
        assert!(world.kept(GLOBEX) == globex);
        let theirs = ws_open(&world.machine(&world.globex, Build::Dev), &ws_name("globex")).unwrap();
        assert_eq!(theirs.box_key(&world.keystore, "dev").unwrap().unwrap().hex().as_str(), "42".repeat(32));
    }

    #[test]
    fn a_release_build_refuses_dev_adapters_before_anything_is_read() {
        let world = World::new();
        let (reads, anchor_reads, asks) = (world.files.calls(), world.anchor.reads(), world.asks());
        let release = world.machine(&world.acme, Build::Release);
        let soft = Refusal::NotAdmitted { adapter: "soft-key", grade: Grade::Dev };
        assert_eq!(refused(ws_box_new(&release, &ws_name("acme"), None, &policy("dev", BOX_TEXT, Base::New), || Ok(()), world.nonces())), soft);
        assert_eq!(refused(ws_box_rm(&release, &ws_name("acme"), "dev", [0; 12])), soft);
        assert_eq!((world.files.calls(), world.anchor.reads(), world.asks()), (reads, anchor_reads, asks));
    }
}
