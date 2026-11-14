//! The verbs on a workspace's approved policies: approve some, list what is approved. Each starts
//! as the verbs on secrets do (`items`): admission, the record and its kinds, one approval naming
//! its change, and the manifest's checks, item names included.
//!
//! An approval lives in the sealed manifest, under a key only the inner key gives, so nothing that
//! an open workspace hands out can write one: approving asks the key holder again. Texts are
//! hashed here, never by the caller.

use anyhow::Result;

use super::items::with_list;
use super::ws::Machine;
use crate::holder::Change;
use crate::ids::WsName;
use crate::manifest::Manifest;
use crate::policy::{Approval, Edit, Kind, Proposal, apply};
use crate::refusal::Refusal;

/// What approving did to one policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Was {
    /// It had no approval.
    New,
    /// It had one, of another text, which this replaced.
    Replaced,
    /// That text was approved already.
    Already,
}

/// Approves each proposal's text as its policy, replacing any approval it had: one approval
/// (`Change::Approve`). What it did to each, in the order given.
///
/// Every base is checked against the sealed list first (`policy::Base`); one that doesn't hold is
/// `Refusal::NotTheBase`, and nothing is written. The manifest is replaced once and the pin moves
/// by one, unless every text was approved already, when nothing is written. A bad name or text, a
/// policy given twice, or none given is `Refusal::BadPolicy`, before anything is asked.
///
/// A cut short before the pin moves leaves the approvals as they were; after it, the next unlock
/// finishes it.
pub fn ws_approve(machine: &Machine<'_>, name: &WsName, proposals: &[Proposal<'_>], manifest_nonce: [u8; 12]) -> Result<Vec<Was>> {
    let approvals = proposals.iter().map(|proposal| Approval::of(proposal.kind, proposal.name, proposal.text)).collect::<Result<Vec<Approval>, Refusal>>()?;
    let mut named: Vec<(Kind, &str)> = proposals.iter().map(|proposal| (proposal.kind, proposal.name)).collect();
    named.sort_unstable();
    named.dedup();
    if proposals.is_empty() || named.len() != proposals.len() {
        return Err(Refusal::BadPolicy.into());
    }
    with_list(machine, name, Change::Approve, |ws, unlocked, manifest, _| {
        if let Some(proposal) = proposals.iter().find(|proposal| !proposal.base_holds(&manifest.approvals)) {
            return Err(Refusal::NotTheBase { name: proposal.name.to_string() }.into());
        }
        let was = approvals
            .iter()
            .map(|approval| match manifest.approvals.iter().find(|old| old.is(approval.kind(), approval.name())) {
                None => Was::New,
                Some(old) if old == approval => Was::Already,
                Some(_) => Was::Replaced,
            })
            .collect();
        let list = apply(&manifest.approvals, approvals.into_iter().map(Edit::Set));
        if list == manifest.approvals {
            return Ok(was);
        }
        let sealed = Manifest { approvals: list, ..manifest }.seal(unlocked.inner, ws, name, &manifest_nonce)?;
        unlocked.replace_manifest(&sealed)?;
        Ok(was)
    })
}

/// The approvals the workspace holds, in order of kind and name: one approval (`Change::Open`).
/// Writes nothing, and leaves the pin where it was.
pub fn ws_approvals(machine: &Machine<'_>, name: &WsName) -> Result<Vec<Approval>> {
    with_list(machine, name, Change::Open, |_, _, manifest, _| Ok(manifest.approvals))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use zeroize::Zeroizing;

    use super::*;
    use crate::anchor::{Anchor, Pin, state_hash};
    use crate::crypto::vectors::{
        KAT_HARDWARE_WRAP, POLICY_TEXT, approval_manifest_nonce, hardware_rand, hardware_seed, hex, inner_bytes, manifest_nonce, recovery_rand, recovery_seed, ws_bytes,
    };
    use crate::fakes::{MemAnchor, MemFiles, MemKeystore, SoftKey};
    use crate::holder::{KeyHolder, KeyKind};
    use crate::ids::WsId;
    use crate::item::{ItemKey, Secret};
    use crate::key::InnerKey;
    use crate::manifest::{LogHead, Recorded};
    use crate::platform::{Build, Grade, Lacks, Os, Property, Role};
    use crate::policy::Base;
    use crate::store::{FileKey, Files, KeystoreKind};
    use crate::verbs::{Draws, Fresh, Host, Nonces, Which, ws_new, ws_remove, ws_set};

    // Every key here is held in software: nothing is derived at 64 MiB.

    const GLOBEX: WsId = WsId::from_bytes([2; 16]);
    /// globex's inner key.
    const GLOBEX_INNER: [u8; 32] = [0x22; 32];
    /// Another text for github's policy.
    const WIDER: &[u8] = b"[fetch]\nhosts = [\"https://api.github.com\", \"https://uploads.github.com\"]\n";
    /// A text for linear's.
    const LINEAR: &[u8] = b"[fetch]\nhosts = [\"https://api.linear.example\"]\n";

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn ws_name(text: &str) -> WsName {
        WsName::parse(text).unwrap()
    }

    fn key(resource: &str, field: &str) -> ItemKey {
        ItemKey::parse(resource, field).unwrap()
    }

    /// The refusal a verb failed with. Panics if it did not fail, or failed some other way.
    fn refused<T>(result: Result<T>) -> Refusal {
        result.err().expect("it fails").downcast::<Refusal>().expect("with a refusal")
    }

    /// A resource's text to approve, and what it was shown against.
    fn proposal<'a>(name: &'a str, text: &'a [u8], base: Base<'a>) -> Proposal<'a> {
        Proposal { kind: Kind::Resource, name, text, base }
    }

    fn approval(name: &str, text: &[u8]) -> Approval {
        Approval::of(Kind::Resource, name, text).unwrap()
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

    /// Everything of a workspace an approval could change: its manifest, any manifest beside it, and its pin.
    type Kept = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Pin>);

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

        /// A nonce never drawn before in this world.
        fn nonce(&self) -> [u8; 12] {
            let n = self.drawn.get() + 1;
            self.drawn.set(n);
            [n; 12]
        }

        /// Each verb, in a debug build.
        fn approve(&self, text: &str, proposals: &[Proposal<'_>]) -> Result<Vec<Was>> {
            ws_approve(&self.machine(self.holder(text), Build::Dev), &ws_name(text), proposals, self.nonce())
        }

        fn approvals(&self, text: &str) -> Result<Vec<Approval>> {
            ws_approvals(&self.machine(self.holder(text), Build::Dev), &ws_name(text))
        }

        fn set(&self, text: &str, key: &ItemKey) -> Result<()> {
            let value = || Ok(Secret::new(Zeroizing::new(b"a value".to_vec()))?);
            ws_set(&self.machine(self.holder(text), Build::Dev), &ws_name(text), key, value, Nonces { value: [0x70; 12], manifest: self.nonce() }).map(|_| ())
        }

        fn remove(&self, text: &str, which: &Which) -> Result<Vec<ItemKey>> {
            ws_remove(&self.machine(self.holder(text), Build::Dev), &ws_name(text), which, self.nonce())
        }

        fn file(&self, key: &FileKey) -> Option<Vec<u8>> {
            self.files.read(key).unwrap()
        }

        fn pin(&self, ws: WsId) -> Pin {
            self.anchor.read(ws).unwrap().unwrap()
        }

        fn kept(&self, ws: WsId) -> Kept {
            (self.file(&FileKey::Manifest(ws)), self.file(&FileKey::NextManifest(ws)), self.anchor.read(ws).unwrap())
        }

        /// acme's manifest, opened.
        fn manifest(&self) -> Manifest {
            Manifest::open(&InnerKey::from_bytes(Zeroizing::new(inner_bytes())), acme(), &ws_name("acme"), &self.file(&FileKey::Manifest(acme())).unwrap()).unwrap()
        }

        /// How many times acme's holder was asked.
        fn asks(&self) -> usize {
            self.acme.asked().len()
        }

        /// Puts `sealed` in place of acme's manifest, and moves the pin over it at a higher version: what a program running
        /// as the user can do where the pin is kept in a file.
        fn repin(&self, sealed: &[u8]) {
            self.files.write_atomic(&FileKey::Manifest(acme()), sealed).unwrap();
            let pin = self.pin(acme());
            let state = state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), sealed, b"");
            self.anchor.advance(acme(), &Pin { version: pin.version + 1, state, ..pin }).unwrap();
        }
    }

    #[test]
    fn approving_takes_one_approval_and_seals_the_text_s_hash() {
        let world = World::new();
        let was = ws_approve(&world.machine(&world.acme, Build::Dev), &ws_name("acme"), &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)], approval_manifest_nonce());
        assert_eq!(was.unwrap(), [Was::New]);
        let asked: Vec<(Change, String)> = world.acme.asked().into_iter().map(|(.., change, text)| (change, text)).collect();
        assert_eq!(
            asked,
            [(Change::Create, "[DEV, not protected] create workspace acme".to_string()), (Change::Approve, "[DEV, not protected] approve policies in workspace acme".to_string())]
        );
        assert_eq!(world.acme.decapsulations(), 1);
        // The manifest is acme's with that one approval, sealed with the nonce given.
        let approved = Manifest { approvals: vec![approval("github", POLICY_TEXT.as_bytes())], ..dev_manifest() };
        assert_eq!(world.manifest(), approved);
        let sealed = world.file(&FileKey::Manifest(acme())).unwrap();
        assert_eq!(sealed, approved.seal(&InnerKey::from_bytes(Zeroizing::new(inner_bytes())), acme(), &ws_name("acme"), &approval_manifest_nonce()).unwrap());
        assert_eq!(world.file(&FileKey::NextManifest(acme())), None);
        // The pin moved on by one, over that manifest.
        let pin = world.pin(acme());
        assert_eq!(pin.version, 2);
        assert_eq!(pin.state, state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), &sealed, b""));
        // And it is listed, with one more ask, to open.
        assert_eq!(world.approvals("acme").unwrap(), [approval("github", POLICY_TEXT.as_bytes())]);
        assert_eq!(world.acme.asked().last().unwrap().2, Change::Open);
        assert_eq!(world.pin(acme()), pin, "listing leaves the pin where it was");
    }

    #[test]
    fn approving_several_is_one_change() {
        let world = World::new();
        let asks = world.asks();
        let was = world.approve("acme", &[proposal("linear", LINEAR, Base::New), proposal("github", POLICY_TEXT.as_bytes(), Base::Shown)]).unwrap();
        assert_eq!(was, [Was::New, Was::New], "in the order given");
        assert_eq!((world.asks(), world.acme.decapsulations()), (asks + 1, 1));
        assert_eq!(world.pin(acme()).version, 2);
        // Listed in order of name.
        assert_eq!(world.approvals("acme").unwrap(), [approval("github", POLICY_TEXT.as_bytes()), approval("linear", LINEAR)]);
        // One of each outcome, still one change.
        let was = world.approve("acme", &[proposal("github", WIDER, Base::Shown), proposal("linear", LINEAR, Base::Shown), proposal("slack", b"[fetch]\n", Base::New)]).unwrap();
        assert_eq!(was, [Was::Replaced, Was::Already, Was::New]);
        assert_eq!(world.pin(acme()).version, 3);
    }

    #[test]
    fn approving_what_is_approved_writes_nothing() {
        let world = World::new();
        world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)]).unwrap();
        let (kept, asks) = (world.kept(acme()), world.asks());
        for base in [Base::Shown, Base::Copy(POLICY_TEXT.as_bytes())] {
            assert_eq!(world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), base)]).unwrap(), [Was::Already]);
        }
        assert_eq!(world.asks(), asks + 2, "still asked each time");
        assert!(world.kept(acme()) == kept, "the manifest and pin are as they were");
    }

    #[test]
    fn a_changed_text_replaces_its_approval() {
        let world = World::new();
        world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)]).unwrap();
        assert_eq!(world.approve("acme", &[proposal("github", WIDER, Base::Copy(POLICY_TEXT.as_bytes()))]).unwrap(), [Was::Replaced]);
        assert_eq!(world.manifest().approvals, [approval("github", WIDER)]);
        assert_eq!(world.pin(acme()).version, 3);
        // The text approved before no longer is.
        let listed = world.approvals("acme").unwrap();
        assert!(listed[0].approves(WIDER) && !listed[0].approves(POLICY_TEXT.as_bytes()));
    }

    #[test]
    fn a_base_that_isn_t_the_sealed_one_refuses_everything() {
        let world = World::new();
        world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New), proposal("linear", LINEAR, Base::New)]).unwrap();
        let good = proposal("slack", b"[fetch]\n", Base::New);
        let cases: [(&[Proposal<'_>], &str); 6] = [
            (&[proposal("github", WIDER, Base::New)], "github"),
            (&[proposal("github", WIDER, Base::Copy(b"[fetch]\n"))], "github"),
            (&[proposal("github", WIDER, Base::Copy(LINEAR))], "github"),
            (&[proposal("slack", b"[fetch]\n", Base::Copy(b"[fetch]\n"))], "slack"),
            (&[good, proposal("linear", LINEAR, Base::Shown), proposal("github", WIDER, Base::New)], "github"),
            (&[proposal("github", WIDER, Base::Copy(POLICY_TEXT.as_bytes())), proposal("linear", WIDER, Base::Copy(POLICY_TEXT.as_bytes())), good], "linear"),
        ];
        for (proposals, name) in cases {
            let (kept, asks) = (world.kept(acme()), world.asks());
            let refusal = refused(world.approve("acme", proposals));
            assert_eq!(refusal, Refusal::NotTheBase { name: name.to_string() }, "{proposals:?}");
            assert_eq!(world.asks(), asks + 1, "refused after the one ask");
            assert!(world.kept(acme()) == kept, "{proposals:?}: nothing was written");
        }
        assert_eq!(Refusal::NotTheBase { name: "github".to_string() }.to_string(), "the approved copy of github isn't what was approved, so nothing was approved");
        // A text shown whole is never checked against anything; a copy that is what was approved holds.
        assert_eq!(world.approve("acme", &[proposal("github", WIDER, Base::Shown)]).unwrap(), [Was::Replaced]);
        assert_eq!(world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::Copy(WIDER))]).unwrap(), [Was::Replaced]);
    }

    #[test]
    fn a_bad_or_repeated_policy_is_refused_before_anything_is_asked() {
        let world = World::new();
        let too_long = vec![b'x'; Approval::MAX_TEXT + 1];
        let cases: [&[Proposal<'_>]; 7] = [
            &[],
            &[proposal("Git", POLICY_TEXT.as_bytes(), Base::Shown)],
            &[proposal("", POLICY_TEXT.as_bytes(), Base::Shown)],
            &[proposal("github", b"", Base::Shown)],
            &[proposal("github", &too_long, Base::Shown)],
            &[proposal("github", POLICY_TEXT.as_bytes(), Base::Shown), proposal("github", POLICY_TEXT.as_bytes(), Base::Shown)],
            &[proposal("github", POLICY_TEXT.as_bytes(), Base::Shown), proposal("linear", LINEAR, Base::New), proposal("github", WIDER, Base::New)],
        ];
        let reads = world.files.calls();
        for proposals in cases {
            assert_eq!(refused(world.approve("acme", proposals)), Refusal::BadPolicy, "{proposals:?}");
        }
        assert_eq!(world.acme.asked().into_iter().map(|(.., change, _)| change).collect::<Vec<Change>>(), [Change::Create]);
        assert_eq!(world.files.calls(), reads, "nothing was read");
        assert_eq!(Refusal::BadPolicy.to_string(), "that policy can't be approved: a policy is 1 to 65536 bytes, for a resource of a-z, 0-9 and -");
    }

    #[test]
    fn a_declined_approval_changes_nothing() {
        let world = World::new();
        world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)]).unwrap();
        let kept = world.kept(acme());
        world.acme.decline(true);
        assert_eq!(refused(world.approve("acme", &[proposal("github", WIDER, Base::Shown), proposal("linear", LINEAR, Base::New)])), Refusal::Declined);
        assert!(world.kept(acme()) == kept);
        world.acme.decline(false);
        assert_eq!(world.approvals("acme").unwrap(), [approval("github", POLICY_TEXT.as_bytes())]);
        // A workspace that is not there is refused before anything is asked.
        let asks = world.asks();
        assert_eq!(refused(world.approve("initech", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)])), Refusal::Unknown(ws_name("initech")));
        assert_eq!(world.asks(), asks);
    }

    #[test]
    fn an_approval_cut_short_leaves_the_old_approvals() {
        let world = World::new();
        world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)]).unwrap();
        let pin = world.pin(acme());
        world.anchor.fail_next_advance();
        let error = world.approve("acme", &[proposal("github", WIDER, Base::Shown), proposal("linear", LINEAR, Base::New)]).unwrap_err();
        assert!(error.to_string().contains("could not be written"), "{error}");
        assert_eq!(world.pin(acme()), pin);
        assert_eq!(world.approvals("acme").unwrap(), [approval("github", POLICY_TEXT.as_bytes())]);
        assert_eq!(world.file(&FileKey::NextManifest(acme())), None, "the next unlock dropped what was written");
        // Approving again works, against the approvals as they were.
        assert_eq!(
            world.approve("acme", &[proposal("github", WIDER, Base::Copy(POLICY_TEXT.as_bytes())), proposal("linear", LINEAR, Base::New)]).unwrap(),
            [Was::Replaced, Was::New]
        );
        assert_eq!(world.approvals("acme").unwrap(), [approval("github", WIDER), approval("linear", LINEAR)]);
        assert_eq!(world.pin(acme()).version, pin.version + 1);
    }

    #[test]
    fn approvals_outlive_storing_and_removing_a_field() {
        let world = World::new();
        world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)]).unwrap();
        world.set("acme", &key("github", "token")).unwrap();
        world.set("acme", &key("github", "user")).unwrap();
        assert_eq!(world.remove("acme", &Which::Field(key("github", "user"))).unwrap(), [key("github", "user")]);
        assert_eq!(world.approvals("acme").unwrap(), [approval("github", POLICY_TEXT.as_bytes())]);
        // And approving keeps the secrets.
        world.approve("acme", &[proposal("linear", LINEAR, Base::New)]).unwrap();
        assert_eq!(world.manifest().items.iter().map(|entry| entry.key.clone()).collect::<Vec<ItemKey>>(), [key("github", "token")]);
    }

    #[test]
    fn removing_a_resource_drops_its_approval() {
        let world = World::new();
        world.set("acme", &key("github", "token")).unwrap();
        world.set("acme", &key("linear", "token")).unwrap();
        world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New), proposal("linear", LINEAR, Base::New), proposal("slack", b"[fetch]\n", Base::New)]).unwrap();
        // Its secrets and its approval, in one change.
        let version = world.pin(acme()).version;
        assert_eq!(world.remove("acme", &Which::Resource("github".to_string())).unwrap(), [key("github", "token")]);
        assert_eq!(world.pin(acme()).version, version + 1);
        assert_eq!(world.approvals("acme").unwrap(), [approval("linear", LINEAR), approval("slack", b"[fetch]\n")]);
        // One with an approval and no secrets: no secret is removed, and that is no refusal.
        assert_eq!(world.remove("acme", &Which::Resource("slack".to_string())).unwrap(), []);
        assert_eq!(world.pin(acme()).version, version + 2);
        assert_eq!(world.approvals("acme").unwrap(), [approval("linear", LINEAR)]);
        // With neither: refused after one ask, with nothing written.
        let (kept, asks) = (world.kept(acme()), world.asks());
        assert_eq!(refused(world.remove("acme", &Which::Resource("slack".to_string()))), Refusal::NoSecret { ws: ws_name("acme"), what: "slack".to_string() });
        assert_eq!(world.asks(), asks + 1);
        assert!(world.kept(acme()) == kept);
        // A field that isn't stored is no secret, whatever is approved; one that is goes, and leaves the approval.
        assert_eq!(refused(world.remove("acme", &Which::Field(key("linear", "user")))), Refusal::NoSecret { ws: ws_name("acme"), what: "linear/user".to_string() });
        world.remove("acme", &Which::Field(key("linear", "token"))).unwrap();
        assert_eq!(world.approvals("acme").unwrap(), [approval("linear", LINEAR)]);
    }

    #[test]
    fn a_planted_or_copied_approval_approves_nothing() {
        let world = World::new().with_globex();
        world.approve("globex", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)]).unwrap();
        let theirs = world.file(&FileKey::Manifest(GLOBEX)).unwrap();
        let ours = world.file(&FileKey::Manifest(acme())).unwrap();
        // Each is put in place of acme's manifest, or beside it; then acme is put back as it was.
        let put_back = |pin: Pin| {
            world.files.write_atomic(&FileKey::Manifest(acme()), &ours).unwrap();
            world.files.remove(&FileKey::Policy(acme())).unwrap();
            let now = world.pin(acme());
            world.anchor.advance(acme(), &Pin { version: now.version + 1, ..pin }).unwrap();
        };

        // globex's sealed manifest over acme's: no pin covers it, so it is refused before anything is asked.
        let (pin, asks) = (world.pin(acme()), world.asks());
        world.files.write_atomic(&FileKey::Manifest(acme()), &theirs).unwrap();
        assert_eq!(refused(world.approvals("acme")), Refusal::Unreadable);
        assert_eq!(refused(world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::Copy(POLICY_TEXT.as_bytes()))])), Refusal::Unreadable);
        assert_eq!(world.asks(), asks);
        put_back(pin);
        // A policy file beside it: the pin covers that too.
        world.files.write_atomic(&FileKey::Policy(acme()), b"github").unwrap();
        assert_eq!(refused(world.approvals("acme")), Refusal::Unreadable);
        assert_eq!(world.asks(), asks);
        put_back(pin);

        // Re-pinned over it: the seal names globex, so it doesn't open, after one ask.
        let sealed_for_acme_by_globex = Manifest { approvals: vec![approval("github", POLICY_TEXT.as_bytes())], ..dev_manifest() }
            .seal(&InnerKey::from_bytes(Zeroizing::new(GLOBEX_INNER)), acme(), &ws_name("acme"), &[0x55; 12])
            .unwrap();
        let mut changed = world.file(&FileKey::Manifest(acme())).unwrap();
        changed[40] ^= 0x01;
        for (planted, what) in [(&theirs, "globex's"), (&sealed_for_acme_by_globex, "sealed for acme under globex's inner key"), (&changed, "one byte changed")] {
            world.repin(planted);
            let asks = world.asks();
            assert_eq!(refused(world.approvals("acme")), Refusal::Tampered, "{what}");
            assert_eq!(refused(world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::Copy(POLICY_TEXT.as_bytes()))])), Refusal::Tampered, "{what}");
            assert_eq!(world.asks(), asks + 2, "{what}");
            put_back(pin);
        }
        // Put back, acme has approved nothing, and its github is new.
        assert_eq!(world.approvals("acme").unwrap(), []);
        assert_eq!(world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)]).unwrap(), [Was::New]);
    }

    #[test]
    fn any_manifest_put_back_with_a_pin_reads_as_it_was() {
        // Not prevented while the pin is a file: a manifest acme once sealed, put back with a pin re-hashed over it at a
        // higher version, opens, and its approvals and revocations are as they were then.
        let world = World::new();
        world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)]).unwrap();
        let first = world.file(&FileKey::Manifest(acme())).unwrap();
        world.approve("acme", &[proposal("linear", LINEAR, Base::New)]).unwrap();
        world.remove("acme", &Which::Resource("github".to_string())).unwrap();
        assert_eq!(world.approvals("acme").unwrap(), [approval("linear", LINEAR)]);
        world.repin(&first);
        assert_eq!(world.approvals("acme").unwrap(), [approval("github", POLICY_TEXT.as_bytes())]);
    }

    #[test]
    fn approvals_of_one_workspace_never_reach_another() {
        let world = World::new().with_globex();
        let globex = world.kept(GLOBEX);
        world.approve("acme", &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)]).unwrap();
        assert!(world.kept(GLOBEX) == globex, "approving in acme wrote nothing of globex's");
        assert_eq!(world.approvals("globex").unwrap(), []);
        assert_eq!(world.globex.asked().last().unwrap().2, Change::Open);
        // In globex the same policy is new, and a copy of acme's approval is no base.
        assert_eq!(
            refused(world.approve("globex", &[proposal("github", POLICY_TEXT.as_bytes(), Base::Copy(POLICY_TEXT.as_bytes()))])),
            Refusal::NotTheBase { name: "github".to_string() }
        );
        assert_eq!(world.approve("globex", &[proposal("github", WIDER, Base::New)]).unwrap(), [Was::New]);
        assert_eq!(world.approvals("acme").unwrap(), [approval("github", POLICY_TEXT.as_bytes())]);
        assert_eq!(world.approvals("globex").unwrap(), [approval("github", WIDER)]);
    }

    #[test]
    fn a_release_build_refuses_dev_adapters_before_anything_is_read() {
        let world = World::new();
        let (reads, anchor_reads, asks) = (world.files.calls(), world.anchor.reads(), world.asks());
        let release = world.machine(&world.acme, Build::Release);
        let soft = Refusal::NotAdmitted { adapter: "soft-key", grade: Grade::Dev };
        assert_eq!(refused(ws_approve(&release, &ws_name("acme"), &[proposal("github", POLICY_TEXT.as_bytes(), Base::New)], [0; 12])), soft);
        assert_eq!(refused(ws_approvals(&release, &ws_name("acme"))), soft);
        // Nothing was read, written or asked.
        assert_eq!((world.files.calls(), world.anchor.reads(), world.asks()), (reads, anchor_reads, asks));
    }
}
