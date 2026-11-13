//! The saved passphrase, end to end through core's verbs: real workspace files in a test folder, the
//! copies in memory instead of the Keychain, the approval engine's fake `World`, and every question
//! answered by the holder's test answer. No test here reaches the Keychain, sudo or Touch ID.
//!
//! Each make, open and delete that reaches a passphrase derives a key at 64 MiB once.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs;

use super::*;
use crate::approval::fake_tests::Fake;
use crate::util::{TempDir, sha256_hex};

const ACME: &str = "acme passphrase one";
const GLOBEX: &str = "globex passphrase one";
const OPENED: [&str; 2] = ["passphrase correct", "workspaces can't stay open yet, so acme was closed again"];
const DEBUG: &str = "debug build: this workspace opens only with a debug build";

/// Saved passphrases in memory, with how often one was read. `broken`: none can be added or removed,
/// as with a locked keychain.
#[derive(Default)]
struct Memory {
    items: RefCell<BTreeMap<WsId, Zeroizing<String>>>,
    reads: Cell<usize>,
    broken: Cell<bool>,
}

impl Memory {
    fn copy(&self, ws: WsId) -> Option<String> {
        self.items.borrow().get(&ws).map(|text| text.to_string())
    }

    /// What another program, or a person in Keychain Access, can put there.
    fn put(&self, ws: WsId, text: &str) {
        self.items.borrow_mut().insert(ws, Zeroizing::new(text.to_string()));
    }
}

impl Copies for Memory {
    fn exists(&self, ws: WsId) -> bool {
        self.items.borrow().contains_key(&ws)
    }

    fn add(&self, ws: WsId, passphrase: &str) -> Result<()> {
        if self.broken.get() {
            bail!("the keychain is locked");
        }
        self.put(ws, passphrase);
        Ok(())
    }

    fn get(&self, ws: WsId) -> Option<Zeroizing<String>> {
        self.reads.set(self.reads.get() + 1);
        self.items.borrow().get(&ws).cloned()
    }

    fn remove(&self, ws: WsId) -> bool {
        !self.broken.get() && self.items.borrow_mut().remove(&ws).is_some()
    }
}

/// A workspaces folder of the test's own, removed when dropped.
struct Folder {
    here: Here,
    dir: TempDir,
}

fn folder(prefix: &str) -> Folder {
    let dir = TempDir::new(prefix).unwrap();
    Folder { here: Here::at(&dir.0.join("ws")), dir }
}

fn name(text: &str) -> WsName {
    WsName::parse(text).unwrap()
}

/// Makes `text` with `passphrase`, of the person's own, saved in `copies` when `saving`, as `ws new`
/// does where the keychain is the manager.
fn make(here: &Here, text: &str, passphrase: &str, saving: bool, copies: &Memory) -> (WsId, Said) {
    let holder = TtyPassphrase::new(false).answering(passphrase);
    let holder = if saving { holder.saving() } else { holder };
    let said = new_with(here, &name(text), &holder, copies).unwrap();
    (here.id_of(&name(text)).unwrap(), said)
}

/// Every question answered with `passphrase`.
fn typing(passphrase: &str) -> impl Fn() -> TtyPassphrase {
    move || TtyPassphrase::new(false).answering(passphrase)
}

fn way<'a>(world: &'a Fake, copies: &'a Memory, means: Option<Means>) -> Way<'a> {
    Way { world, copies, means, detail: None }
}

fn out(said: &Said) -> Vec<&str> {
    said.out.iter().map(String::as_str).collect()
}

#[test]
fn ws_new_saves_the_passphrase_only_where_a_manager_keeps_it() {
    let f = folder("halti-saved-new");
    let copies = Memory::default();
    let (acme, said) = make(&f.here, "acme", ACME, true, &copies);
    assert_eq!(out(&said), ["created workspace acme", "its passphrase is saved in the keychain", "open it with: halti open acme", DEBUG]);
    assert!(said.notes.is_empty());
    assert_eq!(copies.copy(acme).as_deref(), Some(ACME));
    // Typed each time: nothing is saved, and nothing more is said.
    let (globex, said) = make(&f.here, "globex", GLOBEX, false, &copies);
    assert_eq!(out(&said), ["created workspace globex", "open it with: halti open globex", DEBUG]);
    assert!(!copies.exists(globex));
    // Each records which way it was made.
    let made_with_a_copy = |text: &str, passphrase: &str| {
        let holder = TtyPassphrase::new(false).answering(passphrase);
        made_saved(ws_open(&f.here.machine(&holder), &name(text)).unwrap().manifest())
    };
    assert!(made_with_a_copy("acme", ACME) && !made_with_a_copy("globex", GLOBEX));
    // A copy that can't be saved leaves the workspace as made, and says it is typed next time.
    copies.broken.set(true);
    let (initech, said) = make(&f.here, "initech", "initech passphrase one", true, &copies);
    assert_eq!(out(&said), ["created workspace initech", "open it with: halti open initech", DEBUG]);
    assert_eq!(said.notes, ["the passphrase of initech was not saved in the keychain. it is typed the next time initech is opened"]);
    assert!(!copies.exists(initech) && f.here.anchor.read(initech).unwrap().is_some());
}

#[test]
fn the_saved_copy_is_released_after_the_approval_each_means_asks_for() {
    let f = folder("halti-saved-open");
    let copies = Memory::default();
    let (acme, _) = make(&f.here, "acme", ACME, true, &copies);
    let asked = |what: &str| vec![format!("{what}: [DEV, not protected] open workspace acme")];
    for (means, calls) in [(Means::Sudo, asked("sudo")), (Means::TouchId, asked("touch id")), (Means::None, Vec::new())] {
        let world = Fake::answering(true, true);
        // Any question would be answered wrong: it opens only from the copy.
        let said = open_with(&f.here, &name("acme"), &way(&world, &copies, Some(means)), &typing("not the passphrase")).unwrap();
        assert_eq!((out(&said), said.notes.len()), (OPENED.to_vec(), 0), "{means:?}");
        assert_eq!(world.calls(), calls, "{means:?}");
    }
    assert_eq!((copies.reads.get(), copies.copy(acme).as_deref()), (3, Some(ACME)));
}

#[test]
fn a_declined_approval_releases_nothing_and_says_how_to_type_it() {
    let f = folder("halti-saved-declined");
    let copies = Memory::default();
    let (acme, _) = make(&f.here, "acme", ACME, true, &copies);
    for means in [Means::Sudo, Means::TouchId] {
        let world = Fake::answering(false, false);
        let error = open_with(&f.here, &name("acme"), &way(&world, &copies, Some(means)), &typing(ACME)).unwrap_err();
        assert_eq!(error.to_string(), "acme was not opened. to type the passphrase instead: halti open acme --type", "{means:?}");
        let error = delete_with(&f.here, &name("acme"), &way(&world, &copies, Some(means)), &typing(ACME)).unwrap_err();
        assert_eq!(error.to_string(), "acme was not deleted. to type the passphrase instead: halti ws delete acme --type", "{means:?}");
        assert_eq!(world.calls().len(), 2, "{means:?}: asked once each, and nothing typed after");
    }
    assert_eq!(copies.reads.get(), 0, "the copy was never read");
    // The workspace and its copy are as they were.
    assert_eq!(copies.copy(acme).as_deref(), Some(ACME));
    let said = open_with(&f.here, &name("acme"), &way(&Fake::answering(true, true), &copies, None), &typing(ACME)).unwrap();
    assert_eq!(out(&said), OPENED);
}

#[test]
fn a_typed_passphrase_never_reads_the_copy_or_asks_for_an_approval() {
    // With `--type`, or where the line says passphrase, there is no means (`saved_means`).
    let f = folder("halti-saved-typed");
    let copies = Memory::default();
    let (acme, _) = make(&f.here, "acme", ACME, true, &copies);
    copies.put(acme, "a copy never read");
    let world = Fake::answering(true, true);
    let said = open_with(&f.here, &name("acme"), &way(&world, &copies, None), &typing(ACME)).unwrap();
    assert_eq!(out(&said), OPENED);
    // A wrong one typed is refused as ever.
    let error = open_with(&f.here, &name("acme"), &way(&world, &copies, None), &typing("acme passphrase two")).unwrap_err();
    assert_eq!(error.downcast_ref::<Refusal>(), Some(&Refusal::Unreadable));
    assert!(world.calls().is_empty() && copies.reads.get() == 0);
    assert_eq!(copies.copy(acme).as_deref(), Some("a copy never read"), "left as it is");
}

#[test]
fn a_missing_stale_or_swapped_copy_is_typed_once_and_saved_again() {
    let f = folder("halti-saved-again");
    let copies = Memory::default();
    let (acme, _) = make(&f.here, "acme", ACME, true, &copies);
    let (globex, _) = make(&f.here, "globex", GLOBEX, true, &copies);
    let swapped = copies.copy(globex).unwrap();
    let again = ["passphrase correct", "saved the passphrase of acme in the keychain again", "workspaces can't stay open yet, so acme was closed again"];
    // Another passphrase, one too short to be any, globex's own, and none.
    for copy in [Some("acme passphrase two"), Some("short"), Some(swapped.as_str()), None] {
        match copy {
            Some(text) => copies.put(acme, text),
            None => assert!(copies.remove(acme)),
        }
        let world = Fake::answering(true, true);
        let said = open_with(&f.here, &name("acme"), &way(&world, &copies, Some(Means::TouchId)), &typing(ACME)).unwrap();
        assert_eq!(out(&said), again, "{copy:?}");
        assert_eq!(copies.copy(acme).as_deref(), Some(ACME), "{copy:?}");
        // The approval is asked only where there was a copy to release.
        assert_eq!(world.calls().len(), usize::from(copy.is_some()), "{copy:?}");
    }
    assert_eq!(copies.copy(globex).as_deref(), Some(GLOBEX), "globex's own copy is untouched");
    // The copy saved again opens it, with nothing typed.
    let said = open_with(&f.here, &name("acme"), &way(&Fake::answering(true, true), &copies, Some(Means::TouchId)), &typing("not the passphrase")).unwrap();
    assert_eq!(out(&said), OPENED);
    // One that can't be saved again: typed now, and said so.
    assert!(copies.remove(acme));
    copies.broken.set(true);
    let said = open_with(&f.here, &name("acme"), &way(&Fake::answering(true, true), &copies, Some(Means::TouchId)), &typing(ACME)).unwrap();
    assert_eq!(out(&said), OPENED);
    assert_eq!(said.notes, ["the passphrase of acme was not saved in the keychain. it is typed the next time acme is opened"]);
}

#[test]
fn a_workspace_made_to_be_typed_never_opens_from_a_copy() {
    let f = folder("halti-saved-made-typed");
    let copies = Memory::default();
    let (acme, _) = make(&f.here, "acme", ACME, false, &copies);
    let each_time = ["passphrase correct", "acme was made without a saved passphrase, so it is typed each time", "workspaces can't stay open yet, so acme was closed again"];
    // No copy: typed, and none is saved for it.
    let world = Fake::answering(true, true);
    let said = open_with(&f.here, &name("acme"), &way(&world, &copies, Some(Means::TouchId)), &typing(ACME)).unwrap();
    assert_eq!(out(&said), each_time);
    assert!(!copies.exists(acme) && world.calls().is_empty());
    // The right passphrase planted as its copy: core refuses to open it from there, it is typed instead, and the copy goes.
    copies.put(acme, ACME);
    let said = open_with(&f.here, &name("acme"), &way(&world, &copies, Some(Means::TouchId)), &typing(ACME)).unwrap();
    assert_eq!(out(&said), each_time);
    assert!(!copies.exists(acme));
    assert_eq!(world.calls().len(), 1);
    // And typed wrong after it, nothing opens.
    copies.put(acme, ACME);
    let error = open_with(&f.here, &name("acme"), &way(&world, &copies, Some(Means::TouchId)), &typing("acme passphrase two")).unwrap_err();
    assert_eq!(error.downcast_ref::<Refusal>(), Some(&Refusal::Unreadable));
}

#[test]
fn a_changed_workspace_is_refused_as_it_is_and_nothing_is_asked_or_typed() {
    let f = folder("halti-saved-changed");
    let copies = Memory::default();
    let (acme, _) = make(&f.here, "acme", ACME, true, &copies);
    let wrap = f.dir.0.join("ws").join(acme.to_string()).join("wrap");
    let mut bytes = fs::read(&wrap).unwrap();
    bytes[1682] ^= 0x01;
    fs::write(wrap, bytes).unwrap();
    let world = Fake::answering(true, true);
    let never = || -> TtyPassphrase { panic!("nothing is typed") };
    let error = open_with(&f.here, &name("acme"), &way(&world, &copies, Some(Means::TouchId)), &never).unwrap_err();
    assert_eq!(error.downcast_ref::<Refusal>(), Some(&Refusal::Unreadable));
    let error = delete_with(&f.here, &name("acme"), &way(&world, &copies, Some(Means::TouchId)), &never).unwrap_err();
    assert!(error.to_string().starts_with("nothing was deleted") && error.downcast_ref::<Refusal>() == Some(&Refusal::Unreadable), "{error:#}");
    assert!(world.calls().is_empty() && copies.reads.get() == 0);
    assert_eq!(copies.copy(acme).as_deref(), Some(ACME));
}

#[test]
fn deleting_removes_the_saved_copy_whichever_way_it_goes() {
    let f = folder("halti-saved-delete");
    let copies = Memory::default();
    // From the copy, after sudo.
    let (acme, _) = make(&f.here, "acme", ACME, true, &copies);
    let world = Fake::answering(true, true);
    let said = delete_with(&f.here, &name("acme"), &way(&world, &copies, Some(Means::Sudo)), &typing("not the passphrase")).unwrap();
    assert_eq!((out(&said), said.notes.len()), (vec!["deleted workspace acme"], 0));
    assert_eq!(world.calls(), ["sudo: [DEV, not protected] delete workspace acme"]);
    assert!(!copies.exists(acme) && f.here.id_of(&name("acme")).is_none());
    // Typed: the copy goes by the id the record named.
    let (globex, _) = make(&f.here, "globex", GLOBEX, true, &copies);
    let said = delete_with(&f.here, &name("globex"), &way(&world, &copies, None), &typing(GLOBEX)).unwrap();
    assert_eq!(out(&said), ["deleted workspace globex"]);
    assert!(!copies.exists(globex));
    // With no pin nothing is asked, and the copy goes all the same.
    let (initech, _) = make(&f.here, "initech", "initech passphrase one", true, &copies);
    f.here.anchor.forget(initech).unwrap();
    let said = delete_with(&f.here, &name("initech"), &way(&world, &copies, Some(Means::TouchId)), &typing("not the passphrase")).unwrap();
    assert_eq!(out(&said), ["removed workspace initech. it was never fully created, so no passphrase was asked"]);
    assert!(!copies.exists(initech) && world.calls().is_empty());
    // A copy that can't be removed is named, so the person can remove it.
    let (umbrella, _) = make(&f.here, "umbrella", "umbrella passphrase one", true, &copies);
    copies.broken.set(true);
    let said = delete_with(&f.here, &name("umbrella"), &way(&world, &copies, Some(Means::None)), &typing("not the passphrase")).unwrap();
    assert_eq!(out(&said), ["deleted workspace umbrella"]);
    assert_eq!(said.notes, [format!("the saved passphrase of umbrella is still in the keychain. remove the item named halti-ws:{umbrella} in keychain access")]);
    assert!(world.calls().is_empty(), "none asks nothing");
}

#[test]
fn secrets_are_stored_listed_and_removed_after_one_approval_each_with_the_value_read_once() {
    let f = folder("halti-saved-secrets");
    let copies = Memory::default();
    let (acme, _) = make(&f.here, "acme", ACME, true, &copies);
    let key = ItemKey::parse("github", "token").unwrap();
    let reads = Cell::new(0);
    let value = || {
        reads.set(reads.get() + 1);
        Ok(Secret::new(Zeroizing::new(b"acme github token".to_vec()))?)
    };
    // Through the copy, after Touch ID: nothing is typed, and any question would be answered wrong.
    let world = Fake::answering(true, true);
    let touch_id = way(&world, &copies, Some(Means::TouchId));
    let said = set_with(&f.here, &name("acme"), &key, &touch_id, &typing("not the passphrase"), &value).unwrap();
    assert_eq!((out(&said), reads.get()), (vec!["stored github/token in acme"], 1));
    assert_eq!(world.calls(), ["touch id: [DEV, not protected] store a secret in workspace acme"]);
    let said = items_with(&f.here, &name("acme"), &touch_id, &typing("not the passphrase")).unwrap();
    assert_eq!(out(&said), ["RESOURCE         FIELDS", "github           token"]);
    assert_eq!(world.calls(), ["touch id: [DEV, not protected] open workspace acme"]);

    // Declined: nothing is read, typed or changed, and each says how to type the passphrase instead.
    let no = Fake::answering(false, false);
    let declined = way(&no, &copies, Some(Means::TouchId));
    let error = set_with(&f.here, &name("acme"), &key, &declined, &typing(ACME), &value).unwrap_err();
    assert_eq!(error.to_string(), "github/token was not stored. to type the passphrase instead: halti ws set acme/github token --type");
    let error = items_with(&f.here, &name("acme"), &declined, &typing(ACME)).unwrap_err();
    assert_eq!(error.to_string(), "the secrets of acme were not listed. to type the passphrase instead: halti ws ls acme --type");
    let error = rm_with(&f.here, &name("acme"), &Which::Resource("github".to_string()), &declined, &typing(ACME)).unwrap_err();
    assert_eq!(error.to_string(), "github was not removed. to type the passphrase instead: halti ws rm acme/github --type");
    assert_eq!((no.calls().len(), reads.get()), (3, 1));

    // A copy that can't be used is typed once, the value is still read once, and the copy is left for `open` to save again.
    copies.put(acme, "acme passphrase two");
    let world = Fake::answering(true, true);
    let said = set_with(&f.here, &name("acme"), &key, &way(&world, &copies, Some(Means::TouchId)), &typing(ACME), &value).unwrap();
    assert_eq!((out(&said), reads.get(), world.calls().len()), (vec!["replaced github/token in acme"], 2, 1));
    assert_eq!(copies.copy(acme).as_deref(), Some("acme passphrase two"));

    // Removing names what it removed, and naming nothing stored is refused after the approval.
    let world = Fake::answering(true, true);
    let typed = way(&world, &copies, None);
    let said = rm_with(&f.here, &name("acme"), &Which::Resource("github".to_string()), &typed, &typing(ACME)).unwrap();
    assert_eq!(out(&said), ["removed github from acme"]);
    let error = rm_with(&f.here, &name("acme"), &Which::Field(key.clone()), &typed, &typing(ACME)).unwrap_err();
    assert_eq!(error.downcast_ref::<Refusal>(), Some(&Refusal::NoSecret { ws: name("acme"), what: "github/token".to_string() }));
    let said = items_with(&f.here, &name("acme"), &typed, &typing(ACME)).unwrap();
    assert_eq!(out(&said), ["acme has no secrets yet. add one with: halti ws set acme/RESOURCE FIELD"]);
    assert!(world.calls().is_empty(), "typed, nothing else is asked");
}

#[test]
fn a_store_in_a_workspace_made_to_be_typed_reads_the_value_once_after_typing() {
    let f = folder("halti-saved-secrets-typed");
    let copies = Memory::default();
    let (globex, _) = make(&f.here, "globex", GLOBEX, false, &copies);
    // The right passphrase planted as its copy: core refuses the copy before the value is read, and it is typed.
    copies.put(globex, GLOBEX);
    let reads = Cell::new(0);
    let value = || {
        reads.set(reads.get() + 1);
        Ok(Secret::new(Zeroizing::new(b"globex linear token".to_vec()))?)
    };
    let world = Fake::answering(true, true);
    let key = ItemKey::parse("linear", "token").unwrap();
    let said = set_with(&f.here, &name("globex"), &key, &way(&world, &copies, Some(Means::Sudo)), &typing(GLOBEX), &value).unwrap();
    assert_eq!((out(&said), reads.get(), world.calls().len()), (vec!["stored linear/token in globex"], 1, 1));
    // Typed wrong, nothing is read or stored.
    let error = set_with(&f.here, &name("globex"), &key, &way(&world, &copies, None), &typing("globex passphrase two"), &value).unwrap_err();
    assert_eq!((error.downcast_ref::<Refusal>(), reads.get()), (Some(&Refusal::Unreadable), 1));
    // An empty value stores nothing, and says so.
    let empty = || -> Result<Secret> { bail!("no value was given, so nothing was stored") };
    let error = set_with(&f.here, &name("globex"), &ItemKey::parse("github", "token").unwrap(), &way(&world, &copies, None), &typing(GLOBEX), &empty).unwrap_err();
    assert_eq!(error.to_string(), "no value was given, so nothing was stored");
    let said = items_with(&f.here, &name("globex"), &way(&world, &copies, None), &typing(GLOBEX)).unwrap();
    assert_eq!(out(&said), ["RESOURCE         FIELDS", "linear           token"]);
}

#[test]
fn the_approve_window_names_the_policies() {
    let f = folder("halti-saved-policies");
    let copies = Memory::default();
    let (acme, _) = make(&f.here, "acme", ACME, true, &copies);
    let files = f.here.policies(acme);
    let text = |resource: &str| format!("# {resource}\n[fetch]\nhosts = [\"https://{resource}.example\"]\n");
    let hash = |resource: &str| sha256_hex(text(resource).as_bytes())[..12].to_string();
    for resource in ["github", "linear", "slack", "zoom", "zulip"] {
        assert!(files.create(resource, &text(resource)).unwrap());
    }
    // Every policy, through the copy after Touch ID: the window names three, then how many more.
    let world = Fake::answering(true, true);
    let said = policies::approve_with(&f.here, &name("acme"), None, &way(&world, &copies, Some(Means::TouchId)), &typing("not the passphrase")).unwrap();
    let approved: Vec<String> = ["github", "linear", "slack", "zoom", "zulip"].iter().map(|resource| format!("approved the policy for {resource} in acme")).collect();
    assert_eq!(said.out, approved);
    let (github, linear, slack) = (hash("github"), hash("linear"), hash("slack"));
    let named = format!("touch id: [DEV, not protected] approve policies github {github}, linear {linear}, slack {slack} and 2 more in workspace acme");
    assert_eq!(world.calls(), [named]);
    // One, after sudo: named alone.
    fs::write(files.path("zoom"), format!("{}# wider\n", text("zoom"))).unwrap();
    let said = policies::approve_with(&f.here, &name("acme"), Some("zoom"), &way(&world, &copies, Some(Means::Sudo)), &typing("not the passphrase")).unwrap();
    assert_eq!(out(&said), ["approved the policy for zoom in acme"]);
    let zoom = sha256_hex(fs::read(files.path("zoom")).unwrap().as_slice())[..12].to_string();
    assert_eq!(world.calls(), [format!("sudo: [DEV, not protected] approve policies zoom {zoom} in workspace acme")]);
    // Any other change says only core's words, whatever detail the way was given.
    let named = Way { world: &world, copies: &copies, means: Some(Means::TouchId), detail: Some(format!("github {github}")) };
    assert_eq!(out(&open_with(&f.here, &name("acme"), &named, &typing("not the passphrase")).unwrap()), OPENED);
    assert_eq!(world.calls(), ["touch id: [DEV, not protected] open workspace acme"]);
    // Typed, nothing but the passphrase is asked.
    let said = policies::approve_with(&f.here, &name("acme"), None, &way(&world, &copies, None), &typing(ACME)).unwrap();
    assert_eq!(said.out.iter().filter(|line| line.ends_with("was approved already")).count(), 5);
    assert!(world.calls().is_empty());
    // A policy added to the five unchanged ones: the window names only what approving changes.
    assert!(files.create("zeta", &text("zeta")).unwrap());
    let said = policies::approve_with(&f.here, &name("acme"), None, &way(&world, &copies, Some(Means::TouchId)), &typing("not the passphrase")).unwrap();
    assert!(said.out.contains(&"approved the policy for zeta in acme".to_string()), "{:?}", said.out);
    assert_eq!(world.calls(), [format!("touch id: [DEV, not protected] approve policies zeta {} in workspace acme", hash("zeta"))]);
    // With none changed, every one is named.
    policies::approve_with(&f.here, &name("acme"), None, &way(&world, &copies, Some(Means::TouchId)), &typing("not the passphrase")).unwrap();
    assert_eq!(world.calls(), [format!("touch id: [DEV, not protected] approve policies github {github}, linear {linear}, slack {slack} and 3 more in workspace acme")]);
}
