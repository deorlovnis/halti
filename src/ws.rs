//! Workspaces on this machine: where their files are, how a passphrase and a secret's value are
//! read, and what `ws new`, `ws ls`, `ws set`, `ws rm`, `ws delete`, `open` and `close` print. What
//! a workspace is, every check on it, and how its secrets are sealed are core's
//! (`halti_core::verbs`); nothing here decides whether one opens, and no key of a workspace's
//! reaches this side.
//!
//! The settings in effect (`config`) say where the workspaces folder is, whose passphrase a new
//! workspace gets unless `ws new` says, whether a password manager keeps it (`saved`), and what
//! approves opening one or listing its secrets, storing a secret, removing secrets, and deleting
//! one: the passphrase typed, which core asks for, or, where a manager keeps it, the means their
//! line names before halti takes it from there. With `--type` it is typed whatever they say. Each
//! command asks for one approval; a saved copy that can't be used is typed instead, once. A
//! workspace opens with what it was made with, which its own records hold.
//!
//! A secret's value is read only after the approval and the checks (`tty::read_value`), once, and
//! is never printed. Only `open` saves a typed passphrase again.
//!
//! Workspaces can't stay open yet: `open` checks the passphrase and the files and wipes the keys as
//! it ends, and `close` has nothing to do and says so.

mod files;
mod memory;
mod saved;
mod tty;

use std::cell::Cell;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use halti_core::anchor::Anchor;
use halti_core::directory::DirRecord;
use halti_core::holder::{KeyHolder, KeyKind};
use halti_core::ids::{WsId, WsName};
use halti_core::item::{ItemKey, Secret};
use halti_core::manifest::Manifest;
use halti_core::platform::{Build, Os, Role};
use halti_core::refusal::Refusal;
use halti_core::store::{FileKey, Files};
use halti_core::verbs::{
    Deleted, Draws, Fresh, Host, Machine, Nonces, Put, State, Stored, Which, Workspace, resolve_name, ws_delete, ws_items, ws_list, ws_new, ws_open, ws_remove, ws_set,
};
use zeroize::Zeroizing;

use crate::approval::{Action, Declined, Means, Real, World};
use crate::config::{self, Manager, PassphraseMode, Settings};
use crate::names;
use files::{DirFiles, FileAnchor, FileKeystore};
use saved::{Copies, KeychainPassphrase};
use tty::TtyPassphrase;

/// How this binary was built, as core is told it: core never works it out for itself.
const BUILD: Build = if cfg!(halti_dev) { Build::Dev } else { Build::Release };

/// The system halti runs on: it is built for macOS and Linux only.
pub const OS: Os = if cfg!(target_os = "macos") { Os::Macos } else { Os::Linux };

/// This machine's adapters but the key holder, which each command picks. Making them touches no file.
struct Here {
    files: DirFiles,
    anchor: FileAnchor,
    keystore: FileKeystore,
}

impl Here {
    /// Over the workspaces folder `root`, with stored secrets in halti's files.
    fn at(root: &Path) -> Here {
        Here { files: DirFiles::at(root), anchor: FileAnchor::at(root), keystore: FileKeystore::at(root) }
    }

    fn machine<'a>(&'a self, holder: &'a dyn KeyHolder) -> Machine<'a> {
        Machine { host: Host { files: &self.files, holder, anchor: &self.anchor }, keystore: &self.keystore, build: BUILD, os: OS }
    }

    /// The id the directory record of `name` names, if it reads: for finding its saved passphrase.
    /// Core reads the record again, and the copy it is handed is the one of the id core read.
    fn id_of(&self, name: &WsName) -> Option<WsId> {
        let bytes = self.files.read(&FileKey::DirRecord(name.clone())).ok()??;
        DirRecord::from_bytes(&bytes).ok().map(|record| record.id)
    }
}

/// What a command says once it is done: lines for stdout, and notes for stderr.
#[derive(Default, PartialEq, Eq, Debug)]
struct Said {
    out: Vec<String>,
    notes: Vec<String>,
}

impl Said {
    fn print(&self) {
        for line in &self.out {
            println!("{line}");
        }
        for note in &self.notes {
            eprintln!("halti: {note}");
        }
    }
}

/// How a command on one workspace has its passphrase: from the saved copy through the approval
/// engine (`World`) after `means`, or typed when there is no means.
struct Way<'a> {
    world: &'a dyn World,
    copies: &'a dyn Copies,
    means: Option<Means>,
}

/// The means that releases the saved passphrase for `action`, or none if it is typed: with `--type`,
/// with no password manager, or where the action's line says passphrase.
fn saved_means(settings: &Settings, action: Action, type_it: bool) -> Option<Means> {
    if type_it || settings.manager == Manager::None {
        return None;
    }
    settings.means(action).filter(|means| *means != Means::Passphrase)
}

/// What is said before the question when the saved copy couldn't give the passphrase.
fn type_it_once(name: &WsName) -> String {
    format!("the saved passphrase of {name} can't be read. type it once.")
}

/// Whether a workspace was made with its passphrase saved, as its manifest records.
fn made_saved(manifest: &Manifest) -> bool {
    manifest.adapters.iter().any(|recorded| recorded.role == Role::KeyHolder && recorded.adapter == saved::LABEL.adapter)
}

/// `N` bytes from the system's random source, wiped when dropped.
fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0; N]);
    File::open("/dev/urandom").and_then(|mut source| source.read_exact(bytes.as_mut_slice())).context("reading /dev/urandom")?;
    Ok(bytes)
}

/// A key kind as listings show it: the name its records are written with.
fn key_name(kind: KeyKind) -> &'static str {
    match kind {
        KeyKind::Passphrase => "passphrase",
        KeyKind::Soft => "soft",
        _ => "other",
    }
}

/// `halti ws new NAME`: creates a workspace with one passphrase: the person's own, or one made here
/// and shown once, as `choice` says, else as the settings do. With no terminal to ask in, nothing
/// is made. The terminal asks for the passphrase, and once core has created the workspace stdout
/// says so and how to open it. Where a password manager keeps passphrases, it is saved there then.
/// Its id is in `ws ls`.
pub fn new(name: &str, choice: Option<PassphraseMode>) -> Result<()> {
    let name = WsName::parse(name)?;
    tty::ready()?;
    let settings = config::settings();
    memory::harden();
    let holder = TtyPassphrase::new(choice.unwrap_or(settings.passphrase) == PassphraseMode::Generate);
    let holder = match settings.manager {
        Manager::None => holder,
        Manager::Keychain => holder.saving(),
    };
    new_with(&Here::at(&settings.workspaces.path), &name, &holder, &saved::Keychain)?.print();
    Ok(())
}

/// Makes `name` with `holder`, then saves the passphrase it kept, if it keeps one, in `copies`. A
/// copy that can't be saved leaves the workspace as it is, typed until the next open saves it.
fn new_with(here: &Here, name: &WsName, holder: &TtyPassphrase, copies: &dyn Copies) -> Result<Said> {
    let fresh = Fresh { id: *random::<16>()?, key: Draws { inner: random::<32>()?, wrap: random::<64>()? }, manifest: *random::<12>()? };
    let drawn = WsId::from_bytes(fresh.id);
    let id = ws_new(&here.machine(holder), name, fresh).map_err(|error| not_made(here, name, drawn, error))?;
    let mut said = Said { out: vec![format!("created workspace {name}")], notes: Vec::new() };
    if let Some(passphrase) = holder.take() {
        match copies.add(id, &passphrase) {
            Ok(()) => said.out.push("its passphrase is saved in the keychain".to_string()),
            Err(_) => said.notes.push(format!("the passphrase of {name} was not saved in the keychain. it is typed the next time {name} is opened")),
        }
    }
    said.out.push(format!("open it with: halti open {name}"));
    if cfg!(halti_dev) {
        said.out.push("debug build: this workspace opens only with a debug build".to_string());
    }
    Ok(said)
}
/// What a `ws new` that failed leaves and says. The lock file of the id it drew goes if nothing of
/// that id is left (`forget_drawn_lock`). A name taken by a workspace with no pin, which a create
/// cut short leaves, says how to remove it.
fn not_made(here: &Here, name: &WsName, drawn: WsId, error: anyhow::Error) -> anyhow::Error {
    let _ = forget_drawn_lock(here, drawn);
    if !matches!(error.downcast_ref::<Refusal>(), Some(Refusal::Taken(_))) {
        return error;
    }
    let unfinished = ws_list(&here.files, &here.anchor).is_ok_and(|listed| listed.iter().any(|entry| entry.name == *name && entry.record.is_some() && !entry.pinned));
    if !unfinished {
        return error;
    }
    error.context(format!("{name} was never fully created. remove it with: halti ws delete {name}"))
}

/// Removes the lock file of the id a failed `ws new` drew, if no record names that id and none of
/// its files or its pin is there: then nothing else can know the id, so nothing will lock it again.
/// Every other lock file stays, as `DirFiles::lock` leaves it. Core leaves this to the binary,
/// since its `Files` has no way to remove a lock.
fn forget_drawn_lock(here: &Here, drawn: WsId) -> Result<()> {
    // A record that can't be read could be the one naming it.
    let named = ws_list(&here.files, &here.anchor)?.iter().any(|entry| entry.record.is_none_or(|record| record.id == drawn));
    if named || here.anchor.read(drawn)?.is_some() {
        return Ok(());
    }
    for file in [FileKey::KeyRef(drawn), FileKey::Wrap(drawn), FileKey::Manifest(drawn)] {
        if here.files.read(&file)?.is_some() {
            return Ok(());
        }
    }
    here.files.forget_lock(drawn)
}

/// `halti open [NAME] [--type]`: checks the passphrase and the files. Workspaces can't stay open
/// yet: the keys are wiped before anything is printed.
pub fn open(typed: Option<&str>, type_it: bool) -> Result<()> {
    let settings = config::settings();
    memory::harden();
    let here = Here::at(&settings.workspaces.path);
    let name = resolve_name(&here.files, typed)?;
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsOpen, type_it) };
    open_with(&here, &name, &way, &|| TtyPassphrase::new(false))?.print();
    Ok(())
}

/// Runs `verb` on `name` with the key holder `way` says, approved as `action` asks. With no means,
/// the passphrase is typed (`typing`). Through the saved copy: if there is one, the approval, then
/// the copy. Declined, nothing more happens, and the error is `declined`. A copy that can't be used,
/// or a workspace made to be typed, goes on to typing, after a line that says so; with no copy, the
/// usual question is asked. Any other failure is said as it is. So the passphrase is asked for at
/// most once, and `verb` runs at most twice, the second time only if the first failed before core
/// went past its checks.
///
/// The holder that typed it after a means was tried comes back with what `verb` gave, for `open`.
fn approved<T>(
    here: &Here,
    name: &WsName,
    way: &Way<'_>,
    action: Action,
    declined: &str,
    typing: &dyn Fn() -> TtyPassphrase,
    verb: &dyn Fn(&Machine<'_>) -> Result<T>,
) -> Result<(T, Option<TtyPassphrase>)> {
    let Some(means) = way.means else {
        return Ok((verb(&here.machine(&typing()))?, None));
    };
    let found = here.id_of(name).is_some_and(|id| way.copies.exists(id));
    if found {
        let holder = KeychainPassphrase::new(way.copies, way.world, means, action);
        match verb(&here.machine(&holder)) {
            Ok(done) => return Ok((done, None)),
            Err(error) if error.is::<Declined>() => bail!("{declined}"),
            Err(error) if !saved::falls_to_typing(&error) => return Err(error),
            Err(_) => {}
        }
    }
    let holder = if found { typing().telling(type_it_once(name)) } else { typing() };
    let done = verb(&here.machine(&holder))?;
    Ok((done, Some(holder)))
}

/// What a declined approval says: what didn't happen, and the command that types the passphrase
/// instead.
fn declined(what: &str, command: &str) -> String {
    format!("{what}. to type the passphrase instead: halti {command} --type")
}

/// Opens `name` the way `way` says (`approved`), with `typing` making the holder that has it typed.
/// Typed after a means was tried, a workspace made with a saved copy has it saved again, and one
/// made to be typed loses any copy found for it.
fn open_with(here: &Here, name: &WsName, way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase) -> Result<Said> {
    let closed = format!("workspaces can't stay open yet, so {name} was closed again");
    // Kept only where it may be saved again.
    let keeping = || typing().keeping();
    let typing: &dyn Fn() -> TtyPassphrase = if way.means.is_some() { &keeping } else { typing };
    let declined = declined(&format!("{name} was not opened"), &format!("open {name}"));
    let open = |machine: &Machine<'_>| ws_open(machine, name);
    let (Workspace { id, keys, manifest }, typed) = approved(here, name, way, Action::WsOpen, &declined, typing, &open)?;
    drop(keys);
    let mut said = Said { out: vec!["passphrase correct".to_string()], notes: Vec::new() };
    let Some(holder) = typed else {
        said.out.push(closed);
        return Ok(said);
    };
    if made_saved(&manifest) {
        if let Some(passphrase) = holder.take() {
            match way.copies.add(id, &passphrase) {
                Ok(()) => said.out.push(format!("saved the passphrase of {name} in the keychain again")),
                Err(_) => said.notes.push(format!("the passphrase of {name} was not saved in the keychain. it is typed the next time {name} is opened")),
            }
        }
    } else {
        if way.copies.exists(id) {
            way.copies.remove(id);
        }
        said.out.push(format!("{name} was made without a saved passphrase, so it is typed each time"));
    }
    said.out.push(closed);
    Ok(said)
}

/// `halti close [NAME]`: workspaces can't stay open yet, so there is nothing to close. It says so,
/// and asks nothing.
pub fn close(typed: Option<&str>) -> Result<()> {
    let name = resolve_name(&DirFiles::at(&config::settings().workspaces.path), typed)?;
    println!("{name} isn't open");
    Ok(())
}

/// `halti ws ls [WS] [--type]`: with a name, the secrets of that workspace, approved as opening it
/// is (`items_with`). Without one, every workspace, from the directory records and the pins, which
/// reads no secret and asks nothing.
pub fn ls(typed: Option<&str>, type_it: bool) -> Result<()> {
    let settings = config::settings();
    if let Some(typed) = typed {
        let name = WsName::parse(typed)?;
        memory::harden();
        let here = Here::at(&settings.workspaces.path);
        let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsOpen, type_it) };
        items_with(&here, &name, &way, &|| TtyPassphrase::new(false))?.print();
        return Ok(());
    }
    let here = Here::at(&settings.workspaces.path);
    let listed = ws_list(&here.files, &here.anchor)?;
    if listed.is_empty() {
        println!("no workspaces yet. create one with: halti ws new NAME");
    } else {
        println!("{:<16} {:<10} {:<10} ID", "WORKSPACE", "STATE", "KEY");
    }
    for entry in &listed {
        let name = entry.name.as_str();
        match entry.record {
            Some(record) => println!("{name:<16} {:<10} {:<10} {}", if entry.pinned { "closed" } else { "unfinished" }, key_name(record.key), record.id),
            None => println!("{name:<16} {:<10} {:<10} -", "unreadable", "-"),
        }
    }
    for entry in listed.iter().filter(|entry| entry.record.is_some() && !entry.pinned) {
        println!("{0} was never fully created. remove it with: halti ws delete {0}", entry.name);
    }
    Ok(())
}

/// Why halti won't use `root` as the workspaces folder, if it won't: one halti didn't make, which it
/// never changes or fills (see `files::root_problem`).
pub fn folder_problem(root: &Path) -> Option<&'static str> {
    files::root_problem(root)
}

/// The names of the workspaces in the folder `root`, for saying which a new folder leaves behind.
pub fn names_in(root: &Path) -> Vec<String> {
    let here = Here::at(root);
    ws_list(&here.files, &here.anchor).map(|listed| listed.iter().map(|entry| entry.name.to_string()).collect()).unwrap_or_default()
}

/// `halti ws delete NAME [--type]`: one approval, then the workspace's items, pin, key and files,
/// its record, and its saved passphrase. One with no pin (never fully created, a delete cut short,
/// or its pin removed) goes with no approval: its record and its files go, its key file among them
/// (the passphrase key is nowhere else), and any stored items are left, which with the key gone
/// nothing can open.
pub fn delete(name: &str, type_it: bool) -> Result<()> {
    let name = WsName::parse(name)?;
    let settings = config::settings();
    memory::harden();
    let here = Here::at(&settings.workspaces.path);
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsDelete, type_it) };
    delete_with(&here, &name, &way, &|| TtyPassphrase::new(false))?.print();
    Ok(())
}

/// Deletes `name` the way `way` says (`approved`), then removes its saved passphrase by the id its
/// record named, whichever way it went.
fn delete_with(here: &Here, name: &WsName, way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase) -> Result<Said> {
    // Core refuses to delete what fails its checks, and removes nothing of it.
    let refused = |error: anyhow::Error| {
        if matches!(error.downcast_ref::<Refusal>(), Some(Refusal::Unreadable | Refusal::Tampered | Refusal::OtherBuild(_))) {
            return error.context("nothing was deleted");
        }
        error
    };
    let id = here.id_of(name);
    let declined = declined(&format!("{name} was not deleted"), &format!("ws delete {name}"));
    let delete = |machine: &Machine<'_>| ws_delete(machine, name);
    let (deleted, _) = approved(here, name, way, Action::WsDelete, &declined, typing, &delete).map_err(refused)?;
    let mut said = Said::default();
    said.out.push(match deleted {
        Deleted::Whole => format!("deleted workspace {name}"),
        Deleted::FilesOnly => format!("removed workspace {name}. it was never fully created, so no passphrase was asked"),
    });
    if let Some(id) = id
        && way.copies.exists(id)
        && !way.copies.remove(id)
    {
        said.notes.push(format!("the saved passphrase of {name} is still in the keychain. remove the item named {}{id} in keychain access", names::WS_KEYCHAIN_PREFIX));
    }
    Ok(said)
}

/// `acme/github`: a workspace's name, then after the first `/` a resource, each as core checks it.
pub fn target(text: &str) -> Result<(WsName, &str)> {
    let Some((name, resource)) = text.split_once('/') else { bail!("use a workspace and a resource, e.g. acme/github") };
    let name = WsName::parse(name)?;
    ItemKey::check_resource(resource)?;
    Ok((name, resource))
}

/// `halti ws set WS/RESOURCE FIELD [--type]`: stores a secret, approved as `[workspace.approval]
/// set` says, then its value: piped in, or typed unseen.
pub fn set(target_text: &str, field: &str, type_it: bool) -> Result<()> {
    let (name, resource) = target(target_text)?;
    let key = ItemKey::parse(resource, field)?;
    let settings = config::settings();
    memory::harden();
    let here = Here::at(&settings.workspaces.path);
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsSet, type_it) };
    set_with(&here, &name, &key, &way, &|| TtyPassphrase::new(false), &|| tty::read_value(&key))?.print();
    Ok(())
}

/// Stores `key` in `name` the way `way` says (`approved`), with the value `value` reads: once, and
/// only once the approval is given and the workspace has passed its checks.
fn set_with(here: &Here, name: &WsName, key: &ItemKey, way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase, value: &dyn Fn() -> Result<Secret>) -> Result<Said> {
    let read = Cell::new(false);
    let once = || {
        if read.replace(true) {
            bail!("the value was read already, so nothing was stored");
        }
        value()
    };
    let store = |machine: &Machine<'_>| {
        let nonces = Nonces { value: *random::<12>()?, manifest: *random::<12>()? };
        ws_set(machine, name, key, once, nonces)
    };
    let declined = declined(&format!("{key} was not stored"), &format!("ws set {name}/{} {}", key.resource(), key.field()));
    let (put, _) = approved(here, name, way, Action::WsSet, &declined, typing, &store)?;
    let done = match put {
        Put::Added => "stored",
        Put::Replaced => "replaced",
    };
    Ok(Said { out: vec![format!("{done} {key} in {name}")], notes: Vec::new() })
}

/// `halti ws rm WS/RESOURCE [FIELD] [--type]`: removes one field, or every field of the resource,
/// approved as `[workspace.approval] rm` says.
pub fn rm(target_text: &str, field: Option<&str>, type_it: bool) -> Result<()> {
    let (name, resource) = target(target_text)?;
    let which = match field {
        Some(field) => Which::Field(ItemKey::parse(resource, field)?),
        None => Which::Resource(resource.to_string()),
    };
    let settings = config::settings();
    memory::harden();
    let here = Here::at(&settings.workspaces.path);
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsRm, type_it) };
    rm_with(&here, &name, &which, &way, &|| TtyPassphrase::new(false))?.print();
    Ok(())
}

/// Removes what `which` names from `name` the way `way` says (`approved`).
fn rm_with(here: &Here, name: &WsName, which: &Which, way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase) -> Result<Said> {
    let (what, command) = match which {
        Which::Field(key) => (key.to_string(), format!("ws rm {name}/{} {}", key.resource(), key.field())),
        Which::Resource(resource) => (resource.clone(), format!("ws rm {name}/{resource}")),
    };
    let remove = |machine: &Machine<'_>| ws_remove(machine, name, which, *random::<12>()?);
    approved(here, name, way, Action::WsRm, &declined(&format!("{what} was not removed"), &command), typing, &remove)?;
    Ok(Said { out: vec![format!("removed {what} from {name}")], notes: Vec::new() })
}

/// The secrets of `name`, approved as opening it is: what a listing gets from core.
fn items_with(here: &Here, name: &WsName, way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase) -> Result<Said> {
    let declined = declined(&format!("the secrets of {name} were not listed"), &format!("ws ls {name}"));
    let list = |machine: &Machine<'_>| ws_items(machine, name);
    let (stored, _) = approved(here, name, way, Action::WsOpen, &declined, typing, &list)?;
    Ok(listing(name, &stored))
}

/// A workspace's secrets as `ws ls WS` prints them: one line per resource with its fields, in the
/// order of their text, then a line for each that can't be read, saying how to set it again.
fn listing(name: &WsName, stored: &[Stored]) -> Said {
    if stored.is_empty() {
        return Said { out: vec![format!("{name} has no secrets yet. add one with: halti ws set {name}/RESOURCE FIELD")], notes: Vec::new() };
    }
    // Sorted by text, so a resource's fields are next to each other.
    let mut rows: Vec<(&str, Vec<&str>)> = Vec::new();
    for item in stored {
        match rows.last_mut() {
            Some((resource, fields)) if *resource == item.key.resource() => fields.push(item.key.field()),
            _ => rows.push((item.key.resource(), vec![item.key.field()])),
        }
    }
    let mut out = vec![format!("{:<16} FIELDS", "RESOURCE")];
    out.extend(rows.iter().map(|(resource, fields)| format!("{resource:<16} {}", fields.join(", "))));
    for item in stored.iter().filter(|item| item.state == State::Unreadable) {
        out.push(format!("{} can't be read. set it again with: halti ws set {name}/{} {}", item.key, item.key.resource(), item.key.field()));
    }
    Said { out, notes: Vec::new() }
}

#[cfg(all(test, halti_dev))]
mod saved_tests;

#[cfg(test)]
mod tests {
    use halti_core::passphrase;
    use halti_core::platform::{Adapter, Grade, Lacks, Property, admit};

    use super::*;

    /// They are the four a release build runs workspaces on, on either system, and a release
    /// manifest records each as core's known answers do.
    #[test]
    fn the_adapters_are_the_ones_a_release_build_admits_on_either_system() {
        let labels = [passphrase::LABEL, files::ANCHOR, files::FILES, files::KEYSTORE];
        for os in [Os::Macos, Os::Linux] {
            assert_eq!(admit(&labels, Build::Release, os), Ok(()), "{os:?}");
        }
        let recorded: Vec<(&str, Grade, u32)> = labels.iter().map(|label| (label.adapter, label.grade, label.lacks.bits())).collect();
        let expected = [("passphrase-key", Grade::Weaker, 0x07), ("file-anchor", Grade::Weaker, 0x60), ("dir-files", Grade::Weaker, 0x60), ("file-keystore", Grade::Weaker, 0x20)];
        assert_eq!(recorded, expected);
        // And they are what this machine uses, in the order of their roles, whichever passphrase a new one gets.
        let here = Here::at(Path::new("ws"));
        for generate in [false, true] {
            let used = [TtyPassphrase::new(generate).label(), here.anchor.label(), here.files.label(), here.keystore.label()];
            assert_eq!(used.map(|label| label.adapter), ["passphrase-key", "file-anchor", "dir-files", "file-keystore"], "{generate}");
            assert_eq!(TtyPassphrase::new(generate).saving().label().adapter, "keychain-passphrase-key", "{generate}");
        }
    }

    /// A passphrase with a copy in the keychain lacks what a typed one does, and that others can
    /// touch it: so a workspace made to be typed never opens from a copy. Only a Mac's release build
    /// runs it.
    #[test]
    fn a_saved_copy_lacks_more_than_a_typed_passphrase_and_runs_only_on_a_mac() {
        let label = saved::LABEL;
        assert_eq!((label.adapter, label.grade, label.lacks.bits()), ("keychain-passphrase-key", Grade::Weaker, 0x27));
        assert_eq!(label.lacks.beyond(passphrase::LABEL.lacks), Lacks::of(&[Property::OthersCantTouch]));
        assert!(passphrase::LABEL.lacks.within(label.lacks), "a workspace made with a copy still opens by typing");
        let all = [label, files::ANCHOR, files::FILES, files::KEYSTORE];
        assert_eq!(admit(&all, Build::Release, Os::Macos), Ok(()));
        assert!(admit(&all, Build::Release, Os::Linux).is_err());
    }

    #[test]
    fn a_target_is_a_workspace_then_a_resource() {
        let (name, resource) = target("acme/github").unwrap();
        assert_eq!((name.as_str(), resource), ("acme", "github"));
        assert_eq!(target("9lives/github-ee").unwrap().1, "github-ee");
        for refused in ["acme", "acme/", "/github", "Acme/github", "acme/github/token", "acme/Git", "acme/-x", "", "acme\x1b[2J/github"] {
            assert!(target(refused).is_err(), "{refused:?}");
        }
        // Nothing of what was typed is said back.
        assert!(!format!("{:#}", target("acme\x1b[2J/github").unwrap_err()).contains('\x1b'));
    }

    #[test]
    fn a_listing_groups_fields_by_resource_and_names_what_cant_be_read() {
        let name = WsName::parse("acme").unwrap();
        let stored = |text: &str, state: State| {
            let (resource, field) = text.split_once('/').unwrap();
            Stored { key: ItemKey::parse(resource, field).unwrap(), state }
        };
        let listed = [
            stored("github-ee/token", State::Readable),
            stored("github/token", State::Readable),
            stored("github/user", State::Unreadable),
            stored("linear/token", State::Unreadable),
        ];
        let said = listing(&name, &listed);
        assert_eq!(
            said.out,
            [
                "RESOURCE         FIELDS",
                "github-ee        token",
                "github           token, user",
                "linear           token",
                "github/user can't be read. set it again with: halti ws set acme/github user",
                "linear/token can't be read. set it again with: halti ws set acme/linear token",
            ]
        );
        assert!(said.notes.is_empty());
        assert_eq!(listing(&name, &[]).out, ["acme has no secrets yet. add one with: halti ws set acme/RESOURCE FIELD"]);
    }

    #[test]
    fn the_saved_copy_is_used_only_with_a_manager_and_a_line_that_is_not_the_passphrase() {
        let settings = |text: &str| config::parse(text, Os::Macos).unwrap();
        let managed = settings("[passwords]\nmanager = \"keychain\"\n\n[workspace.approval]\nopen = \"touchid\"\nset = \"sudo\"\ndelete = \"none\"\n");
        assert_eq!(saved_means(&managed, Action::WsOpen, false), Some(Means::TouchId));
        assert_eq!(saved_means(&managed, Action::WsDelete, false), Some(Means::None));
        assert_eq!(saved_means(&managed, Action::WsSet, false), Some(Means::Sudo));
        // A line left out types it.
        assert_eq!(saved_means(&managed, Action::WsRm, false), None);
        assert_eq!(saved_means(&managed, Action::WsSet, true), None);
        // `--type` types it, whatever the settings say.
        assert_eq!((saved_means(&managed, Action::WsOpen, true), saved_means(&managed, Action::WsDelete, true)), (None, None));
        // A line that says passphrase types it, and so does the template, with or without a manager.
        let typed = settings("[passwords]\nmanager = \"keychain\"\n\n[workspace.approval]\nopen = \"passphrase\"\n");
        assert_eq!((saved_means(&typed, Action::WsOpen, false), saved_means(&typed, Action::WsDelete, false)), (None, None));
        for os in [Os::Macos, Os::Linux] {
            assert_eq!(saved_means(&Settings::builtin(os), Action::WsOpen, false), None, "{os:?}");
        }
    }
}
