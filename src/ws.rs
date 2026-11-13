//! Workspaces on this machine: where their files are, how a passphrase is read, and what `ws new`,
//! `ws ls`, `ws delete`, `open` and `close` print. What a workspace is, and every check on it, is
//! core's (`halti_core::verbs`); nothing here decides whether one opens.
//!
//! The settings in effect (`config`) say where the workspaces folder is, whose passphrase a new
//! workspace gets unless `ws new` says, and what approves opening and deleting one: today a
//! workspace's own passphrase, which core asks for. A workspace opens with what it was made with,
//! which its own records hold.
//!
//! Workspaces can't stay open yet: `open` checks the passphrase and the files and wipes the keys as
//! it ends, and `close` has nothing to do and says so.

mod files;
mod memory;
mod tty;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use halti_core::anchor::Anchor;
use halti_core::holder::KeyKind;
use halti_core::ids::{WsId, WsName};
use halti_core::platform::{Build, Os};
use halti_core::refusal::Refusal;
use halti_core::store::{FileKey, Files};
use halti_core::verbs::{Deleted, Draws, Fresh, Host, Machine, Workspace, resolve_name, ws_delete, ws_list, ws_new, ws_open};
use zeroize::Zeroizing;

use crate::approval::{self, Action};
use crate::config::{self, PassphraseMode};
use files::{DirFiles, FileAnchor, FileKeystore};
use tty::TtyPassphrase;

/// How this binary was built, as core is told it: core never works it out for itself.
const BUILD: Build = if cfg!(halti_dev) { Build::Dev } else { Build::Release };

/// The system halti runs on: it is built for macOS and Linux only.
pub const OS: Os = if cfg!(target_os = "macos") { Os::Macos } else { Os::Linux };

/// This machine's adapters. Making them touches no file.
struct Here {
    files: DirFiles,
    anchor: FileAnchor,
    keystore: FileKeystore,
    holder: TtyPassphrase,
}

impl Here {
    /// Over the workspaces folder `root`: a passphrase typed at each open, and stored secrets in
    /// halti's files. `generate`: `ws new` makes the passphrase and shows it once, instead of asking
    /// for one of the person's own.
    fn new(root: &Path, generate: bool) -> Here {
        Here { files: DirFiles::at(root), anchor: FileAnchor::at(root), keystore: FileKeystore::at(root), holder: TtyPassphrase::new(generate) }
    }

    fn machine(&self) -> Machine<'_> {
        Machine { host: Host { files: &self.files, holder: &self.holder, anchor: &self.anchor }, keystore: &self.keystore, build: BUILD, os: OS }
    }
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
/// says so and how to open it. Its id is in `ws ls`.
pub fn new(name: &str, choice: Option<PassphraseMode>) -> Result<()> {
    let name = WsName::parse(name)?;
    tty::ready()?;
    let settings = config::settings();
    memory::harden();
    let generate = choice.unwrap_or(settings.passphrase) == PassphraseMode::Generate;
    let here = Here::new(&settings.workspaces.path, generate);
    let fresh = Fresh { id: *random::<16>()?, key: Draws { inner: random::<32>()?, wrap: random::<64>()? }, manifest: *random::<12>()? };
    let drawn = WsId::from_bytes(fresh.id);
    ws_new(&here.machine(), &name, fresh).map_err(|error| not_made(&here, &name, drawn, error))?;
    println!("created workspace {name}");
    println!("open it with: halti open {name}");
    if cfg!(halti_dev) {
        println!("debug build: this workspace opens only with a debug build");
    }
    Ok(())
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

/// `halti open [NAME]`: checks the passphrase and the files. Workspaces can't stay open yet: the
/// keys are wiped before anything is printed.
pub fn open(typed: Option<&str>) -> Result<()> {
    let settings = config::settings();
    memory::harden();
    let here = Here::new(&settings.workspaces.path, false);
    let name = resolve_name(&here.files, typed)?;
    approval::approve(&settings, Action::WsOpen, &format!("open workspace {name}"))?;
    let Workspace { keys, .. } = ws_open(&here.machine(), &name)?;
    drop(keys);
    println!("passphrase correct");
    println!("workspaces can't stay open yet, so {name} was closed again");
    Ok(())
}

/// `halti close [NAME]`: workspaces can't stay open yet, so there is nothing to close. It says so,
/// and asks nothing.
pub fn close(typed: Option<&str>) -> Result<()> {
    let name = resolve_name(&DirFiles::at(&config::settings().workspaces.path), typed)?;
    println!("{name} isn't open");
    Ok(())
}

/// `halti ws ls`: every workspace, from the directory records and the pins. Reads no secret and
/// asks nothing.
pub fn ls() -> Result<()> {
    let here = Here::new(&config::settings().workspaces.path, false);
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
    let here = Here::new(root, false);
    ws_list(&here.files, &here.anchor).map(|listed| listed.iter().map(|entry| entry.name.to_string()).collect()).unwrap_or_default()
}

/// `halti ws delete NAME`: one passphrase, then the workspace's items, pin, key and files, and its
/// record. One with no pin (never fully created, a delete cut short, or its pin removed) goes with no
/// passphrase: its record and its files go, its key file among them (the passphrase key is nowhere
/// else), and any stored items are left, which with the key gone nothing can open.
pub fn delete(name: &str) -> Result<()> {
    let name = WsName::parse(name)?;
    let settings = config::settings();
    memory::harden();
    let here = Here::new(&settings.workspaces.path, false);
    approval::approve(&settings, Action::WsDelete, &format!("delete workspace {name}"))?;
    let deleted = ws_delete(&here.machine(), &name).map_err(|error| {
        // Core refuses to delete what fails its checks, and removes nothing of it.
        if matches!(error.downcast_ref::<Refusal>(), Some(Refusal::Unreadable | Refusal::Tampered | Refusal::OtherBuild(_))) {
            return error.context("nothing was deleted");
        }
        error
    })?;
    match deleted {
        Deleted::Whole => println!("deleted workspace {name}"),
        Deleted::FilesOnly => println!("removed workspace {name}. it was never fully created, so no passphrase was asked"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use halti_core::passphrase;
    use halti_core::platform::{Adapter, Grade, admit};

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
        for generate in [false, true] {
            let here = Here::new(Path::new("ws"), generate);
            let used = [here.holder.label(), here.anchor.label(), here.files.label(), here.keystore.label()];
            assert_eq!(used.map(|label| label.adapter), ["passphrase-key", "file-anchor", "dir-files", "file-keystore"], "{generate}");
        }
    }
}
