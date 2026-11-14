//! `halti open`, which keeps a workspace open in its terminal, and `halti close`, which closes it
//! from another.
//!
//! `open` refuses a workspace another terminal keeps open before it asks anything: that one holds
//! its lock (`boxes::Kept`). Otherwise it takes the lock, asks as `[workspace.approval] open` says,
//! and hands `main` the workspace to choose as the place and what keeps it open, which then stays
//! (`boxes::keep::serve`) until it is closed.
//!
//! Every other command finds an open workspace by its lock, and reaches it only through its socket
//! (`crate::keep`), with names: it asks nothing, chooses no place and reads nothing sealed. The lock
//! is a hint, since a program running as you can hold it, so a word is never the last say: `close`
//! is told the workspace closed, and still waits until the lock is free before it says so.

use anyhow::{Result, bail};
use halti_core::directory::DirRecord;
use halti_core::ids::{WsId, WsName};
use halti_core::refusal::Refusal;
use halti_core::store::{FileKey, Files};
use halti_core::verbs::resolve_name;

use super::boxes::{self, Kept};
use super::tty::TtyPassphrase;
use super::{Here, Reading, Way, memory, open_with, saved, saved_means};
use crate::approval::{Action, Real};
use crate::config;
use crate::keep::{self, Reply, Request};
use crate::source::Source;

/// What `halti open` hands `main`: the workspace, opened, to choose as the place, and what keeps it
/// open.
pub struct Opened {
    pub source: Box<Source>,
    pub keep: Box<boxes::Keep>,
}

/// `halti open [NAME] [--type]`: refused before anything is asked if another terminal keeps it open;
/// otherwise asked as `[workspace.approval] open` says, and kept open by `main`.
pub fn open(typed: Option<&str>, type_it: bool) -> Result<Opened> {
    let settings = config::settings();
    memory::harden();
    let here = Here::at(&settings.workspaces.path);
    let name = resolve_name(&here.files, typed)?;
    let id = record_id(&here, &name)?;
    let kept = Kept::of(&here, id)?;
    let open_already = || anyhow::anyhow!("{name} is open already, in another terminal. close it with: halti close {name}");
    if kept.held() {
        return Err(open_already());
    }
    let Some(lock) = kept.take()? else { return Err(open_already()) };
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsOpen, type_it), detail: None };
    let (reader, said) = open_with(&here, &name, &way, &|| TtyPassphrase::new(false))?;
    // Its boxes, and its lock, were found by the id the record named.
    if reader.id() != id {
        bail!("workspace {name} changed while it was opened: try again");
    }
    said.print();
    // The keys are wiped once it closes; this process lives as long as it is open.
    memory::release();
    let keep = boxes::keep(&here, &name, id, kept, lock, &settings)?;
    let source = Source::workspace(name, reader, Reading::at(&here.root), settings);
    Ok(Opened { source: Box::new(source), keep: Box::new(keep) })
}

/// The id the directory record of `name` names: a record that can't be read is refused as core
/// refuses it.
fn record_id(here: &Here, name: &WsName) -> Result<WsId> {
    let bytes = here.files.read(&FileKey::DirRecord(name.clone()))?.ok_or_else(|| Refusal::Unknown(name.clone()))?;
    Ok(DirRecord::from_bytes(&bytes)?.id)
}

/// `halti close [NAME]`: asks nothing. An open workspace is asked to close, and once its lock is
/// free, the boxes of it that other terminals run are stopped too. One that isn't open has what a
/// `halti open` or a run left put away, and those boxes stopped.
pub fn close(typed: Option<&str>) -> Result<()> {
    let settings = config::settings();
    let here = Here::at(&settings.workspaces.path);
    let name = resolve_name(&here.files, typed)?;
    let kept = Kept::of(&here, record_id(&here, &name)?)?;
    if !kept.held() {
        let left = kept.left(&settings)?;
        let (others, held) = kept.others(&settings);
        let mut said = format!("{name} isn't open");
        if !left.is_empty() {
            said += &format!(". put away what its last open left: {}", left.join(", "));
        }
        if !others.is_empty() {
            said += &format!(". stopped {} that another terminal ran: {}", count(others.len()), others.join(", "));
        }
        println!("{said}");
        return still_running(&name, &held);
    }
    match keep::ask(&kept.socket(), &Request::Close(name.clone()), keep::CLOSE_WAIT) {
        Some(Reply::Closed(stopped)) => {
            if !kept.let_go() {
                bail!("{name} is still open. close it in its own terminal with Ctrl-C");
            }
            let (others, held) = kept.others(&settings);
            let stopped = stopped as usize + others.len();
            match stopped {
                0 => println!("closed {name}"),
                _ => println!("closed {name} and stopped {}", count(stopped)),
            }
            still_running(&name, &held)
        }
        Some(Reply::Other) => bail!("{name}'s record names another workspace, which is open. nothing was done"),
        _ => bail!("{name} is being opened or closed: try again in a moment"),
    }
}

/// `1 box`, `2 boxes`.
fn count(boxes: usize) -> String {
    if boxes == 1 { "1 box".to_string() } else { format!("{boxes} boxes") }
}

/// Fails if another terminal's box of `name` held on once it was stopped.
fn still_running(name: &WsName, held: &[String]) -> Result<()> {
    match held.first() {
        Some(first) => bail!("box {name}/{first} still runs in another terminal. stop it with: halti ws stop {name}/{first}"),
        None => Ok(()),
    }
}

/// Whether workspace `name`, whose id is `id`, is open: its lock is held, and it answers at its
/// socket within a second. A lock alone is no proof.
pub(super) fn answers(here: &Here, name: &WsName, id: WsId) -> bool {
    let Ok(kept) = Kept::of(here, id) else { return false };
    kept.held() && matches!(keep::ask(&kept.socket(), &Request::Ping(name.clone()), keep::PING_WAIT), Some(Reply::Open(_)))
}
