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
//! is told the workspace closed, and still waits until the lock is free before it says so, and
//! `ws stop` waits for the box's lock the same way.
//!
//! `ws run` of an open workspace's box asks it to start the box (`start`), and holds the connection
//! while the agent works in it (`Session`): the box stops when its last session ends. A session
//! whose connection ends without the word that the box was put away has lost the open workspace,
//! killed with the door of its box: it stops the box itself.

use std::io::{ErrorKind, Read};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
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
use crate::keep::{self, No, Reply, Request};
use crate::source::Source;

/// How often a session looks whether its client has left.
const WATCH_EVERY: Duration = Duration::from_millis(100);

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
    let Some(keep) = boxes::keep(&here, &name, id, kept, &settings)? else { return Err(open_already()) };
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsOpen, type_it), detail: None };
    let (reader, said) = open_with(&here, &name, &way, &|| TtyPassphrase::new(false))?;
    // Its boxes, and its lock, were found by the id the record named.
    if reader.id() != id {
        bail!("workspace {name} changed while it was opened: try again");
    }
    said.print();
    // The keys are wiped once it closes; this process lives as long as it is open.
    memory::release();
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
            // A box another terminal still runs holds the workspace's keys: then it isn't closed.
            let (others, held) = kept.others(&settings);
            still_running(&name, &held)?;
            let stopped = stopped as usize + others.len();
            match stopped {
                0 => println!("closed {name}"),
                _ => println!("closed {name} and stopped {}", count(stopped)),
            }
            Ok(())
        }
        Some(Reply::Other) => Err(other(&name)),
        _ => Err(opening(&name)),
    }
}

/// The record of `name` led to an open workspace of another name.
fn other(name: &WsName) -> anyhow::Error {
    anyhow!("{name}'s record names another workspace, which is open. nothing was done")
}

/// The lock of `name` is held, and nothing answered in time: it is being opened, or closing.
fn opening(name: &WsName) -> anyhow::Error {
    anyhow!("{name} is being opened or closed: try again in a moment")
}

fn box_busy(shown: &str) -> anyhow::Error {
    anyhow!("box {shown} is being opened or closed: try again in a moment")
}

/// What an open workspace answered to a start.
pub(super) enum Started {
    /// The box runs for this session: the connection, held.
    Session(UnixStream),
    /// Another halti runs the box: join it there.
    Elsewhere,
}

/// Asks the open workspace `name`, which `kept` found, to start its box `box_name`, or join it if it
/// runs. Asks nothing here. A refusal is said in halti's words, the word's kind alone: the reason in
/// full is in the terminal where it is open.
pub(super) fn start(kept: &Kept, name: &WsName, box_name: &str) -> Result<Started> {
    let shown = format!("{name}/{box_name}");
    match keep::ask_held(&kept.socket(), &Request::Start(name.clone(), box_name.to_string()), keep::START_WAIT) {
        Some((Reply::Started | Reply::Running, stream)) => Ok(Started::Session(stream)),
        Some((Reply::Elsewhere, _)) => Ok(Started::Elsewhere),
        Some((Reply::Busy, _)) => Err(box_busy(&shown)),
        Some((Reply::Full, _)) => bail!("{name} has too many sessions: end one first"),
        Some((Reply::No(no), _)) => Err(not_started(name, &shown, &no)),
        Some((Reply::Other, _)) => Err(other(name)),
        _ => Err(opening(name)),
    }
}

/// A start refused for this kind of reason, as `ws run` says it.
fn not_started(name: &WsName, shown: &str, no: &No) -> anyhow::Error {
    let says = format!("the terminal where {name} is open says why");
    let why = match no {
        No::Box => format!("there is no box {shown}. make one with: halti ws box new {shown}"),
        No::Unapproved => format!("its policy isn't approved. approve it with: halti ws box approve {shown}"),
        No::Changed => format!("its policy changed since it was approved. approve it with: halti ws box approve {shown}"),
        No::Store => format!("it has no store. make one with: halti ws box new {shown}"),
        No::Key => format!("it has a store but no key. remove it with: halti ws box rm {shown}"),
        No::Site(site) => format!("{site} isn't ready in {name}. {says}"),
        No::Engine => format!("the box engine isn't ready. {says}"),
        No::Failed => return anyhow!("box {shown} was not started. {says}"),
    };
    anyhow!("box {shown} was not started: {why}")
}

/// What an open workspace answered to a stop.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Stopped {
    /// It said it put the box away: its lock is still to be waited for.
    Said,
    /// It doesn't run the box.
    Idle,
}

/// Asks the open workspace `name`, which `kept` found, to stop its box `box_name`. Asks nothing.
pub(super) fn stop(kept: &Kept, name: &WsName, box_name: &str) -> Result<Stopped> {
    match keep::ask(&kept.socket(), &Request::Stop(name.clone(), box_name.to_string()), keep::STOP_WAIT) {
        Some(Reply::Stopped) => Ok(Stopped::Said),
        Some(Reply::Idle) => Ok(Stopped::Idle),
        Some(Reply::Busy) => Err(box_busy(&format!("{name}/{box_name}"))),
        Some(Reply::Other) => Err(other(name)),
        _ => Err(opening(name)),
    }
}

/// A session of a box an open workspace runs: the connection its start holds open while the agent
/// works in the box. A thread watches it. The word that the box was put away ends the watch; the
/// connection ending without it means the open workspace is gone, and its box with no door: the
/// thread then puts the box away (`lost`), which stops its VM and so ends the agent's command.
pub struct Session {
    stream: UnixStream,
    left: Arc<AtomicBool>,
    watch: Option<JoinHandle<bool>>,
    name: WsName,
    shown: String,
}

impl Session {
    /// Holds `stream`, the session of box `shown` of `name`, and watches it.
    pub(super) fn hold(stream: UnixStream, name: &WsName, shown: &str, lost: Box<dyn FnOnce() + Send>) -> Result<Session> {
        let watched = stream.try_clone()?;
        let left = Arc::new(AtomicBool::new(false));
        let leaving = left.clone();
        let watch = thread::spawn(move || {
            let gone = watch(watched, &leaving);
            if gone {
                lost();
            }
            gone
        });
        Ok(Session { stream, left, watch: Some(watch), name: name.clone(), shown: shown.to_string() })
    }

    /// Ends the session once the agent's command ended with `result`: the box stops if this was its
    /// last. If the open workspace was gone, the box was put away here, and that is what is said.
    pub fn end(mut self, result: Result<u8>) -> Result<u8> {
        self.left.store(true, Ordering::SeqCst);
        let _ = self.stream.shutdown(Shutdown::Both);
        let lost = self.watch.take().is_some_and(|watch| watch.join().unwrap_or(false));
        if lost {
            bail!("{} is no longer open, so box {} was stopped", self.name, self.shown);
        }
        result
    }
}

impl Drop for Session {
    /// The watch holds a copy of the connection: a session dropped unended still leaves.
    fn drop(&mut self) {
        self.left.store(true, Ordering::SeqCst);
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// Reads what the open workspace says on a session until the client leaves (`left`), or the word
/// that the box was put away: false. True if the connection ended without it.
fn watch(mut stream: UnixStream, left: &AtomicBool) -> bool {
    let _ = stream.set_read_timeout(Some(WATCH_EVERY));
    let (mut line, mut byte) = (Vec::new(), [0u8; 1]);
    loop {
        if left.load(Ordering::SeqCst) {
            return false;
        }
        match stream.read(&mut byte) {
            Ok(0) => return !left.load(Ordering::SeqCst),
            Ok(_) if byte[0] == b'\n' => {
                if std::str::from_utf8(&line).ok().and_then(Reply::parse) == Some(Reply::Stopped) {
                    return false;
                }
                line.clear();
            }
            Ok(_) => {
                if line.len() < keep::LINE_MAX {
                    line.push(byte[0]);
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
            Err(_) => return !left.load(Ordering::SeqCst),
        }
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

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::time::Instant;

    use super::*;

    fn acme() -> WsName {
        WsName::parse("acme").unwrap()
    }

    /// A session of acme/dev on one end of a pair, and whether it put its box away.
    fn held() -> (Session, UnixStream, Arc<AtomicBool>) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let noted = stopped.clone();
        let session = Session::hold(ours, &acme(), "acme/dev", Box::new(move || noted.store(true, Ordering::SeqCst))).unwrap();
        (session, theirs, stopped)
    }

    fn until(done: &AtomicBool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        done.load(Ordering::SeqCst)
    }

    #[test]
    fn a_session_that_loses_its_open_workspace_stops_its_box() {
        let (session, mut theirs, stopped) = held();
        // A line that isn't the word, then the end, as from a workspace that was killed.
        theirs.write_all(b"halti-keep/1 open 1\nnot a line\n").unwrap();
        drop(theirs);
        assert!(until(&stopped), "the box is put away while the agent still works");
        let said = session.end(Ok(0)).unwrap_err();
        assert_eq!(said.to_string(), "acme is no longer open, so box acme/dev was stopped");
    }

    #[test]
    fn a_box_put_away_by_its_open_workspace_is_not_lost() {
        let (session, mut theirs, stopped) = held();
        theirs.write_all(b"halti-keep/1 stopped\n").unwrap();
        drop(theirs);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(session.end(Ok(7)).unwrap(), 7);
        assert!(!stopped.load(Ordering::SeqCst));
    }

    #[test]
    fn a_session_its_agent_ended_leaves_the_open_workspace() {
        let (session, mut theirs, stopped) = held();
        assert_eq!(session.end(Ok(3)).unwrap(), 3);
        // The open workspace sees the session leave.
        let _ = theirs.set_read_timeout(Some(Duration::from_secs(5)));
        assert_eq!(theirs.read(&mut [0u8; 8]).unwrap(), 0);
        assert!(!stopped.load(Ordering::SeqCst));
        // One dropped unended leaves too.
        let (session, mut theirs, stopped) = held();
        drop(session);
        let _ = theirs.set_read_timeout(Some(Duration::from_secs(5)));
        assert_eq!(theirs.read(&mut [0u8; 8]).unwrap(), 0);
        thread::sleep(Duration::from_millis(300));
        assert!(!stopped.load(Ordering::SeqCst));
    }

    #[test]
    fn a_refused_start_says_its_kind_in_halti_s_words() {
        let said = |no: No| not_started(&acme(), "acme/dev", &no).to_string();
        let not = "box acme/dev was not started";
        let says = "the terminal where acme is open says why";
        assert_eq!(said(No::Box), format!("{not}: there is no box acme/dev. make one with: halti ws box new acme/dev"));
        assert_eq!(said(No::Unapproved), format!("{not}: its policy isn't approved. approve it with: halti ws box approve acme/dev"));
        assert_eq!(said(No::Changed), format!("{not}: its policy changed since it was approved. approve it with: halti ws box approve acme/dev"));
        assert_eq!(said(No::Store), format!("{not}: it has no store. make one with: halti ws box new acme/dev"));
        assert_eq!(said(No::Key), format!("{not}: it has a store but no key. remove it with: halti ws box rm acme/dev"));
        assert_eq!(said(No::Site("github".into())), format!("{not}: github isn't ready in acme. {says}"));
        assert_eq!(said(No::Engine), format!("{not}: the box engine isn't ready. {says}"));
        assert_eq!(said(No::Failed), format!("{not}. {says}"));
    }
}
