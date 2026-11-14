//! The socket of an open workspace, and what crosses it.
//!
//! `halti open acme` stays, and while it does, acme is open: that process holds its keys and runs
//! its boxes. It listens on one socket, `TAG.keep.sock` in the private folder of the workspaces'
//! box sockets, mode 0600, and each end checks that the other runs as the same user. A command
//! reaches it with one line, and gets one line back:
//!
//! ```text
//! request = "halti-keep/1 " VERB " " WS [" " BOX] "\n"      start WS BOX, stop WS BOX, close WS, ping WS
//! reply   = "halti-keep/1 " WORD [" " ARG] "\n"
//! ```
//!
//! Every line is printable ASCII, at most 128 bytes with its newline, and names only: a workspace,
//! a box, a site, a count. No passphrase, key, value, policy, path or command crosses, either way.
//! A request names its workspace, and the open workspace acts only on its own name. A start that is
//! refused answers its kind (`No`); the reason in full is printed where the workspace is open, since
//! it is built from many layers and may name a path. A line that is longer, slower than five
//! seconds or not plain is dropped with no answer.
//!
//! What a word says is never taken on trust where it matters: a client that is told a workspace was
//! closed or a box stopped waits until its lock is free (see `ws::keep`).

use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use halti_core::boxkey::check_box;
use halti_core::ids::WsName;
use halti_core::item::ItemKey;

/// The first word of every line.
const VERSION: &str = "halti-keep/1";
/// The longest line, its newline included.
pub const LINE_MAX: usize = 128;
/// How long the open workspace waits for a request's line.
pub const LINE_WAIT: Duration = Duration::from_secs(5);
/// How long a client waits to be let in.
const CONNECT_WAIT: Duration = Duration::from_secs(2);
/// How long a client waits for the answer to a `ping`, and to a `close`, which comes once every box
/// is put away.
pub const PING_WAIT: Duration = Duration::from_secs(1);
pub const CLOSE_WAIT: Duration = Duration::from_secs(300);

/// The kind of a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum No {
    /// There is no such box.
    Box,
    /// Its policy isn't approved.
    Unapproved,
    /// Its policy changed since it was approved.
    Changed,
    /// It keeps a store, and has none.
    Store,
    /// It has a store, and no key.
    Key,
    /// A site it uses isn't ready: the site's name.
    Site(String),
    /// The box engine isn't there, or isn't running.
    Engine,
    /// Anything else.
    Failed,
}

impl No {
    /// The words after `no` on the socket.
    fn word(&self) -> String {
        match self {
            No::Box => "box".into(),
            No::Unapproved => "unapproved".into(),
            No::Changed => "changed".into(),
            No::Store => "store".into(),
            No::Key => "key".into(),
            No::Site(site) => format!("site {site}"),
            No::Engine => "engine".into(),
            No::Failed => "failed".into(),
        }
    }

    fn parse(words: &[&str]) -> Option<No> {
        Some(match words {
            ["box"] => No::Box,
            ["unapproved"] => No::Unapproved,
            ["changed"] => No::Changed,
            ["store"] => No::Store,
            ["key"] => No::Key,
            ["site", site] => {
                ItemKey::check_resource(site).ok()?;
                No::Site(site.to_string())
            }
            ["engine"] => No::Engine,
            ["failed"] => No::Failed,
            _ => return None,
        })
    }
}

/// A start that was refused: its kind, and the reason as halti says it.
pub struct Refused {
    pub no: No,
    pub why: anyhow::Error,
}

impl Refused {
    pub fn new(no: No, why: anyhow::Error) -> Self {
        Refused { no, why }
    }
}

/// A failure of no kind of its own.
impl From<anyhow::Error> for Refused {
    fn from(why: anyhow::Error) -> Self {
        Refused { no: No::Failed, why }
    }
}

impl std::fmt::Debug for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {:#}", self.no, self.why)
    }
}

/// What a command asks of an open workspace, by its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Start the box, or join it if it runs: the connection, held, is a session of it.
    Start(WsName, String),
    /// Stop the box.
    Stop(WsName, String),
    /// Put every box away and close the workspace.
    Close(WsName),
    /// Say how many boxes run.
    Ping(WsName),
}

impl Request {
    /// The workspace it names.
    pub fn ws(&self) -> &WsName {
        match self {
            Request::Start(ws, _) | Request::Stop(ws, _) | Request::Close(ws) | Request::Ping(ws) => ws,
        }
    }

    pub fn line(&self) -> String {
        match self {
            Request::Start(ws, name) => format!("{VERSION} start {ws} {name}\n"),
            Request::Stop(ws, name) => format!("{VERSION} stop {ws} {name}\n"),
            Request::Close(ws) => format!("{VERSION} close {ws}\n"),
            Request::Ping(ws) => format!("{VERSION} ping {ws}\n"),
        }
    }

    /// A line without its newline. None for another version, verb or shape, or a name that isn't
    /// one: a box's name is checked before anything else.
    pub fn parse(line: &str) -> Option<Request> {
        let words: Vec<&str> = line.strip_prefix(VERSION)?.strip_prefix(' ')?.split(' ').collect();
        match words[..] {
            [verb @ ("start" | "stop"), ws, name] => {
                check_box(name).ok()?;
                let ws = WsName::parse(ws).ok()?;
                Some(if verb == "start" { Request::Start(ws, name.to_string()) } else { Request::Stop(ws, name.to_string()) })
            }
            ["close", ws] => Some(Request::Close(WsName::parse(ws).ok()?)),
            ["ping", ws] => Some(Request::Ping(WsName::parse(ws).ok()?)),
            _ => None,
        }
    }
}

/// What an open workspace answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// The box was started for this session.
    Started,
    /// The box ran already: this is one more session of it.
    Running,
    /// Another halti runs the box: join it there.
    Elsewhere,
    /// The box is starting or stopping, or the workspace is closing.
    Busy,
    /// As many sessions are held as one open workspace takes.
    Full,
    /// The box was not started, for this kind of reason.
    No(No),
    /// The box was put away.
    Stopped,
    /// The box doesn't run.
    Idle,
    /// The workspace is closed, and this many boxes were stopped.
    Closed(u32),
    /// The workspace is open, and this many of its boxes run.
    Open(u32),
    /// The request named another workspace: nothing was done.
    Other,
    /// Another version, verb or shape.
    Unsupported,
}

impl Reply {
    /// The line, its newline included. One that would be too long (a site's long name) says
    /// `no failed` instead.
    pub fn line(&self) -> String {
        let words = match self {
            Reply::Started => "started".to_string(),
            Reply::Running => "running".to_string(),
            Reply::Elsewhere => "elsewhere".to_string(),
            Reply::Busy => "busy".to_string(),
            Reply::Full => "full".to_string(),
            Reply::No(no) => format!("no {}", no.word()),
            Reply::Stopped => "stopped".to_string(),
            Reply::Idle => "idle".to_string(),
            Reply::Closed(n) => format!("closed {n}"),
            Reply::Open(n) => format!("open {n}"),
            Reply::Other => "other".to_string(),
            Reply::Unsupported => "unsupported".to_string(),
        };
        let line = format!("{VERSION} {words}\n");
        if line.len() > LINE_MAX { Reply::No(No::Failed).line() } else { line }
    }

    /// A line without its newline. None for anything that isn't one of the words, with a name
    /// that is one and a count that is a number.
    pub fn parse(line: &str) -> Option<Reply> {
        let words: Vec<&str> = line.strip_prefix(VERSION)?.strip_prefix(' ')?.split(' ').collect();
        let count = |text: &str| text.parse::<u32>().ok().filter(|_| text.len() <= 9 && text.bytes().all(|b| b.is_ascii_digit()));
        Some(match words[..] {
            ["started"] => Reply::Started,
            ["running"] => Reply::Running,
            ["elsewhere"] => Reply::Elsewhere,
            ["busy"] => Reply::Busy,
            ["full"] => Reply::Full,
            ["no", ref rest @ ..] => Reply::No(No::parse(rest)?),
            ["stopped"] => Reply::Stopped,
            ["idle"] => Reply::Idle,
            ["closed", n] => Reply::Closed(count(n)?),
            ["open", n] => Reply::Open(count(n)?),
            ["other"] => Reply::Other,
            ["unsupported"] => Reply::Unsupported,
            _ => return None,
        })
    }
}

/// Reads one line of printable ASCII, at most `LINE_MAX` bytes with its newline, within `wait`,
/// and nothing after it. None for a longer, slower or other line, or a connection that ends first.
pub fn read_line(stream: &mut UnixStream, wait: Duration) -> Option<String> {
    let deadline = Instant::now() + wait;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let left = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero())?;
        // A socket whose peer has closed it refuses the option on a Mac, and has nothing to wait for.
        let _ = stream.set_read_timeout(Some(left));
        match stream.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) if byte[0] == b'\n' => return String::from_utf8(line).ok(),
            Ok(_) if (0x20..0x7f).contains(&byte[0]) && line.len() < LINE_MAX - 1 => line.push(byte[0]),
            Ok(_) => return None,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
}

/// Writes a line, failing rather than waiting long for a peer that reads nothing.
pub fn write_line(stream: &mut UnixStream, line: &str) -> io::Result<()> {
    let _ = stream.set_write_timeout(Some(CONNECT_WAIT));
    stream.write_all(line.as_bytes())
}

/// This process's user.
fn own_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// The user of the process at the other end of a local socket.
#[cfg(not(target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let (mut uid, mut gid) = (0, 0);
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let got = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut length) };
    if got != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Whether a peer may talk to us: one whose user could be read, and is ours.
fn peer_allowed(peer: io::Result<u32>, own: u32) -> bool {
    peer.is_ok_and(|uid| uid == own)
}

/// Whether the other end of `stream` runs as this user.
pub fn peer_is_own(stream: &UnixStream) -> bool {
    peer_allowed(peer_uid(stream), own_uid())
}

/// Listens at `path`, readable and writable by this user alone. A socket left there by a process
/// that is gone is removed first; one that something answers at is left as it is, and None comes
/// back: two workspaces can share a socket's name, and each holds its own lock.
///
/// The socket is made beside it, made private, then put in its place, so it is never at `path` with
/// a wider mode, and the process's umask, which every thread shares, is left alone.
pub fn bind(path: &Path) -> Result<Option<UnixListener>> {
    if fs::symlink_metadata(path).is_ok() {
        if UnixStream::connect(path).is_ok() {
            return Ok(None);
        }
        fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    }
    let mut beside = path.as_os_str().to_owned();
    beside.push(".new");
    let beside = PathBuf::from(beside);
    let _ = fs::remove_file(&beside);
    let listener = UnixListener::bind(&beside).with_context(|| format!("listening at {}", beside.display()))?;
    let placed = fs::set_permissions(&beside, fs::Permissions::from_mode(0o600)).and_then(|()| fs::rename(&beside, path));
    if let Err(e) = placed {
        let _ = fs::remove_file(&beside);
        return Err(e).with_context(|| format!("securing {}", path.display()));
    }
    Ok(Some(listener))
}

/// Connects to `path` within a moment, to a process of this user. None if nothing lets us in.
pub fn connect(path: &Path) -> Option<UnixStream> {
    let (sent, got) = mpsc::channel();
    let path = path.to_path_buf();
    // A connect that waits on a full queue is left to end by itself.
    thread::spawn(move || {
        let _ = sent.send(UnixStream::connect(path));
    });
    let stream = got.recv_timeout(CONNECT_WAIT).ok()?.ok()?;
    peer_is_own(&stream).then_some(stream)
}

/// Sends `request` to the open workspace at `path`, and reads the line that answers it within
/// `wait`. None if nothing answered in time, or not with one of the words.
pub fn ask(path: &Path, request: &Request, wait: Duration) -> Option<Reply> {
    let mut stream = connect(path)?;
    write_line(&mut stream, &request.line()).ok()?;
    Reply::parse(&read_line(&mut stream, wait)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    fn acme() -> WsName {
        WsName::parse("acme").unwrap()
    }

    #[test]
    fn a_request_reads_only_as_what_was_written() {
        let longest = WsName::parse(&"w".repeat(32)).unwrap();
        for request in
            [Request::Start(acme(), "dev".into()), Request::Stop(acme(), "dev".into()), Request::Close(acme()), Request::Ping(acme()), Request::Start(longest, "b".repeat(32))]
        {
            let line = request.line();
            assert_eq!(Request::parse(line.strip_suffix('\n').unwrap()), Some(request), "{line}");
        }
        for reply in [
            Reply::Started,
            Reply::Running,
            Reply::Elsewhere,
            Reply::Busy,
            Reply::Full,
            Reply::No(No::Box),
            Reply::No(No::Unapproved),
            Reply::No(No::Changed),
            Reply::No(No::Store),
            Reply::No(No::Key),
            Reply::No(No::Site("github-ee".into())),
            Reply::No(No::Engine),
            Reply::No(No::Failed),
            Reply::Stopped,
            Reply::Idle,
            Reply::Closed(2),
            Reply::Open(0),
            Reply::Other,
            Reply::Unsupported,
        ] {
            let line = reply.line();
            assert_eq!(Reply::parse(line.strip_suffix('\n').unwrap()), Some(reply), "{line}");
        }
        assert_eq!(Request::Ping(acme()).line(), "halti-keep/1 ping acme\n");
        assert_eq!(Reply::No(No::Site("github".into())).line(), "halti-keep/1 no site github\n");
        // Anything else is nothing: a reply's site and count are checked before they are shown.
        for line in ["halti-keep/1 no site Git\x1b", "halti-keep/1 no site ../x", "halti-keep/1 closed -1", "halti-keep/1 open 1e3", "halti-keep/1 started ", "halti-keep/1 maybe"]
        {
            assert_eq!(Reply::parse(line), None, "{line}");
        }
    }

    #[test]
    fn another_version_is_unsupported() {
        for line in ["halti-keep/2 ping acme", "halti-keep/1 reread acme", "halti-keep/1  ping acme", "ping acme", "halti-keep/1 ping acme extra", "halti-keep/1 start acme"] {
            assert_eq!(Request::parse(line), None, "{line}");
        }
        assert_eq!(Reply::Unsupported.line(), "halti-keep/1 unsupported\n");
    }

    #[test]
    fn a_box_name_is_checked_before_anything_else() {
        for name in ["../x", "Dev", "-x", "dev.keep", &"b".repeat(33), ""] {
            assert_eq!(Request::parse(&format!("halti-keep/1 start acme {name}")), None, "{name}");
            assert_eq!(Request::parse(&format!("halti-keep/1 stop acme {name}")), None, "{name}");
        }
    }

    #[test]
    fn a_request_names_its_workspace() {
        let request = Request::parse("halti-keep/1 start globex dev").unwrap();
        assert_eq!(request.ws().as_str(), "globex");
        assert_eq!(request, Request::Start(WsName::parse("globex").unwrap(), "dev".into()));
        for ws in ["Acme", "acme/dev", &"w".repeat(33)] {
            assert_eq!(Request::parse(&format!("halti-keep/1 close {ws}")), None, "{ws}");
        }
    }

    #[test]
    fn the_longest_request_fits() {
        let longest = Request::Start(WsName::parse(&"w".repeat(32)).unwrap(), "b".repeat(32)).line();
        assert_eq!(longest.len(), 85);
        // A site's name long enough to pass the limit is said as a failure.
        assert_eq!(Reply::No(No::Site("s".repeat(120))).line(), "halti-keep/1 no failed\n");
    }

    fn pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    #[test]
    fn a_line_over_128_bytes_is_dropped() {
        let (mut ours, mut theirs) = pair();
        let fits = format!("{}\n", "x".repeat(LINE_MAX - 1));
        theirs.write_all(fits.as_bytes()).unwrap();
        assert_eq!(read_line(&mut ours, LINE_WAIT).map(|line| line.len()), Some(LINE_MAX - 1));
        theirs.write_all(format!("{}\n", "x".repeat(LINE_MAX)).as_bytes()).unwrap();
        assert_eq!(read_line(&mut ours, LINE_WAIT), None);
        // Nor anything but printable ASCII.
        let (mut ours, mut theirs) = pair();
        theirs.write_all("halti-keep/1 ping acmé\n".as_bytes()).unwrap();
        assert_eq!(read_line(&mut ours, LINE_WAIT), None);
    }

    #[test]
    fn a_slow_line_is_dropped() {
        let (mut ours, mut theirs) = pair();
        theirs.write_all(b"halti-keep/1 ping").unwrap();
        let started = Instant::now();
        assert_eq!(read_line(&mut ours, Duration::from_millis(300)), None);
        assert!(started.elapsed() < Duration::from_secs(2));
        // A connection that ends before its newline says nothing either.
        drop(theirs);
        assert_eq!(read_line(&mut ours, LINE_WAIT), None);
    }

    #[test]
    fn a_peer_of_another_user_is_refused() {
        assert!(peer_allowed(Ok(501), 501));
        assert!(!peer_allowed(Ok(0), 501) && !peer_allowed(Ok(502), 501));
        assert!(!peer_allowed(Err(io::Error::other("no peer")), 501));
        // Both ends of a pair this process made are its own.
        let (ours, _theirs) = pair();
        assert!(peer_is_own(&ours));
    }

    #[test]
    fn the_socket_is_private() {
        let dir = TempDir::new("halti-keep-mode").unwrap();
        let path = dir.0.join("t.keep.sock");
        let _listener = bind(&path).unwrap().unwrap();
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!((meta.mode() & 0o777, fs::metadata(&dir.0).unwrap().mode() & 0o777), (0o600, 0o700));
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1, "nothing is left beside it");
    }

    #[test]
    fn a_socket_that_answers_is_not_removed() {
        let dir = TempDir::new("halti-keep-bind").unwrap();
        let path = dir.0.join("t.keep.sock");
        let first = bind(&path).unwrap().unwrap();
        assert!(bind(&path).unwrap().is_none(), "something answers there");
        assert!(path.exists());
        // One that nobody answers at is a leftover, and goes.
        drop(first);
        assert!(path.exists());
        assert!(bind(&path).unwrap().is_some());
    }

    #[test]
    fn a_read_that_gets_no_answer_ends_in_time() {
        let dir = TempDir::new("halti-keep-ask").unwrap();
        let path = dir.0.join("t.keep.sock");
        // Nothing listens: no answer, at once.
        assert_eq!(ask(&path, &Request::Ping(acme()), PING_WAIT), None);
        // Something listens and never answers: no answer, once the wait is over.
        let _listener = bind(&path).unwrap().unwrap();
        let started = Instant::now();
        assert_eq!(ask(&path, &Request::Ping(acme()), Duration::from_millis(300)), None);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn an_answer_is_read_as_its_word() {
        let dir = TempDir::new("halti-keep-answer").unwrap();
        let path = dir.0.join("t.keep.sock");
        let listener = bind(&path).unwrap().unwrap();
        let answering = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let line = read_line(&mut stream, LINE_WAIT).unwrap();
            write_line(&mut stream, &Reply::Open(1).line()).unwrap();
            line
        });
        assert_eq!(ask(&path, &Request::Ping(acme()), PING_WAIT), Some(Reply::Open(1)));
        assert_eq!(answering.join().unwrap(), "halti-keep/1 ping acme");
    }
}
