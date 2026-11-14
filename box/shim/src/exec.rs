//! The exec service: the host runs a command in the box through it, as the agent or as root, on a
//! terminal or on pipes, as `container exec` does in a box that Apple's tool runs. `serve --vsock`
//! listens for it on `names::EXEC_PORT`, for the host only.
//!
//! The wire is frames: a kind byte, the payload's length (u32, big-endian) and the payload. No
//! frame is longer than `MAX_FRAME`, and the length is checked before anything is allocated. The
//! host sends one `REQUEST` first (`Request`), then any number of `INPUT` and `RESIZE`. The shim
//! answers with `OUTPUT` and `ERROR`, and ends with one `EXIT` or one `FAILED`.
//!
//! The command's environment travels in the request, so none of it is on a command line in the
//! box, where any process could read it.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use crate::Conn;

/// The longest payload of any frame.
pub const MAX_FRAME: usize = 64 * 1024;

/// Host to box, first and once: what to run (`Request`).
pub const REQUEST: u8 = b'R';
/// Host to box: bytes for the command's input. Empty: the input has ended (on pipes; a terminal
/// has no end of input but a hang-up).
pub const INPUT: u8 = b'I';
/// Host to box: the terminal's new size, rows and columns, each a u16.
pub const RESIZE: u8 = b'W';
/// Box to host: the terminal's output, or the command's standard output.
pub const OUTPUT: u8 = b'O';
/// Box to host: the command's standard error, on pipes.
pub const ERROR: u8 = b'E';
/// Box to host, last: the command's raw wait status, an i32.
pub const EXIT: u8 = b'X';
/// Box to host, last: why the command did not start, as text.
pub const FAILED: u8 = b'F';

/// The request's first byte.
const VERSION: u8 = 1;
/// After the command ends, how long its output may take to arrive before `EXIT` is sent anyway: a
/// process it left behind can hold its output open for ever.
const DRAIN: Duration = Duration::from_secs(2);
/// How often the end of the command is looked for.
const POLL: Duration = Duration::from_millis(10);

/// A terminal's size.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
}

/// What to run. On the wire: the version, the user (0 the agent, 1 root), a terminal or not (1 or
/// 0), its rows and columns (u16 each), the number of arguments (u16) and each argument, the
/// number of variables (u16) and each name and value. A string is its length (u32) and its bytes.
#[derive(Debug, PartialEq)]
pub struct Request {
    pub root: bool,
    /// A terminal of this size; `None` for pipes.
    pub tty: Option<Size>,
    pub argv: Vec<Vec<u8>>,
    pub env: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Request {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut r = Cursor(bytes);
        if r.u8()? != VERSION {
            return Err("unknown request version");
        }
        let root = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err("unknown user"),
        };
        let tty = r.u8()?;
        let size = Size { rows: r.u16()?, cols: r.u16()? };
        let tty = match tty {
            0 => None,
            1 => Some(size),
            _ => return Err("unknown terminal flag"),
        };
        let argv = (0..r.u16()?).map(|_| r.string()).collect::<Result<Vec<_>, _>>()?;
        if argv.is_empty() {
            return Err("no command");
        }
        let env = (0..r.u16()?).map(|_| Ok((r.string()?, r.string()?))).collect::<Result<Vec<_>, &'static str>>()?;
        if !r.0.is_empty() {
            return Err("bytes after the request");
        }
        if argv.iter().chain(env.iter().flat_map(|(k, v)| [k, v])).any(|s| s.contains(&0)) {
            return Err("a NUL byte in the request");
        }
        if env.iter().any(|(k, _)| k.is_empty() || k.contains(&b'=')) {
            return Err("a bad variable name");
        }
        Ok(Self { root, tty, argv, env })
    }

    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        let size = self.tty.unwrap_or(Size { rows: 0, cols: 0 });
        let mut out = vec![VERSION, self.root as u8, self.tty.is_some() as u8];
        out.extend(size.rows.to_be_bytes());
        out.extend(size.cols.to_be_bytes());
        let string = |out: &mut Vec<u8>, s: &[u8]| {
            out.extend((s.len() as u32).to_be_bytes());
            out.extend(s);
        };
        out.extend((self.argv.len() as u16).to_be_bytes());
        for arg in &self.argv {
            string(&mut out, arg);
        }
        out.extend((self.env.len() as u16).to_be_bytes());
        for (key, value) in &self.env {
            string(&mut out, key);
            string(&mut out, value);
        }
        out
    }
}

/// Reads a request's fields, never past its end.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        if n > self.0.len() {
            return Err("the request is cut short");
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, &'static str> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }
    fn string(&mut self) -> Result<Vec<u8>, &'static str> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().expect("four bytes"));
        Ok(self.take(len as usize)?.to_vec())
    }
}

/// The next frame, or `None` if the stream ended before one began.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut kind = [0u8];
    loop {
        match r.read(&mut kind) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("a frame of {len} bytes, over the limit of {MAX_FRAME}")));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some((kind[0], payload)))
}

/// One frame, in one write, so frames from several threads never interleave.
pub fn write_frame(w: &mut impl Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    debug_assert!(payload.len() <= MAX_FRAME);
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(kind);
    frame.extend((payload.len() as u32).to_be_bytes());
    frame.extend(payload);
    w.write_all(&frame)
}

/// Who a command runs as.
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

/// The box's two users, and what every command starts with.
pub struct Users {
    pub agent: User,
    pub root: User,
    /// The folder commands start in.
    pub workdir: String,
}

impl Users {
    /// The agent image's: its user 1000 is the agent (box/agent.Containerfile), whose home is
    /// /home/agent and where `container exec` starts, as root too. The host's `container exec`
    /// passes the same ids.
    pub fn guest() -> Self {
        Self { agent: User { uid: 1000, gid: 1000, home: "/home/agent".into() }, root: User { uid: 0, gid: 0, home: "/root".into() }, workdir: "/home/agent".into() }
    }
}

/// The variables every command gets before the request's own. `container exec` starts from the
/// image's configured environment; a VM booted from the image's files has none, so this stands in
/// for it.
fn base_env(user: &User) -> [(&'static str, String); 2] {
    [("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()), ("HOME", user.home.clone())]
}

/// Serve each connection on a thread of its own.
pub fn accept_loop<S: Conn>(hosts: impl Iterator<Item = io::Result<S>>, users: Arc<Users>) {
    for host in hosts {
        match host {
            Ok(host) => {
                let users = users.clone();
                thread::spawn(move || serve(host, &users));
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// One connection: read the request, run it, and send its output and how it ended.
pub fn serve<S: Conn>(mut host: S, users: &Users) {
    let request = match read_frame(&mut host) {
        Ok(Some((REQUEST, payload))) => Request::decode(&payload).map_err(str::to_string),
        Ok(Some(_)) => Err("the first frame is not a request".to_string()),
        Ok(None) => return,
        Err(e) => Err(format!("reading the request: {e}")),
    };
    let out = match host.dup() {
        Ok(writer) => Arc::new(Out(Mutex::new(Some(writer)))),
        Err(_) => return,
    };
    match request.and_then(|request| run(request, host, &out, users)) {
        Ok(status) => out.last(EXIT, &status.into_raw().to_be_bytes()),
        Err(why) => out.last(FAILED, why.as_bytes()),
    }
}

/// The host's end for writing, shared by the threads that send output. `last` closes it, and later
/// sends are dropped.
struct Out<S>(Mutex<Option<S>>);

impl<S: Conn> Out<S> {
    fn send(&self, kind: u8, payload: &[u8]) {
        if let Some(host) = self.0.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            let _ = write_frame(host, kind, payload);
        }
    }

    /// The last frame. Both halves of the connection are shut, which also ends the thread that
    /// reads the host's input.
    fn last(&self, kind: u8, payload: &[u8]) {
        if let Some(mut host) = self.0.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = write_frame(&mut host, kind, payload);
            let _ = host.shut(Shutdown::Both);
        }
    }
}

/// Start the command, carry its streams, and wait for it. An error is a command that did not
/// start.
fn run<S: Conn>(request: Request, host: S, out: &Arc<Out<S>>, users: &Users) -> Result<ExitStatus, String> {
    let user = if request.root { &users.root } else { &users.agent };
    let program = OsStr::from_bytes(&request.argv[0]);
    let mut cmd = Command::new(program);
    cmd.args(request.argv[1..].iter().map(|a| OsStr::from_bytes(a)))
        .env_clear()
        .envs(base_env(user))
        .envs(request.env.iter().map(|(k, v)| (OsStr::from_bytes(k), OsStr::from_bytes(v))))
        .current_dir(&users.workdir)
        .uid(user.uid)
        .gid(user.gid);
    // SAFETY: `fresh_signals` makes only async-signal-safe calls.
    unsafe { cmd.pre_exec(fresh_signals) };
    let failed = |e: io::Error| format!("running {}: {e}", program.to_string_lossy());

    let (done, finished) = mpsc::channel();
    let pump = |from: File, kind: u8| {
        let (out, done) = (out.clone(), done.clone());
        thread::spawn(move || {
            copy_out(from, kind, &out);
            let _ = done.send(());
        });
    };
    let (child, input, pumps) = match request.tty {
        Some(size) => {
            let (terminal, other_end) = open_terminal(size).map_err(|e| format!("opening a terminal: {e}"))?;
            cmd.stdin(Stdio::from(other_end.try_clone().map_err(failed)?)).stdout(Stdio::from(other_end.try_clone().map_err(failed)?)).stderr(Stdio::from(other_end));
            // SAFETY: `take_terminal` makes only async-signal-safe calls (setsid, ioctl).
            unsafe { cmd.pre_exec(take_terminal) };
            let child = cmd.spawn().map_err(failed)?;
            // The terminal's end held by `cmd` closes with it, so only the command holds it now.
            drop(cmd);
            pump(terminal.try_clone().map_err(failed)?, OUTPUT);
            (child, Input::Terminal(terminal), 1)
        }
        None => {
            let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(failed)?;
            pump(File::from(OwnedFd::from(child.stdout.take().expect("piped"))), OUTPUT);
            pump(File::from(OwnedFd::from(child.stderr.take().expect("piped"))), ERROR);
            let stdin = File::from(OwnedFd::from(child.stdin.take().expect("piped")));
            (child, Input::Pipe(Some(stdin)), 2)
        }
    };
    let child = Arc::new(Mutex::new(child));
    let c = child.clone();
    thread::spawn(move || feed(host, input, &c));

    let status = wait(&child).map_err(failed)?;
    for _ in 0..pumps {
        if finished.recv_timeout(DRAIN).is_err() {
            break;
        }
    }
    Ok(status)
}

/// Wait for the command, reaping it only with the lock held, so a hang-up (`feed`) never signals
/// a process id that was freed and given to another process.
fn wait(child: &Mutex<Child>) -> io::Result<ExitStatus> {
    loop {
        if let Some(status) = child.lock().unwrap_or_else(|e| e.into_inner()).try_wait()? {
            return Ok(status);
        }
        thread::sleep(POLL);
    }
}

/// Copy a stream of the command to the host as frames of `kind`, to its end. Once the host is gone
/// the output is still read, so the command is never stopped by a full pipe.
fn copy_out<S: Conn>(mut from: File, kind: u8, out: &Out<S>) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => out.send(kind, &buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // a terminal whose other end has closed reads as an error on Linux
            Err(_) => return,
        }
    }
}

/// Where the host's input goes.
enum Input {
    /// The command's standard input, until the input ends.
    Pipe(Option<File>),
    /// The terminal's end that halti holds.
    Terminal(File),
}

/// Carry the host's frames to the command until the host hangs up or breaks the protocol. On
/// pipes a hang-up ends the input; on a terminal it is a hang-up of the terminal: the command's
/// session gets SIGHUP, as when a terminal window closes.
fn feed<S: Conn>(mut host: S, mut input: Input, child: &Mutex<Child>) {
    while let Ok(Some((kind, bytes))) = read_frame(&mut host) {
        match (&mut input, kind) {
            (Input::Pipe(stdin), INPUT) => {
                // an input that can't be written (the command closed it) ends here too
                if bytes.is_empty() || stdin.as_mut().is_some_and(|stdin| stdin.write_all(&bytes).is_err()) {
                    *stdin = None;
                }
            }
            (Input::Terminal(terminal), INPUT) => {
                let _ = terminal.write_all(&bytes);
            }
            (Input::Terminal(terminal), RESIZE) if bytes.len() == 4 => {
                let size = Size { rows: u16::from_be_bytes([bytes[0], bytes[1]]), cols: u16::from_be_bytes([bytes[2], bytes[3]]) };
                let _ = resize(terminal, size);
            }
            (Input::Pipe(_), RESIZE) => {}
            _ => break,
        }
    }
    if let Input::Terminal(_) = input {
        let mut child = child.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(None) = child.try_wait() {
            // SAFETY: kill(2) of the command's own session (it is the session's leader, so the
            // group's id is its id); the lock keeps it from being reaped meanwhile.
            unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGHUP) };
        }
    }
}

fn winsize(size: Size) -> libc::winsize {
    libc::winsize { ws_row: size.rows, ws_col: size.cols, ws_xpixel: 0, ws_ypixel: 0 }
}

/// A new terminal of `size`: (halti's end, the command's end), neither inherited by a command.
fn open_terminal(size: Size) -> io::Result<(File, OwnedFd)> {
    let (mut ours, mut theirs) = (-1, -1);
    let mut ws = winsize(size);
    // SAFETY: openpty(3) writes two descriptors, which `OwnedFd` then owns alone; it reads the
    // size, and the name and settings it is given are null.
    if unsafe { libc::openpty(&mut ours, &mut theirs, std::ptr::null_mut(), std::ptr::null_mut(), &raw mut ws) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(ours), OwnedFd::from_raw_fd(theirs)) };
    // Another thread can start a command before these are set: it would hold this terminal open
    // until it ends, which delays a hang-up but gives it nothing to read.
    for fd in [&ours, &theirs] {
        // SAFETY: fcntl(2) setting a flag of a descriptor owned here.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((File::from(ours), theirs))
}

fn resize(terminal: &File, size: Size) -> io::Result<()> {
    let ws = winsize(size);
    // SAFETY: ioctl(2) reading a winsize from a live value.
    if unsafe { libc::ioctl(terminal.as_raw_fd(), libc::TIOCSWINSZ as _, &ws) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// In a new process before it runs its program: no signal blocked, and SIGPIPE back to its
/// default, as a command that `container exec` starts has them. A child keeps both otherwise:
/// the shim ignores SIGPIPE, as every Rust program does, and `boot` blocks the signals it waits
/// for.
pub fn fresh_signals() -> io::Result<()> {
    // SAFETY: sigemptyset on a local set, then sigprocmask(2) and signal(2), which are
    // async-signal-safe.
    unsafe {
        let mut none: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut none);
        if libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut()) == -1 || libc::signal(libc::SIGPIPE, libc::SIG_DFL) == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// In the command's process before it runs: a session of its own, whose terminal is its standard
/// input, so Ctrl-C and a hang-up reach it.
fn take_terminal() -> io::Result<()> {
    // SAFETY: setsid(2) and ioctl(2) with no pointers.
    if unsafe { libc::setsid() } == -1 || unsafe { libc::ioctl(0, libc::TIOCSCTTY as _, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::{env, fs, process};

    fn request(root: bool, tty: Option<Size>, argv: &[&str], env: &[(&str, &str)]) -> Request {
        Request { root, tty, argv: argv.iter().map(|a| a.as_bytes().to_vec()).collect(), env: env.iter().map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec())).collect() }
    }

    /// A test folder with a home for each user; both users are this process's own ids, which a
    /// process that isn't root may still set.
    fn users(name: &str) -> (Users, PathBuf) {
        let dir = env::temp_dir().join(format!("halti-shim-exec-{name}-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // SAFETY: getuid(2) and getgid(2) can't fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let home = |who: &str| dir.join(who).display().to_string();
        let users = Users { agent: User { uid, gid, home: home("agent") }, root: User { uid, gid, home: home("root") }, workdir: dir.display().to_string() };
        (users, dir)
    }

    /// The host's side of one exec: send the request, then `then`, and gather what comes back
    /// until the last frame.
    struct Session {
        host: UnixStream,
        frames: Vec<(u8, Vec<u8>)>,
    }

    impl Session {
        fn start(users: Users, request: &Request) -> Self {
            let (mut host, shim) = UnixStream::pair().unwrap();
            thread::spawn(move || serve(shim, &users));
            write_frame(&mut host, REQUEST, &request.encode()).unwrap();
            Self { host, frames: Vec::new() }
        }

        fn send(&mut self, kind: u8, payload: &[u8]) {
            write_frame(&mut self.host, kind, payload).unwrap();
        }

        /// Read frames until one of `kind` arrives; return everything of `kind` read so far.
        fn until(&mut self, kind: u8, text: &str) -> String {
            loop {
                let sofar = self.text(kind);
                if sofar.contains(text) {
                    return sofar;
                }
                let frame = read_frame(&mut self.host).unwrap().unwrap_or_else(|| panic!("ended before {text:?}; got {:?}", self.frames));
                self.frames.push(frame);
            }
        }

        /// Read to the last frame and return it.
        fn end(&mut self) -> (u8, Vec<u8>) {
            while let Some(frame) = read_frame(&mut self.host).unwrap() {
                self.frames.push(frame);
            }
            self.frames.last().cloned().expect("a last frame")
        }

        fn text(&self, kind: u8) -> String {
            self.frames.iter().filter(|(k, _)| *k == kind).map(|(_, p)| String::from_utf8_lossy(p).into_owned()).collect()
        }

        fn status(&mut self) -> ExitStatus {
            let (kind, payload) = self.end();
            assert_eq!(kind, EXIT, "{}", String::from_utf8_lossy(&payload));
            ExitStatus::from_raw(i32::from_be_bytes(payload.try_into().unwrap()))
        }
    }

    #[test]
    fn exec_runs_as_the_user_asked_and_returns_its_exit_code() {
        for root in [false, true] {
            let (users, dir) = users(if root { "root" } else { "agent" });
            let (want_uid, want_home) = if root { (users.root.uid, users.root.home.clone()) } else { (users.agent.uid, users.agent.home.clone()) };
            let mut s = Session::start(users, &request(root, None, &["sh", "-c", "echo \"$(id -u) $HOME $(pwd)\"; exit 3"], &[]));
            assert_eq!(s.status().code(), Some(3));
            let pwd = fs::canonicalize(&dir).unwrap();
            let line = s.text(OUTPUT);
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_eq!((fields[0], fields[1]), (want_uid.to_string().as_str(), want_home.as_str()));
            assert_eq!(fs::canonicalize(fields[2]).unwrap(), pwd);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn pipes_carry_input_output_and_errors() {
        let (users, dir) = users("pipes");
        let mut s = Session::start(users, &request(false, None, &["sh", "-c", "cat; echo oops >&2"], &[]));
        s.send(INPUT, b"hello ");
        s.send(INPUT, b"box");
        s.send(INPUT, b"");
        assert!(s.status().success());
        assert_eq!((s.text(OUTPUT), s.text(ERROR)), ("hello box".to_string(), "oops\n".to_string()));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_environment_travels_in_the_request_not_on_a_command_line() {
        let (users, dir) = users("env");
        let req = request(false, None, &["sh", "-c", "printf '%s|%s|%s' \"$TOKEN_STANDIN\" \"$HOME\" \"$PATH\"; printf '|%s' \"$@\"", "sh"], &[("TOKEN_STANDIN", "halti-managed")]);
        assert!(req.argv.iter().all(|a| !a.windows(13).any(|w| w == b"halti-managed")));
        let home = users.agent.home.clone();
        let mut s = Session::start(users, &req);
        assert!(s.status().success());
        assert_eq!(s.text(OUTPUT), format!("halti-managed|{home}|{}|", base_env(&Users::guest().agent)[0].1));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_terminal_has_its_size_and_follows_a_resize() {
        let (users, dir) = users("tty");
        let mut s = Session::start(users, &request(false, Some(Size { rows: 30, cols: 100 }), &["sh", "-c", "stty size; [ -t 0 ] && echo terminal; read go; stty size"], &[]));
        s.until(OUTPUT, "terminal");
        assert!(s.text(OUTPUT).contains("30 100"));
        s.send(RESIZE, &[0, 40, 0, 120]);
        s.send(INPUT, b"go\n");
        assert!(s.status().success());
        assert!(s.text(OUTPUT).contains("40 120"), "{:?}", s.text(OUTPUT));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_hang_up_reaches_a_terminal_session() {
        let (users, dir) = users("hangup");
        let mut s = Session::start(users, &request(false, Some(Size { rows: 24, cols: 80 }), &["sh", "-c", "trap 'exit 7' HUP; echo ready; while :; do sleep 0.05; done"], &[]));
        s.until(OUTPUT, "ready");
        s.host.shutdown(Shutdown::Write).unwrap();
        let status = s.status();
        assert!(status.code() == Some(7) || status.signal() == Some(libc::SIGHUP), "{status:?}");
        fs::remove_dir_all(dir).unwrap();
    }

    /// Whatever the shim's thread blocks or ignores, a command starts with no signal blocked and
    /// SIGPIPE at its default (`yes | head` ends `yes`).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_command_starts_with_no_signal_blocked_or_ignored() {
        for tty in [None, Some(Size { rows: 24, cols: 80 })] {
            let (users, dir) = users(if tty.is_some() { "signals-tty" } else { "signals" });
            let mut s = thread::spawn(move || {
                // SAFETY: a set built with sigemptyset and sigaddset, blocked on this thread only.
                unsafe {
                    let mut set: libc::sigset_t = std::mem::zeroed();
                    libc::sigemptyset(&mut set);
                    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGPWR, libc::SIGCHLD] {
                        libc::sigaddset(&mut set, signal);
                    }
                    assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()), 0);
                }
                Session::start(users, &request(false, tty, &["grep", "-E", "^Sig(Blk|Ign)", "/proc/self/status"], &[]))
            })
            .join()
            .unwrap();
            assert!(s.status().success());
            let text = s.text(OUTPUT);
            let mask = |name: &str| {
                let line = text.lines().find(|l| l.starts_with(name)).unwrap_or_else(|| panic!("{text}"));
                u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap()
            };
            assert_eq!(mask("SigBlk:"), 0, "{text}");
            assert_eq!(mask("SigIgn:") & (1 << (libc::SIGPIPE - 1)), 0, "{text}");
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn a_command_that_cannot_start_says_why() {
        let (users, dir) = users("missing");
        let mut s = Session::start(users, &request(false, None, &["/nonexistent/program"], &[]));
        let (kind, why) = s.end();
        assert_eq!(kind, FAILED);
        assert!(String::from_utf8_lossy(&why).starts_with("running /nonexistent/program: "));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_oversized_frame_is_refused() {
        let mut header = vec![REQUEST];
        header.extend((MAX_FRAME as u32 + 1).to_be_bytes());
        let err = read_frame(&mut &header[..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // and the service answers it without running anything
        let (mut host, shim) = UnixStream::pair().unwrap();
        let (users, dir) = users("oversized");
        thread::spawn(move || serve(shim, &users));
        host.write_all(&header).unwrap();
        let (kind, why) = read_frame(&mut host).unwrap().unwrap();
        assert_eq!((kind, String::from_utf8_lossy(&why).contains("over the limit")), (FAILED, true));
        assert!(read_frame(&mut host).unwrap().is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_request_reads_only_as_what_was_written() {
        let req = request(true, Some(Size { rows: 50, cols: 200 }), &["claude", "--resume", ""], &[("A", "1"), ("EMPTY", "")]);
        let bytes = req.encode();
        assert_eq!(Request::decode(&bytes).unwrap(), req);
        let plain = request(false, None, &["true"], &[]);
        assert_eq!(Request::decode(&plain.encode()).unwrap(), plain);

        for cut in 0..bytes.len() {
            assert!(Request::decode(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(Request::decode(&longer), Err("bytes after the request"));
        let bad = |at: usize, value: u8| {
            let mut b = bytes.clone();
            b[at] = value;
            Request::decode(&b)
        };
        assert_eq!(bad(0, 2), Err("unknown request version"));
        assert_eq!(bad(1, 2), Err("unknown user"));
        assert_eq!(bad(2, 2), Err("unknown terminal flag"));
        assert_eq!(Request::decode(&request(false, None, &[], &[]).encode()), Err("no command"));
        assert_eq!(Request::decode(&request(false, None, &["a\0b"], &[]).encode()), Err("a NUL byte in the request"));
        assert_eq!(Request::decode(&request(false, None, &["true"], &[("A=B", "c")]).encode()), Err("a bad variable name"));
        assert_eq!(Request::decode(&request(false, None, &["true"], &[("", "c")]).encode()), Err("a bad variable name"));
    }

    #[test]
    fn random_frames_never_panic_and_never_allocate_past_the_cap() {
        // xorshift: the same bytes every run
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let valid = request(false, Some(Size { rows: 1, cols: 2 }), &["sh", "-c", "x"], &[("K", "V")]).encode();
        for _ in 0..20_000 {
            let len = (next() % 64) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if next() % 2 == 0 {
                // a valid request with one byte changed, so the parse gets past the first fields
                bytes = valid.clone();
                let at = (next() as usize) % bytes.len();
                bytes[at] = next() as u8;
            }
            let _ = Request::decode(&bytes);
            let mut stream = &bytes[..];
            while let Ok(Some((_, payload))) = read_frame(&mut stream) {
                assert!(payload.len() <= MAX_FRAME);
            }
        }
    }
}
