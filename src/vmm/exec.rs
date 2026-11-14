//! The client of the shim's exec service: halti runs a command in a box's VM through it, as the
//! agent or as root, on a terminal or on pipes, as `container exec` does for a box that Apple's
//! tool runs. The service is the box's (box/shim/src/exec.rs), on `names::EXEC_PORT`.
//!
//! The wire is frames: a kind byte, the payload's length (u32, big-endian) and the payload. halti
//! sends one `REQUEST` first, then `INPUT` and `RESIZE`; the box answers with `OUTPUT` and `ERROR`
//! and ends with one `EXIT` or one `FAILED`.
//!
//! Every frame comes from inside the box, where an agent with Docker is root and can replace the
//! shim, and is read in the process that holds the workspace's keys. So a frame is never longer
//! than `MAX_FRAME`, which is checked before anything is allocated; a frame of a kind halti does
//! not know ends the command; what the box says about a failure is shown cut short and without
//! control characters; and nothing read here can panic.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};

/// The longest payload of any frame, as the shim has it.
pub const MAX_FRAME: usize = 64 * 1024;

pub const REQUEST: u8 = b'R';
pub const INPUT: u8 = b'I';
pub const RESIZE: u8 = b'W';
pub const OUTPUT: u8 = b'O';
pub const ERROR: u8 = b'E';
pub const EXIT: u8 = b'X';
pub const FAILED: u8 = b'F';

/// The request's first byte.
const VERSION: u8 = 1;
/// How often the input is looked at, so its thread notices the command's end.
const POLL: Duration = Duration::from_millis(100);
/// The most of a failure's text that is shown.
const MOST_SHOWN: usize = 300;

/// A terminal's size.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
}

/// What to run, and as whom.
pub struct Request<'a> {
    pub root: bool,
    /// A terminal of this size; `None` for pipes.
    pub tty: Option<Size>,
    pub argv: &'a [String],
    /// The command's own variables. They travel in the request, so none is on a command line in
    /// the box.
    pub env: &'a [(String, String)],
}

impl Request<'_> {
    /// The request's payload: the version, the user (0 the agent, 1 root), a terminal or not, its
    /// rows and columns (u16 each), the number of arguments (u16) and each, the number of variables
    /// (u16) and each name and value; a string is its length (u32) and its bytes. Refused where
    /// the shim would refuse it, so a command that can't run says so here.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.argv.is_empty() {
            bail!("no command to run");
        }
        if self.argv.iter().chain(self.env.iter().flat_map(|(k, v)| [k, v])).any(|s| s.contains('\0')) {
            bail!("a command or a variable with a NUL byte can't be run");
        }
        if let Some((key, _)) = self.env.iter().find(|(k, _)| k.is_empty() || k.contains('=')) {
            bail!("{key:?} can't be a variable's name");
        }
        if self.argv.len() > u16::MAX as usize || self.env.len() > u16::MAX as usize {
            bail!("too many arguments or variables");
        }
        let size = self.tty.unwrap_or(Size { rows: 0, cols: 0 });
        let mut out = vec![VERSION, self.root as u8, self.tty.is_some() as u8];
        out.extend(size.rows.to_be_bytes());
        out.extend(size.cols.to_be_bytes());
        let string = |out: &mut Vec<u8>, s: &str| {
            out.extend((s.len() as u32).to_be_bytes());
            out.extend(s.as_bytes());
        };
        out.extend((self.argv.len() as u16).to_be_bytes());
        for arg in self.argv {
            string(&mut out, arg);
        }
        out.extend((self.env.len() as u16).to_be_bytes());
        for (key, value) in self.env {
            string(&mut out, key);
            string(&mut out, value);
        }
        if out.len() > MAX_FRAME {
            bail!("the command and its variables are too long to send ({} bytes, at most {MAX_FRAME})", out.len());
        }
        Ok(out)
    }
}

/// The next frame, or `None` if the stream ended before one began. A length over `MAX_FRAME` is
/// refused before anything is allocated for it.
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
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("the box sent a frame of {len} bytes, over the limit of {MAX_FRAME}")));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some((kind[0], payload)))
}

/// One frame, in one write. A payload over `MAX_FRAME` is refused, and nothing is written.
pub fn write_frame(w: &mut impl Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("a frame of {} bytes, over the limit of {MAX_FRAME}", payload.len())));
    }
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(kind);
    frame.extend((payload.len() as u32).to_be_bytes());
    frame.extend(payload);
    w.write_all(&frame)
}

/// What the box says, made safe to print: control characters (a terminal's escapes among them)
/// shown as `?`, and cut to `MOST_SHOWN` characters.
pub fn shown(text: &[u8]) -> String {
    let text = String::from_utf8_lossy(&text[..text.len().min(4 * MOST_SHOWN)]);
    let mut out: String = text.chars().take(MOST_SHOWN).map(|c| if c.is_control() { '?' } else { c }).collect();
    if text.chars().count() > MOST_SHOWN {
        out.push_str("...");
    }
    out
}

/// Where the command's input comes from.
pub enum Input<'a> {
    /// These bytes, then the end of the input.
    Bytes(&'a [u8]),
    /// halti's own standard input, until it ends or the command does. On a terminal, the
    /// terminal's size goes too, and again each time it changes.
    Stdin,
}

/// Where the command's output goes, and how much of it is taken.
pub struct Sink<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    /// The most standard output kept; more ends the command with an error. `None`: no limit (it
    /// is passed on as it comes).
    pub most: Option<usize>,
}

/// Run `request` over `stream` (a connection to the exec service) and return how the command
/// ended. An error is a command that did not start, a box that broke the protocol, or a connection
/// that ended with no last frame.
pub fn run(stream: UnixStream, request: &Request, input: Input, sink: Sink) -> Result<ExitStatus> {
    let payload = request.encode()?;
    let mut writer = stream.try_clone()?;
    write_frame(&mut writer, REQUEST, &payload)?;
    let done = Arc::new(AtomicBool::new(false));
    let feeding = match input {
        Input::Bytes(bytes) => {
            send_bytes(&mut writer, bytes);
            None
        }
        Input::Stdin => {
            let done = done.clone();
            let tty = request.tty.is_some();
            Some(thread::spawn(move || feed_stdin(writer, tty, &done)))
        }
    };
    let ended = read_answers(&stream, sink);
    done.store(true, Ordering::SeqCst);
    let _ = stream.shutdown(Shutdown::Both);
    if let Some(feeding) = feeding {
        let _ = feeding.join();
    }
    ended
}

/// Send `bytes` as input frames, then the end of the input. A box that stops reading ends it.
fn send_bytes(w: &mut UnixStream, bytes: &[u8]) {
    for chunk in bytes.chunks(MAX_FRAME) {
        if write_frame(w, INPUT, chunk).is_err() {
            return;
        }
    }
    let _ = write_frame(w, INPUT, b"");
}

/// Read the box's frames to the last one.
fn read_answers(stream: &UnixStream, sink: Sink) -> Result<ExitStatus> {
    let mut reader = stream;
    let mut kept = 0usize;
    loop {
        let frame = match read_frame(&mut reader) {
            Ok(Some(frame)) => frame,
            Ok(None) => bail!("the box ended the command's connection before it said how the command ended"),
            Err(e) => bail!("reading from the box: {e}"),
        };
        match frame {
            (OUTPUT, bytes) => {
                kept += bytes.len();
                if sink.most.is_some_and(|most| kept > most) {
                    bail!("the command's output is over the limit of {} bytes", sink.most.unwrap_or(0));
                }
                // a reader that went away (halti's own output closed) doesn't stop the command
                let _ = sink.out.write_all(&bytes).and_then(|()| sink.out.flush());
            }
            (ERROR, bytes) => {
                let _ = sink.err.write_all(&bytes).and_then(|()| sink.err.flush());
            }
            (EXIT, raw) => match <[u8; 4]>::try_from(raw.as_slice()) {
                Ok(raw) => return Ok(ExitStatus::from_raw(i32::from_be_bytes(raw))),
                Err(_) => bail!("the box sent an exit status of {} bytes", raw.len()),
            },
            (FAILED, why) => bail!("{}", shown(&why)),
            (kind, _) => bail!("the box sent a frame of a kind halti doesn't know ({kind})"),
        }
    }
}

/// Carry halti's standard input to the command until it ends, the command ends (`done`), or the
/// box stops reading. On a terminal, the terminal's size goes first and again when it changes, and
/// the terminal is raw meanwhile, so each key reaches the command as it is typed.
fn feed_stdin(mut w: UnixStream, tty: bool, done: &AtomicBool) {
    let _raw = if tty { Raw::new(0) } else { None };
    let mut size = if tty { terminal_size(0) } else { None };
    let mut buf = vec![0u8; 16 * 1024];
    while !done.load(Ordering::SeqCst) {
        if tty && let Some(now) = terminal_size(0).filter(|now| Some(*now) != size) {
            size = Some(now);
            let mut payload = now.rows.to_be_bytes().to_vec();
            payload.extend(now.cols.to_be_bytes());
            if write_frame(&mut w, RESIZE, &payload).is_err() {
                return;
            }
        }
        if !readable(0, POLL) {
            continue;
        }
        // SAFETY: read(2) into a live buffer of the length given.
        let n = match unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) } {
            -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
            -1 => 0,
            n => n as usize,
        };
        // the end of the input: on pipes it is passed on; a terminal has no end but a hang-up
        if write_frame(&mut w, INPUT, &buf[..n]).is_err() || n == 0 {
            return;
        }
    }
}

/// Whether `fd` has something to read (or has ended) within `wait`.
fn readable(fd: i32, wait: Duration) -> bool {
    let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: poll(2) on one live pollfd.
    let n = unsafe { libc::poll(&mut poll, 1, wait.as_millis() as libc::c_int) };
    n > 0
}

/// The size of the terminal on `fd`, if it is one.
pub fn terminal_size(fd: i32) -> Option<Size> {
    // SAFETY: winsize is plain integers; ioctl(2) TIOCGWINSZ writes one.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let got = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, &mut ws) } == 0;
    (got && ws.ws_row > 0 && ws.ws_col > 0).then_some(Size { rows: ws.ws_row, cols: ws.ws_col })
}

/// A terminal in raw mode, put back as it was when dropped.
struct Raw {
    fd: i32,
    was: libc::termios,
}

impl Raw {
    fn new(fd: i32) -> Option<Self> {
        // SAFETY: termios is plain data; tcgetattr(3) fills it.
        let mut was: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: as above, on a descriptor halti holds.
        if unsafe { libc::tcgetattr(fd, &mut was) } != 0 {
            return None;
        }
        let mut raw = was;
        // SAFETY: cfmakeraw(3) and tcsetattr(3) on live values.
        unsafe {
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(fd, libc::TCSANOW, &raw);
        }
        Some(Self { fd, was })
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        // SAFETY: tcsetattr(3) with the settings read in `new`.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.was) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// What a fake box was sent: the request, and the frames after it.
    type Sent = (Vec<u8>, Vec<(u8, Vec<u8>)>);

    /// A box's side of one exec, played by a script: it reads the request and the input, and
    /// answers with `answer`.
    fn fake_box(answer: Vec<u8>) -> (UnixStream, thread::JoinHandle<Sent>) {
        let (host, mut shim) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || {
            let (kind, request) = read_frame(&mut shim).unwrap().unwrap();
            assert_eq!(kind, REQUEST);
            let mut frames = Vec::new();
            while let Ok(Some(frame)) = read_frame(&mut shim) {
                let last = frame.0 == INPUT && frame.1.is_empty();
                frames.push(frame);
                if last {
                    break;
                }
            }
            let _ = shim.write_all(&answer);
            (request, frames)
        });
        (host, handle)
    }

    fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_frame(&mut out, kind, payload).unwrap();
        out
    }

    #[test]
    fn a_request_reads_only_as_what_was_written() {
        let argv = strings(&["claude", "--resume", ""]);
        let env = vec![("A".to_string(), "1".to_string()), ("EMPTY".to_string(), String::new())];
        let request = Request { root: true, tty: Some(Size { rows: 50, cols: 200 }), argv: &argv, env: &env };
        let mut want = vec![1, 1, 1, 0, 50, 0, 200, 0, 3];
        for arg in ["claude", "--resume", ""] {
            want.extend((arg.len() as u32).to_be_bytes());
            want.extend(arg.as_bytes());
        }
        want.extend([0, 2]);
        for s in ["A", "1", "EMPTY", ""] {
            want.extend((s.len() as u32).to_be_bytes());
            want.extend(s.as_bytes());
        }
        assert_eq!(request.encode().unwrap(), want);
        let plain = Request { root: false, tty: None, argv: &strings(&["true"]), env: &[] }.encode().unwrap();
        assert_eq!(plain, [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, b't', b'r', b'u', b'e', 0, 0]);

        // what the shim would refuse is refused here
        let refused = |argv: &[&str], env: &[(&str, &str)]| {
            let argv = strings(argv);
            let env: Vec<(String, String)> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            Request { root: false, tty: None, argv: &argv, env: &env }.encode().is_err()
        };
        assert!(refused(&[], &[]));
        assert!(refused(&["a\0b"], &[]));
        assert!(refused(&["true"], &[("A=B", "c")]));
        assert!(refused(&["true"], &[("", "c")]));
        assert!(refused(&["true"], &[("K", "v\0")]));
        assert!(refused(&[&"x".repeat(MAX_FRAME)], &[]));
    }

    #[test]
    fn frames_carry_input_output_resize_and_the_exit_code() {
        let mut answer = frame(OUTPUT, b"hello ");
        answer.extend(frame(ERROR, b"oops"));
        answer.extend(frame(OUTPUT, b"box"));
        answer.extend(frame(EXIT, &(3i32 << 8).to_be_bytes()));
        let (host, the_box) = fake_box(answer);
        let argv = strings(&["cat"]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let input = vec![7u8; MAX_FRAME + 10];
        let status = run(host, &Request { root: false, tty: None, argv: &argv, env: &[] }, Input::Bytes(&input), Sink { out: &mut out, err: &mut err, most: None }).unwrap();
        assert_eq!(status.code(), Some(3));
        assert_eq!((out.as_slice(), err.as_slice()), (&b"hello box"[..], &b"oops"[..]));
        let (_, frames) = the_box.join().unwrap();
        // the input in frames no longer than the cap, then its end
        let sizes: Vec<(u8, usize)> = frames.iter().map(|(k, p)| (*k, p.len())).collect();
        assert_eq!(sizes, [(INPUT, MAX_FRAME), (INPUT, 10), (INPUT, 0)]);

        // a terminal's size travels as RESIZE: rows, then columns
        let mut payload = 40u16.to_be_bytes().to_vec();
        payload.extend(120u16.to_be_bytes());
        assert_eq!(frame(RESIZE, &payload), [b'W', 0, 0, 0, 4, 0, 40, 0, 120]);

        // a command that did not start says why, made safe to print
        let (host, _the_box) = fake_box(frame(FAILED, b"running nope: \x1b[31mnot found"));
        let err =
            run(host, &Request { root: false, tty: None, argv: &strings(&["nope"]), env: &[] }, Input::Bytes(b""), Sink { out: &mut Vec::new(), err: &mut Vec::new(), most: None })
                .unwrap_err();
        assert_eq!(err.to_string(), "running nope: ?[31mnot found");

        // output over the caller's limit ends it
        let (host, _the_box) = fake_box(frame(OUTPUT, &[1; 100]));
        let err = run(host, &Request { root: false, tty: None, argv: &argv, env: &[] }, Input::Bytes(b""), Sink { out: &mut Vec::new(), err: &mut Vec::new(), most: Some(99) })
            .unwrap_err();
        assert!(err.to_string().contains("over the limit"), "{err}");

        // a connection that ends with no last frame, as when the command stopped the box
        let (host, _the_box) = fake_box(frame(OUTPUT, b"bye"));
        let err =
            run(host, &Request { root: true, tty: None, argv: &argv, env: &[] }, Input::Bytes(b""), Sink { out: &mut Vec::new(), err: &mut Vec::new(), most: None }).unwrap_err();
        assert!(err.to_string().contains("before it said how the command ended"), "{err}");
    }

    #[test]
    fn an_oversized_frame_is_refused() {
        let mut sent = Vec::new();
        assert_eq!(write_frame(&mut sent, INPUT, &vec![0; MAX_FRAME + 1]).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(sent.is_empty(), "nothing is written");
        write_frame(&mut sent, INPUT, &vec![0; MAX_FRAME]).unwrap();
        assert_eq!(read_frame(&mut &sent[..]).unwrap().unwrap().1.len(), MAX_FRAME);

        let mut header = vec![OUTPUT];
        header.extend((MAX_FRAME as u32 + 1).to_be_bytes());
        assert_eq!(read_frame(&mut &header[..]).unwrap_err().kind(), io::ErrorKind::InvalidData);
        // and the client ends the command on it
        let (host, _the_box) = fake_box(header);
        let err =
            run(host, &Request { root: false, tty: None, argv: &strings(&["x"]), env: &[] }, Input::Bytes(b""), Sink { out: &mut Vec::new(), err: &mut Vec::new(), most: None })
                .unwrap_err();
        assert!(err.to_string().contains("over the limit"), "{err}");
        // an exit status of the wrong size, and a kind nobody sends, end it too
        for bad in [frame(EXIT, &[0; 5]), frame(b'Z', b"")] {
            let (host, _the_box) = fake_box(bad);
            assert!(
                run(
                    host,
                    &Request { root: false, tty: None, argv: &strings(&["x"]), env: &[] },
                    Input::Bytes(b""),
                    Sink { out: &mut Vec::new(), err: &mut Vec::new(), most: None }
                )
                .is_err()
            );
        }
    }

    /// The client fed random and cut-off frames: it ends each with an answer or an error, never a
    /// panic, and never takes a length over the cap as a size to allocate.
    #[test]
    fn random_frames_never_panic_and_never_allocate_past_the_cap() {
        // xorshift: the same bytes every run
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let kinds = [OUTPUT, ERROR, EXIT, FAILED, INPUT, 0, 0xff];
        let mut sink = (Vec::new(), Vec::new());
        for _ in 0..20_000 {
            let mut bytes = Vec::new();
            for _ in 0..(next() % 4) {
                let len = (next() % 12) as usize;
                let mut f = frame(kinds[(next() % kinds.len() as u64) as usize], &(0..len).map(|_| next() as u8).collect::<Vec<_>>());
                if next() % 3 == 0 {
                    // a byte changed anywhere: the kind, the length or the payload
                    let at = (next() as usize) % f.len();
                    f[at] = next() as u8;
                }
                if next() % 5 == 0 {
                    f.truncate((next() as usize) % f.len());
                }
                bytes.extend(f);
            }
            let mut stream = &bytes[..];
            while let Ok(Some(_)) = read_frame(&mut stream) {}
            // the answers' reader, through a socket pair as the box would send them
            let (host, mut shim) = UnixStream::pair().unwrap();
            shim.write_all(&bytes).unwrap();
            drop(shim);
            sink.0.clear();
            let _ = read_answers(&host, Sink { out: &mut sink.0, err: &mut sink.1, most: Some(1024) });

            // a length over the cap, followed by as many bytes as it asks for: refused unread
            let len = MAX_FRAME as u64 + 1 + next() % (u32::MAX as u64 - MAX_FRAME as u64);
            let mut header = vec![next() as u8];
            header.extend((len as u32).to_be_bytes());
            assert_eq!(read_frame(&mut (&header[..]).chain(io::repeat(0))).unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn the_environment_travels_in_the_request_not_on_a_command_line() {
        let argv = strings(&["sh", "-c", "echo \"$TOKEN_STANDIN\""]);
        let env = vec![("TOKEN_STANDIN".to_string(), "halti-managed".to_string())];
        let (host, the_box) = fake_box(frame(EXIT, &0i32.to_be_bytes()));
        run(host, &Request { root: false, tty: None, argv: &argv, env: &env }, Input::Bytes(b""), Sink { out: &mut Vec::new(), err: &mut Vec::new(), most: None }).unwrap();
        let (request, _) = the_box.join().unwrap();
        assert!(argv.iter().all(|a| !a.contains("halti-managed")), "not in an argument");
        let at = request.windows(13).rposition(|w| w == b"TOKEN_STANDIN").expect("the name is in the request");
        assert_eq!(&request[at + 13..at + 17], &13u32.to_be_bytes(), "its value follows, by its length");
        assert_eq!(&request[at + 17..], b"halti-managed");
    }

    #[test]
    fn what_the_box_says_is_shown_safely() {
        assert_eq!(shown(b"plain"), "plain");
        assert_eq!(shown(b"bell\x07 and \x1b]0;title\x07"), "bell? and ?]0;title?");
        let long = shown(&[b'a'; 10_000]);
        assert_eq!(long.len(), MOST_SHOWN + 3);
        assert_eq!(shown(&[0xff, b'x']), "\u{fffd}x");
    }
}
