//! `inspect::serve` over plain sockets: the guest and the site are both ends of local socket
//! pairs, so no TLS is needed. The site is a scripted server that records what reaches it.
//!
//! Policies, approvals and values live in files (the debug-only fake Keychain), set up through
//! environment variables, so each scenario runs in a copy of this test binary started with its
//! own environment (as in `tests`), with Touch ID answering yes or no.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::bail;
use serde_json::{Value, json};

use super::addr::Net as Dial;
use super::http::{self, Body, Head};
use super::inspect::{Caller, Ctx, LOOK_AHEAD, Net, RETRY_BODY, first_while_fresh, serve};
use super::{Config, Shared};
use crate::approval::Means;
use crate::chain::Chain;
use crate::policy::{self, Mode};
use crate::requests::{self, Desk, Here, Prompt, Prompted, Record, RunId, answer_digest};
use crate::util::TempDir;
use crate::{approve, keychain};

const SECRET: &str = "tok-SECRET-0123456789-abcdef";
const LOG_KEY: [u8; 32] = [9; 32];
const WAIT: Duration = Duration::from_secs(10);
const MASK: &str = "********";

// --- the scenario's environment ---

const YES: &str = "door::inspect_tests::the_requests_of_a_box_are_judged_and_touch_id_says_yes";
const NO: &str = "door::inspect_tests::the_requests_of_a_box_are_judged_and_touch_id_says_no";

#[test]
fn the_requests_of_a_box_are_judged_and_touch_id_says_yes() {
    run_scenario(YES, "yes");
}

#[test]
fn the_requests_of_a_box_are_judged_and_touch_id_says_no() {
    run_scenario(NO, "no");
}

fn run_scenario(name: &str, answer: &str) {
    if let Some(dir) = std::env::var_os("HALTI_INSPECT_DIR") {
        return scenario(Path::new(&dir), answer == "yes");
    }
    let dir = TempDir::new("halti-inspect").unwrap();
    for sub in ["keychain", "policy", "home"] {
        fs::create_dir(dir.0.join(sub)).unwrap();
    }
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("HALTI_INSPECT_DIR", &dir.0)
        .env("HOME", dir.0.join("home"))
        .env("HALTI_INDEX", dir.0.join("index.json"))
        .env("HALTI_POLICY_DIR", dir.0.join("policy"))
        .env("HALTI_TEST_KEYCHAIN", dir.0.join("keychain"))
        .env("HALTI_TEST_APPROVE", "yes")
        .env("HALTI_AUDIT", dir.0.join("audit.log"))
        .env("HALTI_AUDIT_KEY", "test-key");
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "scenario failed:\n{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

// --- a scripted site ---

/// What the site saw of a request; the body is decoded.
#[derive(Clone)]
struct Seen {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn count(&self, name: &str) -> usize {
        self.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).count()
    }

    fn target(&self) -> &str {
        self.line.split(' ').nth(1).unwrap()
    }
}

/// Routes: `/plain`, `/echo` (the secret in a body with a length), `/split` (the secret cut
/// across two chunks), `/sse` (an event, then the secret cut across two chunks after `release`),
/// `/gzip`, `/close` (a body that ends with the connection), `POST /submit` (echoes the body).
fn respond(seen: &Seen, out: &mut UnixStream, released: &Mutex<Receiver<()>>) {
    let method = seen.line.split(' ').next().unwrap();
    let path = seen.target().split('?').next().unwrap();
    let whole = |out: &mut UnixStream, extra: &str, body: &str| {
        write!(out, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n{extra}content-length: {}\r\n\r\n{body}", body.len()).unwrap();
    };
    let chunk = |out: &mut UnixStream, data: &str| {
        write!(out, "{:x}\r\n{data}\r\n", data.len()).unwrap();
        out.flush().unwrap();
        thread::sleep(Duration::from_millis(40));
    };
    match (method, path) {
        ("HEAD", _) => write!(out, "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n").unwrap(),
        (_, "/plain") => whole(out, "", "plain page"),
        (_, "/echo") => whole(out, "etag: \"x\"\r\n", &format!("token is {SECRET} ok")),
        (_, "/split") => {
            write!(out, "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n").unwrap();
            chunk(out, "token is tok-SEC");
            chunk(out, "RET-0123456789-abcdef ok");
            write!(out, "0\r\n\r\n").unwrap();
        }
        (_, "/sse") => {
            write!(out, "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n").unwrap();
            chunk(out, "event: ping\ndata: 1\n\n");
            released.lock().unwrap().recv_timeout(WAIT).unwrap();
            chunk(out, "data: tok-SECR");
            chunk(out, "ET-0123456789-abcdef\n\n");
            write!(out, "0\r\n\r\n").unwrap();
        }
        (_, "/gzip") => out.write_all(b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 4\r\n\r\n\x1f\x8b\x08\x00").unwrap(),
        // The site closes the connection after answering, without saying so.
        (_, "/once") => {
            whole(out, "", "plain page");
            out.flush().unwrap();
            out.shutdown(Shutdown::Both).unwrap();
        }
        // The site starts an answer and dies.
        (_, "/partial") => {
            out.write_all(b"HTTP/1.1 200 OK\r\ncon").unwrap();
            out.flush().unwrap();
            out.shutdown(Shutdown::Both).unwrap();
        }
        (_, "/close") => {
            write!(out, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nclosing {SECRET}").unwrap();
            out.flush().unwrap();
            out.shutdown(Shutdown::Both).unwrap();
        }
        ("POST", "/submit") => whole(out, "", &format!("got {}", String::from_utf8_lossy(&seen.body))),
        _ => write!(out, "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n").unwrap(),
    }
    out.flush().unwrap();
}

/// One connection for a host: the guest's end, the site's record, and the thread running `serve`.
struct Rig {
    guest: Conn,
    seen: Arc<Mutex<Vec<Seen>>>,
    release: Sender<()>,
    /// How many connections the door made to the site.
    connects: Arc<AtomicUsize>,
    /// While set, the door can't connect to the site.
    unreachable: Arc<AtomicBool>,
    /// What `serve` counted, and the answers to what the door asked: they are kept on the thread
    /// that asked.
    serving: JoinHandle<((u64, u64), Vec<bool>)>,
}

impl Rig {
    fn new(shared: &Arc<Shared>, host: &str) -> Self {
        Rig::with_first(shared, host, None)
    }

    /// With `first`, the door is handed a connection made before any request, as at CONNECT, to a
    /// site that closes it once it has sat unused for `first.1`; the door uses it while it is no
    /// older than `first.0`. Without, each connection is made as a request needs it.
    fn with_first(shared: &Arc<Shared>, host: &str, first: Option<(Duration, Duration)>) -> Self {
        let (guest, door_guest) = UnixStream::pair().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (release, released) = mpsc::channel();
        let released = Arc::new(Mutex::new(released));
        let (connects, unreachable) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicBool::new(false)));
        // Each connection the door makes gets a site of its own; they all record into `seen`.
        let (record, count, down) = (seen.clone(), connects.clone(), unreachable.clone());
        let site = move |idle: Option<Duration>| {
            count.fetch_add(1, Ordering::SeqCst);
            let (door_upstream, site) = UnixStream::pair().unwrap();
            let (record, released) = (record.clone(), released.clone());
            site.set_read_timeout(idle).unwrap();
            thread::spawn(move || {
                let mut reader = BufReader::new(site.try_clone().unwrap());
                let mut out = site;
                // A site that times out an idle connection closes it.
                while let Ok(Some(head)) = http::read_head(&mut reader) {
                    let framing = http::request_framing(&head).unwrap();
                    let mut body = Vec::new();
                    Body::new(&mut reader, framing).read_to_end(&mut body).unwrap();
                    let seen = Seen { line: head.line.clone(), headers: head.headers.clone(), body };
                    record.lock().unwrap().push(seen.clone());
                    respond(&seen, &mut out, &released);
                }
                let _ = out.shutdown(Shutdown::Both);
            });
            door_upstream
        };
        let made = first.map(|(_, idle)| site(Some(idle)));
        let dial = move || {
            if down.load(Ordering::SeqCst) {
                bail!("no route to the site");
            }
            Ok(site(None))
        };
        let (shared, host) = (shared.clone(), host.to_string());
        let serving = thread::spawn(move || {
            let ctx = Ctx { shared: &shared, host: &host, caller: &Caller::Agent };
            let counted = match (made, first) {
                (Some(made), Some((fresh, _))) => serve(door_guest, first_while_fresh(made, fresh, dial), &ctx),
                _ => serve(door_guest, dial, &ctx),
            };
            (counted, approve::take_answers())
        });
        guest.set_read_timeout(Some(WAIT)).unwrap();
        Self { guest: Conn { reader: BufReader::new(guest.try_clone().unwrap()), stream: guest, seen: Vec::new() }, seen, release, connects, unreachable, serving }
    }

    fn connects(&self) -> usize {
        self.connects.load(Ordering::SeqCst)
    }

    fn reached(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// End the guest's side and wait for the door to finish: the log is complete after this.
    fn finish(self) -> (u64, u64) {
        self.end().0
    }

    /// `finish`, and how each question the door asked on this connection was answered.
    fn finish_asked(self) -> Vec<bool> {
        self.end().1
    }

    fn end(self) -> ((u64, u64), Vec<bool>) {
        let _ = self.guest.stream.shutdown(Shutdown::Write);
        drop(self.guest);
        self.serving.join().unwrap()
    }
}

struct Conn {
    reader: BufReader<UnixStream>,
    stream: UnixStream,
    /// Everything the door sent back.
    seen: Vec<u8>,
}

struct Reply {
    status: u16,
    head: Head,
}

impl Conn {
    fn send(&mut self, text: &str) {
        self.stream.write_all(text.as_bytes()).unwrap();
    }

    fn head(&mut self) -> Reply {
        let head = http::read_head(&mut self.reader).unwrap().expect("the door closed the connection");
        self.seen.extend_from_slice(head.line.as_bytes());
        for (n, v) in &head.headers {
            self.seen.extend_from_slice(format!("{n}: {v}\n").as_bytes());
        }
        Reply { status: head.status().unwrap(), head }
    }

    /// One piece of a chunked body; empty for the last.
    fn chunk(&mut self) -> Vec<u8> {
        let mut size = String::new();
        self.reader.read_line(&mut size).unwrap();
        let size = usize::from_str_radix(size.trim(), 16).unwrap();
        let mut data = vec![0; size + 2];
        self.reader.read_exact(&mut data).unwrap();
        assert_eq!(&data[size..], b"\r\n");
        data.truncate(size);
        self.seen.extend_from_slice(&data);
        data
    }

    fn body(&mut self, reply: &Reply) -> String {
        let mut all = Vec::new();
        if reply.head.header("transfer-encoding") == Some("chunked") {
            loop {
                let chunk = self.chunk();
                if chunk.is_empty() {
                    break;
                }
                all.extend(chunk);
            }
        } else if let Some(len) = reply.head.header("content-length") {
            all = vec![0; len.parse().unwrap()];
            self.reader.read_exact(&mut all).unwrap();
            self.seen.extend_from_slice(&all);
        } else {
            self.reader.read_to_end(&mut all).unwrap();
            self.seen.extend_from_slice(&all);
        }
        String::from_utf8_lossy(&all).into_owned()
    }

    /// The door ends the connection within `WAIT`.
    fn closed(&mut self) -> bool {
        let mut byte = [0u8; 1];
        matches!(self.reader.read(&mut byte), Ok(0) | Err(_))
    }

    /// Send a request, return the status and the body.
    fn get(&mut self, host: &str, target: &str, headers: &[(&str, &str)]) -> (Reply, String) {
        self.send(&request("GET", target, host, headers, None));
        let reply = self.head();
        let body = self.body(&reply);
        (reply, body)
    }

    fn post(&mut self, host: &str, target: &str, headers: &[(&str, &str)], body: &str) -> (Reply, String) {
        self.send(&request("POST", target, host, headers, Some(body)));
        let reply = self.head();
        let body = self.body(&reply);
        (reply, body)
    }
}

fn request(method: &str, target: &str, host: &str, headers: &[(&str, &str)], body: Option<&str>) -> String {
    let headers: String = headers.iter().map(|(n, v)| format!("{n}: {v}\r\n")).collect();
    let length = body.map_or(String::new(), |b| format!("Content-Length: {}\r\n", b.len()));
    format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\n{headers}{length}\r\n{}", body.unwrap_or(""))
}

// --- the box ---

fn write_policy(res: &str, toml: &str) {
    fs::write(policy::path(res), toml).unwrap();
}

fn store(res: &str, field: &str, value: &str) {
    keychain::set(res, field, value).unwrap();
}

/// A door's shared state with these write rules, logging to `dir/<name>.log`; a write `[net]` asks
/// about is asked with Touch ID.
fn shared(dir: &Path, name: &str, writes: Mode, allow_writes: &[&str]) -> Arc<Shared> {
    shared_asking(dir, name, writes, allow_writes, Some(Means::TouchId))
}

/// The same, with a write `[net]` asks about approved by `ask` (`[box.approval] write`).
fn shared_asking(dir: &Path, name: &str, writes: Mode, allow_writes: &[&str], ask: Option<Means>) -> Arc<Shared> {
    let config = Config {
        name: "testbox".into(),
        socket: dir.join("unused.sock"),
        port: None,
        allow: vec!["*".into()],
        model: None,
        sites: vec!["app".into(), "readonly".into(), "askme".into(), "pending".into()],
        net: Net { writes, allow_writes: allow_writes.iter().map(|p| p.to_string()).collect(), ask },
        log: dir.join(format!("{name}.log")),
        log_key: LOG_KEY,
        browser: None,
        ca: None,
        browser_socket: None,
        browser_tokens: Default::default(),
        requests: None,
    };
    Arc::new(Shared::new(config, Dial::system()).unwrap())
}

fn log_lines(dir: &Path, name: &str) -> Vec<Value> {
    fs::read_to_string(dir.join(format!("{name}.log"))).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn scenario(dir: &Path, yes: bool) {
    // The box's sites: one that may write, one read-only, one that asks, one never approved.
    let hosts = [("app", "app.example.com", "writes = \"allow\"\n"), ("readonly", "ro.example.com", ""), ("askme", "ask.example.com", "writes = \"ask\"\n")];
    for (res, host, writes) in hosts {
        write_policy(res, &format!("[fetch]\nhosts = [\"https://{host}\"]\n{writes}auth = \"Bearer {{token}}\"\nheaders = {{ x-client = \"halti\" }}\n"));
        store(res, "token", SECRET);
    }
    write_policy("pending", "[fetch]\nhosts = [\"https://pending.example.com\"]\nwrites = \"allow\"\nauth = \"Bearer {token}\"\n");
    store("pending", "token", SECRET);
    fs::write(dir.join("index.json"), json!({ "app": site_index(), "readonly": site_index(), "askme": site_index(), "pending": site_index() }).to_string()).unwrap();
    policy::approve(&["app".into(), "readonly".into(), "askme".into()]).unwrap();
    approve::take_answers();
    // The policies are approved; from here Touch ID answers as this scenario says.
    // SAFETY: no other thread is running yet; the doors' threads start later.
    unsafe { std::env::set_var("HALTI_TEST_APPROVE", if yes { "yes" } else { "no" }) };

    let deny = shared(dir, "deny", Mode::Deny, &["https://free.example.com/hook"]);
    other_hosts(&deny);
    site_hosts(&deny, yes);
    the_site_closes_idle_connections(&deny);
    net_asks(&shared(dir, "ask", Mode::Ask, &[]), yes);
    net_asks_nothing(&shared_asking(dir, "none", Mode::Ask, &[], Some(Means::None)));
    // Nothing here can approve it, and a means asked on the terminal, which the agent holds, never does.
    for (name, ask) in [("nowhere", None), ("sudo", Some(Means::Sudo)), ("passphrase", Some(Means::Passphrase))] {
        net_cannot_ask(&shared_asking(dir, name, Mode::Ask, &[], ask));
    }
    // `[box.approval] write` is for `[net]` only: a site's own `writes = "ask"` still asks Touch ID
    // on a door that lets `[net]` writes through unasked, and on one with nothing to ask `[net]` by.
    site_asks(&shared_asking(dir, "site-none", Mode::Ask, &[], Some(Means::None)), yes);
    site_asks(&shared_asking(dir, "site-nowhere", Mode::Ask, &[], None), yes);
    site_raises(dir);
    net_allows(&shared(dir, "allow", Mode::Allow, &[]));
    the_log_chains(dir, yes);
}

fn site_index() -> Value {
    json!({ "fields": { "token": {} } })
}

/// Hosts no site covers: reads pass untouched; writes follow `[net]`.
fn other_hosts(sh: &Arc<Shared>) {
    let host = "web.example.com";
    let mut rig = Rig::new(sh, host);

    // The guest's own headers reach the site as they are, answers come back as they are.
    let (reply, body) = rig.guest.get(host, "/plain?token=abc123", &[("authorization", "Bearer guests-own"), ("accept-encoding", "gzip"), ("connection", "keep-alive")]);
    assert_eq!((reply.status, body.as_str()), (200, "plain page"));
    assert_eq!(reply.head.header("content-length"), Some("10"), "an answer that needs no change keeps its length");
    let first = rig.reached()[0].clone();
    assert_eq!(first.line, "GET /plain?token=abc123 HTTP/1.1");
    assert_eq!((first.header("authorization"), first.header("accept-encoding"), first.header("x-client")), (Some("Bearer guests-own"), Some("gzip"), None));
    assert_eq!(first.header("host"), Some(host));

    // A refused write is answered, and the same connection goes on to serve a read.
    let before = rig.reached().len();
    let (reply, body) = rig.guest.post(host, "/submit", &[], "payload");
    assert_eq!(reply.status, 403);
    assert!(body.contains("doesn't allow POST") && body.contains("allow_writes"), "{body}");
    assert_eq!(rig.reached().len(), before, "a refused write never reaches the site");
    let (reply, body) = rig.guest.get(host, "/plain", &[]);
    assert_eq!((reply.status, body.as_str()), (200, "plain page"));
    // The body of a refused write is read past, whatever its framing.
    rig.guest.send("POST /submit HTTP/1.1\r\nHost: web.example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
    let reply = rig.guest.head();
    assert_eq!(reply.status, 403);
    rig.guest.body(&reply);
    assert_eq!(rig.guest.get(host, "/plain", &[]).0.status, 200);
    let methods = ["PUT", "PATCH", "DELETE"];
    for method in methods {
        rig.guest.send(&request(method, "/x", host, &[], Some("data")));
        let reply = rig.guest.head();
        assert_eq!(reply.status, 403, "{method}");
        rig.guest.body(&reply);
    }

    // Git: fetching and cloning are reads, pushing is not.
    let (reply, body) = rig.guest.post(host, "/o/r.git/git-upload-pack", &[("Content-Type", "application/x-git-upload-pack-request")], "0032want abc\n");
    assert_eq!(reply.status, 404, "the scripted site has no such route; it was reached");
    assert!(body.is_empty());
    assert_eq!(rig.reached().last().unwrap().target(), "/o/r.git/git-upload-pack");
    let (reply, _) = rig.guest.post(host, "/o/r.git/git-receive-pack", &[("Content-Type", "application/x-git-receive-pack-request")], "PACK");
    assert_eq!(reply.status, 403);
    assert_eq!(rig.guest.get(host, "/o/r.git/info/refs?service=git-receive-pack", &[]).0.status, 404, "advertising refs is a read");

    // An upgrade is a write; a request that isn't a path is refused.
    let (reply, _) = rig.guest.get(host, "/plain", &[("Connection", "Upgrade"), ("Upgrade", "websocket")]);
    assert_eq!(reply.status, 403);
    rig.guest.send("GET http://web.example.com/plain HTTP/1.1\r\nHost: web.example.com\r\n\r\n");
    let reply = rig.guest.head();
    assert_eq!(reply.status, 400);
    rig.guest.body(&reply);
    assert!(rig.guest.closed());
    let reached = rig.reached();
    rig.finish();

    // The Host header has to be the host the guest connected to, or the connection ends.
    let mut rig = Rig::new(sh, host);
    for header in ["evil.example.com", "web.example.com.evil.com", "app.example.com"] {
        let mut rig = Rig::new(sh, host);
        let (reply, body) = rig.guest.get(header, "/plain", &[]);
        assert_eq!(reply.status, 421, "{header}");
        assert!(body.contains("Host header must be web.example.com"), "{body}");
        assert!(rig.guest.closed());
        assert!(rig.reached().is_empty(), "a request for another host never reaches the site");
        rig.finish();
    }
    rig.guest.send("GET /plain HTTP/1.1\r\n\r\n");
    assert_eq!(rig.guest.head().status, 421, "no Host header at all");
    rig.finish();
    assert_eq!(reached.len(), 5);

    // Unmasked answers stream: the first event arrives before the site has sent the second.
    let mut rig = Rig::new(sh, host);
    rig.guest.send(&request("GET", "/sse", host, &[], None));
    let reply = rig.guest.head();
    assert_eq!(reply.head.header("transfer-encoding"), Some("chunked"));
    assert_eq!(rig.guest.chunk(), b"event: ping\ndata: 1\n\n");
    rig.release.send(()).unwrap();
    let mut rest = Vec::new();
    loop {
        let chunk = rig.guest.chunk();
        if chunk.is_empty() {
            break;
        }
        rest.extend(chunk);
    }
    assert_eq!(String::from_utf8(rest).unwrap(), format!("data: {SECRET}\n\n"), "other hosts' answers are not masked");
    // Compression is the guest's business there.
    let (reply, _) = rig.guest.get(host, "/gzip", &[]);
    assert_eq!((reply.status, reply.head.header("content-encoding")), (200, Some("gzip")));
    rig.finish();

    // [net] allow_writes: a prefix on the host and path boundaries, nothing near it.
    let free = "free.example.com";
    let mut rig = Rig::new(sh, free);
    assert_eq!(rig.guest.post(free, "/hook", &[], "a").0.status, 404, "reached");
    assert_eq!(rig.guest.post(free, "/hook/deeper?x=1", &[], "a").0.status, 404, "reached");
    for refused in ["/hooks", "/hook/../admin", "/hook/%2e%2e/admin", "/hook%2Fx", "/other"] {
        assert_eq!(rig.guest.post(free, refused, &[], "a").0.status, 403, "{refused}");
    }
    assert_eq!(rig.reached().len(), 2);
    rig.finish();
    let mut rig = Rig::new(sh, "free.example.com.evil.com");
    assert_eq!(rig.guest.post("free.example.com.evil.com", "/hook", &[], "a").0.status, 403, "another host is not the prefix's");
    rig.finish();
}

/// Hosts of the box's sites: the site's policy rules, its credentials replace the guest's, and
/// answers are masked as they stream.
fn site_hosts(sh: &Arc<Shared>, yes: bool) {
    let host = "app.example.com";
    let mut rig = Rig::new(sh, host);

    // The credential is the site's whatever the guest sent, once, and the answer is masked.
    let (reply, body) = rig.guest.get(
        host,
        "/echo?api_key=hunter2",
        &[("Authorization", "Bearer guests-own"), ("authorization", "Basic Zm9v"), ("X-Client", "mine"), ("Accept-Encoding", "gzip, br")],
    );
    assert_eq!(reply.status, 200);
    assert_eq!(body, format!("token is {MASK} ok"));
    assert_eq!(reply.head.header("content-length"), None, "masking changes the length");
    assert_eq!(reply.head.header("transfer-encoding"), Some("chunked"));
    assert_eq!(reply.head.header("etag"), Some("\"x\""), "other headers pass");
    let seen = rig.reached()[0].clone();
    assert_eq!(seen.count("authorization"), 1);
    assert_eq!(
        (seen.header("authorization"), seen.header("x-client"), seen.header("accept-encoding")),
        (Some(format!("Bearer {SECRET}").as_str()), Some("halti"), Some("identity"))
    );
    assert_eq!(seen.count("x-client"), 1);

    // A value cut across two chunks is still found.
    let (_, body) = rig.guest.get(host, "/split", &[]);
    assert_eq!(body, format!("token is {MASK} ok"));
    // Events arrive one by one, before the site is done; the secret cut across chunks is masked.
    rig.guest.send(&request("GET", "/sse", host, &[], None));
    rig.guest.head();
    assert_eq!(rig.guest.chunk(), b"event: ping\ndata: 1\n\n", "the first event isn't held back");
    rig.release.send(()).unwrap();
    let mut rest = Vec::new();
    loop {
        let chunk = rig.guest.chunk();
        if chunk.is_empty() {
            break;
        }
        rest.extend(chunk);
    }
    assert_eq!(String::from_utf8(rest).unwrap(), format!("data: {MASK}\n\n"));

    // Writes follow the site's policy; a chunked body with Expect arrives whole, and the
    // answer's body is read once the request is done.
    rig.guest.send("POST /submit HTTP/1.1\r\nHost: app.example.com\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\nAuthorization: Bearer guests-own\r\n\r\n");
    assert_eq!(rig.guest.head().status, 100);
    rig.guest.send("6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n");
    let reply = rig.guest.head();
    assert_eq!((reply.status, rig.guest.body(&reply).as_str()), (200, "got hello world"));
    let seen = rig.reached().last().unwrap().clone();
    assert_eq!(seen.body, b"hello world");
    assert_eq!((seen.header("transfer-encoding"), seen.header("expect"), seen.header("authorization")), (Some("chunked"), None, Some(format!("Bearer {SECRET}").as_str())));
    // A body with a length, and a HEAD, go through the same connection.
    let (reply, body) = rig.guest.post(host, "/submit", &[], "x".repeat(40_000).as_str());
    assert_eq!((reply.status, body.len()), (200, 4 + 40_000));
    assert_eq!(rig.reached().last().unwrap().header("content-length"), Some("40000"));
    rig.guest.send(&request("HEAD", "/plain", host, &[], None));
    let reply = rig.guest.head();
    assert_eq!((reply.status, reply.head.header("content-length")), (200, Some("10")));
    assert_eq!(rig.guest.get(host, "/plain", &[]).1, "plain page");

    // A compressed answer can't be masked, so it isn't passed on.
    let (reply, body) = rig.guest.get(host, "/gzip", &[]);
    assert_eq!(reply.status, 502);
    assert!(body.contains("can't mask"), "{body}");
    assert!(rig.guest.closed());
    rig.finish();

    // An answer that ends with the connection is masked and ends the guest's connection too.
    let mut rig = Rig::new(sh, host);
    rig.guest.send(&request("GET", "/close", host, &[], None));
    let reply = rig.guest.head();
    assert_eq!(reply.head.header("connection"), Some("close"));
    assert_eq!(rig.guest.body(&reply), format!("closing {MASK}"));
    let (up, down) = rig.finish();
    assert_eq!((up, down), (0, format!("closing {SECRET}").len() as u64));

    // A guest that speaks HTTP/1.0 can't take chunks: the masked answer ends with the connection.
    let mut rig = Rig::new(sh, host);
    rig.guest.send("GET /echo HTTP/1.0\r\nHost: app.example.com\r\n\r\n");
    let reply = rig.guest.head();
    assert_eq!((reply.head.header("transfer-encoding"), reply.head.header("connection")), (None, Some("close")));
    assert_eq!(rig.guest.body(&reply), format!("token is {MASK} ok"));
    rig.finish();

    // Nothing the door sent back anywhere holds the secret.
    let mut rig = Rig::new(sh, host);
    rig.guest.get(host, "/echo", &[]);
    rig.guest.get(host, "/split", &[]);
    assert!(!String::from_utf8_lossy(&rig.guest.seen).contains(SECRET));
    rig.finish();

    // A read-only site refuses writes in its own words; reads carry its credential.
    let ro = "ro.example.com";
    let mut rig = Rig::new(sh, ro);
    let (reply, body) = rig.guest.post(ro, "/submit", &[], "x");
    assert_eq!(reply.status, 403);
    assert!(body.contains("the policy for readonly doesn't allow POST") && !body.contains("allow_writes"), "{body}");
    assert!(rig.reached().is_empty());
    rig.guest.get(ro, "/plain", &[]);
    assert_eq!(rig.reached()[0].header("authorization"), Some(format!("Bearer {SECRET}").as_str()));
    rig.finish();

    site_asks(sh, yes);

    // A site whose policy isn't approved gets no credentials, and its writes follow [net].
    let pending = "pending.example.com";
    let mut rig = Rig::new(sh, pending);
    rig.guest.get(pending, "/plain", &[("Authorization", "Bearer guests-own")]);
    let seen = rig.reached()[0].clone();
    assert_eq!((seen.header("authorization"), seen.header("x-client")), (Some("Bearer guests-own"), None));
    assert_eq!(rig.guest.post(pending, "/submit", &[], "x").0.status, 403);
    let (_, body) = rig.guest.get(pending, "/echo", &[]);
    assert!(body.contains(SECRET), "nothing is masked for it: the agent's own values are its own");
    assert!(rig.finish_asked().is_empty());

    // A site approved a moment ago and revoked since covers nothing (policies are read per request).
    policy::revoke("readonly").unwrap();
    let mut rig = Rig::new(sh, ro);
    rig.guest.get(ro, "/plain", &[]);
    assert_eq!(rig.reached()[0].header("authorization"), None);
    rig.finish();
}

/// A site whose policy asks (`askme`, `[fetch] writes = "ask"`): Touch ID's answer decides, whatever
/// the door's `[box.approval] write` is, which covers `[net]` only.
fn site_asks(sh: &Arc<Shared>, yes: bool) {
    let ask = "ask.example.com";
    let mut rig = Rig::new(sh, ask);
    let (reply, body) = rig.guest.post(ask, "/submit?id=1", &[], "data");
    if yes {
        assert_eq!((reply.status, body.as_str()), (200, "got data"));
        assert_eq!(rig.reached().len(), 1);
    } else {
        assert_eq!(reply.status, 403);
        assert!(body.contains("wasn't approved"), "{body}");
        assert!(rig.reached().is_empty());
        assert_eq!(rig.guest.get(ask, "/plain", &[]).0.status, 200, "the connection goes on");
    }
    assert_eq!(rig.finish_asked(), [yes], "one prompt for the one write, none for reads");
}

/// The site closes connections the door keeps for it; the door makes a new one, once, and only
/// when nothing of an answer has arrived.
fn the_site_closes_idle_connections(sh: &Arc<Shared>) {
    // Hosts of a site that allows writes, so a request with a body can be sent again too.
    let host = "app.example.com";
    let mut rig = Rig::new(sh, host);
    assert_eq!(rig.connects(), 0, "the door connects when a request needs it");
    assert_eq!(rig.guest.get(host, "/once", &[]).1, "plain page");
    assert_eq!(rig.connects(), 1);
    let (reply, body) = rig.guest.get(host, "/plain", &[]);
    assert_eq!((reply.status, body.as_str()), (200, "plain page"), "the next request goes over a new connection");
    assert_eq!(rig.connects(), 2);
    assert_eq!(rig.reached().len(), 2);
    // A body that was kept is sent again, with the site's credential, in the framing it came in.
    assert_eq!(rig.guest.get(host, "/once", &[]).0.status, 200);
    let (reply, body) = rig.guest.post(host, "/submit", &[], "payload");
    assert_eq!((reply.status, body.as_str()), (200, "got payload"));
    assert_eq!(rig.connects(), 3);
    let seen = rig.reached();
    assert_eq!(seen.iter().filter(|s| s.target() == "/submit").count(), 1, "it reached the site once: the first try died with the connection");
    assert_eq!(seen.last().unwrap().header("authorization"), Some(format!("Bearer {SECRET}").as_str()));
    assert_eq!(rig.guest.get(host, "/once", &[]).0.status, 200);
    rig.guest.send("POST /submit HTTP/1.1\r\nHost: app.example.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n");
    let reply = rig.guest.head();
    assert_eq!((reply.status, rig.guest.body(&reply).as_str()), (200, "got abcdef"));
    assert_eq!(rig.connects(), 4);

    // A body too big to have been kept isn't sent again: the request fails.
    assert_eq!(rig.guest.get(host, "/once", &[]).0.status, 200);
    let big = "x".repeat(RETRY_BODY + 1);
    let (reply, body) = rig.guest.post(host, "/submit", &[], &big);
    assert_eq!(reply.status, 502, "{body}");
    assert!(body.contains("couldn't send"), "{body}");
    assert_eq!(rig.connects(), 4, "no new connection for a request that can't be sent again");
    assert!(rig.guest.closed());
    rig.finish();

    // Once any of an answer has arrived, nothing is sent again.
    let mut rig = Rig::new(sh, host);
    assert_eq!(rig.guest.get(host, "/plain", &[]).0.status, 200);
    let (reply, body) = rig.guest.get(host, "/partial", &[]);
    assert_eq!(reply.status, 502, "{body}");
    assert_eq!(rig.reached().iter().filter(|s| s.target() == "/partial").count(), 1);
    assert_eq!(rig.connects(), 1);
    rig.finish();

    // A connection that can't be made is a 502, and a refused request needs none at all.
    let mut rig = Rig::new(sh, host);
    rig.unreachable.store(true, Ordering::SeqCst);
    let (reply, body) = rig.guest.get(host, "/plain", &[]);
    assert_eq!(reply.status, 502);
    assert!(body.contains("couldn't connect"), "{body}");
    rig.finish();
    let mut rig = Rig::new(sh, "web.example.com");
    assert_eq!(rig.guest.post("web.example.com", "/submit", &[], "x").0.status, 403);
    assert_eq!(rig.connects(), 0, "a refused request never reaches the site, not even to connect");
    rig.finish();
}

/// `[net] writes = "ask"` on a host no site covers.
fn net_asks(sh: &Arc<Shared>, yes: bool) {
    let host = "web.example.com";
    let mut rig = Rig::new(sh, host);
    let (reply, body) = rig.guest.post(host, "/submit?token=sekrit&q=1", &[], "data");
    assert_eq!(reply.status, if yes { 200 } else { 403 }, "{body}");
    assert_eq!(rig.reached().len(), usize::from(yes));
    assert_eq!(rig.guest.get(host, "/plain", &[]).0.status, 200);
    assert_eq!(rig.finish_asked(), [yes]);
}

/// `[net] writes = "ask"` with `[box.approval] write = "none"`: the write passes and nothing is asked.
fn net_asks_nothing(sh: &Arc<Shared>) {
    let host = "web.example.com";
    let mut rig = Rig::new(sh, host);
    let (reply, body) = rig.guest.post(host, "/submit", &[], "data");
    assert_eq!(reply.status, 200, "{body}");
    assert_eq!(rig.reached().len(), 1);
    assert!(rig.finish_asked().is_empty(), "nothing was asked");
}

/// With nothing on this system that can approve it, a write `[net]` asks about is refused, saying so.
fn net_cannot_ask(sh: &Arc<Shared>) {
    let host = "web.example.com";
    let mut rig = Rig::new(sh, host);
    let (reply, body) = rig.guest.post(host, "/submit", &[], "data");
    assert_eq!(reply.status, 403, "{body}");
    assert!(body.contains("wasn't approved: a write the box's policy says to ask about needs an approval this system can't give"), "{body}");
    assert!(rig.reached().is_empty());
    assert!(rig.finish_asked().is_empty(), "nothing was asked");
}

/// `[net] writes = "allow"`: everything passes, and the log says so.
fn net_allows(sh: &Arc<Shared>) {
    let host = "web.example.com";
    let mut rig = Rig::new(sh, host);
    assert_eq!(rig.guest.post(host, "/submit", &[], "data").1, "got data");
    rig.guest.send(&request("DELETE", "/x", host, &[], None));
    assert_eq!(rig.guest.head().status, 404);
    // A WebSocket can't be carried, even where writes are allowed.
    let (reply, body) = rig.guest.get(host, "/socket", &[("Connection", "Upgrade"), ("Upgrade", "websocket")]);
    assert_eq!(reply.status, 501, "{body}");
    let ((up, down), asked) = rig.end();
    assert_eq!((up, down), (4, 8));
    assert!(asked.is_empty());
}

/// One line per request, chained, with the URL masked; an edit or a deletion shows.
fn the_log_chains_check(dir: &Path, name: &str, lines: usize) {
    let chain = Chain::new(&dir.join(format!("{name}.log")), LOG_KEY);
    let found = chain.verify().unwrap();
    assert_eq!(found.unchained, 0);
    assert_eq!(found.chained, lines);
}

fn the_log_chains(dir: &Path, yes: bool) {
    the_log_chains_check(dir, "deny", fs::read_to_string(dir.join("deny.log")).unwrap().lines().count());
    let text = fs::read_to_string(dir.join("deny.log")).unwrap();
    assert!(!text.contains(SECRET) && !text.contains("guests-own") && !text.to_lowercase().contains("authorization"), "{text}");
    let lines = log_lines(dir, "deny");
    let find = |method: &str, decision: &str, host: &str| {
        lines.iter().find(|l| l["method"] == method && l["decision"] == decision && l["host"] == host).unwrap_or_else(|| panic!("no {method} {decision} {host} in {text}"))
    };
    let read = find("GET", "allowed", "web.example.com");
    assert_eq!(read["kind"], "request");
    assert_eq!(read["status"], 200);
    assert_eq!(read["url"], format!("https://web.example.com/plain?token={MASK}"), "the query's token is masked");
    assert!(read["time"].is_string());
    let refused = find("POST", "blocked:writes", "web.example.com");
    assert_eq!((refused["status"].clone(), refused["url"].clone()), (json!(403), json!("https://web.example.com/submit")));
    assert_eq!(find("GET", "blocked:host-mismatch", "web.example.com")["status"], 421);
    assert_eq!(find("POST", "blocked:writes", "pending.example.com")["status"], 403, "an unapproved site's writes follow [net]");
    assert_eq!(find("POST", "blocked:writes", "ro.example.com")["status"], 403);
    assert_eq!(find("GET", "blocked:encoded", "app.example.com")["status"], 502);
    assert_eq!(find("GET", "allowed", "app.example.com")["url"], format!("https://app.example.com/echo?api_key={MASK}"), "a key in a query is masked");
    assert!(lines.iter().any(|l| l["host"] == "app.example.com" && l["method"] == "POST" && l["up"] == 11 && l["down"] == 15), "bytes up and down are the request's own");
    assert_eq!(find("POST", if yes { "asked:yes" } else { "asked:no" }, "ask.example.com")["method"], "POST");
    assert!(lines.iter().any(|l| l["host"] == "free.example.com" && l["decision"] == "allowed" && l["method"] == "POST"));
    assert_eq!(find("GET", "blocked:writes", "web.example.com")["url"], "https://web.example.com/plain", "an upgrade is refused as a write");
    the_log_chains_check(dir, "ask", 2);
    the_log_chains_check(dir, "allow", 3);
    // `[box.approval] write`: none lets the write through unasked; with no means here it is refused.
    let decisions = ["none", "nowhere", "sudo", "passphrase"].map(|name| log_lines(dir, name).iter().map(|l| l["decision"].clone()).collect::<Vec<_>>());
    assert_eq!(decisions, [vec![json!("allowed")], vec![json!("asked:no")], vec![json!("asked:no")], vec![json!("asked:no")]]);
    // A site's own `writes = "ask"` was asked about on both, and answered as Touch ID said.
    for name in ["site-none", "site-nowhere"] {
        let posts: Vec<_> = log_lines(dir, name).iter().filter(|l| l["method"] == "POST").map(|l| l["decision"].clone()).collect();
        assert_eq!(posts, [json!(if yes { "asked:yes" } else { "asked:no" })], "{name}");
    }

    // Changing a line shows, wherever it is; so does taking one out of the middle.
    let path = dir.join("deny.log");
    let original = fs::read_to_string(&path).unwrap();
    let chain = Chain::new(&path, LOG_KEY);
    let mut edited: Vec<String> = original.lines().map(str::to_string).collect();
    let target = edited.iter().position(|l| l.contains("blocked:writes")).unwrap();
    edited[target] = edited[target].replace("blocked:writes", "allowed");
    fs::write(&path, edited.join("\n") + "\n").unwrap();
    let e = chain.verify().unwrap_err().to_string();
    assert!(e.contains(&format!("line {}", target + 1)), "{e}");

    let mut missing: Vec<&str> = original.lines().collect();
    let middle = missing.len() / 2;
    missing.remove(middle);
    fs::write(&path, missing.join("\n") + "\n").unwrap();
    let e = chain.verify().unwrap_err().to_string();
    assert!(e.contains(&format!("line {}", middle + 1)), "{e}");
    fs::write(&path, &original).unwrap();
    chain.verify().unwrap();
    assert!(Chain::new(&path, [1; 32]).verify().is_err(), "only the box's key verifies it");
}

// --- a box an open workspace runs ---

/// The prompt here, saying one thing every time it is asked.
struct Saying(Prompted);

impl Prompt for Saying {
    fn ask(&self, _reason: &str, _withdrawn: &dyn Fn() -> bool) -> Prompted {
        self.0
    }
}

/// The prompt here, saying yes every time, and noting what it was asked.
#[derive(Default)]
struct Noting(Mutex<Vec<String>>);

impl Prompt for Noting {
    fn ask(&self, reason: &str, _withdrawn: &dyn Fn() -> bool) -> Prompted {
        self.0.lock().unwrap().push(reason.to_string());
        Prompted::Yes
    }
}

/// A site's own `ask` (`askme`), in a box an open workspace runs, raises a request. Where there is
/// Touch ID it asks where the box runs, though `[box.approval] write` says none, which covers
/// `[net]` only; elsewhere nothing asks, and another terminal answers it.
fn site_raises(dir: &Path) {
    let noting = Arc::new(Noting::default());
    let desk = Desk::new("mac-1".into(), "acme".into(), requests::LIMITS, noting.clone());
    let sh = shared_raising_with(dir, "site-raises", Some(Means::None), &desk, &["app", "readonly", "askme", "pending"]);
    let host = "ask.example.com";
    let touch_id = cfg!(target_os = "macos");
    let answered = (!touch_id).then(|| answering(&desk, true));
    let mut rig = Rig::new(&sh, host);
    let (reply, body) = rig.guest.post(host, "/submit?id=1", &[], "data");
    assert_eq!((reply.status, body.as_str()), (200, "got data"));
    assert_eq!(rig.reached().len(), 1);
    assert!(rig.finish_asked().is_empty(), "nothing asked on the door's own thread");
    let answered = answered.map(|answered| answered.join().unwrap());
    let asked = noting.0.lock().unwrap().clone();
    if touch_id {
        assert_eq!(asked, ["let box acme/dev send POST https://ask.example.com/submit?id=1"]);
    } else {
        assert!(asked.is_empty(), "{asked:?}");
    }
    let line = log_lines(dir, "site-raises").remove(0);
    assert_eq!((line["decision"].clone(), line["by"].clone()), (json!("asked:yes"), json!("local")));
    assert_eq!(line["request"].as_str().map(str::len), Some(32));
    if let Some(answered) = answered {
        assert_eq!(line["request"], json!(answered));
    }
}

/// A door whose box an open workspace runs, with no sites: its writes follow `[net]`, which asks,
/// approved by `ask`, and raise requests on `desk`.
fn shared_raising(dir: &Path, name: &str, ask: Option<Means>, desk: &Arc<Desk>) -> Arc<Shared> {
    shared_raising_with(dir, name, ask, desk, &[])
}

/// The same, with these sites.
fn shared_raising_with(dir: &Path, name: &str, ask: Option<Means>, desk: &Arc<Desk>, sites: &[&str]) -> Arc<Shared> {
    let config = Config {
        name: "acme/dev".into(),
        socket: dir.join("unused.sock"),
        port: None,
        allow: vec!["*".into()],
        model: None,
        sites: sites.iter().map(|site| site.to_string()).collect(),
        net: Net { writes: Mode::Ask, allow_writes: Vec::new(), ask },
        log: dir.join(format!("{name}.log")),
        log_key: LOG_KEY,
        browser: None,
        ca: None,
        browser_socket: None,
        browser_tokens: Default::default(),
        requests: Some(desk.asker("dev", RunId([7; 8]))),
    };
    Arc::new(Shared::new(config, Dial::system()).unwrap())
}

/// Answers the next request that waits on `desk`, as another terminal would; its id.
fn answering(desk: &Arc<Desk>, yes: bool) -> JoinHandle<String> {
    let desk = desk.clone();
    thread::spawn(move || {
        let deadline = std::time::Instant::now() + WAIT;
        loop {
            if let Some(bytes) = desk.records().pop() {
                let id = Record::decode(&bytes).unwrap().id.hex();
                let said = desk.answer_here(yes, &answer_digest(&bytes, yes));
                assert_eq!(said, if yes { Here::Approved } else { Here::Denied });
                return id;
            }
            assert!(std::time::Instant::now() < deadline, "no request was raised");
            thread::sleep(Duration::from_millis(10));
        }
    })
}

#[test]
fn a_write_of_a_box_an_open_workspace_runs_waits_as_a_request() {
    let dir = TempDir::new("halti-inspect-requests").unwrap();
    let host = "web.example.com";
    // Nothing here asks (Linux): the request waits for another terminal's answer.
    let desk = Desk::new("mac-1".into(), "acme".into(), requests::LIMITS, Arc::new(Saying(Prompted::Unshown)));
    let sh = shared_raising(&dir.0, "nowhere", None, &desk);
    let mut rig = Rig::new(&sh, host);
    let yes = answering(&desk, true);
    let (reply, body) = rig.guest.post(host, "/submit?token=sekrit", &[], "data");
    assert_eq!((reply.status, body.as_str()), (200, "got data"));
    let approved = yes.join().unwrap();
    let no = answering(&desk, false);
    let (reply, body) = rig.guest.post(host, "/submit", &[], "data");
    assert_eq!((reply.status, body.as_str()), (403, "halti: POST https://web.example.com/submit wasn't approved\n"));
    let denied = no.join().unwrap();
    assert_eq!(rig.reached().len(), 1, "a denied write never reaches the site");
    assert!(rig.finish_asked().is_empty(), "nothing asked on the door's own thread");
    let lines = log_lines(&dir.0, "nowhere");
    let posts: Vec<(Value, Value, Value)> = lines.iter().map(|l| (l["decision"].clone(), l["by"].clone(), l["request"].clone())).collect();
    assert_eq!(posts, [(json!("asked:yes"), json!("local"), json!(approved)), (json!("asked:no"), json!("local"), json!(denied))]);
    assert_eq!(lines[0]["url"], format!("https://web.example.com/submit?token={MASK}"));

    // Touch ID here (a Mac): it answers, and the request names who did.
    let desk = Desk::new("mac-1".into(), "acme".into(), requests::LIMITS, Arc::new(Saying(Prompted::Yes)));
    let sh = shared_raising(&dir.0, "touchid", Some(Means::TouchId), &desk);
    let mut rig = Rig::new(&sh, host);
    assert_eq!(rig.guest.post(host, "/submit", &[], "data").0.status, 200);
    rig.finish();
    let line = log_lines(&dir.0, "touchid").remove(0);
    assert_eq!((line["decision"].clone(), line["by"].clone()), (json!("asked:yes"), json!("local")));
    assert_eq!(line["request"].as_str().map(str::len), Some(32));
    // `none` lets it through and raises nothing.
    let sh = shared_raising(&dir.0, "none", Some(Means::None), &desk);
    let mut rig = Rig::new(&sh, host);
    assert_eq!(rig.guest.post(host, "/submit", &[], "data").0.status, 200);
    rig.finish();
    let line = log_lines(&dir.0, "none").remove(0);
    assert_eq!((line["decision"].clone(), line["by"].clone(), line["request"].clone()), (json!("allowed"), Value::Null, Value::Null));
}

#[test]
fn a_request_nobody_answers_or_one_too_many_is_refused_saying_why() {
    let dir = TempDir::new("halti-inspect-unanswered").unwrap();
    let host = "web.example.com";
    let limits = requests::Limits { wait: Duration::from_secs(1), per_box: 1, ..requests::LIMITS };
    let desk = Desk::new("mac-1".into(), "acme".into(), limits, Arc::new(Saying(Prompted::Unshown)));
    let sh = shared_raising(&dir.0, "unanswered", None, &desk);
    let mut rig = Rig::new(&sh, host);
    let (reply, body) = rig.guest.post(host, "/submit", &[], "data");
    assert_eq!((reply.status, body.as_str()), (403, "halti: POST https://web.example.com/submit wasn't approved: nobody answered within 1 seconds\n"));
    rig.finish();
    // One waits already: the next is refused at once, and raises nothing.
    let waits = desk.asker("dev", RunId([7; 8]));
    let waiting = thread::spawn(move || waits.raise("POST https://web.example.com/other", false, &|| false));
    while desk.records().is_empty() {
        thread::sleep(Duration::from_millis(10));
    }
    let mut rig = Rig::new(&sh, host);
    let (reply, body) = rig.guest.post(host, "/submit", &[], "data");
    assert_eq!((reply.status, body.as_str()), (403, "halti: POST https://web.example.com/submit wasn't approved: box acme/dev has 1 requests waiting already\n"));
    rig.finish();
    desk.close();
    assert_eq!(waiting.join().unwrap().came, requests::Came::Withdrawn);
    let lines = log_lines(&dir.0, "unanswered");
    let decisions: Vec<(Value, Value)> = lines.iter().map(|l| (l["decision"].clone(), l["by"].clone())).collect();
    assert_eq!(decisions, [(json!("asked:no"), Value::Null), (json!("blocked:requests"), Value::Null)]);
    assert!(lines[0]["request"].is_string() && lines[1]["request"].is_null());
}

#[test]
fn a_write_when_the_workspace_has_as_many_waiting_as_it_may_says_it_is_the_workspaces() {
    let dir = TempDir::new("halti-inspect-workspace-full").unwrap();
    let host = "web.example.com";
    let limits = requests::Limits { per_desk: 1, ..requests::LIMITS };
    let desk = Desk::new("mac-1".into(), "acme".into(), limits, Arc::new(Saying(Prompted::Unshown)));
    // Another box's request waits; this box has none.
    let waits = desk.asker("web", RunId([8; 8]));
    let waiting = thread::spawn(move || waits.raise("POST https://web.example.com/other", false, &|| false));
    while desk.records().is_empty() {
        thread::sleep(Duration::from_millis(10));
    }
    let sh = shared_raising(&dir.0, "full", None, &desk);
    let mut rig = Rig::new(&sh, host);
    let (reply, body) = rig.guest.post(host, "/submit", &[], "data");
    assert_eq!((reply.status, body.as_str()), (403, "halti: POST https://web.example.com/submit wasn't approved: box acme/dev's workspace has 1 requests waiting already\n"));
    rig.finish();
    desk.close();
    assert_eq!(waiting.join().unwrap().came, requests::Came::Withdrawn);
    let line = log_lines(&dir.0, "full").remove(0);
    assert_eq!((line["decision"].clone(), line["by"].clone(), line["request"].clone()), (json!("blocked:requests"), Value::Null, Value::Null));
}

// --- a client that gives up while its request waits ---

/// Answers the next request that waits on `desk`, `after` it was raised.
fn answering_after(desk: &Arc<Desk>, yes: bool, after: Duration) -> JoinHandle<String> {
    let desk = desk.clone();
    thread::spawn(move || {
        let deadline = std::time::Instant::now() + WAIT;
        let bytes = loop {
            if let Some(bytes) = desk.records().pop() {
                break bytes;
            }
            assert!(std::time::Instant::now() < deadline, "no request was raised");
            thread::sleep(Duration::from_millis(10));
        };
        thread::sleep(after);
        assert_eq!(desk.answer_here(yes, &answer_digest(&bytes, yes)), if yes { Here::Approved } else { Here::Denied });
        Record::decode(&bytes).unwrap().id.hex()
    })
}

/// Waits until `check` holds, for `WAIT` at most.
fn until(check: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + WAIT;
    while !check() {
        assert!(std::time::Instant::now() < deadline, "it never happened");
        thread::sleep(Duration::from_millis(10));
    }
}

/// `n` bytes in which a piece out of place, lost or sent twice shows.
fn patterned(n: usize) -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            b'a' + (x >> 24) as u8 % 26
        })
        .collect()
}

#[test]
fn a_client_that_hangs_up_while_its_request_waits_sends_nothing_and_costs_nothing() {
    let dir = TempDir::new("halti-inspect-gave-up").unwrap();
    let host = "web.example.com";
    // One request a box at most, and one strike rests it for an hour: the next write shows both.
    let limits = requests::Limits { per_box: 1, strikes: 1, rest: Duration::from_secs(3600), ..requests::LIMITS };
    let desk = Desk::new("mac-1".into(), "acme".into(), limits, Arc::new(Saying(Prompted::Unshown)));
    let sh = shared_raising(&dir.0, "gave-up", None, &desk);
    let mut rig = Rig::new(&sh, host);
    rig.guest.send(&request("POST", "/submit", host, &[], Some("data")));
    until(|| desk.records().len() == 1);
    rig.guest.stream.shutdown(Shutdown::Both).unwrap();
    until(|| desk.records().is_empty());
    let (seen, connects) = (rig.seen.clone(), rig.connects.clone());
    rig.finish();
    assert!(seen.lock().unwrap().is_empty(), "nothing reached the site");
    assert_eq!(connects.load(Ordering::SeqCst), 0, "the site was never even dialed");
    let line = log_lines(&dir.0, "gave-up").remove(0);
    assert_eq!((line["decision"].clone(), line["status"].clone(), line["by"].clone()), (json!("withdrawn:client gave up"), Value::Null, Value::Null));
    assert_eq!(line["request"].as_str().map(str::len), Some(32));

    // No strike was counted and the box's one place is free: the next write waits and goes.
    let yes = answering(&desk, true);
    let mut rig = Rig::new(&sh, host);
    let (reply, body) = rig.guest.post(host, "/submit", &[], "again");
    assert_eq!((reply.status, body.as_str()), (200, "got again"));
    yes.join().unwrap();
    rig.finish();
}

/// The prompt where the box runs: it hangs up the client, then says yes.
struct HangsUpThenYes(Mutex<Option<UnixStream>>);

impl Prompt for HangsUpThenYes {
    fn ask(&self, _reason: &str, _withdrawn: &dyn Fn() -> bool) -> Prompted {
        // The door is asleep between its looks by then.
        thread::sleep(Duration::from_millis(250));
        if let Some(client) = self.0.lock().unwrap().take() {
            client.shutdown(Shutdown::Both).unwrap();
        }
        Prompted::Yes
    }
}

#[test]
fn a_client_that_hangs_up_just_before_its_approval_sends_nothing() {
    let dir = TempDir::new("halti-inspect-gave-up-approved").unwrap();
    let host = "web.example.com";
    let prompt = Arc::new(HangsUpThenYes(Mutex::new(None)));
    let desk = Desk::new("mac-1".into(), "acme".into(), requests::LIMITS, prompt.clone());
    let sh = shared_raising(&dir.0, "gave-up-approved", Some(Means::TouchId), &desk);
    let mut rig = Rig::new(&sh, host);
    *prompt.0.lock().unwrap() = Some(rig.guest.stream.try_clone().unwrap());
    rig.guest.send(&request("POST", "/submit", host, &[], Some("data")));
    until(|| desk.records().len() == 1);
    until(|| desk.records().is_empty());
    let (seen, connects) = (rig.seen.clone(), rig.connects.clone());
    rig.finish();
    assert!(seen.lock().unwrap().is_empty(), "nothing reached the site");
    assert_eq!(connects.load(Ordering::SeqCst), 0);
    let line = log_lines(&dir.0, "gave-up-approved").remove(0);
    // It was approved, and the look made then found the client gone.
    assert_eq!((line["decision"].clone(), line["by"].clone()), (json!("withdrawn:client gave up"), json!("local")));
}

#[test]
fn an_approved_write_arrives_whole_though_its_body_is_more_than_the_door_reads_ahead() {
    let dir = TempDir::new("halti-inspect-big-body").unwrap();
    let host = "web.example.com";
    let desk = Desk::new("mac-1".into(), "acme".into(), requests::LIMITS, Arc::new(Saying(Prompted::Unshown)));
    let sh = shared_raising(&dir.0, "big-body", None, &desk);
    let mut rig = Rig::new(&sh, host);
    let body = patterned(5 * LOOK_AHEAD + 123);
    let yes = answering_after(&desk, true, Duration::from_millis(600));
    // The client sends it all at once, as far as the socket takes it, while the request waits.
    let mut client = rig.guest.stream.try_clone().unwrap();
    let sent = body.clone();
    let sending = thread::spawn(move || {
        client.write_all(format!("POST /upload HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n", sent.len()).as_bytes()).unwrap();
        client.write_all(&sent).unwrap();
    });
    let reply = rig.guest.head();
    assert_eq!(reply.status, 404, "the site's own answer");
    rig.guest.body(&reply);
    sending.join().unwrap();
    yes.join().unwrap();
    let reached = rig.reached();
    assert_eq!(reached.len(), 1);
    assert!(reached[0].body == body, "the body arrived whole, in order, once: {} bytes of {}", reached[0].body.len(), body.len());
    rig.finish();
}

#[test]
fn a_body_sent_slowly_while_its_request_waits_arrives_whole() {
    let dir = TempDir::new("halti-inspect-slow-body").unwrap();
    let host = "web.example.com";
    let desk = Desk::new("mac-1".into(), "acme".into(), requests::LIMITS, Arc::new(Saying(Prompted::Unshown)));
    let sh = shared_raising(&dir.0, "slow-body", None, &desk);
    let mut rig = Rig::new(&sh, host);
    let body = patterned(40_000);
    let yes = answering_after(&desk, true, Duration::from_millis(900));
    rig.guest.send(&format!("POST /upload HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n"));
    // In pieces of every size, some before the answer and some after.
    for piece in body.chunks(3_001) {
        rig.guest.stream.write_all(format!("{:x}\r\n", piece.len()).as_bytes()).unwrap();
        rig.guest.stream.write_all(piece).unwrap();
        rig.guest.stream.write_all(b"\r\n").unwrap();
        thread::sleep(Duration::from_millis(80));
    }
    rig.guest.send("0\r\n\r\n");
    let reply = rig.guest.head();
    assert_eq!(reply.status, 404);
    rig.guest.body(&reply);
    yes.join().unwrap();
    let reached = rig.reached();
    assert_eq!(reached.len(), 1);
    assert!(reached[0].body == body, "the body arrived whole, in order, once: {} bytes of {}", reached[0].body.len(), body.len());
    rig.finish();
}

// --- the site's connection, after a long wait ---

#[test]
fn a_first_connection_that_sat_unused_too_long_is_dialed_again() {
    let dir = TempDir::new("halti-inspect-stale").unwrap();
    let host = "web.example.com";
    let desk = Desk::new("mac-1".into(), "acme".into(), requests::LIMITS, Arc::new(Saying(Prompted::Unshown)));
    let sh = shared_raising(&dir.0, "stale", None, &desk);
    // The site closes a connection unused for 200 ms; the request waits 500 ms for its answer.
    let idle = Duration::from_millis(200);
    let wait = Duration::from_millis(500);

    // Used though it is older than that, the first connection is gone: the request fails.
    let mut rig = Rig::with_first(&sh, host, Some((Duration::from_secs(60), idle)));
    let yes = answering_after(&desk, true, wait);
    let (reply, body) = rig.guest.post(host, "/submit", &[], "data");
    assert_eq!(reply.status, 502, "{body}");
    yes.join().unwrap();
    assert_eq!(rig.connects(), 1);
    rig.finish();

    // Dropped once it is older than its time, a new one is dialed and the request goes.
    let mut rig = Rig::with_first(&sh, host, Some((Duration::from_millis(100), idle)));
    let yes = answering_after(&desk, true, wait);
    let (reply, body) = rig.guest.post(host, "/submit", &[], "data");
    assert_eq!((reply.status, body.as_str()), (200, "got data"));
    yes.join().unwrap();
    assert_eq!(rig.connects(), 2);
    assert_eq!(rig.reached().len(), 1);
    rig.finish();

    // A request answered at once uses the first connection.
    let mut rig = Rig::with_first(&sh, host, Some((Duration::from_secs(60), Duration::from_secs(60))));
    let yes = answering(&desk, true);
    assert_eq!(rig.guest.post(host, "/submit", &[], "data").0.status, 200);
    yes.join().unwrap();
    assert_eq!(rig.connects(), 1);
    rig.finish();
}
