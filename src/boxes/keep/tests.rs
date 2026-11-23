//! The keeper through its socket: a fake engine (`Fake`, which is the `World` and the `Vms`), real
//! stores (hdiutil, so a Mac's) and a real socket in a short folder under /tmp, since a socket's
//! path is short. Each box started here makes a store of its own, as a box that keeps nothing does.

use std::any::Any;
use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;

use halti_core::ids::WsId;

use super::*;
use crate::engine::VmSpec;
use crate::requests::{Asker, By, Came, Prompt, Prompted, Raised, Record, Trusted, answer_digest};
use crate::ws::boxes::{put_away_left, stop_others};
use crate::{chain, door};

const IMAGE: &str = "agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TAG: [u8; 16] = [0x5e; 16];
/// Long enough for a store to be made, opened and put away.
const LONG: Duration = Duration::from_secs(60);

/// VMs as a set of names, and what was done to them.
#[derive(Default)]
struct Fake {
    up: Mutex<BTreeSet<String>>,
    calls: Mutex<Vec<String>>,
    /// A site that isn't ready.
    unready: Option<&'static str>,
    /// How long a VM takes to start, and to stop.
    slow_start: Duration,
    slow_stop: Duration,
    /// What each door it started raises its requests through.
    askers: Mutex<Vec<Option<Asker>>>,
}

impl Fake {
    fn note(&self, call: String) {
        self.calls.lock().unwrap().push(call);
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn up(&self) -> BTreeSet<String> {
        self.up.lock().unwrap().clone()
    }

    /// Noted as it begins; up once it has taken its time.
    fn start(&self, name: &str) {
        self.note(format!("start {name}"));
        thread::sleep(self.slow_start);
        self.up.lock().unwrap().insert(name.to_string());
    }

    fn stop(&self, name: &str) {
        thread::sleep(self.slow_stop);
        self.note(format!("stop {name}"));
        self.up.lock().unwrap().remove(name);
    }
}

impl World for Fake {
    fn confirm(&self, _reason: &str) -> Result<()> {
        bail!("a box of an open workspace asks nothing")
    }

    fn available(&self) -> Result<()> {
        Ok(())
    }

    fn running(&self, vm: &str) -> bool {
        self.up.lock().unwrap().contains(vm)
    }

    fn start_vm(&self, spec: &VmSpec) -> Result<()> {
        self.start(&spec.name);
        Ok(())
    }

    fn stop_vm(&self, vm: &str) {
        self.stop(vm);
    }

    fn start_door(&self, cfg: door::Config) -> Result<Box<dyn Any>> {
        self.askers.lock().unwrap().push(cfg.requests);
        Ok(Box::new(()))
    }

    fn browser_image(&self) -> Result<String> {
        bail!("no browser here")
    }

    fn install_ca(&self, _vm: &str, _pem: &str) -> Result<()> {
        Ok(())
    }

    fn start_docker(&self, _vm: &str) -> Result<()> {
        Ok(())
    }

    fn model_uses_bearer(&self, _model: &str) -> Result<bool> {
        Ok(false)
    }

    fn site_ready(&self, site: &str) -> Result<()> {
        if self.unready == Some(site) {
            bail!("{site} isn't approved");
        }
        Ok(())
    }

    fn key(&self, _name: &str) -> Result<String> {
        bail!("no box here keeps a store")
    }

    fn record_sessions(&self, _name: &str, _sites: &[String]) -> Result<()> {
        Ok(())
    }

    fn record_log_head(&self, _name: &str, _head: &chain::Head) -> Result<()> {
        Ok(())
    }

    fn exec(&self, _vm: &str, _env: &[(String, String)], _cmd: &[String], _tty: bool) -> Result<ExitStatus> {
        bail!("the keeper runs no agent's command")
    }

    fn takes_disk(&self) -> bool {
        false
    }

    fn pipe(&self, _vm: &str, _cmd: &[String], _input: &[u8]) -> Result<Vec<u8>> {
        bail!("the keeper runs no agent's command")
    }
}

impl Vms for Fake {
    fn available(&self) -> Result<()> {
        Ok(())
    }

    fn running(&self, name: &str) -> bool {
        self.up.lock().unwrap().contains(name)
    }

    fn run(&self, spec: &VmSpec) -> Result<()> {
        self.start(&spec.name);
        Ok(())
    }

    fn stop(&self, name: &str) -> Result<()> {
        Fake::stop(self, name);
        Ok(())
    }

    fn exec(&self, _name: &str, _env: &[(String, String)], _cmd: &[String], _tty: bool) -> Result<ExitStatus> {
        bail!("the keeper runs no agent's command")
    }

    fn install_ca(&self, _name: &str, _pem: &str) -> Result<()> {
        Ok(())
    }

    fn start_docker(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    fn image_digest(&self, _reference: &str) -> Result<String> {
        bail!("no images here")
    }

    fn takes_disk(&self) -> bool {
        false
    }

    fn pipe(&self, _name: &str, _cmd: &[String], _input: &[u8]) -> Result<Vec<u8>> {
        bail!("the keeper runs no agent's command")
    }
}

/// A folder under /tmp, short enough for the sockets in it; removed when dropped.
struct Short(PathBuf);

impl Short {
    fn new() -> Short {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let dir = PathBuf::from(format!("/tmp/hk-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::SeqCst)));
        let _ = fs::remove_dir_all(&dir);
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Short(dir)
    }
}

impl Drop for Short {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn acme() -> WsName {
    WsName::parse("acme").unwrap()
}

/// A box that keeps nothing between runs, with these lines too.
fn policy(extra: &str) -> (Vec<u8>, BoxPolicy) {
    let text = format!("image = \"{IMAGE}\"\nkeep = false\n{extra}");
    let policy = BoxPolicy::parse_in(&text, &MountRule::Workspace(Vec::new())).unwrap();
    (text.into_bytes(), policy)
}

/// The prompt here where there is none, as on Linux: it says nothing.
struct Nobody;

impl Prompt for Nobody {
    fn ask(&self, _reason: &str, _withdrawn: &dyn Fn() -> bool) -> Prompted {
        Prompted::Unshown
    }
}

/// A workspace's boxes in a short folder, and what its keeper is given.
struct Bench {
    dir: Short,
    fake: Fake,
    close: AtomicBool,
    /// When the keys were wiped: the VMs that ran then.
    wiped: Mutex<Option<BTreeSet<String>>>,
    /// The workspace's files went back, until the keeper is told so; and how often it looked.
    went_back: AtomicBool,
    looked: AtomicUsize,
    /// The requests its boxes wait on.
    desk: Arc<Desk>,
    /// The devices this machine trusts.
    trusted: Mutex<Vec<Trusted>>,
    /// What the agents' MCP sessions came to, in order (`serve_agent`).
    agents: Mutex<Vec<String>>,
}

impl Bench {
    fn new(fake: Fake) -> Bench {
        let desk = Desk::new("mac-1".into(), "acme".into(), requests::LIMITS, Arc::new(Nobody));
        Bench {
            dir: Short::new(),
            fake,
            close: AtomicBool::new(false),
            wiped: Mutex::new(None),
            went_back: AtomicBool::new(false),
            looked: AtomicUsize::new(0),
            desk,
            trusted: Mutex::default(),
            agents: Mutex::default(),
        }
    }

    fn trust(&self, name: &str) -> Option<Trusted> {
        self.trusted.lock().unwrap().iter().find(|trusted| trusted.name == name).cloned()
    }

    fn layout(&self) -> Layout {
        Layout::under_workspace(&self.dir.0, WsId::from_bytes(TAG)).unwrap()
    }

    fn socket(&self) -> PathBuf {
        self.layout().keeper_socket().unwrap()
    }

    /// The agent's VM of box `name`.
    fn vm(&self, name: &str) -> String {
        self.layout().vm(name)
    }

    /// What keeps acme open, with these boxes, each with these lines in its policy: any other
    /// name has no box.
    fn keep(&self, boxes: &[(&'static str, &'static str)]) -> Keep {
        let layout = self.layout();
        layout.prepare().unwrap();
        let lock = store::lock(&layout.keeper_lock()).unwrap().unwrap();
        let known: BTreeMap<&str, &str> = boxes.iter().copied().collect();
        let check = move |name: &str| -> Result<Checked, Refused> {
            let Some(extra) = known.get(name) else { return Err(Refused::new(No::Box, anyhow!("there is no box acme/{name}"))) };
            let (text, policy) = policy(extra);
            Ok(Checked { text, policy })
        };
        let names: Vec<String> = boxes.iter().map(|(name, _)| name.to_string()).collect();
        let (left_in, others_in) = (self.layout(), self.layout());
        Keep {
            name: acme(),
            lock,
            layout,
            mounts: MountRule::Workspace(Vec::new()),
            vms: None,
            settings: Settings::builtin(crate::ws::OS),
            check: Box::new(check),
            left: Box::new(move |vms| put_away_left(&left_in, vms, &names)),
            others: Box::new(move |vms| stop_others(&others_in, vms)),
        }
    }

    /// Keeps acme open with these boxes while `test` runs, with an engine or none; `test` closes it.
    fn keeping(&self, boxes: &[(&'static str, &'static str)], engine: bool, test: impl FnOnce(&Path) + Send) -> Result<u8> {
        let keep = self.keep(boxes);
        let ready = |_: &str, _: &str, _: &Checked| Ok(());
        let wipe = || *self.wiped.lock().unwrap() = Some(self.fake.up());
        let refused = || {
            self.looked.fetch_add(1, Ordering::SeqCst);
            self.went_back.swap(false, Ordering::SeqCst)
        };
        let outside = Outside {
            world: engine.then_some(&self.fake as &dyn World),
            vms: engine.then_some(&self.fake as &dyn Vms),
            ready: &ready,
            close: &self.close,
            wipe: &wipe,
            refused: &refused,
            desk: &self.desk,
            trust: &|name| self.trust(name),
            mcp: &|reading, writing, ended| self.serve_agent(reading, writing, &ended),
        };
        let socket = self.socket();
        thread::scope(|scope| {
            let keeper = scope.spawn(|| serve_with(keep, &outside));
            // A test that fails closes it too, and so fails rather than waits for ever.
            let _closes = Closes(&self.close);
            let deadline = Instant::now() + LONG;
            while keep::ask(&socket, &Request::Ping(acme()), keep::PING_WAIT).is_none() {
                assert!(Instant::now() < deadline && !keeper.is_finished(), "the keeper never listened");
                thread::sleep(Duration::from_millis(20));
            }
            test(&socket);
            keeper.join().unwrap()
        })
    }
}

impl Bench {
    /// What the keeper serves an agent here, in place of MCP: each line back, marked. `ask` stands
    /// for a Touch ID window, which stays up until the session's flag withdraws it. `fail` ends the
    /// session with an error while a reader still holds the connection, as `mcp::serve_io`'s may.
    /// As it ends it waits a moment, then notes whether the keys were wiped by then.
    fn serve_agent(&self, reading: UnixStream, mut writing: UnixStream, ended: &AtomicBool) -> Result<()> {
        let note = |what: &str| self.agents.lock().unwrap().push(format!("{what}, keys wiped: {}", self.wiped.lock().unwrap().is_some()));
        let mut lines = BufReader::new(reading.try_clone()?).lines();
        let served = loop {
            let Some(Ok(line)) = lines.next() else { break Ok(()) };
            match line.as_str() {
                "ask" => {
                    note("asked");
                    // Up as long as a test may wait; one never withdrawn says so, and ends.
                    let up = Instant::now() + Duration::from_secs(10);
                    while !ended.load(Ordering::SeqCst) && Instant::now() < up {
                        thread::sleep(Duration::from_millis(20));
                    }
                    note(if ended.load(Ordering::SeqCst) { "withdrawn" } else { "never withdrawn" });
                }
                "fail" => {
                    let mut reading = reading;
                    thread::spawn(move || reading.read(&mut [0u8; 8]));
                    break Err(anyhow!("the line isn't UTF-8"));
                }
                line => {
                    if writeln!(writing, "served {line}").is_err() {
                        break Ok(());
                    }
                }
            }
        };
        thread::sleep(Duration::from_millis(300));
        note("ended");
        served
    }

    fn agents(&self) -> Vec<String> {
        self.agents.lock().unwrap().clone()
    }
}

/// What the keeper serves an agent where no test sends one.
fn no_agent(_reading: UnixStream, _writing: UnixStream, _ended: Arc<AtomicBool>) -> Result<()> {
    bail!("no agent is served here")
}

/// Sets the flag when dropped.
struct Closes<'a>(&'a AtomicBool);

impl Drop for Closes<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn ask(socket: &Path, request: Request) -> Option<Reply> {
    keep::ask(socket, &request, LONG)
}

/// A `start` held open: its reply, and the session.
fn session(socket: &Path, name: &str) -> (Reply, UnixStream) {
    let mut stream = keep::connect(socket).unwrap();
    keep::write_line(&mut stream, &Request::Start(acme(), name.into()).line()).unwrap();
    let reply = keep::read_line(&mut stream, LONG).and_then(|line| Reply::parse(&line)).unwrap();
    (reply, stream)
}

/// An agent's MCP session: its reply, and the connection.
fn mcp_session(socket: &Path) -> (Reply, UnixStream) {
    let mut stream = keep::connect(socket).unwrap();
    keep::write_line(&mut stream, &Request::Mcp(acme()).line()).unwrap();
    let reply = keep::read_line(&mut stream, LONG).and_then(|line| Reply::parse(&line)).unwrap();
    (reply, stream)
}

/// What the keeper says on a session when its box is put away.
fn said_on(stream: &mut UnixStream) -> Option<Reply> {
    keep::read_line(stream, LONG).and_then(|line| Reply::parse(&line))
}

fn running(socket: &Path) -> Option<Reply> {
    ask(socket, Request::Ping(acme()))
}

/// Waits until `check` holds, or a minute passes.
fn until(check: impl Fn() -> bool) {
    let deadline = Instant::now() + LONG;
    while !check() {
        assert!(Instant::now() < deadline, "it never happened");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn an_agent_s_mcp_session_is_served_until_the_workspace_closes_and_the_keys_are_wiped_after() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[], false, |socket| {
        let (said, mut agent) = mcp_session(socket);
        assert_eq!(said, Reply::Serving);
        let (second, _other_agent) = mcp_session(socket);
        assert_eq!(second, Reply::Serving);
        // Longer than a line may take to come: a session has no time limit.
        thread::sleep(keep::LINE_WAIT + Duration::from_secs(1));
        agent.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n").unwrap();
        assert_eq!(keep::read_line(&mut agent, LONG).as_deref(), Some("served {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"));
        // Another workspace's name is served nothing.
        assert_eq!(ask(socket, Request::Mcp(WsName::parse("globex").unwrap())), Some(Reply::Other));
        assert_eq!(running(socket), Some(Reply::Open(0)), "a session runs no box");
        assert!(bench.wiped.lock().unwrap().is_none());
        // A close ends both sessions, then wipes the keys, then answers.
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
        assert!(bench.wiped.lock().unwrap().is_some());
        assert_eq!(bench.agents(), ["ended, keys wiped: false", "ended, keys wiped: false"]);
        // A socket whose peer has closed it refuses the option on a Mac.
        let _ = agent.set_read_timeout(Some(LONG));
        assert_eq!(agent.read(&mut [0u8; 8]).unwrap(), 0, "the session ended");
    });
    assert_eq!(code.unwrap(), 0);
    assert!(!bench.socket().exists());
}

#[test]
fn a_close_withdraws_what_an_agent_s_session_asks_before_the_keys_are_wiped() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[], false, |socket| {
        let (said, mut agent) = mcp_session(socket);
        assert_eq!(said, Reply::Serving);
        agent.write_all(b"ask\n").unwrap();
        until(|| !bench.agents().is_empty());
        // The close doesn't wait for the window to be answered or to time out: it takes it down.
        let asked = Instant::now();
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
        assert!(asked.elapsed() < Duration::from_secs(10), "{:?}", asked.elapsed());
        assert_eq!(bench.agents(), ["asked, keys wiped: false", "withdrawn, keys wiped: false", "ended, keys wiped: false"]);
    });
    assert_eq!(code.unwrap(), 0);
}

#[test]
fn a_session_that_fails_ends_for_its_agent_too_and_frees_its_place() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[], false, |socket| {
        let (said, mut agent) = mcp_session(socket);
        assert_eq!(said, Reply::Serving);
        agent.write_all(b"fail\n").unwrap();
        // Its reader still holds the connection, and the agent is told it is over all the same.
        agent.set_read_timeout(Some(LONG)).unwrap();
        assert_eq!(agent.read(&mut [0u8; 8]).unwrap(), 0, "the session ended");
        until(|| bench.agents().len() == 1);
        assert_eq!(bench.agents(), ["ended, keys wiped: false"]);
        // The workspace stays open, and the place is free again.
        let (said, _again) = mcp_session(socket);
        assert_eq!(said, Reply::Serving);
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
}

#[test]
fn an_agent_that_leaves_ends_its_mcp_session_and_frees_its_place() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[], false, |socket| {
        let mut held: Vec<UnixStream> = (0..SESSIONS)
            .map(|_| mcp_session(socket))
            .map(|(said, agent)| {
                assert_eq!(said, Reply::Serving);
                agent
            })
            .collect();
        // As many sessions as an open workspace takes: one more is refused.
        assert_eq!(mcp_session(socket).0, Reply::Full);
        assert_eq!(ask(socket, Request::Start(acme(), "dev".into())), Some(Reply::Full));
        // One leaves: its place is free again.
        drop(held.pop());
        until(|| {
            let (said, _agent) = mcp_session(socket);
            said == Reply::Serving
        });
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn two_boxes_run_in_one_keeper_and_stop_apart() {
    let bench = Bench::new(Fake::default());
    let (dev, web) = (bench.vm("dev"), bench.vm("web"));
    let code = bench.keeping(&[("dev", ""), ("web", "")], true, |socket| {
        let (dev_said, mut dev_session) = session(socket, "dev");
        let (web_said, _web_session) = session(socket, "web");
        assert_eq!((dev_said, web_said), (Reply::Started, Reply::Started));
        assert_eq!(running(socket), Some(Reply::Open(2)));
        assert_eq!(bench.fake.up(), BTreeSet::from([dev.clone(), web.clone()]));
        // One is stopped; the other runs on.
        assert_eq!(ask(socket, Request::Stop(acme(), "dev".into())), Some(Reply::Stopped));
        assert_eq!(said_on(&mut dev_session), Some(Reply::Stopped));
        assert_eq!(bench.fake.up(), BTreeSet::from([web.clone()]));
        assert_eq!(running(socket), Some(Reply::Open(1)));
        assert_eq!(ask(socket, Request::Stop(acme(), "dev".into())), Some(Reply::Idle));
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(1)));
    });
    assert_eq!(code.unwrap(), 0);
    assert!(bench.fake.up().is_empty());
    for name in ["dev", "web"] {
        assert!(!store::is_mounted(&bench.layout().mount_point(name)) && !bench.layout().ephemeral_bundle(name).exists(), "{name} is put away");
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn a_box_stops_when_its_last_session_leaves_and_a_second_keeps_it_running() {
    let bench = Bench::new(Fake::default());
    let dev = bench.vm("dev");
    let code = bench.keeping(&[("dev", "")], true, |socket| {
        let (first, first_session) = session(socket, "dev");
        let (second, second_session) = session(socket, "dev");
        assert_eq!((first, second), (Reply::Started, Reply::Running));
        // The first leaves: the second keeps it running.
        drop(first_session);
        thread::sleep(Duration::from_millis(500));
        assert!(bench.fake.up().contains(&dev));
        assert_eq!(running(socket), Some(Reply::Open(1)));
        // The last leaves: it is put away.
        drop(second_session);
        until(|| running(socket) == Some(Reply::Open(0)) && !bench.layout().ephemeral_bundle("dev").exists());
        assert!(bench.fake.up().is_empty());
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
    assert_eq!(bench.fake.calls().iter().filter(|call| **call == format!("start {dev}")).count(), 1, "started once");
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn a_start_while_stopping_is_busy() {
    let bench = Bench::new(Fake { slow_stop: Duration::from_secs(2), ..Fake::default() });
    let code = bench.keeping(&[("dev", "")], true, |socket| {
        let (said, mut session_of_dev) = session(socket, "dev");
        assert_eq!(said, Reply::Started);
        let stopping = thread::scope(|scope| {
            let stopping = scope.spawn(|| ask(socket, Request::Stop(acme(), "dev".into())));
            thread::sleep(Duration::from_millis(500));
            assert_eq!(ask(socket, Request::Start(acme(), "dev".into())), Some(Reply::Busy));
            assert_eq!(ask(socket, Request::Stop(acme(), "dev".into())), Some(Reply::Busy));
            stopping.join().unwrap()
        });
        assert_eq!(stopping, Some(Reply::Stopped));
        assert_eq!(said_on(&mut session_of_dev), Some(Reply::Stopped));
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
}

#[test]
fn a_failed_start_says_the_word_and_prints_the_reason() {
    let bench = Bench::new(Fake { unready: Some("github"), ..Fake::default() });
    let code = bench.keeping(&[("dev", "sites = [\"github\"]\n"), ("web", "")], true, |socket| {
        // The kind of each refusal, and the site's name; nothing was started.
        assert_eq!(ask(socket, Request::Start(acme(), "dev".into())), Some(Reply::No(No::Site("github".into()))));
        assert_eq!(ask(socket, Request::Start(acme(), "nobox".into())), Some(Reply::No(No::Box)));
        assert_eq!(running(socket), Some(Reply::Open(0)));
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
    assert!(bench.fake.calls().iter().all(|call| !call.starts_with("start ")), "{:?}", bench.fake.calls());
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn close_stops_every_box_then_answers_and_the_keys_are_wiped_after() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[("dev", ""), ("web", "")], true, |socket| {
        let (_, mut dev) = session(socket, "dev");
        let (_, mut web) = session(socket, "web");
        assert!(bench.wiped.lock().unwrap().is_none());
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(2)));
        // Both sessions were told, and the keys were wiped once no VM ran.
        assert_eq!((said_on(&mut dev), said_on(&mut web)), (Some(Reply::Stopped), Some(Reply::Stopped)));
        assert_eq!(bench.wiped.lock().unwrap().clone(), Some(BTreeSet::new()));
    });
    assert_eq!(code.unwrap(), 0);
    // The socket is gone, and the lock is free.
    assert!(!bench.socket().exists());
    assert!(store::lock(&bench.layout().keeper_lock()).unwrap().is_some());
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn a_signal_closes_as_close_does() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[("dev", "")], true, |socket| {
        let (_, mut dev) = session(socket, "dev");
        // The test's own flag, as a signal sets the process's.
        bench.close.store(true, Ordering::SeqCst);
        assert_eq!(said_on(&mut dev), Some(Reply::Stopped));
    });
    assert_eq!(code.unwrap(), 0);
    assert!(bench.fake.up().is_empty() && !bench.socket().exists());
    assert_eq!(bench.wiped.lock().unwrap().clone(), Some(BTreeSet::new()));
    assert!(store::lock(&bench.layout().keeper_lock()).unwrap().is_some());
}

#[test]
fn leftovers_are_put_away_before_listening() {
    let bench = Bench::new(Fake::default());
    let layout = bench.layout();
    layout.prepare().unwrap();
    // A halti that died left dev's VMs running and a store made for its run; web left nothing.
    for name in ["dev", "web"] {
        fs::write(layout.lock(name), "").unwrap();
    }
    fs::create_dir_all(layout.ephemeral_bundle("dev")).unwrap();
    bench.fake.up.lock().unwrap().extend([layout.vm("dev"), layout.browser_vm("dev")]);
    let code = bench.keeping(&[("dev", ""), ("web", "")], true, |socket| {
        assert!(bench.fake.up().is_empty() && !layout.ephemeral_bundle("dev").exists(), "put away before anything listened");
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
    // A box whose lock is held is another halti's, and nothing of it is touched.
    fs::create_dir_all(layout.ephemeral_bundle("dev")).unwrap();
    let held = store::lock(&layout.lock("dev")).unwrap().unwrap();
    assert!(put_away_left(&layout, &bench.fake, &["dev".into(), "web".into()]).is_empty());
    drop(held);
    assert_eq!(put_away_left(&layout, &bench.fake, &["dev".into(), "web".into()]), ["dev"]);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn a_box_another_halti_runs_is_elsewhere_and_close_stops_it() {
    let bench = Bench::new(Fake::default());
    let layout = bench.layout();
    layout.prepare().unwrap();
    let dev = layout.vm("dev");
    let code = bench.keeping(&[("dev", "")], true, |socket| {
        // Another halti holds dev, and runs its VM; it lets go once its VM is stopped.
        let held = store::lock(&layout.lock("dev")).unwrap().unwrap();
        bench.fake.up.lock().unwrap().insert(dev.clone());
        assert_eq!(ask(socket, Request::Start(acme(), "dev".into())), Some(Reply::Elsewhere));
        thread::scope(|scope| {
            scope.spawn(|| {
                until(|| !bench.fake.up().contains(&dev));
                drop(held);
            });
            assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(1)));
        });
    });
    assert_eq!(code.unwrap(), 0);
    assert!(bench.fake.up().is_empty() && store::lock(&layout.lock("dev")).unwrap().is_some());
}

#[test]
fn close_stops_a_box_of_another_terminal_whose_vm_comes_up_while_it_waits() {
    let bench = Bench::new(Fake::default());
    let layout = bench.layout();
    layout.prepare().unwrap();
    let dev = layout.vm("dev");
    let code = bench.keeping(&[("dev", "")], true, |socket| {
        // Another halti holds dev and is still starting it: its VM comes up only once the close
        // waits for it to let go, and then it lets go once its VM is stopped.
        let held = store::lock(&layout.lock("dev")).unwrap().unwrap();
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_secs(1));
                bench.fake.up.lock().unwrap().insert(dev.clone());
                until(|| !bench.fake.up().contains(&dev));
                drop(held);
            });
            assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(1)));
        });
    });
    assert_eq!(code.unwrap(), 0);
    assert!(bench.fake.up().is_empty() && store::lock(&layout.lock("dev")).unwrap().is_some());
}

#[test]
fn a_box_of_another_terminal_that_holds_on_leaves_the_workspace_not_closed() {
    let bench = Bench::new(Fake::default());
    let layout = bench.layout();
    layout.prepare().unwrap();
    // Another halti holds dev, and never lets go.
    let _held = store::lock(&layout.lock("dev")).unwrap().unwrap();
    let code = bench.keeping(&[("dev", "")], true, |socket| {
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    // Its keys are wiped and its socket is gone, but it isn't said to be closed.
    assert_eq!(code.unwrap(), 1);
    assert!(bench.wiped.lock().unwrap().is_some() && !bench.socket().exists());
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn close_waits_for_a_box_that_is_still_starting_and_a_start_during_close_is_refused() {
    let bench = Bench::new(Fake { slow_start: Duration::from_secs(2), ..Fake::default() });
    let dev = bench.vm("dev");
    let code = bench.keeping(&[("dev", ""), ("web", "")], true, |socket| {
        thread::scope(|scope| {
            let starting = scope.spawn(|| session(socket, "dev"));
            // Its VM is starting when the close comes.
            until(|| !bench.fake.calls().is_empty());
            let closing = scope.spawn(|| ask(socket, Request::Close(acme())));
            thread::sleep(Duration::from_millis(300));
            assert_eq!(ask(socket, Request::Start(acme(), "web".into())), Some(Reply::Busy));
            // The start ends once its VM is up, cut short by the close: no agent gets in, and
            // everything it opened is put away before the close is answered.
            assert_eq!(starting.join().unwrap().0, Reply::Busy);
            assert_eq!(closing.join().unwrap(), Some(Reply::Closed(0)));
            assert_eq!(bench.fake.calls(), [format!("start {dev}"), format!("stop {dev}")]);
            assert!(!store::is_mounted(&bench.layout().mount_point("dev")) && !bench.layout().ephemeral_bundle("dev").exists());
        });
    });
    assert_eq!(code.unwrap(), 0);
    assert!(!bench.layout().ephemeral_bundle("web").exists());
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn the_33rd_session_is_full_and_close_is_still_served() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[("dev", "")], true, |socket| {
        let sessions: Vec<(Reply, UnixStream)> = (0..32).map(|_| session(socket, "dev")).collect();
        assert_eq!(sessions[0].0, Reply::Started);
        assert!(sessions[1..].iter().all(|(said, _)| *said == Reply::Running));
        assert_eq!(ask(socket, Request::Start(acme(), "dev".into())), Some(Reply::Full));
        // Held sessions keep out neither a ping, a stop nor a close.
        assert_eq!(running(socket), Some(Reply::Open(1)));
        assert_eq!(ask(socket, Request::Stop(acme(), "web".into())), Some(Reply::Idle));
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(1)));
        drop(sessions);
    });
    assert_eq!(code.unwrap(), 0);
}

#[test]
fn another_workspace_s_name_is_other_and_nothing_starts() {
    let bench = Bench::new(Fake::default());
    let globex = WsName::parse("globex").unwrap();
    let code = bench.keeping(&[("dev", "")], true, |socket| {
        assert_eq!(ask(socket, Request::Start(globex.clone(), "dev".into())), Some(Reply::Other));
        assert_eq!(ask(socket, Request::Ping(globex.clone())), Some(Reply::Other));
        assert_eq!(ask(socket, Request::Close(globex.clone())), Some(Reply::Other));
        // Nor a line that isn't one.
        let mut stream = keep::connect(socket).unwrap();
        keep::write_line(&mut stream, "halti-keep/2 ping acme\n").unwrap();
        assert_eq!(keep::read_line(&mut stream, LONG).as_deref(), Some("halti-keep/1 unsupported"));
        assert_eq!(running(socket), Some(Reply::Open(0)));
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
    assert!(bench.fake.calls().is_empty());
}

#[test]
fn a_keeper_with_no_engine_opens_and_closes() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[("dev", "")], false, |socket| {
        assert_eq!(ask(socket, Request::Start(acme(), "dev".into())), Some(Reply::No(No::Engine)));
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
    assert!(bench.fake.calls().is_empty() && !bench.socket().exists());
}

#[test]
fn a_second_keeper_never_takes_a_socket_that_answers() {
    let bench = Bench::new(Fake::default());
    let socket = bench.socket();
    bench.layout().prepare().unwrap();
    let _other = keep::bind(&socket).unwrap().unwrap();
    let ready = |_: &str, _: &str, _: &Checked| Ok(());
    let outside = Outside { world: None, vms: None, ready: &ready, close: &bench.close, wipe: &|| {}, refused: &|| false, desk: &bench.desk, trust: &|_| None, mcp: &no_agent };
    let error = serve_with(bench.keep(&[]), &outside).unwrap_err();
    assert_eq!(error.to_string(), "another workspace is open at acme's socket");
    assert!(socket.exists());
}

fn no_box(_: &str) -> Result<Checked, Refused> {
    Err(Refused::new(No::Box, anyhow!("no box here")))
}

fn ready(_: &str, _: &str, _: &Checked) -> Result<(), Refused> {
    Ok(())
}

/// A keeper with no engine and no socket, whose table a test fills itself.
fn bare<'a>(bench: &'a Bench, name: &'a WsName, layout: &'a Layout, mounts: &'a MountRule) -> Keeper<'a> {
    Keeper {
        name,
        layout,
        mounts,
        write: None,
        world: None,
        check: &no_box,
        ready: &ready,
        close: &bench.close,
        table: Mutex::default(),
        changed: Condvar::new(),
        waiting: AtomicUsize::new(0),
        closers: Mutex::default(),
        done: AtomicBool::new(false),
        desk: &bench.desk,
        trust: &|_| None,
        serve_mcp: &no_agent,
    }
}

/// A box that runs, started in `round`, its run named by the round too.
fn running_in(round: u64) -> Slot {
    Slot { round, state: State::Running, sessions: 1, stop: Arc::default(), word: None, run: RunId([round as u8; 8]) }
}

#[test]
fn a_box_is_stopping_as_its_last_session_leaves_or_a_stop_is_asked() {
    let bench = Bench::new(Fake::default());
    let (name, layout, mounts) = (acme(), bench.layout(), MountRule::Workspace(Vec::new()));
    let keeper = bare(&bench, &name, &layout, &mounts);
    let state = |box_name: &str| keeper.table().boxes[box_name].state;
    keeper.table().boxes.insert("dev".into(), running_in(1));
    assert!(!keeper.last_left("dev", 1));
    // Its last session leaves: as the box's thread sees that, the box is stopping, so a start
    // that comes after is busy, and never joins a box that is being put away.
    keeper.leave("dev", 1);
    assert!(keeper.last_left("dev", 1));
    assert_eq!(state("dev"), State::Stopping);
    // A stop: stopping as it is asked, and answered once the box is put away.
    keeper.table().boxes.insert("web".into(), running_in(2));
    thread::scope(|scope| {
        let stopping = scope.spawn(|| keeper.stop_box("web", None));
        until(|| state("web") == State::Stopping);
        assert!(keeper.table().boxes["web"].stop.load(Ordering::SeqCst));
        keeper.table().boxes.remove("web");
        keeper.changed.notify_all();
        assert_eq!(stopping.join().unwrap(), Reply::Stopped);
    });
}

#[test]
fn a_signed_stop_leaves_a_later_run_of_a_box_it_named() {
    let bench = Bench::new(Fake::default());
    let (name, layout, mounts) = (acme(), bench.layout(), MountRule::Workspace(Vec::new()));
    let keeper = bare(&bench, &name, &layout, &mounts);
    let state = |box_name: &str| keeper.table().boxes.get(box_name).map(|slot| (slot.run, slot.state));
    let (dev, web, later_web) = (running_in(1), running_in(2), running_in(3));
    let (dev_run, web_run, later_run) = (dev.run, web.run, later_web.run);
    keeper.table().boxes.insert("dev".into(), dev);
    keeper.table().boxes.insert("web".into(), web);
    thread::scope(|scope| {
        let stopping = scope.spawn(|| Runs::stop(&keeper, &[dev_run, web_run]));
        // While dev is put away, web's run ends by itself and web starts again with a new run.
        until(|| state("dev") == Some((dev_run, State::Stopping)));
        keeper.table().boxes.insert("web".into(), later_web);
        keeper.table().boxes.remove("dev");
        keeper.changed.notify_all();
        until(|| stopping.is_finished() || state("web") != Some((later_run, State::Running)));
        let later = state("web");
        // Let a stop that took the later run end, so the test fails rather than waits.
        if later != Some((later_run, State::Running)) {
            keeper.table().boxes.remove("web");
            keeper.changed.notify_all();
        }
        assert_eq!(stopping.join().unwrap(), 1);
        assert_eq!(later, Some((later_run, State::Running)), "the later run of web was never signed for");
    });
    assert!(!keeper.table().boxes["web"].stop.load(Ordering::SeqCst));
}

#[test]
fn the_33rd_connection_waiting_to_send_is_closed_with_no_answer() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[], false, |socket| {
        // 32 send nothing. Each is taken before the next, so the 33rd finds them all waiting.
        let waiting: Vec<UnixStream> = (0..32).map(|_| keep::connect(socket).unwrap()).collect();
        let mut one_more = keep::connect(socket).unwrap();
        let _ = keep::write_line(&mut one_more, &Request::Ping(acme()).line());
        assert_eq!(keep::read_line(&mut one_more, LONG), None);
        // Once they go, it answers again.
        drop(waiting);
        until(|| running(socket) == Some(Reply::Open(0)));
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
}

#[test]
fn files_that_went_back_are_looked_for_while_open() {
    let bench = Bench::new(Fake::default());
    bench.went_back.store(true, Ordering::SeqCst);
    let code = bench.keeping(&[], false, |socket| {
        // Looked for again and again while it is open; what was found is taken, and said, once.
        until(|| bench.looked.load(Ordering::SeqCst) >= 3);
        assert!(!bench.went_back.load(Ordering::SeqCst));
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
}

/// The one request that waits at the socket: its record and bytes, once it waits.
fn the_one_at(socket: &Path) -> (Record, Vec<u8>) {
    until(|| keep::list(socket, &acme(), LONG).is_some_and(|listed| listed.is_ok_and(|records| records.len() == 1)));
    let bytes = keep::list(socket, &acme(), LONG).unwrap().unwrap().remove(0);
    (Record::decode(&bytes).unwrap(), bytes)
}

#[test]
fn a_request_is_listed_and_answered_on_the_socket_in_records() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[], false, |socket| {
        assert_eq!(keep::list(socket, &acme(), LONG), Some(Ok(Vec::new())));
        let asker = bench.desk.asker("dev", RunId([7; 8]));
        thread::scope(|scope| {
            let raised = scope.spawn(|| asker.raise("POST https://api.example.com/v1/x", false, &|| false));
            let (record, bytes) = the_one_at(socket);
            assert_eq!((record.ws.as_str(), record.box_name.as_str(), record.action.as_str()), ("acme", "dev", "POST https://api.example.com/v1/x"));
            // Another workspace's name does nothing; another decision's digest names nothing.
            let globex = WsName::parse("globex").unwrap();
            assert_eq!(keep::answer(socket, &globex, true, answer_digest(&bytes, true), LONG), Some(Told::Other));
            assert_eq!(keep::list(socket, &globex, LONG), Some(Err(Told::Other)));
            assert_eq!(keep::answer(socket, &acme(), true, answer_digest(&bytes, false), LONG), Some(Told::Gone));
            assert_eq!(keep::answer(socket, &acme(), true, answer_digest(&bytes, true), LONG), Some(Told::Approved));
            assert_eq!(raised.join().unwrap(), Raised { id: Some(record.id), came: Came::Yes(By::Local), wait: requests::LIMITS.wait });
            // The first answer won: the second finds nothing.
            assert_eq!(keep::answer(socket, &acme(), false, answer_digest(&bytes, false), LONG), Some(Told::Gone));
            assert_eq!(keep::list(socket, &acme(), LONG), Some(Ok(Vec::new())));
        });
        // A denial counts at once.
        thread::scope(|scope| {
            let raised = scope.spawn(|| asker.raise("DELETE https://api.example.com/v1/x", false, &|| false));
            let (_, bytes) = the_one_at(socket);
            assert_eq!(keep::answer(socket, &acme(), false, answer_digest(&bytes, false), LONG), Some(Told::Denied));
            assert_eq!(raised.join().unwrap().came, Came::No(By::Local));
        });
        // The lines of names are answered as before.
        assert_eq!(running(socket), Some(Reply::Open(0)));
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
}

#[test]
fn closing_withdraws_the_requests_that_wait() {
    let bench = Bench::new(Fake::default());
    let asker = bench.desk.asker("dev", RunId([7; 8]));
    let came = thread::scope(|scope| {
        let mut raised = None;
        let code = bench.keeping(&[], false, |socket| {
            raised = Some(scope.spawn(|| asker.raise("POST https://api.example.com/v1/x", false, &|| false)));
            the_one_at(socket);
            assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
        });
        assert_eq!(code.unwrap(), 0);
        raised.unwrap().join().unwrap().came
    });
    assert_eq!(came, Came::Withdrawn);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn each_run_s_door_raises_its_requests_on_the_desk_with_a_run_id_of_its_own() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[("dev", "")], true, |socket| {
        let mut runs = Vec::new();
        for _ in 0..2 {
            // The first run's box may still be being put away.
            let (reply, stream) = loop {
                match session(socket, "dev") {
                    (Reply::Busy, _) => thread::sleep(Duration::from_millis(20)),
                    started => break started,
                }
            };
            assert_eq!(reply, Reply::Started);
            let asker = bench.fake.askers.lock().unwrap().last().cloned().flatten().expect("the door was given an asker");
            thread::scope(|scope| {
                let raised = scope.spawn(|| asker.raise("POST https://api.example.com/v1/x", false, &|| false));
                let (record, bytes) = the_one_at(socket);
                assert_eq!(record.shown(), "acme/dev");
                runs.push(record.run);
                assert_eq!(keep::answer(socket, &acme(), true, answer_digest(&bytes, true), LONG), Some(Told::Approved));
                assert_eq!(raised.join().unwrap().came, Came::Yes(By::Local));
            });
            drop(stream);
        }
        assert_ne!(runs[0], runs[1], "a run id is drawn as the box starts");
        // The second run's box may still be being put away, and is counted then.
        assert!(matches!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0 | 1))));
    });
    assert_eq!(code.unwrap(), 0);
}

/// A phone's signing key, and how this machine trusts it, for acme.
fn phone(name: &str) -> (rcgen::KeyPair, Trusted) {
    use rcgen::PublicKeyData;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let spki = key.subject_public_key_info();
    let trusted =
        Trusted { name: name.into(), key: halti_core::device::DeviceKey::from_spki(&spki).unwrap(), fingerprint: crate::hub::wire::fingerprint(&spki), ws: vec!["acme".into()] };
    (key, trusted)
}

fn sign(key: &rcgen::KeyPair, bytes: &[u8]) -> Vec<u8> {
    use rcgen::SigningKey;
    key.sign(bytes).unwrap()
}

#[test]
fn a_signed_answer_counts_on_the_socket_only_from_a_trusted_device() {
    let bench = Bench::new(Fake::default());
    let (pixel, trusted) = phone("pixel");
    let (stranger, _) = phone("stranger");
    bench.trusted.lock().unwrap().push(trusted);
    let code = bench.keeping(&[], false, |socket| {
        let asker = bench.desk.asker("dev", RunId([7; 8]));
        thread::scope(|scope| {
            let raised = scope.spawn(|| asker.raise("POST https://api.example.com/v1/x", false, &|| false));
            let (record, bytes) = the_one_at(socket);
            let line = |device: &str, key: &rcgen::KeyPair| Records::Signed {
                ws: acme(),
                device: device.into(),
                yes: true,
                id: record.id,
                signature: sign(key, &requests::answer_bytes(&bytes, true)),
            };
            assert_eq!(keep::tell(socket, &line("stranger", &stranger), LONG), Some(Told::Refused));
            assert_eq!(keep::tell(socket, &line("pixel", &stranger), LONG), Some(Told::Refused));
            assert_eq!(keep::tell(socket, &line("pixel", &pixel), LONG), Some(Told::Approved));
            assert!(matches!(raised.join().unwrap().came, Came::Yes(By::Device(_))));
            assert_eq!(keep::tell(socket, &line("pixel", &pixel), LONG), Some(Told::Gone));
        });
        assert_eq!(keep::runs(socket, &acme(), LONG), Some(Ok(Vec::new())));
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn a_signed_stop_stops_the_runs_it_names_and_only_those() {
    let bench = Bench::new(Fake::default());
    let (pixel, trusted) = phone("pixel");
    let (stranger, _) = phone("stranger");
    bench.trusted.lock().unwrap().push(trusted);
    let (dev, web) = (bench.vm("dev"), bench.vm("web"));
    let code = bench.keeping(&[("dev", ""), ("web", "")], true, |socket| {
        let (_, mut dev_session) = session(socket, "dev");
        let (_, _web_session) = session(socket, "web");
        let runs = keep::runs(socket, &acme(), LONG).unwrap().unwrap();
        assert_eq!(runs.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(), ["dev", "web"]);
        assert_ne!(runs[0].1, runs[1].1, "each run its own id");
        let (dev_run, web_run) = (runs[0].1, runs[1].1);
        let stop = |key: &rcgen::KeyPair, machine: &str, runs: Vec<(&str, RunId)>| {
            let runs: Vec<(String, RunId)> = runs.into_iter().map(|(name, run)| (name.to_string(), run)).collect();
            Records::Stop { ws: acme(), device: "pixel".into(), signature: sign(key, &crate::hub::wire::stop_bytes(machine, "acme", &runs)), runs }
        };
        let stopped = |stopped, wrong_box| Some(Told::Stopped { stopped, wrong_box });
        // Another key, or signed for another machine's name: nothing stops.
        assert_eq!(keep::tell(socket, &stop(&stranger, "mac-1", vec![("dev", dev_run)]), LONG), Some(Told::Refused));
        assert_eq!(keep::tell(socket, &stop(&pixel, "mac-2", vec![("dev", dev_run)]), LONG), Some(Told::Refused));
        // web's run named as dev's: web runs on.
        assert_eq!(keep::tell(socket, &stop(&pixel, "mac-1", vec![("dev", web_run)]), LONG), stopped(0, 1));
        assert_eq!(bench.fake.up(), BTreeSet::from([dev.clone(), web.clone()]));
        // Signed: the box of that run is put away, and its session told.
        assert_eq!(keep::tell(socket, &stop(&pixel, "mac-1", vec![("dev", dev_run), ("dev", RunId([9; 8]))]), LONG), stopped(1, 0));
        assert_eq!(said_on(&mut dev_session), Some(Reply::Stopped));
        assert_eq!(bench.fake.up(), BTreeSet::from([web.clone()]));
        // Sent again, it stops nothing new, and a later run of dev isn't the one it named.
        assert_eq!(keep::tell(socket, &stop(&pixel, "mac-1", vec![("dev", dev_run)]), LONG), stopped(0, 0));
        assert!(matches!(ask(socket, Request::Close(acme())), Some(Reply::Closed(1))));
    });
    assert_eq!(code.unwrap(), 0);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn a_running_box_is_marked_away_and_its_mark_ends_with_its_run() {
    let bench = Bench::new(Fake::default());
    let code = bench.keeping(&[("dev", "")], true, |socket| {
        // A box that doesn't run has no run to mark; another workspace's name does nothing.
        assert_eq!(ask(socket, Request::Away(acme(), "dev".into(), Some(3600))), Some(Reply::Idle));
        let globex = WsName::parse("globex").unwrap();
        assert_eq!(ask(socket, Request::Away(globex, "dev".into(), Some(3600))), Some(Reply::Other));
        let (said, session) = session(socket, "dev");
        assert_eq!(said, Reply::Started);
        let run = keep::runs(socket, &acme(), LONG).unwrap().unwrap().remove(0).1;
        let Some(Reply::Away(Some(ends))) = ask(socket, Request::Away(acme(), "dev".into(), Some(3600))) else { panic!("not marked") };
        assert!((3599..=3601).contains(&(ends - requests::now_secs())), "{ends}");
        assert_eq!(bench.desk.away_until(run), Some(ends));
        assert_eq!(ask(socket, Request::Away(acme(), "dev".into(), None)), Some(Reply::Away(None)));
        assert_eq!(bench.desk.away_until(run), None);
        // Marked again, it goes when the run ends.
        assert!(matches!(ask(socket, Request::Away(acme(), "dev".into(), Some(600))), Some(Reply::Away(Some(_)))));
        drop(session);
        until(|| running(socket) == Some(Reply::Open(0)));
        until(|| bench.desk.away_until(run).is_none());
        assert_eq!(ask(socket, Request::Close(acme())), Some(Reply::Closed(0)));
    });
    assert_eq!(code.unwrap(), 0);
}
