//! The keeper through its socket: a fake engine (`Fake`, which is the `World` and the `Vms`), real
//! stores (hdiutil, so a Mac's) and a real socket in a short folder under /tmp, since a socket's
//! path is short. Each box started here makes a store of its own, as a box that keeps nothing does.

use std::any::Any;
use std::collections::BTreeSet;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;

use halti_core::ids::WsId;

use super::*;
use crate::engine::VmSpec;
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

    fn start_door(&self, _cfg: door::Config) -> Result<Box<dyn Any>> {
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
}

impl Bench {
    fn new(fake: Fake) -> Bench {
        Bench { dir: Short::new(), fake, close: AtomicBool::new(false), wiped: Mutex::new(None), went_back: AtomicBool::new(false), looked: AtomicUsize::new(0) }
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
    let outside = Outside { world: None, vms: None, ready: &ready, close: &bench.close, wipe: &|| {}, refused: &|| false };
    let error = serve_with(bench.keep(&[]), &outside).unwrap_err();
    assert_eq!(error.to_string(), "another workspace is open at acme's socket");
    assert!(socket.exists());
}

#[test]
fn a_box_is_stopping_as_its_last_session_leaves_or_a_stop_is_asked() {
    let bench = Bench::new(Fake::default());
    let (name, layout, mounts) = (acme(), bench.layout(), MountRule::Workspace(Vec::new()));
    let check = |_: &str| -> Result<Checked, Refused> { Err(Refused::new(No::Box, anyhow!("no box here"))) };
    let ready = |_: &str, _: &str, _: &Checked| Ok(());
    let keeper = Keeper {
        name: &name,
        layout: &layout,
        mounts: &mounts,
        write: None,
        world: None,
        check: &check,
        ready: &ready,
        close: &bench.close,
        table: Mutex::default(),
        changed: Condvar::new(),
        waiting: AtomicUsize::new(0),
        closers: Mutex::default(),
        done: AtomicBool::new(false),
    };
    let running = |round| Slot { round, state: State::Running, sessions: 1, stop: Arc::default(), word: None };
    let state = |box_name: &str| keeper.table().boxes[box_name].state;
    keeper.table().boxes.insert("dev".into(), running(1));
    assert!(!keeper.last_left("dev", 1));
    // Its last session leaves: as the box's thread sees that, the box is stopping, so a start
    // that comes after is busy, and never joins a box that is being put away.
    keeper.leave("dev", 1);
    assert!(keeper.last_left("dev", 1));
    assert_eq!(state("dev"), State::Stopping);
    // A stop: stopping as it is asked, and answered once the box is put away.
    keeper.table().boxes.insert("web".into(), running(2));
    thread::scope(|scope| {
        let stopping = scope.spawn(|| keeper.stop("web"));
        until(|| state("web") == State::Stopping);
        assert!(keeper.table().boxes["web"].stop.load(Ordering::SeqCst));
        keeper.table().boxes.remove("web");
        keeper.changed.notify_all();
        assert_eq!(stopping.join().unwrap(), Reply::Stopped);
    });
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
