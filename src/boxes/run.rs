//! `halti box run`: open the box, start its VM and door, work in it, and put everything away.
//!
//! A run is `start`, then `work` (or `wait`), then `stop`. The order is the point. Opening needs a
//! lock (one halti per open box), the person's yes (as `[box.approval] run` says), the key and the
//! store; then the folders are set up while no VM has them mounted, then the VM and the door start.
//! Ending runs the other way round, in one order whatever ended the box: the VMs stop, then the
//! door, then the store is detached (and deleted, for a box that isn't kept), and the lock goes
//! last (`Running::put_away`). A started box is one value that is put away when it is dropped, so
//! an error, a panic or a signal (see `catch_signals`) unwinds the same way.
//!
//! Everything outside halti (the approval, the engine, the door) is reached through `World`, so the
//! sequence can be tested with fakes while the store is real.

use std::any::Any;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};

use super::browser_vm::BrowserVm;
use super::nofollow;
use super::sessions::{InBox, Launch, Sessions};
use super::store::{self, Layout};
use super::{BoxPolicy, KeyStore, MountPolicy, MountRule, mount_problem_in};
use crate::approval::{self, Action, Means};
use crate::chain::{self, Chain};
use crate::config::Settings;
use crate::engine::{self, Vms};
use crate::index::Index;
use crate::keep::{No, Refused};
use crate::source::{self, BoxItem};
use crate::{door, names, policy, seal};

/// Where the store's folders appear in the VM, and where `ro` folders go.
const GUEST_HOME: &str = "/home/agent";
const GUEST_WORK: &str = "/work";
const GUEST_DOWNLOADS: &str = "/downloads";
const GUEST_MOUNTS: &str = "/mnt";
/// How long to wait for browsers to close and seal their sessions once the agent is gone.
const SETTLE: Duration = Duration::from_secs(30);
/// How often a stop request (a signal) is looked for while the agent works.
const WATCH_EVERY: Duration = Duration::from_millis(100);
/// How often a box that waits looks whether its VM still runs.
const LOOK_EVERY: Duration = Duration::from_secs(2);

/// What a run needs from outside halti.
pub trait World: Sync {
    /// The person's yes to opening the box.
    fn confirm(&self, reason: &str) -> Result<()>;
    fn available(&self) -> Result<()>;
    fn running(&self, vm: &str) -> bool;
    fn start_vm(&self, spec: &engine::VmSpec) -> Result<()>;
    /// Stop a VM; fine if it is gone already.
    fn stop_vm(&self, vm: &str);
    /// Start the door. It stops when the returned value is dropped.
    fn start_door(&self, cfg: door::Config) -> Result<Box<dyn Any>>;
    /// After the agent's command ended and before any VM stops: let the door finish what the end
    /// of the agent's connections sets off (browsers closing, their sessions sealed).
    fn settle(&self, _door: &dyn Any) {}
    /// The pinned reference of the browser image; fails if it isn't built.
    fn browser_image(&self) -> Result<String>;
    /// Make the box's CA trusted inside the VM (as root, before the agent starts).
    fn install_ca(&self, vm: &str, pem: &str) -> Result<()>;
    /// Start Docker Engine in a VM started with `docker` (as root, after the CA, before the agent).
    fn start_docker(&self, vm: &str) -> Result<()>;
    fn model_uses_bearer(&self, model: &str) -> Result<bool>;
    /// Fails unless the site has an approved policy.
    fn site_ready(&self, site: &str) -> Result<()>;
    /// The store key of a kept box.
    fn key(&self, name: &str) -> Result<String>;
    /// Keep the names of the sites that have a sealed session, outside the store, for `halti box ls`.
    fn record_sessions(&self, name: &str, sites: &[String]) -> Result<()>;
    /// Keep where the box's log chain stands, outside the store.
    fn record_log_head(&self, name: &str, head: &chain::Head) -> Result<()>;
    fn exec(&self, vm: &str, env: &[(String, String)], cmd: &[String], tty: bool) -> Result<ExitStatus>;
}

/// The real thing, as the settings say: the engine `[box] engine` picked, where `[box] keys` keeps
/// the key, and `[box.approval] run`.
pub struct Real<'a> {
    pub(super) vms: &'static dyn Vms,
    pub(super) keys: KeyStore,
    pub(super) settings: &'a Settings,
}

impl World for Real<'_> {
    fn confirm(&self, reason: &str) -> Result<()> {
        super::ask_for(&approval::Real, self.settings, Action::BoxRun, reason)
    }

    fn available(&self) -> Result<()> {
        self.vms.available()
    }

    fn running(&self, vm: &str) -> bool {
        self.vms.running(vm)
    }

    fn start_vm(&self, spec: &engine::VmSpec) -> Result<()> {
        self.vms.run(spec)
    }

    fn stop_vm(&self, vm: &str) {
        if let Err(e) = self.vms.stop(vm) {
            crate::util::warn(&format!("stopping {vm}: {e:#}"));
        }
    }

    fn start_door(&self, cfg: door::Config) -> Result<Box<dyn Any>> {
        Ok(Box::new(door::Door::start(cfg)?))
    }

    fn settle(&self, door: &dyn Any) {
        if let Some(door) = door.downcast_ref::<door::Door>() {
            door.wait_idle(SETTLE);
        }
    }

    fn browser_image(&self) -> Result<String> {
        self.vms.image_digest(engine::BROWSER_IMAGE)
    }

    fn install_ca(&self, vm: &str, pem: &str) -> Result<()> {
        self.vms.install_ca(vm, pem)
    }

    fn start_docker(&self, vm: &str) -> Result<()> {
        self.vms.start_docker(vm)
    }

    fn model_uses_bearer(&self, model: &str) -> Result<bool> {
        door::model_uses_bearer(model)
    }

    fn site_ready(&self, site: &str) -> Result<()> {
        policy::load(site)?;
        // A new halti build needs a Keychain prompt per item. It belongs here, while the box opens:
        // in the door it would hold an open connection until the site dropped it.
        let _ = Index::load().map(|index| index.values(site));
        Ok(())
    }

    fn key(&self, name: &str) -> Result<String> {
        self.keys.open_key(name)
    }

    fn record_sessions(&self, name: &str, sites: &[String]) -> Result<()> {
        super::keep_session_names(name, sites)
    }

    fn record_log_head(&self, name: &str, head: &chain::Head) -> Result<()> {
        source::current().set_box_item(name, BoxItem::LogHead, &serde_json::to_string(head)?)
    }

    fn exec(&self, vm: &str, env: &[(String, String)], cmd: &[String], tty: bool) -> Result<ExitStatus> {
        let status = self.vms.exec(vm, env, cmd, tty);
        // `container exec` shares the terminal and may leave it non-blocking.
        crate::util::blocking_stdio();
        status
    }
}

/// One run of a box.
pub struct Request<'a> {
    pub name: &'a str,
    /// What names the VM, socket, lock and mount: the box's name, or a unique one for `--temp`.
    pub id: String,
    pub policy: &'a BoxPolicy,
    /// The SHA-256 of the approved policy text: a join must run under the policy the box opened with.
    pub policy_sha: String,
    /// A kept box, whose store and key last; otherwise a store made for this run and shredded after.
    pub persistent: bool,
    /// The id belongs to this run alone, so its lock file goes with it.
    pub unique: bool,
    /// Run this instead of the policy's `run`.
    pub command: Option<Vec<String>>,
    pub tty: bool,
    /// Set (by a signal) to stop the box.
    pub stop: &'a AtomicBool,
    /// How the door approves a write the box's policy says to ask about (`[box.approval] write`):
    /// read as the box opens, and kept while it runs. None: this system has no means for it.
    pub write: Option<Means>,
    /// The box as messages name it, and the door in a workspace: `dev` today, `acme/dev` in a
    /// workspace.
    pub shown: String,
    /// The command that stops it: `halti box stop dev`, or `halti ws stop acme/dev`.
    pub stop_with: String,
    /// Which folders it may mount: today's guarded folders, or a workspace's rule.
    pub mounts: MountRule,
    /// Whether the person is asked as `[box.approval] run` says: not where opening the workspace
    /// was the approval.
    pub confirm: bool,
}

pub fn vm_name(id: &str) -> String {
    format!("{}{id}", names::BOX_VM_PREFIX)
}

/// The agent's environment: the model's stand-in where it takes a bearer token (`bearer`) or a
/// key, and the policy's stand-ins.
fn agent_env(policy: &BoxPolicy, bearer: bool) -> Vec<(String, String)> {
    let mut env = engine::agent_env(bearer);
    // For tools that won't start without a token; the door adds the real one on the sites' hosts.
    env.extend(policy.standins.iter().map(|name| (name.clone(), door::STANDIN.to_string())));
    env
}

/// Run the box. Returns the exit code of the command inside.
pub fn run(layout: &Layout, world: &dyn World, req: &Request) -> Result<u8> {
    let running = match start(layout, world, req).map_err(|refused| refused.why)? {
        Begun::Here(running) => *running,
        Begun::Elsewhere => return join_open(layout, world, req),
    };
    let status = running.work(req.command.as_deref().unwrap_or(&req.policy.run), req.tty);
    running.stop();
    exit_code(status?)
}

/// Another halti has the box open: work in the same VM, through the same door.
fn join_open(layout: &Layout, world: &dyn World, req: &Request) -> Result<u8> {
    let vm = layout.vm(&req.id);
    if !world.running(&vm) {
        bail!("box {} is being opened or closed by another halti: try again in a moment", req.shown);
    }
    // The door of the open box keeps the rules it started with, so joining under a policy
    // approved since would promise rules nothing enforces.
    if fs::read_to_string(layout.opened_with(&req.id)).ok().as_deref() != Some(req.policy_sha.as_str()) {
        bail!("box {} runs with the policy it was opened with, not the one approved since: stop it ({}) and run it again", req.shown, req.stop_with);
    }
    let bearer = req.policy.model.as_deref().map(|m| world.model_uses_bearer(m)).transpose()?.unwrap_or(false);
    let command = guest_command(req.command.as_deref().unwrap_or(&req.policy.run));
    exit_code(world.exec(&vm, &agent_env(req.policy, bearer), &command, req.tty)?)
}

/// What `start` found.
pub enum Begun<'a> {
    /// Another halti has the box open: join it, or say so.
    Elsewhere,
    Here(Box<Running<'a>>),
}

/// A box that is started, or being started: its lock, store, door and VMs, and the names they go
/// by. It is put away (`put_away`) when it is dropped, so `stop`, a start that fails half way, a
/// panic and a signal all end it in the same order.
pub struct Running<'a> {
    world: &'a dyn World,
    req: &'a Request<'a>,
    vm: String,
    socket: PathBuf,
    mnt: PathBuf,
    log_key: [u8; 32],
    /// The agent's environment.
    env: Vec<(String, String)>,
    /// From just before the agent's VM is started: it may run, and is stopped when the box ends.
    vm_armed: bool,
    /// Set by whoever stopped the agent's VM: the watch in `work`, or `put_away`.
    vm_stopped: AtomicBool,
    /// The start finished: the box ran, so its end is logged and what it kept is noted.
    started: bool,
    browser: Option<Arc<BrowserVm>>,
    door: Option<Box<dyn Any>>,
    /// The box's sealed sessions, read as the box ends.
    sealed: Option<Sessions>,
    store: Option<store::Open>,
    lock: Option<store::Lock>,
    lock_file: PathBuf,
}

/// Open the box: take its lock, clear what a crashed run left, check what it needs, ask (if
/// `req.confirm`), open its store, start its VM and door. A refusal says its kind; whatever was
/// opened by then is put away.
pub fn start<'a>(layout: &'a Layout, world: &'a dyn World, req: &'a Request<'a>) -> Result<Begun<'a>, Refused> {
    layout.prepare()?;
    let Some(lock) = store::lock(&layout.lock(&req.id))? else { return Ok(Begun::Elsewhere) };
    let mut running = Running {
        world,
        req,
        vm: layout.vm(&req.id),
        socket: layout.socket(&req.id),
        mnt: layout.mount_point(&req.id),
        log_key: [0; 32],
        env: Vec::new(),
        vm_armed: false,
        vm_stopped: AtomicBool::new(false),
        started: false,
        browser: None,
        door: None,
        sealed: None,
        store: None,
        lock: Some(lock),
        lock_file: layout.lock(&req.id),
    };
    running.open(layout)?;
    Ok(Begun::Here(Box::new(running)))
}

impl Running<'_> {
    fn open(&mut self, layout: &Layout) -> Result<(), Refused> {
        let (world, req) = (self.world, self.req);
        let vm = self.vm.clone();
        let policy = req.policy;
        fs::write(layout.opened_with(&req.id), &req.policy_sha).with_context(|| format!("noting the policy box {} opens with", req.name))?;

        // Holding the lock, whatever a crashed run left is ours to clear: its VMs too.
        sweep_temp(layout)?;
        sweep(layout, &req.id)?;
        for leftover in [vm.clone(), layout.browser_vm(&req.id)] {
            if world.running(&leftover) {
                world.stop_vm(&leftover);
            }
        }

        world.available().map_err(|why| Refused::new(No::Engine, why))?;
        let image =
            policy.image.as_deref().ok_or_else(|| anyhow!("the policy of box {} names no image (set image = \"{}@sha256:...\" and approve it)", req.shown, names::AGENT_IMAGE))?;
        // A workspace's box names itself in what its model's lookup says; today's keep their words.
        // A model that can't be looked up isn't ready, as a site that isn't.
        let bearer = || -> Result<bool> { Ok(policy.model.as_deref().map(|m| world.model_uses_bearer(m)).transpose()?.unwrap_or(false)) };
        let uses_bearer = match &policy.model {
            Some(model) if layout.in_workspace() => bearer().with_context(|| format!("box {} uses {model}", req.shown)).map_err(not_ready(model))?,
            Some(model) => bearer().map_err(not_ready(model))?,
            None => false,
        };
        self.env = agent_env(policy, uses_bearer);
        for site in policy.model.iter().chain(&policy.sites) {
            world.site_ready(site).with_context(|| format!("box {} uses {site}", req.shown)).map_err(not_ready(site))?;
        }
        let folders = resolve_mounts(&policy.mounts, &req.mounts)?;
        layout.sockets_fit(&req.id)?;

        if req.confirm {
            let sites = if policy.sites.is_empty() { String::new() } else { format!(" and let it use {}", policy.sites.join(", ")) };
            world.confirm(&format!("open box {}{sites}", req.name))?;
            self.unless_stopped()?;
        }
        // What a second terminal needs to join a workspace's box, which reads no approval.
        if layout.in_workspace() {
            fs::write(layout.bearer(&req.id), if uses_bearer { "1" } else { "0" }).with_context(|| format!("noting how box {} reaches its model", req.shown))?;
        }

        let mnt = self.mnt.clone();
        let (bundle, key) = if req.persistent {
            (layout.bundle(req.name), world.key(req.name)?)
        } else {
            let (bundle, key) = (layout.ephemeral_bundle(&req.id), store::new_key()?);
            store::create(layout, &bundle, &key)?;
            (bundle, key)
        };
        self.log_key = super::log_key(&key);
        let mut store = store::open(&bundle, &mnt, &key, false).inspect_err(|_| {
            if !req.persistent {
                let _ = store::shred(&bundle);
            }
        })?;
        if !req.persistent {
            store.shred_on_close();
        }
        self.store = Some(store);
        self.unless_stopped()?;
        let ca = Arc::new(box_ca(&mnt, req.name, &key, req.persistent)?);
        let sessions = Sessions::new(&mnt, &key, policy.browser.keep_sessions);
        self.sealed = Some(Sessions::new(&mnt, &key, true));
        let _ = store::log_event(&mnt, &self.log_key, "box", &req.id, 0, "started");

        // The folders are changed here, while no VM has them.
        for replaced in prepare_home(&mnt, policy.docker).with_context(|| format!("box {}", req.shown))? {
            crate::util::warn(&format!("box {}: {} was a link or a special file, so halti replaced it and followed nothing", req.shown, replaced.display()));
        }
        let mut mounts = vec![
            engine::Mount { host: mnt.join("home"), guest: GUEST_HOME.into(), readonly: false },
            engine::Mount { host: mnt.join("work"), guest: GUEST_WORK.into(), readonly: false },
            engine::Mount { host: mnt.join("downloads"), guest: GUEST_DOWNLOADS.into(), readonly: false },
        ];
        for (mount, host) in &folders {
            if mount.readonly() {
                mounts.push(engine::Mount { host: host.clone(), guest: format!("{GUEST_MOUNTS}/{}", mount.name()), readonly: true });
            } else {
                clone_into(&mnt.join("work"), &mount.name(), host)?;
            }
        }

        let socket = self.socket.clone();
        let _ = fs::remove_file(&socket);

        // The browser VM is made for the box's sites but started by the first runner that asks.
        let browser_socket = layout.browser_socket(&req.id);
        let _ = fs::remove_file(&browser_socket);
        let tokens = door::Tokens::default();
        let (browser_vm, launch): (Option<Arc<BrowserVm>>, Launch) = match (!policy.sites.is_empty()).then(|| world.browser_image()) {
            Some(Ok(image)) => {
                let downloads = policy.browser.downloads.then(|| layout.downloads(req.name));
                let vm = Arc::new(BrowserVm::new(&layout.browser_vm(&req.id), &image, browser_socket.clone(), downloads, ca.cert_pem(), tokens.clone()));
                let runners = vm.clone();
                (Some(vm), Box::new(move |site| runners.runner(site)))
            }
            Some(Err(e)) => {
                let why = format!("{e:#}");
                (None, Box::new(move |_| bail!("the browser VM isn't available: {why}")))
            }
            None => (None, Box::new(|_| bail!("this box has no sites to browse"))),
        };
        let spec = engine::VmSpec {
            name: vm.clone(),
            image: image.to_string(),
            cpus: policy.cpus,
            memory: policy.memory.clone(),
            socket: socket.clone(),
            mounts,
            docker: policy.docker,
            rosetta: policy.rosetta,
        };
        let config = door::Config {
            // A workspace's box is named with its workspace, in the door's answers and the audit log.
            name: if layout.in_workspace() { req.shown.clone() } else { req.id.clone() },
            socket,
            allow: policy.allow(),
            model: policy.model.clone(),
            sites: policy.sites.clone(),
            net: door::inspect::Net { writes: policy.net.writes, allow_writes: policy.net.allow_writes.clone(), ask: req.write },
            log: store::door_log(&mnt),
            ca: Some(ca.clone()),
            log_key: self.log_key,
            browser: Some(Arc::new(InBox::new(sessions, launch, policy.browser.downloads))),
            browser_socket: browser_vm.as_ref().map(|_| browser_socket),
            browser_tokens: tokens,
        };

        self.browser = browser_vm;
        self.vm_armed = true;
        world.start_vm(&spec)?;
        self.unless_stopped()?;
        self.door = Some(world.start_door(config)?);
        world.install_ca(&vm, &ca.cert_pem())?;
        self.unless_stopped()?;
        if policy.docker {
            world.start_docker(&vm)?;
            self.unless_stopped()?;
        }
        self.started = true;
        Ok(())
    }

    /// A stop asked while the box starts (Ctrl-C or a closed terminal, which no longer reach the
    /// steps that wait on a child) ends the start: the agent's command never runs.
    fn unless_stopped(&self) -> Result<(), Refused> {
        if self.req.stop.load(Ordering::SeqCst) {
            return Err(Refused::new(No::Failed, stopped_before_the_agent(&self.req.shown)));
        }
        Ok(())
    }

    /// Run `command` in the box as the agent, with the terminal if `tty`, until it ends. A stop
    /// (`req.stop`) stops the agent's VM, which ends it; one asked already runs nothing.
    pub fn work(&self, command: &[String], tty: bool) -> Result<ExitStatus> {
        let (world, vm, stopped, stop) = (self.world, self.vm.as_str(), &self.vm_stopped, self.req.stop);
        if stop.load(Ordering::SeqCst) {
            return Err(stopped_before_the_agent(&self.req.shown));
        }
        let command = guest_command(command);
        let done = AtomicBool::new(false);
        thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(Ordering::SeqCst) {
                    if stop.load(Ordering::SeqCst) {
                        if !stopped.swap(true, Ordering::SeqCst) {
                            world.stop_vm(vm);
                        }
                        return;
                    }
                    thread::sleep(WATCH_EVERY);
                }
            });
            let status = world.exec(vm, &self.env, &command, tty);
            done.store(true, Ordering::SeqCst);
            status
        })
    }

    /// Keep the box until a stop is asked (`req.stop`), `leave` says to, or its VM is gone (stopped
    /// by hand, say): a box whose agents come and go by other ways in.
    pub fn wait(&self, leave: &dyn Fn() -> bool) {
        let mut looked = Instant::now();
        while !self.req.stop.load(Ordering::SeqCst) && !leave() {
            if looked.elapsed() >= LOOK_EVERY {
                if !self.world.running(&self.vm) {
                    return;
                }
                looked = Instant::now();
            }
            thread::sleep(WATCH_EVERY);
        }
    }

    /// Put the box away (see `put_away`).
    pub fn stop(self) {
        drop(self);
    }

    /// Stop the agent's VM, unless that was done.
    fn stop_vm(&self) {
        if !self.vm_stopped.swap(true, Ordering::SeqCst) {
            self.world.stop_vm(&self.vm);
        }
    }

    /// Everything the box has, in the order it must end. If a stop was asked, the agent is still
    /// connected: its VM stops first, so the browsers its connections kept open close now, rather
    /// than settling waiting for it. Otherwise the agent left by itself, and the door settles first,
    /// with both VMs still up. Then the agent's VM (if it still runs), the browser VM and its
    /// runners, the door, what is kept outside the store, the store, and the lock last.
    fn put_away(&mut self) {
        let (world, req) = (self.world, self.req);
        if self.vm_armed && req.stop.load(Ordering::SeqCst) {
            self.stop_vm();
        }
        if self.started {
            // Browsers the agent left open close now, sealing their sessions, while the VMs they use still run.
            if let Some(door) = &self.door {
                world.settle(door.as_ref());
            }
            let _ = store::log_event(&self.mnt, &self.log_key, "box", &req.id, 0, "stopped");
        }
        if self.vm_armed {
            if !self.vm_stopped.swap(true, Ordering::SeqCst) || world.running(&self.vm) {
                world.stop_vm(&self.vm);
            }
            let _ = fs::remove_file(&self.socket);
        }
        if let Some(browser) = self.browser.take() {
            browser.stop();
        }
        drop(self.door.take());
        if self.started && req.persistent {
            if let Some(sealed) = &self.sealed
                && let Err(e) = world.record_sessions(req.name, &sealed.sites())
            {
                crate::util::warn(&format!("keeping which sites of box {} have a session: {e:#}", req.shown));
            }
            record_head(world, req.name, &req.shown, &self.mnt, self.log_key);
        }
        drop(self.store.take());
        if let Some(lock) = self.lock.take() {
            if req.unique {
                let _ = fs::remove_file(&self.lock_file);
            }
            drop(lock);
        }
    }
}

fn stopped_before_the_agent(shown: &str) -> anyhow::Error {
    anyhow!("box {shown} was stopped before its agent started")
}

/// A refusal for a site (or the model) that isn't ready.
fn not_ready(site: &str) -> impl FnOnce(anyhow::Error) -> Refused + '_ {
    move |why| Refused::new(No::Site(site.to_string()), why)
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.put_away();
    }
}

/// Note where the log's chain stands, so `halti box log --verify` can tell a log whose chain was
/// stripped or whose end was cut off. A log whose chain is already broken keeps the head it had.
/// `shown` is the box as messages name it.
fn record_head(world: &dyn World, name: &str, shown: &str, mnt: &Path, log_key: [u8; 32]) {
    match Chain::new(&store::door_log(mnt), log_key).verify() {
        Ok(found) => {
            if let Some(head) = found.head()
                && let Err(e) = world.record_log_head(name, &head)
            {
                crate::util::warn(&format!("keeping where the log of box {shown} stands: {e:#}"));
            }
        }
        Err(e) => crate::util::warn(&format!("the log of box {shown}: {e:#}")),
    }
}

/// Join a workspace's box that another halti has open, from a second terminal: the engine only.
/// Nothing is asked and nothing is looked up: the policy file must be the one the box opened with
/// (`policy` is its bytes, read once), and how the model is reached is what the opener noted.
#[allow(clippy::too_many_arguments)]
pub fn join(layout: &Layout, vms: &dyn Vms, box_name: &str, shown: &str, mounts: &MountRule, policy: &[u8], command: Option<&[String]>, tty: bool) -> Result<u8> {
    let vm = layout.vm(box_name);
    let busy = || anyhow!("box {shown} is being opened or closed by another halti: try again in a moment");
    if !vms.running(&vm) {
        return Err(busy());
    }
    if fs::read_to_string(layout.opened_with(box_name)).ok().as_deref() != Some(crate::util::sha256_hex(policy).as_str()) {
        bail!("box {shown} runs with the policy it was opened with, and its file has changed since: stop it (halti ws stop {shown}) and run it again");
    }
    let text = std::str::from_utf8(policy).map_err(|_| anyhow!("the policy of box {shown} isn't text"))?;
    let policy = BoxPolicy::parse_in(text, mounts)?;
    let bearer = match fs::read_to_string(layout.bearer(box_name)).ok().as_deref() {
        Some("1") => true,
        Some("0") => false,
        _ => return Err(busy()),
    };
    let command = guest_command(command.unwrap_or(&policy.run));
    let status = vms.exec(&vm, &agent_env(&policy, bearer), &command, tty);
    // `container exec` shares the terminal and may leave it non-blocking.
    crate::util::blocking_stdio();
    exit_code(status?)
}

/// The box's CA, which only its VM trusts. A kept box has it sealed in its store (with a key
/// derived from the box key), made on the first run that needs it, so a box from before the door
/// ended TLS gets one too. A box that isn't kept gets one for this run, in memory only.
fn box_ca(mnt: &Path, name: &str, box_key: &str, persistent: bool) -> Result<door::BoxCa> {
    if !persistent {
        return door::BoxCa::generate(name);
    }
    let key = seal::derive(box_key.as_bytes(), door::CA_PURPOSE);
    let file = store::ca_file(mnt);
    match fs::read(&file) {
        Ok(sealed) => door::BoxCa::from_sealed(&sealed, &key).with_context(|| format!("box {name}'s CA ({})", file.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let ca = door::BoxCa::generate(name)?;
            let tmp = file.with_extension("new");
            let mut out = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            out.write_all(&ca.to_sealed(&key)?)?;
            out.sync_all()?;
            fs::rename(&tmp, &file).with_context(|| format!("saving {}", file.display()))?;
            Ok(ca)
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", file.display())),
    }
}

fn exit_code(status: ExitStatus) -> Result<u8> {
    Ok(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)) as u8)
}

/// The command as the VM runs it: in the work folder, which is where the agent's files are.
fn guest_command(cmd: &[String]) -> Vec<String> {
    let mut full = vec!["sh".to_string(), "-c".to_string(), format!("cd {GUEST_WORK} && exec \"$0\" \"$@\"")];
    full.extend(cmd.iter().cloned());
    full
}

/// The mounts of the policy, checked to be folders that exist and can be shared under `rule`, with
/// their real paths (a link is followed once, here, and the target is what gets checked and mounted).
fn resolve_mounts<'a>(mounts: &'a [MountPolicy], rule: &MountRule) -> Result<Vec<(&'a MountPolicy, PathBuf)>> {
    mounts
        .iter()
        .map(|m| {
            let real = fs::canonicalize(m.host()).map_err(|_| anyhow!("[[mount]] {} doesn't exist", m.path))?;
            if !real.is_dir() {
                bail!("[[mount]] {} isn't a folder", m.path);
            }
            if let Some(why) = mount_problem_in(&real, rule) {
                bail!("[[mount]] {} ({}) {why}", m.path, real.display());
            }
            Ok((m, real))
        })
        .collect()
}

/// Copy a folder into work/<name> the first time. Later runs keep the agent's own copy, even a link
/// in its place, which isn't followed.
fn clone_into(work: &Path, name: &str, host: &Path) -> Result<()> {
    let dst = work.join(name);
    if fs::symlink_metadata(&dst).is_ok() {
        return Ok(());
    }
    match store::copy_tree(host, &dst) {
        Ok(copied) => {
            if copied.skipped > 0 {
                crate::util::warn(&format!("{} links and special files in {} weren't copied", copied.skipped, host.display()));
            }
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&dst);
            Err(e.context(format!("copying {} into the box", host.display())))
        }
    }
}

/// What the agent needs in its home: Claude Code skips its web-fetch check (the door's rules take
/// its place), knows halti's tools, and doesn't stop at first-run screens. Merged into what is
/// there, so what the agent keeps in these files stays. `mnt` is the open store; nothing in its
/// home is reached through a link the agent left there. Returns what was replaced for being a link
/// or a special file.
fn prepare_home(mnt: &Path, docker: bool) -> Result<Vec<PathBuf>> {
    let mut replaced = Vec::new();
    // The Docker CLI hands containers the door's proxy (they can't reach the agent's 127.0.0.1).
    if docker {
        replaced.extend(merge_json(mnt, "home/.docker/config.json", |o| {
            o.insert("proxies".into(), engine::docker_proxies());
        })?);
    }
    replaced.extend(merge_json(mnt, "home/.claude/settings.json", |o| {
        o.insert("skipWebFetchPreflight".into(), json!(true));
    })?);
    // User-scope MCP servers live in ~/.claude.json.
    replaced.extend(merge_json(mnt, "home/.claude.json", |o| {
        o.insert("hasCompletedOnboarding".into(), json!(true));
        let servers = o.entry("mcpServers").or_insert_with(|| json!({}));
        if let Some(servers) = servers.as_object_mut() {
            servers.insert(names::MCP_SERVER_KEY.into(), json!({ "type": "stdio", "command": names::SHIM, "args": ["mcp"], "env": {} }));
        }
    })?);
    Ok(replaced)
}

/// Changes the JSON object in the file `rel` of the store `mnt`; one that isn't there, isn't a plain
/// file or holds no JSON object is made anew. One that can't be read is left alone, and the start
/// fails.
fn merge_json(mnt: &Path, rel: &str, change: impl FnOnce(&mut Map<String, Value>)) -> Result<Vec<PathBuf>> {
    let rel = Path::new(rel);
    let found = nofollow::read(mnt, rel)?;
    let mut value = found.and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok()).filter(Value::is_object).unwrap_or_else(|| json!({}));
    change(value.as_object_mut().expect("an object"));
    nofollow::write(mnt, rel, (serde_json::to_string_pretty(&value)? + "\n").as_bytes())
}

/// Clear what a crashed run left for an id: a mounted store, and a store made for one run.
pub fn sweep(layout: &Layout, id: &str) -> Result<()> {
    store::detach(&layout.mount_point(id))?;
    store::shred(&layout.ephemeral_bundle(id))
}

/// Clear the leftovers of runs that ended without cleaning up (no halti holds their lock any more):
/// stores made for one run have no key to open them again, so they go.
fn sweep_temp(layout: &Layout) -> Result<()> {
    for entry in fs::read_dir(layout.root.join("temp")).into_iter().flatten().flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = file.strip_suffix(".sparsebundle") else { continue };
        let lock = layout.lock(id);
        if let Some(_held) = store::lock(&lock)? {
            sweep(layout, id)?;
            if id.contains("-tmp-") {
                let _ = fs::remove_file(&lock);
            }
        }
    }
    Ok(())
}

// --- signals ---

static SIGNALLED: AtomicBool = AtomicBool::new(false);

/// Set once the process got SIGHUP, SIGINT or SIGTERM after `catch_signals`.
pub fn signalled() -> &'static AtomicBool {
    &SIGNALLED
}

extern "C" fn on_signal(_signal: i32) {
    SIGNALLED.store(true, Ordering::SeqCst);
}

unsafe extern "C" {
    fn signal(signal: i32, handler: usize) -> usize;
}

/// Have the signals that end a terminal session set a flag instead of killing halti, so the
/// box is put away properly. A child gets the default again when it starts (a handler isn't
/// inherited across exec), so the ones that need no terminal start in a process group of their
/// own (`engine`, `store`): Ctrl-C and a closed terminal don't end a VM's stop or a store's detach
/// half way.
pub fn catch_signals() {
    const SIGHUP: i32 = 1;
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    for sig in [SIGHUP, SIGINT, SIGTERM] {
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
        unsafe { signal(sig, on_signal as extern "C" fn(i32) as usize) };
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Condvar, Mutex};

    use halti_core::ids::WsId;

    use super::*;
    use crate::browse::BoxBrowser;
    use crate::legacy;
    use crate::util::{TempDir, config_dir, sha256_hex, store_root};

    const DIGEST: &str = "agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    type SpecSeen = (String, String, u32, String, PathBuf, Vec<(PathBuf, String, bool)>, bool);
    type DoorSeen = (Vec<String>, Option<String>, Vec<String>, PathBuf);
    type NetSeen = (policy::Mode, Vec<String>, [u8; 32], Option<Means>);
    type ExecSeen = (Vec<(String, String)>, Vec<String>, bool);
    type Hook = Box<dyn Fn(&Path) + Sync + Send>;
    /// Runs when what the box kept is noted, as it ends.
    type Check = Box<dyn Fn() + Sync + Send>;
    /// Runs in exec with the door's browser and the store's mount point.
    type BrowserHook = Box<dyn Fn(&dyn BoxBrowser, &Path) + Sync + Send>;

    #[derive(Default)]
    struct Seen {
        calls: Vec<String>,
        spec: Option<SpecSeen>,
        door: Option<DoorSeen>,
        /// The CA installed in the VM, as PEM, and whether the door was given one.
        ca: Option<String>,
        door_ca: Option<String>,
        net: Option<NetSeen>,
        /// The lines of the log head recorded when the box was put away.
        log_head: Option<usize>,
        exec: Option<ExecSeen>,
        /// The VM `exec` ran in.
        exec_vm: Option<String>,
        /// The names of the sites with a sealed session, as recorded when the box was put away.
        sessions: Option<Vec<String>>,
        /// What the door was given to run browsers with.
        browser: Option<Arc<dyn BoxBrowser>>,
        /// Files of the box as the agent would find them, read when it starts.
        files: BTreeMap<String, String>,
        stopped: bool,
        /// The VMs stopped, by name.
        stopped_vms: Vec<String>,
    }

    /// Records what a run does; `exec` can change files the way the agent would.
    #[derive(Default)]
    struct Fake {
        seen: Mutex<Seen>,
        wake: Condvar,
        running: Mutex<bool>,
        /// The name of the one VM that runs (when `running`); `None`: any name.
        only: Option<String>,
        /// VMs that run whatever else does: other boxes'.
        others: Vec<String>,
        deny: bool,
        unavailable: bool,
        door_fails: bool,
        /// A site (or model) that isn't ready.
        unready: Option<&'static str>,
        /// Note `settle` among the calls.
        settles: bool,
        /// Block in exec until the VM is stopped (a signal's doing).
        block: bool,
        /// Set the flag (as a signal would) during the call that starts with this.
        stop_at: Option<(&'static str, Arc<AtomicBool>)>,
        key: String,
        /// Runs in exec with the box's work folder.
        hook: Option<Hook>,
        browser_hook: Option<BrowserHook>,
        recording: Option<Check>,
    }

    impl Fake {
        fn calls(&self) -> Vec<String> {
            self.seen.lock().unwrap().calls.clone()
        }

        fn note(&self, call: impl Into<String>) {
            let call = call.into();
            if let Some((at, stop)) = &self.stop_at
                && call.starts_with(at)
            {
                stop.store(true, Ordering::SeqCst);
            }
            self.seen.lock().unwrap().calls.push(call);
        }
    }

    impl World for Fake {
        fn confirm(&self, reason: &str) -> Result<()> {
            self.note(format!("confirm: {reason}"));
            if self.deny { bail!("not approved") } else { Ok(()) }
        }

        fn available(&self) -> Result<()> {
            self.note("available");
            if self.unavailable { bail!("container isn't installed") } else { Ok(()) }
        }

        fn running(&self, vm: &str) -> bool {
            (*self.running.lock().unwrap() && self.only.as_ref().is_none_or(|only| only == vm)) || self.others.iter().any(|other| other == vm)
        }

        fn start_vm(&self, spec: &engine::VmSpec) -> Result<()> {
            self.note("start_vm");
            let mounts = spec.mounts.iter().map(|m| (m.host.clone(), m.guest.clone(), m.readonly)).collect();
            self.seen.lock().unwrap().spec = Some((spec.name.clone(), spec.image.clone(), spec.cpus, spec.memory.clone(), spec.socket.clone(), mounts, spec.docker));
            *self.running.lock().unwrap() = true;
            Ok(())
        }

        fn stop_vm(&self, vm: &str) {
            self.note("stop_vm");
            *self.running.lock().unwrap() = false;
            self.seen.lock().unwrap().stopped = true;
            self.seen.lock().unwrap().stopped_vms.push(vm.to_string());
            self.wake.notify_all();
        }

        fn start_door(&self, cfg: door::Config) -> Result<Box<dyn Any>> {
            self.note("start_door");
            if self.door_fails {
                bail!("the door can't start");
            }
            let mut seen = self.seen.lock().unwrap();
            seen.door_ca = cfg.ca.as_ref().map(|ca| ca.cert_pem());
            seen.net = Some((cfg.net.writes, cfg.net.allow_writes, cfg.log_key, cfg.net.ask));
            seen.door = Some((cfg.allow, cfg.model, cfg.sites, cfg.log));
            seen.browser = cfg.browser;
            Ok(Box::new(()))
        }

        fn settle(&self, _door: &dyn Any) {
            if self.settles {
                self.note("settle");
            }
        }

        fn browser_image(&self) -> Result<String> {
            Ok("browser@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into())
        }

        fn install_ca(&self, _vm: &str, pem: &str) -> Result<()> {
            self.note("install_ca");
            self.seen.lock().unwrap().ca = Some(pem.to_string());
            Ok(())
        }

        fn start_docker(&self, _vm: &str) -> Result<()> {
            self.note("start_docker");
            Ok(())
        }

        fn model_uses_bearer(&self, model: &str) -> Result<bool> {
            self.note(format!("bearer: {model}"));
            if self.unready == Some(model) {
                bail!("{model} has no approved policy");
            }
            Ok(true)
        }

        fn site_ready(&self, site: &str) -> Result<()> {
            self.note(format!("site: {site}"));
            if self.unready == Some(site) {
                bail!("{site} has no approved policy");
            }
            Ok(())
        }

        fn key(&self, _name: &str) -> Result<String> {
            Ok(self.key.clone())
        }

        fn record_sessions(&self, _name: &str, sites: &[String]) -> Result<()> {
            if let Some(check) = &self.recording {
                check();
            }
            self.seen.lock().unwrap().sessions = Some(sites.to_vec());
            Ok(())
        }

        fn record_log_head(&self, _name: &str, head: &chain::Head) -> Result<()> {
            self.seen.lock().unwrap().log_head = Some(head.lines);
            Ok(())
        }

        fn exec(&self, vm: &str, env: &[(String, String)], cmd: &[String], tty: bool) -> Result<ExitStatus> {
            self.note("exec");
            let mut seen = self.seen.lock().unwrap();
            seen.exec = Some((env.to_vec(), cmd.to_vec(), tty));
            seen.exec_vm = Some(vm.to_string());
            let mounts = seen.spec.as_ref().map(|s| s.5.clone()).unwrap_or_default();
            let host = |guest: &str| mounts.iter().find(|m| m.1 == guest).map(|m| m.0.clone());
            if let Some(home) = host(GUEST_HOME) {
                for file in [".claude/settings.json", ".claude.json", ".docker/config.json"] {
                    if let Ok(text) = fs::read_to_string(home.join(file)) {
                        seen.files.insert(file.to_string(), text);
                    }
                }
            }
            if let Some(work) = host(GUEST_WORK) {
                for entry in fs::read_dir(&work).unwrap().flatten() {
                    seen.files.insert(format!("work/{}", entry.file_name().to_string_lossy()), String::new());
                }
                if let Ok(text) = fs::read_to_string(work.join("proj/README")) {
                    seen.files.insert("work/proj/README".into(), text);
                }
                if let Some(hook) = &self.hook {
                    hook(&work);
                }
                if let (Some(hook), Some(browser)) = (&self.browser_hook, &seen.browser) {
                    hook(browser.as_ref(), work.parent().unwrap());
                }
            }
            if self.block {
                while !seen.stopped {
                    seen = self.wake.wait(seen).unwrap();
                }
                return Ok(ExitStatus::from_raw(15));
            }
            Ok(ExitStatus::from_raw(0))
        }
    }

    struct Setup {
        dir: TempDir,
        layout: Layout,
        stop: AtomicBool,
    }

    fn setup() -> Setup {
        let dir = TempDir::new("halti-run").unwrap();
        let layout = Layout::under(&dir.0).unwrap();
        Setup { dir, layout, stop: AtomicBool::new(false) }
    }

    fn request<'a>(s: &'a Setup, policy: &'a BoxPolicy, persistent: bool) -> Request<'a> {
        Request {
            name: "r",
            id: "r".into(),
            policy,
            policy_sha: "sha-1".into(),
            persistent,
            unique: false,
            command: None,
            tty: false,
            stop: &s.stop,
            write: Some(Means::None),
            shown: "r".into(),
            stop_with: "halti box stop r".into(),
            mounts: MountRule::Guarded(vec![config_dir(), store_root(), crate::config::workspaces_in_effect()]),
            confirm: true,
        }
    }

    fn policy(s: &Setup, extra: &str) -> BoxPolicy {
        let (proj, data) = (s.dir.0.join("proj"), s.dir.0.join("data"));
        fs::create_dir_all(proj.join(".git")).unwrap();
        fs::create_dir_all(&data).unwrap();
        fs::write(proj.join("README"), "original").unwrap();
        fs::write(proj.join(".git/HEAD"), "ref: refs/heads/main").unwrap();
        BoxPolicy::parse(&format!(
            r#"
            image = "{DIGEST}"
            model = "anthropic"
            sites = ["github"]
            standins = ["GH_TOKEN"]
            [net]
            allow = ["https://docs.rs"]
            writes = "ask"
            allow_writes = ["https://api.example.com/search"]
            [[mount]]
            path = "{}"
            [[mount]]
            path = "{}"
            mode = "ro"
            {extra}
            "#,
            proj.display(),
            data.display()
        ))
        .unwrap()
    }

    fn assert_put_away(s: &Setup) {
        assert!(!store::is_mounted(&s.layout.mount_point("r")), "the store is still attached");
        assert!(!s.layout.ephemeral_bundle("r").exists(), "the store was not shredded");
        assert!(!s.layout.socket("r").exists());
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn runs_a_box_in_order_and_puts_it_away() {
        let s = setup();
        let p = policy(&s, "");
        // A run that ended without cleaning up left a store no key can open again.
        let stale = s.layout.ephemeral_bundle("old-tmp-1");
        store::create(&s.layout, &stale, &store::new_key().unwrap()).unwrap();
        let fake = Fake::default();

        let code = run(&s.layout, &fake, &Request { command: Some(vec!["bash".into(), "-l".into()]), tty: true, ..request(&s, &p, false) }).unwrap();

        assert_eq!(code, 0);
        assert_eq!(
            fake.calls(),
            [
                "available",
                "bearer: anthropic",
                "site: anthropic",
                "site: github",
                "confirm: open box r and let it use github",
                "start_vm",
                "start_door",
                "install_ca",
                "exec",
                "stop_vm"
            ]
        );
        assert_put_away(&s);
        assert!(!stale.exists(), "leftovers of crashed runs are cleared");

        let seen = fake.seen.lock().unwrap();
        let (name, image, cpus, memory, socket, mounts, docker) = seen.spec.clone().unwrap();
        assert_eq!((name.as_str(), image.as_str(), cpus, memory.as_str(), docker), ("halti-box-r", DIGEST, 4, "8G", false));
        assert_eq!(socket, s.layout.socket("r"));
        let guests: Vec<_> = mounts.iter().map(|m| (m.1.as_str(), m.2)).collect();
        assert_eq!(guests, [("/home/agent", false), ("/work", false), ("/downloads", false), ("/mnt/data", true)]);
        assert_eq!(mounts[3].0, fs::canonicalize(s.dir.0.join("data")).unwrap());
        let (allow, model, sites, log) = seen.door.clone().unwrap();
        assert_eq!((allow, model, sites), (vec!["https://docs.rs".to_string()], Some("anthropic".to_string()), vec!["github".to_string()]));
        assert!(log.ends_with("log/door.log"), "{}", log.display());

        let (env, cmd, tty) = seen.exec.clone().unwrap();
        assert!(env.contains(&("CLAUDE_CODE_OAUTH_TOKEN".into(), names::STANDIN.into())), "the bearer stand-in: {env:?}");
        let pem = seen.ca.clone().expect("the CA is installed in the VM");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----") && !pem.contains("PRIVATE"), "{pem}");
        assert_eq!(seen.door_ca.as_deref(), Some(pem.as_str()), "the door ends TLS with the CA the VM trusts");
        for var in ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CERT", "GIT_SSL_CAINFO"] {
            assert!(env.iter().any(|(k, v)| k == var && v.starts_with("/")), "{var} in {env:?}");
        }
        assert!(env.contains(&("GH_TOKEN".into(), names::STANDIN.into())), "the policy's stand-ins: {env:?}");
        let (writes, allow_writes, _, ask) = seen.net.clone().unwrap();
        assert_eq!((writes, allow_writes), (policy::Mode::Ask, vec!["https://api.example.com/search".to_string()]));
        // Not the door's default (Touch ID), so a request whose means were dropped would fail here.
        assert_ne!(Some(Means::None), door::inspect::Net::default().ask);
        assert_eq!(ask, Some(Means::None), "the door asks about writes as the box opened with");
        assert_eq!(&cmd[..2], ["sh", "-c"]);
        assert!(cmd[2].starts_with("cd /work && exec"), "{}", cmd[2]);
        assert_eq!(&cmd[3..], ["bash", "-l"]);
        assert!(tty);

        let settings: Value = serde_json::from_str(&seen.files[".claude/settings.json"]).unwrap();
        assert_eq!(settings["skipWebFetchPreflight"], json!(true));
        let claude: Value = serde_json::from_str(&seen.files[".claude.json"]).unwrap();
        let server = &claude["mcpServers"][names::MCP_SERVER_KEY];
        assert_eq!((server["command"].clone(), server["args"].clone()), (json!(names::SHIM), json!(["mcp"])));
        assert!(seen.files.contains_key("work/proj"), "the clone: {:?}", seen.files.keys());
        assert_eq!(seen.files["work/proj/README"], "original");
        assert!(!seen.files.contains_key("work/data"), "ro folders are not copied");
        assert!(!seen.files.contains_key(".docker/config.json"), "no Docker settings without docker = true");
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_docker_box_starts_dockerd_after_the_ca_and_before_the_agent() {
        let s = setup();
        let mut p = policy(&s, "");
        p.docker = true;
        let fake = Fake::default();
        run(&s.layout, &fake, &request(&s, &p, false)).unwrap();

        let calls = fake.calls();
        let at = |call: &str| calls.iter().position(|c| c == call).unwrap();
        assert!(at("install_ca") < at("start_docker") && at("start_docker") < at("exec"), "{calls:?}");
        let seen = fake.seen.lock().unwrap();
        assert!(seen.spec.as_ref().unwrap().6, "the VM is made for Docker");
        let config: Value = serde_json::from_str(&seen.files[".docker/config.json"]).unwrap();
        assert_eq!(config["proxies"]["default"]["httpsProxy"], json!("http://172.17.0.1:3128"));
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_kept_box_keeps_its_files_and_its_own_copy() {
        let s = setup();
        let p = policy(&s, "");
        let key = store::new_key().unwrap();
        store::create(&s.layout, &s.layout.bundle("r"), &key).unwrap();
        let log_key = super::super::log_key(&key);
        let hook: Hook = Box::new(move |work| {
            fs::write(work.join("proj/README"), "agent's edit").unwrap();
            // The line for the start is in the log, chained with the key the door gets.
            let log = store::door_log(work.parent().unwrap());
            assert_eq!(crate::chain::Chain::new(&log, log_key).verify().unwrap().chained, 1);
        });
        let first = Fake { key: key.clone(), hook: Some(hook), ..Fake::default() };
        run(&s.layout, &first, &request(&s, &p, true)).unwrap();
        assert_eq!(first.seen.lock().unwrap().net.as_ref().unwrap().2, log_key, "the door chains its log with a key derived from the box key");
        assert!(s.layout.bundle("r").exists() && !store::is_mounted(&s.layout.mount_point("r")));
        assert_eq!(first.seen.lock().unwrap().log_head, Some(2), "where the log stands (started, stopped) is kept outside the store");

        // The source changes; the agent's copy is not replaced.
        fs::write(s.dir.0.join("proj/README"), "changed on the Mac").unwrap();
        let second = Fake { key, ..Fake::default() };
        run(&s.layout, &second, &request(&s, &p, true)).unwrap();
        assert_eq!(second.seen.lock().unwrap().files["work/proj/README"], "agent's edit");
        assert_eq!(second.seen.lock().unwrap().log_head, Some(4));
        assert!(s.layout.bundle("r").exists());
    }

    #[test]
    fn joins_a_box_that_runs() {
        let s = setup();
        let p = policy(&s, "");
        s.layout.prepare().unwrap();
        let held = store::lock(&s.layout.lock("r")).unwrap().unwrap();
        fs::write(s.layout.opened_with("r"), "sha-1").unwrap();

        let fake = Fake { running: Mutex::new(true), ..Fake::default() };
        let code = run(&s.layout, &fake, &Request { command: Some(vec!["bash".into()]), ..request(&s, &p, false) }).unwrap();
        assert_eq!(code, 0);
        assert_eq!(fake.calls(), ["bearer: anthropic", "exec"], "no second store, VM or door");
        assert!(!store::is_mounted(&s.layout.mount_point("r")));

        // Approved again since the box opened: joining would run under rules the door doesn't know.
        let changed = Fake { running: Mutex::new(true), ..Fake::default() };
        let e = run(&s.layout, &changed, &Request { policy_sha: "sha-2".into(), ..request(&s, &p, false) }).unwrap_err().to_string();
        assert!(e.contains("halti box stop r"), "{e}");
        assert!(changed.calls().is_empty(), "nothing runs: {:?}", changed.calls());

        let starting = Fake::default();
        let e = run(&s.layout, &starting, &request(&s, &p, false)).unwrap_err().to_string();
        assert!(e.contains("another halti"), "{e}");
        assert!(starting.calls().is_empty());
        drop(held);
    }

    #[test]
    fn joins_only_a_box_under_its_own_name() {
        let s = setup();
        let p = policy(&s, "");
        s.layout.prepare().unwrap();
        let held = store::lock(&s.layout.lock("r")).unwrap().unwrap();
        fs::write(s.layout.opened_with("r"), "sha-1").unwrap();

        // A VM of the same box started by another install is not this box: nothing is joined.
        let other = format!("{}r", legacy::BOX_VM_PREFIX);
        let fake = Fake { running: Mutex::new(true), only: Some(other), ..Fake::default() };
        let err = run(&s.layout, &fake, &request(&s, &p, false)).unwrap_err().to_string();
        assert!(err.contains("being opened or closed by another halti"), "{err}");
        assert_eq!(fake.calls(), Vec::<String>::new(), "nothing started, nothing joined");

        let fake = Fake { running: Mutex::new(true), only: Some(vm_name("r")), ..Fake::default() };
        assert_eq!(run(&s.layout, &fake, &request(&s, &p, false)).unwrap(), 0);
        assert_eq!(fake.calls(), ["bearer: anthropic", "exec"], "no second VM");
        assert_eq!(fake.seen.lock().unwrap().exec_vm.as_deref(), Some("halti-box-r"));
        drop(held);
    }

    #[test]
    fn leaves_a_browser_vm_of_another_install_alone() {
        let s = setup();
        let p = policy(&s, "");
        let other = format!("{}r", legacy::BROWSER_VM_PREFIX);
        let fake = Fake { running: Mutex::new(true), only: Some(other), unavailable: true, ..Fake::default() };
        assert!(run(&s.layout, &fake, &request(&s, &p, false)).is_err());
        assert_eq!(fake.calls(), ["available"], "not ours to stop");
        assert_put_away(&s);
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn replaces_a_vm_nobody_runs() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake { running: Mutex::new(true), ..Fake::default() };
        run(&s.layout, &fake, &request(&s, &p, false)).unwrap();
        assert_eq!(&fake.calls()[..2], ["stop_vm", "available"]);
        assert_put_away(&s);
    }

    #[test]
    fn asks_and_checks_before_anything_opens() {
        let s = setup();
        let p = policy(&s, "");
        let untouched = |fake: &Fake, last: &str| {
            assert_eq!(fake.calls().last().map(String::as_str), Some(last));
            assert!(!s.layout.root.join("temp").exists() || fs::read_dir(s.layout.root.join("temp")).unwrap().next().is_none(), "a store was made");
            assert_put_away(&s);
        };

        let denied = Fake { deny: true, ..Fake::default() };
        assert!(run(&s.layout, &denied, &request(&s, &p, false)).is_err());
        untouched(&denied, "confirm: open box r and let it use github");

        let missing = Fake { unavailable: true, ..Fake::default() };
        let e = run(&s.layout, &missing, &request(&s, &p, false)).unwrap_err().to_string();
        assert!(e.contains("container"), "{e}");
        assert_eq!(missing.calls(), ["available"]);

        let no_image = BoxPolicy::parse("").unwrap();
        let fake = Fake::default();
        assert!(run(&s.layout, &fake, &request(&s, &no_image, false)).unwrap_err().to_string().contains("names no image"));
        assert!(!fake.calls().iter().any(|c| c.starts_with("confirm")));

        let gone = policy(&s, "[[mount]]\npath = \"/nonexistent/folder\"");
        let fake = Fake::default();
        assert!(run(&s.layout, &fake, &request(&s, &gone, false)).unwrap_err().to_string().contains("doesn't exist"));
        assert!(!fake.calls().iter().any(|c| c.starts_with("confirm")));
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn puts_everything_away_when_the_door_fails() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake { door_fails: true, ..Fake::default() };
        let e = run(&s.layout, &fake, &request(&s, &p, false)).unwrap_err().to_string();
        assert!(e.contains("door"), "{e}");
        assert_eq!(&fake.calls()[fake.calls().len() - 3..], ["start_vm", "start_door", "stop_vm"]);
        assert_put_away(&s);
        assert!(store::lock(&s.layout.lock("r")).unwrap().is_some(), "the lock is released");
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_signal_stops_the_box_and_puts_it_away() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake { block: true, ..Fake::default() };
        let code = thread::scope(|scope| {
            // While the agent runs: a stop before that runs no agent at all.
            scope.spawn(|| {
                while !fake.calls().iter().any(|c| c == "exec") {
                    thread::sleep(Duration::from_millis(20));
                }
                s.stop.store(true, Ordering::SeqCst);
            });
            run(&s.layout, &fake, &request(&s, &p, false)).unwrap()
        });
        assert_eq!(code, 143, "killed by SIGTERM");
        assert!(fake.calls().iter().filter(|c| *c == "stop_vm").count() >= 1);
        assert_put_away(&s);
    }

    /// Starts the box for `req`, which no other halti has open.
    fn started<'a>(s: &'a Setup, fake: &'a Fake, req: &'a Request<'a>) -> Running<'a> {
        match start(&s.layout, fake, req).unwrap() {
            Begun::Here(running) => *running,
            Begun::Elsewhere => panic!("another halti has the box open"),
        }
    }

    /// The calls after the box was started.
    fn after_start(fake: &Fake) -> Vec<String> {
        let calls = fake.calls();
        let at = calls.iter().position(|c| c == "install_ca").expect("the box started");
        calls[at + 1..].to_vec()
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn start_then_stop_is_today_s_run() {
        let s = setup();
        let p = policy(&s, "");
        let key = store::new_key().unwrap();
        store::create(&s.layout, &s.layout.bundle("r"), &key).unwrap();
        let order = [
            "available",
            "bearer: anthropic",
            "site: anthropic",
            "site: github",
            "confirm: open box r and let it use github",
            "start_vm",
            "start_door",
            "install_ca",
            "exec",
            "settle",
            "stop_vm",
        ];
        let today = Fake { key: key.clone(), settles: true, ..Fake::default() };
        assert_eq!(run(&s.layout, &today, &request(&s, &p, true)).unwrap(), 0);
        assert_eq!(today.calls(), order);

        let split = Fake { key, settles: true, ..Fake::default() };
        let req = request(&s, &p, true);
        let running = started(&s, &split, &req);
        assert!(running.work(&p.run, false).unwrap().success());
        running.stop();
        assert_eq!(split.calls(), order);
        assert!(s.layout.bundle("r").exists() && !store::is_mounted(&s.layout.mount_point("r")));
        assert!(store::lock(&s.layout.lock("r")).unwrap().is_some(), "the lock is released");
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_stop_while_the_box_starts_lets_no_agent_in() {
        let s = setup();
        let mut p = policy(&s, "");
        p.docker = true;
        // Where the start waits: the person's yes, the VM, the CA, Docker. What was opened is put away.
        for (step, last) in [
            ("confirm", &["confirm: open box r and let it use github"][..]),
            ("start_vm", &["start_vm", "stop_vm"]),
            ("install_ca", &["install_ca", "stop_vm"]),
            ("start_docker", &["start_docker", "stop_vm"]),
        ] {
            let stop = Arc::new(AtomicBool::new(false));
            let fake = Fake { settles: true, stop_at: Some((step, stop.clone())), ..Fake::default() };
            let req = Request { stop: &stop, ..request(&s, &p, false) };
            let e = run(&s.layout, &fake, &req).unwrap_err();
            assert_eq!(e.to_string(), "box r was stopped before its agent started");
            let calls = fake.calls();
            assert!(calls[calls.len() - last.len()..] == *last && !calls.iter().any(|c| c == "exec" || c == "settle"), "{step}: {calls:?}");
            assert_put_away(&s);
            assert!(store::lock(&s.layout.lock("r")).unwrap().is_some(), "the lock is released");
        }
        let stop = Arc::new(AtomicBool::new(false));
        let fake = Fake { stop_at: Some(("start_vm", stop.clone())), ..Fake::default() };
        let req = Request { stop: &stop, ..request(&s, &p, false) };
        let Err(refused) = start(&s.layout, &fake, &req) else { panic!("started though stopped") };
        assert_eq!(refused.no, No::Failed);
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_box_stopped_before_its_agent_starts_runs_nothing() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake::default();
        let req = request(&s, &p, false);
        let running = started(&s, &fake, &req);
        s.stop.store(true, Ordering::SeqCst);
        assert_eq!(running.work(&p.run, false).unwrap_err().to_string(), "box r was stopped before its agent started");
        running.stop();
        assert_eq!(after_start(&fake), ["stop_vm"]);
        assert_put_away(&s);
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_started_box_waits_until_told() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake::default();
        let req = request(&s, &p, false);
        let running = started(&s, &fake, &req);
        let told = AtomicBool::new(false);
        let waited = thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(300));
                told.store(true, Ordering::SeqCst);
            });
            let began = Instant::now();
            running.wait(&|| told.load(Ordering::SeqCst));
            began.elapsed()
        });
        assert!(waited >= Duration::from_millis(300), "{waited:?}");
        assert!(fake.running("halti-box-r") && after_start(&fake).is_empty(), "it runs, and nothing ran in it: {:?}", fake.calls());
        assert!(store::is_mounted(&s.layout.mount_point("r")));
        running.stop();
        assert_put_away(&s);
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_box_whose_vm_is_gone_is_put_away() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake { settles: true, ..Fake::default() };
        let req = request(&s, &p, false);
        let running = started(&s, &fake, &req);
        thread::scope(|scope| {
            // Stopped by hand, outside halti.
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(200));
                *fake.running.lock().unwrap() = false;
            });
            running.wait(&|| false);
        });
        running.stop();
        assert_eq!(after_start(&fake), ["settle", "stop_vm"]);
        assert_put_away(&s);
        assert!(store::lock(&s.layout.lock("r")).unwrap().is_some(), "the lock is released");
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn the_browser_vm_stops_before_the_lock_goes() {
        let s = setup();
        let p = policy(&s, "");
        let key = store::new_key().unwrap();
        store::create(&s.layout, &s.layout.bundle("r"), &key).unwrap();
        let (socket, lock) = (s.layout.browser_socket("r"), s.layout.lock("r"));
        let published = socket.clone();
        // Where the browser VM publishes its door's socket while it runs.
        let hook: Hook = Box::new(move |_| fs::write(&published, "").unwrap());
        let recording: Check = Box::new(move || {
            assert!(!socket.exists(), "the browser VM is stopped");
            assert!(store::is_held(&lock), "before the lock goes");
        });
        let fake = Fake { key, hook: Some(hook), recording: Some(recording), ..Fake::default() };
        run(&s.layout, &fake, &request(&s, &p, true)).unwrap();
        assert_eq!(fake.seen.lock().unwrap().sessions.as_deref(), Some(&[][..]), "what the box kept was noted");
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_stop_while_the_agent_runs_stops_its_vm_before_settling() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake { settles: true, ..Fake::default() };
        let req = request(&s, &p, false);
        let running = started(&s, &fake, &req);
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(200));
                s.stop.store(true, Ordering::SeqCst);
            });
            running.wait(&|| false);
        });
        running.stop();
        // The agent is still connected: its VM goes first, so settling waits for nothing.
        assert_eq!(after_start(&fake), ["stop_vm", "settle"]);
        assert_put_away(&s);
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_box_left_by_its_last_session_settles_first() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake { settles: true, ..Fake::default() };
        let req = request(&s, &p, false);
        let running = started(&s, &fake, &req);
        running.wait(&|| true);
        running.stop();
        // Browsers close and seal their sessions while both VMs still run.
        assert_eq!(after_start(&fake), ["settle", "stop_vm"]);
        assert_put_away(&s);

        // The same when the agent's command ends by itself.
        let fake = Fake { settles: true, ..Fake::default() };
        run(&s.layout, &fake, &request(&s, &p, false)).unwrap();
        assert_eq!(after_start(&fake), ["exec", "settle", "stop_vm"]);
    }

    #[test]
    fn a_site_that_isn_t_ready_is_no_site() {
        let s = setup();
        let p = policy(&s, "");
        // The model too, which today's box doesn't name itself for.
        for (site, calls, said) in [("github", 4, "box r uses github: github has no approved policy"), ("anthropic", 2, "anthropic has no approved policy")] {
            let fake = Fake { unready: Some(site), ..Fake::default() };
            let req = request(&s, &p, false);
            let Err(refused) = start(&s.layout, &fake, &req) else { panic!("{site} isn't ready") };
            assert_eq!(refused.no, No::Site(site.to_string()));
            assert_eq!(format!("{:#}", refused.why), said);
            assert_eq!(fake.calls().len(), calls, "nothing asked or opened: {:?}", fake.calls());
            assert_put_away(&s);
            // Today's run says the same.
            let today = Fake { unready: Some(site), ..Fake::default() };
            assert_eq!(format!("{:#}", run(&s.layout, &today, &req).unwrap_err()), said);
        }
        let missing = Fake { unavailable: true, ..Fake::default() };
        let req = request(&s, &p, false);
        let Err(refused) = start(&s.layout, &missing, &req) else { panic!("there is no engine") };
        assert_eq!(refused.no, No::Engine);
        let no_image = BoxPolicy::parse("").unwrap();
        let req = request(&s, &no_image, false);
        let Err(refused) = start(&s.layout, &Fake::default(), &req) else { panic!("there is no image") };
        assert_eq!(refused.no, No::Failed);
        assert!(store::lock(&s.layout.lock("r")).unwrap().is_some(), "the lock is released");
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_temporary_box_has_its_own_name_and_lock() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake::default();
        let id = "r-tmp-0a1b2c3d".to_string();
        run(&s.layout, &fake, &Request { id: id.clone(), unique: true, ..request(&s, &p, false) }).unwrap();
        assert_eq!(fake.seen.lock().unwrap().spec.as_ref().unwrap().0, "halti-box-r-tmp-0a1b2c3d");
        assert_eq!(fake.seen.lock().unwrap().log_head, None, "a box that isn't kept keeps nothing");
        assert!(!s.layout.ephemeral_bundle(&id).exists() && !s.layout.lock(&id).exists());
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_temporary_box_keeps_its_ca_in_memory_only() {
        let s = setup();
        let p = policy(&s, "");
        let hook: Hook = Box::new(|work| {
            let mnt = work.parent().unwrap();
            assert!(!mnt.join("door/ca.sealed").exists(), "nothing is written for a box that isn't kept");
        });
        let first = Fake { hook: Some(hook), ..Fake::default() };
        run(&s.layout, &first, &request(&s, &p, false)).unwrap();
        let second = Fake::default();
        run(&s.layout, &second, &request(&s, &p, false)).unwrap();
        let (a, b) = (first.seen.lock().unwrap().ca.clone().unwrap(), second.seen.lock().unwrap().ca.clone().unwrap());
        assert_ne!(a, b, "every temporary box has a CA of its own");
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_kept_box_gets_a_ca_once_sealed_in_its_store() {
        let s = setup();
        let p = policy(&s, "");
        let key = store::new_key().unwrap();
        store::create(&s.layout, &s.layout.bundle("r"), &key).unwrap();
        let sealed_at = |work: &Path| work.parent().unwrap().join("door/ca.sealed");

        // A box made before the door ended TLS has no CA; the first run makes one.
        let hook: Hook = Box::new(move |work| {
            let sealed = fs::read(sealed_at(work)).expect("the CA is saved in the store");
            assert!(!String::from_utf8_lossy(&sealed).contains("BEGIN"), "sealed, not plain");
            assert!(!work.parent().unwrap().join("work/door").exists());
        });
        let first = Fake { key: key.clone(), hook: Some(hook), ..Fake::default() };
        run(&s.layout, &first, &request(&s, &p, true)).unwrap();
        let second = Fake { key: key.clone(), ..Fake::default() };
        run(&s.layout, &second, &request(&s, &p, true)).unwrap();
        let (a, b) = (first.seen.lock().unwrap().ca.clone().unwrap(), second.seen.lock().unwrap().ca.clone().unwrap());
        assert_eq!(a, b, "later runs load the same CA");

        // No VM mounts the folder it is in.
        let mounted = first.seen.lock().unwrap().spec.clone().unwrap().5;
        assert!(mounted.iter().all(|m| !m.0.ends_with("door") && !m.0.ends_with("log")), "{mounted:?}");

        // A CA that doesn't open stops the run before any VM starts, rather than being replaced.
        let hook: Hook = Box::new(move |work| fs::write(sealed_at(work), b"garbage that isn't a sealed CA at all").unwrap());
        let damage = Fake { key: key.clone(), hook: Some(hook), ..Fake::default() };
        run(&s.layout, &damage, &request(&s, &p, true)).unwrap();
        let broken = Fake { key, ..Fake::default() };
        let e = format!("{:#}", run(&s.layout, &broken, &request(&s, &p, true)).unwrap_err());
        assert!(e.contains("CA"), "{e}");
        assert!(!broken.calls().iter().any(|c| c == "start_vm"));
        assert!(!store::is_mounted(&s.layout.mount_point("r")));
    }

    /// Seals sessions through the door's browser while the box runs; the reading side sees what was kept.
    fn seal_in(site: &'static str, state: &'static str) -> BrowserHook {
        Box::new(move |browser, mnt| {
            browser.seal(site, state).unwrap();
            assert!(mnt.join("browser").is_dir(), "the sessions folder is in the store");
        })
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn sessions_are_sealed_in_the_store_and_no_vm_mounts_them() {
        let s = setup();
        let p = policy(&s, "");
        let key = store::new_key().unwrap();
        store::create(&s.layout, &s.layout.bundle("r"), &key).unwrap();
        let state = r#"{"cookies":[{"name":"sid","value":"SESSION-VALUE-0123456789"}],"origins":[]}"#;

        let first = Fake { key: key.clone(), browser_hook: Some(seal_in("github", state)), ..Fake::default() };
        run(&s.layout, &first, &request(&s, &p, true)).unwrap();
        let seen = first.seen.lock().unwrap();
        assert_eq!(seen.sessions.as_deref(), Some(&["github".to_string()][..]), "which sites have a session is noted outside the store");
        let mounted = seen.spec.clone().unwrap().5;
        assert!(mounted.iter().all(|m| !m.0.ends_with("browser") && !m.0.to_string_lossy().contains("/browser/")), "no VM mounts the sessions: {mounted:?}");
        assert!(mounted.iter().all(|m| !m.1.contains("browser")), "{mounted:?}");
        drop(seen);

        // The next run finds it again, opened with the key the box key gives; the file holds no plain value.
        let read = Box::new(move |browser: &dyn BoxBrowser, mnt: &Path| {
            assert_eq!(browser.sealed("github").unwrap().as_deref(), Some(state));
            assert_eq!(browser.sealed("other").unwrap(), None);
            let file = fs::read(mnt.join("browser/github.sealed")).unwrap();
            assert!(!String::from_utf8_lossy(&file).contains("SESSION-VALUE"));
            // A file for one site isn't another's.
            fs::copy(mnt.join("browser/github.sealed"), mnt.join("browser/other.sealed")).unwrap();
            assert!(browser.sealed("other").is_err());
            fs::remove_file(mnt.join("browser/other.sealed")).unwrap();
        });
        let second = Fake { key: key.clone(), browser_hook: Some(read), ..Fake::default() };
        run(&s.layout, &second, &request(&s, &p, true)).unwrap();
        assert_eq!(second.seen.lock().unwrap().sessions.as_deref(), Some(&["github".to_string()][..]));

        // With the box gone, there is no store to write into.
        let browser = second.seen.lock().unwrap().browser.clone().unwrap();
        assert!(browser.seal("github", "{}").is_err());
        assert!(!store::is_mounted(&s.layout.mount_point("r")) && !s.layout.mount_point("r").exists());
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_box_that_keeps_no_sessions_never_writes_one() {
        let s = setup();
        let p = policy(&s, "[browser]\nkeep_sessions = false");
        let key = store::new_key().unwrap();
        store::create(&s.layout, &s.layout.bundle("r"), &key).unwrap();
        let hook: BrowserHook = Box::new(|browser, mnt| {
            browser.seal("github", "{\"cookies\":[]}").unwrap();
            assert_eq!(browser.sealed("github").unwrap(), None);
            assert!(fs::read_dir(mnt.join("browser")).unwrap().next().is_none(), "nothing was written");
        });
        let fake = Fake { key, browser_hook: Some(hook), ..Fake::default() };
        run(&s.layout, &fake, &request(&s, &p, true)).unwrap();
        assert_eq!(fake.seen.lock().unwrap().sessions.as_deref(), Some(&[][..]));
    }

    /// A folder with a short path, removed when dropped.
    struct Short(PathBuf);

    impl Drop for Short {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A workspace's box `dev`, as `ws run acme/dev` asks for it once the workspace is open.
    fn in_workspace<'a>(s: &'a Setup, policy: &'a BoxPolicy) -> Request<'a> {
        Request {
            name: "dev",
            id: "dev".into(),
            shown: "acme/dev".into(),
            stop_with: "halti ws stop acme/dev".into(),
            mounts: MountRule::Workspace(vec![config_dir(), store_root()]),
            confirm: false,
            ..request(s, policy, false)
        }
    }

    const ACME: [u8; 16] = [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78];

    /// A policy a workspace's box may have: no mounts outside a plain home folder.
    fn plain_policy() -> BoxPolicy {
        BoxPolicy::parse(&format!("image = \"{DIGEST}\"\nmodel = \"anthropic\"\nsites = [\"github\"]\nstandins = [\"GH_TOKEN\"]\n")).unwrap()
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn a_workspace_box_runs_in_order_without_a_confirm() {
        let s = setup();
        let mut layout = Layout::under_workspace(&s.dir.0, WsId::from_bytes(ACME)).unwrap();
        // A test folder's path is too long for a workspace's browser socket on a Mac.
        let short = Short(PathBuf::from(format!("/tmp/halti-ws-test-{}", std::process::id())));
        layout.sockets = short.0.join("ws");
        let p = plain_policy();
        let bearer = layout.bearer("dev");
        let hook: Hook = Box::new(move |_| assert_eq!(fs::read_to_string(&bearer).unwrap(), "1", "a second terminal can join"));
        let fake = Fake { hook: Some(hook), ..Fake::default() };
        assert_eq!(run(&layout, &fake, &in_workspace(&s, &p)).unwrap(), 0);
        // The workspace's open was the approval: nothing else is asked.
        assert_eq!(fake.calls(), ["available", "bearer: anthropic", "site: anthropic", "site: github", "start_vm", "start_door", "install_ca", "exec", "stop_vm"]);
        let seen = fake.seen.lock().unwrap();
        let (name, _, _, _, socket, mounts, _) = seen.spec.clone().unwrap();
        assert_eq!((name.as_str(), socket), ("halti-wsbox-abcdef012345-dev", short.0.join("ws/abcdef012345-dev.sock")));
        assert!(mounts.iter().all(|m| m.0.starts_with(s.dir.0.join("boxes/open/dev"))), "the store is in the workspace's boxes folder: {mounts:?}");
        assert!(seen.files.contains_key(".claude.json"));
        assert_eq!(seen.exec_vm.as_deref(), Some("halti-wsbox-abcdef012345-dev"));
        assert!(!store::is_mounted(&layout.mount_point("dev")) && !layout.ephemeral_bundle("dev").exists() && !layout.socket("dev").exists());
        assert!(!s.dir.0.join("box").exists(), "nothing of today's boxes' folders");
    }

    #[test]
    fn a_workspace_run_never_stops_a_keychain_or_cred_box_of_the_same_name() {
        let s = setup();
        let layout = Layout::under_workspace(&s.dir.0, WsId::from_bytes(ACME)).unwrap();
        let p = plain_policy();
        let others = vec![vm_name("dev"), crate::engine::browser_vm_name("dev"), format!("{}dev", legacy::BOX_VM_PREFIX), format!("{}dev", legacy::BROWSER_VM_PREFIX)];
        // They run: only the workspace's own leftovers would be stopped, and none is there.
        let fake = Fake { others: others.clone(), unavailable: true, ..Fake::default() };
        assert!(run(&layout, &fake, &in_workspace(&s, &p)).is_err());
        assert_eq!(fake.calls(), ["available"], "nothing stopped");
        assert!(others.iter().all(|vm| fake.running(vm)));
        // A leftover of the workspace's own box is stopped, and only that.
        let fake = Fake { others: [others.clone(), vec![layout.vm("dev"), layout.browser_vm("dev")]].concat(), unavailable: true, ..Fake::default() };
        assert!(run(&layout, &fake, &in_workspace(&s, &p)).is_err());
        assert_eq!(fake.seen.lock().unwrap().stopped_vms, ["halti-wsbox-abcdef012345-dev", "halti-wsbrowser-abcdef012345-dev"]);
    }

    /// The VM, environment and command a join ran.
    type Joined = (String, Vec<(String, String)>, Vec<String>);

    /// An engine that notes each call: a join reaches nothing else.
    #[derive(Default)]
    struct Engine {
        calls: Mutex<Vec<String>>,
        exec: Mutex<Option<Joined>>,
    }

    impl Vms for Engine {
        fn available(&self) -> Result<()> {
            self.calls.lock().unwrap().push("available".into());
            Ok(())
        }

        fn running(&self, _name: &str) -> bool {
            self.calls.lock().unwrap().push("running".into());
            true
        }

        fn run(&self, _spec: &engine::VmSpec) -> Result<()> {
            self.calls.lock().unwrap().push("run".into());
            Ok(())
        }

        fn stop(&self, _name: &str) -> Result<()> {
            self.calls.lock().unwrap().push("stop".into());
            Ok(())
        }

        fn exec(&self, name: &str, env: &[(String, String)], cmd: &[String], _tty: bool) -> Result<ExitStatus> {
            self.calls.lock().unwrap().push("exec".into());
            *self.exec.lock().unwrap() = Some((name.to_string(), env.to_vec(), cmd.to_vec()));
            Ok(ExitStatus::from_raw(0))
        }

        fn install_ca(&self, _name: &str, _pem: &str) -> Result<()> {
            self.calls.lock().unwrap().push("install_ca".into());
            Ok(())
        }

        fn start_docker(&self, _name: &str) -> Result<()> {
            self.calls.lock().unwrap().push("start_docker".into());
            Ok(())
        }

        fn image_digest(&self, _reference: &str) -> Result<String> {
            self.calls.lock().unwrap().push("image_digest".into());
            Ok(DIGEST.into())
        }
    }

    /// A workspace's box `dev` as its opener leaves it: the lock held, the policy's hash and the
    /// model's answer noted. Returns the lock and the policy's bytes.
    fn opened(layout: &Layout, bearer: &str) -> (store::Lock, Vec<u8>) {
        layout.prepare().unwrap();
        let text = format!("image = \"{DIGEST}\"\nmodel = \"anthropic\"\nrun = [\"claude\", \"-c\"]\nstandins = [\"GH_TOKEN\"]\n").into_bytes();
        let held = store::lock(&layout.lock("dev")).unwrap().unwrap();
        fs::write(layout.opened_with("dev"), sha256_hex(&text)).unwrap();
        fs::write(layout.bearer("dev"), bearer).unwrap();
        (held, text)
    }

    #[test]
    fn a_join_asks_nothing_and_looks_nothing_up() {
        let s = setup();
        let layout = Layout::under_workspace(&s.dir.0, WsId::from_bytes(ACME)).unwrap();
        let (_held, text) = opened(&layout, "1");
        let rule = MountRule::Workspace(vec![]);
        let vms = Engine::default();
        assert_eq!(join(&layout, &vms, "dev", "acme/dev", &rule, &text, None, true).unwrap(), 0);
        assert_eq!(*vms.calls.lock().unwrap(), ["running", "exec"]);
        let (vm, env, cmd) = vms.exec.lock().unwrap().clone().unwrap();
        assert_eq!(vm, "halti-wsbox-abcdef012345-dev");
        assert!(env.contains(&("CLAUDE_CODE_OAUTH_TOKEN".into(), names::STANDIN.into())) && env.contains(&("GH_TOKEN".into(), names::STANDIN.into())), "{env:?}");
        assert_eq!(&cmd[3..], ["claude", "-c"], "the policy's run");
        // The model's other answer, and a command of the person's own.
        fs::write(layout.bearer("dev"), "0").unwrap();
        let vms = Engine::default();
        join(&layout, &vms, "dev", "acme/dev", &rule, &text, Some(&["bash".to_string()][..]), false).unwrap();
        let (_, env, cmd) = vms.exec.lock().unwrap().clone().unwrap();
        assert!(env.contains(&("ANTHROPIC_API_KEY".into(), names::STANDIN.into())), "{env:?}");
        assert_eq!(&cmd[3..], ["bash"]);
        // With no answer noted, the box is still being opened.
        fs::remove_file(layout.bearer("dev")).unwrap();
        let vms = Engine::default();
        let error = join(&layout, &vms, "dev", "acme/dev", &rule, &text, None, false).unwrap_err().to_string();
        assert_eq!(error, "box acme/dev is being opened or closed by another halti: try again in a moment");
        assert_eq!(*vms.calls.lock().unwrap(), ["running"]);
    }

    #[test]
    fn a_join_refuses_a_policy_file_changed_since_the_open() {
        let s = setup();
        let layout = Layout::under_workspace(&s.dir.0, WsId::from_bytes(ACME)).unwrap();
        let (_held, text) = opened(&layout, "1");
        let rule = MountRule::Workspace(vec![]);
        let changed = [text.as_slice(), b"cpus = 2\n"].concat();
        let vms = Engine::default();
        let error = join(&layout, &vms, "dev", "acme/dev", &rule, &changed, None, false).unwrap_err().to_string();
        assert_eq!(error, "box acme/dev runs with the policy it was opened with, and its file has changed since: stop it (halti ws stop acme/dev) and run it again");
        assert_eq!(*vms.calls.lock().unwrap(), ["running"], "nothing runs");
        // Changed the same way as the hash noted, it is still checked by the workspace's rule.
        let hidden = [text.as_slice(), b"[[mount]]\npath = \"~/.ssh\"\n"].concat();
        fs::write(layout.opened_with("dev"), sha256_hex(&hidden)).unwrap();
        let error = format!("{:#}", join(&layout, &vms, "dev", "acme/dev", &rule, &hidden, None, false).unwrap_err());
        assert!(error.contains("[[mount]] ~/.ssh: a box in a workspace mounts only folders"), "{error}");
        assert_eq!(*vms.calls.lock().unwrap(), ["running", "running"]);
    }

    #[test]
    fn long_sockets_are_refused_before_the_box_opens() {
        let s = setup();
        let mut layout = Layout::under_workspace(&s.dir.0, WsId::from_bytes(ACME)).unwrap();
        layout.sockets = s.dir.0.join("s".repeat(104));
        let p = plain_policy();
        for confirm in [true, false] {
            let fake = Fake::default();
            let error = run(&layout, &fake, &Request { confirm, ..in_workspace(&s, &p) }).unwrap_err().to_string();
            assert!(error.contains("is too long"), "{error}");
            assert_eq!(fake.calls(), ["available", "bearer: anthropic", "site: anthropic", "site: github"], "nothing asked or opened");
            assert!(!layout.bearer("dev").exists() && !layout.root.join("temp/dev.sparsebundle").exists());
        }
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn today_s_layout_writes_no_bearer_file() {
        let s = setup();
        let p = policy(&s, "");
        let hook: Hook = Box::new(|work| {
            let open = work.parent().unwrap().parent().unwrap();
            let mut found: Vec<String> = fs::read_dir(open).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            found.sort();
            assert_eq!(found, ["r", "r.lock", "r.policy"], "no .bearer");
        });
        let fake = Fake { hook: Some(hook), ..Fake::default() };
        run(&s.layout, &fake, &request(&s, &p, false)).unwrap();
        assert!(fake.calls().contains(&"exec".to_string()));
        assert!(!s.layout.bearer("r").exists());
    }

    #[test]
    fn keeps_what_the_agent_wrote_in_its_settings() {
        let dir = TempDir::new("halti-home").unwrap();
        let home = dir.0.join("home");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::write(home.join(".claude/settings.json"), r#"{"theme":"dark","skipWebFetchPreflight":false}"#).unwrap();
        fs::write(home.join(".claude.json"), r#"{"mcpServers":{"mine":{"command":"x"}},"halti":1}"#).unwrap();
        assert!(prepare_home(&dir.0, false).unwrap().is_empty());
        let settings: Value = serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap()).unwrap();
        assert_eq!((settings["theme"].clone(), settings["skipWebFetchPreflight"].clone()), (json!("dark"), json!(true)));
        let claude: Value = serde_json::from_str(&fs::read_to_string(home.join(".claude.json")).unwrap()).unwrap();
        assert_eq!((claude["mcpServers"]["mine"]["command"].clone(), claude["halti"].clone()), (json!("x"), json!(1)));
        assert_eq!(claude["mcpServers"][names::MCP_SERVER_KEY]["command"], json!(names::SHIM));

        fs::write(home.join(".claude.json"), "not json").unwrap();
        assert!(prepare_home(&dir.0, false).unwrap().is_empty());
        assert!(fs::read_to_string(home.join(".claude.json")).unwrap().contains(names::SHIM), "a broken file is replaced");

        assert!(!home.join(".docker").exists());
        fs::create_dir_all(home.join(".docker")).unwrap();
        fs::write(home.join(".docker/config.json"), r#"{"auths":{"x":{}}}"#).unwrap();
        assert!(prepare_home(&dir.0, true).unwrap().is_empty());
        let docker: Value = serde_json::from_str(&fs::read_to_string(home.join(".docker/config.json")).unwrap()).unwrap();
        assert_eq!((docker["auths"]["x"].clone(), docker["proxies"]["default"]["noProxy"].clone()), (json!({}), json!("localhost,127.0.0.1")));

        // However large: Claude Code keeps its history of projects in this file.
        let projects = "x".repeat(65 << 20);
        fs::write(home.join(".claude.json"), format!(r#"{{"projects":"{projects}"}}"#)).unwrap();
        assert!(prepare_home(&dir.0, false).unwrap().is_empty());
        let claude: Value = serde_json::from_slice(&fs::read(home.join(".claude.json")).unwrap()).unwrap();
        assert!(claude["projects"] == json!(projects), "a large file is kept");
        assert_eq!(claude["mcpServers"][names::MCP_SERVER_KEY]["command"], json!(names::SHIM));
    }

    #[test]
    fn a_settings_file_that_cant_be_read_is_left_alone() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return; // root reads it anyway
        }
        let dir = TempDir::new("halti-home").unwrap();
        let file = dir.0.join("home/.claude.json");
        fs::create_dir_all(dir.0.join("home")).unwrap();
        fs::write(&file, r#"{"mine":1}"#).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o200)).unwrap();
        let error = format!("{:#}", prepare_home(&dir.0, false).unwrap_err());
        assert!(error.contains("reading home/.claude.json"), "{error}");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), r#"{"mine":1}"#);
    }

    #[test]
    fn a_link_in_the_home_is_not_written_through() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new("halti-home-links").unwrap();
        let (home, outside) = (dir.0.join("home"), dir.0.join("outside"));
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(outside.join("claude")).unwrap();
        fs::write(outside.join("notes.txt"), "the person's own").unwrap();
        fs::write(outside.join("claude/settings.json"), r#"{"theirs":1}"#).unwrap();
        symlink(outside.join("notes.txt"), home.join(".claude.json")).unwrap();
        symlink(outside.join("claude"), home.join(".claude")).unwrap();
        symlink(outside.join("docker"), home.join(".docker")).unwrap();

        let replaced = prepare_home(&dir.0, true).unwrap();
        assert_eq!(replaced, [".docker", ".claude", ".claude.json"].map(|name| Path::new("home").join(name)), "named as the box sees them");
        assert_eq!(fs::read_to_string(outside.join("notes.txt")).unwrap(), "the person's own");
        assert_eq!(fs::read_to_string(outside.join("claude/settings.json")).unwrap(), r#"{"theirs":1}"#);
        assert!(!outside.join("docker").exists(), "nothing was made outside");
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 2);
        assert_eq!(fs::read_dir(outside.join("claude")).unwrap().count(), 1);

        // In their place, plain files of halti's, as in a home with no links.
        for file in [".docker/config.json", ".claude/settings.json", ".claude.json"] {
            assert!(!fs::symlink_metadata(home.join(file)).unwrap().file_type().is_symlink(), "{file}");
            assert!(!fs::symlink_metadata(home.join(file).parent().unwrap()).unwrap().file_type().is_symlink(), "{file}");
        }
        assert!(fs::read_to_string(home.join(".claude.json")).unwrap().contains(names::SHIM));
        assert!(prepare_home(&dir.0, true).unwrap().is_empty(), "the next start finds nothing to replace");
    }

    #[test]
    fn a_link_in_place_of_a_copy_is_kept_and_not_followed() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new("halti-clone-links").unwrap();
        let (work, outside, host) = (dir.0.join("work"), dir.0.join("outside"), dir.0.join("proj"));
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(&host).unwrap();
        fs::write(host.join("README"), "original").unwrap();
        symlink(&outside, work.join("proj")).unwrap();
        symlink(dir.0.join("gone"), work.join("other")).unwrap();

        clone_into(&work, "proj", &host).unwrap();
        clone_into(&work, "other", &host).unwrap();
        assert!(fs::read_dir(&outside).unwrap().next().is_none() && !dir.0.join("gone").exists(), "nothing was copied through a link");
        assert!(fs::symlink_metadata(work.join("other")).unwrap().file_type().is_symlink(), "the agent's link stays");

        clone_into(&work, "new", &host).unwrap();
        assert_eq!(fs::read_to_string(work.join("new/README")).unwrap(), "original");
    }
}
