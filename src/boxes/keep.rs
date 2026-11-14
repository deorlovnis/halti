//! A workspace that stays open: what `halti open` does once the workspace is opened and `main` has
//! chosen it as the place. It starts and stops the workspace's boxes when asked on its socket
//! (`crate::keep`), each box on a thread of its own, and asks nothing: opening the workspace was
//! the approval. A start held open is a session of its box, and a box stops when its last session
//! ends, or when it is asked to.
//!
//! Closing is one order, whatever asked for it (`halti close`, Ctrl-C, a closed terminal, `kill`):
//! from the first moment every start is refused (`busy`); every box is asked to stop and is put
//! away, one that is still starting once its start is done; the boxes of the workspace that other
//! terminals run are stopped; the keys are wiped; whoever asked is answered; the socket goes, and
//! the lock last.

use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, Scope};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use halti_core::boxkey::check_box;
use halti_core::ids::WsName;

use super::run::{self, Begun, World};
use super::store::{self, Layout};
use super::{BoxPolicy, KeyStore, MountRule};
use crate::approval::{Action, Means};
use crate::config::Settings;
use crate::engine::Vms;
use crate::keep::{self, No, Refused, Reply, Request};
use crate::source;
use crate::util::{say, sha256_hex, warn};

/// How many sessions one open workspace holds, of all its boxes.
const SESSIONS: usize = 32;
/// How many connections may wait to send their line at once.
const WAITING: usize = 32;
/// How often the keeper looks for a signal, a new connection, or a session that left.
const LOOK_EVERY: Duration = Duration::from_millis(100);
/// How long a box another halti runs is waited for once it is stopped: 60 times this.
const LET_GO_EVERY: Duration = Duration::from_millis(250);

/// A box's policy file, read once and checked before it starts: the copy kept when it was approved
/// is the same, a box that keeps a store has one, and its sockets fit. Its bytes, and what they
/// parse to.
pub struct Checked {
    pub text: Vec<u8>,
    pub policy: BoxPolicy,
}

/// The checks of a box's files before it starts, by its name, which the workspace's commands make.
pub type Check = Box<dyn Fn(&str) -> Result<Checked, Refused> + Send + Sync>;

/// What `halti open` hands on once the workspace is opened, to keep it open.
pub struct Keep {
    pub name: WsName,
    /// Held for as long as the workspace stays open.
    pub lock: store::Lock,
    pub layout: Layout,
    pub mounts: MountRule,
    /// None where this system has no box engine: then no box starts.
    pub vms: Option<&'static dyn Vms>,
    /// Read once, before the workspace was opened.
    pub settings: Settings,
    /// The boxes with a policy file, whose leftovers are put away before anything starts.
    pub boxes: Vec<String>,
    pub check: Check,
}

/// Keeps the workspace open until it is closed: by `halti close`, or a signal (Ctrl-C, a closed
/// terminal, `kill`). Its boxes are looked up through the place, which `main` has chosen.
pub fn serve(keep: Keep) -> Result<u8> {
    run::catch_signals();
    source::current().lock_keys();
    let settings = keep.settings.clone();
    let world = keep.vms.map(|vms| run::Real { vms, keys: KeyStore::of(&settings), settings: &settings });
    let ready = |name: &str, shown: &str, checked: &Checked| super::ready(name, shown, &checked.text, checked.policy.keep, &settings);
    let outside = Outside {
        world: world.as_ref().map(|world| world as &dyn World),
        vms: keep.vms,
        ready: &ready,
        close: run::signalled(),
        wipe: &|| source::current().close(),
        refused: &|| source::current().refused_reread(),
    };
    serve_with(keep, &outside)
}

/// What the keeper reaches outside itself; tests give their own.
struct Outside<'a> {
    /// What starts a box: none without an engine.
    world: Option<&'a dyn World>,
    /// What stops the VMs of boxes left behind, or run by other terminals.
    vms: Option<&'a dyn Vms>,
    /// The checks of a box's approval and key through the place.
    ready: &'a (dyn Fn(&str, &str, &Checked) -> Result<(), Refused> + Sync),
    /// Set by a signal: close.
    close: &'a AtomicBool,
    /// Wipes the workspace's keys.
    wipe: &'a (dyn Fn() + Sync),
    /// True once, after a lookup found the workspace's files gone back to an older state.
    refused: &'a (dyn Fn() -> bool + Sync),
}

fn serve_with(keep: Keep, outside: &Outside) -> Result<u8> {
    let Keep { name, lock, layout, mounts, vms: _, settings, boxes, check } = keep;
    let socket = layout.keeper_socket().ok_or_else(|| anyhow!("only a workspace stays open"))?;
    if let Some(vms) = outside.vms {
        let left = put_away_left(&layout, vms, &boxes);
        if !left.is_empty() {
            say(&format!("put away what the last open of {name} left: {}", left.join(", ")));
        }
    }
    let Some(listener) = keep::bind(&socket)? else {
        (outside.wipe)();
        bail!("another workspace is open at {name}'s socket");
    };
    listener.set_nonblocking(true)?;
    say(&format!("{name} is open in this terminal. close it with Ctrl-C, or from another terminal: halti close {name}"));
    let keeper = Keeper {
        name: &name,
        layout: &layout,
        mounts: &mounts,
        write: settings.means(Action::BoxWrite),
        world: outside.world,
        check: &*check,
        ready: outside.ready,
        close: outside.close,
        table: Mutex::default(),
        changed: Condvar::new(),
        waiting: AtomicUsize::new(0),
        closers: Mutex::default(),
        done: AtomicBool::new(false),
    };
    thread::scope(|scope| {
        let keeper = &keeper;
        let listener = &listener;
        scope.spawn(move || keeper.accept(scope, listener));
        while !keeper.closing() {
            if (outside.refused)() {
                warn(&format!("{name}'s files went back to an older state. its boxes are refused every secret. close {name} and check its files"));
            }
            thread::sleep(LOOK_EVERY);
        }
        let mut stopped = keeper.put_all_away();
        if let Some(vms) = outside.vms {
            let (others, held) = stop_others(&layout, vms);
            for box_name in &others {
                say(&format!("stopped box {name}/{box_name}"));
            }
            for box_name in &held {
                warn(&format!("box {name}/{box_name} still runs in another terminal. stop it with: halti ws stop {name}/{box_name}"));
            }
            stopped += others.len();
        }
        (outside.wipe)();
        keeper.answer_close(u32::try_from(stopped).unwrap_or(u32::MAX));
    });
    let _ = fs::remove_file(&socket);
    drop(lock);
    say(&format!("closed {name}"));
    Ok(0)
}

/// Where a box is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Starting,
    Running,
    Stopping,
    /// Its start was refused: `word` says how, to each session that waited for it.
    Ended,
}

/// One box the keeper started, or is starting. `round` tells it from a later start of the same box.
struct Slot {
    round: u64,
    state: State,
    /// The connections held open for it, and those that wait for its start.
    sessions: usize,
    /// Its `run::Request::stop`.
    stop: Arc<AtomicBool>,
    word: Option<Reply>,
}

#[derive(Default)]
struct Table {
    /// Every start from now on is refused.
    closing: bool,
    boxes: BTreeMap<String, Slot>,
    next: u64,
    /// The boxes put away while closing.
    put_away: usize,
}

impl Table {
    fn sessions(&self) -> usize {
        self.boxes.values().map(|slot| slot.sessions).sum()
    }

    fn slot(&mut self, name: &str, round: u64) -> Option<&mut Slot> {
        self.boxes.get_mut(name).filter(|slot| slot.round == round)
    }

    fn has(&self, name: &str, round: u64) -> bool {
        self.boxes.get(name).is_some_and(|slot| slot.round == round)
    }
}

/// The keeper, as its threads share it.
struct Keeper<'a> {
    name: &'a WsName,
    layout: &'a Layout,
    mounts: &'a MountRule,
    write: Option<Means>,
    world: Option<&'a dyn World>,
    check: &'a (dyn Fn(&str) -> Result<Checked, Refused> + Send + Sync),
    ready: &'a (dyn Fn(&str, &str, &Checked) -> Result<(), Refused> + Sync),
    close: &'a AtomicBool,
    table: Mutex<Table>,
    /// Told whenever a box's state, sessions or the table change.
    changed: Condvar,
    /// The connections that haven't sent their line yet.
    waiting: AtomicUsize,
    /// Who asked to close, and once it is closed, how many boxes were stopped.
    closers: Mutex<(Vec<UnixStream>, Option<u32>)>,
    /// Closed and answered: nothing more is accepted.
    done: AtomicBool,
}

fn reply(stream: &mut UnixStream, reply: Reply) {
    let _ = keep::write_line(stream, &reply.line());
}

impl<'a> Keeper<'a> {
    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'t>(&self, table: MutexGuard<'t, Table>) -> MutexGuard<'t, Table> {
        self.changed.wait(table).unwrap_or_else(PoisonError::into_inner)
    }

    fn closing_in(&self, table: &Table) -> bool {
        table.closing || self.close.load(Ordering::SeqCst)
    }

    fn closing(&self) -> bool {
        self.closing_in(&self.table())
    }

    /// Takes connections until the keeper is done, each on a thread of its own. One more than may
    /// wait to send its line, or one of another user, is closed with no answer.
    fn accept<'scope>(&'scope self, scope: &'scope Scope<'scope, '_>, listener: &'scope UnixListener) {
        while !self.done.load(Ordering::SeqCst) {
            let Ok((stream, _)) = listener.accept() else {
                thread::sleep(LOOK_EVERY);
                continue;
            };
            if self.waiting.fetch_add(1, Ordering::SeqCst) >= WAITING || !keep::peer_is_own(&stream) || stream.set_nonblocking(false).is_err() {
                self.waiting.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            scope.spawn(move || self.answer(scope, stream));
        }
    }

    /// Reads one request and answers it. A start keeps the connection as a session.
    fn answer<'scope>(&'scope self, scope: &'scope Scope<'scope, '_>, mut stream: UnixStream) {
        let line = keep::read_line(&mut stream, keep::LINE_WAIT);
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        let Some(line) = line else { return };
        let answer = match Request::parse(&line) {
            None => Reply::Unsupported,
            Some(request) if request.ws() != self.name => Reply::Other,
            Some(Request::Start(_, name)) => return self.start(scope, stream, name),
            Some(Request::Stop(_, name)) => self.stop(&name),
            Some(Request::Close(_)) => return self.asked_to_close(stream),
            Some(Request::Ping(_)) => Reply::Open(self.running()),
        };
        reply(&mut stream, answer);
    }

    /// How many boxes run.
    fn running(&self) -> u32 {
        let running = self.table().boxes.values().filter(|slot| slot.state == State::Running).count();
        u32::try_from(running).unwrap_or(u32::MAX)
    }

    /// `start`: a box that isn't there is started on a thread of its own; one that is starting is
    /// waited for; one that runs is joined. Once it runs, the connection is a session of it until
    /// the client leaves or the box is put away.
    fn start<'scope>(&'scope self, scope: &'scope Scope<'scope, '_>, mut stream: UnixStream, name: String) {
        let mut table = self.table();
        if self.closing_in(&table) {
            drop(table);
            return reply(&mut stream, Reply::Busy);
        }
        if table.sessions() >= SESSIONS {
            drop(table);
            return reply(&mut stream, Reply::Full);
        }
        let (round, fresh) = match table.boxes.get_mut(&name) {
            Some(slot) if matches!(slot.state, State::Starting | State::Running) => {
                slot.sessions += 1;
                (slot.round, false)
            }
            Some(_) => {
                drop(table);
                return reply(&mut stream, Reply::Busy);
            }
            None => {
                table.next += 1;
                let round = table.next;
                let stop = Arc::new(AtomicBool::new(false));
                table.boxes.insert(name.clone(), Slot { round, state: State::Starting, sessions: 1, stop: stop.clone(), word: None });
                let box_name = name.clone();
                scope.spawn(move || self.run_box(&box_name, round, &stop));
                (round, true)
            }
        };
        while let Some(slot) = table.slot(&name, round) {
            match slot.state {
                State::Starting => table = self.wait(table),
                State::Running | State::Stopping => break,
                State::Ended => {
                    slot.sessions -= 1;
                    let word = slot.word.clone().unwrap_or(Reply::No(No::Failed));
                    if slot.sessions == 0 {
                        table.boxes.remove(&name);
                    }
                    drop(table);
                    self.changed.notify_all();
                    return reply(&mut stream, word);
                }
            }
        }
        drop(table);
        let started = if fresh { Reply::Started } else { Reply::Running };
        if keep::write_line(&mut stream, &started.line()).is_ok() {
            self.hold(&mut stream, &name, round);
        } else {
            self.leave(&name, round);
        }
    }

    /// A session: until the client leaves (one session fewer), or the box is put away (`stopped`).
    fn hold(&self, stream: &mut UnixStream, name: &str, round: u64) {
        let _ = stream.set_read_timeout(Some(LOOK_EVERY));
        let mut ignored = [0u8; 64];
        loop {
            if !self.table().has(name, round) {
                return reply(stream, Reply::Stopped);
            }
            match stream.read(&mut ignored) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
                Err(_) => break,
            }
        }
        self.leave(name, round);
    }

    fn leave(&self, name: &str, round: u64) {
        if let Some(slot) = self.table().slot(name, round) {
            slot.sessions = slot.sessions.saturating_sub(1);
        }
        self.changed.notify_all();
    }

    /// One box, from its start to its end, on its own thread: checked, started, kept until it is
    /// asked to stop, its last session leaves or its VM is gone, then put away.
    fn run_box(&self, name: &str, round: u64, stop: &AtomicBool) {
        let shown = format!("{}/{name}", self.name);
        let ready = self.world.ok_or_else(|| Refused::new(No::Engine, anyhow!("boxes can't run on this system: halti has no box engine for it"))).and_then(|world| {
            let checked = (self.check)(name)?;
            (self.ready)(name, &shown, &checked)?;
            Ok((world, checked))
        });
        let (world, checked) = match ready {
            Ok(ready) => ready,
            Err(refused) => return self.refused(name, round, &shown, stop, refused),
        };
        let request = run::Request {
            name,
            id: name.to_string(),
            policy: &checked.policy,
            policy_sha: sha256_hex(&checked.text),
            persistent: checked.policy.keep,
            unique: false,
            command: None,
            tty: false,
            stop,
            write: self.write,
            shown: shown.clone(),
            stop_with: format!("halti ws stop {shown}"),
            mounts: self.mounts.clone(),
            confirm: false,
        };
        match run::start(self.layout, world, &request) {
            Err(refused) => self.refused(name, round, &shown, stop, refused),
            Ok(Begun::Elsewhere) => self.end(name, round, Reply::Elsewhere),
            Ok(Begun::Here(running)) => {
                self.set(name, round, State::Running);
                say(&format!("started box {shown}"));
                running.wait(&|| self.table().boxes.get(name).is_some_and(|slot| slot.round == round && slot.sessions == 0));
                self.set(name, round, State::Stopping);
                (*running).stop();
                say(&format!("stopped box {shown}"));
                let mut table = self.table();
                if table.has(name, round) {
                    table.boxes.remove(name);
                }
                if table.closing {
                    table.put_away += 1;
                }
                drop(table);
                self.changed.notify_all();
            }
        }
    }

    /// A start that was refused: its reason in full here, its kind to those who wait. One that a
    /// close cut short is only busy.
    fn refused(&self, name: &str, round: u64, shown: &str, stop: &AtomicBool, refused: Refused) {
        if stop.load(Ordering::SeqCst) {
            return self.end(name, round, Reply::Busy);
        }
        warn(&format!("box {shown} was not started: {:#}", refused.why));
        self.end(name, round, Reply::No(refused.no));
    }

    fn set(&self, name: &str, round: u64, state: State) {
        if let Some(slot) = self.table().slot(name, round) {
            slot.state = state;
        }
        self.changed.notify_all();
    }

    fn end(&self, name: &str, round: u64, word: Reply) {
        let mut table = self.table();
        if let Some(slot) = table.slot(name, round) {
            slot.state = State::Ended;
            slot.word = Some(word);
            if slot.sessions == 0 {
                table.boxes.remove(name);
            }
        }
        drop(table);
        self.changed.notify_all();
    }

    /// `stop`: the box is asked to stop, and answered once it is put away.
    fn stop(&self, name: &str) -> Reply {
        let mut table = self.table();
        if self.closing_in(&table) {
            return Reply::Busy;
        }
        let Some((round, state, stop)) = table.boxes.get(name).map(|slot| (slot.round, slot.state, slot.stop.clone())) else { return Reply::Idle };
        if state != State::Running {
            return Reply::Busy;
        }
        stop.store(true, Ordering::SeqCst);
        while table.has(name, round) {
            table = self.wait(table);
        }
        Reply::Stopped
    }

    /// `close`: answered once everything is put away.
    fn asked_to_close(&self, mut stream: UnixStream) {
        let mut closers = self.closers.lock().unwrap_or_else(PoisonError::into_inner);
        match closers.1 {
            Some(stopped) => reply(&mut stream, Reply::Closed(stopped)),
            None => closers.0.push(stream),
        }
        drop(closers);
        self.table().closing = true;
        self.changed.notify_all();
    }

    /// Refuses every start from now on, asks every box to stop, and waits until each is put away
    /// (one still starting finishes its start first). Returns how many were put away.
    fn put_all_away(&self) -> usize {
        let mut table = self.table();
        table.closing = true;
        for slot in table.boxes.values() {
            slot.stop.store(true, Ordering::SeqCst);
        }
        while !table.boxes.is_empty() {
            table = self.wait(table);
        }
        table.put_away
    }

    fn answer_close(&self, stopped: u32) {
        let mut closers = self.closers.lock().unwrap_or_else(PoisonError::into_inner);
        closers.1 = Some(stopped);
        for mut stream in closers.0.drain(..) {
            reply(&mut stream, Reply::Closed(stopped));
        }
        self.done.store(true, Ordering::SeqCst);
    }
}

/// Puts away what a halti that ended without cleaning up left of these boxes: for each whose lock
/// is free, its VMs if they run, its store if it is still attached, and a store made for one run.
/// Returns the boxes that had something left.
pub fn put_away_left(layout: &Layout, vms: &dyn Vms, boxes: &[String]) -> Vec<String> {
    let mut left = Vec::new();
    for name in boxes {
        let lock = layout.lock(name);
        if !lock.exists() {
            continue;
        }
        let Ok(Some(_held)) = store::lock(&lock) else { continue };
        let running: Vec<String> = [layout.vm(name), layout.browser_vm(name)].into_iter().filter(|vm| vms.running(vm)).collect();
        if running.is_empty() && !store::is_mounted(&layout.mount_point(name)) && !layout.ephemeral_bundle(name).exists() {
            continue;
        }
        for vm in &running {
            if let Err(e) = vms.stop(vm) {
                warn(&format!("stopping {vm}: {e:#}"));
            }
        }
        if let Err(e) = run::sweep(layout, name) {
            warn(&format!("box {name}: {e:#}"));
        }
        left.push(name.clone());
    }
    left
}

/// Stops the boxes in this layout that another halti runs, as `ws stop` does, names only: a box
/// started while its workspace wasn't open holds the workspace's keys in the process that runs it.
/// Each is waited for until that halti lets go of it, and what is left is cleared. Returns the
/// boxes that were stopped, and those whose halti held on.
pub fn stop_others(layout: &Layout, vms: &dyn Vms) -> (Vec<String>, Vec<String>) {
    let mut names: Vec<String> = fs::read_dir(layout.open_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.strip_suffix(".lock").map(str::to_string))
        .filter(|name| check_box(name).is_ok())
        .collect();
    names.sort();
    let (mut stopped, mut held) = (Vec::new(), Vec::new());
    for name in names {
        let lock = layout.lock(&name);
        if !store::is_held(&lock) {
            continue;
        }
        let vm = layout.vm(&name);
        if vms.running(&vm)
            && let Err(e) = vms.stop(&vm)
        {
            warn(&format!("stopping {vm}: {e:#}"));
        }
        let let_go = (0..60).any(|_| {
            let Ok(Some(_free)) = store::lock(&lock) else {
                thread::sleep(LET_GO_EVERY);
                return false;
            };
            let _ = run::sweep(layout, &name);
            let browser = layout.browser_vm(&name);
            if vms.running(&browser)
                && let Err(e) = vms.stop(&browser)
            {
                warn(&format!("stopping {browser}: {e:#}"));
            }
            true
        });
        if let_go { stopped.push(name) } else { held.push(name) }
    }
    (stopped, held)
}

#[cfg(test)]
mod tests;
