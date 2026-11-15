//! `halti link`: one process per joined machine, meant to run as a service from boot. It holds the
//! machine token and no key that signs or decrypts, and decides nothing. Three threads:
//!
//! - **Report.** Every second it asks this machine's open workspaces, on their sockets, which
//!   requests wait and which boxes run, for the workspaces a trusted device may see. When that
//!   changed, and at least every 20 seconds, it reports the whole state to the hub; the reply names
//!   the requests the hub lacks, which it then posts one by one (a hub that restarted has none),
//!   and lists the phones not revoked, from which the trust list is kept: a device not on a
//!   complete list is no longer trusted. Adding trust takes `halti devices trust`, never a list.
//! - **Inbox.** It holds one call to the hub that waits for what phones sent this machine: signed
//!   answers and stops. Each goes to the open workspace it names, which checks it, and what came of
//!   it is said to the hub with the next call.
//! - **Socket.** `link.sock` in its folder, 0600, for `halti devices trust` as the same user: lines
//!   of printable ASCII, at most 4 KiB with their newline.
//!
//! ```text
//! client: "halti-link/1 device NAME"   the keys and workspaces of the phone NAME, from the hub
//! link:   "halti-link/1 device JSON" | "halti-link/1 no WORD"
//! client: "halti-link/1 sync"          report now
//! link:   "halti-link/1 synced" | "halti-link/1 no WORD"
//! ```
//!
//! WORD is the hub's word for a refusal, or `unreachable` or `not-joined`.
//!
//! It renews its own token from day 10 of its life, by the hub's clock: it draws a new token, writes
//! it down as the next one, then asks the hub. If no reply comes, the next one is tried before
//! anything else is done, so a renewal the hub made and whose reply was lost costs nothing; one
//! the hub refuses is dropped. While it renews no other call is under way, so the old token is never
//! sent after the new one was used. A token the hub refuses for good (`unknown`, `expired`,
//! `conflict`) is noted in the folder, and `halti open`, `halti ws run` and `halti requests` then
//! say so.
//!
//! When the hub can't be reached it tries again, waiting longer each time, up to a minute. Nothing
//! on the machine waits for it: requests are answered at the machine as before.

use std::collections::HashMap;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use halti_core::ids::WsName;
use serde_json::{Value, json};

use super::files::{Entry, Folder, Joined};
use crate::hub::{pin, wire};
use crate::keep::{self, Records, Told};
use crate::requests::{Id, Record, RunId};
use crate::util::{self, hex, say};

/// The first word of every line on the link's socket.
pub const VERSION: &str = "halti-link/1";
/// The longest line on it, its newline included.
pub const LINE_MAX: usize = 4096;
/// How long the socket waits for a client's line.
const LINE_WAIT: Duration = Duration::from_secs(5);
/// How long an open workspace has to list its requests or runs, or to answer what a phone sent.
const KEEPER_WAIT: Duration = Duration::from_secs(5);
/// How long a signed answer may take at the open workspace: it settles at once, or says it doesn't.
const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// How long a signed stop may take there: until every box it names is put away.
const STOP_WAIT: Duration = Duration::from_secs(300);

/// How often the link does what it does. The tests make them shorter.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// How often it looks at the open workspaces.
    pub look: Duration,
    /// How often it reports its state when nothing changed.
    pub heartbeat: Duration,
    /// How often it asks the hub whether its token is due for renewal.
    pub renew_every: Duration,
    /// The longest wait before trying an unreachable hub again.
    pub retry_max: Duration,
    /// How long a call may take, past what the hub itself waits.
    pub call_wait: Duration,
}

pub const TIMING: Timing = Timing {
    look: Duration::from_secs(1),
    heartbeat: Duration::from_secs(20),
    renew_every: Duration::from_secs(3600),
    retry_max: Duration::from_secs(60),
    call_wait: Duration::from_secs(15),
};

/// This machine's workspaces, as the link sees them.
pub trait Local: Send + Sync {
    /// Every workspace, with the socket of its open workspace if it is open.
    fn workspaces(&self) -> Vec<(WsName, Option<PathBuf>)>;
}

/// How a call to the hub went wrong.
#[derive(Debug)]
enum Failed {
    /// No reply: the hub can't be reached, or isn't the pinned one.
    Down(String),
    /// A refusal: its status and word.
    Refused(u16, String),
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A phone's keys and workspaces, as the hub lists them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    pub signing_key: String,
    pub agreement_key: String,
    pub key_signature: String,
    pub ws: Vec<WsName>,
}

impl Listed {
    /// One as the hub writes it: every field there and of its form, or None.
    pub fn read(value: &Value) -> Option<Listed> {
        let object = value.as_object()?;
        if object.len() != 5 {
            return None;
        }
        let text = |field: &str| object.get(field)?.as_str().map(str::to_string);
        let key = |field: &str| text(field).filter(|hex| util::unhex(hex).is_some_and(|key| key.len() == wire::KEY_LEN));
        let name = text("name").filter(|name| wire::check_name(name).is_ok())?;
        let key_signature = text("key_signature").filter(|hex| util::unhex(hex).is_some_and(|sig| !sig.is_empty() && sig.len() <= halti_core::device::SIGNATURE_MAX))?;
        let ws = object.get("ws")?.as_array()?.iter().map(|ws| ws.as_str().and_then(|ws| WsName::parse(ws).ok())).collect::<Option<Vec<_>>>()?;
        Some(Listed { name, signing_key: key("signing_key")?, agreement_key: key("agreement_key")?, key_signature, ws })
    }

    /// Whether `entry` is this device with these keys.
    fn holds(&self, entry: &Entry) -> bool {
        self.name == entry.name && self.signing_key == entry.signing_key && self.agreement_key == entry.agreement_key
    }

    pub fn json(&self) -> Value {
        json!({"name": self.name, "signing_key": self.signing_key, "agreement_key": self.agreement_key, "key_signature": self.key_signature, "ws": self.ws})
    }
}

/// What the link saw at one look.
struct Look {
    /// The body of its report.
    state: Value,
    /// The requests that wait, each with its bytes.
    records: Vec<(Record, Vec<u8>)>,
    /// The trust list the report was made from.
    trust: Vec<Entry>,
}

/// The running link, as its threads share it.
pub struct Link<'a> {
    folder: &'a Folder,
    local: &'a dyn Local,
    timing: Timing,
    stop: &'a AtomicBool,
    /// Drawn as this process starts: the hub tells a restart by it.
    instance: [u8; 16],
    /// What `link.json` says. A call holds it for reading while it is under way; a renewal holds it
    /// for writing.
    joined: RwLock<Option<Joined>>,
    /// The workspace of each request it last saw, by id.
    ids: Mutex<HashMap<[u8; 16], WsName>>,
    /// Reports asked for (by the socket's `sync`) and made, and how the last one went.
    reports: Mutex<(u64, u64, Option<String>)>,
    reported: Condvar,
    /// The last thing said about the hub, so each is said once.
    said: Mutex<String>,
}

/// Runs the link in `folder` for this machine's workspaces until `stop` is set.
pub fn run(folder: &Folder, local: &dyn Local, timing: Timing, stop: &AtomicBool) -> Result<()> {
    folder.make()?;
    let Some(listener) = keep::bind(&folder.socket())? else { bail!("a link runs already as this user ({})", folder.socket().display()) };
    listener.set_nonblocking(true)?;
    let link = Link {
        folder,
        local,
        timing,
        stop,
        instance: util::random(),
        joined: RwLock::new(None),
        ids: Mutex::default(),
        reports: Mutex::new((0, 0, None)),
        reported: Condvar::new(),
        said: Mutex::default(),
    };
    thread::scope(|scope| {
        let link = &link;
        scope.spawn(move || link.inbox());
        scope.spawn(move || link.serve(&listener));
        link.report_loop();
    });
    let _ = std::fs::remove_file(folder.socket());
    Ok(())
}

impl Link<'_> {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Sleeps `wait`, or less if the link is stopped.
    fn nap(&self, wait: Duration) {
        let deadline = Instant::now() + wait;
        while !self.stopping() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            thread::sleep(left.min(Duration::from_millis(50)));
        }
    }

    /// Says `line` if it isn't what was said last.
    fn say_once(&self, line: &str) {
        let mut said = locked(&self.said);
        if *said != line {
            say(&format!("link: {line}"));
            *said = line.to_string();
        }
    }

    fn joined(&self) -> Option<Joined> {
        self.joined.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Takes what `link.json` says now: a join or a leave since, or the link's own last write.
    fn reread(&self) {
        match self.folder.joined() {
            Ok(now) if now == self.joined() => {}
            Ok(now) => {
                if let Some(now) = &now {
                    say(&format!("link: this machine is {} at the hub at {}", now.name, now.address));
                }
                *self.joined.write().unwrap_or_else(PoisonError::into_inner) = now;
            }
            Err(e) => self.say_once(&format!("{e:#}")),
        }
    }

    /// One call to the hub with the token, held for reading while it is under way.
    fn call(&self, method: &str, path: &str, body: Option<&Value>, wait: Duration) -> Result<Value, Failed> {
        let guard = self.joined.read().unwrap_or_else(PoisonError::into_inner);
        let Some(joined) = guard.as_ref() else { return Err(Failed::Refused(401, "not-joined".into())) };
        let token = joined.token.clone();
        self.call_with(joined, &token, method, path, body, wait)
    }

    /// One call with `token`, whatever holds it. A refusal for good is noted.
    fn call_with(&self, joined: &Joined, token: &str, method: &str, path: &str, body: Option<&Value>, wait: Duration) -> Result<Value, Failed> {
        let result = send(joined, token, method, path, body, wait);
        match &result {
            Ok(_) if self.folder.refused().is_some() => self.folder.clear_refused(),
            Err(Failed::Refused(401, word)) if matches!(word.as_str(), "unknown" | "expired" | "conflict") => {
                self.folder.set_refused(word);
                self.say_once(&format!("{} ({word})", super::REFUSED_LINE));
            }
            _ => {}
        }
        result
    }

    /// Says how a call went wrong, once, and how long to wait before the next.
    fn failed(&self, failed: &Failed, backoff: &mut Duration) -> Duration {
        match failed {
            Failed::Down(why) => self.say_once(&format!("the hub can't be reached ({why}): trying again")),
            Failed::Refused(_, word) if word == "pending" => self.say_once("the hub hasn't been told yet that this machine joined: answer y at halti pair there"),
            Failed::Refused(_, word) if word == "not-joined" => {}
            Failed::Refused(status, word) => self.say_once(&format!("the hub refused a call: {status} {word}")),
        }
        let wait = *backoff;
        *backoff = (*backoff * 2).min(self.timing.retry_max);
        wait
    }

    // --- the report ---

    fn report_loop(&self) {
        let mut last: Option<(Value, Instant)> = None;
        let mut backoff = self.timing.look;
        let mut renew_at = Instant::now();
        while !self.stopping() {
            self.reread();
            if self.joined().is_none() {
                self.say_once("this machine hasn't joined a hub: halti hub join");
                last = None;
                self.nap(self.timing.look);
                continue;
            }
            self.renew(&mut renew_at);
            // The reports asked for so far are made by the look that follows.
            let asked = locked(&self.reports).0;
            let look = self.look();
            let due = match &last {
                None => true,
                Some((body, at)) => *body != look.state || at.elapsed() >= self.timing.heartbeat || asked > locked(&self.reports).1,
            };
            if !due {
                self.nap(self.timing.look);
                continue;
            }
            match self.report(&look) {
                Ok(()) => {
                    last = Some((look.state, Instant::now()));
                    backoff = self.timing.look;
                    if let Some(joined) = self.joined() {
                        self.say_once(&format!("reporting to the hub at {} as {}", joined.address, joined.name));
                    }
                    self.reports_done(asked, None);
                    self.nap(self.timing.look);
                }
                Err(failed) => {
                    let word = match &failed {
                        Failed::Down(_) => "unreachable".to_string(),
                        Failed::Refused(_, word) => word.clone(),
                    };
                    self.reports_done(asked, Some(word));
                    let wait = self.failed(&failed, &mut backoff);
                    self.nap(wait);
                }
            }
        }
    }

    /// Notes that the reports asked for up to `asked` are made, and how the last went.
    fn reports_done(&self, asked: u64, failed: Option<String>) {
        let mut reports = locked(&self.reports);
        reports.1 = reports.1.max(asked);
        reports.2 = failed;
        drop(reports);
        self.reported.notify_all();
    }

    /// The state to report, the requests that wait, each with its bytes, and the trust list it was
    /// made from: of the workspaces a trusted device may see, those open asked on their sockets.
    fn look(&self) -> Look {
        let trust = self.folder.trust().unwrap_or_else(|e| {
            self.say_once(&format!("{e:#}"));
            Vec::new()
        });
        let name = self.joined().map(|joined| joined.name).unwrap_or_default();
        let mut trusted_ws: Vec<WsName> = Vec::new();
        for entry in &trust {
            for ws in &entry.ws {
                if !trusted_ws.contains(ws) {
                    trusted_ws.push(ws.clone());
                }
            }
        }
        let mut workspaces = Vec::new();
        let mut records = Vec::new();
        let mut ids = HashMap::new();
        for (ws, socket) in self.local.workspaces() {
            if !trusted_ws.contains(&ws) {
                continue;
            }
            let mut runs = Vec::new();
            let mut open = false;
            if let Some(socket) = socket {
                if let Some(Ok(listed)) = keep::list(&socket, &ws, KEEPER_WAIT) {
                    open = true;
                    for bytes in listed {
                        let Some(record) = Record::decode(&bytes).filter(|record| record.ws == ws.as_str()) else { continue };
                        if record.machine != name {
                            self.say_once(&format!("{ws} was opened before this machine joined as {name}: its requests name {}. close it and open it again", record.machine));
                            continue;
                        }
                        ids.insert(record.id.0, ws.clone());
                        records.push((record, bytes));
                    }
                }
                if let Some(Ok(running)) = keep::runs(&socket, &ws, KEEPER_WAIT) {
                    runs = running;
                }
            }
            let runs: Vec<Value> = runs.iter().map(|(name, run)| json!({"box": name, "run": run.hex()})).collect();
            workspaces.push(json!({"name": ws, "open": open, "runs": runs}));
        }
        *locked(&self.ids) = ids;
        let trusted: Vec<Value> = trust.iter().map(|entry| json!({"device": entry.name, "ws": entry.ws})).collect();
        let requests: Vec<String> = records.iter().map(|(record, _)| record.id.hex()).collect();
        Look { state: json!({"link": hex(&self.instance), "workspaces": workspaces, "trusted": trusted, "requests": requests}), records, trust }
    }

    /// Reports what `look` saw, posts the requests the hub lacks, and keeps the trust list to the
    /// phones the hub lists.
    fn report(&self, look: &Look) -> Result<(), Failed> {
        let reply = self.call("POST", "/v1/machine/state", Some(&look.state), self.timing.call_wait)?;
        let devices = reply["devices"].as_array().and_then(|devices| devices.iter().map(Listed::read).collect::<Option<Vec<_>>>());
        let missing = reply["missing"].as_array().and_then(|ids| ids.iter().map(|id| id.as_str().and_then(wire::unhex::<16>)).collect::<Option<Vec<_>>>());
        let (Some(devices), Some(missing)) = (devices, missing) else {
            self.say_once("the hub's reply to a report isn't one: the trust list is left as it is");
            return Ok(());
        };
        self.keep_trust(&devices, &look.trust);
        for id in missing {
            let Some((_, bytes)) = look.records.iter().find(|(record, _)| record.id.0 == id) else { continue };
            // A request the hub won't hold (expired, or one more than it holds) waits here as before.
            match self.call("POST", "/v1/machine/request", Some(&json!({"record": hex(bytes)})), self.timing.call_wait) {
                Ok(_) | Err(Failed::Refused(410, _)) => {}
                Err(Failed::Refused(429, _)) => self.say_once("the hub holds as many of this machine's requests as it takes: the rest are answered here"),
                Err(failed) => return Err(failed),
            }
        }
        Ok(())
    }

    /// Drops trust in every device the report named that isn't on the hub's complete list with the
    /// same keys. One trusted since the report was made is left for the next.
    fn keep_trust(&self, devices: &[Listed], reported: &[Entry]) {
        let gone = |entry: &Entry| {
            reported.iter().any(|named| named.name == entry.name && named.signing_key == entry.signing_key && named.agreement_key == entry.agreement_key)
                && !devices.iter().any(|device| device.holds(entry))
        };
        let dropped = self.folder.change_trust(|entries| {
            let dropped: Vec<String> = entries.iter().filter(|entry| gone(entry)).map(|entry| entry.name.clone()).collect();
            entries.retain(|entry| !gone(entry));
            let changed = !dropped.is_empty();
            (dropped, changed)
        });
        match dropped {
            Ok(dropped) => {
                for name in dropped {
                    say(&format!("link: {name} is no longer trusted here: the hub no longer lists it with the keys it was trusted with"));
                }
            }
            Err(e) => self.say_once(&format!("{e:#}")),
        }
    }

    // --- renewal ---

    /// Tries the next token if one is written down; otherwise, once `renew_every` has passed, asks
    /// the hub whether the token is due, and renews it if it is.
    fn renew(&self, renew_at: &mut Instant) {
        if self.joined().is_some_and(|joined| joined.next.is_some()) {
            return self.try_next();
        }
        if Instant::now() < *renew_at {
            return;
        }
        *renew_at = Instant::now() + self.timing.renew_every;
        let Ok(me) = self.call("GET", "/v1/me", None, self.timing.call_wait) else { return };
        let (Some(now), Some(from)) = (me["now"].as_str(), me["renew_from"].as_str()) else { return };
        let (Ok(now), Ok(from)) = (now.parse::<jiff::Timestamp>(), from.parse::<jiff::Timestamp>()) else { return };
        if now >= from && me["conflict"].is_null() {
            self.renew_now();
        }
    }

    /// The next token, tried before anything else is sent: the token from now on if it works,
    /// dropped if the hub doesn't know it, kept to try again if the hub can't be reached.
    fn try_next(&self) {
        let mut guard = self.joined.write().unwrap_or_else(PoisonError::into_inner);
        let Some(joined) = guard.clone() else { return };
        let Some(next) = &joined.next else { return };
        // The hub may not know it: that is no refusal of the token this machine holds.
        match send(&joined, next, "GET", "/v1/me", None, self.timing.call_wait) {
            Ok(_) => {
                let renewed = Joined { token: next.clone(), next: None, ..joined };
                if self.write(&mut guard, renewed) {
                    say("link: renewed this machine's token");
                }
            }
            Err(Failed::Refused(401, word)) if word == "unknown" => {
                self.write(&mut guard, Joined { next: None, ..joined });
            }
            Err(_) => {}
        }
    }

    /// Renews the token, with no other call under way: a new token is drawn and written down as the
    /// next one before the hub is asked.
    fn renew_now(&self) {
        let mut guard = self.joined.write().unwrap_or_else(PoisonError::into_inner);
        let Some(joined) = guard.clone().filter(|joined| joined.next.is_none()) else { return };
        let new = format!("{}{}", wire::Kind::Machine.prefix(), hex(&util::random::<32>()));
        // Written down before it is sent: a reply lost, or this process ended, still finds it.
        if !self.write(&mut guard, Joined { next: Some(new.clone()), ..joined.clone() }) {
            return;
        }
        let body = json!({"token_hash": hex(&wire::token_hash(&new))});
        match self.call_with(&joined, &joined.token, "POST", "/v1/renew", Some(&body), self.timing.call_wait) {
            Ok(reply) => {
                if self.write(&mut guard, Joined { token: new, next: None, ..joined }) {
                    say(&format!("link: renewed this machine's token; it works until {}", reply["expires"].as_str().unwrap_or("?")));
                }
            }
            // No reply: the hub may have taken it, so the new token is tried first next time.
            Err(Failed::Down(_)) => {}
            Err(Failed::Refused(status, word)) => {
                self.say_once(&format!("the hub refused to renew this machine's token: {status} {word}"));
                self.write(&mut guard, Joined { next: None, ..joined });
            }
        }
    }

    /// Writes `joined` down, and holds it once it is: whether it was.
    fn write(&self, held: &mut Option<Joined>, joined: Joined) -> bool {
        match self.folder.write_joined(&joined) {
            Ok(()) => {
                *held = Some(joined);
                true
            }
            Err(e) => {
                self.say_once(&format!("{e:#}"));
                false
            }
        }
    }

    // --- the inbox ---

    fn inbox(&self) {
        let mut done: Vec<Value> = Vec::new();
        let mut backoff = self.timing.look;
        while !self.stopping() {
            if self.joined().is_none() {
                self.nap(self.timing.look);
                continue;
            }
            let wait = crate::hub::INBOX_WAIT + self.timing.call_wait;
            match self.call("POST", "/v1/machine/inbox", Some(&json!({"done": done})), wait) {
                Ok(reply) => {
                    backoff = self.timing.look;
                    done.clear();
                    for item in reply["items"].as_array().map(Vec::as_slice).unwrap_or_default() {
                        if let Some(n) = item["n"].as_u64() {
                            done.push(json!({"n": n, "said": self.deliver(item)}));
                        }
                    }
                }
                Err(failed) => {
                    let wait = self.failed(&failed, &mut backoff);
                    self.nap(wait);
                }
            }
        }
    }

    /// The socket of the open workspace `ws`, if it is open.
    fn keeper(&self, ws: &WsName) -> Option<PathBuf> {
        self.local.workspaces().into_iter().find(|(name, _)| name == ws).and_then(|(_, socket)| socket)
    }

    /// Hands an item to the open workspace it names, and says what came of it: the workspace's
    /// word, `unreached` if none answered, `malformed` for an item that isn't one.
    fn deliver(&self, item: &Value) -> &'static str {
        let text = |field: &str| item[field].as_str();
        let device = text("device").filter(|name| crate::fields::is_name(name));
        let ws = text("ws").and_then(|ws| WsName::parse(ws).ok());
        let signature = text("signature").and_then(util::unhex).filter(|sig| !sig.is_empty() && sig.len() <= halti_core::device::SIGNATURE_MAX);
        let (Some(device), Some(ws), Some(signature)) = (device, ws, signature) else { return "malformed" };
        let device = device.to_string();
        match text("kind") {
            Some("answer") => {
                let id = text("id").and_then(wire::unhex::<16>).map(Id);
                let yes = match text("decision") {
                    Some("yes") => Some(true),
                    Some("no") => Some(false),
                    _ => None,
                };
                let (Some(id), Some(yes)) = (id, yes) else { return "malformed" };
                // The workspace is the one this machine's own listing gave the id, where it has it.
                let ws = locked(&self.ids).get(&id.0).cloned().unwrap_or(ws);
                let Some(socket) = self.keeper(&ws) else { return "unreached" };
                match keep::tell(&socket, &Records::Signed { ws, device, yes, id, signature }, ANSWER_WAIT) {
                    Some(Told::Approved) => "approved",
                    Some(Told::Denied) => "denied",
                    Some(Told::Gone) => "gone",
                    Some(Told::Refused) => "refused",
                    _ => "unreached",
                }
            }
            Some("stop") => {
                let runs = item["runs"].as_array().and_then(|runs| runs.iter().map(|run| run.as_str().and_then(RunId::parse)).collect::<Option<Vec<_>>>());
                let Some(runs) = runs.filter(|runs| !runs.is_empty() && runs.len() <= keep::STOP_RUNS_MAX) else { return "malformed" };
                let Some(socket) = self.keeper(&ws) else { return "unreached" };
                match keep::tell(&socket, &Records::Stop { ws, device, runs, signature }, STOP_WAIT) {
                    Some(Told::Stopped(0)) => "none",
                    Some(Told::Stopped(_)) => "stopped",
                    Some(Told::Refused) => "refused",
                    _ => "unreached",
                }
            }
            // A kind this link doesn't know is said so, and nothing is done with it.
            _ => "unknown",
        }
    }

    // --- the socket ---

    fn serve(&self, listener: &UnixListener) {
        while !self.stopping() {
            match listener.accept() {
                Ok((stream, _)) if keep::peer_is_own(&stream) && stream.set_nonblocking(false).is_ok() => self.answer(stream),
                Ok(_) => {}
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    fn answer(&self, mut stream: UnixStream) {
        let Some(line) = keep::read_line_up_to(&mut stream, LINE_WAIT, LINE_MAX) else { return };
        let words: Vec<&str> = line.strip_prefix(VERSION).and_then(|rest| rest.strip_prefix(' ')).map(|rest| rest.split(' ').collect()).unwrap_or_default();
        let reply = match words[..] {
            ["device", name] if wire::check_name(name).is_ok() => self.device(name),
            ["sync"] => self.sync(),
            _ => "no malformed".to_string(),
        };
        let _ = keep::write_line(&mut stream, &format!("{VERSION} {reply}\n"));
    }

    /// The phone `name`'s keys and workspaces from the hub, as the socket says them.
    fn device(&self, name: &str) -> String {
        match self.call("POST", "/v1/machine/device", Some(&json!({"name": name})), self.timing.call_wait) {
            Ok(reply) => match Listed::read(&reply) {
                Some(listed) => format!("device {}", listed.json()),
                None => "no malformed".to_string(),
            },
            Err(Failed::Down(_)) => "no unreachable".to_string(),
            Err(Failed::Refused(_, word)) if wire::check_name(&word).is_ok() => format!("no {word}"),
            Err(Failed::Refused(..)) => "no refused".to_string(),
        }
    }

    /// Asks for a report now, and waits for it.
    fn sync(&self) -> String {
        let mut reports = locked(&self.reports);
        reports.0 += 1;
        let asked = reports.0;
        let deadline = Instant::now() + self.timing.call_wait * 2;
        while reports.1 < asked {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || self.stopping() {
                return "no unreachable".to_string();
            }
            reports = self.reported.wait_timeout(reports, left).unwrap_or_else(PoisonError::into_inner).0;
        }
        match &reports.2 {
            None => "synced".to_string(),
            Some(word) => format!("no {word}"),
        }
    }
}

/// One call to the hub `joined` names, with `token`: the reply's body, or how it went wrong.
fn send(joined: &Joined, token: &str, method: &str, path: &str, body: Option<&Value>, wait: Duration) -> Result<Value, Failed> {
    let pin = joined.pin().map_err(|e| Failed::Down(format!("{e:#}")))?;
    let (status, reply) = pin::request(&joined.address, pin, method, path, Some(token), body, wait).map_err(|e| Failed::Down(format!("{e:#}")))?;
    if (200..300).contains(&status) {
        return Ok(reply);
    }
    Err(Failed::Refused(status, reply["error"].as_str().unwrap_or("").to_string()))
}

/// What the link at `socket` answers to `words`: the words after the version, or None if no link
/// answered in time.
pub fn ask(socket: &std::path::Path, words: &str, wait: Duration) -> Option<String> {
    let mut stream = keep::connect(socket)?;
    keep::write_line(&mut stream, &format!("{VERSION} {words}\n")).ok()?;
    keep::read_line_up_to(&mut stream, wait, LINE_MAX)?.strip_prefix(VERSION)?.strip_prefix(' ').map(str::to_string)
}
