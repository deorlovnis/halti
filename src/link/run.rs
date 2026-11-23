//! `halti link`: one process per joined machine, meant to run as a service from boot. It holds the
//! machine token and no key that signs or decrypts, and decides nothing. Three threads:
//!
//! - **Report.** Every second it asks this machine's open workspaces, on their sockets, which
//!   requests wait, which notices that an agent waits are sent (`crate::notices`) and which boxes
//!   run, for the workspaces a trusted device may see. When that changed, and at least every 20
//!   seconds, it reports the whole state to the hub, cut to what the hub takes in a report; the
//!   reply names the requests the hub lacks and has room for, which it then posts one by one (a hub
//!   that restarted has none), and lists the phones not revoked, from which the trust list is kept:
//!   a device not on a complete list is no longer trusted. Adding trust takes `halti devices
//!   trust`, never a list. Then it names the open notices to the hub, which closes the rest, and
//!   posts each the hub lacks, sealed by the machine key to each device trusted for its workspace,
//!   and again when those devices change. That is the only key it reads, and only to seal: a copy
//!   is made once, kept while its notice is open, and the key read again for the next. The questions
//!   of agents in runs marked away come sealed already from the open workspace, which alone can
//!   read them (`crate::questions`): it names them to the hub, with the phones each is sealed to,
//!   and posts each copy the hub lacks. So a question asked while the hub can't be reached is
//!   posted when it can.
//! - **Inbox.** It holds one call to the hub that waits for what phones sent this machine: signed
//!   answers and stops, and sealed answers to questions. Each goes to the open workspace it names,
//!   which checks it, and what came of it is said to the hub with the next call, with the receipt
//!   the open workspace sealed for the phone if there is one. A stop waits until its boxes are put away, so each
//!   is handed over on a thread of its own and answers go on meanwhile. An item of a kind this link
//!   doesn't know is said `unknown`.
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
//! it down as the next one, then asks the hub. If no reply comes, every call first tries the next
//! one, and none is sent with the old one until the hub has answered that try: the new token from
//! then on if the hub knows it, the old one again if it doesn't. So a renewal the hub made and
//! whose reply was lost costs nothing, nor does a lost reply to that try, and the old token is
//! never sent after the new one was used. While it renews or tries no other call is under way. It
//! writes `link.json` only over what it read there, so a leave or a join meanwhile stands. A token
//! the hub refuses for good (`unknown`, `expired`, `conflict`) is noted in the folder, and
//! `halti open`, `halti ws run` and `halti requests` then say so.
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
use halti_core::sealed;
use serde_json::{Value, json};

use super::files::{Entry, Folder, Joined};
use crate::hub::{BODY_MAX, ITEMS_MAX, NOTICES_MAX, QUESTIONS_MAX, REPORT_IDS_MAX, REPORT_MAX, STATE_BODY_MAX, pin, wire};
use crate::keep::{self, Records, STOP_RUNS_MAX, Told};
use crate::notices::Notice;
use crate::questions;
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

/// What a phone sent this machine, read whole from what the hub handed over: a signed answer, or
/// a signed stop of runs, each with the box the phone named it with.
enum Inbound {
    Answer {
        ws: WsName,
        device: String,
        id: Id,
        yes: bool,
        signature: Vec<u8>,
    },
    Stop {
        ws: WsName,
        device: String,
        runs: Vec<(String, RunId)>,
        signature: Vec<u8>,
    },
    /// A sealed answer to a question.
    Reply {
        ws: WsName,
        device: String,
        id: Id,
        sealed: Vec<u8>,
    },
}

/// What came of the items the hub handed over, each known by its number and signature: a hub
/// that restarted numbers its items from 1 again.
#[derive(Default)]
struct Handled {
    /// Handled, and to be said to the hub with the next call: the number, the signature (for a
    /// sealed answer, the sealed bytes), the word, and the receipt for the phone, if there is one.
    said: Vec<(u64, String, &'static str, Option<String>)>,
    /// Being handled on a thread of its own.
    under_way: Vec<(u64, String)>,
}

/// What the link saw at one look.
struct Look {
    /// The body of its report.
    state: Value,
    /// The requests that wait, each with its bytes.
    records: Vec<(Record, Vec<u8>)>,
    /// The notices that are open, each with its bytes and the text it is sealed with.
    notices: Vec<(Notice, Vec<u8>, Vec<u8>)>,
    /// The questions that wait, each its clear fields read, their bytes, and a copy for each phone.
    questions: Vec<Asking>,
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
    /// What was said about this machine's own state, each once while the link runs.
    noted: Mutex<Vec<String>>,
    /// What came of the items the hub handed over, until the hub is told.
    handled: Mutex<Handled>,
    /// Each notice's copy sealed to a device, by the notice's bytes, the device's name and its
    /// second key, while the notice is open.
    sealed: Mutex<HashMap<CopyOf, Vec<u8>>>,
    /// Each open notice the hub was given, with the devices, by name and second key, it was
    /// sealed to then. When those change it is given again.
    posted: Mutex<HashMap<[u8; 16], Devices>>,
}

/// A question that waits: its clear fields read, their bytes, and a copy for each phone.
type Asking = (questions::Record, Vec<u8>, Vec<(String, Vec<u8>)>);

/// Which copy of a notice: its bytes, the text it is sealed with, and the name and second key of the
/// device it is sealed to.
type CopyOf = (Vec<u8>, Vec<u8>, String, String);

/// The devices a notice is sealed to, each its name and second key.
type Devices = Vec<(String, String)>;

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
        noted: Mutex::default(),
        handled: Mutex::default(),
        sealed: Mutex::default(),
        posted: Mutex::default(),
    };
    thread::scope(|scope| {
        let link = &link;
        scope.spawn(move || link.inbox(scope));
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

    /// Says `line` if it wasn't said before while the link runs.
    fn note_once(&self, line: String) {
        let mut noted = locked(&self.noted);
        if !noted.contains(&line) {
            say(&format!("link: {line}"));
            noted.push(line);
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

    /// One call to the hub with the token, held for reading while it is under way. A next token
    /// written down is tried first, and until the hub has answered that, nothing is sent.
    fn call(&self, method: &str, path: &str, body: Option<&Value>, wait: Duration) -> Result<Value, Failed> {
        loop {
            let guard = self.joined.read().unwrap_or_else(PoisonError::into_inner);
            let Some(joined) = guard.as_ref() else { return Err(Failed::Refused(401, "not-joined".into())) };
            if joined.next.is_none() {
                let token = joined.token.clone();
                return self.call_with(joined, &token, method, path, body, wait);
            }
            drop(guard);
            self.try_next()?;
        }
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
        let mut last: Option<(Value, Vec<Vec<u8>>, Instant)> = None;
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
            let mut notices: Vec<Vec<u8>> = look.notices.iter().map(|(notice, _, _)| notice.id.0.to_vec()).collect();
            // A question, or the phones it is sealed to, changing is a change too.
            for (record, _, copies) in &look.questions {
                notices.push(record.id.0.iter().copied().chain(copies.iter().flat_map(|(device, _)| device.bytes().chain([b' ']))).collect());
            }
            let due = match &last {
                None => true,
                Some((body, open, at)) => *body != look.state || *open != notices || at.elapsed() >= self.timing.heartbeat || asked > locked(&self.reports).1,
            };
            if !due {
                self.nap(self.timing.look);
                continue;
            }
            match self.report(&look) {
                Ok(()) => {
                    last = Some((look.state, notices, Instant::now()));
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
        let mut trust = self.folder.trust().unwrap_or_else(|e| {
            self.say_once(&format!("{e:#}"));
            Vec::new()
        });
        if trust.len() > REPORT_MAX {
            self.note_once(format!("this machine trusts more than {REPORT_MAX} devices: the hub is told of the first {REPORT_MAX}"));
            trust.truncate(REPORT_MAX);
        }
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
        let mut notices = Vec::new();
        let mut asked = Vec::new();
        let mut ids = HashMap::new();
        for (ws, socket) in self.local.workspaces() {
            if !trusted_ws.contains(&ws) {
                continue;
            }
            if workspaces.len() == REPORT_MAX {
                self.note_once(format!("more than {REPORT_MAX} workspaces have a trusted device: the hub is told of {REPORT_MAX}"));
                break;
            }
            let mut runs = Vec::new();
            let mut open = false;
            if let Some(socket) = socket {
                if let Some(Ok(listed)) = keep::list(&socket, &ws, KEEPER_WAIT) {
                    open = true;
                    for bytes in listed {
                        let Some(record) = Record::decode(&bytes).filter(|record| record.ws == ws.as_str()) else { continue };
                        if record.machine != name {
                            self.note_once(format!("{ws} has requests raised before this machine joined as {name}: they name {}, and are answered here", record.machine));
                            continue;
                        }
                        if records.len() == REPORT_IDS_MAX {
                            self.note_once(format!("more than {REPORT_IDS_MAX} requests wait: the hub is told of {REPORT_IDS_MAX}, and the rest are answered here"));
                            break;
                        }
                        ids.insert(record.id.0, ws.clone());
                        records.push((record, bytes));
                    }
                }
                for (bytes, said) in keep::notices(&socket, &ws, KEEPER_WAIT).and_then(Result::ok).unwrap_or_default() {
                    let Some(notice) = Notice::decode(&bytes).filter(|notice| notice.ws == ws.as_str() && notice.machine == name) else { continue };
                    if notices.len() == NOTICES_MAX {
                        self.note_once(format!("more than {NOTICES_MAX} agents wait: the hub is told of {NOTICES_MAX}"));
                        break;
                    }
                    notices.push((notice, bytes, said));
                }
                for (bytes, copies) in keep::questions(&socket, &ws, KEEPER_WAIT).and_then(Result::ok).unwrap_or_default() {
                    let Some(record) = questions::Record::decode(&bytes).filter(|record| record.ws == ws.as_str() && record.machine == name) else { continue };
                    if asked.len() == QUESTIONS_MAX {
                        self.note_once(format!("more than {QUESTIONS_MAX} agents ask: the hub is told of {QUESTIONS_MAX}"));
                        break;
                    }
                    asked.push((record, bytes, copies));
                }
                if let Some(Ok(running)) = keep::runs(&socket, &ws, KEEPER_WAIT) {
                    runs = running;
                }
                if runs.len() > STOP_RUNS_MAX {
                    self.note_once(format!("more than {STOP_RUNS_MAX} boxes run in {ws}: the hub is told of {STOP_RUNS_MAX}"));
                    runs.truncate(STOP_RUNS_MAX);
                }
            }
            let runs: Vec<Value> = runs.iter().map(|(name, run)| json!({"box": name, "run": run.hex()})).collect();
            workspaces.push(json!({"name": ws, "open": open, "runs": runs}));
        }
        let trusted: Vec<Value> = trust.iter().map(|entry| json!({"device": entry.name, "ws": entry.ws})).collect();
        let state = |records: &[(Record, Vec<u8>)]| {
            let requests: Vec<String> = records.iter().map(|(record, _)| record.id.hex()).collect();
            json!({"link": hex(&self.instance), "workspaces": workspaces, "trusted": trusted, "requests": requests})
        };
        // A report the hub would refuse as too large names fewer requests: the rest are answered here.
        while !records.is_empty() && state(&records).to_string().len() > STATE_BODY_MAX {
            let (record, _) = records.pop().expect("not empty");
            ids.remove(&record.id.0);
            self.note_once("this machine's report is longer than the hub takes: it names fewer requests, and the rest are answered here".to_string());
        }
        *locked(&self.ids) = ids;
        Look { state: state(&records), records, notices, questions: asked, trust }
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
                // The rest would be refused too.
                Err(Failed::Refused(429, _)) => {
                    self.say_once("the hub holds as many of this machine's requests as it takes: the rest are answered here");
                    break;
                }
                Err(failed) => return Err(failed),
            }
        }
        self.post_notices(look)?;
        self.post_questions(look)
    }

    /// Names the questions that wait to the hub, each with the phones it is sealed to: the hub drops
    /// the rest, and the copies of phones not named. Then posts each copy the hub lacks. A hub that
    /// carries no questions is noted once.
    fn post_questions(&self, look: &Look) -> Result<(), Failed> {
        let listed: Vec<Value> =
            look.questions.iter().map(|(record, _, copies)| json!({"id": record.id.hex(), "devices": copies.iter().map(|(device, _)| device).collect::<Vec<_>>()})).collect();
        let reply = match self.call("POST", "/v1/machine/questions", Some(&json!({"questions": listed})), self.timing.call_wait) {
            Ok(reply) => reply,
            Err(Failed::Refused(404, _)) => {
                if !look.questions.is_empty() {
                    self.note_once("the hub carries no questions of agents: it runs an older halti, so they are answered here".to_string());
                }
                return Ok(());
            }
            Err(failed) => return Err(failed),
        };
        let missing = reply["missing"].as_array().map(Vec::as_slice).unwrap_or_default();
        for wanted in missing {
            let (Some(id), Some(device)) = (wanted["id"].as_str().and_then(wire::unhex::<16>), wanted["device"].as_str()) else { continue };
            let Some((_, bytes, copies)) = look.questions.iter().find(|(record, _, _)| record.id.0 == id) else { continue };
            let Some((_, sealed)) = copies.iter().find(|(named, _)| named == device) else { continue };
            let body = json!({"record": hex(bytes), "device": device, "sealed": hex(sealed)});
            match self.call("POST", "/v1/machine/question", Some(&body), self.timing.call_wait) {
                Ok(_) | Err(Failed::Refused(410, _)) => {}
                Err(Failed::Refused(429, _)) => {
                    self.say_once("the hub holds as many of this machine's questions as it takes: the rest are answered here");
                    break;
                }
                Err(failed) => return Err(failed),
            }
        }
        Ok(())
    }

    /// Names the open notices to the hub, which closes the rest, and posts each it lacks, sealed
    /// to each device trusted for its workspace. One whose devices changed since it was posted, as
    /// a phone was trusted, untrusted or paired again, is posted again with the copies of now. A
    /// hub that carries no notices is noted once.
    fn post_notices(&self, look: &Look) -> Result<(), Failed> {
        let ids: Vec<String> = look.notices.iter().map(|(notice, _, _)| notice.id.hex()).collect();
        let reply = match self.call("POST", "/v1/machine/notices", Some(&json!({"notices": ids})), self.timing.call_wait) {
            Ok(reply) => reply,
            Err(Failed::Refused(404, _)) => {
                self.note_once("the hub carries no notices that an agent waits: it runs an older halti".to_string());
                return Ok(());
            }
            Err(failed) => return Err(failed),
        };
        locked(&self.sealed).retain(|(bytes, _, _, _), _| look.notices.iter().any(|(_, open, _)| open == bytes));
        locked(&self.posted).retain(|id, _| look.notices.iter().any(|(notice, _, _)| notice.id.0 == *id));
        let missing: Vec<[u8; 16]> = reply["missing"].as_array().map(Vec::as_slice).unwrap_or_default().iter().filter_map(|id| id.as_str().and_then(wire::unhex::<16>)).collect();
        for (notice, bytes, said) in &look.notices {
            let id = notice.id.0;
            let devices = sealed_to(&notice.ws, &look.trust).map(|(entry, _)| (entry.name.clone(), entry.agreement_key.clone())).collect::<Vec<_>>();
            let changed = locked(&self.posted).get(&id).is_some_and(|posted| *posted != devices);
            if !missing.contains(&id) && !changed {
                continue;
            }
            let mut copies = self.copies(notice, bytes, said, &look.trust);
            let body = |copies: &[Value]| json!({"record": hex(bytes), "sealed": copies});
            while !copies.is_empty() && body(&copies).to_string().len() > BODY_MAX {
                copies.pop();
                self.note_once(format!("more devices are trusted for {} than one notice takes: the last ones aren't told", notice.ws));
            }
            if copies.is_empty() {
                continue;
            }
            match self.call("POST", "/v1/machine/notice", Some(&body(&copies)), self.timing.call_wait) {
                Ok(_) => {
                    locked(&self.posted).insert(id, devices);
                }
                Err(Failed::Refused(429, _)) => {
                    self.say_once("the hub holds as many of this machine's notices as it takes: the rest aren't told");
                    break;
                }
                Err(failed) => return Err(failed),
            }
        }
        Ok(())
    }

    /// A copy of `notice`, whose bytes are `bytes`, sealed with the text `said` by the machine key
    /// to each device in `trust` that is trusted for its workspace: those made before, and the rest
    /// made now.
    fn copies(&self, notice: &Notice, bytes: &[u8], said: &[u8], trust: &[Entry]) -> Vec<Value> {
        let mut key = None;
        let mut copies = Vec::new();
        for (entry, second) in sealed_to(&notice.ws, trust) {
            let held = (bytes.to_vec(), said.to_vec(), entry.name.clone(), entry.agreement_key.clone());
            let made = locked(&self.sealed).get(&held).cloned();
            let sealed = match made {
                Some(sealed) => sealed,
                None => {
                    if key.is_none() {
                        key = match self.folder.sealing_key() {
                            Ok(Some(key)) => Some(key),
                            Ok(None) => return Vec::new(),
                            Err(e) => {
                                self.say_once(&format!("{e:#}"));
                                return Vec::new();
                            }
                        };
                    }
                    let machine = key.as_ref().expect("read above");
                    let Ok(sealed) = sealed::seal(sealed::Kind::Notice, machine, &second, bytes, said, &util::random()) else { continue };
                    locked(&self.sealed).insert(held, sealed.clone());
                    sealed
                }
            };
            copies.push(json!({"device": entry.name, "sealed": hex(&sealed)}));
        }
        copies
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

    /// Once `renew_every` has passed, asks the hub whether the token is due, and renews it if it
    /// is. A next token written down is tried first, as before every call.
    fn renew(&self, renew_at: &mut Instant) {
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

    /// The next token, tried before anything else is sent: the token from now on if the hub takes
    /// it, dropped if the hub refuses it (it never took the renewal, or refuses this machine's
    /// token anyway, which the token held then hears). Kept, and how the try went, if no answer
    /// came.
    fn try_next(&self) -> Result<(), Failed> {
        let mut guard = self.joined.write().unwrap_or_else(PoisonError::into_inner);
        let Some(joined) = guard.clone() else { return Ok(()) };
        let Some(next) = joined.next.clone() else { return Ok(()) };
        match send(&joined, &next, "GET", "/v1/me", None, self.timing.call_wait) {
            Ok(_) => {
                self.keep(&mut guard, &joined, Joined { token: next, next: None, ..joined.clone() });
                say("link: renewed this machine's token");
                Ok(())
            }
            Err(Failed::Refused(401, _)) => {
                self.keep(&mut guard, &joined, Joined { next: None, ..joined.clone() });
                Ok(())
            }
            Err(failed) => Err(failed),
        }
    }

    /// Renews the token, with no other call under way: a new token is drawn and written down as the
    /// next one before the hub is asked.
    fn renew_now(&self) {
        let mut guard = self.joined.write().unwrap_or_else(PoisonError::into_inner);
        let Some(joined) = guard.clone().filter(|joined| joined.next.is_none()) else { return };
        let new = format!("{}{}", wire::Kind::Machine.prefix(), hex(&util::random::<32>()));
        let pending = Joined { next: Some(new.clone()), ..joined.clone() };
        // Written down before it is sent: a reply lost, or this process ended, still finds it.
        match self.folder.change_joined(&joined, &pending) {
            Ok(true) => *guard = Some(pending.clone()),
            Ok(false) => {
                *guard = None;
                return;
            }
            Err(e) => {
                self.say_once(&format!("{e:#}"));
                return;
            }
        }
        let body = json!({"token_hash": hex(&wire::token_hash(&new))});
        match self.call_with(&joined, &joined.token, "POST", "/v1/renew", Some(&body), self.timing.call_wait) {
            Ok(reply) => {
                self.keep(&mut guard, &pending, Joined { token: new, next: None, ..joined });
                let until = reply["expires"].as_str().and_then(|time| time.parse::<jiff::Timestamp>().ok()).map_or("?".to_string(), wire::time);
                say(&format!("link: renewed this machine's token; it works until {until}"));
            }
            // No reply: the hub may have taken it, so the new token is tried first from now on.
            Err(Failed::Down(_)) => {}
            Err(Failed::Refused(status, word)) => {
                self.say_once(&format!("the hub refused to renew this machine's token: {status} {word}"));
                self.keep(&mut guard, &pending, Joined { next: None, ..joined });
            }
        }
    }

    /// Holds `to` in place of `from`, which the hub has answered about, and writes it down if
    /// `link.json` still says `from`. If it says something else (a leave, or a join), that is left
    /// as it is and read again. If it can't be written, `to` is held anyway: `from` on disk names
    /// the next token, which is then tried again before anything is sent.
    fn keep(&self, held: &mut Option<Joined>, from: &Joined, to: Joined) {
        match self.folder.change_joined(from, &to) {
            Ok(true) => *held = Some(to),
            Ok(false) => *held = None,
            Err(e) => {
                self.say_once(&format!("{e:#}"));
                *held = Some(to);
            }
        }
    }

    // --- the inbox ---

    fn inbox<'s>(&'s self, scope: &'s thread::Scope<'s, '_>) {
        let mut backoff = self.timing.look;
        while !self.stopping() {
            if self.joined().is_none() {
                self.nap(self.timing.look);
                continue;
            }
            // As many words as the hub takes in one call; any more go with the next.
            let said: Vec<_> = locked(&self.handled).said.iter().take(ITEMS_MAX).cloned().collect();
            let done: Vec<Value> = said
                .iter()
                .map(|(n, _, word, receipt)| match receipt {
                    Some(receipt) => json!({"n": n, "said": word, "receipt": receipt}),
                    None => json!({"n": n, "said": word}),
                })
                .collect();
            let wait = crate::hub::INBOX_WAIT + self.timing.call_wait;
            match self.call("POST", "/v1/machine/inbox", Some(&json!({"done": done})), wait) {
                Ok(reply) => {
                    backoff = self.timing.look;
                    locked(&self.handled).said.retain(|item| !said.contains(item));
                    let mut new = false;
                    for item in reply["items"].as_array().map(Vec::as_slice).unwrap_or_default() {
                        let Some(n) = item["n"].as_u64() else { continue };
                        let key = (n, item["signature"].as_str().or(item["sealed"].as_str()).unwrap_or("").to_string());
                        let handled = locked(&self.handled);
                        if handled.under_way.contains(&key) || handled.said.iter().any(|(m, signature, _, _)| (*m, signature) == (key.0, &key.1)) {
                            continue;
                        }
                        drop(handled);
                        new = true;
                        match inbound(item) {
                            Ok(stop @ Inbound::Stop { .. }) => {
                                locked(&self.handled).under_way.push(key.clone());
                                scope.spawn(move || {
                                    let (word, receipt) = self.hand(stop);
                                    let mut handled = locked(&self.handled);
                                    handled.said.push((key.0, key.1.clone(), word, receipt));
                                    handled.under_way.retain(|under_way| *under_way != key);
                                });
                            }
                            Ok(answer) => {
                                let (word, receipt) = self.hand(answer);
                                locked(&self.handled).said.push((key.0, key.1, word, receipt));
                            }
                            Err(word) => locked(&self.handled).said.push((key.0, key.1, word, None)),
                        }
                    }
                    // What is under way stays queued at the hub, which hands it over again at once:
                    // the next call waits a moment, and says what came of it once it is done.
                    if !new && !locked(&self.handled).under_way.is_empty() {
                        self.nap(self.timing.look);
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

    /// Hands what a phone sent to the open workspace it names, and says what came of it: the
    /// workspace's word, or `unreached` if none answered; and for a sealed answer, the receipt for
    /// the phone, in hex, if the workspace sealed one.
    fn hand(&self, inbound: Inbound) -> (&'static str, Option<String>) {
        let word = match inbound {
            Inbound::Answer { ws, device, id, yes, signature } => {
                // The workspace is the one this machine's own listing gave the id, where it has it.
                let ws = locked(&self.ids).get(&id.0).cloned().unwrap_or(ws);
                let Some(socket) = self.keeper(&ws) else { return ("unreached", None) };
                match keep::tell(&socket, &Records::Signed { ws, device, yes, id, signature }, ANSWER_WAIT) {
                    Some(Told::Approved) => "approved",
                    Some(Told::Denied) => "denied",
                    Some(Told::Gone) => "gone",
                    Some(Told::Refused) => "refused",
                    _ => "unreached",
                }
            }
            Inbound::Stop { ws, device, runs, signature } => {
                let Some(socket) = self.keeper(&ws) else { return ("unreached", None) };
                match keep::tell(&socket, &Records::Stop { ws, device, runs, signature }, STOP_WAIT) {
                    Some(Told::Stopped { wrong_box: 1.., .. }) => "wrong-box",
                    Some(Told::Stopped { stopped: 0, .. }) => "none",
                    Some(Told::Stopped { .. }) => "stopped",
                    Some(Told::Refused) => "refused",
                    _ => "unreached",
                }
            }
            Inbound::Reply { ws, device, id, sealed } => {
                let Some(socket) = self.keeper(&ws) else { return ("unreached", None) };
                return match keep::tell(&socket, &Records::Reply { ws, device, id, sealed }, ANSWER_WAIT) {
                    Some(Told::Receipt(outcome, receipt)) => (outcome.word(), receipt.map(|sealed| hex(&sealed))),
                    Some(Told::Refused) => ("refused", None),
                    _ => ("unreached", None),
                };
            }
        };
        (word, None)
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

/// The devices in `trust` a notice of workspace `ws` is sealed to: those trusted for it whose second
/// key reads, each with that key.
fn sealed_to<'a>(ws: &'a str, trust: &'a [Entry]) -> impl Iterator<Item = (&'a Entry, sealed::AgreementKey)> + 'a {
    trust.iter().filter(move |entry| entry.ws.iter().any(|named| named.as_str() == ws)).filter_map(|entry| Some((entry, entry.second_key()?)))
}

/// An item the hub handed over, read whole; or the word it is said with: `unknown` for a kind
/// this link doesn't know, whatever else it holds, and `malformed` for one of a kind it knows that
/// isn't one.
fn inbound(item: &Value) -> Result<Inbound, &'static str> {
    let text = |field: &str| item[field].as_str();
    let kind = text("kind");
    if !matches!(kind, Some("answer" | "stop" | "reply")) {
        return Err("unknown");
    }
    let device = text("device").filter(|name| crate::fields::is_name(name)).map(str::to_string);
    let ws = text("ws").and_then(|ws| WsName::parse(ws).ok());
    if kind == Some("reply") {
        let id = text("id").and_then(wire::unhex::<16>).map(Id);
        let sealed = text("sealed").and_then(util::unhex).filter(|sealed| (1..=crate::hub::REPLY_SEALED_MAX).contains(&sealed.len()));
        let (Some(device), Some(ws), Some(id), Some(sealed)) = (device, ws, id, sealed) else { return Err("malformed") };
        return Ok(Inbound::Reply { ws, device, id, sealed });
    }
    let signature = text("signature").and_then(util::unhex).filter(|sig| !sig.is_empty() && sig.len() <= halti_core::device::SIGNATURE_MAX);
    let (Some(device), Some(ws), Some(signature)) = (device, ws, signature) else { return Err("malformed") };
    if kind == Some("answer") {
        let id = text("id").and_then(wire::unhex::<16>).map(Id);
        let yes = match text("decision") {
            Some("yes") => Some(true),
            Some("no") => Some(false),
            _ => None,
        };
        let (Some(id), Some(yes)) = (id, yes) else { return Err("malformed") };
        return Ok(Inbound::Answer { ws, device, id, yes, signature });
    }
    let named = |run: &Value| Some((run["box"].as_str().filter(|name| crate::fields::is_name(name))?.to_string(), RunId::parse(run["run"].as_str()?)?));
    let runs = item["runs"].as_array().and_then(|runs| runs.iter().map(named).collect::<Option<Vec<_>>>());
    let Some(runs) = runs.filter(|runs| !runs.is_empty() && runs.len() <= STOP_RUNS_MAX) else { return Err("malformed") };
    Ok(Inbound::Stop { ws, device, runs, signature })
}

/// One call to the hub `joined` names, with `token`: the reply's body, or how it went wrong. A
/// refusal's word is taken only if it is one (`wire::is_word`), and is `?` otherwise: what a hub
/// says is printed.
fn send(joined: &Joined, token: &str, method: &str, path: &str, body: Option<&Value>, wait: Duration) -> Result<Value, Failed> {
    let pin = joined.pin().map_err(|e| Failed::Down(format!("{e:#}")))?;
    let (status, reply) = pin::request(&joined.address, pin, method, path, Some(token), body, wait).map_err(|e| Failed::Down(format!("{e:#}")))?;
    if (200..300).contains(&status) {
        return Ok(reply);
    }
    Err(Failed::Refused(status, reply["error"].as_str().filter(|word| wire::is_word(word)).unwrap_or("?").to_string()))
}

/// What the link at `socket` answers to `words`: the words after the version, or None if no link
/// answered in time.
pub fn ask(socket: &std::path::Path, words: &str, wait: Duration) -> Option<String> {
    let mut stream = keep::connect(socket)?;
    keep::write_line(&mut stream, &format!("{VERSION} {words}\n")).ok()?;
    keep::read_line_up_to(&mut stream, wait, LINE_MAX)?.strip_prefix(VERSION)?.strip_prefix(' ').map(str::to_string)
}
