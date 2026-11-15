//! Requests: a write a box's policy says to ask about, kept as a record while it waits for its
//! answer. The door of a box an open workspace runs raises one (`Asker`); the open workspace keeps
//! it on its desk (`Desk`) until the first answer, from the prompt where the box runs or from
//! `halti requests` in another terminal, or until it expires, which is a no.
//!
//! A record is one fixed byte string: each field is its length, two bytes big-endian, then its
//! bytes, in this order.
//!
//! ```text
//! label    "halti-approval-v1"
//! machine  this machine's name
//! ws       the workspace
//! box      the box
//! run      8 random bytes the open workspace drew as the box started
//! kind     "write"
//! action   the method and the URL as the door's log writes it, masked: printable ASCII, every
//!          other byte percent-encoded, at most 1024 bytes, ending " (cut)" where it was cut
//! id       16 random bytes the open workspace drew for this request
//! expiry   seconds since 1970 by this machine's clock, 8 bytes big-endian
//! ```
//!
//! Names follow one rule (`fields::is_name`): 1 to 32 bytes of a-z, 0-9, `-` and `_`, starting
//! with a letter or a digit. A record that breaks any of this, or has bytes after its last field, is
//! refused whole.
//!
//! An answer names the bytes it was shown: it is the SHA-256 of the record followed by one more
//! field, `yes` or `no` (`answer_digest`). The open workspace rebuilds that from its own record, so
//! an answer counts only for the request it was shown, once, before it expires.
//!
//! A phone's answer is a signature over those same bytes (`answer_bytes`) by a device this machine
//! trusts for the workspace: ECDSA over P-256 with SHA-256 hashes them to the same digest. The open
//! workspace checks it against the trusted key and its own record (`Desk::answer_signed`); the
//! first answer that counts wins, from here or from a phone.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use halti_core::device::DeviceKey;
use sha2::{Digest, Sha256};

use crate::fields::{self, NAME_MAX};
use crate::keep::{Records, Told};
use crate::util::{hex, random, say};

/// The first field of every request.
pub const LABEL: &str = "halti-approval-v1";
/// The longest action in a record.
pub const ACTION_MAX: usize = 1024;
/// What ends an action that was cut.
const CUT: &str = " (cut)";
/// How often a request that waits looks whether its box has stopped.
const LOOK_EVERY: Duration = Duration::from_millis(100);

/// The numbers a desk keeps to.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// How long a request waits for its answer.
    pub wait: Duration,
    /// How many requests one box may have waiting.
    pub per_box: usize,
    /// How many requests the open workspace may have waiting, of all its boxes.
    pub per_desk: usize,
    /// After this many denials or unanswered requests of one box in a row, its requests are
    /// refused for `rest`.
    pub strikes: u32,
    pub rest: Duration,
}

pub const LIMITS: Limits = Limits { wait: Duration::from_secs(120), per_box: 3, per_desk: 50, strikes: 3, rest: Duration::from_secs(300) };

/// Whether `name` may stand in a record (`fields::is_name`).
pub fn check_name(name: &str) -> Result<()> {
    if !fields::is_name(name) {
        bail!("{name:?} isn't a name a record takes: 1 to 32 of a-z, 0-9, - and _, starting with a letter or digit");
    }
    Ok(())
}

/// This machine's name, as records give it: the name its hub knows it by once it has joined one
/// (`halti hub join`); before that its host name up to the first dot, lower case, every character
/// the name rule doesn't take made `-`, without the `-` and `_` it would start with, cut at 32
/// bytes, and `machine` if nothing is left.
pub fn machine_name() -> String {
    if let Some(name) = crate::link::joined_name() {
        return name;
    }
    let mut buf = [0u8; 256];
    let got = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    let host = if got == 0 { String::from_utf8_lossy(&buf[..buf.iter().position(|b| *b == 0).unwrap_or(buf.len())]).into_owned() } else { String::new() };
    machine_from(&host)
}

fn machine_from(host: &str) -> String {
    let short = host.split('.').next().unwrap_or("");
    let name: String = short
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' { c } else { '-' })
        .skip_while(|c| *c == '-' || *c == '_')
        .take(NAME_MAX)
        .collect();
    if name.is_empty() { "machine".to_string() } else { name }
}

/// A request's id: 16 random bytes this machine drew.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Id(pub [u8; 16]);

impl Id {
    pub fn random() -> Id {
        Id(random())
    }

    pub fn hex(&self) -> String {
        hex(&self.0)
    }

    /// What people type: the first 8 hex characters.
    pub fn short(&self) -> String {
        hex(&self.0[..4])
    }
}

/// A run's id: 8 random bytes drawn as its box started.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RunId(pub [u8; 8]);

impl RunId {
    pub fn random() -> RunId {
        RunId(random())
    }

    pub fn hex(&self) -> String {
        hex(&self.0)
    }

    /// Its 16 lowercase hex characters back; None for anything else.
    pub fn parse(text: &str) -> Option<RunId> {
        Some(RunId(crate::util::unhex(text)?.try_into().ok()?))
    }
}

/// What a request asks for. A write whose rule is `ask` is the only kind yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Write,
}

impl Kind {
    fn word(self) -> &'static str {
        match self {
            Kind::Write => "write",
        }
    }

    fn parse(word: &[u8]) -> Option<Kind> {
        (word == b"write").then_some(Kind::Write)
    }
}

/// The action of a request: `method` and `url` as the door's log writes them, in printable ASCII,
/// every other byte percent-encoded. The log's own mark for a cut URL, and an action too long for
/// a record, end in " (cut)".
pub fn action(method: &str, url: &str) -> String {
    let (url, cut) = match url.strip_suffix('…') {
        Some(url) => (url, true),
        None => (url, false),
    };
    let mut text = String::new();
    for byte in format!("{method} {url}").bytes() {
        if (0x20..0x7f).contains(&byte) {
            text.push(byte as char);
        } else {
            text.push_str(&format!("%{byte:02X}"));
        }
    }
    if cut || text.len() > ACTION_MAX {
        text.truncate(text.len().min(ACTION_MAX - CUT.len()));
        text.push_str(CUT);
    }
    text
}

/// One request, field by field.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    pub machine: String,
    pub ws: String,
    pub box_name: String,
    pub run: RunId,
    pub kind: Kind,
    pub action: String,
    pub id: Id,
    /// Seconds since 1970, by this machine's clock.
    pub expiry: u64,
}

impl Record {
    /// Its bytes. Fails for a field the record can't take.
    pub fn encode(&self) -> Result<Vec<u8>> {
        for name in [&self.machine, &self.ws, &self.box_name] {
            check_name(name)?;
        }
        if !printable(self.action.as_bytes()) || self.action.is_empty() || self.action.len() > ACTION_MAX {
            bail!("an action is 1 to {ACTION_MAX} bytes of printable ASCII");
        }
        Ok(fields::join(&[
            LABEL.as_bytes(),
            self.machine.as_bytes(),
            self.ws.as_bytes(),
            self.box_name.as_bytes(),
            &self.run.0,
            self.kind.word().as_bytes(),
            self.action.as_bytes(),
            &self.id.0,
            &self.expiry.to_be_bytes(),
        ]))
    }

    /// The record these bytes are, or None if they are not one in every field.
    pub fn decode(bytes: &[u8]) -> Option<Record> {
        let mut rest = bytes;
        let mut field = || -> Option<&[u8]> {
            let (length, after) = rest.split_first_chunk::<2>()?;
            let length = usize::from(u16::from_be_bytes(*length));
            let (field, after) = after.split_at_checked(length)?;
            rest = after;
            Some(field)
        };
        let name = |bytes: &[u8]| -> Option<String> {
            let text = std::str::from_utf8(bytes).ok()?;
            check_name(text).ok()?;
            Some(text.to_string())
        };
        if field()? != LABEL.as_bytes() {
            return None;
        }
        let (machine, ws, box_name) = (name(field()?)?, name(field()?)?, name(field()?)?);
        let run = RunId(field()?.try_into().ok()?);
        let kind = Kind::parse(field()?)?;
        let action = field()?;
        if action.is_empty() || action.len() > ACTION_MAX || !printable(action) {
            return None;
        }
        let action = String::from_utf8(action.to_vec()).ok()?;
        let id = Id(field()?.try_into().ok()?);
        let expiry = u64::from_be_bytes(field()?.try_into().ok()?);
        rest.is_empty().then_some(Record { machine, ws, box_name, run, kind, action, id, expiry })
    }

    /// The box as people name it: `acme/dev`.
    pub fn shown(&self) -> String {
        format!("{}/{}", self.ws, self.box_name)
    }
}

fn printable(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| (0x20..0x7f).contains(b))
}

/// What an answer to `record` signs: the record's bytes followed by the decision as one more field.
pub fn answer_bytes(record: &[u8], yes: bool) -> Vec<u8> {
    let mut bytes = record.to_vec();
    fields::push(&mut bytes, if yes { b"yes" } else { b"no" });
    bytes
}

/// What an answer to `record` says: the SHA-256 of `answer_bytes`, which is what a phone's
/// signature over them signs.
pub fn answer_digest(record: &[u8], yes: bool) -> [u8; 32] {
    Sha256::digest(answer_bytes(record, yes)).into()
}

/// Seconds since 1970 by this machine's clock.
pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// The expiry of a request that waits `wait` from now: the next whole second after it, so the
/// record never says less than its wait.
fn expiry_after(wait: Duration) -> u64 {
    let end = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default() + wait;
    end.as_secs() + u64::from(end.subsec_nanos() > 0)
}

/// Who answered a request.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum By {
    /// The person at this machine: the prompt where the box runs, or `halti requests`.
    Local,
    /// A trusted device, by a signature this machine checked.
    Device(Arc<Signed>),
}

/// A phone's answer as it was checked: who signed it, and what, kept for the log so a later reader
/// can check it again without the hub.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signed {
    pub device: String,
    pub fingerprint: String,
    /// The record as this machine made it; the signature is over it and the decision.
    pub record: Vec<u8>,
    pub signature: Vec<u8>,
}

impl By {
    /// The `by` of the door's log line: `local`, or the device's name and fingerprint.
    pub fn word(&self) -> String {
        match self {
            By::Local => "local".to_string(),
            By::Device(signed) => format!("{} {}", signed.device, signed.fingerprint),
        }
    }
}

/// A device this machine trusts (`halti devices trust`): its signing key, and the workspaces it
/// may answer for.
#[derive(Clone, Debug)]
pub struct Trusted {
    pub name: String,
    pub key: DeviceKey,
    pub fingerprint: String,
    pub ws: Vec<String>,
}

/// Finds a trusted device by its name, as the trust list says now.
pub type Trust<'a> = &'a (dyn Fn(&str) -> Option<Trusted> + Sync);

/// What a request came to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Came {
    Yes(By),
    No(By),
    /// Nobody answered before it expired.
    Expired,
    /// The box stopped, or the workspace closed, while it waited.
    Withdrawn,
    /// Never raised: the box has as many waiting as it may.
    Full,
    /// Never raised: the open workspace has as many waiting as it may, of all its boxes.
    WorkspaceFull,
    /// Never raised: the box's last requests were refused or not answered, so it rests.
    Resting,
}

/// A request that was raised, or not: its id, if it got one, and what it came to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Raised {
    pub id: Option<Id>,
    pub came: Came,
}

/// What the prompt where the box runs said.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Prompted {
    Yes,
    No,
    /// Nothing could be shown here, or it was withdrawn before an answer: it says nothing.
    Unshown,
}

/// The prompt at this machine: Touch ID on a Mac.
pub trait Prompt: Send + Sync {
    /// Asks the person, until `withdrawn` says the question is gone.
    fn ask(&self, reason: &str, withdrawn: &dyn Fn() -> bool) -> Prompted;
}

/// Touch ID, withdrawn as the request is answered elsewhere. Nothing is shown where there is none.
pub struct TouchId;

impl Prompt for TouchId {
    fn ask(&self, reason: &str, withdrawn: &dyn Fn() -> bool) -> Prompted {
        crate::approve::ask_until(reason, withdrawn)
    }
}

/// What came of an answer from another terminal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Here {
    Approved,
    Denied,
    /// No request waits with those bytes: answered already, expired, or never raised.
    Gone,
    /// The prompt asked before a yes said no, or could not be shown.
    Declined,
    /// The prompt here already asks about a yes from another terminal for this request.
    Busy,
    /// A signed answer that doesn't count: its device isn't trusted for this workspace, or the
    /// signature isn't its own over this request and decision.
    Refused,
}

/// One request that waits.
struct Waiting {
    record: Record,
    bytes: Vec<u8>,
    deadline: Instant,
    /// Whether the person at this machine confirms a yes: the prompt where the box runs, and the
    /// same prompt before a yes from another terminal counts.
    confirm: bool,
    answer: Option<(bool, By)>,
    /// Another terminal's yes is being confirmed: the prompt where the box runs is withdrawn.
    taken: bool,
    /// The prompt where the box runs is up, or not yet taken down.
    prompting: bool,
}

impl Waiting {
    /// Whether it can no longer be answered: answered, or past its time. Both clocks count: the
    /// one a wait is timed by stops while the machine sleeps, and the record's expiry is the
    /// machine's own clock.
    fn closed(&self, now: Instant) -> bool {
        self.answer.is_some() || now >= self.deadline || SystemTime::now() >= UNIX_EPOCH + Duration::from_secs(self.record.expiry)
    }
}

/// The run of denials and unanswered requests of one box.
#[derive(Default)]
struct Strikes {
    count: u32,
    until: Option<Instant>,
}

#[derive(Default)]
struct Table {
    waiting: Vec<Waiting>,
    strikes: HashMap<String, Strikes>,
    closed: bool,
}

/// The requests of one open workspace that wait for an answer.
pub struct Desk {
    machine: String,
    ws: String,
    limits: Limits,
    prompt: Arc<dyn Prompt>,
    table: Mutex<Table>,
    /// Told whenever a request is raised, answered or goes.
    changed: Condvar,
}

impl Desk {
    pub fn new(machine: String, ws: String, limits: Limits, prompt: Arc<dyn Prompt>) -> Arc<Desk> {
        Arc::new(Desk { machine, ws, limits, prompt, table: Mutex::default(), changed: Condvar::new() })
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What a box's door raises its requests through, for one run.
    pub fn asker(self: &Arc<Self>, box_name: &str, run: RunId) -> Asker {
        Asker { desk: self.clone(), box_name: box_name.to_string(), run }
    }

    /// The bytes of every request that waits and may still be answered.
    pub fn records(&self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        self.table().waiting.iter().filter(|waiting| !waiting.closed(now)).map(|waiting| waiting.bytes.clone()).collect()
    }

    /// Withdraws every request, and raises none from now on: the workspace is closing.
    pub fn close(&self) {
        self.table().closed = true;
        self.changed.notify_all();
    }

    /// A phone's answer: `yes` or not, to request `id`, signed by the device named `device`. It
    /// counts only if `trust` trusts that device for this workspace and the signature is its key's
    /// over this machine's own record of `id` and the decision. Nothing is asked here: the phone
    /// asked for its fingerprint or PIN. The first answer wins, as for one from here.
    pub fn answer_signed(&self, trust: Trust, device: &str, yes: bool, id: Id, signature: &[u8]) -> Here {
        let bytes = {
            let table = self.table();
            let Some(waiting) = table.waiting.iter().find(|waiting| waiting.record.id == id && !waiting.closed(Instant::now())) else { return Here::Gone };
            waiting.bytes.clone()
        };
        let Some(trusted) = trust(device).filter(|trusted| trusted.ws.contains(&self.ws)) else { return Here::Refused };
        if trusted.key.verify(&answer_bytes(&bytes, yes), signature).is_err() {
            return Here::Refused;
        }
        let by = By::Device(Arc::new(Signed { device: trusted.name, fingerprint: trusted.fingerprint, record: bytes, signature: signature.to_vec() }));
        match (self.settle(id, yes, by), yes) {
            (false, _) => Here::Gone,
            (true, true) => Here::Approved,
            (true, false) => Here::Denied,
        }
    }

    /// Settles request `id` as `yes` if it still waits, unanswered and unexpired: the first answer
    /// wins. Whether this one did.
    fn settle(&self, id: Id, yes: bool, by: By) -> bool {
        let mut table = self.table();
        let now = Instant::now();
        let Some(waiting) = table.waiting.iter_mut().find(|waiting| waiting.record.id == id) else { return false };
        if waiting.closed(now) {
            return false;
        }
        waiting.answer = Some((yes, by));
        drop(table);
        self.changed.notify_all();
        true
    }

    /// Whether request `id` no longer needs an answer: answered, expired, or gone.
    fn settled(&self, id: Id) -> bool {
        let now = Instant::now();
        !self.table().waiting.iter().any(|waiting| waiting.record.id == id && !waiting.closed(now))
    }

    /// Whether the prompt where the box runs should go: the request is settled, or another
    /// terminal answers it.
    fn withdrawn(&self, id: Id) -> bool {
        self.settled(id) || self.table().waiting.iter().any(|waiting| waiting.record.id == id && waiting.taken)
    }

    /// Asks the prompt where the box runs about request `id`, on a thread of its own, until it is
    /// withdrawn; what it says settles the request.
    fn prompt_where_box_runs(self: &Arc<Self>, id: Id, reason: String) {
        let desk = self.clone();
        thread::spawn(move || {
            match desk.prompt.ask(&reason, &|| desk.withdrawn(id)) {
                Prompted::Yes => {
                    desk.settle(id, true, By::Local);
                }
                Prompted::No => {
                    desk.settle(id, false, By::Local);
                }
                Prompted::Unshown => {}
            }
            if let Some(waiting) = desk.table().waiting.iter_mut().find(|waiting| waiting.record.id == id) {
                waiting.prompting = false;
            }
            desk.changed.notify_all();
        });
    }

    /// An answer from another terminal, to the request whose bytes and this decision make `digest`.
    /// A no counts at once. A yes counts at once where nothing confirms it here (Linux). On a Mac
    /// the prompt where the box runs is taken down, and once it is, the same prompt asks here
    /// first; only one such yes is asked about at a time. If it isn't given, the prompt where the
    /// box runs comes back.
    pub fn answer_here(self: &Arc<Self>, yes: bool, digest: &[u8; 32]) -> Here {
        let mut table = self.table();
        let now = Instant::now();
        let Some(waiting) = table.waiting.iter_mut().find(|waiting| answer_digest(&waiting.bytes, yes) == *digest) else { return Here::Gone };
        if waiting.closed(now) {
            return Here::Gone;
        }
        let id = waiting.record.id;
        if !yes || !waiting.confirm {
            drop(table);
            return match (self.settle(id, yes, By::Local), yes) {
                (false, _) => Here::Gone,
                (true, true) => Here::Approved,
                (true, false) => Here::Denied,
            };
        }
        if waiting.taken {
            return Here::Busy;
        }
        waiting.taken = true;
        let shown = format!("let box {} send {}", waiting.record.shown(), waiting.record.action);
        self.changed.notify_all();
        // Two prompts are never up at once: this one waits for the other to be taken down.
        loop {
            let Some(waiting) = table.waiting.iter().find(|waiting| waiting.record.id == id) else { return Here::Gone };
            if waiting.closed(Instant::now()) {
                return Here::Gone;
            }
            if !waiting.prompting {
                break;
            }
            table = self.changed.wait_timeout(table, LOOK_EVERY).unwrap_or_else(PoisonError::into_inner).0;
        }
        drop(table);
        let said = self.prompt.ask(&format!("{shown}, as answered in another terminal"), &|| self.settled(id));
        if said == Prompted::Yes && self.settle(id, true, By::Local) {
            return Here::Approved;
        }
        let mut table = self.table();
        let now = Instant::now();
        let Some(waiting) = table.waiting.iter_mut().find(|waiting| waiting.record.id == id && !waiting.closed(now)) else { return Here::Gone };
        waiting.taken = false;
        waiting.prompting = true;
        drop(table);
        self.prompt_where_box_runs(id, shown);
        Here::Declined
    }

    /// Raises a request for box `box_name`'s run `run` to do `action`, and waits for what it comes
    /// to. With `confirm` the prompt here asks too, on a thread of its own, and is withdrawn once
    /// the request is settled. `stopped` says the box has stopped.
    fn raise(self: &Arc<Self>, box_name: &str, run: RunId, action: &str, confirm: bool, stopped: &dyn Fn() -> bool) -> Raised {
        let not = |came| Raised { id: None, came };
        let mut table = self.table();
        if table.closed {
            return not(Came::Withdrawn);
        }
        let now = Instant::now();
        if table.strikes.get(box_name).and_then(|strikes| strikes.until).is_some_and(|until| now < until) {
            return not(Came::Resting);
        }
        if table.waiting.iter().filter(|waiting| waiting.record.box_name == box_name).count() >= self.limits.per_box {
            return not(Came::Full);
        }
        if table.waiting.len() >= self.limits.per_desk {
            return not(Came::WorkspaceFull);
        }
        let record = Record {
            machine: self.machine.clone(),
            ws: self.ws.clone(),
            box_name: box_name.to_string(),
            run,
            kind: Kind::Write,
            action: action.to_string(),
            id: Id::random(),
            expiry: expiry_after(self.limits.wait),
        };
        let Ok(bytes) = record.encode() else { return not(Came::Withdrawn) };
        let (id, shown) = (record.id, record.shown());
        say(&format!("request {}: box {shown} asks to send {action}. answer it with: halti requests approve {0}, or deny {0}", id.short()));
        table.waiting.push(Waiting { record, bytes, deadline: now + self.limits.wait, confirm, answer: None, taken: false, prompting: confirm });
        drop(table);
        self.changed.notify_all();
        if confirm {
            self.prompt_where_box_runs(id, format!("let box {shown} send {action}"));
        }
        let came = self.wait_for(id, stopped);
        self.after(box_name, &came);
        say(&format!("request {}: {}", id.short(), said(&came)));
        Raised { id: Some(id), came }
    }

    /// Waits until request `id` is settled, expires, or is withdrawn; then it goes.
    fn wait_for(&self, id: Id, stopped: &dyn Fn() -> bool) -> Came {
        let mut table = self.table();
        let came = loop {
            let closed = table.closed;
            let Some(waiting) = table.waiting.iter().find(|waiting| waiting.record.id == id) else { break Came::Withdrawn };
            match &waiting.answer {
                Some((true, by)) => break Came::Yes(by.clone()),
                Some((false, by)) => break Came::No(by.clone()),
                None if closed || stopped() => break Came::Withdrawn,
                None if waiting.closed(Instant::now()) => break Came::Expired,
                None => {}
            }
            table = self.changed.wait_timeout(table, LOOK_EVERY).unwrap_or_else(PoisonError::into_inner).0;
        };
        table.waiting.retain(|waiting| waiting.record.id != id);
        drop(table);
        self.changed.notify_all();
        came
    }

    /// Counts a denial or an unanswered request against the box; a yes clears its count.
    fn after(&self, box_name: &str, came: &Came) {
        let mut table = self.table();
        let strikes = table.strikes.entry(box_name.to_string()).or_default();
        match came {
            Came::Yes(_) => strikes.count = 0,
            Came::No(_) | Came::Expired => {
                strikes.count += 1;
                if strikes.count >= self.limits.strikes {
                    strikes.count = 0;
                    strikes.until = Some(Instant::now() + self.limits.rest);
                }
            }
            Came::Withdrawn | Came::Full | Came::WorkspaceFull | Came::Resting => {}
        }
    }
}

/// What the terminal where the workspace is open says a request came to.
fn said(came: &Came) -> String {
    match came {
        Came::Yes(by) => format!("approved ({})", by.word()),
        Came::No(by) => format!("denied ({})", by.word()),
        Came::Expired => "not answered in time, so refused".to_string(),
        Came::Withdrawn => "withdrawn: its box stopped, or the workspace is closing".to_string(),
        Came::Full | Came::WorkspaceFull | Came::Resting => "refused".to_string(),
    }
}

/// The boxes an open workspace runs, as a phone's stop names them: each by its run.
pub trait Runs: Sync {
    /// Every box that runs, and its run.
    fn runs(&self) -> Vec<(String, RunId)>;
    /// Stops the boxes whose runs these are, and says how many it stopped: a run it doesn't have
    /// is passed over.
    fn stop(&self, runs: &[RunId]) -> u32;
}

/// A phone's stop of `runs` in the desk's workspace, signed by the device named `device`: how many
/// boxes it stopped, or None if it doesn't count. It counts only if `trust` trusts that device for
/// this workspace and the signature is its key's over this machine's name, the workspace and the
/// runs (`hub::wire::stop_bytes`). A run this workspace doesn't run is passed over, so a stop sent
/// again stops nothing new.
pub fn stop_signed(desk: &Desk, trust: Trust, boxes: &dyn Runs, device: &str, runs: &[RunId], signature: &[u8]) -> Option<u32> {
    let trusted = trust(device).filter(|trusted| trusted.ws.contains(&desk.ws))?;
    trusted.key.verify(&crate::hub::wire::stop_bytes(&desk.machine, &desk.ws, runs), signature).ok()?;
    let count = boxes.stop(runs);
    say(&format!("a stop signed by {} named {} runs of {}: stopped {count}", trusted.name, runs.len(), desk.ws));
    Some(count)
}

/// What the open workspace whose desk this is answers to `records`, which name it: the lines of
/// its reply, in order.
pub fn told(desk: &Arc<Desk>, trust: Trust, boxes: &dyn Runs, records: &Records) -> Vec<Told> {
    match records {
        Records::List(_) => desk.records().into_iter().map(Told::Request).chain([Told::End]).collect(),
        Records::Runs(_) => boxes.runs().into_iter().map(|(name, run)| Told::Run(name, run)).chain([Told::End]).collect(),
        Records::Answer(_, yes, digest) => vec![told_by(desk.answer_here(*yes, digest))],
        Records::Signed { device, yes, id, signature, .. } => vec![told_by(desk.answer_signed(trust, device, *yes, *id, signature))],
        Records::Stop { device, runs, signature, .. } => vec![stop_signed(desk, trust, boxes, device, runs, signature).map_or(Told::Refused, Told::Stopped)],
    }
}

fn told_by(here: Here) -> Told {
    match here {
        Here::Approved => Told::Approved,
        Here::Denied => Told::Denied,
        Here::Gone => Told::Gone,
        Here::Declined => Told::Declined,
        Here::Busy => Told::Busy,
        Here::Refused => Told::Refused,
    }
}

/// What one run of a box raises its requests through.
#[derive(Clone)]
pub struct Asker {
    desk: Arc<Desk>,
    box_name: String,
    run: RunId,
}

impl Asker {
    /// Raises a request to do `action` (`action` makes it), and waits for what it comes to. With
    /// `confirm`, the prompt here asks too, and confirms a yes from another terminal.
    pub fn raise(&self, action: &str, confirm: bool, stopped: &dyn Fn() -> bool) -> Raised {
        self.desk.raise(&self.box_name, self.run, action, confirm, stopped)
    }

    /// The numbers its desk keeps to.
    pub fn limits(&self) -> Limits {
        self.desk.limits
    }
}

#[cfg(test)]
mod tests;
