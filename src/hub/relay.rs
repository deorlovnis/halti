//! What the hub carries between machines and phones, in memory only: each machine's last report of
//! its state, the requests it posted, the notices that an agent waits (`crate::notices`) and the
//! questions of agents (`crate::questions`), sealed to each phone, and what phones sent it, signed
//! answers and stops and sealed answers to questions, until its link has taken them and said what
//! came of them, with the receipt it sealed for the phone. A restart loses all of it: a machine's link reports again, and is
//! told which of its requests and notices the hub lacks, so it posts them again.
//!
//! Nothing here can say yes. An answer or a stop counts only at the machine, which checks the
//! signature against its own trust list and its own record; the hub checks the signature too, but
//! only to refuse what could never count.

use std::collections::{BTreeMap, HashMap, VecDeque};

use halti_core::ids::WsName;
use jiff::{SignedDuration, Timestamp};
use serde::Deserialize;
use serde_json::{Value, json};

use super::wire::{self, Refused};
use crate::keep::STOP_RUNS_MAX;
use crate::notices::Notice;
use crate::questions;
use crate::requests::{Id, Record, RunId};
use crate::util::hex;

/// The most requests the hub holds for one machine.
pub const REQUESTS_MAX: usize = 50;
/// The most notices the hub holds for one machine, and the most one call of its link names.
pub const NOTICES_MAX: usize = 50;
/// The shortest and the longest sealed copy of a notice: the sealed text is empty, or the id.
pub const SEALED_MIN: usize = 65 + 16;
pub const SEALED_MAX: usize = 256;
/// The most answers and stops that wait for one machine to take them.
pub const ITEMS_MAX: usize = 64;
/// The most questions the hub holds for one machine, and the most one call of its link names.
pub const QUESTIONS_MAX: usize = 20;
/// The longest sealed copy of a question: a whole record's sealed fields, sealed.
pub const QUESTION_SEALED_MAX: usize = questions::RECORD_MAX + 65 + 16;
/// The longest sealed answer: its form, salt, content and signature, sealed.
pub const REPLY_SEALED_MAX: usize = 3 * 1024;
/// The longest sealed receipt: the answer's hash and a word, sealed.
pub const RECEIPT_SEALED_MAX: usize = 256;
/// How many of what each phone sent one machine are kept once taken, for the phone to see what
/// came of them, and for how long at most. What one phone sends never pushes out another's.
const DONE_MAX: usize = 64;
const DONE_LIFE: SignedDuration = SignedDuration::from_hours(1);
/// How long past its expiry a request is still held: a machine's clock and the hub's may differ by
/// this much.
pub const GRACE: SignedDuration = SignedDuration::from_secs(60);
/// How long the id of a request dropped at its expiry is remembered, so a machine isn't asked for it
/// again.
const EXPIRED_KEPT: SignedDuration = SignedDuration::from_secs(600);
/// The most workspaces, trust entries and request ids one report names.
pub const REPORT_MAX: usize = 64;
pub const REPORT_IDS_MAX: usize = 256;
/// The most of what one phone sent one machine that the phone is shown.
const SENT_MAX: usize = 64;

/// What a machine reported last.
#[derive(Clone, Debug)]
pub struct Report {
    /// When the hub got it.
    pub at: Timestamp,
    /// When the hub first heard from this run of the link: a later time is a restart.
    pub since: Timestamp,
    link: [u8; 16],
    pub workspaces: Vec<WsState>,
    pub trusted: Vec<TrustedOn>,
}

/// A workspace with a trusted device, as its machine reported it.
#[derive(Clone, Debug)]
pub struct WsState {
    pub name: WsName,
    pub open: bool,
    /// The boxes that run, and their runs.
    pub runs: Vec<(String, RunId)>,
}

/// A device the machine trusts, and for which workspaces.
#[derive(Clone, Debug)]
pub struct TrustedOn {
    pub device: String,
    pub ws: Vec<WsName>,
}

/// A request a machine posted.
struct Held {
    record: Record,
    bytes: Vec<u8>,
    /// A phone closed its remote copy: no phone is shown it, and none may answer it.
    hidden: bool,
}

/// A notice's sealed copies, each with the name of the phone it is sealed to.
pub type Copies = Vec<(String, Vec<u8>)>;

/// A notice a machine posted: its record, and a sealed copy for each phone it may go to.
struct HeldNotice {
    notice: Notice,
    bytes: Vec<u8>,
    sealed: Copies,
}

/// A question a machine posted: its clear fields read, their bytes, and a copy for each phone.
struct HeldQuestion {
    record: questions::Record,
    bytes: Vec<u8>,
    sealed: Copies,
}

/// A notice as a held call of a phone tells it apart: its id, and the machine, workspace and box
/// it is of. A question is told apart the same way.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NoticeKey {
    pub id: [u8; 16],
    pub machine: String,
    pub ws: String,
    pub box_name: String,
}

/// What a phone sent a machine.
#[derive(Clone, Debug)]
pub struct Item {
    pub n: u64,
    /// The device that sent it.
    pub from: String,
    pub at: Timestamp,
    pub what: What,
    /// The machine's link has taken it at least once.
    pub taken: bool,
    /// What the machine said came of it.
    pub said: Option<String>,
    /// For a sealed answer, the receipt the machine sealed for the phone.
    pub receipt: Option<Vec<u8>>,
}

/// A signed answer, or a signed stop of runs, each with the box the phone named it with.
#[derive(Clone, Debug)]
pub enum What {
    Answer {
        ws: String,
        id: Id,
        yes: bool,
        signature: Vec<u8>,
    },
    Stop {
        ws: String,
        runs: Vec<(String, RunId)>,
        signature: Vec<u8>,
    },
    /// A sealed answer to a question.
    Reply {
        ws: String,
        id: Id,
        sealed: Vec<u8>,
    },
}

impl What {
    fn ws(&self) -> &str {
        match self {
            What::Answer { ws, .. } | What::Stop { ws, .. } | What::Reply { ws, .. } => ws,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            What::Answer { .. } => "answer",
            What::Stop { .. } => "stop",
            What::Reply { .. } => "reply",
        }
    }
}

#[derive(Default)]
struct Mailbox {
    report: Option<Report>,
    requests: BTreeMap<[u8; 16], Held>,
    /// The notices of its agents that wait, by id. None is ever dropped for its age.
    notices: BTreeMap<[u8; 16], HeldNotice>,
    /// The questions of its agents, by id, until their expiry.
    questions: BTreeMap<[u8; 16], HeldQuestion>,
    /// Requests dropped at their expiry, until this time.
    expired: HashMap<[u8; 16], Timestamp>,
    /// Waiting for the machine, oldest first.
    items: Vec<Item>,
    /// Taken and answered, newest last.
    done: VecDeque<Item>,
}

impl Mailbox {
    fn purge(&mut self, now: Timestamp) {
        let now_secs = now.as_second();
        let grace = GRACE.as_secs();
        let late: Vec<[u8; 16]> =
            self.requests.iter().filter(|(_, held)| i64::try_from(held.record.expiry).unwrap_or(i64::MAX).saturating_add(grace) <= now_secs).map(|(id, _)| *id).collect();
        for id in late {
            self.requests.remove(&id);
            self.expired.insert(id, now + EXPIRED_KEPT);
        }
        self.questions.retain(|_, held| i64::try_from(held.record.expiry).unwrap_or(i64::MAX).saturating_add(grace) > now_secs);
        self.expired.retain(|_, until| now < *until);
        self.done.retain(|item| now.duration_since(item.at) < DONE_LIFE);
        // Each phone's oldest go first, until it has DONE_MAX.
        let mut held: HashMap<String, usize> = HashMap::new();
        for item in &self.done {
            *held.entry(item.from.clone()).or_default() += 1;
        }
        self.done.retain(|item| {
            let left = held.get_mut(&item.from).expect("counted above");
            *left -= 1;
            *left < DONE_MAX
        });
    }
}

/// Every machine's mailbox, by the machine's name.
#[derive(Default)]
pub struct Relay {
    machines: BTreeMap<String, Mailbox>,
    /// The number of the last item queued.
    next: u64,
}

/// A machine's report, as its link sends it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportBody {
    link: String,
    workspaces: Vec<WsBody>,
    trusted: Vec<TrustedBody>,
    requests: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WsBody {
    name: String,
    open: bool,
    runs: Vec<RunBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunBody {
    #[serde(rename = "box")]
    box_name: String,
    run: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedBody {
    device: String,
    ws: Vec<String>,
}

/// A machine's report as it sent it: its link's id for this run, its workspaces, its trust, and the
/// ids of the requests it holds.
pub struct Reported {
    pub link: [u8; 16],
    pub workspaces: Vec<WsState>,
    pub trusted: Vec<TrustedOn>,
    pub ids: Vec<[u8; 16]>,
}

/// A machine's key and since when it is marked `token conflict`, as the table has them.
pub type MachineRow = (Vec<u8>, Option<Timestamp>);

/// A machine's report, from the body of its state call.
pub fn report_body(body: &[u8]) -> Result<Reported, Refused> {
    let body: ReportBody = wire::json(body)?;
    if body.workspaces.len() > REPORT_MAX || body.trusted.len() > REPORT_MAX || body.requests.len() > REPORT_IDS_MAX {
        return Err(Refused::Malformed);
    }
    let mut workspaces = Vec::new();
    for ws in body.workspaces {
        if ws.runs.len() > STOP_RUNS_MAX {
            return Err(Refused::Malformed);
        }
        workspaces.push(WsState { name: ws_name(&ws.name)?, open: ws.open, runs: named_runs(ws.runs)? });
    }
    let trusted = body.trusted.into_iter().map(|entry| Ok(TrustedOn { device: name(&entry.device)?, ws: wire::workspaces(&entry.ws)? })).collect::<Result<Vec<_>, Refused>>()?;
    let ids = body.requests.iter().map(|id| wire::bytes(id)).collect::<Result<Vec<[u8; 16]>, Refused>>()?;
    Ok(Reported { link: wire::bytes(&body.link)?, workspaces, trusted, ids })
}

fn name(text: &str) -> Result<String, Refused> {
    wire::check_name(text)?;
    Ok(text.to_string())
}

fn ws_name(text: &str) -> Result<WsName, Refused> {
    WsName::parse(text).map_err(|_| Refused::Malformed)
}

fn run_id(text: &str) -> Result<RunId, Refused> {
    Ok(RunId(wire::bytes(text)?))
}

/// Runs as a body names them: each by its box and its id.
fn named_runs(runs: Vec<RunBody>) -> Result<Vec<(String, RunId)>, Refused> {
    runs.into_iter().map(|run| Ok((name(&run.box_name)?, run_id(&run.run)?))).collect()
}

/// Runs as a reply names them.
fn runs_json(runs: &[(String, RunId)]) -> Vec<Value> {
    runs.iter().map(|(name, run)| json!({"box": name, "run": run.hex()})).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordBody {
    record: String,
}

/// A request's record, from the body of a machine's call.
pub fn record_body(body: &[u8]) -> Result<(Record, Vec<u8>), Refused> {
    let body: RecordBody = wire::json(body)?;
    let bytes = crate::util::unhex(&body.record).ok_or(Refused::Malformed)?;
    let record = Record::decode(&bytes).ok_or(Refused::Malformed)?;
    Ok((record, bytes))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticesBody {
    notices: Vec<String>,
}

/// The ids of the notices a machine's link says are open, from the body of its call.
pub fn notices_body(body: &[u8]) -> Result<Vec<[u8; 16]>, Refused> {
    let body: NoticesBody = wire::json(body)?;
    if body.notices.len() > NOTICES_MAX {
        return Err(Refused::Malformed);
    }
    body.notices.iter().map(|id| wire::bytes(id)).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticeBody {
    record: String,
    sealed: Vec<SealedBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedBody {
    device: String,
    sealed: String,
}

/// A notice a machine posts: its record, its bytes, and each phone's sealed copy, from the body of
/// its call. Only the form is checked: the hub can open none of them.
pub fn notice_body(body: &[u8]) -> Result<(Notice, Vec<u8>, Copies), Refused> {
    let body: NoticeBody = wire::json(body)?;
    let bytes = crate::util::unhex(&body.record).ok_or(Refused::Malformed)?;
    let notice = Notice::decode(&bytes).ok_or(Refused::Malformed)?;
    if body.sealed.is_empty() || body.sealed.len() > REPORT_MAX {
        return Err(Refused::Malformed);
    }
    let mut sealed: Copies = Vec::new();
    for copy in body.sealed {
        let device = name(&copy.device)?;
        let bytes = crate::util::unhex(&copy.sealed).filter(|bytes| (SEALED_MIN..=SEALED_MAX).contains(&bytes.len())).ok_or(Refused::Malformed)?;
        if sealed.iter().any(|(named, _)| *named == device) {
            return Err(Refused::Malformed);
        }
        sealed.push((device, bytes));
    }
    Ok((notice, bytes, sealed))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionsBody {
    questions: Vec<QuestionListed>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionListed {
    id: String,
    devices: Vec<String>,
}

/// A question a machine's link names: its id, and the phones it is sealed to.
pub type Named = ([u8; 16], Vec<String>);

/// What a machine's link says came of an item it took: its number, the word, and for a sealed
/// answer the receipt for the phone.
pub type Done = (u64, String, Option<Vec<u8>>);

/// The questions a machine's link says wait, each with the phones it is sealed to, from the body
/// of its call.
pub fn questions_body(body: &[u8]) -> Result<Vec<Named>, Refused> {
    let body: QuestionsBody = wire::json(body)?;
    if body.questions.len() > QUESTIONS_MAX {
        return Err(Refused::Malformed);
    }
    body.questions
        .into_iter()
        .map(|listed| {
            if listed.devices.len() > REPORT_MAX {
                return Err(Refused::Malformed);
            }
            Ok((wire::bytes(&listed.id)?, listed.devices.iter().map(|device| name(device)).collect::<Result<_, _>>()?))
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionBody {
    record: String,
    device: String,
    sealed: String,
}

/// One phone's copy of a question a machine posts: its clear fields read, their bytes, the phone
/// and the sealed bytes, from the body of its call. Only the form is checked: the hub can open
/// none of it.
pub fn question_body(body: &[u8]) -> Result<(questions::Record, Vec<u8>, String, Vec<u8>), Refused> {
    let body: QuestionBody = wire::json(body)?;
    let bytes = crate::util::unhex(&body.record).ok_or(Refused::Malformed)?;
    let record = questions::Record::decode(&bytes).ok_or(Refused::Malformed)?;
    let sealed = crate::util::unhex(&body.sealed).filter(|sealed| (SEALED_MIN..=QUESTION_SEALED_MAX).contains(&sealed.len())).ok_or(Refused::Malformed)?;
    Ok((record, bytes, name(&body.device)?, sealed))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DoneBody {
    done: Vec<Said>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Said {
    n: u64,
    said: String,
    receipt: Option<String>,
}

/// What a machine's link says came of the items it took: their numbers and words, and for a sealed
/// answer the receipt for the phone.
pub fn done_body(body: &[u8]) -> Result<Vec<Done>, Refused> {
    let body: DoneBody = wire::json(body)?;
    if body.done.len() > ITEMS_MAX {
        return Err(Refused::Malformed);
    }
    body.done
        .into_iter()
        .map(|said| {
            let receipt = said
                .receipt
                .map(|receipt| crate::util::unhex(&receipt).filter(|sealed| (SEALED_MIN..=RECEIPT_SEALED_MAX).contains(&sealed.len())).ok_or(Refused::Malformed))
                .transpose()?;
            if wire::is_word(&said.said) { Ok((said.n, said.said, receipt)) } else { Err(Refused::Malformed) }
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyBody {
    machine: String,
    id: String,
    sealed: String,
}

/// A phone's sealed answer: the machine, the question's id, and the sealed bytes.
pub fn reply_body(body: &[u8]) -> Result<(String, Id, Vec<u8>), Refused> {
    let body: ReplyBody = wire::json(body)?;
    let sealed = crate::util::unhex(&body.sealed).filter(|sealed| (SEALED_MIN..=REPLY_SEALED_MAX).contains(&sealed.len())).ok_or(Refused::Malformed)?;
    Ok((name(&body.machine)?, Id(wire::bytes(&body.id)?), sealed))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerBody {
    machine: String,
    id: String,
    decision: String,
    signature: String,
}

/// A phone's answer: the machine, the request's id, yes or not, and the signature.
pub fn answer_body(body: &[u8]) -> Result<(String, Id, bool, Vec<u8>), Refused> {
    let body: AnswerBody = wire::json(body)?;
    let yes = match body.decision.as_str() {
        "yes" => true,
        "no" => false,
        _ => return Err(Refused::Malformed),
    };
    Ok((name(&body.machine)?, Id(wire::bytes(&body.id)?), yes, wire::signature(&body.signature)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopBody {
    machine: String,
    ws: String,
    runs: Vec<RunBody>,
    signature: String,
}

/// A phone's stop as its body gives it.
pub struct Stop {
    pub machine: String,
    pub ws: WsName,
    /// Each run, with the box the phone named it with.
    pub runs: Vec<(String, RunId)>,
    pub signature: Vec<u8>,
}

/// A phone's stop, from the body of its call.
pub fn stop_body(body: &[u8]) -> Result<Stop, Refused> {
    let body: StopBody = wire::json(body)?;
    if body.runs.is_empty() || body.runs.len() > STOP_RUNS_MAX {
        return Err(Refused::Malformed);
    }
    Ok(Stop { machine: name(&body.machine)?, ws: ws_name(&body.ws)?, runs: named_runs(body.runs)?, signature: wire::signature(&body.signature)? })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HideBody {
    machine: String,
    id: String,
}

/// The request a phone closes the remote copy of.
pub fn hide_body(body: &[u8]) -> Result<(String, Id), Refused> {
    let body: HideBody = wire::json(body)?;
    Ok((name(&body.machine)?, Id(wire::bytes(&body.id)?)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NameBody {
    name: String,
}

/// The device a machine asks the keys of.
pub fn name_body(body: &[u8]) -> Result<String, Refused> {
    let body: NameBody = wire::json(body)?;
    name(&body.name)
}

/// Whether `ws` is among `scope`.
fn in_scope(scope: &[WsName], ws: &str) -> bool {
    scope.iter().any(|name| name.as_str() == ws)
}

impl Relay {
    fn mailbox(&mut self, machine: &str, now: Timestamp) -> &mut Mailbox {
        let mailbox = self.machines.entry(machine.to_string()).or_default();
        mailbox.purge(now);
        mailbox
    }

    /// The mailbox of `machine` if the hub holds one: a phone's call that names a machine makes
    /// none.
    fn held(&mut self, machine: &str, now: Timestamp) -> Option<&mut Mailbox> {
        let mailbox = self.machines.get_mut(machine)?;
        mailbox.purge(now);
        Some(mailbox)
    }

    /// A machine's report: kept as its state, and the requests it no longer lists dropped. The ids
    /// it lists that the hub lacks come back, as many as it has room for: the machine posts those
    /// again.
    pub fn report(&mut self, machine: &str, reported: Reported, now: Timestamp) -> Vec<[u8; 16]> {
        let Reported { link, workspaces, trusted, ids } = reported;
        let mailbox = self.mailbox(machine, now);
        let since = match &mailbox.report {
            Some(report) if report.link == link => report.since,
            _ => now,
        };
        mailbox.report = Some(Report { at: now, since, link, workspaces, trusted });
        mailbox.requests.retain(|id, _| ids.contains(id));
        let room = REQUESTS_MAX.saturating_sub(mailbox.requests.len());
        ids.iter().filter(|id| !mailbox.requests.contains_key(*id) && !mailbox.expired.contains_key(*id)).take(room).copied().collect()
    }

    /// A request a machine posts. One the hub holds already is left as it is.
    pub fn post(&mut self, machine: &str, record: Record, bytes: Vec<u8>, now: Timestamp) -> Result<(), Refused> {
        if record.machine != machine {
            return Err(Refused::OtherMachine);
        }
        let mailbox = self.mailbox(machine, now);
        if mailbox.requests.contains_key(&record.id.0) {
            return Ok(());
        }
        if mailbox.expired.contains_key(&record.id.0) || i64::try_from(record.expiry).unwrap_or(i64::MAX).saturating_add(GRACE.as_secs()) <= now.as_second() {
            return Err(Refused::Gone);
        }
        if mailbox.requests.len() >= REQUESTS_MAX {
            return Err(Refused::Full);
        }
        mailbox.requests.insert(record.id.0, Held { record, bytes, hidden: false });
        Ok(())
    }

    /// The notices a machine's link says are open: those it no longer names are closed, and the ids
    /// it names that the hub lacks come back, as many as it has room for. The link posts those.
    pub fn sync_notices(&mut self, machine: &str, ids: &[[u8; 16]], now: Timestamp) -> Vec<[u8; 16]> {
        let mailbox = self.mailbox(machine, now);
        mailbox.notices.retain(|id, _| ids.contains(id));
        let room = NOTICES_MAX.saturating_sub(mailbox.notices.len());
        ids.iter().filter(|id| !mailbox.notices.contains_key(*id)).take(room).copied().collect()
    }

    /// A notice a machine posts, with its sealed copies. One the hub holds already keeps its record,
    /// and takes these copies in place of its own: the phones trusted for it changed.
    pub fn post_notice(&mut self, machine: &str, notice: Notice, bytes: Vec<u8>, sealed: Copies, now: Timestamp) -> Result<(), Refused> {
        if notice.machine != machine {
            return Err(Refused::OtherMachine);
        }
        let mailbox = self.mailbox(machine, now);
        if let Some(held) = mailbox.notices.get_mut(&notice.id.0) {
            if held.bytes == bytes {
                held.sealed = sealed;
            }
            return Ok(());
        }
        if mailbox.notices.len() >= NOTICES_MAX {
            return Err(Refused::Full);
        }
        mailbox.notices.insert(notice.id.0, HeldNotice { notice, bytes, sealed });
        Ok(())
    }

    /// The notices phone `device`, which sees `scope`, may see: each machine's name, the record and
    /// the copy sealed to that phone. A notice with no copy for it is not its.
    pub fn notices(&mut self, device: &str, scope: &[WsName], machines: &[String], now: Timestamp) -> Vec<(String, Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        for machine in machines {
            let Some(mailbox) = self.held(machine, now) else { continue };
            for held in mailbox.notices.values().filter(|held| in_scope(scope, &held.notice.ws)) {
                if let Some((_, sealed)) = held.sealed.iter().find(|(named, _)| named == device) {
                    out.push((machine.clone(), held.bytes.clone(), sealed.clone()));
                }
            }
        }
        out
    }

    /// The notices `notices` lists for that phone, as its held call tells them apart, by id.
    pub fn notice_keys(&mut self, device: &str, scope: &[WsName], machines: &[String], now: Timestamp) -> Vec<NoticeKey> {
        let mut out: Vec<NoticeKey> = self
            .notices(device, scope, machines, now)
            .into_iter()
            .filter_map(|(machine, bytes, _)| {
                let notice = Notice::decode(&bytes)?;
                Some(NoticeKey { id: notice.id.0, machine, ws: notice.ws, box_name: notice.box_name })
            })
            .collect();
        out.sort_by_key(|key| key.id);
        out
    }

    /// The questions a machine's link says wait, each with the phones it is sealed to: the rest are
    /// dropped, and the copies of phones not named. The copies it names that the hub lacks come
    /// back, each the question's id and the phone, for as many questions as it has room for. The
    /// link posts those.
    pub fn sync_questions(&mut self, machine: &str, listed: &[Named], now: Timestamp) -> Vec<([u8; 16], String)> {
        let mailbox = self.mailbox(machine, now);
        mailbox.questions.retain(|id, _| listed.iter().any(|(named, _)| named == id));
        let mut missing = Vec::new();
        let mut room = QUESTIONS_MAX.saturating_sub(mailbox.questions.len());
        for (id, devices) in listed {
            match mailbox.questions.get_mut(id) {
                Some(held) => {
                    held.sealed.retain(|(device, _)| devices.contains(device));
                    missing.extend(devices.iter().filter(|device| !held.sealed.iter().any(|(named, _)| named == *device)).map(|device| (*id, device.clone())));
                }
                None if room > 0 => {
                    room -= 1;
                    missing.extend(devices.iter().map(|device| (*id, device.clone())));
                }
                None => {}
            }
        }
        missing
    }

    /// One phone's copy of a question a machine posts. One the hub holds already with the same
    /// record takes it in place of that phone's copy; another record of the same id is refused.
    pub fn post_question(&mut self, machine: &str, record: questions::Record, bytes: Vec<u8>, device: String, sealed: Vec<u8>, now: Timestamp) -> Result<(), Refused> {
        if record.machine != machine {
            return Err(Refused::OtherMachine);
        }
        if i64::try_from(record.expiry).unwrap_or(i64::MAX).saturating_add(GRACE.as_secs()) <= now.as_second() {
            return Err(Refused::Gone);
        }
        let mailbox = self.mailbox(machine, now);
        if let Some(held) = mailbox.questions.get_mut(&record.id.0) {
            if held.bytes != bytes {
                return Err(Refused::Malformed);
            }
            held.sealed.retain(|(named, _)| *named != device);
            held.sealed.push((device, sealed));
            return Ok(());
        }
        if mailbox.questions.len() >= QUESTIONS_MAX {
            return Err(Refused::Full);
        }
        mailbox.questions.insert(record.id.0, HeldQuestion { record, bytes, sealed: vec![(device, sealed)] });
        Ok(())
    }

    /// The questions phone `device`, which sees `scope`, may see: each machine's name, the clear
    /// fields and the copy sealed to that phone. A question with no copy for it is not its.
    pub fn questions(&mut self, device: &str, scope: &[WsName], machines: &[String], now: Timestamp) -> Vec<(String, Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        for machine in machines {
            let Some(mailbox) = self.held(machine, now) else { continue };
            for held in mailbox.questions.values().filter(|held| in_scope(scope, &held.record.ws)) {
                if let Some((_, sealed)) = held.sealed.iter().find(|(named, _)| named == device) {
                    out.push((machine.clone(), held.bytes.clone(), sealed.clone()));
                }
            }
        }
        out
    }

    /// The questions `questions` lists for that phone, as its held call tells them apart, by id.
    pub fn question_keys(&mut self, device: &str, scope: &[WsName], machines: &[String], now: Timestamp) -> Vec<NoticeKey> {
        let mut out: Vec<NoticeKey> = self
            .questions(device, scope, machines, now)
            .into_iter()
            .filter_map(|(machine, bytes, _)| {
                let record = questions::Record::decode(&bytes)?;
                Some(NoticeKey { id: record.id.0, machine, ws: record.ws, box_name: record.box_name })
            })
            .collect();
        out.sort_by_key(|key| key.id);
        out
    }

    /// The workspace of question `id` on `machine`, if phone `device` of `scope` may answer it: it
    /// is held, in its workspaces, with a copy sealed to it.
    pub fn question_ws(&mut self, machine: &str, id: Id, device: &str, scope: &[WsName], now: Timestamp) -> Option<String> {
        let held = self.held(machine, now)?.questions.get(&id.0)?;
        (in_scope(scope, &held.record.ws) && held.sealed.iter().any(|(named, _)| named == device)).then(|| held.record.ws.clone())
    }

    /// The requests phones of `scope` may see: each machine's name and record.
    pub fn requests(&mut self, scope: &[WsName], machines: &[String], now: Timestamp) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for machine in machines {
            let Some(mailbox) = self.held(machine, now) else { continue };
            for held in mailbox.requests.values().filter(|held| !held.hidden && in_scope(scope, &held.record.ws)) {
                out.push((machine.clone(), held.bytes.clone()));
            }
        }
        out
    }

    /// The ids of the requests phones of `scope` may see, sorted.
    pub fn ids(&mut self, scope: &[WsName], machines: &[String], now: Timestamp) -> Vec<[u8; 16]> {
        let mut out = Vec::new();
        for machine in machines {
            let Some(mailbox) = self.held(machine, now) else { continue };
            out.extend(mailbox.requests.iter().filter(|(_, held)| !held.hidden && in_scope(scope, &held.record.ws)).map(|(id, _)| *id));
        }
        out.sort();
        out
    }

    /// The record of request `id` on `machine`, if a phone of `scope` may answer it.
    pub fn record(&mut self, machine: &str, id: Id, scope: &[WsName], now: Timestamp) -> Option<(Record, Vec<u8>)> {
        let held = self.held(machine, now)?.requests.get(&id.0)?;
        (!held.hidden && in_scope(scope, &held.record.ws)).then(|| (held.record.clone(), held.bytes.clone()))
    }

    /// Closes the remote copy of request `id` on `machine` for every phone. Nothing reaches the
    /// machine: its own prompt and `halti requests` go on.
    pub fn hide(&mut self, machine: &str, id: Id, scope: &[WsName], now: Timestamp) -> Result<(), Refused> {
        let held =
            self.held(machine, now).and_then(|mailbox| mailbox.requests.get_mut(&id.0)).filter(|held| !held.hidden && in_scope(scope, &held.record.ws)).ok_or(Refused::Gone)?;
        held.hidden = true;
        Ok(())
    }

    /// Queues what device `from` sent `machine`; its number comes back.
    pub fn queue(&mut self, machine: &str, from: &str, what: What, now: Timestamp) -> Result<u64, Refused> {
        let mailbox = self.mailbox(machine, now);
        if mailbox.items.len() >= ITEMS_MAX {
            return Err(Refused::Full);
        }
        self.next += 1;
        let n = self.next;
        let mailbox = self.mailbox(machine, now);
        mailbox.items.push(Item { n, from: from.to_string(), at: now, what, taken: false, said: None, receipt: None });
        Ok(n)
    }

    /// What `machine`'s link takes: first what it says came of the items it took before, which then
    /// leave the queue; then every item still queued, taken before or not.
    pub fn take(&mut self, machine: &str, done: &[Done], now: Timestamp) -> Vec<Item> {
        let mailbox = self.mailbox(machine, now);
        for (n, said, receipt) in done {
            if let Some(at) = mailbox.items.iter().position(|item| item.n == *n && item.taken) {
                let mut item = mailbox.items.remove(at);
                item.said = Some(said.clone());
                item.receipt = receipt.clone().filter(|_| matches!(item.what, What::Reply { .. }));
                mailbox.done.push_back(item);
            }
        }
        mailbox.purge(now);
        for item in &mut mailbox.items {
            item.taken = true;
        }
        mailbox.items.clone()
    }

    /// How many machines the hub holds a mailbox for.
    #[cfg(test)]
    pub fn mailboxes(&self) -> usize {
        self.machines.len()
    }

    /// How many items taken and answered the hub keeps for `machine`.
    #[cfg(test)]
    pub fn kept(&self, machine: &str) -> usize {
        self.machines.get(machine).map_or(0, |mailbox| mailbox.done.len())
    }

    /// Whether `machine` has items queued.
    pub fn waiting(&self, machine: &str) -> bool {
        self.machines.get(machine).is_some_and(|mailbox| !mailbox.items.is_empty())
    }

    /// Forgets a revoked machine's mailbox, and what a revoked device sent that no machine has
    /// taken yet.
    pub fn forget(&mut self, name: &str) {
        self.machines.remove(name);
        for mailbox in self.machines.values_mut() {
            mailbox.items.retain(|item| item.from != name || item.taken);
        }
    }

    /// The workspaces `machine` reported trusted devices for, all of them.
    pub fn trusted_ws(&self, machine: &str) -> Vec<WsName> {
        let mut out: Vec<WsName> = Vec::new();
        for entry in self.machines.get(machine).and_then(|mailbox| mailbox.report.as_ref()).map(|report| report.trusted.as_slice()).unwrap_or_default() {
            for ws in &entry.ws {
                if !out.contains(ws) {
                    out.push(ws.clone());
                }
            }
        }
        out
    }

    /// What phone `device`, which sees `scope`, is shown: each machine that reported trusting it,
    /// with that machine's key and conflict mark as `row` gives them, and the last `SENT_MAX` it
    /// sent each machine.
    pub fn view(&mut self, device: &str, scope: &[WsName], row: &dyn Fn(&str) -> Option<MachineRow>, now: Timestamp) -> Value {
        let mut machines = Vec::new();
        let mut sent = Vec::new();
        let names: Vec<String> = self.machines.keys().cloned().collect();
        for name in names {
            let Some((key, conflict)) = row(&name) else { continue };
            let mailbox = self.mailbox(&name, now);
            let mut mine: Vec<&Item> = mailbox.items.iter().chain(mailbox.done.iter()).filter(|item| item.from == device).collect();
            mine.sort_by_key(|item| item.n);
            for item in mine.iter().skip(mine.len().saturating_sub(SENT_MAX)) {
                let state = match (&item.said, item.taken) {
                    (Some(said), _) => said.clone(),
                    (None, true) => "taken".to_string(),
                    (None, false) => "queued".to_string(),
                };
                let mut entry = json!({"n": item.n, "kind": item.what.kind(), "machine": name, "ws": item.what.ws(), "state": state, "at": wire::time(item.at)});
                match &item.what {
                    What::Answer { id, .. } => entry["id"] = id.hex().into(),
                    What::Stop { runs, .. } => entry["runs"] = runs_json(runs).into(),
                    What::Reply { id, .. } => {
                        entry["id"] = id.hex().into();
                        if let Some(receipt) = &item.receipt {
                            entry["receipt"] = hex(receipt).into();
                        }
                    }
                }
                sent.push(entry);
            }
            let Some(report) = &mailbox.report else { continue };
            let Some(trusted) = report.trusted.iter().find(|entry| entry.device == device) else { continue };
            let ws: Vec<&WsName> = trusted.ws.iter().filter(|ws| in_scope(scope, ws.as_str())).collect();
            if ws.is_empty() {
                continue;
            }
            let workspaces: Vec<Value> = report
                .workspaces
                .iter()
                .filter(|state| ws.contains(&&state.name))
                .map(|state| json!({"name": state.name, "open": state.open, "runs": runs_json(&state.runs)}))
                .collect();
            machines.push(json!({
                "name": name,
                "key": hex(&key),
                "ws": ws,
                "conflict": conflict.map(wire::time),
                "reported": wire::time(report.at),
                "since": wire::time(report.since),
                "workspaces": workspaces,
            }));
        }
        sent.sort_by_key(|entry| entry["n"].as_u64());
        json!({"machines": machines, "sent": sent})
    }
}

/// An item as the machine's link takes it.
pub fn item_json(item: &Item) -> Value {
    match &item.what {
        What::Answer { ws, id, yes, signature } => json!({
            "n": item.n, "kind": "answer", "device": item.from, "ws": ws, "id": id.hex(),
            "decision": if *yes { "yes" } else { "no" }, "signature": hex(signature),
        }),
        What::Stop { ws, runs, signature } => json!({
            "n": item.n, "kind": "stop", "device": item.from, "ws": ws,
            "runs": runs_json(runs), "signature": hex(signature),
        }),
        What::Reply { ws, id, sealed } => json!({
            "n": item.n, "kind": "reply", "device": item.from, "ws": ws, "id": id.hex(), "sealed": hex(sealed),
        }),
    }
}
