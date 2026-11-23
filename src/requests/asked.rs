//! The questions of an open workspace's boxes (`crate::questions`), kept on its desk beside the
//! requests and notices: made as a box's asker holds its call in a run marked away, sealed to each
//! phone trusted for the workspace, answered by the first answer that counts, from a phone or from
//! `halti requests`, and withdrawn otherwise. Apart from requests: no question holds up, replaces or
//! counts against a request, nor the other way round, and an answer reaches nothing but the asker
//! that waits.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use halti_core::sealed::{self, AgreementKey, ReplyKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{By, Desk, Id, RunId, Signed, Table, Trusted, now_secs};
use crate::notices::{self, Event, Reason};
use crate::questions::{self, Answer, Form, Kind, Outcome, Record, Said};
use crate::util::{random, say};

/// How many questions one box may have waiting, and the open workspace of all its boxes.
pub const PER_BOX: usize = 3;
pub const PER_DESK: usize = 20;
/// How many closed questions are remembered, to say what came of a late answer.
const CLOSED_KEPT: usize = 64;
/// How often a held question looks whether a phone is still trusted for its workspace.
const TRUST_EVERY: Duration = Duration::from_secs(5);

/// The phones a question goes to, and the key it is sealed by. The open workspace reads them from
/// this machine's link's files; tests give their own.
pub trait Phones: Send + Sync {
    /// Every device this machine trusts, with its second key where it reads.
    fn trusted(&self) -> Vec<(Trusted, Option<AgreementKey>)>;
    /// The machine key, if this machine joined a hub.
    fn machine_key(&self) -> Option<SecretKey>;
}

/// No phone: a desk of the tests that ask none.
#[cfg(test)]
pub struct NoPhones;

#[cfg(test)]
impl Phones for NoPhones {
    fn trusted(&self) -> Vec<(Trusted, Option<AgreementKey>)> {
        Vec::new()
    }

    fn machine_key(&self) -> Option<SecretKey> {
        None
    }
}

/// The files of this machine's link, in its folder: the trust list and the machine key.
pub struct LinkFiles(pub crate::link::files::Folder);

impl Phones for LinkFiles {
    fn trusted(&self) -> Vec<(Trusted, Option<AgreementKey>)> {
        let entries = self.0.trust().unwrap_or_default();
        entries.iter().filter_map(|entry| Some((entry.trusted()?, entry.second_key()))).collect()
    }

    fn machine_key(&self) -> Option<SecretKey> {
        self.0.sealing_key().ok().flatten()
    }
}

/// What the held asker is told.
#[derive(Debug)]
pub enum Asked {
    /// Nobody answers from the phone: the agent's own prompt shows.
    Nobody,
    /// The answer, as the asker is told it (`nobody` for "Leave it stopped"), and what the door's
    /// log says of it.
    Answered { reply: Vec<u8>, line: Line },
}

/// What the door's log says of an answer: who gave it, to which question, of what kind, in what
/// form; the SHA-256 of the question's record (salted, as the record holds a salt), and a phone's
/// signed bytes with its signature (`By::Device`), which hold no text.
#[derive(Clone, Debug)]
pub struct Line {
    pub by: By,
    pub id: Id,
    pub kind: Kind,
    pub form: Form,
    pub hash: [u8; 32],
}

/// Where a question is.
pub(super) enum State {
    Waiting,
    Answered {
        form: Form,
        content: Zeroizing<Vec<u8>>,
        by: By,
    },
    /// Withdrawn or expired; with the reason its notice comes back with, if the agent still waits.
    Closed(Option<Reason>),
    /// The link couldn't give it to the hub: answered nobody, as one past the cap is. Its notice,
    /// open beside it, stays.
    Unposted,
}

/// A question that waits for its answer.
pub(super) struct Pending {
    pub(super) record: Record,
    clear: Vec<u8>,
    /// Its sealed fields, in the clear: held in memory only.
    sealed: Zeroizing<Vec<u8>>,
    hash: [u8; 32],
    said: Said,
    reply_key: ReplyKey,
    tag: Vec<u8>,
    since: u64,
    /// A copy for each phone it is sealed to: the phone's name, its second key, the sealed bytes.
    copies: Vec<(String, AgreementKey, Vec<u8>)>,
    state: State,
    deadline: Instant,
}

impl Pending {
    fn waiting(&self) -> bool {
        matches!(self.state, State::Waiting)
    }

    /// Whether its time is over: both clocks count, as for a request.
    fn late(&self, now: Instant) -> bool {
        now >= self.deadline || SystemTime::now() >= UNIX_EPOCH + Duration::from_secs(self.record.expiry)
    }
}

/// The phones trusted for `ws` whose second keys read.
fn phones_of(trusted: &[(Trusted, Option<AgreementKey>)], ws: &str) -> Vec<(String, AgreementKey)> {
    trusted.iter().filter(|(trusted, _)| trusted.ws.iter().any(|named| named == ws)).filter_map(|(trusted, second)| Some((trusted.name.clone(), (*second)?))).collect()
}

impl Table {
    /// Withdraws every waiting question that `which` picks, with the reason each one's notice comes
    /// back with: `reason` says it for each.
    pub(super) fn withdraw(&mut self, which: impl Fn(&Pending) -> bool, reason: impl Fn(&Pending) -> Option<Reason>) {
        for pending in self.questions.iter_mut().filter(|pending| pending.waiting() && which(pending)) {
            pending.state = State::Closed(reason(pending));
        }
    }

    /// The sessions of `run` that have a question waiting.
    pub(super) fn asking(&self, run: RunId) -> Vec<u32> {
        self.questions.iter().filter(|pending| pending.record.run == run && pending.waiting()).map(|pending| pending.record.session).collect()
    }

    /// Whether the session `tag` of `run` has a question waiting.
    pub(super) fn has_question(&mut self, run: RunId, tag: &[u8]) -> bool {
        self.questions.iter().any(|pending| pending.record.run == run && pending.tag == tag && pending.waiting())
    }

    /// What the asker reported for session `tag` of `run`, for its questions: `working` withdraws
    /// its own, as the agent went on; `typed` too, and ends the run's mark, which withdraws the
    /// rest of the run's with the reason that it is no longer marked away.
    pub(super) fn told(&mut self, run: RunId, event: Event, tag: &[u8]) {
        match event {
            Event::Working => self.withdraw(|pending| pending.record.run == run && pending.tag == tag, |_| None),
            Event::Typed => {
                self.withdraw(|pending| pending.record.run == run && pending.tag == tag, |_| None);
                self.away.remove(&run);
                self.withdraw(|pending| pending.record.run == run, |_| Some(Reason::NotAway));
            }
            Event::Waiting(_) | Event::Permit => {}
        }
    }

    /// Remembers what a late answer to question `id` is told.
    fn closed(&mut self, id: Id, outcome: Outcome) {
        self.closed_questions.push_back((id, outcome));
        while self.closed_questions.len() > CLOSED_KEPT {
            self.closed_questions.pop_front();
        }
    }
}

impl Desk {
    /// When the away mark of run `run` ends, if it has one that hasn't.
    fn mark_of(&self, run: RunId) -> Option<u64> {
        let now = now_secs();
        self.table().away.get(&run).copied().filter(|until| *until > now)
    }

    /// What the newer asker in box `box_name`'s run `run` reported for its session `tag`, with the
    /// text its hook showed: held as a question until it is answered, in a run marked away with a
    /// phone to ask; `nobody` at once otherwise. The notice is made as before either way: it stays
    /// beside the question, for a phone whose app reads no questions, and the hub that carries
    /// none. `held` is called once the question is made, before the wait: the asker is told that
    /// its call is held, as it gives up on one that isn't answered at once. `gone` says the asker's
    /// call was closed: it gave up, or Claude Code ended its hook.
    #[allow(clippy::too_many_arguments)]
    pub fn ask(self: &Arc<Self>, box_name: &str, run: RunId, event: Event, tag: &[u8], text: &[u8], held: &dyn Fn(), gone: &dyn Fn() -> bool) -> Asked {
        let kind = match event {
            Event::Permit => Kind::Permit,
            Event::Waiting(notices::Kind::Question) => Kind::Choice,
            Event::Waiting(notices::Kind::TurnEnded) => Kind::Idle,
            _ => {
                self.tell(box_name, run, event, tag);
                return Asked::Nobody;
            }
        };
        let said = Said::parse(kind, text);
        let opened = match (self.mark_of(run), said) {
            (Some(until), Some(said)) => self.open_question(box_name, run, kind, tag, text, said, until),
            _ => None,
        };
        self.tell(box_name, run, event, tag);
        let Some(id) = opened else { return Asked::Nobody };
        held();
        self.wait_question(id, gone)
    }

    /// Makes the question, sealed to each phone trusted for the workspace: its id, or None where
    /// none may be made (no phone, no machine key, a run that ended, a workspace closing, the
    /// session asking already, or as many waiting as may), and then a notice is made as before.
    #[allow(clippy::too_many_arguments)]
    fn open_question(&self, box_name: &str, run: RunId, kind: Kind, tag: &[u8], text: &[u8], said: Said, until: u64) -> Option<Id> {
        let phones = phones_of(&self.phones.trusted(), &self.ws);
        let key = self.phones.machine_key()?;
        if phones.is_empty() {
            return None;
        }
        let now = now_secs();
        let life = questions::LIFE.min(Duration::from_secs(until.saturating_sub(now)));
        let reply_key = ReplyKey::make(&random());
        let mut table = self.table();
        if table.closed || table.notices.ended(run) {
            return None;
        }
        if table.has_question(run, tag)
            || table.questions.iter().filter(|pending| pending.record.box_name == box_name && pending.waiting()).count() >= PER_BOX
            || table.questions.iter().filter(|pending| pending.waiting()).count() >= PER_DESK
        {
            return None;
        }
        let busy = table.asking(run);
        let session = table.notices.session(run, tag, self.limits.notices_per_box, &busy)?;
        let record = Record {
            machine: (self.machine)(),
            ws: self.ws.clone(),
            box_name: box_name.to_string(),
            run,
            session,
            kind,
            id: Id::random(),
            expiry: now.saturating_add(life.as_secs()),
        };
        let clear = record.encode().ok()?;
        let sealed = Zeroizing::new(questions::sealed_fields(&random(), &reply_key.public().spki(), text));
        if clear.len() + sealed.len() > questions::RECORD_MAX {
            return None;
        }
        let copies =
            phones.into_iter().filter_map(|(name, second)| Some((name, second, sealed::seal(sealed::Kind::Question, &key, &second, &clear, &sealed, &random()).ok()?))).collect();
        let id = record.id;
        let hash = questions::hash(&clear, &sealed);
        table.questions.push(Pending {
            record,
            clear,
            sealed,
            hash,
            said,
            reply_key,
            tag: tag.to_vec(),
            since: now,
            copies,
            state: State::Waiting,
            deadline: Instant::now() + life,
        });
        drop(table);
        self.changed.notify_all();
        say(&format!("question {}: the agent in {}/{box_name} asks ({}). answer it on a phone, or here: halti requests", id.short(), self.ws, kind.word()));
        Some(id)
    }

    /// Waits until question `id` is answered, expires, or is withdrawn, then it goes: what the asker
    /// is told. One answered closes its session's notice, as the agent goes on; one that ends with
    /// the agent still waiting gives its notice back, with the reason.
    fn wait_question(&self, id: Id, gone: &dyn Fn() -> bool) -> Asked {
        let mut looked = Instant::now();
        let mut table = self.table();
        loop {
            let Some(at) = table.questions.iter().position(|pending| pending.record.id == id) else { return Asked::Nobody };
            let marked = table.away.get(&table.questions[at].record.run).is_some_and(|until| *until > now_secs());
            let closing = table.closed;
            let pending = &mut table.questions[at];
            if pending.waiting() {
                if closing {
                    pending.state = State::Closed(None);
                } else if pending.late(Instant::now()) {
                    pending.state = State::Closed(Some(Reason::Expired(pending.record.expiry)));
                } else if !marked {
                    pending.state = State::Closed(Some(Reason::NotAway));
                }
            }
            if !pending.waiting() {
                let pending = table.questions.remove(at);
                let outcome = if matches!(pending.state, State::Closed(Some(Reason::Expired(_)))) { Outcome::Expired } else { Outcome::NotPending };
                table.closed(id, outcome);
                let record = &pending.record;
                return match pending.state {
                    State::Answered { form, content, by } => {
                        if form == Form::Stopped {
                            let due = Instant::now();
                            table.notices.reopen(&record.box_name, record.run, record.session, record.kind.notice(), pending.since, Reason::Left, due, self.limits.notices_per_box);
                        } else {
                            table.notices.close_session(record.run, record.session);
                        }
                        drop(table);
                        self.changed.notify_all();
                        say(&format!("question {}: answered ({})", id.short(), by.word()));
                        let line = Line { by, id, kind: record.kind, form, hash: pending.hash };
                        // "Leave it stopped" is an answer, logged as one, and the asker is told
                        // nobody: the agent stops as it was about to.
                        let reply = if form == Form::Stopped { crate::notices::NOBODY.as_bytes().to_vec() } else { questions::reply(form, &content) };
                        Asked::Answered { reply, line }
                    }
                    State::Unposted => {
                        drop(table);
                        self.changed.notify_all();
                        say(&format!("question {}: the hub can't take it, so it is answered here: back to its terminal", id.short()));
                        Asked::Nobody
                    }
                    State::Closed(reason) => {
                        if let Some(reason) = reason {
                            let away = table.away.get(&record.run).is_some_and(|until| *until > now_secs());
                            let due = if away { Instant::now() } else { Instant::now() + self.limits.notice_delay };
                            table.notices.reopen(&record.box_name, record.run, record.session, record.kind.notice(), pending.since, reason, due, self.limits.notices_per_box);
                        }
                        drop(table);
                        self.changed.notify_all();
                        say(&format!("question {}: {}", id.short(), reason.map_or("withdrawn: the agent no longer waits", |reason| reason_said(reason))));
                        Asked::Nobody
                    }
                    State::Waiting => unreachable!("closed above"),
                };
            }
            drop(table);
            if gone() {
                self.table().withdraw(|pending| pending.record.id == id, |_| None);
            } else if looked.elapsed() >= TRUST_EVERY {
                looked = Instant::now();
                if phones_of(&self.phones.trusted(), &self.ws).is_empty() {
                    self.table().withdraw(|pending| pending.record.id == id, |_| Some(Reason::NoPhone));
                }
            }
            table = self.table();
            if table.questions.iter().any(|pending| pending.record.id == id && pending.waiting()) {
                table = self.changed.wait_timeout(table, super::LOOK_EVERY).unwrap_or_else(std::sync::PoisonError::into_inner).0;
            }
        }
    }

    /// The questions that wait, each its clear fields and a copy sealed to each phone trusted for the
    /// workspace now: copies for phones trusted since are sealed now, and those of phones no longer
    /// trusted dropped. One with no phone left is withdrawn.
    pub fn questions(&self) -> Vec<crate::keep::SealedQuestion> {
        let phones = phones_of(&self.phones.trusted(), &self.ws);
        let mut key = None;
        let mut table = self.table();
        if phones.is_empty() {
            table.withdraw(|_| true, |_| Some(Reason::NoPhone));
        }
        let mut out = Vec::new();
        for pending in table.questions.iter_mut().filter(|pending| pending.waiting()) {
            pending.copies.retain(|(name, second, _)| phones.iter().any(|(trusted, key)| trusted == name && key == second));
            for (name, second) in &phones {
                if pending.copies.iter().any(|(named, _, _)| named == name) {
                    continue;
                }
                if key.is_none() {
                    key = self.phones.machine_key();
                }
                let Some(machine) = &key else { break };
                if let Ok(copy) = sealed::seal(sealed::Kind::Question, machine, second, &pending.clear, &pending.sealed, &random()) {
                    pending.copies.push((name.clone(), *second, copy));
                }
            }
            out.push((pending.clear.clone(), pending.copies.iter().map(|(name, _, copy)| (name.clone(), copy.clone())).collect()));
        }
        drop(table);
        self.changed.notify_all();
        out
    }

    /// The link couldn't give the hub questions `ids`: more wait on this machine than the hub holds,
    /// or the hub carries no questions. Each that still waits is answered nobody, as one past the
    /// cap is: Claude Code shows its own prompt, and the wait's notice tells the phone.
    pub fn unposted(&self, ids: &[Id]) {
        let mut table = self.table();
        for pending in table.questions.iter_mut().filter(|pending| pending.waiting() && ids.contains(&pending.record.id)) {
            pending.state = State::Unposted;
        }
        drop(table);
        self.changed.notify_all();
    }

    /// The whole records of the questions that wait, their sealed fields in the clear: for
    /// `halti requests` at this machine.
    pub fn asked(&self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        self.table().questions.iter().filter(|pending| pending.waiting() && !pending.late(now)).map(|pending| [pending.clear.as_slice(), &pending.sealed].concat()).collect()
    }

    /// An answer from `halti requests`, to question `id`: handed to its asker if it still waits and
    /// the answer fits it (`Outcome::handed`). The run's mark ends, and its other questions are
    /// withdrawn.
    pub fn answer_question_here(&self, id: Id, form: Form, content: &[u8]) -> Outcome {
        let mut table = self.table();
        let now = Instant::now();
        let Some(pending) = table.questions.iter_mut().find(|pending| pending.record.id == id) else {
            return table.closed_questions.iter().find(|(closed, _)| *closed == id).map_or(Outcome::NotPending, |(_, outcome)| *outcome);
        };
        if !pending.waiting() {
            return Outcome::NotPending;
        }
        if pending.late(now) {
            return Outcome::Expired;
        }
        if !questions::fits(pending.record.kind, &pending.said, form, content) {
            return Outcome::DoesNotFit;
        }
        pending.state = State::Answered { form, content: Zeroizing::new(content.to_vec()), by: By::Local };
        let (run, kind) = (pending.record.run, pending.record.kind);
        table.away.remove(&run);
        table.withdraw(|pending| pending.record.run == run, |_| Some(Reason::NotAway));
        drop(table);
        self.changed.notify_all();
        say(&format!("box run {} is no longer away: a question of it was answered here", run.hex()));
        Outcome::handed(kind)
    }

    /// A phone's sealed answer to question `id`, from the device named `device`: what came of it,
    /// and the receipt sealed by the machine key to that device, if it is trusted here at all. It
    /// counts only if the device is trusted for this workspace, it opens under the question's reply
    /// key and the device's second key, the signature is the device's over this question's own
    /// record and the answer, the question still waits and its time isn't over, and the answer fits
    /// it. The first answer that counts wins; it is `delivered`, or `maybe-unused` for a `permit`,
    /// whose dialog the terminal may have answered meanwhile without ending the hook.
    pub fn reply(&self, device: &str, id: Id, sealed: &[u8]) -> (Outcome, Option<Vec<u8>>) {
        let trusted = self.phones.trusted();
        let Some((trusted, second)) = trusted.into_iter().find(|(trusted, _)| trusted.name == device) else { return (Outcome::Untrusted, None) };
        let (outcome, answered) = self.check_reply(&trusted, second.as_ref(), id, sealed);
        let receipt = second.and_then(|second| {
            let key = self.phones.machine_key()?;
            let clear = questions::receipt_clear(&(self.machine)(), &self.ws, id);
            sealed::seal(sealed::Kind::Receipt, &key, &second, &clear, &questions::receipt_fields(&answered, outcome), &random()).ok()
        });
        say(&format!("question {}: an answer from {device}: {}", id.short(), outcome.word()));
        (outcome, receipt)
    }

    /// The checks of `reply`, in order: what came of it, and the SHA-256 of the signed bytes
    /// rebuilt from this machine's own record (zeros where the answer didn't open).
    fn check_reply(&self, trusted: &Trusted, second: Option<&AgreementKey>, id: Id, sealed: &[u8]) -> (Outcome, [u8; 32]) {
        let none = [0; 32];
        if !trusted.ws.contains(&self.ws) {
            return (Outcome::Untrusted, none);
        }
        let Some(second) = second else { return (Outcome::Untrusted, none) };
        let mut table = self.table();
        let now = Instant::now();
        let Some(pending) = table.questions.iter_mut().find(|pending| pending.record.id == id) else {
            let outcome = table.closed_questions.iter().find(|(closed, _)| *closed == id).map_or(Outcome::NotPending, |(_, outcome)| *outcome);
            return (outcome, none);
        };
        let Some(answer) = pending.reply_key.open(second, &pending.clear, sealed).ok().and_then(|opened| Answer::decode(&opened)) else { return (Outcome::Unreadable, none) };
        let signed = questions::signed_bytes(&pending.hash, answer.form, &answer.salt, &answer.content);
        let answered: [u8; 32] = Sha256::digest(&signed).into();
        if trusted.key.verify(&signed, &answer.signature).is_err() {
            return (Outcome::BadSignature, answered);
        }
        if !pending.waiting() {
            return (Outcome::NotPending, answered);
        }
        if pending.late(now) {
            return (Outcome::Expired, answered);
        }
        if !questions::fits(pending.record.kind, &pending.said, answer.form, &answer.content) {
            return (Outcome::DoesNotFit, answered);
        }
        let by = By::Device(Arc::new(Signed { device: trusted.name.clone(), fingerprint: trusted.fingerprint.clone(), record: signed, signature: answer.signature }));
        pending.state = State::Answered { form: answer.form, content: Zeroizing::new(answer.content), by };
        let outcome = Outcome::handed(pending.record.kind);
        drop(table);
        self.changed.notify_all();
        (outcome, answered)
    }
}

/// Why a question went, as the terminal where the workspace is open says it.
fn reason_said(reason: Reason) -> &'static str {
    match reason {
        Reason::Expired(_) => "not answered in time: back to its terminal",
        Reason::NotAway => "withdrawn: the run is no longer marked away",
        Reason::Left => "left for its terminal",
        Reason::NoPhone => "withdrawn: no phone is trusted for the workspace any more",
        Reason::BeforeAway => "back to its terminal",
    }
}
