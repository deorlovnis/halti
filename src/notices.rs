//! Notices: that an agent in a box waits for its owner, and what kind of wait it is. The phone
//! then says "the agent in acme/dev is waiting for you: permission prompt", and the answer is given
//! at its terminal. Nothing can be answered from a notice.
//!
//! Inside the box, Claude Code's hooks (the image's managed settings) run the asker,
//! `halti-shim ask`, which says what the hook saw to the door at `POST /ask` on halti.internal,
//! in one fixed form (`Ask`): fields as a request's record has them, each its length in two bytes
//! big-endian, then its bytes, in this order and nothing after.
//!
//! ```text
//! label    "halti-ask-v1"
//! event    "permission-prompt", "question", "turn-ended" or "needs-input": the agent waits;
//!          "working": it no longer does; "typed": the same, as the owner typed at its terminal
//! session  0 to 16 bytes the box chose to tell its agent sessions apart
//! text     0 to 8,192 bytes of what the agent wrote; read and dropped here
//! ```
//!
//! It comes with `Content-Type: application/octet-stream` and no `Origin`, which no web page in the
//! box can send without a preflight the door never answers: another type is `415`, an `Origin`
//! `403`. It is answered at once, `200` with the body `nobody`: nobody answers from the phone.
//! Anything else is `400`.
//!
//! The asker of a newer image says `halti-ask-v2` in place of the label, with the same fields and
//! caps, and its text in the form `crate::questions` gives. It also says `permit` as Claude Code
//! asks leave to run a tool. Its `permit`, `question` and `turn-ended` are held in a run marked
//! away, and answered with what a phone or `halti requests` said (`crate::questions`), after the
//! interim reply `HTTP/1.1 102 Processing` written at once: the asker gives up on a call that is
//! neither answered nor held within 5 seconds. Otherwise, and every other event, at once, as above.
//! An asker of an older image is never held.
//!
//! The door knows which machine, workspace, box and run it serves; the box names none of them. The
//! open workspace keeps a run's session tags on this machine and gives each a number of its own, 1,
//! 2, 3 within the run, as its first notice opens: the smallest that no other tag of the run holds.
//! Only as many tags of a run keep a number as a box may have notices open, so a number is never
//! more than that, eight. A notice's record carries that number, never the tag, and the text never
//! reaches it: **no byte a box chose is in a notice**. What a box can choose is whether there is
//! one, when, and which of four kinds it is.
//!
//! The record, in the same fields, in this order and nothing else:
//!
//! ```text
//! label    "halti-notice-v1"
//! machine  this machine's name
//! ws       the workspace
//! box      the box
//! run      the run id (8)
//! session  the session's number in the run, 4 bytes big-endian, from 1
//! kind     "permission-prompt", "question", "turn-ended" or "needs-input"
//! id       16 random bytes the open workspace drew for this notice
//! since    when the wait began: seconds since 1970 by this machine's clock, 8 bytes big-endian
//! ```
//!
//! Names follow the record's rule (`fields::is_name`). A record that breaks any of this is refused
//! whole. It goes to a phone sealed (`halti_core::sealed`, `Kind::Notice`): these bytes are the
//! associated data, so the hub can change none of them, and the sealed text is empty.
//!
//! A notice is sent after `Limits::notice_delay` (5 minutes), or at once in a run marked away;
//! `working` for its session in that time sends nothing, as the owner was at the keyboard. It is
//! closed by `working`, by the end of its run, or as the workspace closes; never for its age. A run
//! that ended opens none: an ask the door read before it stopped may come after. One is open per
//! session, the first kind kept (two hooks may see one wait), and eight per box.
//!
//! A session's notice stays open while its question waits, so that a phone whose app reads no
//! questions, or a hub that carries none, still tells the owner of the wait; an app that lists the
//! question shows it in the notice's place. An answer closes the notice, as the agent goes on. When
//! the question ends with the agent still waiting (its time was over, the run is no longer marked
//! away, the owner left it for the terminal, or no phone is trusted any more), a new notice takes
//! the session's place, with the reason: its sealed text (`Reason`), which no box chose. A notice
//! open as its run is marked away comes back at once with the reason that its wait began before the
//! mark.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::fields;
use crate::requests::{Id, RunId, check_name};

/// The first field of a notice's record.
pub const LABEL: &str = "halti-notice-v1";
/// The first field of what the asker sends.
pub const ASK_LABEL: &str = "halti-ask-v1";
/// The first field of what the asker of a newer image sends, whose asks may be held.
pub const ASK_LABEL_V2: &str = "halti-ask-v2";
/// The path the asker sends it to on halti.internal.
pub const ASK_PATH: &str = "/ask";
/// What every ask is answered: nobody answers from the phone.
pub const NOBODY: &str = "nobody";
/// The longest session tag, and the longest text, an ask may carry.
pub const TAG_MAX: usize = 16;
pub const TEXT_MAX: usize = 8 * 1024;
/// The longest ask: its four fields at their longest.
pub const ASK_MAX: usize = 8 + ASK_LABEL.len() + 17 + TAG_MAX + TEXT_MAX;

/// What kind of wait a notice is: the box's claim.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Kind {
    /// Claude Code asks leave to run a tool.
    PermissionPrompt,
    /// It asks a question with options.
    Question,
    /// It finished its turn.
    TurnEnded,
    /// It needs some other input.
    NeedsInput,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::PermissionPrompt, Kind::Question, Kind::TurnEnded, Kind::NeedsInput];

    pub fn word(self) -> &'static str {
        match self {
            Kind::PermissionPrompt => "permission-prompt",
            Kind::Question => "question",
            Kind::TurnEnded => "turn-ended",
            Kind::NeedsInput => "needs-input",
        }
    }

    pub fn parse(word: &[u8]) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.word().as_bytes() == word)
    }
}

/// What the asker reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    /// The agent waits.
    Waiting(Kind),
    /// Claude Code asks leave to run a tool, as its dialog opens: a question in a run marked away
    /// (`crate::questions`), and nothing else. Its notice comes from the Notification that follows.
    Permit,
    /// It no longer waits.
    Working,
    /// It no longer waits: the owner typed at its terminal. Counted as `Working` here.
    Typed,
}

impl Event {
    #[cfg(test)]
    pub fn word(self) -> &'static str {
        match self {
            Event::Waiting(kind) => kind.word(),
            Event::Permit => "permit",
            Event::Working => "working",
            Event::Typed => "typed",
        }
    }

    pub fn parse(word: &[u8]) -> Option<Event> {
        match word {
            b"working" => Some(Event::Working),
            b"typed" => Some(Event::Typed),
            b"permit" => Some(Event::Permit),
            _ => Kind::parse(word).map(Event::Waiting),
        }
    }
}

/// What an ask comes to here: its event and session tag, and from a newer asker its text, which may
/// become a question. The text of an older one is checked for length and dropped as it is read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ask {
    pub event: Event,
    pub tag: Vec<u8>,
    /// From an asker that may be held (`ASK_LABEL_V2`): what the hook showed.
    pub text: Option<Vec<u8>>,
}

impl Ask {
    /// The ask these bytes are, or None if they are not one in every field.
    pub fn parse(body: &[u8]) -> Option<Ask> {
        let [label, event, tag, text] = fields::split(body)?[..] else { return None };
        let held = label == ASK_LABEL_V2.as_bytes();
        if !(held || label == ASK_LABEL.as_bytes()) || tag.len() > TAG_MAX || text.len() > TEXT_MAX {
            return None;
        }
        Some(Ask { event: Event::parse(event)?, tag: tag.to_vec(), text: held.then(|| text.to_vec()) })
    }

    /// The bytes the asker sends for `event`, `tag` and `text`.
    #[cfg(test)]
    pub fn bytes(event: &[u8], tag: &[u8], text: &[u8]) -> Vec<u8> {
        fields::join(&[ASK_LABEL.as_bytes(), event, tag, text])
    }

    /// The bytes a newer asker sends.
    #[cfg(test)]
    pub fn bytes_v2(event: &[u8], tag: &[u8], text: &[u8]) -> Vec<u8> {
        fields::join(&[ASK_LABEL_V2.as_bytes(), event, tag, text])
    }
}

/// Why a notice came back from a question that ended while its agent still waited.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    /// The question's time was over, at this time: seconds since 1970.
    Expired(u64),
    /// The run is no longer marked away.
    NotAway,
    /// The owner left it for the terminal ("Leave it stopped").
    Left,
    /// No phone is trusted for the workspace any more.
    NoPhone,
    /// The wait began before the run was marked away.
    BeforeAway,
}

impl Reason {
    pub fn word(self) -> &'static str {
        match self {
            Reason::Expired(_) => "expired",
            Reason::NotAway => "not-away",
            Reason::Left => "left",
            Reason::NoPhone => "no-phone",
            Reason::BeforeAway => "before-away",
        }
    }

    /// The notice's sealed text: the word, and the time it names (the expiry), else 0, 8 bytes
    /// big-endian.
    pub fn said(self) -> Vec<u8> {
        let at = if let Reason::Expired(at) = self { at } else { 0 };
        fields::join(&[self.word().as_bytes(), &at.to_be_bytes()])
    }
}

/// One notice, field by field.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Notice {
    pub machine: String,
    pub ws: String,
    pub box_name: String,
    pub run: RunId,
    pub session: u32,
    pub kind: Kind,
    pub id: Id,
    /// Seconds since 1970, by this machine's clock.
    pub since: u64,
}

impl Notice {
    /// Its bytes. Fails for a name the record can't take.
    pub fn encode(&self) -> Result<Vec<u8>> {
        for name in [&self.machine, &self.ws, &self.box_name] {
            check_name(name)?;
        }
        Ok(fields::join(&[
            LABEL.as_bytes(),
            self.machine.as_bytes(),
            self.ws.as_bytes(),
            self.box_name.as_bytes(),
            &self.run.0,
            &self.session.to_be_bytes(),
            self.kind.word().as_bytes(),
            &self.id.0,
            &self.since.to_be_bytes(),
        ]))
    }

    /// The notice these bytes are, or None if they are not one in every field.
    pub fn decode(bytes: &[u8]) -> Option<Notice> {
        let [label, machine, ws, box_name, run, session, kind, id, since] = fields::split(bytes)?[..] else { return None };
        let name = |bytes: &[u8]| -> Option<String> {
            let text = std::str::from_utf8(bytes).ok()?;
            check_name(text).ok()?;
            Some(text.to_string())
        };
        if label != LABEL.as_bytes() {
            return None;
        }
        Some(Notice {
            machine: name(machine)?,
            ws: name(ws)?,
            box_name: name(box_name)?,
            run: RunId(run.try_into().ok()?),
            session: u32::from_be_bytes(session.try_into().ok()?),
            kind: Kind::parse(kind)?,
            id: Id(id.try_into().ok()?),
            since: u64::from_be_bytes(since.try_into().ok()?),
        })
    }
}

/// A notice that is open: sent once `due` has passed.
#[derive(Clone, Debug)]
pub struct Open {
    pub box_name: String,
    pub run: RunId,
    pub session: u32,
    pub kind: Kind,
    pub id: Id,
    pub since: u64,
    /// Why it came back, if it did.
    pub reason: Option<Reason>,
    due: Instant,
}

/// The session tags of one run that had a notice open, with their numbers and when each was last
/// used.
#[derive(Default)]
struct Sessions {
    tags: Vec<(Vec<u8>, u32, u64)>,
}

/// The notices of one open workspace, and the numbers of its runs' sessions.
#[derive(Default)]
pub struct Table {
    open: Vec<Open>,
    runs: HashMap<RunId, Sessions>,
    /// Counts uses of a tag, to tell which was used longest ago.
    uses: u64,
    /// The runs that ended while the workspace is open.
    ended: HashSet<RunId>,
}

/// How the table is told the time: the clock a delay counts on, and seconds since 1970.
#[derive(Clone, Copy)]
pub struct Now {
    pub instant: Instant,
    pub secs: u64,
}

impl Table {
    /// What box `box_name`'s run `run` reported for the session `tag`. `away` says whether the run
    /// is marked away now; `delay` is how long a notice waits before it is sent, and `per_box` how
    /// many may be open for one box. Nothing, once the run ended.
    #[allow(clippy::too_many_arguments)]
    pub fn tell(&mut self, box_name: &str, run: RunId, event: Event, tag: &[u8], away: bool, delay: Duration, per_box: usize, now: Now) {
        if self.ended.contains(&run) {
            return;
        }
        match event {
            Event::Waiting(kind) => {
                let known = self.known(run, tag);
                if known.is_some_and(|session| self.open.iter().any(|open| open.run == run && open.session == session)) {
                    return;
                }
                if self.open.iter().filter(|open| open.box_name == box_name).count() >= per_box {
                    return;
                }
                // Numbered only as its notice opens, so a wait that opens none moves no number.
                let Some(session) = known.or_else(|| self.number(run, tag, per_box, &[])) else { return };
                let due = if away { now.instant } else { now.instant.checked_add(delay).unwrap_or(now.instant) };
                self.open.push(Open { box_name: box_name.to_string(), run, session, kind, id: Id::random(), since: now.secs, reason: None, due });
            }
            Event::Permit => {}
            Event::Working | Event::Typed => {
                if let Some(session) = self.known(run, tag) {
                    self.open.retain(|open| !(open.run == run && open.session == session));
                }
            }
        }
    }

    /// The number of `tag` in `run`, given now if it has none, for a question: `busy` are the
    /// sessions of the run with a question, which keep their numbers as one with a notice does.
    pub fn session(&mut self, run: RunId, tag: &[u8], keep: usize, busy: &[u32]) -> Option<u32> {
        self.known(run, tag).or_else(|| self.number(run, tag, keep, busy))
    }

    /// A number for `tag`, which has none in `run`: the smallest no other tag kept for the run
    /// holds. At most `keep` tags of a run are kept, so it is never more than `keep`; past that, the
    /// one used longest ago that has no notice open, nor is `busy`, gives its place up. None if
    /// every one has.
    fn number(&mut self, run: RunId, tag: &[u8], keep: usize, busy: &[u32]) -> Option<u32> {
        let mut open: Vec<u32> = self.open.iter().filter(|open| open.run == run).map(|open| open.session).collect();
        open.extend_from_slice(busy);
        self.uses += 1;
        let uses = self.uses;
        let sessions = self.runs.entry(run).or_default();
        while sessions.tags.len() >= keep {
            let oldest = sessions.tags.iter().enumerate().filter(|(_, (_, session, _))| !open.contains(session)).min_by_key(|(_, (_, _, used))| *used).map(|(at, _)| at)?;
            sessions.tags.remove(oldest);
        }
        let number = (1..).find(|number| !sessions.tags.iter().any(|(_, session, _)| session == number))?;
        sessions.tags.push((tag.to_vec(), number, uses));
        Some(number)
    }

    /// The number `tag` has in `run`, if it has one.
    pub fn known(&mut self, run: RunId, tag: &[u8]) -> Option<u32> {
        self.uses += 1;
        let uses = self.uses;
        let (_, session, used) = self.runs.get_mut(&run)?.tags.iter_mut().find(|(kept, _, _)| kept == tag)?;
        *used = uses;
        Some(*session)
    }

    /// The notices that are sent now: open, and past their delay.
    pub fn due(&self, now: Instant) -> Vec<Open> {
        self.open.iter().filter(|open| open.due <= now).cloned().collect()
    }

    /// Closes the notice of session `session` of `run`, if one is open: its question was answered,
    /// or gives it back with a reason.
    pub fn close_session(&mut self, run: RunId, session: u32) {
        self.open.retain(|open| !(open.run == run && open.session == session));
    }

    /// Opens a notice again for a wait that a question gave back, with the reason, as a new notice
    /// in place of the session's own. Nothing once the run ended, or when the box has as many open
    /// as it may.
    #[allow(clippy::too_many_arguments)]
    pub fn reopen(&mut self, box_name: &str, run: RunId, session: u32, kind: Kind, since: u64, reason: Reason, due: Instant, per_box: usize) {
        if self.ended.contains(&run) {
            return;
        }
        self.close_session(run, session);
        if self.open.iter().filter(|open| open.box_name == box_name).count() >= per_box {
            return;
        }
        self.open.push(Open { box_name: box_name.to_string(), run, session, kind, id: Id::random(), since, reason: Some(reason), due });
    }

    /// The run `run` was marked away: each notice of it open now comes back at once, as a new
    /// notice, with the reason that its wait began before the mark. Not those of the sessions
    /// `asking`, whose waits are questions already: a mark set again leaves them be.
    pub fn before_away(&mut self, run: RunId, now: Instant, asking: &[u32]) {
        for open in self.open.iter_mut().filter(|open| open.run == run && open.reason.is_none() && !asking.contains(&open.session)) {
            open.id = Id::random();
            open.reason = Some(Reason::BeforeAway);
            open.due = now;
        }
    }

    /// Whether run `run` ended while the workspace is open.
    pub fn ended(&self, run: RunId) -> bool {
        self.ended.contains(&run)
    }

    /// Closes the notices of run `run`, which ended, forgets its sessions, and opens none for it
    /// from now on.
    pub fn end_run(&mut self, run: RunId) {
        self.open.retain(|open| open.run != run);
        self.runs.remove(&run);
        self.ended.insert(run);
    }

    /// Closes every notice: the workspace is closing.
    pub fn clear(&mut self) {
        self.open.clear();
        self.runs.clear();
    }
}

#[cfg(test)]
mod tests;
