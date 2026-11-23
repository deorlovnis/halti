//! Questions: an agent in a box of a run marked away waits, and its owner may answer from a phone.
//! The asker in the box (`halti-shim ask`) says what the hook saw in the second form of the ask
//! (`crate::notices`, label `halti-ask-v2`), and holds the call. The open workspace makes a question
//! of it, sealed to each phone trusted for the workspace; the first answer that counts goes back on
//! the held call, and the asker turns it into the hook's output. In a run not marked away, or with
//! no phone to ask, it is answered `nobody` at once, as before.
//!
//! A question's text is written by the agent. halti did not write it and can't check it. An answer
//! goes into the box, to the session that asked, and nowhere else: it never reaches the door's
//! decisions or a policy, and grants nothing.
//!
//! Every byte string here is a run of fields, each its length in two bytes big-endian then its
//! bytes (`crate::fields`), in the order given and nothing after.
//!
//! **The text an asker sends**, by kind, after the label, event and session tag of the ask:
//!
//! ```text
//! permit   left out (4), tool (0 to 80), input (0 to 2,000: the tool's input as JSON, cut at its end)
//! choice   left out (4), then 1 to 4 questions, each one field holding: header (0 to 80),
//!          question (0 to 300), "0" or "1" (several options may be taken), then 0 to 4 options,
//!          each its label (0 to 80) and description (0 to 200)
//! idle     left out (4), the end of the agent's last message (0 to 2,000, cut at its start)
//! ```
//!
//! Text is UTF-8. `left out` is how many bytes of what the agent wrote the asker cut to fit, 4 bytes
//! big-endian: the box's word for it. The asks are `permit` (PermissionRequest), `question`
//! (PreToolUse on AskUserQuestion) and `turn-ended` (Stop).
//!
//! **The question record.** Its clear fields:
//!
//! ```text
//! label    "halti-question-v1"
//! machine, ws, box   names (`fields::is_name`)
//! run      the run id (8)
//! session  the session's number in the run, 4 bytes big-endian, from 1
//! kind     "permit", "choice" or "idle"
//! id       16 random bytes the open workspace drew
//! expiry   seconds since 1970 by this machine's clock, 8 bytes big-endian
//! ```
//!
//! and its sealed fields: a salt (16 random bytes), the reply key (91: the public half of a P-256
//! key made for this question alone and held in memory), then the text fields as above. The whole
//! record is the clear fields followed by the sealed ones, at most 8 KiB; its SHA-256 is what an
//! answer names. Each phone gets the sealed fields sealed by the machine key to its second key
//! (`halti_core::sealed`, `Kind::Question`), the clear fields being the associated data.
//!
//! **An answer** is one of the forms `yes` or `no` (permit), `options` (choice), `text` or `stopped`
//! (idle: "Leave it stopped"), with its content:
//!
//! ```text
//! yes, stopped  nothing
//! no            the reason typed, 0 to 2,000 bytes
//! text          the text typed, 1 to 2,000 bytes
//! options       for each question of the record, in order, two fields: the numbers of the options
//!               taken, one byte each from 1, rising, one unless the question takes several; and the
//!               text typed in place of an option. Exactly one of the two is empty. The text of all
//!               questions together is at most 2,000 bytes.
//! ```
//!
//! The phone signs, with its signing key, the fields `halti-answer-v1`, the SHA-256 of the whole
//! question record as it opened and showed it (32), the form, and the SHA-256 of 16 random bytes of
//! salt followed by the content (32). It seals, by its second key to the question's reply key
//! (`Kind::Answer`), with the question's clear fields as the associated data, the fields: form,
//! salt (16), content, signature. So the signed bytes hold no text and can be kept.
//!
//! **A receipt** tells the phone what came of its answer, sealed by the machine key to it
//! (`Kind::Receipt`). Its clear fields, the associated data: `halti-receipt-v1`, machine, ws, the
//! question's id (16). Its sealed fields: the SHA-256 of the signed answer bytes (32, or 32 zeros
//! for an answer that didn't open), and one word (`Outcome`).
//!
//! **What the held asker is told**: `nobody`, or the fields `halti-reply-v1`, the form and the
//! content, in place of it.

use sha2::{Digest, Sha256};

use crate::fields;
use crate::requests::{Id, RunId, check_name};

/// The first field of a question's record.
pub const LABEL: &str = "halti-question-v1";
/// The first field of the bytes a phone signs to answer.
pub const ANSWER_LABEL: &str = "halti-answer-v1";
/// The first field of a receipt's clear fields.
pub const RECEIPT_LABEL: &str = "halti-receipt-v1";
/// The first field of what the held asker is told in place of `nobody`.
pub const REPLY_LABEL: &str = "halti-reply-v1";

/// A tool's name, or a question's header.
pub const NAME_MAX: usize = 80;
/// A tool's input, or the end of the last message.
pub const BODY_MAX: usize = 2000;
/// A question of a choice.
pub const QUESTION_MAX: usize = 300;
/// An option's label, and its description.
pub const LABEL_MAX: usize = 80;
pub const DESCRIPTION_MAX: usize = 200;
/// How many questions a choice holds, and options a question.
pub const QUESTIONS_MAX: usize = 4;
pub const OPTIONS_MAX: usize = 4;
/// The whole record.
pub const RECORD_MAX: usize = 8 * 1024;
/// Text typed in an answer.
pub const TYPED_MAX: usize = 2000;
/// How long a question waits at most. Its hook's own limit (box/claude-code/halti.json) is longer.
pub const LIFE: std::time::Duration = std::time::Duration::from_secs(8 * 3600);
/// The reply key's length as the record carries it.
pub const REPLY_KEY_LEN: usize = halti_core::device::SPKI_LEN;

/// What kind of wait a question is.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Kind {
    /// Claude Code asks leave to run a tool: yes or no.
    Permit,
    /// It asks questions with options: an option, or typed text, for each.
    Choice,
    /// It finished its turn: typed text, or "Leave it stopped".
    Idle,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Permit, Kind::Choice, Kind::Idle];

    pub fn word(self) -> &'static str {
        match self {
            Kind::Permit => "permit",
            Kind::Choice => "choice",
            Kind::Idle => "idle",
        }
    }

    pub fn parse(word: &[u8]) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.word().as_bytes() == word)
    }

    /// The notice's kind for the same wait.
    pub fn notice(self) -> crate::notices::Kind {
        match self {
            Kind::Permit => crate::notices::Kind::PermissionPrompt,
            Kind::Choice => crate::notices::Kind::Question,
            Kind::Idle => crate::notices::Kind::TurnEnded,
        }
    }
}

/// The form of an answer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    Yes,
    No,
    Options,
    Text,
    /// "Leave it stopped".
    Stopped,
}

impl Form {
    pub const ALL: [Form; 5] = [Form::Yes, Form::No, Form::Options, Form::Text, Form::Stopped];

    pub fn word(self) -> &'static str {
        match self {
            Form::Yes => "yes",
            Form::No => "no",
            Form::Options => "options",
            Form::Text => "text",
            Form::Stopped => "stopped",
        }
    }

    pub fn parse(word: &[u8]) -> Option<Form> {
        Form::ALL.into_iter().find(|form| form.word().as_bytes() == word)
    }
}

/// One question of a choice, as the record holds it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Asked {
    pub header: String,
    pub question: String,
    pub several: bool,
    /// Each option's label and description.
    pub options: Vec<(String, String)>,
}

/// What a question asks, read from its text fields.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Text {
    Permit { tool: String, input: String },
    Choice(Vec<Asked>),
    Idle { message: String },
}

/// The text fields of a question, checked: how many bytes the asker says it left out, and what is
/// asked.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Said {
    pub left_out: u32,
    pub text: Text,
}

fn utf8(bytes: &[u8], max: usize) -> Option<String> {
    (bytes.len() <= max).then_some(())?;
    String::from_utf8(bytes.to_vec()).ok()
}

impl Said {
    /// The text fields of a question of `kind`, or None if they break any rule.
    pub fn parse(kind: Kind, bytes: &[u8]) -> Option<Said> {
        let parts = fields::split(bytes)?;
        let (left_out, rest) = parts.split_first()?;
        let left_out = u32::from_be_bytes((*left_out).try_into().ok()?);
        let text = match (kind, rest) {
            (Kind::Permit, [tool, input]) => Text::Permit { tool: utf8(tool, NAME_MAX)?, input: utf8(input, BODY_MAX)? },
            (Kind::Idle, [message]) => Text::Idle { message: utf8(message, BODY_MAX)? },
            (Kind::Choice, questions) if (1..=QUESTIONS_MAX).contains(&questions.len()) => Text::Choice(questions.iter().map(|question| asked(question)).collect::<Option<_>>()?),
            _ => return None,
        };
        Some(Said { left_out, text })
    }

    /// How many questions an answer must answer: those of a choice, else none.
    pub fn questions(&self) -> &[Asked] {
        match &self.text {
            Text::Choice(asked) => asked,
            _ => &[],
        }
    }
}

fn asked(bytes: &[u8]) -> Option<Asked> {
    let parts = fields::split(bytes)?;
    let [header, question, several, options @ ..] = &parts[..] else { return None };
    if options.len() % 2 != 0 || options.len() / 2 > OPTIONS_MAX {
        return None;
    }
    let several = match *several {
        b"0" => false,
        b"1" => true,
        _ => return None,
    };
    let options = options.chunks(2).map(|pair| Some((utf8(pair[0], LABEL_MAX)?, utf8(pair[1], DESCRIPTION_MAX)?))).collect::<Option<_>>()?;
    Some(Asked { header: utf8(header, NAME_MAX)?, question: utf8(question, QUESTION_MAX)?, several, options })
}

/// A question's clear fields.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    pub machine: String,
    pub ws: String,
    pub box_name: String,
    pub run: RunId,
    pub session: u32,
    pub kind: Kind,
    pub id: Id,
    /// Seconds since 1970, by this machine's clock.
    pub expiry: u64,
}

impl Record {
    /// The clear fields' bytes. Fails for a name the record can't take.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
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
            &self.expiry.to_be_bytes(),
        ]))
    }

    /// The clear fields these bytes are, or None if they are not in every field.
    pub fn decode(bytes: &[u8]) -> Option<Record> {
        let [label, machine, ws, box_name, run, session, kind, id, expiry] = fields::split(bytes)?[..] else { return None };
        let name = |bytes: &[u8]| -> Option<String> {
            let text = std::str::from_utf8(bytes).ok()?;
            check_name(text).ok()?;
            Some(text.to_string())
        };
        if label != LABEL.as_bytes() {
            return None;
        }
        Some(Record {
            machine: name(machine)?,
            ws: name(ws)?,
            box_name: name(box_name)?,
            run: RunId(run.try_into().ok()?),
            session: u32::from_be_bytes(session.try_into().ok()?),
            kind: Kind::parse(kind)?,
            id: Id(id.try_into().ok()?),
            expiry: u64::from_be_bytes(expiry.try_into().ok()?),
        })
    }

    /// The box as people name it: `acme/dev`.
    pub fn shown(&self) -> String {
        format!("{}/{}", self.ws, self.box_name)
    }
}

/// The sealed fields of a question: its salt, its reply key, then its text fields as the asker sent
/// them.
pub fn sealed_fields(salt: &[u8; 16], reply_key: &[u8], text: &[u8]) -> Vec<u8> {
    let mut bytes = fields::join(&[salt, reply_key]);
    bytes.extend_from_slice(text);
    bytes
}

/// A whole record read back: its clear fields, salt, reply key and text. None if any part breaks a
/// rule, or it is longer than a record may be.
pub fn open_whole(bytes: &[u8]) -> Option<(Record, [u8; 16], Vec<u8>, Said)> {
    if bytes.len() > RECORD_MAX {
        return None;
    }
    let parts = fields::split(bytes)?;
    if parts.len() < 11 {
        return None;
    }
    let clear_len: usize = parts[..9].iter().map(|part| part.len() + 2).sum();
    let record = Record::decode(&bytes[..clear_len])?;
    let salt: [u8; 16] = parts[9].try_into().ok()?;
    let reply_key = parts[10].to_vec();
    if reply_key.len() != REPLY_KEY_LEN {
        return None;
    }
    let text_start = clear_len + 2 + 16 + 2 + REPLY_KEY_LEN;
    let said = Said::parse(record.kind, &bytes[text_start..])?;
    Some((record, salt, reply_key, said))
}

/// The SHA-256 of a whole record: what an answer names.
pub fn hash(clear: &[u8], sealed: &[u8]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(clear);
    sha.update(sealed);
    sha.finalize().into()
}

/// The SHA-256 of an answer's salt followed by its content.
pub fn content_hash(salt: &[u8; 16], content: &[u8]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(salt);
    sha.update(content);
    sha.finalize().into()
}

/// What a phone signs to answer the question whose whole record hashes to `question`.
pub fn signed_bytes(question: &[u8; 32], form: Form, salt: &[u8; 16], content: &[u8]) -> Vec<u8> {
    fields::join(&[ANSWER_LABEL.as_bytes(), question, form.word().as_bytes(), &content_hash(salt, content)])
}

/// An answer as it opened: its form, salt, content and signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Answer {
    pub form: Form,
    pub salt: [u8; 16],
    pub content: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Answer {
    /// The fields a phone seals.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        fields::join(&[self.form.word().as_bytes(), &self.salt, &self.content, &self.signature])
    }

    /// The answer these opened bytes are, or None.
    pub fn decode(bytes: &[u8]) -> Option<Answer> {
        let [form, salt, content, signature] = fields::split(bytes)?[..] else { return None };
        if signature.is_empty() || signature.len() > halti_core::device::SIGNATURE_MAX {
            return None;
        }
        Some(Answer { form: Form::parse(form)?, salt: salt.try_into().ok()?, content: content.to_vec(), signature: signature.to_vec() })
    }
}

/// One question's part of an `options` answer: the options taken, or the text typed in place.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Pick {
    Options(Vec<u8>),
    Text(String),
}

/// The content of an `options` answer.
pub fn options_content(picks: &[Pick]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for pick in picks {
        match pick {
            Pick::Options(numbers) => {
                fields::push(&mut bytes, numbers);
                fields::push(&mut bytes, b"");
            }
            Pick::Text(text) => {
                fields::push(&mut bytes, b"");
                fields::push(&mut bytes, text.as_bytes());
            }
        }
    }
    bytes
}

/// The picks of an `options` answer to `asked`, if it fits them: one for each question; numbers of
/// options it has, rising, one unless it takes several; or text, at most `TYPED_MAX` in all.
pub fn picks(asked: &[Asked], content: &[u8]) -> Option<Vec<Pick>> {
    let parts = fields::split(content)?;
    if parts.len() != asked.len() * 2 {
        return None;
    }
    let mut typed = 0;
    let mut picks = Vec::new();
    for (question, pair) in asked.iter().zip(parts.chunks(2)) {
        let (numbers, text) = (pair[0], pair[1]);
        match (numbers.is_empty(), text.is_empty()) {
            (false, true) => {
                let in_range = numbers.iter().all(|n| (1..=question.options.len()).contains(&usize::from(*n)));
                let rising = numbers.windows(2).all(|pair| pair[0] < pair[1]);
                if !in_range || !rising || (numbers.len() > 1 && !question.several) {
                    return None;
                }
                picks.push(Pick::Options(numbers.to_vec()));
            }
            (true, false) => {
                typed += text.len();
                picks.push(Pick::Text(String::from_utf8(text.to_vec()).ok()?));
            }
            _ => return None,
        }
    }
    (typed <= TYPED_MAX).then_some(picks)
}

/// Whether an answer of `form` with `content` fits a question of `kind` that asks `said`.
pub fn fits(kind: Kind, said: &Said, form: Form, content: &[u8]) -> bool {
    let typed = |min: usize| (min..=TYPED_MAX).contains(&content.len()) && std::str::from_utf8(content).is_ok();
    match (kind, form) {
        (Kind::Permit, Form::Yes) | (Kind::Idle, Form::Stopped) => content.is_empty(),
        (Kind::Permit, Form::No) => typed(0),
        (Kind::Idle, Form::Text) => typed(1),
        (Kind::Choice, Form::Options) => picks(said.questions(), content).is_some(),
        _ => false,
    }
}

/// What came of an answer, as a receipt says it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Handed to the agent's waiting hook.
    Delivered,
    /// No such question waits: answered already, withdrawn, or the agent no longer waits.
    NotPending,
    /// The question's time was over.
    Expired,
    /// The answer is not one the question takes: another form, an option it doesn't offer, too
    /// much text.
    DoesNotFit,
    /// The signature isn't the device's over this question's record and this answer.
    BadSignature,
    /// The device isn't trusted here for this workspace.
    Untrusted,
    /// It didn't open under the question's reply key and the device's second key.
    Unreadable,
}

impl Outcome {
    pub const ALL: [Outcome; 7] = [Outcome::Delivered, Outcome::NotPending, Outcome::Expired, Outcome::DoesNotFit, Outcome::BadSignature, Outcome::Untrusted, Outcome::Unreadable];

    pub fn word(self) -> &'static str {
        match self {
            Outcome::Delivered => "delivered",
            Outcome::NotPending => "not-pending",
            Outcome::Expired => "expired",
            Outcome::DoesNotFit => "does-not-fit",
            Outcome::BadSignature => "bad-signature",
            Outcome::Untrusted => "untrusted",
            Outcome::Unreadable => "unreadable",
        }
    }

    pub fn parse(word: &str) -> Option<Outcome> {
        Outcome::ALL.into_iter().find(|outcome| outcome.word() == word)
    }
}

/// A receipt's clear fields.
pub fn receipt_clear(machine: &str, ws: &str, id: Id) -> Vec<u8> {
    fields::join(&[RECEIPT_LABEL.as_bytes(), machine.as_bytes(), ws.as_bytes(), &id.0])
}

/// A receipt's sealed fields: the hash of the answer's signed bytes, and the outcome.
pub fn receipt_fields(answer: &[u8; 32], outcome: Outcome) -> Vec<u8> {
    fields::join(&[answer, outcome.word().as_bytes()])
}

/// What the held asker is told in place of `nobody`.
pub fn reply(form: Form, content: &[u8]) -> Vec<u8> {
    fields::join(&[REPLY_LABEL.as_bytes(), form.word().as_bytes(), content])
}

/// Text as `halti requests` shows it: control, direction-changing and zero-width characters as
/// escapes, line breaks kept.
pub fn shown(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        let hidden = (c.is_control() && c != '\n') || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}');
        if hidden {
            out.push_str(&c.escape_unicode().to_string());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests;
