//! `halti requests`: the requests this machine's open workspaces wait on, listed and answered.
//!
//! It finds each open workspace by its lock and asks it on its socket (`crate::keep`), as `close`
//! does, and asks nothing itself. What it shows of a request is the record it was sent, read whole
//! and checked; an answer names those bytes and the decision (`requests::answer_digest`), so it
//! counts only for the request shown, and only once. Answering needs a terminal. That is a check
//! here, not a lock: any program running as you could send the same line. On a Mac the open
//! workspace asks Touch ID itself before it takes a yes; on Linux nothing more is asked.
//!
//! The questions of agents in runs marked away (`crate::questions`) are listed under their own
//! heading, their text as the agent wrote it with control characters shown as escapes, and answered
//! with `reply`: it grants nothing, so nothing is asked, and the run is no longer marked away.

use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use halti_core::ids::WsName;
use halti_core::verbs::ws_list;

use super::Here;
use super::boxes::Kept;
use crate::config;
use crate::keep::{self, Told};
use crate::questions::{self, Form, Outcome, Pick, Said, Text};
use crate::requests::{Record, answer_digest, now_secs};
use crate::util::warn;

/// How long an open workspace has to list what waits.
const LIST_WAIT: Duration = Duration::from_secs(5);
/// How long it has to answer: on a Mac it asks Touch ID first, whose window stays up this long.
const ANSWER_WAIT: Duration = Duration::from_secs(crate::approve::TOUCH_ID_WAIT.as_secs() + 30);

/// A request that waits, as the open workspace sent it.
struct Found {
    ws: WsName,
    socket: PathBuf,
    record: Record,
    bytes: Vec<u8>,
}

/// A question that waits, as the open workspace sent it, whole.
struct Question {
    ws: WsName,
    socket: PathBuf,
    record: questions::Record,
    said: Said,
}

/// The questions every open workspace waits on. One that doesn't list them is passed over: it
/// runs an older halti, or the list of requests said it already.
fn questions_waiting() -> Result<Vec<Question>> {
    let settings = config::settings();
    let here = Here::at(&settings.workspaces.path);
    let mut found = Vec::new();
    for entry in ws_list(&here.files, &here.anchor)? {
        let (Some(record), true) = (entry.record, entry.pinned) else { continue };
        let Ok(kept) = Kept::of(&here, record.id) else { continue };
        if !kept.held() {
            continue;
        }
        let socket = kept.socket();
        let Some(Ok(asked)) = keep::asked(&socket, &entry.name, LIST_WAIT) else { continue };
        for whole in asked {
            match questions::open_whole(&whole) {
                Some((record, _, _, said)) if record.ws == entry.name.as_str() => found.push(Question { ws: entry.name.clone(), socket: socket.clone(), record, said }),
                _ => warn(&format!("{} sent a question that isn't one of its own, which isn't shown", entry.name)),
            }
        }
    }
    Ok(found)
}

/// The requests every open workspace waits on, and how many workspaces are open. A workspace
/// that doesn't list them is said, and passed over.
fn waiting() -> Result<(usize, Vec<Found>)> {
    let settings = config::settings();
    let here = Here::at(&settings.workspaces.path);
    let (mut open, mut found) = (0, Vec::new());
    for entry in ws_list(&here.files, &here.anchor)? {
        let (Some(record), true) = (entry.record, entry.pinned) else { continue };
        let Ok(kept) = Kept::of(&here, record.id) else { continue };
        if !kept.held() {
            continue;
        }
        let socket = kept.socket();
        let Some(Ok(records)) = keep::list(&socket, &entry.name, LIST_WAIT) else {
            warn(&format!("{} didn't list its requests: try again in a moment", entry.name));
            continue;
        };
        open += 1;
        for bytes in records {
            match Record::decode(&bytes) {
                Some(record) if record.ws == entry.name.as_str() => found.push(Found { ws: entry.name.clone(), socket: socket.clone(), record, bytes }),
                _ => warn(&format!("{} sent a request that isn't one of its own, which isn't shown", entry.name)),
            }
        }
    }
    Ok((open, found))
}

/// The workspaces in the folder `root`, each with the socket of its open workspace if its lock is
/// held: what this machine's link asks. One whose files don't read is left out.
pub fn workspaces(root: &std::path::Path) -> Vec<(WsName, Option<PathBuf>)> {
    let here = Here::at(root);
    let Ok(entries) = ws_list(&here.files, &here.anchor) else { return Vec::new() };
    entries
        .into_iter()
        .filter_map(|entry| {
            let (Some(record), true) = (entry.record, entry.pinned) else { return None };
            let kept = Kept::of(&here, record.id).ok()?;
            let socket = kept.held().then(|| kept.socket());
            Some((entry.name, socket))
        })
        .collect()
}

/// `halti requests`: one line for each request that waits, then the agents' questions.
pub fn list() -> Result<()> {
    crate::link::warn_if_refused();
    let (open, found) = waiting()?;
    if open == 0 {
        println!("no workspace is open, so no request waits");
        return Ok(());
    }
    if found.is_empty() {
        println!("no request waits");
    } else {
        let width = found.iter().map(|found| found.record.shown().len()).max().unwrap_or(0);
        for found in &found {
            println!("{}", line(&found.record, width, now_secs()));
        }
        println!("answer one with: halti requests approve ID, or: halti requests deny ID");
    }
    let asked = questions_waiting()?;
    if !asked.is_empty() {
        println!();
        println!("agents ask (their text is the agent's: halti did not write it and cannot check it; it tells you nothing about a request):");
        for question in &asked {
            print!("{}", asked_lines(&question.record, &question.said, now_secs()));
        }
        println!("answer one with: halti requests reply ID ANSWER (see halti requests reply --help)");
    }
    Ok(())
}

/// A question as `halti requests` lists it: its short id, its box, its kind and the time it has
/// left, then what it asks, indented, control characters shown as escapes.
fn asked_lines(record: &questions::Record, said: &Said, now: u64) -> String {
    let left = record.expiry.saturating_sub(now);
    let left = if left >= 3600 {
        format!("{}h{:02}m", left / 3600, left % 3600 / 60)
    } else if left > 120 {
        format!("{}m", left / 60)
    } else {
        format!("{left}s")
    };
    let mut out = format!("{}  {}  {}  {left} left\n", record.id.short(), record.shown(), record.kind.word());
    let indent = |text: &str| questions::shown(text).lines().map(|line| format!("    {line}\n")).collect::<String>();
    match &said.text {
        Text::Permit { tool, input } => {
            out.push_str(&indent(&format!("may it run {tool}?")));
            out.push_str(&indent(input));
            out.push_str("    answer: yes, or no and a reason\n");
        }
        Text::Choice(asked) => {
            for (n, question) in asked.iter().enumerate() {
                let several = if question.several { ", one or more" } else { "" };
                out.push_str(&indent(&format!("{}. {}: {}{several}", n + 1, question.header, question.question)));
                for (m, (label, description)) in question.options.iter().enumerate() {
                    out.push_str(&indent(&format!("   {}) {label}: {description}", m + 1)));
                }
            }
            out.push_str("    answer: for each question, its option numbers (2, or 1,3), or text in their place\n");
        }
        Text::Idle { message } => {
            out.push_str("    its turn ended. the end of its last message:\n");
            out.push_str(&indent(message));
            out.push_str("    answer: text to send it, or --leave to leave it stopped\n");
        }
    }
    if said.left_out > 0 {
        out.push_str(&format!("    ({} bytes of what the agent wrote are not shown)\n", said.left_out));
    }
    out
}

/// What `halti requests reply` sends for a question that asks `said`: the form and content the
/// words make, or why they make none.
fn reply_of(said: &Said, leave: bool, words: &[String]) -> Result<(Form, Vec<u8>)> {
    match &said.text {
        Text::Permit { .. } => match words.split_first() {
            Some((yes, [])) if yes == "yes" => Ok((Form::Yes, Vec::new())),
            Some((no, reason)) if no == "no" => Ok((Form::No, reason.join(" ").into_bytes())),
            _ => bail!("answer a permission prompt with yes, or no and a reason"),
        },
        Text::Choice(asked) => {
            if words.len() != asked.len() {
                bail!("answer each of its {} questions: its option numbers (2, or 1,3), or text in their place, quoted", asked.len());
            }
            let pick = |word: &String| {
                let numbers: Option<Vec<u8>> = word.split(',').map(|n| n.trim().parse::<u8>().ok()).collect();
                match numbers {
                    Some(numbers) if !word.is_empty() => Pick::Options(numbers),
                    _ => Pick::Text(word.clone()),
                }
            };
            Ok((Form::Options, questions::options_content(&words.iter().map(pick).collect::<Vec<_>>())))
        }
        Text::Idle { .. } if leave => Ok((Form::Stopped, Vec::new())),
        Text::Idle { .. } if words.is_empty() => bail!("answer with the text to send the agent, or --leave to leave it stopped"),
        Text::Idle { .. } => Ok((Form::Text, words.join(" ").into_bytes())),
    }
}

/// `halti requests reply ID ANSWER...`: answers the one question whose id starts with `typed`.
pub fn reply(typed: &str, leave: bool, words: &[String]) -> Result<()> {
    if !io::stdin().is_terminal() {
        bail!("halti requests answers only at a terminal");
    }
    let asked = questions_waiting()?;
    let typed_id = typed.to_ascii_lowercase();
    if !(8..=32).contains(&typed_id.len()) || !typed_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("a question's id is 8 to 32 of 0-9 and a-f, as halti requests lists it");
    }
    let matching: Vec<&Question> = asked.iter().filter(|question| question.record.id.hex().starts_with(&typed_id)).collect();
    let question = match matching[..] {
        [one] => one,
        [] => bail!("no question {typed_id} waits. list them with: halti requests"),
        _ => bail!("more than one question starts with {typed_id}: give more of its id"),
    };
    let (form, content) = reply_of(&question.said, leave, words)?;
    let short = question.record.id.short();
    let records = keep::Records::Here { ws: question.ws.clone(), id: question.record.id, form, content };
    match keep::tell(&question.socket, &records, LIST_WAIT) {
        Some(Told::Receipt(Outcome::Delivered, _)) => {
            println!("answered {short}: the agent in {} goes on. {} is no longer marked away", question.record.shown(), question.record.shown())
        }
        Some(Told::Receipt(Outcome::MaybeUnused, _)) => println!(
            "answered {short}: handed to the agent in {}. Its terminal shows the same prompt: if it was answered there first, this answer is not used. {} is no longer marked away",
            question.record.shown(),
            question.record.shown()
        ),
        Some(Told::Receipt(Outcome::DoesNotFit, _)) => bail!("that answer doesn't fit question {short}: see halti requests reply --help"),
        Some(Told::Receipt(Outcome::Expired | Outcome::NotPending, _)) => bail!("question {short} no longer waits: it was answered, or the agent went on"),
        _ => bail!("{} didn't answer: try again in a moment", question.ws),
    }
    Ok(())
}

/// A request as `halti requests` lists it: its short id, its box, what it would send, and the time
/// it has left.
fn line(record: &Record, width: usize, now: u64) -> String {
    let left = record.expiry.saturating_sub(now);
    let left = if left > 120 { format!("{}m", left / 60) } else { format!("{left}s") };
    format!("{}  {:<width$}  {}  {left} left", record.id.short(), record.shown(), record.action)
}

/// `halti requests approve ID` and `deny ID`: the one request whose id starts with `typed`, at
/// least the 8 characters the list shows.
pub fn answer(typed: &str, yes: bool) -> Result<()> {
    if !io::stdin().is_terminal() {
        bail!("halti requests answers only at a terminal");
    }
    crate::link::warn_if_refused();
    let (_, found) = waiting()?;
    let found = pick(&found, typed)?;
    let (short, ws) = (found.record.id.short(), &found.ws);
    let what = format!("box {} to send {}", found.record.shown(), found.record.action);
    match keep::answer(&found.socket, ws, yes, answer_digest(&found.bytes, yes), ANSWER_WAIT) {
        Some(Told::Approved) => println!("approved {short}: {what}"),
        Some(Told::Denied) => println!("denied {short}: {what}"),
        Some(Told::Gone) => bail!("request {short} no longer waits: it was answered, or it expired"),
        Some(Told::Declined) => bail!("request {short} wasn't approved: Touch ID, asked where {ws} is open, wasn't given"),
        Some(Told::Busy) => bail!("request {short} wasn't approved: Touch ID asks about another approval of it where {ws} is open"),
        _ => bail!("{ws} didn't answer: try again in a moment"),
    }
    Ok(())
}

/// The one request whose id starts with `typed`: 8 to 32 hex characters. Fewer than the list
/// shows could name a newer request than the one that was read.
fn pick<'a>(found: &'a [Found], typed: &str) -> Result<&'a Found> {
    let typed = typed.to_ascii_lowercase();
    if !(8..=32).contains(&typed.len()) || !typed.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("a request's id is 8 to 32 of 0-9 and a-f, as halti requests lists it");
    }
    let matching: Vec<&Found> = found.iter().filter(|found| found.record.id.hex().starts_with(&typed)).collect();
    match matching[..] {
        [one] => Ok(one),
        [] => bail!("no request {typed} waits. list them with: halti requests"),
        _ => bail!("more than one request starts with {typed}: give more of its id"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requests::{Id, Kind, RunId};

    fn found(id: [u8; 16]) -> Found {
        let record = Record {
            machine: "mac".into(),
            ws: "acme".into(),
            box_name: "dev".into(),
            run: RunId([1; 8]),
            kind: Kind::Write,
            action: "POST https://api.example.com/v1/x".into(),
            id: Id(id),
            expiry: 1_000,
        };
        let bytes = record.encode().unwrap();
        Found { ws: WsName::parse("acme").unwrap(), socket: PathBuf::from("/nowhere"), record, bytes }
    }

    #[test]
    fn a_request_is_picked_by_the_start_of_its_id() {
        let mut one = [0x1a; 16];
        one[5] = 0x01;
        let mut two = [0x1a; 16];
        two[5] = 0x02;
        let found = [found(one), found(two)];
        assert_eq!(pick(&found, "1a1a1a1a1a01").unwrap().record.id, Id(one));
        assert_eq!(pick(&found, "1A1A1A1A1A02").unwrap().record.id, Id(two), "either case");
        assert_eq!(pick(&found, &Id(two).hex()).unwrap().record.id, Id(two), "the whole id");
        let said = |typed: &str| pick(&found, typed).err().unwrap().to_string();
        assert_eq!(said("1a1a1a1a"), "more than one request starts with 1a1a1a1a: give more of its id");
        assert_eq!(said("1a1a1a1a1a03"), "no request 1a1a1a1a1a03 waits. list them with: halti requests");
        // Fewer than the 8 characters the list shows is refused, even where one request starts so.
        assert_eq!(pick(&found[..1], "1a1a").err().unwrap().to_string(), "a request's id is 8 to 32 of 0-9 and a-f, as halti requests lists it");
        for typed in ["1a1a", "1a1a1a1", "1a1a1a0g", &"1".repeat(33), "", "../1a1a1a"] {
            assert_eq!(said(typed), "a request's id is 8 to 32 of 0-9 and a-f, as halti requests lists it", "{typed}");
        }
    }

    fn said(kind: questions::Kind, parts: &[&[u8]]) -> Said {
        let mut all: Vec<&[u8]> = vec![&[0, 0, 0, 0]];
        all.extend_from_slice(parts);
        Said::parse(kind, &crate::fields::join(&all)).unwrap()
    }

    fn words(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| word.to_string()).collect()
    }

    #[test]
    fn the_words_of_a_reply_make_the_answer_of_its_question_s_kind() {
        let permit = said(questions::Kind::Permit, &[b"Bash", b"{}"]);
        assert_eq!(reply_of(&permit, false, &words(&["yes"])).unwrap(), (Form::Yes, Vec::new()));
        assert_eq!(reply_of(&permit, false, &words(&["no", "not", "on", "main"])).unwrap(), (Form::No, b"not on main".to_vec()));
        assert_eq!(reply_of(&permit, false, &words(&["no"])).unwrap(), (Form::No, Vec::new()));
        for bad in [&[][..], &["yes", "please"], &["maybe"]] {
            assert!(reply_of(&permit, false, &words(bad)).is_err(), "{bad:?}");
        }
        let question = crate::fields::join(&[b"Color", b"Which?", b"1", b"Red", b"", b"Blue", b""]);
        let choice = said(questions::Kind::Choice, &[&question, &question]);
        let (form, content) = reply_of(&choice, false, &words(&["1,2", "Green, on Tuesdays"])).unwrap();
        assert_eq!(form, Form::Options);
        assert_eq!(content, questions::options_content(&[Pick::Options(vec![1, 2]), Pick::Text("Green, on Tuesdays".into())]));
        assert!(questions::fits(questions::Kind::Choice, &choice, form, &content));
        assert!(reply_of(&choice, false, &words(&["1"])).is_err(), "one answer for each question");
        let idle = said(questions::Kind::Idle, &[b"done"]);
        assert_eq!(reply_of(&idle, false, &words(&["run", "the", "tests"])).unwrap(), (Form::Text, b"run the tests".to_vec()));
        assert_eq!(reply_of(&idle, true, &[]).unwrap(), (Form::Stopped, Vec::new()));
        assert!(reply_of(&idle, false, &[]).is_err());
    }

    #[test]
    fn a_question_is_listed_with_its_text_escaped_and_what_was_left_out() {
        let record = questions::Record {
            machine: "mac".into(),
            ws: "acme".into(),
            box_name: "dev".into(),
            run: RunId([1; 8]),
            session: 1,
            kind: questions::Kind::Permit,
            id: Id([0xab; 16]),
            expiry: 10_000,
        };
        let mut all: Vec<&[u8]> = vec![&[0, 0, 0, 9]];
        all.extend_from_slice(&[b"Bash", "rm -rf /\u{1b}[2J\nok".as_bytes()]);
        let said = Said::parse(questions::Kind::Permit, &crate::fields::join(&all)).unwrap();
        assert_eq!(
            asked_lines(&record, &said, 10_000 - 7_300),
            "abababab  acme/dev  permit  2h01m left\n    may it run Bash?\n    rm -rf /\\u{1b}[2J\n    ok\n    answer: yes, or no and a reason\n    (9 bytes of what the agent wrote are not shown)\n"
        );
    }

    #[test]
    fn a_request_is_listed_on_one_line() {
        let found = found([0xab; 16]);
        assert_eq!(line(&found.record, 10, 880), "abababab  acme/dev    POST https://api.example.com/v1/x  120s left");
        assert_eq!(line(&found.record, 0, 2_000), "abababab  acme/dev  POST https://api.example.com/v1/x  0s left", "an expired one has none");
        // A request of a run marked away has minutes left.
        let away = Record { expiry: 10_000, ..found.record.clone() };
        assert_eq!(line(&away, 0, 10_000 - 28 * 60 - 30), "abababab  acme/dev  POST https://api.example.com/v1/x  28m left");
        assert_eq!(line(&away, 0, 10_000 - 121), "abababab  acme/dev  POST https://api.example.com/v1/x  2m left");
    }
}
