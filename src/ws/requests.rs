//! `halti requests`: the requests this machine's open workspaces wait on, listed and answered.
//!
//! It finds each open workspace by its lock and asks it on its socket (`crate::keep`), as `close`
//! does, and asks nothing itself. What it shows of a request is the record it was sent, read whole
//! and checked; an answer names those bytes and the decision (`requests::answer_digest`), so it
//! counts only for the request shown, and only once. Answering needs a terminal. That is a check
//! here, not a lock: any program running as you could send the same line. On a Mac the open
//! workspace asks Touch ID itself before it takes a yes; on Linux nothing more is asked.

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
use crate::requests::{self, Record, answer_digest, now_secs};
use crate::util::warn;

/// How long an open workspace has to list what waits.
const LIST_WAIT: Duration = Duration::from_secs(5);
/// How long it has to answer: on a Mac it asks Touch ID first, which waits as long as a request.
const ANSWER_WAIT: Duration = Duration::from_secs(requests::LIMITS.wait.as_secs() + 30);

/// A request that waits, as the open workspace sent it.
struct Found {
    ws: WsName,
    socket: PathBuf,
    record: Record,
    bytes: Vec<u8>,
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

/// This machine's workspaces, each with the socket of its open workspace if its lock is held: what
/// this machine's link asks. One whose files don't read is left out.
pub fn workspaces() -> Vec<(WsName, Option<PathBuf>)> {
    let settings = config::settings();
    let here = Here::at(&settings.workspaces.path);
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

/// `halti requests`: one line for each request that waits.
pub fn list() -> Result<()> {
    crate::link::warn_if_refused();
    let (open, found) = waiting()?;
    if open == 0 {
        println!("no workspace is open, so no request waits");
    } else if found.is_empty() {
        println!("no request waits");
    } else {
        let width = found.iter().map(|found| found.record.shown().len()).max().unwrap_or(0);
        for found in &found {
            println!("{}", line(&found.record, width, now_secs()));
        }
        println!("answer one with: halti requests approve ID, or: halti requests deny ID");
    }
    Ok(())
}

/// A request as `halti requests` lists it: its short id, its box, what it would send, and the time
/// it has left.
fn line(record: &Record, width: usize, now: u64) -> String {
    let left = record.expiry.saturating_sub(now);
    format!("{}  {:<width$}  {}  {left}s left", record.id.short(), record.shown(), record.action)
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

    #[test]
    fn a_request_is_listed_on_one_line() {
        let found = found([0xab; 16]);
        assert_eq!(line(&found.record, 10, 880), "abababab  acme/dev    POST https://api.example.com/v1/x  120s left");
        assert_eq!(line(&found.record, 0, 2_000), "abababab  acme/dev  POST https://api.example.com/v1/x  0s left", "an expired one has none");
    }
}
