//! The hub's own socket, and the commands that reach the running hub through it: `halti pair`,
//! `halti devices` and `halti revoke`. They run on the hub, as the hub's user: the socket is
//! `admin.sock` in the hub's folder, mode 0600, and each end checks that the other runs as the same
//! user. Lines are printable ASCII, at most 4 KiB with their newline:
//!
//! ```text
//! client: "halti-hub/1 pair device NAME WS[,WS...]" | "halti-hub/1 pair machine NAME"
//! hub:    "halti-hub/1 code INVITE" | "halti-hub/1 taken" | "halti-hub/1 bad"
//! hub:    "halti-hub/1 claimed device FINGERPRINT" | "halti-hub/1 claimed machine" | "halti-hub/1 expired"
//! client: "halti-hub/1 confirm" | "halti-hub/1 refuse"
//! hub:    "halti-hub/1 paired" | "halti-hub/1 refused" | "halti-hub/1 taken" | "halti-hub/1 gone"
//!
//! client: "halti-hub/1 devices"
//! hub:    "halti-hub/1 row JSON" for each row, then "halti-hub/1 end"
//!
//! client: "halti-hub/1 revoke NAME"
//! hub:    "halti-hub/1 revoked" | "halti-hub/1 unknown"
//! ```
//!
//! A pairing lasts as long as its connection: the client that goes, Ctrl-C at `halti pair` say,
//! takes the pairing with it, claimed or not. FINGERPRINT is the 20 hex characters people compare.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use halti_core::ids::WsName;
use jiff::Timestamp;
use jiff::tz::TimeZone;
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

use super::table::{CODE_LIFE, Claim, Listed, NotPaired, TokenState};
use super::wire::{self, Invite, Kind};
use super::{Hub, locked, random};
use crate::keep;
use crate::util;

/// The first word of every line.
const VERSION: &str = "halti-hub/1";
/// The longest line, its newline included.
const LINE_MAX: usize = 4096;
/// How long either end waits for a line it expects at once.
const LINE_WAIT: Duration = Duration::from_secs(5);
/// How long the person at the terminal has to answer once a pairing is claimed.
const ANSWER_WAIT: Duration = Duration::from_secs(600);
/// How often a waiting pairing looks whether its client is still there.
const LOOK_EVERY: Duration = Duration::from_millis(200);

/// What a client asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Pair { kind: Kind, name: String, ws: Vec<WsName> },
    Devices,
    Revoke(String),
}

impl Request {
    pub fn line(&self) -> String {
        match self {
            Request::Pair { kind: Kind::Device, name, ws } => {
                format!("{VERSION} pair device {name} {}\n", ws.iter().map(WsName::as_str).collect::<Vec<_>>().join(","))
            }
            Request::Pair { kind: Kind::Machine, name, .. } => format!("{VERSION} pair machine {name}\n"),
            Request::Devices => format!("{VERSION} devices\n"),
            Request::Revoke(name) => format!("{VERSION} revoke {name}\n"),
        }
    }

    /// A line without its newline. None for anything else, a name that isn't one included.
    pub fn parse(line: &str) -> Option<Request> {
        let words: Vec<&str> = line.strip_prefix(VERSION)?.strip_prefix(' ')?.split(' ').collect();
        match words[..] {
            ["pair", "device", name, ws] => {
                wire::check_name(name).ok()?;
                let ws = wire::workspaces(&ws.split(',').map(str::to_string).collect::<Vec<_>>()).ok()?;
                Some(Request::Pair { kind: Kind::Device, name: name.to_string(), ws })
            }
            ["pair", "machine", name] => {
                wire::check_name(name).ok()?;
                Some(Request::Pair { kind: Kind::Machine, name: name.to_string(), ws: Vec::new() })
            }
            ["devices"] => Some(Request::Devices),
            ["revoke", name] => {
                wire::check_name(name).ok()?;
                Some(Request::Revoke(name.to_string()))
            }
            _ => None,
        }
    }
}

fn say(stream: &mut UnixStream, words: &str) -> io::Result<()> {
    keep::write_line(stream, &format!("{VERSION} {words}\n"))
}

/// A line's words after the version, within `wait`.
fn hear(stream: &mut UnixStream, wait: Duration) -> Option<String> {
    keep::read_line_up_to(stream, wait, LINE_MAX)?.strip_prefix(VERSION)?.strip_prefix(' ').map(str::to_string)
}

/// Whether the other end has gone: looked at without waiting. Anything it sends unasked counts as
/// gone too.
fn gone(stream: &mut UnixStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return true;
    }
    let went = match stream.read(&mut [0u8; 1]) {
        Ok(_) => true,
        Err(e) => !matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted),
    };
    went || stream.set_nonblocking(false).is_err()
}

/// Serves the socket for as long as it lasts, a thread for each client of this user.
pub fn serve(hub: Arc<Hub>, listener: UnixListener) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if !keep::peer_is_own(&stream) {
            continue;
        }
        let hub = hub.clone();
        thread::spawn(move || session(&hub, stream));
    }
}

fn session(hub: &Hub, mut stream: UnixStream) {
    let Some(line) = keep::read_line_up_to(&mut stream, LINE_WAIT, LINE_MAX) else { return };
    let _ = match Request::parse(&line) {
        Some(Request::Pair { kind, name, ws }) => pairing(hub, &mut stream, kind, &name, ws),
        Some(Request::Devices) => {
            let rows = hub.with_table(|table, now| table.list(now));
            rows.iter().try_for_each(|row| say(&mut stream, &format!("row {}", serde_json::to_string(row).expect("a row as JSON")))).and_then(|()| say(&mut stream, "end"))
        }
        Some(Request::Revoke(name)) => {
            let found = hub.with_table(|table, _| table.revoke(&name));
            say(&mut stream, if found { "revoked" } else { "unknown" })
        }
        None => say(&mut stream, "bad"),
    };
}

/// One pairing, from its code to the y or N at the terminal.
fn pairing(hub: &Hub, stream: &mut UnixStream, kind: Kind, name: &str, ws: Vec<WsName>) -> io::Result<()> {
    let code = random::<16>();
    let Ok(id) = hub.with_table(|table, now| table.start(kind, name, ws, code, now)) else { return say(stream, "taken") };
    let invite = Invite { kind, address: hub.address.clone(), pin: hub.pin, code };
    if say(stream, &format!("code {invite}")).is_err() {
        hub.with_table(|table, _| table.drop_pairing(id));
        return Ok(());
    }
    // Wait for the claim, the end of the code's time, or the client to go.
    let claim = loop {
        let table = locked(&hub.table);
        let now = hub.now();
        match table.pairing(id) {
            None => break None,
            Some(p) if p.claim.is_some() => break p.claim.clone(),
            Some(p) if now >= p.until => break None,
            Some(_) => {}
        }
        drop(hub.changed.wait_timeout(table, LOOK_EVERY));
        if gone(stream) {
            hub.with_table(|table, _| table.drop_pairing(id));
            return Ok(());
        }
    };
    let Some(claim) = claim else {
        hub.with_table(|table, _| table.drop_pairing(id));
        return say(stream, "expired");
    };
    let claimed = match claim {
        Claim::Device { signing, .. } => format!("claimed device {}", wire::fingerprint(&signing).replace(' ', "")),
        Claim::Machine { .. } => "claimed machine".to_string(),
    };
    let answer = say(stream, &claimed).ok().and_then(|()| hear(stream, ANSWER_WAIT));
    if answer.as_deref() != Some("confirm") {
        hub.with_table(|table, _| table.drop_pairing(id));
        return say(stream, "refused");
    }
    match hub.with_table(|table, now| table.confirm(id, now)) {
        Ok(()) => say(stream, "paired"),
        Err(NotPaired::Taken) => say(stream, "taken"),
        Err(NotPaired::Gone) => say(stream, "gone"),
    }
}

// --- the commands ---

/// The running hub's socket, as this user.
fn socket() -> PathBuf {
    util::config_dir().join("hub").join("admin.sock")
}

/// Connects to the running hub, or says why not.
fn reach(socket: &Path) -> Result<UnixStream> {
    keep::connect(socket).ok_or_else(|| anyhow!("no hub answers at {}: run this as the hub's user, with halti hub serve running", socket.display()))
}

/// How a pairing ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Paired,
    /// The person said no, or didn't answer in time.
    Refused,
    /// Nobody used the code in its time.
    Expired,
    /// The name is taken by a row or another pairing.
    Taken,
}

/// Asks the hub at `socket` for a pairing and follows it: `show` gets the pairing string, and once
/// it is claimed `confirm` gets the fingerprint (a phone's) and says whether the person said yes.
pub fn pair_at(socket: &Path, request: &Request, mut show: impl FnMut(&Invite), mut confirm: impl FnMut(Option<&str>) -> Result<bool>) -> Result<Outcome> {
    let mut stream = reach(socket)?;
    keep::write_line(&mut stream, &request.line())?;
    let lost = || anyhow!("the hub stopped answering");
    let first = hear(&mut stream, LINE_WAIT).ok_or_else(lost)?;
    let invite = match first.split_once(' ') {
        Some(("code", line)) => Invite::parse(line).ok_or_else(lost)?,
        _ if first == "taken" => return Ok(Outcome::Taken),
        _ => bail!("the hub refused the request"),
    };
    show(&invite);
    // The code's time, and a little more for the hub to say it is over.
    let wait = Duration::from_secs(CODE_LIFE.as_secs().unsigned_abs() + 30);
    let claimed = hear(&mut stream, wait).ok_or_else(lost)?;
    let fingerprint = match claimed.as_str() {
        "expired" => return Ok(Outcome::Expired),
        "claimed machine" => None,
        other => match other.strip_prefix("claimed device ") {
            Some(hex) if hex.len() == 20 => Some(hex.as_bytes().chunks(4).map(|g| String::from_utf8_lossy(g).into_owned()).collect::<Vec<_>>().join(" ")),
            _ => return Err(lost()),
        },
    };
    let yes = confirm(fingerprint.as_deref())?;
    keep::write_line(&mut stream, &format!("{VERSION} {}\n", if yes { "confirm" } else { "refuse" }))?;
    Ok(match hear(&mut stream, LINE_WAIT).ok_or_else(lost)?.as_str() {
        "paired" => Outcome::Paired,
        "taken" => Outcome::Taken,
        _ => Outcome::Refused,
    })
}

/// The pairing string as a QR code for a dark terminal: the light modules and the border drawn,
/// the dark ones left as the background.
pub fn qr(invite: &Invite) -> String {
    let code = QrCode::new(invite.to_string().as_bytes()).expect("a pairing string fits a QR code");
    code.render::<Dense1x2>().dark_color(Dense1x2::Light).light_color(Dense1x2::Dark).quiet_zone(true).build()
}

/// Asks a yes-or-no question at the terminal; only `y` is yes.
fn ask_terminal(question: &str) -> Result<bool> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty").map_err(|_| anyhow!("halti pair asks at a terminal, and halti has none here"))?;
    let mut out = tty.try_clone()?;
    write!(out, "{question} [y/N] ")?;
    out.flush()?;
    let mut answer = String::new();
    BufReader::new(tty).read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("y"))
}

/// `halti pair --name NAME --ws WS` and `halti pair --machine NAME`.
pub fn pair(device: Option<&str>, machine: Option<&str>, ws: &[String]) -> Result<()> {
    let request = match (device, machine) {
        (Some(name), None) => {
            wire::check_name(name).map_err(|_| anyhow!("a device's name is 1 to 32 of a-z, 0-9, - and _, starting with a letter or digit"))?;
            let ws = wire::workspaces(ws).map_err(|_| anyhow!("--ws takes one or more workspace names, e.g. acme,beta"))?;
            Request::Pair { kind: Kind::Device, name: name.to_string(), ws }
        }
        (None, Some(name)) => {
            wire::check_name(name).map_err(|_| anyhow!("a machine's name is 1 to 32 of a-z, 0-9, - and _, starting with a letter or digit"))?;
            Request::Pair { kind: Kind::Machine, name: name.to_string(), ws: Vec::new() }
        }
        _ => bail!("name a device with --name and --ws, or a machine with --machine"),
    };
    let Request::Pair { kind, name, ws } = &request else { unreachable!("built above") };
    let show = |invite: &Invite| match kind {
        Kind::Device => {
            util::say(&qr(invite));
            util::say(&invite.to_string());
            util::say(&format!("scan this with the halti app within {} minutes, or paste the line into it", CODE_LIFE.as_mins()));
        }
        Kind::Machine => {
            util::say(&format!("on {name}, within {} minutes: halti hub join {invite}", CODE_LIFE.as_mins()));
        }
    };
    let confirm = |fingerprint: Option<&str>| match fingerprint {
        Some(f) => ask_terminal(&format!("device {name}, fingerprint {f}: same as on the phone?")),
        None => ask_terminal(&format!("did `halti hub join` print `joined` on {name}?")),
    };
    match pair_at(&socket(), &request, show, confirm)? {
        Outcome::Paired if *kind == Kind::Device => {
            let ws: Vec<&str> = ws.iter().map(WsName::as_str).collect();
            util::say(&format!("paired {name} for {}. its token works for 30 days, and the app renews it", ws.join(", ")));
            Ok(())
        }
        Outcome::Paired => {
            util::say(&format!("paired {name}. its token works for 30 days; the machine renews it from day 10"));
            Ok(())
        }
        Outcome::Refused => bail!("{name} was not paired. if the phone or the machine had no say in it, someone else used the code: check halti devices"),
        Outcome::Expired => bail!("nobody used the code in time: nothing was paired"),
        Outcome::Taken => bail!("{name} is taken: halti devices lists it. revoke it first to pair it again"),
    }
}

/// The rows of the hub at `socket`.
pub fn list_at(socket: &Path) -> Result<Vec<Listed>> {
    let mut stream = reach(socket)?;
    keep::write_line(&mut stream, &Request::Devices.line())?;
    let mut rows = Vec::new();
    loop {
        let line = hear(&mut stream, LINE_WAIT).ok_or_else(|| anyhow!("the hub stopped answering"))?;
        if line == "end" {
            return Ok(rows);
        }
        let json = line.strip_prefix("row ").ok_or_else(|| anyhow!("the hub said something else"))?;
        rows.push(serde_json::from_str(json).context("reading the hub's rows")?);
    }
}

fn when(t: Timestamp) -> String {
    t.to_zoned(TimeZone::system()).strftime("%Y-%m-%d %H:%M").to_string()
}

fn day(t: Timestamp) -> String {
    t.to_zoned(TimeZone::system()).strftime("%Y-%m-%d").to_string()
}

/// What `halti devices` says of a row's token.
pub fn token_text(row: &Listed) -> String {
    if let Some(since) = row.conflict_since {
        return format!("token conflict since {}", day(since));
    }
    match row.token {
        TokenState::Left { days: 1 } => "token: 1 day left".to_string(),
        TokenState::Left { days } => format!("token: {days} days left"),
        TokenState::Renewable { until } => format!("token: expired, renewable until {}", day(until)),
        TokenState::Expired => "token: expired, join again".to_string(),
    }
}

/// `halti devices`: every phone and machine paired with the hub.
pub fn devices() -> Result<()> {
    let rows = list_at(&socket())?;
    if rows.is_empty() {
        util::say("nothing is paired (halti pair --name NAME --ws WS, or halti pair --machine NAME)");
        return Ok(());
    }
    util::say(&format!("{:<20} {:<8} {:<24} {:<25} {:<36} {:<17} PUSH ADDRESS", "NAME", "KIND", "WORKSPACES", "FINGERPRINT", "TOKEN", "LAST SEEN"));
    for row in &rows {
        let ws = if row.ws.is_empty() { "-".to_string() } else { row.ws.join(",") };
        let seen = row.last_seen.map_or("never".to_string(), when);
        let push = row.push_changed.map_or("none".to_string(), |t| format!("set {}", day(t)));
        let fingerprint = row.fingerprint.as_deref().unwrap_or("-");
        util::say(&format!("{:<20} {:<8} {ws:<24} {fingerprint:<25} {:<36} {seen:<17} {push}", row.name, row.kind.word(), token_text(row)));
    }
    Ok(())
}

/// Revokes the row at the hub at `socket`; whether there was one.
pub fn revoke_at(socket: &Path, name: &str) -> Result<bool> {
    let mut stream = reach(socket)?;
    keep::write_line(&mut stream, &Request::Revoke(name.to_string()).line())?;
    match hear(&mut stream, LINE_WAIT).as_deref() {
        Some("revoked") => Ok(true),
        Some("unknown") => Ok(false),
        _ => bail!("the hub stopped answering"),
    }
}

/// `halti revoke NAME`: the row goes, and its token with it, at once.
pub fn revoke(name: &str) -> Result<()> {
    wire::check_name(name).map_err(|_| anyhow!("that isn't a device's or a machine's name"))?;
    if !revoke_at(&socket(), name)? {
        bail!("nothing is paired as {name} (halti devices lists what is)");
    }
    util::say(&format!("revoked {name}: its token no longer works. to use it again, pair it again"));
    Ok(())
}
