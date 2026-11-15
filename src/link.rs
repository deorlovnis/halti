//! This machine and its hub: `halti hub join` and `halti hub leave`, `halti link`, which carries
//! requests, state, answers and stops between this machine's open workspaces and the hub, and
//! `halti devices trust` and `untrust`, which say which phones may answer here.
//!
//! The hub is never trusted to say yes. A phone's answer or stop counts only at the open workspace
//! it names, and only if it is signed by a device this machine trusts for that workspace, over this
//! machine's own record (`requests::Desk::answer_signed`) or its own name, the workspace and the
//! runs (`requests::stop_signed`). Trust is added only at a terminal here, after two comparisons:
//! the phone's fingerprint, read from the hub and shown here, and the machine code, shown here and
//! on the phone, which computes it from what the hub passed on. Each value is made from the keys
//! of one side, so a hub that swaps a key must match a fixed 80-bit value. Trust is dropped when the
//! hub no longer lists the phone (`run`), or by `untrust`, which needs no hub.
//!
//! The wire to the hub is in `hub::wire`; the files are in `files`.

pub mod files;
pub mod run;

#[cfg(test)]
mod tests;

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use halti_core::device::{self, DeviceKey};
use halti_core::ids::WsName;
use rcgen::PublicKeyData;
use serde_json::json;

use crate::hub::{pin, wire};
use crate::requests::Trusted;
use crate::util::{self, hex, say, warn};
use files::{Entry, Folder, Joined};
use run::Listed;

/// What `halti open`, `halti ws run` and `halti requests` say while the hub refuses this machine's
/// token.
pub const REFUSED_LINE: &str = "the hub no longer accepts this machine's token. revoke it on the hub and join again";

/// How long `halti hub join` waits for the hub.
const JOIN_WAIT: Duration = Duration::from_secs(15);
/// How long `devices trust` waits for the link: it asks the hub.
const LINK_WAIT: Duration = Duration::from_secs(40);

/// The name the hub knows this machine by, once it has joined one.
pub fn joined_name() -> Option<String> {
    Folder::here().joined().ok().flatten().map(|joined| joined.name)
}

/// The device of this name, if this machine trusts it now and its keys read.
pub fn trusted(name: &str) -> Option<Trusted> {
    trusted_in(&Folder::here(), name)
}

/// As `trusted`, for the trust list in `folder`.
pub fn trusted_in(folder: &Folder, name: &str) -> Option<Trusted> {
    folder.trust().ok()?.into_iter().find(|entry| entry.name == name)?.trusted()
}

/// Says `REFUSED_LINE` if the hub refuses this machine's token.
pub fn warn_if_refused() {
    if Folder::here().refused().is_some() {
        warn(REFUSED_LINE);
    }
}

/// This machine's workspaces, as the link asks them.
struct Machine;

impl run::Local for Machine {
    fn workspaces(&self) -> Vec<(WsName, Option<PathBuf>)> {
        crate::ws::requests::workspaces()
    }
}

/// `halti link`: runs until it is stopped.
pub fn serve() -> Result<()> {
    let folder = Folder::here();
    if folder.joined()?.is_none() {
        warn("this machine hasn't joined a hub yet: the link waits for halti hub join");
    }
    run::run(&folder, &Machine, run::TIMING, &AtomicBool::new(false))
}

/// `halti hub join STRING`.
pub fn join(line: &str) -> Result<()> {
    let folder = Folder::here();
    let (name, made) = join_at(&folder, line)?;
    let joined = folder.joined()?.expect("written by the join");
    if made {
        say("made this machine's key");
    }
    say(&format!("joined the hub at {} as {name}", joined.address));
    say("answer y at halti pair on the hub. then run the link, as a service: halti link");
    Ok(())
}

/// Joins the hub of the pairing string `line` with the machine key in `folder`, made if there is
/// none: the name the hub gave, and whether the key was made.
pub fn join_at(folder: &Folder, line: &str) -> Result<(String, bool)> {
    let invite = wire::Invite::parse(line.trim()).ok_or_else(|| anyhow!("that isn't a pairing string: on the hub, halti pair --machine NAME prints one"))?;
    if invite.kind != wire::Kind::Machine {
        bail!("that string pairs a phone: scan it with the app. on the hub, halti pair --machine NAME prints one for a machine");
    }
    let (key, made) = folder.keep_machine_key()?;
    let token = format!("{}{}", wire::Kind::Machine.prefix(), hex(&util::random::<32>()));
    let body = json!({"code": hex(&invite.code), "machine_key": hex(&key.subject_public_key_info()), "token_hash": hex(&wire::token_hash(&token))});
    let (status, reply) =
        pin::request(&invite.address, invite.pin, "POST", "/v1/join", None, Some(&body), JOIN_WAIT).map_err(|e| anyhow!("can't reach the hub at {}: {e:#}", invite.address))?;
    if status != 202 {
        let word = reply["error"].as_str().unwrap_or("");
        match word {
            "bad-code" => bail!("the hub refused the code: it was used, is older than 2 minutes, or is for a phone. run halti pair --machine NAME on the hub again"),
            _ => bail!("the hub refused to join: {status} {word}"),
        }
    }
    let name = reply["name"].as_str().filter(|name| wire::check_name(name).is_ok()).ok_or_else(|| anyhow!("the hub's reply names no machine"))?.to_string();
    folder.write_joined(&Joined { version: 1, address: invite.address, pin: hex(&invite.pin), name: name.clone(), token, next: None })?;
    folder.clear_refused();
    Ok((name, made))
}

/// `halti hub leave`.
pub fn leave() -> Result<()> {
    let folder = Folder::here();
    let name = folder.joined().ok().flatten().map(|joined| joined.name);
    if !folder.leave()? {
        bail!("this machine hasn't joined a hub");
    }
    say("left the hub: this machine's token, the hub's pin and the machine key are gone. the devices it trusts are kept");
    if let Some(name) = name {
        say(&format!("revoke it on the hub too: halti revoke {name}. a new join makes a new key, and each phone compares the machine code again"));
    }
    Ok(())
}

/// Asks a yes-or-no question at the terminal; only `y` is yes.
fn ask_terminal(question: &str) -> Result<bool> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty").map_err(|_| anyhow!("halti devices trust asks at a terminal, and halti has none here"))?;
    let mut out = tty.try_clone()?;
    write!(out, "{question} [y/N] ")?;
    out.flush()?;
    let mut answer = String::new();
    BufReader::new(tty).read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("y"))
}

/// `halti devices trust NAME --ws WS`.
pub fn trust(name: &str, ws: &[String]) -> Result<()> {
    let folder = Folder::here();
    let trusted = trust_at(&folder, name, ws, &ask_terminal)?;
    let joined = folder.joined()?.expect("trust needs a join");
    say(&format!("trusted {name} for {} on this machine, which the hub knows as {}", trusted.ws.join(", "), joined.name));
    say(&format!("machine code: {}", trusted.code));
    if let Some(why) = trusted.unsynced {
        say(&format!("the link couldn't tell the hub yet ({why}): the phone shows the code once it does"));
    }
    say(&format!("on the phone, Machines shows {} with a code: tap same only if it is this one", joined.name));
    Ok(())
}

/// What a trust came to.
pub struct Trusting {
    /// The workspaces the device is trusted for here now.
    pub ws: Vec<String>,
    /// The machine code over them.
    pub code: String,
    /// Why the link couldn't report it to the hub, if it couldn't.
    pub unsynced: Option<String>,
}

/// Trusts the phone `name` for workspaces `ws` here, if `ask` says yes to its fingerprint, read
/// from the hub through the link whose folder is `folder`.
pub fn trust_at(folder: &Folder, name: &str, ws: &[String], ask: &dyn Fn(&str) -> Result<bool>) -> Result<Trusting> {
    wire::check_name(name).map_err(|_| anyhow!("a device's name is 1 to 32 of a-z, 0-9, - and _, starting with a letter or digit"))?;
    let ws = wire::workspaces(ws).map_err(|_| anyhow!("--ws takes one or more workspace names, e.g. acme,beta"))?;
    let joined = folder.joined()?.ok_or_else(|| anyhow!("this machine hasn't joined a hub: halti hub join"))?;
    let key = folder.machine_key()?.ok_or_else(|| anyhow!("this machine has no machine key: join the hub again (halti hub join)"))?;
    let said = run::ask(&folder.socket(), &format!("device {name}"), LINK_WAIT).ok_or_else(|| anyhow!("no link answers here: start it with halti link"))?;
    let device = match said.split_once(' ') {
        Some(("device", text)) => serde_json::from_str(text).ok().as_ref().and_then(Listed::read).filter(|device| device.name == name),
        Some(("no", "gone")) => bail!("the hub has no phone named {name}: halti devices on the hub lists them"),
        Some(("no", "unreachable")) => bail!("the link can't reach the hub: try again once it does"),
        Some(("no", word)) => bail!("the hub refused: {word}"),
        _ => None,
    };
    let device = device.ok_or_else(|| anyhow!("the link said something else"))?;
    let signing = util::unhex(&device.signing_key).expect("checked as it was read");
    let agreement = util::unhex(&device.agreement_key).expect("checked as it was read");
    let binding = util::unhex(&device.key_signature).expect("checked as it was read");
    let checked =
        DeviceKey::from_spki(&signing).ok().filter(|key| device::check_agreement_key(&agreement).is_ok() && key.verify(&wire::keys_bytes(&signing, &agreement), &binding).is_ok());
    if checked.is_none() {
        bail!("the hub's keys for {name} aren't a phone's signing key vouching for its second key: nothing was trusted");
    }
    if let Some(outside) = ws.iter().find(|ws| !device.ws.contains(ws)) {
        bail!("{name} may not see {outside} at the hub: pair it there with --ws including {outside}");
    }
    if let Some(known) = folder.trust()?.into_iter().find(|entry| entry.name == name)
        && (known.signing_key != device.signing_key || known.agreement_key != device.agreement_key)
    {
        bail!("{name} is trusted here with other keys. if it was paired again, untrust it first: halti devices untrust {name}");
    }
    if !ask(&format!("device {name}, fingerprint {}: same as on the phone?", wire::fingerprint(&signing)))? {
        bail!("{name} was not trusted");
    }
    let entry = folder.change_trust(|entries| {
        let at = match entries.iter().position(|entry| entry.name == name) {
            Some(at) => at,
            None => {
                entries.push(Entry {
                    name: name.to_string(),
                    signing_key: device.signing_key.clone(),
                    agreement_key: device.agreement_key.clone(),
                    key_signature: device.key_signature.clone(),
                    ws: Vec::new(),
                });
                entries.len() - 1
            }
        };
        let entry = &mut entries[at];
        let before = entry.ws.len();
        for ws in &ws {
            if !entry.ws.contains(ws) {
                entry.ws.push(ws.clone());
            }
        }
        let changed = entry.ws.len() != before;
        (entry.clone(), changed)
    })?;
    let code = wire::machine_code(&joined.name, &key.subject_public_key_info(), &entry.ws_names());
    let unsynced = match run::ask(&folder.socket(), "sync", LINK_WAIT) {
        Some(said) if said == "synced" => None,
        Some(said) => Some(said.strip_prefix("no ").unwrap_or(&said).to_string()),
        None => Some("no link answers".to_string()),
    };
    Ok(Trusting { ws: entry.ws_names(), code, unsynced })
}

/// `halti devices untrust NAME`: needs no hub.
pub fn untrust(name: &str) -> Result<()> {
    let folder = Folder::here();
    if !untrust_at(&folder, name)? {
        bail!("{name} isn't trusted here");
    }
    say(&format!("{name} is no longer trusted here: its answers and stops are refused from now on"));
    let _ = run::ask(&folder.socket(), "sync", Duration::from_secs(2));
    Ok(())
}

/// Drops trust in `name`; whether it was trusted.
pub fn untrust_at(folder: &Folder, name: &str) -> Result<bool> {
    folder.change_trust(|entries| {
        let before = entries.len();
        entries.retain(|entry| entry.name != name);
        let changed = entries.len() != before;
        (changed, changed)
    })
}

/// The devices this machine trusts, for `halti devices`: one line each.
pub fn trusted_lines() -> Vec<String> {
    let Ok(entries) = Folder::here().trust() else { return Vec::new() };
    entries
        .iter()
        .map(|entry| {
            let fingerprint = util::unhex(&entry.signing_key).map_or("?".to_string(), |key| wire::fingerprint(&key));
            format!("{:<20} {:<24} {fingerprint}", entry.name, entry.ws_names().join(","))
        })
        .collect()
}
