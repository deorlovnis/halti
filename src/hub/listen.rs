//! The hub's listener: TLS 1.3 over TCP, one HTTP/1.1 request per connection, with the limits
//! `wire` states. A thread serves each connection; there are never more than `CONNECTIONS` of them.
//! A machine's call for what phones sent it holds its thread while it waits (`super::INBOX_WAIT`).

use std::collections::{HashMap, VecDeque};
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::PoisonError;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value, json};

use super::relay::{self, NoticeKey, What};
use super::table::{Caller, DeviceKeys};
use super::wire::{self, Kind, Refused};
use super::{AgentLimits, Hub, locked};
use crate::door::http;
use crate::requests::answer_bytes;
use crate::util;
use halti_core::device::DeviceKey;
use halti_core::ids::WsName;

/// The longest request head.
pub const HEAD_MAX: usize = 8 * 1024;
/// The longest request body.
pub const BODY_MAX: usize = 4 * 1024;
/// The longest body of a machine's report of its state.
pub const STATE_BODY_MAX: usize = 16 * 1024;
/// The path of a machine's report of its state.
const STATE_PATH: &str = "/v1/machine/state";
/// The path of a phone's call to be told what waits: the one that takes a wake credential.
const WAIT_PATH: &str = "/v1/wait";
/// How often a held call looks again, at most this far apart.
const WAIT_LOOK: Duration = Duration::from_secs(1);
/// How long a connection has to send its whole request, TLS handshake included.
pub const REQUEST_WAIT: Duration = Duration::from_secs(10);
/// How long the reply may take to be written.
const REPLY_WAIT: Duration = Duration::from_secs(10);
/// Connections open at once, and from one address: an IPv4 address, or an IPv6 /64, which one host
/// commonly holds whole.
pub const CONNECTIONS: usize = 64;
pub const PER_ADDRESS: usize = 8;

/// The limits a listener keeps. The hub's are the constants above; tests make them smaller.
#[derive(Clone, Copy)]
pub struct Limits {
    pub request_wait: Duration,
    pub connections: usize,
    pub per_address: usize,
}

impl Limits {
    pub const HUB: Limits = Limits { request_wait: REQUEST_WAIT, connections: CONNECTIONS, per_address: PER_ADDRESS };
}

/// How many connections are open, in all and from each address, as `from` counts them.
pub struct Gate {
    limits: Limits,
    open: Mutex<(usize, HashMap<IpAddr, usize>)>,
}

/// One connection let in: counted until it is dropped.
pub struct Pass {
    gate: Arc<Gate>,
    ip: IpAddr,
}

impl Gate {
    pub fn new(limits: Limits) -> Gate {
        Gate { limits, open: Mutex::new((0, HashMap::new())) }
    }

    /// A pass for one more connection from `ip`, if the limits have room.
    pub fn enter(self: &Arc<Gate>, ip: IpAddr) -> Option<Pass> {
        let ip = from(ip);
        let mut open = locked(&self.open);
        let from = open.1.get(&ip).copied().unwrap_or(0);
        if open.0 >= self.limits.connections || from >= self.limits.per_address {
            return None;
        }
        open.0 += 1;
        open.1.insert(ip, from + 1);
        Some(Pass { gate: self.clone(), ip })
    }
}

/// The address a connection from `ip` counts against: an IPv4 address as it is, also when a
/// dual-stack listener sees it as IPv6, and an IPv6 address as its /64.
pub fn from(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
        v4 => v4,
    }
}

impl Drop for Pass {
    fn drop(&mut self) {
        let mut open = locked(&self.gate.open);
        open.0 -= 1;
        if let Some(from) = open.1.get_mut(&self.ip) {
            *from -= 1;
            if *from == 0 {
                open.1.remove(&self.ip);
            }
        }
    }
}

/// Accepts connections for as long as the listener lasts.
pub fn run(hub: Arc<Hub>, listener: TcpListener, tls: Arc<ServerConfig>, limits: Limits) {
    let gate = Arc::new(Gate::new(limits));
    for tcp in listener.incoming() {
        let Ok(tcp) = tcp else { continue };
        let Ok(peer) = tcp.peer_addr() else { continue };
        // Counted before its thread starts, so a flood never has more threads than the limit. One
        // past it is dropped here, which closes it.
        let Some(pass) = gate.enter(peer.ip()) else { continue };
        let (hub, tls) = (hub.clone(), tls.clone());
        let _ = thread::Builder::new().spawn(move || {
            let _pass = pass;
            connection(&hub, tcp, tls, limits.request_wait);
        });
    }
}

/// A socket whose reads and writes end at a deadline.
struct Timed {
    tcp: TcpStream,
    deadline: Instant,
}

impl Timed {
    fn left(&self) -> io::Result<Duration> {
        self.deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()).ok_or_else(|| io::ErrorKind::TimedOut.into())
    }
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tcp.set_read_timeout(Some(self.left()?))?;
        self.tcp.read(buf)
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp.set_write_timeout(Some(self.left()?))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

/// One request read, and the reply written: or nothing at all, for a request that doesn't come in
/// time or isn't one, a request line that isn't `METHOD TARGET HTTP/...` included.
fn connection(hub: &Hub, tcp: TcpStream, tls: Arc<ServerConfig>, request_wait: Duration) {
    let Ok(conn) = ServerConnection::new(tls) else { return };
    let mut stream = StreamOwned::new(conn, Timed { tcp, deadline: Instant::now() + request_wait });
    let request: Option<Result<(http::Head, Vec<u8>), Refused>> = {
        let mut reader = BufReader::new((&mut stream).take((HEAD_MAX + STATE_BODY_MAX + 1024) as u64));
        match http::read_head(&mut reader) {
            Ok(Some(head)) if head_len(&head) <= HEAD_MAX && head.parts().is_some() => match http::read_body(&mut reader, &head, body_max(&head)) {
                Ok(body) => Some(Ok((head, body))),
                Err(e) if e.kind() == io::ErrorKind::FileTooLarge => {
                    // What was sent is read first, as far as the limits go: closing with it unread
                    // would reset the connection and lose the reply.
                    let declared = head.header("content-length").and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
                    let _ = io::copy(&mut (&mut reader).take(declared), &mut io::sink());
                    Some(Err(Refused::TooLarge))
                }
                Err(_) => None,
            },
            _ => None,
        }
    };
    let Some(request) = request else { return };
    let (status, body) = match request.and_then(|(head, body): (http::Head, Vec<u8>)| {
        let (method, target, _) = head.parts().expect("checked as it was read");
        route(hub, method, target, head.header("authorization"), &body)
    }) {
        Ok(reply) => reply,
        Err(refused) => (refused.status(), refused.body()),
    };
    stream.sock.deadline = Instant::now() + REPLY_WAIT;
    let _ = reply(&mut stream, status, &body);
}

/// The longest body this request may have: a machine's report may be longer than other calls'.
fn body_max(head: &http::Head) -> usize {
    match head.parts() {
        Some((_, STATE_PATH, _)) => STATE_BODY_MAX,
        _ => BODY_MAX,
    }
}

/// The length of a head as it came, near enough: lines, their breaks and the blank line.
fn head_len(head: &http::Head) -> usize {
    head.line.len() + 2 + head.headers.iter().map(|(name, value)| name.len() + value.len() + 4).sum::<usize>() + 2
}

fn reply(stream: &mut StreamOwned<ServerConnection, Timed>, status: u16, body: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(body)?;
    let headers = [
        ("Content-Type", "application/json".to_string()),
        ("Content-Length", body.len().to_string()),
        ("Connection", "close".to_string()),
        ("Cache-Control", "no-store".to_string()),
    ]
    .map(|(name, value)| (name.to_string(), value));
    let mut out = Vec::new();
    http::write_head(&mut out, &format!("HTTP/1.1 {status} {}", http::reason(status)), &headers)?;
    out.extend_from_slice(&body);
    stream.write_all(&out)?;
    stream.conn.send_close_notify();
    stream.flush()
}

/// The paths the hub answers, and the method each takes.
pub(super) const PATHS: [(&str, &str); 18] = [
    ("POST", "/v1/pair"),
    ("POST", "/v1/join"),
    ("GET", "/v1/me"),
    ("POST", "/v1/renew/nonce"),
    ("POST", "/v1/renew"),
    ("GET", "/v1/requests"),
    ("GET", "/v1/state"),
    ("GET", "/v1/notices"),
    ("POST", "/v1/answer"),
    ("POST", "/v1/stop"),
    ("POST", "/v1/hide"),
    ("POST", WAIT_PATH),
    ("POST", STATE_PATH),
    ("POST", "/v1/machine/request"),
    ("POST", "/v1/machine/inbox"),
    ("POST", "/v1/machine/device"),
    ("POST", "/v1/machine/notices"),
    ("POST", "/v1/machine/notice"),
];

/// What a request gets: its status and body.
fn route(hub: &Hub, method: &str, path: &str, authorization: Option<&str>, body: &[u8]) -> Result<(u16, Value), Refused> {
    match PATHS.iter().find(|(_, p)| *p == path) {
        None => return Err(Refused::NotFound),
        Some((m, _)) if *m != method => return Err(Refused::Method),
        Some(_) => {}
    }
    if path == "/v1/pair" {
        return pair(hub, body);
    }
    if path == "/v1/join" {
        return join(hub, body);
    }
    if path == WAIT_PATH {
        return wait(hub, authorization, body);
    }
    // Every other call has a token, checked before anything else.
    let (kind, hash) = authorization.and_then(wire::bearer).ok_or(Refused::NoToken)?;
    let renewal = path.starts_with("/v1/renew");
    let caller = hub.with_table(|table, now| table.authenticate(kind, &hash, renewal, now))?;
    match path {
        "/v1/me" => me(hub, &caller, body),
        "/v1/renew/nonce" => nonce(hub, &caller, body),
        "/v1/renew" => renew(hub, &caller, body),
        machine if machine.starts_with("/v1/machine/") => {
            if caller.kind != Kind::Machine {
                return Err(Refused::WrongKind);
            }
            match machine {
                STATE_PATH => report(hub, &caller, body),
                "/v1/machine/request" => post_request(hub, &caller, body),
                "/v1/machine/inbox" => inbox(hub, &caller, body),
                "/v1/machine/notices" => sync_notices(hub, &caller, body),
                "/v1/machine/notice" => post_notice(hub, &caller, body),
                _ => device_keys(hub, body),
            }
        }
        phone => {
            if caller.kind != Kind::Device {
                return Err(Refused::WrongKind);
            }
            let scope = hub.with_table(|table, _| table.row(&caller.name).map(|row| row.ws.clone())).ok_or(Refused::Unknown)?;
            match phone {
                "/v1/requests" => requests(hub, &scope, body),
                "/v1/state" => state(hub, &caller, &scope, body),
                "/v1/notices" => notices(hub, &caller, &scope, body),
                "/v1/answer" => answer(hub, &caller, &scope, body),
                "/v1/stop" => stop(hub, &caller, &scope, body),
                _ => hide(hub, &scope, body),
            }
        }
    }
}

fn pair(hub: &Hub, body: &[u8]) -> Result<(u16, Value), Refused> {
    let (request, signature) = wire::pair_body(body)?;
    request.verify(&hub.pin, &signature)?;
    let (name, ws) = hub.with_table(|table, now| table.claim_device(request, now))?;
    Ok((202, json!({"name": name, "ws": ws})))
}

fn join(hub: &Hub, body: &[u8]) -> Result<(u16, Value), Refused> {
    let request = wire::join_body(body)?;
    let name = hub.with_table(|table, now| table.claim_machine(request, now))?;
    Ok((202, json!({"name": name})))
}

fn me(hub: &Hub, caller: &Caller, body: &[u8]) -> Result<(u16, Value), Refused> {
    wire::no_body(body)?;
    let row = hub.with_table(|table, _| table.row(&caller.name).cloned()).ok_or(Refused::Unknown)?;
    Ok((
        200,
        json!({
            "kind": row.kind(),
            "name": row.name,
            "ws": row.ws,
            "issued": wire::time(row.token.issued),
            "expires": wire::time(row.expires()),
            "renew_from": wire::time(row.renew_from()),
            "renewable_until": wire::time(row.renewable_until()),
            "conflict": row.conflict_since.map(wire::time),
            "now": wire::time(hub.now()),
        }),
    ))
}

fn nonce(hub: &Hub, caller: &Caller, body: &[u8]) -> Result<(u16, Value), Refused> {
    wire::no_body(body)?;
    if caller.kind != Kind::Device {
        return Err(Refused::WrongKind);
    }
    let (nonce, until) = hub.with_table(|table, now| table.nonce(caller, &hub.nonce_key, util::random(), now))?;
    Ok((200, json!({"nonce": util::hex(&nonce), "expires": wire::time(until)})))
}

fn renew(hub: &Hub, caller: &Caller, body: &[u8]) -> Result<(u16, Value), Refused> {
    let expires = match caller.kind {
        Kind::Device => {
            let renewal = wire::device_renew_body(body)?;
            hub.grant(|table, now| table.renew_device(caller, &renewal, &hub.pin, &hub.nonce_key, now)).ok_or(Refused::Unwritten)??
        }
        Kind::Machine => {
            let hash = wire::machine_renew_body(body)?;
            hub.grant(|table, now| table.renew_machine(caller, hash, now)).ok_or(Refused::Unwritten)??
        }
    };
    Ok((200, json!({"expires": wire::time(expires)})))
}

/// A phone's keys and workspaces, as a machine is told them.
fn device_json(device: &DeviceKeys) -> Value {
    json!({
        "name": device.name,
        "signing_key": util::hex(&device.signing),
        "agreement_key": util::hex(&device.agreement),
        "key_signature": util::hex(&device.binding),
        "ws": device.ws,
    })
}

/// A machine reports its state and the requests it holds: it is told the phones not revoked that
/// see a workspace it trusts a phone for, and which of its requests the hub lacks.
fn report(hub: &Hub, caller: &Caller, body: &[u8]) -> Result<(u16, Value), Refused> {
    let reported = relay::report_body(body)?;
    let now = hub.now();
    let (missing, wanted) = {
        let mut relay = locked(&hub.relay);
        let missing = relay.report(&caller.name, reported, now);
        (missing, relay.trusted_ws(&caller.name))
    };
    hub.stir();
    let devices: Vec<Value> = hub.with_table(|table, now| table.devices(now)).iter().filter(|device| device.ws.iter().any(|ws| wanted.contains(ws))).map(device_json).collect();
    Ok((200, json!({"devices": devices, "missing": missing.iter().map(|id| util::hex(id)).collect::<Vec<_>>()})))
}

/// A machine posts a request's record.
fn post_request(hub: &Hub, caller: &Caller, body: &[u8]) -> Result<(u16, Value), Refused> {
    let (record, bytes) = relay::record_body(body)?;
    locked(&hub.relay).post(&caller.name, record, bytes, hub.now())?;
    hub.stir();
    Ok((200, json!({})))
}

/// A machine's link says which of its notices are open: the rest are closed. It is told those the
/// hub lacks and has room for.
fn sync_notices(hub: &Hub, caller: &Caller, body: &[u8]) -> Result<(u16, Value), Refused> {
    let ids = relay::notices_body(body)?;
    let missing = locked(&hub.relay).sync_notices(&caller.name, &ids, hub.now());
    hub.stir();
    Ok((200, json!({"missing": missing.iter().map(|id| util::hex(id)).collect::<Vec<_>>()})))
}

/// A machine posts a notice, sealed to each phone it may go to.
fn post_notice(hub: &Hub, caller: &Caller, body: &[u8]) -> Result<(u16, Value), Refused> {
    let (notice, bytes, sealed) = relay::notice_body(body)?;
    locked(&hub.relay).post_notice(&caller.name, notice, bytes, sealed, hub.now())?;
    hub.stir();
    Ok((200, json!({})))
}

/// A phone lists the notices in its workspaces sealed to it, from every machine.
fn notices(hub: &Hub, caller: &Caller, scope: &[WsName], body: &[u8]) -> Result<(u16, Value), Refused> {
    wire::no_body(body)?;
    let machines: Vec<String> = hub.with_table(|table, now| table.machines(now)).into_iter().map(|(name, _, _)| name).collect();
    let held = locked(&hub.relay).notices(&caller.name, scope, &machines, hub.now());
    let listed: Vec<Value> = held.iter().map(|(machine, record, sealed)| json!({"machine": machine, "record": util::hex(record), "sealed": util::hex(sealed)})).collect();
    Ok((200, json!({"notices": listed})))
}

/// A machine takes what phones sent it, saying first what came of what it took before. With
/// nothing to take, the call waits until something comes or `inbox_wait` is over.
fn inbox(hub: &Hub, caller: &Caller, body: &[u8]) -> Result<(u16, Value), Refused> {
    let done = relay::done_body(body)?;
    let deadline = Instant::now() + hub.inbox_wait;
    let mut relay = locked(&hub.relay);
    let mut items = relay.take(&caller.name, &done, hub.now());
    while items.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        relay = hub.sent.wait_timeout(relay, left).unwrap_or_else(PoisonError::into_inner).0;
        if relay.waiting(&caller.name) {
            items = relay.take(&caller.name, &[], hub.now());
        }
    }
    Ok((200, json!({"items": items.iter().map(relay::item_json).collect::<Vec<_>>()})))
}

/// A machine asks for a phone's keys and workspaces, to compare at `halti devices trust`.
fn device_keys(hub: &Hub, body: &[u8]) -> Result<(u16, Value), Refused> {
    let name = relay::name_body(body)?;
    let device = hub.with_table(|table, now| table.device(&name, now)).ok_or(Refused::Gone)?;
    Ok((200, device_json(&device)))
}

/// A phone lists the requests in its workspaces, from every machine.
fn requests(hub: &Hub, scope: &[WsName], body: &[u8]) -> Result<(u16, Value), Refused> {
    wire::no_body(body)?;
    let machines: Vec<String> = hub.with_table(|table, now| table.machines(now)).into_iter().map(|(name, _, _)| name).collect();
    let held = locked(&hub.relay).requests(scope, &machines, hub.now());
    let listed: Vec<Value> = held.iter().map(|(machine, record)| json!({"machine": machine, "record": util::hex(record)})).collect();
    Ok((200, json!({"requests": listed})))
}

/// A phone sees the machines that trust it, as they reported, and what it sent them.
fn state(hub: &Hub, caller: &Caller, scope: &[WsName], body: &[u8]) -> Result<(u16, Value), Refused> {
    wire::no_body(body)?;
    let machines: HashMap<String, relay::MachineRow> = hub.with_table(|table, now| table.machines(now)).into_iter().map(|(name, key, conflict)| (name, (key, conflict))).collect();
    let view = locked(&hub.relay).view(&caller.name, scope, &|name| machines.get(name).cloned(), hub.now());
    Ok((200, view))
}

/// The signing key of the phone that calls.
fn caller_key(hub: &Hub, caller: &Caller) -> Result<DeviceKey, Refused> {
    let device = hub.with_table(|table, now| table.device(&caller.name, now)).ok_or(Refused::Unknown)?;
    DeviceKey::from_spki(&device.signing).map_err(|_| Refused::Unknown)
}

/// Whether a machine of this name is paired.
fn machine_known(hub: &Hub, name: &str) -> bool {
    hub.with_table(|table, now| table.machines(now)).iter().any(|(machine, _, _)| machine == name)
}

/// A phone's signed answer to a request it may see. The signature is checked here only so that one
/// that could never count is refused; the machine checks it again against its own trust list.
fn answer(hub: &Hub, caller: &Caller, scope: &[WsName], body: &[u8]) -> Result<(u16, Value), Refused> {
    let (machine, id, yes, signature) = relay::answer_body(body)?;
    if !machine_known(hub, &machine) {
        return Err(Refused::Gone);
    }
    let (record, bytes) = locked(&hub.relay).record(&machine, id, scope, hub.now()).ok_or(Refused::Gone)?;
    caller_key(hub, caller)?.verify(&answer_bytes(&bytes, yes), &signature).map_err(|_| Refused::BadSignature)?;
    let n = locked(&hub.relay).queue(&machine, &caller.name, What::Answer { ws: record.ws, id, yes, signature }, hub.now())?;
    hub.sent.notify_all();
    Ok((202, json!({"n": n})))
}

/// A phone's signed stop of runs in a workspace it may see.
fn stop(hub: &Hub, caller: &Caller, scope: &[WsName], body: &[u8]) -> Result<(u16, Value), Refused> {
    let relay::Stop { machine, ws, runs, signature } = relay::stop_body(body)?;
    if !scope.contains(&ws) || !machine_known(hub, &machine) {
        return Err(Refused::Gone);
    }
    caller_key(hub, caller)?.verify(&wire::stop_bytes(&machine, ws.as_str(), &runs), &signature).map_err(|_| Refused::BadSignature)?;
    let n = locked(&hub.relay).queue(&machine, &caller.name, What::Stop { ws: ws.to_string(), runs, signature }, hub.now())?;
    hub.sent.notify_all();
    Ok((202, json!({"n": n})))
}

/// A phone closes the remote copy of a request, with its token alone.
fn hide(hub: &Hub, scope: &[WsName], body: &[u8]) -> Result<(u16, Value), Refused> {
    let (machine, id) = relay::hide_body(body)?;
    if !machine_known(hub, &machine) {
        return Err(Refused::Gone);
    }
    locked(&hub.relay).hide(&machine, id, scope, hub.now())?;
    hub.stir();
    Ok((200, json!({})))
}

/// A phone's call, with its wake credential alone, to be told the ids of the requests it may see,
/// and from an app that names the notices it was told, of the notices too: at once if the requests
/// are not what it was last told, else once they change or `wait_hold` is over. A change of the
/// notices alone ends it only as `Agents::wake` allows. A notice new to the phone is in an answer
/// only as `Agents::wake` allows, whatever ends the call: else it is held back for a later one.
/// A newer call of the same phone ends it, as does its row's revoking or renewal (`401 unknown`).
fn wait(hub: &Hub, authorization: Option<&str>, body: &[u8]) -> Result<(u16, Value), Refused> {
    if authorization.is_some_and(|value| value.starts_with("Bearer ")) {
        return Err(Refused::WrongKind);
    }
    let wake = authorization.and_then(wire::wake).ok_or(Refused::NoToken)?;
    let (name, _) = hub.with_table(|table, now| table.wake(&wake, now))?;
    let seen = wire::wait_body(body)?;
    let mine = {
        let mut waits = locked(&hub.waits);
        let newest = waits.newest.entry(name.clone()).or_default();
        *newest += 1;
        *newest
    };
    hub.stir();
    let deadline = Instant::now() + hub.wait_hold;
    let held = || -> Result<Listed, Refused> {
        loop {
            let stirs = locked(&hub.waits).stirs;
            let (scope, machines) = hub.with_table(|table, now| -> Result<_, Refused> {
                let (_, scope) = table.wake(&wake, now)?;
                Ok((scope, table.machines(now).into_iter().map(|(name, _, _)| name).collect::<Vec<_>>()))
            })?;
            let (ids, notices) = {
                let mut relay = locked(&hub.relay);
                let ids = relay.ids(&scope, &machines, hub.now());
                (ids, seen.notices.map(|_| relay.notice_keys(&name, &scope, &machines, hub.now())))
            };
            let left = deadline.saturating_duration_since(Instant::now());
            let mut waits = locked(&hub.waits);
            if wire::seen_of(&ids) != seen.requests || left.is_zero() || waits.newest.get(&name) != Some(&mine) {
                let agents = waits.agents.entry(name.clone()).or_default();
                let notices = seen.notices.zip(notices).map(|(told, listed)| agents.told_now(told, listed, &hub.agent_limits, Instant::now()));
                return Ok((ids, notices));
            }
            if let (Some(told), Some(listed)) = (seen.notices, &notices)
                && wire::seen_of(&listed.iter().map(|key| key.id).collect::<Vec<_>>()) != told
                && waits.agents.entry(name.clone()).or_default().wake(told, listed, &hub.agent_limits, Instant::now())
            {
                return Ok((ids, notices));
            }
            if waits.stirs == stirs {
                drop(hub.stirred.wait_timeout(waits, left.min(WAIT_LOOK)).unwrap_or_else(PoisonError::into_inner));
            }
        }
    };
    let told = held();
    {
        let mut waits = locked(&hub.waits);
        if waits.newest.get(&name) == Some(&mine) {
            waits.newest.remove(&name);
        }
        if let Ok((_, Some(notices))) = &told {
            waits.agents.entry(name.clone()).or_default().answered(notices.clone());
        }
    }
    let (ids, notices) = told?;
    let mut reply = json!({"requests": ids.iter().map(|id| util::hex(id)).collect::<Vec<_>>()});
    if let Some(notices) = notices {
        reply["notices"] = notices.iter().map(|key| util::hex(&key.id)).collect::<Vec<_>>().into();
    }
    Ok((200, reply))
}

/// What a held call answers: the request ids, and the notices for an app that is told of them.
type Listed = (Vec<[u8; 16]>, Option<Vec<NoticeKey>>);

/// How many answers before the last one the hub keeps for a phone, to know what it names as told.
const EARLIER_KEPT: usize = 4;

/// A phone's wake-ups for agents' notices: what its held calls last told it, and when a change of
/// the notices last ended one, and for which boxes.
#[derive(Default)]
pub struct Agents {
    pub(super) told: Vec<NoticeKey>,
    /// The answers before `told`, the newest first. A phone that gave up on a call (the app does at
    /// each start) or lost its answer names one of these as what it was told.
    earlier: VecDeque<Vec<NoticeKey>>,
    last: Option<Instant>,
    /// Each box a notice of which ended a held call within the window: when, and the machine,
    /// workspace and box.
    woke: Vec<(Instant, String, String, String)>,
}

impl Agents {
    /// Keeps `notices` as what the phone was last answered, and the answer before it among the
    /// earlier ones.
    pub(super) fn answered(&mut self, notices: Vec<NoticeKey>) {
        if notices != self.told {
            let before = std::mem::replace(&mut self.told, notices);
            self.earlier.push_front(before);
            self.earlier.truncate(EARLIER_KEPT);
        }
    }

    /// The ids of the notices the phone was told, if `told` names one of the answers kept; else
    /// none.
    fn known(&self, told: Option<[u8; 32]>) -> Vec<[u8; 16]> {
        let ids = |answer: &[NoticeKey]| answer.iter().map(|key| key.id).collect::<Vec<_>>();
        std::iter::once(&self.told).chain(&self.earlier).map(|answer| ids(answer)).find(|ids| wire::seen_of(ids) == told).unwrap_or_default()
    }

    /// The notices an answer that ends for another reason (a request, the hold's end, a newer call)
    /// tells the phone of, out of those `listed`: each one if the change from `told` may end a call
    /// now (counted, as `wake` says), else only those it was told already. So a notice the limits
    /// hold back raises the app's agent notification at no answer.
    pub fn told_now(&mut self, told: Option<[u8; 32]>, listed: Vec<NoticeKey>, limits: &AgentLimits, now: Instant) -> Vec<NoticeKey> {
        if wire::seen_of(&listed.iter().map(|key| key.id).collect::<Vec<_>>()) == told || self.wake(told, &listed, limits, now) {
            return listed;
        }
        let known = self.known(told);
        listed.into_iter().filter(|key| known.contains(&key.id)).collect()
    }

    /// Whether the change from what the phone says it was told, `told`, to the notices `listed` may
    /// end its held call now, counted if so. Not within `gap` of the last. A change that adds no
    /// notice may; one that adds notices may if any of them is of a box and a machine under their
    /// counts in the window, and counts once for each such box. The phone's notices are known from
    /// the answer of the hub's that `told` names, of the last few; else every notice listed counts
    /// as new.
    pub fn wake(&mut self, told: Option<[u8; 32]>, listed: &[NoticeKey], limits: &AgentLimits, now: Instant) -> bool {
        if self.last.is_some_and(|last| now.duration_since(last) < limits.gap) {
            return false;
        }
        self.woke.retain(|(at, ..)| now.duration_since(*at) < limits.window);
        let known = self.known(told);
        let mut boxes: Vec<(&str, &str, &str)> = Vec::new();
        let mut added = false;
        for key in listed.iter().filter(|key| !known.contains(&key.id)) {
            added = true;
            let named = (key.machine.as_str(), key.ws.as_str(), key.box_name.as_str());
            let of_box = self.woke.iter().filter(|(_, machine, ws, box_name)| (machine.as_str(), ws.as_str(), box_name.as_str()) == named).count();
            let of_machine = self.woke.iter().filter(|(_, machine, ..)| machine == &key.machine).count() + boxes.iter().filter(|(machine, ..)| *machine == named.0).count();
            if of_box < limits.per_box && of_machine < limits.per_machine && !boxes.contains(&named) {
                boxes.push(named);
            }
        }
        if added && boxes.is_empty() {
            return false;
        }
        for (machine, ws, box_name) in boxes {
            self.woke.push((now, machine.to_string(), ws.to_string(), box_name.to_string()));
        }
        self.last = Some(now);
        true
    }
}
