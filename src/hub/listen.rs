//! The hub's listener: TLS 1.3 over TCP, one HTTP/1.1 request per connection, with the limits
//! `wire` states. A thread serves each connection; there are never more than `CONNECTIONS` of them.
//! A machine's call for what phones sent it holds its thread while it waits (`super::INBOX_WAIT`).

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::PoisonError;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value, json};

use super::relay::{self, What};
use super::table::{Caller, DeviceKeys};
use super::wire::{self, Kind, Refused};
use super::{Hub, locked};
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
const PATHS: [(&str, &str); 14] = [
    ("POST", "/v1/pair"),
    ("POST", "/v1/join"),
    ("GET", "/v1/me"),
    ("POST", "/v1/renew/nonce"),
    ("POST", "/v1/renew"),
    ("GET", "/v1/requests"),
    ("GET", "/v1/state"),
    ("POST", "/v1/answer"),
    ("POST", "/v1/stop"),
    ("POST", "/v1/hide"),
    ("POST", STATE_PATH),
    ("POST", "/v1/machine/request"),
    ("POST", "/v1/machine/inbox"),
    ("POST", "/v1/machine/device"),
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
    let devices: Vec<Value> = hub.with_table(|table, now| table.devices(now)).iter().filter(|device| device.ws.iter().any(|ws| wanted.contains(ws))).map(device_json).collect();
    Ok((200, json!({"devices": devices, "missing": missing.iter().map(|id| util::hex(id)).collect::<Vec<_>>()})))
}

/// A machine posts a request's record.
fn post_request(hub: &Hub, caller: &Caller, body: &[u8]) -> Result<(u16, Value), Refused> {
    let (record, bytes) = relay::record_body(body)?;
    locked(&hub.relay).post(&caller.name, record, bytes, hub.now())?;
    Ok((200, json!({})))
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
    let (machine, ws, runs, signature) = relay::stop_body(body)?;
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
    Ok((200, json!({})))
}
