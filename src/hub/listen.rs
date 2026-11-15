//! The hub's listener: TLS 1.3 over TCP, one HTTP/1.1 request per connection, with the limits
//! `wire` states. A thread serves each connection; there are never more than `CONNECTIONS` of them.

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value, json};

use super::table::Caller;
use super::wire::{self, Kind, Refused};
use super::{Hub, locked, random};
use crate::door::http;

/// The longest request head.
pub const HEAD_MAX: usize = 8 * 1024;
/// The longest request body.
pub const BODY_MAX: usize = 4 * 1024;
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
        let mut reader = BufReader::new((&mut stream).take((HEAD_MAX + BODY_MAX + 1024) as u64));
        match http::read_head(&mut reader) {
            Ok(Some(head)) if head_len(&head) <= HEAD_MAX && head.parts().is_some() => match http::read_body(&mut reader, &head, BODY_MAX) {
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
const PATHS: [(&str, &str); 5] = [("POST", "/v1/pair"), ("POST", "/v1/join"), ("GET", "/v1/me"), ("POST", "/v1/renew/nonce"), ("POST", "/v1/renew")];

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
        _ => renew(hub, &caller, body),
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
        }),
    ))
}

fn nonce(hub: &Hub, caller: &Caller, body: &[u8]) -> Result<(u16, Value), Refused> {
    wire::no_body(body)?;
    if caller.kind != Kind::Device {
        return Err(Refused::WrongKind);
    }
    let (nonce, until) = hub.with_table(|table, now| table.nonce(caller, &hub.nonce_key, random(), now))?;
    Ok((200, json!({"nonce": wire::hex(&nonce), "expires": wire::time(until)})))
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
