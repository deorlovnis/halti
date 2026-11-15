//! A hub in this process for tests outside this module: behind a loopback proxy, so it can be made
//! unreachable and restarted at the same address, with a clock the tests move, and a phone that
//! speaks its wire as the app would.

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData, SigningKey};
use serde_json::{Value, json};

pub use super::admin::Outcome;
use super::admin::{self, Request};
use super::listen::{self, Limits};
use super::table::Listed;
use super::wire::{self, Invite, Kind};
use super::*;
use crate::requests::RunId;

/// The tests' clock: real time when it starts, then moved only when told.
pub struct Hands(Mutex<Timestamp>);

impl Clock for Hands {
    fn now(&self) -> Timestamp {
        *locked(&self.0)
    }
}

/// Forwards connections to the hub it points at, or closes them at once when it points nowhere.
/// Each connection is held until both its directions end, so a restart can cut those still open.
struct Proxy {
    address: String,
    target: Arc<Mutex<Option<String>>>,
    open: Arc<Mutex<HashMap<u64, [TcpStream; 2]>>>,
    /// How each new connection goes: held this long before it is forwarded, and whether the hub's
    /// reply is lost.
    how: Arc<Mutex<(Duration, bool)>>,
}

impl Proxy {
    fn new() -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let target: Arc<Mutex<Option<String>>> = Arc::default();
        let open: Arc<Mutex<HashMap<u64, [TcpStream; 2]>>> = Arc::default();
        let how: Arc<Mutex<(Duration, bool)>> = Arc::default();
        let (to, held, going) = (target.clone(), open.clone(), how.clone());
        thread::spawn(move || {
            for (n, client) in listener.incoming().flatten().enumerate() {
                let Some(target) = locked(&to).clone() else { continue };
                let (wait, lose) = *locked(&going);
                let Ok(upstream) = TcpStream::connect(&target) else { continue };
                let (Ok(client_in), Ok(upstream_out), Ok(client_out), Ok(upstream_in)) = (client.try_clone(), upstream.try_clone(), client.try_clone(), upstream.try_clone())
                else {
                    continue;
                };
                let id = n as u64;
                locked(&held).insert(id, [client, upstream]);
                let held = held.clone();
                thread::spawn(move || {
                    thread::sleep(wait);
                    if lose {
                        let cut = Arc::new(AtomicBool::new(false));
                        let cutting = cut.clone();
                        let back = thread::spawn(move || copy_until(upstream_in, client_out, &cut));
                        copy_cutting(client_in, upstream_out, &cutting);
                        let _ = back.join();
                    } else {
                        let back = thread::spawn(move || copy(upstream_in, client_out));
                        copy(client_in, upstream_out);
                        let _ = back.join();
                    }
                    locked(&held).remove(&id);
                });
            }
        });
        Proxy { address, target, open, how }
    }

    /// Points it at `target`, or nowhere; every connection open through it is cut.
    fn point(&self, target: Option<String>) {
        *locked(&self.target) = target;
        for [client, upstream] in locked(&self.open).values() {
            let _ = client.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
        }
    }
}

/// Copies one direction until it ends, then ends it at the other side.
fn copy(mut from: TcpStream, mut into: TcpStream) {
    let _ = io::copy(&mut from, &mut into);
    let _ = into.shutdown(Shutdown::Write);
}

/// Copies the client's side to the hub one TLS record at a time, and sets `cut` just before the
/// client's second application-data record goes on: the first is its handshake's Finished, the
/// second its request. The hub reads the whole request.
fn copy_cutting(mut from: TcpStream, mut into: TcpStream, cut: &AtomicBool) {
    let (mut pending, mut buf, mut seen) = (Vec::new(), [0u8; 16 * 1024], 0);
    while let Ok(n @ 1..) = from.read(&mut buf) {
        pending.extend_from_slice(&buf[..n]);
        while pending.len() >= 5 {
            let len = 5 + usize::from(u16::from_be_bytes([pending[3], pending[4]]));
            if pending.len() < len {
                break;
            }
            if pending[0] == 0x17 {
                seen += 1;
                if seen == 2 {
                    cut.store(true, Ordering::SeqCst);
                }
            }
            if into.write_all(&pending.drain(..len).collect::<Vec<_>>()).is_err() {
                return;
            }
        }
    }
    let _ = into.shutdown(Shutdown::Write);
}

/// Copies the hub's side to the client until `cut`; from then on the client is cut off and what
/// the hub sends is dropped: its reply is lost.
fn copy_until(mut from: TcpStream, mut into: TcpStream, cut: &AtomicBool) {
    let mut buf = [0u8; 16 * 1024];
    while let Ok(n @ 1..) = from.read(&mut buf) {
        if cut.load(Ordering::SeqCst) {
            let _ = into.shutdown(Shutdown::Both);
        } else if into.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = into.shutdown(Shutdown::Write);
}

/// A hub in this process.
pub struct TestHub {
    pub folder: PathBuf,
    /// Where clients reach it: the proxy.
    pub address: String,
    pub pin: [u8; 32],
    pub clock: Arc<Hands>,
    proxy: Proxy,
    /// The admin socket of the hub that runs now, and where it listens.
    admin: Mutex<PathBuf>,
    target: Mutex<Option<String>>,
    starts: Mutex<u32>,
    inbox_wait: Duration,
}

impl TestHub {
    /// A hub whose files are in `folder`, whose calls from machines wait `inbox_wait` at most.
    pub fn start(folder: &Path, inbox_wait: Duration) -> TestHub {
        let key = tls_key(folder).unwrap();
        let hub = TestHub {
            folder: folder.to_path_buf(),
            address: String::new(),
            pin: pin_of(&key),
            clock: Arc::new(Hands(Mutex::new(Timestamp::from_second(Timestamp::now().as_second()).unwrap()))),
            proxy: Proxy::new(),
            admin: Mutex::default(),
            target: Mutex::default(),
            starts: Mutex::new(0),
            inbox_wait,
        };
        let hub = TestHub { address: hub.proxy.address.clone(), ..hub };
        hub.restart();
        hub
    }

    /// Starts a new hub process, as it were, on the same files: what it held in memory is gone.
    /// The one before stays unreachable.
    pub fn restart(&self) {
        let key = tls_key(&self.folder).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let mut hub = Hub::open(&self.folder, &self.address, pin_of(&key), self.clock.clone()).unwrap();
        hub.inbox_wait = self.inbox_wait;
        let hub = Arc::new(hub);
        let mut starts = locked(&self.starts);
        *starts += 1;
        let socket = self.folder.join(format!("admin-{starts}.sock"));
        let admin_listener = crate::keep::bind(&socket).unwrap().unwrap();
        *locked(&self.admin) = socket;
        let (for_admin, for_listener) = (hub.clone(), hub);
        thread::spawn(move || admin::serve(for_admin, admin_listener));
        let config = server_config(&key).unwrap();
        thread::spawn(move || listen::run(for_listener, listener, config, Limits { request_wait: Duration::from_secs(5), ..Limits::HUB }));
        *locked(&self.target) = Some(target.clone());
        self.proxy.point(Some(target));
    }

    /// Loses the hub's reply to every call made from now on, once the hub has read the call, or
    /// stops losing them.
    pub fn lose_replies(&self, lose: bool) {
        locked(&self.proxy.how).1 = lose;
    }

    /// Holds every connection made from now on this long before it is forwarded.
    pub fn delay(&self, wait: Duration) {
        locked(&self.proxy.how).0 = wait;
    }

    /// Makes the hub unreachable, or the same hub reachable again.
    pub fn reachable(&self, up: bool) {
        let target = if up { locked(&self.target).clone() } else { None };
        self.proxy.point(target);
    }

    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    pub fn advance(&self, by: SignedDuration) {
        *locked(&self.clock.0) += by;
    }

    fn admin(&self) -> PathBuf {
        locked(&self.admin).clone()
    }

    pub fn rows(&self) -> Vec<Listed> {
        admin::list_at(&self.admin()).unwrap()
    }

    pub fn revoke(&self, name: &str) -> bool {
        admin::revoke_at(&self.admin(), name).unwrap()
    }

    /// Pairs machine `name`: `join` gets the pairing string, as `halti hub join` would, and the
    /// person at the hub says yes once it said it joined.
    pub fn pair_machine(&self, name: &str, join: impl FnOnce(&str) -> anyhow::Result<()> + Send) -> Outcome {
        let request = Request::Pair { kind: Kind::Machine, name: name.into(), ws: Vec::new() };
        let joined = Mutex::new(None);
        let said = &joined;
        thread::scope(|scope| {
            let (sent, got) = std::sync::mpsc::channel::<String>();
            let joining = scope.spawn(move || {
                let line = got.recv_timeout(Duration::from_secs(10)).unwrap();
                *locked(said) = Some(join(&line).is_ok());
            });
            let outcome = admin::pair_at(&self.admin(), &request, |invite| sent.send(invite.to_string()).unwrap(), |_| Ok(true)).unwrap();
            joining.join().unwrap();
            assert_eq!(*locked(&joined), Some(true), "the join failed");
            outcome
        })
    }

    /// Pairs a new phone `name` for workspaces `ws`, the person saying yes.
    pub fn pair_phone(&self, name: &str, ws: &[&str]) -> Phone {
        let phone = Phone::new(name);
        let request = Request::Pair { kind: Kind::Device, name: name.into(), ws: ws.iter().map(|w| halti_core::ids::WsName::parse(w).unwrap()).collect() };
        let claimer = &phone;
        let outcome = thread::scope(|scope| {
            let (sent, got) = std::sync::mpsc::channel::<Invite>();
            let claiming = scope.spawn(move || {
                let invite = got.recv_timeout(Duration::from_secs(10)).unwrap();
                let (status, body) = self.call("POST", "/v1/pair", None, Some(&claimer.pair_body(&invite)));
                assert_eq!(status, 202, "{body}");
            });
            let outcome = admin::pair_at(&self.admin(), &request, |invite| sent.send(invite.clone()).unwrap(), |_| Ok(true)).unwrap();
            claiming.join().unwrap();
            outcome
        });
        assert_eq!(outcome, Outcome::Paired);
        phone
    }

    /// One call, its status and body.
    pub fn call(&self, method: &str, path: &str, token: Option<&str>, body: Option<&Value>) -> (u16, Value) {
        pin::request(&self.address, self.pin, method, path, token, body, Duration::from_secs(30)).unwrap()
    }
}

/// A phone: its two keys and its token, as the app makes them.
pub struct Phone {
    pub name: String,
    signing: KeyPair,
    agreement: KeyPair,
    pub token: String,
}

impl Phone {
    pub fn new(name: &str) -> Phone {
        let key = || KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        Phone { name: name.into(), signing: key(), agreement: key(), token: format!("{}{}", Kind::Device.prefix(), util::hex(&util::random::<32>())) }
    }

    pub fn signing_key(&self) -> Vec<u8> {
        self.signing.subject_public_key_info()
    }

    pub fn agreement_key(&self) -> Vec<u8> {
        self.agreement.subject_public_key_info()
    }

    pub fn fingerprint(&self) -> String {
        wire::fingerprint(&self.signing_key())
    }

    /// A signature by its signing key, after a fingerprint, as it were.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing.sign(message).unwrap()
    }

    fn pair_body(&self, invite: &Invite) -> Value {
        let (signing, agreement) = (self.signing_key(), self.agreement.subject_public_key_info());
        let request = wire::PairRequest {
            code: invite.code,
            key_signature: self.sign(&wire::keys_bytes(&signing, &agreement)),
            signing_key: signing,
            agreement_key: agreement,
            token_hash: wire::token_hash(&self.token),
            push: String::new(),
        };
        let signature = self.sign(&wire::pair_bytes(&invite.pin, &request));
        json!({
            "code": util::hex(&request.code),
            "signing_key": util::hex(&request.signing_key),
            "agreement_key": util::hex(&request.agreement_key),
            "key_signature": util::hex(&request.key_signature),
            "token_hash": util::hex(&request.token_hash),
            "push": request.push,
            "signature": util::hex(&signature),
        })
    }

    /// The requests it is shown: each machine's name and record.
    pub fn requests(&self, hub: &TestHub) -> Vec<(String, Vec<u8>)> {
        let (status, body) = hub.call("GET", "/v1/requests", Some(&self.token), None);
        assert_eq!(status, 200, "{body}");
        body["requests"].as_array().unwrap().iter().map(|r| (r["machine"].as_str().unwrap().to_string(), util::unhex(r["record"].as_str().unwrap()).unwrap())).collect()
    }

    /// What it is shown of the machines that trust it, and what it sent.
    pub fn state(&self, hub: &TestHub) -> Value {
        let (status, body) = hub.call("GET", "/v1/state", Some(&self.token), None);
        assert_eq!(status, 200, "{body}");
        body
    }

    /// Answers the request whose record is `record` on `machine`, signing with `signer`'s key.
    pub fn answer_signed_by(&self, signer: &Phone, hub: &TestHub, machine: &str, record: &[u8], yes: bool) -> (u16, Value) {
        let id = &crate::requests::Record::decode(record).unwrap().id;
        let signature = signer.sign(&crate::requests::answer_bytes(record, yes));
        let body = json!({"machine": machine, "id": id.hex(), "decision": if yes { "yes" } else { "no" }, "signature": util::hex(&signature)});
        hub.call("POST", "/v1/answer", Some(&self.token), Some(&body))
    }

    pub fn answer(&self, hub: &TestHub, machine: &str, record: &[u8], yes: bool) -> (u16, Value) {
        self.answer_signed_by(self, hub, machine, record, yes)
    }

    /// Stops these runs of `ws` on `machine`, each named with its box.
    pub fn stop(&self, hub: &TestHub, machine: &str, ws: &str, runs: &[(&str, RunId)]) -> (u16, Value) {
        let runs: Vec<(String, RunId)> = runs.iter().map(|(name, run)| (name.to_string(), *run)).collect();
        let signature = self.sign(&wire::stop_bytes(machine, ws, &runs));
        let listed: Vec<Value> = runs.iter().map(|(name, run)| json!({"box": name, "run": run.hex()})).collect();
        let body = json!({"machine": machine, "ws": ws, "runs": listed, "signature": util::hex(&signature)});
        hub.call("POST", "/v1/stop", Some(&self.token), Some(&body))
    }
}

/// A hub that answers each path as it is told, whatever is sent, and keeps every body sent: what a
/// broken hub could do, behind the pin it gave. A path it wasn't told of is `404 not-found`. A
/// machine's inbox call waits a moment before its answer, as the real one waits.
pub struct FakeHub {
    pub address: String,
    pub pin: [u8; 32],
    replies: Arc<Mutex<HashMap<String, (u16, String)>>>,
    sent: Arc<Mutex<Vec<(String, Value)>>>,
}

impl FakeHub {
    pub fn start(folder: &Path) -> FakeHub {
        let key = tls_key(folder).unwrap();
        let config = server_config(&key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let hub = FakeHub { address: listener.local_addr().unwrap().to_string(), pin: pin_of(&key), replies: Arc::default(), sent: Arc::default() };
        let (replies, sent) = (hub.replies.clone(), hub.sent.clone());
        thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let (config, replies, sent) = (config.clone(), replies.clone(), sent.clone());
                thread::spawn(move || {
                    let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), tcp);
                    let mut reader = BufReader::new(&mut stream);
                    let Ok(Some(head)) = crate::door::http::read_head(&mut reader) else { return };
                    let Ok(body) = crate::door::http::read_body(&mut reader, &head, 1 << 16) else { return };
                    let Some((_, path, _)) = head.parts() else { return };
                    let path = path.to_string();
                    locked(&sent).push((path.clone(), serde_json::from_slice(&body).unwrap_or(Value::Null)));
                    let (status, body) = locked(&replies).get(&path).cloned().unwrap_or((404, r#"{"error": "not-found"}"#.to_string()));
                    if path == "/v1/machine/inbox" {
                        thread::sleep(Duration::from_millis(100));
                    }
                    let reply = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = stream.write_all(reply.as_bytes());
                    stream.conn.send_close_notify();
                    let _ = stream.flush();
                });
            }
        });
        hub
    }

    /// Answers `path` with `status` and `body` from now on.
    pub fn answer(&self, path: &str, status: u16, body: &str) {
        locked(&self.replies).insert(path.to_string(), (status, body.to_string()));
    }

    /// The bodies sent to `path` so far, oldest first.
    pub fn sent(&self, path: &str) -> Vec<Value> {
        locked(&self.sent).iter().filter(|(to, _)| to == path).map(|(_, body)| body.clone()).collect()
    }
}
