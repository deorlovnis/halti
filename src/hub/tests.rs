//! A hub in this process, on a loopback port, with a clock the tests move, and a client that speaks
//! its wire as a phone or a machine would: TLS pinned, then one request per connection.

use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData, SigningKey};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde_json::{Value, json};

use super::admin::{self, Outcome, Request};
use super::listen::{self, Limits};
use super::table::{Listed, TokenState};
use super::wire::{self, Invite, Kind};
use super::*;
use crate::door::http;
use crate::util::{TempDir, random};

/// The tests' clock: it moves only when told.
struct Hands(Mutex<Timestamp>);

impl Clock for Hands {
    fn now(&self) -> Timestamp {
        *locked(&self.0)
    }
}

const START: &str = "2026-11-15T10:00:00Z";
const DAY: SignedDuration = SignedDuration::from_hours(24);

/// A hub on a loopback port, its folder, and the hands on its clock.
struct Running {
    _dir: TempDir,
    folder: PathBuf,
    address: String,
    pin: [u8; 32],
    clock: Arc<Hands>,
}

fn start() -> Running {
    start_with(Limits { request_wait: Duration::from_secs(5), ..Limits::HUB })
}

fn start_with(limits: Limits) -> Running {
    let dir = TempDir::new("halti-hub").unwrap();
    start_in(dir, limits, Arc::new(Hands(Mutex::new(START.parse().unwrap()))))
}

fn start_in(dir: TempDir, limits: Limits, clock: Arc<Hands>) -> Running {
    let folder = dir.0.clone();
    let key = tls_key(&folder).unwrap();
    let pin = pin_of(&key);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let mut hub = Hub::open(&folder, &address, pin, clock.clone()).unwrap();
    hub.inbox_wait = INBOX_WAIT;
    let hub = Arc::new(hub);
    let admin_socket = crate::keep::bind(&folder.join("admin.sock")).unwrap().unwrap();
    let (for_admin, for_listener) = (hub.clone(), hub.clone());
    thread::spawn(move || admin::serve(for_admin, admin_socket));
    let config = server_config(&key).unwrap();
    thread::spawn(move || listen::run(for_listener, listener, config, limits));
    Running { _dir: dir, folder, address, pin, clock }
}

impl Running {
    fn socket(&self) -> PathBuf {
        self.folder.join("admin.sock")
    }

    fn advance(&self, by: SignedDuration) {
        let mut now = locked(&self.clock.0);
        *now += by;
    }

    /// Moves the clock to this long after `START`.
    fn at(&self, since_start: SignedDuration) {
        *locked(&self.clock.0) = START.parse::<Timestamp>().unwrap() + since_start;
    }

    /// One request, and its reply's status and body.
    fn call(&self, method: &str, path: &str, token: Option<&str>, body: Option<&Value>) -> (u16, Value) {
        let body = body.map(Value::to_string).unwrap_or_default();
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: halti-hub\r\nContent-Length: {}\r\n", body.len());
        if let Some(token) = token {
            head.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        head.push_str("\r\n");
        self.raw(&[head.as_bytes(), body.as_bytes()].concat()).expect("a reply")
    }

    /// Sends these bytes after the handshake; the reply, or None if the hub closed with none.
    fn raw(&self, request: &[u8]) -> Option<(u16, Value)> {
        let mut stream = pin::connect(&self.address, self.pin, Duration::from_secs(10)).unwrap();
        stream.write_all(request).unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        let head = http::read_head(&mut reader).ok()??;
        assert_eq!(head.header("connection"), Some("close"));
        assert_eq!(head.header("content-type"), Some("application/json"));
        assert_eq!(head.header("cache-control"), Some("no-store"));
        let body = http::read_body(&mut reader, &head, 1 << 20).unwrap();
        Some((head.status().unwrap(), serde_json::from_slice(&body).unwrap()))
    }

    fn list(&self) -> Vec<Listed> {
        admin::list_at(&self.socket()).unwrap()
    }

    fn row(&self, name: &str) -> Listed {
        self.list().into_iter().find(|row| row.name == name).unwrap()
    }
}

/// A phone: its two keys and its token, as the app makes them.
struct Phone {
    signing: KeyPair,
    agreement: KeyPair,
    token: String,
}

fn token(kind: Kind) -> String {
    format!("{}{}", kind.prefix(), util::hex(&random::<32>()))
}

impl Phone {
    fn new() -> Phone {
        let key = || KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        Phone { signing: key(), agreement: key(), token: token(Kind::Device) }
    }

    fn signing_key(&self) -> Vec<u8> {
        self.signing.subject_public_key_info()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing.sign(message).unwrap()
    }

    /// The body of `POST /v1/pair` for this code, signed for the hub with this pin.
    fn pair_body(&self, invite: &Invite, push: &str) -> Value {
        let (signing, agreement) = (self.signing_key(), self.agreement.subject_public_key_info());
        let request = wire::PairRequest {
            code: invite.code,
            key_signature: self.sign(&wire::keys_bytes(&signing, &agreement)),
            signing_key: signing,
            agreement_key: agreement,
            token_hash: wire::token_hash(&self.token),
            push: push.to_string(),
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
}

/// A machine: its key and its token, as `halti hub join` will make them.
struct Machine {
    key: KeyPair,
    token: String,
}

impl Machine {
    fn new() -> Machine {
        Machine { key: KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(), token: token(Kind::Machine) }
    }

    fn join_body(&self, invite: &Invite) -> Value {
        json!({"code": util::hex(&invite.code), "machine_key": util::hex(&self.key.subject_public_key_info()), "token_hash": util::hex(&wire::token_hash(&self.token))})
    }
}

/// A `halti pair` running in a thread, as the person at the hub's terminal: it hands over the
/// pairing string, then the fingerprint once claimed, and answers as it is told.
struct Pairing {
    invite: Invite,
    fingerprint: mpsc::Receiver<Option<String>>,
    answer: mpsc::Sender<bool>,
    done: thread::JoinHandle<anyhow::Result<Outcome>>,
}

fn begin(hub: &Running, request: Request) -> Result<Pairing, Outcome> {
    let (invite_tx, invite_rx) = mpsc::channel();
    let (fingerprint_tx, fingerprint) = mpsc::channel();
    let (answer, answer_rx) = mpsc::channel::<bool>();
    let socket = hub.socket();
    let done = thread::spawn(move || {
        admin::pair_at(
            &socket,
            &request,
            |invite| invite_tx.send(invite.clone()).unwrap(),
            |seen| {
                fingerprint_tx.send(seen.map(str::to_string)).unwrap();
                Ok(answer_rx.recv_timeout(Duration::from_secs(30)).unwrap_or(false))
            },
        )
    });
    match invite_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(invite) => Ok(Pairing { invite, fingerprint, answer, done }),
        Err(_) => Err(done.join().unwrap().unwrap()),
    }
}

impl Pairing {
    /// The fingerprint `halti pair` shows once the code is claimed (none for a machine).
    fn claimed(&self) -> Option<String> {
        self.fingerprint.recv_timeout(Duration::from_secs(10)).expect("the pairing is claimed")
    }

    fn answer(self, yes: bool) -> Outcome {
        self.answer.send(yes).unwrap();
        self.done.join().unwrap().unwrap()
    }
}

fn device(name: &str, ws: &[&str]) -> Request {
    Request::Pair { kind: Kind::Device, name: name.into(), ws: ws.iter().map(|w| halti_core::ids::WsName::parse(w).unwrap()).collect() }
}

fn machine(name: &str) -> Request {
    Request::Pair { kind: Kind::Machine, name: name.into(), ws: Vec::new() }
}

/// Pairs a new phone, the person saying yes.
fn paired_phone(hub: &Running, name: &str) -> Phone {
    let phone = Phone::new();
    let pairing = begin(hub, device(name, &["acme"])).unwrap();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&phone.pair_body(&pairing.invite, ""))).0, 202);
    pairing.claimed();
    assert_eq!(pairing.answer(true), Outcome::Paired);
    phone
}

/// Pairs a new machine, the person saying yes.
fn paired_machine(hub: &Running, name: &str) -> Machine {
    let machine_ = Machine::new();
    let pairing = begin(hub, machine(name)).unwrap();
    assert_eq!(hub.call("POST", "/v1/join", None, Some(&machine_.join_body(&pairing.invite))).0, 202);
    assert_eq!(pairing.claimed(), None);
    assert_eq!(pairing.answer(true), Outcome::Paired);
    machine_
}

fn error(word: &str) -> Value {
    json!({"error": word})
}

/// A phone's renewal: a nonce, then the signed request for a new token. The new token, and the
/// renewal's status and body.
fn renew_phone(hub: &Running, phone: &Phone) -> (String, u16, Value) {
    let (status, body) = hub.call("POST", "/v1/renew/nonce", Some(&phone.token), None);
    if status != 200 {
        return (String::new(), status, body);
    }
    let nonce: [u8; 16] = wire::unhex(body["nonce"].as_str().unwrap()).unwrap();
    let new = token(Kind::Device);
    let hash = wire::token_hash(&new);
    let signature = phone.sign(&wire::renew_bytes(&hub.pin, "pixel", &nonce, &hash));
    let body = json!({"nonce": util::hex(&nonce), "token_hash": util::hex(&hash), "signature": util::hex(&signature)});
    let (status, body) = hub.call("POST", "/v1/renew", Some(&phone.token), Some(&body));
    (new, status, body)
}

fn renew_machine(hub: &Running, token_: &str) -> (String, u16, Value) {
    let new = token(Kind::Machine);
    let (status, body) = hub.call("POST", "/v1/renew", Some(token_), Some(&json!({"token_hash": util::hex(&wire::token_hash(&new))})));
    (new, status, body)
}

fn time(since_start: SignedDuration) -> String {
    wire::time(START.parse::<Timestamp>().unwrap() + since_start)
}

// --- pairing ---

#[test]
fn a_phone_is_paired_once_the_terminal_says_yes() {
    let hub = start();
    let phone = Phone::new();
    let pairing = begin(&hub, device("pixel", &["acme", "beta"])).unwrap();
    assert_eq!((pairing.invite.kind, &pairing.invite.address, pairing.invite.pin), (Kind::Device, &hub.address, hub.pin));
    let (status, body) = hub.call("POST", "/v1/pair", None, Some(&phone.pair_body(&pairing.invite, "fcm:abc")));
    assert_eq!((status, body), (202, json!({"name": "pixel", "ws": ["acme", "beta"]})));
    // The terminal shows the phone's own fingerprint; until y or N there, the token waits.
    assert_eq!(pairing.claimed(), Some(wire::fingerprint(&phone.signing_key())));
    assert_eq!(hub.call("GET", "/v1/me", Some(&phone.token), None), (401, error("pending")));
    assert_eq!(pairing.answer(true), Outcome::Paired);
    let (status, me) = hub.call("GET", "/v1/me", Some(&phone.token), None);
    assert_eq!(status, 200);
    assert_eq!(
        me,
        json!({
            "kind": "device", "name": "pixel", "ws": ["acme", "beta"], "issued": START, "expires": time(30 * DAY),
            "renew_from": START, "renewable_until": time(90 * DAY), "conflict": null, "now": START,
        })
    );
    let row = hub.row("pixel");
    assert_eq!((row.kind, row.ws.clone(), row.fingerprint.clone()), (Kind::Device, vec!["acme".to_string(), "beta".to_string()], Some(wire::fingerprint(&phone.signing_key()))));
    assert_eq!((row.token, row.last_seen, row.conflict_since), (TokenState::Left { days: 30 }, Some(START.parse().unwrap()), None));
    assert_eq!(row.push_changed, Some(START.parse().unwrap()));
}

#[test]
fn a_phone_the_terminal_says_no_to_is_not_paired() {
    let hub = start();
    let phone = Phone::new();
    let pairing = begin(&hub, device("pixel", &["acme"])).unwrap();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&phone.pair_body(&pairing.invite, ""))).0, 202);
    pairing.claimed();
    assert_eq!(pairing.answer(false), Outcome::Refused);
    assert_eq!(hub.call("GET", "/v1/me", Some(&phone.token), None), (401, error("unknown")));
    assert!(hub.list().is_empty());
    // The name is free again.
    paired_phone(&hub, "pixel");
}

#[test]
fn a_code_works_once_for_its_two_minutes_and_its_kind() {
    let hub = start();
    let (first, second) = (Phone::new(), Phone::new());
    let pairing = begin(&hub, device("pixel", &["acme"])).unwrap();
    // Another code, and the right code at a machine's endpoint, are refused.
    let mut wrong = pairing.invite.clone();
    wrong.code[0] ^= 1;
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&first.pair_body(&wrong, ""))), (403, error("bad-code")));
    assert_eq!(hub.call("POST", "/v1/join", None, Some(&Machine::new().join_body(&pairing.invite))), (403, error("bad-code")));
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&first.pair_body(&pairing.invite, ""))).0, 202);
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&second.pair_body(&pairing.invite, ""))), (403, error("bad-code")));
    pairing.claimed();
    let used = pairing.invite.clone();
    assert_eq!(pairing.answer(true), Outcome::Paired);
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&second.pair_body(&used, ""))), (403, error("bad-code")));

    // Unused for two minutes, a code is over, and `halti pair` says so.
    let late = begin(&hub, device("tablet", &["acme"])).unwrap();
    hub.advance(SignedDuration::from_secs(120));
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&second.pair_body(&late.invite, ""))), (403, error("bad-code")));
    assert_eq!(late.done.join().unwrap().unwrap(), Outcome::Expired);
    assert_eq!(hub.list().len(), 1);
}

#[test]
fn a_name_is_taken_by_a_row_or_a_pairing_under_way() {
    let hub = start();
    paired_phone(&hub, "pixel");
    assert_eq!(begin(&hub, device("pixel", &["beta"])).err(), Some(Outcome::Taken));
    assert_eq!(begin(&hub, machine("pixel")).err(), Some(Outcome::Taken));
    // A pairing under way is no row: it is told apart, since devices and revoke don't know it.
    let under_way = begin(&hub, machine("server-1")).unwrap();
    assert_eq!(begin(&hub, device("server-1", &["acme"])).err(), Some(Outcome::Busy));
    assert_eq!(begin(&hub, machine("server-1")).err(), Some(Outcome::Busy));
    assert!(!hub.list().iter().any(|row| row.name == "server-1"));
    assert!(!admin::revoke_at(&hub.socket(), "server-1").unwrap());
    drop(under_way);
}

#[test]
fn a_pairing_ends_when_its_terminal_goes() {
    let hub = start();
    let mut stream = crate::keep::connect(&hub.socket()).unwrap();
    crate::keep::write_line(&mut stream, &device("pixel", &["acme"]).line()).unwrap();
    let line = crate::keep::read_line_up_to(&mut stream, Duration::from_secs(5), 4096).unwrap();
    let invite = Invite::parse(line.strip_prefix("halti-hub/1 code ").unwrap()).unwrap();
    drop(stream);
    thread::sleep(Duration::from_millis(600));
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&Phone::new().pair_body(&invite, ""))), (403, error("bad-code")));
    // And the name is free.
    paired_phone(&hub, "pixel");
}

#[test]
fn a_pairing_request_with_a_bad_signature_is_refused() {
    let hub = start();
    let phone = Phone::new();
    let pairing = begin(&hub, device("pixel", &["acme"])).unwrap();
    // Signed for another hub's pin.
    let mut other = pairing.invite.clone();
    other.pin[0] ^= 1;
    let mut body = phone.pair_body(&other, "");
    body["code"] = util::hex(&pairing.invite.code).into();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&body)), (403, error("bad-signature")));
    // A push address changed after signing.
    let mut body = phone.pair_body(&pairing.invite, "fcm:abc");
    body["push"] = "fcm:other".into();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&body)), (403, error("bad-signature")));
    // The agreement key vouched for by another key.
    let mut body = phone.pair_body(&pairing.invite, "");
    let stranger = Phone::new();
    body["key_signature"] = util::hex(&stranger.sign(&wire::keys_bytes(&phone.signing_key(), &phone.agreement.subject_public_key_info()))).into();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&body)), (403, error("bad-signature")));
    // A key that isn't one.
    let mut body = phone.pair_body(&pairing.invite, "");
    body["signing_key"] = util::hex(&[0u8; 91]).into();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&body)), (400, error("malformed")));
    // None of these used the code: the right request still pairs.
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&phone.pair_body(&pairing.invite, ""))).0, 202);
    pairing.claimed();
    assert_eq!(pairing.answer(true), Outcome::Paired);
}

#[test]
fn a_machine_is_paired_and_its_token_works() {
    let hub = start();
    let machine_ = Machine::new();
    let pairing = begin(&hub, machine("server-1")).unwrap();
    assert_eq!(pairing.invite.kind, Kind::Machine);
    assert_eq!(hub.call("POST", "/v1/join", None, Some(&machine_.join_body(&pairing.invite))), (202, json!({"name": "server-1"})));
    assert_eq!(pairing.claimed(), None);
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None), (401, error("pending")));
    assert_eq!(pairing.answer(true), Outcome::Paired);
    let (status, me) = hub.call("GET", "/v1/me", Some(&machine_.token), None);
    assert_eq!((status, &me["kind"], &me["ws"], &me["renew_from"], &me["renewable_until"]), (200, &json!("machine"), &json!([]), &json!(time(10 * DAY)), &json!(time(30 * DAY))));
    let row = hub.row("server-1");
    assert_eq!((row.kind, row.fingerprint, row.token), (Kind::Machine, None, TokenState::Left { days: 30 }));
    // A machine's token at a phone's call.
    assert_eq!(hub.call("POST", "/v1/renew/nonce", Some(&machine_.token), None), (403, error("wrong-kind")));
}

#[test]
fn a_token_whose_prefix_lies_is_unknown() {
    let hub = start();
    // A phone that registered the hash of a machine-looking token gets nothing for it.
    let mut phone = Phone::new();
    phone.token = token(Kind::Machine);
    let pairing = begin(&hub, device("pixel", &["acme"])).unwrap();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&phone.pair_body(&pairing.invite, ""))).0, 202);
    pairing.claimed();
    assert_eq!(pairing.answer(true), Outcome::Paired);
    assert_eq!(hub.call("GET", "/v1/me", Some(&phone.token), None), (401, error("unknown")));
}

// --- revoke ---

#[test]
fn a_revoked_token_stops_at_once() {
    let hub = start();
    let phone = paired_phone(&hub, "pixel");
    let machine_ = paired_machine(&hub, "server-1");
    assert_eq!(hub.call("GET", "/v1/me", Some(&phone.token), None).0, 200);
    assert!(admin::revoke_at(&hub.socket(), "pixel").unwrap());
    assert_eq!(hub.call("GET", "/v1/me", Some(&phone.token), None), (401, error("unknown")));
    assert_eq!(hub.call("POST", "/v1/renew/nonce", Some(&phone.token), None), (401, error("unknown")));
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None).0, 200, "the others are untouched");
    assert!(!admin::revoke_at(&hub.socket(), "pixel").unwrap());
    assert_eq!(hub.list().iter().map(|row| row.name.as_str()).collect::<Vec<_>>(), ["server-1"]);
}

// --- a phone's renewal ---

#[test]
fn a_phone_renews_on_any_day_until_day_90() {
    for day in 0..90 {
        let hub = start();
        let phone = paired_phone(&hub, "pixel");
        hub.at(day * DAY + SignedDuration::from_secs(3600));
        let me = hub.call("GET", "/v1/me", Some(&phone.token), None);
        if day < 30 {
            assert_eq!(me.0, 200, "day {day}");
        } else {
            assert_eq!(me, (401, json!({"error": "expired", "renewable_until": time(90 * DAY)})), "day {day}");
        }
        let (new, status, body) = renew_phone(&hub, &phone);
        assert_eq!((status, body), (200, json!({"expires": time(day * DAY + SignedDuration::from_secs(3600) + 30 * DAY)})), "day {day}");
        let (status, me) = hub.call("GET", "/v1/me", Some(&new), None);
        assert_eq!((status, &me["issued"]), (200, &json!(time(day * DAY + SignedDuration::from_secs(3600)))), "day {day}");
        assert_eq!(hub.row("pixel").token, TokenState::Left { days: 30 });
    }
}

#[test]
fn a_phone_not_renewed_by_day_90_is_deleted() {
    let hub = start();
    let phone = paired_phone(&hub, "pixel");
    hub.at(90 * DAY - SignedDuration::from_secs(1));
    assert_eq!(hub.row("pixel").token, TokenState::Renewable { until: START.parse::<Timestamp>().unwrap() + 90 * DAY });
    assert_eq!(
        admin::token_text(&hub.row("pixel")),
        format!("token: expired, renewable until {}", (START.parse::<Timestamp>().unwrap() + 90 * DAY).to_zoned(jiff::tz::TimeZone::system()).strftime("%Y-%m-%d"))
    );
    hub.at(90 * DAY);
    assert_eq!(hub.call("POST", "/v1/renew/nonce", Some(&phone.token), None), (401, error("unknown")));
    assert!(hub.list().is_empty());
}

#[test]
fn the_replaced_token_works_until_the_new_one_is_used() {
    let hub = start();
    let mut phone = paired_phone(&hub, "pixel");
    let old = phone.token.clone();
    let (new, status, _) = renew_phone(&hub, &phone);
    assert_eq!(status, 200);
    // The reply may have been lost: the old token still works, but not for a renewal.
    assert_eq!(hub.call("GET", "/v1/me", Some(&old), None).0, 200);
    assert_eq!(hub.call("POST", "/v1/renew/nonce", Some(&old), None), (401, error("replaced")));
    phone.token = new.clone();
    assert_eq!(hub.call("GET", "/v1/me", Some(&new), None).0, 200);
    assert_eq!(hub.call("GET", "/v1/me", Some(&old), None), (401, error("unknown")));

    // Unused, the new token leaves the old one 24 hours.
    let (newer, status, _) = renew_phone(&hub, &phone);
    assert_eq!(status, 200);
    hub.advance(OLD_TOKEN_LEFT);
    assert_eq!(hub.call("GET", "/v1/me", Some(&new), None).0, 200);
    hub.advance(SignedDuration::from_secs(2));
    assert_eq!(hub.call("GET", "/v1/me", Some(&new), None), (401, error("unknown")));
    assert_eq!(hub.call("GET", "/v1/me", Some(&newer), None).0, 200);
}

/// A little under the 24 hours the replaced token keeps.
const OLD_TOKEN_LEFT: SignedDuration = SignedDuration::from_secs(24 * 3600 - 1);

/// Asks for a renewal nonce with this token.
fn ask_nonce(hub: &Running, token_: &str) -> [u8; 16] {
    let (status, body) = hub.call("POST", "/v1/renew/nonce", Some(token_), None);
    assert_eq!(status, 200, "{body}");
    wire::unhex(body["nonce"].as_str().unwrap()).unwrap()
}

/// A phone's renewal with this token, nonce, new token hash and signature.
fn send_renewal(hub: &Running, token_: &str, nonce: &[u8; 16], hash: &[u8; 32], signature: &[u8]) -> (u16, Value) {
    hub.call("POST", "/v1/renew", Some(token_), Some(&json!({"nonce": util::hex(nonce), "token_hash": util::hex(hash), "signature": util::hex(signature)})))
}

#[test]
fn a_nonce_is_good_once_for_two_minutes() {
    let hub = start();
    let mut phone = paired_phone(&hub, "pixel");
    let sign = |phone: &Phone, nonce: &[u8; 16], hash: &[u8; 32]| phone.sign(&wire::renew_bytes(&hub.pin, "pixel", nonce, hash));
    let hash = wire::token_hash(&token(Kind::Device));
    // A nonce the hub never gave, or one it gave with any byte changed.
    assert_eq!(send_renewal(&hub, &phone.token, &[7; 16], &hash, &sign(&phone, &[7; 16], &hash)), (403, error("bad-nonce")));
    let nonce = ask_nonce(&hub, &phone.token);
    for i in [0, 3, 4, 15] {
        let mut other = nonce;
        other[i] ^= 1;
        assert_eq!(send_renewal(&hub, &phone.token, &other, &hash, &sign(&phone, &other, &hash)), (403, error("bad-nonce")), "byte {i}");
    }
    // Too late.
    hub.advance(SignedDuration::from_secs(120));
    assert_eq!(send_renewal(&hub, &phone.token, &nonce, &hash, &sign(&phone, &nonce, &hash)), (403, error("bad-nonce")));
    // Asking again gives another and leaves the first good. A refused renewal leaves its nonce
    // good too, a body that isn't one included.
    let (first, second) = (ask_nonce(&hub, &phone.token), ask_nonce(&hub, &phone.token));
    let no_hash = json!({"nonce": util::hex(&first), "signature": util::hex(&sign(&phone, &first, &hash))});
    assert_eq!(hub.call("POST", "/v1/renew", Some(&phone.token), Some(&no_hash)), (400, error("malformed")));
    assert_eq!(send_renewal(&hub, &phone.token, &first, &hash, &sign(&phone, &first, &[0; 32])), (403, error("bad-signature")));
    let new = token(Kind::Device);
    let new_hash = wire::token_hash(&new);
    assert_eq!(send_renewal(&hub, &phone.token, &first, &new_hash, &sign(&phone, &first, &new_hash)).0, 200);
    phone.token = new;
    // A renewal it made used it up; the second is still good.
    let newer = wire::token_hash(&token(Kind::Device));
    assert_eq!(send_renewal(&hub, &phone.token, &first, &newer, &sign(&phone, &first, &newer)), (403, error("bad-nonce")));
    assert_eq!(send_renewal(&hub, &phone.token, &second, &newer, &sign(&phone, &second, &newer)).0, 200);
}

#[test]
fn a_nonce_is_good_only_for_the_row_it_was_given_to() {
    let hub = start();
    let phone = paired_phone(&hub, "pixel");
    let sign = |nonce: &[u8; 16], hash: &[u8; 32]| phone.sign(&wire::renew_bytes(&hub.pin, "pixel", nonce, hash));
    let hash = wire::token_hash(&token(Kind::Device));
    // Another phone's.
    let tablet = paired_phone(&hub, "tablet");
    let theirs = ask_nonce(&hub, &tablet.token);
    assert_eq!(send_renewal(&hub, &phone.token, &theirs, &hash, &sign(&theirs, &hash)), (403, error("bad-nonce")));
    // One given to this name before it was revoked and paired again.
    let before = ask_nonce(&hub, &phone.token);
    assert!(admin::revoke_at(&hub.socket(), "pixel").unwrap());
    hub.advance(SignedDuration::from_secs(1));
    let again = paired_phone(&hub, "pixel");
    let signed = again.sign(&wire::renew_bytes(&hub.pin, "pixel", &before, &hash));
    assert_eq!(send_renewal(&hub, &again.token, &before, &hash, &signed), (403, error("bad-nonce")));
}

#[test]
fn a_copy_of_a_phone_token_cannot_keep_the_phone_from_renewing() {
    // On a day the token works, and after day 30, when the copy can still ask for nonces.
    for day in [5, 45] {
        let hub = start();
        let phone = paired_phone(&hub, "pixel");
        let copy = phone.token.clone();
        hub.at(day * DAY);
        let nonce = ask_nonce(&hub, &phone.token);
        // While the phone asks for a fingerprint, the copy asks for nonces and sends what it can.
        let stranger = Phone::new();
        for _ in 0..3 {
            let its = ask_nonce(&hub, &copy);
            let hash = wire::token_hash(&token(Kind::Device));
            assert_eq!(send_renewal(&hub, &copy, &its, &hash, &stranger.sign(&wire::renew_bytes(&hub.pin, "pixel", &its, &hash))), (403, error("bad-signature")), "day {day}");
            assert_eq!(send_renewal(&hub, &copy, &nonce, &hash, &stranger.sign(&wire::renew_bytes(&hub.pin, "pixel", &nonce, &hash))), (403, error("bad-signature")), "day {day}");
        }
        let new = token(Kind::Device);
        let hash = wire::token_hash(&new);
        assert_eq!(send_renewal(&hub, &phone.token, &nonce, &hash, &phone.sign(&wire::renew_bytes(&hub.pin, "pixel", &nonce, &hash))).0, 200, "day {day}");
        // Once the phone uses its new token, the copy is worth nothing.
        assert_eq!(hub.call("GET", "/v1/me", Some(&new), None).0, 200, "day {day}");
        assert_eq!(hub.call("POST", "/v1/renew/nonce", Some(&copy), None), (401, error("unknown")), "day {day}");
    }
}

/// Signs a renewal for a nonce, somehow.
type Sign<'a> = Box<dyn Fn(&[u8; 16]) -> Vec<u8> + 'a>;

#[test]
fn a_renewal_with_a_bad_signature_is_refused() {
    let hub = start();
    let phone = paired_phone(&hub, "pixel");
    let stranger = Phone::new();
    let hash = wire::token_hash(&token(Kind::Device));
    let mut other_pin = hub.pin;
    other_pin[31] ^= 1;
    let attempts: [(&str, Sign<'_>); 5] = [
        ("another key", Box::new(|n| stranger.sign(&wire::renew_bytes(&hub.pin, "pixel", n, &hash)))),
        ("another hub", Box::new(|n| phone.sign(&wire::renew_bytes(&other_pin, "pixel", n, &hash)))),
        ("another name", Box::new(|n| phone.sign(&wire::renew_bytes(&hub.pin, "tablet", n, &hash)))),
        ("another token", Box::new(|n| phone.sign(&wire::renew_bytes(&hub.pin, "pixel", n, &[0; 32])))),
        ("the pairing's bytes", Box::new(|n| phone.sign(&crate::fields::join(&[wire::PAIR_LABEL.as_bytes(), n])))),
    ];
    let nonce = ask_nonce(&hub, &phone.token);
    for (what, sign) in attempts {
        assert_eq!(send_renewal(&hub, &phone.token, &nonce, &hash, &sign(&nonce)), (403, error("bad-signature")), "{what}");
    }
    // The token itself was never replaced, and the nonce is still good for the right signature.
    assert_eq!(hub.call("GET", "/v1/me", Some(&phone.token), None).1["issued"], json!(START));
    assert_eq!(send_renewal(&hub, &phone.token, &nonce, &hash, &phone.sign(&wire::renew_bytes(&hub.pin, "pixel", &nonce, &hash))).0, 200);
}

#[test]
fn a_new_token_must_be_new() {
    let hub = start();
    let phone = paired_phone(&hub, "pixel");
    let nonce: [u8; 16] = wire::unhex(hub.call("POST", "/v1/renew/nonce", Some(&phone.token), None).1["nonce"].as_str().unwrap()).unwrap();
    let same = wire::token_hash(&phone.token);
    let body = json!({"nonce": util::hex(&nonce), "token_hash": util::hex(&same), "signature": util::hex(&phone.sign(&wire::renew_bytes(&hub.pin, "pixel", &nonce, &same)))});
    assert_eq!(hub.call("POST", "/v1/renew", Some(&phone.token), Some(&body)), (400, error("malformed")));
}

// --- a machine's renewal ---

#[test]
fn a_machine_renews_from_day_10_to_day_30_and_never_after() {
    for (day, renews) in [(0, false), (9, false), (10, true), (20, true), (29, true), (30, false), (45, false)] {
        let hub = start();
        let machine_ = paired_machine(&hub, "server-1");
        hub.at(day * DAY);
        let (new, status, body) = renew_machine(&hub, &machine_.token);
        match (renews, day) {
            (true, _) => {
                assert_eq!((status, body), (200, json!({"expires": time(day * DAY + 30 * DAY)})), "day {day}");
                assert_eq!(hub.call("GET", "/v1/me", Some(&new), None).0, 200, "day {day}");
            }
            (false, day) if day < 10 => assert_eq!((status, body), (403, error("too-early")), "day {day}"),
            (false, _) => {
                assert_eq!((status, body), (401, error("expired")), "day {day}");
                assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None), (401, error("expired")), "day {day}");
                assert_eq!(hub.row("server-1").token, TokenState::Expired);
                assert_eq!(admin::token_text(&hub.row("server-1")), "token: expired, join again");
            }
        }
    }
}

#[test]
fn an_expired_machine_is_paired_again_under_its_name_and_deleted_at_day_90() {
    let hub = start();
    let machine_ = paired_machine(&hub, "server-1");
    // While its token works, the name is taken.
    hub.at(29 * DAY);
    assert_eq!(begin(&hub, machine("server-1")).err(), Some(Outcome::Taken));
    hub.at(31 * DAY);
    let again = paired_machine(&hub, "server-1");
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None), (401, error("unknown")));
    assert_eq!(hub.call("GET", "/v1/me", Some(&again.token), None).0, 200);
    // Left alone, an expired machine's row goes on day 90.
    let other = paired_machine(&hub, "server-2");
    hub.at(31 * DAY + 90 * DAY);
    assert_eq!(hub.call("GET", "/v1/me", Some(&other.token), None), (401, error("unknown")));
    assert!(hub.list().is_empty());
}

#[test]
fn a_replaced_machine_token_used_again_marks_a_conflict() {
    let hub = start();
    let machine_ = paired_machine(&hub, "server-1");
    hub.at(10 * DAY);
    let (new, status, _) = renew_machine(&hub, &machine_.token);
    assert_eq!(status, 200);
    // Before the new token is used, the old one still works, as when the reply was lost.
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None).0, 200);
    assert_eq!(hub.call("GET", "/v1/me", Some(&new), None).0, 200);
    assert_eq!(hub.row("server-1").conflict_since, None);
    // Once it is, the old one used again is a copy.
    hub.advance(SignedDuration::from_secs(60));
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None), (401, error("conflict")));
    let marked = START.parse::<Timestamp>().unwrap() + 10 * DAY + SignedDuration::from_secs(60);
    let row = hub.row("server-1");
    assert_eq!(row.conflict_since, Some(marked));
    assert!(admin::token_text(&row).starts_with("token conflict since "), "{}", admin::token_text(&row));
    let (status, me) = hub.call("GET", "/v1/me", Some(&new), None);
    assert_eq!((status, &me["conflict"]), (200, &json!(wire::time(marked))));
    // Neither side gets more time.
    hub.at(15 * DAY);
    assert_eq!(renew_machine(&hub, &new).1, 409);
    assert_eq!(renew_machine(&hub, &new).2, error("conflict"));
    // The mark stays; only a revoke clears it, with the row.
    assert_eq!(hub.row("server-1").conflict_since, Some(marked));
    assert!(admin::revoke_at(&hub.socket(), "server-1").unwrap());
    assert!(hub.list().is_empty());
}

#[test]
fn a_second_renewal_with_the_old_token_marks_a_conflict() {
    let hub = start();
    let machine_ = paired_machine(&hub, "server-1");
    hub.at(12 * DAY);
    let (new, status, _) = renew_machine(&hub, &machine_.token);
    assert_eq!(status, 200);
    // A copy that still holds the old token tries to renew it: the real link has.
    assert_eq!(renew_machine(&hub, &machine_.token).2, error("conflict"));
    assert!(hub.row("server-1").conflict_since.is_some());
    assert_eq!(hub.call("GET", "/v1/me", Some(&new), None).1["conflict"], json!(time(12 * DAY)));
}

#[test]
fn an_old_token_past_its_24_hours_marks_a_conflict() {
    let hub = start();
    let machine_ = paired_machine(&hub, "server-1");
    hub.at(10 * DAY);
    assert_eq!(renew_machine(&hub, &machine_.token).1, 200);
    hub.advance(OLD_TOKEN_LEFT);
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None).0, 200);
    hub.advance(SignedDuration::from_secs(2));
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None), (401, error("conflict")));
}

#[test]
fn any_earlier_machine_token_used_again_marks_a_conflict() {
    // A copy renews on day 10 and day 20; the real machine comes back with its day-0 token.
    let hub = start();
    let machine_ = paired_machine(&hub, "server-1");
    hub.at(10 * DAY);
    let (second, status, _) = renew_machine(&hub, &machine_.token);
    assert_eq!(status, 200);
    assert_eq!(hub.call("GET", "/v1/me", Some(&second), None).0, 200);
    hub.at(20 * DAY);
    let (third, status, _) = renew_machine(&hub, &second);
    assert_eq!(status, 200);
    assert_eq!(hub.call("GET", "/v1/me", Some(&third), None).0, 200);
    hub.at(25 * DAY);
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None), (401, error("conflict")));
    assert_eq!(hub.row("server-1").conflict_since, Some(START.parse::<Timestamp>().unwrap() + 25 * DAY));

    // The same from a backup restored after the token in it expired, and with a renewal.
    let hub = start();
    let machine_ = paired_machine(&hub, "server-1");
    let mut held = machine_.token.clone();
    for day in [10, 20, 30] {
        hub.at(day * DAY);
        let (new, status, _) = renew_machine(&hub, &held);
        assert_eq!(status, 200, "day {day}");
        assert_eq!(hub.call("GET", "/v1/me", Some(&new), None).0, 200, "day {day}");
        held = new;
    }
    hub.at(35 * DAY);
    assert_eq!(renew_machine(&hub, &machine_.token).2, error("conflict"));
    assert!(hub.row("server-1").conflict_since.is_some());
}

#[test]
fn an_earlier_machine_token_is_forgotten_90_days_after_its_issue() {
    let hub = start();
    let machine_ = paired_machine(&hub, "server-1");
    let mut held = machine_.token.clone();
    let mut tokens = vec![held.clone()];
    for day in [10, 20, 30, 40, 50, 60, 70, 80] {
        hub.at(day * DAY);
        let (new, status, _) = renew_machine(&hub, &held);
        assert_eq!(status, 200, "day {day}");
        assert_eq!(hub.call("GET", "/v1/me", Some(&new), None).0, 200, "day {day}");
        tokens.push(new.clone());
        held = new;
    }
    // The day-0 token is gone; the day-10 one is still known.
    hub.at(90 * DAY);
    assert_eq!(hub.call("GET", "/v1/me", Some(&tokens[0]), None), (401, error("unknown")));
    assert_eq!(hub.row("server-1").conflict_since, None);
    assert_eq!(hub.call("GET", "/v1/me", Some(&tokens[1]), None), (401, error("conflict")));
}

#[test]
fn a_marked_machine_is_paired_again_only_after_a_revoke() {
    let hub = start();
    let machine_ = paired_machine(&hub, "server-1");
    hub.at(10 * DAY);
    let (new, status, _) = renew_machine(&hub, &machine_.token);
    assert_eq!(status, 200);
    assert_eq!(hub.call("GET", "/v1/me", Some(&new), None).0, 200);
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None), (401, error("conflict")));
    // Past day 30 the machine's token has expired, and its name is still not free.
    hub.at(41 * DAY);
    assert_eq!(begin(&hub, machine("server-1")).err(), Some(Outcome::Marked));
    assert_eq!(begin(&hub, device("server-1", &["acme"])).err(), Some(Outcome::Marked));
    assert!(hub.row("server-1").conflict_since.is_some());
    assert!(admin::revoke_at(&hub.socket(), "server-1").unwrap());
    paired_machine(&hub, "server-1");
    assert_eq!(hub.row("server-1").conflict_since, None);

    // Marked while its pairing waits for the terminal: the y there pairs nothing.
    let hub = start();
    let machine_ = paired_machine(&hub, "server-1");
    hub.at(10 * DAY);
    let (new, status, _) = renew_machine(&hub, &machine_.token);
    assert_eq!(status, 200);
    assert_eq!(hub.call("GET", "/v1/me", Some(&new), None).0, 200);
    hub.at(41 * DAY);
    let again = Machine::new();
    let pairing = begin(&hub, machine("server-1")).unwrap();
    assert_eq!(hub.call("POST", "/v1/join", None, Some(&again.join_body(&pairing.invite))).0, 202);
    assert_eq!(pairing.claimed(), None);
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None), (401, error("conflict")));
    assert_eq!(pairing.answer(true), Outcome::Marked);
    assert_eq!(hub.call("GET", "/v1/me", Some(&again.token), None), (401, error("unknown")));
    assert!(hub.row("server-1").conflict_since.is_some());
}

#[test]
fn a_phone_has_no_conflict_mark() {
    let hub = start();
    let phone = paired_phone(&hub, "pixel");
    let (new, _, _) = renew_phone(&hub, &phone);
    assert_eq!(hub.call("GET", "/v1/me", Some(&new), None).0, 200);
    assert_eq!(hub.call("GET", "/v1/me", Some(&phone.token), None), (401, error("unknown")));
    assert_eq!(hub.row("pixel").conflict_since, None);
}

// --- what any call gets ---

#[test]
fn a_call_without_a_token_or_to_nothing_is_refused() {
    let hub = start();
    let phone = paired_phone(&hub, "pixel");
    assert_eq!(hub.call("GET", "/v1/me", None, None), (401, error("no-token")));
    assert_eq!(hub.call("GET", "/v1/me", Some("halti_dev_short"), None), (401, error("no-token")));
    assert_eq!(hub.call("GET", "/v1/me", Some(&token(Kind::Device)), None), (401, error("unknown")));
    assert_eq!(hub.call("GET", "/v1/nothing", Some(&phone.token), None), (404, error("not-found")));
    assert_eq!(hub.call("GET", "/v1/me?x=1", Some(&phone.token), None), (404, error("not-found")));
    assert_eq!(hub.call("POST", "/v1/me", Some(&phone.token), None), (405, error("method")));
    assert_eq!(hub.call("GET", "/v1/pair", None, None), (405, error("method")));
    assert_eq!(hub.call("GET", "/v1/me", Some(&phone.token), Some(&json!({}))), (400, error("malformed")));
    assert_eq!(hub.call("POST", "/v1/renew", Some(&phone.token), Some(&json!({"token_hash": "00"}))), (400, error("malformed")));
    // A token in the URL is not a token.
    assert_eq!(hub.call("GET", &format!("/v1/me?token={}", phone.token), None, None), (404, error("not-found")));
}

#[test]
fn a_body_over_4_kib_is_too_large() {
    let hub = start();
    let big = json!({"code": "a".repeat(5000)});
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&big)), (413, error("too-large")));
    let fits = json!({"code": "a".repeat(4000)});
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&fits)), (400, error("malformed")));
}

#[test]
fn a_head_over_8_kib_gets_no_reply() {
    let hub = start();
    let long = format!("GET /v1/me HTTP/1.1\r\nX-Pad: {}\r\n\r\n", "a".repeat(9000));
    assert_eq!(hub.raw(long.as_bytes()), None);
    let fits = format!("GET /v1/me HTTP/1.1\r\nX-Pad: {}\r\n\r\n", "a".repeat(7000));
    assert_eq!(hub.raw(fits.as_bytes()), Some((401, error("no-token"))));
}

#[test]
fn a_slow_request_is_closed_without_a_reply() {
    let hub = start_with(Limits { request_wait: Duration::from_millis(500), ..Limits::HUB });
    let mut stream = pin::connect(&hub.address, hub.pin, Duration::from_secs(10)).unwrap();
    stream.write_all(b"GET /v1/me HTTP/1.1\r\n").unwrap();
    stream.flush().unwrap();
    let started = std::time::Instant::now();
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    assert!(rest.is_empty(), "{rest:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    // A TCP connection that never starts TLS is closed too, by the hub: a read that only times out
    // is not a close.
    let mut tcp = TcpStream::connect(&hub.address).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let started = std::time::Instant::now();
    let read = tcp.read(&mut [0; 16]);
    assert!(matches!(read, Ok(0)) || matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset), "{read:?}");
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[test]
fn a_request_line_that_is_not_one_gets_no_reply() {
    let hub = start();
    for line in ["GET /v1/me", "GET  /v1/me HTTP/1.1", "GET /v1/me HTTP/1.1 x", "GET /v1/me FTP/1.0", " /v1/me HTTP/1.1"] {
        assert_eq!(hub.raw(format!("{line}\r\n\r\n").as_bytes()), None, "{line}");
    }
    assert_eq!(hub.raw(b"GET /v1/me HTTP/1.1\r\nNo colon\r\n\r\n"), None);
    assert_eq!(hub.raw(b"GET /v1/me HTTP/1.1\r\n\r\n"), Some((401, error("no-token"))));
}

/// Whether the hub closes a connection at once: one more than its limits allow.
fn closed_at_once(address: &str) -> bool {
    let mut tcp = TcpStream::connect(address).unwrap();
    tcp.set_read_timeout(Some(Duration::from_millis(1500))).unwrap();
    matches!(tcp.read(&mut [0; 1]), Ok(0)) || matches!(tcp.read(&mut [0; 1]), Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset)
}

#[test]
fn connections_past_the_limits_are_closed_before_tls() {
    let hub = start_with(Limits { request_wait: Duration::from_secs(5), connections: 3, per_address: 2 });
    let held: Vec<TcpStream> = (0..2).map(|_| TcpStream::connect(&hub.address).unwrap()).collect();
    thread::sleep(Duration::from_millis(200));
    assert!(closed_at_once(&hub.address), "a third from one address");
    drop(held);
    thread::sleep(Duration::from_millis(300));
    assert_eq!(hub.call("GET", "/v1/me", None, None), (401, error("no-token")), "room again once they went");
    // In all: the per-address limit is above the total.
    let hub = start_with(Limits { request_wait: Duration::from_secs(5), connections: 2, per_address: 8 });
    let _held: Vec<TcpStream> = (0..2).map(|_| TcpStream::connect(&hub.address).unwrap()).collect();
    thread::sleep(Duration::from_millis(200));
    assert!(closed_at_once(&hub.address), "a third in all");
}

#[test]
fn the_gate_counts_an_ipv6_64_as_one_address() {
    let gate = Arc::new(listen::Gate::new(Limits::HUB));
    let ip = |text: &str| -> std::net::IpAddr { text.parse().unwrap() };
    let held: Vec<_> = (1..=8).map(|i| gate.enter(ip(&format!("2001:db8:1:2::{i}"))).unwrap()).collect();
    assert!(gate.enter(ip("2001:db8:1:2:ffff::9")).is_none(), "the same /64");
    let _next = gate.enter(ip("2001:db8:1:3::1")).unwrap();
    // IPv4 counts each address, also as a dual-stack listener sees it.
    let v4: Vec<_> = (0..8).map(|_| gate.enter(ip("192.0.2.9")).unwrap()).collect();
    assert!(gate.enter(ip("::ffff:192.0.2.9")).is_none());
    assert!(gate.enter(ip("::ffff:192.0.2.10")).is_some());
    drop((held, v4));
    assert_eq!(listen::from(ip("2001:db8:1:2:3:4:5:6")), ip("2001:db8:1:2::"));
    assert_eq!(listen::from(ip("::ffff:10.0.0.1")), ip("10.0.0.1"));
}

#[test]
fn the_gate_counts_each_address_apart() {
    let gate = Arc::new(listen::Gate::new(Limits { request_wait: Duration::from_secs(1), connections: 3, per_address: 2 }));
    let (a, b): (std::net::IpAddr, std::net::IpAddr) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
    let first = gate.enter(a).unwrap();
    let _second = gate.enter(a).unwrap();
    assert!(gate.enter(a).is_none());
    let _third = gate.enter(b).unwrap();
    assert!(gate.enter(b).is_none(), "the total");
    drop(first);
    assert!(gate.enter(a).is_some());
}

// --- TLS ---

#[test]
fn only_the_pinned_key_is_trusted() {
    let hub = start();
    assert!(pin::connect(&hub.address, hub.pin, Duration::from_secs(5)).is_ok());
    let mut other = hub.pin;
    other[0] ^= 1;
    assert!(pin::connect(&hub.address, other, Duration::from_secs(5)).is_err());
}

/// Shows the given certificate, and signs the handshake with the given key, whether they match or not.
#[derive(Debug)]
struct Shows(Arc<CertifiedKey>);

impl ResolvesServerCert for Shows {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[test]
fn the_right_certificate_with_the_wrong_key_fails() {
    let right = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let wrong = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec![CERT_NAME.to_string()]).unwrap().self_signed(&right).unwrap();
    let signer = provider().key_provider.load_private_key(rustls::pki_types::PrivateKeyDer::Pkcs8(wrong.serialize_der().into())).unwrap();
    let shows = Arc::new(Shows(Arc::new(CertifiedKey::new(vec![cert.der().clone()], signer))));
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider()).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_no_client_auth().with_cert_resolver(shows),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(config.clone()).unwrap(), tcp);
            let _ = stream.read(&mut [0; 1]);
        }
    });
    let said = pin::connect(&address.to_string(), pin_of(&right), Duration::from_secs(5)).map(drop).expect_err("the handshake fails").to_string();
    assert!(said.contains("TLS with the hub"), "{said}");
}

#[test]
fn the_hub_speaks_only_tls_1_3() {
    let hub = start();
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    let mut stream = rustls::StreamOwned::new(rustls::ClientConnection::new(Arc::new(config), CERT_NAME.try_into().unwrap()).unwrap(), TcpStream::connect(&hub.address).unwrap());
    assert!(stream.write_all(b"GET /v1/me HTTP/1.1\r\n\r\n").and_then(|()| stream.flush()).and_then(|()| stream.read(&mut [0; 1])).is_err());
}

/// Trusts anything: a client for the TLS 1.2 test, which must fail before any certificate.
#[derive(Debug)]
struct AnyCert;

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

// --- files ---

#[test]
fn the_table_and_the_key_outlive_a_restart() {
    let dir = TempDir::new("halti-hub-restart").unwrap();
    let folder = dir.0.clone();
    let clock = Arc::new(Hands(Mutex::new(START.parse().unwrap())));
    let first = start_in(dir, Limits::HUB, clock.clone());
    let phone = paired_phone(&first, "pixel");
    let machine_ = paired_machine(&first, "server-1");
    first.at(10 * DAY);
    let (new, status, _) = renew_machine(&first, &machine_.token);
    assert_eq!(status, 200);
    let seen = first.list();
    let (pin, Running { _dir: dir, .. }) = (first.pin, first);
    let mode = |name: &str| fs::metadata(folder.join(name)).unwrap().permissions().mode() & 0o777;
    assert_eq!((mode("table.json"), mode("tls-key.pem")), (0o600, 0o600));
    // The same key gives the same pin; the rows, the replaced token and the last-seen times come back.
    assert_eq!(pin_of(&tls_key(&folder).unwrap()), pin);
    let hub = Hub::open(&folder, "127.0.0.1:1", pin, clock).unwrap();
    let now = hub.now();
    assert_eq!(locked(&hub.table).list(now), seen);
    let mut table = locked(&hub.table);
    assert_eq!(table.authenticate(Kind::Device, &wire::token_hash(&phone.token), false, now).map(|c| c.name), Ok("pixel".to_string()));
    assert_eq!(table.authenticate(Kind::Machine, &wire::token_hash(&new), false, now).map(|c| c.name), Ok("server-1".to_string()));
    assert_eq!(table.authenticate(Kind::Machine, &wire::token_hash(&machine_.token), false, now).err(), Some(wire::Refused::Conflict));
    drop(table);
    drop(dir);
}

#[test]
fn last_seen_is_written_down_as_the_hub_shows_it() {
    let hub = start();
    let machine_ = paired_machine(&hub, "server-1");
    // A client that calls every 30 seconds for 20 minutes.
    for i in 0..=40 {
        hub.at(SignedDuration::from_secs(30 * i));
        assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None).0, 200);
    }
    let shown = hub.row("server-1").last_seen.unwrap();
    let last = START.parse::<Timestamp>().unwrap() + SignedDuration::from_secs(1200);
    assert!(shown <= last && last.duration_since(shown) < SignedDuration::from_secs(60), "{shown}");
    let written = Hub::open(&hub.folder, "x:1", hub.pin, hub.clock.clone()).unwrap();
    let now = written.now();
    assert_eq!(locked(&written.table).list(now)[0].last_seen, Some(shown));
}

#[test]
fn a_change_the_hub_cannot_write_down_is_not_reported_as_made() {
    let hub = start();
    let phone = paired_phone(&hub, "pixel");
    let machine_ = paired_machine(&hub, "server-1");
    // The table's file is a folder now: no write can replace it.
    let path = hub.folder.join("table.json");
    let text = fs::read_to_string(&path).unwrap();
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(path.join("in-the-way"), "").unwrap();

    // A revoke holds, and says it isn't written down.
    let said = admin::revoke_at(&hub.socket(), "pixel").unwrap_err().to_string();
    assert!(said.contains("could not write") && said.contains("restarts"), "{said}");
    assert_eq!(hub.call("GET", "/v1/me", Some(&phone.token), None), (401, error("unknown")));
    // A pairing is not made.
    let tablet = Phone::new();
    let pairing = begin(&hub, device("tablet", &["acme"])).unwrap();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&tablet.pair_body(&pairing.invite, ""))).0, 202);
    pairing.claimed();
    assert_eq!(pairing.answer(true), Outcome::Unwritten);
    assert_eq!(hub.call("GET", "/v1/me", Some(&tablet.token), None), (401, error("unknown")));
    assert!(!hub.list().iter().any(|row| row.name == "tablet"));
    // Nor is a renewal: the token sent still works, the new one doesn't.
    hub.at(10 * DAY);
    let (new, status, body) = renew_machine(&hub, &machine_.token);
    assert_eq!((status, body), (503, error("unavailable")));
    assert_eq!(hub.call("GET", "/v1/me", Some(&new), None), (401, error("unknown")));
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None).1["issued"], json!(START));

    // Once the file can be written, the next call writes what holds: the revoke, and no more.
    fs::remove_dir_all(&path).unwrap();
    fs::write(&path, &text).unwrap();
    assert_eq!(hub.call("GET", "/v1/me", Some(&machine_.token), None).0, 200);
    let reopened = Hub::open(&hub.folder, "x:1", hub.pin, hub.clock.clone()).unwrap();
    let now = reopened.now();
    let mut table = locked(&reopened.table);
    assert_eq!(table.list(now).iter().map(|row| row.name.as_str()).collect::<Vec<_>>(), ["server-1"]);
    assert_eq!(table.authenticate(Kind::Machine, &wire::token_hash(&machine_.token), false, now).map(|c| c.name), Ok("server-1".to_string()));
}

#[test]
fn a_table_file_that_was_changed_by_hand_is_refused() {
    let hub = start();
    paired_phone(&hub, "pixel");
    let path = hub.folder.join("table.json");
    let text = fs::read_to_string(&path).unwrap();
    // Another agreement key, which the signing key never vouched for.
    let other = util::hex(&KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap().subject_public_key_info());
    let stored: Value = serde_json::from_str(&text).unwrap();
    let agreement = stored["rows"][0]["keys"]["device"]["agreement"].as_str().unwrap().to_string();
    fs::write(&path, text.replace(&agreement, &other)).unwrap();
    let said = Hub::open(&hub.folder, "x:1", hub.pin, hub.clock.clone()).err().unwrap().to_string();
    assert!(said.contains("pixel's keys aren't signed"), "{said}");
    fs::write(&path, text.replace("\"version\": 1", "\"version\": 2")).unwrap();
    assert!(Hub::open(&hub.folder, "x:1", hub.pin, hub.clock.clone()).is_err());
}

// --- the admin socket ---

#[test]
fn an_admin_request_reads_only_as_what_was_written() {
    for request in [device("pixel", &["acme", "beta"]), machine("server-1"), Request::Devices, Request::Revoke("pixel".into())] {
        let line = request.line();
        assert_eq!(Request::parse(line.strip_suffix('\n').unwrap()), Some(request), "{line}");
    }
    assert_eq!(device("pixel", &["acme", "beta"]).line(), "halti-hub/1 pair device pixel acme,beta\n");
    for line in [
        "halti-hub/2 devices",
        "halti-hub/1 pair device pixel",
        "halti-hub/1 pair device Pixel acme",
        "halti-hub/1 pair device pixel Acme",
        "halti-hub/1 pair machine server-1 acme",
        "halti-hub/1 pair phone pixel acme",
        "halti-hub/1 revoke ../x",
        "halti-hub/1 devices now",
    ] {
        assert_eq!(Request::parse(line), None, "{line}");
    }
}

#[test]
fn listen_and_address_are_checked() {
    let (at, address, warning) = addresses("10.0.0.5:8443", None).unwrap();
    assert_eq!((at.to_string(), address, warning), ("10.0.0.5:8443".to_string(), "10.0.0.5:8443".to_string(), None));
    for private_ in ["127.0.0.1:8443", "192.168.1.2:8443", "172.16.0.1:8443", "100.101.102.103:8443", "[fd00::5]:8443", "[fe80::1]:8443", "[::1]:8443"] {
        assert_eq!(addresses(private_, None).unwrap().2, None, "{private_}");
    }
    for public in ["203.0.113.5:8443", "100.128.0.1:8443", "[2001:db8::1]:8443"] {
        assert!(addresses(public, None).unwrap().2.is_some(), "{public}");
    }
    for port in [53, 80, 443] {
        assert!(addresses(&format!("10.0.0.5:{port}"), None).unwrap_err().to_string().contains(&format!("port {port}")));
    }
    assert!(addresses("0.0.0.0:8443", None).unwrap_err().to_string().contains("--address"));
    let (_, address, warning) = addresses("0.0.0.0:8443", Some("hub.example:8443")).unwrap();
    assert_eq!(address, "hub.example:8443");
    assert!(warning.is_some(), "every address");
    assert!(addresses("hub.example:8443", None).is_err(), "a name to listen on");
    assert!(addresses("10.0.0.5", None).is_err());
    assert!(addresses("10.0.0.5:8443", Some("hub/x:8443")).is_err());
}

#[test]
fn a_second_hub_as_the_same_user_is_refused() {
    let hub = start();
    assert!(crate::keep::bind(&hub.socket()).unwrap().is_none());
}

#[test]
fn the_pairing_string_fits_a_qr_code_at_its_longest() {
    let invite = Invite { kind: Kind::Machine, address: format!("{}:65535", "h".repeat(253)), pin: [0xff; 32], code: [0xff; 16] };
    let drawn = admin::qr(&invite);
    assert!(drawn.lines().count() > 20 && drawn.chars().all(|c| matches!(c, ' ' | '\n' | '\u{2580}' | '\u{2584}' | '\u{2588}')));
}

// --- the service unit ---

#[test]
fn the_service_unit_runs_the_hub_confined_as_its_own_user() {
    let unit = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("service/halti-hub.service")).unwrap();
    let lines: Vec<&str> = unit.lines().collect();
    for line in [
        "User=halti-hub",
        "Group=halti-hub",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "ProtectProc=invisible",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "StateDirectory=halti-hub",
        "UMask=0077",
    ] {
        assert!(lines.contains(&line), "{line}");
    }
    let exec = lines.iter().find_map(|l| l.strip_prefix("ExecStart=")).unwrap();
    assert!(exec.starts_with("/usr/local/bin/halti hub serve --listen "), "{exec}");
    let listen = exec.split(' ').nth(4).unwrap();
    assert!(addresses(listen, None).unwrap().2.is_none(), "the example listens on a private address");
    assert!(!lines.iter().any(|l| l.starts_with("ReadWritePaths=") || l.starts_with("User=root")));
}

#[test]
fn days_left_count_a_part_of_a_day_whole() {
    let hub = start();
    paired_phone(&hub, "pixel");
    for (at, days) in [(SignedDuration::ZERO, 30), (SignedDuration::from_secs(1), 30), (DAY, 29), (29 * DAY + SignedDuration::from_secs(3600), 1)] {
        hub.at(at);
        assert_eq!(hub.row("pixel").token, TokenState::Left { days }, "{at:?}");
    }
    assert_eq!(admin::token_text(&hub.row("pixel")), "token: 1 day left");
    hub.at(30 * DAY);
    assert!(matches!(hub.row("pixel").token, TokenState::Renewable { .. }));
}

// --- what the hub carries between machines and phones ---

/// A request of `machine`'s, in workspace `ws`, good for two minutes by the real clock.
fn record(machine: &str, ws: &str, id: u8) -> (crate::requests::Record, Vec<u8>) {
    let record = crate::requests::Record {
        machine: machine.into(),
        ws: ws.into(),
        box_name: "dev".into(),
        run: crate::requests::RunId([1; 8]),
        kind: crate::requests::Kind::Write,
        action: "POST https://api.example.com/v1/x".into(),
        id: crate::requests::Id([id; 16]),
        expiry: crate::requests::now_secs() + 120,
    };
    let bytes = record.encode().unwrap();
    (record, bytes)
}

/// A hub on the real clock, so a request's expiry by this machine's clock means what it says.
fn start_now() -> Running {
    let dir = TempDir::new("halti-hub").unwrap();
    start_in(dir, Limits { request_wait: Duration::from_secs(5), ..Limits::HUB }, Arc::new(Hands(Mutex::new(Timestamp::from_second(Timestamp::now().as_second()).unwrap()))))
}

fn report(hub: &Running, machine: &Machine, trusted: Value, ids: &[[u8; 16]]) -> (u16, Value) {
    let body = json!({"link": util::hex(&[5; 16]), "workspaces": [], "trusted": trusted, "requests": ids.iter().map(|id| util::hex(id)).collect::<Vec<_>>()});
    hub.call("POST", "/v1/machine/state", Some(&machine.token), Some(&body))
}

#[test]
fn a_machine_posts_requests_its_phones_list_and_the_hub_holds_fifty() {
    let hub = start_now();
    let server = paired_machine(&hub, "server-1");
    let other = paired_machine(&hub, "server-2");
    let pixel = paired_phone(&hub, "pixel");
    let (_, bytes) = record("server-1", "acme", 1);
    let post = |token: &str, bytes: &[u8]| hub.call("POST", "/v1/machine/request", Some(token), Some(&json!({"record": util::hex(bytes)})));
    assert_eq!(post(&server.token, &bytes), (200, json!({})));
    assert_eq!(post(&server.token, &bytes), (200, json!({})), "one held already is left as it is");
    // A record that names another machine, or isn't one; a phone's token at a machine's call.
    assert_eq!(post(&other.token, &bytes), (403, error("other-machine")));
    assert_eq!(post(&server.token, &bytes[..bytes.len() - 1]), (400, error("malformed")));
    assert_eq!(post(&pixel.token, &bytes), (403, error("wrong-kind")));
    // The phone sees it in its workspace, and not one of another workspace.
    let (_, beta) = record("server-1", "beta", 2);
    assert_eq!(post(&server.token, &beta).0, 200);
    let (status, listed) = hub.call("GET", "/v1/requests", Some(&pixel.token), None);
    assert_eq!((status, listed), (200, json!({"requests": [{"machine": "server-1", "record": util::hex(&bytes)}]})));
    assert_eq!(hub.call("GET", "/v1/requests", Some(&server.token), None), (403, error("wrong-kind")));
    // Fifty at most for one machine.
    for id in 3..51 {
        assert_eq!(post(&server.token, &record("server-1", "acme", id).1).0, 200, "{id}");
    }
    assert_eq!(post(&server.token, &record("server-1", "acme", 51).1), (429, error("full")));
    // A report drops what the machine no longer holds, and names what the hub lacks.
    let (status, reply) = report(&hub, &server, json!([]), &[[1; 16], [99; 16]]);
    assert_eq!((status, &reply["missing"]), (200, &json!([util::hex(&[99; 16])])));
    assert_eq!(hub.call("GET", "/v1/requests", Some(&pixel.token), None).1["requests"].as_array().unwrap().len(), 1);
    assert_eq!(post(&server.token, &record("server-1", "acme", 51).1).0, 200, "room again");
}

#[test]
fn a_report_gets_the_phones_that_see_its_workspaces_and_a_phone_the_machines_that_trust_it() {
    let hub = start_now();
    let server = paired_machine(&hub, "server-1");
    let pixel = paired_phone(&hub, "pixel");
    let tablet = Phone::new();
    let pairing = begin(&hub, device("tablet", &["beta"])).unwrap();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&tablet.pair_body(&pairing.invite, ""))).0, 202);
    pairing.claimed();
    assert_eq!(pairing.answer(true), Outcome::Paired);
    // It trusts pixel for acme: the hub lists the phones that may see acme.
    let (status, reply) = report(&hub, &server, json!([{"device": "pixel", "ws": ["acme"]}]), &[]);
    assert_eq!(status, 200);
    let devices = reply["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["name"], "pixel");
    assert_eq!(devices[0]["signing_key"], util::hex(&pixel.signing_key()));
    assert_eq!(devices[0]["ws"], json!(["acme"]));
    // The machine asks for a phone's keys by name; one there isn't is gone.
    let (status, keys) = hub.call("POST", "/v1/machine/device", Some(&server.token), Some(&json!({"name": "tablet"})));
    assert_eq!((status, &keys["ws"]), (200, &json!(["beta"])));
    assert_eq!(hub.call("POST", "/v1/machine/device", Some(&server.token), Some(&json!({"name": "nobody"}))), (410, error("gone")));
    // pixel sees the machine, its key and the workspace it is trusted for; tablet sees nothing.
    let (status, state) = hub.call("GET", "/v1/state", Some(&pixel.token), None);
    assert_eq!(status, 200);
    assert_eq!((&state["machines"][0]["name"], &state["machines"][0]["ws"], &state["machines"][0]["conflict"]), (&json!("server-1"), &json!(["acme"]), &Value::Null));
    assert_eq!(state["machines"][0]["key"], util::hex(&server.key.subject_public_key_info()));
    assert_eq!(hub.call("GET", "/v1/state", Some(&tablet.token), None).1, json!({"machines": [], "sent": []}));
    // Revoked, the machine is gone from the phone's view.
    assert!(admin::revoke_at(&hub.socket(), "server-1").unwrap());
    assert_eq!(hub.call("GET", "/v1/state", Some(&pixel.token), None).1["machines"], json!([]));
}

#[test]
fn a_report_may_be_longer_than_other_calls_and_no_longer_than_16_kib() {
    let hub = start_now();
    let server = paired_machine(&hub, "server-1");
    let names = |n: usize| {
        (0..n)
            .map(|i| json!({"name": format!("w{i}"), "open": true, "runs": (0..32).map(|r| json!({"box": format!("b{r}"), "run": util::hex(&[r as u8; 8])})).collect::<Vec<_>>()}))
            .collect::<Vec<_>>()
    };
    let body = |n: usize| json!({"link": util::hex(&[5; 16]), "workspaces": names(n), "trusted": [], "requests": []});
    assert!((4096..16 * 1024).contains(&body(4).to_string().len()));
    assert_eq!(hub.call("POST", "/v1/machine/state", Some(&server.token), Some(&body(4))).0, 200);
    assert!(body(16).to_string().len() > 16 * 1024);
    assert_eq!(hub.call("POST", "/v1/machine/state", Some(&server.token), Some(&body(16))), (413, error("too-large")));
    assert_eq!(hub.call("POST", "/v1/machine/request", Some(&server.token), Some(&json!({"record": "00".repeat(2100)}))), (413, error("too-large")));
}

#[test]
fn a_machine_s_inbox_waits_for_what_a_phone_sends_and_keeps_it_until_done() {
    let hub = start_now();
    let server = paired_machine(&hub, "server-1");
    let pixel = paired_phone(&hub, "pixel");
    let (_, bytes) = record("server-1", "acme", 1);
    assert_eq!(hub.call("POST", "/v1/machine/request", Some(&server.token), Some(&json!({"record": util::hex(&bytes)}))).0, 200);
    let inbox = |done: Value| hub.call("POST", "/v1/machine/inbox", Some(&server.token), Some(&json!({"done": done})));
    // Nothing waits: the call ends empty once the hub's wait is over.
    let started = std::time::Instant::now();
    assert_eq!(inbox(json!([])), (200, json!({"items": []})));
    assert!(started.elapsed() >= INBOX_WAIT - Duration::from_millis(50));
    // A phone's signed answer wakes a call that waits.
    let waiting = thread::scope(|scope| {
        let waiting = scope.spawn(|| inbox(json!([])));
        thread::sleep(Duration::from_millis(100));
        let signature = pixel.sign(&crate::requests::answer_bytes(&bytes, true));
        let body = json!({"machine": "server-1", "id": util::hex(&[1; 16]), "decision": "yes", "signature": util::hex(&signature)});
        assert_eq!(hub.call("POST", "/v1/answer", Some(&pixel.token), Some(&body)), (202, json!({"n": 1})));
        waiting.join().unwrap()
    });
    let item = &waiting.1["items"][0];
    assert_eq!(
        (item["n"].as_u64(), item["kind"].as_str(), item["device"].as_str(), item["ws"].as_str(), item["decision"].as_str()),
        (Some(1), Some("answer"), Some("pixel"), Some("acme"), Some("yes"))
    );
    // Taken but not said done, it comes again; said done, it goes, and the phone sees the word.
    assert_eq!(inbox(json!([])).1["items"].as_array().unwrap().len(), 1);
    let sent = |phone: &Phone| hub.call("GET", "/v1/state", Some(&phone.token), None).1["sent"].clone();
    assert_eq!(sent(&pixel)[0]["state"], "taken");
    assert_eq!(inbox(json!([{"n": 1, "said": "approved"}])).1, json!({"items": []}));
    assert_eq!(sent(&pixel)[0]["state"], "approved");
    assert_eq!(inbox(json!([{"n": 1, "said": "Approved!"}])), (400, error("malformed")));
}

/// How long a machine's call for what phones sent it waits, in these tests.
const INBOX_WAIT: Duration = Duration::from_millis(500);
