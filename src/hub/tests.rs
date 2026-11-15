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
use crate::util::TempDir;

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
    let hub = Arc::new(Hub::open(&folder, &address, pin, clock.clone()).unwrap());
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
    format!("{}{}", kind.prefix(), wire::hex(&random::<32>()))
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
            "code": wire::hex(&request.code),
            "signing_key": wire::hex(&request.signing_key),
            "agreement_key": wire::hex(&request.agreement_key),
            "key_signature": wire::hex(&request.key_signature),
            "token_hash": wire::hex(&request.token_hash),
            "push": request.push,
            "signature": wire::hex(&signature),
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
        json!({"code": wire::hex(&invite.code), "machine_key": wire::hex(&self.key.subject_public_key_info()), "token_hash": wire::hex(&wire::token_hash(&self.token))})
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
    let body = json!({"nonce": wire::hex(&nonce), "token_hash": wire::hex(&hash), "signature": wire::hex(&signature)});
    let (status, body) = hub.call("POST", "/v1/renew", Some(&phone.token), Some(&body));
    (new, status, body)
}

fn renew_machine(hub: &Running, token_: &str) -> (String, u16, Value) {
    let new = token(Kind::Machine);
    let (status, body) = hub.call("POST", "/v1/renew", Some(token_), Some(&json!({"token_hash": wire::hex(&wire::token_hash(&new))})));
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
            "renew_from": START, "renewable_until": time(90 * DAY), "conflict": null,
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
    let under_way = begin(&hub, machine("server-1")).unwrap();
    assert_eq!(begin(&hub, device("server-1", &["acme"])).err(), Some(Outcome::Taken));
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
    body["code"] = wire::hex(&pairing.invite.code).into();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&body)), (403, error("bad-signature")));
    // A push address changed after signing.
    let mut body = phone.pair_body(&pairing.invite, "fcm:abc");
    body["push"] = "fcm:other".into();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&body)), (403, error("bad-signature")));
    // The agreement key vouched for by another key.
    let mut body = phone.pair_body(&pairing.invite, "");
    let stranger = Phone::new();
    body["key_signature"] = wire::hex(&stranger.sign(&wire::keys_bytes(&phone.signing_key(), &phone.agreement.subject_public_key_info()))).into();
    assert_eq!(hub.call("POST", "/v1/pair", None, Some(&body)), (403, error("bad-signature")));
    // A key that isn't one.
    let mut body = phone.pair_body(&pairing.invite, "");
    body["signing_key"] = wire::hex(&[0u8; 91]).into();
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
    for day in [0, 1, 20, 29, 30, 31, 60, 89] {
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

#[test]
fn a_nonce_is_good_once_for_two_minutes() {
    let hub = start();
    let phone = paired_phone(&hub, "pixel");
    let sign = |nonce: &[u8; 16], hash: &[u8; 32]| phone.sign(&wire::renew_bytes(&hub.pin, "pixel", nonce, hash));
    let ask = || -> [u8; 16] { wire::unhex(hub.call("POST", "/v1/renew/nonce", Some(&phone.token), None).1["nonce"].as_str().unwrap()).unwrap() };
    let renew = |nonce: &[u8; 16], hash: &[u8; 32], signature: &[u8]| {
        hub.call("POST", "/v1/renew", Some(&phone.token), Some(&json!({"nonce": wire::hex(nonce), "token_hash": wire::hex(hash), "signature": wire::hex(signature)})))
    };
    let hash = wire::token_hash(&token(Kind::Device));
    // No nonce asked for, or another one.
    assert_eq!(renew(&[7; 16], &hash, &sign(&[7; 16], &hash)), (403, error("bad-nonce")));
    let nonce = ask();
    let mut other = nonce;
    other[0] ^= 1;
    assert_eq!(renew(&other, &hash, &sign(&other, &hash)), (403, error("bad-nonce")));
    // That try used the nonce up.
    assert_eq!(renew(&nonce, &hash, &sign(&nonce, &hash)), (403, error("bad-nonce")));
    // Too late.
    let nonce = ask();
    hub.advance(SignedDuration::from_secs(120));
    assert_eq!(renew(&nonce, &hash, &sign(&nonce, &hash)), (403, error("bad-nonce")));
    // Asking again replaces it.
    let (first, second) = (ask(), ask());
    assert_eq!(renew(&first, &hash, &sign(&first, &hash)), (403, error("bad-nonce")));
    assert_ne!(first, second);
}

/// Signs a renewal for a nonce, somehow.
type Sign<'a> = Box<dyn Fn(&[u8; 16]) -> Vec<u8> + 'a>;

#[test]
fn a_renewal_with_a_bad_signature_is_refused_and_uses_its_nonce() {
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
        ("the pairing's bytes", Box::new(|n| phone.sign(&wire::fields(&[wire::PAIR_LABEL.as_bytes(), n])))),
    ];
    for (what, sign) in attempts {
        let nonce: [u8; 16] = wire::unhex(hub.call("POST", "/v1/renew/nonce", Some(&phone.token), None).1["nonce"].as_str().unwrap()).unwrap();
        let body = json!({"nonce": wire::hex(&nonce), "token_hash": wire::hex(&hash), "signature": wire::hex(&sign(&nonce))});
        assert_eq!(hub.call("POST", "/v1/renew", Some(&phone.token), Some(&body)), (403, error("bad-signature")), "{what}");
        let right = json!({"nonce": wire::hex(&nonce), "token_hash": wire::hex(&hash), "signature": wire::hex(&phone.sign(&wire::renew_bytes(&hub.pin, "pixel", &nonce, &hash)))});
        assert_eq!(hub.call("POST", "/v1/renew", Some(&phone.token), Some(&right)), (403, error("bad-nonce")), "{what}");
    }
    // The token itself was never replaced.
    assert_eq!(hub.call("GET", "/v1/me", Some(&phone.token), None).1["issued"], json!(START));
}

#[test]
fn a_new_token_must_be_new() {
    let hub = start();
    let phone = paired_phone(&hub, "pixel");
    let nonce: [u8; 16] = wire::unhex(hub.call("POST", "/v1/renew/nonce", Some(&phone.token), None).1["nonce"].as_str().unwrap()).unwrap();
    let same = wire::token_hash(&phone.token);
    let body = json!({"nonce": wire::hex(&nonce), "token_hash": wire::hex(&same), "signature": wire::hex(&phone.sign(&wire::renew_bytes(&hub.pin, "pixel", &nonce, &same)))});
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
    // A TCP connection that never starts TLS is closed too.
    let mut tcp = TcpStream::connect(&hub.address).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(tcp.read(&mut [0; 16]).unwrap_or(0), 0);
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
    let (pin, Running { _dir: dir, .. }) = (first.pin, first);
    let mode = |name: &str| fs::metadata(folder.join(name)).unwrap().permissions().mode() & 0o777;
    assert_eq!((mode("table.json"), mode("tls-key.pem")), (0o600, 0o600));
    // The same key gives the same pin; the rows, the replaced token and the last-seen times come back.
    assert_eq!(pin_of(&tls_key(&folder).unwrap()), pin);
    let hub = Hub::open(&folder, "127.0.0.1:1", pin, clock).unwrap();
    let mut table = locked(&hub.table);
    let now = hub.now();
    assert_eq!(table.authenticate(Kind::Device, &wire::token_hash(&phone.token), false, now).map(|c| c.name), Ok("pixel".to_string()));
    assert_eq!(table.authenticate(Kind::Machine, &wire::token_hash(&new), false, now).map(|c| c.name), Ok("server-1".to_string()));
    assert_eq!(table.authenticate(Kind::Machine, &wire::token_hash(&machine_.token), false, now).err(), Some(wire::Refused::Conflict));
    drop(table);
    drop(dir);
}

#[test]
fn a_table_file_that_was_changed_by_hand_is_refused() {
    let hub = start();
    paired_phone(&hub, "pixel");
    let path = hub.folder.join("table.json");
    let text = fs::read_to_string(&path).unwrap();
    // Another agreement key, which the signing key never vouched for.
    let other = wire::hex(&KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap().subject_public_key_info());
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
