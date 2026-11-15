//! A hub in this process for tests outside this module: behind a loopback proxy, so it can be made
//! unreachable and restarted at the same address, with a clock the tests move, and a phone that
//! speaks its wire as the app would.

use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
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
struct Proxy {
    address: String,
    target: Arc<Mutex<Option<String>>>,
    open: Arc<Mutex<Vec<TcpStream>>>,
}

impl Proxy {
    fn new() -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let target: Arc<Mutex<Option<String>>> = Arc::default();
        let open: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
        let (to, held) = (target.clone(), open.clone());
        thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let Some(target) = locked(&to).clone() else { continue };
                let Ok(upstream) = TcpStream::connect(&target) else { continue };
                {
                    let mut held = locked(&held);
                    held.push(client.try_clone().unwrap());
                    held.push(upstream.try_clone().unwrap());
                }
                for (mut from, mut into) in [(client.try_clone().unwrap(), upstream.try_clone().unwrap()), (upstream, client)] {
                    thread::spawn(move || {
                        let _ = io::copy(&mut from, &mut into);
                        let _ = into.shutdown(Shutdown::Write);
                    });
                }
            }
        });
        Proxy { address, target, open }
    }

    /// Points it at `target`, or nowhere; every connection open through it is cut.
    fn point(&self, target: Option<String>) {
        *locked(&self.target) = target;
        for stream in locked(&self.open).drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
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

    /// Stops these runs of `ws` on `machine`.
    pub fn stop(&self, hub: &TestHub, machine: &str, ws: &str, runs: &[RunId]) -> (u16, Value) {
        let signature = self.sign(&wire::stop_bytes(machine, ws, runs));
        let body = json!({"machine": machine, "ws": ws, "runs": runs.iter().map(RunId::hex).collect::<Vec<_>>(), "signature": util::hex(&signature)});
        hub.call("POST", "/v1/stop", Some(&self.token), Some(&body))
    }
}
