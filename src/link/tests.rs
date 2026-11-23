//! A hub, a link and open workspaces in this process, with phones made of P-256 keys: requests a
//! fake box raises go through the link and the hub to a phone, and what the phone signs comes back.
//! The open workspaces here are a desk on a socket that answers as an open workspace does
//! (`requests::told`); `boxes::keep`'s tests run the real one.

use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use halti_core::sealed::{self, AgreementKey, Kind, ReplyKey};
use jiff::SignedDuration;
use serde_json::Value;

use super::*;
use crate::hub::testing::{Phone, TestHub};
use crate::keep::{self, Records, Told};
use crate::requests::{self, By, Came, Desk, Here, Id, Limits, Prompt, Prompted, Raised, Record, RunId, Runs, answer_bytes, answer_digest};

const LONG: Duration = Duration::from_secs(30);
/// The hub's wait for a machine's inbox call, short so a test's link stops soon.
const INBOX_WAIT: Duration = Duration::from_millis(300);
const TIMING: run::Timing = run::Timing {
    look: Duration::from_millis(50),
    heartbeat: Duration::from_millis(500),
    renew_every: Duration::from_millis(200),
    retry_max: Duration::from_millis(200),
    call_wait: Duration::from_secs(10),
};
const MACHINE: &str = "server-1";
const ACTION: &str = "POST https://api.example.com/v1/x";

/// A folder under /tmp, short enough for the sockets in it; removed when dropped.
struct Short(PathBuf);

impl Short {
    fn new() -> Short {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let dir = PathBuf::from(format!("/tmp/hl-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Short(dir)
    }
}

impl Drop for Short {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Waits until `check` holds, or fails after a while.
fn until(what: &str, check: impl Fn() -> bool) {
    let deadline = Instant::now() + LONG;
    while !check() {
        assert!(Instant::now() < deadline, "never: {what}");
        thread::sleep(Duration::from_millis(50));
    }
}

/// No prompt here, as on Linux.
struct Nobody;

impl Prompt for Nobody {
    fn ask(&self, _reason: &str, _withdrawn: &dyn Fn() -> bool) -> Prompted {
        Prompted::Unshown
    }
}

/// The boxes an open workspace runs here: names and runs, gone once stopped, which takes as long as
/// the second field says.
#[derive(Default)]
struct Boxes(Mutex<Vec<(String, RunId)>>, Mutex<Duration>);

impl Runs for Boxes {
    fn runs(&self) -> Vec<(String, RunId)> {
        self.0.lock().unwrap().clone()
    }

    fn stop(&self, runs: &[RunId]) -> u32 {
        let slow = *self.1.lock().unwrap();
        thread::sleep(slow);
        let mut boxes = self.0.lock().unwrap();
        let before = boxes.len();
        boxes.retain(|(_, run)| !runs.contains(run));
        (before - boxes.len()) as u32
    }
}

/// An open workspace: its desk and boxes, answering on its socket as an open workspace does, and
/// checking against the trust list in the link's folder.
struct Keeper {
    desk: Arc<Desk>,
    boxes: Arc<Boxes>,
    socket: PathBuf,
}

impl Keeper {
    fn start(dir: &Path, folder: &Folder, ws: &str, limits: Limits) -> Keeper {
        Keeper::start_with(dir, folder, ws, Desk::new(MACHINE.into(), ws.into(), limits, Arc::new(Nobody)))
    }

    fn start_with(dir: &Path, folder: &Folder, ws: &str, desk: Arc<Desk>) -> Keeper {
        let boxes = Arc::new(Boxes::default());
        let socket = dir.join(format!("{ws}.keep.sock"));
        let listener = keep::bind(&socket).unwrap().unwrap();
        let (desk_, boxes_, folder, ws) = (desk.clone(), boxes.clone(), folder.clone(), WsName::parse(ws).unwrap());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let (desk, boxes, folder, ws) = (desk_.clone(), boxes_.clone(), folder.clone(), ws.clone());
                thread::spawn(move || {
                    let Some(line) = keep::read_line_up_to(&mut stream, keep::LINE_WAIT, keep::RECORDS_REQUEST_MAX) else { return };
                    let Some(records) = Records::parse(&line) else { return };
                    let trust = |name: &str| super::trusted_in(&folder, name);
                    let lines = if *records.ws() != ws { vec![Told::Other] } else { requests::told(&desk, &trust, &*boxes, &records) };
                    for told in lines {
                        let _ = keep::write_line(&mut stream, &told.line());
                    }
                });
            }
        });
        Keeper { desk, boxes, socket }
    }

    /// A fake box's door raises a request, and waits for what it comes to.
    fn raise(&self, box_name: &str) -> JoinHandle<Raised> {
        let asker = self.desk.asker(box_name, RunId::random());
        thread::spawn(move || asker.raise(ACTION, false, &|| false))
    }

    /// Sends what a broken hub might: a signed answer straight to this open workspace.
    fn signed(&self, ws: &str, device: &str, yes: bool, id: Id, signature: Vec<u8>) -> Option<Told> {
        keep::tell(&self.socket, &Records::Signed { ws: WsName::parse(ws).unwrap(), device: device.into(), yes, id, signature }, LONG)
    }
}

/// This machine's workspaces in the test: each open one's socket.
#[derive(Default)]
struct Locals(Mutex<Vec<(WsName, Option<PathBuf>)>>);

impl run::Local for Locals {
    fn workspaces(&self) -> Vec<(WsName, Option<PathBuf>)> {
        self.0.lock().unwrap().clone()
    }
}

/// A hub, a machine joined to it as `server-1` with its link running, and its open workspaces.
struct World {
    dir: Short,
    hub: TestHub,
    folder: Folder,
    locals: Arc<Locals>,
    keepers: Vec<(String, Keeper)>,
    link: Option<(Arc<AtomicBool>, JoinHandle<()>)>,
}

impl World {
    fn new() -> World {
        let dir = Short::new();
        let hub_dir = dir.0.join("hub");
        std::fs::DirBuilder::new().mode(0o700).create(&hub_dir).unwrap();
        let hub = TestHub::start(&hub_dir, INBOX_WAIT);
        let folder = Folder::at(&dir.0.join("link"));
        let joining = folder.clone();
        assert_eq!(hub.pair_machine(MACHINE, move |line| join_at(&joining, line).map(drop)), crate::hub::testing::Outcome::Paired);
        let mut world = World { dir, hub, folder, locals: Arc::default(), keepers: Vec::new(), link: None };
        world.start_link();
        world
    }

    fn start_link(&mut self) {
        let stop = Arc::new(AtomicBool::new(false));
        let (folder, locals, stopping) = (self.folder.clone(), self.locals.clone(), stop.clone());
        let running = thread::spawn(move || run::run(&folder, &*locals, TIMING, &stopping).unwrap());
        self.link = Some((stop, running));
        until("the link listens", || self.folder.socket().exists());
    }

    fn stop_link(&mut self) {
        let (stop, running) = self.link.take().unwrap();
        stop.store(true, Ordering::SeqCst);
        running.join().unwrap();
    }

    /// Opens workspace `ws` here, with a request's wait as `limits` says.
    fn open(&mut self, ws: &str, limits: Limits) {
        let keeper = Keeper::start(&self.dir.0, &self.folder, ws, limits);
        self.opened(ws, keeper);
    }

    fn opened(&mut self, ws: &str, keeper: Keeper) {
        self.locals.0.lock().unwrap().push((WsName::parse(ws).unwrap(), Some(keeper.socket.clone())));
        self.keepers.push((ws.to_string(), keeper));
    }

    fn keeper(&self, ws: &str) -> &Keeper {
        &self.keepers.iter().find(|(name, _)| name == ws).unwrap().1
    }

    /// Trusts `phone` here for `ws`, both comparisons said same.
    fn trust(&self, phone: &Phone, ws: &[&str]) -> Trusting {
        let fingerprint = phone.fingerprint();
        let ws: Vec<String> = ws.iter().map(|ws| ws.to_string()).collect();
        trust_at(&self.folder, &phone.name, &ws, &|question| {
            assert_eq!(question, format!("device {}, fingerprint {fingerprint}: same as on the phone?", phone.name));
            Ok(true)
        })
        .unwrap()
    }

    fn joined(&self) -> Joined {
        self.folder.joined().unwrap().unwrap()
    }

    /// The one request `phone` is shown, once it is.
    fn shown(&self, phone: &Phone) -> Vec<u8> {
        until("the phone is shown the request", || phone.requests(&self.hub).len() == 1);
        let (machine, record) = phone.requests(&self.hub).remove(0);
        assert_eq!(machine, MACHINE);
        record
    }

    /// What the machine said came of item `n` that `phone` sent, once it said anything.
    fn said(&self, phone: &Phone, n: u64) -> String {
        let state = || phone.state(&self.hub)["sent"].as_array().unwrap().iter().find(|sent| sent["n"] == n).map(|sent| sent["state"].as_str().unwrap().to_string());
        until("the machine says what came of it", || state().is_some_and(|state| state != "queued" && state != "taken"));
        state().unwrap()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        if self.link.is_some() {
            self.stop_link();
        }
    }
}

fn limits() -> Limits {
    requests::LIMITS
}

/// The device `By` of a request a phone answered.
fn by_device(came: &Came) -> &requests::Signed {
    match came {
        Came::Yes(By::Device(signed)) | Came::No(By::Device(signed)) => signed,
        other => panic!("not a device's answer: {other:?}"),
    }
}

// --- joining and trust ---

#[test]
fn a_join_keeps_the_machine_key_and_a_leave_forgets_the_hub() {
    let world = World::new();
    let key = world.folder.machine_key().unwrap().unwrap().subject_public_key_info();
    let joined = world.joined();
    assert_eq!((joined.name.as_str(), joined.address.as_str(), joined.next.as_ref()), (MACHINE, world.hub.address.as_str(), None));
    assert!(joined.token.starts_with("halti_mach_") && joined.token.len() == 75);
    let mode = |name: &str| std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(world.dir.0.join("link").join(name)).unwrap().permissions()) & 0o777;
    assert_eq!((mode("link.json"), mode("machine-key.pem"), mode("")), (0o600, 0o600, 0o700));
    // The hub has the machine's key.
    let phone = world.hub.pair_phone("pixel", &["acme"]);
    world.trust(&phone, &["acme"]);
    until("the hub reports the machine", || phone.state(&world.hub)["machines"].as_array().unwrap().len() == 1);
    assert_eq!(phone.state(&world.hub)["machines"][0]["key"], hex(&key));
    // A second join, after the first expired, keeps the key: a new token, the same key.
    world.hub.advance(SignedDuration::from_hours(31 * 24));
    let folder = world.folder.clone();
    world.hub.pair_machine(MACHINE, move |line| join_at(&folder, line).map(drop));
    assert_eq!(world.folder.machine_key().unwrap().unwrap().subject_public_key_info(), key);
    assert_ne!(world.joined().token, joined.token);
    // A phone's pairing string is not a machine's, and a string that isn't one is refused.
    let invite = wire::Invite { kind: wire::Kind::Device, address: world.hub.address.clone(), pin: world.hub.pin, code: [1; 16] };
    assert!(join_at(&world.folder, &invite.to_string()).unwrap_err().to_string().contains("pairs a phone"));
    assert!(join_at(&world.folder, "halti-pair/1/machine/x").is_err());
    // Leave forgets the hub, the token and the key; the trust list stays.
    assert!(world.folder.leave().unwrap());
    assert!(world.folder.joined().unwrap().is_none() && world.folder.machine_key().unwrap().is_none());
    assert_eq!(world.folder.trust().unwrap().len(), 1);
    assert!(!world.folder.leave().unwrap());
}

#[test]
fn trust_takes_the_fingerprint_and_shows_the_machine_code_the_phone_computes() {
    let mut world = World::new();
    world.open("acme", limits());
    let phone = world.hub.pair_phone("pixel", &["acme", "beta"]);
    // Said no: nothing is trusted.
    let ws = vec!["acme".to_string()];
    let said = trust_at(&world.folder, "pixel", &ws, &|_| Ok(false)).err().unwrap();
    assert_eq!(said.to_string(), "pixel was not trusted");
    assert!(world.folder.trust().unwrap().is_empty());
    // A workspace the phone may not see at the hub, and a phone the hub doesn't have.
    let said = trust_at(&world.folder, "pixel", &["globex".to_string()], &|_| Ok(true)).err().unwrap();
    assert_eq!(said.to_string(), "pixel may not see globex at the hub: pair it there with --ws including globex");
    let said = trust_at(&world.folder, "tablet", &ws, &|_| Ok(true)).err().unwrap();
    assert_eq!(said.to_string(), "the hub has no phone named tablet: halti devices on the hub lists them");
    // Said yes: the code over the machine's name, its key and the workspaces, as the phone gets them
    // from the hub.
    let trusting = world.trust(&phone, &["acme"]);
    assert_eq!((trusting.ws.clone(), trusting.unsynced.clone()), (ws.clone(), None));
    let state = phone.state(&world.hub);
    let machine = &state["machines"][0];
    assert_eq!((machine["name"].as_str(), machine["ws"].clone()), (Some(MACHINE), json!(["acme"])));
    let key = util::unhex(machine["key"].as_str().unwrap()).unwrap();
    assert_eq!(wire::machine_code(MACHINE, &key, &ws), trusting.code);
    assert_eq!(machine["workspaces"], json!([{"name": "acme", "open": true, "runs": []}]));
    // More workspaces later: the code is over all of them.
    let both = world.trust(&phone, &["beta"]);
    assert_eq!(both.ws, ["acme", "beta"]);
    assert_eq!(both.code, wire::machine_code(MACHINE, &key, &["beta".into(), "acme".into()]));
    // The same name with other keys is refused until it is untrusted. A running link would drop
    // such an entry at once, as the hub lists other keys: here one that only answers `device`.
    let entry = world.folder.trust().unwrap().remove(0);
    world.stop_link();
    let joined = world.joined();
    let (status, listed) = world.hub.call("POST", "/v1/machine/device", Some(&joined.token), Some(&json!({"name": "pixel"})));
    assert_eq!(status, 200);
    let listener = keep::bind(&world.folder.socket()).unwrap().unwrap();
    let answering = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        keep::read_line_up_to(&mut stream, LONG, run::LINE_MAX).unwrap();
        keep::write_line(&mut stream, &format!("halti-link/1 device {listed}\n")).unwrap();
    });
    let other = hex(&Phone::new("x").signing_key());
    world.folder.change_trust(|entries| ((), std::mem::replace(&mut entries[0].signing_key, other.clone()) != other)).unwrap();
    assert!(trust_at(&world.folder, "pixel", &ws, &|_| Ok(true)).err().unwrap().to_string().starts_with("pixel is trusted here with other keys"));
    answering.join().unwrap();
    assert!(untrust_at(&world.folder, "pixel").unwrap());
    assert!(!untrust_at(&world.folder, "pixel").unwrap());
    let _ = std::fs::remove_file(world.folder.socket());
    world.start_link();
    world.trust(&phone, &["acme"]);
    assert_eq!(world.folder.trust().unwrap()[0].signing_key, entry.signing_key);
}

#[test]
fn text_is_sealed_with_the_keys_of_the_join_and_the_trust() {
    let world = World::new();
    let phone = world.hub.pair_phone("pixel", &["acme"]);
    world.trust(&phone, &["acme"]);
    // The machine key `hub join` made, and the second key `devices trust` kept: nothing is paired,
    // joined or trusted again.
    let machine = world.folder.sealing_key().unwrap().unwrap();
    assert_eq!(machine.public().spki().to_vec(), world.folder.machine_key().unwrap().unwrap().subject_public_key_info());
    let entry = world.folder.trust().unwrap().remove(0);
    let second = entry.second_key().unwrap();
    assert_eq!(second.spki().to_vec(), phone.agreement_key());
    // The phone has the machine key as the hub passed it on, which it compared.
    until("the hub reports the machine", || phone.state(&world.hub)["machines"].as_array().unwrap().len() == 1);
    let compared = AgreementKey::from_spki(&util::unhex(phone.state(&world.hub)["machines"][0]["key"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(compared, machine.public());
    // A question opens on the phone, under that key.
    let clear = b"halti-question-v1 server-1 acme dev";
    let question = sealed::seal(Kind::Question, &machine, &second, clear, b"Run the tests?", &util::random()).unwrap();
    assert_eq!(sealed::open(Kind::Question, &phone.second_key(), &compared, clear, &question).unwrap().as_slice(), b"Run the tests?");
    // Its answer goes to the question's reply key, which the machine key can't stand in for.
    let reply = ReplyKey::make(&util::random());
    let answer = sealed::seal(Kind::Answer, &phone.second_key(), &reply.public(), clear, b"yes", &util::random()).unwrap();
    assert_eq!(reply.open(&second, clear, &answer).unwrap().as_slice(), b"yes");
    assert_eq!(sealed::open(Kind::Answer, &machine, &second, clear, &answer).unwrap_err(), halti_core::refusal::Refusal::Unreadable);
    // An entry whose signing key doesn't vouch for its second key gives none.
    let other = Entry { agreement_key: hex(&Phone::new("x").agreement_key()), ..entry.clone() };
    assert_eq!(other.second_key(), None);
    // After a leave there is no machine key to seal with.
    assert!(world.folder.leave().unwrap());
    assert!(world.folder.sealing_key().unwrap().is_none());
}

// --- answers ---

#[test]
fn a_phone_approves_and_denies_with_its_signature() {
    let mut world = World::new();
    world.open("acme", limits());
    let phone = world.hub.pair_phone("pixel", &["acme"]);
    world.trust(&phone, &["acme"]);
    for yes in [true, false] {
        let raised = world.keeper("acme").raise("dev");
        let record = world.shown(&phone);
        let decoded = Record::decode(&record).unwrap();
        assert_eq!((decoded.machine.as_str(), decoded.ws.as_str(), decoded.box_name.as_str(), decoded.action.as_str()), (MACHINE, "acme", "dev", ACTION));
        let (status, body) = phone.answer(&world.hub, MACHINE, &record, yes);
        assert_eq!(status, 202, "{body}");
        let came = raised.join().unwrap().came;
        assert!(if yes { matches!(came, Came::Yes(_)) } else { matches!(came, Came::No(_)) }, "{came:?}");
        let signed = by_device(&came);
        assert_eq!((signed.device.as_str(), signed.fingerprint.clone(), &signed.record), ("pixel", phone.fingerprint(), &record));
        assert_eq!(By::Device(Arc::new(signed.clone())).word(), format!("pixel {}", phone.fingerprint()));
        // What it signed is what the log keeps, and checks from it alone.
        assert!(halti_core::device::DeviceKey::from_spki(&phone.signing_key()).unwrap().verify(&answer_bytes(&signed.record, yes), &signed.signature).is_ok());
        assert_eq!(world.said(&phone, body["n"].as_u64().unwrap()), if yes { "approved" } else { "denied" });
        until("the request leaves the phone's list", || phone.requests(&world.hub).is_empty());
    }
}

#[test]
fn nothing_a_hub_or_a_token_holder_could_forge_counts() {
    let mut world = World::new();
    world.open("acme", limits());
    world.open("beta", limits());
    let pixel = world.hub.pair_phone("pixel", &["acme"]);
    let tablet = world.hub.pair_phone("tablet", &["acme"]);
    let watch = world.hub.pair_phone("watch", &["acme", "beta"]);
    world.trust(&pixel, &["acme"]);
    world.trust(&watch, &["beta"]);
    let raised = world.keeper("acme").raise("dev");
    let record = world.shown(&pixel);
    let id = Record::decode(&record).unwrap().id;
    let keeper = world.keeper("acme");

    // Another key's signature under pixel's name: the hub refuses it, and so does the machine.
    assert_eq!(pixel.answer_signed_by(&tablet, &world.hub, MACHINE, &record, true), (403, json!({"error": "bad-signature"})));
    assert_eq!(keeper.signed("acme", "pixel", true, id, tablet.sign(&answer_bytes(&record, true))), Some(Told::Refused));
    // A device the hub knows and this machine doesn't trust: delivered, refused here.
    let (status, body) = tablet.answer(&world.hub, MACHINE, &record, true);
    assert_eq!(status, 202);
    assert_eq!(world.said(&tablet, body["n"].as_u64().unwrap()), "refused");
    // A device trusted here for another workspace.
    let (status, body) = watch.answer(&world.hub, MACHINE, &record, true);
    assert_eq!(status, 202);
    assert_eq!(world.said(&watch, body["n"].as_u64().unwrap()), "refused");
    // A signature over the same request said to be another workspace's, or another machine's: it is
    // not over this machine's record.
    let as_beta = Record { ws: "beta".into(), ..Record::decode(&record).unwrap() }.encode().unwrap();
    let as_other = Record { machine: "server-2".into(), ..Record::decode(&record).unwrap() }.encode().unwrap();
    for other in [&as_beta, &as_other] {
        assert_eq!(keeper.signed("acme", "pixel", true, id, pixel.sign(&answer_bytes(other, true))), Some(Told::Refused));
    }
    assert_eq!(world.keeper("beta").signed("beta", "watch", true, id, watch.sign(&answer_bytes(&record, true))), Some(Told::Gone), "beta has no such request");
    assert_eq!(keeper.signed("beta", "watch", true, id, watch.sign(&answer_bytes(&record, true))), Some(Told::Other), "acme acts only on its own name");
    // The hub holds the request for server-1 only, not for another machine paired with it.
    let elsewhere = Folder::at(&world.dir.0.join("elsewhere"));
    world.hub.pair_machine("server-2", move |line| join_at(&elsewhere, line).map(drop));
    assert_eq!(pixel.answer(&world.hub, "server-2", &record, true), (410, json!({"error": "gone"})));
    // The signature for "no" is not one for "yes".
    assert_eq!(keeper.signed("acme", "pixel", true, id, pixel.sign(&answer_bytes(&record, false))), Some(Told::Refused));
    // None of it counted: the request still waits, and the right answer wins.
    assert_eq!(keeper.desk.records(), vec![record.clone()]);
    let (status, body) = pixel.answer(&world.hub, MACHINE, &record, true);
    assert_eq!(status, 202);
    assert!(matches!(raised.join().unwrap().came, Came::Yes(By::Device(_))));
    assert_eq!(world.said(&pixel, body["n"].as_u64().unwrap()), "approved");

    // Sent again, the answer finds nothing: at the hub once the machine says it is gone, and here.
    until("the hub drops the answered request", || pixel.requests(&world.hub).is_empty());
    assert_eq!(pixel.answer(&world.hub, MACHINE, &record, true), (410, json!({"error": "gone"})));
    assert_eq!(keeper.signed("acme", "pixel", true, id, pixel.sign(&answer_bytes(&record, true))), Some(Told::Gone));
    // An old signature for a new request is no signature for it.
    let raised = keeper.raise("dev");
    let new = world.shown(&pixel);
    let new_id = Record::decode(&new).unwrap().id;
    let old = pixel.sign(&answer_bytes(&record, true));
    let body = json!({"machine": MACHINE, "id": new_id.hex(), "decision": "yes", "signature": hex(&old)});
    assert_eq!(world.hub.call("POST", "/v1/answer", Some(&pixel.token), Some(&body)), (403, json!({"error": "bad-signature"})));
    assert_eq!(keeper.signed("acme", "pixel", true, new_id, old), Some(Told::Refused));
    // A token alone closes the remote copy and nothing else: the machine still waits, and answers.
    assert_eq!(world.hub.call("POST", "/v1/hide", Some(&tablet.token), Some(&json!({"machine": MACHINE, "id": new_id.hex()}))).0, 200);
    assert!(pixel.requests(&world.hub).is_empty());
    assert_eq!(pixel.answer(&world.hub, MACHINE, &new, true).0, 410);
    assert_eq!(keeper.desk.answer_here(true, &answer_digest(&new, true)), Here::Approved);
    assert_eq!(raised.join().unwrap().came, Came::Yes(By::Local));
}

#[test]
fn a_revoked_or_untrusted_device_counts_for_nothing() {
    let mut world = World::new();
    world.open("acme", limits());
    let pixel = world.hub.pair_phone("pixel", &["acme"]);
    let tablet = world.hub.pair_phone("tablet", &["acme"]);
    world.trust(&pixel, &["acme"]);
    world.trust(&tablet, &["acme"]);
    // Revoked at the hub: the machine drops it at its next report, and refuses what it signed.
    assert!(world.hub.revoke("pixel"));
    until("the machine drops the revoked phone", || world.folder.trust().unwrap().iter().all(|entry| entry.name != "pixel"));
    assert_eq!(world.hub.call("GET", "/v1/me", Some(&pixel.token), None).0, 401);
    let raised = world.keeper("acme").raise("dev");
    let record = world.shown(&tablet);
    let id = Record::decode(&record).unwrap().id;
    let keeper = world.keeper("acme");
    assert_eq!(keeper.signed("acme", "pixel", true, id, pixel.sign(&answer_bytes(&record, true))), Some(Told::Refused));
    // Untrusted here, with no hub to ask: refused at once.
    world.hub.reachable(false);
    assert!(untrust_at(&world.folder, "tablet").unwrap());
    assert_eq!(keeper.signed("acme", "tablet", true, id, tablet.sign(&answer_bytes(&record, true))), Some(Told::Refused));
    assert_eq!(keeper.desk.answer_here(false, &answer_digest(&record, false)), Here::Denied);
    assert_eq!(raised.join().unwrap().came, Came::No(By::Local));
    // One revoked and one untrusted: none is left.
    assert!(world.folder.trust().unwrap().is_empty());
}

#[test]
fn an_answer_after_its_request_expired_is_gone() {
    let mut world = World::new();
    world.open("acme", Limits { wait: Duration::from_secs(5), ..limits() });
    let phone = world.hub.pair_phone("pixel", &["acme"]);
    world.trust(&phone, &["acme"]);
    let raised = world.keeper("acme").raise("dev");
    let record = world.shown(&phone);
    assert_eq!(raised.join().unwrap().came, Came::Expired);
    let id = Record::decode(&record).unwrap().id;
    assert_eq!(world.keeper("acme").signed("acme", "pixel", true, id, phone.sign(&answer_bytes(&record, true))), Some(Told::Gone));
    until("the hub drops the expired request", || phone.requests(&world.hub).is_empty());
    assert_eq!(phone.answer(&world.hub, MACHINE, &record, true), (410, json!({"error": "gone"})));
}

// --- stops ---

#[test]
fn a_signed_stop_stops_its_runs_and_says_so() {
    let mut world = World::new();
    world.open("acme", limits());
    let pixel = world.hub.pair_phone("pixel", &["acme"]);
    let tablet = world.hub.pair_phone("tablet", &["acme"]);
    world.trust(&pixel, &["acme"]);
    let (dev, web) = (RunId([1; 8]), RunId([2; 8]));
    *world.keeper("acme").boxes.0.lock().unwrap() = vec![("dev".into(), dev), ("web".into(), web)];
    let runs = || pixel.state(&world.hub)["machines"][0]["workspaces"][0]["runs"].clone();
    until("the phone sees what runs", || runs() == json!([{"box": "dev", "run": dev.hex()}, {"box": "web", "run": web.hex()}]));
    let (status, body) = pixel.stop(&world.hub, MACHINE, "acme", &[("dev", dev)]);
    assert_eq!(status, 202);
    let n = body["n"].as_u64().unwrap();
    assert_eq!(world.said(&pixel, n), "stopped");
    assert_eq!(world.keeper("acme").boxes.runs(), vec![("web".to_string(), web)]);
    let sent = pixel.state(&world.hub)["sent"].as_array().unwrap().iter().find(|sent| sent["n"] == n).unwrap().clone();
    assert_eq!((sent["kind"].as_str(), sent["ws"].as_str(), sent["runs"].clone()), (Some("stop"), Some("acme"), json!([{"box": "dev", "run": dev.hex()}])));
    // Sent again, it stops nothing new.
    let (_, body) = pixel.stop(&world.hub, MACHINE, "acme", &[("dev", dev)]);
    assert_eq!(world.said(&pixel, body["n"].as_u64().unwrap()), "none");
    // From a device not trusted here, or with another's signature: nothing stops.
    let (_, body) = tablet.stop(&world.hub, MACHINE, "acme", &[("web", web)]);
    assert_eq!(world.said(&tablet, body["n"].as_u64().unwrap()), "refused");
    let named = vec![("web".to_string(), web)];
    let forged = json!({"machine": MACHINE, "ws": "acme", "runs": [{"box": "web", "run": web.hex()}], "signature": hex(&tablet.sign(&wire::stop_bytes(MACHINE, "acme", &named)))});
    assert_eq!(world.hub.call("POST", "/v1/stop", Some(&pixel.token), Some(&forged)), (403, json!({"error": "bad-signature"})));
    // A body whose box isn't the one signed is refused at the hub.
    let swapped = json!({"machine": MACHINE, "ws": "acme", "runs": [{"box": "dev", "run": web.hex()}], "signature": hex(&pixel.sign(&wire::stop_bytes(MACHINE, "acme", &named)))});
    assert_eq!(world.hub.call("POST", "/v1/stop", Some(&pixel.token), Some(&swapped)), (403, json!({"error": "bad-signature"})));
    // A stop signed for another machine's name stops nothing here.
    let other = pixel.sign(&wire::stop_bytes("server-2", "acme", &named));
    let line = Records::Stop { ws: WsName::parse("acme").unwrap(), device: "pixel".into(), runs: named.clone(), signature: other };
    assert_eq!(keep::tell(&world.keeper("acme").socket, &line, LONG), Some(Told::Refused));
    // A workspace outside the phone's is gone at the hub.
    assert_eq!(pixel.stop(&world.hub, MACHINE, "beta", &[("web", web)]).0, 410);
    assert_eq!(world.keeper("acme").boxes.runs(), vec![("web".to_string(), web)]);
}

#[test]
fn a_stop_that_names_a_run_with_another_box_leaves_that_run() {
    let mut world = World::new();
    world.open("acme", limits());
    let pixel = world.hub.pair_phone("pixel", &["acme"]);
    world.trust(&pixel, &["acme"]);
    let (dev, prod) = (RunId([1; 8]), RunId([2; 8]));
    *world.keeper("acme").boxes.0.lock().unwrap() = vec![("dev".into(), dev), ("prod".into(), prod)];
    until("the phone sees what runs", || pixel.state(&world.hub)["machines"][0]["workspaces"][0]["runs"].as_array().unwrap().len() == 2);
    // A hub that showed prod's run as a box named scratch gets a stop of "scratch" signed: prod runs
    // on, and the machine says so. dev, named with its own box, is stopped.
    let (status, body) = pixel.stop(&world.hub, MACHINE, "acme", &[("dev", dev), ("scratch", prod)]);
    assert_eq!(status, 202);
    assert_eq!(world.said(&pixel, body["n"].as_u64().unwrap()), "wrong-box");
    assert_eq!(world.keeper("acme").boxes.runs(), vec![("prod".to_string(), prod)]);
    // Named alone with another box, nothing is stopped.
    let (_, body) = pixel.stop(&world.hub, MACHINE, "acme", &[("dev", prod)]);
    assert_eq!(world.said(&pixel, body["n"].as_u64().unwrap()), "wrong-box");
    assert_eq!(world.keeper("acme").boxes.runs(), vec![("prod".to_string(), prod)]);
    // Named with its own box, it is.
    let (_, body) = pixel.stop(&world.hub, MACHINE, "acme", &[("prod", prod)]);
    assert_eq!(world.said(&pixel, body["n"].as_u64().unwrap()), "stopped");
    assert!(world.keeper("acme").boxes.runs().is_empty());
}

#[test]
fn stop_all_stops_every_run_on_a_machine() {
    let mut world = World::new();
    world.open("acme", limits());
    world.open("beta", limits());
    let phone = world.hub.pair_phone("pixel", &["acme", "beta"]);
    world.trust(&phone, &["acme", "beta"]);
    *world.keeper("acme").boxes.0.lock().unwrap() = vec![("dev".into(), RunId([1; 8])), ("web".into(), RunId([2; 8]))];
    *world.keeper("beta").boxes.0.lock().unwrap() = vec![("dev".into(), RunId([3; 8]))];
    let running = || -> usize {
        let state = phone.state(&world.hub);
        state["machines"][0]["workspaces"].as_array().unwrap().iter().map(|ws| ws["runs"].as_array().unwrap().len()).sum()
    };
    until("the phone sees all three", || running() == 3);
    // What the app does for "stop all": one stop for each workspace, of every run it shows.
    let state = phone.state(&world.hub);
    let mut sent = Vec::new();
    for ws in state["machines"][0]["workspaces"].as_array().unwrap() {
        let runs: Vec<(&str, RunId)> =
            ws["runs"].as_array().unwrap().iter().map(|run| (run["box"].as_str().unwrap(), RunId::parse(run["run"].as_str().unwrap()).unwrap())).collect();
        let (status, body) = phone.stop(&world.hub, MACHINE, ws["name"].as_str().unwrap(), &runs);
        assert_eq!(status, 202);
        sent.push(body["n"].as_u64().unwrap());
    }
    for n in sent {
        assert_eq!(world.said(&phone, n), "stopped");
    }
    assert!(world.keeper("acme").boxes.runs().is_empty() && world.keeper("beta").boxes.runs().is_empty());
    until("the phone sees none run", || running() == 0);
}

// --- restarts and outages ---

#[test]
fn a_request_outlives_a_hub_restart() {
    let mut world = World::new();
    world.open("acme", limits());
    let phone = world.hub.pair_phone("pixel", &["acme"]);
    world.trust(&phone, &["acme"]);
    let raised = world.keeper("acme").raise("dev");
    let record = world.shown(&phone);
    world.hub.restart();
    // The new hub holds nothing until the link reports, is told what it lacks, and posts it again.
    assert_eq!(world.shown(&phone), record);
    let (status, _) = phone.answer(&world.hub, MACHINE, &record, true);
    assert_eq!(status, 202);
    assert!(matches!(raised.join().unwrap().came, Came::Yes(By::Device(_))));
}

#[test]
fn a_request_outlives_a_link_restart() {
    let mut world = World::new();
    world.open("acme", limits());
    let phone = world.hub.pair_phone("pixel", &["acme"]);
    world.trust(&phone, &["acme"]);
    let raised = world.keeper("acme").raise("dev");
    let record = world.shown(&phone);
    let since = phone.state(&world.hub)["machines"][0]["since"].clone();
    world.stop_link();
    world.hub.advance(SignedDuration::from_secs(5));
    // An answer sent while no link runs waits at the hub.
    let (status, body) = phone.answer(&world.hub, MACHINE, &record, true);
    assert_eq!(status, 202);
    world.start_link();
    assert!(matches!(raised.join().unwrap().came, Came::Yes(By::Device(_))));
    assert_eq!(world.said(&phone, body["n"].as_u64().unwrap()), "approved");
    // The hub tells the phone the link started again.
    until("the phone sees the restart", || phone.state(&world.hub)["machines"][0]["since"] != since);
}

#[test]
fn with_the_hub_unreachable_requests_are_answered_here() {
    let mut world = World::new();
    world.open("acme", limits());
    let phone = world.hub.pair_phone("pixel", &["acme"]);
    world.trust(&phone, &["acme"]);
    world.hub.reachable(false);
    let keeper = world.keeper("acme");
    let raised = keeper.raise("dev");
    until("it waits", || keeper.desk.records().len() == 1);
    let record = keeper.desk.records().remove(0);
    assert_eq!(keeper.desk.answer_here(true, &answer_digest(&record, true)), Here::Approved);
    assert_eq!(raised.join().unwrap().came, Came::Yes(By::Local));
    // Once the hub is back, the next request reaches the phone.
    world.hub.reachable(true);
    let raised = keeper.raise("dev");
    let record = world.shown(&phone);
    assert_eq!(phone.answer(&world.hub, MACHINE, &record, false).0, 202);
    assert!(matches!(raised.join().unwrap().came, Came::No(By::Device(_))));
}

// --- the machine token ---

#[test]
fn the_link_renews_its_token_from_day_10() {
    let world = World::new();
    let first = world.joined().token;
    world.hub.advance(SignedDuration::from_hours(9 * 24));
    thread::sleep(Duration::from_millis(600));
    assert_eq!(world.joined().token, first, "not before day 10");
    world.hub.advance(SignedDuration::from_hours(24));
    until("the link renews", || world.joined().token != first);
    let joined = world.joined();
    assert_eq!(joined.next, None);
    let (status, me) = world.hub.call("GET", "/v1/me", Some(&joined.token), None);
    assert_eq!((status, &me["conflict"], &me["issued"]), (200, &Value::Null, &json!(wire::time(world.hub.now()))));
    // The link goes on with the new one, and no copy was seen.
    thread::sleep(Duration::from_millis(600));
    let row = world.hub.rows().into_iter().find(|row| row.name == MACHINE).unwrap();
    assert_eq!(row.conflict_since, None);
}

#[test]
fn a_renewal_whose_reply_was_lost_is_found_by_its_new_token() {
    let mut world = World::new();
    world.stop_link();
    let joined = world.joined();
    world.hub.advance(SignedDuration::from_hours(10 * 24));
    // The hub took the renewal; the link wrote the new token down and never saw the reply.
    let new = format!("halti_mach_{}", hex(&util::random::<32>()));
    let (status, _) = world.hub.call("POST", "/v1/renew", Some(&joined.token), Some(&json!({"token_hash": hex(&wire::token_hash(&new))})));
    assert_eq!(status, 200);
    world.folder.write_joined(&Joined { next: Some(new.clone()), ..joined.clone() }).unwrap();
    world.start_link();
    until("the link takes the new token", || world.joined().token == new);
    assert_eq!(world.joined().next, None);
    thread::sleep(Duration::from_millis(600));
    assert_eq!(world.hub.rows().into_iter().find(|row| row.name == MACHINE).unwrap().conflict_since, None);
    // One the hub never took is dropped, and the token it holds goes on.
    world.stop_link();
    let held = world.joined();
    let never = format!("halti_mach_{}", hex(&util::random::<32>()));
    world.folder.write_joined(&Joined { next: Some(never), ..held.clone() }).unwrap();
    world.start_link();
    until("the link drops it", || world.joined().next.is_none());
    assert_eq!(world.joined().token, held.token);
    assert_eq!(world.folder.refused(), None, "the hub not knowing it is no refusal of the token held");
    assert_eq!(world.hub.call("GET", "/v1/me", Some(&held.token), None).0, 200);
}

#[test]
fn a_token_the_hub_refuses_is_noted_until_it_works_again() {
    let world = World::new();
    assert_eq!(world.folder.refused(), None);
    assert!(world.hub.revoke(MACHINE));
    until("the link notes it", || world.folder.refused().as_deref() == Some("unknown"));
    // Joined again: the note goes.
    let folder = world.folder.clone();
    world.hub.pair_machine(MACHINE, move |line| join_at(&folder, line).map(drop));
    assert_eq!(world.folder.refused(), None);
}

// --- what is read from the hub, and the service ---

#[test]
fn a_phone_on_the_hub_s_list_is_read_whole_or_not_at_all() {
    let key = hex(&Phone::new("x").signing_key());
    let good = json!({"name": "pixel", "signing_key": key, "agreement_key": key, "key_signature": "3006020101020101", "ws": ["acme"]});
    assert_eq!(Listed::read(&good).map(|listed| listed.json()), Some(good.clone()));
    let changed = |field: &str, value: Value| {
        let mut changed = good.clone();
        changed[field] = value;
        changed
    };
    let mut extra = good.clone();
    extra["push"] = "x".into();
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("ws");
    for bad in [
        extra,
        missing,
        changed("name", "Pixel".into()),
        changed("signing_key", key[..180].into()),
        changed("agreement_key", key.to_uppercase().into()),
        changed("key_signature", "".into()),
        changed("key_signature", "30".repeat(73).into()),
        changed("ws", json!(["Acme"])),
        changed("ws", json!("acme")),
    ] {
        assert_eq!(Listed::read(&bad), None, "{bad}");
    }
    // One entry that isn't one makes the whole list none, which changes no trust.
    let list = json!([good, {"name": "tablet"}]);
    assert_eq!(list.as_array().unwrap().iter().map(Listed::read).collect::<Option<Vec<_>>>(), None);
}

#[test]
fn the_service_unit_runs_the_link_as_the_box_running_user() {
    let unit = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("service/halti-link@.service")).unwrap();
    let lines: Vec<&str> = unit.lines().collect();
    for line in [
        "User=%i",
        "ExecStart=/usr/local/bin/halti link",
        "Restart=always",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "UMask=0077",
    ] {
        assert!(lines.contains(&line), "{line}");
    }
    // Its /tmp is the system's, where the open workspaces' sockets are, and its home is its own.
    assert!(!lines.iter().any(|line| line.starts_with("PrivateTmp=yes") || line.starts_with("ProtectHome=") || line.starts_with("User=root")));
}

// --- what review found ---

/// Since when the hub marks this machine's token as used from two places.
fn conflict(world: &World) -> Option<jiff::Timestamp> {
    world.hub.rows().into_iter().find(|row| row.name == MACHINE).unwrap().conflict_since
}

/// With the link stopped, the hub takes a renewal on day 10 whose reply the link never saw: it
/// holds the new token as the next one. The new token.
fn renewed_unseen(world: &mut World) -> String {
    world.stop_link();
    let joined = world.joined();
    world.hub.advance(SignedDuration::from_hours(10 * 24));
    let new = format!("halti_mach_{}", hex(&util::random::<32>()));
    let (status, _) = world.hub.call("POST", "/v1/renew", Some(&joined.token), Some(&json!({"token_hash": hex(&wire::token_hash(&new))})));
    assert_eq!(status, 200);
    world.folder.write_joined(&Joined { next: Some(new.clone()), ..joined }).unwrap();
    new
}

#[test]
fn a_lost_reply_to_the_new_token_s_first_call_marks_no_conflict() {
    let mut world = World::new();
    let new = renewed_unseen(&mut world);
    // For a while every call reaches the hub and no reply comes back: the hub sees the new token
    // used, and the link doesn't learn it.
    world.hub.lose_replies(true);
    world.start_link();
    thread::sleep(Duration::from_millis(1500));
    world.hub.lose_replies(false);
    until("the link takes the new token", || world.joined().token == new);
    thread::sleep(Duration::from_millis(600));
    assert_eq!(conflict(&world), None, "the old token was sent after the new one was used");
}

#[test]
fn the_old_token_is_not_sent_while_the_new_one_waits_to_be_tried() {
    let mut world = World::new();
    let phone = world.hub.pair_phone("pixel", &["slow"]);
    world.trust(&phone, &["slow"]);
    // An open workspace that never answers, so each look at it takes a while.
    let socket = world.dir.0.join("slow.keep.sock");
    let listener = keep::bind(&socket).unwrap().unwrap();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
    world.locals.0.lock().unwrap().push((WsName::parse("slow").unwrap(), Some(socket)));
    let new = renewed_unseen(&mut world);
    world.hub.reachable(false);
    world.start_link();
    thread::sleep(Duration::from_millis(400));
    // The hub is back more than a day later: the old token's 24 hours are over.
    world.hub.advance(SignedDuration::from_hours(25));
    world.hub.reachable(true);
    until("the link takes the new token", || world.joined().token == new);
    thread::sleep(Duration::from_millis(600));
    assert_eq!(conflict(&world), None, "the old token was sent before the new one was tried");
}

#[test]
fn a_slow_stop_holds_up_no_answer() {
    let mut world = World::new();
    world.open("acme", limits());
    let pixel = world.hub.pair_phone("pixel", &["acme"]);
    world.trust(&pixel, &["acme"]);
    let dev = RunId([1; 8]);
    *world.keeper("acme").boxes.0.lock().unwrap() = vec![("dev".into(), dev)];
    *world.keeper("acme").boxes.1.lock().unwrap() = Duration::from_secs(3);
    until("the phone sees what runs", || pixel.state(&world.hub)["machines"][0]["workspaces"][0]["runs"] == json!([{"box": "dev", "run": dev.hex()}]));
    let raised = world.keeper("acme").raise("web");
    let record = world.shown(&pixel);
    let (status, body) = pixel.stop(&world.hub, MACHINE, "acme", &[("dev", dev)]);
    assert_eq!(status, 202);
    let stop = body["n"].as_u64().unwrap();
    let state = || pixel.state(&world.hub)["sent"].as_array().unwrap().iter().find(|sent| sent["n"] == stop).map(|sent| sent["state"].as_str().unwrap().to_string());
    until("the link takes the stop", || state().as_deref() == Some("taken"));
    // While dev is put away, an answer goes through.
    let at = Instant::now();
    assert_eq!(pixel.answer(&world.hub, MACHINE, &record, true).0, 202);
    assert!(matches!(raised.join().unwrap().came, Came::Yes(By::Device(_))));
    assert!(at.elapsed() < Duration::from_secs(2), "the answer waited {:?} for the stop", at.elapsed());
    assert_eq!(world.said(&pixel, stop), "stopped");
}

#[test]
fn a_stop_the_link_handled_as_it_stopped_keeps_its_word() {
    let mut world = World::new();
    world.open("acme", limits());
    let pixel = world.hub.pair_phone("pixel", &["acme"]);
    world.trust(&pixel, &["acme"]);
    let dev = RunId([1; 8]);
    *world.keeper("acme").boxes.0.lock().unwrap() = vec![("dev".into(), dev)];
    *world.keeper("acme").boxes.1.lock().unwrap() = Duration::from_millis(1500);
    until("the phone sees what runs", || pixel.state(&world.hub)["machines"][0]["workspaces"][0]["runs"] == json!([{"box": "dev", "run": dev.hex()}]));
    let (_, body) = pixel.stop(&world.hub, MACHINE, "acme", &[("dev", dev)]);
    let n = body["n"].as_u64().unwrap();
    let state = || pixel.state(&world.hub)["sent"].as_array().unwrap().iter().find(|sent| sent["n"] == n).map(|sent| sent["state"].as_str().unwrap().to_string());
    until("the link takes the stop", || state().as_deref() == Some("taken"));
    // The link stops while dev is put away, before it could say so; the hub hands the stop over
    // again once it runs again, and the open workspace says what it said the first time.
    world.stop_link();
    assert!(world.keeper("acme").boxes.runs().is_empty());
    world.start_link();
    assert_eq!(world.said(&pixel, n), "stopped");
    // Handed over again while the first is still under way, as by a link that was killed and
    // started again: it waits for the first, and is said the same.
    let web = RunId([2; 8]);
    *world.keeper("acme").boxes.0.lock().unwrap() = vec![("web".into(), web)];
    let named = vec![("web".to_string(), web)];
    let line = Records::Stop { ws: WsName::parse("acme").unwrap(), device: "pixel".into(), runs: named.clone(), signature: pixel.sign(&wire::stop_bytes(MACHINE, "acme", &named)) };
    let socket = world.keeper("acme").socket.clone();
    let first = {
        let (socket, line) = (socket.clone(), line.clone());
        thread::spawn(move || keep::tell(&socket, &line, LONG))
    };
    thread::sleep(Duration::from_millis(300));
    let stopped = Some(Told::Stopped { stopped: 1, wrong_box: 0 });
    assert_eq!(keep::tell(&socket, &line, LONG), stopped);
    assert_eq!(first.join().unwrap(), stopped);
}

#[test]
fn a_workspace_opened_before_the_join_takes_signed_stops_once_joined() {
    let mut world = World::new();
    let pixel = world.hub.pair_phone("pixel", &["acme"]);
    world.trust(&pixel, &["acme"]);
    // The machine leaves the hub, and acme is opened while it has joined none: its open workspace
    // names this machine by its host, as records do.
    assert!(world.folder.leave().unwrap());
    let folder = world.folder.clone();
    let desk = Desk::following(move || requests::machine_name_in(&folder), "acme".into(), limits(), Arc::new(Nobody));
    let host = requests::machine_name_in(&world.folder);
    let keeper = Keeper::start_with(&world.dir.0, &world.folder, "acme", desk);
    world.opened("acme", keeper);
    let before = world.keeper("acme").raise("dev");
    until("it waits", || world.keeper("acme").desk.records().len() == 1);
    // Joined again, as server-1.
    assert!(world.hub.revoke(MACHINE));
    let folder = world.folder.clone();
    world.hub.pair_machine(MACHINE, move |line| join_at(&folder, line).map(drop));
    assert_eq!(requests::machine_name_in(&world.folder), MACHINE);
    // A stop of what the phone is shown counts.
    let dev = RunId([1; 8]);
    *world.keeper("acme").boxes.0.lock().unwrap() = vec![("dev".into(), dev)];
    until("the phone sees what runs", || pixel.state(&world.hub)["machines"][0]["workspaces"][0]["runs"] == json!([{"box": "dev", "run": dev.hex()}]));
    let (_, body) = pixel.stop(&world.hub, MACHINE, "acme", &[("dev", dev)]);
    assert_eq!(world.said(&pixel, body["n"].as_u64().unwrap()), "stopped");
    assert!(world.keeper("acme").boxes.runs().is_empty());
    // A request raised from now on names server-1 and reaches the phone; the one raised before
    // names the host, and is answered here.
    let after = world.keeper("acme").raise("dev");
    let record = world.shown(&pixel);
    assert_eq!(Record::decode(&record).unwrap().machine, MACHINE);
    assert_eq!(pixel.answer(&world.hub, MACHINE, &record, true).0, 202);
    assert!(matches!(after.join().unwrap().came, Came::Yes(By::Device(_))));
    let waiting = world.keeper("acme").desk.records().remove(0);
    assert_eq!(Record::decode(&waiting).unwrap().machine, host);
    assert_eq!(world.keeper("acme").desk.answer_here(true, &answer_digest(&waiting, true)), Here::Approved);
    assert_eq!(before.join().unwrap().came, Came::Yes(By::Local));
}

#[test]
fn a_report_past_the_hub_s_limits_is_cut_to_them_and_the_trust_list_is_still_kept() {
    let mut world = World::new();
    world.open("acme", limits());
    let pixel = world.hub.pair_phone("pixel", &["acme"]);
    let tablet = world.hub.pair_phone("tablet", &["acme"]);
    world.trust(&pixel, &["acme"]);
    world.trust(&tablet, &["acme"]);
    // One box more than a report names in a workspace.
    *world.keeper("acme").boxes.0.lock().unwrap() = (0..=keep::STOP_RUNS_MAX as u8).map(|i| (format!("b{i}"), RunId([i; 8]))).collect();
    until("the phone sees 32 of them", || pixel.state(&world.hub)["machines"][0]["workspaces"][0]["runs"].as_array().is_some_and(|runs| runs.len() == keep::STOP_RUNS_MAX));
    assert!(world.hub.revoke("tablet"));
    until("the machine drops the revoked phone", || world.folder.trust().unwrap().iter().all(|entry| entry.name != "tablet"));
}

/// A link joined as server-1 to a hub that answers as it is told, and this machine's workspaces.
struct Faked {
    _dir: Short,
    hub: crate::hub::testing::FakeHub,
    folder: Folder,
    link: Option<(Arc<AtomicBool>, JoinHandle<()>)>,
}

impl Faked {
    fn new(locals: Vec<(WsName, Option<PathBuf>)>) -> Faked {
        let dir = Short::new();
        let hub_dir = dir.0.join("hub");
        std::fs::DirBuilder::new().mode(0o700).create(&hub_dir).unwrap();
        let hub = crate::hub::testing::FakeHub::start(&hub_dir);
        hub.answer("/v1/machine/inbox", 200, r#"{"items": []}"#);
        let folder = Folder::at(&dir.0.join("link"));
        let token = format!("halti_mach_{}", hex(&util::random::<32>()));
        folder.write_joined(&Joined { version: 1, address: hub.address.clone(), pin: hex(&hub.pin), name: MACHINE.into(), token, next: None }).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (running, stopping) = (folder.clone(), stop.clone());
        let link = thread::spawn(move || run::run(&running, &Locals(Mutex::new(locals)), TIMING, &stopping).unwrap());
        Faked { _dir: dir, hub, folder, link: Some((stop, link)) }
    }
}

impl Drop for Faked {
    fn drop(&mut self) {
        let (stop, link) = self.link.take().unwrap();
        stop.store(true, Ordering::SeqCst);
        let _ = link.join();
    }
}

#[test]
fn an_item_of_a_kind_the_link_doesn_t_know_is_said_unknown() {
    let faked = Faked::new(Vec::new());
    let items = json!({"items": [
        {"n": 1, "kind": "notice", "sealed": "abcd"},
        {"n": 2, "kind": "question"},
        {"n": 3},
        {"n": 4, "kind": "stop", "device": "pixel", "ws": "acme"},
        {"n": 5, "kind": "answer", "device": "pixel", "ws": "acme", "id": "00", "decision": "yes", "signature": "3006020101020101"},
    ]});
    faked.hub.answer("/v1/machine/inbox", 200, &items.to_string());
    let said = json!([
        {"n": 1, "said": "unknown"}, {"n": 2, "said": "unknown"}, {"n": 3, "said": "unknown"},
        {"n": 4, "said": "malformed"}, {"n": 5, "said": "malformed"},
    ]);
    until("the link says what came of each", || faked.hub.sent("/v1/machine/inbox").iter().any(|body| body["done"] == said));
}

#[test]
fn a_device_list_that_isn_t_whole_changes_no_trust() {
    let pixel = Phone::new("pixel");
    let (signing, agreement) = (pixel.signing_key(), pixel.agreement_key());
    let listed = json!({"name": "pixel", "signing_key": hex(&signing), "agreement_key": hex(&agreement), "key_signature": hex(&pixel.sign(&wire::keys_bytes(&signing, &agreement))), "ws": ["acme"]});
    let faked = Faked::new(vec![(WsName::parse("acme").unwrap(), None)]);
    let entry = Entry {
        name: "pixel".into(),
        signing_key: hex(&signing),
        agreement_key: hex(&agreement),
        key_signature: listed["key_signature"].as_str().unwrap().into(),
        ws: vec![WsName::parse("acme").unwrap()],
    };
    faked
        .folder
        .change_trust(|entries| {
            entries.push(entry.clone());
            ((), true)
        })
        .unwrap();
    let reports = || faked.hub.sent("/v1/machine/state").len();
    // A list with one entry that isn't one, and a reply that is no report: each is left as it is.
    for reply in [json!({"devices": [listed, {"name": "tablet"}], "missing": []}), json!({"devices": "pixel", "missing": []}), json!({"missing": []})] {
        faked.hub.answer("/v1/machine/state", 200, &reply.to_string());
        let before = reports();
        until("the link reports twice more", || reports() >= before + 2);
        assert_eq!(faked.folder.trust().unwrap(), std::slice::from_ref(&entry), "{reply}");
    }
    // A whole list without pixel drops it.
    faked.hub.answer("/v1/machine/state", 200, r#"{"devices": [], "missing": []}"#);
    until("the link drops pixel", || faked.folder.trust().unwrap().is_empty());
}

#[test]
fn a_hub_s_words_reach_the_terminal_only_as_words() {
    let dir = Short::new();
    let hub_dir = dir.0.join("hub");
    std::fs::DirBuilder::new().mode(0o700).create(&hub_dir).unwrap();
    let hub = crate::hub::testing::FakeHub::start(&hub_dir);
    hub.answer("/v1/join", 400, r#"{"error": "\u001b[2J\u001b[Hjoined the hub as server-1\nall good"}"#);
    let invite = wire::Invite { kind: wire::Kind::Machine, address: hub.address.clone(), pin: hub.pin, code: [1; 16] };
    let folder = Folder::at(&dir.0.join("link"));
    assert_eq!(format!("{:#}", join_at(&folder, &invite.to_string()).unwrap_err()), "the hub refused to join: 400 ?");
    hub.answer("/v1/join", 400, r#"{"error": "malformed"}"#);
    assert_eq!(format!("{:#}", join_at(&folder, &invite.to_string()).unwrap_err()), "the hub refused to join: 400 malformed");
}

#[test]
fn a_renewal_under_way_writes_nothing_back_after_a_leave() {
    let world = World::new();
    world.hub.advance(SignedDuration::from_hours(10 * 24));
    world.hub.delay(Duration::from_millis(1500));
    until("a renewal is under way", || world.folder.joined().unwrap().is_some_and(|joined| joined.next.is_some()));
    // halti hub leave, while the renewal waits for its reply.
    assert!(world.folder.leave().unwrap());
    world.hub.delay(Duration::ZERO);
    thread::sleep(Duration::from_secs(3));
    assert_eq!(world.folder.joined().unwrap(), None);
    assert!(world.folder.machine_key().unwrap().is_none());
}
