use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use halti_core::device::DeviceKey;
use halti_core::sealed::{self, AgreementKey, SecretKey};
use serde_json::{Value, json};

use super::*;
use crate::notices::{Event, Notice, Reason};
use crate::requests::{self, Desk, Limits, Phones, Prompt, Prompted, Trusted};
use crate::util::{hex, random, unhex};

/// A question's clear fields with every field fixed.
fn known() -> Record {
    Record {
        machine: "server-1".into(),
        ws: "acme".into(),
        box_name: "dev".into(),
        run: RunId([1, 2, 3, 4, 5, 6, 7, 8]),
        session: 1,
        kind: Kind::Permit,
        id: Id([0x10; 16]),
        expiry: 1_763_164_800,
    }
}

/// Its bytes, worked out apart from this code (Python's struct).
const KNOWN: &str = concat!(
    "001168616c74692d7175657374696f6e2d7631",
    "00087365727665722d31",
    "000461636d65",
    "0003646576",
    "00080102030405060708",
    "000400000001",
    "00067065726d6974",
    "001010101010101010101010101010101010",
    "0008000000006917c280",
);

/// The text fields an asker sends: what it left out, then `parts`.
fn text(left_out: u32, parts: &[&[u8]]) -> Vec<u8> {
    let mut all: Vec<&[u8]> = Vec::new();
    let left_out = left_out.to_be_bytes();
    all.push(&left_out);
    all.extend_from_slice(parts);
    fields::join(&all)
}

fn permit_text() -> Vec<u8> {
    text(0, &[b"Bash", br#"{"command":"npm test"}"#])
}

/// A choice of one question, `Which color?`, with the options Red and Blue.
fn choice_text(several: bool) -> Vec<u8> {
    let question = fields::join(&[b"Color", b"Which color?", if several { b"1" } else { b"0" }, b"Red", b"Select red", b"Blue", b"Select blue"]);
    text(0, &[&question])
}

fn idle_text() -> Vec<u8> {
    text(12, &[b"Done. The tests pass."])
}

#[test]
fn a_record_is_its_fields_each_after_its_length_in_order() {
    let bytes = known().encode().unwrap();
    assert_eq!(hex(&bytes), KNOWN);
    assert_eq!(Record::decode(&bytes), Some(known()));
    for kind in Kind::ALL {
        assert_eq!(Record::decode(&Record { kind, ..known() }.encode().unwrap()).unwrap().kind, kind);
    }
    assert_eq!(Kind::ALL.map(Kind::word), ["permit", "choice", "idle"]);
    assert_eq!(Form::ALL.map(Form::word), ["yes", "no", "options", "text", "stopped"]);
    // Cut anywhere, with a field more, another label or a name the rule refuses, it is nothing.
    for end in 0..bytes.len() {
        assert_eq!(Record::decode(&bytes[..end]), None, "cut at {end}");
    }
    assert_eq!(Record::decode(&[bytes.as_slice(), &[0, 0]].concat()), None);
    let parts: Vec<Vec<u8>> = fields::split(&bytes).unwrap().into_iter().map(<[u8]>::to_vec).collect();
    for (at, bad) in [(0, &b"halti-approval-v1"[..]), (1, b"Server"), (3, b"d/v"), (4, &[1; 7]), (5, &[0; 3]), (6, b"write"), (7, &[1; 15]), (8, &[0; 4])] {
        let mut broken = parts.clone();
        broken[at] = bad.to_vec();
        let broken: Vec<&[u8]> = broken.iter().map(Vec::as_slice).collect();
        assert_eq!(Record::decode(&fields::join(&broken)), None, "field {at}");
    }
    assert!(Record { box_name: "Dev".into(), ..known() }.encode().is_err());
}

#[test]
fn the_text_of_each_kind_is_read_only_within_its_caps() {
    assert_eq!(Said::parse(Kind::Permit, &permit_text()).unwrap().text, Text::Permit { tool: "Bash".into(), input: r#"{"command":"npm test"}"#.into() });
    assert_eq!(Said::parse(Kind::Idle, &idle_text()).unwrap(), Said { left_out: 12, text: Text::Idle { message: "Done. The tests pass.".into() } });
    let choice = Said::parse(Kind::Choice, &choice_text(true)).unwrap();
    assert_eq!(
        choice.questions()[0],
        Asked { header: "Color".into(), question: "Which color?".into(), several: true, options: vec![("Red".into(), "Select red".into()), ("Blue".into(), "Select blue".into())] }
    );
    // Text of one kind isn't another's.
    assert_eq!(Said::parse(Kind::Choice, &permit_text()), None);
    assert_eq!(Said::parse(Kind::Idle, &permit_text()), None);
    // Each cap, and one byte past it.
    let long = |n: usize| "x".repeat(n);
    assert!(Said::parse(Kind::Permit, &text(0, &[long(NAME_MAX).as_bytes(), long(BODY_MAX).as_bytes()])).is_some());
    assert_eq!(Said::parse(Kind::Permit, &text(0, &[long(NAME_MAX + 1).as_bytes(), b""])), None);
    assert_eq!(Said::parse(Kind::Permit, &text(0, &[b"", long(BODY_MAX + 1).as_bytes()])), None);
    assert_eq!(Said::parse(Kind::Idle, &text(0, &[long(BODY_MAX + 1).as_bytes()])), None);
    let question = |header: usize, asked: usize, label: usize, description: usize, options: usize| {
        let mut parts = vec![long(header), long(asked), "0".to_string()];
        for _ in 0..options {
            parts.push(long(label));
            parts.push(long(description));
        }
        fields::join(&parts.iter().map(String::as_bytes).collect::<Vec<_>>())
    };
    let fits = question(NAME_MAX, QUESTION_MAX, LABEL_MAX, DESCRIPTION_MAX, OPTIONS_MAX);
    assert!(Said::parse(Kind::Choice, &text(0, &[&fits, &fits, &fits, &fits])).is_some());
    assert_eq!(Said::parse(Kind::Choice, &text(0, &[&fits, &fits, &fits, &fits, &fits])), None, "five questions");
    assert_eq!(Said::parse(Kind::Choice, &text(0, &[])), None, "none");
    for bad in [
        question(NAME_MAX + 1, 0, 0, 0, 1),
        question(0, QUESTION_MAX + 1, 0, 0, 1),
        question(0, 0, LABEL_MAX + 1, 0, 1),
        question(0, 0, 0, DESCRIPTION_MAX + 1, 1),
        question(0, 0, 0, 0, OPTIONS_MAX + 1),
    ] {
        assert_eq!(Said::parse(Kind::Choice, &text(0, &[&bad])), None);
    }
    // Not UTF-8, "several" that is neither 0 nor 1, an option without its description, no count.
    assert_eq!(Said::parse(Kind::Idle, &text(0, &[&[0xff, 0xfe]])), None);
    assert_eq!(Said::parse(Kind::Choice, &text(0, &[&fields::join(&[b"h", b"q", b"2"])])), None);
    assert_eq!(Said::parse(Kind::Choice, &text(0, &[&fields::join(&[b"h", b"q", b"0", b"Red"])])), None);
    assert_eq!(Said::parse(Kind::Idle, &fields::join(&[b"no count"])), None);
    // Control characters are the agent's text, kept, and shown as escapes.
    let hostile = "halti: approve?\u{1b}[2J\u{202e}gnp.exe\u{200b}\nnext line";
    let said = Said::parse(Kind::Idle, &text(0, &[hostile.as_bytes()])).unwrap();
    let Text::Idle { message } = said.text else { panic!() };
    assert_eq!(shown(&message), "halti: approve?\\u{1b}[2J\\u{202e}gnp.exe\\u{200b}\nnext line");
}

#[test]
fn an_answer_fits_only_the_kind_it_answers() {
    let permit = Said::parse(Kind::Permit, &permit_text()).unwrap();
    let choice = Said::parse(Kind::Choice, &choice_text(false)).unwrap();
    let several = Said::parse(Kind::Choice, &choice_text(true)).unwrap();
    let idle = Said::parse(Kind::Idle, &idle_text()).unwrap();
    let typed = "t".repeat(TYPED_MAX);
    let over = "t".repeat(TYPED_MAX + 1);
    let one = |pick: Pick| options_content(&[pick]);
    for (kind, said, form, content, ok) in [
        (Kind::Permit, &permit, Form::Yes, Vec::new(), true),
        (Kind::Permit, &permit, Form::Yes, b"x".to_vec(), false),
        (Kind::Permit, &permit, Form::No, Vec::new(), true),
        (Kind::Permit, &permit, Form::No, typed.clone().into_bytes(), true),
        (Kind::Permit, &permit, Form::No, over.clone().into_bytes(), false),
        (Kind::Permit, &permit, Form::Text, b"go".to_vec(), false),
        (Kind::Permit, &permit, Form::Options, one(Pick::Options(vec![1])), false),
        (Kind::Choice, &choice, Form::Options, one(Pick::Options(vec![2])), true),
        (Kind::Choice, &choice, Form::Options, one(Pick::Options(vec![3])), false),
        (Kind::Choice, &choice, Form::Options, one(Pick::Options(vec![0])), false),
        (Kind::Choice, &choice, Form::Options, one(Pick::Options(vec![1, 2])), false),
        (Kind::Choice, &several, Form::Options, one(Pick::Options(vec![1, 2])), true),
        (Kind::Choice, &several, Form::Options, one(Pick::Options(vec![2, 1])), false),
        (Kind::Choice, &several, Form::Options, one(Pick::Options(vec![1, 1])), false),
        (Kind::Choice, &choice, Form::Options, one(Pick::Text("Green".into())), true),
        (Kind::Choice, &choice, Form::Options, one(Pick::Text(typed.clone())), true),
        (Kind::Choice, &choice, Form::Options, one(Pick::Text(over.clone())), false),
        (Kind::Choice, &choice, Form::Options, fields::join(&[b"\x01", b"x"]), false),
        (Kind::Choice, &choice, Form::Options, fields::join(&[b"", b""]), false),
        (Kind::Choice, &choice, Form::Options, options_content(&[Pick::Options(vec![1]), Pick::Options(vec![1])]), false),
        (Kind::Choice, &choice, Form::Text, b"Green".to_vec(), false),
        (Kind::Choice, &choice, Form::Yes, Vec::new(), false),
        (Kind::Idle, &idle, Form::Text, b"run the tests".to_vec(), true),
        (Kind::Idle, &idle, Form::Text, Vec::new(), false),
        (Kind::Idle, &idle, Form::Text, typed.clone().into_bytes(), true),
        (Kind::Idle, &idle, Form::Text, over.clone().into_bytes(), false),
        (Kind::Idle, &idle, Form::Text, vec![0xff], false),
        (Kind::Idle, &idle, Form::Stopped, Vec::new(), true),
        (Kind::Idle, &idle, Form::Stopped, b"x".to_vec(), false),
        (Kind::Idle, &idle, Form::Yes, Vec::new(), false),
        (Kind::Idle, &idle, Form::Options, one(Pick::Options(vec![1])), false),
    ] {
        assert_eq!(fits(kind, said, form, &content), ok, "{kind:?} {form:?} {}", hex(&content[..content.len().min(16)]));
    }
}

#[test]
fn the_bytes_a_phone_signs_hold_no_text() {
    let hash = [0xab; 32];
    let signed = signed_bytes(&hash, Form::Text, &[0x01; 16], b"push to main");
    let parts = fields::split(&signed).unwrap();
    assert_eq!(parts, [ANSWER_LABEL.as_bytes(), &hash, b"text", &content_hash(&[0x01; 16], b"push to main")[..]]);
    assert!(!signed.windows(4).any(|w| w == b"push"));
    // Another salt, content, form or question is other bytes.
    assert_ne!(signed, signed_bytes(&hash, Form::Text, &[0x02; 16], b"push to main"));
    assert_ne!(signed, signed_bytes(&hash, Form::Text, &[0x01; 16], b"push to dev"));
    assert_ne!(signed, signed_bytes(&hash, Form::No, &[0x01; 16], b"push to main"));
    assert_ne!(signed, signed_bytes(&[0xac; 32], Form::Text, &[0x01; 16], b"push to main"));
    // The label is none other's.
    assert!(![crate::requests::LABEL, crate::notices::LABEL, LABEL, RECEIPT_LABEL, REPLY_LABEL].contains(&ANSWER_LABEL));
    let answer = Answer { form: Form::Yes, salt: [3; 16], content: Vec::new(), signature: vec![0x30; 70] };
    assert_eq!(Answer::decode(&answer.encode()), Some(answer.clone()));
    for bad in [Answer { signature: Vec::new(), ..answer.clone() }, Answer { signature: vec![0x30; 73], ..answer.clone() }] {
        assert_eq!(Answer::decode(&bad.encode()), None);
    }
    assert_eq!(Answer::decode(&fields::join(&[b"maybe", &[3; 16], b"", &[0x30]])), None);
    assert_eq!(Answer::decode(&fields::join(&[b"yes", &[3; 15], b"", &[0x30]])), None);
    assert_eq!(Outcome::ALL.map(Outcome::word), ["delivered", "not-pending", "expired", "does-not-fit", "bad-signature", "untrusted", "unreadable"]);
    for outcome in Outcome::ALL {
        assert_eq!(Outcome::parse(outcome.word()), Some(outcome));
        assert!(crate::hub::wire::is_word(outcome.word()));
    }
}

// --- a desk's questions ---

/// A phone: its signing key and second key, and how this machine trusts it.
struct Phone {
    signing: rcgen::KeyPair,
    second: SecretKey,
    /// What made its second key.
    ikm: [u8; 32],
    trusted: Trusted,
}

fn phone(name: &str, ws: &[&str]) -> Phone {
    phone_with(name, ws, random())
}

fn phone_with(name: &str, ws: &[&str], ikm: [u8; 32]) -> Phone {
    use rcgen::PublicKeyData;
    let signing = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let spki = signing.subject_public_key_info();
    let trusted = Trusted {
        name: name.into(),
        key: DeviceKey::from_spki(&spki).unwrap(),
        fingerprint: crate::hub::wire::fingerprint(&spki),
        ws: ws.iter().map(|ws| ws.to_string()).collect(),
    };
    Phone { signing, second: SecretKey::derive(&ikm), ikm, trusted }
}

/// The phones this machine trusts, which a test changes, and its machine key.
struct Trust {
    phones: Mutex<Vec<(Trusted, Option<AgreementKey>)>>,
    machine: [u8; 32],
}

impl Trust {
    fn of(phones: &[&Phone]) -> Arc<Trust> {
        Arc::new(Trust { phones: Mutex::new(phones.iter().map(|phone| (phone.trusted.clone(), Some(phone.second.public()))).collect()), machine: random() })
    }

    fn machine(&self) -> AgreementKey {
        SecretKey::derive(&self.machine).public()
    }

    fn set(&self, phones: &[&Phone]) {
        *self.phones.lock().unwrap() = phones.iter().map(|phone| (phone.trusted.clone(), Some(phone.second.public()))).collect();
    }
}

struct Shared(Arc<Trust>);

impl Phones for Shared {
    fn trusted(&self) -> Vec<(Trusted, Option<AgreementKey>)> {
        self.0.phones.lock().unwrap().clone()
    }

    fn machine_key(&self) -> Option<SecretKey> {
        Some(SecretKey::derive(&self.0.machine))
    }
}

struct Nobody;

impl Prompt for Nobody {
    fn ask(&self, _reason: &str, _withdrawn: &dyn Fn() -> bool) -> Prompted {
        Prompted::Unshown
    }
}

const RUN: RunId = RunId([7; 8]);

fn desk(trust: &Arc<Trust>) -> Arc<Desk> {
    let limits = Limits { notice_delay: Duration::ZERO, wait: Duration::from_secs(20), ..requests::LIMITS };
    Desk::with_phones("server-1".into(), "acme".into(), limits, Arc::new(Nobody), Box::new(Shared(trust.clone())))
}

/// A held asker of box `box_name` on a thread of its own: what it is told, once it is, and a flag
/// that closes its call.
struct Held {
    told: thread::JoinHandle<requests::Asked>,
    hang_up: Arc<AtomicBool>,
}

fn held(desk: &Arc<Desk>, box_name: &str, event: Event, tag: &[u8], text: Vec<u8>) -> Held {
    held_in(desk, box_name, RUN, event, tag, text)
}

/// As `held`, for the run `run` of the box.
fn held_in(desk: &Arc<Desk>, box_name: &str, run: RunId, event: Event, tag: &[u8], text: Vec<u8>) -> Held {
    let asker = desk.asker(box_name, run);
    let hang_up = Arc::new(AtomicBool::new(false));
    let gone = hang_up.clone();
    let tag = tag.to_vec();
    Held { told: thread::spawn(move || asker.ask(event, &tag, &text, &|| gone.load(Ordering::SeqCst))), hang_up }
}

impl Held {
    fn told(self) -> requests::Asked {
        self.told.join().unwrap()
    }
}

/// Waits until `check` holds, or ten seconds pass.
fn until(what: &str, check: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !check() {
        assert!(Instant::now() < deadline, "{what} never happened");
        thread::sleep(Duration::from_millis(10));
    }
}

fn away(desk: &Desk) {
    desk.set_away(RUN, Some(requests::now_secs() + 3600));
}

/// The questions that wait, once there are `n`: each its clear fields, and the copy for `phone`.
fn waiting(desk: &Desk, n: usize, phone: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    until(&format!("{n} questions"), || desk.questions().len() == n);
    desk.questions().into_iter().map(|(clear, copies)| (clear, copies.into_iter().find(|(name, _)| name == phone).map(|(_, copy)| copy).unwrap_or_default())).collect()
}

/// What `phone` sees of a question: the whole record, opened under the machine key.
fn opened(phone: &Phone, trust: &Trust, clear: &[u8], copy: &[u8]) -> Vec<u8> {
    let sealed = sealed::open(sealed::Kind::Question, &phone.second, &trust.machine(), clear, copy).unwrap();
    [clear, &sealed].concat()
}

/// The sealed answer `phone` sends, signed over `signed_for` (the record it showed, as a rule).
fn answer_with(phone: &Phone, whole: &[u8], signed_for: &[u8], form: Form, content: &[u8]) -> Vec<u8> {
    use rcgen::SigningKey;
    let (record, _, reply_key, _) = open_whole(whole).unwrap();
    let clear = record.encode().unwrap();
    let salt = random();
    let hash: [u8; 32] = Sha256::digest(signed_for).into();
    let signed = signed_bytes(&hash, form, &salt, content);
    let signature = phone.signing.sign(&signed).unwrap();
    let answer = Answer { form, salt, content: content.to_vec(), signature };
    sealed::seal(sealed::Kind::Answer, &phone.second, &AgreementKey::from_spki(&reply_key).unwrap(), &clear, &answer.encode(), &random()).unwrap()
}

fn answer(phone: &Phone, whole: &[u8], form: Form, content: &[u8]) -> Vec<u8> {
    answer_with(phone, whole, whole, form, content)
}

/// What a receipt sealed to `phone` says: the answer's hash and the outcome.
fn receipt(phone: &Phone, trust: &Trust, id: Id, sealed: &[u8]) -> ([u8; 32], Outcome) {
    let clear = receipt_clear("server-1", "acme", id);
    let opened = sealed::open(sealed::Kind::Receipt, &phone.second, &trust.machine(), &clear, sealed).unwrap();
    let [hash, word] = fields::split(&opened).unwrap()[..] else { panic!() };
    (hash.try_into().unwrap(), Outcome::parse(std::str::from_utf8(word).unwrap()).unwrap())
}

fn notices(desk: &Desk) -> Vec<(Notice, Vec<u8>)> {
    desk.notices().into_iter().map(|(record, said)| (Notice::decode(&record).unwrap(), said)).collect()
}

#[test]
fn a_run_not_marked_away_is_answered_nobody_at_once_with_its_notice_made() {
    let pixel = phone("pixel", &["acme"]);
    let trust = Trust::of(&[&pixel]);
    let desk = desk(&trust);
    let started = Instant::now();
    for (event, text) in
        [(Event::Permit, permit_text()), (Event::Waiting(crate::notices::Kind::Question), choice_text(false)), (Event::Waiting(crate::notices::Kind::TurnEnded), idle_text())]
    {
        assert!(matches!(held(&desk, "dev", event, &[event.word().len() as u8], text).told(), requests::Asked::Nobody));
    }
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(desk.questions().is_empty());
    // A permission prompt's notice comes from its Notification; the question and the turn's end
    // made theirs.
    let kinds: Vec<_> = notices(&desk).iter().map(|(notice, _)| notice.kind).collect();
    assert_eq!(kinds, [crate::notices::Kind::Question, crate::notices::Kind::TurnEnded]);
    // Marked away, a workspace with no phone, or a machine with no key, still asks nobody.
    away(&desk);
    let alone = Desk::new("server-1".into(), "acme".into(), requests::LIMITS, Arc::new(Nobody));
    alone.set_away(RUN, Some(requests::now_secs() + 3600));
    assert!(matches!(held(&alone, "dev", Event::Permit, b"t", permit_text()).told(), requests::Asked::Nobody));
    let elsewhere = phone("tablet", &["beta"]);
    trust.set(&[&elsewhere]);
    assert!(matches!(held(&desk, "dev", Event::Permit, b"t", permit_text()).told(), requests::Asked::Nobody), "a phone trusted for another workspace only");
}

#[test]
fn a_question_goes_sealed_to_each_phone_and_the_first_answer_that_counts_reaches_the_asker() {
    let (pixel, tablet) = (phone("pixel", &["acme"]), phone("tablet", &["acme", "beta"]));
    let other = phone("other", &["beta"]);
    let trust = Trust::of(&[&pixel, &tablet, &other]);
    let desk = desk(&trust);
    away(&desk);
    let asker = held(&desk, "dev", Event::Permit, b"session-1", permit_text());
    waiting(&desk, 1, "pixel");
    let listed = desk.questions();
    let [(clear, copies)] = &listed[..] else { panic!("one question") };
    let record = Record::decode(clear).unwrap();
    assert_eq!((record.machine.as_str(), record.ws.as_str(), record.box_name.as_str(), record.run, record.session, record.kind), ("server-1", "acme", "dev", RUN, 1, Kind::Permit));
    let names: Vec<&str> = copies.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["pixel", "tablet"], "sealed only to the phones trusted for acme");
    // The life of a question is its mark's end at most.
    assert!(record.expiry <= requests::now_secs() + 3601 && record.expiry > requests::now_secs() + 3500);
    // Each phone opens its own copy, and the two are the same record; another's doesn't open.
    let whole = opened(&pixel, &trust, clear, &copies[0].1);
    assert_eq!(whole, opened(&tablet, &trust, clear, &copies[1].1));
    assert!(sealed::open(sealed::Kind::Question, &pixel.second, &trust.machine(), clear, &copies[1].1).is_err());
    let (_, _, _, said) = open_whole(&whole).unwrap();
    assert_eq!(said, Said::parse(Kind::Permit, &permit_text()).unwrap());
    assert_eq!(desk.asked(), std::slice::from_ref(&whole));
    // The phone's yes reaches the asker, which is told it; a receipt says so.
    let (outcome, sealed) = desk.reply("pixel", record.id, &answer(&pixel, &whole, Form::Yes, b""));
    assert_eq!(outcome, Outcome::Delivered);
    let (hash, said) = receipt(&pixel, &trust, record.id, &sealed.unwrap());
    assert_eq!(said, Outcome::Delivered);
    assert_ne!(hash, [0; 32]);
    let requests::Asked::Answered { reply: told, line } = asker.told() else { panic!("answered") };
    assert_eq!(told, reply(Form::Yes, b""));
    assert_eq!((line.id, line.kind, line.form, line.hash), (record.id, Kind::Permit, Form::Yes, <[u8; 32]>::from(Sha256::digest(&whole))));
    let requests::By::Device(signed) = &line.by else { panic!("signed") };
    assert_eq!((signed.device.as_str(), &signed.fingerprint), ("pixel", &pixel.trusted.fingerprint));
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&signed.record)), hash, "the receipt names the signed bytes the log keeps");
    pixel.trusted.key.verify(&signed.record, &signed.signature).unwrap();
    // The other phone's answer comes too late, and its receipt says so, never that it was delivered.
    let (late, sealed) = desk.reply("tablet", record.id, &answer(&tablet, &whole, Form::No, b""));
    assert_eq!(late, Outcome::NotPending);
    assert_eq!(receipt(&tablet, &trust, record.id, &sealed.unwrap()).1, Outcome::NotPending);
    assert!(desk.questions().is_empty());
}

#[test]
fn every_check_of_an_answer_holds() {
    let (pixel, beta, gone) = (phone("pixel", &["acme"]), phone("tablet", &["beta"]), phone("old", &["acme"]));
    let trust = Trust::of(&[&pixel, &beta]);
    let desk = desk(&trust);
    away(&desk);
    let asker = held(&desk, "dev", Event::Waiting(crate::notices::Kind::Question), b"s", choice_text(false));
    let [(clear, copy)] = &waiting(&desk, 1, "pixel")[..] else { panic!() };
    let id = Record::decode(clear).unwrap().id;
    let whole = opened(&pixel, &trust, clear, copy);
    let options = |pick: Pick| options_content(&[pick]);
    // Signed by another key: the device's own second key seals it, so it opens, but it isn't the
    // device's signature.
    let forged = answer(&phone_with("pixel", &["acme"], pixel.ikm), &whole, Form::Options, &options(Pick::Options(vec![1])));
    assert_eq!(desk.reply("pixel", id, &forged).0, Outcome::BadSignature);
    // Signed over another question's record.
    let mut other_record = whole.clone();
    *other_record.last_mut().unwrap() ^= 1;
    assert_eq!(desk.reply("pixel", id, &answer_with(&pixel, &whole, &other_record, Form::Options, &options(Pick::Options(vec![1])))).0, Outcome::BadSignature);
    // A device trusted only for another workspace; one no longer trusted at all, which gets no
    // receipt: there is no key to seal it to.
    assert_eq!(desk.reply("tablet", id, &answer(&beta, &whole, Form::Options, &options(Pick::Options(vec![1])))).0, Outcome::Untrusted);
    assert_eq!(desk.reply("old", id, &answer(&gone, &whole, Form::Options, &options(Pick::Options(vec![1])))), (Outcome::Untrusted, None));
    // Sealed by another phone under this one's name, or not sealed at all: it doesn't open.
    assert_eq!(desk.reply("pixel", id, &answer(&beta, &whole, Form::Options, &options(Pick::Options(vec![1])))).0, Outcome::Unreadable);
    assert_eq!(desk.reply("pixel", id, b"noise").0, Outcome::Unreadable);
    // Another id: none waits.
    assert_eq!(desk.reply("pixel", Id([0x55; 16]), &answer(&pixel, &whole, Form::Options, &options(Pick::Options(vec![1])))).0, Outcome::NotPending);
    // An option not offered, two where one is taken, text over the cap, an answer of another kind.
    for (form, content) in [
        (Form::Options, options(Pick::Options(vec![3]))),
        (Form::Options, options(Pick::Options(vec![1, 2]))),
        (Form::Options, options(Pick::Text("x".repeat(TYPED_MAX + 1)))),
        (Form::Yes, Vec::new()),
        (Form::Text, b"Green".to_vec()),
        (Form::Stopped, Vec::new()),
    ] {
        let (outcome, sealed) = desk.reply("pixel", id, &answer(&pixel, &whole, form, &content));
        assert_eq!(outcome, Outcome::DoesNotFit, "{form:?}");
        assert_eq!(receipt(&pixel, &trust, id, &sealed.unwrap()).1, Outcome::DoesNotFit);
    }
    // None of that reached the asker; one that fits does, once: the same answer again is replayed.
    assert!(!asker.told.is_finished());
    let good = answer(&pixel, &whole, Form::Options, &options(Pick::Text("Green, on Tuesdays".into())));
    assert_eq!(desk.reply("pixel", id, &good).0, Outcome::Delivered);
    let requests::Asked::Answered { reply: told, .. } = asker.told() else { panic!() };
    assert_eq!(told, reply(Form::Options, &options(Pick::Text("Green, on Tuesdays".into()))));
    assert_eq!(desk.reply("pixel", id, &good).0, Outcome::NotPending);
}

#[test]
fn an_answer_after_its_question_expired_or_was_withdrawn_is_told_so() {
    let pixel = phone("pixel", &["acme"]);
    let trust = Trust::of(&[&pixel]);
    let desk = desk(&trust);
    // A mark that ends in two seconds is the question's life.
    desk.set_away(RUN, Some(requests::now_secs() + 2));
    let asker = held(&desk, "dev", Event::Permit, b"s", permit_text());
    let [(clear, copy)] = &waiting(&desk, 1, "pixel")[..] else { panic!() };
    let id = Record::decode(clear).unwrap().id;
    let whole = opened(&pixel, &trust, clear, copy);
    assert!(matches!(asker.told(), requests::Asked::Nobody));
    let (outcome, sealed) = desk.reply("pixel", id, &answer(&pixel, &whole, Form::Yes, b""));
    assert!(matches!(outcome, Outcome::Expired | Outcome::NotPending), "{outcome:?}");
    assert_eq!(receipt(&pixel, &trust, id, &sealed.unwrap()).1, outcome);
    // One withdrawn as its agent went on: not pending.
    away(&desk);
    let asker = held(&desk, "dev", Event::Permit, b"s", permit_text());
    let [(clear, copy)] = &waiting(&desk, 1, "pixel")[..] else { panic!() };
    let id = Record::decode(clear).unwrap().id;
    let whole = opened(&pixel, &trust, clear, copy);
    desk.asker("dev", RUN).tell(Event::Working, b"s");
    assert!(matches!(asker.told(), requests::Asked::Nobody));
    assert_eq!(desk.reply("pixel", id, &answer(&pixel, &whole, Form::Yes, b"")).0, Outcome::NotPending);
}

#[test]
fn the_hold_ends_on_every_path_and_the_asker_is_released() {
    let pixel = phone("pixel", &["acme"]);
    let trust = Trust::of(&[&pixel]);
    type End = Box<dyn Fn(&Arc<Desk>, &Held)>;
    let ends: Vec<(&str, End, Option<&str>)> = vec![
        ("the agent went on", Box::new(|desk, _| desk.asker("dev", RUN).tell(Event::Working, b"s")), None),
        ("the owner typed", Box::new(|desk, _| desk.asker("dev", RUN).tell(Event::Typed, b"s")), None),
        ("another session's owner typed", Box::new(|desk, _| desk.asker("dev", RUN).tell(Event::Typed, b"other")), Some("not-away")),
        ("the mark was cleared", Box::new(|desk, _| desk.set_away(RUN, None)), Some("not-away")),
        ("the run ended", Box::new(|desk, _| desk.end_run(RUN)), None),
        ("the workspace closed", Box::new(|desk, _| desk.close()), None),
        ("the asker hung up", Box::new(|_, held| held.hang_up.store(true, Ordering::SeqCst)), None),
        (
            "no phone is trusted any more",
            Box::new(|desk, _| {
                desk.questions();
            }),
            Some("no-phone"),
        ),
        ("it was answered here", Box::new(|desk, _| assert_eq!(desk.answer_question_here(only(desk), Form::Yes, b""), Outcome::Delivered)), None),
    ];
    for (what, end, notice) in ends {
        let desk = desk(&trust);
        trust.set(&[&pixel]);
        away(&desk);
        let asker = held(&desk, "dev", Event::Permit, b"s", permit_text());
        waiting(&desk, 1, "pixel");
        assert!(notices(&desk).is_empty(), "{what}: a question replaces its notice");
        if what == "no phone is trusted any more" {
            trust.set(&[]);
        }
        end(&desk, &asker);
        let started = Instant::now();
        let told = asker.told();
        assert!(started.elapsed() < Duration::from_secs(3), "{what}: released at once");
        assert_eq!(matches!(told, requests::Asked::Answered { .. }), what == "it was answered here", "{what}");
        assert!(desk.questions().is_empty() && desk.asked().is_empty(), "{what}");
        let reasons: Vec<String> = notices(&desk).iter().map(|(_, said)| String::from_utf8_lossy(fields::split(said).unwrap()[0]).into_owned()).collect();
        assert_eq!(reasons, notice.into_iter().map(str::to_string).collect::<Vec<_>>(), "{what}: its notice back with the reason, where the agent still waits");
    }
}

/// The id of the one question that waits.
fn only(desk: &Desk) -> Id {
    Record::decode(&desk.questions()[0].0).unwrap().id
}

#[test]
fn leave_it_stopped_releases_the_asker_with_nobody_and_gives_its_notice_back() {
    let pixel = phone("pixel", &["acme"]);
    let trust = Trust::of(&[&pixel]);
    let desk = desk(&trust);
    away(&desk);
    let asker = held(&desk, "dev", Event::Waiting(crate::notices::Kind::TurnEnded), b"s", idle_text());
    let [(clear, copy)] = &waiting(&desk, 1, "pixel")[..] else { panic!() };
    let whole = opened(&pixel, &trust, clear, copy);
    assert_eq!(desk.reply("pixel", Record::decode(clear).unwrap().id, &answer(&pixel, &whole, Form::Stopped, b"")).0, Outcome::Delivered);
    // An answer, logged as one; the asker is told nobody, so the agent stops as it was about to.
    let requests::Asked::Answered { reply: told, line } = asker.told() else { panic!("answered") };
    assert_eq!((told.as_slice(), line.form), (&b"nobody"[..], Form::Stopped));
    let [(notice, said)] = &notices(&desk)[..] else { panic!("its notice") };
    assert_eq!((notice.kind, said.clone()), (crate::notices::Kind::TurnEnded, Reason::Left.said()));
    assert_eq!(hex(&Reason::Left.said()), "00046c65667400080000000000000000");
    assert_eq!(hex(&Reason::Expired(0x6917c280).said()), "0007657870697265640008000000006917c280");
}

#[test]
fn an_answer_here_ends_the_mark_and_withdraws_the_run_s_other_questions() {
    let pixel = phone("pixel", &["acme"]);
    let trust = Trust::of(&[&pixel]);
    let desk = desk(&trust);
    away(&desk);
    let first = held(&desk, "dev", Event::Permit, b"one", permit_text());
    waiting(&desk, 1, "pixel");
    let id = only(&desk);
    let second = held(&desk, "dev", Event::Waiting(crate::notices::Kind::TurnEnded), b"two", idle_text());
    waiting(&desk, 2, "pixel");
    assert_eq!(desk.marks().len(), 1);
    // What doesn't fit is refused, and nothing changes.
    assert_eq!(desk.answer_question_here(id, Form::Text, b"go"), Outcome::DoesNotFit);
    assert_eq!(desk.answer_question_here(Id([1; 16]), Form::Yes, b""), Outcome::NotPending);
    assert_eq!(desk.answer_question_here(id, Form::No, b"not now"), Outcome::Delivered);
    let requests::Asked::Answered { reply: told, line } = first.told() else { panic!() };
    assert_eq!((told, line.by), (reply(Form::No, b"not now"), requests::By::Local));
    assert!(matches!(second.told(), requests::Asked::Nobody));
    assert!(desk.marks().is_empty(), "the mark ended");
    // The next wait of that run is a notice, answered nobody at once.
    assert!(matches!(held(&desk, "dev", Event::Permit, b"one", permit_text()).told(), requests::Asked::Nobody));
}

#[test]
fn an_answer_reaches_neither_a_request_nor_anything_but_its_asker() {
    let pixel = phone("pixel", &["acme"]);
    let trust = Trust::of(&[&pixel]);
    let desk = desk(&trust);
    away(&desk);
    // A write that asks waits beside the question: both are there, neither holds the other up.
    let asker = desk.asker("dev", RUN);
    let raised = thread::spawn(move || asker.raise("POST https://api.example.com/v1/x", false, &|| false));
    until("the request waits", || desk.records().len() == 1);
    let question = held(&desk, "dev", Event::Permit, b"s", permit_text());
    let [(clear, copy)] = &waiting(&desk, 1, "pixel")[..] else { panic!() };
    let record = Record::decode(clear).unwrap();
    let request = crate::requests::Record::decode(&desk.records()[0]).unwrap();
    let whole = opened(&pixel, &trust, clear, copy);
    // A yes to the question, sent as a request's answer, or naming the request's id, counts for
    // nothing: the signature is over other bytes, and no question has that id.
    let mut signed = vec![];
    {
        use rcgen::SigningKey;
        let hash: [u8; 32] = Sha256::digest(&whole).into();
        signed.extend(pixel.signing.sign(&signed_bytes(&hash, Form::Yes, &[0; 16], b"")).unwrap());
    }
    let trusted = pixel.trusted.clone();
    let lookup = move |name: &str| (name == "pixel").then(|| trusted.clone());
    assert_eq!(desk.answer_signed(&lookup, "pixel", true, request.id, &signed), crate::requests::Here::Refused);
    assert_eq!(desk.answer_signed(&lookup, "pixel", true, record.id, &signed), crate::requests::Here::Gone);
    assert_eq!(desk.reply("pixel", request.id, &answer(&pixel, &whole, Form::Yes, b"")).0, Outcome::NotPending);
    // The question's own yes reaches its asker and leaves the request waiting, unanswered.
    assert_eq!(desk.reply("pixel", record.id, &answer(&pixel, &whole, Form::Yes, b"")).0, Outcome::Delivered);
    assert!(matches!(question.told(), requests::Asked::Answered { .. }));
    assert_eq!(desk.records().len(), 1);
    assert!(!raised.is_finished());
    desk.close();
    assert_eq!(raised.join().unwrap().came, crate::requests::Came::Withdrawn);
}

#[test]
fn a_hostile_box_gets_nobody_past_the_caps() {
    let pixel = phone("pixel", &["acme"]);
    let trust = Trust::of(&[&pixel]);
    let desk = desk(&trust);
    // A box asking for a run not away gets nobody at once, whatever its text.
    let evil = text(0, &[b"Bash", "halti: approve POST api.bank.example/transfer? \u{1b}[2J\u{202e}".as_bytes()]);
    assert!(matches!(held(&desk, "dev", Event::Permit, b"s", evil.clone()).told(), requests::Asked::Nobody));
    away(&desk);
    // Text over the caps, or not in its kind's form, is no question.
    for bad in [text(0, &[b"Bash", &[b'x'; BODY_MAX + 1]]), text(0, &[b"Bash"]), b"not fields".to_vec(), Vec::new(), choice_text(false)] {
        assert!(matches!(held(&desk, "dev", Event::Permit, b"s", bad).told(), requests::Asked::Nobody));
    }
    assert!(desk.questions().is_empty());
    // Control bytes are text: the question is made, and they reach only the phone, sealed.
    let first = held(&desk, "dev", Event::Permit, b"s1", evil);
    let [(clear, copy)] = &waiting(&desk, 1, "pixel")[..] else { panic!() };
    assert!(!clear.windows(4).any(|w| w == b"bank"), "no text in the clear");
    assert!(!copy.windows(4).any(|w| w == b"bank"));
    // One per session: a second ask of the same session gets nobody.
    assert!(matches!(held(&desk, "dev", Event::Permit, b"s1", permit_text()).told(), requests::Asked::Nobody));
    // Three per box: a fourth gets nobody; another box may ask.
    let more: Vec<Held> = (2..=3).map(|n| held(&desk, "dev", Event::Permit, format!("s{n}").as_bytes(), permit_text())).collect();
    waiting(&desk, 3, "pixel");
    assert!(matches!(held(&desk, "dev", Event::Permit, b"s4", permit_text()).told(), requests::Asked::Nobody));
    let web_run = RunId([8; 8]);
    desk.set_away(web_run, Some(requests::now_secs() + 3600));
    let web = held_in(&desk, "web", web_run, Event::Permit, b"s1", permit_text());
    waiting(&desk, 4, "pixel");
    // Session numbers are the keeper's, never the box's tag.
    let sessions: Vec<u32> = desk.questions().iter().map(|(clear, _)| Record::decode(clear).unwrap().session).collect();
    assert!(sessions.iter().all(|session| (1..=8).contains(session)), "{sessions:?}");
    desk.close();
    for held in [first, web].into_iter().chain(more) {
        assert!(matches!(held.told(), requests::Asked::Nobody));
    }
}

#[test]
fn twenty_wait_at_most_in_one_workspace() {
    let pixel = phone("pixel", &["acme"]);
    let trust = Trust::of(&[&pixel]);
    let desk = desk(&trust);
    away(&desk);
    let mut asked = Vec::new();
    let run = |n: usize| RunId([n as u8 / 3; 8]);
    for n in 0..=requests::QUESTIONS_PER_DESK {
        desk.set_away(run(n), Some(requests::now_secs() + 3600));
    }
    for n in 0..requests::QUESTIONS_PER_DESK {
        asked.push(held_in(&desk, &format!("b{}", n / 3), run(n), Event::Permit, format!("s{n}").as_bytes(), permit_text()));
    }
    waiting(&desk, requests::QUESTIONS_PER_DESK, "pixel");
    let n = requests::QUESTIONS_PER_DESK;
    assert!(matches!(held_in(&desk, "last", run(n), Event::Permit, b"s", permit_text()).told(), requests::Asked::Nobody));
    desk.close();
    for held in asked {
        assert!(matches!(held.told(), requests::Asked::Nobody));
    }
}

#[test]
fn a_notice_open_as_its_run_is_marked_away_comes_back_with_its_reason() {
    let trust = Trust::of(&[]);
    let desk = desk(&trust);
    desk.asker("dev", RUN).tell(Event::Waiting(crate::notices::Kind::TurnEnded), b"s");
    let [(before, said)] = &notices(&desk)[..] else { panic!() };
    assert!(said.is_empty());
    away(&desk);
    let [(after, said)] = &notices(&desk)[..] else { panic!() };
    assert_ne!(before.id, after.id, "a new notice");
    assert_eq!(said, &Reason::BeforeAway.said());
}

#[test]
fn a_phone_trusted_while_a_question_waits_gets_a_copy_and_one_untrusted_loses_its() {
    let (pixel, tablet) = (phone("pixel", &["acme"]), phone("tablet", &["acme"]));
    let trust = Trust::of(&[&pixel]);
    let desk = desk(&trust);
    away(&desk);
    let asker = held(&desk, "dev", Event::Permit, b"s", permit_text());
    waiting(&desk, 1, "pixel");
    trust.set(&[&tablet]);
    let listed = desk.questions();
    let names: Vec<&str> = listed[0].1.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["tablet"]);
    let whole = opened(&tablet, &trust, &listed[0].0, &listed[0].1[0].1);
    assert_eq!(desk.reply("tablet", only(&desk), &answer(&tablet, &whole, Form::Yes, b"")).0, Outcome::Delivered);
    assert!(matches!(asker.told(), requests::Asked::Answered { .. }));
}

// --- the published vectors ---

const VECTORS: &str = "tests/fixtures/question-vectors.json";

/// The PKCS#8 form of a P-256 key with this scalar, as rcgen reads it.
fn pkcs8(scalar: &[u8; 32]) -> Vec<u8> {
    let prefix = unhex("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420").unwrap();
    let point = &SecretKey::from_scalar(scalar).unwrap().public().spki()[26..];
    [prefix.as_slice(), scalar, &unhex("a144034200").unwrap(), point].concat()
}

struct Fixed {
    machine: SecretKey,
    device: SecretKey,
    signing: [u8; 32],
}

fn fixed() -> Fixed {
    Fixed {
        machine: SecretKey::derive(&arr(&unhex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f").unwrap())),
        device: SecretKey::derive(&arr(&unhex("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").unwrap())),
        signing: arr(&unhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap()),
    }
}

fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap()
}

/// The cases of the vectors: kind, text, the answer's form and content.
fn cases() -> Vec<(Kind, Vec<u8>, Form, Vec<u8>)> {
    vec![
        (Kind::Permit, permit_text(), Form::Yes, Vec::new()),
        (Kind::Permit, permit_text(), Form::No, b"not on main".to_vec()),
        (Kind::Choice, choice_text(true), Form::Options, options_content(&[Pick::Options(vec![1, 2])])),
        (Kind::Choice, choice_text(false), Form::Options, options_content(&[Pick::Text("Green, but only on Tuesdays".into())])),
        (Kind::Idle, idle_text(), Form::Text, "Run the tests again, then stop.".as_bytes().to_vec()),
        (Kind::Idle, idle_text(), Form::Stopped, Vec::new()),
    ]
}

/// Everything of one case but the signature, which is drawn anew each time: the app checks that
/// the one given verifies, and that its own does.
fn case(n: u8, kind: Kind, text: &[u8], form: Form, content: &[u8], signature: &[u8]) -> Value {
    let keys = fixed();
    let record = Record { kind, id: Id([0x10 + n; 16]), ..known() };
    let clear = record.encode().unwrap();
    let reply_ikm = [0x50 + n; 32];
    let reply_key = SecretKey::derive(&reply_ikm).public().spki();
    let salt = [0x60 + n; 16];
    let sealed_fields = sealed_fields(&salt, &reply_key, text);
    let whole = [clear.as_slice(), &sealed_fields].concat();
    let question_ikm = [0x70 + n; 32];
    let question = sealed::seal(sealed::Kind::Question, &keys.machine, &keys.device.public(), &clear, &sealed_fields, &question_ikm).unwrap();
    let answer_salt = [0x80 + n; 16];
    let signed = signed_bytes(&hash(&clear, &sealed_fields), form, &answer_salt, content);
    let plaintext = Answer { form, salt: answer_salt, content: content.to_vec(), signature: signature.to_vec() }.encode();
    let answer_ikm = [0x90 + n; 32];
    let answer = sealed::seal(sealed::Kind::Answer, &keys.device, &SecretKey::derive(&reply_ikm).public(), &clear, &plaintext, &answer_ikm).unwrap();
    let answer_hash: [u8; 32] = Sha256::digest(&signed).into();
    let receipt_clear = receipt_clear(&record.machine, &record.ws, record.id);
    let receipt_fields = receipt_fields(&answer_hash, Outcome::Delivered);
    let receipt_ikm = [0xa0 + n; 32];
    let receipt = sealed::seal(sealed::Kind::Receipt, &keys.machine, &keys.device.public(), &receipt_clear, &receipt_fields, &receipt_ikm).unwrap();
    json!({
        "kind": kind.word(),
        "record": {"machine": record.machine, "ws": record.ws, "box": record.box_name, "run": hex(&record.run.0), "session": record.session, "kind": kind.word(), "id": hex(&record.id.0), "expiry": record.expiry},
        "clear": hex(&clear),
        "salt": hex(&salt),
        "reply_ikm": hex(&reply_ikm),
        "reply_key": hex(&reply_key),
        "text": hex(text),
        "sealed_fields": hex(&sealed_fields),
        "whole": hex(&whole),
        "question_hash": hex(&hash(&clear, &sealed_fields)),
        "question_ikm_e": hex(&question_ikm),
        "question_sealed": hex(&question),
        "answer": {
            "form": form.word(),
            "content": hex(content),
            "salt": hex(&answer_salt),
            "content_hash": hex(&content_hash(&answer_salt, content)),
            "signed": hex(&signed),
            "signature": hex(signature),
            "plaintext": hex(&plaintext),
            "ikm_e": hex(&answer_ikm),
            "sealed": hex(&answer),
            "hash": hex(&answer_hash),
        },
        "receipt": {"outcome": "delivered", "clear": hex(&receipt_clear), "fields": hex(&receipt_fields), "ikm_e": hex(&receipt_ikm), "sealed": hex(&receipt)},
        "to_asker": hex(&reply(form, content)),
    })
}

fn vectors(signatures: &[Vec<u8>]) -> Value {
    let keys = fixed();
    let signing = rcgen::KeyPair::try_from(pkcs8(&keys.signing).as_slice()).unwrap();
    let spki = {
        use rcgen::PublicKeyData;
        signing.subject_public_key_info()
    };
    let cases: Vec<Value> = cases().iter().enumerate().map(|(n, (kind, text, form, content))| case(n as u8, *kind, text, *form, content, &signatures[n])).collect();
    json!({
        "about": [
            "An agent's question, its answer and the receipt, between a halti machine and a phone: known answers that halti (src/questions.rs) and the app both test against. src/hub/wire.rs says what each is.",
            "Every byte string is a run of fields, each its length in two bytes big-endian, then its bytes.",
            "Sealing is as in sealed-text-vectors.json: HPKE mode_auth with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM; info is the kind's label; sealed is enc then ciphertext and tag. Each ikm_e makes that seal's ephemeral key, so every sealed value here is exact.",
            "keys.machine and keys.device are the machine and device keys of sealed-text-vectors.json (DeriveKeyPair of their ikm). keys.signing is the device's signing key: private is its scalar, spki its public key. A reply key is DeriveKeyPair(reply_ikm).",
            "clear is the question's clear fields, the associated data of its seals and of the answer's. sealed_fields is salt, reply key (91) and the text fields, and the plaintext of question_sealed. whole is clear then sealed_fields; question_hash its SHA-256.",
            "answer.signed is what the phone signs: halti-answer-v1, question_hash, the form, SHA-256(salt then content). ECDSA is drawn anew each time: answer.signature is one valid signature by keys.signing (DER), not the only one. answer.plaintext is form, salt, content, signature; answer.sealed seals it by keys.device to the reply key.",
            "receipt.clear is halti-receipt-v1, machine, ws, the question's id; receipt.fields is SHA-256(answer.signed) then the outcome; receipt.sealed seals them by keys.machine to keys.device. to_asker is what the door tells the agent's held asker.",
            "notice_reasons: a notice that came back from a question has the reason as its sealed text, a word and 8 bytes (the expiry for expired, else 0).",
        ],
        "keys": {
            "machine": {"ikm": "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f", "spki": hex(&keys.machine.public().spki())},
            "device": {"ikm": "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", "spki": hex(&keys.device.public().spki())},
            "signing": {"private": hex(&keys.signing), "spki": hex(&spki)},
        },
        "cases": cases,
        "notice_reasons": [
            {"reason": "expired", "at": 1_763_164_800u64, "said": hex(&Reason::Expired(1_763_164_800).said())},
            {"reason": "not-away", "said": hex(&Reason::NotAway.said())},
            {"reason": "left", "said": hex(&Reason::Left.said())},
            {"reason": "no-phone", "said": hex(&Reason::NoPhone.said())},
            {"reason": "before-away", "said": hex(&Reason::BeforeAway.said())},
        ],
    })
}

/// Writes the vectors anew, with fresh signatures: `cargo test write_the_vectors -- --ignored`.
#[test]
#[ignore]
fn write_the_vectors() {
    use rcgen::SigningKey;
    let keys = fixed();
    let signing = rcgen::KeyPair::try_from(pkcs8(&keys.signing).as_slice()).unwrap();
    let signatures: Vec<Vec<u8>> = cases()
        .iter()
        .enumerate()
        .map(|(n, (kind, text, form, content))| {
            let signed = unhex(case(n as u8, *kind, text, *form, content, &[]).pointer("/answer/signed").unwrap().as_str().unwrap()).unwrap();
            signing.sign(&signed).unwrap()
        })
        .collect();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    std::fs::write(path, serde_json::to_string_pretty(&vectors(&signatures)).unwrap() + "\n").unwrap();
}

#[test]
fn the_published_vectors_are_what_this_code_makes_and_open_as_the_machine_opens_them() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = file["cases"].as_array().unwrap();
    let signatures: Vec<Vec<u8>> = cases.iter().map(|case| unhex(case.pointer("/answer/signature").unwrap().as_str().unwrap()).unwrap()).collect();
    assert_eq!(file, vectors(&signatures));
    let keys = fixed();
    let signing = DeviceKey::from_spki(&unhex(file.pointer("/keys/signing/spki").unwrap().as_str().unwrap()).unwrap()).unwrap();
    let bytes = |case: &Value, at: &str| unhex(case.pointer(at).unwrap().as_str().unwrap()).unwrap();
    for case in cases {
        // Each signature is the device's over its signed bytes.
        signing.verify(&bytes(case, "/answer/signed"), &bytes(case, "/answer/signature")).unwrap();
        // The phone opens its copy of the question, and the whole record reads back.
        let clear = bytes(case, "/clear");
        let opened = sealed::open(sealed::Kind::Question, &keys.device, &keys.machine.public(), &clear, &bytes(case, "/question_sealed")).unwrap();
        assert_eq!(opened.as_slice(), bytes(case, "/sealed_fields"));
        let (record, _, reply_key, said) = open_whole(&bytes(case, "/whole")).unwrap();
        assert_eq!(record.encode().unwrap(), clear);
        assert_eq!(reply_key, bytes(case, "/reply_key"));
        // The machine opens the answer with the reply key, and it fits the question.
        let reply_key = sealed::ReplyKey::make(&arr(&bytes(case, "/reply_ikm")));
        let answer = Answer::decode(&reply_key.open(&keys.device.public(), &clear, &bytes(case, "/answer/sealed")).unwrap()).unwrap();
        assert!(fits(record.kind, &said, answer.form, &answer.content));
        // The receipt opens on the phone.
        let receipt = sealed::open(sealed::Kind::Receipt, &keys.device, &keys.machine.public(), &bytes(case, "/receipt/clear"), &bytes(case, "/receipt/sealed")).unwrap();
        assert_eq!(receipt.as_slice(), bytes(case, "/receipt/fields"));
    }
}

use sha2::{Digest, Sha256};
