//! Sealed text between a machine and a phone (`halti_core::sealed`) against the known answers in
//! tests/fixtures/sealed-text-vectors.json, the file the app's tests read too: every case seals to
//! exactly its bytes and opens again, and nothing opens under another clear field, machine key,
//! device, label or recipient.

use std::fs;
use std::path::Path;

use halti_core::refusal::Refusal;
use halti_core::sealed::{self, AgreementKey, Kind, ReplyKey, SecretKey};
use serde_json::Value;

fn vectors() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sealed-text-vectors.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn bytes(value: &Value, field: &str) -> Vec<u8> {
    unhex(value[field].as_str().unwrap_or_else(|| panic!("{field} is a string")))
}

fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap()
}

fn kind(name: &str) -> Kind {
    match name {
        "question" => Kind::Question,
        "notice" => Kind::Notice,
        "receipt" => Kind::Receipt,
        "answer" => Kind::Answer,
        _ => panic!("no kind {name}"),
    }
}

/// The private key named `name` in the file.
fn secret(v: &Value, name: &str) -> SecretKey {
    SecretKey::from_scalar(&arr(&bytes(&v["keys"][name], "private"))).unwrap()
}

/// Its public key, as both sides store it.
fn public(v: &Value, name: &str) -> AgreementKey {
    AgreementKey::from_spki(&bytes(&v["keys"][name], "spki")).unwrap()
}

/// The cases, each with its kind, sender, recipient, clear fields, plaintext and sealed bytes.
struct Case {
    kind: Kind,
    from: String,
    to: String,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
    sealed: Vec<u8>,
}

fn cases(v: &Value) -> Vec<Case> {
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| Case {
            kind: kind(c["kind"].as_str().unwrap()),
            from: c["from"].as_str().unwrap().to_string(),
            to: c["to"].as_str().unwrap().to_string(),
            aad: bytes(c, "aad"),
            plaintext: bytes(c, "plaintext"),
            sealed: bytes(c, "sealed"),
        })
        .collect()
}

#[test]
fn the_file_is_the_one_suite_and_every_kind() {
    let v = vectors();
    assert_eq!(v["suite"], serde_json::json!({"mode": 2, "kem_id": 16, "kdf_id": 1, "aead_id": 2}));
    let kinds: Vec<Kind> = cases(&v).iter().map(|c| c.kind).collect();
    assert_eq!(kinds, [Kind::Question, Kind::Notice, Kind::Receipt, Kind::Answer]);
    for c in v["cases"].as_array().unwrap() {
        let label = kind(c["kind"].as_str().unwrap()).label();
        assert_eq!(c["info_text"], label);
        assert_eq!(bytes(c, "info"), label.as_bytes(), "the info is the label alone");
        let sealed = bytes(c, "sealed");
        assert_eq!(sealed[..65], bytes(c, "enc"), "sealed starts with enc");
        assert_eq!(sealed.len(), 65 + bytes(c, "plaintext").len() + 16);
    }
}

#[test]
fn every_key_reads_as_both_sides_store_it() {
    let v = vectors();
    for (name, key) in v["keys"].as_object().unwrap() {
        let private = secret(&v, name);
        assert_eq!(private.public(), public(&v, name), "{name}");
        assert_eq!(private.public().spki().as_slice(), bytes(key, "spki"), "{name}");
        assert_eq!(bytes(key, "spki")[26..], bytes(key, "point"), "{name}: the spki ends in the point");
        assert_eq!(SecretKey::derive(&arr(&bytes(key, "ikm"))).public(), private.public(), "{name}: DeriveKeyPair of its ikm");
    }
    for name in ["machine", "other_machine"] {
        let from_file = SecretKey::from_pkcs8(&bytes(&v["keys"][name], "pkcs8")).unwrap();
        assert_eq!(from_file.public(), public(&v, name), "{name} from its pkcs8");
    }
    let reply = ReplyKey::make(&arr(&bytes(&v["keys"]["reply"], "ikm")));
    assert_eq!(reply.public(), public(&v, "reply"));
}

#[test]
fn every_case_seals_to_exactly_its_bytes_and_opens() {
    let v = vectors();
    for (c, raw) in cases(&v).iter().zip(v["cases"].as_array().unwrap()) {
        let ikm_e = arr(&bytes(raw, "ikm_e"));
        let ephemeral = SecretKey::from_scalar(&arr(&bytes(raw, "ephemeral_private"))).unwrap();
        assert_eq!(SecretKey::derive(&ikm_e).public(), ephemeral.public(), "{:?}: the ephemeral key is DeriveKeyPair(ikm_e)", c.kind);
        assert_eq!(ephemeral.public().spki()[26..], bytes(raw, "enc"), "{:?}", c.kind);
        let sealed = sealed::seal(c.kind, &secret(&v, &c.from), &public(&v, &c.to), &c.aad, &c.plaintext, &ikm_e).unwrap();
        assert_eq!(sealed, c.sealed, "{:?}", c.kind);
        let opened = sealed::open(c.kind, &secret(&v, &c.to), &public(&v, &c.from), &c.aad, &c.sealed).unwrap();
        assert_eq!(opened.as_slice(), c.plaintext, "{:?}", c.kind);
    }
}

#[test]
fn the_machine_seals_to_the_device_and_the_device_to_the_reply_key() {
    let v = vectors();
    for c in cases(&v) {
        let way = if c.kind == Kind::Answer { ("device", "reply") } else { ("machine", "device") };
        assert_eq!((c.from.as_str(), c.to.as_str()), way, "{:?}", c.kind);
    }
    // The keeper opens an answer with the reply key it made for the question.
    let answer = cases(&v).into_iter().find(|c| c.kind == Kind::Answer).unwrap();
    let reply = ReplyKey::make(&arr(&bytes(&v["keys"]["reply"], "ikm")));
    assert_eq!(reply.open(&public(&v, "device"), &answer.aad, &answer.sealed).unwrap().as_slice(), answer.plaintext);
}

#[test]
fn a_sealed_text_does_not_open_with_a_changed_clear_field() {
    let v = vectors();
    for c in cases(&v) {
        let (to, from) = (secret(&v, &c.to), public(&v, &c.from));
        for i in 0..c.aad.len() {
            let mut changed = c.aad.clone();
            changed[i] ^= 0x01;
            assert_eq!(sealed::open(c.kind, &to, &from, &changed, &c.sealed).unwrap_err(), Refusal::Unreadable, "{:?} byte {i}", c.kind);
        }
        // A name the hub swapped for another of the same length, and fields cut or added to.
        let at = c.aad.windows(8).position(|w| w == b"server-1").unwrap_or_else(|| panic!("{:?} names the machine", c.kind));
        let mut renamed = c.aad.clone();
        renamed[at + 7] = b'2';
        let longer = [c.aad.as_slice(), &[0, 0]].concat();
        for aad in [renamed.as_slice(), &c.aad[..c.aad.len() - 1], &longer, b""] {
            assert_eq!(sealed::open(c.kind, &to, &from, aad, &c.sealed).unwrap_err(), Refusal::Unreadable, "{:?}", c.kind);
        }
        // And no byte of the sealed text can change.
        for i in 0..c.sealed.len() {
            let mut changed = c.sealed.clone();
            changed[i] ^= 0x01;
            assert_eq!(sealed::open(c.kind, &to, &from, &c.aad, &changed).unwrap_err(), Refusal::Unreadable, "{:?} sealed byte {i}", c.kind);
        }
    }
}

#[test]
fn a_sealed_text_does_not_open_under_another_machine_key() {
    let v = vectors();
    let (device, other) = (secret(&v, "device"), secret(&v, "other_machine"));
    for c in cases(&v).into_iter().filter(|c| c.from == "machine") {
        // The phone compared one machine key; a text from it doesn't open as another machine's.
        assert_eq!(sealed::open(c.kind, &device, &other.public(), &c.aad, &c.sealed).unwrap_err(), Refusal::Unreadable, "{:?}", c.kind);
        // And a text another machine key sealed, with the same names, doesn't open as this machine's.
        let forged = sealed::seal(c.kind, &other, &device.public(), &c.aad, &c.plaintext, &[0x55; 32]).unwrap();
        assert_eq!(sealed::open(c.kind, &device, &public(&v, "machine"), &c.aad, &forged).unwrap_err(), Refusal::Unreadable, "{:?}", c.kind);
        assert_eq!(sealed::open(c.kind, &device, &other.public(), &c.aad, &forged).unwrap().as_slice(), c.plaintext, "{:?}", c.kind);
    }
}

#[test]
fn a_sealed_text_does_not_open_for_another_device() {
    let v = vectors();
    let (other, machine) = (secret(&v, "other_device"), public(&v, "machine"));
    for c in cases(&v).into_iter().filter(|c| c.to == "device") {
        assert_eq!(sealed::open(c.kind, &other, &machine, &c.aad, &c.sealed).unwrap_err(), Refusal::Unreadable, "{:?}", c.kind);
    }
    // Nor does an answer another device sealed open as this device's.
    let answer = cases(&v).into_iter().find(|c| c.kind == Kind::Answer).unwrap();
    let reply = ReplyKey::make(&arr(&bytes(&v["keys"]["reply"], "ikm")));
    assert_eq!(reply.open(&public(&v, "other_device"), &answer.aad, &answer.sealed).unwrap_err(), Refusal::Unreadable);
    let forged = sealed::seal(Kind::Answer, &other, &reply.public(), &answer.aad, &answer.plaintext, &[0x55; 32]).unwrap();
    assert_eq!(reply.open(&public(&v, "device"), &answer.aad, &forged).unwrap_err(), Refusal::Unreadable);
}

#[test]
fn a_sealed_text_does_not_open_under_another_label() {
    let v = vectors();
    let all = [Kind::Question, Kind::Notice, Kind::Receipt, Kind::Answer];
    for c in cases(&v) {
        let (to, from) = (secret(&v, &c.to), public(&v, &c.from));
        for other in all.into_iter().filter(|k| *k != c.kind) {
            assert_eq!(sealed::open(other, &to, &from, &c.aad, &c.sealed).unwrap_err(), Refusal::Unreadable, "{:?} as {other:?}", c.kind);
        }
    }
    // A question handed to the keeper as an answer doesn't open with a reply key either.
    let question = cases(&v).into_iter().find(|c| c.kind == Kind::Question).unwrap();
    let reply = ReplyKey::make(&arr(&bytes(&v["keys"]["reply"], "ikm")));
    assert_eq!(reply.open(&public(&v, "machine"), &question.aad, &question.sealed).unwrap_err(), Refusal::Unreadable);
}

#[test]
fn an_answer_does_not_open_with_the_machine_key_file_alone() {
    let v = vectors();
    let answer = cases(&v).into_iter().find(|c| c.kind == Kind::Answer).unwrap();
    // Whoever copied machine-key.pem has the machine key, and nothing of the reply key.
    let machine = SecretKey::from_pkcs8(&bytes(&v["keys"]["machine"], "pkcs8")).unwrap();
    let device = public(&v, "device");
    for kind in [Kind::Question, Kind::Notice, Kind::Receipt, Kind::Answer] {
        assert_eq!(sealed::open(kind, &machine, &device, &answer.aad, &answer.sealed).unwrap_err(), Refusal::Unreadable, "as {kind:?}");
    }
    // Nor does another question's reply key open it: only the one the answer was sealed to.
    let other_reply = ReplyKey::make(&[0x51; 32]);
    assert_ne!(other_reply.public(), public(&v, "reply"));
    assert_eq!(other_reply.open(&device, &answer.aad, &answer.sealed).unwrap_err(), Refusal::Unreadable);
    let reply = ReplyKey::make(&arr(&bytes(&v["keys"]["reply"], "ikm")));
    assert_eq!(reply.open(&device, &answer.aad, &answer.sealed).unwrap().as_slice(), answer.plaintext);
}
