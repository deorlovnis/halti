//! The workspace place against real workspaces in a test folder (`ws::bench_tests`): what it
//! answers, what it refuses, and that it reads the workspace again while it is open. Each make,
//! change and open derives a key at 64 MiB once.

use std::fs;
use std::os::unix::fs::MetadataExt;

use super::*;
use crate::util::sha256_hex;
use crate::ws::bench_tests::Bench;

const ACME: &str = "acme passphrase one";
const GLOBEX: &str = "globex passphrase one";
const GITHUB: &str = "[fetch]\nhosts = [\"https://api.github.com\"]\nauth = \"Bearer {token}\"\n";
const DEV: &str = "image = \"halti-agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n";

/// acme with github/token, github's policy approved and box dev with a key; globex with a
/// github/token of its own. Returns the bench and acme's place.
fn acme_and_globex(prefix: &str) -> (Bench, Source) {
    let bench = Bench::new(prefix);
    bench.make("acme", ACME);
    bench.make("globex", GLOBEX);
    bench.set("acme", ACME, "github", "token", "acme's token");
    bench.set("globex", GLOBEX, "github", "token", "globex's token");
    bench.set("globex", GLOBEX, "linear", "token", "globex's linear");
    bench.approve("acme", ACME, "github", GITHUB);
    bench.make_box("acme", ACME, "dev", [0x30; 32], DEV);
    let (reader, reading) = bench.open("acme", ACME);
    let settings = Settings::builtin(crate::ws::OS);
    (bench, Source::workspace(WsName::parse("acme").unwrap(), reader, reading, settings))
}

#[test]
fn the_place_answers_from_the_workspace_only() {
    let (bench, acme) = acme_and_globex("halti-place-only");
    // Its own values, never globex's, and nothing it lacks.
    assert_eq!(acme.value("github", "token").as_deref(), Some("acme's token"));
    assert!(acme.has_value("github", "token") && !acme.has_value("linear", "token"));
    assert_eq!((acme.value("linear", "token"), acme.value("github", "user"), acme.value("github", "_policy"), acme.value("Git", "token")), (None, None, None, None));
    let index = acme.index().unwrap();
    assert_eq!(index.keys().collect::<Vec<_>>(), ["github"]);
    assert_eq!(index["github"].fields.keys().collect::<Vec<_>>(), ["token"]);
    assert!(index["github"].url.is_empty() && index["github"].description.is_empty());
    // Its approvals: the sealed hash, no scripts and no text.
    let record: serde_json::Value = serde_json::from_str(&acme.record(Record::Resource("github")).unwrap()).unwrap();
    assert_eq!(record, serde_json::json!({ "policy": sha256_hex(GITHUB.as_bytes()), "scripts": {}, "text": null }));
    assert_eq!(acme.record(Record::Resource("linear")), None);
    assert!(acme.record(Record::Resource("dev")).is_none(), "a box's approval never reads as a resource's");
    let record: serde_json::Value = serde_json::from_str(&acme.record(Record::Box("dev")).unwrap()).unwrap();
    assert_eq!(record["policy"], sha256_hex(DEV.as_bytes()));
    // Its box key, as hdiutil is given it; there is none for a box it doesn't list.
    assert_eq!(acme.box_item("dev", BoxItem::Key).as_deref(), Some("30".repeat(32).as_str()));
    assert!(acme.has_box_item("dev", BoxItem::Key) && !acme.has_box_item("other", BoxItem::Key) && acme.box_item("other", BoxItem::Key).is_none());
    // Its folders, all in its own folder.
    let acme_dir = acme_dir(&bench, &acme);
    assert_eq!(acme.policy_dir(), acme_dir.join("policies"));
    assert_eq!(
        (acme.box_dir(), acme.audit_log(), acme.blocked_dir()),
        (acme_dir.join("boxes/policies").as_path(), acme_dir.join("boxes/audit.log").as_path(), acme_dir.join("boxes/blocked-writes"))
    );
    assert_eq!(acme.audit_key(true).unwrap().len(), 32);
    assert_eq!(acme.audit_key(false).unwrap(), acme.audit_key(true).unwrap(), "the same key, made by nothing");
    // A policy file is read as the workspace's commands read it.
    assert_eq!(acme.policy_text("github").unwrap(), None);
    fs::create_dir_all(acme_dir.join("policies")).unwrap();
    fs::write(acme_dir.join("policies/github.toml"), GITHUB).unwrap();
    assert_eq!(acme.policy_text("github").unwrap().as_deref(), Some(GITHUB.as_bytes()));
    std::os::unix::fs::symlink(acme_dir.join("policies/github.toml"), acme_dir.join("policies/linear.toml")).unwrap();
    assert!(acme.policy_text("linear").is_err(), "never through a link");
}

#[test]
fn settings_after_the_choice_are_the_copy() {
    let bench = Bench::new("halti-place-settings");
    bench.make("acme", ACME);
    let (reader, reading) = bench.open("acme", ACME);
    // Settings unlike the template's, as read before the choice.
    let read_before = crate::config::parse("[paths]\nworkspaces = \"~/elsewhere/ws\"\n", crate::ws::OS).unwrap();
    assert_ne!(read_before, Settings::builtin(crate::ws::OS));
    let cell = std::sync::OnceLock::new();
    assert!(machine_open_in(&cell) && settings_in(&cell).is_none());
    choose_in(&cell, Source::workspace(WsName::parse("acme").unwrap(), reader, reading, read_before.clone())).unwrap();
    // The machine's own items are closed, and the settings are the copy.
    assert!(!machine_open_in(&cell));
    assert_eq!(settings_in(&cell), Some(&read_before));
}

/// The workspace folder of the place.
fn acme_dir(bench: &Bench, acme: &Source) -> PathBuf {
    acme.policy_dir().parent().filter(|dir| dir.parent() == Some(bench.root())).expect("in the workspaces folder").to_path_buf()
}

#[test]
fn a_value_set_while_running_is_read_at_the_next_lookup() {
    let (bench, acme) = acme_and_globex("halti-place-live");
    let pin = bench.root().join("pins").join(acme_dir(&bench, &acme).file_name().unwrap());
    let opened_under = fs::read(&pin).unwrap();
    assert_eq!(acme.value("github", "token").as_deref(), Some("acme's token"));
    // Rotated, added and approved since the open: the next lookup sees each.
    bench.set("acme", ACME, "github", "token", "acme's new token");
    assert_eq!(acme.value("github", "token").as_deref(), Some("acme's new token"));
    bench.set("acme", ACME, "linear", "token", "acme's linear");
    assert_eq!(acme.value("linear", "token").as_deref(), Some("acme's linear"));
    assert!(acme.index().unwrap().contains_key("linear"));
    assert_eq!(acme.record(Record::Resource("linear")), None);
    bench.approve("acme", ACME, "linear", "[fetch]\nhosts = [\"https://linear.example.com\"]\n");
    assert!(acme.record(Record::Resource("linear")).is_some());
    // The pin the place was opened under, put back: every lookup fails, until the pin is the one
    // seen again.
    let now = fs::read(&pin).unwrap();
    fs::write(&pin, &opened_under).unwrap();
    assert_eq!((acme.value("github", "token"), acme.record(Record::Resource("github")), acme.box_item("dev", BoxItem::Key)), (None, None, None));
    assert!(acme.index().is_err() && acme.audit_key(true).is_err() && !acme.has_box_item("dev", BoxItem::Key));
    fs::write(&pin, &now).unwrap();
    assert_eq!(acme.value("github", "token").as_deref(), Some("acme's new token"));
}

#[test]
fn sealed_writes_are_refused() {
    let (bench, acme) = acme_and_globex("halti-place-refused");
    let said = |result: Result<()>| result.unwrap_err().to_string();
    assert_eq!(said(acme.store_value("github", "token", "planted")), "a running box can't change acme's secrets: halti ws set acme/github token");
    assert_eq!(said(acme.reseal_value("github", "token", "planted")), "a running box can't change acme's secrets: halti ws set acme/github token");
    assert_eq!(said(acme.save_index(&BTreeMap::new())), "a running box can't change acme's secrets: halti ws set acme/RESOURCE FIELD");
    assert!(!acme.remove_value("github", "token"));
    assert_eq!(said(acme.pin_record(Record::Resource("linear"), "{}")), "approving a policy in a workspace takes its passphrase: halti ws policy approve acme/linear");
    assert_eq!(said(acme.pin_record(Record::Box("dev"), "{}")), "approving a policy in a workspace takes its passphrase: halti ws box approve acme/dev");
    assert_eq!(said(acme.remove_record(Record::Resource("github"))), "approving a policy in a workspace takes its passphrase: halti ws policy approve acme/github");
    assert_eq!(said(acme.set_box_item("dev", BoxItem::Key, "00")), "a box's key in a workspace is kept only by: halti ws box new acme/dev");
    assert!(!acme.remove_box_item("dev", BoxItem::Key));
    // Nothing changed.
    assert_eq!(acme.value("github", "token").as_deref(), Some("acme's token"));
    assert!(acme.record(Record::Resource("github")).is_some() && acme.record(Record::Resource("linear")).is_none());
    assert_eq!(acme.box_item("dev", BoxItem::Key).as_deref(), Some("30".repeat(32).as_str()));
    // What a run notes is plain files beside the boxes, 0600.
    acme.set_box_item("dev", BoxItem::Sessions, "github,linear").unwrap();
    acme.set_box_item("dev", BoxItem::LogHead, "{\"lines\":2}").unwrap();
    let boxes = acme_dir(&bench, &acme).join("boxes");
    assert_eq!(fs::read_to_string(boxes.join("dev.sessions")).unwrap(), "github,linear");
    assert_eq!(fs::metadata(boxes.join("dev.head")).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&boxes).unwrap().mode() & 0o777, 0o700);
    assert_eq!(acme.box_item("dev", BoxItem::Sessions).as_deref(), Some("github,linear"));
    assert!(acme.has_box_item("dev", BoxItem::LogHead) && acme.remove_box_item("dev", BoxItem::LogHead) && !acme.has_box_item("dev", BoxItem::LogHead));
    assert!(acme.set_box_item("../x", BoxItem::Sessions, "x").is_err() && acme.box_item("../x", BoxItem::Sessions).is_none());
}

#[test]
fn app_password_is_refused_and_refresh_is_off() {
    let (_bench, acme) = acme_and_globex("halti-place-app");
    assert_eq!(acme.app_password("Chrome Safe Storage", "Chrome").unwrap_err().to_string(), "a box in a workspace can't read another app's password");
    assert!(!acme.refreshes() && acme.keeps_box_keys());
    assert!(Source::keychain().refreshes() && !Source::keychain().keeps_box_keys());
}

#[test]
fn the_hints_name_the_workspace_s_commands() {
    let (_bench, acme) = acme_and_globex("halti-place-hints");
    let hints =
        |source: &Source| [Hint::WritePolicy("github"), Hint::ApprovePolicy("github"), Hint::SetValue("github", "token"), Hint::RemoveBox("dev")].map(|hint| source.hint(hint));
    assert_eq!(hints(&acme), ["halti ws policy edit acme/github", "halti ws policy approve acme/github", "halti ws set acme/github token", "halti ws box rm acme/dev"]);
    assert_eq!(hints(&Source::keychain()), ["halti policy edit github", "halti policy approve github", "halti set github token", "halti box rm dev"]);
    assert_eq!((acme.named("github"), Source::keychain().named("github")), ("github in acme".to_string(), "github".to_string()));
}
