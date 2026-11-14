//! Where this process finds and keeps what it guards: values, the field list, approval records,
//! the policy and box folders, box items and the audit log. At most one place is chosen per
//! process, before the first lookup, and never changed. Every lookup is live: the source keeps
//! paths, never what it reads. The machine's own items (the settings record, saved passphrases)
//! are not the place's: they are free functions here.

mod keychain_items;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::{boxes, index, names};

static CHOSEN: OnceLock<Source> = OnceLock::new();

/// The place chosen for this process.
pub struct Source {
    place: Place,
}

enum Place {
    /// The Keychain items `halti:<res>/<field>` and the files under the config folder.
    Keychain(keychain_items::Items),
}

/// An approval record a place keeps.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Record<'a> {
    Resource(&'a str),
    Box(&'a str),
}

/// What halti keeps for a box outside its store.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BoxItem {
    Key,
    Sessions,
    LogHead,
}

/// Fix this process's source. A second call fails and changes nothing.
pub fn choose(source: Source) -> Result<()> {
    choose_in(&CHOSEN, source)
}

fn choose_in(cell: &OnceLock<Source>, source: Source) -> Result<()> {
    if cell.set(source).is_err() {
        bail!("where secrets are kept was chosen already");
    }
    Ok(())
}

/// The source chosen for this process. Unit tests that choose none get `Source::keychain()`.
/// Anything else that asks when none was chosen is a bug, and panics.
pub fn current() -> &'static Source {
    #[cfg(test)]
    return CHOSEN.get_or_init(Source::keychain);
    #[cfg(not(test))]
    CHOSEN.get().expect("this command chose no place for secrets, so it looks none up")
}

/// What policy.rs's key for an approval record names.
#[derive(PartialEq, Eq, Debug)]
enum Named<'a> {
    /// `config.<sha16>`: the machine's settings record.
    Settings,
    Place(Record<'a>),
}

/// `config.` is the machine's settings record, `box.` a box, anything else a resource. Resource
/// names can't contain a dot, so the three never meet.
fn named(key: &str) -> Named<'_> {
    if key.starts_with(names::CONFIG_KEY_PREFIX) {
        return Named::Settings;
    }
    match key.strip_prefix(boxes::KEY_PREFIX) {
        Some(name) => Named::Place(Record::Box(name)),
        None => Named::Place(Record::Resource(key)),
    }
}

// Approval records by policy.rs's key: `config.<sha16>` is the machine's settings record, any
// other goes to `current()`. Read only if it can be trusted (on the Keychain: with no prompt, so
// a planted item reads as missing); written as a new item that only the running halti reads.

pub fn record(key: &str) -> Option<String> {
    match named(key) {
        Named::Settings => machine_open().then(|| keychain_items::settings_record(key))?,
        Named::Place(of) => current().record(of),
    }
}

pub fn pin_record(key: &str, json: &str) -> Result<()> {
    match named(key) {
        Named::Settings if machine_open() => keychain_items::pin_settings(key, json),
        Named::Settings => bail!("the settings can't be approved from a process that keeps a workspace"),
        Named::Place(of) => current().pin_record(of, json),
    }
}

pub fn remove_record(key: &str) {
    match named(key) {
        Named::Settings if machine_open() => keychain_items::remove_settings(key),
        Named::Settings => {}
        Named::Place(of) => current().remove_record(of),
    }
}

// A workspace's saved passphrase, as `ws/saved.rs` keeps it.

pub fn saved_exists(ws: &str) -> bool {
    machine_open() && keychain_items::saved_exists(ws)
}

pub fn saved_add(ws: &str, passphrase: &str) -> Result<()> {
    if !machine_open() {
        bail!("a passphrase can't be saved from a process that keeps a workspace");
    }
    keychain_items::saved_add(ws, passphrase)
}

pub fn saved_get(ws: &str) -> Option<Zeroizing<String>> {
    machine_open().then(|| keychain_items::saved_get(ws))?
}

pub fn saved_remove(ws: &str) -> bool {
    machine_open() && keychain_items::saved_remove(ws)
}

/// Whether the machine's items may be reached: before any choice, or with the Keychain chosen.
fn machine_open() -> bool {
    match CHOSEN.get().map(|s| &s.place) {
        None | Some(Place::Keychain(_)) => true,
    }
}

impl Source {
    /// The Keychain and the config folder. The folders, and the hooks that move them in debug
    /// builds, are read now.
    pub fn keychain() -> Source {
        Source { place: Place::Keychain(keychain_items::Items::new()) }
    }

    // Values, by the names `halti set` takes.

    pub fn value(&self, res: &str, field: &str) -> Option<String> {
        match &self.place {
            Place::Keychain(k) => k.value(res, field),
        }
    }

    /// Without reading the value, so it never prompts.
    pub fn has_value(&self, res: &str, field: &str) -> bool {
        match &self.place {
            Place::Keychain(k) => k.has_value(res, field),
        }
    }

    pub fn store_value(&self, res: &str, field: &str, value: &str) -> Result<()> {
        match &self.place {
            Place::Keychain(k) => k.store_value(res, field, value),
        }
    }

    /// Stored again as a new item.
    pub fn reseal_value(&self, res: &str, field: &str, value: &str) -> Result<()> {
        match &self.place {
            Place::Keychain(k) => k.reseal_value(res, field, value),
        }
    }

    pub fn remove_value(&self, res: &str, field: &str) -> bool {
        match &self.place {
            Place::Keychain(k) => k.remove_value(res, field),
        }
    }

    // The field list.

    pub fn index(&self) -> Result<BTreeMap<String, index::Resource>> {
        match &self.place {
            Place::Keychain(k) => k.index(),
        }
    }

    pub fn save_index(&self, map: &BTreeMap<String, index::Resource>) -> Result<()> {
        match &self.place {
            Place::Keychain(k) => k.save_index(map),
        }
    }

    // Approval records this place keeps (reached through the free functions above).

    fn record(&self, of: Record<'_>) -> Option<String> {
        match &self.place {
            Place::Keychain(k) => k.record(of),
        }
    }

    fn pin_record(&self, of: Record<'_>, json: &str) -> Result<()> {
        match &self.place {
            Place::Keychain(k) => k.pin_record(of, json),
        }
    }

    fn remove_record(&self, of: Record<'_>) {
        match &self.place {
            Place::Keychain(k) => k.remove_record(of),
        }
    }

    // Folders.

    pub fn policy_dir(&self) -> &Path {
        match &self.place {
            Place::Keychain(k) => k.policy_dir(),
        }
    }

    pub fn box_dir(&self) -> &Path {
        match &self.place {
            Place::Keychain(k) => k.box_dir(),
        }
    }

    // Box items. The key is read as values are, so it may prompt; the others with no prompt.
    // `set_box_item` updates an item in place.

    pub fn box_item(&self, name: &str, item: BoxItem) -> Option<String> {
        match &self.place {
            Place::Keychain(k) => k.box_item(name, item),
        }
    }

    pub fn has_box_item(&self, name: &str, item: BoxItem) -> bool {
        match &self.place {
            Place::Keychain(k) => k.has_box_item(name, item),
        }
    }

    pub fn set_box_item(&self, name: &str, item: BoxItem, value: &str) -> Result<()> {
        match &self.place {
            Place::Keychain(k) => k.set_box_item(name, item, value),
        }
    }

    pub fn remove_box_item(&self, name: &str, item: BoxItem) -> bool {
        match &self.place {
            Place::Keychain(k) => k.remove_box_item(name, item),
        }
    }

    // The audit log and the key that chains it, made on first use if `create`.

    pub fn audit_log(&self) -> &Path {
        match &self.place {
            Place::Keychain(k) => k.audit_log(),
        }
    }

    pub fn audit_key(&self, create: bool) -> Result<Vec<u8>> {
        match &self.place {
            Place::Keychain(k) => k.audit_key(create),
        }
    }

    /// A password another app keeps, such as Chrome's "Chrome Safe Storage".
    pub fn app_password(&self, service: &str, account: &str) -> Result<Vec<u8>> {
        match &self.place {
            Place::Keychain(k) => k.app_password(service, account),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::keychain_items::{AUDIT, box_item_name, record_item, settings_item};
    use super::*;

    #[test]
    fn each_kind_keeps_its_keychain_name() {
        let pair = |(res, field): (String, &str)| format!("{res}/{field}");
        assert_eq!(pair(record_item(Record::Resource("app"))), "app/_policy");
        assert_eq!(pair(record_item(Record::Box("dev"))), "box.dev/_policy");
        assert_eq!(pair(settings_item("config.0123456789abcdef")), "config.0123456789abcdef/_policy");
        assert_eq!(pair(box_item_name("dev", BoxItem::Key)), "box.dev/_key");
        assert_eq!(pair(box_item_name("dev", BoxItem::Sessions)), "box.dev/_sessions");
        assert_eq!(pair(box_item_name("dev", BoxItem::LogHead)), "box.dev/_loghead");
        assert_eq!(AUDIT, ("_audit", "hmac"));
    }

    #[test]
    fn a_key_reads_as_the_kind_it_names() {
        assert_eq!(named("app"), Named::Place(Record::Resource("app")));
        assert_eq!(named("box.dev"), Named::Place(Record::Box("dev")));
        assert_eq!(named("config.x"), Named::Settings);
    }

    #[test]
    fn a_second_choice_is_refused() {
        let cell = OnceLock::new();
        choose_in(&cell, Source::keychain()).unwrap();
        let first = cell.get().unwrap().policy_dir().to_path_buf();
        assert!(choose_in(&cell, Source::keychain()).is_err());
        assert_eq!(cell.get().unwrap().policy_dir(), first);
    }
}
