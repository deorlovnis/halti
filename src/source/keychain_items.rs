//! halti's Keychain items, as `keychain` names them (`halti:<res>/<field>`), the saved
//! passphrases, and the files under the config folder. The only code that names `keychain::`.

use std::collections::BTreeMap;
#[cfg(halti_dev)]
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use zeroize::Zeroizing;

use super::{BoxItem, Record};
use crate::util::config_dir;
#[cfg(halti_dev)]
use crate::util::dev_var;
use crate::{boxes, index, keychain};

/// The Keychain field of an approval record. Field names can't start with "_".
const APPROVAL: &str = "_policy";
/// The Keychain field of a box's store key.
const KEY_FIELD: &str = "_key";
/// The Keychain field of where the box's door log stood when it last stopped (`chain::Head`).
const LOG_HEAD_FIELD: &str = "_loghead";
/// The Keychain field with the names of the sites that have a sealed session, kept by the halti that
/// sealed them so `halti box ls` can show them without opening the store.
const SESSIONS_FIELD: &str = "_sessions";
/// Keychain item of the audit log's HMAC key. Resource names can't start with "_".
pub(super) const AUDIT: (&str, &str) = ("_audit", "hmac");

/// The Keychain name of an approval record: a resource's, or a box's under `box.<name>`.
pub(super) fn record_item(of: Record<'_>) -> (String, &'static str) {
    match of {
        Record::Resource(res) => (res.to_string(), APPROVAL),
        Record::Box(name) => (boxes::key(name), APPROVAL),
    }
}

/// The Keychain name of the machine's settings record, by its key (`config.<sha16>`).
pub(super) fn settings_item(key: &str) -> (String, &'static str) {
    (key.to_string(), APPROVAL)
}

/// The Keychain name of what halti keeps for a box outside its store.
pub(super) fn box_item_name(name: &str, item: BoxItem) -> (String, &'static str) {
    let field = match item {
        BoxItem::Key => KEY_FIELD,
        BoxItem::Sessions => SESSIONS_FIELD,
        BoxItem::LogHead => LOG_HEAD_FIELD,
    };
    (boxes::key(name), field)
}

// The machine's own items.

pub(super) fn settings_record(key: &str) -> Option<String> {
    let (res, field) = settings_item(key);
    keychain::get_silently(&res, field)
}

pub(super) fn pin_settings(key: &str, json: &str) -> Result<()> {
    let (res, field) = settings_item(key);
    keychain::replace(&res, field, json)
}

pub(super) fn remove_settings(key: &str) {
    let (res, field) = settings_item(key);
    keychain::delete(&res, field);
}

pub(super) fn saved_exists(ws: &str) -> bool {
    keychain::ws_exists(ws)
}

pub(super) fn saved_add(ws: &str, passphrase: &str) -> Result<()> {
    keychain::ws_add(ws, passphrase)
}

pub(super) fn saved_get(ws: &str) -> Option<Zeroizing<String>> {
    keychain::ws_get(ws)
}

pub(super) fn saved_remove(ws: &str) -> bool {
    keychain::ws_delete(ws)
}

/// The Keychain and the files under the config folder, where this build keeps them.
pub(super) struct Items {
    /// The field list: index.json.
    index: PathBuf,
    /// Resources' policies.
    policies: PathBuf,
    /// Boxes' policies.
    boxes: PathBuf,
    audit_log: PathBuf,
    /// Where pages' blocked writes are noted.
    blocked: PathBuf,
    /// A key tests give the audit log instead of the Keychain's.
    #[cfg(halti_dev)]
    audit_key: Option<OsString>,
}

impl Items {
    pub(super) fn new() -> Items {
        let config = config_dir();
        let items = Items {
            index: config.join("index.json"),
            policies: config.join("policy"),
            boxes: config.join("box"),
            audit_log: config.join("audit.log"),
            blocked: config.join("blocked-writes"),
            #[cfg(halti_dev)]
            audit_key: None,
        };
        #[cfg(halti_dev)]
        let items = items.hooked();
        items
    }

    /// Tests keep an index, policies, box policies and an audit log of their own, and give the
    /// audit log its key. Release builds don't contain this.
    #[cfg(halti_dev)]
    fn hooked(mut self) -> Items {
        if let Some(path) = dev_var("HALTI_INDEX") {
            self.index = path.into();
        }
        if let Some(dir) = dev_var("HALTI_POLICY_DIR") {
            self.policies = dir.into();
        }
        if let Some(dir) = dev_var("HALTI_BOX_DIR") {
            self.boxes = dir.into();
        }
        if let Some(path) = dev_var("HALTI_AUDIT") {
            self.audit_log = path.into();
        }
        self.audit_key = dev_var("HALTI_AUDIT_KEY");
        self
    }

    pub(super) fn value(&self, res: &str, field: &str) -> Option<String> {
        keychain::get(res, field)
    }

    pub(super) fn has_value(&self, res: &str, field: &str) -> bool {
        keychain::exists(res, field)
    }

    pub(super) fn store_value(&self, res: &str, field: &str, value: &str) -> Result<()> {
        keychain::set(res, field, value)
    }

    pub(super) fn reseal_value(&self, res: &str, field: &str, value: &str) -> Result<()> {
        keychain::replace(res, field, value)
    }

    pub(super) fn remove_value(&self, res: &str, field: &str) -> bool {
        keychain::delete(res, field)
    }

    pub(super) fn index(&self) -> Result<BTreeMap<String, index::Resource>> {
        let path = &self.index;
        Ok(match fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).with_context(|| format!("reading {}", path.display()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        })
    }

    pub(super) fn save_index(&self, map: &BTreeMap<String, index::Resource>) -> Result<()> {
        if let Some(dir) = self.index.parent() {
            fs::create_dir_all(dir)?;
        }
        // Write then rename, so a crash never leaves a half-written index.
        let tmp = self.index.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(map)? + "\n")?;
        fs::rename(&tmp, &self.index)?;
        Ok(())
    }

    /// Read only if macOS lets halti do so without asking: one planted by another program would
    /// need a prompt, so it reads as missing.
    pub(super) fn record(&self, of: Record<'_>) -> Option<String> {
        let (res, field) = record_item(of);
        keychain::get_silently(&res, field)
    }

    /// In a new item, so its access list names only the halti running now.
    pub(super) fn pin_record(&self, of: Record<'_>, json: &str) -> Result<()> {
        let (res, field) = record_item(of);
        keychain::replace(&res, field, json)
    }

    pub(super) fn remove_record(&self, of: Record<'_>) {
        let (res, field) = record_item(of);
        keychain::delete(&res, field);
    }

    pub(super) fn policy_dir(&self) -> &Path {
        &self.policies
    }

    pub(super) fn box_dir(&self) -> &Path {
        &self.boxes
    }

    pub(super) fn blocked_dir(&self) -> PathBuf {
        self.blocked.clone()
    }

    pub(super) fn box_item(&self, name: &str, item: BoxItem) -> Option<String> {
        let (res, field) = box_item_name(name, item);
        match item {
            BoxItem::Key => keychain::get(&res, field),
            BoxItem::Sessions | BoxItem::LogHead => keychain::get_silently(&res, field),
        }
    }

    pub(super) fn has_box_item(&self, name: &str, item: BoxItem) -> bool {
        let (res, field) = box_item_name(name, item);
        keychain::exists(&res, field)
    }

    pub(super) fn set_box_item(&self, name: &str, item: BoxItem, value: &str) -> Result<()> {
        let (res, field) = box_item_name(name, item);
        keychain::set(&res, field, value)
    }

    pub(super) fn remove_box_item(&self, name: &str, item: BoxItem) -> bool {
        let (res, field) = box_item_name(name, item);
        keychain::delete(&res, field)
    }

    pub(super) fn audit_log(&self) -> &Path {
        &self.audit_log
    }

    pub(super) fn audit_key(&self, create: bool) -> Result<Vec<u8>> {
        // Tests inject a key instead of touching the Keychain. Release builds don't contain this.
        #[cfg(halti_dev)]
        if let Some(key) = &self.audit_key {
            return Ok(key.clone().into_encoded_bytes());
        }
        let (res, field) = AUDIT;
        if keychain::exists(res, field) {
            return keychain::get(res, field).map(String::into_bytes).ok_or_else(|| anyhow!("can't read the audit key from the Keychain"));
        }
        if !create {
            bail!("the audit key isn't in the Keychain, so the log can't be verified");
        }
        let mut bytes = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let key: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        keychain::set(res, field, &key)?;
        Ok(key.into_bytes())
    }

    pub(super) fn app_password(&self, service: &str, account: &str) -> Result<Vec<u8>> {
        keychain::get_app_password(service, account)
    }
}
