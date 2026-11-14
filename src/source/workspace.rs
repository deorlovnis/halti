//! One open workspace as the place: every lookup of a process that runs one of its boxes answers
//! from it, and from nothing else. A miss is a miss: nothing here falls back to another place, so
//! a resource this workspace lacks can never be read from one of the same name elsewhere.
//!
//! What it holds is core's `Reader`, behind a lock: the keys for values, the store and the audit
//! log, and the manifest as last read, never a key that seals. Before each lookup it reads the pin
//! and, if it moved, the manifest again, so a value stored or a policy approved since is used at
//! once; a pin put back below the one seen makes every lookup fail, and is reported once
//! (`refused_reread`). A value that doesn't open is read again once, for a change that landed
//! while it was read. Once closed, the keys are wiped, and every lookup fails.
//!
//! Every sealed write is refused: values, approvals and box keys change only through the
//! workspace's commands, which ask for its passphrase. What a run notes outside the store (which
//! sites have a session, where the log stands, the MCP audit log, blocked writes) is plain files
//! in the workspace's boxes folder.

use std::collections::BTreeMap;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use anyhow::{Result, anyhow, bail};
use halti_core::boxkey::check_box;
use halti_core::ids::{WsId, WsName};
use halti_core::item::ItemKey;
use halti_core::policy::Kind;
use halti_core::refusal::Refusal;
use halti_core::verbs::Reader;

use super::{BoxItem, Hint, Record};
use crate::config::Settings;
use crate::ws::Reading;
use crate::{index, policy};

/// A workspace opened once, and the settings read before it was chosen.
pub(super) struct Opened {
    name: WsName,
    id: WsId,
    /// None once closed.
    reader: Mutex<Option<Reader>>,
    /// A reread was refused for files that went back: 1 until it is reported, then 2.
    refused: AtomicU8,
    reading: Reading,
    settings: Settings,
    /// WSDIR/policies
    policies: PathBuf,
    /// WSDIR/boxes/policies
    box_policies: PathBuf,
    /// WSDIR/boxes/audit.log
    audit_log: PathBuf,
    /// WSDIR/boxes/blocked-writes
    blocked: PathBuf,
}

impl Opened {
    /// The workspace `name` as `reader` opened it, its folders where `reading` finds them by the
    /// id the open read.
    pub(super) fn new(name: WsName, reader: Reader, reading: Reading, settings: Settings) -> Opened {
        let id = reader.id();
        let boxes = reading.dir(id).join("boxes");
        Opened {
            policies: reading.policy_dir(id),
            box_policies: boxes.join("policies"),
            audit_log: boxes.join("audit.log"),
            blocked: boxes.join("blocked-writes"),
            name,
            id,
            reader: Mutex::new(Some(reader)),
            refused: AtomicU8::new(0),
            reading,
            settings,
        }
    }

    /// The reader, with the manifest read again if the pin moved since; none once closed.
    fn read(&self) -> Result<Held<'_>> {
        let mut held = self.reader.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(reader) = held.as_mut() else { bail!("{} is closed", self.name) };
        if let Err(error) = reader.reread(self.reading.files(), self.reading.anchor(), &self.name) {
            if error.downcast_ref::<Refusal>() == Some(&Refusal::Tampered) {
                let _ = self.refused.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
            }
            return Err(error);
        }
        Ok(Held(held))
    }

    /// Wipes the keys: every lookup fails from now on. The reader is dropped where it is: one moved
    /// out first would be wiped as the copy, and leave its keys here.
    pub(super) fn close(&self) {
        *self.reader.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// True once, after a reread was refused because the workspace's files went back to an older
    /// state: from then on every lookup fails, which reads like a secret that isn't stored.
    pub(super) fn refused_reread(&self) -> bool {
        self.refused.compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }

    /// Keeps the pages that hold the keys out of swap, for a process that holds them all day. They
    /// are inline in this value.
    pub(super) fn lock_keys(&self) {
        crate::ws::lock_pages((self as *const Self).cast(), std::mem::size_of::<Self>());
    }

    pub(super) fn settings(&self) -> &Settings {
        &self.settings
    }

    /// What the person or the agent is told to do, in the workspace's commands.
    pub(super) fn hint(&self, hint: Hint<'_>) -> String {
        let ws = &self.name;
        match hint {
            Hint::WritePolicy(res) => format!("halti ws policy edit {ws}/{res}"),
            Hint::ApprovePolicy(res) => format!("halti ws policy approve {ws}/{res}"),
            Hint::SetValue(res, field) => format!("halti ws set {ws}/{res} {field}"),
            Hint::RemoveBox(name) => format!("halti ws box rm {ws}/{name}"),
        }
    }

    pub(super) fn named(&self, res: &str) -> String {
        format!("{res} in {}", self.name)
    }

    pub(super) fn no_policy(&self, res: &str) -> String {
        format!("{res} has no policy in {}. write one with: {}", self.name, self.hint(Hint::WritePolicy(res)))
    }

    pub(super) fn unapproved(&self, res: &str) -> String {
        format!("the policy for {} isn't approved. approve it with: {}", self.named(res), self.hint(Hint::ApprovePolicy(res)))
    }

    // Values: read live, never written.

    /// A field that isn't one an item can have, or a value that can't be read, is none.
    pub(super) fn value(&self, res: &str, field: &str) -> Option<String> {
        let key = ItemKey::parse(res, field).ok()?;
        for _ in 0..2 {
            let reader = self.read().ok()?;
            match reader.value(self.reading.keystore(), &key) {
                Ok(value) => return value.and_then(|secret| String::from_utf8(secret.as_bytes().to_vec()).ok()),
                // Replaced while it was read: once more, with the manifest that lists it.
                Err(error) if error.downcast_ref::<Refusal>() == Some(&Refusal::Unreadable) => continue,
                Err(_) => return None,
            }
        }
        None
    }

    pub(super) fn has_value(&self, res: &str, field: &str) -> bool {
        self.value(res, field).is_some()
    }

    fn secrets_refused(&self, res: &str, field: &str) -> anyhow::Error {
        anyhow!("a running box can't change {}'s secrets: {}", self.name, self.hint(Hint::SetValue(res, field)))
    }

    pub(super) fn store_value(&self, res: &str, field: &str) -> Result<()> {
        Err(self.secrets_refused(res, field))
    }

    /// The field list, from the secrets the manifest lists: no dates, url or description.
    pub(super) fn index(&self) -> Result<BTreeMap<String, index::Resource>> {
        let reader = self.read()?;
        let mut map: BTreeMap<String, index::Resource> = BTreeMap::new();
        for key in reader.items() {
            map.entry(key.resource().to_string()).or_default().fields.insert(key.field().to_string(), index::Field::default());
        }
        Ok(map)
    }

    pub(super) fn save_index(&self) -> Result<()> {
        Err(self.secrets_refused("RESOURCE", "FIELD"))
    }

    // Approvals: the sealed hashes, as an approval record with no scripts and no text.

    pub(super) fn record(&self, of: Record<'_>) -> Option<String> {
        let (kind, name) = match of {
            Record::Resource(res) => (Kind::Resource, res),
            Record::Box(name) => (Kind::Box, name),
        };
        let reader = self.read().ok()?;
        let sha256: String = reader.approval(kind, name)?.sha256().iter().map(|b| format!("{b:02x}")).collect();
        serde_json::to_string(&policy::Approval::sealed(&sha256)).ok()
    }

    pub(super) fn pin_record(&self, of: Record<'_>) -> Result<()> {
        let command = match of {
            Record::Resource(res) => self.hint(Hint::ApprovePolicy(res)),
            Record::Box(name) => format!("halti ws box approve {}/{name}", self.name),
        };
        bail!("approving a policy in a workspace takes its passphrase: {command}")
    }

    // Folders.

    pub(super) fn policy_dir(&self) -> &Path {
        &self.policies
    }

    /// A resource's policy, read as the workspace's commands read it: never through a link, and at
    /// most a policy's longest text.
    pub(super) fn policy_text(&self, res: &str) -> Result<Option<Vec<u8>>> {
        self.reading.policy(self.id, res)
    }

    pub(super) fn box_dir(&self) -> &Path {
        &self.box_policies
    }

    // Box items: the key sealed in the workspace, the others plain files beside its boxes.

    /// The plain file of a box item other than its key: BOX.sessions, BOX.head.
    fn box_file(name: &str, item: BoxItem) -> Option<String> {
        check_box(name).ok()?;
        match item {
            BoxItem::Key => None,
            BoxItem::Sessions => Some(format!("{name}.sessions")),
            BoxItem::LogHead => Some(format!("{name}.head")),
        }
    }

    pub(super) fn box_item(&self, name: &str, item: BoxItem) -> Option<String> {
        if item == BoxItem::Key {
            let reader = self.read().ok()?;
            return reader.box_key(self.reading.keystore(), name).ok()?.map(|key| key.hex().to_string());
        }
        let bytes = self.reading.box_file(self.id, &Self::box_file(name, item)?).ok()??;
        String::from_utf8(bytes).ok()
    }

    pub(super) fn has_box_item(&self, name: &str, item: BoxItem) -> bool {
        if item == BoxItem::Key {
            return self.read().is_ok_and(|reader| reader.manifest().boxes.iter().any(|entry| entry.name == name));
        }
        Self::box_file(name, item).is_some_and(|file| self.reading.box_file(self.id, &file).is_ok_and(|bytes| bytes.is_some()))
    }

    pub(super) fn set_box_item(&self, name: &str, item: BoxItem, value: &str) -> Result<()> {
        if item == BoxItem::Key {
            bail!("a box's key in a workspace is kept only by: halti ws box new {}/{name}", self.name);
        }
        let file = Self::box_file(name, item).ok_or_else(|| anyhow!("that isn't a box: 1 to 32 of a-z, 0-9 and -"))?;
        self.reading.put_box_file(self.id, &file, value.as_bytes())
    }

    pub(super) fn remove_box_item(&self, name: &str, item: BoxItem) -> bool {
        Self::box_file(name, item).is_some_and(|file| self.reading.remove_box_file(self.id, &file).unwrap_or(false))
    }

    // The MCP audit log of the workspace's boxes, chained with a key derived from its logs key.

    pub(super) fn audit_log(&self) -> &Path {
        &self.audit_log
    }

    pub(super) fn audit_key(&self) -> Result<Vec<u8>> {
        Ok(self.read()?.audit_key().to_vec())
    }

    pub(super) fn app_password(&self) -> Result<Vec<u8>> {
        bail!("a box in a workspace can't read another app's password")
    }

    pub(super) fn blocked_dir(&self) -> &Path {
        &self.blocked
    }
}

/// The reader of a workspace that is open, while its lock is held.
struct Held<'a>(MutexGuard<'a, Option<Reader>>);

impl Deref for Held<'_> {
    type Target = Reader;

    fn deref(&self) -> &Reader {
        self.0.as_ref().expect("checked to be open")
    }
}
