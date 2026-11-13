//! What a workspace was made with, sealed under a key only its inner key gives: the build and
//! system that made it, its key and keystore kinds, and each adapter's label as it was then. The
//! directory record keeps the kinds in clear; opening checks them against this.
//!
//! ```text
//! plain   = 0x01 (format) ‖ built_by (1) ‖ origin (1) ‖ key kind (1) ‖ keystore kind (1) ‖ trial (1, 0x00 or 0x01)
//!           ‖ n (1) ‖ n × (role (1) ‖ length (1) ‖ name (1 to 32 of a-z, 0-9, -) ‖ grade (1) ‖ lacks (4, big-endian bits))
//!           ‖ pin version (8) ‖ log count (8) ‖ log MAC (48)
//!           ‖ store length (2) ‖ store (at most 1024) ‖ keystore ref length (2) ‖ keystore ref (at most 1024)
//!           ‖ m (4) ‖ m × (item name (32) ‖ version (8) ‖ length (1) ‖ resource ‖ length (1) ‖ field)
//!           [ ‖ p (2) ‖ p × (kind (1) ‖ length (1) ‖ name ‖ sha256 (32))
//!             [ ‖ b (2) ‖ b × (length (1) ‖ box ‖ item name (32) ‖ version (8)) ] ]
//! sealed  = aead::seal(manifest key, nonce, aad, plain)
//! aad     = ws (16) ‖ length of the name (1) ‖ name
//! ```
//!
//! Every number is big-endian. Roles, item names, approvals and boxes are strictly increasing.
//! What follows the items is written only when there is an approval or a box: then the count of
//! approvals always, and the boxes only when there is at least one, so a count of no approvals is
//! written only with boxes after it, and a count of no boxes never. Nothing follows the boxes, so
//! each manifest has one encoding and every encoding read back is written the same. The places
//! between the adapters and the items are kept for later steps, empty or zero until then. Each
//! item's resource and field are what a person calls it (`item::ItemKey`), each 1 to 32 bytes, so
//! an item takes at least 44 bytes. A manifest with no items is written as it was before items had
//! a resource and field, one with no approvals and no boxes as it was before there were
//! approvals, and one with no boxes as it was before there were boxes.
//!
//! An approval is a policy's kind (`policy::Kind`), its name, 1 to 32 bytes as a resource is, and
//! the SHA-256 of the text approved, so it takes at least 35 bytes. Approvals are ordered by kind,
//! then name, so there is at most one for each policy.
//!
//! A box is its name, 1 to 32 bytes as a resource's, the name its key is kept under in the keystore
//! (`boxkey`) and the pin version that key was sealed for, so it takes at least 42 bytes. A box
//! made with no key to keep (a box that keeps nothing between runs) is approved and not listed.
//!
//! The workspace's id and name are not fields: the seal binds them, so a manifest copied from
//! another workspace, or read under another name, does not open. Whoever holds the inner key can
//! seal any manifest; the seal proves no more than that.

use std::fmt;

use zeroize::Zeroizing;

use crate::boxkey::check_box;
use crate::crypto::aead;
use crate::holder::KeyKind;
use crate::ids::{WsId, WsName};
use crate::item::ItemKey;
use crate::key::InnerKey;
use crate::platform::{Build, Grade, Label, Lacks, Os, Role};
use crate::policy::{Approval, Kind};
use crate::refusal::Refusal;
use crate::store::{ItemName, KeystoreKind};

/// The one manifest format so far.
const FORMAT: u8 = 0x01;

/// The longest name an adapter's label can have in a manifest.
const MAX_ADAPTER: usize = 32;

/// The fewest bytes an item takes: its name, its version, and a resource and a field of one byte
/// each, with their lengths.
const MIN_ITEM: usize = 32 + 8 + 1 + 1 + 1 + 1;

/// The fewest bytes an approval takes: its kind, a name of one byte with its length, and its hash.
const MIN_APPROVAL: usize = 1 + 1 + 1 + 32;

/// The fewest bytes a box takes: a name of one byte with its length, its key's name and its version.
const MIN_BOX: usize = 1 + 1 + 32 + 8;

/// What a workspace was made with, sealed so that only its inner key reads or writes it. The
/// directory keeps the name, id and two kinds in clear; this is what they are checked against.
/// Printing it shows the lengths of its references, item map, approvals and boxes, not their
/// contents: those can identify a client.
#[derive(Clone, PartialEq, Eq)]
pub struct Manifest {
    pub built_by: Build,
    pub origin: Os,
    pub key: KeyKind,
    pub keystore: KeystoreKind,
    /// Made while the formats may still change: a later version may refuse it, and it is made again.
    pub trial: bool,
    /// Each adapter as it was when the workspace was made, one per role, in role order.
    pub adapters: Vec<Recorded>,
    /// The pin version this manifest was sealed for; 0 until pins are compared with it.
    pub pin_version: u64,
    pub log_head: LogHead,
    /// Where the workspace's store is, as its adapter names it; empty until there is a store.
    pub store: Vec<u8>,
    /// Which vault or keystore account holds its items, as that keystore names it; empty for a
    /// keystore that needs none.
    pub keystore_ref: Vec<u8>,
    /// Each stored secret, in name order; empty until one is stored.
    pub items: Vec<Entry>,
    /// Each approved policy, in order of kind and name; empty until one is approved.
    pub approvals: Vec<Approval>,
    /// Each box whose key the keystore keeps, in order of name; empty until one is made.
    pub boxes: Vec<BoxEntry>,
}

impl fmt::Debug for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manifest")
            .field("built_by", &self.built_by)
            .field("origin", &self.origin)
            .field("key", &self.key)
            .field("keystore", &self.keystore)
            .field("trial", &self.trial)
            .field("adapters", &self.adapters)
            .field("pin_version", &self.pin_version)
            .field("log_head", &self.log_head.count)
            .field("store", &format_args!("{} bytes", self.store.len()))
            .field("keystore_ref", &format_args!("{} bytes", self.keystore_ref.len()))
            .field("items", &format_args!("{} items", self.items.len()))
            .field("approvals", &format_args!("{} approvals", self.approvals.len()))
            .field("boxes", &format_args!("{} boxes", self.boxes.len()))
            .finish()
    }
}

/// One stored secret as a manifest lists it: the name it is kept under, the pin version it was
/// sealed for, and what a person calls it. The name is derived from the key under the workspace's
/// names key; nothing here checks that, since only the verbs hold that key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    pub name: ItemName,
    pub version: u64,
    pub key: ItemKey,
}

/// One box as a manifest lists it: its name, the name its key is kept under, and the pin version
/// that key was sealed for. The key's name is derived from the box's under the workspace's names
/// key (`boxkey`); nothing here checks that, since only the verbs hold that key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BoxEntry {
    pub name: String,
    pub item: ItemName,
    pub version: u64,
}

/// One adapter as a manifest records it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Recorded {
    pub role: Role,
    pub adapter: String,
    pub grade: Grade,
    pub lacks: Lacks,
}

impl Recorded {
    /// How an adapter's label is recorded for the part it plays.
    pub fn of(role: Role, label: &Label) -> Recorded {
        Recorded { role, adapter: label.adapter.to_string(), grade: label.grade, lacks: label.lacks }
    }
}

/// Where the workspace's log had got to when the manifest was sealed: its count of lines and the
/// MAC of the last. All zero is none.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LogHead {
    pub count: u64,
    pub mac: [u8; 48],
}

impl LogHead {
    /// No log yet.
    pub const NONE: LogHead = LogHead { count: 0, mac: [0; 48] };
}

impl Manifest {
    /// The longest store or keystore reference.
    pub const MAX_REF: usize = 1024;

    /// Refuses, with `Refusal::Unreadable`, one whose bytes would not read back as it is: an
    /// adapter name that is not 1 to 32 of a-z, 0-9 and -, roles, items, approvals or boxes out of
    /// order or repeated, a box name that isn't one, more approvals or boxes than two bytes count,
    /// a reference over `MAX_REF` bytes. An
    /// item's resource and field, and an approval's name, are well formed already: an `ItemKey`
    /// or an `Approval` can't be made otherwise.
    pub fn check(&self) -> Result<(), Refusal> {
        let names = self.adapters.iter().all(|recorded| adapter_name(recorded.adapter.as_bytes()));
        let roles = self.adapters.windows(2).all(|pair| pair[0].role < pair[1].role);
        let items = self.items.windows(2).all(|pair| pair[0].name < pair[1].name) && u32::try_from(self.items.len()).is_ok();
        let approvals = self.approvals.windows(2).all(|pair| (pair[0].kind(), pair[0].name()) < (pair[1].kind(), pair[1].name())) && u16::try_from(self.approvals.len()).is_ok();
        let boxes = self.boxes.iter().all(|entry| check_box(&entry.name).is_ok())
            && self.boxes.windows(2).all(|pair| pair[0].name < pair[1].name)
            && u16::try_from(self.boxes.len()).is_ok();
        let refs = self.store.len() <= Manifest::MAX_REF && self.keystore_ref.len() <= Manifest::MAX_REF;
        if names && roles && items && approvals && boxes && refs { Ok(()) } else { Err(Refusal::Unreadable) }
    }

    /// Seals it for `ws` and `name` under the key `inner` gives manifests. Checks it first
    /// (`check`), and refuses what would not read back. `nonce` is 12 fresh random bytes the caller
    /// drew, never used twice under one inner key.
    pub(crate) fn seal(&self, inner: &InnerKey, ws: WsId, name: &WsName, nonce: &[u8; 12]) -> Result<Vec<u8>, Refusal> {
        self.check()?;
        let plain = Zeroizing::new(encode(self));
        // `check` and `decode` hold the same rules; this keeps a difference between them from being written.
        if decode(&plain).as_ref() != Some(self) {
            return Err(Refusal::Unreadable);
        }
        Ok(aead::seal(&inner.manifest_key(), nonce, &aad(ws, name), &plain))
    }

    /// Opens what `seal` made for `ws` and `name`. Called only once the key holder has proved its
    /// answer, so every failure is `Refusal::Tampered`.
    pub(crate) fn open(inner: &InnerKey, ws: WsId, name: &WsName, sealed: &[u8]) -> Result<Manifest, Refusal> {
        Manifest::open_under(&inner.manifest_key(), ws, name, sealed)
    }

    /// Opens it under the manifest key itself, as an open workspace reads it again. Every failure is
    /// `Refusal::Tampered`.
    pub(crate) fn open_under(key: &[u8; 32], ws: WsId, name: &WsName, sealed: &[u8]) -> Result<Manifest, Refusal> {
        let plain = aead::open(key, &aad(ws, name), sealed).map_err(|_| Refusal::Tampered)?;
        decode(&plain).ok_or(Refusal::Tampered)
    }
}

/// Whether bytes can be an adapter's name in a manifest: 1 to 32 of a-z, 0-9 and `-`.
fn adapter_name(name: &[u8]) -> bool {
    (1..=MAX_ADAPTER).contains(&name.len()) && name.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// The plaintext of a checked manifest.
///
/// Panics if it was not checked: a length would not fit its place.
fn encode(m: &Manifest) -> Vec<u8> {
    let mut out = vec![FORMAT, m.built_by.tag(), m.origin.tag(), m.key.tag(), m.keystore.tag(), u8::from(m.trial)];
    out.push(u8::try_from(m.adapters.len()).expect("a checked manifest has one adapter per role"));
    for recorded in &m.adapters {
        out.push(recorded.role.tag());
        out.push(u8::try_from(recorded.adapter.len()).expect("a checked adapter name is at most 32 bytes"));
        out.extend_from_slice(recorded.adapter.as_bytes());
        out.push(recorded.grade.tag());
        out.extend_from_slice(&recorded.lacks.bits().to_be_bytes());
    }
    out.extend_from_slice(&m.pin_version.to_be_bytes());
    out.extend_from_slice(&m.log_head.count.to_be_bytes());
    out.extend_from_slice(&m.log_head.mac);
    for reference in [&m.store, &m.keystore_ref] {
        out.extend_from_slice(&u16::try_from(reference.len()).expect("a checked reference is at most 1024 bytes").to_be_bytes());
        out.extend_from_slice(reference);
    }
    out.extend_from_slice(&u32::try_from(m.items.len()).expect("a checked manifest has fewer than 2^32 items").to_be_bytes());
    for entry in &m.items {
        out.extend_from_slice(entry.name.as_bytes());
        out.extend_from_slice(&entry.version.to_be_bytes());
        for part in [entry.key.resource(), entry.key.field()] {
            out.push(u8::try_from(part.len()).expect("a resource or field is at most 32 bytes"));
            out.extend_from_slice(part.as_bytes());
        }
    }
    if !m.approvals.is_empty() || !m.boxes.is_empty() {
        out.extend_from_slice(&u16::try_from(m.approvals.len()).expect("a checked manifest has fewer than 2^16 approvals").to_be_bytes());
        for approval in &m.approvals {
            out.push(approval.kind().tag());
            out.push(u8::try_from(approval.name().len()).expect("a name is at most 32 bytes"));
            out.extend_from_slice(approval.name().as_bytes());
            out.extend_from_slice(approval.sha256());
        }
    }
    if !m.boxes.is_empty() {
        out.extend_from_slice(&u16::try_from(m.boxes.len()).expect("a checked manifest has fewer than 2^16 boxes").to_be_bytes());
        for entry in &m.boxes {
            out.push(u8::try_from(entry.name.len()).expect("a checked box name is at most 32 bytes"));
            out.extend_from_slice(entry.name.as_bytes());
            out.extend_from_slice(entry.item.as_bytes());
            out.extend_from_slice(&entry.version.to_be_bytes());
        }
    }
    out
}

/// Reads a plaintext as `encode` writes it, or gives none: every tag known, every bound and order
/// held, nothing left over. Nothing is allocated for a length before the bytes it names are there.
fn decode(bytes: &[u8]) -> Option<Manifest> {
    let mut r = Reader(bytes);
    if r.byte()? != FORMAT {
        return None;
    }
    let built_by = Build::from_tag(r.byte()?).ok()?;
    let origin = Os::from_tag(r.byte()?).ok()?;
    let key = KeyKind::from_tag(r.byte()?).ok()?;
    let keystore = KeystoreKind::from_tag(r.byte()?).ok()?;
    let trial = match r.byte()? {
        0x00 => false,
        0x01 => true,
        _ => return None,
    };
    let mut adapters: Vec<Recorded> = Vec::new();
    for _ in 0..r.byte()? {
        let role = Role::from_tag(r.byte()?).ok()?;
        let len = r.byte()?;
        let name = r.take(usize::from(len))?;
        if !adapter_name(name) || adapters.last().is_some_and(|last| last.role >= role) {
            return None;
        }
        let grade = Grade::from_tag(r.byte()?).ok()?;
        let lacks = Lacks::from_bits(r.u32()?).ok()?;
        adapters.push(Recorded { role, adapter: String::from_utf8(name.to_vec()).ok()?, grade, lacks });
    }
    let pin_version = r.u64()?;
    let log_head = LogHead { count: r.u64()?, mac: r.array::<48>()? };
    let store = r.reference()?;
    let keystore_ref = r.reference()?;
    let count = r.u32()?;
    // The items are last: at least their fewest bytes must be left, before any is read.
    if usize::try_from(count).ok()?.checked_mul(MIN_ITEM)? > r.0.len() {
        return None;
    }
    let mut items: Vec<Entry> = Vec::new();
    for _ in 0..count {
        let name = ItemName::from_bytes(r.array::<32>()?);
        if items.last().is_some_and(|last| last.name >= name) {
            return None;
        }
        let version = r.u64()?;
        let resource = r.text()?;
        let field = r.text()?;
        items.push(Entry { name, version, key: ItemKey::parse(resource, field).ok()? });
    }
    let mut approvals: Vec<Approval> = Vec::new();
    let mut boxes: Vec<BoxEntry> = Vec::new();
    if r.0.is_empty() {
        return Some(Manifest { built_by, origin, key, keystore, trial, adapters, pin_version, log_head, store, keystore_ref, items, approvals, boxes });
    }
    // Written only when an approval or a box follows: a count of none, only when boxes come after it.
    let count = r.u16()?;
    if usize::from(count).checked_mul(MIN_APPROVAL)? > r.0.len() {
        return None;
    }
    for _ in 0..count {
        let kind = Kind::from_tag(r.byte()?).ok()?;
        let name = r.text()?;
        let approval = Approval::sealed(kind, name, r.array::<32>()?).ok()?;
        if approvals.last().is_some_and(|last| (last.kind(), last.name()) >= (kind, name)) {
            return None;
        }
        approvals.push(approval);
    }
    if !r.0.is_empty() {
        // Written only when there is one: a count of none is never written.
        let count = r.u16()?;
        if count == 0 || usize::from(count).checked_mul(MIN_BOX)? > r.0.len() {
            return None;
        }
        for _ in 0..count {
            let name = r.text()?;
            check_box(name).ok()?;
            if boxes.last().is_some_and(|last| last.name.as_str() >= name) {
                return None;
            }
            boxes.push(BoxEntry { name: name.to_string(), item: ItemName::from_bytes(r.array::<32>()?), version: r.u64()? });
        }
    } else if count == 0 {
        return None;
    }
    if !r.0.is_empty() {
        return None;
    }
    Some(Manifest { built_by, origin, key, keystore, trial, adapters, pin_version, log_head, store, keystore_ref, items, approvals, boxes })
}

/// The associated data of the seal: the workspace and its name.
fn aad(ws: WsId, name: &WsName) -> Vec<u8> {
    let name = name.as_str().as_bytes();
    let len = u8::try_from(name.len()).expect("a workspace name is at most 32 bytes");
    [ws.as_bytes().as_slice(), [len].as_slice(), name].concat()
}

/// Reads bytes front to back; a read past the end gives none.
struct Reader<'b>(&'b [u8]);

impl<'b> Reader<'b> {
    fn take(&mut self, n: usize) -> Option<&'b [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }

    fn byte(&mut self) -> Option<u8> {
        self.array::<1>().map(|[b]| b)
    }

    fn u16(&mut self) -> Option<u16> {
        self.array::<2>().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array::<4>().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.array::<8>().map(u64::from_be_bytes)
    }

    /// Text of one byte's length: what an item's resource or field, an approval's name or a box's
    /// name is checked from.
    fn text(&mut self) -> Option<&'b str> {
        let len = usize::from(self.byte()?);
        str::from_utf8(self.take(len)?).ok()
    }

    /// A reference: its length in two bytes, at most `Manifest::MAX_REF`, then its bytes.
    fn reference(&mut self) -> Option<Vec<u8>> {
        let len = usize::from(self.u16()?);
        if len > Manifest::MAX_REF {
            return None;
        }
        Some(self.take(len)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::state_hash;
    use crate::crypto::vectors::{
        KAT_APPROVAL_PIN_STATE, KAT_BOX_NAME, KAT_BOX_PIN_STATE, KAT_HARDWARE_WRAP, KAT_ITEM_NAME, KAT_ITEM_PIN_STATE, KAT_KEY_MANIFEST, KAT_MANIFEST, KAT_MANIFEST_APPROVAL,
        KAT_MANIFEST_APPROVAL_PLAIN, KAT_MANIFEST_BOX, KAT_MANIFEST_BOX_ONLY_PLAIN, KAT_MANIFEST_BOX_PLAIN, KAT_MANIFEST_ITEM, KAT_MANIFEST_ITEM_APPROVAL_PLAIN,
        KAT_MANIFEST_ITEM_PLAIN, KAT_MANIFEST_PLAIN, KAT_POLICY_SHA256, KAT_TWO_APPROVALS, KAT_WS_PIN_STATE, POLICY_TEXT, approval_manifest_nonce, arr, box_manifest_nonce, hex,
        inner_bytes, item_manifest_nonce, manifest_nonce, seq, ws_bytes,
    };
    use crate::passphrase::LABEL;
    use crate::platform::Property;

    const GLOBEX: WsId = WsId::from_bytes([2; 16]);

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn ws_name(text: &str) -> WsName {
        WsName::parse(text).unwrap()
    }

    /// The known answers' inner key.
    fn inner() -> InnerKey {
        InnerKey::from_bytes(Zeroizing::new(inner_bytes()))
    }

    /// The manifest of the known answers, as a release build on macOS might record a workspace on a passphrase key and files.
    fn release() -> Manifest {
        let weaker = |role: Role, adapter: &str, lacks: &[Property]| Recorded { role, adapter: adapter.to_string(), grade: Grade::Weaker, lacks: Lacks::of(lacks) };
        Manifest {
            built_by: Build::Release,
            origin: Os::Macos,
            key: KeyKind::Passphrase,
            keystore: KeystoreKind::Files,
            trial: true,
            adapters: vec![
                weaker(Role::KeyHolder, "passphrase-key", &[Property::KeyInHardware, Property::PresenceProof, Property::TrustedPrompt]),
                weaker(Role::Anchor, "file-anchor", &[Property::OthersCantTouch, Property::RollbackProof]),
                weaker(Role::Files, "dir-files", &[Property::OthersCantTouch, Property::RollbackProof]),
                weaker(Role::Keystore, "file-keystore", &[Property::OthersCantTouch]),
            ],
            pin_version: 0,
            log_head: LogHead::NONE,
            store: Vec::new(),
            keystore_ref: Vec::new(),
            items: Vec::new(),
            approvals: Vec::new(),
            boxes: Vec::new(),
        }
    }

    /// An item of the list: its name all `byte`, at `version`, called `resource/field`.
    fn entry(byte: u8, version: u64, resource: &str, field: &str) -> Entry {
        Entry { name: ItemName::from_bytes([byte; 32]), version, key: ItemKey::parse(resource, field).unwrap() }
    }

    /// The known answers' manifest with github/token stored in it, at version 2.
    fn with_a_secret() -> Manifest {
        let token = Entry { name: ItemName::from_bytes(arr(&hex(KAT_ITEM_NAME))), version: 2, key: ItemKey::parse("github", "token").unwrap() };
        Manifest { items: vec![token], ..release() }
    }

    /// An approval of a resource's policy, by the hash it holds.
    fn approval(name: &str, sha256: [u8; 32]) -> Approval {
        Approval::sealed(Kind::Resource, name, sha256).unwrap()
    }

    /// The known answers' approval: `POLICY_TEXT` as github's policy.
    fn github() -> Approval {
        Approval::of(Kind::Resource, "github", POLICY_TEXT.as_bytes()).unwrap()
    }

    /// The known answers' manifest with that approval.
    fn with_an_approval() -> Manifest {
        Manifest { approvals: vec![github()], ..release() }
    }

    /// A box as a manifest lists it: its key's name all `byte`, at `version`.
    fn listed(name: &str, byte: u8, version: u64) -> BoxEntry {
        BoxEntry { name: name.to_string(), item: ItemName::from_bytes([byte; 32]), version }
    }

    /// The known answers' box dev: its key's known name, at version 2.
    fn dev() -> BoxEntry {
        BoxEntry { name: "dev".to_string(), item: ItemName::from_bytes(arr(&hex(KAT_BOX_NAME))), version: 2 }
    }

    /// The known answers' manifest with that approval and box dev.
    fn with_a_box() -> Manifest {
        Manifest { boxes: vec![dev()], ..with_an_approval() }
    }

    #[test]
    fn a_manifest_is_written_in_its_fixed_layout() {
        let plain = encode(&release());
        assert_eq!(plain.len(), 154);
        // Piece by piece first, so that a difference says where it is.
        assert_eq!(plain[..7], hex("01 02 01 05 02 01 04"), "the format, release, macOS, a passphrase key, a keystore of files, trial, four adapters");
        assert_eq!(plain[7..28], hex("01 0e 706173737068726173652d6b6579 02 00000007"), "the key holder");
        assert_eq!(plain[28..46], hex("02 0b 66696c652d616e63686f72 02 00000060"), "the anchor");
        assert_eq!(plain[46..62], hex("03 09 6469722d66696c6573 02 00000060"), "the files");
        assert_eq!(plain[62..82], hex("04 0d 66696c652d6b657973746f7265 02 00000020"), "the keystore");
        assert_eq!(plain[82..90], [0; 8], "the pin version");
        assert_eq!(plain[90..146], [0; 56], "the log head");
        assert_eq!(plain[146..], hex("0000 0000 00000000"), "no store, no keystore reference, no items");
        assert_eq!(plain, hex(KAT_MANIFEST_PLAIN));
        assert_eq!(decode(&plain), Some(release()), "and it reads back");
        // The key holder is recorded as a passphrase key's label says it.
        assert_eq!(Recorded::of(Role::KeyHolder, &LABEL), release().adapters[0]);
    }

    #[test]
    fn a_sealed_manifest_is_unchanged() {
        let sealed = release().seal(&inner(), acme(), &ws_name("acme"), &manifest_nonce()).unwrap();
        assert_eq!(sealed.len(), 183);
        assert_eq!(sealed[0], 0x01, "aead's format");
        assert_eq!(sealed[1..13], manifest_nonce(), "the nonce, as given");
        assert_eq!(sealed, hex(KAT_MANIFEST));
        // Bound to the workspace and its name, under the manifest's own key.
        assert_eq!(aad(acme(), &ws_name("acme")), [ws_bytes().as_slice(), [0x04].as_slice(), b"acme".as_slice()].concat());
        let key: [u8; 32] = arr(&hex(KAT_KEY_MANIFEST));
        assert_eq!(*aead::open(&key, &aad(acme(), &ws_name("acme")), &sealed).unwrap(), hex(KAT_MANIFEST_PLAIN));
        assert_eq!(Manifest::open(&inner(), acme(), &ws_name("acme"), &sealed), Ok(release()), "it opens back to the manifest");
    }

    #[test]
    fn a_manifest_has_one_reading_and_one_encoding() {
        let known = hex(KAT_MANIFEST_PLAIN);
        let with_item = hex(KAT_MANIFEST_ITEM_PLAIN);
        let approved = hex(KAT_MANIFEST_APPROVAL_PLAIN);
        let boxed = hex(KAT_MANIFEST_BOX_PLAIN);
        let box_only = hex(KAT_MANIFEST_BOX_ONLY_PLAIN);
        // Every other value of every byte is refused, or read as a manifest that is written back as exactly those bytes.
        let mut one_bit = [0, 0, 0, 0, 0];
        for (n, plain) in [&known, &with_item, &approved, &boxed, &box_only].into_iter().enumerate() {
            for (i, &byte) in plain.iter().enumerate() {
                for value in (0..=255).filter(|&value| value != byte) {
                    let mut changed = plain.clone();
                    changed[i] = value;
                    if let Some(manifest) = decode(&changed) {
                        assert!(encode(&manifest) == changed, "manifest {n}, byte {i} as {value:#04x}");
                        one_bit[n] += usize::from(value == (byte ^ 0x01));
                    }
                }
            }
            for len in 0..plain.len() {
                // Cut where what follows the items starts, each is the manifest with nothing there; cut where the boxes start,
                // the one with an approval and a box is the one with the approval.
                let whole = match len {
                    154 if n >= 2 => Some(release()),
                    196 if n == 3 => Some(with_an_approval()),
                    _ => None,
                };
                assert_eq!(decode(&plain[..len]), whole, "manifest {n}, cut to {len} bytes");
            }
        }
        // Of the changes to bit 0 of each, the independent implementation reads the same as manifests: 118 of the one with no
        // items, as before there were boxes.
        assert_eq!(one_bit, [118, 169, 156, 199, 161]);

        // Each of these breaks a rule: `check` refuses it, and so does `decode` as it is written.
        let adapters = release().adapters;
        let named = |name: &str| {
            let mut adapters = release().adapters;
            adapters[2].adapter = name.to_string();
            Manifest { adapters, ..release() }
        };
        let broken = [
            Manifest { adapters: vec![adapters[1].clone(), adapters[0].clone(), adapters[2].clone(), adapters[3].clone()], ..release() },
            Manifest { adapters: vec![adapters[0].clone(), adapters[0].clone(), adapters[2].clone(), adapters[3].clone()], ..release() },
            Manifest { items: vec![entry(0x08, 2, "github", "token"), entry(0x07, 1, "linear", "token")], ..release() },
            Manifest { items: vec![entry(0x07, 1, "github", "token"), entry(0x07, 9, "github", "user")], ..release() },
            named("Mem-Files"),
            named(""),
            named(&"a".repeat(33)),
            Manifest { store: vec![b's'; 1025], ..release() },
            Manifest { keystore_ref: vec![b'k'; 1025], ..release() },
            Manifest { approvals: vec![approval("linear", [0; 32]), github()], ..release() },
            Manifest { approvals: vec![github(), approval("github", [0; 32])], ..release() },
            Manifest { approvals: vec![github(), github()], ..release() },
            Manifest { boxes: vec![listed("test", 0x07, 2), dev()], ..release() },
            Manifest { boxes: vec![dev(), listed("dev", 0x08, 3)], ..release() },
            Manifest { boxes: vec![listed("Dev", 0x07, 2)], ..release() },
            Manifest { boxes: vec![listed("", 0x07, 2)], ..release() },
            Manifest { boxes: vec![listed("-dev", 0x07, 2)], ..release() },
            Manifest { boxes: vec![listed(&"a".repeat(33), 0x07, 2)], ..with_an_approval() },
        ];
        for manifest in &broken {
            assert_eq!(manifest.check(), Err(Refusal::Unreadable), "{manifest:?}");
            assert_eq!(decode(&encode(manifest)), None, "{manifest:?}");
        }
        assert_eq!(named("Mem-Files").seal(&inner(), acme(), &ws_name("acme"), &manifest_nonce()), Err(Refusal::Unreadable), "nor is it sealed");
        // More approvals than two bytes count: refused before it is written.
        let mut names: Vec<String> = (0..=u16::MAX as u32).map(|n| format!("r{n}")).collect();
        names.sort();
        let many = Manifest { approvals: names.iter().map(|name| approval(name, [0; 32])).collect(), ..release() };
        assert_eq!(many.check(), Err(Refusal::Unreadable));
        assert_eq!(Manifest { approvals: many.approvals[1..].to_vec(), ..release() }.check(), Ok(()), "as many as two bytes count");
        // And so with boxes.
        let many = Manifest { boxes: names.iter().map(|name| listed(name, 0, 1)).collect(), ..release() };
        assert_eq!(many.check(), Err(Refusal::Unreadable));
        assert_eq!(Manifest { boxes: many.boxes[1..].to_vec(), ..release() }.check(), Ok(()), "as many boxes as two bytes count");
        // And bytes no manifest is written as.
        let with = |at: usize, bytes: &[u8]| [&known[..at], bytes, &known[at + bytes.len()..]].concat();
        let unwritten = [
            ([known.as_slice(), [0x00].as_slice()].concat(), "one byte more"),
            (with(0, &[0x02]), "format 0x02"),
            (with(5, &[0x02]), "trial 0x02"),
            (with(7, &[0x05]), "role 0x05, kept for the door"),
            (with(24, &0x2000u32.to_be_bytes()), "a lacks bit past the last property"),
            (with(150, &[0xff; 4]), "0xffffffff items, and none behind"),
            ([&known[..150], &[0, 0, 0, 1], &[0; MIN_ITEM - 1]].concat(), "one item, and a byte too few behind"),
            ([&with_item[..150], &[0, 0, 0, 2], &with_item[154..]].concat(), "two items, and one behind"),
            ([with_item.as_slice(), [0x00].as_slice()].concat(), "one byte more after the items"),
            ([&with_item[..194], &[0x03], b"Git", &with_item[201..]].concat(), "the resource Git"),
            ([&with_item[..194], &[0x06], b"git/hu", &with_item[201..]].concat(), "a resource with a slash"),
            ([&with_item[..194], &[0x21], &[b'a'; 33], &with_item[201..]].concat(), "a resource of 33 bytes"),
            ([&with_item[..194], &[0x06], b"githu\xff", &with_item[201..]].concat(), "a resource that is not UTF-8"),
            ([&with_item[..201], &[0x00]].concat(), "an empty field"),
            ([&with_item[..201], &[0x05], b"Token"].concat(), "the field Token"),
            ([&with_item[..194], &[0x00, 0x05], b"token"].concat(), "an empty resource"),
            ([known.as_slice(), &[0x00, 0x00]].concat(), "no approvals, written out"),
            ([with_item.as_slice(), &[0x00, 0x00]].concat(), "no approvals, written out after an item"),
            ([approved.as_slice(), [0x00].as_slice()].concat(), "one byte more after the approvals"),
            ([&approved[..154], &[0x00, 0x02], &approved[156..]].concat(), "two approvals, and one behind"),
            ([&known[..], &[0xff, 0xff]].concat(), "0xffff approvals, and none behind"),
            ([&known[..], &[0x00, 0x01], &[0; MIN_APPROVAL - 1]].concat(), "one approval, and a byte too few behind"),
            (with_at(&approved, 156, &[0x03]), "kind 0x03, kept for later"),
            (with_at(&approved, 156, &[0x00]), "kind 0x00"),
            ([&approved[..157], &[0x03], b"Git", &approved[164..]].concat(), "the name Git"),
            ([&approved[..157], &[0x06], b"-ithub", &approved[164..]].concat(), "a name starting with -"),
            ([&approved[..157], &[0x06], b"git/hu", &approved[164..]].concat(), "a name with a slash"),
            ([&approved[..157], &[0x21], &[b'a'; 33], &approved[164..]].concat(), "a name of 33 bytes"),
            ([&approved[..157], &[0x00], &approved[164..]].concat(), "an empty name"),
            ([&known[..], &hex(KAT_TWO_APPROVALS)[..2], &hex(KAT_TWO_APPROVALS)[42..], &hex(KAT_TWO_APPROVALS)[2..42]].concat(), "two approvals out of order"),
            ([&known[..], &[0x00, 0x02], &approved[156..], &approved[156..]].concat(), "the same approval twice"),
            ([&known[..], &[0x00, 0x02], &approved[156..164], &[0; 32], &approved[156..]].concat(), "two approvals of one name"),
            ([approved.as_slice(), &[0x00, 0x00]].concat(), "no boxes, written out after an approval"),
            ([known.as_slice(), &[0x00, 0x00, 0x00, 0x00]].concat(), "no approvals and no boxes, written out"),
            ([boxed.as_slice(), [0x00].as_slice()].concat(), "one byte more after the boxes"),
            ([&boxed[..196], &[0x00, 0x02], &boxed[198..]].concat(), "two boxes, and one behind"),
            ([&known[..], &[0x00, 0x00, 0xff, 0xff]].concat(), "0xffff boxes, and none behind"),
            ([&known[..], &[0x00, 0x00, 0x00, 0x01], &[0; MIN_BOX - 1]].concat(), "one box, and a byte too few behind"),
            ([&known[..], &[0x00, 0x00], &[0; MIN_BOX]].concat(), "a box count of none, with a box's bytes behind"),
            ([&boxed[..198], &[0x03], b"Dev", &boxed[202..]].concat(), "the box Dev"),
            ([&boxed[..198], &[0x03], b"d.v", &boxed[202..]].concat(), "a box with a dot"),
            ([&boxed[..198], &[0x03], b"-ev", &boxed[202..]].concat(), "a box starting with -"),
            ([&boxed[..198], &[0x03], b"d\xffv", &boxed[202..]].concat(), "a box that is not UTF-8"),
            ([&boxed[..198], &[0x00], &boxed[202..]].concat(), "an empty box name"),
            ([&boxed[..198], &[0x21], &[b'a'; 33], &boxed[202..]].concat(), "a box name of 33 bytes"),
            ([&boxed[..196], &[0x00, 0x02], &boxed[198..], &boxed[198..]].concat(), "the same box twice"),
            ([&boxed[..196], &[0x00, 0x02], &boxed[198..202], &[0; 40], &boxed[198..]].concat(), "two boxes of one name"),
            ([&boxed[..196], &[0x00, 0x02], &[0x04], b"test", &[0; 40], &boxed[198..]].concat(), "two boxes out of order"),
        ];
        for (bytes, what) in unwritten {
            assert_eq!(decode(&bytes), None, "{what}");
        }

        // Every place kept for later, full, and items with the shortest and the longest resource and field, read back.
        let longest = "z".repeat(ItemKey::MAX);
        let full = Manifest {
            pin_version: 7,
            log_head: LogHead { count: 3, mac: arr(&seq(0x40, 48)) },
            store: vec![b's'; Manifest::MAX_REF],
            keystore_ref: vec![b'k'; Manifest::MAX_REF],
            items: vec![entry(0x07, 1, "a", "b"), entry(0x08, 2, "github", "token"), entry(0xf0, u64::MAX, &longest, &longest)],
            ..release()
        };
        assert_eq!(full.check(), Ok(()));
        let plain = encode(&full);
        assert_eq!(plain.len(), 154 + 1024 + 1024 + MIN_ITEM + (MIN_ITEM + 5 + 4) + (MIN_ITEM + 31 + 31));
        assert_eq!(decode(&plain), Some(full.clone()));
        let sealed = full.seal(&inner(), acme(), &ws_name("acme"), &manifest_nonce()).unwrap();
        assert_eq!(Manifest::open(&inner(), acme(), &ws_name("acme"), &sealed), Ok(full));
        // One item as short as an item is: exactly the fewest bytes are left after the count, and it reads back.
        let shortest = Manifest { items: vec![entry(0x07, 1, "a", "b")], ..release() };
        let plain = encode(&shortest);
        assert_eq!(plain.len(), 154 + MIN_ITEM);
        assert_eq!(decode(&plain), Some(shortest));
        // And so with an approval: the shortest, then the longest name after it.
        let approvals = vec![approval("a", [0x5a; 32]), approval(&longest, [0xa5; 32])];
        let shortest = Manifest { approvals: approvals[..1].to_vec(), ..release() };
        let plain = encode(&shortest);
        assert_eq!(plain.len(), 154 + 2 + MIN_APPROVAL);
        assert_eq!(decode(&plain), Some(shortest));
        let both = Manifest { approvals, ..release() };
        let plain = encode(&both);
        assert_eq!(plain.len(), 154 + 2 + MIN_APPROVAL + (MIN_APPROVAL + 31));
        assert_eq!(decode(&plain), Some(both));
        // And so with a box, after an empty count of approvals: the shortest, then the longest name and version after it.
        let boxes = vec![listed("a", 0x5a, 1), listed(&longest, 0xa5, u64::MAX)];
        let shortest = Manifest { boxes: boxes[..1].to_vec(), ..release() };
        let plain = encode(&shortest);
        assert_eq!(plain.len(), 154 + 2 + 2 + MIN_BOX);
        assert_eq!(decode(&plain), Some(shortest));
        let both = Manifest { boxes, items: vec![entry(0x07, 1, "a", "b")], approvals: vec![github()], ..release() };
        assert_eq!(both.check(), Ok(()));
        let plain = encode(&both);
        assert_eq!(decode(&plain), Some(both.clone()));
        let sealed = both.seal(&inner(), acme(), &ws_name("acme"), &manifest_nonce()).unwrap();
        assert_eq!(Manifest::open(&inner(), acme(), &ws_name("acme"), &sealed), Ok(both));
    }

    /// `bytes` with `at` onwards overwritten by `with`.
    fn with_at(bytes: &[u8], at: usize, with: &[u8]) -> Vec<u8> {
        [&bytes[..at], with, &bytes[at + with.len()..]].concat()
    }

    #[test]
    fn a_manifest_with_an_approval_is_unchanged() {
        let plain = encode(&with_an_approval());
        assert_eq!(plain.len(), 196);
        // Piece by piece first, so that a difference says where it is.
        let known = hex(KAT_MANIFEST_PLAIN);
        assert_eq!(plain[..154], known[..], "all before the approvals, as with none");
        assert_eq!(plain[154..158], hex("0001 01 06"), "one approval, of a resource, its name 6 bytes");
        assert_eq!(plain[158..164], *b"github");
        assert_eq!(plain[164..], hex(KAT_POLICY_SHA256), "the SHA-256 of the text");
        assert_eq!(plain, hex(KAT_MANIFEST_APPROVAL_PLAIN));
        assert_eq!(decode(&plain), Some(with_an_approval()), "and it reads back");

        let sealed = with_an_approval().seal(&inner(), acme(), &ws_name("acme"), &approval_manifest_nonce()).unwrap();
        assert_eq!(sealed.len(), 225);
        assert_eq!(sealed, hex(KAT_MANIFEST_APPROVAL));
        let key: [u8; 32] = arr(&hex(KAT_KEY_MANIFEST));
        assert_eq!(*aead::open(&key, &aad(acme(), &ws_name("acme")), &sealed).unwrap(), hex(KAT_MANIFEST_APPROVAL_PLAIN));
        assert_eq!(Manifest::open(&inner(), acme(), &ws_name("acme"), &sealed), Ok(with_an_approval()), "it opens back to the manifest");
        let state = state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), &sealed, b"");
        assert_eq!(state.as_slice(), hex(KAT_APPROVAL_PIN_STATE));
    }

    #[test]
    fn a_manifest_with_a_box_is_unchanged() {
        let plain = encode(&with_a_box());
        assert_eq!(plain.len(), 242);
        // Piece by piece first, so that a difference says where it is.
        assert_eq!(plain[..196], hex(KAT_MANIFEST_APPROVAL_PLAIN), "all before the boxes, as with none");
        assert_eq!(plain[196..202], hex("0001 03 646576"), "one box, its name 3 bytes, dev");
        assert_eq!(plain[202..234], hex(KAT_BOX_NAME), "its key's name");
        assert_eq!(plain[234..], 2u64.to_be_bytes(), "its key's version");
        assert_eq!(plain, hex(KAT_MANIFEST_BOX_PLAIN));
        assert_eq!(decode(&plain), Some(with_a_box()), "and it reads back");

        let sealed = with_a_box().seal(&inner(), acme(), &ws_name("acme"), &box_manifest_nonce()).unwrap();
        assert_eq!(sealed.len(), 271);
        assert_eq!(sealed, hex(KAT_MANIFEST_BOX));
        let key: [u8; 32] = arr(&hex(KAT_KEY_MANIFEST));
        assert_eq!(*aead::open(&key, &aad(acme(), &ws_name("acme")), &sealed).unwrap(), hex(KAT_MANIFEST_BOX_PLAIN));
        assert_eq!(Manifest::open(&inner(), acme(), &ws_name("acme"), &sealed), Ok(with_a_box()), "it opens back to the manifest");
        let state = state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), &sealed, b"");
        assert_eq!(state.as_slice(), hex(KAT_BOX_PIN_STATE));
    }

    #[test]
    fn boxes_come_after_approvals_or_after_an_empty_count() {
        // With no approval, the count of none is written, then the box.
        let only = Manifest { boxes: vec![dev()], ..release() };
        let plain = encode(&only);
        assert_eq!(plain.len(), 202);
        assert_eq!(plain[..154], hex(KAT_MANIFEST_PLAIN), "all before, as with nothing after the items");
        assert_eq!(plain[154..156], [0, 0], "no approvals");
        assert_eq!(plain[156..], hex(KAT_MANIFEST_BOX_PLAIN)[196..], "then the box, as after an approval");
        assert_eq!(plain, hex(KAT_MANIFEST_BOX_ONLY_PLAIN));
        assert_eq!(decode(&plain), Some(only));

        // After an item, an approval of a resource and one of a box of the same name: the box's approval second, then the box.
        let box_approval = Approval::of(Kind::Box, "dev", b"run = [\"claude\"]\n").unwrap();
        let resource = Approval::of(Kind::Resource, "dev", POLICY_TEXT.as_bytes()).unwrap();
        let all = Manifest { approvals: vec![resource, github(), box_approval.clone()], boxes: vec![dev()], ..with_a_secret() };
        let plain = encode(&all);
        assert_eq!(plain[..207], hex(KAT_MANIFEST_ITEM_PLAIN), "the item first");
        assert_eq!(plain[207..209], [0, 3], "three approvals");
        // The box section is its count and dev's 44 bytes; the box's approval, 37 bytes, comes right before it.
        let boxes_at = plain.len() - 46;
        assert_eq!(plain[boxes_at - 37..boxes_at - 32], hex("02 03 646576"), "the box's approval last of them");
        assert_eq!(plain[boxes_at..], hex(KAT_MANIFEST_BOX_PLAIN)[196..], "then the box");
        assert_eq!(decode(&plain), Some(all));
        // Kinds in order: a box's approval before a resource's is refused, read or written.
        let wrong = Manifest { approvals: vec![box_approval, github()], ..release() };
        assert_eq!(wrong.check(), Err(Refusal::Unreadable));
        assert_eq!(decode(&encode(&wrong)), None);
    }

    #[test]
    fn items_come_before_approvals() {
        let both = Manifest { approvals: vec![github()], ..with_a_secret() };
        let plain = encode(&both);
        assert_eq!(plain.len(), 249);
        assert_eq!(plain[..207], hex(KAT_MANIFEST_ITEM_PLAIN), "the item first, as with no approval");
        assert_eq!(plain[207..], hex(KAT_MANIFEST_APPROVAL_PLAIN)[154..], "then the approval, as with no item");
        assert_eq!(plain, hex(KAT_MANIFEST_ITEM_APPROVAL_PLAIN));
        assert_eq!(decode(&plain), Some(both));

        // Two, in order of name. linear's hash is the SHA-256 of no bytes, which no text approved can have.
        let empty = arr(&hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        let two = Manifest { approvals: vec![github(), approval("linear", empty)], ..release() };
        let plain = encode(&two);
        assert_eq!(plain, [hex(KAT_MANIFEST_PLAIN), hex(KAT_TWO_APPROVALS)].concat());
        assert_eq!(decode(&plain), Some(two));
    }

    #[test]
    fn a_manifest_with_a_secret_is_unchanged() {
        let plain = encode(&with_a_secret());
        assert_eq!(plain.len(), 207);
        // Piece by piece first, so that a difference says where it is.
        let known = hex(KAT_MANIFEST_PLAIN);
        assert_eq!(plain[..150], known[..150], "all before the items, as with none");
        assert_eq!(plain[150..154], [0, 0, 0, 1], "one item");
        assert_eq!(plain[154..186], hex(KAT_ITEM_NAME), "its name");
        assert_eq!(plain[186..194], 2u64.to_be_bytes(), "its version");
        assert_eq!(plain[194..], hex("06 676974687562 05 746f6b656e"), "github, then token");
        assert_eq!(plain, hex(KAT_MANIFEST_ITEM_PLAIN));
        assert_eq!(decode(&plain), Some(with_a_secret()), "and it reads back");

        let sealed = with_a_secret().seal(&inner(), acme(), &ws_name("acme"), &item_manifest_nonce()).unwrap();
        assert_eq!(sealed.len(), 236);
        assert_eq!(sealed, hex(KAT_MANIFEST_ITEM));
        let key: [u8; 32] = arr(&hex(KAT_KEY_MANIFEST));
        assert_eq!(*aead::open(&key, &aad(acme(), &ws_name("acme")), &sealed).unwrap(), hex(KAT_MANIFEST_ITEM_PLAIN));
        assert_eq!(Manifest::open(&inner(), acme(), &ws_name("acme"), &sealed), Ok(with_a_secret()), "it opens back to the manifest");
    }

    #[test]
    fn a_sealed_manifest_opens_only_for_its_workspace_and_name_under_its_inner_key() {
        let sealed = hex(KAT_MANIFEST);
        let opened = |key: &InnerKey, ws: WsId, name: &str, bytes: &[u8]| Manifest::open(key, ws, &ws_name(name), bytes);
        assert_eq!(opened(&inner(), acme(), "acme", &sealed), Ok(release()));
        // Another workspace, another name, another inner key: a planted wrap's.
        let planted = InnerKey::from_bytes(Zeroizing::new([0x21; 32]));
        assert_eq!(opened(&inner(), GLOBEX, "acme", &sealed), Err(Refusal::Tampered), "globex's id");
        assert_eq!(opened(&inner(), acme(), "globex", &sealed), Err(Refusal::Tampered), "the name globex");
        assert_eq!(opened(&planted, acme(), "acme", &sealed), Err(Refusal::Tampered), "another inner key");
        for i in 0..sealed.len() {
            let mut changed = sealed.clone();
            changed[i] ^= 0x01;
            assert_eq!(opened(&inner(), acme(), "acme", &changed), Err(Refusal::Tampered), "byte {i}");
        }
        for len in 0..sealed.len() {
            assert_eq!(opened(&inner(), acme(), "acme", &sealed[..len]), Err(Refusal::Tampered), "cut to {len} bytes");
        }
        let mut longer = sealed.clone();
        longer.push(0);
        assert_eq!(opened(&inner(), acme(), "acme", &longer), Err(Refusal::Tampered), "one byte more");
    }

    #[test]
    fn a_manifest_prints_no_reference_or_item_name() {
        let manifest = Manifest { store: b"acme-store".to_vec(), keystore_ref: b"acme-vault".to_vec(), approvals: vec![github()], boxes: vec![dev()], ..with_a_secret() };
        for shown in [format!("{manifest:?}"), format!("{manifest:#?}")] {
            assert!(!shown.contains("acme") && !shown.contains("github") && !shown.contains("token") && !shown.contains(&KAT_ITEM_NAME[..8]), "{shown}");
            assert!(!shown.contains(&KAT_POLICY_SHA256[..8]), "{shown}");
            assert!(!shown.contains("dev") && !shown.contains(&KAT_BOX_NAME[..8]), "{shown}");
            assert!(shown.contains("10 bytes") && shown.contains("1 items") && shown.contains("1 approvals") && shown.contains("1 boxes"), "{shown}");
        }
    }

    #[test]
    fn the_pin_of_a_workspace_with_its_manifest_is_unchanged() {
        let state = state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), &hex(KAT_MANIFEST), b"");
        assert_eq!(state.as_slice(), hex(KAT_WS_PIN_STATE));
        // And once github/token is stored in it.
        let state = state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), &hex(KAT_MANIFEST_ITEM), b"");
        assert_eq!(state.as_slice(), hex(KAT_ITEM_PIN_STATE));
    }
}
