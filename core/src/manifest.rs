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
//! sealed  = aead::seal(manifest key, nonce, aad, plain)
//! aad     = ws (16) ‖ length of the name (1) ‖ name
//! ```
//!
//! Every number is big-endian. Roles and item names are strictly increasing, and nothing follows
//! the items, so each manifest has one encoding and every encoding read back is written the same.
//! The places between the adapters and the items are kept for later steps, empty or zero until
//! then. Each item's resource and field are what a person calls it (`item::ItemKey`), each 1 to
//! 32 bytes, so an item takes at least 44 bytes. A manifest with no items is written as it was
//! before items had a resource and field.
//!
//! The workspace's id and name are not fields: the seal binds them, so a manifest copied from
//! another workspace, or read under another name, does not open. Whoever holds the inner key can
//! seal any manifest; the seal proves no more than that.

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::aead;
use crate::holder::KeyKind;
use crate::ids::{WsId, WsName};
use crate::item::ItemKey;
use crate::key::InnerKey;
use crate::platform::{Build, Grade, Label, Lacks, Os, Role};
use crate::refusal::Refusal;
use crate::store::{ItemName, KeystoreKind};

/// The one manifest format so far.
const FORMAT: u8 = 0x01;

/// The longest name an adapter's label can have in a manifest.
const MAX_ADAPTER: usize = 32;

/// The fewest bytes an item takes: its name, its version, and a resource and a field of one byte
/// each, with their lengths.
const MIN_ITEM: usize = 32 + 8 + 1 + 1 + 1 + 1;

/// What a workspace was made with, sealed so that only its inner key reads or writes it. The
/// directory keeps the name, id and two kinds in clear; this is what they are checked against.
/// Printing it shows the lengths of its references and item map, not their contents: those can
/// identify a client.
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
    /// adapter name that is not 1 to 32 of a-z, 0-9 and -, roles or items out of order or
    /// repeated, a reference over `MAX_REF` bytes. An item's resource and field are well formed
    /// already: an `ItemKey` can't be made otherwise.
    pub fn check(&self) -> Result<(), Refusal> {
        let names = self.adapters.iter().all(|recorded| adapter_name(recorded.adapter.as_bytes()));
        let roles = self.adapters.windows(2).all(|pair| pair[0].role < pair[1].role);
        let items = self.items.windows(2).all(|pair| pair[0].name < pair[1].name) && u32::try_from(self.items.len()).is_ok();
        let refs = self.store.len() <= Manifest::MAX_REF && self.keystore_ref.len() <= Manifest::MAX_REF;
        if names && roles && items && refs { Ok(()) } else { Err(Refusal::Unreadable) }
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
        let plain = aead::open(&inner.manifest_key(), &aad(ws, name), sealed).map_err(|_| Refusal::Tampered)?;
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
    if !r.0.is_empty() {
        return None;
    }
    Some(Manifest { built_by, origin, key, keystore, trial, adapters, pin_version, log_head, store, keystore_ref, items })
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

    /// Text of one byte's length: what an item's resource or field is checked from.
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
        KAT_HARDWARE_WRAP, KAT_ITEM_NAME, KAT_ITEM_PIN_STATE, KAT_KEY_MANIFEST, KAT_MANIFEST, KAT_MANIFEST_ITEM, KAT_MANIFEST_ITEM_PLAIN, KAT_MANIFEST_PLAIN, KAT_WS_PIN_STATE,
        arr, hex, inner_bytes, item_manifest_nonce, manifest_nonce, seq, ws_bytes,
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
        // Every other value of every byte is refused, or read as a manifest that is written back as exactly those bytes.
        let mut one_bit = [0, 0];
        for (n, plain) in [&known, &with_item].into_iter().enumerate() {
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
                assert_eq!(decode(&plain[..len]), None, "manifest {n}, cut to {len} bytes");
            }
        }
        // Of the changes to bit 0 of the manifest with no items, the independent implementation reads the same 118 as manifests.
        assert_eq!(one_bit[0], 118);

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
        ];
        for manifest in &broken {
            assert_eq!(manifest.check(), Err(Refusal::Unreadable), "{manifest:?}");
            assert_eq!(decode(&encode(manifest)), None, "{manifest:?}");
        }
        assert_eq!(named("Mem-Files").seal(&inner(), acme(), &ws_name("acme"), &manifest_nonce()), Err(Refusal::Unreadable), "nor is it sealed");
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
        let manifest = Manifest { store: b"acme-store".to_vec(), keystore_ref: b"acme-vault".to_vec(), ..with_a_secret() };
        for shown in [format!("{manifest:?}"), format!("{manifest:#?}")] {
            assert!(!shown.contains("acme") && !shown.contains("github") && !shown.contains("token") && !shown.contains(&KAT_ITEM_NAME[..8]), "{shown}");
            assert!(shown.contains("10 bytes") && shown.contains("1 items"), "{shown}");
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
