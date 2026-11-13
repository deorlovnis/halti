//! The fixed sequences that make a workspace's key and unlock it for one change. Every check that
//! needs no answer from the key holder comes before it is asked, and it is asked once: core never
//! asks again.
//!
//! Refusals tell three things apart. A check that fails before the holder answers is
//! `Refusal::Unreadable`, whichever it is. The holder's "no" is `Refusal::Declined`. A check that
//! fails after the holder proved its answer is `Refusal::Tampered`. What an adapter fails with (a
//! lock already held, a disk) passes through as it is.
//!
//! A change replaces the manifest through a second file, so a crash part way never leaves a
//! manifest the pin does not cover: the new one is written beside it, the pin is moved on to it,
//! and only then is it put in the old one's place. The next `unlock` finishes or drops what a crash
//! left, before anything is asked (see `unlock`).

use std::cell::Cell;
use std::fmt;

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::anchor::{Anchor, Pin, key_ref_hash, public_key_hash, state_hash};
use crate::crypto::kem::ciphertext_of;
use crate::holder::{Change, KeyHolder, KeyRef, Prompt};
use crate::ids::{WsId, WsName};
use crate::key::{DoorKeys, InnerKey, NamesKey, StoreKey, WRAP_LEN, WrapKind};
use crate::platform::Build;
use crate::refusal::Refusal;
use crate::store::{FileKey, Files};

/// What this machine gives the sequences.
pub struct Host<'a> {
    pub files: &'a dyn Files,
    pub holder: &'a dyn KeyHolder,
    pub anchor: &'a dyn Anchor,
}

/// Fresh random bytes the caller drew for a new workspace: its inner key, and the randomness of its
/// wrap. Never reused.
pub struct Draws {
    pub inner: Zeroizing<[u8; 32]>,
    pub wrap: Zeroizing<[u8; 64]>,
}

/// What opening hands out, one part for each place. Still one value in one process: the parts go
/// apart only when the door runs on its own. Printing it shows nothing of it.
pub struct Opened {
    pub door: DoorKeys,
    pub store: StoreKey,
    pub names: NamesKey,
}

impl fmt::Debug for Opened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Opened(..)")
    }
}

/// Makes a workspace's key, wrap and first pin: one approval, no decapsulation. `then` is handed
/// the inner key once the key ref and the wrap are written, and writes the rest of what the first
/// pin covers. The pin is written last, so a failure part way leaves files and no pin, which
/// `unlock` refuses and a second `create_key` does too.
///
/// It does not check that the holder kept the commitment: a holder that did not makes a workspace
/// whose first open is `Refusal::Tampered`.
pub(crate) fn create_key(host: &Host<'_>, ws: WsId, name: &WsName, build: Build, draws: Draws, then: impl FnOnce(&InnerKey) -> Result<()>) -> Result<()> {
    let _held = host.files.lock(ws)?;
    if host.anchor.read(ws)?.is_some() || host.files.read(&FileKey::KeyRef(ws))?.is_some() || host.files.read(&FileKey::Wrap(ws))?.is_some() {
        bail!("workspace {ws} already has a key");
    }
    let inner = InnerKey::from_bytes(draws.inner);
    let (key_ref, public) = host.holder.create(&Prompt::new(ws, name, Change::Create, build), &inner.commitment())?;
    if host.holder.public(&key_ref)? != public {
        bail!("the key holder gives another public key than the one it made");
    }
    let wrap = inner.wrap_to(&public, ws, WrapKind::Hardware, &draws.wrap)?;
    host.files.write_atomic(&FileKey::KeyRef(ws), &key_ref.0)?;
    host.files.write_atomic(&FileKey::Wrap(ws), &wrap)?;
    then(&inner)?;
    let pin = Pin { version: 1, key_ref: key_ref_hash(ws, host.holder.kind(), &key_ref), public_key: public_key_hash(ws, &public), state: state(host.files, ws, name, &wrap)? };
    host.anchor.advance(ws, &pin)
}

/// What `unlock` hands its closure: the inner key, the key ref the pin named and the manifest the
/// pin was checked over, and what is needed to move the pin on by exactly one.
pub(crate) struct Unlocked<'u> {
    pub inner: &'u InnerKey,
    pub key_ref: &'u KeyRef,
    pub manifest: &'u [u8],
    host: &'u Host<'u>,
    ws: WsId,
    name: &'u WsName,
    pin: Pin,
    wrap: &'u [u8],
    policy: &'u [u8],
    replaced: Cell<bool>,
}

impl Unlocked<'_> {
    /// The version the pin will have once this change is made: what a value stored in it is sealed
    /// for.
    pub(crate) fn next(&self) -> Result<u64> {
        match self.pin.version.checked_add(1) {
            Some(next) => Ok(next),
            None => bail!("workspace {} can't be changed again: its pin is at the last version", self.ws),
        }
    }

    /// Replaces the manifest with `sealed`, and moves the pin on by one to cover it, at most once
    /// for each unlock. The new manifest is written beside the old, the pin is moved, then the new
    /// one is put in the old one's place. A failure before the pin moves is returned, and leaves
    /// the old manifest the one that opens; the next `unlock` drops what was written. Once the pin
    /// has moved the change is made: a failure after it is not returned, and the next `unlock`
    /// finishes it.
    #[cfg_attr(not(test), expect(dead_code, reason = "storing a secret is its first caller outside tests"))]
    pub(crate) fn replace_manifest(&self, sealed: &[u8]) -> Result<()> {
        if self.replaced.get() {
            bail!("the manifest was already replaced in this change");
        }
        let (files, ws) = (self.host.files, self.ws);
        let pin = Pin { version: self.next()?, state: state_hash(ws, self.name, self.wrap, sealed, self.policy), ..self.pin };
        files.write_atomic(&FileKey::NextManifest(ws), sealed)?;
        // A failed advance may still have written the pin, so the new manifest stays for the next
        // `unlock`, which keeps whichever of the two the pin covers.
        self.host.anchor.advance(ws, &pin)?;
        self.replaced.set(true);
        let _ = files.write_atomic(&FileKey::Manifest(ws), sealed).and_then(|()| files.remove(&FileKey::NextManifest(ws)));
        Ok(())
    }
}

/// Unlocks a workspace for one change: every check before the one decapsulation and the
/// commitment right after it, then `then`, still under the lock, with what `Unlocked` holds. No
/// inner key leaves the call; it is wiped before it returns.
///
/// A manifest replacement a crash cut short is settled first, under the lock and before anything
/// is asked, by which file the pin covers. The manifest covered: any new one beside it was never
/// committed, or is already in place, and is removed. Only the new one covered: the pin was moved
/// and the new one never put in place, so it is put there now. Neither: refused, as any file the
/// pin does not cover is. Nothing is trusted that the pin did not already cover.
pub(crate) fn unlock<T>(host: &Host<'_>, ws: WsId, name: &WsName, build: Build, change: Change, then: impl FnOnce(&Unlocked<'_>) -> Result<T>) -> Result<T> {
    let _held = host.files.lock(ws)?;
    let Some(pin) = host.anchor.read(ws)?.filter(|pin| pin.version > 0) else { return Err(Refusal::Unreadable.into()) };
    let (Some(key_ref), Some(wrap)) = (host.files.read(&FileKey::KeyRef(ws))?, host.files.read(&FileKey::Wrap(ws))?) else { return Err(Refusal::Unreadable.into()) };
    let key_ref = KeyRef(key_ref);
    check(key_ref_hash(ws, host.holder.kind(), &key_ref) == pin.key_ref)?;
    let public = host.holder.public(&key_ref)?;
    check(public_key_hash(ws, &public) == pin.public_key)?;
    // Read once: what `then` is handed is what the pin was checked over.
    let mut manifest = host.files.read(&FileKey::Manifest(ws))?.unwrap_or_default();
    let policy = host.files.read(&FileKey::Policy(ws))?.unwrap_or_default();
    let covered = |manifest: &[u8]| state_hash(ws, name, &wrap, manifest, &policy) == pin.state;
    let next = host.files.read(&FileKey::NextManifest(ws))?;
    if covered(&manifest) {
        if next.is_some() {
            host.files.remove(&FileKey::NextManifest(ws))?;
        }
    } else {
        let Some(next) = next.filter(|next| covered(next)) else { return Err(Refusal::Unreadable.into()) };
        host.files.write_atomic(&FileKey::Manifest(ws), &next)?;
        host.files.remove(&FileKey::NextManifest(ws))?;
        manifest = next;
    }
    // Before anything is asked: a wrap of another length, format or suite would otherwise be found
    // only by its tag, after the holder had answered.
    check(wrap.len() == WRAP_LEN)?;
    let ct = ciphertext_of(&wrap)?;
    check(ct.suite == public.suite)?;

    let released = host.holder.decapsulate(&key_ref, &Prompt::new(ws, name, change, build), &ct)?;
    // The holder has answered, so a wrap that does not open under its answer was changed: no typo gives this.
    let inner = InnerKey::unwrap_with(&wrap, &public, ws, WrapKind::Hardware, &released.shares).map_err(|_| Refusal::Tampered)?;
    if inner.commitment() != released.commitment {
        return Err(Refusal::Tampered.into());
    }
    let unlocked = Unlocked { inner: &inner, key_ref: &key_ref, manifest: &manifest, host, ws, name, pin, wrap: &wrap, policy: &policy, replaced: Cell::new(false) };
    then(&unlocked)
}

/// The working keys of an unwrapped inner key, split for each place.
pub(crate) fn opened(inner: &InnerKey) -> Opened {
    let (door, store, names) = inner.open_keys().split();
    Opened { door, store, names }
}

/// The pin's state hash of what is on disk now. A manifest or policy that is not there counts as
/// empty.
fn state(files: &dyn Files, ws: WsId, name: &WsName, wrap: &[u8]) -> Result<[u8; 48]> {
    let manifest = files.read(&FileKey::Manifest(ws))?.unwrap_or_default();
    let policy = files.read(&FileKey::Policy(ws))?.unwrap_or_default();
    Ok(state_hash(ws, name, wrap, &manifest, &policy))
}

/// A check before the holder is asked: every failure is the same refusal.
fn check(holds: bool) -> Result<(), Refusal> {
    if holds { Ok(()) } else { Err(Refusal::Unreadable) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::DecapKey;
    use crate::crypto::vectors::{
        KAT_HARDWARE_WRAP, KAT_PASSPHRASE_RECORD, KAT_PIN, PASSPHRASE, hardware_rand, hardware_seed, hex, inner_bytes, passphrase_nonce, passphrase_salt, recovery_rand,
        recovery_seed, ws_bytes,
    };
    use crate::fakes::{FixedPassphrase, MemAnchor, MemFiles, SoftKey};
    use crate::holder::KeyKind;
    use crate::passphrase::{KdfParams, Passphrase, PassphraseRecord};
    use crate::platform::{Adapter, Label};
    use crate::store::Held;

    // The tests that name a passphrase derive a key at 64 MiB once for each ask, and once more where a record is sealed: six in
    // all here. The others hold their key in software and derive nothing.

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn ws_name(text: &str) -> WsName {
        WsName::parse(text).unwrap()
    }

    /// Opening as the verbs do, without the manifest: every check, one decapsulation, the keys split.
    fn open(host: &Host<'_>, ws: WsId, name: &WsName, build: Build) -> Result<Opened> {
        unlock(host, ws, name, build, Change::Open, |unlocked| Ok(opened(unlocked.inner)))
    }

    /// The known answers' inner key and wrap randomness, as the caller would have drawn them.
    fn draws() -> Draws {
        Draws { inner: Zeroizing::new(inner_bytes()), wrap: Zeroizing::new(hardware_rand()) }
    }

    /// The refusal a sequence failed with. Panics if it did not fail, or failed some other way.
    fn refused<T>(result: Result<T>) -> Refusal {
        result.err().expect("it fails").downcast::<Refusal>().expect("with a refusal")
    }

    /// One machine: its files, its anchor and the key holder under test.
    struct World<H> {
        files: MemFiles,
        anchor: MemAnchor,
        holder: H,
    }

    impl<H: KeyHolder> World<H> {
        fn with(holder: H) -> World<H> {
            World { files: MemFiles::new(), anchor: MemAnchor::new(), holder }
        }

        fn host(&self) -> Host<'_> {
            Host { files: &self.files, holder: &self.holder, anchor: &self.anchor }
        }

        fn create_acme(&self) -> Result<()> {
            create_key(&self.host(), acme(), &ws_name("acme"), Build::Release, draws(), |_| Ok(()))
        }

        /// Opens acme's workspace under `name`.
        fn open_as(&self, name: &str) -> Result<Opened> {
            open(&self.host(), acme(), &ws_name(name), Build::Release)
        }

        /// Writes `bytes` as the file, then a pin that matches what is now on disk: what a program running as the user can do
        /// where the pin is kept in a file.
        fn plant(&self, file: FileKey, bytes: &[u8]) {
            self.files.write_atomic(&file, bytes).unwrap();
            self.repin();
        }

        /// Advances the pin to match acme's files as they are.
        fn repin(&self) {
            let ws = acme();
            let key_ref = KeyRef(self.files.read(&FileKey::KeyRef(ws)).unwrap().unwrap());
            let wrap = self.files.read(&FileKey::Wrap(ws)).unwrap().unwrap();
            let public = self.holder.public(&key_ref).unwrap();
            let version = self.anchor.read(ws).unwrap().map_or(1, |pin| pin.version + 1);
            let state = state(&self.files, ws, &ws_name("acme"), &wrap).unwrap();
            let pin = Pin { version, key_ref: key_ref_hash(ws, self.holder.kind(), &key_ref), public_key: public_key_hash(ws, &public), state };
            self.anchor.advance(ws, &pin).unwrap();
        }

        /// Unlocks acme and replaces its manifest with `sealed`, as a change does.
        fn replace(&self, sealed: &[u8]) -> Result<()> {
            replace(&self.host(), sealed)
        }

        /// The manifest an unlock of acme hands its closure.
        fn handed(&self) -> Result<Vec<u8>> {
            handed(&self.host())
        }

        fn file(&self, file: FileKey) -> Option<Vec<u8>> {
            self.files.read(&file).unwrap()
        }

        fn pin(&self) -> Pin {
            self.anchor.read(acme()).unwrap().unwrap()
        }

        /// Moves acme's pin on by one to cover `manifest` instead of its manifest file: a replacement's second step.
        fn pin_over(&self, manifest: &[u8]) {
            let pin = self.pin();
            let state = state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), manifest, b"");
            self.anchor.advance(acme(), &Pin { version: pin.version + 1, state, ..pin }).unwrap();
        }
    }

    /// Unlocks acme and replaces its manifest with `sealed`.
    fn replace(host: &Host<'_>, sealed: &[u8]) -> Result<()> {
        unlock(host, acme(), &ws_name("acme"), Build::Release, Change::Open, |unlocked| unlocked.replace_manifest(sealed))
    }

    /// The manifest an unlock of acme hands its closure.
    fn handed(host: &Host<'_>) -> Result<Vec<u8>> {
        unlock(host, acme(), &ws_name("acme"), Build::Release, Change::Open, |unlocked| Ok(unlocked.manifest.to_vec()))
    }

    /// Files in memory whose next write of a manifest fails, as a disk would, after the manifest beside it was written.
    #[derive(Default)]
    struct LastWriteFails {
        files: MemFiles,
        fail: Cell<bool>,
    }

    impl Adapter for LastWriteFails {
        fn label(&self) -> Label {
            self.files.label()
        }
    }

    impl Files for LastWriteFails {
        fn read(&self, k: &FileKey) -> Result<Option<Vec<u8>>> {
            self.files.read(k)
        }

        fn write_atomic(&self, k: &FileKey, bytes: &[u8]) -> Result<()> {
            if matches!(k, FileKey::Manifest(_)) && self.fail.replace(false) {
                bail!("the manifest could not be written");
            }
            self.files.write_atomic(k, bytes)
        }

        fn create_new(&self, k: &FileKey, bytes: &[u8]) -> Result<bool> {
            self.files.create_new(k, bytes)
        }

        fn append(&self, k: &FileKey, line: &[u8]) -> Result<()> {
            self.files.append(k, line)
        }

        fn remove(&self, k: &FileKey) -> Result<()> {
            self.files.remove(k)
        }

        fn names(&self) -> Result<Vec<WsName>> {
            self.files.names()
        }

        fn lock(&self, ws: WsId) -> Result<Box<dyn Held>> {
            self.files.lock(ws)
        }
    }

    /// No workspace yet, and a key held in software.
    fn soft() -> World<SoftKey> {
        World::with(SoftKey::from_seed(hardware_seed()))
    }

    /// The workspace acme, made with a key held in software.
    fn created() -> World<SoftKey> {
        let world = soft();
        world.create_acme().unwrap();
        world
    }

    /// The workspace acme with a passphrase key, as `create_key` writes it (`creating_then_opening_with_a_passphrase_takes_one_ask_each`),
    /// from the known answers' record rather than by sealing one.
    fn passphrase_acme() -> World<FixedPassphrase> {
        let world = World::with(FixedPassphrase::new(PASSPHRASE, hardware_seed(), passphrase_salt(), passphrase_nonce()));
        world.files.write_atomic(&FileKey::KeyRef(acme()), &hex(KAT_PASSPHRASE_RECORD)).unwrap();
        world.files.write_atomic(&FileKey::Wrap(acme()), &hex(KAT_HARDWARE_WRAP)).unwrap();
        world.repin();
        world
    }

    /// Whether the soft key was shown a prompt to open.
    fn asked_to_open(holder: &SoftKey) -> bool {
        holder.asked().iter().any(|(.., change, _)| *change == Change::Open)
    }

    /// Checks that opening handed out the fixed inner key's working keys, split.
    fn opens_to_the_inner_key(opened: &Opened) {
        let (door, store, names) = InnerKey::from_bytes(Zeroizing::new(inner_bytes())).open_keys().split();
        assert_eq!((opened.door.secrets(), opened.door.logs(), opened.door.sessions()), (door.secrets(), door.logs(), door.sessions()));
        assert_eq!(opened.door.policy_verify(), door.policy_verify());
        assert_eq!((opened.store.as_bytes(), opened.names.as_bytes()), (store.as_bytes(), names.as_bytes()));
    }

    /// An anchor that reads the one pin it was given, whatever it is: for a pin `MemAnchor` would not keep.
    struct Kept(Pin);

    impl Adapter for Kept {
        fn label(&self) -> Label {
            MemAnchor::new().label()
        }
    }

    impl Anchor for Kept {
        fn read(&self, _ws: WsId) -> Result<Option<Pin>> {
            Ok(Some(self.0))
        }

        fn advance(&self, _ws: WsId, _pin: &Pin) -> Result<()> {
            bail!("this anchor keeps the one pin it was given")
        }

        fn forget(&self, _ws: WsId) -> Result<()> {
            bail!("this anchor keeps the one pin it was given")
        }
    }

    #[test]
    fn creating_then_opening_takes_one_approval_each_and_one_decapsulation() {
        let world = soft();
        world.create_acme().unwrap();
        assert_eq!((world.holder.creates(), world.holder.decapsulations()), (1, 0));
        assert_eq!(world.holder.asked(), [(acme(), ws_name("acme"), Change::Create, "create workspace acme".to_string())]);
        // The holder's key ref, the wrap the known answers have, and a first pin.
        assert_eq!(world.files.read(&FileKey::KeyRef(acme())).unwrap().unwrap(), [KeyKind::Soft.tag()]);
        assert!(world.files.read(&FileKey::Wrap(acme())).unwrap().unwrap() == hex(KAT_HARDWARE_WRAP));
        assert_eq!(world.anchor.read(acme()).unwrap().map(|pin| pin.version), Some(1));

        let opened = world.open_as("acme").unwrap();
        assert_eq!((world.holder.creates(), world.holder.decapsulations()), (1, 1));
        assert_eq!(world.holder.asked()[1], (acme(), ws_name("acme"), Change::Open, "open workspace acme".to_string()));
        opens_to_the_inner_key(&opened);
        // Opening again asks again: the holder keeps nothing for a next call, and core never asks twice in one.
        world.open_as("acme").unwrap();
        assert_eq!((world.holder.asked().len(), world.holder.decapsulations()), (3, 2));
    }

    #[test]
    fn opening_with_no_pin_is_refused_before_any_prompt() {
        let world = soft();
        assert_eq!(refused(world.open_as("acme")), Refusal::Unreadable, "nothing made");
        assert!(world.holder.asked().is_empty());
        // Made, then its pin lost: the files alone do not open.
        let world = created();
        world.anchor.forget(acme()).unwrap();
        assert_eq!(refused(world.open_as("acme")), Refusal::Unreadable, "no pin");
        // Nor a pin of version 0, which no anchor keeps.
        let world = created();
        let zero = Kept(Pin { version: 0, ..world.anchor.read(acme()).unwrap().unwrap() });
        let host = Host { files: &world.files, holder: &world.holder, anchor: &zero };
        assert_eq!(refused(open(&host, acme(), &ws_name("acme"), Build::Release)), Refusal::Unreadable, "version 0");
        assert_eq!(world.holder.decapsulations(), 0);
        assert!(!asked_to_open(&world.holder));
    }

    #[test]
    fn a_changed_key_record_is_refused_before_any_prompt() {
        let world = created();
        world.files.write_atomic(&FileKey::KeyRef(acme()), &[KeyKind::Soft.tag(), 0x00]).unwrap();
        assert_eq!(refused(world.open_as("acme")), Refusal::Unreadable);
        // Nor does the key ref as it was open under a pin of another holder's kind.
        world.files.write_atomic(&FileKey::KeyRef(acme()), &[KeyKind::Soft.tag()]).unwrap();
        let pin = world.anchor.read(acme()).unwrap().unwrap();
        let other_kind = key_ref_hash(acme(), KeyKind::Passphrase, &KeyRef(vec![KeyKind::Soft.tag()]));
        world.anchor.advance(acme(), &Pin { version: 2, key_ref: other_kind, ..pin }).unwrap();
        assert_eq!(refused(world.open_as("acme")), Refusal::Unreadable);
        assert_eq!(world.holder.decapsulations(), 0);
        assert!(!asked_to_open(&world.holder));
    }

    #[test]
    fn a_swapped_public_key_is_refused_before_any_prompt() {
        let world = created();
        // A holder that answers to the same key ref with another key: initech's.
        let initech = SoftKey::from_seed(recovery_seed());
        let host = Host { files: &world.files, holder: &initech, anchor: &world.anchor };
        assert_eq!(refused(open(&host, acme(), &ws_name("acme"), Build::Release)), Refusal::Unreadable);
        assert_eq!((initech.decapsulations(), initech.asked().len()), (0, 0));
    }

    #[test]
    fn a_changed_wrap_or_a_swapped_name_is_refused_before_any_prompt() {
        let world = created();
        // acme's files, read under globex's name.
        assert_eq!(refused(world.open_as("globex")), Refusal::Unreadable, "another name");
        // A manifest or a policy where there was none.
        for file in [FileKey::Manifest(acme()), FileKey::Policy(acme())] {
            world.files.write_atomic(&file, b"allow nothing").unwrap();
            assert_eq!(refused(world.open_as("acme")), Refusal::Unreadable, "{file:?}");
            world.files.remove(&file).unwrap();
        }
        // One changed byte of the wrap, wherever it is: in its sealed part it would otherwise be found only by the tag, after the
        // holder had been asked.
        for i in [0, 2, 1600, 1682] {
            let mut wrap = hex(KAT_HARDWARE_WRAP);
            wrap[i] ^= 0x01;
            world.files.write_atomic(&FileKey::Wrap(acme()), &wrap).unwrap();
            assert_eq!(refused(world.open_as("acme")), Refusal::Unreadable, "byte {i}");
        }
        assert_eq!(world.holder.decapsulations(), 0);
        assert!(!asked_to_open(&world.holder));
        // Put back as it was, it opens under its own name.
        world.files.write_atomic(&FileKey::Wrap(acme()), &hex(KAT_HARDWARE_WRAP)).unwrap();
        world.open_as("acme").unwrap();
        assert_eq!(world.holder.decapsulations(), 1);
    }

    #[test]
    fn a_wrap_of_the_wrong_length_is_refused_before_any_prompt_even_with_a_matching_pin() {
        let world = created();
        let wrap = hex(KAT_HARDWARE_WRAP);
        let mut longer = wrap.clone();
        longer.push(0);
        let (mut other_format, mut other_suite) = (wrap.clone(), wrap.clone());
        other_format[0] = 0x02;
        other_suite[1] = 0x02;
        // A ciphertext with nothing sealed after it, and one byte more, would both reach the holder without the length check.
        for planted in [wrap[..1635].to_vec(), wrap[..WRAP_LEN - 1].to_vec(), longer, Vec::new(), other_format, other_suite] {
            world.plant(FileKey::Wrap(acme()), &planted);
            assert_eq!(refused(world.open_as("acme")), Refusal::Unreadable, "{} bytes", planted.len());
        }
        assert_eq!(world.holder.decapsulations(), 0);
        assert!(!asked_to_open(&world.holder));
        // The pins were rewritten to match each: the wrap as it was, under one more, opens.
        world.plant(FileKey::Wrap(acme()), &wrap);
        world.open_as("acme").unwrap();
        assert_eq!(world.holder.decapsulations(), 1);
    }

    #[test]
    fn a_planted_wrap_with_a_rewritten_pin_is_tampered_after_one_decapsulation() {
        let world = created();
        // Anyone with the public key can wrap an inner key of their own to it, and rewrite a pin kept in a file.
        let public = world.holder.public();
        let planted = InnerKey::from_bytes(Zeroizing::new([0x21; 32])).wrap_to(&public, acme(), WrapKind::Hardware, &recovery_rand()).unwrap();
        world.plant(FileKey::Wrap(acme()), &planted);
        // Every check before the holder passes, and it is asked once; the commitment it keeps refuses the wrap.
        let refusal = refused(world.open_as("acme"));
        assert_eq!(refusal, Refusal::Tampered);
        assert_eq!(refusal.to_string(), "this workspace's files were changed by something other than halti");
        assert_eq!(world.holder.decapsulations(), 1);
    }

    #[test]
    fn a_damaged_wrap_with_a_rewritten_pin_is_tampered_not_a_wrong_answer() {
        // One byte of the sealed key, and one of the ML-KEM ciphertext: every check before the holder still passes.
        for at in [1682, 2] {
            let world = created();
            let mut wrap = hex(KAT_HARDWARE_WRAP);
            wrap[at] ^= 0x01;
            world.plant(FileKey::Wrap(acme()), &wrap);
            assert_eq!(refused(world.open_as("acme")), Refusal::Tampered, "byte {at}");
            assert_eq!(world.holder.decapsulations(), 1, "byte {at}");
        }
    }

    #[test]
    fn a_planted_wrap_with_a_rewritten_pin_is_tampered_under_the_owners_passphrase() {
        let world = passphrase_acme();
        let public = PassphraseRecord::from_key_ref(&KeyRef(hex(KAT_PASSPHRASE_RECORD))).unwrap().public().clone();
        let planted = InnerKey::from_bytes(Zeroizing::new([0x21; 32])).wrap_to(&public, acme(), WrapKind::Hardware, &recovery_rand()).unwrap();
        world.plant(FileKey::Wrap(acme()), &planted);
        assert_eq!(refused(world.open_as("acme")), Refusal::Tampered);
        assert_eq!(world.holder.asks(), 1);
    }

    #[test]
    fn a_replaced_record_and_pin_do_not_open_with_the_owners_passphrase() {
        let world = passphrase_acme();
        // initech's program seals a key of its own under a passphrase of its own, wraps an inner key of its own to it, and
        // rewrites the pin to match.
        let (theirs, their_inner) = (DecapKey::from_seed(Zeroizing::new(recovery_seed())), InnerKey::from_bytes(Zeroizing::new([0x21; 32])));
        let typed = Passphrase::new(Zeroizing::new("initech passphrase".to_string())).unwrap();
        let create = Prompt::new(acme(), &ws_name("acme"), Change::Create, Build::Release);
        let record = PassphraseRecord::seal(&create, &typed, &theirs, &their_inner.commitment(), KdfParams::DEFAULT, &[0x55; 16], &[0x66; 12]).unwrap();
        world.files.write_atomic(&FileKey::KeyRef(acme()), &record.to_key_ref().0).unwrap();
        world.plant(FileKey::Wrap(acme()), &their_inner.wrap_to(record.public(), acme(), WrapKind::Hardware, &recovery_rand()).unwrap());
        // The owner types their own passphrase, as ever, and nothing opens.
        assert_eq!(refused(world.open_as("acme")), Refusal::Unreadable);
        assert_eq!(world.holder.asks(), 1);
    }

    #[test]
    fn a_wrong_passphrase_spends_one_ask_and_opens_nothing() {
        let world = passphrase_acme();
        world.holder.answer("acme passphrase two");
        assert_eq!(refused(world.open_as("acme")), Refusal::Unreadable);
        assert_eq!(world.holder.asks(), 1, "asked once, and not again");
    }

    #[test]
    fn creating_then_opening_with_a_passphrase_takes_one_ask_each() {
        let world = World::with(FixedPassphrase::new(PASSPHRASE, hardware_seed(), passphrase_salt(), passphrase_nonce()));
        world.create_acme().unwrap();
        assert_eq!(world.holder.asks(), 1);
        // What it wrote is what the known answers have: the record, the wrap and the pin.
        assert!(world.files.read(&FileKey::KeyRef(acme())).unwrap().unwrap() == hex(KAT_PASSPHRASE_RECORD));
        assert!(world.files.read(&FileKey::Wrap(acme())).unwrap().unwrap() == hex(KAT_HARDWARE_WRAP));
        assert_eq!(world.anchor.read(acme()).unwrap().unwrap().to_bytes().as_slice(), hex(KAT_PIN));

        let opened = world.open_as("acme").unwrap();
        assert_eq!(world.holder.asks(), 2);
        opens_to_the_inner_key(&opened);
    }

    #[test]
    fn a_declined_approval_is_a_refusal_and_opens_nothing() {
        let world = created();
        world.holder.decline(true);
        let refusal = refused(world.open_as("acme"));
        assert_eq!(refusal, Refusal::Declined);
        assert_eq!(refusal.to_string(), "that was not approved");
        assert_eq!(world.holder.decapsulations(), 0);
        assert!(asked_to_open(&world.holder), "it was asked, and said no");

        // A declined create writes nothing.
        let world = soft();
        world.holder.decline(true);
        assert_eq!(refused(world.create_acme()), Refusal::Declined);
        assert_eq!((world.files.read(&FileKey::KeyRef(acme())).unwrap(), world.files.read(&FileKey::Wrap(acme())).unwrap()), (None, None));
        assert_eq!(world.anchor.read(acme()).unwrap(), None);
        // Once it says yes, the workspace is made and opens.
        world.holder.decline(false);
        world.create_acme().unwrap();
        world.open_as("acme").unwrap();
    }

    #[test]
    fn every_refusal_before_the_prompt_is_the_same() {
        // Opens acme's workspace with another anchor or holder, or under another name, and checks that nothing was asked.
        let unasked = |world: &World<SoftKey>, anchor: Option<&dyn Anchor>, holder: Option<&SoftKey>, name: &str| {
            let holder = holder.unwrap_or(&world.holder);
            let host = Host { files: &world.files, holder, anchor: anchor.unwrap_or(&world.anchor) };
            let refusal = refused(open(&host, acme(), &ws_name(name), Build::Release));
            assert_eq!(holder.decapsulations(), 0);
            assert!(!asked_to_open(holder));
            refusal
        };
        // Step 2: no pin, or one of version 0.
        let mut refusals = vec![unasked(&soft(), None, None, "acme")];
        let world = created();
        let zero: &dyn Anchor = &Kept(Pin { version: 0, ..world.anchor.read(acme()).unwrap().unwrap() });
        refusals.push(unasked(&world, Some(zero), None, "acme"));
        // Step 3: either file missing, or a key ref the pin does not name.
        for file in [FileKey::KeyRef(acme()), FileKey::Wrap(acme())] {
            let world = created();
            world.files.remove(&file).unwrap();
            refusals.push(unasked(&world, None, None, "acme"));
        }
        let world = created();
        world.files.write_atomic(&FileKey::KeyRef(acme()), &[KeyKind::Passphrase.tag()]).unwrap();
        refusals.push(unasked(&world, None, None, "acme"));
        // Step 4: another public key.
        refusals.push(unasked(&created(), None, Some(&SoftKey::from_seed(recovery_seed())), "acme"));
        // Step 5: another name, or a policy where there was none.
        refusals.push(unasked(&created(), None, None, "globex"));
        let world = created();
        world.files.write_atomic(&FileKey::Policy(acme()), b"allow nothing").unwrap();
        refusals.push(unasked(&world, None, None, "acme"));
        // Step 6: a wrap of another length or format, under a pin that matches it.
        let world = created();
        let mut wrap = hex(KAT_HARDWARE_WRAP);
        wrap.push(0);
        world.plant(FileKey::Wrap(acme()), &wrap);
        refusals.push(unasked(&world, None, None, "acme"));
        wrap.pop();
        wrap[0] = 0x02;
        world.plant(FileKey::Wrap(acme()), &wrap);
        refusals.push(unasked(&world, None, None, "acme"));

        assert_eq!(refusals.len(), 10);
        for refusal in refusals {
            assert_eq!(refusal, Refusal::Unreadable);
            assert_eq!(refusal.to_string(), "that can't be opened (wrong key, or it was changed)");
        }
    }

    #[test]
    fn opening_a_locked_workspace_fails_without_a_prompt_and_says_it_is_locked() {
        let world = created();
        let held = world.files.lock(acme()).unwrap();
        let reads = world.anchor.reads();
        let error = world.open_as("acme").unwrap_err();
        assert!(error.downcast_ref::<Refusal>().is_none(), "not a refusal: {error}");
        assert!(error.to_string().contains("locked"), "{error}");
        assert_eq!(world.anchor.reads(), reads, "the lock is taken before anything is read");
        assert_eq!(world.holder.decapsulations(), 0);
        // Nor does creating wait for it.
        let error = world.create_acme().unwrap_err();
        assert!(error.downcast_ref::<Refusal>().is_none() && error.to_string().contains("locked"), "{error}");
        assert!(!asked_to_open(&world.holder));
        drop(held);
        world.open_as("acme").unwrap();
    }

    #[test]
    fn a_workspace_is_not_created_twice() {
        let world = created();
        let kept = || (world.files.read(&FileKey::KeyRef(acme())).unwrap(), world.files.read(&FileKey::Wrap(acme())).unwrap(), world.anchor.read(acme()).unwrap());
        let before = kept();
        assert!(world.create_acme().unwrap_err().to_string().contains("already has a key"));
        assert!(create_key(&world.host(), acme(), &ws_name("globex"), Build::Release, draws(), |_| Ok(())).is_err(), "nor under another name");
        assert_eq!(world.holder.creates(), 1, "the holder was not asked again");
        assert_eq!(kept(), before);
        // Nor where only the pin is left, only the key ref, or only the wrap: and the holder is not asked, nor a file written.
        world.files.remove(&FileKey::KeyRef(acme())).unwrap();
        world.files.remove(&FileKey::Wrap(acme())).unwrap();
        let error = world.create_acme().unwrap_err();
        assert!(error.to_string().contains("already has a key"), "a pin: {error}");
        assert_eq!(world.holder.creates(), 1, "a pin: the holder was not asked again");
        assert_eq!((world.files.read(&FileKey::KeyRef(acme())).unwrap(), world.files.read(&FileKey::Wrap(acme())).unwrap()), (None, None));
        let world = created();
        world.anchor.forget(acme()).unwrap();
        world.files.remove(&FileKey::Wrap(acme())).unwrap();
        assert!(world.create_acme().unwrap_err().to_string().contains("already has a key"), "a key ref");
        assert_eq!(world.holder.creates(), 1);
        let world = created();
        world.anchor.forget(acme()).unwrap();
        world.files.remove(&FileKey::KeyRef(acme())).unwrap();
        assert!(world.create_acme().unwrap_err().to_string().contains("already has a key"), "a wrap");
        assert_eq!(world.holder.creates(), 1);
        assert_eq!(world.files.read(&FileKey::KeyRef(acme())).unwrap(), None);
    }

    #[test]
    fn creating_writes_the_key_record_and_the_wrap_before_the_pin() {
        let world = soft();
        world.anchor.fail_next_advance();
        assert!(world.create_acme().unwrap_err().to_string().contains("could not be written"));
        assert_eq!(world.files.read(&FileKey::KeyRef(acme())).unwrap(), Some(vec![KeyKind::Soft.tag()]));
        assert!(world.files.read(&FileKey::Wrap(acme())).unwrap() == Some(hex(KAT_HARDWARE_WRAP)));
        assert_eq!(world.anchor.read(acme()).unwrap(), None, "no pin");
        // Files with no pin do not open, and are not made again over.
        assert_eq!(refused(world.open_as("acme")), Refusal::Unreadable);
        assert_eq!(world.holder.decapsulations(), 0);
        assert!(world.create_acme().is_err());
        assert_eq!(world.holder.creates(), 1);
    }

    #[test]
    fn replacing_the_manifest_moves_the_pin_on_by_one_and_opens_after() {
        let world = created();
        let first = world.pin();
        // Inside the change, the version the pin will move to.
        let next = unlock(&world.host(), acme(), &ws_name("acme"), Build::Release, Change::Open, |unlocked| unlocked.next()).unwrap();
        assert_eq!((first.version, next), (1, 2));
        world.replace(b"second").unwrap();
        assert_eq!(world.holder.decapsulations(), 2);
        // One version on, over the new manifest; the key ref and the public key are the ones it had.
        let state = state_hash(acme(), &ws_name("acme"), &hex(KAT_HARDWARE_WRAP), b"second", b"");
        assert_eq!(world.pin(), Pin { version: 2, state, ..first });
        assert_eq!((world.file(FileKey::Manifest(acme())), world.file(FileKey::NextManifest(acme()))), (Some(b"second".to_vec()), None));
        // The next unlock is handed it, and one more replacement moves the pin to 3.
        assert_eq!(world.handed().unwrap(), b"second");
        world.replace(b"third").unwrap();
        assert_eq!((world.pin().version, world.handed().unwrap()), (3, b"third".to_vec()));
        assert_eq!(world.holder.decapsulations(), 5);
        opens_to_the_inner_key(&world.open_as("acme").unwrap());

        // Once per change: a second replacement in the same unlock fails, and the first stands.
        let twice = unlock(&world.host(), acme(), &ws_name("acme"), Build::Release, Change::Open, |unlocked| {
            unlocked.replace_manifest(b"fourth")?;
            unlocked.replace_manifest(b"fifth")
        });
        assert!(twice.unwrap_err().to_string().contains("already replaced"));
        assert_eq!((world.pin().version, world.handed().unwrap()), (4, b"fourth".to_vec()));
        assert_eq!(world.file(FileKey::NextManifest(acme())), None);
    }

    #[test]
    fn a_replacement_cut_short_before_the_pin_is_dropped_before_any_prompt() {
        let world = created();
        world.replace(b"second").unwrap();
        let pin = world.pin();
        // Written beside it, and the pin never moved: a crash, or a disk that failed it.
        world.files.write_atomic(&FileKey::NextManifest(acme()), b"third").unwrap();
        // Before the holder is asked, and so even when it says no, the new one is dropped.
        world.holder.decline(true);
        let decapsulations = world.holder.decapsulations();
        assert_eq!(refused(world.handed()), Refusal::Declined);
        assert_eq!(world.file(FileKey::NextManifest(acme())), None);
        world.holder.decline(false);
        // It opens to the manifest the pin covers, with one decapsulation, and nothing was moved.
        assert_eq!(world.handed().unwrap(), b"second");
        assert_eq!(world.holder.decapsulations(), decapsulations + 1);
        assert_eq!((world.pin(), world.file(FileKey::Manifest(acme()))), (pin, Some(b"second".to_vec())));

        // Nor is one already put in place, and left beside it by a crash, kept.
        world.files.write_atomic(&FileKey::NextManifest(acme()), b"second").unwrap();
        assert_eq!(world.handed().unwrap(), b"second");
        assert_eq!(world.file(FileKey::NextManifest(acme())), None);
        assert_eq!(world.pin(), pin);
    }

    #[test]
    fn a_replacement_cut_short_after_the_pin_is_finished_before_any_prompt() {
        let world = created();
        world.replace(b"second").unwrap();
        // Written beside it and covered by the pin, but never put in its place.
        world.files.write_atomic(&FileKey::NextManifest(acme()), b"third").unwrap();
        world.pin_over(b"third");
        let pin = world.pin();
        // Before the holder is asked, and so even when it says no, the new one is put in place.
        world.holder.decline(true);
        let decapsulations = world.holder.decapsulations();
        assert_eq!(refused(world.handed()), Refusal::Declined);
        assert_eq!((world.file(FileKey::Manifest(acme())), world.file(FileKey::NextManifest(acme()))), (Some(b"third".to_vec()), None));
        world.holder.decline(false);
        // It opens to the new one, with one decapsulation, and the pin is as it was moved.
        assert_eq!(world.handed().unwrap(), b"third");
        assert_eq!((world.holder.decapsulations(), world.pin()), (decapsulations + 1, pin));
        opens_to_the_inner_key(&world.open_as("acme").unwrap());
    }

    #[test]
    fn a_next_manifest_the_pin_does_not_cover_opens_nothing() {
        let world = created();
        world.replace(b"second").unwrap();
        let (asked, decapsulations) = (world.holder.asked().len(), world.holder.decapsulations());
        // The manifest changed, and a new one beside it that the pin does not cover either; then the manifest removed.
        world.files.write_atomic(&FileKey::Manifest(acme()), b"changed").unwrap();
        world.files.write_atomic(&FileKey::NextManifest(acme()), b"planted").unwrap();
        assert_eq!(refused(world.handed()), Refusal::Unreadable);
        world.files.remove(&FileKey::Manifest(acme())).unwrap();
        assert_eq!(refused(world.handed()), Refusal::Unreadable);
        // Nothing was asked, and nothing written: the new one is left as it was.
        assert_eq!((world.holder.asked().len(), world.holder.decapsulations()), (asked, decapsulations));
        assert_eq!((world.file(FileKey::Manifest(acme())), world.file(FileKey::NextManifest(acme()))), (None, Some(b"planted".to_vec())));
        // Neither manifest, and none beside it, is refused as before.
        world.files.remove(&FileKey::NextManifest(acme())).unwrap();
        assert_eq!(refused(world.handed()), Refusal::Unreadable);
        assert_eq!(world.holder.decapsulations(), decapsulations);
    }

    #[test]
    fn a_failed_advance_leaves_the_old_manifest_opening() {
        let world = created();
        world.replace(b"second").unwrap();
        let pin = world.pin();
        world.anchor.fail_next_advance();
        let error = world.replace(b"third").unwrap_err();
        assert!(error.to_string().contains("could not be written"), "{error}");
        assert_eq!((world.pin(), world.file(FileKey::Manifest(acme()))), (pin, Some(b"second".to_vec())));
        // The next unlock keeps the manifest the pin covers, and drops the one beside it.
        assert_eq!(world.handed().unwrap(), b"second");
        assert_eq!(world.file(FileKey::NextManifest(acme())), None);
        // And the change can be made again.
        world.replace(b"third").unwrap();
        assert_eq!((world.pin().version, world.handed().unwrap()), (3, b"third".to_vec()));
    }

    #[test]
    fn a_replacement_whose_last_write_fails_is_made_and_finished_by_the_next_unlock() {
        let (files, anchor, holder) = (LastWriteFails::default(), MemAnchor::new(), SoftKey::from_seed(hardware_seed()));
        let host = Host { files: &files, holder: &holder, anchor: &anchor };
        create_key(&host, acme(), &ws_name("acme"), Build::Release, draws(), |_| Ok(())).unwrap();
        replace(&host, b"second").unwrap();
        // The pin moved, so the change is made: the failed write after it is not reported.
        files.fail.set(true);
        replace(&host, b"third").unwrap();
        assert!(!files.fail.get(), "the write was tried, and failed");
        assert_eq!(anchor.read(acme()).unwrap().map(|pin| pin.version), Some(3));
        let file = |file: FileKey| files.read(&file).unwrap();
        assert_eq!((file(FileKey::Manifest(acme())), file(FileKey::NextManifest(acme()))), (Some(b"second".to_vec()), Some(b"third".to_vec())));
        // The next unlock puts it in place and is handed it.
        assert_eq!(handed(&host).unwrap(), b"third");
        assert_eq!((file(FileKey::Manifest(acme())), file(FileKey::NextManifest(acme()))), (Some(b"third".to_vec()), None));
        assert_eq!(holder.decapsulations(), 3);
    }
}
