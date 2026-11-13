//! A workspace's passphrase saved by a password manager (`[passwords] manager`): the Keychain, on a
//! Mac. `ws new` saves it once the workspace is made, and `open` and `ws delete` take it from there
//! after the approval the settings name for them (`[workspace.approval]`), instead of having it
//! typed.
//!
//! A workspace records which way it was made. One made with the saved copy records this module's
//! label, which lacks more than a typed one's: a program running as you has more ways to get a
//! saved passphrase. So, by core's rule, a workspace made to be typed never opens from a copy, and
//! one made with a copy still opens by typing.
//!
//! The copy is the passphrase's exact text, in an item named by the workspace's id
//! (`names::WS_KEYCHAIN_PREFIX`). It is read only after the approval, and only while macOS may show
//! no window, so an item the running halti didn't write reads as missing. One that is missing or
//! can't be used sends the person to typing, and is saved again once the typed passphrase has
//! opened the workspace.

use std::cell::Cell;
use std::fmt;

use anyhow::{Result, bail};
use halti_core::holder::{Change, Commitment, KeyHolder, KeyKind, KeyRef, Prompt, Released};
use halti_core::ids::WsId;
use halti_core::key::{KemCiphertext, PublicKey};
use halti_core::passphrase::{self, Passphrase, PassphraseRecord};
use halti_core::platform::{Adapter, Grade, Label, Lacks, Property};
use halti_core::refusal::Refusal;
use zeroize::Zeroizing;

use super::tty;
use crate::approval::{self, Action, Declined, Means, World};
use crate::keychain;

/// What a workspace made with a saved copy of its passphrase records, and what opening it from the
/// copy says: everything a typed passphrase lacks, and that others can touch it.
pub const LABEL: Label = Label {
    adapter: "keychain-passphrase-key",
    grade: Grade::Weaker,
    lacks: Lacks::of(&[Property::KeyInHardware, Property::PresenceProof, Property::TrustedPrompt, Property::OthersCantTouch]),
    why: "passphrase key with a copy in the keychain: halti asks for the approval its settings name before it reads the copy, but macOS does not; \
          a program running as you has more ways to get the passphrase",
};

/// Where saved passphrases are kept, by workspace id: the Keychain, or memory in tests.
pub trait Copies {
    fn exists(&self, ws: WsId) -> bool;
    /// A new copy, in place of any that is there.
    fn add(&self, ws: WsId, passphrase: &str) -> Result<()>;
    /// None if it is missing or can't be read without a window. Wiped when dropped.
    fn get(&self, ws: WsId) -> Option<Zeroizing<String>>;
    /// Whether one was removed.
    fn remove(&self, ws: WsId) -> bool;
}

/// The login Keychain.
pub struct Keychain;

impl Copies for Keychain {
    fn exists(&self, ws: WsId) -> bool {
        keychain::ws_exists(&ws.to_string())
    }

    fn add(&self, ws: WsId, passphrase: &str) -> Result<()> {
        keychain::ws_add(&ws.to_string(), passphrase)
    }

    fn get(&self, ws: WsId) -> Option<Zeroizing<String>> {
        keychain::ws_get(&ws.to_string())
    }

    fn remove(&self, ws: WsId) -> bool {
        keychain::ws_delete(&ws.to_string())
    }
}

/// The saved copy can't be used: missing, not readable without a window, or not the passphrase.
/// The person types it instead.
#[derive(Debug)]
pub struct Unusable;

impl fmt::Display for Unusable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the saved passphrase can't be used")
    }
}

impl std::error::Error for Unusable {}

/// Whether a try with the saved copy that failed goes on to typing: the copy can't be used, or the
/// workspace was made to be typed (core finds that once the copy has opened it, and refuses it as
/// lacking what was recorded). Anything else, such as changed files, is said as it is.
pub fn falls_to_typing(error: &anyhow::Error) -> bool {
    let only_the_copy = LABEL.lacks.beyond(passphrase::LABEL.lacks);
    error.is::<Unusable>() || matches!(error.downcast_ref::<Refusal>(), Some(Refusal::Downgraded(more)) if more.within(only_the_copy))
}

/// The key holder that takes a workspace's passphrase from its saved copy, after the approval the
/// settings name for `action`. It never asks for the passphrase itself, and never makes a key:
/// `ws new` has it typed.
pub struct KeychainPassphrase<'a> {
    copies: &'a dyn Copies,
    world: &'a dyn World,
    /// Any but the passphrase, which is typed instead of taken from here.
    means: Means,
    action: Action,
    /// The workspace whose copy it read, so `destroy` removes that copy.
    read: Cell<Option<WsId>>,
}

impl<'a> KeychainPassphrase<'a> {
    pub fn new(copies: &'a dyn Copies, world: &'a dyn World, means: Means, action: Action) -> KeychainPassphrase<'a> {
        KeychainPassphrase { copies, world, means, action, read: Cell::new(None) }
    }
}

impl Adapter for KeychainPassphrase<'_> {
    fn label(&self) -> Label {
        LABEL
    }
}

impl KeyHolder for KeychainPassphrase<'_> {
    fn kind(&self) -> KeyKind {
        KeyKind::Passphrase
    }

    fn create(&self, _prompt: &Prompt, _commitment: &Commitment) -> Result<(KeyRef, PublicKey)> {
        bail!("a workspace's passphrase is typed when it is made")
    }

    fn public(&self, key: &KeyRef) -> Result<PublicKey> {
        Ok(PassphraseRecord::from_key_ref(key)?.public().clone())
    }

    /// Says what a delete removes, asks for the approval (`approval::Declined` if it isn't given),
    /// then reads the copy of the workspace core named, with no window allowed. A copy that is
    /// missing, isn't a passphrase or doesn't open the record is `Unusable`.
    fn decapsulate(&self, key: &KeyRef, prompt: &Prompt, ct: &KemCiphertext) -> Result<Released> {
        let record = PassphraseRecord::from_key_ref(key)?;
        if self.means == Means::Passphrase {
            return Err(Unusable.into());
        }
        if prompt.change() == Change::Delete {
            tty::tell(&tty::deleting(prompt.name()));
        }
        approval::ask_by(self.world, Some(self.means), self.action, &prompt.text()).map_err(|_| Declined)?;
        self.read.set(Some(prompt.ws()));
        let text = self.copies.get(prompt.ws()).ok_or(Unusable)?;
        let passphrase = Passphrase::new(text).map_err(|_| Unusable)?;
        tty::unseal(&record, prompt, &passphrase, ct).map_err(|refusal| match refusal {
            Refusal::Unreadable => anyhow::Error::from(Unusable),
            refusal => anyhow::Error::from(refusal),
        })
    }

    /// Removes the copy it read: core calls this once the pin is gone, before the files go.
    fn destroy(&self, _key: &KeyRef) -> Result<()> {
        if let Some(ws) = self.read.get() {
            self.copies.remove(ws);
        }
        Ok(())
    }
}
