//! What holds a workspace's private key, as core sees it. A key holder may be on this machine or
//! another, behind a passphrase, hardware or a person's phone: core asks it one question at a time,
//! with a `Prompt` only core can make, and never assumes the answer is typed here.
//!
//! Beside its key a holder keeps a `Commitment` to the workspace's inner key, and gives it back
//! with the shares. Opening checks the unwrapped key against it, so a wrap planted by anyone who
//! has the public key is refused once the holder has answered.

use std::fmt;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::ids::{WsId, WsName, write_hex};
use crate::key::{KemCiphertext, KemShares, PublicKey};
use crate::platform::{Adapter, Build};
use crate::refusal::Refusal;

/// What kind of key holds a workspace's private half. Tags and names are written into records, so
/// they are fixed. Tags 0x01 to 0x03 are kept for keys in hardware.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum KeyKind {
    /// A seed in memory or in a file, behind nothing: for tests and development.
    Soft,
    /// A seed sealed under a passphrase (`passphrase`).
    Passphrase,
}

impl KeyKind {
    /// The byte that names it in a record.
    pub const fn tag(self) -> u8 {
        match self {
            KeyKind::Soft => 0x04,
            KeyKind::Passphrase => 0x05,
        }
    }

    /// Refuses a byte that names no kind this build knows.
    pub fn from_tag(tag: u8) -> Result<KeyKind, Refusal> {
        match tag {
            0x04 => Ok(KeyKind::Soft),
            0x05 => Ok(KeyKind::Passphrase),
            _ => Err(Refusal::Unreadable),
        }
    }
}

/// What a key holder needs to find its key again: opaque to core, hashed into the pin.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyRef(pub Vec<u8>);

/// Its length only: a passphrase holder's key ref is its whole record, which is enough to guess passphrases offline.
impl fmt::Debug for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyRef({} bytes)", self.0.len())
    }
}

/// The change a key holder is asked to approve.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Change {
    /// Making the workspace's key.
    Create,
    /// Opening the workspace.
    Open,
    /// Deleting the workspace: its items, pin, key and files.
    Delete,
    /// Storing a secret in the workspace, or replacing one.
    Store,
    /// Removing secrets from the workspace.
    Remove,
}

/// One request to a key holder: one workspace, one change. Only core makes one, from checked
/// fields, so a holder far away can show the fields as they are. It cannot be copied: a holder sees
/// it only for the call core makes.
///
/// ```compile_fail
/// let _ = halti_core::holder::Prompt::new;
/// ```
///
/// (That fails because `new` is private to this crate, as this, which is public, does not.)
///
/// ```
/// let _ = halti_core::holder::Prompt::text;
/// ```
#[derive(PartialEq, Eq, Debug)]
pub struct Prompt {
    ws: WsId,
    name: WsName,
    change: Change,
    build: Build,
}

impl Prompt {
    pub(crate) fn new(ws: WsId, name: &WsName, change: Change, build: Build) -> Prompt {
        Prompt { ws, name: name.clone(), change, build }
    }

    pub fn ws(&self) -> WsId {
        self.ws
    }

    pub fn name(&self) -> &WsName {
        &self.name
    }

    pub fn change(&self) -> Change {
        self.change
    }

    pub fn build(&self) -> Build {
        self.build
    }

    /// The words to show: `open workspace acme`, or `store a secret in workspace acme`, after
    /// `[DEV, not protected] ` in a development build. The name is the only part that varies, and a name holds only a-z, 0-9 and `-`, so
    /// the text holds no control or direction character.
    pub fn text(&self) -> String {
        let dev = match self.build {
            Build::Dev => "[DEV, not protected] ",
            Build::Release => "",
        };
        let verb = match self.change {
            Change::Create => "create",
            Change::Open => "open",
            Change::Delete => "delete",
            Change::Store => "store a secret in",
            Change::Remove => "remove secrets from",
        };
        format!("{dev}{verb} workspace {}", self.name)
    }
}

/// What a key holder keeps beside its key and gives back with the shares: the policy verifying
/// key of the workspace's inner key, 65 bytes. Not secret, and any holder can return any value: it
/// is worth what the place the holder keeps it is worth.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Commitment([u8; 65]);

impl Commitment {
    pub const fn from_bytes(bytes: [u8; 65]) -> Commitment {
        Commitment(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }
}

/// 130 lowercase hex characters.
impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

/// What one approved decapsulation gives back. It can't be cloned, and printing it shows nothing
/// of it.
pub struct Released {
    pub shares: KemShares,
    pub commitment: Commitment,
}

impl fmt::Debug for Released {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Released(..)")
    }
}

/// Holds a workspace's private key. It is asked with a `Prompt` and answers with shares or a
/// refusal.
pub trait KeyHolder: Adapter {
    fn kind(&self) -> KeyKind;

    /// Makes a key for `prompt.ws()` and keeps `commitment` where only this key's owner can change
    /// it. One approval, no decapsulation.
    fn create(&self, prompt: &Prompt, commitment: &Commitment) -> Result<(KeyRef, PublicKey)>;

    /// The public half, with no approval. Trusted only once a decapsulation under it has been
    /// checked.
    fn public(&self, key: &KeyRef) -> Result<PublicKey>;

    /// Exactly one approval naming `prompt`, then both decapsulations under it. Nothing is kept
    /// for a next call. A "no" is `Refusal::Declined`; a wrong answer is `Refusal::Unreadable`; an
    /// answer that unseals something that does not match is `Refusal::Tampered`.
    fn decapsulate(&self, key: &KeyRef, prompt: &Prompt, ct: &KemCiphertext) -> Result<Released>;

    /// Forgets the key, where the holder keeps anything.
    fn destroy(&self, key: &KeyRef) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vectors::ws_bytes;

    fn acme() -> WsId {
        WsId::from_bytes(ws_bytes())
    }

    fn name(text: &str) -> WsName {
        WsName::parse(text).unwrap()
    }

    #[test]
    fn the_prompt_names_the_workspace_and_the_change() {
        let prompt = Prompt::new(acme(), &name("acme"), Change::Open, Build::Release);
        assert_eq!((prompt.ws(), prompt.name(), prompt.change(), prompt.build()), (acme(), &name("acme"), Change::Open, Build::Release));
        assert_eq!(prompt.text(), "open workspace acme");
        assert_eq!(Prompt::new(acme(), &name("acme"), Change::Create, Build::Release).text(), "create workspace acme");
        assert_eq!(Prompt::new(acme(), &name("acme"), Change::Delete, Build::Release).text(), "delete workspace acme");
        assert_eq!(Prompt::new(acme(), &name("acme"), Change::Store, Build::Release).text(), "store a secret in workspace acme");
        assert_eq!(Prompt::new(acme(), &name("acme"), Change::Remove, Build::Release).text(), "remove secrets from workspace acme");
        // A development build says so first, whatever the change.
        assert_eq!(Prompt::new(acme(), &name("acme"), Change::Open, Build::Dev).text(), "[DEV, not protected] open workspace acme");
        assert_eq!(Prompt::new(acme(), &name("globex"), Change::Create, Build::Dev).text(), "[DEV, not protected] create workspace globex");
        assert_eq!(Prompt::new(acme(), &name("acme"), Change::Delete, Build::Dev).text(), "[DEV, not protected] delete workspace acme");
        assert_eq!(Prompt::new(acme(), &name("acme"), Change::Store, Build::Dev).text(), "[DEV, not protected] store a secret in workspace acme");
        assert_eq!(Prompt::new(acme(), &name("globex"), Change::Remove, Build::Dev).text(), "[DEV, not protected] remove secrets from workspace globex");
        // Each field tells one prompt from another.
        let globex = WsId::from_bytes([2; 16]);
        assert_ne!(prompt, Prompt::new(globex, &name("acme"), Change::Open, Build::Release));
        assert_ne!(prompt, Prompt::new(acme(), &name("globex"), Change::Open, Build::Release));
        assert_ne!(prompt, Prompt::new(acme(), &name("acme"), Change::Create, Build::Release));
        assert_ne!(prompt, Prompt::new(acme(), &name("acme"), Change::Delete, Build::Release));
        assert_ne!(prompt, Prompt::new(acme(), &name("acme"), Change::Store, Build::Release));
        assert_ne!(prompt, Prompt::new(acme(), &name("acme"), Change::Remove, Build::Release));
        assert_ne!(prompt, Prompt::new(acme(), &name("acme"), Change::Open, Build::Dev));
    }

    #[test]
    fn a_prompt_holds_no_control_or_direction_character() {
        let longest = "z".repeat(WsName::MAX);
        // Lowercase letters, digits, spaces and dashes, and the fixed words and brackets of the dev prefix: nothing a terminal draws as something else.
        let shown_as_typed = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || " -[],DEV".contains(c);
        for text in ["acme", "globex", "initech", "0-a", longest.as_str()] {
            for change in [Change::Create, Change::Open, Change::Delete, Change::Store, Change::Remove] {
                for build in [Build::Dev, Build::Release] {
                    let shown = Prompt::new(acme(), &name(text), change, build).text();
                    assert!(shown.chars().all(shown_as_typed), "{shown:?}");
                    assert!(shown.ends_with(&format!(" workspace {text}")), "{shown:?}");
                }
            }
        }
    }

    #[test]
    fn a_key_kind_is_written_as_its_fixed_tag_and_name() {
        assert_eq!((KeyKind::Soft.tag(), KeyKind::Passphrase.tag()), (0x04, 0x05));
        for tag in 0..=255 {
            let known = match tag {
                0x04 => Ok(KeyKind::Soft),
                0x05 => Ok(KeyKind::Passphrase),
                _ => Err(Refusal::Unreadable),
            };
            assert_eq!(KeyKind::from_tag(tag), known, "tag {tag}");
        }
        assert_eq!(serde_json::to_string(&[KeyKind::Soft, KeyKind::Passphrase]).unwrap(), r#"["soft","passphrase"]"#);
    }
}
