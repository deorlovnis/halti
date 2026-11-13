//! Real workspaces in a test folder, for tests outside this module that need one open: made,
//! changed and opened through core's verbs, every passphrase answered by the holder's test answer.
//! Nothing here reaches the Keychain, sudo or Touch ID.

use halti_core::boxkey::BoxKey;
use halti_core::policy::{Base, Kind, Proposal};
use halti_core::verbs::{BoxNonces, Reader, ws_approve, ws_box_new};

use super::*;
use crate::util::TempDir;

/// A workspaces folder of the test's own, removed when dropped.
pub struct Bench {
    here: Here,
    /// Removed when the bench is dropped.
    _dir: TempDir,
}

impl Bench {
    pub fn new(prefix: &str) -> Bench {
        let dir = TempDir::new(prefix).unwrap();
        Bench { here: Here::at(&dir.0.join("ws")), _dir: dir }
    }

    /// The workspaces folder.
    pub fn root(&self) -> &Path {
        &self.here.root
    }

    fn holder(passphrase: &str) -> TtyPassphrase {
        TtyPassphrase::new(false).answering(passphrase)
    }

    /// Makes workspace `name` with `passphrase`.
    pub fn make(&self, name: &str, passphrase: &str) -> WsId {
        new_with(&self.here, &WsName::parse(name).unwrap(), &Self::holder(passphrase), &saved::Keychain).unwrap();
        self.here.id_of(&WsName::parse(name).unwrap()).unwrap()
    }

    /// Stores `value` as `resource/field` in `name`, as `ws set` does.
    pub fn set(&self, name: &str, passphrase: &str, resource: &str, field: &str, value: &str) {
        let key = ItemKey::parse(resource, field).unwrap();
        let value = || Secret::new(Zeroizing::new(value.as_bytes().to_vec())).map_err(Into::into);
        let nonces = Nonces { value: *random::<12>().unwrap(), manifest: *random::<12>().unwrap() };
        ws_set(&self.here.machine(&Self::holder(passphrase)), &WsName::parse(name).unwrap(), &key, value, nonces).unwrap();
    }

    /// Approves `text` as the policy of `resource` in `name`, as `ws policy approve` does.
    pub fn approve(&self, name: &str, passphrase: &str, resource: &str, text: &str) {
        let proposal = Proposal { kind: Kind::Resource, name: resource, text: text.as_bytes(), base: Base::Shown };
        ws_approve(&self.here.machine(&Self::holder(passphrase)), &WsName::parse(name).unwrap(), &[proposal], *random::<12>().unwrap()).unwrap();
    }

    /// Makes box `box_name` in `name` with this key and policy, as `ws box new` will.
    pub fn make_box(&self, name: &str, passphrase: &str, box_name: &str, key: [u8; 32], text: &str) {
        let key = BoxKey::from_bytes(Zeroizing::new(key));
        let proposal = Proposal { kind: Kind::Box, name: box_name, text: text.as_bytes(), base: Base::New };
        let nonces = BoxNonces { key: *random::<12>().unwrap(), manifest: *random::<12>().unwrap() };
        ws_box_new(&self.here.machine(&Self::holder(passphrase)), &WsName::parse(name).unwrap(), Some(&key), &proposal, || Ok(()), nonces).unwrap();
    }

    /// Opens `name`: the reader core hands out, and what reads it again.
    pub fn open(&self, name: &str, passphrase: &str) -> (Reader, Reading) {
        let reader = ws_open(&self.here.machine(&Self::holder(passphrase)), &WsName::parse(name).unwrap()).unwrap();
        (reader, Reading::at(&self.here.root))
    }
}
