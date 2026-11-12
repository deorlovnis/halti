//! The reasons core itself says no, as values a caller can tell apart. What an adapter fails with
//! (a disk, a keystore) stays a plain `anyhow` error; a caller finds one of these in it with
//! `downcast_ref::<Refusal>()`.

use std::fmt;

use crate::ids::WsName;

/// Why core said no.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The text isn't a workspace name. It is never echoed: it may hold anything.
    BadName,
    /// The text isn't a workspace id.
    BadId,
    /// No workspace exists, so none can be meant.
    NoWorkspace,
    /// More than one workspace exists and none was typed. It names none of them.
    NameOne,
    /// The typed name is well formed and no workspace has it. It holds only what was typed.
    Unknown(WsName),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::BadName => write!(f, "that isn't a workspace name (1 to {} of a-z, 0-9 and -, starting with a letter or digit)", WsName::MAX),
            Refusal::BadId => write!(f, "that isn't a workspace id (32 lowercase hex characters)"),
            Refusal::NoWorkspace => write!(f, "there is no workspace yet (make one first)"),
            Refusal::NameOne => write!(f, "there is more than one workspace (name one)"),
            Refusal::Unknown(name) => write!(f, "there is no workspace named {name}"),
        }
    }
}

impl std::error::Error for Refusal {}
