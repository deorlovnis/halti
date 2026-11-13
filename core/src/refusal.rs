//! The reasons core itself says no, as values a caller can tell apart. What an adapter fails with
//! (a disk, a keystore) stays a plain `anyhow` error; a caller finds one of these in it with
//! `downcast_ref::<Refusal>()`.

use std::fmt;

use crate::ids::WsName;
use crate::passphrase::Passphrase;
use crate::platform::{Build, Grade, Lacks, Property};

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
    /// It could not be opened or checked: wrong key, or it was changed. It carries nothing, so
    /// every such failure looks the same.
    Unreadable,
    /// The key holder was asked and said no, or the person stopped it.
    Declined,
    /// A check failed after the key holder proved its answer: the workspace's files were changed.
    Tampered,
    /// A new passphrase is too short. It is never echoed.
    ShortPassphrase,
    /// A workspace already has the name. It holds only what was typed.
    Taken(WsName),
    /// A release build does not run a workspace on this adapter on this system.
    NotAdmitted { adapter: &'static str, grade: Grade },
    /// This machine lacks protections the workspace was made with: these, which it did not lack
    /// then.
    Downgraded(Lacks),
    /// The workspace was made by a build of the other kind.
    OtherBuild(Build),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::BadName => write!(f, "that isn't a workspace name (1 to {} of a-z, 0-9 and -, starting with a letter or digit)", WsName::MAX),
            Refusal::BadId => write!(f, "that isn't a workspace id (32 lowercase hex characters)"),
            Refusal::NoWorkspace => write!(f, "there is no workspace yet (make one first)"),
            Refusal::NameOne => write!(f, "there is more than one workspace (name one)"),
            Refusal::Unknown(name) => write!(f, "there is no workspace named {name}"),
            Refusal::Unreadable => write!(f, "that can't be opened (wrong key, or it was changed)"),
            Refusal::Declined => write!(f, "that was not approved"),
            Refusal::Tampered => write!(f, "this workspace's files were changed by something other than halti"),
            Refusal::ShortPassphrase => write!(f, "a passphrase has at least {} characters", Passphrase::MIN_CHARS),
            Refusal::Taken(name) => write!(f, "there is already a workspace named {name}"),
            Refusal::NotAdmitted { adapter, grade } => write!(f, "a release build does not run workspaces on {adapter} ({})", grade.name()),
            Refusal::Downgraded(lacks) => {
                let names: Vec<&str> = lacks.iter().map(Property::name).collect();
                write!(f, "this machine lacks what this workspace was made with: {}", names.join(", "))
            }
            Refusal::OtherBuild(build) => write!(f, "this workspace was made by a {} build", build.name()),
        }
    }
}

impl std::error::Error for Refusal {}
