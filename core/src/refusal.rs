//! The reasons core itself says no, as values a caller can tell apart. What an adapter fails with
//! (a disk, a keystore) stays a plain `anyhow` error; a caller finds one of these in it with
//! `downcast_ref::<Refusal>()`.

use std::fmt;

use crate::ids::WsName;
use crate::item::Secret;
use crate::passphrase::Passphrase;
use crate::platform::{Build, Grade, Lacks, Property};
use crate::policy::Approval;

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
    /// The text isn't a secret's resource and field. Neither is echoed.
    BadSecretName,
    /// The value isn't one a secret can hold (`item::Secret`). It is never echoed.
    BadSecret,
    /// The workspace holds no secret of that name, or none of that resource. `what` is an
    /// `item::ItemKey`'s text or a checked resource, so it holds only what was typed and checked.
    NoSecret { ws: WsName, what: String },
    /// A policy can't be approved as given: its name isn't a resource's, its text is empty or too
    /// long, it is given twice, or none is given. Neither is echoed.
    BadPolicy,
    /// A policy was shown against a copy of what was approved, or as new, and the workspace says
    /// otherwise, so nothing was approved. `name` is a checked resource.
    NotTheBase { name: String },
    /// The workspace already has a box of that name. `name` is a checked box name.
    BoxExists { ws: WsName, name: String },
    /// The text isn't a box's name. It is never echoed.
    BadBox,
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
            Refusal::BadSecretName => write!(f, "that isn't a secret's name (a resource of a-z, 0-9 and -, then a field of a-z, 0-9 and _)"),
            Refusal::BadSecret => write!(f, "that value can't be stored: a secret is text of up to {} bytes", Secret::MAX),
            Refusal::NoSecret { ws, what } => write!(f, "there is no {what} in {ws}"),
            Refusal::BadPolicy => write!(f, "that policy can't be approved: a policy is 1 to {} bytes, for a resource of a-z, 0-9 and -", Approval::MAX_TEXT),
            Refusal::NotTheBase { name } => write!(f, "the approved copy of {name} isn't what was approved, so nothing was approved"),
            Refusal::BoxExists { ws, name } => write!(f, "box {ws}/{name} exists already"),
            Refusal::BadBox => write!(f, "that isn't a box: 1 to 32 of a-z, 0-9 and -"),
        }
    }
}

impl std::error::Error for Refusal {}
