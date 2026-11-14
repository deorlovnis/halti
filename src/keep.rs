//! Why a box was not started: the kind of refusal, and the reason in full.
//!
//! A start is checked in steps: the box's files, its approval and key, its sites, the engine. Each
//! refusal says which kind it is beside the text halti prints, so a caller that must not pass the
//! text on (it can be built from many layers, and name a path) can answer with the kind alone.

/// The kind of a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum No {
    /// There is no such box.
    Box,
    /// Its policy isn't approved.
    Unapproved,
    /// Its policy changed since it was approved.
    Changed,
    /// It keeps a store, and has none.
    Store,
    /// It has a store, and no key.
    Key,
    /// A site it uses isn't ready: the site's name.
    Site(String),
    /// The box engine isn't there, or isn't running.
    Engine,
    /// Anything else.
    Failed,
}

/// A start that was refused: its kind, and the reason as halti says it.
pub struct Refused {
    pub no: No,
    pub why: anyhow::Error,
}

impl Refused {
    pub fn new(no: No, why: anyhow::Error) -> Self {
        Refused { no, why }
    }
}

/// A failure of no kind of its own.
impl From<anyhow::Error> for Refused {
    fn from(why: anyhow::Error) -> Self {
        Refused { no: No::Failed, why }
    }
}

impl std::fmt::Debug for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {:#}", self.no, self.why)
    }
}
