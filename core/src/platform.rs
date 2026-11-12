//! What an adapter says about itself. Core is handed its files, keystore and the rest as traits,
//! and each implementation carries a label: how far it falls short of the full design, and which
//! protections it lacks. The names here are written into a workspace's own records, so they are
//! fixed: a workspace made on a weaker machine says so for good.
//!
//! This is the data only. Deciding what a build admits, and working a grade out from what a
//! machine was probed to lack, comes with the first adapters that need it.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// How far an adapter falls short of the full design. Ordered: Dev < Weaker < Production.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Grade {
    Dev,
    Weaker,
    Production,
}

/// What the full design keeps and an adapter may lack. An adapter lists what it lacks.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Property {
    KeyInHardware,
    PresenceProof,
    TrustedPrompt,
    EncryptedAtRest,
    DeleteKillsCopies,
    OthersCantTouch,
    RollbackProof,
    VmBoundary,
    NetApart,
    PrivateProc,
    ResourceLimits,
    GuestRootApart,
    InstallProtected,
}

impl Property {
    /// Every property, in the order they are declared and written.
    pub const ALL: [Property; 13] = [
        Property::KeyInHardware,
        Property::PresenceProof,
        Property::TrustedPrompt,
        Property::EncryptedAtRest,
        Property::DeleteKillsCopies,
        Property::OthersCantTouch,
        Property::RollbackProof,
        Property::VmBoundary,
        Property::NetApart,
        Property::PrivateProc,
        Property::ResourceLimits,
        Property::GuestRootApart,
        Property::InstallProtected,
    ];

    /// The name written in a workspace's records and shown in labels: the string serde writes.
    pub const fn name(self) -> &'static str {
        match self {
            Property::KeyInHardware => "key-in-hardware",
            Property::PresenceProof => "presence-proof",
            Property::TrustedPrompt => "trusted-prompt",
            Property::EncryptedAtRest => "encrypted-at-rest",
            Property::DeleteKillsCopies => "delete-kills-copies",
            Property::OthersCantTouch => "others-cant-touch",
            Property::RollbackProof => "rollback-proof",
            Property::VmBoundary => "vm-boundary",
            Property::NetApart => "net-apart",
            Property::PrivateProc => "private-proc",
            Property::ResourceLimits => "resource-limits",
            Property::GuestRootApart => "guest-root-apart",
            Property::InstallProtected => "install-protected",
        }
    }
}

/// The set of properties an adapter lacks. Written as a list of names, in declaration order.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Lacks(u32);

impl Lacks {
    /// Lacks nothing.
    pub const NONE: Lacks = Lacks(0);

    pub const fn of(props: &[Property]) -> Lacks {
        let mut set = Lacks::NONE;
        let mut i = 0;
        while i < props.len() {
            set = set.with(props[i]);
            i += 1;
        }
        set
    }

    /// This set and one more property: what a probe adds when it finds a protection missing.
    pub const fn with(self, p: Property) -> Lacks {
        Lacks(self.0 | (1 << (p as u32)))
    }

    pub const fn contains(self, p: Property) -> bool {
        self.0 & (1 << (p as u32)) != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether nothing is lacking here that `recorded` didn't lack already. A workspace opened
    /// where more is lacking than when it was made has been moved somewhere weaker.
    pub const fn within(self, recorded: Lacks) -> bool {
        self.0 & !recorded.0 == 0
    }

    /// The lacking properties, in declaration order.
    pub fn iter(self) -> impl Iterator<Item = Property> {
        Property::ALL.into_iter().filter(move |p| self.contains(*p))
    }
}

impl fmt::Debug for Lacks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter().map(Property::name)).finish()
    }
}

impl Serialize for Lacks {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.iter())
    }
}

/// A name that isn't a property is an error: a record that claims to lack something this build
/// doesn't know can't be compared. A repeated name changes nothing.
impl<'de> Deserialize<'de> for Lacks {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Lacks, D::Error> {
        Ok(Lacks::of(&Vec::<Property>::deserialize(d)?))
    }
}

/// What one adapter says about itself.
#[derive(Clone, Copy, Debug)]
pub struct Label {
    pub adapter: &'static str,
    pub grade: Grade,
    pub lacks: Lacks,
    pub why: &'static str,
}

/// Anything core is handed says what it is.
pub trait Adapter {
    fn label(&self) -> Label;
}

/// How this binary was built. The binary sets it; core never works it out for itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Build {
    Dev,
    Release,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_is_below_weaker_is_below_production() {
        assert!(Grade::Dev < Grade::Weaker && Grade::Weaker < Grade::Production);
    }

    #[test]
    fn a_probe_can_add_a_lack() {
        let before = Lacks::of(&[Property::VmBoundary]);
        let after = before.with(Property::PrivateProc);
        assert!(!before.contains(Property::PrivateProc) && after.contains(Property::PrivateProc) && after.contains(Property::VmBoundary));
        assert_eq!(after.with(Property::PrivateProc), after);
        assert!(Lacks::NONE.is_empty() && !after.is_empty() && Lacks::default() == Lacks::NONE);
    }

    #[test]
    fn a_set_with_more_lacks_is_not_within_the_recorded_one() {
        let recorded = Lacks::of(&[Property::VmBoundary, Property::KeyInHardware]);
        assert!(recorded.within(recorded) && Lacks::NONE.within(recorded) && Lacks::of(&[Property::VmBoundary]).within(recorded));
        assert!(!recorded.with(Property::NetApart).within(recorded));
        assert!(!Lacks::of(&[Property::NetApart]).within(recorded), "lacking something else, however little, is not within");
        assert!(!recorded.within(Lacks::NONE));
    }

    #[test]
    fn lacks_are_written_by_name_in_a_fixed_order() {
        let set = Lacks::of(&[Property::NetApart, Property::KeyInHardware, Property::NetApart]);
        let text = serde_json::to_string(&set).unwrap();
        assert_eq!(text, r#"["key-in-hardware","net-apart"]"#);
        assert_eq!(serde_json::from_str::<Lacks>(&text).unwrap(), set);
        assert_eq!(serde_json::from_str::<Lacks>(r#"["net-apart","key-in-hardware","net-apart"]"#).unwrap(), set);
        assert_eq!(format!("{set:?}"), r#"["key-in-hardware", "net-apart"]"#);
        assert_eq!(serde_json::to_string(&Lacks::NONE).unwrap(), "[]");
    }

    #[test]
    fn an_unknown_lacks_name_is_refused() {
        assert!(serde_json::from_str::<Lacks>(r#"["net-apart","made-up"]"#).is_err());
        assert!(serde_json::from_str::<Lacks>(r#"["NetApart"]"#).is_err());
    }

    /// Byte for byte: these go into a workspace's records, so an edit orphans every record written.
    #[test]
    fn the_property_names_are_unchanged() {
        let names: Vec<&str> = Property::ALL.iter().map(|p| p.name()).collect();
        let expected = [
            "key-in-hardware",
            "presence-proof",
            "trusted-prompt",
            "encrypted-at-rest",
            "delete-kills-copies",
            "others-cant-touch",
            "rollback-proof",
            "vm-boundary",
            "net-apart",
            "private-proc",
            "resource-limits",
            "guest-root-apart",
            "install-protected",
        ];
        assert_eq!(names, expected);
        assert_eq!(Lacks::of(&Property::ALL).iter().count(), Property::ALL.len());
    }

    #[test]
    fn serde_and_name_agree_for_every_property() {
        for p in Property::ALL {
            assert_eq!(serde_json::to_string(&p).unwrap(), format!("\"{}\"", p.name()));
            assert_eq!(serde_json::from_str::<Property>(&format!("\"{}\"", p.name())).unwrap(), p);
        }
    }

    #[test]
    fn build_and_grade_are_written_in_lowercase() {
        assert_eq!(serde_json::to_string(&[Build::Dev, Build::Release]).unwrap(), r#"["dev","release"]"#);
        assert_eq!(serde_json::to_string(&[Grade::Dev, Grade::Weaker, Grade::Production]).unwrap(), r#"["dev","weaker","production"]"#);
    }
}
