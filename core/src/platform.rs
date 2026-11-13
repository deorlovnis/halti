//! What an adapter says about itself. Core is handed its files, keystore and the rest as traits,
//! and each implementation carries a label: how far it falls short of the full design, and which
//! protections it lacks. The names here are written into a workspace's own records, so they are
//! fixed: a workspace made on a weaker machine says so for good.
//!
//! Deciding what a build admits is `admit`, over both systems' lists, which are data here so each
//! is tested on either system. Working a grade out from what a machine was probed to lack comes
//! with the first adapters that need it.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::refusal::Refusal;

/// How far an adapter falls short of the full design. Ordered: Dev < Weaker < Production.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Grade {
    Dev,
    Weaker,
    Production,
}

impl Grade {
    /// The byte that names it in a manifest: 0x01 dev, 0x02 weaker, 0x03 production.
    pub const fn tag(self) -> u8 {
        match self {
            Grade::Dev => 0x01,
            Grade::Weaker => 0x02,
            Grade::Production => 0x03,
        }
    }

    /// Refuses a byte that names no grade.
    pub fn from_tag(tag: u8) -> Result<Grade, Refusal> {
        match tag {
            0x01 => Ok(Grade::Dev),
            0x02 => Ok(Grade::Weaker),
            0x03 => Ok(Grade::Production),
            _ => Err(Refusal::Unreadable),
        }
    }

    /// The name shown in labels and refusals: the string serde writes.
    pub const fn name(self) -> &'static str {
        match self {
            Grade::Dev => "dev",
            Grade::Weaker => "weaker",
            Grade::Production => "production",
        }
    }
}

/// The system a binary runs on. The binary says which; core never works it out for itself.
/// Written into a workspace's manifest as its origin, so the tags are fixed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Os {
    Macos,
    Linux,
}

impl Os {
    /// The byte that names it in a manifest: 0x01 macOS, 0x02 Linux.
    pub const fn tag(self) -> u8 {
        match self {
            Os::Macos => 0x01,
            Os::Linux => 0x02,
        }
    }

    /// Refuses a byte that names no system.
    pub fn from_tag(tag: u8) -> Result<Os, Refusal> {
        match tag {
            0x01 => Ok(Os::Macos),
            0x02 => Ok(Os::Linux),
            _ => Err(Refusal::Unreadable),
        }
    }
}

/// The part an adapter plays in a workspace. Written into its manifest, so the tags are fixed:
/// 0x01 to 0x04 in this order; 0x05 to 0x07 are kept for the door, the store and the box engine.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Role {
    KeyHolder,
    Anchor,
    Files,
    Keystore,
}

impl Role {
    /// The byte that names it in a manifest.
    pub const fn tag(self) -> u8 {
        match self {
            Role::KeyHolder => 0x01,
            Role::Anchor => 0x02,
            Role::Files => 0x03,
            Role::Keystore => 0x04,
        }
    }

    /// Refuses a byte that names no role this build knows.
    pub fn from_tag(tag: u8) -> Result<Role, Refusal> {
        match tag {
            0x01 => Ok(Role::KeyHolder),
            0x02 => Ok(Role::Anchor),
            0x03 => Ok(Role::Files),
            0x04 => Ok(Role::Keystore),
            _ => Err(Refusal::Unreadable),
        }
    }
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

/// The set of properties an adapter lacks. Written as a list of names in declaration order, or in
/// a manifest as bits (`bits`).
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

    /// What this set lacks that `recorded` did not: empty exactly when `within` holds.
    pub const fn beyond(self, recorded: Lacks) -> Lacks {
        Lacks(self.0 & !recorded.0)
    }

    /// The set as bits, bit i for `Property::ALL[i]`: how a manifest writes it.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Refuses a bit that names no property this build knows.
    pub fn from_bits(bits: u32) -> Result<Lacks, Refusal> {
        if !Lacks(bits).within(Lacks::of(&Property::ALL)) {
            return Err(Refusal::Unreadable);
        }
        Ok(Lacks(bits))
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

impl Build {
    /// The byte that names it in a manifest: 0x01 dev, 0x02 release.
    pub const fn tag(self) -> u8 {
        match self {
            Build::Dev => 0x01,
            Build::Release => 0x02,
        }
    }

    /// Refuses a byte that names no kind of build.
    pub fn from_tag(tag: u8) -> Result<Build, Refusal> {
        match tag {
            0x01 => Ok(Build::Dev),
            0x02 => Ok(Build::Release),
            _ => Err(Refusal::Unreadable),
        }
    }

    /// "dev" or "release": the string serde writes.
    pub const fn name(self) -> &'static str {
        match self {
            Build::Dev => "dev",
            Build::Release => "release",
        }
    }
}

/// The Weaker adapters a release build admits on `os`. A release build admits every Production
/// adapter and never a Dev one; a debug build admits all three. Only a Mac has a keychain to keep a
/// copy of a passphrase in (`keychain-passphrase-key`).
pub const fn release_accepts(os: Os) -> &'static [&'static str] {
    match os {
        Os::Macos => &["passphrase-key", "keychain-passphrase-key", "file-anchor", "dir-files", "file-keystore"],
        Os::Linux => &["passphrase-key", "file-anchor", "dir-files", "file-keystore"],
    }
}

/// Whether this build may run a workspace on these adapters, judged by each label's name and
/// grade. Called before any file is read or a key holder asked; the first adapter refused is named.
pub fn admit(labels: &[Label], build: Build, os: Os) -> Result<(), Refusal> {
    for label in labels {
        let refused = match (build, label.grade) {
            (Build::Dev, _) | (Build::Release, Grade::Production) => false,
            (Build::Release, Grade::Dev) => true,
            (Build::Release, Grade::Weaker) => !release_accepts(os).contains(&label.adapter),
        };
        if refused {
            return Err(Refusal::NotAdmitted { adapter: label.adapter, grade: label.grade });
        }
    }
    Ok(())
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
        // What is beyond the recorded set is exactly what is not within it.
        assert_eq!(recorded.with(Property::NetApart).beyond(recorded), Lacks::of(&[Property::NetApart]));
        assert!(recorded.beyond(recorded).is_empty() && Lacks::NONE.beyond(recorded).is_empty());
        assert_eq!(recorded.beyond(Lacks::of(&[Property::VmBoundary])), Lacks::of(&[Property::KeyInHardware]));
    }

    #[test]
    fn lacks_read_back_from_their_bits_and_an_unknown_bit_is_refused() {
        // Bit i is `Property::ALL[i]`, which `the_property_names_are_unchanged` fixes: a bit is as stable as a name.
        for (i, p) in Property::ALL.into_iter().enumerate() {
            assert_eq!(Lacks::of(&[p]).bits(), 1 << i, "{}", p.name());
            assert_eq!(Lacks::from_bits(1 << i), Ok(Lacks::of(&[p])), "{}", p.name());
        }
        assert_eq!(Lacks::of(&Property::ALL).bits(), 0x1fff);
        assert_eq!(Lacks::from_bits(0x1fff), Ok(Lacks::of(&Property::ALL)));
        assert_eq!(Lacks::from_bits(0x07), Ok(Lacks::of(&[Property::KeyInHardware, Property::PresenceProof, Property::TrustedPrompt])));
        assert_eq!(Lacks::from_bits(0), Ok(Lacks::NONE));
        // A bit past the last property names nothing this build knows.
        for bits in [1 << 13, 0x3fff, 1 << 31, u32::MAX] {
            assert_eq!(Lacks::from_bits(bits), Err(Refusal::Unreadable), "{bits:#x}");
        }
    }

    /// Byte for byte: these go into a workspace's manifest, so an edit orphans every manifest written.
    #[test]
    fn the_tags_of_build_system_grade_and_role_are_fixed() {
        assert_eq!([Build::Dev, Build::Release].map(Build::tag), [0x01, 0x02]);
        assert_eq!([Os::Macos, Os::Linux].map(Os::tag), [0x01, 0x02]);
        assert_eq!([Grade::Dev, Grade::Weaker, Grade::Production].map(Grade::tag), [0x01, 0x02, 0x03]);
        assert_eq!([Role::KeyHolder, Role::Anchor, Role::Files, Role::Keystore].map(Role::tag), [0x01, 0x02, 0x03, 0x04]);
        for tag in 0..=255 {
            let build = match tag {
                0x01 => Ok(Build::Dev),
                0x02 => Ok(Build::Release),
                _ => Err(Refusal::Unreadable),
            };
            let os = match tag {
                0x01 => Ok(Os::Macos),
                0x02 => Ok(Os::Linux),
                _ => Err(Refusal::Unreadable),
            };
            let grade = match tag {
                0x01 => Ok(Grade::Dev),
                0x02 => Ok(Grade::Weaker),
                0x03 => Ok(Grade::Production),
                _ => Err(Refusal::Unreadable),
            };
            // 0x05 to 0x07 are kept for roles to come, and refused until then.
            let role = match tag {
                0x01 => Ok(Role::KeyHolder),
                0x02 => Ok(Role::Anchor),
                0x03 => Ok(Role::Files),
                0x04 => Ok(Role::Keystore),
                _ => Err(Refusal::Unreadable),
            };
            assert_eq!((Build::from_tag(tag), Os::from_tag(tag), Grade::from_tag(tag), Role::from_tag(tag)), (build, os, grade, role), "tag {tag}");
        }
        // The names are the strings serde writes.
        assert_eq!([Build::Dev, Build::Release].map(Build::name), ["dev", "release"]);
        assert_eq!([Grade::Dev, Grade::Weaker, Grade::Production].map(Grade::name), ["dev", "weaker", "production"]);
        for build in [Build::Dev, Build::Release] {
            assert_eq!(serde_json::to_string(&build).unwrap(), format!("\"{}\"", build.name()));
        }
        for grade in [Grade::Dev, Grade::Weaker, Grade::Production] {
            assert_eq!(serde_json::to_string(&grade).unwrap(), format!("\"{}\"", grade.name()));
        }
        // Roles are ordered as their tags are, which is the order a manifest lists them in.
        assert!(Role::KeyHolder < Role::Anchor && Role::Anchor < Role::Files && Role::Files < Role::Keystore);
    }

    /// An adapter of this name and grade, lacking nothing.
    fn labelled(adapter: &'static str, grade: Grade) -> Label {
        Label { adapter, grade, lacks: Lacks::NONE, why: "for the test" }
    }

    #[test]
    fn a_debug_build_admits_every_grade_on_either_system() {
        let labels = [labelled("soft-key", Grade::Dev), labelled("process-door", Grade::Weaker), labelled("passphrase-key", Grade::Dev), labelled("made-up", Grade::Production)];
        for os in [Os::Macos, Os::Linux] {
            assert_eq!(admit(&labels, Build::Dev, os), Ok(()), "{os:?}");
            assert_eq!(admit(&[], Build::Dev, os), Ok(()), "{os:?}");
        }
    }

    #[test]
    fn a_release_build_admits_production_and_listed_weaker_adapters_and_never_dev() {
        for os in [Os::Macos, Os::Linux] {
            assert_eq!(admit(&[labelled("made-up", Grade::Production)], Build::Release, os), Ok(()), "{os:?}");
            let listed: Vec<Label> = release_accepts(os).iter().map(|&adapter| labelled(adapter, Grade::Weaker)).collect();
            assert_eq!(admit(&listed, Build::Release, os), Ok(()), "{os:?}");
            // A listed name labelled dev is refused all the same.
            assert_eq!(admit(&[labelled("passphrase-key", Grade::Dev)], Build::Release, os), Err(Refusal::NotAdmitted { adapter: "passphrase-key", grade: Grade::Dev }));
            let refusal = admit(&[labelled("process-door", Grade::Weaker)], Build::Release, os).unwrap_err();
            assert_eq!(refusal, Refusal::NotAdmitted { adapter: "process-door", grade: Grade::Weaker }, "{os:?}");
            assert_eq!(refusal.to_string(), "a release build does not run workspaces on process-door (weaker)");
            // The first adapter refused is the one named.
            let mixed = [labelled("passphrase-key", Grade::Weaker), labelled("mem-files", Grade::Dev), labelled("process-door", Grade::Weaker)];
            assert_eq!(admit(&mixed, Build::Release, os), Err(Refusal::NotAdmitted { adapter: "mem-files", grade: Grade::Dev }), "{os:?}");
        }
    }

    /// Byte for byte: a release build's labels must use these names, and a workspace records them.
    #[test]
    fn the_release_lists_are_unchanged() {
        assert_eq!(release_accepts(Os::Macos), ["passphrase-key", "keychain-passphrase-key", "file-anchor", "dir-files", "file-keystore"]);
        assert_eq!(release_accepts(Os::Linux), ["passphrase-key", "file-anchor", "dir-files", "file-keystore"]);
    }

    /// A passphrase key with a copy kept in the keychain runs in a release build on a Mac, and nowhere else.
    #[test]
    fn a_release_build_runs_a_keychain_copy_of_a_passphrase_only_on_a_mac() {
        let keychain = labelled("keychain-passphrase-key", Grade::Weaker);
        assert_eq!(admit(&[keychain], Build::Release, Os::Macos), Ok(()));
        let refused = Refusal::NotAdmitted { adapter: "keychain-passphrase-key", grade: Grade::Weaker };
        assert_eq!(admit(&[keychain], Build::Release, Os::Linux), Err(refused));
        assert_eq!(admit(&[keychain], Build::Dev, Os::Linux), Ok(()), "a debug build admits every adapter");
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
