//! What a workspace has approved: for each policy, whose it is and the SHA-256 of its text. Kept
//! in the sealed manifest, so only an approved unlock writes one.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::ids::write_hex;
use crate::item::ItemKey;
use crate::refusal::Refusal;

/// Whose policy an approval is. Its tag is written into manifests, so it is fixed. A kind added
/// later gets a tag of its own, and every `match` on it must then answer it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Kind {
    /// A resource's policy: which hosts and tools its secrets may be used with.
    Resource,
}

impl Kind {
    /// The byte that names it in a manifest.
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Kind::Resource => 0x01,
        }
    }

    /// Refuses a byte that names no kind this build knows.
    pub(crate) fn from_tag(tag: u8) -> Result<Kind, Refusal> {
        match tag {
            0x01 => Ok(Kind::Resource),
            _ => Err(Refusal::Unreadable),
        }
    }
}

/// One approved policy: its kind, its name, and the SHA-256 of the text approved. Ordered by kind,
/// then name. It can't be made with a name that isn't one.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Approval {
    kind: Kind,
    name: String,
    sha256: [u8; 32],
}

impl Approval {
    /// The longest policy text: 64 KiB.
    pub const MAX_TEXT: usize = 65536;

    /// The approval of `text` as `name`'s policy. The name is a resource's (`ItemKey::check_resource`:
    /// 1 to 32 of a-z, 0-9 and `-`, starting with a letter or digit), and the text 1 to `MAX_TEXT`
    /// bytes. Anything else is `Refusal::BadPolicy`.
    pub fn of(kind: Kind, name: &str, text: &[u8]) -> Result<Approval, Refusal> {
        if text.is_empty() || text.len() > Approval::MAX_TEXT {
            return Err(Refusal::BadPolicy);
        }
        Approval::sealed(kind, name, sha256(text)).map_err(|_| Refusal::BadPolicy)
    }

    /// An approval as a manifest holds it: the hash, not the text. The name is checked as in `of`,
    /// and refused as `Refusal::BadSecretName`.
    pub(crate) fn sealed(kind: Kind, name: &str, sha256: [u8; 32]) -> Result<Approval, Refusal> {
        ItemKey::check_resource(name)?;
        Ok(Approval { kind, name: name.to_string(), sha256 })
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Whether `text` is exactly what was approved.
    pub fn approves(&self, text: &[u8]) -> bool {
        sha256(text) == self.sha256
    }

    /// Whether it is the approval of this kind and name.
    pub(crate) fn is(&self, kind: Kind, name: &str) -> bool {
        self.kind == kind && self.name == name
    }
}

/// Its name and the first 12 hex characters of its hash, as halti shows a policy's hash.
impl fmt::Debug for Approval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Approval({}, ", self.name)?;
        write_hex(f, &self.sha256[..6])?;
        f.write_str(")")
    }
}

/// What the person was shown a text against, so that what they were told about it is checked once
/// the workspace is open.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Base<'a> {
    /// The whole text was shown: nothing to check.
    Shown,
    /// It was shown as new: it has no approval.
    New,
    /// It was shown against these bytes, as what was approved: they are.
    Copy(&'a [u8]),
}

/// One text to approve as a policy, and what it was shown against.
#[derive(Clone, Copy, Debug)]
pub struct Proposal<'a> {
    pub kind: Kind,
    pub name: &'a str,
    pub text: &'a [u8],
    pub base: Base<'a>,
}

impl Proposal<'_> {
    /// Whether what it was shown against is what `list` holds for it.
    pub(crate) fn base_holds(&self, list: &[Approval]) -> bool {
        let approved = list.iter().find(|approval| approval.is(self.kind, self.name));
        match self.base {
            Base::Shown => true,
            Base::New => approved.is_none(),
            Base::Copy(copy) => approved.is_some_and(|approval| approval.approves(copy)),
        }
    }
}

/// One change to a list of approvals.
pub(crate) enum Edit<'a> {
    /// This becomes the approval of its kind and name, replacing any.
    Set(Approval),
    /// The approval of this kind and name, if there is one, goes.
    Drop(Kind, &'a str),
}

/// `list` with `edits` made in turn. It stays in order, with at most one approval per kind and
/// name, if it was so before.
pub(crate) fn apply<'a>(list: &[Approval], edits: impl IntoIterator<Item = Edit<'a>>) -> Vec<Approval> {
    let mut list = list.to_vec();
    for edit in edits {
        let at = match &edit {
            Edit::Set(approval) => list.binary_search_by(|listed| (listed.kind, listed.name.as_str()).cmp(&(approval.kind, approval.name.as_str()))),
            &Edit::Drop(kind, name) => list.binary_search_by(|listed| (listed.kind, listed.name.as_str()).cmp(&(kind, name))),
        };
        match (edit, at) {
            (Edit::Set(approval), Ok(at)) => list[at] = approval,
            (Edit::Set(approval), Err(at)) => list.insert(at, approval),
            (Edit::Drop(..), Ok(at)) => {
                list.remove(at);
            }
            (Edit::Drop(..), Err(_)) => {}
        }
    }
    list
}

fn sha256(text: &[u8]) -> [u8; 32] {
    Sha256::digest(text).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vectors::{KAT_POLICY_SHA256, POLICY_TEXT, hex};

    fn resource(name: &str, text: &[u8]) -> Approval {
        Approval::of(Kind::Resource, name, text).unwrap()
    }

    #[test]
    fn an_approval_is_a_resource_and_the_sha256_of_its_text() {
        let approval = resource("github", POLICY_TEXT.as_bytes());
        assert_eq!((approval.kind(), approval.name()), (Kind::Resource, "github"));
        assert_eq!(approval.sha256().as_slice(), hex(KAT_POLICY_SHA256));
        assert!(approval.approves(POLICY_TEXT.as_bytes()));
        // One byte changed, one more or one less, is another text.
        let mut changed = POLICY_TEXT.as_bytes().to_vec();
        changed[10] ^= 0x01;
        assert!(!approval.approves(&changed));
        assert!(!approval.approves(format!("{POLICY_TEXT}\n").as_bytes()));
        assert!(!approval.approves(&POLICY_TEXT.as_bytes()[1..]));

        let longest = "a".repeat(32);
        for name in ["a", "0", "github", "github-ee", longest.as_str()] {
            assert_eq!(Approval::of(Kind::Resource, name, b"x").map(|approval| approval.name().to_string()), Ok(name.to_string()));
        }
        let too_long = "a".repeat(33);
        for name in ["", "Git", "-x", "a/b", "git hub", "gitλ", too_long.as_str()] {
            assert_eq!(Approval::of(Kind::Resource, name, b"x"), Err(Refusal::BadPolicy), "{name:?}");
        }
        assert_eq!(Approval::of(Kind::Resource, "github", b""), Err(Refusal::BadPolicy), "an empty text");
        assert_eq!(Approval::of(Kind::Resource, "github", &vec![b'x'; Approval::MAX_TEXT + 1]), Err(Refusal::BadPolicy), "65537 bytes");
        assert!(Approval::of(Kind::Resource, "github", &vec![b'x'; Approval::MAX_TEXT]).is_ok(), "65536 bytes");

        // Printed with its name and the first 12 hex characters of its hash, never the whole hash.
        assert_eq!(format!("{approval:?}"), "Approval(github, 80982e4c451a)");
        assert!(!format!("{approval:#?}").contains(&KAT_POLICY_SHA256[..13]));
    }

    #[test]
    fn a_kind_is_written_as_its_fixed_tag() {
        assert_eq!(Kind::Resource.tag(), 0x01);
        for tag in 0..=255 {
            let known = if tag == 0x01 { Ok(Kind::Resource) } else { Err(Refusal::Unreadable) };
            assert_eq!(Kind::from_tag(tag), known, "tag {tag}");
        }
    }

    #[test]
    fn approvals_are_set_and_dropped_in_order() {
        let (a, b, c) = (resource("a", b"1"), resource("b", b"1"), resource("c", b"1"));
        let set = |approval: &Approval| Edit::Set(approval.clone());
        assert_eq!(apply(&[], [set(&c), set(&a), set(&b)]), [a.clone(), b.clone(), c.clone()]);
        // Set again: it replaces the one of its name.
        let b2 = resource("b", b"2");
        assert_eq!(apply(&[a.clone(), b.clone(), c.clone()], [set(&b2)]), [a.clone(), b2.clone(), c.clone()]);
        // Dropped, and dropping one that isn't there.
        assert_eq!(apply(&[a.clone(), b.clone(), c.clone()], [Edit::Drop(Kind::Resource, "b"), Edit::Drop(Kind::Resource, "z")]), [a.clone(), c.clone()]);
        assert_eq!(apply(&[], [Edit::Drop(Kind::Resource, "b")]), []);
        // In turn: set, then dropped.
        assert_eq!(apply(&[], [set(&a), set(&b), Edit::Drop(Kind::Resource, "b")]), [a]);
    }

    #[test]
    fn a_base_holds_only_for_what_was_approved() {
        let list = [resource("github", POLICY_TEXT.as_bytes())];
        let base = |name: &'static str, base: Base<'static>| Proposal { kind: Kind::Resource, name, text: b"anything", base }.base_holds(&list);
        assert!(base("github", Base::Shown) && base("linear", Base::Shown), "the whole text was shown: nothing is checked");
        assert!(base("linear", Base::New) && !base("github", Base::New));
        assert!(base("github", Base::Copy(POLICY_TEXT.as_bytes())));
        assert!(!base("github", Base::Copy(b"[fetch]\n")), "another copy");
        assert!(!base("linear", Base::Copy(POLICY_TEXT.as_bytes())), "a copy of what has no approval");
    }
}
