//! A workspace's policies: what each of its resources' secrets may be used for. `ws policy edit`
//! writes one in the workspace's folder (`files::PolicyFiles`), `ws policy approve` approves it, and
//! `ws policy show` says whether it is approved. Nothing uses them yet.
//!
//! An approval is the SHA-256 of a policy's text, sealed in the workspace's manifest by core
//! (`halti_core::verbs::ws_approve`): only the workspace's passphrase writes one, asked as
//! `[workspace.approval] policy` says, which is never `none`. Whether a policy is approved is that
//! hash against the file's bytes, read now; nothing else decides it.
//!
//! What is shown before the approval is what is sealed: each file is read once, checked, and those
//! bytes are shown and sent to core. Approving every policy of a workspace shows each against the
//! copy kept at its last approval (new, changed with a diff, or unchanged), and core checks that
//! the copy is what was approved, so a policy a program planted or changed can't be swept in with
//! the others. Approving one shows its whole text.
//!
//! A policy in a workspace isn't empty, is plain ASCII outside lines that are only a comment, can't
//! refresh yet, and keeps `[run]` and `[agent]` as an empty policy has them (`policy::in_workspace`). Of the binary's policy module only what reaches
//! no source is used here: the workspace's place comes later.

use std::io::{self, IsTerminal};

use anyhow::{Context, Result, anyhow, bail};
use halti_core::ids::WsName;
use halti_core::policy::{Approval, Base, Kind, Proposal};
use halti_core::refusal::Refusal;
use halti_core::verbs::{Machine, Was, ws_approvals, ws_approve};

use super::files::PolicyFiles;
use super::tty::TtyPassphrase;
use super::{Here, Said, Way, approved, declined, memory, random, saved, saved_means, target};
use crate::approval::{Action, Real};
use crate::config;
use crate::policy;
use crate::util::sha256_hex;

/// How many policies the Touch ID window or sudo names before it says how many more.
const NAMED: usize = 3;

/// `acme` or `acme/github`: a workspace, and maybe one of its resources.
fn which(text: &str) -> Result<(WsName, Option<&str>)> {
    if text.contains('/') {
        let (name, resource) = target(text)?;
        return Ok((name, Some(resource)));
    }
    Ok((WsName::parse(text)?, None))
}

/// `halti ws policy edit WS/RESOURCE`: opens the policy in the editor, from the template if there
/// is no file. Asks nothing; on a terminal it offers to approve what was saved.
pub fn edit(target_text: &str) -> Result<()> {
    let (name, resource) = target(target_text)?;
    let settings = config::settings();
    let here = Here::at(&settings.workspaces.path);
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsPolicy, false), detail: None };
    let approve_now = |bytes: Vec<u8>, copy: Option<Vec<u8>>| {
        memory::harden();
        approve_edited(&here, &name, resource, bytes, copy, &way)?.print();
        Ok(())
    };
    edit_with(&here, &name, resource, &approve_now)
}

/// `halti ws policy approve WS[/RESOURCE] [--type]`: approves one policy, or every policy in the
/// workspace, asked as `[workspace.approval] policy` says.
pub fn approve(target_text: &str, type_it: bool) -> Result<()> {
    let (name, which) = which(target_text)?;
    let settings = config::settings();
    memory::harden();
    let here = Here::at(&settings.workspaces.path);
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsPolicy, type_it), detail: None };
    approve_with(&here, &name, which, &way, &|| TtyPassphrase::new(false))?.print();
    Ok(())
}

/// `halti ws policy show WS[/RESOURCE] [--type]`: a policy and whether it is approved, or every
/// policy of the workspace, asked as opening it is.
pub fn show(target_text: &str, type_it: bool) -> Result<()> {
    let (name, which) = which(target_text)?;
    let settings = config::settings();
    memory::harden();
    let here = Here::at(&settings.workspaces.path);
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsOpen, type_it), detail: None };
    show_with(&here, &name, which, &way, &|| TtyPassphrase::new(false))?.print();
    Ok(())
}

/// The policies of `name`, by the id its record names: there is no workspace without one.
fn policies_of(here: &Here, name: &WsName) -> Result<PolicyFiles> {
    let id = here.id_of(name).ok_or_else(|| Refusal::Unknown(name.clone()))?;
    Ok(here.policies(id))
}

/// Writes the template if `resource` has no policy file, opens the file in the editor, and reads it
/// once when the editor ends: checked, and shown against the approved copy. What was read is what
/// `approve_now` approves, against that copy, if the person says so.
fn edit_with(here: &Here, name: &WsName, resource: &str, approve_now: &dyn Fn(Vec<u8>, Option<Vec<u8>>) -> Result<()>) -> Result<()> {
    let files = policies_of(here, name)?;
    files.create(resource, &policy::WORKSPACE_TEMPLATE.replace("RES", resource).replace("WS", name.as_str()))?;
    // A path there that isn't a plain file, or is too large, is refused before the editor opens it.
    files.read(resource)?;
    let path = files.path(resource);
    // A copy that can't be read, or isn't text, is taken as none: the edit is then approved as new,
    // which core refuses if the policy has an approval.
    let copy = files.approved_copy(resource).ok().flatten().filter(|copy| std::str::from_utf8(copy).is_ok());
    let read = |_: &std::path::Path| files.read(resource)?.ok_or_else(|| no_file(name, resource));
    let check = |text: &str| policy::in_workspace(text.as_bytes(), &policy::Policy::parse(text)?);
    let shown_against = || copy.as_deref().map(|copy| String::from_utf8_lossy(copy).into_owned());
    let Some(bytes) = policy::edit_against(&path, read, shown_against, &format!("{resource} in {name}"), check)? else { return Ok(()) };
    policy::offer_approval(&path, &format!("halti ws policy approve {name}/{resource}"), || approve_now(bytes, copy))
}

fn no_file(name: &WsName, resource: &str) -> anyhow::Error {
    anyhow!("{name} has no policy file for {resource}. write one with: halti ws policy edit {name}/{resource}")
}

/// What a policy was shown against, as core checks it (`Base`).
enum Against {
    /// Its whole text.
    Whole,
    /// Nothing: it was shown as new.
    New,
    /// The copy kept at its last approval.
    Copy(Vec<u8>),
}

/// One policy read, checked and shown, to approve.
struct Prepared {
    resource: String,
    text: Vec<u8>,
    against: Against,
    /// What is printed before the approval is asked for.
    shown: String,
}

impl Prepared {
    fn sha12(&self) -> String {
        sha256_hex(&self.text)[..12].to_string()
    }
}

/// A policy's bytes, read once and checked: none if there is no file. A text that doesn't parse,
/// that is empty, isn't plain ASCII or holds what a workspace's policy can't, is refused with its
/// path.
fn read_checked(files: &PolicyFiles, resource: &str) -> Result<Option<Vec<u8>>> {
    let Some(bytes) = files.read(resource)? else { return Ok(None) };
    let path = files.path(resource);
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{} isn't UTF-8", path.display()))?;
    let parsed = policy::Policy::parse(text).with_context(|| path.display().to_string())?;
    policy::in_workspace(&bytes, &parsed).with_context(|| path.display().to_string())?;
    Ok(Some(bytes))
}

/// `resource`'s policy, read and checked, as one to approve. With `whole`, its whole text is shown,
/// and no word from the approved copy, since core checks that copy only when it is shown against
/// it. Otherwise it is shown against the copy: one that can't be read is taken as none, so the
/// policy is shown as new, which core refuses if it has an approval.
fn prepared(files: &PolicyFiles, name: &WsName, resource: &str, whole: bool) -> Result<Prepared> {
    let text = read_checked(files, resource)?.ok_or_else(|| no_file(name, resource))?;
    let mut prepared = Prepared { resource: resource.to_string(), text, against: Against::Whole, shown: String::new() };
    let sha12 = prepared.sha12();
    let head = format!("Policy for {resource} in {name} ({})", files.path(resource).display());
    let utf8 = |bytes: &[u8]| String::from_utf8_lossy(bytes).trim_end().to_string();
    if whole {
        prepared.shown = format!("{head}:\n\n{}\n\nsha256 {sha12}\n\n", utf8(&prepared.text));
        return Ok(prepared);
    }
    prepared.shown = match files.approved_copy(resource).ok().flatten() {
        None => {
            prepared.against = Against::New;
            format!("{head}, new:\n\n{}\n\nsha256 {sha12}\n\n", utf8(&prepared.text))
        }
        Some(copy) => {
            let shown = if copy == prepared.text {
                format!("{head}, unchanged, sha256 {sha12}\n\n")
            } else {
                let diff = policy::diff_from("approved", &String::from_utf8_lossy(&copy), &String::from_utf8_lossy(&prepared.text), io::stdout().is_terminal());
                format!("{head}, changed:\n{diff}sha256 {sha12}\n\n")
            };
            prepared.against = Against::Copy(copy);
            shown
        }
    };
    Ok(prepared)
}

/// Reads, checks and shows one policy in full, or every policy file of the workspace against its
/// approved copy, then approves them all with one approval.
pub(super) fn approve_with(here: &Here, name: &WsName, which: Option<&str>, way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase) -> Result<Said> {
    let files = policies_of(here, name)?;
    let (all, declined) = match which {
        Some(resource) => {
            let declined = declined(&format!("the policy for {resource} in {name} was not approved"), &format!("ws policy approve {name}/{resource}"));
            (vec![prepared(&files, name, resource, true)?], declined)
        }
        None => {
            let names = files.names()?;
            if names.is_empty() {
                bail!("{name} has no policy files. write one with: halti ws policy edit {name}/RESOURCE");
            }
            let all = names.iter().map(|resource| prepared(&files, name, resource, false)).collect::<Result<Vec<Prepared>>>()?;
            (all, declined(&format!("the policies in {name} were not approved"), &format!("ws policy approve {name}")))
        }
    };
    approve_shown(here, name, &files, &all, way, typing, &declined)
}

/// Approves what `ws policy edit` read: after a diff against the approved copy only its hash is
/// shown, and a policy shown with no diff is shown whole as new, which core checks.
fn approve_edited(here: &Here, name: &WsName, resource: &str, text: Vec<u8>, copy: Option<Vec<u8>>, way: &Way<'_>) -> Result<Said> {
    let files = policies_of(here, name)?;
    let mut edited = Prepared { resource: resource.to_string(), text, against: Against::Whole, shown: String::new() };
    let sha12 = edited.sha12();
    edited.shown = match copy {
        Some(copy) => {
            edited.against = Against::Copy(copy);
            format!("sha256 {sha12}\n\n")
        }
        None => {
            edited.against = Against::New;
            let path = files.path(resource);
            format!("Policy for {resource} in {name} ({}), new:\n\n{}\n\nsha256 {sha12}\n\n", path.display(), String::from_utf8_lossy(&edited.text).trim_end())
        }
    };
    let declined = declined(&format!("the policy for {resource} in {name} was not approved"), &format!("ws policy approve {name}/{resource}"));
    approve_shown(here, name, &files, &[edited], way, &|| TtyPassphrase::new(false), &declined)
}

/// Prints what each policy is shown as, then asks once (`approved`, as `[workspace.approval]
/// policy` says) and has core seal them. Once it has, each approved copy is written with the bytes
/// just approved, where it isn't those already.
fn approve_shown(here: &Here, name: &WsName, files: &PolicyFiles, all: &[Prepared], way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase, declined: &str) -> Result<Said> {
    for prepared in all {
        print!("{}", prepared.shown);
    }
    let proposals: Vec<Proposal<'_>> = all
        .iter()
        .map(|prepared| {
            let base = match &prepared.against {
                Against::Whole => Base::Shown,
                Against::New => Base::New,
                Against::Copy(copy) => Base::Copy(copy),
            };
            Proposal { kind: Kind::Resource, name: &prepared.resource, text: &prepared.text, base }
        })
        .collect();
    let way = Way { world: way.world, copies: way.copies, means: way.means, detail: Some(detail(all)) };
    let approve = |machine: &Machine<'_>| ws_approve(machine, name, &proposals, *random::<12>()?);
    let (was, _) = approved(here, name, &way, Action::WsPolicy, declined, typing, &approve).map_err(|error| not_the_base(error, name))?;
    let mut said = Said::default();
    for (prepared, was) in all.iter().zip(was) {
        let resource = &prepared.resource;
        said.out.push(match was {
            Was::Already => format!("the policy for {resource} in {name} was approved already"),
            Was::New | Was::Replaced => format!("approved the policy for {resource} in {name}"),
        });
        let kept = files.approved_copy(resource).ok().flatten();
        if kept.as_deref() != Some(prepared.text.as_slice()) && files.keep_approved(resource, &prepared.text).is_err() {
            said.notes.push(format!("the approved copy of {resource} couldn't be kept. approve it alone next time: halti ws policy approve {name}/{resource}"));
        }
    }
    Ok(said)
}

/// What the Touch ID window or sudo names: each policy that approving changes, as it was shown (not
/// unchanged), and the start of its hash, the first few of them, then how many more. When none
/// changes, every one is named.
fn detail(all: &[Prepared]) -> String {
    let unchanged = |prepared: &&Prepared| matches!(&prepared.against, Against::Copy(copy) if *copy == prepared.text);
    let changing: Vec<&Prepared> = all.iter().filter(|prepared| !unchanged(prepared)).collect();
    let named_from = if changing.is_empty() { all.iter().collect() } else { changing };
    let named: Vec<String> = named_from.iter().take(NAMED).map(|prepared| format!("{} {}", prepared.resource, prepared.sha12())).collect();
    let more = named_from.len().saturating_sub(NAMED);
    if more == 0 { named.join(", ") } else { format!("{} and {more} more", named.join(", ")) }
}

/// Core's refusal of a copy that isn't what was approved, said with the workspace and the command
/// that approves that policy alone.
fn not_the_base(error: anyhow::Error, name: &WsName) -> anyhow::Error {
    match error.downcast_ref::<Refusal>() {
        Some(Refusal::NotTheBase { name: resource }) => {
            anyhow!("the approved copy of {resource} in {name} isn't what was approved, so nothing was approved. approve it alone: halti ws policy approve {name}/{resource}")
        }
        _ => error,
    }
}

/// Whether a policy is approved, as `ws policy show` says: its file's bytes, read now, against the
/// sealed hash.
fn status(approval: Option<&Approval>, text: Option<&[u8]>) -> &'static str {
    match (approval, text) {
        (None, _) => "not approved",
        (Some(_), None) => "approved, no file",
        (Some(approval), Some(text)) if approval.approves(text) => "approved",
        (Some(_), Some(_)) => "changed since approval",
    }
}

/// One policy with its status and the text that was hashed, or every policy of the workspace with
/// its status: approved, or with a file. Asked as opening it is; nothing is written.
fn show_with(here: &Here, name: &WsName, which: Option<&str>, way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase) -> Result<Said> {
    let files = policies_of(here, name)?;
    let list = |machine: &Machine<'_>| ws_approvals(machine, name);
    let Some(resource) = which else {
        let names = files.names()?;
        let declined = declined(&format!("the policies of {name} were not listed"), &format!("ws policy show {name}"));
        let (approvals, _) = approved(here, name, way, Action::WsOpen, &declined, typing, &list)?;
        // Each approval's file read for its status, then the files with none; listed by name.
        let mut rows: Vec<(&str, &str)> = Vec::new();
        for approval in &approvals {
            match approval.kind() {
                Kind::Resource => rows.push((approval.name(), status(Some(approval), files.read(approval.name())?.as_deref()))),
            }
        }
        let approved_names: Vec<&str> = approvals.iter().map(Approval::name).collect();
        rows.extend(names.iter().filter(|resource| !approved_names.contains(&resource.as_str())).map(|resource| (resource.as_str(), status(None, None))));
        if rows.is_empty() {
            return Ok(Said { out: vec![format!("{name} has no policy files. write one with: halti ws policy edit {name}/RESOURCE")], notes: Vec::new() });
        }
        rows.sort();
        let mut out = vec![format!("{:<16} POLICY", "RESOURCE")];
        out.extend(rows.iter().map(|(resource, status)| format!("{resource:<16} {status}")));
        return Ok(Said { out, notes: Vec::new() });
    };
    let Some(text) = read_checked(&files, resource)? else {
        return Ok(Said { out: vec![format!("no policy file for {resource} in {name}. write one with: halti ws policy edit {name}/{resource}")], notes: Vec::new() });
    };
    let declined = declined(&format!("the policy for {resource} in {name} was not shown"), &format!("ws policy show {name}/{resource}"));
    let (approvals, _) = approved(here, name, way, Action::WsOpen, &declined, typing, &list)?;
    let approval = approvals.iter().find(|approval| approval.kind() == Kind::Resource && approval.name() == resource);
    let path = files.path(resource);
    let out = vec![format!("{} ({})", path.display(), status(approval, Some(&text))), String::new(), String::from_utf8_lossy(&text).trim_end().to_string()];
    Ok(Said { out, notes: Vec::new() })
}
