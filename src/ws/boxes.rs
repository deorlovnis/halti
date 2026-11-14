//! A workspace's boxes: `ws box new`, `edit`, `approve`, `ls`, `rm` and `log`, `ws run` and
//! `ws stop`. A box of a workspace is its policy in the workspace's boxes folder, the approval of
//! that policy sealed in the workspace, and for a box that keeps a store, the store's key sealed
//! there too (`halti_core::verbs::ws_box_new`) and the store in the boxes folder.
//!
//! Making, approving and removing a box ask as `[workspace.approval] policy` and `rm` say; starting
//! one opens the workspace, as `open` says, and that is the only question: the run itself is
//! today's (`boxes::run_in`), with the workspace as the place everything is looked up in, which
//! `main` chooses. A second terminal joins a box that runs and is asked nothing: it reads only what
//! the opener noted beside the store (`boxes::join_in`). Listing and stopping ask nothing.
//!
//! A workspace that `halti open` keeps open (`ws::keep`) starts its boxes after the same checks of
//! their files, which are made here and handed to it (`keep`); `Kept` is where other commands find
//! it: its lock and its socket. While it is open, `ws run` and `ws stop` ask it, with names, and
//! ask nothing themselves.
//!
//! What is shown before an approval is what is sealed: a policy's file is read once, checked
//! against the workspace's mount rule and plain text, and those bytes are shown and sent to core.
//! Nothing here looks anything up through a place: of `boxes` only what reaches none is used.

use std::cell::Cell;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use halti_core::boxkey::{BoxKey, check_box};
use halti_core::ids::{WsId, WsName};
use halti_core::policy::{Base, Kind, Proposal};
use halti_core::refusal::Refusal;
use halti_core::verbs::{BoxNonces, Machine, Was, ws_approve, ws_box_new, ws_box_rm, ws_open};
use jiff::Timestamp;
use jiff::tz::TimeZone;

use super::files::{PolicyFiles, Reading, boxes_dir, remove_boxes, stores_in};
use super::tty::TtyPassphrase;
use super::{Here, Said, Way, approved, declined, keep, memory, random, saved, saved_means};
use crate::approval::{Action, Real};
use crate::boxes::store::Layout;
use crate::boxes::{self, BoxPolicy, MountRule};
use crate::config::{self, Settings};
use crate::engine::{self, Vms};
use crate::keep::{No, Refused};
use crate::source::Source;
use crate::util::{sha256_hex, warn};
use crate::{names, policy};

/// `acme/dev`: a workspace's name, then after the first `/` a box, each as core checks it.
pub fn target(text: &str) -> Result<(WsName, &str)> {
    let Some((name, box_name)) = text.split_once('/') else { bail!("use a workspace and a box, e.g. acme/dev") };
    let name = WsName::parse(name)?;
    check_box(box_name)?;
    Ok((name, box_name))
}

/// One box of a workspace, by the id the workspace's record names: its policy files and where its
/// store, lock and VMs are.
struct Found {
    name: WsName,
    id: WsId,
    box_name: String,
    /// `acme/dev`, as messages name it.
    shown: String,
    files: PolicyFiles,
    layout: Layout,
}

/// Box `box_name` of `name`. There is no workspace without a record.
fn find(here: &Here, name: &WsName, box_name: &str) -> Result<Found> {
    let id = here.id_of(name).ok_or_else(|| Refusal::Unknown(name.clone()))?;
    found_in(&here.root, name, id, box_name)
}

/// Box `box_name` of workspace `name`, whose id is `id`, in the workspaces folder `root`.
fn found_in(root: &Path, name: &WsName, id: WsId, box_name: &str) -> Result<Found> {
    let layout = Layout::workspace(&boxes_dir(root, id), id)?;
    Ok(Found { name: name.clone(), id, box_name: box_name.to_string(), shown: format!("{name}/{box_name}"), files: PolicyFiles::boxes(root, id), layout })
}

fn no_box(shown: &str) -> anyhow::Error {
    anyhow!("there is no box {shown}. make one with: halti ws box new {shown}")
}

fn exists(shown: &str) -> anyhow::Error {
    anyhow!("box {shown} exists already. change it with: halti ws box edit {shown}")
}

fn no_store(shown: &str) -> anyhow::Error {
    anyhow!("box {shown} has no store. make one with: halti ws box new {shown}")
}

fn running(shown: &str) -> anyhow::Error {
    anyhow!("box {shown} is running: stop it first (halti ws stop {shown})")
}

fn changed_while_opened(name: &WsName) -> anyhow::Error {
    anyhow!("workspace {name} changed while it was opened: try again")
}

/// The box's policy, read once, as text, and what it parses to under `rule`: none if there is no
/// file. A text that isn't plain or doesn't parse is refused with its path.
fn read_checked(found: &Found, rule: &MountRule) -> Result<Option<(Vec<u8>, BoxPolicy)>> {
    let Some(bytes) = found.files.read(&found.box_name)? else { return Ok(None) };
    let path = found.files.path(&found.box_name);
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{} isn't UTF-8", path.display()))?;
    let parsed = BoxPolicy::parse_in(text, rule).with_context(|| path.display().to_string())?;
    Ok(Some((bytes, parsed)))
}

fn sha12(text: &[u8]) -> String {
    sha256_hex(text)[..12].to_string()
}

/// A policy's whole text as it is shown before an approval: `Box dev in acme (PATH)HOW:`, the
/// text, and the start of its sha256.
fn shown_whole(found: &Found, how: &str, text: &[u8]) -> String {
    let path = found.files.path(&found.box_name);
    format!("Box {} in {} ({}){how}:\n\n{}\n\nsha256 {}\n\n", found.box_name, found.name, path.display(), String::from_utf8_lossy(text).trim_end(), sha12(text))
}

// --- making, changing and approving a box ---

/// `halti ws box new WS/BOX [--type]`: the policy in the editor (the workspace's template if there
/// is no file), then one approval as `[workspace.approval] policy` says, which stores the box's key,
/// approves its policy and, for `keep = true`, makes its store.
///
/// A box approved to keep a store it hasn't got (made to keep nothing and changed since, or
/// approved before it was made) is made here too, against its approved copy. One approved to keep
/// nothing is made already.
pub fn new(target_text: &str, type_it: bool) -> Result<()> {
    let (name, box_name) = target(target_text)?;
    let settings = config::settings();
    let vms = boxes::vms(&settings)?;
    let here = Here::at(&settings.workspaces.path);
    let found = find(&here, &name, box_name)?;
    let rule = MountRule::workspace(&settings);
    found.layout.prepare()?;
    if found.layout.bundle(box_name).exists() {
        return Err(exists(&found.shown));
    }
    let copy = found.files.approved_copy(box_name)?;
    let keeps = |copy: &[u8]| std::str::from_utf8(copy).ok().and_then(|text| BoxPolicy::parse_in(text, &rule).ok()).is_some_and(|parsed| parsed.keep);
    if copy.as_deref().is_some_and(|copy| !keeps(copy)) {
        return Err(exists(&found.shown));
    }
    if found.files.read(box_name)?.is_none() {
        // The pinned image of the engine's agent system, if there is one yet.
        let image = vms.image_digest(engine::AGENT_IMAGE).ok();
        found.files.create(box_name, &boxes::workspace_template(&name, box_name, image.as_deref()))?;
    }
    policy::run_editor(&found.files.path(box_name))?;
    let (text, parsed) = read_checked(&found, &rule)?.ok_or_else(|| no_box(&found.shown))?;
    memory::harden();
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsPolicy, type_it), detail: None };
    make_with(&here, &found, &text, copy.as_deref(), parsed.keep, &way, &|| TtyPassphrase::new(false), &boxes::store::create)?.print();
    Ok(())
}

/// Makes the box `found` with the policy `text`, shown whole as new, approved the way `way` says,
/// in place of `copy` if the box's policy was approved before it was made. For a box that `keep`s
/// a store, a key is drawn and `create` makes the store with it once core has the approval and has
/// checked the box isn't there; a failure after that shreds the store.
#[allow(clippy::too_many_arguments)]
fn make_with(
    here: &Here,
    found: &Found,
    text: &[u8],
    copy: Option<&[u8]>,
    keep: bool,
    way: &Way<'_>,
    typing: &dyn Fn() -> TtyPassphrase,
    create: &dyn Fn(&Layout, &Path, &str) -> Result<()>,
) -> Result<Said> {
    let (box_name, shown) = (found.box_name.as_str(), found.shown.as_str());
    print!("{}", shown_whole(found, ", new", text));
    let key = if keep { Some(BoxKey::from_bytes(random::<32>()?)) } else { None };
    let bundle = found.layout.bundle(box_name);
    let made = Cell::new(false);
    let proposal = Proposal { kind: Kind::Box, name: box_name, text, base: copy.map_or(Base::New, Base::Copy) };
    let make = |machine: &Machine<'_>| {
        let store = || {
            if let Some(key) = &key {
                create(&found.layout, &bundle, &key.hex())?;
                made.set(true);
            }
            Ok(())
        };
        ws_box_new(machine, &found.name, key.as_ref(), &proposal, store, BoxNonces { key: *random::<12>()?, manifest: *random::<12>()? })
    };
    let way = Way { world: way.world, copies: way.copies, means: way.means, detail: Some(format!("{box_name} {}", sha12(text))) };
    let declined = declined(&format!("box {shown} was not made"), &format!("ws box new {shown}"));
    if let Err(error) = approved(here, &found.name, &way, Action::WsPolicy, &declined, typing, &make) {
        if made.get() {
            let _ = boxes::store::shred(&bundle);
        }
        return Err(match error.downcast_ref::<Refusal>() {
            // Its key is listed and its store is gone: only removing it makes room for a new one.
            Some(Refusal::BoxExists { .. }) if !bundle.exists() => anyhow!("box {shown} has a key but no store. remove it with: halti ws box rm {shown}"),
            Some(Refusal::BoxExists { .. } | Refusal::NotTheBase { .. }) => exists(shown),
            _ => error,
        });
    }
    let mut said = Said::default();
    said.out.push(match keep {
        true => format!("made box {shown}. run it with: halti ws run {shown}"),
        false => format!("made box {shown}. it keeps nothing between runs. run it with: halti ws run {shown}"),
    });
    if found.files.keep_approved(box_name, text).is_err() {
        said.notes.push(format!("the approved copy of box {shown} couldn't be kept. approve it again: halti ws box approve {shown}"));
    }
    Ok(said)
}

/// `halti ws box edit WS/BOX`: the box's policy in the editor, read once when it ends, checked and
/// shown against the approved copy. Asks nothing; on a terminal it offers to approve what was saved.
pub fn edit(target_text: &str) -> Result<()> {
    let (name, box_name) = target(target_text)?;
    let settings = config::settings();
    let here = Here::at(&settings.workspaces.path);
    let found = find(&here, &name, box_name)?;
    let rule = MountRule::workspace(&settings);
    // A path there that isn't a plain file, or is too large, is refused before the editor opens it.
    if found.files.read(box_name)?.is_none() {
        return Err(no_box(&found.shown));
    }
    let path = found.files.path(box_name);
    // A copy that can't be read, or isn't text, is taken as none: the edit is then approved as new,
    // which core refuses if the box's policy has an approval.
    let copy = found.files.approved_copy(box_name).ok().flatten().filter(|copy| std::str::from_utf8(copy).is_ok());
    let read = |_: &Path| found.files.read(box_name)?.ok_or_else(|| no_box(&found.shown));
    let check = |text: &str| BoxPolicy::parse_in(text, &rule).map(drop);
    let shown_against = || copy.as_deref().map(|copy| String::from_utf8_lossy(copy).into_owned());
    let Some(bytes) = policy::edit_against(&path, read, shown_against, &format!("box {box_name} in {name}"), check)? else { return Ok(()) };
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsPolicy, false), detail: None };
    policy::offer_approval(&path, &format!("halti ws box approve {}", found.shown), || {
        memory::harden();
        let (base, shown) = match &copy {
            Some(copy) => (Base::Copy(copy), format!("sha256 {}\n\n", sha12(&bytes))),
            None => (Base::New, shown_whole(&found, ", new", &bytes)),
        };
        approve_shown(&here, &found, &bytes, base, &shown, &way, &|| TtyPassphrase::new(false))?.print();
        Ok(())
    })
}

/// `halti ws box approve WS/BOX [--type]`: the box's policy, read once, checked and shown whole,
/// approved as `[workspace.approval] policy` says.
pub fn approve(target_text: &str, type_it: bool) -> Result<()> {
    let (name, box_name) = target(target_text)?;
    let settings = config::settings();
    memory::harden();
    let here = Here::at(&settings.workspaces.path);
    let found = find(&here, &name, box_name)?;
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsPolicy, type_it), detail: None };
    approve_with(&here, &found, &MountRule::workspace(&settings), &way, &|| TtyPassphrase::new(false))?.print();
    Ok(())
}

fn approve_with(here: &Here, found: &Found, rule: &MountRule, way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase) -> Result<Said> {
    let (text, _) = read_checked(found, rule)?.ok_or_else(|| no_box(&found.shown))?;
    approve_shown(here, found, &text, Base::Shown, &shown_whole(found, "", &text), way, typing)
}

/// Prints `shown`, then asks once (`approved`, as `[workspace.approval] policy` says) and has core
/// seal the approval of `text` as the box's policy. Once it has, the approved copy is written with
/// the bytes just approved, where it isn't those already.
fn approve_shown(here: &Here, found: &Found, text: &[u8], base: Base<'_>, shown: &str, way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase) -> Result<Said> {
    let (box_name, name) = (found.box_name.as_str(), &found.name);
    print!("{shown}");
    let proposal = Proposal { kind: Kind::Box, name: box_name, text, base };
    let way = Way { world: way.world, copies: way.copies, means: way.means, detail: Some(format!("of box {box_name} {}", sha12(text))) };
    let approve = |machine: &Machine<'_>| ws_approve(machine, name, std::slice::from_ref(&proposal), *random::<12>()?);
    let declined = declined(&format!("the policy of box {} was not approved", found.shown), &format!("ws box approve {}", found.shown));
    let (was, _) = approved(here, name, &way, Action::WsPolicy, &declined, typing, &approve).map_err(|error| match error.downcast_ref::<Refusal>() {
        Some(Refusal::NotTheBase { .. }) => {
            anyhow!("the approved copy of box {box_name} in {name} isn't what was approved, so nothing was approved. approve it alone: halti ws box approve {}", found.shown)
        }
        _ => error,
    })?;
    let mut said = Said::default();
    match was.first() {
        Some(Was::Already) => said.out.push(format!("box {box_name} in {name} was approved already")),
        _ => {
            said.out.push(format!("approved box {box_name} in {name}"));
            if boxes::store::is_held(&found.layout.lock(box_name)) {
                said.out.push(format!("a running box keeps the policy it started with. stop it (halti ws stop {}) and run it again", found.shown));
            }
        }
    }
    let kept = found.files.approved_copy(box_name).ok().flatten();
    if kept.as_deref() != Some(text) && found.files.keep_approved(box_name, text).is_err() {
        said.notes.push(format!("the approved copy of box {} couldn't be kept. approve it again: halti ws box approve {}", found.shown, found.shown));
    }
    Ok(said)
}

// --- listing, removing ---

/// `halti ws box ls WS`: the workspace's boxes, from their files and folders; asks nothing. A box
/// is listed if it has a policy file or a store.
pub fn ls(name_text: &str) -> Result<()> {
    let name = WsName::parse(name_text)?;
    let settings = config::settings();
    let here = Here::at(&settings.workspaces.path);
    listing(&here, &name, &MountRule::workspace(&settings))?.print();
    Ok(())
}

fn listing(here: &Here, name: &WsName, rule: &MountRule) -> Result<Said> {
    let id = here.id_of(name).ok_or_else(|| Refusal::Unknown(name.clone()))?;
    let folder = boxes_dir(&here.root, id);
    let layout = Layout::workspace(&folder, id)?;
    let files = PolicyFiles::boxes(&here.root, id);
    let mut names = files.names()?;
    names.extend(stores_in(&folder)?.into_iter().filter(|box_name| check_box(box_name).is_ok()));
    names.sort();
    names.dedup();
    if names.is_empty() {
        return Ok(Said { out: vec![format!("{name} has no boxes. make one with: halti ws box new {name}/NAME")], notes: Vec::new() });
    }
    let reading = Reading::at(&here.root);
    let mut out = vec![format!("{:<20} {:<9} {:>9}  {:<17} {:<24} {:<16} ABOUT", "BOX", "STATE", "SIZE", "LAST USED", "SITES", "SESSIONS")];
    for box_name in &names {
        let text = files.read(box_name).ok().flatten();
        let parsed = text.as_deref().and_then(|text| std::str::from_utf8(text).ok()).and_then(|text| BoxPolicy::parse_in(text, rule).ok());
        let bundle = layout.bundle(box_name);
        let state = match (boxes::store::is_held(&layout.lock(box_name)), bundle.exists(), parsed.as_ref().is_some_and(|parsed| !parsed.keep)) {
            (true, _, _) => "open",
            (false, true, _) => "locked",
            (false, false, true) => "shredded",
            (false, false, false) => "no store",
        };
        let (bytes, used) = if bundle.exists() { boxes::store::usage(&bundle) } else { (0, None) };
        let size = if bundle.exists() { boxes::human(bytes) } else { "-".to_string() };
        let used = used.and_then(|time| Timestamp::try_from(time).ok()).map_or("-".to_string(), |time| time.to_zoned(TimeZone::system()).strftime("%Y-%m-%d %H:%M").to_string());
        let sites = parsed.as_ref().map_or(String::new(), |parsed| parsed.sites.join(", "));
        let about = parsed.as_ref().map_or("", |parsed| parsed.about.as_str());
        let sessions = reading.box_file(id, &format!("{box_name}.sessions")).ok().flatten().map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).unwrap_or_default();
        let sessions = sessions.split(',').filter(|site| !site.is_empty()).collect::<Vec<_>>().join(", ");
        out.push(format!("{box_name:<20} {state:<9} {size:>9}  {used:<17} {sites:<24} {sessions:<16} {about}").trim_end().to_string());
    }
    Ok(Said { out, notes: Vec::new() })
}

/// `halti ws box rm WS/BOX [--type]`: with the box stopped, one approval as `[workspace.approval] rm`
/// says, which drops its key and its approval from the workspace; then its leftover VMs are
/// stopped, its store shredded, and what its runs left removed. Its policy file stays.
pub fn rm(target_text: &str, type_it: bool) -> Result<()> {
    let (name, box_name) = target(target_text)?;
    let settings = config::settings();
    memory::harden();
    let here = Here::at(&settings.workspaces.path);
    let found = find(&here, &name, box_name)?;
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsRm, type_it), detail: None };
    rm_with(&here, &found, boxes::vms(&settings).ok(), &way, &|| TtyPassphrase::new(false))?.print();
    Ok(())
}

fn rm_with(here: &Here, found: &Found, vms: Option<&dyn Vms>, way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase) -> Result<Said> {
    let (box_name, shown) = (found.box_name.as_str(), found.shown.as_str());
    let bundle = found.layout.bundle(box_name);
    let has_file = found.files.read(box_name)?.is_some();
    if !has_file && !bundle.exists() && found.files.approved_copy(box_name)?.is_none() {
        return Err(no_box(shown));
    }
    found.layout.prepare()?;
    let Some(_held) = boxes::store::lock(&found.layout.lock(box_name))? else { return Err(running(shown)) };
    let way = Way { world: way.world, copies: way.copies, means: way.means, detail: Some(box_name.to_string()) };
    let remove = |machine: &Machine<'_>| ws_box_rm(machine, &found.name, box_name, *random::<12>()?);
    approved(here, &found.name, &way, Action::WsRm, &declined(&format!("box {shown} was not removed"), &format!("ws box rm {shown}")), typing, &remove)?;
    let mut said = Said::default();
    // Its key is gone: what is left is noise to anyone, and goes.
    for vm in [found.layout.vm(box_name), found.layout.browser_vm(box_name)] {
        if let Some(vms) = vms.filter(|vms| vms.running(&vm))
            && let Err(error) = vms.stop(&vm)
        {
            said.notes.push(format!("stopping {vm}: {error:#}"));
        }
    }
    boxes::store::shred(&bundle)?;
    boxes::run::sweep(&found.layout, box_name)?;
    if found.files.forget_approved(box_name).is_err() {
        said.notes.push(format!("the approved copy of box {shown} couldn't be removed. remove {}", found.files.copy_path(box_name).display()));
    }
    let reading = Reading::at(&here.root);
    for file in [format!("{box_name}.sessions"), format!("{box_name}.head")] {
        let _ = reading.remove_box_file(found.id, &file);
    }
    said.out.push(format!("deleted box {shown}: its key and its store"));
    if has_file {
        said.out.push(format!("kept its policy {} (halti ws box new {shown} makes a fresh box from it)", found.files.path(box_name).display()));
    }
    said.out.push(format!(
        "Time Machine may still hold encrypted copies of the store. They stay closed unless restored together with {}'s files from before this, and opened with its passphrase.",
        found.name
    ));
    Ok(said)
}

// --- running, stopping, the log ---

/// What `ws run` hands `main`: a box to join, one to join while its session of an open workspace is
/// held, or the workspace opened and the box to start in it.
pub enum Run {
    Join(Box<boxes::Join>),
    Session { join: Box<boxes::Join>, session: Box<keep::Session> },
    Start { source: Box<Source>, start: Box<boxes::Start> },
}

/// `halti ws run WS/BOX [--type] [-- CMD]`: reads the settings once. A workspace that `halti open`
/// keeps open is asked to start the box, or join it if it runs, and nothing is asked here: the box
/// is joined while the session is held. Otherwise a box that runs is joined, and nothing is asked.
/// Otherwise its policy file is read once and checked, against the copy kept when it was approved
/// too, and so are its store and its sockets; then the workspace is opened, as
/// `[workspace.approval] open` says. `main` chooses it as the place and starts the box.
pub fn run(target_text: &str, command: Vec<String>, type_it: bool) -> Result<Run> {
    let (name, box_name) = target(target_text)?;
    let settings = config::settings();
    let vms = boxes::vms(&settings)?;
    memory::harden();
    let here = Here::at(&settings.workspaces.path);
    let found = find(&here, &name, box_name)?;
    let rule = MountRule::workspace(&settings);
    let command = (!command.is_empty()).then_some(command);
    let kept = Kept::of(&here, found.id)?;
    if kept.held() {
        let started = keep::start(&kept, &name, box_name)?;
        let text = found.files.read(box_name)?.ok_or_else(|| no_box(&found.shown))?;
        let session = match started {
            keep::Started::Elsewhere => None,
            keep::Started::Session(stream) => {
                // A session that loses the open workspace stops the box, as `ws stop` does.
                let (layout, stopped) = (found_in(&here.root, &name, found.id, box_name)?.layout, box_name.to_string());
                let lost = move || {
                    if let Err(e) = stop_box(&layout, &stopped, vms) {
                        warn(&format!("stopping box {name}/{stopped}: {e:#}"));
                    }
                };
                Some(keep::Session::hold(stream, &found.name, &found.shown, Box::new(lost))?)
            }
        };
        let Found { box_name, shown, layout, .. } = found;
        let join = Box::new(boxes::Join { vms, layout, name: box_name, shown, text, mounts: rule, command });
        return Ok(match session {
            Some(session) => Run::Session { join, session: Box::new(session) },
            None => Run::Join(join),
        });
    }
    if boxes::store::is_held(&found.layout.lock(box_name)) {
        let text = found.files.read(box_name)?.ok_or_else(|| no_box(&found.shown))?;
        let Found { box_name, shown, layout, .. } = found;
        return Ok(Run::Join(Box::new(boxes::Join { vms, layout, name: box_name, shown, text, mounts: rule, command })));
    }
    let (text, parsed) = start_check(&found, &rule).map_err(|refused| refused.why)?;
    let shown = found.shown.clone();
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsOpen, type_it), detail: Some(format!("to run box {box_name}")) };
    let reader = open_for(&here, &found, &way, &format!("box {shown} was not started"), &format!("ws run {shown}"), &|| TtyPassphrase::new(false))?;
    // The keys are wiped once read; this process lives as long as the box.
    memory::release();
    let source = Source::workspace(name, reader, Reading::at(&here.root), settings.clone());
    let Found { box_name, layout, .. } = found;
    let start = boxes::Start { settings, vms, layout, name: box_name, shown, text, policy: parsed, mounts: rule, command };
    Ok(Run::Start { source: Box::new(source), start: Box::new(start) })
}

/// What starting the box `found` needs of its files, checked before anything is asked or opened: its
/// policy file, read once and checked under `rule`, is the copy kept when it was approved; a box
/// that keeps a store has one; its sockets fit. Returns the file's bytes and what they parse to.
fn start_check(found: &Found, rule: &MountRule) -> Result<(Vec<u8>, BoxPolicy), Refused> {
    let shown = &found.shown;
    let (text, parsed) = read_checked(found, rule)?.ok_or_else(|| Refused::new(No::Box, no_box(shown)))?;
    match found.files.approved_copy(&found.box_name).ok().flatten() {
        None => return Err(Refused::new(No::Unapproved, anyhow!("box {shown} isn't approved. approve it with: halti ws box approve {shown}"))),
        Some(copy) if copy != text => {
            return Err(Refused::new(No::Changed, anyhow!("the policy of box {shown} changed since it was approved. approve it with: halti ws box approve {shown}")));
        }
        Some(_) => {}
    }
    if parsed.keep && !found.layout.bundle(&found.box_name).exists() {
        return Err(Refused::new(No::Store, no_store(shown)));
    }
    found.layout.sockets_fit(&found.box_name)?;
    Ok((text, parsed))
}

/// Opens the workspace of `found` the way `way` says, and checks it is the one its record named
/// before: the box's folders were found by that id.
fn open_for(here: &Here, found: &Found, way: &Way<'_>, what: &str, command: &str, typing: &dyn Fn() -> TtyPassphrase) -> Result<halti_core::verbs::Reader> {
    let open = |machine: &Machine<'_>| ws_open(machine, &found.name);
    let (reader, _) = approved(here, &found.name, way, Action::WsOpen, &declined(what, command), typing, &open)?;
    if reader.id() != found.id {
        return Err(changed_while_opened(&found.name));
    }
    Ok(reader)
}

/// How long a box another halti runs is waited for once it is stopped: 60 times this.
const LET_GO_EVERY: Duration = Duration::from_millis(250);

/// `halti ws stop WS/BOX`: asks nothing. A workspace that `halti open` keeps open is asked to stop
/// the box; once it says it did, the box's lock is waited for here all the same. Otherwise, or if
/// it doesn't run the box, the box is stopped as `stop_box` does.
pub fn stop(target_text: &str) -> Result<()> {
    let (name, box_name) = target(target_text)?;
    let settings = config::settings();
    let vms = boxes::vms(&settings)?;
    let here = Here::at(&settings.workspaces.path);
    let found = find(&here, &name, box_name)?;
    let kept = Kept::of(&here, found.id)?;
    if kept.held() && keep::stop(&kept, &name, box_name)? == keep::Stopped::Said {
        let (_, let_go) = stop_box(&found.layout, box_name, vms)?;
        if !let_go {
            bail!("box {} is being opened or closed: try again in a moment", found.shown);
        }
        println!("stopped box {}", found.shown);
        return Ok(());
    }
    let (was_running, _) = stop_box(&found.layout, box_name, vms)?;
    if !was_running {
        bail!("box {} isn't running", found.shown);
    }
    println!("stopped box {}", found.shown);
    Ok(())
}

/// Stops box `box_name`'s VM. The halti that runs it then puts it away; once it lets go of the
/// box, what is left is cleared here, and the browser VM is stopped if it still runs (that halti
/// stops it before it lets go, unless it died). Until then its VM is stopped whenever it is seen
/// running: a box that is still starting brings it up meanwhile. Returns whether its VM was seen
/// running, and whether the box was let go of.
fn stop_box(layout: &Layout, box_name: &str, vms: &dyn Vms) -> Result<(bool, bool)> {
    let vm = layout.vm(box_name);
    let mut was_running = vms.running(&vm);
    if was_running {
        vms.stop(&vm)?;
    }
    let lock = layout.lock(box_name);
    if !lock.exists() {
        return Ok((was_running, true));
    }
    for _ in 0..60 {
        if let Some(_held) = boxes::store::lock(&lock)? {
            boxes::run::sweep(layout, box_name)?;
            let browser = layout.browser_vm(box_name);
            if vms.running(&browser) {
                vms.stop(&browser)?;
            }
            return Ok((was_running, true));
        }
        thread::sleep(LET_GO_EVERY);
        if vms.running(&vm) {
            was_running = true;
            vms.stop(&vm)?;
        }
    }
    Ok((was_running, false))
}

/// `halti ws box log WS/BOX [-n N] [--type]`: the last lines of what went through the box's door. A
/// box that runs is read as it is, asking nothing; otherwise the workspace is opened, as `open`
/// says, for the store's key, and the store is opened read-only while it is read.
pub fn log(target_text: &str, last: usize, type_it: bool) -> Result<()> {
    let (name, box_name) = target(target_text)?;
    let settings = config::settings();
    memory::harden();
    let here = Here::at(&settings.workspaces.path);
    let found = find(&here, &name, box_name)?;
    let way = Way { world: &Real, copies: &saved::Keychain, means: saved_means(&settings, Action::WsOpen, type_it), detail: None };
    let text = log_with(&here, &found, &way, &|| TtyPassphrase::new(false))?;
    let lines: Vec<&str> = text.lines().collect();
    for line in &lines[lines.len().saturating_sub(last)..] {
        println!("{line}");
    }
    if lines.is_empty() {
        println!("nothing logged yet");
    }
    Ok(())
}

fn log_with(here: &Here, found: &Found, way: &Way<'_>, typing: &dyn Fn() -> TtyPassphrase) -> Result<String> {
    let (box_name, shown) = (found.box_name.as_str(), found.shown.as_str());
    let bundle = found.layout.bundle(box_name);
    if !bundle.exists() {
        return Err(no_store(shown));
    }
    found.layout.prepare()?;
    let mnt = found.layout.mount_point(box_name);
    let read = |mnt: &Path| fs::read_to_string(boxes::store::door_log(mnt)).unwrap_or_default();
    let Some(_held) = boxes::store::lock(&found.layout.lock(box_name))? else {
        if !boxes::store::is_mounted(&mnt) {
            bail!("box {shown} is being opened or closed by another halti: try again in a moment");
        }
        return Ok(read(&mnt));
    };
    let way = Way { world: way.world, copies: way.copies, means: way.means, detail: Some(format!("to read the log of box {box_name}")) };
    let reader = open_for(here, found, &way, &format!("the log of box {shown} was not read"), &format!("ws box log {shown}"), typing)?;
    let key = reader.box_key(&here.keystore, box_name)?.ok_or_else(|| anyhow!("box {shown} has a store but no key. remove it with: halti ws box rm {shown}"))?;
    drop(reader);
    let open = boxes::store::open(&bundle, &mnt, &key.hex(), true)?;
    Ok(read(open.path()))
}

// --- deleting a workspace ---

/// Refuses to delete workspace `name` (id `id`) while it is open, or one of its boxes runs or has a
/// store: checked before anything is asked.
pub(super) fn refuse_delete(here: &Here, name: &WsName, id: WsId) -> Result<()> {
    let folder = boxes_dir(&here.root, id);
    if boxes::store::is_held(&folder.join(names::KEEPER_LOCK)) {
        bail!("{name} is open: close it first (halti close {name})");
    }
    for entry in fs::read_dir(folder.join("open")).into_iter().flatten().flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        if let Some(box_name) = file.strip_suffix(".lock")
            && boxes::store::is_held(&entry.path())
        {
            return Err(running(&format!("{name}/{box_name}")));
        }
    }
    let stores = stores_in(&folder)?;
    if let Some(first) = stores.first() {
        bail!("{name} has boxes with stores: {}. remove them first: halti ws box rm {name}/{first}", stores.join(", "));
    }
    Ok(())
}

/// Removes the boxes folder of a deleted workspace, after detaching whatever a run that ended
/// without cleaning up left mounted in it. A store in it is never removed (`remove_boxes`).
pub(super) fn clear(here: &Here, id: WsId) -> Result<()> {
    let open = boxes_dir(&here.root, id).join("open");
    for entry in fs::read_dir(&open).into_iter().flatten().flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            boxes::store::detach(&entry.path())?;
        }
    }
    remove_boxes(&here.root, id)
}

/// The VMs a workspace's boxes could have left running, found before it is deleted and stopped once
/// it is gone: both VMs of each box with a policy file, where there is an engine.
pub(super) struct Leftovers {
    vms: Option<&'static dyn Vms>,
    layout: Option<Layout>,
    names: Vec<String>,
}

impl Leftovers {
    pub(super) fn of(here: &Here, name: &WsName, settings: &Settings) -> Leftovers {
        let none = Leftovers { vms: None, layout: None, names: Vec::new() };
        let (Ok(vms), Some(id)) = (boxes::vms(settings), here.id_of(name)) else { return none };
        let names = PolicyFiles::boxes(&here.root, id).names().unwrap_or_default();
        Leftovers { vms: Some(vms), layout: Layout::workspace(&boxes_dir(&here.root, id), id).ok(), names }
    }

    pub(super) fn stop(&self) {
        let (Some(vms), Some(layout)) = (self.vms, &self.layout) else { return };
        for box_name in &self.names {
            for vm in [layout.vm(box_name), layout.browser_vm(box_name)] {
                if vms.running(&vm)
                    && let Err(error) = vms.stop(&vm)
                {
                    eprintln!("halti: stopping {vm}: {error:#}");
                }
            }
        }
    }
}

// --- an open workspace ---

/// What keeps a workspace open, as `halti open` hands it on.
pub type Keep = boxes::keep::Keep;

/// Puts away what a `halti open` or a `ws run` that ended without cleaning up left of these boxes:
/// for each whose lock is free, its VMs if they run, its store if it is still attached, and a store
/// made for one run. Returns the boxes that had something left.
pub fn put_away_left(layout: &Layout, vms: &dyn Vms, names: &[String]) -> Vec<String> {
    let mut left = Vec::new();
    for name in names {
        let lock = layout.lock(name);
        if !lock.exists() {
            continue;
        }
        let Ok(Some(_held)) = boxes::store::lock(&lock) else { continue };
        let running: Vec<String> = [layout.vm(name), layout.browser_vm(name)].into_iter().filter(|vm| vms.running(vm)).collect();
        if running.is_empty() && !boxes::store::is_mounted(&layout.mount_point(name)) && !layout.ephemeral_bundle(name).exists() {
            continue;
        }
        for vm in &running {
            if let Err(e) = vms.stop(vm) {
                warn(&format!("stopping {vm}: {e:#}"));
            }
        }
        if let Err(e) = boxes::run::sweep(layout, name) {
            warn(&format!("box {name}: {e:#}"));
        }
        left.push(name.clone());
    }
    left
}

/// Stops the boxes in this layout that another halti runs, as `ws stop` does, names only: a box
/// started while its workspace wasn't open holds the workspace's keys in the process that runs it.
/// Each is waited for until that halti lets go of it, its VM stopped whenever it is seen running
/// (one still starting brings it up meanwhile), and what is left is cleared. Returns the boxes that
/// were stopped, and those whose halti held on.
pub fn stop_others(layout: &Layout, vms: &dyn Vms) -> (Vec<String>, Vec<String>) {
    let mut names: Vec<String> = fs::read_dir(layout.open_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.strip_suffix(".lock").map(str::to_string))
        .filter(|name| check_box(name).is_ok())
        .collect();
    names.sort();
    let (mut stopped, mut held) = (Vec::new(), Vec::new());
    for name in names {
        let lock = layout.lock(&name);
        if !boxes::store::is_held(&lock) {
            continue;
        }
        let vm = layout.vm(&name);
        let let_go = (0..60).any(|_| {
            if vms.running(&vm)
                && let Err(e) = vms.stop(&vm)
            {
                warn(&format!("stopping {vm}: {e:#}"));
            }
            let Ok(Some(_free)) = boxes::store::lock(&lock) else {
                thread::sleep(LET_GO_EVERY);
                return false;
            };
            let _ = boxes::run::sweep(layout, &name);
            let browser = layout.browser_vm(&name);
            if vms.running(&browser)
                && let Err(e) = vms.stop(&browser)
            {
                warn(&format!("stopping {browser}: {e:#}"));
            }
            true
        });
        if let_go { stopped.push(name) } else { held.push(name) }
    }
    (stopped, held)
}

/// An open workspace as other commands find it, by the id its record names: the lock that
/// `halti open` holds while it keeps the workspace open, its socket, and its boxes.
pub(super) struct Kept {
    layout: Layout,
    files: PolicyFiles,
}

impl Kept {
    pub(super) fn of(here: &Here, id: WsId) -> Result<Kept> {
        Ok(Kept { layout: Layout::workspace(&boxes_dir(&here.root, id), id)?, files: PolicyFiles::boxes(&here.root, id) })
    }

    /// Whether some process holds the lock: a hint that the workspace is open, not proof. A program
    /// running as you can hold it.
    pub(super) fn held(&self) -> bool {
        boxes::store::is_held(&self.layout.keeper_lock())
    }

    /// Waits a while for the lock to be let go of; false if it is still held.
    pub(super) fn let_go(&self) -> bool {
        (0..40).any(|_| {
            let free = !self.held();
            if !free {
                thread::sleep(Duration::from_millis(250));
            }
            free
        })
    }

    pub(super) fn socket(&self) -> std::path::PathBuf {
        self.layout.keeper_socket().expect("a workspace's boxes")
    }

    /// Puts away what a `halti open` or a `ws run` that ended without cleaning up left: the boxes
    /// with something left. Nothing where there is no engine.
    pub(super) fn left(&self, settings: &Settings) -> Result<Vec<String>> {
        let Ok(vms) = boxes::vms(settings) else { return Ok(Vec::new()) };
        Ok(put_away_left(&self.layout, vms, &self.files.names()?))
    }

    /// Stops the boxes that other terminals run, names only: the boxes stopped, and those whose
    /// halti held on.
    pub(super) fn others(&self, settings: &Settings) -> (Vec<String>, Vec<String>) {
        let Ok(vms) = boxes::vms(settings) else { return (Vec::new(), Vec::new()) };
        stop_others(&self.layout, vms)
    }
}

/// What keeps workspace `name` (id `id`) open, made before anything is asked: its lock, taken here
/// (None if another process holds it), its boxes as `kept` found them, the settings read once, the
/// checks of a box's files before it starts, which are `ws run`'s (`start_check`), and what puts
/// away leftovers and stops the boxes other terminals run. The lock's folder is made first: a
/// workspace that never had a box has none.
pub(super) fn keep(here: &Here, name: &WsName, id: WsId, kept: Kept, settings: &Settings) -> Result<Option<Keep>> {
    kept.layout.prepare()?;
    let Some(lock) = boxes::store::lock(&kept.layout.keeper_lock())? else { return Ok(None) };
    let rule = MountRule::workspace(settings);
    let (root, ws, checked_under) = (here.root.clone(), name.clone(), rule.clone());
    let check = move |box_name: &str| -> Result<boxes::keep::Checked, Refused> {
        let found = found_in(&root, &ws, id, box_name)?;
        let (text, policy) = start_check(&found, &checked_under)?;
        Ok(boxes::keep::Checked { text, policy })
    };
    let names = kept.files.names()?;
    let layout = || Layout::workspace(&boxes_dir(&here.root, id), id);
    let (left_in, others_in) = (layout()?, layout()?);
    Ok(Some(boxes::keep::Keep {
        name: name.clone(),
        lock,
        layout: kept.layout,
        mounts: rule,
        vms: boxes::vms(settings).ok(),
        settings: settings.clone(),
        check: Box::new(check),
        left: Box::new(move |vms| put_away_left(&left_in, vms, &names)),
        others: Box::new(move |vms| stop_others(&others_in, vms)),
    }))
}

#[cfg(all(test, halti_dev))]
mod tests {
    use super::super::new_with;
    use super::super::saved::Copies;
    use super::*;
    use crate::approval::Means;
    use crate::approval::fake_tests::Fake;
    use crate::util::TempDir;
    use zeroize::Zeroizing;

    const ACME: &str = "acme passphrase one";
    /// A box that keeps nothing between runs: no store to make.
    const SCRATCH: &str = "run = [\"claude\"]\nkeep = false\n";

    /// One saved passphrase, read after the approval.
    struct OneCopy(Cell<Option<WsId>>);

    impl Copies for OneCopy {
        fn exists(&self, ws: WsId) -> bool {
            self.0.get() == Some(ws)
        }

        fn add(&self, ws: WsId, _passphrase: &str) -> Result<()> {
            self.0.set(Some(ws));
            Ok(())
        }

        fn get(&self, ws: WsId) -> Option<Zeroizing<String>> {
            self.exists(ws).then(|| Zeroizing::new(ACME.to_string()))
        }

        fn remove(&self, _ws: WsId) -> bool {
            false
        }
    }

    fn not_typed() -> TtyPassphrase {
        TtyPassphrase::new(false).answering("not the passphrase")
    }

    fn never_made(_layout: &Layout, _bundle: &Path, _key: &str) -> Result<()> {
        panic!("a box that keeps nothing has no store")
    }

    // Each make and open here derives a key at 64 MiB once.
    #[test]
    fn the_window_names_the_box_for_making_running_and_removing_it() {
        let dir = TempDir::new("halti-ws-box-window").unwrap();
        let here = Here::at(&dir.0.join("ws"));
        let acme = WsName::parse("acme").unwrap();
        let copies = OneCopy(Cell::new(None));
        new_with(&here, &acme, &TtyPassphrase::new(false).answering(ACME).saving(), &copies).unwrap();
        let found = find(&here, &acme, "scratch").unwrap();
        found.files.create("scratch", SCRATCH).unwrap();
        let world = Fake::answering(true, true);
        let way = |means| Way { world: &world, copies: &copies, means: Some(means), detail: None };
        let sha = sha12(SCRATCH.as_bytes());

        let said = make_with(&here, &found, SCRATCH.as_bytes(), None, false, &way(Means::TouchId), &not_typed, &never_made).unwrap();
        assert_eq!(said.out, ["made box acme/scratch. it keeps nothing between runs. run it with: halti ws run acme/scratch"]);
        assert_eq!(world.calls(), [format!("touch id: [DEV, not protected] make box scratch {sha} in workspace acme")]);
        assert_eq!(found.files.approved_copy("scratch").unwrap().as_deref(), Some(SCRATCH.as_bytes()));

        let said = approve_with(&here, &found, &MountRule::Workspace(Vec::new()), &way(Means::Sudo), &not_typed).unwrap();
        assert_eq!(said.out, ["box scratch in acme was approved already"]);
        assert_eq!(world.calls(), [format!("sudo: [DEV, not protected] approve policies of box scratch {sha} in workspace acme")]);

        let way_to_run = Way { detail: Some("to run box scratch".to_string()), ..way(Means::TouchId) };
        open_for(&here, &found, &way_to_run, "not started", "ws run acme/scratch", &not_typed).unwrap();
        assert_eq!(world.calls(), ["touch id: [DEV, not protected] open workspace acme to run box scratch"]);

        let said = rm_with(&here, &found, None, &way(Means::TouchId), &not_typed).unwrap();
        assert_eq!(said.out[0], "deleted box acme/scratch: its key and its store");
        assert_eq!(world.calls(), ["touch id: [DEV, not protected] remove box scratch from workspace acme"]);
        assert_eq!(found.files.approved_copy("scratch").unwrap(), None, "its approved copy goes with it");
        assert!(found.files.read("scratch").unwrap().is_some(), "its policy stays");

        // A no makes nothing, and says how to type the passphrase instead.
        let no = Fake::answering(false, false);
        let declined = Way { world: &no, copies: &copies, means: Some(Means::TouchId), detail: None };
        let error = make_with(&here, &found, SCRATCH.as_bytes(), None, false, &declined, &not_typed, &never_made).unwrap_err();
        assert_eq!(error.to_string(), "box acme/scratch was not made. to type the passphrase instead: halti ws box new acme/scratch --type");
        assert_eq!(found.files.approved_copy("scratch").unwrap(), None);
    }

    #[test]
    fn a_make_that_fails_once_the_store_is_made_shreds_it() {
        let dir = TempDir::new("halti-ws-box-shred").unwrap();
        let here = Here::at(&dir.0.join("ws"));
        let acme = WsName::parse("acme").unwrap();
        let copies = OneCopy(Cell::new(None));
        new_with(&here, &acme, &TtyPassphrase::new(false).answering(ACME).saving(), &copies).unwrap();
        let found = find(&here, &acme, "dev").unwrap();
        found.layout.prepare().unwrap();
        let world = Fake::answering(true, true);
        let way = Way { world: &world, copies: &copies, means: Some(Means::TouchId), detail: None };
        let next = here.root.join(found.id.to_string()).join("manifest.next");
        // The store is made, then the workspace's new list can't be written: a folder is in its way.
        let create = |_: &Layout, bundle: &Path, _: &str| {
            fs::create_dir_all(bundle)?;
            fs::write(bundle.join("bands"), b"x")?;
            fs::create_dir_all(next.join("in-the-way"))?;
            Ok(())
        };
        let text = b"run = [\"claude\"]\nkeep = true\n";
        assert!(make_with(&here, &found, text, None, true, &way, &not_typed, &create).is_err());
        assert!(next.join("in-the-way").exists(), "it failed after the store was made");
        assert!(!found.layout.bundle("dev").exists(), "the store is shredded");
        assert_eq!(found.files.approved_copy("dev").unwrap(), None);
    }

    #[test]
    fn a_start_s_checks_say_their_kind() {
        let dir = TempDir::new("halti-ws-box-checks").unwrap();
        let here = Here::at(&dir.0.join("ws"));
        let acme = WsName::parse("acme").unwrap();
        new_with(&here, &acme, &TtyPassphrase::new(false).answering(ACME), &OneCopy(Cell::new(None))).unwrap();
        let rule = MountRule::Workspace(Vec::new());
        let refused = |found: &Found| start_check(found, &rule).err().map(|refused| (refused.no, refused.why.to_string()));

        let found = find(&here, &acme, "dev").unwrap();
        assert_eq!(refused(&found), Some((No::Box, "there is no box acme/dev. make one with: halti ws box new acme/dev".to_string())));
        found.files.create("dev", SCRATCH).unwrap();
        assert_eq!(refused(&found), Some((No::Unapproved, "box acme/dev isn't approved. approve it with: halti ws box approve acme/dev".to_string())));
        found.files.keep_approved("dev", b"run = [\"bash\"]\nkeep = false\n").unwrap();
        assert_eq!(refused(&found).unwrap().0, No::Changed);
        found.files.keep_approved("dev", SCRATCH.as_bytes()).unwrap();
        assert_eq!(start_check(&found, &rule).unwrap().0, SCRATCH.as_bytes());

        let kept = find(&here, &acme, "kept").unwrap();
        let text = "run = [\"claude\"]\nkeep = true\n";
        kept.files.create("kept", text).unwrap();
        kept.files.keep_approved("kept", text.as_bytes()).unwrap();
        assert_eq!(refused(&kept), Some((No::Store, "box acme/kept has no store. make one with: halti ws box new acme/kept".to_string())));
        kept.files.create("broken", "run = 1\n").unwrap();
        assert_eq!(refused(&find(&here, &acme, "broken").unwrap()).unwrap().0, No::Failed);
    }

    #[test]
    fn a_target_is_a_workspace_then_a_box() {
        let (name, box_name) = target("acme/dev").unwrap();
        assert_eq!((name.as_str(), box_name), ("acme", "dev"));
        for refused in ["acme", "acme/", "/dev", "Acme/dev", "acme/dev/x", "acme/Dev", "acme/-x", "acme/dev.x", "", &format!("acme/{}", "a".repeat(33))] {
            assert!(target(refused).is_err(), "{refused:?}");
        }
        assert_eq!(target("acme").unwrap_err().to_string(), "use a workspace and a box, e.g. acme/dev");
    }
}
