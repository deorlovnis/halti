//! Boxes: isolated, encrypted places where an agent works (`halti box`).
//!
//! A box has a policy, box/<name>.toml in the config folder, that counts only once approved, like
//! a resource's policy (the same approval records, kept under the Keychain name `box.<name>`:
//! resource names can't contain a dot, so the two never collide). Its data lives in an encrypted
//! store (see `store`) whose key is kept where `[box] keys` says (`KeyStore`): in the Keychain, as
//! the item `box.<name>/_key`, read only to open the store. `run` (see `run`) opens the store,
//! starts the VM on the engine `[box] engine` names (`vms`) and the door, and tears it all down again.
//!
//! What asks the person first is in `[box.approval]`: opening a box, approving its policy, a write
//! its policy says to ask about, copying files out, and deleting it. Each is Touch ID unless the
//! settings say otherwise. Reading its log, importing and signing in ask for Touch ID.
//!
//! The door sees every request (see `door::inspect`): `[net] allow` says which hosts the box may
//! reach, `writes` and `allow_writes` what it may send them besides reads, and `standins` which
//! environment variables hold the stand-in for a site's credential. `[browser]` says whether a
//! site's browser session is kept between runs: sealed in the store's `browser/` folder, which no
//! VM mounts (see `sessions`; `halti box login` signs in by hand, see `login`).

pub mod browser_vm;
mod login;
mod nofollow;
pub(crate) mod run;
pub(crate) mod sessions;
pub(crate) mod store;

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::thread;

use anyhow::{Context, Result, anyhow, bail};
use halti_core::ids::WsName;
use jiff::Timestamp;
use jiff::tz::TimeZone;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::approval::{self, Action};
use crate::chain::{self, Chain};
use crate::config::{Engine, Settings};
use crate::door::inspect::parse_prefix;
use crate::engine::Vms;
use crate::policy::{self, Approval, Mode, Site, Status};
use crate::source::{self, BoxItem, Hint};
use crate::util::{config_dir, expand_home, home, store_root};
use crate::{approve, config, engine, legacy, names, parse_env, parse_resource};
pub use login::login;
use store::Layout;

/// Keychain names of box items start with this. Resource names can't contain a dot.
pub const KEY_PREFIX: &str = "box.";
/// A box's name also names its VM and its socket (104-byte limit), so it stays short.
const MAX_NAME: usize = 32;

pub fn key(name: &str) -> String {
    format!("{KEY_PREFIX}{name}")
}

pub fn parse_name(s: &str) -> Result<String, String> {
    let name = parse_resource(s).map_err(|_| "use lowercase letters, digits and -, e.g. research".to_string())?;
    if name.len() > MAX_NAME {
        return Err(format!("at most {MAX_NAME} characters"));
    }
    Ok(name)
}

pub fn dir() -> PathBuf {
    source::current().box_dir().to_path_buf()
}

pub fn path(name: &str) -> PathBuf {
    dir().join(format!("{name}.toml"))
}

/// Boxes that have a policy file, approved or not.
pub fn names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir())
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".toml").map(str::to_string))
        .filter(|n| parse_name(n).is_ok())
        .collect();
    names.sort();
    names
}

// --- the policy ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoxPolicy {
    #[serde(default)]
    pub about: String,
    /// What `halti box run` starts inside.
    #[serde(default = "default_run")]
    pub run: Vec<String>,
    /// The system inside, pinned by digest: a new image is a policy change.
    pub image: Option<String>,
    /// Resource whose key halti adds to the agent's model calls.
    pub model: Option<String>,
    /// Resources the agent may use through halti; their own policies apply.
    #[serde(default)]
    pub sites: Vec<String>,
    /// Environment variables set to the stand-in (`names::STANDIN`) for tools that refuse to start
    /// without a token (`GH_TOKEN`). The door adds the real credential on the hosts of `sites`.
    #[serde(default)]
    pub standins: Vec<String>,
    /// false: the box is shredded when it stops.
    #[serde(default = "default_keep")]
    pub keep: bool,
    #[serde(default = "default_cpus")]
    pub cpus: u32,
    #[serde(default = "default_memory")]
    pub memory: String,
    /// Docker Engine inside the VM, with the extra capabilities it needs; the agent can use it,
    /// which makes it root in the VM (see `engine::start_docker`). Pulls and containers' traffic
    /// still go through the door, under `[net]`.
    #[serde(default)]
    pub docker: bool,
    /// Rosetta in the VM, for x86-64 programs and images on an Apple silicon Mac: a project's
    /// container that has no arm64 build runs under it. Off unless a box asks.
    #[serde(default)]
    pub rosetta: bool,
    #[serde(default)]
    pub net: Net,
    #[serde(default)]
    pub browser: BrowserPolicy,
    #[serde(default, rename = "mount")]
    pub mounts: Vec<MountPolicy>,
}

/// The sandboxed browser agents get for the `sites` whose own policy allows browsing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserPolicy {
    /// Seal each site's session (cookies and Local Storage) when its browser closes, and start the
    /// next one from it.
    #[serde(default = "default_keep")]
    pub keep_sessions: bool,
    /// Pages may download files; they are saved on the Mac outside the box, never in it.
    #[serde(default)]
    pub downloads: bool,
}

impl Default for BrowserPolicy {
    fn default() -> Self {
        Self { keep_sessions: true, downloads: false }
    }
}

/// Where the agent's own requests may go.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Net {
    /// "*" (any public https site) or patterns like "https://*.wikipedia.org". Empty: nowhere.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Requests other than reads (see `door::inspect`) to hosts no site covers: deny | ask | allow.
    #[serde(default)]
    pub writes: Mode,
    /// URL prefixes (`https://host/path`) that may receive writes whatever `writes` says.
    #[serde(default)]
    pub allow_writes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountPolicy {
    pub path: String,
    /// "clone": the agent works on its own copy in work/. "ro": the folder itself, read-only.
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_run() -> Vec<String> {
    vec!["claude".into()]
}

fn default_keep() -> bool {
    true
}

fn default_cpus() -> u32 {
    4
}

fn default_memory() -> String {
    "8G".into()
}

fn default_mode() -> String {
    "clone".into()
}

impl MountPolicy {
    pub fn host(&self) -> PathBuf {
        expand_home(&self.path)
    }

    /// The folder's name, which is its name inside the box too.
    pub fn name(&self) -> String {
        self.host().file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }

    pub fn readonly(&self) -> bool {
        self.mode == "ro"
    }
}

/// Why a folder can't be handed to a box: it holds halti's own files (its config, its store, the
/// workspaces folder in effect), or everything.
pub fn mount_problem(path: &Path) -> Option<String> {
    mount_problem_among(path, &[config_dir(), store_root(), config::workspaces_in_effect()])
}

/// The same, with `own` as halti's folders. Each is compared as written and as its real path, since
/// a mount is checked both ways too.
fn mount_problem_among(path: &Path, own: &[PathBuf]) -> Option<String> {
    if path == Path::new("/") || path == home() {
        return Some("is too broad".into());
    }
    let mut all = own.iter().cloned().chain(own.iter().filter_map(|dir| fs::canonicalize(dir).ok()));
    all.any(|dir| path.starts_with(&dir) || dir.starts_with(path)).then(|| "holds halti's own files".into())
}

/// Which folders a box may mount, with halti's own folders (`own`) kept out of it either way.
pub enum MountRule {
    /// Today's boxes: any folder but halti's own and everything.
    Guarded(Vec<PathBuf>),
    /// A workspace's boxes: only a folder in the home folder, not the home folder itself, with no
    /// hidden folder on its way and not in ~/Library, as written and as its real path. Hidden
    /// folders hold other clients' credentials (~/.ssh, ~/.claude, ~/.config), ~/Library the stores
    /// of running boxes and the Keychains, and outside the home folder are other users' sockets and
    /// mounted disks: a rule that allows names them all, where a list that refuses would miss the
    /// next one.
    Workspace(Vec<PathBuf>),
}

impl MountRule {
    /// Today's rule with halti's folders as the settings say: the config folder, the store root and
    /// the workspaces folder.
    pub fn guarded(settings: &Settings) -> MountRule {
        MountRule::Guarded(own_folders(settings))
    }

    /// A workspace's rule, with the same folders of halti's kept out.
    pub fn workspace(settings: &Settings) -> MountRule {
        MountRule::Workspace(own_folders(settings))
    }

    fn in_workspace(&self) -> bool {
        matches!(self, MountRule::Workspace(_))
    }
}

fn own_folders(settings: &Settings) -> Vec<PathBuf> {
    vec![config_dir(), store_root(), settings.workspaces.path.clone()]
}

/// Why a folder can't be handed to a box under `rule`, if it can't.
pub fn mount_problem_in(path: &Path, rule: &MountRule) -> Option<String> {
    match rule {
        MountRule::Guarded(own) => mount_problem_among(path, own),
        MountRule::Workspace(own) => outside_plain_home(path, &home()).or_else(|| mount_problem_among(path, own)),
    }
}

/// Why `path` isn't a plain folder in `home` (one with no hidden folder on its way and not in
/// Library, nor `home` itself), as written or as its real path, if it isn't. A path that isn't
/// there is checked as written only; a run checks its real path once it is.
fn outside_plain_home(path: &Path, home: &Path) -> Option<String> {
    let plain = |path: &Path, home: &Path| {
        let Ok(rest) = path.strip_prefix(home) else { return false };
        let mut parts = rest.components().peekable();
        let library = matches!(parts.peek(), Some(Component::Normal(first)) if first.to_string_lossy().eq_ignore_ascii_case("Library"));
        !library && parts.peek().is_some() && parts.all(|part| matches!(part, Component::Normal(name) if !name.to_string_lossy().starts_with('.')))
    };
    let real = match fs::canonicalize(path) {
        Ok(real) => plain(&real, &fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf())),
        Err(_) => true,
    };
    (!(plain(path, home) && real)).then(|| "a box in a workspace mounts only folders in your home that aren't hidden and aren't in ~/Library".into())
}

/// The rule a policy's mounts are checked against.
enum Mounts<'a> {
    /// Today's, with the workspaces folder in effect read when a mount is checked.
    Today,
    Under(&'a MountRule),
}

impl BoxPolicy {
    pub fn parse(text: &str) -> Result<Self> {
        Self::parse_with(text, Mounts::Today)
    }

    /// As `parse`, with the mounts checked against `rule`.
    pub fn parse_in(text: &str, rule: &MountRule) -> Result<Self> {
        Self::parse_with(text, Mounts::Under(rule))
    }

    /// Under a workspace's rule the text must also be plain, as any policy approved in a workspace
    /// is (`policy::plain_text`).
    fn parse_with(text: &str, mounts: Mounts<'_>) -> Result<Self> {
        if matches!(mounts, Mounts::Under(rule) if rule.in_workspace()) {
            policy::plain_text(text.as_bytes())?;
        }
        let policy: BoxPolicy = toml::from_str(text)?;
        policy.validate(mounts)?;
        Ok(policy)
    }

    /// `[net] allow` in the form the door matches against.
    pub fn allow(&self) -> Vec<String> {
        self.net.allow.iter().filter_map(|e| Site::parse(e).ok()).map(|s| s.text()).collect()
    }

    fn validate(&self, rule: Mounts<'_>) -> Result<()> {
        if self.run.is_empty() || self.run.iter().any(|a| a.is_empty()) {
            bail!("run must be a command, e.g. [\"claude\"]");
        }
        if let Some(image) = &self.image {
            let pinned = image.split_once("@sha256:").is_some_and(|(name, digest)| {
                !name.is_empty()
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
                    && digest.len() == 64
                    && digest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            });
            if !pinned {
                bail!("image must be pinned by digest, like {}@sha256:<64 hex digits>", names::AGENT_IMAGE);
            }
        }
        if let Some(model) = &self.model {
            parse_resource(model).map_err(|e| anyhow!("model '{model}': {e}"))?;
        }
        let mut seen = BTreeSet::new();
        for site in &self.sites {
            parse_resource(site).map_err(|e| anyhow!("sites: '{site}': {e}"))?;
            if !seen.insert(site) {
                bail!("sites lists {site} twice");
            }
        }
        let reserved: BTreeSet<String> = [true, false].into_iter().flat_map(engine::agent_env).map(|(name, _)| name).collect();
        for name in &self.standins {
            parse_env(name).map_err(|e| anyhow!("standins: '{name}': {e}"))?;
            if reserved.contains(name) {
                bail!("standins: {name} is set by halti already");
            }
            if self.standins.iter().filter(|n| *n == name).count() > 1 {
                bail!("standins lists {name} twice");
            }
        }
        if !(1..=64).contains(&self.cpus) {
            bail!("cpus must be between 1 and 64");
        }
        let digits = self.memory.strip_suffix(['M', 'G']).unwrap_or("");
        if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.bytes().all(|b| b == b'0') {
            bail!("memory must be like 8G or 512M");
        }
        for entry in &self.net.allow {
            let site = Site::parse(entry).map_err(|e| anyhow!("[net] allow '{entry}': {e}"))?;
            // The door connects to port 443 only.
            let text = site.text();
            let https_only = text == "*" || (text.starts_with("https://") && url::Url::parse(&text).map_or(true, |u| u.port().is_none()));
            if !https_only {
                bail!("[net] allow '{entry}': https sites on the default port only");
            }
        }
        for entry in &self.net.allow_writes {
            parse_prefix(entry).map_err(|e| anyhow!("[net] allow_writes '{entry}': {e}"))?;
        }
        let mut names = BTreeSet::new();
        let in_workspace = matches!(rule, Mounts::Under(rule) if rule.in_workspace());
        for m in &self.mounts {
            match m.mode.as_str() {
                "clone" | "ro" => {}
                // A workspace's box has no export yet.
                "rw" if in_workspace => bail!("[[mount]] {}: rw isn't available, a box can't change your files; use clone", m.path),
                "rw" => bail!("[[mount]] {}: rw isn't available, a box can't change your files; use clone and `halti box export`", m.path),
                other => bail!("[[mount]] {}: mode '{other}' isn't clone or ro", m.path),
            }
            let host = m.host();
            if !host.is_absolute() || host.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
                bail!("[[mount]] path '{}' must be absolute or start with ~/, without . or ..", m.path);
            }
            match &rule {
                Mounts::Today => {
                    if let Some(why) = mount_problem(&host) {
                        bail!("[[mount]] path '{}' {why}", m.path);
                    }
                }
                Mounts::Under(rule @ MountRule::Guarded(_)) => {
                    if let Some(why) = mount_problem_in(&host, rule) {
                        bail!("[[mount]] path '{}' {why}", m.path);
                    }
                }
                Mounts::Under(rule @ MountRule::Workspace(_)) => {
                    if let Some(why) = mount_problem_in(&host, rule) {
                        bail!("[[mount]] {}: {why}", m.path);
                    }
                }
            }
            let name = m.name();
            if name.is_empty() || name.starts_with('.') || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
                bail!("[[mount]] path '{}': the folder's name must be letters, digits, . _ - and not start with a dot", m.path);
            }
            if !names.insert(name.clone()) {
                bail!("two [[mount]] folders are named {name}");
            }
        }
        Ok(())
    }
}

fn template(name: &str, image: Option<&str>) -> String {
    let image = image.map_or_else(
        || format!("# image = \"{}@sha256:...\"       # the system inside, pinned: build it with install.sh, then paste its digest", names::AGENT_IMAGE),
        |digest| format!("image = \"{digest}\"                  # the system inside, pinned: a new image is a policy change"),
    );
    format!(
        r#"# halti box policy for {name}. It takes effect only once approved: halti box approve {name}
about = ""
run = ["claude"]                        # what `halti box run {name}` starts
{image}
model = "anthropic"                     # resource whose key halti adds to the agent's model calls
sites = []                              # resources the agent may use through halti; their policies apply
# standins = ["GH_TOKEN"]               # variables set to "{standin}" for tools that insist on a token; halti adds the real credential on the hosts of `sites`
keep = true                            # false: the box is shredded when it stops
# docker = true                         # Docker Engine in the VM; it makes the agent root in the VM, which stays the boundary
# rosetta = true                        # Rosetta in the VM, for x86-64 images with no arm64 build
cpus = 4
memory = "8G"

[browser]                               # the sandboxed browser, for `sites` whose own policy has a [browse] section
# keep_sessions = true                  # seal each site's session when its browser closes, so the next one starts signed in (`halti box login {name}` signs in by hand)
# downloads = false                     # true: pages may download files, kept on the Mac outside the box (`halti box import` brings one in)

[net]                                   # where the agent's own requests may go; nothing else is reachable
allow = ["*"]                           # any public https site, reads only (see writes); or a list like ["https://*.wikipedia.org"], or [] for nowhere
writes = "deny"                         # anything but a read (GET, HEAD, OPTIONS, a fetch or clone) to a host no `sites` entry covers: deny | ask (Touch ID each) | allow
# allow_writes = ["https://api.example.com/search"]   # URL prefixes that may receive writes anyway

# [[mount]]                             # holes in the box: none unless listed
# path = "~/Git/project"
# mode = "clone"                        # clone: the agent works on its own copy in work/ | ro: read-only
"#,
        standin = names::STANDIN
    )
}

/// The box template for a workspace: today's fields, with hints naming `halti ws …`, and no lines
/// for signing in, importing or exporting, which a workspace's boxes don't have yet.
pub fn workspace_template(ws: &WsName, name: &str, image: Option<&str>) -> String {
    let image = image.map_or_else(
        || format!("# image = \"{}@sha256:...\"       # the system inside, pinned: build it with install.sh, then paste its digest", names::AGENT_IMAGE),
        |digest| format!("image = \"{digest}\"                  # the system inside, pinned: a new image is a policy change"),
    );
    format!(
        r#"# The policy of box {name} in workspace {ws}. It takes effect only once approved: halti ws box approve {ws}/{name}
about = ""
run = ["claude"]                        # what `halti ws run {ws}/{name}` starts
{image}
model = "anthropic"                     # resource of {ws} whose key halti adds to the agent's model calls
sites = []                              # resources of {ws} the agent may use through halti; their policies apply
# standins = ["GH_TOKEN"]               # variables set to "{standin}" for tools that insist on a token; halti adds the real credential on the hosts of `sites`
keep = true                            # false: the box is shredded when it stops
# docker = true                         # Docker Engine in the VM; it makes the agent root in the VM, which stays the boundary
# rosetta = true                        # Rosetta in the VM, for x86-64 images with no arm64 build
cpus = 4
memory = "8G"

[browser]                               # the sandboxed browser, for `sites` whose own policy has a [browse] section
# keep_sessions = true                  # seal each site's session when its browser closes, so the next one starts signed in
# downloads = false                     # true: pages may download files, kept on the Mac outside the box

[net]                                   # where the agent's own requests may go; nothing else is reachable
allow = ["*"]                           # any public https site, reads only (see writes); or a list like ["https://*.wikipedia.org"], or [] for nowhere
writes = "deny"                         # anything but a read (GET, HEAD, OPTIONS, a fetch or clone) to a host no `sites` entry covers: deny | ask (Touch ID each) | allow
# allow_writes = ["https://api.example.com/search"]   # URL prefixes that may receive writes anyway

# [[mount]]                             # holes in the box: none unless listed; only folders in your home that aren't hidden and aren't in ~/Library
# path = "~/Git/project"
# mode = "clone"                        # clone: the agent works on its own copy in work/ | ro: read-only
"#,
        standin = names::STANDIN
    )
}

// --- approval ---

/// The approved policy of a box and its text, or why there is none.
fn load(name: &str) -> Result<(BoxPolicy, String)> {
    let p = path(name);
    let text = policy::approved_at(&key(name), &p).map_err(|why| not_approved(name, &why))?;
    let policy = BoxPolicy::parse(&text).with_context(|| p.display().to_string())?;
    Ok((policy, text))
}

fn not_approved(name: &str, why: &Status) -> anyhow::Error {
    match why {
        Status::Missing => anyhow!("there is no box {name} (create it with: halti box new {name})"),
        Status::Unapproved => anyhow!("the policy for box {name} isn't approved (halti box approve {name})"),
        Status::Changed => anyhow!("the policy for box {name} changed since it was approved (halti box approve {name})"),
        Status::Approved => anyhow!("box {name} is approved"),
    }
}

/// Read, check and show a box policy for approval; what is shown is exactly what gets pinned.
pub fn prepare(name: &str) -> Result<(String, Approval)> {
    let p = path(name);
    let text = fs::read_to_string(&p).map_err(|_| not_approved(name, &Status::Missing))?;
    BoxPolicy::parse(&text).with_context(|| p.display().to_string())?;
    let approval = Approval::of(&text);
    println!("Policy for box {name} ({}):\n\n{}\n\nsha256 {}\n", p.display(), text.trim_end(), approval.short());
    Ok((key(name), approval))
}

pub fn approve(names_given: &[String]) -> Result<()> {
    approve_with(&config::settings(), names_given)
}

/// Approves the boxes' policies as `[box.approval] policy` says.
fn approve_with(settings: &Settings, names_given: &[String]) -> Result<()> {
    let given = if names_given.is_empty() { names() } else { names_given.to_vec() };
    if given.is_empty() {
        bail!("there are no boxes (create one with: halti box new NAME)");
    }
    let prepared = given.iter().map(|n| prepare(n)).collect::<Result<_>>()?;
    policy::approve_prepared(prepared, settings)
}

/// Asks for a box's `action` as `[box.approval]` says. No box action takes a passphrase, so what is
/// granted is a yes.
fn ask_for(world: &dyn approval::World, settings: &Settings, action: Action, reason: &str) -> Result<()> {
    approval::approve_with(world, settings, action, reason).map(drop)
}

// --- what the settings pick ---

/// The engine `[box] engine` names: the one place a box's engine is picked. Another engine is one
/// more variant of `config::Engine` and one more arm here.
pub(crate) fn vms(settings: &Settings) -> Result<&'static dyn Vms> {
    match settings.engine {
        Some(Engine::Container) => Ok(&engine::Container),
        None => bail!("boxes can't run on this system: halti has no box engine for it"),
    }
}

/// Where box keys are kept (see `Keys`): the one place a box's store key is read, written and
/// deleted. Another keeper `[box] keys` can name is one more variant of `config::Keys`, and another
/// place that keeps its own is one more `Keys` variant; each is one more arm in each method.
#[derive(Clone, Copy)]
struct KeyStore(Keys);

/// Where a box's key is: where `[box] keys` says, or the chosen place's when it keeps box keys
/// itself, as a workspace does, whatever the settings say.
#[derive(Clone, Copy)]
enum Keys {
    Settings(Option<config::Keys>),
    Place,
}

impl KeyStore {
    fn of(settings: &Settings) -> KeyStore {
        if source::current().keeps_box_keys() {
            return KeyStore(Keys::Place);
        }
        KeyStore(Keys::Settings(settings.keys))
    }

    fn get(self, name: &str) -> Option<String> {
        match self.0 {
            Keys::Settings(Some(config::Keys::Keychain)) | Keys::Place => source::current().box_item(name, BoxItem::Key),
            Keys::Settings(None) => None,
        }
    }

    /// Whether there is one, without reading it.
    fn exists(self, name: &str) -> bool {
        match self.0 {
            Keys::Settings(Some(config::Keys::Keychain)) | Keys::Place => source::current().has_box_item(name, BoxItem::Key),
            Keys::Settings(None) => false,
        }
    }

    fn set(self, name: &str, value: &str) -> Result<()> {
        match self.0 {
            Keys::Settings(Some(config::Keys::Keychain)) | Keys::Place => source::current().set_box_item(name, BoxItem::Key, value),
            Keys::Settings(None) => bail!("a box's key can't be kept on this system"),
        }
    }

    fn delete(self, name: &str) -> bool {
        match self.0 {
            Keys::Settings(Some(config::Keys::Keychain)) | Keys::Place => source::current().remove_box_item(name, BoxItem::Key),
            Keys::Settings(None) => false,
        }
    }

    /// Where a key is, as halti says it.
    fn place(self) -> &'static str {
        match self.0 {
            Keys::Settings(Some(config::Keys::Keychain)) => "in the Keychain",
            Keys::Settings(None) => "anywhere on this system",
            Keys::Place => "in its workspace",
        }
    }

    /// The box's store key, or why its store can't be opened.
    fn open_key(self, name: &str) -> Result<String> {
        self.get(name).ok_or_else(|| anyhow!("the key of box {name} isn't {}, so its store can't be opened ({})", self.place(), source::current().hint(Hint::RemoveBox(name))))
    }
}

// --- commands ---

// STUB: replaced at merge by seal::derive (one key per purpose, derived from the box key)
fn derive(box_key: &[u8], purpose: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(legacy::LOG_KEY_LABEL);
    hash.update(purpose.as_bytes());
    hash.update(b"\0");
    hash.update(box_key);
    hash.finalize().into()
}

/// The key that chains the box's log (`door.log`), derived from the box key; `key` is the box
/// key as the Keychain holds it.
fn log_key(key: &str) -> [u8; 32] {
    derive(key.as_bytes(), "log")
}

/// Note which sites of the box have a sealed session (names only).
fn keep_session_names(name: &str, sites: &[String]) -> Result<()> {
    if sites.is_empty() {
        source::current().remove_box_item(name, BoxItem::Sessions);
        return Ok(());
    }
    source::current().set_box_item(name, BoxItem::Sessions, &sites.join(","))
}

/// The sites of the box that had a sealed session when it was last put away.
fn session_names(name: &str) -> Vec<String> {
    source::current().box_item(name, BoxItem::Sessions).map(|s| s.split(',').filter(|n| !n.is_empty()).map(str::to_string).collect()).unwrap_or_default()
}

/// Make a box: its policy (edited from a template), a key where `[box] keys` says and an empty store.
pub fn new(name: &str) -> Result<()> {
    let settings = config::settings();
    let keys = KeyStore::of(&settings);
    let layout = Layout::real()?;
    let (p, bundle, k) = (path(name), layout.bundle(name), key(name));
    match (keys.exists(name), bundle.exists()) {
        (true, true) => bail!("box {name} exists (halti box edit {name} changes its policy)"),
        (false, true) => bail!("box {name} has a store but no key, so it can't be opened: remove it with halti box rm {name}"),
        _ => {}
    }
    if !p.exists() {
        fs::create_dir_all(dir())?;
        // The pinned image of the engine's agent system, if there is one yet.
        let image = vms(&settings).ok().and_then(|vms| vms.image_digest(engine::AGENT_IMAGE).ok());
        fs::write(&p, template(name, image.as_deref()))?;
    }
    let edited = policy::edit_file(&k, &p, |text| BoxPolicy::parse(text).map(drop))?;
    if BoxPolicy::parse(&fs::read_to_string(&p)?)?.keep {
        let created = !keys.exists(name);
        if created {
            keys.set(name, &store::new_key()?)?;
        }
        let made = keys.get(name).ok_or_else(|| anyhow!("the key of box {name} can't be read"));
        if let Err(e) = made.and_then(|key| store::create(&layout, &bundle, &key)) {
            if created {
                keys.delete(name);
            }
            return Err(e);
        }
        println!("created box {name}: an empty encrypted store, its key {}", keys.place());
    } else {
        println!("created box {name}: keep = false, so every run gets a new store that is shredded when it stops");
    }
    if edited || !matches!(policy::status_of(&k, &p), Status::Approved) {
        policy::offer_approval(&p, &format!("halti box approve {name}"), || approve_with(&settings, &[name.to_string()]))?;
    }
    Ok(())
}

pub fn edit(name: &str) -> Result<()> {
    let p = path(name);
    if !p.exists() {
        return Err(not_approved(name, &Status::Missing));
    }
    if policy::edit_file(&key(name), &p, |text| BoxPolicy::parse(text).map(drop))? {
        policy::offer_approval(&p, &format!("halti box approve {name}"), || approve(&[name.to_string()]))?;
    }
    Ok(())
}

/// `halti box run`: open the box (or join it if it runs), and work in it until it ends.
pub fn run(name: &str, temp: bool, command: Vec<String>) -> Result<u8> {
    let (policy, text) = load(name)?;
    let settings = config::settings();
    let vms = vms(&settings)?;
    let layout = Layout::real()?;
    let persistent = policy.keep && !temp;
    if persistent && !layout.bundle(name).exists() {
        bail!("box {name} has no store (create one with: halti box new {name})");
    }
    let id = if temp { format!("{name}-tmp-{}", &store::new_key()?[..8]) } else { name.to_string() };
    if temp {
        println!("temporary box {id}: shredded when it stops");
    }
    run::catch_signals();
    let request = run::Request {
        name,
        id,
        policy: &policy,
        policy_sha: crate::util::sha256_hex(text.as_bytes()),
        persistent,
        unique: temp,
        command: (!command.is_empty()).then_some(command),
        tty: crate::interactive(),
        stop: run::signalled(),
        write: settings.means(Action::BoxWrite),
        shown: name.to_string(),
        stop_with: format!("halti box stop {name}"),
        mounts: MountRule::guarded(&settings),
        confirm: true,
    };
    run_request(&layout, vms, &settings, &request)
}

/// Today's run of a box, and a workspace's: the engine, the key where `KeyStore::of` finds it, and
/// the settings read for this run.
fn run_request(layout: &Layout, vms: &'static dyn Vms, settings: &Settings, request: &run::Request<'_>) -> Result<u8> {
    run::run(layout, &run::Real { vms, keys: KeyStore::of(settings), settings }, request)
}

/// A workspace's box to start, as `ws run` found it before the workspace was opened: what `run_in`
/// needs once `main` has chosen the workspace as the place.
pub struct Start {
    /// The settings read once, before the choice.
    pub settings: Settings,
    pub vms: &'static dyn Vms,
    pub layout: Layout,
    /// The box's name, and as messages name it: `acme/dev`.
    pub name: String,
    pub shown: String,
    /// The policy file's bytes, read once, and what they parse to under `mounts`.
    pub text: Vec<u8>,
    pub policy: BoxPolicy,
    pub mounts: MountRule,
    pub command: Option<Vec<String>>,
}

/// A second terminal's way into a workspace's box that runs: the engine and the files its opener
/// noted, nothing else (`run::join`).
pub struct Join {
    pub vms: &'static dyn Vms,
    pub layout: Layout,
    pub name: String,
    pub shown: String,
    /// The policy file's bytes, read once.
    pub text: Vec<u8>,
    pub mounts: MountRule,
    pub command: Option<Vec<String>>,
}

/// Runs a workspace's box once `main` has chosen its workspace. The box's approval must approve the
/// text `ws run` read, and a box that keeps a store must have its key in the workspace: both read
/// through the place. Then today's run, with no question: opening the workspace was the approval.
pub fn run_in(start: Start) -> Result<u8> {
    let Start { settings, vms, layout, name, shown, text, policy, mounts, command } = start;
    let approve = format!("halti ws box approve {shown}");
    match policy::status_of_text(&key(&name), &text) {
        Status::Approved => {}
        Status::Changed => bail!("the policy of box {shown} changed since it was approved. approve it with: {approve}"),
        Status::Unapproved | Status::Missing => bail!("box {shown} isn't approved. approve it with: {approve}"),
    }
    if policy.keep && !KeyStore::of(&settings).exists(&name) {
        bail!("box {shown} has a store but no key. remove it with: {}", source::current().hint(Hint::RemoveBox(&name)));
    }
    run::catch_signals();
    let request = run::Request {
        name: &name,
        id: name.clone(),
        policy: &policy,
        policy_sha: crate::util::sha256_hex(&text),
        persistent: policy.keep,
        unique: false,
        command,
        tty: crate::interactive(),
        stop: run::signalled(),
        write: settings.means(Action::BoxWrite),
        stop_with: format!("halti ws stop {shown}"),
        shown,
        mounts,
        confirm: false,
    };
    run_request(&layout, vms, &settings, &request)
}

/// Joins a workspace's box that runs: no place, no question (`run::join`).
pub fn join_in(join: Join) -> Result<u8> {
    run::join(&join.layout, join.vms, &join.name, &join.shown, &join.mounts, &join.text, join.command.as_deref(), crate::interactive())
}

pub fn stop(name: &str) -> Result<()> {
    let vms = vms(&config::settings())?;
    let layout = Layout::real()?;
    let running: Vec<String> = [run::vm_name(name)].into_iter().filter(|vm| vms.running(vm)).collect();
    for vm in &running {
        vms.stop(vm)?;
    }
    let was_running = !running.is_empty();
    let lock = layout.lock(name);
    if lock.exists() {
        // The halti that runs the box shuts it down; when it lets go, nothing is left to clean.
        // If it died, what it left (a mounted store) is cleaned here.
        for _ in 0..60 {
            if let Some(_held) = store::lock(&lock)? {
                run::sweep(&layout, name)?;
                break;
            }
            thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    if was_running {
        println!("stopped box {name}");
        Ok(())
    } else {
        bail!("box {name} isn't running")
    }
}

/// Run `f` on the open store. A store that is closed is opened (and closed again) once `ask` says
/// yes, with its key from where `keys` are kept. One that a run has open can be read, not changed:
/// `readonly`.
fn with_store<T>(name: &str, keys: KeyStore, ask: impl FnOnce() -> Result<()>, readonly: bool, f: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    let layout = Layout::real()?;
    layout.prepare()?;
    let bundle = layout.bundle(name);
    if !bundle.exists() {
        bail!("box {name} has no store (halti box new {name})");
    }
    let mnt = layout.mount_point(name);
    let Some(_lock) = store::lock(&layout.lock(name))? else {
        if !readonly {
            bail!("box {name} is running: stop it first (halti box stop {name}), so nothing changes a folder its VM has mounted");
        }
        if !store::is_mounted(&mnt) {
            bail!("box {name} is being opened or closed: try again in a moment");
        }
        return f(&mnt);
    };
    ask()?;
    let key = keys.open_key(name)?;
    let open = store::open(&bundle, &mnt, &key, readonly)?;
    f(open.path())
}

/// What the door and halti did for a box, latest last. With `verify`, checks the whole log
/// against its chain instead, and fails naming the first line that was changed or removed.
pub fn log(name: &str, last: usize, verify: bool) -> Result<()> {
    let keys = KeyStore::of(&config::settings());
    let ask = || approve::confirm(&format!("read the log of box {name}"));
    with_store(name, keys, ask, true, |mnt| {
        if verify {
            let chain = Chain::new(&store::door_log(mnt), log_key(&keys.open_key(name)?));
            let found = chain.verify().with_context(|| format!("the log of box {name}"))?;
            let head = source::current().box_item(name, BoxItem::LogHead).and_then(|h| serde_json::from_str::<chain::Head>(&h).ok());
            if let Some(head) = &head {
                found.check(head).with_context(|| format!("the log of box {name}"))?;
            }
            let before = if found.unchained > 0 { format!(" ({} older lines from before the log was chained can't be checked)", found.unchained) } else { String::new() };
            println!("{} lines, chain intact{before}", found.chained);
            return Ok(());
        }
        let text = fs::read_to_string(store::door_log(mnt)).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        for line in &lines[lines.len().saturating_sub(last)..] {
            println!("{line}");
        }
        if lines.is_empty() {
            println!("nothing logged yet");
        }
        Ok(())
    })
}

/// A file taken out of a box.
struct Exported {
    file: PathBuf,
    size: u64,
    sha256: String,
}

fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path)?;
    let (mut hash, mut buf, mut size) = (Sha256::new(), vec![0u8; 1 << 16], 0);
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hash.finalize().iter().map(|b| format!("{b:02x}")).collect(), size))
}

/// A path inside the box, as typed: relative, going nowhere but down.
fn box_path(rel: &str) -> Result<PathBuf> {
    let rel = Path::new(rel);
    if rel.as_os_str().is_empty() || !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        bail!("give a path inside the box, like work/report.md (no leading /, . or ..)");
    }
    Ok(rel.to_path_buf())
}

/// Copy `rel` out of the open store into `to`. A path that resolves outside the store (a link the
/// agent made) is refused, and links inside a folder are skipped.
fn export_from(mnt: &Path, rel: &str, to: &Path) -> Result<(Vec<Exported>, usize)> {
    let rel = box_path(rel)?;
    let src = mnt.join(&rel);
    let real = fs::canonicalize(&src).map_err(|_| anyhow!("{} isn't in the box", rel.display()))?;
    if !real.starts_with(fs::canonicalize(mnt)?) {
        bail!("{} leads out of the box", rel.display());
    }
    let to = fs::canonicalize(to).with_context(|| format!("{} isn't a folder", to.display()))?;
    if !to.is_dir() {
        bail!("{} isn't a folder", to.display());
    }
    let dst = to.join(rel.file_name().expect("a normal component"));
    let copied = store::copy_tree(&src, &dst)?;
    let single = src.is_file();
    let mut out = Vec::new();
    for file in copied.files {
        let (sha256, size) = sha256_file(&if single { dst.clone() } else { dst.join(&file) })?;
        out.push(Exported { file: if single { rel.clone() } else { rel.join(file) }, size, sha256 });
    }
    Ok((out, copied.skipped))
}

pub fn export(name: &str, rel: &str, to: &Path) -> Result<()> {
    box_path(rel)?;
    let settings = config::settings();
    let keys = KeyStore::of(&settings);
    let reason = format!("export {rel} from box {name} to {}", to.display());
    let ask = || ask_for(&approval::Real, &settings, Action::BoxExport, &reason);
    with_store(name, keys, ask, false, |mnt| {
        let log_key = log_key(&keys.open_key(name)?);
        let (files, skipped) = export_from(mnt, rel, to)?;
        let mut total = 0;
        for f in &files {
            println!("{:>10}  {}  {}", human(f.size), f.sha256, f.file.display());
            store::log_event(mnt, &log_key, "export", &f.file.display().to_string(), f.size, "allowed")?;
            total += f.size;
        }
        let links = if skipped > 0 { format!(" ({skipped} links and special files skipped)") } else { String::new() };
        println!("exported {} file(s), {}, to {}{links}", files.len(), human(total), to.display());
        Ok(())
    })
}

pub fn import(name: &str, from: &str) -> Result<()> {
    let src = expand_home(from);
    let file_name = src.file_name().map(|n| n.to_os_string()).ok_or_else(|| anyhow!("{from} isn't a file or folder"))?;
    let keys = KeyStore::of(&config::settings());
    let ask = || approve::confirm(&format!("import {} into box {name}", src.display()));
    with_store(name, keys, ask, false, |mnt| {
        let log_key = log_key(&keys.open_key(name)?);
        let dst = mnt.join("work").join(&file_name);
        let copied = store::copy_tree(&src, &dst)?;
        let rel = Path::new("work").join(&file_name);
        store::log_event(mnt, &log_key, "import", &rel.display().to_string(), 0, "allowed")?;
        println!("imported {} file(s) into {}", copied.files.len(), rel.display());
        Ok(())
    })
}

pub fn rm(name: &str) -> Result<()> {
    let settings = config::settings();
    let keys = KeyStore::of(&settings);
    let layout = Layout::real()?;
    let (p, bundle, k) = (path(name), layout.bundle(name), key(name));
    if !p.exists() && !bundle.exists() && !keys.exists(name) {
        bail!("there is no box {name}");
    }
    let lock = layout.lock(name);
    layout.prepare()?;
    let Some(_held) = store::lock(&lock)? else {
        bail!("box {name} is running: stop it first (halti box stop {name})");
    };
    ask_for(&approval::Real, &settings, Action::BoxDelete, &format!("delete box {name}: its data can never be read again"))?;
    // The key goes first: without it the store is noise, whatever happens to the files.
    keys.delete(name);
    source::current().remove_box_item(name, BoxItem::LogHead);
    source::current().remove_box_item(name, BoxItem::Sessions);
    policy::revoke(&k)?;
    store::shred(&bundle)?;
    run::sweep(&layout, name)?;
    println!("deleted box {name}: its key and its store");
    if p.exists() {
        println!("kept its policy {} (halti box new {name} makes a fresh box from it)", p.display());
    }
    println!(
        "Time Machine may still hold encrypted copies of the store (and APFS local snapshots for about a day). \
         They stay closed unless restored together with a Keychain from before this, which has the old key."
    );
    Ok(())
}

pub(crate) fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let (mut value, mut unit) = (bytes as f64, 0);
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

pub fn ls() -> Result<()> {
    let layout = Layout::real()?;
    println!("{:<20} {:<9} {:<22} {:>9}  {:<17} {:<24} {:<16} ABOUT", "BOX", "STATE", "POLICY", "SIZE", "LAST USED", "SITES", "SESSIONS");
    let mut shown = names();
    // Stores whose policy file is gone.
    for entry in fs::read_dir(&layout.root).into_iter().flatten().flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        if let Some(name) = file.strip_suffix(".sparsebundle").filter(|n| !shown.iter().any(|s| s == n)) {
            shown.push(name.to_string());
        }
    }
    for name in &shown {
        let bundle = layout.bundle(name);
        let parsed = fs::read_to_string(path(name)).ok().and_then(|t| BoxPolicy::parse(&t).ok());
        let held = store::is_held(&layout.lock(name));
        let state = match (held, bundle.exists(), parsed.as_ref().is_some_and(|p| !p.keep)) {
            (true, _, _) => "open",
            (false, true, _) => "locked",
            (false, false, true) => "shredded",
            (false, false, false) => "no store",
        };
        let status = if path(name).exists() { policy::status_of(&key(name), &path(name)).text() } else { "no policy" };
        let (bytes, used) = if bundle.exists() { store::usage(&bundle) } else { (0, None) };
        let used = used.and_then(|t| Timestamp::try_from(t).ok()).map_or("-".to_string(), |t| t.to_zoned(TimeZone::system()).strftime("%Y-%m-%d %H:%M").to_string());
        let sites = parsed.as_ref().map_or(String::new(), |p| p.sites.join(", "));
        let about = parsed.as_ref().map_or("", |p| p.about.as_str());
        let size = if bundle.exists() { human(bytes) } else { "-".into() };
        let sessions = session_names(name).join(", ");
        println!("{name:<20} {state:<9} {status:<22} {size:>9}  {used:<17} {sites:<24} {sessions:<16} {about}");
    }
    // Temporary boxes that are running.
    for entry in fs::read_dir(layout.open_dir()).into_iter().flatten().flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = file.strip_suffix(".lock").filter(|id| id.contains("-tmp-")) else { continue };
        if store::is_held(&entry.path()) {
            println!("{id:<20} {:<9} {:<22} {:>9}  {:<17} {:<24} {:<16} temporary", "open", "-", "-", "-", "", "");
        }
    }
    if shown.is_empty() {
        println!("(no boxes: halti box new NAME)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use halti_core::platform::Os;

    use super::*;
    use crate::approval::fake_tests::Fake;
    use crate::parse_field;
    use crate::util::TempDir;

    const DIGEST: &str = "agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn err(text: &str) -> String {
        format!("{:#}", BoxPolicy::parse(text).err().unwrap_or_else(|| panic!("accepted: {text}")))
    }

    #[test]
    fn parses_a_full_policy() {
        let p = BoxPolicy::parse(&format!(
            r#"
            about = "Market research"
            run = ["claude", "--dangerously-skip-permissions"]
            image = "{DIGEST}"
            model = "anthropic"
            sites = ["github", "app"]
            keep = false
            cpus = 2
            memory = "512M"

            standins = ["GH_TOKEN", "NPM_TOKEN"]

            [net]
            allow = ["*", "https://*.wikipedia.org", "https://docs.rs", "https://Example.com"]
            writes = "ask"
            allow_writes = ["https://api.example.com/search", "https://docs.rs"]

            [[mount]]
            path = "~/Git/halti"

            [[mount]]
            path = "/opt/data/"
            mode = "ro"
            "#
        ))
        .unwrap();
        assert_eq!((p.keep, p.cpus, p.memory.as_str(), p.docker), (false, 2, "512M", false));
        assert!(BoxPolicy::parse("docker = true").unwrap().docker);
        assert!(!p.rosetta && BoxPolicy::parse("rosetta = true").unwrap().rosetta);
        assert_eq!(p.allow(), ["*", "https://*.wikipedia.org", "https://docs.rs", "https://example.com"]);
        assert_eq!((p.net.writes, p.net.allow_writes.len(), p.standins.as_slice()), (Mode::Ask, 2, &["GH_TOKEN".to_string(), "NPM_TOKEN".to_string()][..]));
        assert_eq!(BoxPolicy::parse("[net]\nwrites = \"allow\"").unwrap().net.writes, Mode::Allow);
        assert_eq!((p.mounts[0].name(), p.mounts[0].readonly()), ("halti".to_string(), false));
        assert_eq!((p.mounts[1].name(), p.mounts[1].readonly()), ("data".to_string(), true));
    }

    #[test]
    fn an_empty_policy_is_a_closed_box() {
        let p = BoxPolicy::parse("").unwrap();
        assert!(p.net.writes == Mode::Deny && p.net.allow_writes.is_empty() && p.standins.is_empty());
        assert_eq!((p.run.as_slice(), p.keep, p.cpus, p.memory.as_str()), (&["claude".to_string()][..], true, 4, "8G"));
        assert!(p.allow().is_empty() && p.sites.is_empty() && p.mounts.is_empty() && p.image.is_none());
    }

    #[test]
    fn rejects_what_the_door_cannot_keep() {
        for (text, why) in [
            ("[browser]\nkeep_session = true", "unknown field"),
            ("[browser]\ndownloads = \"yes\"", "invalid type"),
            ("[[mount]]\npath = \"/opt/data\"\nmode = \"rw\"", "rw isn't available"),
            ("[[mount]]\npath = \"/opt/data\"\nmode = \"x\"", "isn't clone or ro"),
        ] {
            let e = err(text);
            assert!(e.contains(why), "{text}: {e}");
        }
    }

    #[test]
    fn rejects_unsafe_or_malformed_policies() {
        for (text, why) in [
            ("nope = 1", "unknown field"),
            ("[net]\nalow = []", "unknown field"),
            ("run = []", "run must be"),
            ("run = [\"\"]", "run must be"),
            ("image = \"agent\"", "pinned by digest"),
            ("image = \"agent@sha256:abc\"", "pinned by digest"),
            ("model = \"Bad Name\"", "model"),
            ("sites = [\"github\", \"github\"]", "twice"),
            ("sites = [\"../x\"]", "sites"),
            ("cpus = 0", "cpus"),
            ("memory = \"8\"", "memory"),
            ("memory = \"0G\"", "memory"),
            ("memory = \"lots\"", "memory"),
            ("[net]\nwrites = \"sometimes\"", "unknown variant"),
            ("[net]\nallow_writes = [\"http://a.example.com/x\"]", "allow_writes"),
            ("[net]\nallow_writes = [\"a.example.com/x\"]", "allow_writes"),
            ("[net]\nallow_writes = [\"https://*.example.com/x\"]", "allow_writes"),
            ("[net]\nallow_writes = [\"https://a.example.com/x?y=1\"]", "allow_writes"),
            ("[net]\nallow_writes = [\"https://a.example.com:8443/x\"]", "allow_writes"),
            ("standins = [\"gh_token\"]", "standins"),
            ("standins = [\"GH TOKEN\"]", "standins"),
            ("standins = [\"HTTPS_PROXY\"]", "set by halti already"),
            ("standins = [\"ANTHROPIC_API_KEY\"]", "set by halti already"),
            ("standins = [\"CLAUDE_CODE_OAUTH_TOKEN\"]", "set by halti already"),
            ("standins = [\"GH_TOKEN\", \"GH_TOKEN\"]", "twice"),
            ("[net]\nallow = [\"http://a.example.com\"]", "https"),
            ("[net]\nallow = [\"http://localhost\"]", "https"),
            ("[net]\nallow = [\"https://a.example.com:8443\"]", "default port"),
            ("[net]\nallow = [\"https://a.example.com/path\"]", "scheme://host"),
            ("[net]\nallow = [\"https://*.com\"]", "like https://*.example.com"),
            ("[[mount]]\npath = \"relative/dir\"", "absolute"),
            ("[[mount]]\npath = \"/opt/../etc\"", "absolute"),
            ("[[mount]]\npath = \"/\"", "too broad"),
            ("[[mount]]\npath = \"/opt/.hidden\"", "must be letters"),
            ("[[mount]]\npath = \"/opt/a b\"", "must be letters"),
            ("[[mount]]\npath = \"/opt/a\"\n[[mount]]\npath = \"/srv/a\"", "two [[mount]]"),
            ("[[mount]]\npath = \"/opt/a\"\nmod = \"ro\"", "unknown field"),
        ] {
            let e = err(text);
            assert!(e.contains(why), "{text}: {e}");
        }
    }

    #[test]
    fn keeps_halti_s_own_folders_out_of_boxes() {
        for path in [home(), config_dir(), config_dir().join("policy"), home().join(".config"), store_root().join("box/open/x"), home().join("Library/Application Support")] {
            let text = format!("[[mount]]\npath = \"{}\"", path.display());
            let e = err(&text);
            assert!(e.contains("too broad") || e.contains("halti's own"), "{text}: {e}");
        }
        assert!(BoxPolicy::parse(&format!("[[mount]]\npath = \"{}\"", home().join("Git/project").display())).is_ok());
    }

    #[test]
    fn keeps_the_workspaces_folder_in_effect_out_of_boxes() {
        let ws = home().join("work/ws");
        let own = [config_dir(), store_root(), ws.clone()];
        for path in [ws.clone(), ws.join("acme"), home().join("work")] {
            assert_eq!(mount_problem_among(&path, &own).as_deref(), Some("holds halti's own files"), "{}", path.display());
        }
        assert_eq!(mount_problem_among(&home().join("work/project"), &own), None);
        assert!(mount_problem(&config::workspaces_in_effect()).is_some(), "wherever it is");
    }

    #[test]
    fn a_workspace_box_mounts_only_plain_home_folders() {
        let rule = MountRule::Workspace(vec![config_dir(), store_root()]);
        let refused = [
            home().join(".claude"),
            home().join(".ssh/x"),
            home().join("Git/.env-folder"),
            home(),
            home().join("Library/Keychains"),
            home().join(legacy::STORE_ROOT).join("box/open/crewpoint"),
            home().join("library/Keychains"),
            PathBuf::from("/Volumes/x"),
            PathBuf::from("/tmp/cred-501"),
            PathBuf::from("/"),
            config_dir(),
            store_root().join("box"),
        ];
        for path in &refused {
            let why = mount_problem_in(path, &rule);
            assert_eq!(why.as_deref(), Some("a box in a workspace mounts only folders in your home that aren't hidden and aren't in ~/Library"), "{}", path.display());
        }
        assert_eq!(mount_problem_in(&home().join("Git/project"), &rule), None);
        // Today's guarded folders hold even where they are plain home folders.
        let own = MountRule::Workspace(vec![home().join("work/ws")]);
        assert_eq!(mount_problem_in(&home().join("work/ws/acme"), &own).as_deref(), Some("holds halti's own files"));
        assert_eq!(mount_problem_in(&home().join("work"), &own).as_deref(), Some("holds halti's own files"));

        // A link to a hidden folder is refused by its real path, as written and when a run resolves it.
        let dir = TempDir::new("halti-plain-home").unwrap();
        let home = dir.0.join("home");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(home.join("Git/project")).unwrap();
        std::os::unix::fs::symlink(home.join(".ssh"), home.join("Git/keys")).unwrap();
        assert!(outside_plain_home(&home.join("Git/keys"), &home).is_some());
        assert!(outside_plain_home(&fs::canonicalize(home.join("Git/keys")).unwrap(), &home).is_some());
        assert_eq!(outside_plain_home(&home.join("Git/project"), &home), None);
        assert_eq!(outside_plain_home(&home.join("Git/not-yet"), &home), None, "checked by its real path once it is there");

        // In a policy, as the error names it.
        let text = |path: &str| format!("[[mount]]\npath = \"{path}\"");
        let error = format!("{:#}", BoxPolicy::parse_in(&text("~/.claude"), &rule).err().unwrap());
        assert_eq!(error, "[[mount]] ~/.claude: a box in a workspace mounts only folders in your home that aren't hidden and aren't in ~/Library");
        assert!(BoxPolicy::parse_in(&text("~/Git/project"), &rule).is_ok());
        let error = format!("{:#}", BoxPolicy::parse_in(&format!("{}\nmode = \"rw\"", text("~/Git/project")), &rule).err().unwrap());
        assert_eq!(error, "[[mount]] ~/Git/project: rw isn't available, a box can't change your files; use clone");
    }

    #[test]
    fn the_mount_guard_takes_its_folders() {
        let dir = TempDir::new("halti-guard").unwrap();
        let own = [dir.0.join("config"), dir.0.join("ws")];
        let rule = MountRule::Guarded(own.to_vec());
        for path in [dir.0.join("config/policy"), dir.0.join("ws"), dir.0.clone(), home(), PathBuf::from("/")] {
            assert!(mount_problem_in(&path, &rule).is_some(), "{}", path.display());
        }
        assert_eq!(mount_problem_in(&dir.0.join("project"), &rule), None);
        // Today's rule and today's guard agree: halti's folders as the settings say.
        let mac = config::Settings::builtin(Os::Macos);
        let MountRule::Guarded(today) = MountRule::guarded(&mac) else { panic!("today's rule") };
        assert_eq!(today, [config_dir(), store_root(), mac.workspaces.path.clone()]);
        let MountRule::Workspace(theirs) = MountRule::workspace(&mac) else { panic!("a workspace's rule") };
        assert_eq!(theirs, today);
        assert_eq!(mount_problem_in(&home().join("Git/project"), &MountRule::guarded(&mac)), mount_problem(&home().join("Git/project")));
        assert_eq!(mount_problem_in(&config_dir(), &MountRule::guarded(&mac)), mount_problem(&config_dir()));
        // A policy checked under a rule keeps today's words.
        let text = format!("[[mount]]\npath = \"{}\"", dir.0.join("ws/acme").display());
        let error = format!("{:#}", BoxPolicy::parse_in(&text, &rule).err().unwrap());
        assert_eq!(error, format!("[[mount]] path '{}' holds halti's own files", dir.0.join("ws/acme").display()));
    }

    #[test]
    fn the_workspace_template_is_a_valid_policy_and_names_only_ws_commands() {
        let acme = WsName::parse("acme").unwrap();
        let rule = MountRule::Workspace(vec![config_dir(), store_root()]);
        for image in [None, Some(DIGEST)] {
            let text = workspace_template(&acme, "dev", image);
            let p = BoxPolicy::parse_in(&text, &rule).unwrap();
            assert_eq!((p.image.as_deref(), p.model.as_deref(), p.keep, p.allow(), p.net.writes), (image, Some("anthropic"), true, vec!["*".to_string()], Mode::Deny));
            assert!(text.contains("halti ws box approve acme/dev") && text.contains("halti ws run acme/dev"), "{text}");
            assert!(!text.contains("halti box") && !text.contains("box login") && !text.contains("import") && !text.contains("export"), "{text}");
        }
    }

    #[test]
    fn a_workspace_s_box_keys_are_its_own() {
        // Today's place keeps them where `[box] keys` says, and says so as before.
        assert_eq!(KeyStore::of(&config::Settings::builtin(Os::Macos)).place(), "in the Keychain");
        assert_eq!(KeyStore(Keys::Place).place(), "in its workspace");
    }

    #[test]
    fn the_templates_are_valid_policies() {
        assert!(BoxPolicy::parse(&template("research", None)).is_ok());
        let open = BoxPolicy::parse(&template("research", None)).unwrap();
        assert_eq!((open.allow(), open.net.writes), (vec!["*".to_string()], Mode::Deny), "the open web, reads only");
        let p = BoxPolicy::parse(&template("research", Some(DIGEST))).unwrap();
        assert_eq!((p.image.as_deref(), p.model.as_deref(), p.keep), (Some(DIGEST), Some("anthropic"), true));
        assert!(template("research", None).contains("halti box approve research"));
    }

    #[test]
    fn names_are_short_and_plain() {
        assert!(parse_name("research").is_ok() && parse_name("a-1").is_ok());
        assert!(parse_name("Research").is_err() && parse_name("a.b").is_err() && parse_name("").is_err());
        assert!(parse_name(&"a".repeat(MAX_NAME)).is_ok() && parse_name(&"a".repeat(MAX_NAME + 1)).is_err());
        assert_eq!(key("research"), "box.research");
        assert!(parse_resource(&key("research")).is_err(), "no resource can be named like a box key");
        assert!(parse_field("_key").is_err(), "no field can be named like the key");
    }

    #[test]
    fn says_why_a_box_is_not_approved() {
        let say = |s: Status| not_approved("research", &s).to_string();
        assert!(say(Status::Missing).contains("halti box new research"));
        assert!(say(Status::Unapproved).contains("isn't approved") && say(Status::Unapproved).contains("halti box approve research"));
        assert!(say(Status::Changed).contains("changed since"));
    }

    #[test]
    fn a_box_s_actions_ask_as_the_settings_say() {
        let mac = config::Settings::builtin(Os::Macos);
        let fake = Fake::answering(true, true);
        for action in [Action::BoxRun, Action::BoxPolicy, Action::BoxWrite, Action::BoxExport, Action::BoxDelete] {
            ask_for(&fake, &mac, action, "do it").unwrap();
        }
        assert_eq!(fake.calls(), ["touch id: do it"; 5], "Touch ID, as before the settings had lines");
        let mine = config::parse("[box.approval]\nrun = \"sudo\"\nexport = \"none\"\ndelete = \"sudo\"\n", Os::Macos).unwrap();
        ask_for(&fake, &mine, Action::BoxRun, "open box research").unwrap();
        ask_for(&fake, &mine, Action::BoxExport, "export it").unwrap();
        ask_for(&fake, &mine, Action::BoxDelete, "delete box research").unwrap();
        assert_eq!(fake.calls(), ["sudo: open box research", "sudo: delete box research"], "none asks nothing");

        // A no stops the action, whatever asked it.
        let no = Fake::answering(false, false);
        assert!(ask_for(&no, &mac, Action::BoxExport, "export it").is_err());
        assert!(ask_for(&no, &mine, Action::BoxDelete, "delete box research").unwrap_err().is::<approval::Declined>());
        assert!(ask_for(&no, &mine, Action::BoxExport, "export it").is_ok());
        assert_eq!(no.calls(), ["touch id: export it", "sudo: delete box research"]);

        // No box runs on Linux: halti says so, and asks nothing.
        let linux = config::Settings::builtin(Os::Linux);
        let error = ask_for(&fake, &linux, Action::BoxDelete, "delete box research").unwrap_err();
        assert_eq!(error.to_string(), "deleting a box needs an approval this system can't give");
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn the_settings_pick_the_engine_and_where_keys_are_kept() {
        let mac = config::Settings::builtin(Os::Macos);
        assert!(vms(&mac).is_ok());
        assert_eq!(KeyStore::of(&mac).place(), "in the Keychain");
        // Nothing here touches the Keychain: there is no place for keys on Linux.
        let linux = config::Settings::builtin(Os::Linux);
        assert_eq!(vms(&linux).err().map(|e| e.to_string()).as_deref(), Some("boxes can't run on this system: halti has no box engine for it"));
        let nowhere = KeyStore::of(&linux);
        assert!(!nowhere.exists("research") && nowhere.get("research").is_none() && !nowhere.delete("research"));
        assert_eq!(nowhere.set("research", "k").unwrap_err().to_string(), "a box's key can't be kept on this system");
        let error = nowhere.open_key("research").unwrap_err().to_string();
        assert_eq!(error, "the key of box research isn't anywhere on this system, so its store can't be opened (halti box rm research)");
    }

    #[test]
    fn sizes_read_plainly() {
        assert_eq!(
            (human(0), human(999), human(1500), human(25_000_000), human(3_200_000_000)),
            ("0 B".into(), "999 B".into(), "1.5 KB".into(), "25.0 MB".into(), "3.2 GB".into())
        );
    }

    #[test]
    fn exports_list_each_file_with_size_and_hash() {
        let dir = TempDir::new("halti-export").unwrap();
        let (mnt, to) = (dir.0.join("mnt"), dir.0.join("to"));
        fs::create_dir_all(mnt.join("work/out")).unwrap();
        fs::create_dir_all(&to).unwrap();
        fs::write(mnt.join("work/report.md"), "hello\n").unwrap();
        fs::write(mnt.join("work/out/a.csv"), "").unwrap();
        fs::write(dir.0.join("secret.txt"), "not in the box").unwrap();
        std::os::unix::fs::symlink(dir.0.join("secret.txt"), mnt.join("work/out/link")).unwrap();
        std::os::unix::fs::symlink(&dir.0, mnt.join("work/escape")).unwrap();

        let (files, skipped) = export_from(&mnt, "work/report.md", &to).unwrap();
        assert_eq!((files.len(), skipped), (1, 0));
        assert_eq!((files[0].file.as_path(), files[0].size), (Path::new("work/report.md"), 6));
        assert_eq!(files[0].sha256, crate::util::sha256_hex(b"hello\n"));
        assert_eq!(fs::read_to_string(to.join("report.md")).unwrap(), "hello\n");
        assert!(export_from(&mnt, "work/report.md", &to).is_err(), "never overwrites");

        let (files, skipped) = export_from(&mnt, "work/out", &to).unwrap();
        assert_eq!((files.iter().map(|f| f.file.clone()).collect::<Vec<_>>(), skipped), (vec![PathBuf::from("work/out/a.csv")], 1));
        assert!(to.join("out/a.csv").exists() && !to.join("out/link").exists());
    }

    #[test]
    fn exports_never_leave_the_box() {
        let dir = TempDir::new("halti-escape").unwrap();
        let (mnt, to) = (dir.0.join("mnt"), dir.0.join("to"));
        fs::create_dir_all(mnt.join("work")).unwrap();
        fs::create_dir_all(&to).unwrap();
        fs::write(dir.0.join("secret.txt"), "not in the box").unwrap();
        std::os::unix::fs::symlink(&dir.0, mnt.join("work/escape")).unwrap();
        std::os::unix::fs::symlink(dir.0.join("secret.txt"), mnt.join("work/file-link")).unwrap();

        for rel in ["../secret.txt", "/etc/passwd", "work/../../secret.txt", "", ".", "work/escape/secret.txt", "work/escape", "work/file-link", "work/missing"] {
            assert!(export_from(&mnt, rel, &to).is_err(), "exported {rel:?}");
        }
        assert!(fs::read_dir(&to).unwrap().next().is_none(), "nothing was written");
        assert!(export_from(&mnt, "work", &dir.0.join("nowhere")).is_err());
    }
}
