//! halti's settings: one file the person edits freely (`config.toml` in the config folder, which
//! `halti config` opens in $EDITOR, made from a template the first time), and an approved copy that
//! is what counts. A change counts once approved, as `[approval] config` says: with sudo, which
//! writes it as the approved copy, where only root can change it (`approved`); or with Touch ID, which
//! keeps it in the Keychain under the approved copy, as a policy's approval is kept.
//!
//! The template's values are the floor: with no approved copy, or one that can't be trusted or
//! read, the template is in effect, never something looser. halti works with no file at all.
//!
//! The file names words from halti's own lists and one folder, never a command or a library. Every
//! setting is a row of the schema: a new setting, or a new action's approval (`approval::RULES`), is
//! one more row and its line in the template follows. Nothing from the file is echoed back: a
//! refusal names only halti's own words, and the line.
//!
//! The file is plain ascii with no backslash, its names bare and its values in double quotes on one
//! line, so what a diff of it shows is what halti reads.

pub mod approved;

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use halti_core::platform::Os;
use toml::de::{DeTable, DeValue};

use crate::approval::{self, Action, Declined, Means, RULES, Real, Rule, World};
use crate::ws::{self, OS};
use crate::{names, policy, util};
use approved::{Found, Place};

/// The template's first line.
const HEADER: &str = "# halti config. edit with: halti config";

/// What Touch ID shows, after "halti is trying to".
const TOUCH_ID: &str = "approve your changed settings";

const NO_TERMINAL: &str = "halti config needs a terminal, for sudo to ask for your password";

/// The last line of a refused edit.
const FIX: &str = "nothing was approved. fix it with: halti config";

const RECORD_GONE: &str = "the touch id approval of your settings is missing, so the settings last approved with sudo are in effect. approve yours again with: halti config";

/// A setting that is one word from a closed list. A new choice is one more variant.
pub trait Word: Copy + PartialEq + 'static {
    /// Every word, in the order the template lists them.
    const ALL: &'static [Self];
    fn name(self) -> &'static str;
    /// Whether this system has it.
    fn on(self, _os: Os) -> bool {
        true
    }
}

/// Where a workspace's passphrase is kept for halti's use: nowhere, so it is typed each time, or the
/// Keychain, which is only on a Mac. With a manager, `ws new` saves the passphrase there, and a
/// workspace's approval lines can name another means than the passphrase.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Manager {
    None,
    Keychain,
}

impl Word for Manager {
    const ALL: &'static [Manager] = &[Manager::None, Manager::Keychain];

    fn name(self) -> &'static str {
        match self {
            Manager::None => "none",
            Manager::Keychain => "keychain",
        }
    }

    fn on(self, os: Os) -> bool {
        self == Manager::None || os == Os::Macos
    }
}

/// Where a workspace's stored secrets are kept.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Store {
    Files,
}

impl Word for Store {
    const ALL: &'static [Store] = &[Store::Files];

    fn name(self) -> &'static str {
        match self {
            Store::Files => "files",
        }
    }
}

/// What runs a box's VMs: Apple's container, which is only on a Mac. Another engine is one more
/// variant, and one more arm where a box picks it (`boxes::vms`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Engine {
    Container,
}

impl Word for Engine {
    const ALL: &'static [Engine] = &[Engine::Container];

    fn name(self) -> &'static str {
        match self {
            Engine::Container => "container",
        }
    }

    fn on(self, os: Os) -> bool {
        os == Os::Macos
    }
}

/// Where a box's store key is kept: the Keychain, which is only on a Mac. Another place is one more
/// variant, and one more arm where a box keeps its key (`boxes::KeyStore`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Keys {
    Keychain,
}

impl Word for Keys {
    const ALL: &'static [Keys] = &[Keys::Keychain];

    fn name(self) -> &'static str {
        match self {
            Keys::Keychain => "keychain",
        }
    }

    fn on(self, os: Os) -> bool {
        os == Os::Macos
    }
}

/// Whose passphrase a new workspace gets: one the person types, or one halti makes and shows once.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PassphraseMode {
    Own,
    Generate,
}

impl Word for PassphraseMode {
    const ALL: &'static [PassphraseMode] = &[PassphraseMode::Own, PassphraseMode::Generate];

    fn name(self) -> &'static str {
        match self {
            PassphraseMode::Own => "own",
            PassphraseMode::Generate => "generate",
        }
    }
}

/// The folder of the workspaces: as written, and where that is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Workspaces {
    pub written: String,
    pub path: PathBuf,
}

impl Workspaces {
    /// The `ws` folder of the store root, where workspaces always were.
    fn builtin() -> Workspaces {
        let written = format!("~/{}/{}", if cfg!(halti_dev) { util::DEV_STORE_ROOT } else { names::STORE_ROOT }, names::WS_DIR);
        let path = util::expand_home(&written);
        Workspaces { written, path }
    }
}

/// The settings, read whole. Two are equal when they say the same, whatever the comments.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Settings {
    pub default: Means,
    /// Each action's means on this system, its line or else as `default` says. An action no means
    /// of this system can approve has none.
    means: BTreeMap<Action, Means>,
    pub workspaces: Workspaces,
    pub manager: Manager,
    pub store: Store,
    pub passphrase: PassphraseMode,
    /// None where no engine runs a box: there the `[box]` section has no lines.
    pub engine: Option<Engine>,
    pub keys: Option<Keys>,
}

impl Settings {
    /// The template's.
    pub fn builtin(os: Os) -> Settings {
        Given::default().settings(os)
    }

    /// What approves `action`.
    pub fn means(&self, action: Action) -> Option<Means> {
        self.means.get(&action).copied()
    }

    /// As `--show` prints them: the template's order, without comments.
    pub fn render(&self, os: Os) -> String {
        self.lines(os, false)
    }

    /// Each section after a blank line, its keys lined up; with `comments`, each line says what it
    /// can be, as the template does.
    fn lines(&self, os: Os, comments: bool) -> String {
        let rows = rows();
        let mut out = String::new();
        for table in TABLES {
            let shown: Vec<(&str, String, String)> = rows.iter().filter(|row| row.table == table).filter_map(|row| self.line(row, os)).collect();
            if shown.is_empty() {
                continue;
            }
            let width = shown.iter().map(|(key, ..)| key.len()).max().unwrap_or(0);
            out += &format!("\n[{table}]\n");
            for (key, value, comment) in shown {
                let line = format!("{key:<width$} = {value}");
                out += &if comments && !comment.is_empty() { format!("{line:<29} # {comment}\n") } else { format!("{line}\n") };
            }
        }
        out
    }

    /// One setting's key, its value in quotes, and what it can be on this system.
    fn line(&self, row: &Row, os: Os) -> Option<(&'static str, String, String)> {
        let (value, comment) = match row.slot {
            Slot::Default => (self.default.name(), list(&default_choices(os))),
            Slot::Means(action) => (self.means(action)?.name(), format!("{}: {}", action.rule().about, list(&action.accepts(os)))),
            Slot::Workspaces => return Some((row.key, quoted(&self.workspaces.written), String::new())),
            Slot::Manager => (self.manager.name(), list(&here::<Manager>(os))),
            Slot::Store => (self.store.name(), list(&here::<Store>(os))),
            Slot::Passphrase => (self.passphrase.name(), list(&here::<PassphraseMode>(os))),
            Slot::Engine => (self.engine?.name(), list(&here::<Engine>(os))),
            Slot::Keys => (self.keys?.name(), format!("where a box's key is kept: {}", list(&here::<Keys>(os)))),
        };
        Some((row.key, quoted(value), comment))
    }
}

/// The words of a list, as the template's comments show them.
fn list<W: Word>(words: &[W]) -> String {
    words.iter().map(|word| word.name()).collect::<Vec<_>>().join(" | ")
}

/// A value in double quotes, as the file has it: a value read from it holds no quote or backslash.
fn quoted(text: &str) -> String {
    format!("\"{text}\"")
}

/// The words of a list that this system has.
fn here<W: Word>(os: Os) -> Vec<W> {
    W::ALL.iter().copied().filter(|word| word.on(os)).collect()
}

/// What `[approval] default` can be: each means some action outside `[box.approval]` accepts on
/// this system, a workspace's taken as its passphrase alone, as it was before a password manager
/// could release one. A box's missing line doesn't follow it, nor does a workspace's.
fn default_choices(os: Os) -> Vec<Means> {
    let accepted = |rule: &Rule, means: &Means| !rule.of_box() && rule.action.accepts(os).contains(means) && (!rule.manager || *means == Means::Passphrase);
    Means::ALL.iter().copied().filter(|means| RULES.iter().any(|rule| accepted(rule, means))).collect()
}

/// halti's template for this system, comments and all.
pub fn template(os: Os) -> String {
    format!("{HEADER}\n{}", Settings::builtin(os).lines(os, true))
}

// --- the schema ---

/// The sections, in the template's order.
const TABLES: [&str; 8] = ["approval", "paths", "passwords", "secrets", "workspace", "workspace.approval", "box", "box.approval"];

/// What a setting holds.
#[derive(Clone, Copy)]
enum Slot {
    Default,
    Means(Action),
    Workspaces,
    Manager,
    Store,
    Passphrase,
    Engine,
    Keys,
}

struct Row {
    table: &'static str,
    key: &'static str,
    slot: Slot,
}

/// The settings that aren't an action's approval.
const SETTINGS: [Row; 7] = [
    Row { table: "approval", key: "default", slot: Slot::Default },
    Row { table: "paths", key: "workspaces", slot: Slot::Workspaces },
    Row { table: "passwords", key: "manager", slot: Slot::Manager },
    Row { table: "secrets", key: "store", slot: Slot::Store },
    Row { table: "workspace", key: "passphrase", slot: Slot::Passphrase },
    Row { table: "box", key: "engine", slot: Slot::Engine },
    Row { table: "box", key: "keys", slot: Slot::Keys },
];

/// Every setting: those above and each action's approval, in the template's order.
fn rows() -> Vec<Row> {
    let approvals = RULES.iter().map(|rule| Row { table: rule.table, key: rule.key, slot: Slot::Means(rule.action) });
    let mut rows: Vec<Row> = SETTINGS.into_iter().chain(approvals).collect();
    rows.sort_by_key(|row| TABLES.iter().position(|table| *table == row.table));
    rows
}

/// halti's own name of the section `name`, if it has one: a section, or one with sections in it.
fn section(name: &str) -> Option<&'static str> {
    TABLES.into_iter().find(|table| *table == name || table.strip_prefix(name).is_some_and(|rest| rest.starts_with('.'))).map(|table| &table[..name.len()])
}

/// Why the settings are refused, and on which line.
#[derive(Debug, PartialEq, Eq)]
pub struct Refused {
    pub line: usize,
    pub why: String,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.why)
    }
}

/// `why`, on the line of the byte at `at`.
fn refused(text: &str, at: usize, why: &str) -> Refused {
    let before = &text.as_bytes()[..at.min(text.len())];
    Refused { line: 1 + before.iter().filter(|byte| **byte == b'\n').count(), why: why.to_string() }
}

/// The settings a file's text says, on this system. A missing line takes the template's value, and
/// a missing approval line is as `default` says, or else the first means its action accepts; a box's
/// is the first means it accepts, Touch ID, so a copy approved before `[box]` keeps what boxes did,
/// and a workspace's is its passphrase, as it always was. A workspace's line that releases the
/// passphrase from a password manager needs one. Every problem is found, and the first in the file
/// is the one refused.
pub fn parse(text: &str, os: Os) -> Result<Settings, Refused> {
    // A control character could repaint the diff on a terminal; any other could look like another.
    if let Some((at, c)) = text.char_indices().find(|&(_, c)| !matches!(c, ' '..='~' | '\n' | '\t')) {
        let why = if c.is_control() { "this line has a control character in it" } else { "this line has a character that isn't plain ascii" };
        return Err(refused(text, at, why));
    }
    if let Some(at) = text.find('\\') {
        return Err(refused(text, at, "this line has a backslash in it"));
    }
    let table = DeTable::parse(text).map_err(|error| refused(text, error.span().map_or(0, |span| span.start), "this line isn't valid toml"))?;
    let mut given = Given::default();
    let mut problems: Vec<(usize, String)> = spelling(text).into_iter().collect();
    walk(table.get_ref(), None, os, &mut given, &mut problems);
    problems.extend(given.without_manager());
    match problems.into_iter().min_by_key(|(at, _)| *at) {
        Some((at, why)) => Err(refused(text, at, &why)),
        None => Ok(given.settings(os)),
    }
}

/// The first spelling halti doesn't take, in text that is valid toml, plain ascii and has no
/// backslash: a name in quotes, or a value not in double quotes on one line. Whatever else is
/// there reads as it is written.
fn spelling(text: &str) -> Option<(usize, String)> {
    let bytes = text.as_bytes();
    let (mut at, mut last) = (0, b'\n');
    while at < bytes.len() {
        match bytes[at] {
            b'#' => {
                at += bytes[at..].iter().position(|byte| *byte == b'\n').unwrap_or(bytes.len() - at);
                continue;
            }
            quote @ (b'"' | b'\'') => {
                // A value's quote follows its `=`; any other is a name's, or in a list, which no setting takes.
                if last != b'=' {
                    return Some((at, "a name has to be written without quotes".to_string()));
                }
                if quote == b'\'' || bytes[at..].starts_with(b"\"\"\"") {
                    return Some((at, "a value has to be in double quotes, on one line".to_string()));
                }
                // With no backslash, it ends at the next double quote.
                at += 1 + bytes[at + 1..].iter().position(|byte| *byte == b'"').unwrap_or(bytes.len() - at - 1);
                last = quote;
            }
            b' ' | b'\t' => {}
            byte => last = byte,
        }
        at += 1;
    }
    None
}

/// What a file says, line by line.
#[derive(Default)]
struct Given {
    default: Option<Means>,
    means: BTreeMap<Action, Means>,
    /// Where each approval line's value is.
    means_at: BTreeMap<Action, usize>,
    workspaces: Option<Workspaces>,
    manager: Option<Manager>,
    store: Option<Store>,
    passphrase: Option<PassphraseMode>,
    engine: Option<Engine>,
    keys: Option<Keys>,
}

impl Given {
    /// Each workspace line that releases the passphrase from a password manager while the file
    /// names none, with where its value is and why it is refused.
    fn without_manager(&self) -> Vec<(usize, String)> {
        if self.manager.unwrap_or(Manager::None) != Manager::None {
            return Vec::new();
        }
        let releasing = self.means.iter().filter(|(action, means)| action.rule().manager && **means != Means::Passphrase);
        let why = |action: &Action, means: &Means| format!("{} can't be {} while [passwords] manager is none", action.rule().key, means.name());
        releasing.map(|(action, means)| (self.means_at.get(action).copied().unwrap_or(0), why(action, means))).collect()
    }

    fn settings(self, os: Os) -> Settings {
        let default = self.default.unwrap_or(Means::Sudo);
        let mut means = BTreeMap::new();
        for rule in RULES {
            let accepts = rule.action.accepts(os);
            let line = self.means.get(&rule.action).copied();
            let wanted = if rule.of_box() || rule.manager { accepts.first().copied() } else { Some(default) };
            let chosen = line.or_else(|| wanted.filter(|means| accepts.contains(means))).or_else(|| accepts.iter().copied().find(|means| *means != Means::None));
            if let Some(chosen) = chosen {
                means.insert(rule.action, chosen);
            }
        }
        Settings {
            default,
            means,
            workspaces: self.workspaces.unwrap_or_else(Workspaces::builtin),
            manager: self.manager.unwrap_or(Manager::None),
            store: self.store.unwrap_or(Store::Files),
            passphrase: self.passphrase.unwrap_or(PassphraseMode::Own),
            engine: self.engine.or_else(|| here::<Engine>(os).first().copied()),
            keys: self.keys.or_else(|| here::<Keys>(os).first().copied()),
        }
    }
}

/// Takes each setting of `table`, the root when `inside` is none, and notes each problem with where it is.
fn walk(table: &DeTable<'_>, inside: Option<&'static str>, os: Os, given: &mut Given, problems: &mut Vec<(usize, String)>) {
    for (key, value) in table.iter() {
        let name: &str = key.get_ref();
        let at = key.span().start;
        let nested = match inside {
            None => name.to_string(),
            Some(inside) => match rows().into_iter().find(|row| row.table == inside && row.key == name) {
                Some(row) => {
                    if let Err(why) = take(&row, value.get_ref(), os, given) {
                        problems.push((value.span().start, why));
                    } else if let Slot::Means(action) = row.slot {
                        given.means_at.insert(action, value.span().start);
                    }
                    continue;
                }
                None => format!("{inside}.{name}"),
            },
        };
        match (value.get_ref(), section(&nested), inside) {
            (DeValue::Table(inner), Some(known), _) => walk(inner, Some(known), os, given, problems),
            (DeValue::Table(_), None, _) => problems.push((at, "halti has no section with this name".to_string())),
            (_, _, None) => problems.push((at, "a setting has to be in a section".to_string())),
            (_, _, Some(inside)) => problems.push((at, format!("[{inside}] has no setting with this name"))),
        }
    }
}

/// Takes one setting's value, or says why not.
fn take(row: &Row, value: &DeValue<'_>, os: Os, given: &mut Given) -> Result<(), String> {
    let key = row.key;
    match row.slot {
        Slot::Default => given.default = Some(word(key, value, &default_choices(os), os)?),
        Slot::Means(action) => {
            given.means.insert(action, word(key, value, &action.accepts(os), os)?);
        }
        Slot::Workspaces => given.workspaces = Some(workspaces(value)?),
        Slot::Manager => given.manager = Some(word(key, value, &here::<Manager>(os), os)?),
        Slot::Store => given.store = Some(word(key, value, &here::<Store>(os), os)?),
        Slot::Passphrase => given.passphrase = Some(word(key, value, &here::<PassphraseMode>(os), os)?),
        Slot::Engine => given.engine = Some(word(key, value, &here::<Engine>(os), os)?),
        Slot::Keys => given.keys = Some(word(key, value, &here::<Keys>(os), os)?),
    }
    Ok(())
}

/// The word `key` holds, if it is one of `allowed` on this system; otherwise why not, naming only
/// halti's words.
fn word<W: Word>(key: &str, value: &DeValue<'_>, allowed: &[W], os: Os) -> Result<W, String> {
    let Some(first) = allowed.first() else { return Err(format!("{key} can't be set on this system")) };
    let Some(text) = value.as_str() else { return Err(format!("{key} takes a word in quotes, like \"{}\"", first.name())) };
    let Some(named) = W::ALL.iter().copied().find(|word| word.name() == text) else { return Err(format!("{key} can {}", choices(allowed))) };
    if allowed.contains(&named) {
        return Ok(named);
    }
    if !named.on(os) {
        return Err(format!("{} is only on a mac", named.name()));
    }
    Err(format!("{key} can't be {}. it can {}", named.name(), choices(allowed)))
}

/// "be sudo or touchid", "be sudo, touchid or passphrase", or "only be passphrase".
fn choices<W: Word>(allowed: &[W]) -> String {
    let names: Vec<&str> = allowed.iter().map(|word| word.name()).collect();
    match names.as_slice() {
        [one] => format!("only be {one}"),
        [rest @ .., last] => format!("be {} or {last}", rest.join(", ")),
        [] => "be nothing here".to_string(),
    }
}

/// The workspaces folder: a folder below the home folder (`~/`) or below `/`, each part of its path
/// a plain name, so the path reads as the folder it is.
fn workspaces(value: &DeValue<'_>) -> Result<Workspaces, String> {
    let Some(written) = value.as_str() else { return Err("workspaces takes a path in quotes".to_string()) };
    let Some(rest) = written.strip_prefix("~/").or_else(|| written.strip_prefix('/')) else { return Err("workspaces has to start with ~/ or /".to_string()) };
    if rest.is_empty() {
        return Err("workspaces has to name a folder below ~/ or /".to_string());
    }
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return Err("workspaces can't have // in it or a / at the end".to_string());
    }
    if parts.iter().any(|part| *part == "." || *part == "..") {
        return Err("workspaces can't have a . or .. part".to_string());
    }
    if parts.iter().any(|part| part.contains('\t') || part.trim() != *part) {
        return Err("workspaces can't have a tab, or a space at the start or end of a part".to_string());
    }
    Ok(Workspaces { written: written.to_string(), path: util::expand_home(written) })
}

// --- what is in effect ---

/// Where the settings in effect came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// Nothing usable is approved: the template.
    Template,
    /// The approved copy.
    Sudo,
    /// The Touch ID record the approved copy names.
    TouchId,
}

/// The settings in effect, and what halti says about them.
pub struct InEffect {
    pub settings: Settings,
    /// Their text: the template's, the approved copy's or the Touch ID record's.
    pub text: String,
    pub source: Source,
    /// The approved copy, when it is in effect or names the Touch ID record that is.
    anchor: Option<String>,
    /// An approved copy is there but can't be used: approving anything writes it again.
    unusable: bool,
    /// Said on stderr, each after `halti: `.
    pub notes: Vec<String>,
}

impl InEffect {
    /// Whether approving `new` would change nothing: the same settings, from an approval used whole.
    fn unchanged(&self, new: &Settings) -> bool {
        *new == self.settings && !self.record_gone() && !self.unusable
    }

    /// Whether the approved copy says Touch ID approves a change: then Touch ID changes only its record.
    fn by_touch_id(&self) -> bool {
        self.source == Source::TouchId || (self.source == Source::Sudo && self.settings.means(Action::Config) == Some(Means::TouchId))
    }

    /// The approved copy says Touch ID, but its record is gone: the copy's own settings are in effect.
    fn record_gone(&self) -> bool {
        self.source == Source::Sudo && self.by_touch_id()
    }
}

/// What is in effect: the approved copy, its Touch ID record when it names one that is there and
/// whole, or the template. Never fails: anything wrong leaves the template in effect, with a note.
pub fn in_effect(world: &dyn World, place: &Place, os: Os) -> InEffect {
    let floor = |note: Option<String>| InEffect {
        settings: Settings::builtin(os),
        text: template(os),
        source: Source::Template,
        anchor: None,
        unusable: note.is_some(),
        notes: note.into_iter().collect(),
    };
    let copy = place.file.display();
    let anchor = match world.read(place) {
        Found::Missing => return floor(None),
        Found::Unsafe => {
            let who = place.who();
            return floor(Some(format!("{copy} isn't used, because someone other than {who} could change it or a folder above it. halti's template is in effect")));
        }
        Found::Unreadable(why) => return floor(Some(bad_copy(place, &why))),
        Found::Text(text) => text,
    };
    let settings = match parse(&anchor, os) {
        Ok(settings) => settings,
        Err(refused) => return floor(Some(bad_copy(place, &refused.to_string()))),
    };
    let mut notes = Vec::new();
    if settings.means(Action::Config) == Some(Means::TouchId) {
        let pinned = world.pinned(&approved::record_key(&anchor)).and_then(|text| parse(&text, os).ok().map(|settings| (settings, text)));
        if let Some((settings, text)) = pinned {
            return InEffect { settings, text, source: Source::TouchId, anchor: Some(anchor), unusable: false, notes };
        }
        notes.push(RECORD_GONE.to_string());
    }
    InEffect { settings, text: anchor.clone(), source: Source::Sudo, anchor: Some(anchor), unusable: false, notes }
}

/// The workspaces folder in effect, with nothing said on stderr: for a check that only needs where it is.
pub fn workspaces_in_effect() -> PathBuf {
    in_effect(&Real, &Place::real(), OS).settings.workspaces.path
}

fn bad_copy(place: &Place, why: &str) -> String {
    format!("{} can't be used ({why}), so halti's template is in effect. approve your settings again with: halti config", place.file.display())
}

/// The settings in effect, for every command that uses them, with what halti says about them, and
/// about the person's file, on stderr.
pub fn settings() -> Settings {
    let now = in_effect(&Real, &Place::real(), OS);
    for note in now.notes.iter().chain(&person_notes(&file(), &now, OS)) {
        eprintln!("halti: {note}");
    }
    now.settings
}

/// The person's file.
fn file() -> PathBuf {
    util::config_dir().join(names::CONFIG_FILE)
}

/// What the person's file says that isn't in effect: changes not approved yet, or a file that can't be used.
fn person_notes(path: &Path, now: &InEffect, os: Os) -> Vec<String> {
    let stay = "so the settings stay as they were. fix it with: halti config";
    let note = match read_file(path) {
        Ok(None) => return Vec::new(),
        Ok(Some(text)) => match parse(&text, os) {
            Ok(settings) if settings == now.settings => return Vec::new(),
            Ok(_) => format!("changes in {} aren't approved yet, so they have no effect. approve them with: halti config", path.display()),
            Err(refused) => format!("{} can't be used ({refused}), {stay}", path.display()),
        },
        Err(error) => format!("{error:#}, {stay}"),
    };
    vec![note]
}

/// The person's file, if there is one. It may be a link (to a dotfile manager's copy, say), but it
/// is opened without waiting and refused unless it is a plain file of text, at most 16 KiB.
fn read_file(path: &Path) -> Result<Option<String>> {
    let file = match OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    if !file.metadata().is_ok_and(|meta| meta.is_file()) {
        bail!("{} isn't a plain file", path.display());
    }
    let mut bytes = Vec::new();
    file.take(approved::MOST + 1).read_to_end(&mut bytes).with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() as u64 > approved::MOST {
        bail!("{} is larger than 16 KiB", path.display());
    }
    String::from_utf8(bytes).map(Some).map_err(|_| anyhow!("{} isn't text", path.display()))
}

/// The person's file, ready for the editor: made from `text` if it isn't there. A pipe in its place
/// would hang the editor, and a link to a file that isn't there would be written through, so both
/// are refused; a file too large or not text is the editor's to fix.
fn ready_file(path: &Path, text: &str) -> Result<()> {
    match fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound && fs::symlink_metadata(path).is_ok() => {
            bail!("{} is a link to a file that isn't there. make that file, or remove the link", path.display())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => create(path, text),
        Ok(meta) if meta.is_file() => Ok(()),
        _ => bail!("{} isn't a plain file", path.display()),
    }
}

/// Makes the person's file, 0600 in a 0700 folder, from the text in effect.
fn create(path: &Path, text: &str) -> Result<()> {
    let folder = path.parent().expect("the file is in the config folder");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(folder).with_context(|| format!("creating {}", folder.display()))?;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).with_context(|| format!("creating {}", path.display()))?;
    file.write_all(text.as_bytes()).with_context(|| format!("writing {}", path.display()))
}

// --- halti config ---

/// `halti config`: opens the person's file in $EDITOR, shows what changed, and approves it as the
/// settings in effect say. `--show`: the settings in effect. `--default`: the template.
pub fn command(show: bool, default: bool) -> Result<()> {
    if default {
        print!("{}", template(OS));
        return Ok(());
    }
    let place = Place::real();
    let now = in_effect(&Real, &place, OS);
    let path = file();
    if !show {
        for note in &now.notes {
            eprintln!("halti: {note}");
        }
        return edit(&Real, &now, &place, &path);
    }
    for note in now.notes.iter().chain(&person_notes(&path, &now, OS)) {
        eprintln!("halti: {note}");
    }
    let from = match now.source {
        Source::Template => "no settings of yours are approved yet, so halti uses its template".to_string(),
        Source::Sudo => format!("your settings, approved with sudo ({})", place.file.display()),
        Source::TouchId => "your settings, approved with touch id".to_string(),
    };
    print!("{from}\n{}", now.settings.render(OS));
    Ok(())
}

/// The edit itself: the file, made from what is in effect if it isn't there, read once after the
/// editor ends, parsed, shown as a diff, and approved. Where sudo will ask, a terminal is needed
/// before anything else, and the diff is shown on it.
fn edit(world: &dyn World, now: &InEffect, place: &Place, path: &Path) -> Result<()> {
    if !now.by_touch_id() {
        approval::terminal_ready().map_err(|_| anyhow!(NO_TERMINAL))?;
    }
    ready_file(path, &now.text)?;
    policy::run_editor(path)?;
    let text = read_file(path).and_then(|text| text.ok_or_else(|| anyhow!("{} is gone", path.display()))).map_err(|error| anyhow!("{error:#}\n{FIX}"))?;
    let new = parse(&text, OS).map_err(|refused| anyhow!("{}, {refused}\n{FIX}", path.display()))?;
    if now.unchanged(&new) {
        println!("no change to the settings in effect");
        return Ok(());
    }
    // A folder halti didn't make is never taken for workspaces, so never changed or filled.
    if let Some(why) = ws::folder_problem(&new.workspaces.path) {
        bail!("{why}, so halti won't use it\n{FIX}");
    }
    let sudo = !now.by_touch_id() || new.means(Action::Config) != Some(Means::TouchId);
    if sudo {
        approval::terminal_ready().map_err(|_| anyhow!(NO_TERMINAL))?;
    }
    let (mut shown, color) = screen(sudo);
    if now.unusable {
        writeln!(shown, "{} can't be used, so approving these settings writes it again", place.file.display())?;
    }
    if text != now.text {
        let label = if now.source == Source::Template { "template" } else { "approved" };
        write!(shown, "{}", policy::diff_from(label, &now.text, &text, color))?;
    }
    if let Some(line) = moving(&now.settings, &new) {
        writeln!(shown, "{line}")?;
    }
    shown.flush()?;
    approve_with(world, now, place, path, &text, &new)?;
    println!("approved. these settings are in effect now");
    Ok(())
}

/// Where the diff goes: with sudo, the terminal, where sudo asks, so a redirect can't hide what the
/// password approves (under the debug hook, stdout); with Touch ID, stdout. Whether to color it.
fn screen(sudo: bool) -> (Box<dyn Write>, bool) {
    #[cfg(halti_dev)]
    if util::dev_var("HALTI_TEST_SUDO").is_some() {
        return (Box::new(io::stdout()), io::stdout().is_terminal());
    }
    if sudo && let Ok(tty) = OpenOptions::new().write(true).open("/dev/tty") {
        return (Box::new(tty), true);
    }
    (Box::new(io::stdout()), io::stdout().is_terminal())
}

/// When the workspaces folder changes: the workspaces in the old one, which stop being listed.
/// Nothing is moved.
fn moving(old: &Settings, new: &Settings) -> Option<String> {
    let (from, to) = (&old.workspaces.path, &new.workspaces.path);
    if from == to {
        return None;
    }
    let names = ws::names_in(from);
    if names.is_empty() {
        return None;
    }
    Some(format!("workspaces in {} won't be listed after this: {}. to keep using them, move them to {}", from.display(), names.join(", "), to.display()))
}

/// Approves `text`, which says `new`. sudo writes it as the approved copy, which is then read back
/// through every check. When the approved copy says Touch ID, and so does `text`, Touch ID keeps it
/// as that copy's record instead. Only sudo writes the copy, so neither can undo the other.
fn approve_with(world: &dyn World, now: &InEffect, place: &Place, path: &Path, text: &str, new: &Settings) -> Result<()> {
    let declined = || anyhow!("not approved, so nothing changed. your edits stay in {}. approve them with: halti config", path.display());
    let by_touch_id = new.means(Action::Config) == Some(Means::TouchId);
    if let (true, true, Some(anchor)) = (now.by_touch_id(), by_touch_id, &now.anchor) {
        world.touch_id(TOUCH_ID).map_err(|_| declined())?;
        return world.pin(&approved::record_key(anchor), text);
    }
    let before = world.read(place);
    if let Err(error) = world.sudo_write(place, text.as_bytes()) {
        if !error.is::<Declined>() {
            return Err(error);
        }
        // sudo says no the same way whether it refused or the write failed part way: the copy tells them apart.
        if world.read(place) != before {
            bail!("{} was changed, but the write didn't finish. approve your settings again with: halti config", place.file.display());
        }
        return Err(declined());
    }
    if world.read(place) != Found::Text(text.to_string()) {
        bail!("{} doesn't hold what was approved. approve again with: halti config", place.file.display());
    }
    if by_touch_id {
        // sudo approved exactly this text: the record is made now, so one missing later is seen.
        world.pin(&approved::record_key(text), text)?;
    } else if let (true, Some(anchor)) = (now.by_touch_id(), &now.anchor) {
        world.unpin(&approved::record_key(anchor));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;
    use crate::approval::fake_tests::Fake;
    use crate::util::TempDir;

    const BOTH: [Os; 2] = [Os::Macos, Os::Linux];

    /// The box sections of a Mac's template. No box runs on Linux, so its template has none.
    const BOX_SECTIONS: &str = "\n[box]\nengine = \"container\"          # container\nkeys   = \"keychain\"           # where a box's key is kept: keychain\n\n\
                                [box.approval]\nrun    = \"touchid\"            # opening a box: touchid | sudo | none\n\
                                policy = \"touchid\"            # approving a changed box policy: touchid | sudo | none\n\
                                write  = \"touchid\"            # a write the box's policy says to ask about: touchid | none\n\
                                export = \"touchid\"            # copying files out of a box: touchid | sudo | none\n\
                                delete = \"touchid\"            # deleting a box: touchid | sudo | none\n";

    const BOX_ACTIONS: [Action; 5] = [Action::BoxRun, Action::BoxPolicy, Action::BoxWrite, Action::BoxExport, Action::BoxDelete];

    /// The template a debug build has, as the person sees it.
    fn expected(os: Os) -> String {
        let (default, config, managers, ws, boxes) = match os {
            Os::Macos => ("sudo | touchid | passphrase", "sudo | touchid", "none | keychain", "passphrase | sudo | touchid | none", BOX_SECTIONS),
            Os::Linux => ("sudo | passphrase", "sudo", "none", "passphrase", ""),
        };
        format!(
            "# halti config. edit with: halti config\n\n[approval]\ndefault = \"sudo\"              # {default}\n\
             config  = \"sudo\"              # a change to this file: {config}\n\n[paths]\nworkspaces = \"~/{}/ws\"\n\n\
             [passwords]\nmanager = \"none\"              # {managers}\n\n[secrets]\nstore = \"files\"               # files\n\n\
             [workspace]\npassphrase = \"own\"            # own | generate\n\n[workspace.approval]\n\
             open   = \"passphrase\"         # opening a workspace: {ws}\ndelete = \"passphrase\"         # deleting a workspace: {ws}\n{boxes}",
            util::DEV_STORE_ROOT
        )
    }

    /// The template the build before a password manager could be named had: no manager, and a
    /// workspace's lines taking its passphrase alone.
    fn before_managers(os: Os) -> String {
        let ws = if os == Os::Macos { "passphrase | sudo | touchid | none" } else { "passphrase" };
        let text = template(os).replace("# none | keychain", "# none");
        text.replace(&format!("opening a workspace: {ws}"), "opening a workspace: passphrase").replace(&format!("deleting a workspace: {ws}"), "deleting a workspace: passphrase")
    }

    /// The template with `config` and `workspaces` changed.
    fn text(os: Os, config: &str, workspaces: &str) -> String {
        template(os).replace("config  = \"sudo\"", &format!("config  = \"{config}\"")).replace(&Workspaces::builtin().written, workspaces)
    }

    /// Never touched: the fake keeps the copy in memory.
    fn place() -> Place {
        Place::at(Path::new("/nowhere/approved"), 501, 0, Path::new("/"))
    }

    const FILE: &str = "/nowhere/config.toml";

    fn approve(fake: &Fake, now: &InEffect, text: &str, os: Os) -> Result<()> {
        approve_with(fake, now, &place(), Path::new(FILE), text, &parse(text, os).unwrap())
    }

    #[test]
    fn the_template_is_the_builtin_settings_with_what_each_can_be() {
        for os in BOTH {
            assert_eq!(template(os), expected(os), "{os:?}");
            assert_eq!(parse(&template(os), os), Ok(Settings::builtin(os)), "{os:?}");
        }
        let builtin = Settings::builtin(Os::Macos);
        let means = [Action::Config, Action::WsOpen, Action::WsDelete].map(|action| builtin.means(action));
        assert_eq!(means, [Some(Means::Sudo), Some(Means::Passphrase), Some(Means::Passphrase)]);
        assert_eq!(BOX_ACTIONS.map(|action| builtin.means(action)), [Some(Means::TouchId); 5], "a box asks for Touch ID, as it always did");
        assert_eq!((builtin.engine, builtin.keys), (Some(Engine::Container), Some(Keys::Keychain)));
        assert_eq!(builtin.workspaces.path, util::store_root().join(names::WS_DIR), "where workspaces always were");
        let shown = format!(
            "\n[approval]\ndefault = \"sudo\"\nconfig  = \"sudo\"\n\n[paths]\nworkspaces = \"~/{}/ws\"\n\n[passwords]\nmanager = \"none\"\n\n[secrets]\nstore = \"files\"\n\n\
             [workspace]\npassphrase = \"own\"\n\n[workspace.approval]\nopen   = \"passphrase\"\ndelete = \"passphrase\"\n\n\
             [box]\nengine = \"container\"\nkeys   = \"keychain\"\n\n[box.approval]\nrun    = \"touchid\"\npolicy = \"touchid\"\nwrite  = \"touchid\"\n\
             export = \"touchid\"\ndelete = \"touchid\"\n",
            util::DEV_STORE_ROOT
        );
        assert_eq!(builtin.render(Os::Macos), shown);
        assert!(rows().iter().all(|row| TABLES.contains(&row.table)), "every setting is in a section the template has");
    }

    #[test]
    fn every_refusal_names_its_line_and_why() {
        let cases = [
            ("[nope]\n", Os::Macos, 1, "halti has no section with this name"),
            ("[workspace.nope]\n", Os::Macos, 1, "halti has no section with this name"),
            ("[paths]\nfolder = \"~/ws\"\n", Os::Macos, 2, "[paths] has no setting with this name"),
            ("default = \"sudo\"\n", Os::Macos, 1, "a setting has to be in a section"),
            ("\n[approval]\ndefault = 1\n", Os::Macos, 3, "default takes a word in quotes, like \"sudo\""),
            ("[paths]\nworkspaces = 1\n", Os::Macos, 2, "workspaces takes a path in quotes"),
            ("[approval]\ndefault = \"always\"\n", Os::Macos, 2, "default can be sudo, touchid or passphrase"),
            ("[approval]\ndefault = \"none\"\n", Os::Macos, 2, "default can't be none. it can be sudo, touchid or passphrase"),
            ("[approval]\ndefault = \"touchid\"\n", Os::Linux, 2, "touchid is only on a mac"),
            ("[approval]\nconfig = \"none\"\n", Os::Macos, 2, "config can't be none. it can be sudo or touchid"),
            ("[approval]\nconfig = \"none\"\n", Os::Linux, 2, "config can't be none. it can only be sudo"),
            ("[approval]\nconfig = \"passphrase\"\n", Os::Macos, 2, "config can't be passphrase. it can be sudo or touchid"),
            ("[approval]\nconfig = \"touchid\"\n", Os::Linux, 2, "touchid is only on a mac"),
            ("[workspace.approval]\nopen = \"sudo\"\n", Os::Linux, 2, "open can't be sudo. it can only be passphrase"),
            ("[workspace.approval]\ndelete = \"none\"\n", Os::Linux, 2, "delete can't be none. it can only be passphrase"),
            ("[workspace.approval]\nopen = \"touchid\"\n", Os::Linux, 2, "touchid is only on a mac"),
            ("[workspace.approval]\nopen = \"always\"\n", Os::Macos, 2, "open can be passphrase, sudo, touchid or none"),
            // A workspace's line that takes the passphrase from a password manager, where the file names none.
            ("[workspace.approval]\nopen = \"sudo\"\n", Os::Macos, 2, "open can't be sudo while [passwords] manager is none"),
            ("[workspace.approval]\ndelete = \"none\"\n", Os::Macos, 2, "delete can't be none while [passwords] manager is none"),
            ("[passwords]\nmanager = \"none\"\n[workspace.approval]\ndelete = \"touchid\"\n", Os::Macos, 4, "delete can't be touchid while [passwords] manager is none"),
            ("[passwords]\nmanager = \"keychain\"\n", Os::Linux, 2, "keychain is only on a mac"),
            ("[passwords]\nmanager = \"vault\"\n", Os::Macos, 2, "manager can be none or keychain"),
            ("[passwords]\nmanager = \"vault\"\n", Os::Linux, 2, "manager can only be none"),
            ("[secrets]\nstore = \"keychain\"\n", Os::Macos, 2, "store can only be files"),
            ("[workspace]\npassphrase = \"typed\"\n", Os::Macos, 2, "passphrase can be own or generate"),
            ("[box]\nengine = \"tart\"\n", Os::Macos, 2, "engine can only be container"),
            ("[box]\nengine = \"container\"\n", Os::Linux, 2, "engine can't be set on this system"),
            ("[box]\nkeys = \"files\"\n", Os::Macos, 2, "keys can only be keychain"),
            ("[box]\nkeys = \"keychain\"\n", Os::Linux, 2, "keys can't be set on this system"),
            ("[box]\nrun = \"touchid\"\n", Os::Macos, 2, "[box] has no setting with this name"),
            ("[box.nope]\n", Os::Macos, 1, "halti has no section with this name"),
            ("[box.approval]\nopen = \"touchid\"\n", Os::Macos, 2, "[box.approval] has no setting with this name"),
            ("[box.approval]\nrun = \"passphrase\"\n", Os::Macos, 2, "run can't be passphrase. it can be touchid, sudo or none"),
            ("[box.approval]\nwrite = \"sudo\"\n", Os::Macos, 2, "write can't be sudo. it can be touchid or none"),
            ("[box.approval]\nwrite = \"passphrase\"\n", Os::Macos, 2, "write can't be passphrase. it can be touchid or none"),
            ("[box.approval]\nexport = \"always\"\n", Os::Macos, 2, "export can be touchid, sudo or none"),
            ("[box.approval]\nrun = \"sudo\"\n", Os::Linux, 2, "run can't be set on this system"),
            ("[paths]\nworkspaces = \"work/ws\"\n", Os::Macos, 2, "workspaces has to start with ~/ or /"),
            ("[paths]\nworkspaces = \"~root/ws\"\n", Os::Macos, 2, "workspaces has to start with ~/ or /"),
            ("[paths]\nworkspaces = \"~/\"\n", Os::Macos, 2, "workspaces has to name a folder below ~/ or /"),
            ("[paths]\nworkspaces = \"/\"\n", Os::Linux, 2, "workspaces has to name a folder below ~/ or /"),
            ("[paths]\nworkspaces = \"~//tmp/ws\"\n", Os::Macos, 2, "workspaces can't have // in it or a / at the end"),
            ("[paths]\nworkspaces = \"/srv//ws\"\n", Os::Linux, 2, "workspaces can't have // in it or a / at the end"),
            ("[paths]\nworkspaces = \"~/work/ws/\"\n", Os::Macos, 2, "workspaces can't have // in it or a / at the end"),
            ("[paths]\nworkspaces = \"~/a/../b\"\n", Os::Macos, 2, "workspaces can't have a . or .. part"),
            ("[paths]\nworkspaces = \"~/./ws\"\n", Os::Macos, 2, "workspaces can't have a . or .. part"),
            ("[paths]\nworkspaces = \"~/work/ws \"\n", Os::Macos, 2, "workspaces can't have a tab, or a space at the start or end of a part"),
            ("[paths]\nworkspaces = \"~/ work/ws\"\n", Os::Macos, 2, "workspaces can't have a tab, or a space at the start or end of a part"),
            ("[paths]\nworkspaces = \"~/work\tws\"\n", Os::Macos, 2, "workspaces can't have a tab, or a space at the start or end of a part"),
            // Only plain ascii, with no backslash: nothing in the file reads as other than it is.
            ("[approval]\n# fine\nconfig = \"sudo\" \x1b[2J\n", Os::Macos, 3, "this line has a control character in it"),
            ("[approval]\r\nconfig = \"sudo\"\r\n", Os::Macos, 1, "this line has a control character in it"),
            ("[paths]\n# \u{202e}sw/krow\n", Os::Macos, 2, "this line has a character that isn't plain ascii"),
            ("[paths]\nworkspaces = \"~/work/ws\u{200b}\"\n", Os::Macos, 2, "this line has a character that isn't plain ascii"),
            ("[paths]\nworkspaces = \"~/caf\u{e9}\"\n", Os::Macos, 2, "this line has a character that isn't plain ascii"),
            ("[paths]\nworkspaces = \"~/a\\u0007b\"\n", Os::Macos, 2, "this line has a backslash in it"),
            ("[approval]\nconfig = \"\\u0074ouchid\"\n", Os::Macos, 2, "this line has a backslash in it"),
            ("[paths]\n# a \\ b\n", Os::Macos, 2, "this line has a backslash in it"),
            // Names bare, values in double quotes on one line: what is shown is what is read.
            ("[\"approval\"]\nconfig = \"sudo\"\n", Os::Macos, 1, "a name has to be written without quotes"),
            ("[approval]\n\"config\" = \"sudo\"\n", Os::Macos, 2, "a name has to be written without quotes"),
            ("[approval]\n'config' = \"sudo\"\n", Os::Macos, 2, "a name has to be written without quotes"),
            ("[workspace.\"approval\"]\nopen = \"passphrase\"\n", Os::Macos, 1, "a name has to be written without quotes"),
            ("[\"workspace.approval\"]\nopen = \"passphrase\"\n", Os::Macos, 1, "a name has to be written without quotes"),
            ("[workspace]\n[\"workspace\".approval]\nopen = \"passphrase\"\n", Os::Macos, 2, "a name has to be written without quotes"),
            ("[approval]\nconfig = 'sudo'\n", Os::Macos, 2, "a value has to be in double quotes, on one line"),
            ("[approval]\nconfig = \"\"\"sudo\"\"\"\n", Os::Macos, 2, "a value has to be in double quotes, on one line"),
            ("[paths]\nworkspaces = \"\"\"\n~/work/ws\"\"\"\n", Os::Macos, 2, "a value has to be in double quotes, on one line"),
            ("[paths]\nworkspaces = '''~/work/ws'''\n", Os::Macos, 2, "a value has to be in double quotes, on one line"),
            // Of two problems, the first in the file.
            ("[workspace]\npassphrase = \"own\"\nother = 1\n[nope]\n", Os::Macos, 3, "[workspace] has no setting with this name"),
            ("[paths]\nworkspaces = [\"~/work/ws\"]\n", Os::Macos, 2, "workspaces takes a path in quotes"),
        ];
        for (text, os, line, why) in cases {
            assert_eq!(parse(text, os), Err(Refused { line, why: why.to_string() }), "{text:?}");
        }
        for broken in ["[approval\n", "[approval]\nconfig = sudo\n", "[paths]\nworkspaces = \"a\"\nworkspaces = \"b\"\n"] {
            let refused = parse(broken, Os::Macos).unwrap_err();
            assert_eq!(refused.why, "this line isn't valid toml", "{broken:?}");
            assert!((1..=4).contains(&refused.line), "{broken:?}: {refused}");
        }
        assert_eq!(Refused { line: 5, why: "config can't be none".into() }.to_string(), "line 5: config can't be none");
    }

    #[test]
    fn nothing_from_the_file_is_echoed() {
        for text in ["[paths]\n\"\\u001b[2J\" = 1\n", "[\"\\u001b[31mevil\"]\n", "[paths]\nworkspaces = \"~/\\u001b[2J\"\n", "[\"evil\"]\n", "[paths]\n\"\x1b[2J\" = 1\n"] {
            let refused = parse(text, Os::Macos).unwrap_err().to_string();
            assert!(refused.starts_with("line ") && !refused.contains('\x1b') && !refused.contains("[2J") && !refused.contains("evil"), "{refused}");
        }
    }

    #[test]
    fn a_missing_line_takes_the_template_s_and_an_approval_follows_default() {
        for os in BOTH {
            assert_eq!(parse("", os), Ok(Settings::builtin(os)));
            assert_eq!(parse("# mine\n[workspace]\npassphrase = \"own\"\n", os), Ok(Settings::builtin(os)), "comments don't count");
            let passphrase = parse("[approval]\ndefault = \"passphrase\"\n", os).unwrap();
            assert_eq!((passphrase.means(Action::Config), passphrase.means(Action::WsOpen)), (Some(Means::Sudo), Some(Means::Passphrase)));
        }
        let touch_id = parse("[approval]\ndefault = \"touchid\"\n", Os::Macos).unwrap();
        assert_eq!((touch_id.means(Action::Config), touch_id.means(Action::WsDelete)), (Some(Means::TouchId), Some(Means::Passphrase)));
        let moved = parse("[paths]\nworkspaces = \"/srv/ws\"\n", Os::Linux).unwrap();
        assert_eq!(moved.workspaces, Workspaces { written: "/srv/ws".into(), path: PathBuf::from("/srv/ws") });
        assert_ne!(moved, Settings::builtin(Os::Linux));
        assert_eq!(parse("[paths]\nworkspaces = \"~/work/ws\"\n", Os::Linux).unwrap().workspaces.path, util::home().join("work/ws"));
        let generate = parse("[workspace]\npassphrase = \"generate\"\n", Os::Linux).unwrap();
        assert_eq!((generate.passphrase, generate.manager, generate.store), (PassphraseMode::Generate, Manager::None, Store::Files));
        // What is shown parses back to the same, a path with spaces, a quote mark and a # in it too.
        let odd = parse("[paths]\nworkspaces = \"/srv/my ws's #1\" # mine\n", Os::Linux).unwrap();
        assert_eq!(odd.workspaces.written, "/srv/my ws's #1");
        assert_eq!(parse(&format!("{HEADER}\n{}", odd.lines(Os::Linux, true)), Os::Linux), Ok(odd.clone()));
        assert_eq!(parse(&odd.render(Os::Linux), Os::Linux), Ok(odd));
    }

    #[test]
    fn a_copy_from_before_the_box_lines_keeps_touch_id_for_boxes() {
        let before = template(Os::Macos).split("\n[box]").next().unwrap().to_string();
        assert!(before.ends_with("deleting a workspace: passphrase | sudo | touchid | none\n") && !before.contains("box"), "{before}");
        assert_eq!(parse(&before, Os::Macos), Ok(Settings::builtin(Os::Macos)));
        // Whatever `default` says, a box's missing line is Touch ID, as boxes asked before they had lines.
        for default in ["sudo", "touchid", "passphrase"] {
            let settings = parse(&before.replace("default = \"sudo\"", &format!("default = \"{default}\"")), Os::Macos).unwrap();
            assert_eq!(BOX_ACTIONS.map(|action| settings.means(action)), [Some(Means::TouchId); 5], "{default}");
            assert_eq!((settings.engine, settings.keys), (Some(Engine::Container), Some(Keys::Keychain)));
        }
        // No box runs on Linux: no lines, and nothing approves a box's action.
        let linux = Settings::builtin(Os::Linux);
        assert_eq!((linux.engine, linux.keys), (None, None));
        assert_eq!(BOX_ACTIONS.map(|action| linux.means(action)), [None; 5]);
        assert!(!template(Os::Linux).contains("box") && !linux.render(Os::Linux).contains("box"));
        assert_eq!(default_choices(Os::Macos), [Means::Sudo, Means::TouchId, Means::Passphrase], "a box's none isn't a default");

        // A line says otherwise, and what is shown reads back the same.
        let mine = parse("[box]\nengine = \"container\"\n\n[box.approval]\nrun = \"sudo\"\nwrite = \"none\"\nexport = \"none\"\n", Os::Macos).unwrap();
        let said = BOX_ACTIONS.map(|action| mine.means(action));
        assert_eq!(said, [Some(Means::Sudo), Some(Means::TouchId), Some(Means::None), Some(Means::None), Some(Means::TouchId)]);
        assert_ne!(mine, Settings::builtin(Os::Macos));
        assert_eq!(parse(&mine.render(Os::Macos), Os::Macos), Ok(mine.clone()));
        assert_eq!(parse(&format!("{HEADER}\n{}", mine.lines(Os::Macos, true)), Os::Macos), Ok(mine));
    }

    #[test]
    fn with_the_keychain_as_manager_a_workspace_is_approved_as_its_lines_say() {
        let managed = |open: &str, delete: &str| format!("[passwords]\nmanager = \"keychain\"\n\n[workspace.approval]\nopen = \"{open}\"\ndelete = \"{delete}\"\n");
        let ws = |settings: &Settings| (settings.manager, settings.means(Action::WsOpen), settings.means(Action::WsDelete));
        for (open, delete, means) in [("sudo", "touchid", (Means::Sudo, Means::TouchId)), ("none", "passphrase", (Means::None, Means::Passphrase))] {
            let settings = parse(&managed(open, delete), Os::Macos).unwrap();
            assert_eq!(ws(&settings), (Manager::Keychain, Some(means.0), Some(means.1)), "{open} {delete}");
            // What is shown reads back the same.
            assert_eq!(parse(&settings.render(Os::Macos), Os::Macos), Ok(settings.clone()));
        }
        // The manager alone changes no approval: a workspace's missing line is its passphrase, whatever `default` says.
        for default in ["sudo", "touchid", "passphrase"] {
            let settings = parse(&format!("[approval]\ndefault = \"{default}\"\n\n[passwords]\nmanager = \"keychain\"\n"), Os::Macos).unwrap();
            assert_eq!(ws(&settings), (Manager::Keychain, Some(Means::Passphrase), Some(Means::Passphrase)), "{default}");
        }
        // The line that says the manager is the one that counts, wherever it is in the file.
        let after = "[workspace.approval]\nopen = \"touchid\"\n\n[passwords]\nmanager = \"keychain\"\n";
        assert_eq!(parse(after, Os::Macos).unwrap().means(Action::WsOpen), Some(Means::TouchId));
        assert_eq!(parse(&after.replace("keychain", "none"), Os::Macos), Err(Refused { line: 2, why: "open can't be touchid while [passwords] manager is none".into() }));
        // Linux has no manager: the keychain is refused, and so is any means but the passphrase.
        let refused = parse(&managed("passphrase", "passphrase"), Os::Linux).unwrap_err();
        assert_eq!(refused, Refused { line: 2, why: "keychain is only on a mac".into() });
        assert_eq!(parse("[workspace.approval]\nopen = \"passphrase\"\n", Os::Linux).unwrap().means(Action::WsOpen), Some(Means::Passphrase));
    }

    #[test]
    fn a_copy_approved_by_the_build_before_managers_still_reads() {
        for os in BOTH {
            let before = before_managers(os);
            assert!(before.contains("manager = \"none\"              # none\n") && before.contains("opening a workspace: passphrase\n"), "{before}");
            assert_eq!(parse(&before, os), Ok(Settings::builtin(os)), "{os:?}");
            // With any `default` it took, a workspace still opens and is deleted with its passphrase typed.
            for default in default_choices(os) {
                let settings = parse(&before.replace("default = \"sudo\"", &format!("default = \"{}\"", default.name())), os).unwrap();
                assert_eq!((settings.means(Action::WsOpen), settings.means(Action::WsDelete)), (Some(Means::Passphrase), Some(Means::Passphrase)), "{os:?} {default:?}");
                assert_eq!(settings.manager, Manager::None);
            }
        }
        // As the approved copy: in effect, with nothing said about it.
        let fake = Fake::answering(true, true);
        *fake.anchor.borrow_mut() = Some(before_managers(Os::Macos));
        let now = in_effect(&fake, &place(), Os::Macos);
        assert_eq!((now.source, now.notes.len(), now.settings), (Source::Sudo, 0, Settings::builtin(Os::Macos)));
    }

    #[test]
    fn sudo_writes_the_approved_copy_and_a_no_changes_nothing() {
        let os = Os::Linux;
        let fake = Fake::answering(true, true);
        let now = in_effect(&fake, &place(), os);
        assert_eq!((now.source, now.notes.len(), now.text.as_str()), (Source::Template, 0, template(os).as_str()));
        let moved = text(os, "sudo", "~/work/ws");
        approve(&fake, &now, &moved, os).unwrap();
        assert_eq!(fake.calls(), ["sudo write"]);
        let now = in_effect(&fake, &place(), os);
        assert_eq!((now.source, now.text.as_str(), now.settings.workspaces.written.as_str()), (Source::Sudo, moved.as_str(), "~/work/ws"));
        assert!(!now.by_touch_id() && !now.record_gone());

        let no = Fake::answering(false, true);
        *no.anchor.borrow_mut() = Some(moved.clone());
        let error = approve(&no, &now, &text(os, "sudo", "~/other/ws"), os).unwrap_err();
        assert_eq!(error.to_string(), format!("not approved, so nothing changed. your edits stay in {FILE}. approve them with: halti config"));
        assert_eq!((no.calls(), no.anchor.borrow().clone()), (vec!["sudo write".to_string()], Some(moved.clone())));

        // A write that failed part way changed the copy, and halti says so instead.
        let cut = Fake::answering(true, true);
        *cut.anchor.borrow_mut() = Some(moved.clone());
        cut.cut.set(true);
        let error = approve(&cut, &now, &text(os, "sudo", "~/other/ws"), os).unwrap_err();
        assert_eq!(error.to_string(), "/nowhere/approved/501.toml was changed, but the write didn't finish. approve your settings again with: halti config");
        assert_ne!(cut.anchor.borrow().as_deref(), Some(moved.as_str()));
    }

    #[test]
    fn touch_id_keeps_its_approvals_under_the_copy_sudo_approved() {
        let os = Os::Macos;
        let fake = Fake::answering(true, true);
        // From sudo to Touch ID: sudo writes the copy, and its record is made at once.
        let touch_id = text(os, "touchid", "~/work/ws");
        approve(&fake, &in_effect(&fake, &place(), os), &touch_id, os).unwrap();
        let key = approved::record_key(&touch_id);
        assert_eq!(fake.calls(), ["sudo write".to_string(), format!("pin {key}")]);
        let now = in_effect(&fake, &place(), os);
        assert_eq!((now.source, now.notes.len()), (Source::TouchId, 0));

        // Then a change is Touch ID's alone: the record changes, the copy doesn't.
        let changed = text(os, "touchid", "~/other/ws");
        approve(&fake, &now, &changed, os).unwrap();
        assert_eq!(fake.calls(), [format!("touch id: {TOUCH_ID}"), format!("pin {key}")]);
        assert_eq!(fake.anchor.borrow().as_deref(), Some(touch_id.as_str()));
        let now = in_effect(&fake, &place(), os);
        assert_eq!((now.source, now.text.as_str(), now.settings.workspaces.written.as_str()), (Source::TouchId, changed.as_str(), "~/other/ws"));

        // Touch ID says no: nothing changes.
        let no = Fake::answering(true, false);
        *no.anchor.borrow_mut() = Some(touch_id.clone());
        no.records.borrow_mut().insert(key.clone(), changed.clone());
        let refused = approve(&no, &in_effect(&no, &place(), os), &text(os, "touchid", "~/third/ws"), os).unwrap_err();
        assert!(refused.to_string().starts_with("not approved, so nothing changed"), "{refused}");
        assert_eq!((no.records.borrow().get(&key), no.anchor.borrow().as_deref()), (Some(&changed), Some(touch_id.as_str())));

        // Back to sudo: sudo writes the copy, and the record goes.
        let back = text(os, "sudo", "~/other/ws");
        approve(&fake, &now, &back, os).unwrap();
        assert_eq!(fake.calls(), ["sudo write".to_string(), format!("unpin {key}")]);
        assert!(fake.records.borrow().is_empty());
        let now = in_effect(&fake, &place(), os);
        assert_eq!((now.source, now.text.as_str()), (Source::Sudo, back.as_str()));
    }

    #[test]
    fn a_missing_stale_or_foreign_record_leaves_the_copy_sudo_approved() {
        let os = Os::Macos;
        let fake = Fake::answering(true, true);
        let touch_id = text(os, "touchid", "~/work/ws");
        *fake.anchor.borrow_mut() = Some(touch_id.clone());
        let found = |fake: &Fake| {
            let now = in_effect(fake, &place(), os);
            (now.source, now.text, now.notes)
        };
        let gone = (Source::Sudo, touch_id.clone(), vec![RECORD_GONE.to_string()]);
        assert_eq!(found(&fake), gone);
        // One made under an older copy is under another name; one under this name that isn't settings is no record.
        fake.records.borrow_mut().insert(approved::record_key("[paths]\n"), text(os, "touchid", "~/stale/ws"));
        assert_eq!(found(&fake), gone);
        fake.records.borrow_mut().insert(approved::record_key(&touch_id), "not settings".to_string());
        assert_eq!(found(&fake), gone);

        // Approving it again, changed or not, makes the record with Touch ID.
        let now = in_effect(&fake, &place(), os);
        assert!(now.record_gone());
        approve(&fake, &now, &touch_id, os).unwrap();
        assert_eq!(fake.calls(), [format!("touch id: {TOUCH_ID}"), format!("pin {}", approved::record_key(&touch_id))]);
        assert_eq!(found(&fake), (Source::TouchId, touch_id, vec![]));
    }

    #[test]
    fn a_copy_that_is_not_settings_leaves_the_template() {
        let fake = Fake::answering(true, true);
        *fake.anchor.borrow_mut() = Some("[approval]\nconfig = \"none\"\n".to_string());
        let now = in_effect(&fake, &place(), Os::Linux);
        assert_eq!((now.source, &now.settings), (Source::Template, &Settings::builtin(Os::Linux)));
        let note = "/nowhere/approved/501.toml can't be used (line 2: config can't be none. it can only be sudo), so halti's template is in effect. \
                    approve your settings again with: halti config";
        assert_eq!(now.notes, [note]);
        // Approving the template's own settings is a change then: the copy is written again, and the note goes.
        let builtin = Settings::builtin(Os::Linux);
        assert!(!now.unchanged(&builtin) && in_effect(&Fake::answering(true, true), &place(), Os::Linux).unchanged(&builtin));
        approve(&fake, &now, &template(Os::Linux), Os::Linux).unwrap();
        assert_eq!(fake.calls(), ["sudo write"]);
        let now = in_effect(&fake, &place(), Os::Linux);
        assert_eq!((now.source, now.notes.len(), now.unchanged(&builtin)), (Source::Sudo, 0, true));
    }

    #[test]
    fn a_link_to_a_file_that_isn_t_there_is_named_and_left_alone() {
        let dir = TempDir::new("halti-config-link").unwrap();
        let path = dir.0.join("config.toml");
        symlink(dir.0.join("dotfiles/config.toml"), &path).unwrap();
        let error = ready_file(&path, "[paths]\n").unwrap_err();
        assert_eq!(error.to_string(), format!("{} is a link to a file that isn't there. make that file, or remove the link", path.display()));
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_symlink() && !dir.0.join("dotfiles").exists());
        fs::remove_file(&path).unwrap();
        ready_file(&path, "[paths]\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "[paths]\n");
        ready_file(&path, "[approval]\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "[paths]\n", "a file that is there is left as it is");
    }

    #[test]
    fn the_person_s_file_is_as_in_effect_pending_or_unusable() {
        let dir = TempDir::new("halti-config-file").unwrap();
        let path = dir.0.join("config.toml");
        let now = in_effect(&Fake::answering(true, true), &place(), Os::Linux);
        let notes = || person_notes(&path, &now, Os::Linux);
        assert!(notes().is_empty(), "no file");
        fs::write(&path, format!("# mine\n{}", template(Os::Linux))).unwrap();
        assert!(notes().is_empty(), "comments only");
        let stay = "so the settings stay as they were. fix it with: halti config";
        let shown = path.display();
        fs::write(&path, "[paths]\nworkspaces = \"/srv/ws\"\n").unwrap();
        let pending = format!("changes in {shown} aren't approved yet, so they have no effect. approve them with: halti config");
        assert_eq!(notes(), std::slice::from_ref(&pending));
        fs::write(&path, "[paths]\nworkspaces = 1\n").unwrap();
        assert_eq!(notes(), [format!("{shown} can't be used (line 2: workspaces takes a path in quotes), {stay}")]);
        fs::write(&path, "#".repeat(17 << 10)).unwrap();
        assert_eq!(notes(), [format!("{shown} is larger than 16 KiB, {stay}")]);
        fs::write(&path, b"# \xff\n").unwrap();
        assert_eq!(notes(), [format!("{shown} isn't text, {stay}")]);
        // A link is followed; a folder isn't read.
        let elsewhere = dir.0.join("dotfiles.toml");
        fs::write(&elsewhere, "[paths]\nworkspaces = \"/srv/ws\"\n").unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&elsewhere, &path).unwrap();
        assert_eq!(notes(), [pending]);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(notes(), [format!("{shown} isn't a plain file, {stay}")]);
    }

    #[test]
    fn the_person_s_file_is_made_private() {
        let dir = TempDir::new("halti-config-create").unwrap();
        let path = dir.0.join("config/halti/config.toml");
        create(&path, "[paths]\n").unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&path), mode(&dir.0.join("config/halti")), fs::read_to_string(&path).unwrap()), (0o600, 0o700, "[paths]\n".to_string()));
        assert!(create(&path, "[paths]\n").is_err(), "never over a file that is there");
        assert_eq!(read_file(&path).unwrap().as_deref(), Some("[paths]\n"));
    }
}
