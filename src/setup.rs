//! `halti setup`: where a new workspace's passphrase is kept, and where its stored secrets live.
//!
//! Each setting is a short list of built-in choices (`Choice`), and a new place to keep something
//! is one more variant of its enum: a name for the setup file, one line saying what it means, and
//! the systems that have it. A setup is taken whole from a ready-made set (`Template`: `mac`,
//! `linux`), or setting by setting (`custom`), and kept in one small file in the config folder.
//!
//! Only `halti setup` and `halti ws new` read the file: a workspace that exists opens with what it
//! was made with, which its own records hold, so changing the setup changes nothing about it. The
//! file names built-in choices only, never a path, a command or a library, and a file that holds
//! anything else is refused, never guessed at.
//!
//! halti asks only where there is something to choose, and asks on the terminal itself, never on
//! standard input. With one choice for each setting, as today, it asks nothing.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{Context, Result, anyhow, bail};
use halti_core::platform::Os;
use serde::Deserialize;

use crate::ws::OS;
use crate::{names, util};

/// The last line of a setup that was just saved.
const SAVED: &str = "saved. change it with: halti setup";

/// What `halti setup` says after the setup when there is nothing to choose on this system.
const NOTHING_ELSE: &str = "there is nothing else to choose yet";

/// What `halti setup --show` says with no setup file.
const NOT_SET_UP: &str = "nothing is set up yet. run: halti setup";

/// The error when a question got no answer, or three that weren't one of the choices.
const NOTHING_CHOSEN: &str = "nothing was chosen";

/// The most bytes a setup file is read with: far more than halti writes.
const MOST: u64 = 4096;

/// One built-in choice for a setting. A new place to keep something is one more variant.
pub trait Choice: Copy + PartialEq + 'static {
    /// The setting's name, in the file and on every screen.
    const SETTING: &'static str;
    /// What `custom` asks when this system has more than one choice for it.
    const QUESTION: &'static str;
    /// Every built-in choice, in the order they are offered.
    const ALL: &'static [Self];
    /// Its name in the setup file.
    fn name(self) -> &'static str;
    /// What it means, in one line.
    fn about(self, os: Os) -> String;
    /// Whether this system has it.
    fn available(self, os: Os) -> bool;
}

/// Where a workspace's passphrase is kept for daily use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PassphraseChoice {
    /// Kept nowhere: typed at each open.
    Typed,
}

impl Choice for PassphraseChoice {
    const SETTING: &'static str = "passphrase";
    const QUESTION: &'static str = "where is a workspace's passphrase kept?";
    const ALL: &'static [PassphraseChoice] = &[PassphraseChoice::Typed];

    fn name(self) -> &'static str {
        match self {
            PassphraseChoice::Typed => "typed",
        }
    }

    fn about(self, _os: Os) -> String {
        match self {
            PassphraseChoice::Typed => "typed each time you open a workspace".to_string(),
        }
    }

    fn available(self, _os: Os) -> bool {
        match self {
            PassphraseChoice::Typed => true,
        }
    }
}

/// Where a workspace's stored secrets live.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecretsChoice {
    /// In halti's own files.
    Files,
}

impl Choice for SecretsChoice {
    const SETTING: &'static str = "secrets";
    const QUESTION: &'static str = "where are a workspace's secrets kept?";
    const ALL: &'static [SecretsChoice] = &[SecretsChoice::Files];

    fn name(self) -> &'static str {
        match self {
            SecretsChoice::Files => "files",
        }
    }

    fn about(self, os: Os) -> String {
        match self {
            SecretsChoice::Files => format!("kept in halti's files on this {}", place(os)),
        }
    }

    fn available(self, _os: Os) -> bool {
        match self {
            SecretsChoice::Files => true,
        }
    }
}

/// This system, as the screens name it.
fn place(os: Os) -> &'static str {
    match os {
        Os::Macos => "mac",
        Os::Linux => "system",
    }
}

/// The choices this system has for a setting, in order.
fn offered<C: Choice>(os: Os) -> Vec<C> {
    C::ALL.iter().copied().filter(|choice| choice.available(os)).collect()
}

/// The choice with this name in the setup file.
fn named<C: Choice>(name: &str) -> Option<C> {
    C::ALL.iter().copied().find(|choice| choice.name() == name)
}

/// Whether there is anything to choose on this system: a setting with more than one choice here.
fn anything_to_choose(os: Os) -> bool {
    offered::<PassphraseChoice>(os).len() > 1 || offered::<SecretsChoice>(os).len() > 1
}

/// Where new workspaces keep things.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Setup {
    pub passphrase: PassphraseChoice,
    pub secrets: SecretsChoice,
}

impl Setup {
    /// Whether this system has every choice in it.
    fn available(&self, os: Os) -> bool {
        self.passphrase.available(os) && self.secrets.available(os)
    }

    /// The screen that shows it.
    fn lines(&self, os: Os) -> [String; 3] {
        let line = |setting: &str, about: String| format!("  {setting:<10}  {about}");
        [format!("halti setup for this {}", place(os)), line(PassphraseChoice::SETTING, self.passphrase.about(os)), line(SecretsChoice::SETTING, self.secrets.about(os))]
    }
}

/// A ready-made setup, named after the system it is made for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Template {
    Mac,
    Linux,
}

impl Template {
    pub const ALL: [Template; 2] = [Template::Mac, Template::Linux];

    pub fn name(self) -> &'static str {
        match self {
            Template::Mac => "mac",
            Template::Linux => "linux",
        }
    }

    /// Today both are the same; each can change on its own.
    pub fn setup(self) -> Setup {
        match self {
            Template::Mac => Setup { passphrase: PassphraseChoice::Typed, secrets: SecretsChoice::Files },
            Template::Linux => Setup { passphrase: PassphraseChoice::Typed, secrets: SecretsChoice::Files },
        }
    }

    /// The one for the system halti runs on: what is used unless something else is chosen.
    pub fn for_os(os: Os) -> Template {
        match os {
            Os::Macos => Template::Mac,
            Os::Linux => Template::Linux,
        }
    }

    fn named(name: &str) -> Option<Template> {
        Template::ALL.into_iter().find(|template| template.name() == name)
    }
}

/// The setup file: in the config folder, which a release build finds from the passwd entry.
fn path() -> PathBuf {
    util::config_dir().join(names::SETUP_FILE)
}

/// The setup file as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Written {
    version: i64,
    passphrase: String,
    secrets: String,
}

/// The setup a file's text says, if it is one halti wrote: the three keys and nothing else,
/// version 1, and a built-in choice for each setting.
fn parse(text: &str) -> Option<Setup> {
    let written: Written = toml::from_str(text).ok()?;
    if written.version != 1 {
        return None;
    }
    Some(Setup { passphrase: named(&written.passphrase)?, secrets: named(&written.secrets)? })
}

/// The file's text.
fn render(setup: &Setup) -> String {
    format!(
        "# halti setup: where new workspaces keep things. change it with: halti setup\nversion = 1\n{} = \"{}\"\n{} = \"{}\"\n",
        PassphraseChoice::SETTING,
        setup.passphrase.name(),
        SecretsChoice::SETTING,
        setup.secrets.name()
    )
}

/// What is in the setup file's place.
#[derive(PartialEq, Eq, Debug)]
enum Found {
    Nothing,
    /// Anything that isn't a setup file halti wrote: a link, a pipe, too large, not text, or not its format.
    Broken,
    Setup(Setup),
}

fn read(at: &Path) -> Found {
    let file = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(at) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Found::Nothing,
        Err(_) => return Found::Broken,
    };
    let mut bytes = Vec::<u8>::new();
    let plain = file.metadata().is_ok_and(|meta| meta.is_file());
    if !plain || file.take(MOST + 1).read_to_end(&mut bytes).is_err() || bytes.len() as u64 > MOST {
        return Found::Broken;
    }
    match String::from_utf8(bytes).ok().as_deref().and_then(parse) {
        Some(setup) => Found::Setup(setup),
        None => Found::Broken,
    }
}

/// Writes the file whole, 0600: a new file beside it, renamed over it. Its folder is made 0700 if
/// it isn't there.
fn write(at: &Path, setup: &Setup) -> Result<()> {
    let folder = at.parent().expect("the setup file is in the config folder");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(folder).with_context(|| format!("creating {}", folder.display()))?;
    let new = folder.join(format!(".{}.{}", names::SETUP_FILE, process::id()));
    let _ = fs::remove_file(&new);
    let written = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&new).and_then(|mut file| {
        file.write_all(render(setup).as_bytes())?;
        file.sync_all()
    });
    if let Err(e) = written.and_then(|()| fs::rename(&new, at)) {
        let _ = fs::remove_file(&new);
        return Err(e).with_context(|| format!("writing {}", at.display()));
    }
    Ok(())
}

/// Where setup's questions are asked: the terminal, or a test's script.
pub trait Asker {
    fn say(&mut self, line: &str) -> Result<()>;
    /// What was typed after `question`, trimmed and in lowercase; none when the input ends.
    fn ask(&mut self, question: &str) -> Result<Option<String>>;
}

/// The terminal device: questions are shown and answered there, never on standard input.
struct Terminal(File);

impl Asker for Terminal {
    fn say(&mut self, line: &str) -> Result<()> {
        Ok(writeln!(self.0, "{line}")?)
    }

    fn ask(&mut self, question: &str) -> Result<Option<String>> {
        write!(self.0, "{question}")?;
        let mut typed = String::new();
        if BufReader::new(&self.0).read_line(&mut typed)? == 0 {
            return Ok(None);
        }
        Ok(Some(typed.trim().to_lowercase()))
    }
}

/// Where there is no terminal: a question fails with this line, which names what to run instead.
struct NoTerminal(String);

impl Asker for NoTerminal {
    fn say(&mut self, _line: &str) -> Result<()> {
        Ok(())
    }

    fn ask(&mut self, _question: &str) -> Result<Option<String>> {
        Err(anyhow!(self.0.clone()))
    }
}

/// The terminal, or with none, an asker whose questions fail with `instead`.
fn terminal(instead: String) -> Box<dyn Asker> {
    match OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(tty) => Box::new(Terminal(tty)),
        Err(_) => Box::new(NoTerminal(instead)),
    }
}

/// Asks `question` until `take` takes the answer, three tries in all.
fn answer<T>(asker: &mut dyn Asker, question: &str, take: impl Fn(&str) -> Option<T>) -> Result<T> {
    for left in (0..3).rev() {
        let Some(typed) = asker.ask(question)? else { break };
        if let Some(taken) = take(typed.as_str()) {
            return Ok(taken);
        }
        if left > 0 {
            asker.say("that isn't one of the choices, try again")?;
        }
    }
    bail!(NOTHING_CHOSEN)
}

/// Shows `options` by number under `question`, and asks for one.
fn pick(asker: &mut dyn Asker, question: &str, options: &[String]) -> Result<usize> {
    asker.say(question)?;
    for (n, option) in options.iter().enumerate() {
        asker.say(&format!("  {}  {option}", n + 1))?;
    }
    let ask = format!("type a number from 1 to {}: ", options.len());
    answer(asker, &ask, |typed| typed.parse::<usize>().ok().filter(|n| (1..=options.len()).contains(n)).map(|n| n - 1))
}

/// One setting's choice: the only one this system has, or the one picked.
fn one<C: Choice>(asker: &mut dyn Asker, os: Os) -> Result<C> {
    let here = offered::<C>(os);
    if let [only] = here.as_slice() {
        return Ok(*only);
    }
    let options: Vec<String> = here.iter().map(|choice| choice.about(os)).collect();
    Ok(here[pick(asker, C::QUESTION, &options)?])
}

/// `custom`: each setting in turn. Only a setting with more than one choice here is asked.
fn custom(asker: &mut dyn Asker, os: Os) -> Result<Setup> {
    Ok(Setup { passphrase: one(asker, os)?, secrets: one(asker, os)? })
}

/// The first time: this system's template, taken as it is unless there is something to choose.
fn first(asker: &mut dyn Asker, os: Os, choosing: bool) -> Result<Setup> {
    let ready = Template::for_os(os).setup();
    if !choosing {
        return Ok(ready);
    }
    for line in ready.lines(os) {
        asker.say(&line)?;
    }
    let custom_wanted = answer(asker, "press Enter for this, or type custom to choose: ", |typed| match typed {
        "" => Some(false),
        "custom" => Some(true),
        _ => None,
    })?;
    if custom_wanted { custom(asker, os) } else { Ok(ready) }
}

/// An answer to "press Enter to keep it".
enum Again {
    Keep,
    Custom,
    Take(Setup),
}

/// Once set up, and with something to choose: none keeps the setup as it is.
fn again(asker: &mut dyn Asker, os: Os) -> Result<Option<Setup>> {
    let templates: Vec<Template> = Template::ALL.into_iter().filter(|template| template.setup().available(os)).collect();
    let names: Vec<&str> = templates.iter().map(|template| template.name()).collect();
    let question = format!("press Enter to keep it, or type {} or custom: ", names.join(", "));
    let wanted = answer(asker, &question, |typed| match typed {
        "" => Some(Again::Keep),
        "custom" => Some(Again::Custom),
        _ => templates.iter().find(|template| template.name() == typed).map(|template| Again::Take(template.setup())),
    })?;
    match wanted {
        Again::Keep => Ok(None),
        Again::Custom => custom(asker, os).map(Some),
        Again::Take(setup) => Ok(Some(setup)),
    }
}

/// Shows the setup, then `last` if there is one.
fn screen(out: &mut dyn Write, setup: &Setup, os: Os, last: Option<&str>) -> Result<()> {
    for line in setup.lines(os) {
        writeln!(out, "{line}")?;
    }
    if let Some(last) = last {
        writeln!(out, "{last}")?;
    }
    Ok(())
}

fn not_a_setup_file(at: &Path) -> anyhow::Error {
    anyhow!("{} isn't a setup file halti wrote. write it again with: halti setup", at.display())
}

/// `halti setup [mac|linux|custom] [--show]`. Screens go to stdout, questions to the terminal.
pub fn run(template: Option<&str>, show: bool) -> Result<()> {
    let instead = format!("there is no terminal to ask in. to set up without questions: halti setup {}", Template::for_os(OS).name());
    command(&path(), OS, template, show, &mut io::stdout(), &mut *terminal(instead), anything_to_choose(OS))
}

/// `halti setup` with its file at `at`. `choosing`: whether this system has anything to choose.
fn command(at: &Path, os: Os, template: Option<&str>, show: bool, out: &mut dyn Write, asker: &mut dyn Asker, choosing: bool) -> Result<()> {
    let found = read(at);
    if show {
        return match found {
            Found::Setup(setup) => screen(out, &setup, os, None),
            Found::Nothing => bail!(NOT_SET_UP),
            Found::Broken => Err(not_a_setup_file(at)),
        };
    }
    let chosen = match template {
        Some("custom") => custom(asker, os)?,
        Some(name) => {
            let template = Template::named(name).ok_or_else(|| anyhow!("choose mac, linux or custom"))?;
            if !template.setup().available(os) {
                bail!("the {name} setup uses something this {} doesn't have", place(os));
            }
            template.setup()
        }
        None => match found {
            Found::Setup(current) => {
                screen(out, &current, os, None)?;
                if !choosing {
                    writeln!(out, "{NOTHING_ELSE}")?;
                    return Ok(());
                }
                let Some(chosen) = again(asker, os)? else {
                    writeln!(out, "nothing changed")?;
                    return Ok(());
                };
                chosen
            }
            Found::Broken => {
                writeln!(out, "{} couldn't be read, so halti sets it up again", at.display())?;
                first(asker, os, choosing)?
            }
            Found::Nothing => first(asker, os, choosing)?,
        },
    };
    write(at, &chosen)?;
    screen(out, &chosen, os, Some(SAVED))
}

/// For `halti ws new`: the setup, made the first time it is needed, when the screen goes to stderr.
/// A file that isn't halti's, or names something this system doesn't have, is refused.
pub fn ensure() -> Result<Setup> {
    let instead = format!("nothing is set up yet, and there is no terminal to ask in. run: halti setup {}", Template::for_os(OS).name());
    ensure_at(&path(), OS, &mut io::stderr(), &mut *terminal(instead), anything_to_choose(OS))
}

fn ensure_at(at: &Path, os: Os, out: &mut dyn Write, asker: &mut dyn Asker, choosing: bool) -> Result<Setup> {
    match read(at) {
        Found::Setup(setup) if setup.available(os) => Ok(setup),
        Found::Setup(_) => bail!("the setup uses something this {} doesn't have. change it with: halti setup", place(os)),
        Found::Broken => Err(not_a_setup_file(at)),
        Found::Nothing => {
            let setup = first(asker, os, choosing)?;
            write(at, &setup)?;
            screen(out, &setup, os, Some(SAVED))?;
            Ok(setup)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;
    use crate::util::TempDir;

    /// Answers questions from a list, and keeps everything shown as a terminal would show it.
    struct Script {
        answers: Vec<&'static str>,
        shown: String,
    }

    fn script(answers: &[&'static str]) -> Script {
        Script { answers: answers.to_vec(), shown: String::new() }
    }

    impl Asker for Script {
        fn say(&mut self, line: &str) -> Result<()> {
            self.shown += &format!("{line}\n");
            Ok(())
        }

        fn ask(&mut self, question: &str) -> Result<Option<String>> {
            if self.answers.is_empty() {
                self.shown += question;
                return Ok(None);
            }
            let typed = self.answers.remove(0);
            self.shown += &format!("{question}{typed}\n");
            Ok(Some(typed.to_string()))
        }
    }

    const BOTH: [Os; 2] = [Os::Macos, Os::Linux];
    const TYPED_FILES: Setup = Setup { passphrase: PassphraseChoice::Typed, secrets: SecretsChoice::Files };
    const WRITTEN: &str = "# halti setup: where new workspaces keep things. change it with: halti setup\nversion = 1\npassphrase = \"typed\"\nsecrets = \"files\"\n";

    fn shown(out: Vec<u8>) -> String {
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn each_setting_has_a_choice_on_either_system_and_today_only_one() {
        for os in BOTH {
            assert_eq!(offered::<PassphraseChoice>(os), [PassphraseChoice::Typed], "{os:?}");
            assert_eq!(offered::<SecretsChoice>(os), [SecretsChoice::Files], "{os:?}");
            assert!(!anything_to_choose(os), "{os:?}");
        }
        for template in Template::ALL {
            assert_eq!((template.setup(), Template::named(template.name())), (TYPED_FILES, Some(template)));
        }
        assert_eq!((Template::for_os(Os::Macos), Template::for_os(Os::Linux)), (Template::Mac, Template::Linux));
    }

    #[test]
    fn the_file_is_three_keys_and_anything_else_is_refused() {
        assert_eq!(render(&TYPED_FILES), WRITTEN);
        assert_eq!(parse(WRITTEN), Some(TYPED_FILES));
        assert_eq!(parse("version = 1\nsecrets = \"files\"\npassphrase = \"typed\"\n"), Some(TYPED_FILES), "order and comments don't matter");
        for refused in [
            "version = 1\npassphrase = \"typed\"\n",
            "version = 1\npassphrase = \"typed\"\nsecrets = \"files\"\ncommand = \"/bin/sh\"\n",
            "version = 2\npassphrase = \"typed\"\nsecrets = \"files\"\n",
            "version = \"1\"\npassphrase = \"typed\"\nsecrets = \"files\"\n",
            "version = 1\npassphrase = \"/bin/sh\"\nsecrets = \"files\"\n",
            "version = 1\npassphrase = \"Typed\"\nsecrets = \"files\"\n",
            "version = 1\npassphrase = \"typed\"\nsecrets = \"keychain\"\n",
            "version = 1\npassphrase = [\"typed\"]\nsecrets = \"files\"\n",
            "not toml at all",
            "",
        ] {
            assert_eq!(parse(refused), None, "{refused}");
        }
    }

    #[test]
    fn a_file_that_is_a_link_too_large_or_not_text_is_broken() {
        let dir = TempDir::new("halti-setup-read").unwrap();
        let at = dir.0.join("setup.toml");
        assert_eq!(read(&at), Found::Nothing);
        write(&at, &TYPED_FILES).unwrap();
        assert_eq!((read(&at), fs::read_to_string(&at).unwrap().as_str()), (Found::Setup(TYPED_FILES), WRITTEN));
        assert_eq!(fs::metadata(&at).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1, "nothing in the making is left");
        fs::write(&at, format!("{WRITTEN}{}", "#".repeat(5000))).unwrap();
        assert_eq!(read(&at), Found::Broken);
        fs::write(&at, [WRITTEN.as_bytes(), b"# \xff\n".as_slice()].concat()).unwrap();
        assert_eq!(read(&at), Found::Broken);
        let elsewhere = dir.0.join("elsewhere.toml");
        fs::write(&elsewhere, WRITTEN).unwrap();
        fs::remove_file(&at).unwrap();
        symlink(&elsewhere, &at).unwrap();
        assert_eq!(read(&at), Found::Broken, "a link is not followed");
        // Writing replaces the link, never what it points at.
        write(&at, &TYPED_FILES).unwrap();
        assert!(fs::symlink_metadata(&at).unwrap().is_file() && fs::read_to_string(&elsewhere).unwrap() == WRITTEN);
    }

    #[test]
    fn the_folder_is_made_private_where_it_is_missing() {
        let dir = TempDir::new("halti-setup-folder").unwrap();
        let at = dir.0.join("config/halti/setup.toml");
        write(&at, &TYPED_FILES).unwrap();
        assert_eq!(fs::metadata(dir.0.join("config/halti")).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn a_debug_build_keeps_its_setup_apart_from_an_installed_halti() {
        assert!(path().ends_with(format!("{}/setup.toml", util::DEV_CONFIG_DIR)), "{}", path().display());
    }

    #[test]
    fn the_first_time_nothing_is_asked_and_the_setup_is_shown_and_saved() {
        for (os, place) in [(Os::Macos, "mac"), (Os::Linux, "system")] {
            let dir = TempDir::new("halti-setup-first").unwrap();
            let at = dir.0.join("setup.toml");
            let (mut out, mut asker) = (Vec::<u8>::new(), script(&[]));
            assert_eq!(ensure_at(&at, os, &mut out, &mut asker, false).unwrap(), TYPED_FILES);
            let expected =
                format!("halti setup for this {place}\n  passphrase  typed each time you open a workspace\n  secrets     kept in halti's files on this {place}\n{SAVED}\n");
            assert_eq!((shown(out), asker.shown.as_str()), (expected, ""), "{os:?}");
            assert_eq!(fs::read_to_string(&at).unwrap(), WRITTEN);
            // Then it is only read.
            let mut out = Vec::<u8>::new();
            assert_eq!(ensure_at(&at, os, &mut out, &mut asker, false).unwrap(), TYPED_FILES);
            assert!(out.is_empty());
        }
    }

    #[test]
    fn a_broken_file_is_refused_by_ws_new_and_left_as_it_is() {
        let dir = TempDir::new("halti-setup-broken").unwrap();
        let at = dir.0.join("setup.toml");
        let broken = "version = 1\npassphrase = \"/bin/sh\"\nsecrets = \"files\"\n";
        fs::write(&at, broken).unwrap();
        let error = ensure_at(&at, Os::Linux, &mut Vec::<u8>::new(), &mut script(&[]), false).unwrap_err();
        assert_eq!(error.to_string(), format!("{} isn't a setup file halti wrote. write it again with: halti setup", at.display()));
        assert_eq!(fs::read_to_string(&at).unwrap(), broken);
    }

    #[test]
    fn halti_setup_shows_saves_and_says_when_there_is_nothing_else_to_choose() {
        let dir = TempDir::new("halti-setup-command").unwrap();
        let at = dir.0.join("setup.toml");
        let run = |template: Option<&str>, show: bool| {
            let mut out = Vec::<u8>::new();
            let result = command(&at, Os::Macos, template, show, &mut out, &mut NoTerminal("no terminal".into()), false);
            (result.map_err(|e| e.to_string()), shown(out))
        };
        let lines = "halti setup for this mac\n  passphrase  typed each time you open a workspace\n  secrets     kept in halti's files on this mac\n";
        assert_eq!(run(None, true), (Err(NOT_SET_UP.to_string()), String::new()));
        assert_eq!(run(None, false), (Ok(()), format!("{lines}{SAVED}\n")));
        assert_eq!(run(None, true), (Ok(()), lines.to_string()));
        assert_eq!(run(None, false), (Ok(()), format!("{lines}{NOTHING_ELSE}\n")));
        for template in ["mac", "linux", "custom"] {
            assert_eq!(run(Some(template), false), (Ok(()), format!("{lines}{SAVED}\n")), "{template}");
        }
        fs::write(&at, "version = 1\n").unwrap();
        assert!(run(None, true).0.unwrap_err().contains("isn't a setup file halti wrote"));
        let (result, said) = run(None, false);
        assert_eq!((result, said), (Ok(()), format!("{} couldn't be read, so halti sets it up again\n{lines}{SAVED}\n", at.display())));
        assert_eq!(fs::read_to_string(&at).unwrap(), WRITTEN);
    }

    #[test]
    fn with_something_to_choose_and_no_terminal_nothing_is_saved() {
        let dir = TempDir::new("halti-setup-no-tty").unwrap();
        let at = dir.0.join("setup.toml");
        let mut asker = NoTerminal("there is no terminal to ask in. to set up without questions: halti setup mac".into());
        let error = command(&at, Os::Macos, None, false, &mut Vec::<u8>::new(), &mut asker, true).unwrap_err();
        assert_eq!(error.to_string(), "there is no terminal to ask in. to set up without questions: halti setup mac");
        assert!(ensure_at(&at, Os::Macos, &mut Vec::<u8>::new(), &mut asker, true).is_err());
        assert_eq!(read(&at), Found::Nothing);
        // A template asks nothing.
        command(&at, Os::Macos, Some("mac"), false, &mut Vec::<u8>::new(), &mut asker, true).unwrap();
        assert_eq!(read(&at), Found::Setup(TYPED_FILES));
    }

    #[test]
    fn the_questions_read_as_they_should() {
        let lines = "halti setup for this system\n  passphrase  typed each time you open a workspace\n  secrets     kept in halti's files on this system\n";
        let mut asker = script(&["", "custom"]);
        assert_eq!(first(&mut asker, Os::Linux, true).unwrap(), TYPED_FILES);
        assert_eq!(asker.shown, format!("{lines}press Enter for this, or type custom to choose: \n"));
        assert_eq!(first(&mut script(&["custom"]), Os::Linux, true).unwrap(), TYPED_FILES, "custom shows the only choices");

        let mut asker = script(&["", "linux", "custom"]);
        assert_eq!(again(&mut asker, Os::Linux).unwrap(), None);
        assert_eq!(again(&mut asker, Os::Linux).unwrap(), Some(TYPED_FILES));
        assert_eq!(again(&mut asker, Os::Linux).unwrap(), Some(TYPED_FILES));
        assert!(asker.shown.starts_with("press Enter to keep it, or type mac, linux or custom: \n"), "{}", asker.shown);

        // Three wrong answers, or the input ended: nothing was chosen.
        let mut asker = script(&["mac", "yes", "no"]);
        assert_eq!(first(&mut asker, Os::Macos, true).unwrap_err().to_string(), NOTHING_CHOSEN);
        let again_line = "that isn't one of the choices, try again\n";
        let question = "press Enter for this, or type custom to choose: ";
        let tail = format!("{question}mac\n{again_line}{question}yes\n{again_line}{question}no\n");
        assert!(asker.shown.ends_with(&tail), "{}", asker.shown);
        assert_eq!(again(&mut script(&[]), Os::Macos).unwrap_err().to_string(), NOTHING_CHOSEN);
    }

    #[test]
    fn a_setting_with_more_than_one_choice_is_picked_by_number() {
        let options = ["typed each time you open a workspace".to_string(), "kept somewhere else".to_string()];
        let mut asker = script(&["3", "x", "2"]);
        assert_eq!(pick(&mut asker, PassphraseChoice::QUESTION, &options).unwrap(), 1);
        let ask = "type a number from 1 to 2: ";
        let again_line = "that isn't one of the choices, try again\n";
        let expected = format!(
            "where is a workspace's passphrase kept?\n  1  typed each time you open a workspace\n  2  kept somewhere else\n{ask}3\n{again_line}{ask}x\n{again_line}{ask}2\n"
        );
        assert_eq!(asker.shown, expected);
        assert_eq!(pick(&mut script(&["0", "", "-1"]), "?", &options).unwrap_err().to_string(), NOTHING_CHOSEN);
    }
}
