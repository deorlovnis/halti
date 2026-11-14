//! Approvals: which actions ask the person before they happen, and what answers. Each action has a
//! line in halti's settings (`config`) naming its means, one of those its rule accepts: sudo (the
//! person's password, asked by sudo on the terminal), touchid (the Touch ID window, macOS only),
//! passphrase (a workspace's own passphrase, which core asks for anyway) or none.
//!
//! A workspace's lines take passphrase, or another means where a password manager keeps its
//! passphrase (`[passwords] manager`): then the person approves that way, or not at all, and halti
//! takes the passphrase from the manager. Where this system has no manager, they take passphrase only.
//! Writing into a workspace (storing a secret, approving a policy) is never approved by nothing: a
//! value or a policy of someone else's choosing could then be written with no one asked.
//!
//! An action raised while an agent holds the terminal accepts only a means that shows its own
//! window: the agent could answer what is asked on the terminal, or eat the keystrokes.
//!
//! A box's actions have their lines in `[box.approval]`. Where halti runs no box, nothing approves
//! them, and a missing line is Touch ID whatever `[approval] default` says: they asked for Touch ID
//! before they had lines.
//!
//! Adding an action is one variant and one rule; its line in the settings follows from the rule.

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use halti_core::platform::Os;

use crate::config::approved::{self, Found, Place};
use crate::config::{Engine, Manager, Settings, Word};
use crate::{approve, policy, util};

/// What can ask for an approval.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Action {
    /// A change to halti's settings.
    Config,
    /// Opening a workspace, and listing its secrets.
    WsOpen,
    /// Storing a secret in a workspace.
    WsSet,
    /// Removing secrets from a workspace.
    WsRm,
    /// Approving policies in a workspace.
    WsPolicy,
    WsDelete,
    BoxRun,
    /// Approving a box's policy, new or changed.
    BoxPolicy,
    /// A write the box's `[net] writes = "ask"` asks about, raised by the door while the agent works.
    BoxWrite,
    BoxExport,
    BoxDelete,
}

/// What approves an action. Written in full everywhere: `Means::None` isn't `Option::None`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Means {
    Sudo,
    TouchId,
    Passphrase,
    None,
}

impl Word for Means {
    const ALL: &'static [Means] = &[Means::Sudo, Means::TouchId, Means::Passphrase, Means::None];

    fn name(self) -> &'static str {
        match self {
            Means::Sudo => "sudo",
            Means::TouchId => "touchid",
            Means::Passphrase => "passphrase",
            Means::None => "none",
        }
    }

    fn on(self, os: Os) -> bool {
        self != Means::TouchId || os == Os::Macos
    }
}

impl Means {
    /// Whether it is asked on the terminal, where an agent holding it could answer.
    pub fn asks_on_terminal(self) -> bool {
        matches!(self, Means::Sudo | Means::Passphrase)
    }
}

/// What an approval came to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Granted {
    /// Approved here and now (or nothing was to be asked).
    Now,
    /// Nothing was asked here: the workspace's own passphrase prompt, which core makes, is the approval.
    ByPassphrase,
}

/// An action's line in the settings, and the means it accepts.
pub struct Rule {
    pub action: Action,
    /// Its section and key in the settings.
    pub table: &'static str,
    pub key: &'static str,
    /// What it is, as the template's comment and the screens say.
    pub about: &'static str,
    /// In order of preference.
    accepts: &'static [Means],
    /// Raised while an agent holds the terminal: then only a means with its own window is kept.
    agent_at_terminal: bool,
    /// A workspace's: any means but the passphrase releases the passphrase a password manager keeps,
    /// so it is kept only where this system has a manager. A missing line is the passphrase,
    /// whatever `[approval] default` says.
    pub manager: bool,
}

/// The section of a box's approvals.
const BOX: &str = "box.approval";

/// What a box's action accepts when the person has the terminal. A box has no passphrase: its key
/// is kept for it (`[box] keys`).
const BOX_MEANS: &[Means] = &[Means::TouchId, Means::Sudo, Means::None];

/// What a box's write accepts: the agent has the terminal, so only Touch ID's window, or nothing.
const BOX_WRITE_MEANS: &[Means] = &[Means::TouchId, Means::None];

/// What a change to the settings accepts: what a program running as the person can't answer.
const CONFIG_MEANS: &[Means] = &[Means::Sudo, Means::TouchId];

/// What opening, removing secrets from or deleting a workspace accepts: its passphrase typed, as it
/// always was; or, where a password manager keeps it, the person's password, Touch ID, or nothing
/// before it is taken from there.
const WS_MEANS: &[Means] = &[Means::Passphrase, Means::Sudo, Means::TouchId, Means::None];

/// Writing into a workspace (storing a secret, approving a policy) is never approved by nothing:
/// it accepts what a workspace's other actions do, but `none`.
const WS_SET_MEANS: &[Means] = &[Means::Passphrase, Means::Sudo, Means::TouchId];

/// Config takes only what a program running as the person can't answer: the sudo password, or the
/// Touch ID window. A workspace unlocks with its passphrase, which core demands anyway, or with the
/// passphrase a password manager keeps, released by the means its line names; storing a secret or
/// approving a policy takes some approval, never none. A box's write is
/// asked while the agent has the terminal, so only Touch ID's window, or nothing, answers it.
pub const RULES: &[Rule] = &[
    Rule { action: Action::Config, table: "approval", key: "config", about: "a change to this file", accepts: CONFIG_MEANS, agent_at_terminal: false, manager: false },
    Rule { action: Action::WsOpen, table: "workspace.approval", key: "open", about: "opening a workspace", accepts: WS_MEANS, agent_at_terminal: false, manager: true },
    Rule {
        action: Action::WsSet,
        table: "workspace.approval",
        key: "set",
        about: "storing a secret in a workspace",
        accepts: WS_SET_MEANS,
        agent_at_terminal: false,
        manager: true,
    },
    Rule { action: Action::WsRm, table: "workspace.approval", key: "rm", about: "removing secrets from a workspace", accepts: WS_MEANS, agent_at_terminal: false, manager: true },
    Rule {
        action: Action::WsPolicy,
        table: "workspace.approval",
        key: "policy",
        about: "approving a policy in a workspace",
        accepts: WS_SET_MEANS,
        agent_at_terminal: false,
        manager: true,
    },
    Rule { action: Action::WsDelete, table: "workspace.approval", key: "delete", about: "deleting a workspace", accepts: WS_MEANS, agent_at_terminal: false, manager: true },
    Rule { action: Action::BoxRun, table: BOX, key: "run", about: "opening a box", accepts: BOX_MEANS, agent_at_terminal: false, manager: false },
    Rule { action: Action::BoxPolicy, table: BOX, key: "policy", about: "approving a changed box policy", accepts: BOX_MEANS, agent_at_terminal: false, manager: false },
    Rule {
        action: Action::BoxWrite,
        table: BOX,
        key: "write",
        about: "a write the box's policy says to ask about",
        accepts: BOX_WRITE_MEANS,
        agent_at_terminal: true,
        manager: false,
    },
    Rule { action: Action::BoxExport, table: BOX, key: "export", about: "copying files out of a box", accepts: BOX_MEANS, agent_at_terminal: false, manager: false },
    Rule { action: Action::BoxDelete, table: BOX, key: "delete", about: "deleting a box", accepts: BOX_MEANS, agent_at_terminal: false, manager: false },
];

impl Rule {
    /// A box's action: its line is in `[box.approval]`.
    pub fn of_box(&self) -> bool {
        self.table == BOX
    }
}

impl Action {
    pub fn rule(self) -> &'static Rule {
        RULES.iter().find(|rule| rule.action == self).expect("every action has a rule")
    }

    /// The means it accepts on this system, in order of preference.
    pub fn accepts(self, os: Os) -> Vec<Means> {
        kept(self.rule(), os)
    }
}

/// A rule's means that this system has, without those asked on the terminal when an agent holds it.
/// A box's action has none where no box engine is, and a workspace's only the passphrase where no
/// password manager is.
fn kept(rule: &Rule, os: Os) -> Vec<Means> {
    if rule.of_box() && !Engine::ALL.iter().any(|engine| engine.on(os)) {
        return Vec::new();
    }
    let managed = Manager::ALL.iter().any(|manager| *manager != Manager::None && manager.on(os));
    let here = |means: &Means| means.on(os) && (!rule.agent_at_terminal || !means.asks_on_terminal()) && (!rule.manager || managed || *means == Means::Passphrase);
    rule.accepts.iter().copied().filter(here).collect()
}

/// sudo, or the person, said no.
#[derive(Debug)]
pub struct Declined;

impl fmt::Display for Declined {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not approved")
    }
}

impl std::error::Error for Declined {}

/// Asks for `action` as the settings say. `reason` says what is approved, in a few words.
pub fn approve_with(world: &dyn World, settings: &Settings, action: Action, reason: &str) -> Result<Granted> {
    ask_by(world, settings.means(action), action, reason)
}

/// Asks for `action` by `means`, read from the settings earlier: none when this system has no means
/// the action accepts. The door keeps the means a box opened with this way.
pub fn ask_by(world: &dyn World, means: Option<Means>, action: Action, reason: &str) -> Result<Granted> {
    match means {
        None => bail!("{} needs an approval this system can't give", action.rule().about),
        Some(Means::Sudo) => world.sudo(reason).map(|()| Granted::Now),
        Some(Means::TouchId) => world.touch_id(reason).map(|()| Granted::Now),
        Some(Means::Passphrase) => Ok(Granted::ByPassphrase),
        Some(Means::None) => Ok(Granted::Now),
    }
}

/// What an approval reaches outside halti: the approved copy of the settings, sudo, the Touch ID
/// window and the Keychain's approval records. Tests have one in memory (`fake_tests`).
pub trait World {
    /// The approved copy of the settings.
    fn read(&self, place: &Place) -> Found;
    fn touch_id(&self, reason: &str) -> Result<()>;
    /// A yes or no from sudo: the person's password, typed now.
    fn sudo(&self, reason: &str) -> Result<()>;
    /// Writes the approved copy as root: sudo's yes is the write itself.
    fn sudo_write(&self, place: &Place, bytes: &[u8]) -> Result<()>;
    /// The text of the Touch ID approval record under `key`, if halti reads it silently and it is whole.
    fn pinned(&self, key: &str) -> Option<String>;
    fn pin(&self, key: &str, text: &str) -> Result<()>;
    fn unpin(&self, key: &str);
}

/// This machine.
pub struct Real;

impl World for Real {
    fn read(&self, place: &Place) -> Found {
        approved::read(place)
    }

    fn touch_id(&self, reason: &str) -> Result<()> {
        approve::confirm(reason)
    }

    fn sudo(&self, reason: &str) -> Result<()> {
        #[cfg(halti_dev)]
        if let Some(yes) = hook() {
            return if yes { Ok(()) } else { Err(Declined.into()) };
        }
        run(&prompt(reason), &[OsStr::new(TRUE)], None)
    }

    fn sudo_write(&self, place: &Place, bytes: &[u8]) -> Result<()> {
        #[cfg(halti_dev)]
        if let Some(yes) = hook() {
            return if yes { approved::write_here(place, bytes) } else { Err(Declined.into()) };
        }
        if fs::symlink_metadata(&place.dir).is_err() {
            let make = [OsStr::new(MKDIR), OsStr::new("-p"), OsStr::new("-m"), OsStr::new("0755"), place.dir.as_os_str()];
            run(&prompt(&format!("make {}", place.dir.display())), &make, None)?;
        }
        if !approved::folders_safe(place) {
            bail!("{} could be changed by someone other than {}, so nothing was approved", place.dir.display(), place.who());
        }
        run(&prompt("approve these settings"), &[OsStr::new(TEE), place.file.as_os_str()], Some(bytes))
    }

    fn pinned(&self, key: &str) -> Option<String> {
        policy::pinned_text(key)
    }

    fn pin(&self, key: &str, text: &str) -> Result<()> {
        policy::pin(key, &policy::Approval::of(text))
    }

    fn unpin(&self, key: &str) {
        let _ = policy::revoke(key);
    }
}

/// The only sudo halti runs, never one found on a PATH, and the commands it runs with it.
const SUDO: &str = "/usr/bin/sudo";
const MKDIR: &str = "/bin/mkdir";
const TEE: &str = "/usr/bin/tee";
const TRUE: &str = "/usr/bin/true";

/// The debug hook's answer to sudo: yes, no, or none when it isn't set. Release builds don't contain this.
#[cfg(halti_dev)]
fn hook() -> Option<bool> {
    let answer = util::dev_var("HALTI_TEST_SUDO")?;
    eprintln!("halti: [test] sudo: {}", answer.to_string_lossy());
    Some(answer == "yes")
}

/// Whether sudo can ask here: the terminal, or in a debug build the hook.
pub fn terminal_ready() -> Result<()> {
    #[cfg(halti_dev)]
    if util::dev_var("HALTI_TEST_SUDO").is_some() {
        return Ok(());
    }
    OpenOptions::new().read(true).write(true).open("/dev/tty").map(drop).map_err(|_| anyhow!("there is no terminal for sudo to ask in"))
}

/// What sudo shows on the terminal itself, so a redirect can't hide what the password is for.
/// sudo expands `%` escapes in a prompt, so each `%` is doubled.
pub fn prompt(what: &str) -> String {
    format!("halti needs your password to {}: ", what.replace('%', "%%"))
}

/// `/usr/bin/sudo -k -p PROMPT -- COMMAND...`, with no environment, from `/`. `-k` with a command
/// ignores a ticket cached earlier in this terminal and leaves none, so each approval is the person
/// typing now. The command gets umask 022 (sudo takes the union with the caller's, so the copy is
/// readable), and SIGINT back as default: halti ignores it while it waits, and an ignored signal
/// would be inherited, so Ctrl-C couldn't end sudo.
pub fn sudo_command(prompt: &str, command: &[&OsStr]) -> Command {
    let mut sudo = Command::new(SUDO);
    sudo.env_clear().current_dir("/").args(["-k", "-p", prompt, "--"]).args(command);
    // Only async-signal-safe calls, between fork and exec.
    unsafe {
        sudo.pre_exec(|| {
            libc::umask(0o022);
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            Ok(())
        });
    }
    sudo
}

/// Runs `command` through sudo with `input` on its standard input (or nothing), and waits. Ctrl-C
/// ends sudo, and halti says it wasn't approved. A debug build never runs sudo.
fn run(prompt: &str, command: &[&OsStr], input: Option<&[u8]>) -> Result<()> {
    if cfg!(halti_dev) {
        bail!("a debug build doesn't run sudo");
    }
    if !Path::new(SUDO).is_file() {
        bail!("sudo isn't at {SUDO}, so this can't be approved. nothing changed");
    }
    let mut sudo = sudo_command(prompt, command);
    sudo.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::null());
    let status = util::sigint_ignored(|| -> io::Result<_> {
        let mut child = sudo.spawn()?;
        if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
            // When sudo isn't approved it ends without reading: the write fails, and the status says why.
            let _ = stdin.write_all(bytes);
        }
        child.wait()
    })
    .context("running sudo")?;
    if !status.success() {
        return Err(Declined.into());
    }
    Ok(())
}

#[cfg(test)]
pub mod fake_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::fake_tests::Fake;
    use crate::config;

    #[test]
    fn every_rule_keeps_its_whole_list_where_its_means_are() {
        for rule in RULES {
            assert_eq!(rule.action.accepts(Os::Macos), rule.accepts, "{:?}", rule.action);
            // No box runs on Linux, so nothing there approves a box's action; and no password manager is there, so a
            // workspace's action takes its passphrase only.
            let linux = |means: &Means| *means != Means::TouchId && !rule.of_box() && (!rule.manager || *means == Means::Passphrase);
            let linux: Vec<Means> = rule.accepts.iter().copied().filter(linux).collect();
            assert_eq!(rule.action.accepts(Os::Linux), linux, "{:?}", rule.action);
            assert!(!rule.agent_at_terminal || rule.accepts.iter().all(|means| !means.asks_on_terminal()), "{:?} lists a means an agent could answer", rule.action);
            assert!(!rule.accepts.is_empty() && rule.action.rule().key == rule.key);
        }
    }

    #[test]
    fn a_workspace_takes_any_means_where_a_password_manager_is_and_its_passphrase_elsewhere() {
        for action in [Action::WsOpen, Action::WsSet, Action::WsRm, Action::WsPolicy, Action::WsDelete] {
            assert!(action.rule().manager && action.rule().table == "workspace.approval");
            let any = [Means::Passphrase, Means::Sudo, Means::TouchId, Means::None];
            // Storing a secret or approving a policy is never approved by nothing.
            let expected = if matches!(action, Action::WsSet | Action::WsPolicy) { &any[..3] } else { &any[..] };
            assert_eq!(action.accepts(Os::Macos), expected, "{action:?}");
            assert_eq!(action.accepts(Os::Linux), [Means::Passphrase], "{action:?}");
        }
        assert_eq!(RULES.iter().filter(|rule| rule.manager).count(), 5, "only a workspace's passphrase is kept by a manager");
        let keys: Vec<&str> = RULES.iter().filter(|rule| rule.table == "workspace.approval").map(|rule| rule.key).collect();
        assert_eq!(keys, ["open", "set", "rm", "policy", "delete"]);
    }

    #[test]
    fn with_an_agent_at_the_terminal_only_a_window_is_kept() {
        let accepts = &[Means::Sudo, Means::TouchId, Means::Passphrase];
        let rule = Rule { action: Action::Config, table: "approval", key: "write", about: "a write", accepts, agent_at_terminal: true, manager: false };
        assert_eq!((kept(&rule, Os::Macos), kept(&rule, Os::Linux)), (vec![Means::TouchId], vec![]));
        assert_eq!(Means::ALL.iter().filter(|means| means.asks_on_terminal()).count(), 2);
    }

    #[test]
    fn a_box_s_actions_take_touch_id_sudo_or_nothing_and_its_writes_no_terminal() {
        let boxes: Vec<(Action, Vec<Means>)> = RULES.iter().filter(|rule| rule.of_box()).map(|rule| (rule.action, rule.action.accepts(Os::Macos))).collect();
        let any = vec![Means::TouchId, Means::Sudo, Means::None];
        let expected = [
            (Action::BoxRun, any.clone()),
            (Action::BoxPolicy, any.clone()),
            (Action::BoxWrite, vec![Means::TouchId, Means::None]),
            (Action::BoxExport, any.clone()),
            (Action::BoxDelete, any),
        ];
        assert_eq!(boxes, expected);
        assert!(RULES.iter().filter(|rule| rule.of_box()).all(|rule| !rule.accepts.contains(&Means::Passphrase)), "a box has no passphrase");
        assert!(Action::BoxWrite.rule().agent_at_terminal && RULES.iter().filter(|rule| rule.agent_at_terminal).count() == 1);
        assert!(RULES.iter().filter(|rule| rule.of_box()).all(|rule| rule.table == "box.approval" && rule.action.accepts(Os::Linux).is_empty()));
        assert!(!Action::Config.rule().of_box() && !Action::WsDelete.rule().of_box());
    }

    #[test]
    fn an_action_with_no_means_here_says_so() {
        let fake = Fake::answering(true, true);
        let error = ask_by(&fake, None, Action::BoxRun, "open box research").unwrap_err();
        assert_eq!(error.to_string(), "opening a box needs an approval this system can't give");
        let linux = config::Settings::builtin(Os::Linux);
        let error = approve_with(&fake, &linux, Action::BoxWrite, "let box research send POST https://x.example").unwrap_err();
        assert_eq!(error.to_string(), "a write the box's policy says to ask about needs an approval this system can't give");
        assert!(fake.calls().is_empty(), "nothing is asked");
        assert_eq!(ask_by(&fake, Some(Means::None), Action::BoxWrite, "a write").unwrap(), Granted::Now);
        assert_eq!(ask_by(&fake, Some(Means::TouchId), Action::BoxWrite, "a write").unwrap(), Granted::Now);
        assert_eq!(fake.calls(), ["touch id: a write"]);
    }

    #[test]
    fn a_passphrase_asks_nothing_here_and_the_others_ask_their_way() {
        let yes = Fake::answering(true, true);
        let builtin = config::Settings::builtin(Os::Macos);
        for action in [Action::WsOpen, Action::WsSet, Action::WsRm, Action::WsPolicy, Action::WsDelete] {
            assert_eq!(approve_with(&yes, &builtin, action, "open workspace acme").unwrap(), Granted::ByPassphrase);
        }
        assert!(yes.calls().is_empty(), "core asks for the passphrase");
        assert_eq!(approve_with(&yes, &builtin, Action::Config, "change it").unwrap(), Granted::Now);
        let touch_id = config::parse("[approval]\nconfig = \"touchid\"\n", Os::Macos).unwrap();
        assert_eq!(approve_with(&yes, &touch_id, Action::Config, "change it again").unwrap(), Granted::Now);
        assert_eq!(yes.calls(), ["sudo: change it", "touch id: change it again"]);

        let no = Fake::answering(false, false);
        assert!(approve_with(&no, &builtin, Action::Config, "change it").unwrap_err().is::<Declined>());
        assert!(approve_with(&no, &touch_id, Action::Config, "change it").is_err());
        assert_eq!(no.calls(), ["sudo: change it", "touch id: change it"]);
    }

    #[test]
    fn sudo_runs_only_from_its_own_path_with_the_prompt_on_its_command_line() {
        let file = OsStr::new("/etc/halti/approved/501.toml");
        let sudo = sudo_command(&prompt("approve these settings"), &[OsStr::new(TEE), file]);
        assert_eq!(sudo.get_program(), "/usr/bin/sudo");
        let args: Vec<&OsStr> = sudo.get_args().collect();
        assert_eq!(args, ["-k", "-p", "halti needs your password to approve these settings: ", "--", "/usr/bin/tee", "/etc/halti/approved/501.toml"]);
        assert_eq!(sudo.get_current_dir(), Some(Path::new("/")));
        assert_eq!(prompt("open 100% of it"), "halti needs your password to open 100%% of it: ");
    }

    #[test]
    #[cfg(halti_dev)]
    fn a_debug_build_never_runs_sudo() {
        let error = run(&prompt("approve these settings"), &[OsStr::new(TRUE)], None).unwrap_err();
        assert_eq!(error.to_string(), "a debug build doesn't run sudo");
    }
}
