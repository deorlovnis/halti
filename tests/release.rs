//! A release build has no test hooks and takes no paths from the environment. Each test runs the
//! ci-release binary that check.sh builds (`HALTI_RELEASE_BIN`) with every hook set, and the debug
//! binary the same way, which obeys them, so a test can't pass by checking nothing.
//!
//! The release binary takes its home from the passwd entry, so it runs in a user and mount
//! namespace (`unshare -Urm`) where it is root, with a test folder mounted over /root: it never
//! sees your real files. Linux only.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{env, fs};

const DEBUG: &str = env!("CARGO_BIN_EXE_halti");

/// Every variable a debug build reads to switch a protection off or move its files.
const HOOKS: [&str; 11] = [
    "HALTI_TEST_APPROVE",
    "HALTI_TEST_KEYCHAIN",
    "HALTI_TEST_LOGIN_RUNNER",
    "HALTI_TEST_PASSPHRASE",
    "HALTI_TEST_SUDO",
    "HALTI_AUDIT_KEY",
    "HALTI_RUNNER_DIR",
    "HALTI_INDEX",
    "HALTI_POLICY_DIR",
    "HALTI_BOX_DIR",
    "HALTI_AUDIT",
];

fn release() -> PathBuf {
    let bin = env::var_os("HALTI_RELEASE_BIN").expect("set HALTI_RELEASE_BIN to a ci-release halti, as check.sh does");
    PathBuf::from(bin)
}

/// A test's folders: `home` is mounted over /root, the release binary's home; `hooks` is where the
/// variables point; `env_home` is what `HOME` says.
struct Dirs {
    dir: PathBuf,
}

impl Dirs {
    fn new() -> Self {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let dir = env::temp_dir().join(format!("halti-release-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&dir);
        for sub in ["home/.config/halti/policy", "hooks/keychain", "hooks/policy", "hooks/box", "env_home", "xdg"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        Self { dir }
    }

    fn path(&self, sub: &str) -> PathBuf {
        self.dir.join(sub)
    }

    /// What is in a folder of the test's, sorted by name.
    fn names(&self, sub: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.path(sub)).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    /// `bin ARGS` as namespace root, in a session with no terminal, with /root replaced by `home` and
    /// every hook set. An editor is named that changes nothing.
    fn run(&self, bin: &Path, args: &[&str]) -> Output {
        let hooks = self.path("hooks");
        Command::new("setsid")
            .args(["-w", "unshare", "-Urm", "--", "sh", "-c", "mount --bind \"$1\" /root && shift && exec \"$@\"", "sh"])
            .arg(self.path("home"))
            .arg(bin)
            .args(args)
            .env("HOME", self.path("env_home"))
            .env("XDG_DATA_HOME", self.path("xdg"))
            .env("XDG_CONFIG_HOME", self.path("xdg"))
            .env("HALTI_TEST_APPROVE", "yes")
            .env("HALTI_TEST_PASSPHRASE", "acme passphrase one")
            .env("HALTI_TEST_SUDO", "yes")
            .env("HALTI_TEST_KEYCHAIN", hooks.join("keychain"))
            .env("HALTI_INDEX", hooks.join("index.json"))
            .env("HALTI_POLICY_DIR", hooks.join("policy"))
            .env("HALTI_BOX_DIR", hooks.join("box"))
            .env("HALTI_AUDIT", hooks.join("audit.log"))
            .env("HALTI_AUDIT_KEY", "test-key")
            .env("EDITOR", "true")
            .env_remove("VISUAL")
            .env_remove("HALTI_REFRESHING")
            .env_remove("CRED_REFRESHING")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}

impl Drop for Dirs {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The value of `key=` in `build-info`'s output.
fn info(out: &Output, key: &str) -> String {
    let prefix = format!("{key}=");
    text(&out.stdout).lines().find_map(|l| l.strip_prefix(&prefix).map(String::from)).unwrap_or_else(|| panic!("no {key} in {}", text(&out.stdout)))
}

#[test]
#[ignore = "needs a ci-release binary: HALTI_RELEASE_BIN=<path>, as check.sh sets"]
fn build_info_says_the_release_has_no_hooks() {
    let out = Command::new(release()).arg("build-info").output().unwrap();
    let said = text(&out.stdout);
    assert!(out.status.success() && said.lines().any(|l| l == "debug_assertions=false halti_dev=false"), "{said}");
    assert!(said.lines().any(|l| l == "verified: linux-aarch64") && said.contains(&format!("target={}-unknown-linux-", env::consts::ARCH)), "{said}");
    let debug = text(&Command::new(DEBUG).arg("build-info").output().unwrap().stdout);
    assert!(debug.lines().any(|l| l == "debug_assertions=true halti_dev=true"), "{debug}");
}

#[test]
#[ignore = "needs a ci-release binary: HALTI_RELEASE_BIN=<path>, as check.sh sets"]
fn the_release_binary_has_no_hook_names_in_it() {
    let release = fs::read(release()).unwrap();
    let debug = fs::read(DEBUG).unwrap();
    let has = |bin: &[u8], name: &str| bin.windows(name.len()).any(|w| w == name.as_bytes());
    for name in HOOKS {
        assert!(has(&debug, name), "the debug binary should read {name}");
        assert!(!has(&release, name), "the release binary names {name}");
    }
}

#[test]
#[ignore = "needs a ci-release binary: HALTI_RELEASE_BIN=<path>, as check.sh sets"]
fn the_home_folder_is_the_passwd_one() {
    let dirs = Dirs::new();
    let out = dirs.run(&release(), &["build-info"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(info(&out, "home"), "/root", "HOME, XDG_DATA_HOME and XDG_CONFIG_HOME are ignored");
    assert_eq!(info(&out, "config"), "/root/.config/halti");
    assert_eq!(info(&out, "store"), "/root/Library/Application Support/halti", "where workspaces and boxes are kept");
    assert!(!text(&out.stderr).contains("DEV"), "{}", text(&out.stderr));

    let out = dirs.run(Path::new(DEBUG), &["build-info"]);
    assert_eq!(info(&out, "home"), dirs.path("env_home").display().to_string());
    assert_eq!(info(&out, "config"), dirs.path("env_home/.config/halti-dev").display().to_string(), "debug builds keep their own files");
    assert_eq!(info(&out, "store"), dirs.path("env_home/Library/Application Support/halti-dev").display().to_string());
    assert!(text(&out.stderr).contains("[DEV, not protected]"), "{}", text(&out.stderr));
}

#[test]
#[ignore = "needs a ci-release binary: HALTI_RELEASE_BIN=<path>, as check.sh sets"]
fn no_variable_answers_an_approval() {
    let dirs = Dirs::new();
    let policy = "[run]\nmode = \"allow\"\n";
    fs::write(dirs.path("home/.config/halti/policy/app.toml"), policy).unwrap();
    fs::write(dirs.path("hooks/policy/app.toml"), policy).unwrap();

    let out = dirs.run(&release(), &["policy", "approve", "app"]);
    let said = text(&out.stderr);
    assert!(!out.status.success() && said.contains("not approved (Touch ID needs macOS)") && !said.contains("[test]"), "{said}");
    assert_eq!(fs::read_dir(dirs.path("hooks/keychain")).unwrap().count(), 0, "nothing in the test keychain");

    let out = dirs.run(Path::new(DEBUG), &["policy", "approve", "app"]);
    assert!(out.status.success() && text(&out.stderr).contains("[test]"), "{}", text(&out.stderr));
    assert_eq!(fs::read_dir(dirs.path("hooks/keychain")).unwrap().count(), 1, "the approval went to the test keychain");
}

#[test]
#[ignore = "needs a ci-release binary: HALTI_RELEASE_BIN=<path>, as check.sh sets"]
fn no_variable_moves_the_index_the_policies_the_boxes_or_the_keychain() {
    let dirs = Dirs::new();
    fs::write(dirs.path("hooks/index.json"), r#"{"hooked":{"fields":{"token":{}}}}"#).unwrap();
    fs::write(dirs.path("hooks/keychain/hooked.token"), "s3cret").unwrap();
    fs::write(dirs.path("hooks/policy/hooked.toml"), "[run]\nmode = \"allow\"\n").unwrap();
    fs::write(dirs.path("hooks/box/hookedbox.toml"), "about = \"a box\"\n").unwrap();

    // What the passwd home has, so the release binary is seen reading somewhere.
    fs::write(dirs.path("home/.config/halti/index.json"), r#"{"passwdres":{"fields":{"token":{}}}}"#).unwrap();
    fs::create_dir_all(dirs.path("home/.config/halti/box")).unwrap();
    fs::write(dirs.path("home/.config/halti/box/passwdbox.toml"), "about = \"a box\"\n").unwrap();

    let release = release();
    let debug = Path::new(DEBUG);
    let ls = |bin: &Path| {
        let out = dirs.run(bin, &["ls"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        text(&out.stdout)
    };
    let said = ls(&release);
    assert!(said.contains("passwdres") && !said.contains("hooked"), "{said}");
    assert!(ls(debug).contains("hooked"), "{}", ls(debug));

    let copy = |bin: &Path| text(&dirs.run(bin, &["copy", "hooked", "token"]).stderr);
    assert!(copy(&release).contains("hooked/token not found"), "{}", copy(&release));
    assert!(!copy(debug).contains("not found"), "{}", copy(debug));

    let shown = |bin: &Path| text(&dirs.run(bin, &["policy", "show", "hooked"]).stdout);
    assert!(shown(&release).contains("no policy yet"), "{}", shown(&release));
    assert!(shown(debug).contains("mode = \"allow\""), "{}", shown(debug));

    let boxes = |bin: &Path| {
        let out = dirs.run(bin, &["box", "ls"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        text(&out.stdout)
    };
    let said = boxes(&release);
    assert!(said.contains("passwdbox") && !said.contains("hookedbox"), "{said}");
    assert!(boxes(debug).contains("hookedbox"), "{}", boxes(debug));
}

#[test]
#[ignore = "needs a ci-release binary: HALTI_RELEASE_BIN=<path>, as check.sh sets"]
fn without_a_passwd_home_nothing_runs() {
    // A uid with no passwd entry, as in a container run with `--user N`: its home would be empty,
    // and every path relative to the current folder, where these planted files are.
    let dirs = Dirs::new();
    let cwd = dirs.path("cwd");
    fs::create_dir_all(cwd.join(".config/halti/policy")).unwrap();
    fs::write(cwd.join(".config/halti/index.json"), r#"{"planted":{"fields":{"token":{}}}}"#).unwrap();
    fs::write(cwd.join(".config/halti/policy/planted.toml"), "[run]\nmode = \"allow\"\n").unwrap();
    for args in [&["ls"][..], &["policy", "show", "planted"], &["build-info"]] {
        let out = Command::new("unshare")
            .args(["-U", "--map-user=4242", "--map-group=4242", "--"])
            .arg(release())
            .args(args)
            .current_dir(&cwd)
            .env_remove("HOME")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let said = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert!(!out.status.success() && said.contains("no home folder") && !said.contains("planted"), "{args:?}: {said}");
    }
}

#[test]
#[ignore = "needs a ci-release binary: HALTI_RELEASE_BIN=<path>, as check.sh sets"]
fn no_variable_answers_a_passphrase() {
    let dirs = Dirs::new();
    let store = "home/Library/Application Support/halti";
    let out = dirs.run(&release(), &["ws", "new", "acme"]);
    let said = text(&out.stderr);
    assert!(!out.status.success() && said.contains("read only from a terminal") && !said.contains("[test]"), "{said}");
    // With no terminal nothing is made: nothing under the store root, and the config folder as it was.
    assert!(!dirs.path(store).exists(), "{said}");
    assert_eq!(dirs.names("home/.config/halti"), ["policy"]);
    let listed = text(&dirs.run(&release(), &["ws", "ls"]).stdout);
    assert!(listed.contains("no workspaces yet"), "the name is free: {listed}");
    assert!(dirs.names("env_home").is_empty() && dirs.names("xdg").is_empty(), "HOME and XDG_* are not where it writes");
    assert_eq!(dirs.names("hooks"), ["box", "keychain", "policy"]);
    assert!(["box", "keychain", "policy"].iter().all(|hook| dirs.names(&format!("hooks/{hook}")).is_empty()), "nor are the hooks");

    let out = dirs.run(Path::new(DEBUG), &["ws", "new", "acme"]);
    assert!(out.status.success() && text(&out.stderr).contains("[test] [DEV, not protected] create workspace acme"), "{}", text(&out.stderr));
}

/// The template a release build has on Linux.
const TEMPLATE: &str = "# halti config. edit with: halti config\n\n[approval]\ndefault = \"sudo\"              # sudo | passphrase\n\
                        config  = \"sudo\"              # a change to this file: sudo\n\n[paths]\nworkspaces = \"~/Library/Application Support/halti/ws\"\n\n\
                        [passwords]\nmanager = \"none\"              # none\n\n[secrets]\nstore = \"files\"               # files\n\n[workspace]\n\
                        passphrase = \"own\"            # own | generate\n\n[workspace.approval]\nopen   = \"passphrase\"         # opening a workspace: passphrase\n\
                        set    = \"passphrase\"         # storing a secret in a workspace: passphrase\n\
                        rm     = \"passphrase\"         # removing secrets from a workspace: passphrase\n\
                        policy = \"passphrase\"         # approving a policy in a workspace: passphrase\n\
                        delete = \"passphrase\"         # deleting a workspace: passphrase\n";

#[test]
#[ignore = "needs a ci-release binary: HALTI_RELEASE_BIN=<path>, as check.sh sets"]
fn no_variable_answers_sudo() {
    let dirs = Dirs::new();
    // With no terminal, sudo can't ask: refused before the editor, and nothing is written.
    let out = dirs.run(&release(), &["config"]);
    let said = text(&out.stderr);
    assert!(!out.status.success() && said.contains("halti config needs a terminal, for sudo to ask for your password") && !said.contains("[test]"), "{said}");
    assert_eq!(dirs.names("home/.config/halti"), ["policy"]);
    assert!(dirs.names("env_home").is_empty() && dirs.names("xdg").is_empty(), "{said}");

    let template = dirs.run(&release(), &["config", "--default"]);
    assert!(template.status.success() && text(&template.stdout) == TEMPLATE, "{}", text(&template.stdout));
    let shown = dirs.run(&release(), &["config", "--show"]);
    let said = text(&shown.stdout);
    assert!(shown.status.success() && said.starts_with("no settings of yours are approved yet, so halti uses its template\n\n[approval]\n"), "{said}");
    assert!(said.contains("workspaces = \"~/Library/Application Support/halti/ws\"\n"), "{said}");
    assert_eq!(dirs.names("home/.config/halti"), ["policy"], "showing writes nothing");

    // The debug binary, with the same variables, gets past the terminal: its hook answers for sudo.
    let out = dirs.run(Path::new(DEBUG), &["config"]);
    let said = text(&out.stderr);
    assert!(out.status.success() && text(&out.stdout) == "no change to the settings in effect\n" && !said.contains("needs a terminal"), "{said}");
}
