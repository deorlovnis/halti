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
const HOOKS: [&str; 9] = [
    "HALTI_TEST_APPROVE",
    "HALTI_TEST_KEYCHAIN",
    "HALTI_TEST_LOGIN_RUNNER",
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
        for sub in ["home/.config/cred/policy", "hooks/keychain", "hooks/policy", "hooks/box", "env_home", "xdg"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        Self { dir }
    }

    fn path(&self, sub: &str) -> PathBuf {
        self.dir.join(sub)
    }

    /// `bin ARGS` as namespace root, with /root replaced by `home` and every hook set.
    fn run(&self, bin: &Path, args: &[&str]) -> Output {
        let hooks = self.path("hooks");
        Command::new("unshare")
            .args(["-Urm", "--", "sh", "-c", "mount --bind \"$1\" /root && shift && exec \"$@\"", "sh"])
            .arg(self.path("home"))
            .arg(bin)
            .args(args)
            .env("HOME", self.path("env_home"))
            .env("XDG_DATA_HOME", self.path("xdg"))
            .env("XDG_CONFIG_HOME", self.path("xdg"))
            .env("HALTI_TEST_APPROVE", "yes")
            .env("HALTI_TEST_KEYCHAIN", hooks.join("keychain"))
            .env("HALTI_INDEX", hooks.join("index.json"))
            .env("HALTI_POLICY_DIR", hooks.join("policy"))
            .env("HALTI_BOX_DIR", hooks.join("box"))
            .env("HALTI_AUDIT", hooks.join("audit.log"))
            .env("HALTI_AUDIT_KEY", "test-key")
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
    assert_eq!(info(&out, "config"), "/root/.config/cred");
    assert!(!text(&out.stderr).contains("DEV"), "{}", text(&out.stderr));

    let out = dirs.run(Path::new(DEBUG), &["build-info"]);
    assert_eq!(info(&out, "home"), dirs.path("env_home").display().to_string());
    assert_eq!(info(&out, "config"), dirs.path("env_home/.config/halti-dev").display().to_string(), "debug builds keep their own files");
    assert!(text(&out.stderr).contains("[DEV, not protected]"), "{}", text(&out.stderr));
}

#[test]
#[ignore = "needs a ci-release binary: HALTI_RELEASE_BIN=<path>, as check.sh sets"]
fn no_variable_answers_an_approval() {
    let dirs = Dirs::new();
    let policy = "[run]\nmode = \"allow\"\n";
    fs::write(dirs.path("home/.config/cred/policy/app.toml"), policy).unwrap();
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
    fs::write(dirs.path("home/.config/cred/index.json"), r#"{"passwdres":{"fields":{"token":{}}}}"#).unwrap();
    fs::create_dir_all(dirs.path("home/.config/cred/box")).unwrap();
    fs::write(dirs.path("home/.config/cred/box/passwdbox.toml"), "about = \"a box\"\n").unwrap();

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
    fs::create_dir_all(cwd.join(".config/cred/policy")).unwrap();
    fs::write(cwd.join(".config/cred/index.json"), r#"{"planted":{"fields":{"token":{}}}}"#).unwrap();
    fs::write(cwd.join(".config/cred/policy/planted.toml"), "[run]\nmode = \"allow\"\n").unwrap();
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
