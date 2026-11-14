//! install-linux.sh, run on a copy of itself in a test git repo, with stand-ins for `uname` (so
//! it runs on a Mac too), `id`, `sudo` and `cargo`. The stand-in sudo writes down what it was
//! asked to install and runs nothing; the stand-in cargo makes a halti that only says its
//! build-info. Nothing is installed, and no real sudo or cargo is run. And what check.sh writes for
//! it: what it could not run here, with a stand-in `unshare` that fails as AppArmor makes it.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{env, fs};

const UNAME: &str = "#!/bin/sh\ncase \"$1\" in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac\n";
const ID: &str = "#!/bin/sh\ncase \"$1\" in -u) echo 1000 ;; -un) echo tester ;; *) echo 'uid=1000(tester)' ;; esac\n";
/// `sudo -n -k true` answers as `SUDO_NO_PASSWORD` says; anything else is written down.
const SUDO: &str = "#!/bin/sh\nif [ \"$1\" = -n ]; then [ \"$SUDO_NO_PASSWORD\" = yes ]; exit; fi\necho \"$*\" >>\"$SUDO_LOG\"\n";
/// What `cargo build --release` leaves: a halti that says it has no test hooks.
const CARGO: &str = "#!/bin/sh\nout=\"${CARGO_TARGET_DIR:-target}/release\"\nmkdir -p \"$out\"\nprintf '#!/bin/sh\\necho \"debug_assertions=false halti_dev=false\"\\n' >\"$out/halti\"\nchmod +x \"$out/halti\"\n";

struct Repo {
    dir: PathBuf,
}

impl Repo {
    /// A git repo holding a copy of install-linux.sh, one commit, with `target/` ignored.
    fn new() -> Self {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let dir = env::temp_dir().join(format!("halti-install-linux-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&dir);
        for sub in ["repo", "fakes", "elsewhere"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let repo = Self { dir };
        fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("install-linux.sh"), repo.path("repo/install-linux.sh")).unwrap();
        fs::write(repo.path("repo/.gitignore"), "/target\n").unwrap();
        for (name, text) in [("uname", UNAME), ("id", ID), ("sudo", SUDO), ("cargo", CARGO)] {
            let fake = repo.path("fakes").join(name);
            fs::write(&fake, text).unwrap();
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(repo.path("gitconfig"), "").unwrap();
        repo.git(&["init", "-q"]);
        repo.git(&["add", "-A"]);
        repo.git(&["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", "one"]);
        repo
    }

    fn path(&self, sub: &str) -> PathBuf {
        self.dir.join(sub)
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git").args(args).current_dir(self.path("repo")).env("GIT_CONFIG_GLOBAL", self.path("gitconfig")).env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// The stamp check.sh writes when it passes: the commit, in the target folder.
    fn stamp(&self, target: &Path, commit: &str) {
        fs::create_dir_all(target).unwrap();
        fs::write(target.join("check-passed"), format!("{commit}\n")).unwrap();
    }

    /// Runs the copy of install-linux.sh with the stand-ins first on the PATH.
    fn install(&self, envs: &[(&str, &Path)], no_password: bool) -> Output {
        let path = format!("{}:{}", self.path("fakes").display(), env::var("PATH").unwrap());
        let mut cmd = Command::new(self.path("repo/install-linux.sh"));
        cmd.env("PATH", path)
            .env("HOME", self.path("elsewhere"))
            .env("GIT_CONFIG_GLOBAL", self.path("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("SUDO_LOG", self.path("sudo.log"))
            .env("SUDO_NO_PASSWORD", if no_password { "yes" } else { "no" })
            .env_remove("CARGO_TARGET_DIR");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    /// What the stand-in sudo was asked to do, one line per call.
    fn sudo_log(&self) -> String {
        fs::read_to_string(self.path("sudo.log")).unwrap_or_default()
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn nothing_is_installed_until_check_sh_has_passed_at_this_commit() {
    let repo = Repo::new();
    let out = repo.install(&[], false);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("./check.sh hasn't passed at this commit on this machine"), "{}", text(&out.stderr));
    assert_eq!(repo.sudo_log(), "");

    // A stamp of another commit doesn't count.
    let first = repo.git(&["rev-parse", "HEAD"]);
    repo.stamp(&repo.path("repo/target"), &first);
    fs::write(repo.path("repo/README.md"), "two\n").unwrap();
    repo.git(&["add", "-A"]);
    repo.git(&["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", "two"]);
    let out = repo.install(&[], false);
    assert!(!out.status.success() && text(&out.stderr).contains("hasn't passed at this commit"), "{}", text(&out.stderr));
    assert_eq!(repo.sudo_log(), "");
}

#[test]
fn nothing_is_installed_from_files_with_changes() {
    let repo = Repo::new();
    repo.stamp(&repo.path("repo/target"), &repo.git(&["rev-parse", "HEAD"]));
    fs::write(repo.path("repo/extra.rs"), "fn main() {}\n").unwrap();
    let out = repo.install(&[], false);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("the files have changes since the last commit"), "{}", text(&out.stderr));
    assert_eq!(repo.sudo_log(), "");
}

#[test]
fn it_installs_what_cargo_built_where_cargo_target_dir_says() {
    let repo = Repo::new();
    // An older build left in target/, which must not be the one installed.
    fs::create_dir_all(repo.path("repo/target/release")).unwrap();
    fs::write(repo.path("repo/target/release/halti"), "#!/bin/sh\necho 'debug_assertions=false halti_dev=false'\n").unwrap();
    fs::set_permissions(repo.path("repo/target/release/halti"), fs::Permissions::from_mode(0o755)).unwrap();
    let elsewhere = repo.path("elsewhere/target");
    repo.stamp(&elsewhere, &repo.git(&["rev-parse", "HEAD"]));
    let out = repo.install(&[("CARGO_TARGET_DIR", &elsewhere)], false);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let log = repo.sudo_log();
    let installed = format!("install -o root -g root -m 755 {}/release/halti /usr/local/bin/halti", elsewhere.display());
    assert!(log.lines().any(|l| l == installed), "{log}");
    assert!(text(&out.stdout).lines().any(|l| l == "Installing /usr/local/bin/halti (sudo may ask for your password)."), "{}", text(&out.stdout));
    assert!(!text(&out.stderr).contains("sudo without a password"), "{}", text(&out.stderr));
}

#[test]
fn sudo_without_a_password_is_said_once_and_plainly() {
    let repo = Repo::new();
    repo.stamp(&repo.path("repo/target"), &repo.git(&["rev-parse", "HEAD"]));
    let out = repo.install(&[], true);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).lines().any(|l| l == "Installing /usr/local/bin/halti."), "{}", text(&out.stdout));
    let warning = "warning: tester can use sudo without a password, so any program running as tester is root here; see README \"On a Linux server\"";
    assert!(text(&out.stderr).lines().any(|l| l == warning), "{}", text(&out.stderr));
    assert!(!text(&out.stderr).contains("breaks out of a box"), "{}", text(&out.stderr));
}

#[test]
fn check_sh_writes_the_stamp_install_linux_sh_reads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for script in ["check.sh", "install-linux.sh"] {
        let code = fs::read_to_string(root.join(script)).unwrap();
        assert!(code.lines().any(|l| l == "stamp=\"$target/check-passed\""), "{script} names the stamp");
    }
}

#[test]
fn what_check_sh_could_not_run_is_named_in_one_line() {
    let repo = Repo::new();
    let head = repo.git(&["rev-parse", "HEAD"]);
    repo.stamp(&repo.path("repo/target"), &head);
    let out = repo.install(&[], false);
    assert!(out.status.success() && !text(&out.stderr).contains("not checked"), "{}", text(&out.stderr));

    let lines = "the 6 release tests that run the release build with every test hook set (AppArmor restricts unprivileged user namespaces here)\n\
                 the escape tests of the sandbox engine, which only debug builds have (AppArmor restricts unprivileged user namespaces here)\n";
    fs::write(repo.path("repo/target/check-passed"), format!("{head}\n{lines}")).unwrap();
    let out = repo.install(&[], false);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let note = "note: not checked on this machine: the 6 release tests that run the release build with every test hook set (AppArmor restricts unprivileged user \
                namespaces here); the escape tests of the sandbox engine, which only debug builds have (AppArmor restricts unprivileged user namespaces here)";
    assert!(text(&out.stderr).lines().any(|l| l == note), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr).matches("not checked").count(), 1, "{}", text(&out.stderr));
    assert!(repo.sudo_log().contains("/usr/local/bin/halti"), "installed all the same: {}", repo.sudo_log());
}

#[test]
fn check_sh_says_why_no_user_namespace_can_be_made() {
    let repo = Repo::new();
    let fake = repo.path("fakes/unshare");
    let check = |args: &[&str]| {
        let path = format!("{}:{}", repo.path("fakes").display(), env::var("PATH").unwrap());
        let out = Command::new(Path::new(env!("CARGO_MANIFEST_DIR")).join("check.sh")).arg("userns").args(args).env("PATH", path).output().unwrap();
        assert!(out.status.success(), "{}", text(&out.stderr));
        text(&out.stdout)
    };

    // As unshare fails where AppArmor restricts user namespaces.
    fs::write(&fake, "#!/bin/sh\necho 'unshare: write failed /proc/self/uid_map: Operation not permitted' >&2\nexit 1\n").unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let apparmor = fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").is_ok_and(|v| v.trim() == "1");
    let why = |args: &str| {
        if apparmor {
            "AppArmor restricts unprivileged user namespaces here\n".to_string()
        } else {
            format!("unshare {args} fails here: unshare: write failed /proc/self/uid_map: Operation not permitted\n")
        }
    };
    assert_eq!(check(&[]), why("-Urm"));
    assert_eq!(check(&["-Urnm", "--pid", "--fork"]), why("-Urnm --pid --fork"));

    fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
    assert_eq!(check(&[]), "", "nothing where a user namespace can be made");
}

#[test]
fn check_sh_names_the_release_tests_that_need_a_user_namespace() {
    // check.sh leaves these out where no user namespace can be made: each test of release.rs that
    // makes a Dirs, which runs halti in one, in their order there.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let check = fs::read_to_string(root.join("check.sh")).unwrap();
    let listed: Vec<&str> = check.split("\nrelease_userns_tests=(\n").nth(1).unwrap().split(')').next().unwrap().split_whitespace().collect();
    let release = fs::read_to_string(root.join("tests/release.rs")).unwrap();
    let needing: Vec<&str> = release
        .split("#[test]\n")
        .skip(1)
        .filter(|test| test.contains("Dirs::new()"))
        .map(|test| test.lines().find_map(|l| l.strip_prefix("fn ")).unwrap().split('(').next().unwrap())
        .collect();
    assert_eq!(needing.len(), 6, "{needing:?}");
    assert_eq!(listed, needing);
}
