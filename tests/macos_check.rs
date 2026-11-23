//! The headline of macos-check.sh's report, from a copy of it run in a test git repo with
//! stand-ins for check.sh, `cargo`, `cred`, `container` and `bioutil`, and the report saved under
//! a test home. It runs nothing of the real check, and leaves any install made by cred alone.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

/// Passes, fails or hangs as `CHECK_DOES` says; when it hangs it first touches `CHECK_STARTED`.
const CHECK: &str = "#!/bin/sh\ncase \"$CHECK_DOES\" in\n  fail) exit 1 ;;\n  hang) touch \"$CHECK_STARTED\"; sleep 5 ;;\nesac\n";
/// What the box store tests run: they pass.
const CARGO: &str = "#!/bin/sh\nexit 0\n";
/// No install made by cred, no Apple container and no enrolled finger.
const SAYS_NOTHING: &str = "#!/bin/sh\nexit 0\n";
const NOT_RUNNING: &str = "#!/bin/sh\nexit 1\n";

struct Repo {
    dir: PathBuf,
}

impl Repo {
    /// A git repo holding a copy of macos-check.sh and the stand-in check.sh, one commit.
    fn new() -> Self {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let dir = env::temp_dir().join(format!("halti-macos-check-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&dir);
        for sub in ["repo", "fakes", "home", "tmp"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let repo = Self { dir };
        fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("macos-check.sh"), repo.path("repo/macos-check.sh")).unwrap();
        write_script(&repo.path("repo/check.sh"), CHECK);
        for (name, text) in [("cargo", CARGO), ("cred", SAYS_NOTHING), ("bioutil", SAYS_NOTHING), ("container", NOT_RUNNING)] {
            write_script(&repo.path("fakes").join(name), text);
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

    fn git(&self, args: &[&str]) {
        let out = Command::new("git").args(args).current_dir(self.path("repo")).env("GIT_CONFIG_GLOBAL", self.path("gitconfig")).env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// Runs the copy with `--no-vm`, the stand-in check.sh doing what `does` says; a hanging one
    /// is stopped by a hangup once it has started. The first line of the report it saved.
    fn headline(&self, does: &str) -> String {
        let path = format!("{}:{}", self.path("fakes").display(), env::var("PATH").unwrap());
        let started = self.path("started");
        let mut child = Command::new(self.path("repo/macos-check.sh"))
            .arg("--no-vm")
            .env("PATH", path)
            .env("HOME", self.path("home"))
            .env("TMPDIR", self.path("tmp"))
            .env("GIT_CONFIG_GLOBAL", self.path("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("CHECK_DOES", does)
            .env("CHECK_STARTED", &started)
            .env_remove("MACOS_CHECK_BRANCH")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        if does == "hang" {
            let deadline = Instant::now() + Duration::from_secs(60);
            while !started.exists() {
                assert!(Instant::now() < deadline, "the stand-in check.sh never started");
                thread::sleep(Duration::from_millis(50));
            }
            assert!(Command::new("kill").args(["-HUP", &child.id().to_string()]).status().unwrap().success());
        }
        child.wait().unwrap();
        let checks = self.path("home/Library/Application Support/halti/checks");
        let reports: Vec<PathBuf> = fs::read_dir(&checks).unwrap().map(|e| e.unwrap().path()).collect();
        assert_eq!(reports.len(), 1, "{reports:?}");
        let report = fs::read_to_string(&reports[0]).unwrap();
        fs::remove_file(&reports[0]).unwrap();
        report.lines().next().unwrap().to_string()
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn write_script(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn the_headline_says_passed_only_when_every_step_ran_and_passed() {
    let repo = Repo::new();
    assert_eq!(repo.headline("pass"), "halti macos-check: passed");
    assert_eq!(repo.headline("fail"), "halti macos-check: FAILED");
    // A hangup sets no step failed: the run still hasn't passed.
    assert_eq!(repo.headline("hang"), "halti macos-check: FAILED (stopped before the end)");
}
