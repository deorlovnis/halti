//! install-linux.sh, run on a copy of itself in a test git repo, with stand-ins for `uname` (so
//! it runs on a Mac too), `id`, `sudo` and `cargo`. The stand-in sudo writes down what it was
//! asked to install and runs nothing; the stand-in cargo makes a halti that only says its
//! build-info. Nothing is installed, and no real sudo or cargo is run. And what check.sh writes for
//! it: what it could not run here, with stand-ins for `unshare`, `sysctl` and the debug halti. And
//! box/to-disk.sh, which turns a box image into the disk a box boots from, by hand on Linux.

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

/// Runs `./check.sh userns ARGS` with the stand-ins in `fakes` first on the PATH, and the target
/// folder in the test repo; what it says.
fn check_userns(repo: &Repo, args: &[&str]) -> String {
    let path = format!("{}:{}", repo.path("fakes").display(), env::var("PATH").unwrap());
    let check = Path::new(env!("CARGO_MANIFEST_DIR")).join("check.sh");
    let out = Command::new(check).arg("userns").args(args).env("PATH", path).env("CARGO_TARGET_DIR", repo.path("target")).output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    text(&out.stdout)
}

fn write_script(path: &Path, script: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A script that says each line on stderr and fails.
fn failing(lines: &[&str]) -> String {
    let mut script = "#!/bin/sh\n".to_string();
    for line in lines {
        script.push_str(&format!("echo \"{line}\" >&2\n"));
    }
    script + "exit 1\n"
}

const APPARMOR_ON: &str = "#!/bin/sh\necho 1\n";
const APPARMOR_OFF: &str = "#!/bin/sh\necho 0\n";
const SUCCEEDS: &str = "#!/bin/sh\nexit 0\n";

#[test]
fn check_sh_says_why_no_user_namespace_can_be_made() {
    let repo = Repo::new();
    let (unshare, sysctl) = (repo.path("fakes/unshare"), repo.path("fakes/sysctl"));

    // As unshare fails where AppArmor restricts user namespaces.
    let uid_map = "unshare: write failed /proc/self/uid_map: Operation not permitted";
    write_script(&unshare, &failing(&[uid_map]));
    write_script(&sysctl, APPARMOR_ON);
    assert_eq!(check_userns(&repo, &[]), "AppArmor restricts unprivileged user namespaces here\n");
    write_script(&sysctl, APPARMOR_OFF);
    assert_eq!(check_userns(&repo, &[]), format!("{uid_map}\n"));

    // Where AppArmor's limit is on but something else stops unshare: a container's seccomp filter,
    // or no user namespaces allowed at all. AppArmor isn't named, and unshare's own words are kept.
    write_script(&sysctl, APPARMOR_ON);
    for said in ["unshare: unshare failed: Operation not permitted", "unshare: unshare failed: No space left on device"] {
        write_script(&unshare, &failing(&[said]));
        assert_eq!(check_userns(&repo, &[]), format!("{said}\n"));
    }

    write_script(&unshare, SUCCEEDS);
    assert_eq!(check_userns(&repo, &[]), "", "nothing where a user namespace can be made");
}

#[test]
fn check_sh_asks_the_debug_halti_whether_it_can_make_a_box() {
    // AppArmor's limit is per program: here unshare(1) may make user namespaces, halti may not.
    let repo = Repo::new();
    let halti = repo.path("target/debug/halti");
    write_script(&repo.path("fakes/unshare"), SUCCEEDS);
    write_script(&repo.path("fakes/sysctl"), APPARMOR_ON);
    let dev = "halti: [DEV, not protected] a debug build";

    // As halti fails where AppArmor restricts user namespaces.
    let setgroups = "halti: writing /proc/self/setgroups: Permission denied (os error 13)";
    write_script(&halti, &failing(&[dev, dev, setgroups]));
    assert_eq!(check_userns(&repo, &["box"]), "AppArmor restricts unprivileged user namespaces here\n");
    write_script(&repo.path("fakes/sysctl"), APPARMOR_OFF);
    assert_eq!(check_userns(&repo, &["box"]), format!("{setgroups}\n"));
    let unshare = "halti: making the box's namespaces (does this kernel allow user namespaces?): Operation not permitted";
    write_script(&halti, &failing(&[dev, dev, unshare]));
    assert_eq!(check_userns(&repo, &["box"]), format!("{unshare}\n"));

    // Any other failure is the sandbox's own: the escape tests run and say what it is.
    write_script(&halti, &failing(&[dev, dev, "halti: sandbox: bringing up lo: Operation not permitted"]));
    assert_eq!(check_userns(&repo, &["box"]), "");
    write_script(&halti, SUCCEEDS);
    assert_eq!(check_userns(&repo, &["box"]), "", "nothing where a box can be made");
}

/// The names in one of check.sh's lists, in their order there.
fn check_sh_list(name: &str) -> Vec<String> {
    let check = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("check.sh")).unwrap();
    check.split(&format!("\n{name}=(\n")).nth(1).unwrap().split(')').next().unwrap().split_whitespace().map(String::from).collect()
}

/// Each test of a file of tests/ with its name, in their order there.
fn tests_in(file: &str) -> Vec<(String, String)> {
    let code = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join(file)).unwrap();
    code.split("#[test]\n").skip(1).map(|test| (test.lines().find_map(|l| l.strip_prefix("fn ")).unwrap().split('(').next().unwrap().to_string(), test.to_string())).collect()
}

#[test]
fn check_sh_names_the_release_tests_that_need_a_user_namespace() {
    // check.sh leaves these out where no user namespace can be made: each test of release.rs that
    // makes a Dirs, which runs halti in one, in their order there.
    let needing: Vec<String> = tests_in("release.rs").into_iter().filter(|(_, test)| test.contains("Dirs::new()")).map(|(name, _)| name).collect();
    assert_eq!(needing.len(), 6, "{needing:?}");
    assert_eq!(check_sh_list("release_userns_tests"), needing);
}

#[test]
fn check_sh_names_the_escape_tests_and_cargo_test_runs_them() {
    // check.sh leaves these out of `cargo test` where no box can be made. Elsewhere a plain
    // `cargo test` runs them: none is ignored.
    let tests = tests_in("sandbox.rs");
    for (name, test) in &tests {
        assert!(!test.trim_start().starts_with("#[ignore"), "{name} is ignored");
    }
    let names: Vec<String> = tests.into_iter().map(|(name, _)| name).collect();
    assert_eq!(names.len(), 11, "{names:?}");
    assert_eq!(check_sh_list("escape_tests"), names);
}

/// A test folder and a podman image, removed however the test ends.
struct Made {
    dir: PathBuf,
    image: String,
}

impl Drop for Made {
    fn drop(&mut self) {
        let _ = Command::new("podman").args(["rmi", "-f", &self.image]).output();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The id and group of a file in an ext4 disk image, as debugfs reads them without mounting it.
fn owner_in(disk: &Path, path: &str) -> String {
    let debugfs = ["/usr/sbin/debugfs", "/sbin/debugfs"].into_iter().find(|p| Path::new(p).is_file()).unwrap_or("debugfs");
    let out = Command::new(debugfs).args(["-R", &format!("stat {path}")]).arg(disk).output().unwrap();
    let said = text(&out.stdout);
    let field = |name: &str| said.split(name).nth(1).and_then(|rest| rest.split_whitespace().next()).unwrap_or("?").to_string();
    format!("{}:{}", field("User:"), field("Group:"))
}

/// box/to-disk.sh on a small image podman builds here from an archive whose files have the owners
/// a box image's do: root's, the agent's (1000), the shadow group's (42), and the ids of the
/// machines that built Docker's and uv's archives (1001, and group 117), which the image doesn't
/// name. The disk keeps the image's owners and writes the others as root's. Needs Linux, podman
/// as this user (with subordinate ids), mkfs.ext4 and debugfs:
///
///     cargo test --test install_linux -- --ignored to_disk
#[test]
#[ignore = "needs Linux, podman as this user, mkfs.ext4 and debugfs: see above"]
fn to_disk_keeps_the_image_s_owners_and_makes_the_others_root_s() {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    let made = Made {
        dir: env::temp_dir().join(format!("halti-to-disk-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::Relaxed))),
        image: format!("localhost/halti-to-disk-test:{}", std::process::id()),
    };
    let (dir, image) = (&made.dir, &made.image);
    let _ = fs::remove_dir_all(dir);
    let root = dir.join("root");
    for folder in ["etc", "home/agent", "usr/local/bin"] {
        fs::create_dir_all(root.join(folder)).unwrap();
    }
    fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\nagent:x:1000:1000::/home/agent:/bin/bash\n").unwrap();
    fs::write(root.join("etc/group"), "root:x:0:\nshadow:x:42:\nagent:x:1000:\n").unwrap();
    fs::write(root.join("etc/shadow"), "root:*:1::::::\n").unwrap();
    for program in ["dockerd", "uv", "halti-shim"] {
        fs::write(root.join("usr/local/bin").join(program), format!("#!/bin/sh\necho {program}\n")).unwrap();
    }
    // The archive, a set of files at a time, each set with its owner.
    let tar = dir.join("ctx/root.tar");
    fs::create_dir_all(tar.parent().unwrap()).unwrap();
    for (n, (owner, group, paths)) in [
        ("0", "0", &[".", "etc", "etc/passwd", "etc/group", "home", "usr", "usr/local", "usr/local/bin", "usr/local/bin/halti-shim"][..]),
        ("0", "42", &["etc/shadow"]),
        ("1000", "1000", &["home/agent"]),
        ("1001", "1001", &["usr/local/bin/dockerd"]),
        ("1001", "117", &["usr/local/bin/uv"]),
    ]
    .into_iter()
    .enumerate()
    {
        let out = Command::new("tar")
            .args([if n == 0 { "-cf" } else { "-rf" }])
            .arg(&tar)
            .args(["--numeric-owner", &format!("--owner={owner}"), &format!("--group={group}"), "--no-recursion", "-C"])
            .arg(&root)
            .args(paths)
            .output()
            .unwrap();
        assert!(out.status.success(), "tar: {}", text(&out.stderr));
    }
    fs::write(dir.join("ctx/Containerfile"), "FROM scratch\nADD root.tar /\n").unwrap();
    let built = Command::new("podman").args(["build", "-q", "-t", image, "-f"]).arg(dir.join("ctx/Containerfile")).arg(dir.join("ctx")).output().unwrap();
    assert!(built.status.success(), "podman build: {}", text(&built.stderr));

    let disk = dir.join("agent.img");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("box/to-disk.sh");
    let out = Command::new(&script).arg(image).arg(&disk).output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).ends_with("; 2 whose owner the image doesn't name are root's\n"), "{}", text(&out.stdout));
    let owners: Vec<String> = ["/", "/etc/shadow", "/home/agent", "/usr/local/bin/halti-shim", "/usr/local/bin/dockerd", "/usr/local/bin/uv"]
        .iter()
        .map(|p| format!("{p} {}", owner_in(&disk, p)))
        .collect();
    assert_eq!(owners, ["/ 0:0", "/etc/shadow 0:42", "/home/agent 1000:1000", "/usr/local/bin/halti-shim 0:0", "/usr/local/bin/dockerd 0:0", "/usr/local/bin/uv 0:0"]);
    // Nothing is left beside it, and it is never made over a file that is there.
    let beside: Vec<String> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).filter(|n| n.starts_with('.')).collect();
    assert!(beside.is_empty(), "{beside:?}");
    let again = Command::new(&script).arg(image).arg(&disk).output().unwrap();
    assert!(!again.status.success() && text(&again.stderr).contains("already exists"), "{}", text(&again.stderr));
}
