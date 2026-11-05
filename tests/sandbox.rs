//! Escape tests for the sandbox engine's first light: each runs commands in a box made by
//! `halti box sh --engine sandbox` (the debug binary) and checks, from both sides, what the box
//! can't see or reach, and that nothing of it is left after.
//!
//! Linux only, and only where the kernel lets a user make namespaces: each test prints whether it
//! ran or was skipped, and check.sh shows those lines.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::{fs, process};

const HALTI: &str = env!("CARGO_BIN_EXE_halti");

/// Whether a box can be made here; says so if not.
fn can_sandbox(test: &str) -> bool {
    let ok = Command::new("unshare").args(["-Urnm", "--pid", "--fork", "true"]).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    if !ok {
        println!("escape test skipped: {test} (no user namespaces here)");
    }
    ok
}

fn ran(test: &str) {
    println!("escape test ran: {test}");
}

fn in_box(command: &[&str]) -> Command {
    let mut cmd = Command::new(HALTI);
    cmd.args(["box", "sh", "--engine", "sandbox", "--"]).args(command).stdin(Stdio::null());
    cmd
}

/// `bash -c SCRIPT` in a new box, which must succeed; its stdout.
fn bash(script: &str) -> String {
    let out = in_box(&["bash", "-c", script]).output().unwrap();
    assert!(out.status.success(), "{}{}", text(&out.stdout), text(&out.stderr));
    text(&out.stdout)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The fields of /proc/self/mountinfo's lines that matter here: device, root in its file system,
/// mount point and the mount's own options.
fn mounts(mountinfo: &str) -> Vec<[String; 4]> {
    mountinfo
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            Some([f.get(2)?.to_string(), f.get(3)?.to_string(), f.get(4)?.to_string(), f.get(5)?.to_string()])
        })
        .collect()
}

#[test]
fn bash_and_claude_run_inside() {
    if !can_sandbox("bash and claude run") {
        return;
    }
    let out = in_box(&["bash", "-c", "true"]).output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = in_box(&["bash", "-c", "exit 7"]).output().unwrap();
    assert_eq!(out.status.code(), Some(7), "the command's exit code comes out");
    if !Path::new("/usr/local/bin/claude").exists() && !std::env::home_dir().unwrap().join(".local/bin/claude").exists() {
        println!("escape test skipped: claude --version (no claude here)");
        return;
    }
    let out = in_box(&["claude", "--version"]).output().unwrap();
    assert!(out.status.success() && text(&out.stdout).contains("Claude Code"), "{}{}", text(&out.stdout), text(&out.stderr));
    ran("bash and claude run");
}

#[test]
fn the_network_is_only_lo() {
    if !can_sandbox("only lo") {
        return;
    }
    let said = bash("readlink /proc/self/ns/net; echo ---; sed 1,2d /proc/net/dev | cut -d: -f1 | tr -d ' '; echo ---; ls /sys/class/net 2>/dev/null; true");
    let parts: Vec<&str> = said.split("---\n").collect();
    assert_eq!(parts.len(), 3, "{said}");
    assert_ne!(parts[0].trim(), fs::read_link("/proc/self/ns/net").unwrap().to_string_lossy(), "the box has a network namespace of its own");
    assert_eq!(parts[1].trim(), "lo", "{said}");
    // Empty where the kernel won't mount the box a sysfs of its own (then it has no /sys at all).
    assert!(["", "lo"].contains(&parts[2].trim()), "{said}");
    if Path::new("/usr/bin/python3").exists() {
        let script = "import socket; s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(); socket.create_connection(s.getsockname()); print('lo up')";
        assert_eq!(bash(&format!("python3 -c \"{script}\"")).trim(), "lo up");
    }
    ran("only lo");
}

#[test]
fn tcp_to_the_host_fails() {
    if !can_sandbox("no TCP to the host") {
        return;
    }
    // A listener of the host's own, which the host reaches, so the test can't pass by reaching nothing.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    TcpStream::connect(("127.0.0.1", port)).unwrap();
    // And the outer door of this box, which is only ever dialled from inside a sandbox.
    let said = bash(&format!("for p in 3128 {port}; do (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && echo reached $p; done; echo done"));
    assert_eq!(said.trim(), "done", "{said}");
    ran("no TCP to the host");
}

#[test]
fn a_file_outside_the_bind_set_is_missing() {
    if !can_sandbox("planted file missing") {
        return;
    }
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sandbox-fixture-{}", process::id()));
    fs::create_dir_all(&dir).unwrap();
    let secret = dir.join("secret");
    fs::write(&secret, "planted").unwrap();
    let said = bash(&format!("test -e '{}' && echo visible; test -e '{}' && echo dir visible; test -x /usr/bin/env && echo usr; echo done", secret.display(), dir.display()));
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(said, "usr\ndone\n");
    ran("planted file missing");
}

#[test]
fn no_host_root_in_mountinfo() {
    if !can_sandbox("no host root in mountinfo") {
        return;
    }
    let host = mounts(&fs::read_to_string("/proc/self/mountinfo").unwrap());
    let [root_dev, root_root, ..] = host.iter().find(|[.., at, _]| at == "/").unwrap().clone();
    let inside = mounts(&bash("cat /proc/self/mountinfo"));
    let top = inside.iter().find(|[.., at, _]| at == "/").unwrap();
    assert!(!(top[0] == root_dev && top[1] == root_root), "the box's root is the host's: {top:?}");
    assert!(!inside.iter().any(|[dev, root, ..]| *dev == root_dev && *root == root_root), "the host's root is mounted in the box: {inside:?}");
    assert!(!inside.iter().any(|[.., at, _]| at.starts_with("/.old")), "{inside:?}");
    assert!(inside.iter().any(|[.., at, _]| at == "/usr"), "{inside:?}");
    ran("no host root in mountinfo");
}

#[test]
fn every_proc_mount_is_read_only() {
    if !can_sandbox("/proc read-only") {
        return;
    }
    let out = in_box(&["cat", "/proc/self/mountinfo"]).output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let proc: Vec<_> = mounts(&text(&out.stdout)).into_iter().filter(|[.., at, _]| at == "/proc" || at.starts_with("/proc/")).collect();
    assert!(!proc.is_empty(), "no /proc in the box");
    let writable: Vec<_> = proc.iter().filter(|[.., options]| options.split(',').next() != Some("ro")).collect();
    assert!(writable.is_empty(), "writable in the box: {writable:?}");
    let host = text(&out.stderr).contains("host /proc visible");
    ran(if host { "/proc read-only (the host's, bound)" } else { "/proc read-only (its own)" });
}

#[test]
fn nothing_is_left_after_exit() {
    if !can_sandbox("nothing left after exit") {
        return;
    }
    let marker = format!("600.{}", process::id());
    let running = || fs::read_dir("/proc").unwrap().flatten().any(|e| fs::read(e.path().join("cmdline")).is_ok_and(|c| c.split(|b| *b == 0).any(|a| a == marker.as_bytes())));
    let mounts_before = fs::read_to_string("/proc/self/mountinfo").unwrap();

    // A process left running in the background, and the box waiting until told to end.
    let mut child =
        in_box(&["bash", "-c", &format!("sleep {marker} & echo started; read line")]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    assert_eq!(line, "started\n");
    assert!(running(), "the box's sleep should be running");
    child.stdin.take().unwrap().write_all(b"\n").unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());

    assert!(!running(), "the box left its sleep running");
    assert_eq!(fs::read_to_string("/proc/self/mountinfo").unwrap(), mounts_before, "the box changed the host's mounts");
    ran("nothing left after exit");
}

#[test]
fn a_missing_command_says_so() {
    if !can_sandbox("missing command") {
        return;
    }
    let out = in_box(&["no-such-command"]).output().unwrap();
    assert_eq!(out.status.code(), Some(127));
    assert!(text(&out.stderr).contains("halti: no-such-command:"), "{}", text(&out.stderr));
    ran("missing command");
}
