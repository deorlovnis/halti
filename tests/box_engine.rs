//! The VM engine and the agent image, end to end, with a stand-in for halti's door on the Mac.
//!
//! Needs Apple's `container` (running) and builds the agent image, so it only runs on request:
//!
//!     mise run e2e-box        # HALTI_E2E_BOX=1 cargo test --test box_engine -- --ignored --nocapture
//!
//! The test door does what the real one will: it dials the VM's published socket, reads the line
//! that says which listener a connection came through, and answers.

#[path = "../src/engine.rs"]
mod engine;
#[path = "../src/legacy.rs"]
#[allow(dead_code)]
mod legacy;
#[path = "../src/names.rs"]
#[allow(dead_code)] // the engine uses a few
mod names;
#[path = "../box/shim/src/names.rs"]
#[allow(dead_code)]
mod shim_names;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, fs, process, thread};

const POOL: usize = 4;

/// What the test door was asked: (kind, first line of the request).
type Seen = Arc<Mutex<Vec<(String, String)>>>;

struct TestDoor {
    seen: Seen,
    stop: Arc<AtomicBool>,
}

impl TestDoor {
    fn start(socket: &Path) -> Self {
        let door = Self { seen: Seen::default(), stop: Arc::default() };
        for _ in 0..POOL {
            dial(socket.to_path_buf(), door.seen.clone(), door.stop.clone());
        }
        door
    }

    /// Wait until a request of `kind` containing `needle` has arrived.
    fn saw(&self, kind: &str, needle: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let seen = self.seen.lock().unwrap();
            if seen.iter().any(|(k, line)| k == kind && line.contains(needle)) {
                return true;
            }
            drop(seen);
            thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl Drop for TestDoor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// One idle connection into the VM; when it's taken, another is dialed in its place.
fn dial(socket: PathBuf, seen: Seen, stop: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut kind = String::new();
        let mut conn = loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            kind.clear();
            // the VM may still be starting: refused, or accepted and closed right away
            if let Ok(c) = UnixStream::connect(&socket) {
                let mut reader = BufReader::new(c);
                if reader.read_line(&mut kind).unwrap_or(0) > 0 {
                    break reader;
                }
            }
            thread::sleep(Duration::from_millis(200));
        };
        dial(socket, seen.clone(), stop);
        answer(kind.trim(), &mut conn, &seen);
    });
}

/// Handle one taken connection: record the request, and answer by kind.
fn answer(kind: &str, conn: &mut BufReader<UnixStream>, seen: &Seen) {
    let record = |line: String| seen.lock().unwrap().push((kind.to_string(), line));
    match kind {
        "proxy" | names::DOOR_KIND => {
            // the request head, up to the empty line
            let mut head = String::new();
            loop {
                let mut line = String::new();
                if conn.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            record(head);
            let reply = if kind == names::DOOR_KIND {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            } else {
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            };
            let _ = conn.get_mut().write_all(reply.as_bytes());
            let _ = conn.get_mut().shutdown(std::net::Shutdown::Both);
        }
        "mcp" => {
            // an echo server: one answer per line, until the client is done
            let mut first = true;
            loop {
                let mut line = String::new();
                if conn.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if first {
                    record(line.trim().to_string());
                    first = false;
                }
                let _ = conn.get_mut().write_all(format!("echo:{line}").as_bytes());
            }
            let _ = conn.get_mut().shutdown(std::net::Shutdown::Both);
        }
        other => record(format!("unknown kind {other}")),
    }
}

/// The VM is stopped when the test ends, however it ends.
struct Vm(String);

impl Drop for Vm {
    fn drop(&mut self) {
        let _ = engine::stop(&self.0);
    }
}

/// Run a script in the VM as the agent: (succeeded, stdout and stderr).
fn sh(vm: &str, env: &[(String, String)], script: &str) -> (bool, String) {
    let cmd = ["sh".to_string(), "-c".to_string(), script.to_string()];
    let out = engine::exec_command(vm, env, &cmd, false).stdin(Stdio::null()).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text.trim().to_string())
}

/// The host and the shim keep separate copies of the guest names; they have to say the same.
#[test]
fn host_and_shim_agree_on_the_guest_names() {
    assert_eq!(
        (names::SHIM, names::DOOR_SOCKET, names::LOCAL_SOCKET, names::DOOR_KIND),
        (shim_names::SHIM, shim_names::DOOR_SOCKET, shim_names::LOCAL_SOCKET, shim_names::DOOR_KIND)
    );
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn vm_has_only_the_door() {
    if env::var_os("HALTI_E2E_BOX").is_none() {
        eprintln!("HALTI_E2E_BOX isn't set: skipping");
        return;
    }
    engine::available().unwrap();

    // HALTI_E2E_AGENT_IMAGE: an image built already, under another name, so the agent image stays as it is.
    let image = match env::var("HALTI_E2E_AGENT_IMAGE") {
        Ok(name) => engine::image_digest(&name).unwrap(),
        Err(_) => {
            let image = engine::build_agent_image(&Path::new(env!("CARGO_MANIFEST_DIR")).join("box")).unwrap();
            assert!(image.starts_with(&format!("{}@sha256:", names::AGENT_IMAGE)), "{image}");
            assert_eq!(engine::image_digest(engine::AGENT_IMAGE).unwrap(), image);
            image
        }
    };

    // a short path for the socket (macOS limits them), and folders to mount
    let dir = PathBuf::from(format!("/tmp/halti-e2e-box-{}", process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let (home, ro) = (dir.join("home"), dir.join("ro"));
    fs::create_dir(&home).unwrap();
    fs::create_dir(&ro).unwrap();
    fs::write(ro.join("note"), "read me\n").unwrap();

    let name = format!("halti-e2e-box-{}", process::id());
    let spec = engine::VmSpec {
        name: name.clone(),
        image,
        cpus: 2,
        memory: "2G".into(),
        socket: dir.join("door.sock"),
        mounts: vec![engine::Mount { host: home.clone(), guest: "/home/agent".into(), readonly: false }, engine::Mount { host: ro, guest: "/ro".into(), readonly: true }],
        docker: false,
        rosetta: false,
    };
    let door = TestDoor::start(&spec.socket);
    let vm = Vm(name.clone());
    let started = Instant::now();
    engine::run(&spec).unwrap();
    println!("run returned after {:?}", started.elapsed());
    assert!(engine::running(&name));
    let env = engine::agent_env(true);
    assert!(sh(&name, &env, "true").0);
    println!("first exec ran after {:?}", started.elapsed());

    // the engine's exec: the agent's identity, the environment, the exit status
    let status = engine::exec(&name, &env, &["sh".into(), "-c".into(), "test \"$(id -u):$(id -g):$HOME\" = 1000:1000:/home/agent && exit 3".into()], false).unwrap();
    assert_eq!(status.code(), Some(3));

    // HTTPS through the proxy listener reaches the door as `proxy` with the CONNECT line
    let (ok, out) = sh(&name, &env, "curl -sS -m 10 -x http://127.0.0.1:3128 https://example.com");
    assert!(!ok, "the test door refuses, so curl must fail: {out}");
    assert!(door.saw("proxy", "CONNECT example.com:443"), "{:?}", door.seen.lock().unwrap());

    // halti itself, at 127.0.0.2, is not sent to the proxy even with the agent's environment
    let (ok, out) = sh(&name, &env, "curl -sS -m 10 http://127.0.0.2/model/x");
    assert!(ok && out == "ok", "{out}");
    assert!(door.saw(names::DOOR_KIND, "GET /model/x"), "{:?}", door.seen.lock().unwrap());

    // the shim's `mcp`: stdio in and out, paired with a connection of kind `mcp`
    let mcp = [names::SHIM.to_string(), "mcp".to_string()];
    let mut child = engine::exec_command(&name, &[], &mcp, false).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    stdin.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1}\n").unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "echo:{\"jsonrpc\":\"2.0\",\"id\":1}\n");
    drop(stdin);
    assert!(child.wait().unwrap().success());
    assert!(door.saw("mcp", "jsonrpc"));

    // nothing else gets out: only a loopback interface, and a direct request goes nowhere
    let seen = door.count();
    assert_eq!(sh(&name, &[], "ls /sys/class/net").1, "lo");
    let (ok, out) = sh(&name, &[], "curl -sS -m 5 --noproxy '*' https://example.com");
    assert!(!ok, "{out}");
    let (ok, out) = sh(&name, &[], "curl -sS -m 5 --noproxy '*' http://1.1.1.1");
    assert!(!ok, "{out}");
    assert_eq!(door.count(), seen, "those requests should not have reached the door");

    // /tmp and /var/tmp are memory, and the agent can write nowhere else on the system
    for path in ["/tmp", "/var/tmp"] {
        let (ok, out) = sh(&name, &[], &format!("grep -q ' {path} tmpfs ' /proc/mounts"));
        assert!(ok, "{path} is not a tmpfs: {out}");
    }
    assert!(sh(&name, &[], "touch /usr/x").1.contains("Permission denied"));
    assert!(sh(&name, &[], "touch /etc/x").1.contains("Permission denied"));
    let (_, writable) = sh(
        &name,
        &[],
        &format!(
            "find / -xdev \\( -path /proc -o -path /sys -o -path /dev -o -path /tmp -o -path /var/tmp -o -path /home/agent \\) -prune -o -writable ! -type l ! -path {} -print 2>/dev/null",
            names::LOCAL_SOCKET
        ),
    );
    assert_eq!(writable, "", "the agent can write on the root filesystem");
    assert_eq!(sh(&name, &[], "find / -xdev -perm /6000 -type f 2>/dev/null").1, "", "setuid files");
    assert!(sh(&name, &[], "echo ok > /tmp/x && cat /tmp/x").0);
    let (ok, out) = sh(&name, &[], &format!("python3 -c \"import socket; s = socket.socket(socket.AF_UNIX); s.connect('{}')\"", names::DOOR_SOCKET));
    assert!(!ok && out.contains("Permission denied"), "{out}");

    // the mounted folder is writable as the agent, and the Mac sees it; a read-only mount isn't
    let (ok, out) = sh(&name, &[], "echo from-vm > ~/out.txt && mkdir ~/.claude && echo '{}' > ~/.claude/settings.json");
    assert!(ok, "{out}");
    assert_eq!(fs::read_to_string(home.join("out.txt")).unwrap(), "from-vm\n");
    assert!(home.join(".claude/settings.json").is_file());
    assert_eq!(sh(&name, &[], "cat /ro/note").1, "read me");
    assert!(sh(&name, &[], "touch /ro/x").1.contains("Read-only file system"));

    // stop removes the VM, and the socket; stopping again is fine
    let stopping = Instant::now();
    engine::stop(&name).unwrap();
    println!("stop took {:?}", stopping.elapsed());
    assert!(!engine::running(&name));
    let listed = Command::new("container").args(["ls", "-a"]).output().unwrap();
    assert!(!String::from_utf8_lossy(&listed.stdout).contains(&name));
    assert!(!spec.socket.exists());
    engine::stop(&name).unwrap();

    drop(vm);
    drop(door);
    let _ = fs::remove_dir_all(&dir);
}

/// The browser VM: its image builds, it has only the door, the runner starts in it as an
/// unprivileged user, and Chromium's trust store takes the box CA.
#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn browser_vm_has_only_the_door_and_runs_the_runner() {
    if env::var_os("HALTI_E2E_BOX").is_none() {
        eprintln!("HALTI_E2E_BOX isn't set: skipping");
        return;
    }
    engine::available().unwrap();

    let built = Instant::now();
    let image = engine::build_browser_image(&Path::new(env!("CARGO_MANIFEST_DIR")).join("box")).unwrap();
    println!("browser image built in {:?}: {image}", built.elapsed());
    assert!(image.starts_with(&format!("{}@sha256:", names::BROWSER_IMAGE)), "{image}");
    assert_eq!(engine::image_digest(engine::BROWSER_IMAGE).unwrap(), image);

    let dir = PathBuf::from(format!("/tmp/halti-e2e-browser-{}", process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let name = engine::browser_vm_name(&format!("e2e-{}", process::id()));
    let spec = engine::BrowserSpec {
        name: name.clone(),
        image,
        socket: dir.join("door.sock"),
        // not there yet: run_browser makes it
        downloads: Some(dir.join("downloads")),
    };
    let door = TestDoor::start(&spec.socket);
    let vm = Vm(name.clone());
    let started = Instant::now();
    engine::run_browser(&spec).unwrap();
    assert!(engine::running(&name));
    let env = [("HOME".to_string(), "/home/browser".to_string())];
    assert!(sh(&name, &env, "true").0);
    println!("browser VM running after {:?}", started.elapsed());

    // as the browser's user; no network; no setuid programs; nothing writable but /tmp, its home
    // and the downloads
    assert_eq!(sh(&name, &env, "id -un; id -u").1, "browser\n1000");
    assert_eq!(sh(&name, &[], "ls /sys/class/net").1, "lo");
    assert_eq!(sh(&name, &[], "find / -xdev -perm /6000 -type f 2>/dev/null").1, "");
    let (_, writable) = sh(
        &name,
        &[],
        &format!(
            "find / -xdev \\( -path /proc -o -path /sys -o -path /dev -o -path /tmp -o -path /var/tmp -o -path /home/browser -o -path /downloads \\) -prune -o -writable ! -type l ! -path {} -print 2>/dev/null",
            names::LOCAL_SOCKET
        ),
    );
    assert_eq!(writable, "", "the browser's user can write on the root filesystem");
    let (ok, out) = sh(&name, &[], "node --version");
    assert!(ok && out.starts_with("v22."), "{out}");
    let connect = format!(r#"node -e "require('net').connect('{}').on('error', (e) => {{ console.log(e.code); process.exit(1) }})""#, names::DOOR_SOCKET);
    let (ok, out) = sh(&name, &[], &connect);
    assert!(!ok && out.contains("EACCES"), "only root may dial the door socket: {out}");

    // the downloads folder is shared with the Mac, writable from the VM
    let (ok, out) = sh(&name, &env, "echo saved > /downloads/file.txt");
    assert!(ok, "{out}");
    assert_eq!(fs::read_to_string(dir.join("downloads/file.txt")).unwrap(), "saved\n");

    // the box CA goes where Chromium looks, and only there
    let ca_pem = test_ca_pem();
    let ca = engine::install_browser_ca(&name, &ca_pem);
    assert!(ca.is_ok(), "{ca:?}");
    let (ok, out) = sh(&name, &env, "certutil -L -d sql:$HOME/.pki/nssdb");
    assert!(ok && out.contains("halti-box") && out.contains("C,,"), "{out}");
    // repeatable
    engine::install_browser_ca(&name, &ca_pem).unwrap();

    // the runner starts as the browser's user and answers its protocol on stdout
    let mut runner = engine::exec_runner(&name, &[]).unwrap();
    let mut stdin = runner.stdin.take().unwrap();
    let mut stdout = BufReader::new(runner.stdout.take().unwrap());
    stdin.write_all(b"{\"id\":1,\"cmd\":\"nonsense\"}\n").unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "{\"id\":1,\"ok\":false,\"error\":\"unknown command nonsense\"}");
    drop(stdin); // the runner ends when its stdin does
    assert!(runner.wait().unwrap().success());

    // the proxy listener reaches the door
    let connect = r#"node -e "const s = require('net').connect(3128, '127.0.0.1'); s.write('CONNECT example.com:443 HTTP/1.1\r\n\r\n'); s.on('data', (d) => { console.log(String(d).split('\r')[0]); process.exit(0) })""#;
    let (_, out) = sh(&name, &env, connect);
    assert_eq!(out, "HTTP/1.1 403 Forbidden", "the test door refuses");
    assert!(door.saw("proxy", "CONNECT example.com:443"));

    drop(vm);
    assert!(!engine::running(&name));
    assert!(!spec.socket.exists());
    drop(door);
    let _ = fs::remove_dir_all(&dir);
}

/// A CA certificate (PEM) to install; nothing signs with it.
fn test_ca_pem() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.self_signed(&key).unwrap().pem()
}

// --- a workspace's boxes, through the halti binary ---
//
// These drive the debug binary in a throwaway home, with its test hooks answering passphrases and
// Touch ID, and real VMs. Each box is named for this test run alone, so no box of an installed
// halti or of cred is ever named, stopped or swept.

const HALTI: &str = env!("CARGO_BIN_EXE_halti");
const ACME: &str = "acme passphrase one";
const GLOBEX: &str = "globex passphrase one";

/// A home for the debug binary, one per test, removed when dropped, after its boxes are stopped.
struct Home {
    dir: PathBuf,
    /// Workspace boxes to stop when the test ends, however it ends: `acme/NAME`.
    boxes: Mutex<Vec<String>>,
}

impl Home {
    /// The home of the test `what`, as `box_name` names its box: tests run side by side.
    fn new(what: &str) -> Home {
        let dir = env::temp_dir().join(format!("halti-e2e-wsbox-{what}-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        for sub in ["keychain", "policy", "box", "home"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        Home { dir, boxes: Mutex::default() }
    }

    /// `halti` with every path in this home and Touch ID answering yes; nothing answers a passphrase.
    fn halti(&self) -> Command {
        let mut command = Command::new(HALTI);
        command
            .env("HOME", self.dir.join("home"))
            .env("HALTI_INDEX", self.dir.join("index.json"))
            .env("HALTI_POLICY_DIR", self.dir.join("policy"))
            .env("HALTI_BOX_DIR", self.dir.join("box"))
            .env("HALTI_TEST_KEYCHAIN", self.dir.join("keychain"))
            .env("HALTI_TEST_APPROVE", "yes")
            .env_remove("HALTI_TEST_PASSPHRASE")
            .env_remove("VISUAL")
            .stdin(Stdio::null());
        command
    }

    /// `halti ARGS` with `passphrase` answering, and `editor` as $EDITOR.
    fn ws(&self, passphrase: &str, editor: &str, args: &[&str]) -> std::process::Output {
        let out = self.halti().env("HALTI_TEST_PASSPHRASE", passphrase).env("EDITOR", editor).args(args).output().unwrap();
        println!("halti {args:?}:\n{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        out
    }

    /// An "editor" that writes `text` over the file.
    fn editor(&self, text: &str) -> String {
        static COUNT: Mutex<usize> = Mutex::new(0);
        let mut count = COUNT.lock().unwrap();
        *count += 1;
        let file = self.dir.join(format!("edited-{count}.toml"));
        fs::write(&file, text).unwrap();
        format!("cp {}", file.display())
    }

    /// Stores `value` as RES/FIELD in workspace `ws`, piped in.
    fn set(&self, ws: &str, passphrase: &str, res: &str, field: &str, value: &str) {
        let target = format!("{ws}/{res}");
        let mut child = self
            .halti()
            .env("HALTI_TEST_PASSPHRASE", passphrase)
            .args(["ws", "set", &target, field])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(value.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    /// Writes and approves `text` as RES's policy in workspace `ws`.
    fn policy(&self, ws: &str, passphrase: &str, res: &str, text: &str) {
        let target = format!("{ws}/{res}");
        assert!(self.ws(passphrase, &self.editor(text), &["ws", "policy", "edit", &target]).status.success());
        assert!(self.ws(passphrase, "true", &["ws", "policy", "approve", &target]).status.success());
    }

    /// Workspace `ws` with a model and github, its token `token` (`basic`'s, for httpbin's
    /// /basic-auth), and a box `name` that may use github.
    fn workspace_with_box(&self, ws: &str, passphrase: &str, name: &str, token: &str, image: &str) {
        assert!(self.ws(passphrase, "true", &["ws", "new", ws]).status.success());
        self.set(ws, passphrase, "anthropic", "token", "model-token-not-used");
        self.policy(ws, passphrase, "anthropic", "[fetch]\nhosts = [\"https://api.anthropic.com\"]\nauth = \"Bearer {token}\"\n");
        self.set(ws, passphrase, "github", "token", token);
        self.policy(ws, passphrase, "github", GITHUB);
        let text = format!("run = [\"claude\"]\nimage = \"{image}\"\nmodel = \"anthropic\"\nsites = [\"github\"]\nkeep = true\ncpus = 2\nmemory = \"2G\"\n\n[net]\nallow = []\n");
        let target = format!("{ws}/{name}");
        assert!(self.ws(passphrase, &self.editor(&text), &["ws", "box", "new", &target]).status.success());
        self.boxes.lock().unwrap().push(target);
    }

    /// `halti ws run TARGET -- CMD`, started and left running.
    fn start(&self, passphrase: &str, target: &str, cmd: &[&str]) -> std::process::Child {
        let mut command = self.halti();
        command.env("HALTI_TEST_PASSPHRASE", passphrase).args(["ws", "run", target, "--"]).args(cmd).stdout(Stdio::piped()).stderr(Stdio::piped());
        command.spawn().unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        for target in self.boxes.lock().unwrap().iter() {
            let _ = self.halti().args(["ws", "stop", target]).output();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The agent image to pin, once the engine is there: HALTI_E2E_AGENT_IMAGE's, or the one built.
fn agent_image() -> Option<String> {
    if env::var_os("HALTI_E2E_BOX").is_none() {
        eprintln!("HALTI_E2E_BOX isn't set: skipping");
        return None;
    }
    engine::available().unwrap();
    Some(engine::image_digest(&env::var("HALTI_E2E_AGENT_IMAGE").unwrap_or_else(|_| engine::AGENT_IMAGE.to_string())).unwrap())
}

/// github's policy: httpbin, with the token sent as Basic credentials.
const GITHUB: &str = "[fetch]\nhosts = [\"https://httpbin.org\"]\nauth = \"Basic {token}\"\n";

/// A token for `Basic {token}` that httpbin's /basic-auth/USER/PASSWORD answers 200 to only for
/// this user and password: what the door sent shows in the answer's status, which isn't masked.
fn basic(user: &str, password: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
}

/// A box name of this test run alone.
fn box_name(what: &str) -> String {
    format!("e2e-{what}-{}", process::id())
}

/// Waits until the VM of box `name` (`VM_PREFIX…-NAME`) runs, or a minute passes: this test's,
/// never another's that runs beside it.
fn until_running(vm_prefix: &str, name: &str) -> String {
    let suffix = format!("-{name}");
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        let listed = Command::new("container").args(["ls"]).output().unwrap();
        if let Some(vm) = String::from_utf8_lossy(&listed.stdout).split_whitespace().find(|word| word.starts_with(vm_prefix) && word.ends_with(&suffix)) {
            return vm.to_string();
        }
        thread::sleep(Duration::from_millis(500));
    }
    panic!("no VM {vm_prefix}…{suffix} runs");
}

/// A shell command for the agent: the status httpbin's /basic-auth answers for each user and
/// password, then its echo of a request, with the Authorization the door put on it.
fn statuses_then_headers(pairs: &[(&str, &str)]) -> String {
    let mut script = String::new();
    for (user, password) in pairs {
        script += &format!("curl -sS -m 20 -o /dev/null -w '%{{http_code}} ' https://httpbin.org/basic-auth/{user}/{password}; ");
    }
    script + "curl -sS -m 20 https://httpbin.org/headers"
}

/// The Authorization header as httpbin echoes it, the whole header masked.
const MASKED: &str = "\"Authorization\": \"********\"";

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_workspace_box_reaches_only_its_sites() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("sites");
    let name = box_name("sites");
    // The Keychain's github, approved, and globex's: a box of acme's must reach neither.
    let (acme, globex, keychain) = (basic("acme", "acme-token-0001"), basic("globex", "globex-token-0001"), basic("keychain", "keychain-token-0001"));
    fs::write(home.dir.join("keychain/github.token"), &keychain).unwrap();
    fs::write(home.dir.join("index.json"), "{\"github\":{\"fields\":{\"token\":{}}}}").unwrap();
    fs::write(home.dir.join("policy/github.toml"), GITHUB).unwrap();
    assert!(home.halti().args(["policy", "approve", "github"]).output().unwrap().status.success());
    home.workspace_with_box("globex", GLOBEX, &name, &globex, &image);
    home.workspace_with_box("acme", ACME, &name, &acme, &image);
    // Only acme's credentials are accepted: the door sent acme's token, and no other.
    let script = statuses_then_headers(&[("acme", "acme-token-0001"), ("globex", "globex-token-0001"), ("keychain", "keychain-token-0001")]);
    let out = home.ws(ACME, "true", &["ws", "run", &format!("acme/{name}"), "--", "sh", "-c", &script]);
    let seen = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && seen.starts_with("200 401 401 "), "acme's alone: {seen}");
    assert!(seen.contains(MASKED), "acme's token, masked: {seen}");
    assert!(![&acme, &globex, &keychain].iter().any(|token| seen.contains(token.as_str())), "{seen}");
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_token_set_while_running_is_used_at_once() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("rotate");
    let name = box_name("rotate");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    let target = format!("acme/{name}");
    let mut opener = home.start(ACME, &target, &["sleep", "120"]);
    until_running("halti-wsbox-", &name);
    let new = basic("acme", "acme-token-0002");
    home.set("acme", ACME, "github", "token", &new);
    // A second terminal, in the same VM through the opener's door, which reads acme again: only
    // the new token is accepted.
    let script = statuses_then_headers(&[("acme", "acme-token-0002"), ("acme", "acme-token-0001")]);
    let out = home.halti().args(["ws", "run", &target, "--", "sh", "-c", &script]).output().unwrap();
    let seen = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && seen.starts_with("200 401 ") && seen.contains(MASKED) && !seen.contains(&new), "{seen}");
    assert!(home.halti().args(["ws", "stop", &target]).output().unwrap().status.success());
    opener.wait().unwrap();
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_second_terminal_joins_without_a_question() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("join");
    let name = box_name("join");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    let target = format!("acme/{name}");
    let mut opener = home.start(ACME, &target, &["sleep", "120"]);
    until_running("halti-wsbox-", &name);
    // Nothing answers a passphrase here: the join asks none.
    let out = home.halti().args(["ws", "run", &target, "--", "sh", "-c", "exit 7"]).output().unwrap();
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.code() == Some(7) && !said.contains("[test] asked"), "{said}");
    assert!(home.halti().args(["ws", "stop", &target]).output().unwrap().status.success());
    opener.wait().unwrap();
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn ws_stop_seals_sessions_then_stops_both_vms() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("stop");
    let name = box_name("stop");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    let target = format!("acme/{name}");
    let mut opener = home.start(ACME, &target, &["sleep", "120"]);
    let vm = until_running("halti-wsbox-", &name);
    let out = home.halti().args(["ws", "stop", &target]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("stopped box {target}\n"));
    opener.wait().unwrap();
    assert!(!engine::running(&vm) && !engine::running(&vm.replacen("halti-wsbox-", "halti-wsbrowser-", 1)));
    // The opener put the box away: its lock is free, and its store closed.
    let listed = home.ws(ACME, "true", &["ws", "box", "ls", "acme"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains(" locked "), "{}", String::from_utf8_lossy(&listed.stdout));
    let again = home.halti().args(["ws", "stop", &target]).output().unwrap();
    assert!(String::from_utf8_lossy(&again.stderr).ends_with(&format!("halti: box {target} isn't running\n")));
}

/// github's policy with its pages to browse: the start page sets a cookie, so a browser closed on
/// it leaves a session to seal.
const GITHUB_BROWSED: &str =
    "[fetch]\nhosts = [\"https://httpbin.org\"]\nauth = \"Basic {token}\"\n\n[browse]\norigins = [\"https://httpbin.org\"]\nstart = \"https://httpbin.org/cookies/set?halti=1\"\n";

/// A shell command for the agent: open a browser on `site` through halti's MCP server, then keep
/// the connection, and so the browser, open for two minutes. The server's answers go to stdout.
fn browse_then_wait(site: &str) -> String {
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
    let open = format!(r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"browse_open","arguments":{{"site":"{site}"}}}}}}"#);
    format!("{{ printf '%s\\n' '{init}' '{open}'; sleep 120; }} | {} mcp", names::SHIM)
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn ctrl_c_twice_reaches_only_halti_and_the_box_is_put_away() {
    let Some(image) = agent_image() else { return };
    engine::build_browser_image(&Path::new(env!("CARGO_MANIFEST_DIR")).join("box")).unwrap();
    let home = Home::new("ctrl-c");
    let name = box_name("ctrl-c");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    home.policy("acme", ACME, "github", GITHUB_BROWSED);
    let target = format!("acme/{name}");
    // The opener leads a process group, as a terminal's job does; what it starts that needs no
    // terminal is in a group of its own.
    let mut opener = home
        .halti()
        .env("HALTI_TEST_PASSPHRASE", ACME)
        .args(["ws", "run", &target, "--", "sh", "-c", &browse_then_wait("github")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let vm = until_running("halti-wsbox-", &name);
    let browser_vm = vm.replacen("halti-wsbox-", "halti-wsbrowser-", 1);
    // The agent's browser is open on github, its runner in the browser VM.
    let mut answers = BufReader::new(opener.stdout.take().unwrap());
    let opened = loop {
        let mut line = String::new();
        assert!(answers.read_line(&mut line).unwrap() > 0, "the agent ended before its browser opened");
        let answer: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
        if answer["id"] == 2 {
            break answer;
        }
    };
    assert_eq!(opened["result"]["isError"], false, "{opened}");
    assert!(engine::running(&browser_vm), "the browser VM runs");
    // Ctrl-C as the terminal sends it, to the job's whole group; again while the box is put away.
    let job = opener.id() as i32;
    unsafe { libc::kill(-job, libc::SIGINT) };
    thread::sleep(Duration::from_millis(500));
    unsafe { libc::kill(-job, libc::SIGINT) };
    let out = opener.wait_with_output().unwrap();
    println!("{}", String::from_utf8_lossy(&out.stderr));
    drop(answers);
    assert!(!engine::running(&vm) && !engine::running(&browser_vm), "both VMs are stopped");
    // Its store is detached, and its lock free.
    let mounted = Command::new("/sbin/mount").output().unwrap();
    assert!(!String::from_utf8_lossy(&mounted.stdout).contains(&format!("/open/{name} (")), "the store is still mounted");
    let listed = home.ws(ACME, "true", &["ws", "box", "ls", "acme"]);
    let listed = String::from_utf8_lossy(&listed.stdout);
    let row = listed.lines().find(|line| line.starts_with(&name)).unwrap_or_else(|| panic!("{listed}"));
    assert!(row.contains(" locked "), "{row}");
    // The runner outlived the Ctrl-C, so github's session was sealed as the box was put away: the
    // row names github as a site and as a session.
    assert_eq!(row.matches("github").count(), 2, "{row}");
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_keychain_box_of_the_same_name_keeps_running() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("apart");
    let name = box_name("apart");
    // A Keychain box of this name, running.
    let text = format!("run = [\"claude\"]\nimage = \"{image}\"\nkeep = false\ncpus = 2\nmemory = \"2G\"\n");
    assert!(home.halti().env("EDITOR", home.editor(&text)).args(["box", "new", &name]).output().unwrap().status.success());
    assert!(home.halti().args(["box", "approve", &name]).output().unwrap().status.success());
    let mut keychain_box = home.halti().args(["box", "run", &name, "--", "sleep", "120"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let keychain_vm = format!("{}{name}", names::BOX_VM_PREFIX);
    until_running(names::BOX_VM_PREFIX, &name);
    // acme's box of the same name starts, ends and is stopped beside it.
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    let target = format!("acme/{name}");
    assert!(home.ws(ACME, "true", &["ws", "run", &target, "--", "true"]).status.success());
    let out = home.halti().args(["ws", "stop", &target]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).ends_with(&format!("halti: box {target} isn't running\n")));
    assert!(engine::running(&keychain_vm), "the Keychain box runs on");
    assert!(home.halti().args(["box", "stop", &name]).output().unwrap().status.success());
    keychain_box.wait().unwrap();
}

// --- a workspace kept open by `halti open` ---
//
// The open workspace starts and stops boxes when asked on its socket: some of these speak its lines
// themselves, and the others are its clients, `ws run` and `ws stop`, which ask nothing.

impl Home {
    /// The id of workspace `ws`, as its directory record holds it.
    fn ws_id(&self, ws: &str) -> String {
        let record = fs::read(self.dir.join("home/Library/Application Support/halti-dev/ws/dir").join(ws)).unwrap();
        record[1..17].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `halti open WS`, once it says it is open, with its stdout still to read.
    fn open(&self, ws: &str, passphrase: &str) -> (std::process::Child, BufReader<std::process::ChildStdout>) {
        let mut child = self.halti().env("HALTI_TEST_PASSPHRASE", passphrase).args(["open", ws]).stdout(Stdio::piped()).process_group(0).spawn().unwrap();
        let mut said = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        while !line.contains(" is open in this terminal.") {
            line.clear();
            if said.read_line(&mut line).unwrap() == 0 {
                let _ = child.wait();
                panic!("halti open ended before it was open");
            }
        }
        (child, said)
    }

    /// Where open workspace `ws` listens.
    fn keeper_socket(&self, ws: &str) -> PathBuf {
        PathBuf::from(format!("/tmp/halti-dev-{}/ws/{}.keep.sock", unsafe { libc::getuid() }, &self.ws_id(ws)[..12]))
    }

    /// `halti close WS`: what it printed.
    fn close(&self, ws: &str) -> String {
        let out = self.halti().args(["close", ws]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

/// A `start` of box `name` of `ws`, held open: its answer, and the session.
fn keeper_start(socket: &Path, ws: &str, name: &str) -> (String, BufReader<UnixStream>) {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.write_all(format!("halti-keep/1 start {ws} {name}\n").as_bytes()).unwrap();
    let mut session = BufReader::new(stream);
    let mut answer = String::new();
    session.read_line(&mut answer).unwrap();
    (answer, session)
}

/// One line to an open workspace, and its answer.
fn keeper_ask(socket: &Path, line: &str) -> String {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.write_all(line.as_bytes()).unwrap();
    let mut answer = String::new();
    BufReader::new(stream).read_line(&mut answer).unwrap();
    answer
}

/// Whether the store of box `name` is still attached.
fn mounted(name: &str) -> bool {
    let mounted = Command::new("/sbin/mount").output().unwrap();
    String::from_utf8_lossy(&mounted.stdout).contains(&format!("/open/{name} ("))
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn an_open_workspace_starts_a_box_without_a_question() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("keep-start");
    let name = box_name("keep-start");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    let (mut keeper, _said) = home.open("acme", ACME);
    let (answer, _session) = keeper_start(&home.keeper_socket("acme"), "acme", &name);
    assert_eq!(answer, "halti-keep/1 started\n");
    until_running("halti-wsbox-", &name);
    // A second terminal joins it, and nothing answers a passphrase there: none is asked.
    let out = home.halti().args(["ws", "run", &format!("acme/{name}"), "--", "sh", "-c", "exit 7"]).output().unwrap();
    assert!(out.status.code() == Some(7) && !String::from_utf8_lossy(&out.stderr).contains("[test] asked"), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(home.close("acme"), "closed acme and stopped 1 box\n");
    assert!(keeper.wait().unwrap().success());
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn closing_stops_both_boxes_and_detaches_both_stores() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("keep-two");
    let (one, two) = (box_name("keep-one"), box_name("keep-two"));
    home.workspace_with_box("acme", ACME, &one, &basic("acme", "acme-token-0001"), &image);
    let text = format!("run = [\"claude\"]\nimage = \"{image}\"\nkeep = true\ncpus = 2\nmemory = \"2G\"\n");
    assert!(home.ws(ACME, &home.editor(&text), &["ws", "box", "new", &format!("acme/{two}")]).status.success());
    home.boxes.lock().unwrap().push(format!("acme/{two}"));
    let (mut keeper, _said) = home.open("acme", ACME);
    let socket = home.keeper_socket("acme");
    let (first, mut one_session) = keeper_start(&socket, "acme", &one);
    let (second, mut two_session) = keeper_start(&socket, "acme", &two);
    assert_eq!((first.as_str(), second.as_str()), ("halti-keep/1 started\n", "halti-keep/1 started\n"));
    // Side by side, in one process.
    let (vm_one, vm_two) = (until_running("halti-wsbox-", &one), until_running("halti-wsbox-", &two));
    assert_eq!(keeper_ask(&socket, "halti-keep/1 ping acme\n"), "halti-keep/1 open 2\n");
    assert_eq!(home.close("acme"), "closed acme and stopped 2 boxes\n");
    for session in [&mut one_session, &mut two_session] {
        let mut said = String::new();
        session.read_line(&mut said).unwrap();
        assert_eq!(said, "halti-keep/1 stopped\n");
    }
    assert!(keeper.wait().unwrap().success());
    assert!(!engine::running(&vm_one) && !engine::running(&vm_two) && !mounted(&one) && !mounted(&two));
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn closing_stops_a_box_another_terminal_runs() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("keep-other");
    let name = box_name("keep-other");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    // Started by `ws run` before acme was open: it asked, and holds acme's keys in its own process.
    let mut other = home.start(ACME, &format!("acme/{name}"), &["sleep", "120"]);
    let vm = until_running("halti-wsbox-", &name);
    let (mut keeper, _said) = home.open("acme", ACME);
    assert_eq!(home.close("acme"), "closed acme and stopped 1 box\n");
    assert!(keeper.wait().unwrap().success());
    other.wait().unwrap();
    assert!(!engine::running(&vm) && !mounted(&name));
    let listed = home.ws(ACME, "true", &["ws", "box", "ls", "acme"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains(" locked "), "no box lock of acme is held");
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn the_keeper_socket_is_not_in_a_box() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("keep-unseen");
    let name = box_name("keep-unseen");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    let (mut keeper, _said) = home.open("acme", ACME);
    let (answer, _session) = keeper_start(&home.keeper_socket("acme"), "acme", &name);
    assert_eq!(answer, "halti-keep/1 started\n");
    until_running("halti-wsbox-", &name);
    let look = "ls -d /tmp/halti-* 2>/dev/null; find / -xdev -name '*.keep.sock' 2>/dev/null; echo looked";
    let out = home.halti().args(["ws", "run", &format!("acme/{name}"), "--", "sh", "-c", look]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "looked\n");
    home.close("acme");
    assert!(keeper.wait().unwrap().success());
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_token_set_while_open_is_used_at_once() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("keep-rotate");
    let name = box_name("keep-rotate");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    let (mut keeper, _said) = home.open("acme", ACME);
    let (_, _session) = keeper_start(&home.keeper_socket("acme"), "acme", &name);
    until_running("halti-wsbox-", &name);
    let new = basic("acme", "acme-token-0002");
    home.set("acme", ACME, "github", "token", &new);
    let script = statuses_then_headers(&[("acme", "acme-token-0002"), ("acme", "acme-token-0001")]);
    let out = home.halti().args(["ws", "run", &format!("acme/{name}"), "--", "sh", "-c", &script]).output().unwrap();
    let seen = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && seen.starts_with("200 401 ") && seen.contains(MASKED) && !seen.contains(&new), "{seen}");
    home.close("acme");
    assert!(keeper.wait().unwrap().success());
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_stop_seals_the_session_of_an_open_browser() {
    let Some(image) = agent_image() else { return };
    engine::build_browser_image(&Path::new(env!("CARGO_MANIFEST_DIR")).join("box")).unwrap();
    let home = Home::new("keep-seal");
    let name = box_name("keep-seal");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    home.policy("acme", ACME, "github", GITHUB_BROWSED);
    let (mut keeper, _said) = home.open("acme", ACME);
    let socket = home.keeper_socket("acme");
    let (_, mut session) = keeper_start(&socket, "acme", &name);
    let vm = until_running("halti-wsbox-", &name);
    // The agent opens a browser on github and keeps it open.
    let mut agent = home.halti().args(["ws", "run", &format!("acme/{name}"), "--", "sh", "-c", &browse_then_wait("github")]).stdout(Stdio::piped()).spawn().unwrap();
    let mut answers = BufReader::new(agent.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert!(answers.read_line(&mut line).unwrap() > 0, "the agent ended before its browser opened");
        if serde_json::from_str::<serde_json::Value>(&line).unwrap_or_default()["id"] == 2 {
            break;
        }
    }
    // Stopped while the agent is still connected: its VM goes first, so the browser closes and its
    // session is sealed before the browser VM stops.
    assert_eq!(keeper_ask(&socket, &format!("halti-keep/1 stop acme {name}\n")), "halti-keep/1 stopped\n");
    let mut said = String::new();
    session.read_line(&mut said).unwrap();
    assert_eq!(said, "halti-keep/1 stopped\n");
    agent.wait().unwrap();
    assert!(!engine::running(&vm) && !engine::running(&vm.replacen("halti-wsbox-", "halti-wsbrowser-", 1)) && !mounted(&name));
    home.close("acme");
    assert!(keeper.wait().unwrap().success());
    let listed = home.ws(ACME, "true", &["ws", "box", "ls", "acme"]);
    let listed = String::from_utf8_lossy(&listed.stdout);
    let row = listed.lines().find(|line| line.starts_with(&name)).unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(row.matches("github").count(), 2, "github is a site and a session: {row}");
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_closed_terminal_puts_every_box_away() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("keep-hup");
    let name = box_name("keep-hup");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    let (mut keeper, mut said) = home.open("acme", ACME);
    let (_, _session) = keeper_start(&home.keeper_socket("acme"), "acme", &name);
    let vm = until_running("halti-wsbox-", &name);
    // The terminal closes: SIGHUP to the job's whole group, which the open leads.
    unsafe { libc::kill(-(keeper.id() as i32), libc::SIGHUP) };
    assert!(keeper.wait().unwrap().success());
    let mut rest = String::new();
    said.read_to_string(&mut rest).unwrap();
    assert!(rest.ends_with(&format!("stopped box acme/{name}\nclosed acme\n")), "{rest}");
    assert!(!engine::running(&vm) && !engine::running(&vm.replacen("halti-wsbox-", "halti-wsbrowser-", 1)) && !mounted(&name));
    assert!(!home.keeper_socket("acme").exists());
}

/// Reads lines of `said` (an open workspace's stdout) until one is `line`, or it ends.
fn until_said(said: &mut BufReader<std::process::ChildStdout>, line: &str) {
    let mut read = String::new();
    while read != line {
        read.clear();
        assert!(said.read_line(&mut read).unwrap() > 0, "never said: {line}");
    }
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn ws_run_of_an_open_workspace_asks_nothing_and_its_box_stops_with_its_last_run() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("keep-run");
    let name = box_name("keep-run");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    let (mut keeper, mut said) = home.open("acme", ACME);
    let target = format!("acme/{name}");
    // Nothing answers a passphrase here: none is asked. The box starts for the first run, and the
    // second joins it.
    let first = home.halti().args(["ws", "run", &target, "--", "sleep", "120"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    until_said(&mut said, &format!("started box {target}\n"));
    let vm = until_running("halti-wsbox-", &name);
    let out = home.halti().args(["ws", "run", &target, "--", "sh", "-c", "exit 7"]).output().unwrap();
    assert!(out.status.code() == Some(7) && !String::from_utf8_lossy(&out.stderr).contains("[test] asked"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(engine::running(&vm), "the first run still holds it");
    // Stopped from a third terminal: its last run ends with it.
    let out = home.halti().args(["ws", "stop", &target]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("stopped box {target}\n"));
    until_said(&mut said, &format!("stopped box {target}\n"));
    let out = first.wait_with_output().unwrap();
    assert!(!String::from_utf8_lossy(&out.stderr).contains("no longer open"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!engine::running(&vm) && !mounted(&name));
    // Run again and left by itself: the box stops once that run ends.
    let out = home.halti().args(["ws", "run", &target, "--", "true"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    until_said(&mut said, &format!("stopped box {target}\n"));
    assert!(!engine::running(&vm) && !mounted(&name));
    assert_eq!(home.close("acme"), "closed acme\n");
    assert!(keeper.wait().unwrap().success());
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn two_boxes_of_one_workspace_run_side_by_side() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("keep-side");
    let (one, two) = (box_name("keep-side-one"), box_name("keep-side-two"));
    home.workspace_with_box("acme", ACME, &one, &basic("acme", "acme-token-0001"), &image);
    let text = format!("run = [\"claude\"]\nimage = \"{image}\"\nmodel = \"anthropic\"\nsites = [\"github\"]\nkeep = true\ncpus = 2\nmemory = \"2G\"\n");
    assert!(home.ws(ACME, &home.editor(&text), &["ws", "box", "new", &format!("acme/{two}")]).status.success());
    home.boxes.lock().unwrap().push(format!("acme/{two}"));
    let (mut keeper, _said) = home.open("acme", ACME);
    // Both reach github through their own door, in the one process that keeps acme open.
    let script = statuses_then_headers(&[("acme", "acme-token-0001")]);
    let mut runs: Vec<_> = [&one, &two]
        .into_iter()
        .map(|name| home.halti().args(["ws", "run", &format!("acme/{name}"), "--", "sh", "-c", &format!("{script}; sleep 120")]).stdout(Stdio::piped()).spawn().unwrap())
        .collect();
    let (vm_one, vm_two) = (until_running("halti-wsbox-", &one), until_running("halti-wsbox-", &two));
    // A run's first line comes only once the open workspace said its box started: then both count.
    // Their output stays open until they are killed, so neither ends on a closed pipe.
    let mut outs = Vec::new();
    for run in &mut runs {
        let mut out = BufReader::new(run.stdout.take().unwrap());
        let mut seen = String::new();
        out.read_line(&mut seen).unwrap();
        assert!(seen.starts_with("200 "), "{seen}");
        outs.push(out);
    }
    assert_eq!(keeper_ask(&home.keeper_socket("acme"), "halti-keep/1 ping acme\n"), "halti-keep/1 open 2\n");
    for mut run in runs {
        run.kill().unwrap();
        run.wait().unwrap();
    }
    drop(outs);
    // Each stops once its one run has gone.
    let deadline = Instant::now() + Duration::from_secs(120);
    while (engine::running(&vm_one) || engine::running(&vm_two)) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(500));
    }
    assert!(!engine::running(&vm_one) && !engine::running(&vm_two) && !mounted(&one) && !mounted(&two));
    assert_eq!(home.close("acme"), "closed acme\n");
    assert!(keeper.wait().unwrap().success());
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_killed_keeper_s_box_reaches_nothing_and_is_stopped_by_its_session() {
    let Some(image) = agent_image() else { return };
    let home = Home::new("keep-killed");
    let name = box_name("keep-killed");
    home.workspace_with_box("acme", ACME, &name, &basic("acme", "acme-token-0001"), &image);
    let (mut keeper, _said) = home.open("acme", ACME);
    let target = format!("acme/{name}");
    // The agent asks github every second, and says each status.
    let ask = "while true; do curl -sS -m 5 -o /dev/null -w '%{http_code}\\n' https://httpbin.org/basic-auth/acme/acme-token-0001; sleep 1; done";
    let mut run = home.halti().args(["ws", "run", &target, "--", "sh", "-c", ask]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let vm = until_running("halti-wsbox-", &name);
    let mut statuses = BufReader::new(run.stdout.take().unwrap());
    let mut status = String::new();
    statuses.read_line(&mut status).unwrap();
    assert_eq!(status, "200\n", "through the door while acme is open");
    // Killed, as by kill -9: its door goes with it, and the run puts the box away by itself.
    unsafe { libc::kill(keeper.id() as i32, libc::SIGKILL) };
    let _ = keeper.wait();
    let mut after = String::new();
    statuses.read_to_string(&mut after).unwrap();
    // One request may have been on its way as the door went.
    assert!(after.lines().skip(1).all(|status| status != "200"), "reached github with no door: {after}");
    let out = run.wait_with_output().unwrap();
    assert!(!out.status.success(), "the run fails");
    assert!(String::from_utf8_lossy(&out.stderr).ends_with(&format!("halti: acme is no longer open, so box {target} was stopped\n")), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!engine::running(&vm) && !engine::running(&vm.replacen("halti-wsbox-", "halti-wsbrowser-", 1)) && !mounted(&name));
    let listed = home.ws(ACME, "true", &["ws", "box", "ls", "acme"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains(" locked "), "no box lock of acme is held");
    // What the killed open left is its socket and lock file: the next open takes their place.
    let (mut keeper, _said) = home.open("acme", ACME);
    assert_eq!(home.close("acme"), "closed acme\n");
    assert!(keeper.wait().unwrap().success());
}
