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

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
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

/// A home for the debug binary, removed when dropped, after its boxes are stopped.
struct Home {
    dir: PathBuf,
    /// Workspace boxes to stop when the test ends, however it ends: `acme/NAME`.
    boxes: Mutex<Vec<String>>,
}

impl Home {
    fn new() -> Home {
        let dir = env::temp_dir().join(format!("halti-e2e-wsbox-{}", process::id()));
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

    /// Workspace `ws` with a model and github, its token `token`, and a box `name` that may use github.
    fn workspace_with_box(&self, ws: &str, passphrase: &str, name: &str, token: &str, image: &str) {
        assert!(self.ws(passphrase, "true", &["ws", "new", ws]).status.success());
        self.set(ws, passphrase, "anthropic", "token", "model-token-not-used");
        self.policy(ws, passphrase, "anthropic", "[fetch]\nhosts = [\"https://api.anthropic.com\"]\nauth = \"Bearer {token}\"\n");
        self.set(ws, passphrase, "github", "token", token);
        self.policy(ws, passphrase, "github", "[fetch]\nhosts = [\"https://httpbin.org\"]\nauth = \"Bearer {token}\"\n");
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

/// A box name of this test run alone.
fn box_name(what: &str) -> String {
    format!("e2e-{what}-{}", process::id())
}

/// Waits until `vm` runs, or a minute passes.
fn until_running(vm_prefix: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        let listed = Command::new("container").args(["ls"]).output().unwrap();
        if let Some(name) = String::from_utf8_lossy(&listed.stdout).split_whitespace().find(|word| word.starts_with(vm_prefix)) {
            return name.to_string();
        }
        thread::sleep(Duration::from_millis(500));
    }
    panic!("no VM {vm_prefix}… runs");
}

/// What the agent of the box gets back from httpbin's echo of its request: the Authorization the
/// door put on it, masked with the values of the box's workspace.
fn headers_seen(home: &Home, passphrase: &str, target: &str) -> String {
    let out = home.ws(passphrase, "true", &["ws", "run", target, "--", "curl", "-sS", "-m", "20", "https://httpbin.org/headers"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_workspace_box_reaches_only_its_sites() {
    let Some(image) = agent_image() else { return };
    let home = Home::new();
    let name = box_name("sites");
    // The Keychain's github, approved, and globex's: a box of acme's must reach neither.
    fs::write(home.dir.join("keychain/github.token"), "keychain-token-0001").unwrap();
    fs::write(home.dir.join("index.json"), "{\"github\":{\"fields\":{\"token\":{}}}}").unwrap();
    fs::write(home.dir.join("policy/github.toml"), "[fetch]\nhosts = [\"https://httpbin.org\"]\nauth = \"Bearer {token}\"\n").unwrap();
    assert!(home.halti().args(["policy", "approve", "github"]).output().unwrap().status.success());
    home.workspace_with_box("globex", GLOBEX, &name, "globex-token-0001", &image);
    home.workspace_with_box("acme", ACME, &name, "acme-token-0001", &image);
    let seen = headers_seen(&home, ACME, &format!("acme/{name}"));
    assert!(seen.contains("Bearer ********"), "acme's token, masked: {seen}");
    assert!(!seen.contains("globex-token") && !seen.contains("keychain-token") && !seen.contains("acme-token"), "{seen}");
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_token_set_while_running_is_used_at_once() {
    let Some(image) = agent_image() else { return };
    let home = Home::new();
    let name = box_name("rotate");
    home.workspace_with_box("acme", ACME, &name, "acme-token-0001", &image);
    let target = format!("acme/{name}");
    let mut opener = home.start(ACME, &target, &["sleep", "120"]);
    until_running("halti-wsbox-");
    home.set("acme", ACME, "github", "token", "acme-token-0002");
    // A second terminal, in the same VM through the opener's door, which reads acme again.
    let out = home.halti().args(["ws", "run", &target, "--", "curl", "-sS", "-m", "20", "https://httpbin.org/headers"]).output().unwrap();
    let seen = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && seen.contains("Bearer ********") && !seen.contains("acme-token-0001"), "{seen}");
    assert!(home.halti().args(["ws", "stop", &target]).output().unwrap().status.success());
    opener.wait().unwrap();
}

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_second_terminal_joins_without_a_question() {
    let Some(image) = agent_image() else { return };
    let home = Home::new();
    let name = box_name("join");
    home.workspace_with_box("acme", ACME, &name, "acme-token-0001", &image);
    let target = format!("acme/{name}");
    let mut opener = home.start(ACME, &target, &["sleep", "120"]);
    let vm = until_running("halti-wsbox-");
    assert!(vm.ends_with(&format!("-{name}")), "{vm}");
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
    let home = Home::new();
    let name = box_name("stop");
    home.workspace_with_box("acme", ACME, &name, "acme-token-0001", &image);
    let target = format!("acme/{name}");
    let mut opener = home.start(ACME, &target, &["sleep", "120"]);
    let vm = until_running("halti-wsbox-");
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

#[test]
#[ignore = "needs Apple's `container`; run with `mise run e2e-box`"]
fn a_keychain_box_of_the_same_name_keeps_running() {
    let Some(image) = agent_image() else { return };
    let home = Home::new();
    let name = box_name("apart");
    // A Keychain box of this name, running.
    let text = format!("run = [\"claude\"]\nimage = \"{image}\"\nkeep = false\ncpus = 2\nmemory = \"2G\"\n");
    assert!(home.halti().env("EDITOR", home.editor(&text)).args(["box", "new", &name]).output().unwrap().status.success());
    assert!(home.halti().args(["box", "approve", &name]).output().unwrap().status.success());
    let mut keychain_box = home.halti().args(["box", "run", &name, "--", "sleep", "120"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let keychain_vm = format!("{}{name}", names::BOX_VM_PREFIX);
    until_running(&keychain_vm);
    // acme's box of the same name starts, ends and is stopped beside it.
    home.workspace_with_box("acme", ACME, &name, "acme-token-0001", &image);
    let target = format!("acme/{name}");
    assert!(home.ws(ACME, "true", &["ws", "run", &target, "--", "true"]).status.success());
    let out = home.halti().args(["ws", "stop", &target]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).ends_with(&format!("halti: box {target} isn't running\n")));
    assert!(engine::running(&keychain_vm), "the Keychain box runs on");
    assert!(home.halti().args(["box", "stop", &name]).output().unwrap().status.success());
    keychain_box.wait().unwrap();
}
