//! The VM engine for a workspace's boxes on a Linux server: Cloud Hypervisor with KVM.
//!
//! Each box is one VM, whose VM program halti starts as its child, in a process group of its own,
//! from flags alone: the pinned box kernel, the box image read-only, the box's own disk, no network
//! device, one vsock device and a control socket. The image boots itself, with the shim as its
//! first process (`halti-shim boot`), which mounts the box's disk and serves the door and the exec
//! service on vsock ports (box/shim).
//!
//! The vsock device is a Unix socket the VM program holds. halti dials it and asks for a port in the
//! box with one line, `CONNECT <port>` (`door::connect_port`). A box that dials the server's port N
//! reaches whatever listens on that socket's name with `_N` added; halti makes no such file, and
//! each start removes every file in the VM's sockets folder, which holds that VM's sockets alone.
//! The VM program is confined to that folder, its kernel and its console by Landlock (its disks it
//! adds itself), with its seccomp filter on, as it is unless turned off.
//!
//! A VM program's own stops never reach the box: its power button is an input event nothing in the
//! box reads, and its shutdown does not ask the box. So a stop asks from inside: `kill -TERM 1` as
//! root through the exec service, after which the shim stops the box's processes, writes what is
//! cached to the disk and powers the VM off. Only a VM that is still there after that gets the VM
//! program's own stop, and then a kill.
//!
//! Nothing names this engine yet: it is reached by its tests only.
#![allow(dead_code)] // no setting or command picks this engine yet

pub mod exec;

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

use crate::boxes::store;
use crate::engine::{self, VmSpec, Vms};
use crate::{door, names};
use exec::{Input, Request, Sink};

/// The VM program and the box kernel, by the sha256 of each file: Cloud Hypervisor v54.1
/// (`cloud-hypervisor-static` of its release) and its reference kernel of ch-release-v7.2.8-20261009
/// (`bzImage-x86_64`). Pinned for x86-64, the servers boxes run on.
#[cfg(target_arch = "x86_64")]
const PINS: Option<Pins> =
    Some(Pins { program: "f9ffb9646783233d1f0fb09e77db1fca66499d1041e63bc011b90683c0d49933", kernel: "40f5ac32a703528a850dd2cedb3de5cb5bfc383c5abbff1424a135d7a85bec35" });
#[cfg(not(target_arch = "x86_64"))]
const PINS: Option<Pins> = None;

struct Pins {
    program: &'static str,
    kernel: &'static str,
}

/// The VM program and the kernel, in `names::LINUX_LIB`.
const PROGRAM: &str = "cloud-hypervisor";
const KERNEL: &str = "images/bzImage";
const IMAGES: &str = "images";
/// The VM's sockets in its folder: the vsock device, which the door and the exec client dial, and
/// the VM program's control socket.
const VSOCK: &str = "vsock.sock";
const API: &str = "api.sock";

/// How long a VM has to answer on the exec port once its VM program has started.
const START_LIMIT: Duration = Duration::from_secs(30);
/// How long a box has to power off once asked from inside: the shim gives its processes 5 s and
/// the killed ones 2 s more.
const STOP_WAIT: Duration = Duration::from_secs(15);
/// How long the VM program has to end after its own stop, and after a kill.
const HALT_WAIT: Duration = Duration::from_secs(5);
/// How long an answer on the vsock device or the control socket may take.
const ANSWER_WAIT: Duration = Duration::from_secs(5);
/// The most a command run through `pipe` may write, and the longest answer of the control socket.
const MOST_PIPED: usize = 64 << 20;
const MOST_ANSWER: usize = 64 << 10;
/// How often a starting or stopping VM is looked at.
const LOOK_EVERY: Duration = Duration::from_millis(100);

/// The VM programs this halti started, by VM name, so a stop can wait for its own child.
static CHILDREN: Mutex<BTreeMap<String, Child>> = Mutex::new(BTreeMap::new());

/// Cloud Hypervisor with KVM: where it finds what it runs.
pub struct CloudHypervisor {
    /// The VM program.
    pub program: PathBuf,
    /// The box kernel.
    pub kernel: PathBuf,
    /// The box images, `<image>/<64 hex>.img`.
    pub images: PathBuf,
    /// KVM's device.
    pub kvm: PathBuf,
    /// The folder of a workspace's boxes' sockets, where each VM's sockets folder is made.
    pub sockets: PathBuf,
}

impl CloudHypervisor {
    /// Where install-linux.sh is to put what it runs, for this user's workspaces.
    pub fn installed() -> Self {
        let lib = Path::new(names::LINUX_LIB);
        // SAFETY: getuid(2) can't fail.
        let uid = unsafe { libc::getuid() };
        Self { program: lib.join(PROGRAM), kernel: lib.join(KERNEL), images: lib.join(IMAGES), kvm: "/dev/kvm".into(), sockets: store::sockets(uid).join(names::WS_SOCKETS) }
    }
}

/// A VM's own files, from its name.
#[derive(Debug, PartialEq)]
struct Paths {
    /// Its sockets folder, which holds nothing else.
    dir: PathBuf,
    vsock: PathBuf,
    api: PathBuf,
}

impl CloudHypervisor {
    /// The sockets of the VM `halti-wsbox-TAG-BOX`: `TAG-BOX.vm/` in the workspaces' sockets
    /// folder, as `store::Layout::vm_sockets` has it. Any other name is refused: this engine runs
    /// a workspace's boxes only.
    fn paths(&self, name: &str) -> Result<Paths> {
        let named = name.strip_prefix(names::WS_BOX_VM_PREFIX).filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        let Some(named) = named else {
            bail!("{name}: this engine runs only a workspace's boxes");
        };
        let dir = self.sockets.join(format!("{named}{}", names::VM_SOCKETS));
        Ok(Paths { vsock: dir.join(VSOCK), api: dir.join(API), dir })
    }

    /// The image file a pinned reference names: `<image>/<64 hex>.img`, where the hex is the sha256
    /// the policy pins. It must be there and owned by root.
    fn image_file(&self, reference: &str) -> Result<PathBuf> {
        let parsed =
            reference.split_once("@sha256:").filter(|(name, hex)| plain_name(name) && hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        let Some((name, hex)) = parsed else {
            bail!("image {reference} isn't pinned as name@sha256:<64 hex>");
        };
        let file = self.images.join(name).join(format!("{hex}.img"));
        if !file.exists() {
            bail!("image {reference} isn't here, or was replaced: run install-linux.sh to build the agent image");
        }
        root_owned(&file)?;
        Ok(file)
    }

    /// Fails unless KVM can be used and the VM program and kernel are the pinned ones, owned by
    /// root.
    fn ready(&self) -> Result<()> {
        if let Err(e) = OpenOptions::new().read(true).write(true).open(&self.kvm) {
            match e.kind() {
                io::ErrorKind::NotFound => bail!("boxes can't run on this server: it has no {}", self.kvm.display()),
                io::ErrorKind::PermissionDenied => {
                    let user = crate::util::user_name().unwrap_or_else(|| "your user".into());
                    bail!("boxes can't run on this server: you may not use {} (sudo usermod -aG kvm {user}, then log in again)", self.kvm.display())
                }
                _ => bail!("boxes can't run on this server: opening {}: {e}", self.kvm.display()),
            }
        }
        let Some(pins) = PINS else {
            bail!("boxes can't run on this server: halti pins a VM program for x86-64 servers only");
        };
        pinned("the VM program", &self.program, pins.program)?;
        pinned("the box kernel", &self.kernel, pins.kernel)
    }

    /// The VM program's arguments: no `--net`, so no network device; the image read-only and the
    /// box's disk, each a raw image; one vsock device with the guest id every box has; the control
    /// socket; the console to a file; and Landlock, with a rule for the kernel, the console and the
    /// VM's sockets folder (it adds its disks itself). Never `--seccomp false`.
    fn args(&self, spec: &VmSpec, image: &Path, disk: &Path, console: &Path, paths: &Paths) -> Result<Vec<String>> {
        for path in [&self.kernel, image, disk, console, &paths.dir] {
            if path.to_string_lossy().contains([',', '=']) {
                bail!("{}: a path with a comma or an equals sign can't be given to the VM program", path.display());
            }
        }
        let digits = spec.memory.strip_suffix(['M', 'G']).unwrap_or("");
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            bail!("memory must be like 8G or 512M, not {}", spec.memory);
        }
        let path = |p: &Path| p.display().to_string();
        let cmdline = format!("console=ttyS0 root=/dev/vda ro init={} -- {}", names::SHIM_PATH, names::SHIM_BOOT);
        Ok(vec![
            "--kernel".into(),
            path(&self.kernel),
            "--cmdline".into(),
            cmdline,
            "--disk".into(),
            format!("path={},readonly=on,image_type=raw", path(image)),
            format!("path={},image_type=raw", path(disk)),
            "--cpus".into(),
            format!("boot={}", spec.cpus),
            "--memory".into(),
            format!("size={}", spec.memory),
            "--vsock".into(),
            format!("cid={},socket={}", names::GUEST_CID, path(&paths.vsock)),
            "--api-socket".into(),
            format!("path={}", path(&paths.api)),
            "--serial".into(),
            format!("file={}", path(console)),
            "--console".into(),
            "off".into(),
            "--landlock".into(),
            "--landlock-rules".into(),
            format!("path={},access=r", path(&self.kernel)),
            format!("path={},access=rw", path(console)),
            format!("path={},access=rw", path(&paths.dir)),
        ])
    }

    /// Run `cmd` in the VM, as the agent or as root, with `input`, and return its output; a command
    /// that fails is an error, with what it wrote to its standard error.
    pub fn run_in(&self, name: &str, root: bool, cmd: &[String], env: &[(String, String)], input: &[u8]) -> Result<Vec<u8>> {
        let paths = self.paths(name)?;
        let stream = dial(&paths.vsock, names::EXEC_PORT)?;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let request = Request { root, tty: None, argv: cmd, env };
        let status = exec::run(stream, &request, Input::Bytes(input), Sink { out: &mut out, err: &mut err, most: Some(MOST_PIPED) })?;
        if !status.success() {
            let program = cmd.first().map_or("", String::as_str);
            bail!("running {program} in {name} ({status}): {}", exec::shown(String::from_utf8_lossy(&err).trim().as_bytes()));
        }
        Ok(out)
    }

    /// Whether the VM program still runs: its child here has not ended, or, for one another halti
    /// started, its control socket answers.
    fn alive(&self, name: &str, paths: &Paths) -> bool {
        let mut children = CHILDREN.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(child) = children.get_mut(name) {
            if matches!(child.try_wait(), Ok(None)) {
                return true;
            }
            children.remove(name);
            return false;
        }
        drop(children);
        ask(&paths.api, "GET", "/api/v1/vmm.ping").is_ok_and(|(status, _)| status == 200)
    }

    /// Wait up to `limit` for the VM program to end.
    fn ended(&self, name: &str, paths: &Paths, limit: Duration) -> bool {
        let end = Instant::now() + limit;
        loop {
            if !self.alive(name, paths) {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            thread::sleep(LOOK_EVERY);
        }
    }

    /// The VM program's process id, for the last resort of a kill: its child here, or the id its
    /// control socket gives, when that process is the VM program of these sockets.
    fn pid(&self, name: &str, paths: &Paths) -> Option<i32> {
        if let Some(child) = CHILDREN.lock().unwrap_or_else(|e| e.into_inner()).get(name) {
            return Some(child.id() as i32);
        }
        let (_, body) = ask(&paths.api, "GET", "/api/v1/vmm.ping").ok()?;
        let pid = serde_json::from_slice::<serde_json::Value>(&body).ok()?["pid"].as_i64().and_then(|p| i32::try_from(p).ok()).filter(|p| *p > 1)?;
        let cmdline = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let api = format!("path={}", paths.api.display());
        cmdline.split(|b| *b == 0).any(|arg| arg == api.as_bytes()).then_some(pid)
    }

    /// The VM program ended: reap it, and empty its sockets folder.
    fn put_away(&self, name: &str, paths: &Paths) {
        if let Some(mut child) = CHILDREN.lock().unwrap_or_else(|e| e.into_inner()).remove(name) {
            let _ = child.wait();
        }
        let _ = clear_sockets(&paths.dir);
    }
}

/// A name of an image: lower-case letters, digits and dashes.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Fails unless `file` is a file owned by root that nobody else may write.
fn root_owned(file: &Path) -> Result<()> {
    let meta = fs::metadata(file).with_context(|| format!("reading {}", file.display()))?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        bail!("{} isn't a file owned by root that only root may change: run install-linux.sh", file.display());
    }
    Ok(())
}

/// Fails unless `file` is there, root's, and has the sha256 `pin`.
fn pinned(what: &str, file: &Path, pin: &str) -> Result<()> {
    if !file.exists() {
        bail!("{what} isn't installed at {}: run install-linux.sh", file.display());
    }
    root_owned(file)?;
    if sha256_hex(file)? != pin {
        bail!("{what} at {} isn't the one halti pins: run install-linux.sh", file.display());
    }
    Ok(())
}

fn sha256_hex(file: &Path) -> Result<String> {
    let mut f = File::open(file).with_context(|| format!("reading {}", file.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).with_context(|| format!("reading {}", file.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Make a VM's sockets folder private to this user and empty it: a socket left by an earlier run,
/// and any listener file a program put there for the box to dial (`vsock.sock_<port>`), go.
fn clear_sockets(dir: &Path) -> Result<()> {
    // SAFETY: getuid(2) can't fail.
    store::private_dir(dir, unsafe { libc::getuid() })?;
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(())
}

/// A connection to `port` in the box, through its vsock device.
fn dial(vsock: &Path, port: u32) -> Result<UnixStream> {
    let mut stream = UnixStream::connect(vsock).with_context(|| format!("dialing {}", vsock.display()))?;
    door::connect_port(&mut stream, port, ANSWER_WAIT)?;
    Ok(stream)
}

/// One request to the VM program's control socket, and its status and body. The answer is read
/// with a cap and a time limit.
fn ask(api: &Path, method: &str, path: &str) -> Result<(u16, Vec<u8>)> {
    let mut stream = UnixStream::connect(api)?;
    stream.set_read_timeout(Some(ANSWER_WAIT))?;
    stream.set_write_timeout(Some(ANSWER_WAIT))?;
    stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Length: 0\r\n\r\n").as_bytes())?;
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        if got.len() > MOST_ANSWER {
            bail!("the VM program's answer is too long");
        }
        if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut buf)? {
            0 => bail!("the VM program closed the connection with no answer"),
            n => got.extend_from_slice(&buf[..n]),
        }
    };
    let head = String::from_utf8_lossy(&got[..head_end]).to_string();
    let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("the VM program's answer has no status"))?;
    let length = head
        .lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("content-length")).map(|(_, v)| v.trim().parse::<usize>()))
        .transpose()
        .map_err(|_| anyhow!("the VM program's answer has a bad length"))?
        .unwrap_or(0);
    if length > MOST_ANSWER {
        bail!("the VM program's answer is too long");
    }
    let mut body = got[head_end..].to_vec();
    while body.len() < length {
        match stream.read(&mut buf)? {
            0 => break,
            n => body.extend_from_slice(&buf[..n]),
        }
    }
    body.truncate(length);
    Ok((status, body))
}

/// Where what the VM program writes goes: beside the VM's console, as `<console>.log`.
fn program_log(console: &Path) -> PathBuf {
    let mut log = console.as_os_str().to_owned();
    log.push(".log");
    PathBuf::from(log)
}

/// The last lines of a console file, safe to print.
fn console_tail(console: &Path) -> String {
    let text = fs::read(console).unwrap_or_default();
    let text = String::from_utf8_lossy(&text[text.len().saturating_sub(4096)..]).to_string();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(5)..].iter().map(|l| exec::shown(l.trim().as_bytes())).collect::<Vec<_>>().join(" / ")
}

impl Vms for CloudHypervisor {
    fn available(&self) -> Result<()> {
        self.ready()
    }

    fn running(&self, name: &str) -> bool {
        self.paths(name).is_ok_and(|paths| self.alive(name, &paths))
    }

    /// Start the VM and wait until the shim answers on the exec port. The VM program is this
    /// process's child, in a process group of its own, so Ctrl-C reaches halti alone; if halti
    /// ends without stopping it, the next start finds it by its control socket.
    fn run(&self, spec: &VmSpec) -> Result<()> {
        let paths = self.paths(&spec.name)?;
        if spec.docker {
            bail!("Docker in a box doesn't run on a Linux server yet: set docker = false in the box policy");
        }
        if spec.rosetta {
            bail!("rosetta is only on a mac");
        }
        if !spec.mounts.is_empty() {
            bail!("a box here is given its disk, not folders of this server");
        }
        if spec.socket != paths.vsock {
            bail!("the door's socket of {} is {}, not {}", spec.name, paths.vsock.display(), spec.socket.display());
        }
        let (Some(disk), Some(console)) = (&spec.disk, &spec.console) else {
            bail!("{}: this engine needs the box's disk and a console file", spec.name);
        };
        if !disk.is_file() {
            bail!("the box's disk {} isn't there", disk.display());
        }
        self.ready()?;
        let image = self.image_file(&spec.image)?;
        if self.alive(&spec.name, &paths) {
            bail!("{} is running already", spec.name);
        }
        clear_sockets(&paths.dir)?;
        // Landlock's rule names the console, so it must be there before the start. What the VM
        // program itself says goes in a file beside it, which it never opens.
        let fresh = |path: &Path| OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(path).with_context(|| format!("making {}", path.display()));
        fresh(console)?;
        let log = fresh(&program_log(console))?;
        let args = self.args(spec, &image, disk, console, &paths)?;
        let mut command = Command::new(&self.program);
        command.process_group(0).args(&args).stdin(Stdio::null()).stdout(log.try_clone()?).stderr(log);
        let child = command.spawn().with_context(|| format!("starting {}", self.program.display()))?;
        CHILDREN.lock().unwrap_or_else(|e| e.into_inner()).insert(spec.name.clone(), child);

        let started = Instant::now();
        loop {
            if !self.alive(&spec.name, &paths) {
                self.put_away(&spec.name, &paths);
                bail!("{} did not start. the VM program said: {}. its console: {}", spec.name, console_tail(&program_log(console)), console_tail(console));
            }
            if dial(&paths.vsock, names::EXEC_PORT).is_ok() {
                return Ok(());
            }
            if started.elapsed() >= START_LIMIT {
                let _ = self.stop(&spec.name);
                bail!("{} did not start in {} seconds. its console is in {}", spec.name, START_LIMIT.as_secs(), console.display());
            }
            thread::sleep(LOOK_EVERY);
        }
    }

    /// Ask the box to stop from inside and wait for it to power off; only then the VM program's
    /// own stop, and last a kill. Fine if it is gone already.
    fn stop(&self, name: &str) -> Result<()> {
        let paths = self.paths(name)?;
        if !self.alive(name, &paths) {
            self.put_away(name, &paths);
            return Ok(());
        }
        let pid = self.pid(name, &paths);
        // The command is stopped with the box, so its connection may end with no last frame.
        let _ = self.run_in(name, true, &["sh".into(), "-c".into(), "kill -TERM 1".into()], &[], b"");
        if !self.ended(name, &paths, STOP_WAIT) {
            let _ = ask(&paths.api, "PUT", "/api/v1/vmm.shutdown");
            if !self.ended(name, &paths, HALT_WAIT) {
                if let Some(pid) = pid {
                    // SAFETY: kill(2) of the VM program found above.
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
                if !self.ended(name, &paths, HALT_WAIT) {
                    bail!("{name} is still running after it was killed");
                }
            }
        }
        self.put_away(name, &paths);
        Ok(())
    }

    /// Run a command as the agent, with the terminal if there is one. Its environment travels in
    /// the request, not on a command line.
    fn exec(&self, name: &str, env: &[(String, String)], cmd: &[String], tty: bool) -> Result<ExitStatus> {
        let paths = self.paths(name)?;
        let stream = dial(&paths.vsock, names::EXEC_PORT)?;
        let size = tty.then(|| exec::terminal_size(0).unwrap_or(exec::Size { rows: 24, cols: 80 }));
        let request = Request { root: false, tty: size, argv: cmd, env };
        let (mut out, mut err) = (io::stdout(), io::stderr());
        exec::run(stream, &request, Input::Stdin, Sink { out: &mut out, err: &mut err, most: None })
    }

    fn install_ca(&self, name: &str, pem: &str) -> Result<()> {
        let script = format!("cat > {} && update-ca-certificates", engine::CA_CERT);
        self.run_in(name, true, &["sh".into(), "-c".into(), script], &[], pem.as_bytes()).map(drop).with_context(|| format!("installing the box CA in {name}"))
    }

    fn start_docker(&self, name: &str) -> Result<()> {
        let env: Vec<(String, String)> = engine::docker_env().iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        self.run_in(name, true, &["sh".into(), "-c".into(), engine::docker_script()], &env, b"").map(drop).with_context(|| format!("starting Docker in {name}"))
    }

    /// The pinned reference of an installed image: the image named, as `name@sha256:<hex>` of its
    /// file; of several, the newest.
    fn image_digest(&self, reference: &str) -> Result<String> {
        if reference.contains('@') {
            self.image_file(reference)?;
            return Ok(reference.to_string());
        }
        let name = reference.strip_suffix(":latest").unwrap_or(reference);
        if !plain_name(name) {
            bail!("{reference} isn't the name of an image");
        }
        let mut newest: Option<(std::time::SystemTime, String)> = None;
        for entry in fs::read_dir(self.images.join(name)).into_iter().flatten().flatten() {
            let file = entry.file_name().to_string_lossy().to_string();
            let Some(hex) = file.strip_suffix(".img").filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) else { continue };
            let modified = entry.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
            if newest.as_ref().is_none_or(|(at, _)| modified > *at) {
                newest = Some((modified, hex.to_string()));
            }
        }
        let Some((_, hex)) = newest else {
            bail!("image {name} isn't here: run install-linux.sh to build the agent image");
        };
        let pinned = format!("{name}@sha256:{hex}");
        self.image_file(&pinned)?;
        Ok(pinned)
    }

    fn takes_disk(&self) -> bool {
        true
    }

    fn pipe(&self, name: &str, cmd: &[String], input: &[u8]) -> Result<Vec<u8>> {
        self.run_in(name, false, cmd, &[], input)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod kvm_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boxes::store::Layout;
    use crate::util::TempDir;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn engine(dir: &Path) -> CloudHypervisor {
        CloudHypervisor {
            program: "/lib/halti/cloud-hypervisor".into(),
            kernel: "/lib/halti/images/bzImage".into(),
            images: dir.join("images"),
            kvm: dir.join("kvm"),
            sockets: dir.join("ws"),
        }
    }

    fn spec(engine: &CloudHypervisor, dir: &Path) -> VmSpec {
        let name = format!("{}0123456789ab-dev", names::WS_BOX_VM_PREFIX);
        VmSpec {
            socket: engine.paths(&name).unwrap().vsock,
            name,
            image: format!("halti-agent@sha256:{HEX}"),
            cpus: 2,
            memory: "8G".into(),
            mounts: vec![],
            docker: false,
            rosetta: false,
            disk: Some(dir.join("boxes/dev.img")),
            console: Some(dir.join("boxes/open/dev.console")),
        }
    }

    fn args(dir: &Path) -> Vec<String> {
        let e = engine(dir);
        let s = spec(&e, dir);
        let paths = e.paths(&s.name).unwrap();
        e.args(&s, &dir.join("images/halti-agent/x.img"), s.disk.as_ref().unwrap(), s.console.as_ref().unwrap(), &paths).unwrap()
    }

    #[test]
    fn the_vm_has_no_network_and_one_socket() {
        let dir = TempDir::new("halti-vmm-args").unwrap();
        let d = dir.0.display();
        assert_eq!(
            args(&dir.0).join(" "),
            format!(
                "--kernel /lib/halti/images/bzImage --cmdline console=ttyS0 root=/dev/vda ro init=/usr/local/bin/halti-shim -- boot \
                 --disk path={d}/images/halti-agent/x.img,readonly=on,image_type=raw path={d}/boxes/dev.img,image_type=raw \
                 --cpus boot=2 --memory size=8G \
                 --vsock cid=3,socket={d}/ws/0123456789ab-dev.vm/vsock.sock \
                 --api-socket path={d}/ws/0123456789ab-dev.vm/api.sock \
                 --serial file={d}/boxes/open/dev.console --console off \
                 --landlock --landlock-rules path=/lib/halti/images/bzImage,access=r path={d}/boxes/open/dev.console,access=rw path={d}/ws/0123456789ab-dev.vm,access=rw"
            )
        );
        let args = args(&dir.0);
        assert!(!args.iter().any(|a| a.starts_with("--net") || a.contains("tap") || a.contains("vhost")), "no network device");
        assert_eq!(args.iter().filter(|a| *a == "--vsock").count(), 1);
        // every box has the same guest id: each VM's device is its own
        assert!(args.iter().any(|a| a.starts_with("cid=3,")));
        // a memory that isn't 8G or 512M, and a path the VM program would split, are refused
        let e = engine(&dir.0);
        let mut s = spec(&e, &dir.0);
        let paths = e.paths(&s.name).unwrap();
        s.memory = "8g,size=1T".into();
        assert!(e.args(&s, Path::new("/i.img"), Path::new("/d.img"), Path::new("/c"), &paths).is_err());
        s.memory = "8G".into();
        assert!(e.args(&s, Path::new("/i,x.img"), Path::new("/d.img"), Path::new("/c"), &paths).is_err());
    }

    #[test]
    fn the_vm_program_is_confined_and_seccomp_is_never_turned_off() {
        let dir = TempDir::new("halti-vmm-confined").unwrap();
        let args = args(&dir.0);
        assert!(!args.iter().any(|a| a.contains("seccomp")), "{args:?}");
        let rules = args.iter().position(|a| a == "--landlock-rules").unwrap();
        assert_eq!(args[rules - 1], "--landlock");
        // the kernel read-only, the console, and the VM's own sockets folder: nothing else
        let paths: Vec<&str> = args[rules + 1..].iter().map(|r| r.split(',').next().unwrap()).collect();
        let d = dir.0.display().to_string();
        assert_eq!(paths, ["path=/lib/halti/images/bzImage".to_string(), format!("path={d}/boxes/open/dev.console"), format!("path={d}/ws/0123456789ab-dev.vm")]);
        assert!(args[rules + 1].ends_with(",access=r"));
    }

    #[test]
    fn a_name_gives_the_socket_the_layout_gives() {
        let dir = TempDir::new("halti-vmm-names").unwrap();
        let ws = halti_core::ids::WsId::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 0, 0, 0, 0, 0, 0, 0]);
        let layout = Layout::under_workspace(&dir.0, ws).unwrap();
        let e = CloudHypervisor { sockets: layout.sockets.clone(), ..engine(&dir.0) };
        let paths = e.paths(&layout.vm("dev")).unwrap();
        assert_eq!(paths.dir, layout.vm_sockets("dev"));
        assert_eq!(paths.dir.parent(), layout.socket("dev").parent(), "beside the agent's socket on a Mac");
        assert_eq!((paths.vsock.file_name().unwrap(), paths.api.file_name().unwrap()), ("vsock.sock".as_ref(), "api.sock".as_ref()));
        // the folder of one box is no other box's, and holds no keeper's socket
        assert_ne!(e.paths(&layout.vm("de")).unwrap().dir, paths.dir);
        assert!(!layout.keeper_socket().unwrap().starts_with(&paths.dir));
        // a sockets folder's path stays well within Linux's limit of 108 bytes
        let real = CloudHypervisor::installed().paths(&format!("{}0123456789ab-{}", names::WS_BOX_VM_PREFIX, "b".repeat(32))).unwrap();
        assert!(real.vsock.as_os_str().len() + "_4294967295".len() < 108, "{}", real.vsock.display());
        // this engine runs a workspace's boxes, and no other VM
        let old = format!("{}x", crate::legacy::BOX_VM_PREFIX);
        for other in ["halti-box-dev", "halti-wsbrowser-0123456789ab-dev", &old, "halti-wsbox-", "halti-wsbox-../x", "halti-wsbox-a/b"] {
            assert!(e.paths(other).is_err(), "{other}");
        }
    }

    #[test]
    fn a_listener_file_beside_the_socket_is_removed_before_the_start() {
        // short, for the socket in it
        let dir = TempDir(PathBuf::from(format!("/tmp/hv-{}", std::process::id())));
        let _ = fs::remove_dir_all(&dir.0);
        fs::create_dir(&dir.0).unwrap();
        let e = engine(&dir.0);
        let paths = e.paths(&format!("{}0123456789ab-dev", names::WS_BOX_VM_PREFIX)).unwrap();
        fs::create_dir_all(&paths.dir).unwrap();
        fs::set_permissions(&paths.dir, fs::Permissions::from_mode(0o755)).unwrap();
        // a program's listener for the box's dial to the server's port 9, and old sockets
        let _listener = UnixListener::bind(paths.dir.join("vsock.sock_9")).unwrap();
        fs::write(&paths.vsock, "").unwrap();
        fs::write(&paths.api, "").unwrap();
        clear_sockets(&paths.dir).unwrap();
        assert_eq!(fs::read_dir(&paths.dir).unwrap().count(), 0);
        assert_eq!(fs::metadata(&paths.dir).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn a_missing_kvm_says_so() {
        let dir = TempDir::new("halti-vmm-kvm").unwrap();
        let e = engine(&dir.0);
        assert_eq!(e.ready().unwrap_err().to_string(), format!("boxes can't run on this server: it has no {}", e.kvm.display()));
        fs::write(&e.kvm, "").unwrap();
        fs::set_permissions(&e.kvm, fs::Permissions::from_mode(0o400)).unwrap();
        // SAFETY: geteuid(2) can't fail.
        if unsafe { libc::geteuid() } != 0 {
            let err = e.ready().unwrap_err().to_string();
            assert!(err.starts_with(&format!("boxes can't run on this server: you may not use {} (sudo usermod -aG kvm ", e.kvm.display())), "{err}");
        }
        // with KVM, the VM program must be there, root's, and the pinned one
        fs::set_permissions(&e.kvm, fs::Permissions::from_mode(0o600)).unwrap();
        let err = e.ready().unwrap_err().to_string();
        match PINS {
            Some(_) => assert_eq!(err, "the VM program isn't installed at /lib/halti/cloud-hypervisor: run install-linux.sh"),
            None => assert_eq!(err, "boxes can't run on this server: halti pins a VM program for x86-64 servers only"),
        }
    }

    #[test]
    fn only_the_pinned_vm_program_and_kernel_run() {
        let dir = TempDir::new("halti-vmm-pins").unwrap();
        let mine = dir.0.join("cloud-hypervisor");
        fs::write(&mine, "not it").unwrap();
        let pin = sha256_hex(&mine).unwrap();
        assert_eq!(pin, Sha256::digest(b"not it").iter().map(|b| format!("{b:02x}")).collect::<String>());
        let err = pinned("the VM program", &mine, &pin).unwrap_err().to_string();
        assert!(err.contains("isn't a file owned by root"), "a file this user could replace: {err}");
        // a file of root's that isn't the pinned one
        let err = pinned("the box kernel", Path::new("/bin/sh"), &pin).unwrap_err().to_string();
        assert_eq!(err, "the box kernel at /bin/sh isn't the one halti pins: run install-linux.sh");
        pinned("the box kernel", Path::new("/bin/sh"), &sha256_hex(Path::new("/bin/sh")).unwrap()).unwrap();
        assert!(pinned("the box kernel", &dir.0.join("none"), &pin).unwrap_err().to_string().contains("isn't installed at"));
        if let Some(pins) = PINS {
            for pin in [pins.program, pins.kernel] {
                assert!(pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{pin}");
            }
        }
    }

    #[test]
    fn an_image_is_run_only_by_its_pinned_name() {
        let dir = TempDir::new("halti-vmm-image").unwrap();
        let e = engine(&dir.0);
        let pinned = format!("halti-agent@sha256:{HEX}");
        assert_eq!(e.image_file(&pinned).unwrap_err().to_string(), format!("image {pinned} isn't here, or was replaced: run install-linux.sh to build the agent image"));
        fs::create_dir_all(dir.0.join("images/halti-agent")).unwrap();
        fs::write(dir.0.join(format!("images/halti-agent/{HEX}.img")), "").unwrap();
        // there, but a file this user could replace
        assert!(e.image_file(&pinned).unwrap_err().to_string().contains("isn't a file owned by root"));
        let short = &HEX[..63];
        let upper = HEX.to_uppercase();
        for bad in [
            "halti-agent",
            "halti-agent:latest",
            &format!("halti-agent@sha256:{short}"),
            &format!("halti-agent@sha256:{upper}"),
            &format!("../x@sha256:{HEX}"),
            &format!("a/b@sha256:{HEX}"),
            &format!("halti-agent@sha512:{HEX}"),
        ] {
            assert!(e.image_file(bad).unwrap_err().to_string().contains("isn't pinned as name@sha256:<64 hex>"), "{bad}");
        }
        // the pinned reference of an image is its file's name
        let err = e.image_digest("halti-agent").unwrap_err().to_string();
        assert!(err.contains("isn't a file owned by root"), "{err}");
        assert!(e.image_digest("halti-browser").unwrap_err().to_string().contains("isn't here"));
        assert!(e.image_digest("../etc").is_err());
    }

    #[test]
    fn only_a_workspace_box_without_docker_or_mounts_is_started() {
        let dir = TempDir::new("halti-vmm-run").unwrap();
        let e = engine(&dir.0);
        let good = spec(&e, &dir.0);
        let refused = |change: &dyn Fn(&mut VmSpec)| {
            let mut s = spec(&e, &dir.0);
            change(&mut s);
            e.run(&s).unwrap_err().to_string()
        };
        assert!(refused(&|s| s.name = "halti-box-dev".into()).contains("only a workspace's boxes"));
        assert!(refused(&|s| s.docker = true).starts_with("Docker in a box doesn't run on a Linux server yet"));
        assert_eq!(refused(&|s| s.rosetta = true), "rosetta is only on a mac");
        assert!(refused(&|s| s.mounts = vec![engine::Mount { host: "/src".into(), guest: "/work/src".into(), readonly: true }]).contains("not folders"));
        assert!(refused(&|s| s.socket = dir.0.join("other.sock")).contains("the door's socket of"));
        assert!(refused(&|s| s.disk = None).contains("needs the box's disk"));
        assert!(refused(&|_| {}).contains("isn't there"), "no disk yet");
        // nothing was made for a refused start
        assert!(!e.paths(&good.name).unwrap().dir.exists());
        assert!(!good.console.as_ref().unwrap().exists());
        assert!(e.takes_disk());
    }

    /// The control socket's answers are read with a cap, and a process id it gives is used only
    /// for the VM program of those sockets.
    #[test]
    fn the_control_socket_is_asked_with_a_cap() {
        const PING: &str = "{\"version\":\"54.1\",\"pid\":1}";
        let dir = TempDir(PathBuf::from(format!("/tmp/hva-{}", std::process::id())));
        let _ = fs::remove_dir_all(&dir.0);
        fs::create_dir(&dir.0).unwrap();
        let api = dir.0.join("api.sock");
        let listener = UnixListener::bind(&api).unwrap();
        let answers = [
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{PING}", PING.len()),
            "HTTP/1.1 204 No Content\r\n\r\n".to_string(),
            format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(MOST_ANSWER + 10)),
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", MOST_ANSWER + 1),
        ];
        let server = thread::spawn(move || {
            for answer in answers {
                let (mut s, _) = listener.accept().unwrap();
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(answer.as_bytes());
            }
        });
        let (status, body) = ask(&api, "GET", "/api/v1/vmm.ping").unwrap();
        assert_eq!((status, body.as_slice()), (200, PING.as_bytes()));
        assert_eq!(ask(&api, "PUT", "/api/v1/vmm.shutdown").unwrap().0, 204);
        assert!(ask(&api, "GET", "/x").unwrap_err().to_string().contains("too long"));
        assert!(ask(&api, "GET", "/x").unwrap_err().to_string().contains("too long"));
        server.join().unwrap();
    }
}
