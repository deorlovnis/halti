//! The sandbox engine's first light: `halti box sh --engine sandbox` runs a command in a rootless
//! kernel sandbox, on its own, with no store, door or policy. Debug builds on Linux only, until
//! the engine joins the box commands.
//!
//! `box sh` starts halti again as `__sandbox-init`, which makes new user, mount, network, PID,
//! IPC and UTS namespaces (your uid is root in them) and forks the PID namespace's init. That
//! brings up `lo`, the only network device, and builds a root on a tmpfs: the host's `/usr` and
//! the system folders beside it, a few named files of `/etc`, and the tools, all read-only;
//! generated `passwd`, `group` and `hosts`; sized tmpfs folders for `/tmp`, `/home/agent` and
//! `/run`; a minimal `/dev` with a `devpts` of its own; and `/proc`. It then `pivot_root`s into it
//! and detaches the host's root, so nothing else of the host is reachable by path. The command
//! runs in it, and when it ends the box ends: the kernel kills whatever it left running, and its
//! mounts go with its mount namespace.
//!
//! These are the box's walls, not yet its locks. The command runs as namespace root, which can
//! remount what is read-only here, and Landlock and seccomp aren't applied yet (vsock still
//! reaches the hypervisor). Nothing here parses what the box writes.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result, bail};

use crate::util;

/// Host folders a box sees at the same place, read-only; where the host has a link instead
/// (`/bin` -> `usr/bin`), the box gets the same link. Missing ones are left out.
const SYSTEM: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"];
/// What a box sees of the host's `/etc`, read-only: TLS roots, time zone, the resolver's files and
/// the loader's cache. Links are copied as links.
const ETC: &[&str] = &["ssl", "ca-certificates", "alternatives", "localtime", "resolv.conf", "nsswitch.conf", "ld.so.cache", "ld.so.conf", "ld.so.conf.d"];
/// The host's device nodes a box gets, bound in (a user namespace can't make device nodes).
const DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];
/// Host folders where the box has its own, so no tool can come from them. `/tmp` is where the
/// root is built, which hides the host's (bubblewrap does the same).
const NOT_TOOLS: &[&str] = &["/tmp", "/proc", "/sys", "/dev"];
const BUILD: &str = "/tmp";
/// The memory-backed folders, with their limits (sizes are caps, not reservations).
const ROOT_TMPFS: &str = "size=1m,mode=0755";
const MEMORY: &[(&str, &str)] = &[("tmp", "size=1g,mode=1777"), ("home/agent", "size=1g,mode=0700"), ("run", "size=1m,mode=0755")];
const DEV_TMPFS: &str = "size=64k,mode=0755";
const SHM_TMPFS: &str = "size=64m,mode=1777";

const HOSTNAME: &str = "halti-box";
const HOME: &str = "/home/agent";
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// The command runs as namespace root until the agent gets a nested user namespace of its own.
const PASSWD: &str = "root:x:0:0:root:/home/agent:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
const GROUP: &str = "root:x:0:\nnogroup:x:65534:\n";
const HOSTS: &str = "127.0.0.1\tlocalhost halti-box\n::1\tlocalhost\n";

/// `halti box sh --engine sandbox [--tool PATH]... [-- CMD]`: CMD (bash without one) in a new
/// sandbox, and its exit code. The tools are `claude` by default, from either installer.
pub fn sh(mut tools: Vec<PathBuf>, command: Vec<String>) -> Result<u8> {
    for claude in [util::home().join(".local/bin/claude"), PathBuf::from("/usr/local/bin/claude")] {
        if claude.exists() && !tools.contains(&claude) {
            tools.push(claude);
        }
    }
    let command = if command.is_empty() { vec!["bash".to_string()] } else { command };
    let exe = std::env::current_exe().context("finding halti's own binary")?;
    let mut init = Command::new(exe);
    init.arg("__sandbox-init");
    for tool in &tools {
        init.arg("--tool").arg(tool);
    }
    let status = init.arg("--").args(&command).status().context("starting the sandbox")?;
    Ok(exit_code(status))
}

fn exit_code(status: ExitStatus) -> u8 {
    status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)) as u8
}

/// `halti __sandbox-init`: makes the namespaces and waits for the box's init, whose exit code it
/// returns. The arguments come from `sh`, never from a box.
pub fn init(tools: &[PathBuf], command: &[String]) -> Result<u8> {
    let tools = tools.iter().map(|t| Tool::resolve(t)).collect::<Result<Vec<_>>>()?;
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // If `box sh` goes, the box goes with it.
    check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) }.into())?;
    let flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWPID | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
    check(unsafe { libc::unshare(flags) }.into()).context("making the box's namespaces (does this kernel allow user namespaces?)")?;
    // Your uid and gid, and only them, are root in the box's user namespace.
    write_proc("setgroups", "deny")?;
    write_proc("uid_map", &format!("0 {uid} 1"))?;
    write_proc("gid_map", &format!("0 {gid} 1"))?;
    // The first child is the new PID namespace's init. Nothing here has started a thread.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()).context("starting the box's init"),
        0 => {
            let code = box_init(&tools, command).unwrap_or_else(|e| {
                eprintln!("halti: sandbox: {e:#}");
                125
            });
            let _ = io::stderr().flush();
            unsafe { libc::_exit(code.into()) }
        }
        pid => wait_for(pid),
    }
}

fn write_proc(file: &str, text: &str) -> Result<()> {
    let path = Path::new("/proc/self").join(file);
    OpenOptions::new().write(true).open(&path).and_then(|mut f| f.write_all(text.as_bytes())).with_context(|| format!("writing {}", path.display()))
}

/// PID 1 of the box: builds the root, then runs the command and reaps every orphan until it ends.
fn box_init(tools: &[Tool], command: &[String]) -> Result<u8> {
    check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) }.into())?;
    loopback_up().context("bringing up lo")?;
    check(unsafe { libc::sethostname(HOSTNAME.as_ptr().cast(), HOSTNAME.len()) }.into()).context("naming the box")?;
    if build_root(tools)? == Proc::Host {
        eprintln!("halti: sandbox: this kernel won't give the box a /proc of its own, so it sees the host's, read-only (host /proc visible)");
    }
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]).env_clear().env("PATH", PATH).env("HOME", HOME).env("USER", "root").env("LANG", "C.UTF-8").current_dir(HOME);
    if let Some(term) = std::env::var_os("TERM") {
        cmd.env("TERM", term);
    }
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("halti: {}: {e}", command[0]);
            return Ok(127);
        }
    };
    let pid = child.id() as libc::pid_t;
    loop {
        let mut status = 0;
        match unsafe { libc::waitpid(-1, &mut status, 0) } {
            r if r == pid => return Ok(exit_code(ExitStatus::from_raw(status))),
            -1 if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted => bail!("waiting for {}: {}", command[0], io::Error::last_os_error()),
            _ => {}
        }
    }
}

fn wait_for(pid: libc::pid_t) -> Result<u8> {
    let mut status = 0;
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e).context("waiting for the box's init");
        }
    }
    Ok(exit_code(ExitStatus::from_raw(status)))
}

/// Which `/proc` the box got.
#[derive(Debug, PartialEq)]
enum Proc {
    /// Its own, which shows only the box's processes.
    Private,
    /// The host's, bound read-only: where the kernel refuses a new one, because the host's has
    /// parts covered (as in a container). The bind keeps those covers.
    Host,
}

/// What a refused private `/proc` leaves: the host's, or nothing, for an error that isn't a refusal.
fn proc_choice(private: io::Result<()>) -> Result<Proc> {
    match private {
        Ok(()) => Ok(Proc::Private),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => Ok(Proc::Host),
        Err(e) => Err(e).context("mounting /proc"),
    }
}

fn build_root(tools: &[Tool]) -> Result<Proc> {
    // Nothing mounted from here on reaches the host's mount namespace.
    mount(None::<&str>, Path::new("/"), None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    let root = Path::new(BUILD);
    mount(Some("tmpfs"), root, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some(ROOT_TMPFS))?;
    for dir in SYSTEM {
        mirror(Path::new(dir), root)?;
    }
    fs::create_dir(root.join("etc"))?;
    for name in ETC {
        mirror(&Path::new("/etc").join(name), root)?;
    }
    for (name, text) in [("passwd", PASSWD), ("group", GROUP), ("hosts", HOSTS), ("hostname", "halti-box\n")] {
        fs::write(root.join("etc").join(name), text)?;
    }
    for (dir, options) in MEMORY {
        let at = root.join(dir);
        fs::create_dir_all(&at)?;
        mount(Some("tmpfs"), &at, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some(options))?;
    }
    make_dev(&root.join("dev"))?;
    for tool in tools {
        tool.place(root)?;
    }
    let proc = root.join("proc");
    fs::create_dir(&proc)?;
    let flags = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    let chosen = proc_choice(mount_raw(Some(Path::new("proc")), &proc, Some("proc"), flags, None))?;
    if chosen == Proc::Host {
        mount(Some("/proc"), &proc, None, libc::MS_BIND | libc::MS_REC, None)?;
        read_only(&proc, true)?;
    }
    // A sysfs of its own shows only the box's network devices; where the kernel refuses one (for
    // the same reason as /proc), the box has no /sys rather than the host's.
    let sys = root.join("sys");
    fs::create_dir(&sys)?;
    let _ = mount_raw(Some(Path::new("sysfs")), &sys, Some("sysfs"), flags, None);
    pivot(root)?;
    read_only(Path::new("/"), false)?;
    read_only(Path::new("/dev"), false)?;
    Ok(chosen)
}

/// Puts the host's `path` at the same place under `root`: the same link where it is a link, else
/// bound read-only. A missing one is left out.
fn mirror(path: &Path, root: &Path) -> Result<()> {
    let Ok(meta) = fs::symlink_metadata(path) else { return Ok(()) };
    let at = under(root, path);
    if meta.file_type().is_symlink() {
        return symlink(fs::read_link(path)?, &at).with_context(|| format!("linking {}", at.display()));
    }
    bind_read_only(path, &at, meta.is_dir())
}

fn under(root: &Path, path: &Path) -> PathBuf {
    root.join(path.strip_prefix("/").unwrap_or(path))
}

fn bind_read_only(src: &Path, at: &Path, dir: bool) -> Result<()> {
    if dir {
        fs::create_dir_all(at)?;
    } else {
        fs::create_dir_all(at.parent().expect("under the root"))?;
        File::create(at)?;
    }
    mount(Some(src), at, None, libc::MS_BIND | libc::MS_REC, None)?;
    read_only(at, true)
}

fn make_dev(dev: &Path) -> Result<()> {
    fs::create_dir(dev)?;
    mount(Some("tmpfs"), dev, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NOEXEC, Some(DEV_TMPFS))?;
    for name in DEVICES {
        let at = dev.join(name);
        File::create(&at)?;
        mount(Some(Path::new("/dev").join(name)), &at, None, libc::MS_BIND, None)?;
    }
    for (name, to) in [("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"), ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2"), ("ptmx", "pts/ptmx")] {
        symlink(to, dev.join(name))?;
    }
    let pts = dev.join("pts");
    fs::create_dir(&pts)?;
    mount(Some("devpts"), &pts, Some("devpts"), libc::MS_NOSUID | libc::MS_NOEXEC, Some("newinstance,ptmxmode=0666,mode=0620"))?;
    let shm = dev.join("shm");
    fs::create_dir(&shm)?;
    mount(Some("tmpfs"), &shm, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some(SHM_TMPFS))
}

/// Makes `root` the root and detaches the host's, which then can't be reached by any path.
fn pivot(root: &Path) -> Result<()> {
    let old = root.join(".old");
    fs::create_dir(&old)?;
    let (new_root, put_old) = (cstring(root), cstring(&old));
    check(unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), put_old.as_ptr()) }).context("pivot_root")?;
    std::env::set_current_dir("/")?;
    check(unsafe { libc::umount2(c"/.old".as_ptr(), libc::MNT_DETACH) }.into()).context("detaching the host's root")?;
    fs::remove_dir("/.old").context("removing the host's root folder")
}

/// A tool from the host: the path it was named by and the file or folder that path resolves to.
#[derive(Debug)]
struct Tool {
    named: PathBuf,
    real: PathBuf,
}

impl Tool {
    fn resolve(named: &Path) -> Result<Self> {
        if !named.is_absolute() {
            bail!("a tool is named by its full path: {}", named.display());
        }
        let real = fs::canonicalize(named).with_context(|| format!("tool {}", named.display()))?;
        if let Some(dir) = NOT_TOOLS.iter().find(|d| real.starts_with(d)) {
            bail!("tool {} is under {dir}, where the box has its own", named.display());
        }
        Ok(Self { named: named.to_path_buf(), real })
    }

    /// What the box needs for the tool beyond its bind set: the real file bound, unless the system
    /// folders show it already, and a link at the named path, unless that's the real one or shown.
    fn needs(&self) -> (Option<&Path>, Option<&Path>) {
        let shown = |p: &Path| SYSTEM.iter().any(|d| p.starts_with(d));
        let bind = Some(self.real.as_path()).filter(|p| !shown(p));
        let link = Some(self.named.as_path()).filter(|p| *p != self.real && !shown(p));
        (bind, link)
    }

    fn place(&self, root: &Path) -> Result<()> {
        let (bind, link) = self.needs();
        if let Some(real) = bind {
            bind_read_only(real, &under(root, real), real.is_dir()).with_context(|| format!("tool {}", self.named.display()))?;
        }
        if let Some(named) = link {
            let at = under(root, named);
            fs::create_dir_all(at.parent().expect("under the root"))?;
            symlink(&self.real, &at).with_context(|| format!("tool {}", self.named.display()))?;
        }
        Ok(())
    }
}

/// The `ifreq` of SIOCGIFFLAGS and SIOCSIFFLAGS: a name and the flags, padded to the union's size.
#[repr(C)]
struct IfFlags {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

fn loopback_up() -> Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    check(fd.into())?;
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = IfFlags { name: [0; libc::IFNAMSIZ], flags: 0, _pad: [0; 22] };
    req.name[..2].copy_from_slice(b"lo");
    check(unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req) }.into())?;
    req.flags |= libc::IFF_UP as libc::c_short;
    check(unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &req) }.into())?;
    Ok(())
}

/// `struct mount_attr` of mount_setattr(2), which libc doesn't have.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

const MOUNT_ATTR_RDONLY: u64 = 1;

/// Makes the mount at `at` read-only, and with `recursive` every mount under it too. Unlike a
/// remount, it leaves the flags the kernel locks (nosuid, nodev, ...) as they are.
fn read_only(at: &Path, recursive: bool) -> Result<()> {
    let attr = MountAttr { attr_set: MOUNT_ATTR_RDONLY, attr_clr: 0, propagation: 0, userns_fd: 0 };
    let flags = if recursive { libc::AT_RECURSIVE } else { 0 };
    let path = cstring(at);
    let r = unsafe { libc::syscall(libc::SYS_mount_setattr, libc::AT_FDCWD, path.as_ptr(), flags, &attr, size_of::<MountAttr>()) };
    check(r).with_context(|| format!("making {} read-only", at.display()))
}

fn mount<P: AsRef<Path>>(src: Option<P>, at: &Path, fstype: Option<&str>, flags: libc::c_ulong, data: Option<&str>) -> Result<()> {
    let src = src.as_ref().map(|s| s.as_ref());
    mount_raw(src, at, fstype, flags, data).with_context(|| format!("mounting {} on {}", src.map_or(Path::new("-"), |s| s).display(), at.display()))
}

fn mount_raw(src: Option<&Path>, at: &Path, fstype: Option<&str>, flags: libc::c_ulong, data: Option<&str>) -> io::Result<()> {
    let src = src.map(cstring);
    let at = cstring(at);
    let fstype = fstype.map(|t| CString::new(t).expect("no NUL"));
    let data = data.map(|d| CString::new(d).expect("no NUL"));
    let ptr = |c: &Option<CString>| c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    check(unsafe { libc::mount(ptr(&src), at.as_ptr(), ptr(&fstype), flags, ptr(&data).cast()) }.into())
}

fn cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("paths from arguments and the file system have no NUL")
}

fn check(r: libc::c_long) -> io::Result<()> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::{Path, PathBuf};

    use super::{Proc, Tool, proc_choice};

    #[test]
    fn a_refused_private_proc_falls_back_to_the_hosts_and_other_errors_fail() {
        assert_eq!(proc_choice(Ok(())).unwrap(), Proc::Private);
        assert_eq!(proc_choice(Err(io::Error::from_raw_os_error(libc::EPERM))).unwrap(), Proc::Host);
        assert_eq!(proc_choice(Err(io::Error::from_raw_os_error(libc::EACCES))).unwrap(), Proc::Host);
        assert!(proc_choice(Err(io::Error::from_raw_os_error(libc::ENOENT))).is_err());
        assert!(proc_choice(Err(io::Error::from_raw_os_error(libc::EINVAL))).is_err());
    }

    #[test]
    fn a_tool_is_bound_and_linked_only_where_the_system_folders_dont_show_it() {
        let tool = |named: &str, real: &str| Tool { named: PathBuf::from(named), real: PathBuf::from(real) };
        // npm's: a link in /usr/local/bin to a file under /usr.
        let npm = tool("/usr/local/bin/claude", "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe");
        assert_eq!(npm.needs(), (None, None));
        // The native installer's: a link in the home to a version under it.
        let native = tool("/home/u/.local/bin/claude", "/home/u/.local/share/claude/versions/2.1.0");
        assert_eq!(native.needs(), (Some(Path::new("/home/u/.local/share/claude/versions/2.1.0")), Some(Path::new("/home/u/.local/bin/claude"))));
        let plain = tool("/opt/tool/bin", "/opt/tool/bin");
        assert_eq!(plain.needs(), (Some(Path::new("/opt/tool/bin")), None));
        // Named through a shown folder, resolving outside it: bound, and the link is there already.
        let shown = tool("/usr/bin/x", "/opt/x");
        assert_eq!(shown.needs(), (Some(Path::new("/opt/x")), None));
    }

    #[test]
    fn tools_are_named_by_full_paths_outside_the_boxs_own_folders() {
        assert!(Tool::resolve(Path::new("bin/bash")).is_err());
        let err = Tool::resolve(Path::new("/tmp")).unwrap_err();
        assert!(err.to_string().contains("where the box has its own"), "{err}");
        assert!(Tool::resolve(Path::new("/proc/cpuinfo")).is_err());
        let bash = Tool::resolve(Path::new("/bin/bash")).unwrap();
        assert!(bash.real.starts_with("/usr") || bash.real.starts_with("/bin"), "{}", bash.real.display());
    }
}
