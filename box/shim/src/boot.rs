//! `boot`: the shim as the first process of a Linux VM that boots the box image itself, where no
//! container runtime mounts the system, reaps orphans or stops the VM. It puts the system
//! together (`plan`), starts `serve --vsock`, and then reaps every process left to it until it is
//! asked to stop or `serve` ends (`init`), when it stops the rest and powers the VM off.
//!
//! What the VM is assumed to be like is written once: the folders and disks in `plan`, the signals
//! that ask for a stop in `linux::STOP_SIGNALS`. The calls that need a VM go through `System` and
//! `Init`, so the order of the work is tested anywhere with stand-ins; the Linux side of those two
//! (`linux`) runs only in a VM.

use std::fmt;
use std::io;
use std::time::Duration;

/// Mount flags, numbered as Linux numbers them (a Linux test compares them with libc's).
pub mod flags {
    pub const NOSUID: u64 = 0x2;
    pub const NODEV: u64 = 0x4;
    pub const NOEXEC: u64 = 0x8;
    pub const BIND: u64 = 0x1000;
    pub const REC: u64 = 0x4000;
    pub const PRIVATE: u64 = 0x40000;
}
use flags::*;

/// An empty folder of the image, where the writable root is put together before it becomes the
/// root.
const STAGE: &str = "/mnt";
/// The box's disk: the VM's second disk (the image is its first), holding one ext4 file system
/// with the folders of `FOLDERS`.
const DISK_DEVICE: &str = "/dev/vdb";
const DISK_TYPE: &str = "ext4";
/// Where the disk is mounted while its folders are bound into place. It is let go after, so only
/// those folders are reachable.
const DISK_MOUNT: &str = "/run/halti-disk";
/// The disk's folders, and where they appear: where a Mac box mounts its store's folders.
const FOLDERS: [(&str, &str); 3] = [("home", "/home/agent"), ("work", "/work"), ("downloads", "/downloads")];

/// One step of putting the system together.
#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    /// mount(2). Empty strings are passed as null.
    Mount { source: String, target: String, fstype: String, flags: u64, data: String },
    /// A folder and its parents, if missing.
    Dir(String),
    /// A folder the agent owns, made if missing; a folder already there is left as it is, and
    /// anything else there is an error.
    AgentDir(String),
    /// The root moves to this folder, and the old root is let go.
    EnterRoot(String),
    /// A mount let go; what was bound from it stays.
    Detach(String),
    /// The loopback interface up: the listeners of `serve` are on it.
    LoopbackUp,
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Step::Mount { source, target, .. } if source.is_empty() => write!(f, "changing the mount at {target}"),
            Step::Mount { source, target, .. } => write!(f, "mounting {source} at {target}"),
            Step::Dir(path) | Step::AgentDir(path) => write!(f, "making {path}"),
            Step::EnterRoot(path) => write!(f, "moving the root to {path}"),
            Step::Detach(path) => write!(f, "letting go of {path}"),
            Step::LoopbackUp => write!(f, "bringing up lo"),
        }
    }
}

fn mount(source: &str, target: &str, fstype: &str, flags: u64, data: &str) -> Step {
    Step::Mount { source: source.into(), target: target.into(), fstype: fstype.into(), flags, data: data.into() }
}

/// A file system at `target`, made first if the image lacks the folder.
fn mount_at(source: &str, target: &str, fstype: &str, flags: u64, data: &str) -> [Step; 2] {
    [Step::Dir(target.into()), mount(source, target, fstype, flags, data)]
}

/// Everything `boot` does before it starts `serve`, in order. `bridges`: the box runs Docker.
///
/// What it mounts is what Apple's `container` gives a box: the system file systems, a memory-backed
/// /tmp and /var/tmp, the cgroup file system that Docker's start writes to, and with Docker a
/// memory-backed /var/lib/docker. Then the box's folders from its disk. Two more than the Mac
/// engine's list names, and which `container` mounts too: /dev/pts, for the exec service's
/// terminals, and /dev/shm.
pub fn plan(bridges: bool) -> Vec<Step> {
    let stage = |sub: &str| format!("{STAGE}/{sub}");
    // The root: the read-only image under a layer in memory, so the system is writable and thrown
    // away at every stop, as in a Mac box. pivot_root needs the root's mounts private.
    let mut steps = vec![
        mount("", "/", "", REC | PRIVATE, ""),
        mount("tmpfs", STAGE, "tmpfs", NOSUID | NODEV, "mode=0755"),
        Step::Dir(stage("upper")),
        Step::Dir(stage("work")),
        Step::Dir(stage("root")),
        mount("overlay", &stage("root"), "overlay", 0, &format!("lowerdir=/,upperdir={},workdir={}", stage("upper"), stage("work"))),
        Step::EnterRoot(stage("root")),
    ];
    let system = [
        ("proc", "/proc", "proc", NOSUID | NODEV | NOEXEC, ""),
        ("sysfs", "/sys", "sysfs", NOSUID | NODEV | NOEXEC, ""),
        ("cgroup2", "/sys/fs/cgroup", "cgroup2", NOSUID | NODEV | NOEXEC, ""),
        ("devtmpfs", "/dev", "devtmpfs", NOSUID, "mode=0755"),
        ("devpts", "/dev/pts", "devpts", NOSUID | NOEXEC, "ptmxmode=0666,mode=0620"),
        ("tmpfs", "/dev/shm", "tmpfs", NOSUID | NODEV, "mode=1777"),
        ("tmpfs", "/run", "tmpfs", NOSUID | NODEV, "mode=0755"),
        ("tmpfs", "/tmp", "tmpfs", NOSUID | NODEV, "mode=1777"),
        ("tmpfs", "/var/tmp", "tmpfs", NOSUID | NODEV, "mode=1777"),
    ];
    for (source, target, fstype, flags, data) in system {
        steps.extend(mount_at(source, target, fstype, flags, data));
    }
    if bridges {
        // Docker's images and containers, which hold device files and set-id programs.
        steps.extend(mount_at("tmpfs", "/var/lib/docker", "tmpfs", 0, "mode=0711"));
    }
    steps.extend(mount_at(DISK_DEVICE, DISK_MOUNT, DISK_TYPE, NOSUID | NODEV, ""));
    for (folder, guest) in FOLDERS {
        let on_disk = format!("{DISK_MOUNT}/{folder}");
        steps.push(Step::AgentDir(on_disk.clone()));
        steps.extend(mount_at(&on_disk, guest, "", BIND, ""));
    }
    steps.push(Step::Detach(DISK_MOUNT.into()));
    steps.push(Step::LoopbackUp);
    steps
}

/// What putting the system together asks of the kernel.
pub trait System {
    fn mount(&mut self, source: &str, target: &str, fstype: &str, flags: u64, data: &str) -> io::Result<()>;
    fn dir(&mut self, path: &str) -> io::Result<()>;
    fn agent_dir(&mut self, path: &str) -> io::Result<()>;
    fn enter_root(&mut self, path: &str) -> io::Result<()>;
    fn detach(&mut self, path: &str) -> io::Result<()>;
    fn loopback_up(&mut self) -> io::Result<()>;
}

/// Take the steps in order, stopping at the first that fails, which the error names.
pub fn apply(steps: &[Step], sys: &mut impl System) -> io::Result<()> {
    for step in steps {
        let done = match step {
            Step::Mount { source, target, fstype, flags, data } => sys.mount(source, target, fstype, *flags, data),
            Step::Dir(path) => sys.dir(path),
            Step::AgentDir(path) => sys.agent_dir(path),
            Step::EnterRoot(path) => sys.enter_root(path),
            Step::Detach(path) => sys.detach(path),
            Step::LoopbackUp => sys.loopback_up(),
        };
        done.map_err(|e| io::Error::new(e.kind(), format!("{step}: {e}")))?;
    }
    Ok(())
}

/// What woke the first process.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Signal {
    /// A child ended.
    Child,
    /// The VM is asked to stop.
    Stop,
}

/// One look for an ended child.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Reaped {
    Pid(i32),
    /// Children run, and none has ended.
    Nothing,
    NoChildren,
}

/// What being the first process asks of the kernel.
pub trait Init {
    /// Wait for a signal, at most `timeout`.
    fn wait(&mut self, timeout: Duration) -> Option<Signal>;
    /// Reap one ended child, if there is one.
    fn reap(&mut self) -> Reaped;
    /// Signal every other process: SIGTERM, or SIGKILL if `kill`.
    fn signal_all(&mut self, kill: bool);
    /// Write what is cached to the disks and power the VM off.
    fn power_off(&mut self);
}

/// How long the box's processes have to end once asked, before they are killed.
const GRACE: Duration = Duration::from_secs(5);
/// How long the killed processes have to be gone before the VM powers off anyway.
const KILL_WAIT: Duration = Duration::from_secs(2);
/// How often children are looked for without a signal (signals of ended children can merge).
const TICK: Duration = Duration::from_millis(250);

/// The first process's life after `serve` (`main`) has started: reap until `main` ends or a stop
/// is asked for, then stop everything and power off.
pub fn init(sys: &mut impl Init, main: i32) {
    'running: loop {
        let signal = sys.wait(TICK);
        loop {
            match sys.reap() {
                Reaped::Pid(pid) if pid == main => break 'running,
                Reaped::Pid(_) => {}
                Reaped::Nothing | Reaped::NoChildren => break,
            }
        }
        if signal == Some(Signal::Stop) {
            break;
        }
    }
    sys.signal_all(false);
    if !drain(sys, GRACE) {
        sys.signal_all(true);
        drain(sys, KILL_WAIT);
    }
    sys.power_off();
}

/// Reap until no child is left, for at most `limit`. Whether none is left.
fn drain(sys: &mut impl Init, limit: Duration) -> bool {
    let mut waited = Duration::ZERO;
    loop {
        loop {
            match sys.reap() {
                Reaped::Pid(_) => {}
                Reaped::Nothing => break,
                Reaped::NoChildren => return true,
            }
        }
        if waited >= limit {
            return false;
        }
        sys.wait(TICK);
        waited += TICK;
    }
}

/// `boot [--bridges]`. Returns only if the VM did not power off.
pub fn main(bridges: bool) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    return linux::main(bridges);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = bridges;
        Err(io::Error::new(io::ErrorKind::Unsupported, "boot runs only as a Linux VM's first process"))
    }
}

/// The kernel's side of `System` and `Init`. Only a VM runs any of this: no test does.
#[cfg(target_os = "linux")]
mod linux {
    use super::{Init, Reaped, Signal, System, apply, init, plan};
    use crate::{exec, names};
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::time::Duration;
    use std::{env, fs, io, process, ptr};

    /// The signals that ask the VM to stop: SIGTERM (as `container stop` sends), SIGINT (what
    /// Ctrl-Alt-Del becomes, once turned into a signal) and SIGPWR (a power failure).
    pub const STOP_SIGNALS: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGPWR];

    pub fn main(bridges: bool) -> io::Result<()> {
        if process::id() != 1 {
            return Err(io::Error::other("boot runs only as a VM's first process"));
        }
        let mut real = Real::new()?;
        if let Err(e) = apply(&plan(bridges), &mut real) {
            eprintln!("{}: {e}", names::SHIM);
            real.power_off();
            return Err(io::Error::other("the VM did not power off"));
        }
        match serve(bridges).spawn() {
            Ok(child) => init(&mut real, child.id() as i32),
            Err(e) => {
                eprintln!("{}: starting {} serve: {e}", names::SHIM, names::SHIM_PATH);
                real.power_off();
            }
        }
        Err(io::Error::other("the VM did not power off"))
    }

    /// `serve --vsock`, started with no signal blocked: std would start it with the signals this
    /// process blocks.
    pub fn serve(bridges: bool) -> Command {
        let mut serve = Command::new(names::SHIM_PATH);
        serve.args(["serve", "--vsock"]);
        if bridges {
            serve.arg("--bridges");
        }
        // SAFETY: `fresh_signals` makes only async-signal-safe calls.
        unsafe { serve.pre_exec(exec::fresh_signals) };
        serve
    }

    struct Real {
        /// The signals this process takes with `sigtimedwait`, blocked so none is lost between
        /// two waits. The first process gets only signals it handles or blocks.
        signals: libc::sigset_t,
        agent: (u32, u32),
    }

    fn cvt(result: libc::c_int) -> io::Result<()> {
        if result == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    fn c(s: &str) -> io::Result<Option<CString>> {
        if s.is_empty() { Ok(None) } else { CString::new(s).map(Some).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput)) }
    }

    impl Real {
        fn new() -> io::Result<Self> {
            // SAFETY: sigset_t is plain data; sigemptyset sets it up before any other use.
            let mut signals: libc::sigset_t = unsafe { std::mem::zeroed() };
            // SAFETY: the set is a live value; sigprocmask(2) only reads it.
            unsafe {
                libc::sigemptyset(&mut signals);
                for signal in STOP_SIGNALS.into_iter().chain([libc::SIGCHLD]) {
                    libc::sigaddset(&mut signals, signal);
                }
                cvt(libc::sigprocmask(libc::SIG_BLOCK, &signals, ptr::null_mut()))?;
                // Ctrl-Alt-Del: a SIGINT to this process, not a reset.
                libc::reboot(libc::RB_DISABLE_CAD);
            }
            let agent = exec::Users::guest().agent;
            Ok(Self { signals, agent: (agent.uid, agent.gid) })
        }
    }

    impl System for Real {
        fn mount(&mut self, source: &str, target: &str, fstype: &str, flags: u64, data: &str) -> io::Result<()> {
            let (source, target, fstype, data) = (c(source)?, c(target)?, c(fstype)?, c(data)?);
            let p = |s: &Option<CString>| s.as_ref().map_or(ptr::null(), |s| s.as_ptr());
            // SAFETY: each pointer is null or a live C string.
            cvt(unsafe { libc::mount(p(&source), p(&target), p(&fstype), flags as libc::c_ulong, p(&data).cast()) })
        }

        fn dir(&mut self, path: &str) -> io::Result<()> {
            fs::DirBuilder::new().recursive(true).mode(0o755).create(path)
        }

        fn agent_dir(&mut self, path: &str) -> io::Result<()> {
            match fs::symlink_metadata(path) {
                Ok(meta) if meta.is_dir() => Ok(()),
                Ok(_) => Err(io::Error::other("it is there and not a folder")),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    fs::create_dir(path)?;
                    std::os::unix::fs::chown(path, Some(self.agent.0), Some(self.agent.1))?;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                }
                Err(e) => Err(e),
            }
        }

        fn enter_root(&mut self, path: &str) -> io::Result<()> {
            env::set_current_dir(path)?;
            // SAFETY: pivot_root(2) and umount2(2) with live C strings: the new root goes over
            // the old one at ".", and the old one is then let go.
            unsafe {
                if libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) == -1 {
                    return Err(io::Error::last_os_error());
                }
                cvt(libc::umount2(c".".as_ptr(), libc::MNT_DETACH))?;
            }
            env::set_current_dir("/")
        }

        fn detach(&mut self, path: &str) -> io::Result<()> {
            let path = CString::new(path).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            // SAFETY: a live C string.
            cvt(unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) })
        }

        fn loopback_up(&mut self) -> io::Result<()> {
            // SAFETY: socket(2) returns a new descriptor, which `OwnedFd` then owns alone.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if fd == -1 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            // SAFETY: ifreq is plain data; the name is set below and the flags read into it.
            let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
            for (to, from) in req.ifr_name.iter_mut().zip(b"lo") {
                *to = *from as libc::c_char;
            }
            // SAFETY: ioctl(2) reading and writing the ifreq above; the flags are the union's
            // field that these two requests use.
            unsafe {
                cvt(libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut req))?;
                req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
                cvt(libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS as _, &req))
            }
        }
    }

    impl Init for Real {
        fn wait(&mut self, timeout: Duration) -> Option<Signal> {
            let ts = libc::timespec { tv_sec: timeout.as_secs() as libc::time_t, tv_nsec: timeout.subsec_nanos() as _ };
            // SAFETY: the set and the timeout are live values; no siginfo is asked for.
            match unsafe { libc::sigtimedwait(&self.signals, ptr::null_mut(), &ts) } {
                -1 => None,
                libc::SIGCHLD => Some(Signal::Child),
                _ => Some(Signal::Stop),
            }
        }

        fn reap(&mut self) -> Reaped {
            let mut status = 0;
            // SAFETY: waitpid(2) writing the status into a live value.
            match unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) } {
                -1 if io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) => Reaped::NoChildren,
                -1 | 0 => Reaped::Nothing,
                pid => Reaped::Pid(pid),
            }
        }

        fn signal_all(&mut self, kill: bool) {
            // SAFETY: kill(2) of every process but this one.
            unsafe { libc::kill(-1, if kill { libc::SIGKILL } else { libc::SIGTERM }) };
        }

        fn power_off(&mut self) {
            // SAFETY: sync(2), then reboot(2), which does not return when it works.
            unsafe {
                libc::sync();
                libc::reboot(libc::RB_POWER_OFF);
            }
            eprintln!("{}: powering off: {}", names::SHIM, io::Error::last_os_error());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn mounts(steps: &[Step]) -> Vec<(String, String, u64)> {
        let after_root = steps.iter().skip_while(|s| !matches!(s, Step::EnterRoot(_))).skip(1);
        after_root.filter_map(|s| if let Step::Mount { target, fstype, flags, .. } = s { Some((target.clone(), fstype.clone(), *flags)) } else { None }).collect()
    }

    #[test]
    fn boot_mounts_what_the_mac_engine_gives() {
        let plain = mounts(&plan(false));
        let targets: Vec<&str> = plain.iter().map(|(t, _, _)| t.as_str()).collect();
        assert_eq!(targets, ["/proc", "/sys", "/sys/fs/cgroup", "/dev", "/dev/pts", "/dev/shm", "/run", "/tmp", "/var/tmp", DISK_MOUNT, "/home/agent", "/work", "/downloads"]);
        let kind = |target: &str| plain.iter().find(|(t, _, _)| t == target).map(|(_, k, f)| (k.as_str(), *f)).unwrap();
        // `container run --tmpfs /tmp --tmpfs /var/tmp`, and the cgroups dockerd's start writes to
        assert_eq!(kind("/tmp").0, "tmpfs");
        assert_eq!(kind("/var/tmp").0, "tmpfs");
        assert_eq!(kind("/sys/fs/cgroup").0, "cgroup2");
        // the box's folders, bound from its disk, where a Mac box mounts its store's
        for guest in ["/home/agent", "/work", "/downloads"] {
            assert_eq!(kind(guest), ("", BIND));
        }
        assert_eq!(kind(DISK_MOUNT), (DISK_TYPE, NOSUID | NODEV));
        assert!(plain.iter().all(|(t, _, _)| t != "/var/lib/docker"), "Docker's data only for a box with Docker");

        // with Docker: its data in memory too, as `--tmpfs /var/lib/docker`, and nothing else
        let docker = mounts(&plan(true));
        let added: Vec<_> = docker.iter().filter(|m| !plain.contains(m)).collect();
        assert_eq!(added, [&("/var/lib/docker".to_string(), "tmpfs".to_string(), 0)]);
    }

    #[test]
    fn the_root_is_the_image_under_a_layer_in_memory() {
        let steps = plan(false);
        let enter = steps.iter().position(|s| matches!(s, Step::EnterRoot(_))).unwrap();
        assert_eq!(steps[0], mount("", "/", "", REC | PRIVATE, ""));
        assert_eq!(steps[1], mount("tmpfs", "/mnt", "tmpfs", NOSUID | NODEV, "mode=0755"));
        assert_eq!(steps[enter - 1], mount("overlay", "/mnt/root", "overlay", 0, "lowerdir=/,upperdir=/mnt/upper,workdir=/mnt/work"));
        assert_eq!(steps[enter], Step::EnterRoot("/mnt/root".into()));
        // every other mount is made in the new root, and the disk is let go once bound
        assert!(steps[enter + 1..].iter().all(|s| !matches!(s, Step::EnterRoot(_))));
        let detach = steps.iter().position(|s| *s == Step::Detach(DISK_MOUNT.into())).unwrap();
        let last_bind = steps.iter().rposition(|s| matches!(s, Step::Mount { flags, .. } if *flags == BIND)).unwrap();
        assert!(detach > last_bind);
        assert_eq!(steps.last(), Some(&Step::LoopbackUp));
        // a folder the agent owns is made before it is bound
        for (folder, guest) in FOLDERS {
            let made = steps.iter().position(|s| *s == Step::AgentDir(format!("{DISK_MOUNT}/{folder}"))).unwrap();
            let bound = steps.iter().position(|s| matches!(s, Step::Mount { target, .. } if target == guest)).unwrap();
            assert!(made < bound);
        }
    }

    /// Records each call, and fails the one numbered `fail`.
    #[derive(Default)]
    struct FakeSystem {
        calls: Vec<String>,
        fail: Option<usize>,
    }

    impl FakeSystem {
        fn call(&mut self, what: String) -> io::Result<()> {
            self.calls.push(what);
            if self.fail == Some(self.calls.len()) { Err(io::Error::from(io::ErrorKind::PermissionDenied)) } else { Ok(()) }
        }
    }

    impl System for FakeSystem {
        fn mount(&mut self, source: &str, target: &str, fstype: &str, flags: u64, data: &str) -> io::Result<()> {
            self.call(format!("mount {source} {target} {fstype} {flags:#x} {data}"))
        }
        fn dir(&mut self, path: &str) -> io::Result<()> {
            self.call(format!("dir {path}"))
        }
        fn agent_dir(&mut self, path: &str) -> io::Result<()> {
            self.call(format!("agent_dir {path}"))
        }
        fn enter_root(&mut self, path: &str) -> io::Result<()> {
            self.call(format!("enter_root {path}"))
        }
        fn detach(&mut self, path: &str) -> io::Result<()> {
            self.call(format!("detach {path}"))
        }
        fn loopback_up(&mut self) -> io::Result<()> {
            self.call("loopback_up".into())
        }
    }

    #[test]
    fn every_step_is_taken_in_order_and_the_first_failure_stops_the_rest() {
        let steps = plan(true);
        let mut sys = FakeSystem::default();
        apply(&steps, &mut sys).unwrap();
        assert_eq!(sys.calls.len(), steps.len());
        assert_eq!(sys.calls[0], "mount  /  0x44000 ");
        assert_eq!(sys.calls.last().unwrap(), "loopback_up");

        let disk = steps.iter().position(|s| matches!(s, Step::Mount { source, .. } if source == DISK_DEVICE)).unwrap();
        let mut sys = FakeSystem { fail: Some(disk + 1), ..Default::default() };
        let err = apply(&steps, &mut sys).unwrap_err();
        assert_eq!(err.to_string(), format!("mounting {DISK_DEVICE} at {DISK_MOUNT}: permission denied"));
        assert_eq!(sys.calls.len(), disk + 1, "nothing after the failed step");
    }

    /// A VM's processes, played by a script: what each wait returns, which children end on their
    /// own (at which wait), and which ignore SIGTERM.
    struct FakeInit {
        waits: VecDeque<Option<Signal>>,
        running: Vec<i32>,
        /// (pid, the wait after which it ends on its own)
        ends: Vec<(i32, usize)>,
        stubborn: Vec<i32>,
        ended: VecDeque<i32>,
        waited: usize,
        log: Vec<String>,
    }

    impl FakeInit {
        fn new(waits: &[Option<Signal>], running: &[i32], ends: &[(i32, usize)], stubborn: &[i32]) -> Self {
            Self {
                waits: waits.iter().copied().collect(),
                running: running.to_vec(),
                ends: ends.to_vec(),
                stubborn: stubborn.to_vec(),
                ended: VecDeque::new(),
                waited: 0,
                log: Vec::new(),
            }
        }

        fn end(&mut self, pid: i32) {
            if let Some(i) = self.running.iter().position(|p| *p == pid) {
                self.running.remove(i);
                self.ended.push_back(pid);
            }
        }
    }

    impl Init for FakeInit {
        fn wait(&mut self, timeout: Duration) -> Option<Signal> {
            assert_eq!(timeout, TICK);
            self.waited += 1;
            for (pid, at) in self.ends.clone() {
                if at == self.waited {
                    self.end(pid);
                }
            }
            if self.log.iter().any(|l| l.starts_with("signal")) {
                // stopping: time passes, nothing new is scripted
                return None;
            }
            self.waits.pop_front().unwrap_or_else(|| panic!("waited past the script: {:?}", self.log))
        }

        fn reap(&mut self) -> Reaped {
            match self.ended.pop_front() {
                Some(pid) => {
                    self.log.push(format!("reaped {pid}"));
                    Reaped::Pid(pid)
                }
                None if self.running.is_empty() => Reaped::NoChildren,
                None => Reaped::Nothing,
            }
        }

        fn signal_all(&mut self, kill: bool) {
            self.log.push(format!("signal {}", if kill { "KILL" } else { "TERM" }));
            for pid in self.running.clone() {
                if kill || !self.stubborn.contains(&pid) {
                    self.end(pid);
                }
            }
        }

        fn power_off(&mut self) {
            self.log.push("power off".into());
        }
    }

    const SERVE: i32 = 2;

    #[test]
    fn orphans_are_reaped_until_a_stop_is_asked_for() {
        // two orphans end while the box runs; then a stop; serve and the agent obey SIGTERM
        let mut sys = FakeInit::new(&[None, Some(Signal::Child), None, Some(Signal::Stop)], &[SERVE, 10, 11, 12], &[(11, 1), (12, 3)], &[]);
        init(&mut sys, SERVE);
        assert_eq!(sys.log, ["reaped 11", "reaped 12", "signal TERM", "reaped 2", "reaped 10", "power off"]);
    }

    #[test]
    fn the_vm_powers_off_when_serve_ends() {
        let mut sys = FakeInit::new(&[Some(Signal::Child)], &[SERVE, 10], &[(SERVE, 1)], &[]);
        init(&mut sys, SERVE);
        assert_eq!(sys.log, ["reaped 2", "signal TERM", "reaped 10", "power off"]);
    }

    #[test]
    fn what_ignores_the_stop_is_killed_after_the_grace() {
        let mut sys = FakeInit::new(&[Some(Signal::Stop)], &[SERVE, 10], &[], &[10]);
        init(&mut sys, SERVE);
        assert_eq!(sys.log, ["signal TERM", "reaped 2", "signal KILL", "reaped 10", "power off"]);
        assert_eq!(sys.waited, 1 + (GRACE.as_millis() / TICK.as_millis()) as usize, "it waited the grace out");
    }

    #[test]
    fn the_vm_powers_off_even_if_a_process_outlives_the_kill() {
        struct Unkillable(usize);
        impl Init for Unkillable {
            fn wait(&mut self, _: Duration) -> Option<Signal> {
                self.0 += 1;
                (self.0 == 1).then_some(Signal::Stop)
            }
            fn reap(&mut self) -> Reaped {
                Reaped::Nothing
            }
            fn signal_all(&mut self, _: bool) {}
            fn power_off(&mut self) {
                self.0 += 1000;
            }
        }
        let mut sys = Unkillable(0);
        init(&mut sys, SERVE);
        assert!(sys.0 > 1000, "powered off");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_mount_flags_are_linux_s() {
        assert_eq!(
            [NOSUID, NODEV, NOEXEC, BIND, REC, PRIVATE].map(|f| f as libc::c_ulong),
            [libc::MS_NOSUID, libc::MS_NODEV, libc::MS_NOEXEC, libc::MS_BIND, libc::MS_REC, libc::MS_PRIVATE]
        );
    }

    /// `boot` starts `serve` with its listeners on vsock, and Docker's bridges if asked.
    #[cfg(target_os = "linux")]
    #[test]
    fn boot_starts_serve_on_vsock() {
        for (bridges, args) in [(false, &["serve", "--vsock"][..]), (true, &["serve", "--vsock", "--bridges"])] {
            let serve = linux::serve(bridges);
            assert_eq!(serve.get_program(), crate::names::SHIM_PATH);
            assert_eq!(serve.get_args().collect::<Vec<_>>(), args);
        }
    }
}
