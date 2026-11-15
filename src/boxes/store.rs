//! A box's store: an AES-256 encrypted APFS sparse bundle, mounted only while the box runs. On
//! Linux it is the box's disk and a folder beside it instead (`disk`), behind the same functions.
//!
//! The key (256 random bits, hex) reaches `hdiutil` on stdin, NUL-terminated, and is never put in
//! an argument list or a file. The bundle sits in a 0700 folder; the volume is attached with
//! `-nobrowse` (no Finder, Spotlight or fseventsd) at a mount point whose parent is 0700, since
//! a volume's root is 0755. Closing detaches it, with `-force` only as a fallback.
//!
//! A store never shrinks when files are deleted: `hdiutil compact` fails on APFS images, and
//! `diskutil image attach` (which gives space back) mounts `noowners`, so files would show the
//! wrong owner. TODO: `halti box compact` (copy into a new store) if this matters in practice.

mod disk;

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
#[cfg(not(target_os = "linux"))]
use std::time::SystemTime;

use anyhow::{Context, Result, anyhow, bail};
use halti_core::ids::WsId;
use jiff::Timestamp;
use serde_json::json;

use crate::chain::Chain;
use crate::util::store_root;
use crate::{engine, names};

/// The most a store can hold; the bundle grows as needed and starts small.
#[cfg(not(target_os = "linux"))]
const SIZE: &str = "100g";
/// Folders of a store. `log`, `door` (the box CA, sealed) and `browser` (sealed sessions) are
/// halti's; no VM mounts them.
pub const FOLDERS: [&str; 6] = ["home", "work", "downloads", "log", "door", "browser"];
const DOOR_LOG: &str = "log/door.log";
const CA_FILE: &str = "door/ca.sealed";

/// The longest Unix socket path macOS accepts (104 bytes, with the terminating NUL), as
/// `engine::run` checks it.
const SOCKET_PATH_MAX: usize = 103;
/// Linux's: 108 bytes with the NUL.
#[cfg(target_os = "linux")]
const LINUX_SOCKET_PATH_MAX: usize = 107;
/// What the VM program of an engine that starts its VMs itself (`vmm`) adds to the name of the
/// socket the door dials, for a box that dials this machine's port: `_` and the port.
#[cfg(target_os = "linux")]
const LONGEST_PORT: &str = "_4294967295";

/// The socket in a VM's own sockets folder (`Layout::vm_sockets`) that the door dials: the VM's
/// vsock device.
pub const VM_VSOCK: &str = "vsock.sock";

/// Whether halti encrypts a box's store: on a Mac it does, with the box's key; on Linux the store
/// is as safe at rest as the disk under it (`disk`).
pub const ENCRYPTED: bool = !cfg!(target_os = "linux");

/// Where a box's files live on the Mac. `real()` is the user's; `workspace()` a workspace's boxes';
/// tests build their own.
pub struct Layout {
    /// Stores, mount points and locks: box/ under the store root (`util::store_root`), or a
    /// workspace's boxes/ folder
    pub root: PathBuf,
    /// The sockets the VMs publish, in a short path (104-byte limit): /tmp/halti-<uid>
    /// (/tmp/halti-dev-<uid> for debug builds), and its ws/ folder for a workspace's boxes
    pub sockets: PathBuf,
    /// Where browser VMs save downloads, one folder per box
    downloads: PathBuf,
    uid: u32,
    names: Names,
}

/// How a layout names its VMs and sockets.
enum Names {
    /// `halti-box-ID`, `ID.sock`: today's boxes.
    Keychain,
    /// `halti-wsbox-TAG-ID`, `TAG-ID.sock`: the boxes of the workspace whose id starts with the tag.
    Workspace { tag: String },
}

impl Layout {
    pub fn real() -> Result<Self> {
        let root = store_root();
        if !root.is_absolute() {
            bail!("no home folder");
        }
        let uid = uid()?;
        Ok(Self { root: root.join("box"), sockets: sockets(uid), downloads: root.join("downloads"), uid, names: Names::Keychain })
    }

    /// The boxes of the workspace `ws`, whose boxes folder is `boxes` (WSDIR/boxes): stores, locks,
    /// mount points and downloads in it, sockets in the ws/ folder of the sockets folder, and VMs
    /// named with the first 12 hex characters of its id.
    pub fn workspace(boxes: &Path, ws: WsId) -> Result<Self> {
        let uid = uid()?;
        Ok(Self::of_workspace(boxes, sockets(uid).join(names::WS_SOCKETS), uid, ws))
    }

    fn of_workspace(boxes: &Path, sockets: PathBuf, uid: u32, ws: WsId) -> Self {
        let tag = ws.to_string()[..12].to_string();
        Self { root: boxes.to_path_buf(), sockets, downloads: boxes.join("downloads"), uid, names: Names::Workspace { tag } }
    }

    #[cfg(test)]
    pub fn under(dir: &Path) -> Result<Self> {
        // No `id` here: a child process forked while another test holds a lock would keep it.
        Ok(Self { root: dir.join("box"), sockets: dir.join("sock"), downloads: dir.join("downloads"), uid: fs::metadata(dir)?.uid(), names: Names::Keychain })
    }

    /// A workspace's layout in a test folder: its boxes folder `boxes`, its sockets in `sock/ws`.
    #[cfg(test)]
    pub fn under_workspace(dir: &Path, ws: WsId) -> Result<Self> {
        Ok(Self::of_workspace(&dir.join("boxes"), dir.join("sock").join(names::WS_SOCKETS), fs::metadata(dir)?.uid(), ws))
    }

    /// Whether these are a workspace's boxes.
    pub fn in_workspace(&self) -> bool {
        matches!(self.names, Names::Workspace { .. })
    }

    /// What names the box's VMs and sockets: its id, after the workspace's tag in a workspace.
    fn named(&self, id: &str) -> String {
        match &self.names {
            Names::Keychain => id.to_string(),
            Names::Workspace { tag } => format!("{tag}-{id}"),
        }
    }

    /// The agent's VM: `halti-box-ID`, or `halti-wsbox-TAG-ID` in a workspace.
    pub fn vm(&self, id: &str) -> String {
        match &self.names {
            Names::Keychain => format!("{}{id}", names::BOX_VM_PREFIX),
            Names::Workspace { .. } => format!("{}{}", names::WS_BOX_VM_PREFIX, self.named(id)),
        }
    }

    /// The browser VM: `halti-browser-ID`, or `halti-wsbrowser-TAG-ID` in a workspace.
    pub fn browser_vm(&self, id: &str) -> String {
        match &self.names {
            Names::Keychain => engine::browser_vm_name(id),
            Names::Workspace { .. } => format!("{}{}", names::WS_BROWSER_VM_PREFIX, self.named(id)),
        }
    }

    /// The box's store: `NAME.sparsebundle`, or on Linux its disk, `NAME.img`.
    pub fn bundle(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}{}", names::STORE))
    }

    /// The store of a box that is shredded when it stops, or of `--temp`; its key is never kept.
    pub fn ephemeral_bundle(&self, id: &str) -> PathBuf {
        self.root.join("temp").join(format!("{id}{}", names::STORE))
    }

    pub fn open_dir(&self) -> PathBuf {
        self.root.join("open")
    }

    pub fn mount_point(&self, id: &str) -> PathBuf {
        self.open_dir().join(id)
    }

    pub fn lock(&self, id: &str) -> PathBuf {
        self.open_dir().join(format!("{id}.lock"))
    }

    /// The hash of the approved policy an open box runs with, written by the halti that opened it.
    pub fn opened_with(&self, id: &str) -> PathBuf {
        self.open_dir().join(format!("{id}.policy"))
    }

    /// Whether the open box's model takes a bearer token ("1") or a key ("0"), written by the halti
    /// that opened a workspace's box, so a second terminal joins it without reading an approval.
    pub fn bearer(&self, id: &str) -> PathBuf {
        self.open_dir().join(format!("{id}.bearer"))
    }

    pub fn socket(&self, id: &str) -> PathBuf {
        self.sockets.join(format!("{}.sock", self.named(id)))
    }

    /// The folder of the sockets of a VM that the box's engine starts itself (`vmm`): those of
    /// that VM alone, beside the agent's socket. Its name has a dot, which no box name has, so it
    /// is never another box's socket.
    pub fn vm_sockets(&self, id: &str) -> PathBuf {
        self.sockets.join(format!("{}{}", self.named(id), names::VM_SOCKETS))
    }

    /// The socket the door dials for a box whose engine starts its VMs itself: the VM's vsock
    /// device, in its sockets folder.
    pub fn vm_door_socket(&self, id: &str) -> PathBuf {
        self.vm_sockets(id).join(VM_VSOCK)
    }

    /// What such a box's VM printed while it started: its kernel and its shim.
    pub fn console(&self, id: &str) -> PathBuf {
        self.open_dir().join(format!("{id}.console"))
    }

    /// For such a box, written once its start is done, so a second terminal joins only a box
    /// whose home is written: the halti that opened it removes it as it puts the box away.
    pub fn ready(&self, id: &str) -> PathBuf {
        self.open_dir().join(format!("{id}.ready"))
    }

    /// The socket of the box's browser VM, next to the agent's. In a workspace its name has a dot,
    /// which no box name has, so it is never another box's agent socket.
    #[allow(dead_code)] // for the browser VM of box runs
    pub fn browser_socket(&self, id: &str) -> PathBuf {
        match &self.names {
            Names::Keychain => self.sockets.join(format!("{id}-browser.sock")),
            Names::Workspace { .. } => self.sockets.join(format!("{}.browser.sock", self.named(id))),
        }
    }

    /// Where the box's browser VM saves downloads, one folder per site: outside every store, and
    /// mounted into the browser VM only (downloads/<box> under the store root, or the workspace's
    /// boxes folder).
    #[allow(dead_code)] // for the browser VM of box runs
    pub fn downloads(&self, name: &str) -> PathBuf {
        self.downloads.join(name)
    }

    /// The lock `halti open` holds while it keeps the workspace open, in its boxes folder.
    pub fn keeper_lock(&self) -> PathBuf {
        self.root.join(names::KEEPER_LOCK)
    }

    /// The socket of the `halti open` that keeps the workspace open: `TAG.keep.sock`, beside its
    /// boxes' sockets. Today's boxes have none.
    pub fn keeper_socket(&self) -> Option<PathBuf> {
        match &self.names {
            Names::Keychain => None,
            Names::Workspace { tag } => Some(self.sockets.join(format!("{tag}{}", names::KEEP_SOCKET))),
        }
    }

    /// Fails unless both of the box's sockets fit the system's limit: checked before anything opens.
    /// On Linux the socket a box's VM program makes beside the door's, with a port in its name,
    /// must fit Linux's too.
    pub fn sockets_fit(&self, id: &str) -> Result<()> {
        for socket in [self.socket(id), self.browser_socket(id)] {
            let length = socket.as_os_str().len();
            if length > SOCKET_PATH_MAX {
                bail!("socket path {} is too long ({length} bytes, macOS allows {SOCKET_PATH_MAX})", socket.display());
            }
        }
        #[cfg(target_os = "linux")]
        if self.in_workspace() {
            let socket = self.vm_door_socket(id);
            let length = socket.as_os_str().len() + LONGEST_PORT.len();
            if length > LINUX_SOCKET_PATH_MAX {
                bail!("socket path {}{LONGEST_PORT} is too long ({length} bytes, Linux allows {LINUX_SOCKET_PATH_MAX})", socket.display());
            }
        }
        Ok(())
    }

    /// Create the folders a run needs, private to the user. A workspace's sockets folder is in a
    /// folder of its own, made private first.
    pub fn prepare(&self) -> Result<()> {
        let mut dirs = vec![self.root.clone(), self.open_dir(), self.root.join("temp")];
        if self.in_workspace()
            && let Some(parent) = self.sockets.parent()
        {
            dirs.push(parent.to_path_buf());
        }
        dirs.push(self.sockets.clone());
        for dir in &dirs {
            private_dir(dir, self.uid)?;
        }
        Ok(())
    }
}

/// The sockets folder of this build: /tmp/halti-<uid>, /tmp/halti-dev-<uid> for debug builds.
pub(crate) fn sockets(uid: u32) -> PathBuf {
    // Debug builds' VMs publish their sockets apart from an installed halti's.
    PathBuf::from(format!("/tmp/{}-{uid}", if cfg!(halti_dev) { "halti-dev" } else { "halti" }))
}

fn uid() -> Result<u32> {
    let out = Command::new("id").arg("-u").output().context("running id")?;
    String::from_utf8_lossy(&out.stdout).trim().parse().map_err(|_| anyhow!("can't tell the user id"))
}

/// A folder only this user can enter. One that exists must already be ours, not a link, and private.
pub(crate) fn private_dir(dir: &Path, uid: u32) -> Result<()> {
    if let Some(parent) = dir.parent().filter(|p| !p.exists()) {
        fs::create_dir_all(parent)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != uid {
        bail!("{} isn't a folder of yours", dir.display());
    }
    if meta.mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// 256 random bits as 64 hex characters.
pub fn new_key() -> Result<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Run `hdiutil`, with the key (if any) on stdin. Returns what it printed. It needs no terminal, and
/// starts in a process group of its own, so Ctrl-C reaches halti alone and a detach isn't cut off
/// half way.
fn hdiutil(args: &[&std::ffi::OsStr], key: Option<&str>) -> Result<String> {
    let mut child = Command::new("hdiutil")
        .process_group(0)
        .args(args)
        .stdin(if key.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running hdiutil")?;
    if let Some(key) = key {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(key.as_bytes())?;
        stdin.write_all(&[0])?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        bail!("hdiutil {}: {}", args.first().map_or(String::new(), |a| a.to_string_lossy().into_owned()), why.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(target_os = "linux")]
pub use disk::{Open, create, open, shred, usage};

/// What is said, each line a note, about how what `what` names (`box acme/dev keeps`) is kept at
/// rest in the workspace's folder `wsdir`, where halti doesn't encrypt it, and swap that isn't
/// encrypted; with no `what`, the swap alone. Nothing on a Mac, whose stores and swap are
/// encrypted.
pub fn at_rest_notes(what: Option<&str>, wsdir: &Path) -> Vec<String> {
    #[cfg(target_os = "linux")]
    return disk::at_rest_notes(what, wsdir);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (what, wsdir);
        Vec::new()
    }
}

/// Create an empty encrypted store.
#[cfg(not(target_os = "linux"))]
pub fn create(layout: &Layout, bundle: &Path, key: &str) -> Result<()> {
    layout.prepare()?;
    if bundle.exists() {
        bail!("{} already exists", bundle.display());
    }
    let result = hdiutil(
        &[
            "create".as_ref(),
            "-encryption".as_ref(),
            "AES-256".as_ref(),
            "-stdinpass".as_ref(),
            "-type".as_ref(),
            "SPARSEBUNDLE".as_ref(),
            "-fs".as_ref(),
            "APFS".as_ref(),
            "-size".as_ref(),
            SIZE.as_ref(),
            "-volname".as_ref(),
            "box".as_ref(),
            "-quiet".as_ref(),
            bundle.as_os_str(),
        ],
        Some(key),
    );
    match result {
        Ok(_) => fs::set_permissions(bundle, fs::Permissions::from_mode(0o700)).context("securing the store"),
        Err(e) => {
            let _ = fs::remove_dir_all(bundle);
            Err(e)
        }
    }
}

/// Delete a store. Its key goes first (the caller's job); this only removes the ciphertext.
#[cfg(not(target_os = "linux"))]
pub fn shred(bundle: &Path) -> Result<()> {
    match fs::remove_dir_all(bundle) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("deleting {}", bundle.display())),
    }
}

/// Whether a volume is mounted at this path: it is on another device than its parent folder.
pub fn is_mounted(mnt: &Path) -> bool {
    let (Ok(m), Some(Ok(p))) = (fs::metadata(mnt), mnt.parent().map(fs::metadata)) else { return false };
    m.dev() != p.dev()
}

/// Detach the volume at a mount point (`-force` only if it stays busy) and remove the folder.
pub fn detach(mnt: &Path) -> Result<()> {
    if is_mounted(mnt) {
        let polite = (0..5).any(|i| {
            if i > 0 {
                thread::sleep(Duration::from_millis(400));
            }
            hdiutil(&["detach".as_ref(), mnt.as_os_str()], None).is_ok() || !is_mounted(mnt)
        });
        if !polite {
            hdiutil(&["detach".as_ref(), "-force".as_ref(), mnt.as_os_str()], None).with_context(|| format!("detaching {}", mnt.display()))?;
        }
    }
    let _ = fs::remove_dir(mnt);
    Ok(())
}

/// An attached store. Dropping it detaches the volume, and deletes the store if it is to be shredded.
#[cfg(not(target_os = "linux"))]
pub struct Open {
    mnt: PathBuf,
    bundle: PathBuf,
    shred: bool,
}

#[cfg(not(target_os = "linux"))]
impl Open {
    pub fn path(&self) -> &Path {
        &self.mnt
    }

    /// A disk for the box's VM: none, the VM mounts the store's folders.
    #[allow(dead_code)] // for the engine that takes a disk
    pub fn disk(&self) -> Option<&Path> {
        None
    }

    /// Delete the store when this is closed (after detaching it).
    pub fn shred_on_close(&mut self) {
        self.shred = true;
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for Open {
    fn drop(&mut self) {
        match detach(&self.mnt) {
            Ok(()) if self.shred => {
                let _ = shred(&self.bundle);
            }
            Ok(()) => {}
            Err(e) => crate::util::warn(&format!("{e:#} (detach it with: hdiutil detach -force '{}')", self.mnt.display())),
        }
    }
}

/// Attach a store at `mnt`, whose parent must be a private folder. A volume still mounted there is
/// left over from a crash (the caller holds the box's lock, so nobody else uses it) and is
/// detached first. Writable attaches make sure the folders exist.
#[cfg(not(target_os = "linux"))]
pub fn open(bundle: &Path, mnt: &Path, key: &str, readonly: bool) -> Result<Open> {
    if !bundle.exists() {
        bail!("{} doesn't exist", bundle.display());
    }
    detach(mnt)?;
    fs::DirBuilder::new().mode(0o700).create(mnt).with_context(|| format!("creating {}", mnt.display()))?;
    let mut args: Vec<&std::ffi::OsStr> =
        vec!["attach".as_ref(), "-stdinpass".as_ref(), "-nobrowse".as_ref(), "-noautoopen".as_ref(), "-owners".as_ref(), "on".as_ref(), "-mountpoint".as_ref(), mnt.as_os_str()];
    if readonly {
        args.push("-readonly".as_ref());
    }
    args.push(bundle.as_os_str());
    if let Err(e) = hdiutil(&args, Some(key)) {
        let _ = fs::remove_dir(mnt);
        return Err(e.context("opening the store (is the key right?)"));
    }
    let store = Open { mnt: mnt.to_path_buf(), bundle: bundle.to_path_buf(), shred: false };
    if !readonly {
        for folder in FOLDERS {
            fs::create_dir_all(mnt.join(folder))?;
        }
        for private in ["log", "door", "browser"] {
            fs::set_permissions(mnt.join(private), fs::Permissions::from_mode(0o700))?;
        }
        let marker = mnt.join(".metadata_never_index");
        if !marker.exists() {
            File::create(marker)?;
        }
    }
    Ok(store)
}

/// An exclusive lock on a file, held until dropped: one halti process per open box.
pub struct Lock(#[allow(dead_code)] File);

/// Take the lock; `None` if another process holds it. A busy lock is tried again for a moment:
/// a child that one of our threads has forked but not yet exec'd still shares the lock of a
/// file we just let go of. Opening never waits and follows no link: a pipe or a link planted in
/// the lock file's place is refused at once.
pub fn lock(path: &Path) -> Result<Option<Lock>> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    if !file.metadata().with_context(|| format!("reading {}", path.display()))?.is_file() {
        bail!("{} isn't a plain file", path.display());
    }
    for attempt in 0..20 {
        match file.try_lock() {
            Ok(()) => return Ok(Some(Lock(file))),
            Err(TryLockError::WouldBlock) if attempt < 19 => thread::sleep(Duration::from_millis(10)),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(e)) => return Err(e).with_context(|| format!("locking {}", path.display())),
        }
    }
    Ok(None)
}

/// Whether some process holds the lock right now (a missing lock file is nobody's, and so is one
/// that can't be opened).
pub fn is_held(path: &Path) -> bool {
    path.exists() && matches!(lock(path), Ok(None))
}

/// Space the store takes on disk, and when it last changed.
#[cfg(not(target_os = "linux"))]
pub fn usage(bundle: &Path) -> (u64, Option<SystemTime>) {
    let mut bytes = 0;
    let mut newest = None;
    let mut stack = vec![bundle.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                bytes += meta.blocks() * 512;
                let modified = meta.modified().ok();
                newest = newest.max(modified);
            }
        }
    }
    (bytes, newest)
}

/// Append a line to the store's log, in the door's shape: time, kind, path, bytes, decision. The
/// door's lines chain with the same key, so this one is part of the chain too.
pub fn log_event(mnt: &Path, log_key: &[u8; 32], kind: &str, path: &str, bytes: u64, decision: &str) -> Result<()> {
    let line = json!({ "time": Timestamp::now().to_string(), "kind": kind, "path": path, "bytes": bytes, "decision": decision });
    let chain = Chain::new(&door_log(mnt), *log_key);
    chain.create()?;
    chain.append(line)
}

pub fn door_log(mnt: &Path) -> PathBuf {
    mnt.join(DOOR_LOG)
}

/// Where the sealed browser sessions are, one file per site.
pub fn browser_dir(mnt: &Path) -> PathBuf {
    mnt.join("browser")
}

/// Where the box CA is sealed.
pub fn ca_file(mnt: &Path) -> PathBuf {
    mnt.join(CA_FILE)
}

/// What a copy brought over.
pub struct Copied {
    /// Regular files, relative to the destination (just the file's name when one file was copied).
    pub files: Vec<PathBuf>,
    /// Links and special files, which are never followed or copied.
    pub skipped: usize,
}

/// Copy a file or a folder to `dst`, which must not exist. Links, sockets and devices are
/// skipped, never followed, so a link in a box can't make halti read a file outside it. Modes are
/// reduced to rw-r--r-- or rwxr-xr-x.
pub fn copy_tree(src: &Path, dst: &Path) -> Result<Copied> {
    let meta = fs::symlink_metadata(src).with_context(|| format!("reading {}", src.display()))?;
    let mut copied = Copied { files: Vec::new(), skipped: 0 };
    if meta.file_type().is_symlink() {
        bail!("{} is a link; links aren't followed", src.display());
    } else if meta.is_dir() {
        copy_dir(src, dst, Path::new(""), &mut copied)?;
    } else if meta.is_file() {
        copy_file(src, dst, &meta)?;
        copied.files.push(PathBuf::from(dst.file_name().unwrap_or_default()));
    } else {
        bail!("{} isn't a file or folder", src.display());
    }
    Ok(copied)
}

fn copy_dir(src: &Path, dst: &Path, rel: &Path, copied: &mut Copied) -> Result<()> {
    fs::DirBuilder::new().mode(0o755).create(dst).with_context(|| format!("creating {}", dst.display()))?;
    let mut entries: Vec<_> = fs::read_dir(src).with_context(|| format!("reading {}", src.display()))?.collect::<io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let (from, to, rel) = (entry.path(), dst.join(entry.file_name()), rel.join(entry.file_name()));
        let meta = fs::symlink_metadata(&from)?;
        if meta.is_dir() {
            copy_dir(&from, &to, &rel, copied)?;
        } else if meta.is_file() {
            copy_file(&from, &to, &meta)?;
            copied.files.push(rel);
        } else {
            copied.skipped += 1;
        }
    }
    Ok(())
}

fn copy_file(src: &Path, dst: &Path, meta: &fs::Metadata) -> Result<()> {
    let mode = if meta.mode() & 0o111 != 0 { 0o755 } else { 0o644 };
    let mut from = File::open(src).with_context(|| format!("reading {}", src.display()))?;
    let mut to = OpenOptions::new().write(true).create_new(true).mode(mode).open(dst).with_context(|| format!("creating {}", dst.display()))?;
    io::copy(&mut from, &mut to).with_context(|| format!("copying {}", src.display()))?;
    Ok(())
}

/// A folder as a tar stream (POSIX ustar, with a pax header for a long name or a large file), for
/// a box whose disk only it reads, which unpacks it itself: the same files `copy_tree` copies, the
/// same way. Links, sockets and devices are left out, never followed; modes are rw-r--r-- or
/// rwxr-xr-x, owners root's, which an unpacking user that isn't root doesn't keep. Returns the
/// stream and how many were left out.
pub fn tar_tree(src: &Path) -> Result<(Vec<u8>, usize)> {
    let meta = fs::symlink_metadata(src).with_context(|| format!("reading {}", src.display()))?;
    if !meta.is_dir() {
        bail!("{} isn't a folder", src.display());
    }
    let mut tar = Vec::new();
    let mut skipped = 0;
    tar_dir(src, "", &mut tar, &mut skipped)?;
    // The end: two blocks of zeros.
    tar.extend([0u8; 1024]);
    Ok((tar, skipped))
}

fn tar_dir(src: &Path, rel: &str, tar: &mut Vec<u8>, skipped: &mut usize) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(src).with_context(|| format!("reading {}", src.display()))?.collect::<io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let from = entry.path();
        let Some(name) = entry.file_name().to_str().map(|name| format!("{rel}{name}")) else {
            *skipped += 1;
            continue;
        };
        let meta = fs::symlink_metadata(&from)?;
        let mtime = meta.mtime().max(0) as u64;
        if meta.is_dir() {
            tar_header(tar, &format!("{name}/"), 0o755, 0, mtime, b'5');
            tar_dir(&from, &format!("{name}/"), tar, skipped)?;
        } else if meta.is_file() {
            let mut bytes = Vec::new();
            File::open(&from).and_then(|mut file| file.read_to_end(&mut bytes)).with_context(|| format!("reading {}", from.display()))?;
            let mode = if meta.mode() & 0o111 != 0 { 0o755 } else { 0o644 };
            tar_header(tar, &name, mode, bytes.len() as u64, mtime, b'0');
            tar.extend(&bytes);
            tar.resize(tar.len().next_multiple_of(512), 0);
        } else {
            *skipped += 1;
        }
    }
    Ok(())
}

/// One entry's header block, after a pax header where the name or the size doesn't fit ustar's.
fn tar_header(tar: &mut Vec<u8>, name: &str, mode: u32, size: u64, mtime: u64, kind: u8) {
    const MOST_SIZE: u64 = 0o77777777777;
    let long = name.len() > 100;
    if long || size > MOST_SIZE {
        let mut records = String::new();
        if long {
            records += &pax_record("path", name);
        }
        if size > MOST_SIZE {
            records += &pax_record("size", &size.to_string());
        }
        tar_block(tar, "pax", 0o644, records.len() as u64, mtime, b'x');
        tar.extend(records.as_bytes());
        tar.resize(tar.len().next_multiple_of(512), 0);
    }
    // A long name's first 100 bytes stand in for it, for a reader that has no pax.
    tar_block(tar, name, mode, size.min(MOST_SIZE), mtime, kind);
}

/// A pax record, `<length> <key>=<value>\n`, whose length counts itself.
fn pax_record(key: &str, value: &str) -> String {
    let rest = format!(" {key}={value}\n");
    let mut length = rest.len() + 1;
    while length != rest.len() + length.to_string().len() {
        length = rest.len() + length.to_string().len();
    }
    format!("{length}{rest}")
}

fn tar_block(tar: &mut Vec<u8>, name: &str, mode: u32, size: u64, mtime: u64, kind: u8) {
    let mut block = [0u8; 512];
    let put = |block: &mut [u8; 512], at: usize, bytes: &[u8]| block[at..at + bytes.len()].copy_from_slice(bytes);
    let name = name.as_bytes();
    put(&mut block, 0, &name[..name.len().min(100)]);
    put(&mut block, 100, format!("{mode:07o}\0").as_bytes());
    put(&mut block, 108, b"0000000\0");
    put(&mut block, 116, b"0000000\0");
    put(&mut block, 124, format!("{size:011o}\0").as_bytes());
    put(&mut block, 136, format!("{:011o}\0", mtime.min(0o77777777777)).as_bytes());
    put(&mut block, 148, b"        ");
    block[156] = kind;
    put(&mut block, 257, b"ustar\x0000");
    let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
    put(&mut block, 148, format!("{sum:06o}\0 ").as_bytes());
    tar.extend(block);
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::util::TempDir;

    #[test]
    fn makes_random_hex_keys() {
        let (a, b) = (new_key().unwrap(), new_key().unwrap());
        assert!(a.len() == 64 && a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn copies_trees_without_following_links() {
        let dir = TempDir::new("halti-copy").unwrap();
        let src = dir.0.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), "a").unwrap();
        fs::write(src.join("sub/run.sh"), "#!/bin/sh").unwrap();
        fs::set_permissions(src.join("sub/run.sh"), fs::Permissions::from_mode(0o4750)).unwrap();
        fs::write(dir.0.join("secret"), "s3cret").unwrap();
        symlink(dir.0.join("secret"), src.join("link")).unwrap();

        let copied = copy_tree(&src, &dir.0.join("dst")).unwrap();
        assert_eq!(copied.files, [PathBuf::from("a.txt"), PathBuf::from("sub/run.sh")]);
        assert_eq!(copied.skipped, 1);
        assert!(!dir.0.join("dst/link").exists());
        let mode = |p: &str| fs::metadata(dir.0.join(p)).unwrap().mode() & 0o7777;
        assert_eq!((mode("dst/a.txt"), mode("dst/sub/run.sh")), (0o644, 0o755));

        assert!(copy_tree(&src, &dir.0.join("dst")).is_err(), "never merges into an existing folder");
        assert!(copy_tree(&src.join("link"), &dir.0.join("x")).is_err(), "a link as the source");
        let one = copy_tree(&src.join("a.txt"), &dir.0.join("one.txt")).unwrap();
        assert_eq!(one.files, [PathBuf::from("one.txt")]);
        assert!(copy_tree(&src.join("a.txt"), &dir.0.join("one.txt")).is_err(), "never overwrites");
    }

    #[test]
    fn a_tree_is_sent_as_tar_without_links() {
        let dir = TempDir::new("halti-tar").unwrap();
        let src = dir.0.join("src");
        let long = format!("{}/{}", "d".repeat(80), "f".repeat(60));
        fs::create_dir_all(src.join("sub/empty")).unwrap();
        fs::create_dir_all(src.join(&long).parent().unwrap()).unwrap();
        fs::write(src.join("a.txt"), "a").unwrap();
        fs::write(src.join("sub/run.sh"), "#!/bin/sh\n".repeat(100)).unwrap();
        fs::set_permissions(src.join("sub/run.sh"), fs::Permissions::from_mode(0o4750)).unwrap();
        fs::write(src.join(&long), "deep").unwrap();
        fs::write(dir.0.join("secret"), "s3cret").unwrap();
        symlink(dir.0.join("secret"), src.join("link")).unwrap();

        let (tar, skipped) = tar_tree(&src).unwrap();
        assert_eq!(skipped, 1, "the link");
        assert_eq!(tar.len() % 512, 0);
        let out = dir.0.join("out");
        fs::create_dir(&out).unwrap();
        let mut child = Command::new("tar").args(["-x", "-f", "-", "-C"]).arg(&out).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(&tar).unwrap();
        let done = child.wait_with_output().unwrap();
        assert!(done.status.success(), "{}", String::from_utf8_lossy(&done.stderr));
        assert_eq!(fs::read_to_string(out.join("a.txt")).unwrap(), "a");
        assert_eq!(fs::read_to_string(out.join("sub/run.sh")).unwrap(), "#!/bin/sh\n".repeat(100));
        assert_eq!(fs::read_to_string(out.join(&long)).unwrap(), "deep", "a name past 100 bytes");
        assert!(out.join("sub/empty").is_dir() && !out.join("link").exists());
        let mode = |p: &str| fs::metadata(out.join(p)).unwrap().mode() & 0o7777;
        assert_eq!((mode("a.txt"), mode("sub/run.sh")), (0o644, 0o755));
        assert!(tar_tree(&src.join("a.txt")).is_err() && tar_tree(&src.join("link")).is_err(), "a folder only");
        assert_eq!(pax_record("path", "x"), "9 path=x\n", "the length counts itself");
        assert_eq!(pax_record("path", &"y".repeat(95)), format!("105 path={}\n", "y".repeat(95)));
    }

    #[test]
    fn locks_exclude_each_other() {
        let dir = TempDir::new("halti-lock").unwrap();
        let path = dir.0.join("x.lock");
        let first = lock(&path).unwrap().expect("free");
        assert!(lock(&path).unwrap().is_none(), "held");
        drop(first);
        assert!(lock(&path).unwrap().is_some(), "released");
    }

    #[test]
    fn a_pipe_or_a_link_in_a_lock_s_place_is_refused_at_once() {
        let dir = TempDir::new("halti-lock-planted").unwrap();
        // A pipe with no one at the other end: an open that waited would wait for good.
        let fifo = dir.0.join("pipe.lock");
        let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let link = dir.0.join("link.lock");
        symlink(dir.0.join("elsewhere"), &link).unwrap();
        let (sent, got) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = sent.send((lock(&fifo).map(|_| ()), is_held(&fifo), lock(&link).map(|_| ()), is_held(&link)));
        });
        let (pipe, pipe_held, linked, link_held) = got.recv_timeout(Duration::from_secs(10)).expect("refused at once");
        assert!(pipe.is_err() && !pipe_held);
        assert!(linked.is_err() && !link_held);
        assert!(!dir.0.join("elsewhere").exists(), "a link is never followed");
    }

    #[test]
    fn keeps_folders_private() {
        let dir = TempDir::new("halti-private").unwrap();
        let layout = Layout::under(&dir.0).unwrap();
        layout.prepare().unwrap();
        for d in [&layout.root, &layout.open_dir(), &layout.sockets] {
            assert_eq!(fs::metadata(d).unwrap().mode() & 0o777, 0o700, "{}", d.display());
        }
        fs::set_permissions(&layout.sockets, fs::Permissions::from_mode(0o755)).unwrap();
        layout.prepare().unwrap();
        assert_eq!(fs::metadata(&layout.sockets).unwrap().mode() & 0o777, 0o700, "loosened folders are tightened");
        fs::remove_dir(layout.root.join("temp")).unwrap();
        symlink(&dir.0, layout.root.join("temp")).unwrap();
        assert!(layout.prepare().is_err(), "a link where a private folder belongs");
    }

    const ACME: [u8; 16] = [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78];

    #[test]
    fn a_workspace_layout_is_named_apart() {
        let dir = TempDir::new("halti-layout").unwrap();
        // Today's layout gives today's names, byte for byte.
        let today = Layout::under(&dir.0).unwrap();
        assert!(!today.in_workspace());
        assert_eq!((today.vm("dev"), today.browser_vm("dev")), ("halti-box-dev".to_string(), "halti-browser-dev".to_string()));
        assert_eq!((today.vm("dev"), today.browser_vm("dev")), (super::super::run::vm_name("dev"), engine::browser_vm_name("dev")));
        assert_eq!((today.socket("dev"), today.browser_socket("dev")), (dir.0.join("sock/dev.sock"), dir.0.join("sock/dev-browser.sock")));
        assert_eq!((today.downloads("dev"), today.bundle("dev")), (dir.0.join("downloads/dev"), dir.0.join(format!("box/dev{}", names::STORE))));
        assert_eq!((today.lock("dev"), today.opened_with("dev")), (dir.0.join("box/open/dev.lock"), dir.0.join("box/open/dev.policy")));
        let real = Layout::real().unwrap();
        assert_eq!((real.root.clone(), real.downloads("dev")), (store_root().join("box"), store_root().join("downloads/dev")));
        assert_eq!(real.downloads("dev"), real.root.parent().unwrap().join("downloads").join("dev"), "where downloads always were");
        assert_eq!(real.sockets, PathBuf::from(format!("/tmp/halti-dev-{}", real.uid)));
        assert_eq!(real.vm("dev"), "halti-box-dev");

        // A workspace's: its tag in the VMs' and sockets' names, everything else in its boxes folder.
        let acme = Layout::under_workspace(&dir.0, WsId::from_bytes(ACME)).unwrap();
        assert!(acme.in_workspace());
        assert_eq!((acme.vm("dev"), acme.browser_vm("dev")), ("halti-wsbox-abcdef012345-dev".to_string(), "halti-wsbrowser-abcdef012345-dev".to_string()));
        assert_eq!((acme.socket("dev"), acme.browser_socket("dev")), (dir.0.join("sock/ws/abcdef012345-dev.sock"), dir.0.join("sock/ws/abcdef012345-dev.browser.sock")));
        let boxes = dir.0.join("boxes");
        assert_eq!((acme.bundle("dev"), acme.ephemeral_bundle("dev")), (boxes.join(format!("dev{}", names::STORE)), boxes.join(format!("temp/dev{}", names::STORE))));
        assert_eq!((acme.mount_point("dev"), acme.lock("dev"), acme.opened_with("dev")), (boxes.join("open/dev"), boxes.join("open/dev.lock"), boxes.join("open/dev.policy")));
        assert_eq!((acme.bearer("dev"), acme.downloads("dev")), (boxes.join("open/dev.bearer"), boxes.join("downloads/dev")));
        // Box x's browser socket is never box x-browser's agent socket, as today's are.
        assert_eq!(today.browser_socket("x"), today.socket("x-browser"));
        assert_ne!(acme.browser_socket("x"), acme.socket("x-browser"));
        // Another workspace's box of the same name meets nothing of acme's.
        let globex = Layout::under_workspace(&dir.0, WsId::from_bytes([0x02; 16])).unwrap();
        assert_ne!((globex.vm("dev"), globex.browser_vm("dev"), globex.socket("dev")), (acme.vm("dev"), acme.browser_vm("dev"), acme.socket("dev")));
        let real = Layout::workspace(&boxes, WsId::from_bytes(ACME)).unwrap();
        assert_eq!(real.sockets, PathBuf::from(format!("/tmp/halti-dev-{}/ws", real.uid)));
        assert_eq!(real.socket("dev"), PathBuf::from(format!("/tmp/halti-dev-{}/ws/abcdef012345-dev.sock", real.uid)));
        // The socket of the halti that keeps the workspace open is never a box's: no box name has a dot.
        assert_eq!(real.keeper_socket(), Some(PathBuf::from(format!("/tmp/halti-dev-{}/ws/abcdef012345.keep.sock", real.uid))));
        assert_eq!((acme.keeper_lock(), today.keeper_socket()), (boxes.join("keeper.lock"), None));

        // Its sockets' folder is private, and so is the folder it is in.
        acme.prepare().unwrap();
        for d in [&boxes, &boxes.join("open"), &boxes.join("temp"), &dir.0.join("sock"), &dir.0.join("sock/ws")] {
            assert_eq!(fs::metadata(d).unwrap().mode() & 0o777, 0o700, "{}", d.display());
        }
    }

    #[test]
    fn the_longest_sockets_fit() {
        let longest = Layout::of_workspace(Path::new("/x/boxes"), PathBuf::from("/tmp/halti-dev-4294967295/ws"), 4294967295, WsId::from_bytes([0xff; 16]));
        let name = "a".repeat(32);
        assert_eq!((longest.socket(&name).as_os_str().len(), longest.browser_socket(&name).as_os_str().len()), (79, 87));
        longest.sockets_fit(&name).unwrap();
        assert_eq!(longest.vm(&name).len(), 57);
        assert_eq!(longest.browser_vm(&name).len(), 61);
        assert_eq!(longest.keeper_socket().unwrap().as_os_str().len(), 51);
    }

    #[test]
    fn sockets_fit_refuses_104_bytes() {
        // 103 bytes is the most: 104 with the NUL.
        let at = |length: usize| {
            let sockets = PathBuf::from(format!("/{}", "s".repeat(length - "/".len() - "/".len() - "-dev.browser.sock".len() - 12)));
            Layout::of_workspace(Path::new("/x/boxes"), sockets, 501, WsId::from_bytes([0x10; 16]))
        };
        assert_eq!(at(103).browser_socket("dev").as_os_str().len(), 103);
        if cfg!(target_os = "linux") {
            // On Linux the VM program's socket for a port, beside the door's, is longer still.
            let vm = |length: usize| at(length - ("/101010101010-dev.vm/vsock.sock_4294967295".len() - "/101010101010-dev.browser.sock".len()));
            vm(107).sockets_fit("dev").unwrap();
            let error = vm(108).sockets_fit("dev").unwrap_err().to_string();
            assert!(error.starts_with("socket path /sss") && error.ends_with("-dev.vm/vsock.sock_4294967295 is too long (108 bytes, Linux allows 107)"), "{error}");
        } else {
            at(103).sockets_fit("dev").unwrap();
        }
        let error = at(104).sockets_fit("dev").unwrap_err().to_string();
        assert!(error.starts_with("socket path /sss") && error.ends_with(".browser.sock is too long (104 bytes, macOS allows 103)"), "{error}");
        // Today's are checked the same way.
        let dir = TempDir::new("halti-long").unwrap();
        let mut today = Layout::under(&dir.0).unwrap();
        today.sockets = PathBuf::from(format!("/{}", "s".repeat(87)));
        assert!(today.sockets_fit("dev").is_err() && today.sockets_fit("d").is_ok());
    }

    /// The real thing: hdiutil, in a temp folder, with a random key.
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
    fn stores_are_encrypted_and_open_only_with_the_key() {
        let dir = TempDir::new("halti-store").unwrap();
        let layout = Layout::under(&dir.0).unwrap();
        let (key, other) = (new_key().unwrap(), new_key().unwrap());
        let bundle = layout.bundle("t");
        let mnt = layout.mount_point("t");
        create(&layout, &bundle, &key).unwrap();
        assert!(create(&layout, &bundle, &key).is_err(), "never replaces a store");
        assert_eq!(fs::metadata(&bundle).unwrap().mode() & 0o777, 0o700);

        let store = open(&bundle, &mnt, &key, false).unwrap();
        assert!(is_mounted(&mnt));
        for folder in FOLDERS {
            assert!(mnt.join(folder).is_dir(), "{folder}");
        }
        assert!(mnt.join(".metadata_never_index").exists());
        let marker = "MARKER-0123456789-abcdefghijklmnopqrstuvwxyz";
        fs::write(mnt.join("work/note.txt"), marker.repeat(100)).unwrap();
        assert_eq!(fs::metadata(mnt.join("work/note.txt")).unwrap().uid(), fs::metadata(&dir.0).unwrap().uid(), "owners are kept");
        log_event(store.path(), &[7; 32], "export", "work/note.txt", 4300, "allowed").unwrap();
        assert!(fs::read_to_string(door_log(&mnt)).unwrap().contains("\"kind\":\"export\""));
        drop(store);
        assert!(!is_mounted(&mnt) && !mnt.exists());

        // At rest, the bundle holds no plaintext.
        let (bytes, newest) = usage(&bundle);
        assert!(bytes > 0 && newest.is_some());
        let mut stack = vec![bundle.clone()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(d).unwrap().flatten() {
                if e.path().is_dir() {
                    stack.push(e.path());
                } else {
                    let content = fs::read(e.path()).unwrap();
                    assert!(!content.windows(marker.len()).any(|w| w == marker.as_bytes()), "{}", e.path().display());
                }
            }
        }

        assert!(open(&bundle, &mnt, &other, false).is_err(), "a wrong key");
        assert!(!mnt.exists(), "a failed open leaves no mount folder");

        // Read-only attaches refuse writes; a crash's leftover mount is detached by the next open.
        let ro = open(&bundle, &mnt, &key, true).unwrap();
        assert_eq!(fs::read_to_string(mnt.join("work/note.txt")).unwrap().len(), marker.len() * 100);
        assert!(fs::write(mnt.join("work/new.txt"), "x").is_err());
        std::mem::forget(ro);
        assert!(is_mounted(&mnt));
        let mut again = open(&bundle, &mnt, &key, false).unwrap();
        assert!(mnt.join("work/note.txt").exists());
        again.shred_on_close();
        drop(again);
        assert!(!is_mounted(&mnt) && !bundle.exists(), "dropping a shredded store detaches and deletes it");
    }
}
