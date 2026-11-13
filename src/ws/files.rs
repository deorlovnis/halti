//! Where a workspace's files are on this machine, and the three adapters over them: halti's own
//! files (`DirFiles`), the pins (`FileAnchor`) and stored items (`FileKeystore`). The same on macOS
//! and Linux, all under the workspaces folder (`[paths] workspaces`, by default the `ws` folder of
//! the store root):
//!
//! ```text
//! ws/                             0700
//!   dir/NAME                      0600   a directory record
//!   pins/ID                       0600   a pin, its 153 bytes
//!   locks/ID                      0600   the workspace's lock, held with flock; left in place
//!                                        but for the id of a create that failed
//!   ID/                           0700   key, wrap, manifest, policy, log
//!   ID/manifest.next              0600   a manifest replacing the one there, until it takes
//!                                        its place
//!   ID/items/ITEM                 0600   one stored item, named by 64 hex characters
//!   ID/policies/                  0700   the policies, made by `ws policy edit`
//!   ID/policies/RES.toml          0600   a resource's policy, as the editor left it
//!   ID/policies/approved/         0700
//!   ID/policies/approved/RES.toml 0600   the text last approved, written once it was
//!   ID/boxes/                     0700   the workspace's boxes: their stores and runs, and what
//!                                        a run notes in plain files (`Reading`)
//! ```
//!
//! A policy's file is read as halti's own are, and at most 64 KiB of it. Whether a policy is
//! approved is sealed in the manifest; the copy beside it is only what a change is shown against.
//!
//! The workspaces folder is used only if it isn't there yet, or is this user's alone and holds
//! nothing or only what halti puts there (`root_problem`): a folder halti didn't make is never
//! changed or filled. Every folder below it is made private before anything is written in it, and
//! one already there must be this user's and not a link. Files are opened without following a link,
//! and replaced whole: the bytes go to a new file beside the old one, are flushed to disk, and are
//! renamed over it. A name starting with a dot is such a file in the making, never a record or an
//! item.
//!
//! None of this keeps out a program running as you: it can do all of it too. It keeps out other
//! users, accidents and a link planted to make halti write somewhere else, and the labels say no
//! more than that.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use halti_core::anchor::{Anchor, Pin};
use halti_core::directory::DirRecord;
use halti_core::ids::{WsId, WsName};
use halti_core::item::ItemKey;
use halti_core::platform::{Adapter, Grade, Label, Lacks, Property};
use halti_core::policy::Approval;
use halti_core::store::{FileKey, Files, Held, ItemName, KeystoreBackend, KeystoreKind};

/// What `DirFiles` says of itself.
pub const FILES: Label = Label {
    adapter: "dir-files",
    grade: Grade::Weaker,
    lacks: Lacks::of(&[Property::OthersCantTouch, Property::RollbackProof]),
    why: "files in a private folder: a program running as you can read, change or remove them, or put back older copies",
};

/// What `FileAnchor` says of itself.
pub const ANCHOR: Label = Label {
    adapter: "file-anchor",
    grade: Grade::Weaker,
    lacks: Lacks::of(&[Property::OthersCantTouch, Property::RollbackProof]),
    why: "rollback not prevented: the pin is a file, and a program running as you can rewrite it or put back older files",
};

/// What `FileKeystore` says of itself.
pub const KEYSTORE: Label =
    Label { adapter: "file-keystore", grade: Grade::Weaker, lacks: Lacks::of(&[Property::OthersCantTouch]), why: "keystore: files; a program running as you can delete items" };

/// Why halti won't use `root` as the workspaces folder, if it won't. It may not be there yet; one
/// that is must be this user's, not a link, only they can enter it, and it holds nothing or only
/// what halti puts there: `dir`, `pins`, `locks`, a folder for each workspace's id, an earlier
/// build's `mark`, and Finder's `.DS_Store`.
pub fn root_problem(root: &Path) -> Option<&'static str> {
    let meta = match fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(_) => return Some("the workspaces folder can't be read"),
    };
    if !meta.is_dir() || meta.uid() != unsafe { libc::getuid() } {
        return Some("the workspaces folder isn't a folder of yours");
    }
    if meta.mode() & 0o077 != 0 {
        return Some("the workspaces folder is open to other users");
    }
    let Ok(mut found) = fs::read_dir(root) else { return Some("the workspaces folder can't be read") };
    let halti_s = |name: &str| matches!(name, "dir" | "pins" | "locks" | "mark" | ".DS_Store") || unhex::<16>(name).is_some();
    let only_halti_s = found.all(|entry| entry.is_ok_and(|entry| entry.file_name().to_str().is_some_and(halti_s)));
    (!only_halti_s).then_some("the workspaces folder holds files that aren't halti's")
}

/// The workspaces folder, before anything is written in it: made, private, if it isn't there, and
/// otherwise used as it is, only if `root_problem` finds nothing wrong with it.
fn ready_root(root: &Path) -> Result<()> {
    if let Some(why) = root_problem(root) {
        bail!("{why}, so halti didn't write in it. change it with: halti config");
    }
    private_dir(root)
}

/// A folder only this user can enter, made if it isn't there (with any folders above it that
/// aren't). One that is there must be this user's and not a link, and is made private if it isn't:
/// only ever one below the workspaces folder, which `ready_root` has checked.
fn private_dir(dir: &Path) -> Result<()> {
    if let Some(parent) = dir.parent().filter(|p| !p.exists()) {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
    }
    let meta = fs::symlink_metadata(dir).with_context(|| format!("reading {}", dir.display()))?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::getuid() } {
        bail!("{} isn't a folder of yours", dir.display());
    }
    if meta.mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).with_context(|| format!("making {} private", dir.display()))?;
    }
    Ok(())
}

/// The most bytes a file is read with: far more than any file halti writes holds.
const MOST: u64 = 16 << 20;

/// The file's bytes, or none if it isn't there. A link is refused, not followed, and so is
/// anything that isn't a plain file: opening never waits, so a pipe planted in its place is
/// refused at once instead of hanging the command.
fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    let bytes = read_at_most(path, MOST)?;
    if bytes.as_ref().is_some_and(|bytes| bytes.len() as u64 > MOST) {
        bail!("{} is larger than any file halti writes", path.display());
    }
    Ok(bytes)
}

/// As `read`, with at most `most` bytes and one more read: one more says the file is larger.
fn read_at_most(path: &Path, most: u64) -> Result<Option<Vec<u8>>> {
    let file = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    plain(&file, path)?;
    let mut bytes = Vec::new();
    file.take(most + 1).read_to_end(&mut bytes).with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(bytes))
}

/// Refuses an open file that isn't a plain file: a pipe, a device or a folder.
fn plain(file: &File, path: &Path) -> Result<()> {
    if !file.metadata().with_context(|| format!("reading {}", path.display()))?.is_file() {
        bail!("{} isn't a plain file", path.display());
    }
    Ok(())
}

/// Numbers the files in the making of this process.
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// A new 0600 file beside `path` with `bytes` in it, flushed to disk. Its name starts with a dot.
/// A name already taken, by a run cut short that had this process's number, is left alone and the
/// next one tried: only a file this call made is ever removed.
fn beside(path: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let name = path.file_name().and_then(|name| name.to_str()).expect("halti names its own files");
    let mut tries = 0;
    let (new, mut file) = loop {
        let new = path.with_file_name(format!(".{name}.{}-{}", process::id(), COUNT.fetch_add(1, Ordering::Relaxed)));
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&new) {
            Ok(file) => break (new, file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && tries < 16 => tries += 1,
            Err(e) => return Err(e).with_context(|| format!("writing {}", new.display())),
        }
    };
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&new);
        return Err(e).with_context(|| format!("writing {}", new.display()));
    }
    Ok(new)
}

/// Replaces the file whole, or leaves it as it was.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let new = beside(path, bytes)?;
    if let Err(e) = fs::rename(&new, path) {
        let _ = fs::remove_file(&new);
        return Err(e).with_context(|| format!("writing {}", path.display()));
    }
    sync_folder(path);
    Ok(())
}

/// Writes the file whole only if there is none, and says whether it did. A link, not a rename, puts
/// it in place, so a file already there (or a link) is never replaced.
fn create_new(path: &Path, bytes: &[u8]) -> Result<bool> {
    let new = beside(path, bytes)?;
    let linked = fs::hard_link(&new, path);
    let _ = fs::remove_file(&new);
    match linked {
        Ok(()) => {
            sync_folder(path);
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e).with_context(|| format!("writing {}", path.display())),
    }
}

/// Makes a rename or link in the file's folder last through a crash, as far as the system lets a
/// folder be flushed.
fn sync_folder(path: &Path) {
    if let Some(folder) = path.parent() {
        let _ = File::open(folder).and_then(|folder| folder.sync_all());
    }
}

/// Adds the line and a newline to the end of the file, making it if it isn't there. As for a read,
/// a link or anything that isn't a plain file is refused, at once.
fn append(path: &Path, line: &[u8]) -> Result<()> {
    let file = OpenOptions::new().append(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path);
    let mut file = file.with_context(|| format!("opening {}", path.display()))?;
    plain(&file, path)?;
    file.write_all(&[line, b"\n".as_slice()].concat()).with_context(|| format!("writing {}", path.display()))
}

/// Removes the file, and says whether it was there. Its folder must be this user's and not a link,
/// as for a write, so a link planted in place of a folder never takes a file elsewhere with it.
fn remove(path: &Path) -> Result<bool> {
    let folder = path.parent().expect("every file is in a folder under the root");
    match fs::symlink_metadata(folder) {
        Ok(meta) if meta.is_dir() && meta.uid() == unsafe { libc::getuid() } => {}
        Ok(_) => bail!("{} isn't a folder of yours", folder.display()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("reading {}", folder.display())),
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// After `remove` of the file at `path`: what is left of it in the making (`.NAME.*`, from a run
/// cut short) and Finder's `.DS_Store` go, then the folder if nothing else is in it. A folder
/// still holding other files stays; any other failure is said, so nothing claims it gone.
fn tidy(path: &Path) -> Result<()> {
    let folder = path.parent().expect("every file is in a folder under the root");
    let name = path.file_name().and_then(|name| name.to_str()).expect("halti names its own files");
    let making = format!(".{name}.");
    let found = match fs::read_dir(folder) {
        Ok(found) => found,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", folder.display())),
    };
    for entry in found {
        let entry = entry.with_context(|| format!("reading {}", folder.display()))?;
        let left = entry.file_name().to_str().is_some_and(|file| file.starts_with(&making) || file == ".DS_Store");
        if left && entry.file_type().with_context(|| format!("reading {}", folder.display()))?.is_file() {
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("removing {}", entry.path().display())),
            }
        }
    }
    match fs::remove_dir(folder) {
        Ok(()) => Ok(()),
        // POSIX lets a system say a folder isn't empty with EEXIST too.
        Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::AlreadyExists) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", folder.display())),
    }
}

/// The names in a folder, sorted, without those starting with a dot. A folder that isn't there has
/// none; anything in it that isn't a plain file fails the call.
fn entries(dir: &Path) -> Result<Vec<String>> {
    let found = match fs::read_dir(dir) {
        Ok(found) => found,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut names = Vec::new();
    for entry in found {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let name = entry.file_name().into_string().map_err(|_| anyhow!("{} holds a file whose name isn't text", dir.display()))?;
        if name.starts_with('.') {
            continue;
        }
        if !entry.file_type().with_context(|| format!("reading {}", dir.display()))?.is_file() {
            bail!("{} isn't a plain file", entry.path().display());
        }
        names.push(name);
    }
    names.sort();
    Ok(names)
}

/// 2N lowercase hex characters as N bytes, as ids and item names print.
fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = text.as_bytes();
    if text.len() != 2 * N || !text.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut bytes = [0; N];
    for (byte, pair) in bytes.iter_mut().zip(text.chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(bytes)
}

/// Halti's own files of every workspace.
pub struct DirFiles {
    root: PathBuf,
}

impl DirFiles {
    /// Over the workspaces folder `root`. Nothing is made until something is written.
    pub fn at(root: &Path) -> DirFiles {
        DirFiles { root: root.to_path_buf() }
    }

    fn path(&self, k: &FileKey) -> PathBuf {
        let (ws, name) = match k {
            FileKey::DirRecord(name) => return self.root.join("dir").join(name.as_str()),
            FileKey::KeyRef(ws) => (ws, "key"),
            FileKey::Wrap(ws) => (ws, "wrap"),
            FileKey::Manifest(ws) => (ws, "manifest"),
            FileKey::NextManifest(ws) => (ws, "manifest.next"),
            FileKey::Policy(ws) => (ws, "policy"),
            FileKey::Log(ws) => (ws, "log"),
        };
        self.root.join(ws.to_string()).join(name)
    }

    /// Makes the root and the file's folder private, before anything is written in them.
    fn folder_of(&self, path: &Path) -> Result<()> {
        ready_root(&self.root)?;
        private_dir(path.parent().expect("every file is in a folder under the root"))
    }

    fn lock_path(&self, ws: WsId) -> PathBuf {
        self.root.join("locks").join(ws.to_string())
    }

    /// Removes the workspace's lock file, holding the lock as it does, if the file is there and no
    /// one holds it. Only for an id no record names and nothing else will lock: every other lock
    /// file stays, as `lock` leaves it.
    pub fn forget_lock(&self, ws: WsId) -> Result<()> {
        let path = self.lock_path(ws);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        }
        let _held = self.lock(ws)?;
        remove(&path).map(|_| ())
    }
}

impl Adapter for DirFiles {
    fn label(&self) -> Label {
        FILES
    }
}

/// Holds a workspace's lock: closing the file lets it go.
struct Locked(#[allow(dead_code)] File);

impl Held for Locked {}

impl Files for DirFiles {
    fn read(&self, k: &FileKey) -> Result<Option<Vec<u8>>> {
        read(&self.path(k))
    }

    fn write_atomic(&self, k: &FileKey, bytes: &[u8]) -> Result<()> {
        let path = self.path(k);
        self.folder_of(&path)?;
        replace(&path, bytes)
    }

    fn create_new(&self, k: &FileKey, bytes: &[u8]) -> Result<bool> {
        let path = self.path(k);
        self.folder_of(&path)?;
        create_new(&path, bytes)
    }

    fn append(&self, k: &FileKey, line: &[u8]) -> Result<()> {
        let path = self.path(k);
        self.folder_of(&path)?;
        append(&path, line)
    }

    /// A workspace's folder goes with its last file (see `tidy`).
    fn remove(&self, k: &FileKey) -> Result<()> {
        let path = self.path(k);
        remove(&path)?;
        if matches!(k, FileKey::DirRecord(_)) {
            return Ok(());
        }
        tidy(&path)
    }

    fn names(&self) -> Result<Vec<WsName>> {
        let dir = self.root.join("dir");
        entries(&dir)?.iter().map(|name| WsName::parse(name).with_context(|| format!("{} holds a file that isn't a workspace's record", dir.display()))).collect()
    }

    /// Opening never waits: a pipe planted in the lock file's place is refused at once, with or
    /// without a reader. Taking the lock (`flock`) doesn't wait either.
    fn lock(&self, ws: WsId) -> Result<Box<dyn Held>> {
        let path = self.lock_path(ws);
        self.folder_of(&path)?;
        let file = OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path);
        let file = file.with_context(|| format!("opening {}", path.display()))?;
        plain(&file, &path)?;
        match file.try_lock() {
            Ok(()) => Ok(Box::new(Locked(file))),
            Err(TryLockError::WouldBlock) => bail!("workspace {ws} is locked: another halti is using it"),
            Err(TryLockError::Error(e)) => Err(e).with_context(|| format!("locking {}", path.display())),
        }
    }
}

/// Pins in files, one per workspace: a program running as you can rewrite one, and the label says so.
pub struct FileAnchor {
    root: PathBuf,
}

impl FileAnchor {
    /// Over the workspaces folder `root`.
    pub fn at(root: &Path) -> FileAnchor {
        FileAnchor { root: root.to_path_buf() }
    }

    fn path(&self, ws: WsId) -> PathBuf {
        self.root.join("pins").join(ws.to_string())
    }
}

impl Adapter for FileAnchor {
    fn label(&self) -> Label {
        ANCHOR
    }
}

impl Anchor for FileAnchor {
    fn read(&self, ws: WsId) -> Result<Option<Pin>> {
        let path = self.path(ws);
        let Some(bytes) = read(&path)? else { return Ok(None) };
        let pin = Pin::from_bytes(&bytes).with_context(|| format!("{} isn't a pin halti wrote", path.display()))?;
        Ok(Some(pin))
    }

    fn advance(&self, ws: WsId, pin: &Pin) -> Result<()> {
        let kept = self.read(ws)?.map_or(0, |kept| kept.version);
        if pin.version <= kept {
            bail!("pin version {} of workspace {ws} is not above {kept}", pin.version);
        }
        let path = self.path(ws);
        ready_root(&self.root)?;
        private_dir(path.parent().expect("a pin is in the pins folder"))?;
        replace(&path, &pin.to_bytes())
    }

    fn forget(&self, ws: WsId) -> Result<()> {
        remove(&self.path(ws)).map(|_| ())
    }
}

/// Stored items in files, one per item, in the workspace's folder.
pub struct FileKeystore {
    root: PathBuf,
}

impl FileKeystore {
    /// Over the workspaces folder `root`.
    pub fn at(root: &Path) -> FileKeystore {
        FileKeystore { root: root.to_path_buf() }
    }

    fn items(&self, ws: WsId) -> PathBuf {
        self.root.join(ws.to_string()).join("items")
    }
}

impl Adapter for FileKeystore {
    fn label(&self) -> Label {
        KEYSTORE
    }
}

impl KeystoreBackend for FileKeystore {
    fn kind(&self) -> KeystoreKind {
        KeystoreKind::Files
    }

    fn put(&self, ws: WsId, name: &ItemName, blob: &[u8]) -> Result<()> {
        let items = self.items(ws);
        ready_root(&self.root)?;
        for folder in [items.parent().expect("items are in a workspace's folder"), items.as_path()] {
            private_dir(folder)?;
        }
        replace(&items.join(name.to_string()), blob)
    }

    fn get(&self, ws: WsId, name: &ItemName) -> Result<Option<Vec<u8>>> {
        read(&self.items(ws).join(name.to_string()))
    }

    /// The workspace's items folder goes with its last item (see `tidy`).
    fn delete(&self, ws: WsId, name: &ItemName) -> Result<bool> {
        let item = self.items(ws).join(name.to_string());
        let removed = remove(&item)?;
        tidy(&item)?;
        Ok(removed)
    }

    fn list(&self, ws: WsId) -> Result<Vec<ItemName>> {
        let items = self.items(ws);
        entries(&items)?.iter().map(|name| unhex(name).map(ItemName::from_bytes).with_context(|| format!("{} holds a file that isn't an item", items.display()))).collect()
    }
}

/// What a process that has a workspace open reads it again with, and the plain files it keeps
/// beside it: the three adapters over the workspaces folder, and the folders of one workspace. A
/// sealed write goes through core's verbs, never through this.
pub struct Reading {
    files: DirFiles,
    anchor: FileAnchor,
    keystore: FileKeystore,
    root: PathBuf,
}

impl Reading {
    /// Over the workspaces folder `root`.
    #[allow(dead_code)] // for running a workspace's box
    pub fn at(root: &Path) -> Reading {
        Reading { files: DirFiles::at(root), anchor: FileAnchor::at(root), keystore: FileKeystore::at(root), root: root.to_path_buf() }
    }

    pub fn files(&self) -> &dyn Files {
        &self.files
    }

    pub fn anchor(&self) -> &dyn Anchor {
        &self.anchor
    }

    pub fn keystore(&self) -> &dyn KeystoreBackend {
        &self.keystore
    }

    /// The folder of the workspace `ws`: WSDIR.
    pub fn dir(&self, ws: WsId) -> PathBuf {
        self.root.join(ws.to_string())
    }

    /// The folder of its resources' policies: WSDIR/policies.
    pub fn policy_dir(&self, ws: WsId) -> PathBuf {
        PolicyFiles::resources(&self.root, ws).dir().to_path_buf()
    }

    /// A resource's policy, read as `PolicyFiles::read` reads one.
    pub fn policy(&self, ws: WsId, resource: &str) -> Result<Option<Vec<u8>>> {
        ItemKey::check_resource(resource)?;
        PolicyFiles::resources(&self.root, ws).read(resource)
    }

    /// One of the plain files of its boxes' folder (`boxes_dir`), or none if it isn't there.
    pub fn box_file(&self, ws: WsId, file: &str) -> Result<Option<Vec<u8>>> {
        read(&boxes_dir(&self.root, ws).join(file))
    }

    /// Replaces one of the plain files of its boxes' folder whole, 0600: the workspaces folder,
    /// the workspace's and the boxes' folders made private first.
    pub fn put_box_file(&self, ws: WsId, file: &str, bytes: &[u8]) -> Result<()> {
        let boxes = boxes_dir(&self.root, ws);
        ready_root(&self.root)?;
        for folder in [self.dir(ws), boxes.clone()] {
            private_dir(&folder)?;
        }
        replace(&boxes.join(file), bytes)
    }

    /// Removes one of the plain files of its boxes' folder, and says whether it was there.
    pub fn remove_box_file(&self, ws: WsId, file: &str) -> Result<bool> {
        remove(&boxes_dir(&self.root, ws).join(file))
    }
}

/// The folder of a workspace's boxes: WSDIR/boxes, in the workspaces folder `root`. Their
/// policies, stores, locks, mount points, downloads and what their runs note are in it.
pub fn boxes_dir(root: &Path, ws: WsId) -> PathBuf {
    root.join(ws.to_string()).join("boxes")
}

/// One kind's policies in a workspace: DIR/RES.toml, and the copies last approved in
/// DIR/approved/. A policy is named as a resource is (`ItemKey::check_resource`).
pub struct PolicyFiles {
    dir: PathBuf,
    root: PathBuf,
}

impl PolicyFiles {
    /// The policies of a workspace's resources: WSDIR/policies, in the workspaces folder `root`.
    pub fn resources(root: &Path, ws: WsId) -> PolicyFiles {
        PolicyFiles { dir: root.join(ws.to_string()).join("policies"), root: root.to_path_buf() }
    }

    /// The folder they are in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.toml"))
    }

    /// Where the copy kept at the policy's last approval is.
    pub fn copy_path(&self, name: &str) -> PathBuf {
        self.dir.join("approved").join(format!("{name}.toml"))
    }

    /// The workspace's folder, which holds this one.
    fn ws_dir(&self) -> &Path {
        self.dir.parent().expect("a workspace's policies are in its folder")
    }

    /// The names of the `*.toml` files, sorted. A name starting with a dot, and any other name, is
    /// left out: an editor's leftovers (`.github.toml.swp`, `github.toml~`, `4913`) and the
    /// approved copies' folder. A `*.toml` name that isn't a policy's is refused, not left out (on
    /// a disk that ignores case, `GitHub.toml` opens as `github`), and so is one that isn't a plain
    /// file.
    pub fn names(&self) -> Result<Vec<String>> {
        let found = match fs::read_dir(&self.dir) {
            Ok(found) => found,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.dir.display())),
        };
        let mut names = Vec::new();
        for entry in found {
            let entry = entry.with_context(|| format!("reading {}", self.dir.display()))?;
            let name = entry.file_name().into_string().map_err(|_| anyhow!("{} holds a file whose name isn't text", self.dir.display()))?;
            let Some(stem) = name.strip_suffix(".toml").filter(|_| !name.starts_with('.')) else { continue };
            if ItemKey::check_resource(stem).is_err() {
                bail!("{} isn't a policy file name: use a-z, 0-9 and -", entry.path().display());
            }
            if !entry.file_type().with_context(|| format!("reading {}", self.dir.display()))?.is_file() {
                bail!("{} isn't a plain file", entry.path().display());
            }
            names.push(stem.to_string());
        }
        names.sort();
        Ok(names)
    }

    /// The policy's bytes, or none if there is no file: read as `read` does, and refused if it
    /// holds more than a policy can.
    pub fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        read_policy(&self.path(name))
    }

    /// Writes `text` as the policy, only if there is no file: the workspaces folder, the
    /// workspace's and this one made private first. Says whether it wrote it.
    pub fn create(&self, name: &str, text: &str) -> Result<bool> {
        self.ready(&self.dir)?;
        create_new(&self.path(name), text.as_bytes())
    }

    /// The copy kept at the policy's last approval, if there is one.
    pub fn approved_copy(&self, name: &str) -> Result<Option<Vec<u8>>> {
        read_policy(&self.copy_path(name))
    }

    /// Keeps `bytes` as the copy of what was approved, in place of any.
    pub fn keep_approved(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let path = self.copy_path(name);
        self.ready(path.parent().expect("a copy is in the approved folder"))?;
        replace(&path, bytes)
    }

    /// Removes the copy of what was approved, if there is one.
    pub fn forget_approved(&self, name: &str) -> Result<()> {
        remove(&self.copy_path(name)).map(drop)
    }

    /// The workspaces folder and each folder down to `dir`, made private, before anything is
    /// written in it.
    fn ready(&self, dir: &Path) -> Result<()> {
        ready_root(&self.root)?;
        for folder in [self.ws_dir(), self.dir.as_path(), dir] {
            private_dir(folder)?;
        }
        Ok(())
    }

    /// Removes the folder and all in it, then the workspace's folder if nothing else is left in it.
    /// A link or a file in the folder's place is removed itself, and what it points at is left.
    pub fn remove_all(&self) -> Result<()> {
        let ws = self.ws_dir();
        match fs::symlink_metadata(ws) {
            Ok(meta) if meta.is_dir() && meta.uid() == unsafe { libc::getuid() } => {}
            Ok(_) => bail!("{} isn't a folder of yours", ws.display()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", ws.display())),
        }
        match fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.is_dir() => fs::remove_dir_all(&self.dir).with_context(|| format!("removing {}", self.dir.display()))?,
            Ok(_) => fs::remove_file(&self.dir).with_context(|| format!("removing {}", self.dir.display()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.dir.display())),
        }
        tidy(&self.dir)
    }
}

/// A policy's file, read as `read` reads any, and at most a policy's longest text.
fn read_policy(path: &Path) -> Result<Option<Vec<u8>>> {
    let most = Approval::MAX_TEXT as u64;
    let bytes = read_at_most(path, most).map_err(|e| {
        // What O_NOFOLLOW says of a link.
        if e.downcast_ref::<io::Error>().and_then(io::Error::raw_os_error) == Some(libc::ELOOP) { anyhow!("{} isn't a plain file", path.display()) } else { e }
    })?;
    if bytes.as_ref().is_some_and(|bytes| bytes.len() as u64 > most) {
        bail!("{} is larger than 64 KiB", path.display());
    }
    Ok(bytes)
}

/// The workspaces in the folder `root` that are gone but for their policies: id folders that no
/// directory record names and that hold nothing but `policies/` (and Finder's `.DS_Store`). A
/// crash between a workspace's delete and the removal of its policies leaves one. While any record
/// can't be read, none is.
pub fn orphan_policies(root: &Path) -> Result<Vec<WsId>> {
    let files = DirFiles::at(root);
    let mut named = Vec::new();
    for name in files.names()? {
        let Some(record) = files.read(&FileKey::DirRecord(name))?.and_then(|bytes| DirRecord::from_bytes(&bytes).ok()) else { return Ok(Vec::new()) };
        named.push(record.id);
    }
    let found = match fs::read_dir(root) {
        Ok(found) => found,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", root.display())),
    };
    let mut orphans = Vec::new();
    for entry in found {
        let entry = entry.with_context(|| format!("reading {}", root.display()))?;
        let Some(id) = entry.file_name().to_str().and_then(unhex::<16>).map(WsId::from_bytes) else { continue };
        if named.contains(&id) || !entry.file_type().with_context(|| format!("reading {}", root.display()))?.is_dir() {
            continue;
        }
        let inside: Vec<String> = fs::read_dir(entry.path())
            .with_context(|| format!("reading {}", entry.path().display()))?
            .map(|inner| inner.map(|inner| inner.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<_>>()
            .with_context(|| format!("reading {}", entry.path().display()))?;
        if inside.iter().any(|name| name == "policies") && inside.iter().all(|name| name == "policies" || name == ".DS_Store") {
            orphans.push(id);
        }
    }
    orphans.sort();
    Ok(orphans)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    use halti_core::contract::{anchor_contract, files_contract, keystore_contract};
    use halti_core::refusal::Refusal;

    use super::*;
    use crate::util::TempDir;

    #[test]
    fn the_files_on_disk_keep_the_contract() {
        let dir = TempDir::new("halti-ws-files").unwrap();
        files_contract(&DirFiles::at(&dir.0.join("ws")));
    }

    #[test]
    fn the_anchor_on_disk_keeps_the_contract() {
        let dir = TempDir::new("halti-ws-anchor").unwrap();
        anchor_contract(&FileAnchor::at(&dir.0.join("ws")));
    }

    #[test]
    fn the_keystore_on_disk_keeps_the_contract() {
        let dir = TempDir::new("halti-ws-keystore").unwrap();
        keystore_contract(&FileKeystore::at(&dir.0.join("ws")));
    }

    #[test]
    fn folders_and_files_are_private_and_a_planted_link_is_never_followed() {
        let dir = TempDir::new("halti-ws-links").unwrap();
        let root = dir.0.join("ws");
        let files = DirFiles::at(&root);
        let acme = WsId::from_bytes([0x10; 16]);
        let folder = root.join(acme.to_string());
        files.write_atomic(&FileKey::KeyRef(acme), b"key").unwrap();
        let mode = |p: &Path| fs::symlink_metadata(p).unwrap().mode() & 0o777;
        assert_eq!((mode(&root), mode(&folder), mode(&folder.join("key"))), (0o700, 0o700, 0o600));
        // A link where a file is: reading refuses it, and a write replaces the link, never what it points at.
        let outside = dir.0.join("outside");
        fs::write(&outside, b"not halti's").unwrap();
        symlink(&outside, folder.join("wrap")).unwrap();
        assert!(files.read(&FileKey::Wrap(acme)).is_err());
        assert!(!files.create_new(&FileKey::Wrap(acme), b"wrap").unwrap(), "a link is a file that is there");
        files.write_atomic(&FileKey::Wrap(acme), b"wrap").unwrap();
        assert_eq!((fs::read(&outside).unwrap(), fs::read(folder.join("wrap")).unwrap()), (b"not halti's".to_vec(), b"wrap".to_vec()));
        // A link where a folder is: nothing is written through it.
        let globex = WsId::from_bytes([0x02; 16]);
        symlink(&dir.0, root.join(globex.to_string())).unwrap();
        assert!(files.write_atomic(&FileKey::KeyRef(globex), b"key").is_err());
        assert!(!dir.0.join("key").exists());
        fs::write(dir.0.join("wrap"), b"not halti's").unwrap();
        assert!(files.remove(&FileKey::Wrap(globex)).is_err());
        assert!(dir.0.join("wrap").exists(), "nothing is removed through it either");
        // No write leaves a file in the making behind, and a held lock says so at once.
        assert_eq!(fs::read_dir(&folder).unwrap().count(), 2);
        let held = files.lock(acme).unwrap();
        assert!(files.lock(acme).err().unwrap().to_string().contains("is locked: another halti is using it"));
        drop(held);
    }

    #[test]
    fn with_the_ws_folder_a_link_nothing_is_written_through_it() {
        let dir = TempDir::new("halti-ws-root-link").unwrap();
        let (root, elsewhere) = (dir.0.join("ws"), dir.0.join("elsewhere"));
        fs::create_dir(&elsewhere).unwrap();
        symlink(&elsewhere, &root).unwrap();
        let (files, anchor, keystore) = (DirFiles::at(&root), FileAnchor::at(&root), FileKeystore::at(&root));
        let acme = WsId::from_bytes([0x10; 16]);
        assert!(files.write_atomic(&FileKey::KeyRef(acme), b"key").is_err());
        assert!(files.create_new(&FileKey::DirRecord(WsName::parse("acme").unwrap()), b"record").is_err());
        assert!(files.append(&FileKey::Log(acme), b"line").is_err());
        assert!(files.lock(acme).is_err());
        assert!(anchor.advance(acme, &Pin { version: 1, key_ref: [1; 48], public_key: [2; 48], state: [3; 48] }).is_err());
        assert!(keystore.put(acme, &ItemName::from_bytes([0x07; 32]), b"acme's").is_err());
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0, "nothing was written through the link");
        // Removing a pin or an item checks only the folder it is in, so through this link it would
        // reach: what stops a delete is the workspace's lock, which core takes before either, and
        // which is refused above.
    }

    #[test]
    fn a_link_planted_at_any_folder_or_file_halti_writes_is_refused() {
        let dir = TempDir::new("halti-ws-sub-links").unwrap();
        let root = dir.0.join("ws");
        let (files, anchor, keystore) = (DirFiles::at(&root), FileAnchor::at(&root), FileKeystore::at(&root));
        let acme = WsId::from_bytes([0x10; 16]);
        files.write_atomic(&FileKey::KeyRef(acme), b"key").unwrap();
        let (outside, file) = (dir.0.join("outside"), dir.0.join("outside-file"));
        fs::create_dir(&outside).unwrap();
        fs::write(&file, b"not halti's").unwrap();
        for folder in [root.join("dir"), root.join("pins"), root.join("locks"), root.join(acme.to_string()).join("items")] {
            symlink(&outside, folder).unwrap();
        }
        symlink(&file, root.join(acme.to_string()).join("log")).unwrap();
        assert!(files.write_atomic(&FileKey::DirRecord(WsName::parse("acme").unwrap()), b"record").is_err());
        assert!(anchor.advance(acme, &Pin { version: 1, key_ref: [1; 48], public_key: [2; 48], state: [3; 48] }).is_err());
        assert!(files.lock(acme).is_err());
        assert!(keystore.put(acme, &ItemName::from_bytes([0x07; 32]), b"acme's").is_err());
        assert!(files.append(&FileKey::Log(acme), b"line").is_err());
        // A link where the lock file is.
        fs::remove_file(root.join("locks")).unwrap();
        fs::create_dir(root.join("locks")).unwrap();
        symlink(&file, root.join("locks").join(acme.to_string())).unwrap();
        assert!(files.lock(acme).is_err());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        assert_eq!(fs::read(&file).unwrap(), b"not halti's");
    }

    #[test]
    fn a_workspaces_folder_halti_did_not_make_is_never_changed_or_filled() {
        let dir = TempDir::new("halti-ws-root").unwrap();
        let root = dir.0.join("ws");
        let (acme, globex) = (WsId::from_bytes([0x10; 16]), WsId::from_bytes([0x02; 16]));
        // Not there yet, or there, private and empty: used.
        assert_eq!(root_problem(&root), None);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(root_problem(&root), None);
        // Holding only what halti puts there: used.
        DirFiles::at(&root).write_atomic(&FileKey::DirRecord(WsName::parse("acme").unwrap()), b"record").unwrap();
        DirFiles::at(&root).write_atomic(&FileKey::KeyRef(acme), b"key").unwrap();
        FileAnchor::at(&root).advance(acme, &Pin { version: 1, key_ref: [1; 48], public_key: [2; 48], state: [3; 48] }).unwrap();
        drop(DirFiles::at(&root).lock(acme).unwrap());
        fs::write(root.join(".DS_Store"), b"finder's").unwrap();
        assert_eq!(root_problem(&root), None);
        // A file of someone else's in it: nothing more is written there.
        fs::write(root.join("notes.txt"), b"mine").unwrap();
        assert_eq!(root_problem(&root), Some("the workspaces folder holds files that aren't halti's"));
        let error = DirFiles::at(&root).write_atomic(&FileKey::KeyRef(globex), b"key").unwrap_err();
        assert_eq!(error.to_string(), "the workspaces folder holds files that aren't halti's, so halti didn't write in it. change it with: halti config");
        assert!(!root.join(globex.to_string()).exists());

        // One open to others is refused, and left open and empty.
        let shared = dir.0.join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(root_problem(&shared), Some("the workspaces folder is open to other users"));
        assert!(DirFiles::at(&shared).lock(acme).is_err());
        assert!(FileAnchor::at(&shared).advance(acme, &Pin { version: 1, key_ref: [1; 48], public_key: [2; 48], state: [3; 48] }).is_err());
        assert!(FileKeystore::at(&shared).put(acme, &ItemName::from_bytes([0x07; 32]), b"acme's").is_err());
        assert_eq!((fs::symlink_metadata(&shared).unwrap().mode() & 0o777, fs::read_dir(&shared).unwrap().count()), (0o755, 0));
        // A file in its place is no folder of yours.
        fs::write(dir.0.join("plain"), b"").unwrap();
        assert_eq!(root_problem(&dir.0.join("plain")), Some("the workspaces folder isn't a folder of yours"));
    }

    #[test]
    fn a_pipe_or_an_oversized_file_is_refused_at_once() {
        let dir = TempDir::new("halti-ws-fifo").unwrap();
        let root = dir.0.join("ws");
        let files = DirFiles::at(&root);
        let globex = WsId::from_bytes([0x02; 16]);
        files.write_atomic(&FileKey::KeyRef(globex), b"key").unwrap();
        fs::create_dir_all(root.join("dir")).unwrap();
        fs::create_dir_all(root.join("locks")).unwrap();
        // Pipes with no one at the other end: an open that waited would wait for good.
        let fifo = |path: PathBuf| {
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        };
        fifo(root.join("dir/initech"));
        fifo(root.join(globex.to_string()).join("log"));
        fifo(root.join("locks").join(globex.to_string()));
        let error = files.read(&FileKey::DirRecord(WsName::parse("initech").unwrap())).unwrap_err();
        assert!(error.to_string().contains("isn't a plain file"), "{error:#}");
        assert!(files.append(&FileKey::Log(globex), b"line").is_err());
        assert!(files.lock(globex).is_err());
        // A plain file larger than any halti writes is refused, not read whole.
        File::create(root.join("dir/acme")).unwrap().set_len(MOST + 1).unwrap();
        let error = files.read(&FileKey::DirRecord(WsName::parse("acme").unwrap())).unwrap_err();
        assert!(error.to_string().contains("is larger than any file halti writes"), "{error:#}");
    }

    #[test]
    fn a_file_in_the_making_left_by_a_run_with_this_number_is_never_removed() {
        let dir = TempDir::new("halti-ws-strays").unwrap();
        let files = DirFiles::at(&dir.0.join("ws"));
        let acme = WsId::from_bytes([0x10; 16]);
        files.write_atomic(&FileKey::KeyRef(acme), b"old").unwrap();
        // Left under the next names this process takes, by a run cut short whose process had its number.
        let folder = dir.0.join("ws").join(acme.to_string());
        let next = COUNT.load(Ordering::Relaxed);
        let strays: Vec<PathBuf> = (next..next + 4).map(|n| folder.join(format!(".key.{}-{n}", process::id()))).collect();
        for stray in &strays {
            fs::write(stray, b"not this run's").unwrap();
        }
        files.write_atomic(&FileKey::KeyRef(acme), b"new").unwrap();
        assert_eq!(fs::read(folder.join("key")).unwrap(), b"new");
        assert!(strays.iter().all(|stray| fs::read(stray).unwrap() == b"not this run's"), "each is left as it was");
    }

    #[test]
    fn a_workspace_folder_goes_with_its_last_file_and_what_was_left_half_written() {
        let dir = TempDir::new("halti-ws-tidy").unwrap();
        let root = dir.0.join("ws");
        let (files, keystore) = (DirFiles::at(&root), FileKeystore::at(&root));
        let acme = WsId::from_bytes([0x10; 16]);
        let all = [FileKey::Wrap(acme), FileKey::KeyRef(acme), FileKey::Manifest(acme), FileKey::NextManifest(acme), FileKey::Policy(acme), FileKey::Log(acme)];
        for file in &all {
            files.write_atomic(file, b"written").unwrap();
        }
        let item = ItemName::from_bytes([0x07; 32]);
        keystore.put(acme, &item, b"acme's").unwrap();
        // A key record cut short before its rename, an item's, and Finder's litter in both folders.
        let folder = root.join(acme.to_string());
        for left in [folder.join(".key.4242-0"), folder.join(".DS_Store"), folder.join("items/.DS_Store"), folder.join(format!("items/.{item}.4242-0"))] {
            fs::write(left, b"left").unwrap();
        }
        assert!(keystore.delete(acme, &item).unwrap());
        assert!(!folder.join("items").exists());
        for file in &all {
            files.remove(file).unwrap();
        }
        assert!(!folder.exists());
        // A file that isn't halti's keeps the folder, and is left as it is.
        files.write_atomic(&FileKey::KeyRef(acme), b"written").unwrap();
        fs::write(folder.join("notes"), b"mine").unwrap();
        files.remove(&FileKey::KeyRef(acme)).unwrap();
        assert_eq!(fs::read(folder.join("notes")).unwrap(), b"mine");
    }

    #[test]
    fn a_lock_file_is_forgotten_only_while_no_one_holds_it() {
        let dir = TempDir::new("halti-ws-forget-lock").unwrap();
        let files = DirFiles::at(&dir.0.join("ws"));
        let acme = WsId::from_bytes([0x10; 16]);
        files.forget_lock(acme).unwrap();
        assert!(!dir.0.join("ws").exists(), "with no lock file, nothing is made");
        let path = dir.0.join("ws/locks").join(acme.to_string());
        let held = files.lock(acme).unwrap();
        assert!(files.forget_lock(acme).is_err() && path.exists(), "it is held");
        drop(held);
        files.forget_lock(acme).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn policy_files_list_only_policy_names() {
        let dir = TempDir::new("halti-ws-policy-names").unwrap();
        let root = dir.0.join("ws");
        let acme = WsId::from_bytes([0x10; 16]);
        let policies = PolicyFiles::resources(&root, acme);
        assert_eq!(policies.names().unwrap(), Vec::<String>::new(), "no folder yet: none");
        assert!(policies.create("github", "[fetch]\n").unwrap());
        assert!(!policies.create("github", "another\n").unwrap(), "a file there is never replaced");
        assert_eq!(policies.read("github").unwrap().as_deref(), Some(&b"[fetch]\n"[..]));
        policies.keep_approved("github", b"[fetch]\n").unwrap();
        // An editor's leftovers, and the approved copies' folder, are no policies.
        let folder = root.join(acme.to_string()).join("policies");
        for left in [".github.toml.swp", "github.toml~", "4913", ".DS_Store"] {
            fs::write(folder.join(left), b"left").unwrap();
        }
        assert_eq!(policies.names().unwrap(), ["github"]);
        let mode = |p: &Path| fs::symlink_metadata(p).unwrap().mode() & 0o777;
        assert_eq!((mode(&folder), mode(&folder.join("github.toml")), mode(&folder.join("approved")), mode(&folder.join("approved/github.toml"))), (0o700, 0o600, 0o700, 0o600));
        // A name that isn't a policy's is refused, not left out: on a disk that ignores case it would open as github.
        fs::write(folder.join("Git.toml"), b"[fetch]\n").unwrap();
        let error = policies.names().unwrap_err().to_string();
        assert_eq!(error, format!("{} isn't a policy file name: use a-z, 0-9 and -", folder.join("Git.toml").display()));
        fs::remove_file(folder.join("Git.toml")).unwrap();
        // So is a link, whatever it points at.
        symlink(folder.join("github.toml"), folder.join("x.toml")).unwrap();
        assert_eq!(policies.names().unwrap_err().to_string(), format!("{} isn't a plain file", folder.join("x.toml").display()));
    }

    #[test]
    fn policy_files_never_follow_a_link_at_a_file_and_go_with_their_workspace() {
        let dir = TempDir::new("halti-ws-policy-links").unwrap();
        let root = dir.0.join("ws");
        let acme = WsId::from_bytes([0x10; 16]);
        let policies = PolicyFiles::resources(&root, acme);
        policies.create("linear", "[fetch]\n").unwrap();
        let folder = root.join(acme.to_string()).join("policies");
        let outside = dir.0.join("outside.toml");
        fs::write(&outside, b"[fetch]\nhosts = [\"https://evil.example\"]\n").unwrap();
        // A link at a file: refused when read, as a policy or as its approved copy.
        symlink(&outside, folder.join("github.toml")).unwrap();
        assert_eq!(policies.read("github").unwrap_err().to_string(), format!("{} isn't a plain file", folder.join("github.toml").display()));
        fs::create_dir(folder.join("approved")).unwrap();
        symlink(&outside, folder.join("approved/github.toml")).unwrap();
        assert!(policies.approved_copy("github").is_err());
        // Larger than a policy can be: refused, not read whole.
        File::create(folder.join("big.toml")).unwrap().set_len(65537).unwrap();
        assert_eq!(policies.read("big").unwrap_err().to_string(), format!("{} is larger than 64 KiB", folder.join("big.toml").display()));
        File::create(folder.join("big.toml")).unwrap().set_len(65536).unwrap();
        assert_eq!(policies.read("big").unwrap().map(|bytes| bytes.len()), Some(65536));
        assert_eq!(policies.read("slack").unwrap(), None);
        // Removing them all takes leftovers and the workspace's folder, and leaves what a link pointed at.
        fs::write(folder.join(".linear.toml.swp"), b"left").unwrap();
        policies.remove_all().unwrap();
        assert!(!root.join(acme.to_string()).exists() && outside.exists());
        policies.remove_all().unwrap();
        // A link in the folder's place is unlinked, and what it points at is left.
        let elsewhere = dir.0.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::write(elsewhere.join("github.toml"), b"not halti's").unwrap();
        fs::create_dir_all(root.join(acme.to_string())).unwrap();
        fs::write(root.join(acme.to_string()).join("key"), b"key").unwrap();
        symlink(&elsewhere, &folder).unwrap();
        assert!(policies.create("github", "x").is_err(), "nothing is written through it");
        policies.remove_all().unwrap();
        assert!(fs::symlink_metadata(&folder).is_err() && elsewhere.join("github.toml").exists());
        assert!(root.join(acme.to_string()).join("key").exists(), "a workspace's folder with other files in it stays");
        // A link in the workspace's folder's place: nothing is removed through it.
        let globex = WsId::from_bytes([0x02; 16]);
        fs::create_dir(elsewhere.join("policies")).unwrap();
        symlink(&elsewhere, root.join(globex.to_string())).unwrap();
        assert!(PolicyFiles::resources(&root, globex).remove_all().is_err());
        assert!(elsewhere.join("policies").exists());
    }

    #[test]
    fn orphaned_policies_are_found() {
        let dir = TempDir::new("halti-ws-orphans").unwrap();
        let root = dir.0.join("ws");
        assert_eq!(orphan_policies(&root).unwrap(), []);
        let files = DirFiles::at(&root);
        let (acme, globex, initech) = (WsId::from_bytes([0x10; 16]), WsId::from_bytes([0x02; 16]), WsId::from_bytes([0x03; 16]));
        let record = |id: WsId| DirRecord { id, key: halti_core::holder::KeyKind::Passphrase, keystore: KeystoreKind::Files }.to_bytes();
        files.write_atomic(&FileKey::DirRecord(WsName::parse("acme").unwrap()), &record(acme)).unwrap();
        for id in [acme, globex, initech] {
            PolicyFiles::resources(&root, id).create("github", "[fetch]\n").unwrap();
        }
        fs::write(root.join(globex.to_string()).join(".DS_Store"), b"finder's").unwrap();
        // initech has other files beside its policies: not only policies are left of it.
        files.write_atomic(&FileKey::KeyRef(initech), b"key").unwrap();
        assert_eq!(orphan_policies(&root).unwrap(), [globex], "acme has a record");
        // While a record can't be read, it could name any: none is an orphan.
        fs::write(root.join("dir/umbrella"), b"not a record").unwrap();
        assert_eq!(orphan_policies(&root).unwrap(), []);
    }

    #[test]
    fn a_pin_file_is_its_153_bytes_and_any_other_is_refused() {
        let dir = TempDir::new("halti-ws-pin").unwrap();
        let anchor = FileAnchor::at(&dir.0.join("ws"));
        let acme = WsId::from_bytes([0x10; 16]);
        let pin = Pin { version: 1, key_ref: [1; 48], public_key: [2; 48], state: [3; 48] };
        anchor.advance(acme, &pin).unwrap();
        let path = dir.0.join("ws/pins").join(acme.to_string());
        assert_eq!(fs::read(&path).unwrap(), pin.to_bytes());
        fs::write(&path, &pin.to_bytes()[..152]).unwrap();
        let error = anchor.read(acme).unwrap_err();
        assert_eq!(error.downcast_ref::<Refusal>(), Some(&Refusal::Unreadable), "{error:#}");
    }

    #[test]
    fn a_listing_skips_files_in_the_making_and_refuses_anything_else() {
        let dir = TempDir::new("halti-ws-names").unwrap();
        let files = DirFiles::at(&dir.0.join("ws"));
        files.write_atomic(&FileKey::DirRecord(WsName::parse("acme").unwrap()), b"record").unwrap();
        fs::write(dir.0.join("ws/dir/.acme.4242-0"), b"half").unwrap();
        assert_eq!(files.names().unwrap(), [WsName::parse("acme").unwrap()]);
        fs::write(dir.0.join("ws/dir/Globex"), b"record").unwrap();
        assert!(files.names().is_err(), "a file that isn't a record fails the list, and never drops out of it");
        let keystore = FileKeystore::at(&dir.0.join("ws"));
        let acme = WsId::from_bytes([0x10; 16]);
        keystore.put(acme, &ItemName::from_bytes([0x07; 32]), b"acme's").unwrap();
        fs::write(dir.0.join("ws").join(acme.to_string()).join("items/initech"), b"").unwrap();
        assert!(keystore.list(acme).is_err());
    }
}
