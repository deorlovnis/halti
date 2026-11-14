//! A box's store on Linux: the box's disk, one ext4 file system in a sparse file (`BOX.img`) that
//! only the box's VM mounts, and beside it a private folder of halti's own files for the box
//! (`BOX.d`): its door log, its CA sealed with the box key, and its sealed browser sessions.
//!
//! halti encrypts neither: what the agent keeps on the disk is as safe at rest as the server's own
//! disk under it. The key a store is made and opened with is not used here; halti seals the box's
//! CA and sessions with it, as on a Mac. The server never mounts the disk: halti makes it, hands it
//! to the box's VM and removes it, and the box's kernel is the only one that reads it.
//!
//! The disk is made first and removed last, so a store half made or half removed still has its
//! disk, by whose name every store is found (`names::STORE`).
#![cfg_attr(not(target_os = "linux"), allow(dead_code))] // the store of a Linux build

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use anyhow::{Context, Result, bail};

use super::{FOLDERS, Layout, private_dir};
use crate::names;

/// The most a box's disk can hold: the file is sparse and starts at a few MB.
const SIZE: u64 = 100 << 30;
/// halti's folders of a store, here in the folder beside the disk. The disk's own (home, work,
/// downloads) are made by the shim inside the box.
const OWN: [&str; 3] = [FOLDERS[3], FOLDERS[4], FOLDERS[5]];
/// Where mkfs.ext4 is, ahead of the PATH, which leaves out the system's folders for some users.
const MKFS: [&str; 2] = ["/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"];

/// The folder of halti's files for the store whose disk is `disk`: `BOX.d` beside `BOX.img`.
fn files_of(disk: &Path) -> PathBuf {
    let name = disk.file_name().unwrap_or_default().to_string_lossy();
    let stem = name.strip_suffix(names::STORE).unwrap_or(&name);
    disk.with_file_name(format!("{stem}{}", names::STORE_FILES))
}

/// Make an empty store: the disk, with an empty ext4 file system whose top folder is root's, then
/// the folder of halti's files. A folder left there without a disk belongs to no store, and goes
/// first. A store that fails half way is removed.
pub fn create(layout: &Layout, disk: &Path, _key: &str) -> Result<()> {
    layout.prepare()?;
    if fs::symlink_metadata(disk).is_ok() {
        bail!("{} already exists", disk.display());
    }
    remove(&files_of(disk))?;
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(disk).with_context(|| format!("creating {}", disk.display()))?;
    let sized = file.set_len(SIZE).with_context(|| format!("sizing {}", disk.display()));
    drop(file);
    let made = sized.and_then(|()| mkfs(disk)).and_then(|()| own_files(disk).map(drop));
    if made.is_err() {
        let _ = shred(disk);
    }
    made
}

/// An empty ext4 file system in the file `disk`, written in place: what mkfs.ext4 doesn't write
/// stays a hole in the file. It needs no terminal, and starts in a process group of its own, so
/// Ctrl-C reaches halti alone.
fn mkfs(disk: &Path) -> Result<()> {
    let program = MKFS.iter().map(Path::new).find(|p| p.is_file()).unwrap_or(Path::new("mkfs.ext4"));
    let out = Command::new(program)
        .process_group(0)
        .args(["-q", "-F", "-m", "0", "-E", "root_owner=0:0,lazy_itable_init=1,lazy_journal_init=1"])
        .arg(disk)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {}", program.display()))?;
    if !out.status.success() {
        bail!("mkfs.ext4: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// The folder of halti's files and its folders, private to the user. One that is there must
/// already be ours, not a link, and private.
fn own_files(disk: &Path) -> Result<PathBuf> {
    // SAFETY: getuid(2) can't fail.
    let uid = unsafe { libc::getuid() };
    let files = files_of(disk);
    private_dir(&files, uid)?;
    for folder in OWN {
        private_dir(&files.join(folder), uid)?;
    }
    Ok(files)
}

/// Remove a file or a folder (a link itself, never what it points at); one that isn't there is fine.
fn remove(path: &Path) -> Result<()> {
    let removed = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) => Err(e),
    };
    match removed {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e).with_context(|| format!("deleting {}", path.display())),
        _ => Ok(()),
    }
}

/// Delete a store: the folder of halti's files, then the disk.
pub fn shred(disk: &Path) -> Result<()> {
    remove(&files_of(disk))?;
    remove(disk)
}

/// An open store. Dropping it deletes the store if it is to be shredded.
pub struct Open {
    files: PathBuf,
    disk: PathBuf,
    shred: bool,
}

impl Open {
    /// The folder of halti's files for the box.
    pub fn path(&self) -> &Path {
        &self.files
    }

    /// The disk, which the box's VM is given.
    #[allow(dead_code)] // for the engine that takes a disk
    pub fn disk(&self) -> Option<&Path> {
        Some(&self.disk)
    }

    /// Delete the store when this is closed.
    pub fn shred_on_close(&mut self) {
        self.shred = true;
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        if self.shred
            && let Err(e) = shred(&self.disk)
        {
            crate::util::warn(&format!("{e:#}"));
        }
    }
}

/// Open a store: nothing is mounted, so `mnt` and the key are not used. The disk must be a plain
/// file, never a link: the VM is given it to write. Writable opens make sure halti's folders exist.
pub fn open(disk: &Path, _mnt: &Path, _key: &str, readonly: bool) -> Result<Open> {
    match fs::symlink_metadata(disk) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => bail!("{} isn't a plain file", disk.display()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => bail!("{} doesn't exist", disk.display()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", disk.display())),
    }
    let files = if readonly { files_of(disk) } else { own_files(disk)? };
    Ok(Open { files, disk: disk.to_path_buf(), shred: false })
}

/// Space the store takes on disk (the disk's blocks in use, not its size, and halti's files), and
/// when it last changed.
pub fn usage(disk: &Path) -> (u64, Option<SystemTime>) {
    let mut bytes = 0;
    let mut newest = None;
    let mut stack = vec![disk.to_path_buf(), files_of(disk)];
    while let Some(path) = stack.pop() {
        let Ok(meta) = fs::symlink_metadata(&path) else { continue };
        if meta.is_dir() {
            stack.extend(fs::read_dir(&path).into_iter().flatten().flatten().map(|entry| entry.path()));
        } else {
            bytes += meta.blocks() * 512;
            newest = newest.max(meta.modified().ok());
        }
    }
    (bytes, newest)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;
    use crate::util::TempDir;

    #[test]
    fn halti_s_folders_are_the_store_s_own() {
        assert_eq!(OWN, ["log", "door", "browser"]);
        let disk = Path::new("/w/boxes/dev").with_extension(&names::STORE[1..]);
        assert_eq!(files_of(&disk), Path::new("/w/boxes/dev").with_extension(&names::STORE_FILES[1..]));
    }

    /// The store as halti finds it, made by hand: a disk that is a file of some blocks, and a log.
    fn by_hand(dir: &Path, name: &str) -> PathBuf {
        let disk = dir.join(format!("{name}{}", names::STORE));
        fs::write(&disk, vec![7; 64 << 10]).unwrap();
        fs::create_dir_all(files_of(&disk).join("log")).unwrap();
        fs::write(files_of(&disk).join("log/door.log"), "logged\n").unwrap();
        disk
    }

    #[test]
    fn shredding_removes_both() {
        let dir = TempDir::new("halti-disk-shred").unwrap();
        let disk = by_hand(&dir.0, "dev");
        shred(&disk).unwrap();
        assert!(!disk.exists() && !files_of(&disk).exists());
        shred(&disk).unwrap();
        // A link in either's place goes, and what it points at stays.
        let kept = by_hand(&dir.0, "kept");
        symlink(&kept, &disk).unwrap();
        symlink(files_of(&kept), files_of(&disk)).unwrap();
        shred(&disk).unwrap();
        assert!(fs::symlink_metadata(&disk).is_err() && fs::symlink_metadata(files_of(&disk)).is_err());
        assert!(kept.is_file() && files_of(&kept).join("log/door.log").is_file());
        // A store made as a folder by hand goes too.
        fs::create_dir_all(disk.join("inside")).unwrap();
        shred(&disk).unwrap();
        assert!(!disk.exists());
        // Dropping an open store that is to be shredded removes both.
        let temp = by_hand(&dir.0, "temp");
        let mut open = open(&temp, &dir.0.join("open/temp"), "", false).unwrap();
        open.shred_on_close();
        drop(open);
        assert!(!temp.exists() && !files_of(&temp).exists());
    }

    #[test]
    fn usage_counts_the_image_s_blocks() {
        let dir = TempDir::new("halti-disk-usage").unwrap();
        let disk = by_hand(&dir.0, "dev");
        let (bytes, newest) = usage(&disk);
        let blocks = |p: &Path| fs::metadata(p).unwrap().blocks() * 512;
        assert_eq!(bytes, blocks(&disk) + blocks(&files_of(&disk).join("log/door.log")));
        assert!(bytes >= 64 << 10 && newest.is_some());
        // A sparse disk counts what it holds, not its size.
        let sparse = dir.0.join(format!("sparse{}", names::STORE));
        fs::File::create(&sparse).unwrap().set_len(SIZE).unwrap();
        assert!(usage(&sparse).0 < 1 << 20);
        assert_eq!(usage(&dir.0.join("none.img")), (0, None));
    }

    #[test]
    fn an_open_store_is_the_disk_and_halti_s_folder() {
        let dir = TempDir::new("halti-disk-open").unwrap();
        let disk = dir.0.join(format!("dev{}", names::STORE));
        let mnt = dir.0.join("open/dev");
        let refused = |disk: &Path| open(disk, &mnt, "", false).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(refused(&disk).ends_with("doesn't exist"));
        fs::write(&disk, b"").unwrap();
        // Read only: nothing is made.
        let read = open(&disk, &mnt, "", true).unwrap();
        assert_eq!((read.path(), read.disk()), (files_of(&disk).as_path(), Some(disk.as_path())));
        assert!(!files_of(&disk).exists());
        drop(read);
        let store = open(&disk, &mnt, "", false).unwrap();
        for folder in [PathBuf::new()].into_iter().chain(OWN.map(PathBuf::from)) {
            let meta = fs::symlink_metadata(store.path().join(&folder)).unwrap();
            assert!(meta.is_dir() && meta.mode() & 0o777 == 0o700, "{}", folder.display());
        }
        drop(store);
        assert!(disk.exists() && files_of(&disk).exists(), "a kept store stays");
        assert!(!mnt.exists(), "nothing is mounted");
        // A loosened folder is made private again; a link in the disk's place is refused.
        fs::set_permissions(files_of(&disk), fs::Permissions::from_mode(0o755)).unwrap();
        open(&disk, &mnt, "", false).unwrap();
        assert_eq!(fs::metadata(files_of(&disk)).unwrap().mode() & 0o777, 0o700);
        let link = dir.0.join(format!("link{}", names::STORE));
        symlink(&disk, &link).unwrap();
        assert!(refused(&link).ends_with("isn't a plain file"));
    }

    /// The real thing: mkfs.ext4 makes the disk, debugfs reads it back without mounting it.
    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "needs mkfs.ext4")]
    fn a_store_is_an_image_and_a_folder() {
        let dir = TempDir::new("halti-disk-store").unwrap();
        let layout = Layout::under(&dir.0).unwrap();
        let disk = layout.bundle("dev");
        assert_eq!(disk, layout.root.join("dev.img"));
        // A folder a removed store left is no store's, and goes.
        fs::create_dir_all(layout.root.join("dev.d/door")).unwrap();
        fs::write(layout.root.join("dev.d/door/ca.sealed"), b"an old box's").unwrap();
        create(&layout, &disk, "unused").unwrap();
        assert!(create(&layout, &disk, "unused").unwrap_err().to_string().ends_with("already exists"), "never replaces a store");
        let meta = fs::metadata(&disk).unwrap();
        assert!(meta.is_file() && meta.mode() & 0o777 == 0o600);
        assert_eq!(meta.len(), SIZE);
        assert!(meta.blocks() * 512 < 64 << 20, "sparse: {} bytes in use", meta.blocks() * 512);
        assert!(!layout.root.join("dev.d/door/ca.sealed").exists());
        for folder in ["", "log", "door", "browser"] {
            assert_eq!(fs::metadata(layout.root.join("dev.d").join(folder)).unwrap().mode() & 0o777, 0o700, "{folder}");
        }
        let debugfs = MKFS[0].replace("mkfs.ext4", "debugfs");
        let read = |what: &str| {
            let out = Command::new(&debugfs).args(["-R", what]).arg(&disk).output().unwrap();
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        let top = read("stat /");
        assert!(top.contains("User:     0   Group:     0") && top.contains("Mode:  0755"), "{top}");
        assert!(read("ls -p /").lines().filter(|l| !l.is_empty()).all(|l| l.contains("/.") || l.contains("/lost+found/")), "an empty file system");
        assert!(read("stats").contains("Reserved block count:     0"));

        // Shredded with its folder. A file in the folder's place is no store's either.
        shred(&disk).unwrap();
        assert!(!disk.exists() && !layout.root.join("dev.d").exists());
        fs::write(layout.root.join("dev.d"), b"in the way").unwrap();
        create(&layout, &disk, "unused").unwrap();
        assert!(layout.root.join("dev.d/log").is_dir());
    }
}
