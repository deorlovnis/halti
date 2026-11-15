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
    create_with(layout, disk, MKFS.iter().map(Path::new).find(|p| p.is_file()).unwrap_or(Path::new("mkfs.ext4")))
}

/// `create`, running the mkfs.ext4 at `mkfs_at`.
fn create_with(layout: &Layout, disk: &Path, mkfs_at: &Path) -> Result<()> {
    layout.prepare()?;
    if fs::symlink_metadata(disk).is_ok() {
        bail!("{} already exists", disk.display());
    }
    remove(&files_of(disk))?;
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(disk).with_context(|| format!("creating {}", disk.display()))?;
    let sized = file.set_len(SIZE).with_context(|| format!("sizing {}", disk.display()));
    drop(file);
    let made = sized.and_then(|()| mkfs(mkfs_at, disk)).and_then(|()| own_files(disk).map(drop));
    if made.is_err() {
        let _ = shred(disk);
    }
    made
}

/// An empty ext4 file system in the file `disk`, written in place: what mkfs.ext4 doesn't write
/// stays a hole in the file. It needs no terminal, and starts in a process group of its own, so
/// Ctrl-C reaches halti alone.
fn mkfs(program: &Path, disk: &Path) -> Result<()> {
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

/// The notes of `ws box new` and `halti open` about what `what` names (`box acme/dev keeps`), kept
/// in the workspace's folder `wsdir`, which halti doesn't encrypt: whether the disk that holds
/// `wsdir` is a dm-crypt one, and swap that isn't. halti can't tell a disk its owner unlocks from
/// one that unlocks itself at boot, so the first says only what was checked.
pub fn at_rest_notes(what: &str, wsdir: &Path) -> Vec<String> {
    let sys = Path::new("/sys");
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let swaps = fs::read_to_string("/proc/swaps").unwrap_or_default();
    let real = fs::canonicalize(wsdir).unwrap_or_else(|_| wsdir.to_path_buf());
    let encrypted = device_of(&mountinfo, &real).is_some_and(|device| crypt(sys, &device));
    notes(what, wsdir, encrypted, clear_swap(sys, &swaps))
}

fn notes(what: &str, wsdir: &Path, encrypted: bool, clear_swap: bool) -> Vec<String> {
    let mut said = vec![match encrypted {
        true => format!(
            "note: what {what} is not encrypted by halti here. {} is on a dm-crypt disk. this protects it only if you unlock that disk yourself after each boot",
            wsdir.display()
        ),
        false => format!("note: what {what} is not encrypted. anyone with a copy of this server's disk can read it. see the README: an encrypted data disk"),
    }];
    if clear_swap {
        said.push("note: this server has swap that is not encrypted. tokens and workspace keys can be written to it".to_string());
    }
    said
}

/// Where a block device is in `sys`: its kernel name (`dm-1`, `sda2`), by `MAJOR:MINOR` or by a
/// path to it under /dev.
#[derive(Debug, PartialEq)]
enum Device {
    Number(String),
    Path(PathBuf),
}

/// The device of the mount that holds `path`, from mountinfo's lines: the mount whose mount point
/// is the longest that `path` is in. Its number, unless that is one no device has (major 0, as a
/// btrfs or an overlay mount has), then the path of its source.
fn device_of(mountinfo: &str, path: &Path) -> Option<Device> {
    let mut best: Option<(usize, Device)> = None;
    for line in mountinfo.lines() {
        let Some((fields, after)) = line.split_once(" - ") else { continue };
        let fields: Vec<&str> = fields.split(' ').collect();
        let (Some(number), Some(point)) = (fields.get(2), fields.get(4)) else { continue };
        let point = PathBuf::from(unescape(point));
        if !path.starts_with(&point) || best.as_ref().is_some_and(|(length, _)| *length > point.as_os_str().len()) {
            continue;
        }
        let device = match number.split_once(':') {
            Some(("0", _)) | None => match after.split(' ').nth(1) {
                Some(source) if source.starts_with("/dev/") => Device::Path(PathBuf::from(unescape(source))),
                _ => Device::Number((*number).to_string()),
            },
            Some(_) => Device::Number((*number).to_string()),
        };
        best = Some((point.as_os_str().len(), device));
    }
    best.map(|(_, device)| device)
}

/// mountinfo's escapes of a space, a tab, a new line and a backslash (`\040`) undone.
fn unescape(text: &str) -> String {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\'
            && let Some(code) = text.get(at + 1..at + 4).and_then(|digits| u8::from_str_radix(digits, 8).ok())
        {
            out.push(code);
            at += 4;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether `device` is a dm-crypt one, or is mapped straight onto one, as LVM on LUKS is: its
/// `dm/uuid` in `sys`, or one of its slaves', starts with `CRYPT-`.
fn crypt(sys: &Path, device: &Device) -> bool {
    let name = match device {
        Device::Number(number) => fs::read_link(sys.join("dev/block").join(number)).ok().and_then(|link| link.file_name().map(|n| n.to_string_lossy().into_owned())),
        Device::Path(path) => fs::canonicalize(path).ok().and_then(|real| real.file_name().map(|n| n.to_string_lossy().into_owned())),
    };
    let Some(name) = name else { return false };
    let block = sys.join("class/block").join(&name);
    let slaves = fs::read_dir(block.join("slaves")).into_iter().flatten().flatten().map(|entry| entry.path());
    std::iter::once(block.clone()).chain(slaves).any(|dev| fs::read_to_string(dev.join("dm/uuid")).is_ok_and(|uuid| uuid.starts_with("CRYPT-")))
}

/// A device number as Linux writes it, `MAJOR:MINOR`.
fn number(dev: u64) -> String {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xffff_f000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffff_ff00);
    format!("{major}:{minor}")
}

/// Whether swap that isn't encrypted is on, from /proc/swaps: a swap file counts as the disk it is
/// on, and zram is memory.
fn clear_swap(sys: &Path, swaps: &str) -> bool {
    swaps.lines().skip(1).any(|line| {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(kind)) = (fields.next(), fields.next()) else { return false };
        let name = unescape(name);
        if name.starts_with("/dev/zram") {
            return false;
        }
        let device = match kind {
            "file" => match fs::metadata(&name) {
                Ok(meta) => Device::Number(number(meta.dev())),
                Err(_) => return true,
            },
            _ => Device::Path(PathBuf::from(name)),
        };
        !crypt(sys, &device)
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;
    use crate::util::TempDir;

    /// A made-up /sys: `dm-0` is dm-crypt, `dm-1` is LVM on it, `sda2` is a plain partition.
    fn sys(dir: &Path) -> PathBuf {
        let sys = dir.join("sys");
        for (name, number, uuid) in [("dm-0", "253:0", Some("CRYPT-LUKS2-0123-data")), ("dm-1", "253:1", Some("LVM-abc")), ("sda2", "8:2", None)] {
            let block = sys.join("class/block").join(name);
            fs::create_dir_all(block.join("slaves")).unwrap();
            if let Some(uuid) = uuid {
                fs::create_dir_all(block.join("dm")).unwrap();
                fs::write(block.join("dm/uuid"), format!("{uuid}\n")).unwrap();
            }
            fs::create_dir_all(sys.join("dev/block")).unwrap();
            symlink(format!("../../devices/virtual/block/{name}"), sys.join("dev/block").join(number)).unwrap();
        }
        fs::create_dir(sys.join("class/block/dm-1/slaves/dm-0")).unwrap();
        fs::create_dir_all(sys.join("class/block/dm-1/slaves/dm-0/dm")).unwrap();
        fs::write(sys.join("class/block/dm-1/slaves/dm-0/dm/uuid"), "CRYPT-LUKS2-0123-data\n").unwrap();
        sys
    }

    const MOUNTINFO: &str = "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n\
                             30 22 253:0 / /data rw,relatime shared:5 - ext4 /dev/mapper/data rw\n\
                             31 22 253:1 / /srv/lvm\\040disk rw,relatime shared:6 - xfs /dev/mapper/vg-ws rw\n\
                             32 22 0:45 /@home /home rw,relatime shared:7 - btrfs /dev/sda2 rw\n";

    #[test]
    fn the_note_says_whether_the_disk_is_encrypted() {
        let dir = TempDir::new("halti-at-rest").unwrap();
        let sys = sys(&dir.0);
        let on = |path: &str| device_of(MOUNTINFO, Path::new(path));
        assert_eq!(on("/data/halti-ws/0123"), Some(Device::Number("253:0".into())));
        assert_eq!(on("/datab/ws"), Some(Device::Number("8:2".into())), "a mount point is a folder, not a prefix of a name");
        assert_eq!(on("/srv/lvm disk/ws"), Some(Device::Number("253:1".into())));
        assert_eq!(on("/home/deor/Library"), Some(Device::Path("/dev/sda2".into())), "a mount with no device number is read by its source");
        let encrypted = |path: &str| on(path).is_some_and(|device| crypt(&sys, &device));
        assert!(encrypted("/data/halti-ws") && encrypted("/srv/lvm disk/ws"));
        assert!(!encrypted("/home/deor/ws") && !encrypted("/var/ws"));
        assert!(!crypt(&sys, &Device::Number("9:9".into())), "a device /sys doesn't know");

        let wsdir = Path::new("/data/halti-ws/0123");
        assert_eq!(
            notes("box acme/dev keeps", wsdir, true, false),
            [
                "note: what box acme/dev keeps is not encrypted by halti here. /data/halti-ws/0123 is on a dm-crypt disk. this protects it only if you unlock that disk yourself after each boot"
            ]
        );
        assert_eq!(
            notes("box acme/dev keeps", wsdir, false, true),
            [
                "note: what box acme/dev keeps is not encrypted. anyone with a copy of this server's disk can read it. see the README: an encrypted data disk",
                "note: this server has swap that is not encrypted. tokens and workspace keys can be written to it"
            ]
        );
        // This machine's own answer has the one line or the other, and names the box.
        let said = at_rest_notes("box acme/dev keeps", &dir.0);
        assert!(said[0].starts_with("note: what box acme/dev keeps is not encrypted") && (1..=2).contains(&said.len()), "{said:?}");
    }

    #[test]
    fn swap_that_isn_t_encrypted_is_said() {
        let dir = TempDir::new("halti-swap").unwrap();
        let sys = sys(&dir.0);
        fs::create_dir_all(dir.0.join("dev/mapper")).unwrap();
        symlink(sys.join("class/block/dm-0"), dir.0.join("dev/mapper/swap")).unwrap();
        let header = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
        assert!(!clear_swap(&sys, header), "none");
        assert!(!clear_swap(&sys, &format!("{header}/dev/zram0 partition 1024 0 100\n")), "zram is memory");
        assert!(!clear_swap(&sys, &format!("{header}{} partition 1024 0 -2\n", dir.0.join("dev/mapper/swap").display())));
        assert!(clear_swap(&sys, &format!("{header}{} partition 1024 0 -2\n", sys.join("class/block/sda2").display())));
        assert!(clear_swap(&sys, &format!("{header}/nowhere/swapfile file 1024 0 -2\n")), "a file that can't be read counts as clear");
    }

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
    fn a_store_that_fails_half_way_is_removed() {
        let dir = TempDir::new("halti-disk-failed").unwrap();
        let layout = Layout::under(&dir.0).unwrap();
        let disk = layout.bundle("dev");
        let gone = |disk: &Path| fs::symlink_metadata(disk).is_err() && fs::symlink_metadata(files_of(disk)).is_err();
        // mkfs.ext4 fails, or isn't there.
        assert!(create_with(&layout, &disk, Path::new("false")).unwrap_err().to_string().starts_with("mkfs.ext4"));
        assert!(gone(&disk));
        assert!(create_with(&layout, &disk, &dir.0.join("none")).unwrap_err().to_string().starts_with("running"));
        assert!(gone(&disk));
        // mkfs.ext4 works, but halti's folder can't be made: a link left in its place is refused,
        // and goes with the disk, and what it points at stays.
        fs::create_dir_all(dir.0.join("elsewhere")).unwrap();
        let made = |disk: &Path| {
            fs::write(disk.with_file_name("run.sh"), format!("#!/bin/sh\nln -s {} {}\n", dir.0.join("elsewhere").display(), files_of(disk).display())).unwrap();
            fs::set_permissions(disk.with_file_name("run.sh"), fs::Permissions::from_mode(0o700)).unwrap();
            create_with(&layout, disk, &disk.with_file_name("run.sh"))
        };
        assert!(made(&disk).is_err());
        assert!(gone(&disk) && dir.0.join("elsewhere").is_dir());
        // And one that works leaves both.
        create_with(&layout, &disk, Path::new("true")).unwrap();
        assert!(disk.is_file() && files_of(&disk).join("log").is_dir());
    }

    /// The disk goes last: a store whose folder can't be removed keeps its disk, and is still found.
    #[test]
    fn shredding_keeps_the_disk_until_the_folder_is_gone() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root removes it anyway
        }
        let dir = TempDir::new("halti-disk-shred-order").unwrap();
        let disk = by_hand(&dir.0, "dev");
        let log = files_of(&disk).join("log");
        fs::set_permissions(&log, fs::Permissions::from_mode(0o500)).unwrap();
        let shredded = shred(&disk);
        fs::set_permissions(&log, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(shredded.is_err());
        assert!(disk.is_file());
        shred(&disk).unwrap();
        assert!(!disk.exists() && !files_of(&disk).exists());
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
