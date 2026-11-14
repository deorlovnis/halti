//! Reading and writing in a box's folders from the Mac, following no link.
//!
//! halti works in a box's store as the person, outside the box, and the agent may have left a link
//! anywhere in its home, work and downloads folders (in a kept box, from one run to the next).
//! Followed, such a link would have halti read or change a file of the person's. So each folder on
//! the way is opened from the one before it, and so is the file, always with O_NOFOLLOW: a name
//! swapped for a link after it was looked at fails to open instead of being followed. Files are
//! opened without waiting, so a pipe in their place can't hang halti.

use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

/// What a name in a folder is, a link not followed.
#[derive(PartialEq, Eq, Debug)]
enum Kind {
    Missing,
    Folder,
    File,
    Link,
    /// A pipe, a socket or a device.
    Other,
}

/// The plain file at `rel` in the folder `root`, or none: when it isn't there, a part of `rel` is a
/// link or not a folder, or it isn't a plain file.
pub fn read(root: &Path, rel: &Path) -> Result<Option<Vec<u8>>> {
    let (folders, name) = split(rel)?;
    let mut dir = open_root(root)?;
    let mut at = PathBuf::new();
    for part in folders {
        at.push(part);
        if kind(&dir, part, &at)? != Kind::Folder {
            return Ok(None);
        }
        dir = open_folder(&dir, part, &at)?;
    }
    at.push(name);
    if kind(&dir, name, &at)? != Kind::File {
        return Ok(None);
    }
    let file = open_at(&dir, name, libc::O_RDONLY | libc::O_NONBLOCK, 0).with_context(|| format!("reading {}", at.display()))?;
    if !file.metadata().with_context(|| format!("reading {}", at.display()))?.is_file() {
        return Ok(None);
    }
    // Read whole, however large: Claude Code keeps its history of projects in ~/.claude.json.
    let mut bytes = Vec::new();
    (&file).read_to_end(&mut bytes).with_context(|| format!("reading {}", at.display()))?;
    Ok(Some(bytes))
}

/// Writes `bytes` to the file at `rel` in the folder `root`, making the folders on the way. A link,
/// pipe, socket or device on the way or at `rel` is removed and replaced, never followed, so what a
/// link pointed to is left alone. Returns the parts of `rel` that were replaced.
pub fn write(root: &Path, rel: &Path, bytes: &[u8]) -> Result<Vec<PathBuf>> {
    let (folders, name) = split(rel)?;
    let mut replaced = Vec::new();
    let mut dir = open_root(root)?;
    let mut at = PathBuf::new();
    for part in folders {
        at.push(part);
        match kind(&dir, part, &at)? {
            Kind::Folder => {}
            Kind::File => bail!("{} isn't a folder", at.display()),
            Kind::Missing => make_folder(&dir, part, &at)?,
            Kind::Link | Kind::Other => {
                remove(&dir, part, &at)?;
                replaced.push(at.clone());
                make_folder(&dir, part, &at)?;
            }
        }
        dir = open_folder(&dir, part, &at)?;
    }
    at.push(name);
    match kind(&dir, name, &at)? {
        Kind::Folder => bail!("{} is a folder", at.display()),
        Kind::Link | Kind::Other => {
            remove(&dir, name, &at)?;
            replaced.push(at.clone());
        }
        Kind::Missing | Kind::File => {}
    }
    let mut file = open_at(&dir, name, libc::O_WRONLY | libc::O_CREAT | libc::O_NONBLOCK, 0o666).with_context(|| format!("writing {}", at.display()))?;
    if !file.metadata().with_context(|| format!("writing {}", at.display()))?.is_file() {
        bail!("{} isn't a plain file", at.display());
    }
    file.set_len(0).and_then(|()| file.write_all(bytes)).with_context(|| format!("writing {}", at.display()))?;
    Ok(replaced)
}

/// Fails if a part of `rel` in the folder `root` is a link. A part that isn't there, or isn't a
/// folder, ends the check: nothing is below it.
pub fn no_link(root: &Path, rel: &Path) -> Result<()> {
    let (folders, name) = split(rel)?;
    let mut dir = open_root(root)?;
    let mut at = PathBuf::new();
    for part in folders {
        at.push(part);
        match kind(&dir, part, &at)? {
            Kind::Folder => dir = open_folder(&dir, part, &at)?,
            Kind::Link => bail!("{} is a link; links aren't followed", at.display()),
            _ => return Ok(()),
        }
    }
    at.push(name);
    if kind(&dir, name, &at)? == Kind::Link {
        bail!("{} is a link; links aren't followed", at.display());
    }
    Ok(())
}

/// The folders of `rel` and the name at its end. Only plain names: no `..`, `.` or leading `/`.
fn split(rel: &Path) -> Result<(Vec<&OsStr>, &OsStr)> {
    let mut parts = rel
        .components()
        .map(|c| match c {
            Component::Normal(part) => Ok(part),
            _ => Err(anyhow!("{} isn't a path inside the box", rel.display())),
        })
        .collect::<Result<Vec<_>>>()?;
    let name = parts.pop().ok_or_else(|| anyhow!("no path inside the box given"))?;
    Ok((parts, name))
}

/// The folder everything is opened from: the store's mount point, which halti made.
fn open_root(root: &Path) -> Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC).open(root).with_context(|| format!("opening {}", root.display()))
}

fn open_folder(dir: &File, name: &OsStr, at: &Path) -> Result<File> {
    open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0).with_context(|| format!("opening {}", at.display()))
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// `name` in the folder `dir`, opened with `flags`, never through a link.
fn open_at(dir: &File, name: &OsStr, flags: libc::c_int, mode: libc::c_uint) -> io::Result<File> {
    let name = c_name(name)?;
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn kind(dir: &File, name: &OsStr, at: &Path) -> Result<Kind> {
    let c = c_name(name)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            return Ok(Kind::Missing);
        }
        return Err(e).with_context(|| format!("reading {}", at.display()));
    }
    Ok(match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => Kind::Folder,
        libc::S_IFREG => Kind::File,
        libc::S_IFLNK => Kind::Link,
        _ => Kind::Other,
    })
}

fn make_folder(dir: &File, name: &OsStr, at: &Path) -> Result<()> {
    let c = c_name(name)?;
    if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o777) } != 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("creating {}", at.display()));
    }
    Ok(())
}

/// Removes the link (or pipe, socket or device) itself, never what it points to.
fn remove(dir: &File, name: &OsStr, at: &Path) -> Result<()> {
    let c = c_name(name)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("removing {}", at.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, symlink};

    use super::*;
    use crate::util::TempDir;

    #[test]
    fn writes_and_reads_plain_files_as_today() {
        let dir = TempDir::new("halti-nofollow").unwrap();
        assert_eq!(read(&dir.0, Path::new("home/a/b.json")).unwrap(), None);
        assert!(write(&dir.0, Path::new("home/a/b.json"), b"one").unwrap().is_empty());
        assert_eq!(read(&dir.0, Path::new("home/a/b.json")).unwrap().as_deref(), Some(&b"one"[..]));
        assert!(write(&dir.0, Path::new("home/a/b.json"), b"it").unwrap().is_empty());
        assert_eq!(fs::read_to_string(dir.0.join("home/a/b.json")).unwrap(), "it", "written over, not added to");

        for rel in ["", "/etc/x", "home/../x", "./home/x"] {
            assert!(write(&dir.0, Path::new(rel), b"x").is_err(), "{rel:?}");
            assert!(read(&dir.0, Path::new(rel)).is_err(), "{rel:?}");
        }
        fs::create_dir_all(dir.0.join("home/folder")).unwrap();
        assert!(write(&dir.0, Path::new("home/folder"), b"x").is_err(), "a folder is never replaced");
        assert!(write(&dir.0, Path::new("home/a/b.json/c"), b"x").is_err(), "nor a file where a folder belongs");
        assert_eq!(fs::read_to_string(dir.0.join("home/a/b.json")).unwrap(), "it");
    }

    #[test]
    fn follows_no_link_and_replaces_it() {
        let dir = TempDir::new("halti-nofollow").unwrap();
        let (mnt, outside) = (dir.0.join("mnt"), dir.0.join("outside"));
        fs::create_dir_all(mnt.join("home")).unwrap();
        fs::create_dir_all(outside.join("folder")).unwrap();
        fs::write(outside.join("file"), "the person's own").unwrap();
        fs::write(outside.join("folder/x"), "the person's own").unwrap();
        symlink(outside.join("file"), mnt.join("home/file")).unwrap();
        symlink(outside.join("folder"), mnt.join("home/folder")).unwrap();
        symlink(outside.join("gone"), mnt.join("home/gone")).unwrap();

        for rel in ["home/file", "home/folder/x", "home/gone/x"] {
            assert_eq!(read(&mnt, Path::new(rel)).unwrap(), None, "{rel} is read as if it weren't there");
            let error = no_link(&mnt, Path::new(rel)).unwrap_err().to_string();
            assert!(error.starts_with("home/") && error.ends_with(" is a link; links aren't followed"), "{error}");
        }
        no_link(&mnt, Path::new("home/missing/x")).unwrap();
        assert_eq!(write(&mnt, Path::new("home/file"), b"halti's").unwrap(), [PathBuf::from("home/file")]);
        assert_eq!(write(&mnt, Path::new("home/folder/x"), b"halti's").unwrap(), [PathBuf::from("home/folder")]);
        assert_eq!(write(&mnt, Path::new("home/gone/x"), b"halti's").unwrap(), [PathBuf::from("home/gone")]);

        assert_eq!(fs::read_to_string(outside.join("file")).unwrap(), "the person's own");
        assert_eq!(fs::read_to_string(outside.join("folder/x")).unwrap(), "the person's own");
        assert!(!outside.join("gone").exists());
        for rel in ["home/file", "home/folder/x", "home/gone/x"] {
            assert!(!fs::symlink_metadata(mnt.join(rel)).unwrap().file_type().is_symlink());
            assert_eq!(fs::read_to_string(mnt.join(rel)).unwrap(), "halti's");
        }
    }

    #[test]
    fn a_pipe_in_place_of_a_file_never_hangs() {
        let dir = TempDir::new("halti-nofollow").unwrap();
        fs::create_dir_all(dir.0.join("home")).unwrap();
        let pipe = CString::new(dir.0.join("home/f").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0);
        assert!(fs::symlink_metadata(dir.0.join("home/f")).unwrap().file_type().is_fifo());
        assert_eq!(read(&dir.0, Path::new("home/f")).unwrap(), None);
        assert_eq!(write(&dir.0, Path::new("home/f"), b"x").unwrap(), [PathBuf::from("home/f")]);
        assert_eq!(fs::read_to_string(dir.0.join("home/f")).unwrap(), "x");
    }
}
