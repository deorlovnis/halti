//! Reading and writing in a box's folders from the Mac, following no link.
//!
//! halti works in a box's store as the person, outside the box, and the agent may have left a link
//! anywhere in its home, work and downloads folders (in a kept box, from one run to the next).
//! Followed, such a link would have halti read or change a file of the person's. So each folder on
//! the way is opened from the one before it, and so is the file, always with O_NOFOLLOW: a name
//! swapped for a link after it was looked at fails to open instead of being followed. Files are
//! opened without waiting, so a pipe in their place can't hang halti. macOS has no `openat2`, so
//! each part is opened on its own. The store's log, and copies into and out of a box, go the same
//! way (`open`, `append`, `Folder`).

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
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

/// What is at a name, opened without following a link.
pub enum Found {
    Missing,
    Folder(Folder),
    /// A plain file, opened to read.
    File(File),
    /// A link, not opened.
    Link,
    /// A pipe, a socket or a device, not opened.
    Other,
}

/// A folder opened without following a link. What is in it is opened from it the same way.
pub struct Folder {
    file: File,
    /// The folder as messages name it.
    at: PathBuf,
}

impl Folder {
    /// The folder at `path`, taken as it is: halti's own (a store's mount point) or the person's.
    pub fn of(path: &Path) -> Result<Self> {
        Ok(Self { file: open_root(path)?, at: path.to_path_buf() })
    }

    /// The folder as messages name it.
    pub fn at(&self) -> &Path {
        &self.at
    }

    pub fn metadata(&self) -> Result<fs::Metadata> {
        self.file.metadata().with_context(|| format!("reading {}", self.at.display()))
    }

    /// The names in the folder, sorted, without `.` and `..`.
    pub fn names(&self) -> Result<Vec<OsString>> {
        let failed = |e: io::Error| Err(e).with_context(|| format!("reading {}", self.at.display()));
        // closedir closes this copy, never the folder's own descriptor.
        let fd = unsafe { libc::dup(self.file.as_raw_fd()) };
        if fd < 0 {
            return failed(io::Error::last_os_error());
        }
        let dir = unsafe { libc::fdopendir(fd) };
        if dir.is_null() {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return failed(e);
        }
        // The copy shares the folder's offset, which an earlier read left at the end.
        unsafe { libc::rewinddir(dir) };
        let mut names = Vec::new();
        let read = loop {
            clear_errno();
            let entry = unsafe { libc::readdir(dir) };
            if entry.is_null() {
                let e = io::Error::last_os_error();
                break if e.raw_os_error().unwrap_or(0) == 0 { Ok(()) } else { Err(e) };
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                names.push(OsStr::from_bytes(name).to_os_string());
            }
        };
        unsafe { libc::closedir(dir) };
        if let Err(e) = read {
            return failed(e);
        }
        names.sort();
        Ok(names)
    }

    /// What `name` in the folder is, opened without following a link.
    pub fn open(&self, name: &OsStr) -> Result<Found> {
        let at = self.at.join(name);
        Ok(match kind(&self.file, name, &at)? {
            Kind::Missing => Found::Missing,
            Kind::Link => Found::Link,
            Kind::Other => Found::Other,
            Kind::Folder => Found::Folder(Folder { file: open_folder(&self.file, name, &at)?, at }),
            Kind::File => {
                let file = open_at(&self.file, name, libc::O_RDONLY | libc::O_NONBLOCK, 0).with_context(|| format!("reading {}", at.display()))?;
                if file.metadata().with_context(|| format!("reading {}", at.display()))?.is_file() { Found::File(file) } else { Found::Other }
            }
        })
    }

    /// A new folder `name` in this one, with `mode`: never one that is there, nor a link.
    pub fn make(&self, name: &OsStr, mode: libc::mode_t) -> Result<Folder> {
        let at = self.at.join(name);
        let c = c_name(name)?;
        if unsafe { libc::mkdirat(self.file.as_raw_fd(), c.as_ptr(), mode) } != 0 {
            return Err(io::Error::last_os_error()).with_context(|| format!("creating {}", at.display()));
        }
        Ok(Folder { file: open_folder(&self.file, name, &at)?, at })
    }

    /// A new file `name` in this one, with `mode`, to write: never one that is there, nor through a
    /// link.
    pub fn create(&self, name: &OsStr, mode: libc::c_uint) -> Result<File> {
        open_at(&self.file, name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode).with_context(|| format!("creating {}", self.at.join(name).display()))
    }
}

/// What is at `rel` in the folder `root`, each part opened from the one before. A link on the way
/// is refused; a part on the way that isn't there, or isn't a folder, means nothing is there, and
/// so does no `root`.
pub fn open(root: &Path, rel: &Path) -> Result<Found> {
    let (folders, name) = split(rel)?;
    let file = match root_folder(root) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Found::Missing),
        Err(e) => return Err(e).with_context(|| format!("opening {}", root.display())),
    };
    let mut dir = Folder { file, at: PathBuf::new() };
    for part in folders {
        dir = match dir.open(part)? {
            Found::Folder(next) => next,
            Found::Link => bail!("{} is a link; links aren't followed", dir.at.join(part).display()),
            _ => return Ok(Found::Missing),
        };
    }
    dir.open(name)
}

/// The plain file at `rel` in the folder `root`, opened to read and to append to, and made (with
/// `mode`) with the folders on the way when it isn't there. A link on the way or at `rel` is
/// refused, never followed or replaced, and so is anything else in a folder's or the file's place.
pub fn append(root: &Path, rel: &Path, mode: libc::c_uint) -> Result<File> {
    let (folders, name) = split(rel)?;
    let mut dir = open_root(root)?;
    let mut at = PathBuf::new();
    for part in folders {
        at.push(part);
        match kind(&dir, part, &at)? {
            Kind::Folder => {}
            Kind::Missing => make_folder(&dir, part, &at)?,
            Kind::Link => bail!("{} is a link; links aren't followed", at.display()),
            Kind::File | Kind::Other => bail!("{} isn't a folder", at.display()),
        }
        dir = open_folder(&dir, part, &at)?;
    }
    at.push(name);
    if kind(&dir, name, &at)? == Kind::Link {
        bail!("{} is a link; links aren't followed", at.display());
    }
    let file = open_at(&dir, name, libc::O_RDWR | libc::O_APPEND | libc::O_CREAT | libc::O_NONBLOCK, mode).with_context(|| format!("opening {}", at.display()))?;
    if !file.metadata().with_context(|| format!("opening {}", at.display()))?.is_file() {
        bail!("{} isn't a plain file", at.display());
    }
    Ok(file)
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
    root_folder(root).with_context(|| format!("opening {}", root.display()))
}

fn root_folder(root: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC).open(root)
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

/// Makes the folder `name`. One another process made meanwhile is fine: it is opened next, without
/// following a link.
fn make_folder(dir: &File, name: &OsStr, at: &Path) -> Result<()> {
    let c = c_name(name)?;
    if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o777) } != 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(e).with_context(|| format!("creating {}", at.display()));
        }
    }
    Ok(())
}

/// Sets errno to 0, so that readdir's end, which leaves it alone, can be told from its failure.
fn clear_errno() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        *libc::__errno_location() = 0;
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    unsafe {
        *libc::__error() = 0;
    }
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
        }
        assert!(matches!(open(&mnt, Path::new("home/file")).unwrap(), Found::Link), "a link at the end isn't opened");
        for rel in ["home/folder/x", "home/gone/x"] {
            let error = open(&mnt, Path::new(rel)).err().unwrap().to_string();
            assert!(error.starts_with("home/") && error.ends_with(" is a link; links aren't followed"), "{error}");
        }
        assert!(matches!(open(&mnt, Path::new("home/missing/x")).unwrap(), Found::Missing));
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
    fn opens_appends_and_lists_through_no_link() {
        let dir = TempDir::new("halti-nofollow").unwrap();
        let (mnt, outside) = (dir.0.join("mnt"), dir.0.join("outside"));
        fs::create_dir_all(mnt.join("log")).unwrap();
        fs::create_dir_all(mnt.join("work/sub")).unwrap();
        fs::create_dir_all(outside.join("folder")).unwrap();
        fs::write(outside.join("file"), "the person's own").unwrap();
        fs::write(mnt.join("work/sub/b"), "b").unwrap();
        fs::write(mnt.join("work/a"), "a").unwrap();
        symlink(outside.join("file"), mnt.join("log/door.log")).unwrap();
        symlink(outside.join("folder"), mnt.join("work/link")).unwrap();
        symlink(outside.join("folder"), mnt.join("linked")).unwrap();

        // Appending: a link at the end or on the way is refused, and what it points to stays as it was.
        let error = append(&mnt, Path::new("log/door.log"), 0o600).err().unwrap().to_string();
        assert_eq!(error, "log/door.log is a link; links aren't followed");
        let error = append(&mnt, Path::new("linked/door.log"), 0o600).err().unwrap().to_string();
        assert_eq!(error, "linked is a link; links aren't followed");
        assert_eq!(fs::read_to_string(outside.join("file")).unwrap(), "the person's own");
        assert!(fs::read_dir(outside.join("folder")).unwrap().next().is_none(), "nothing was made through the link");
        // A missing file is made, with the folders on the way, and added to.
        (&append(&mnt, Path::new("new/log/x.log"), 0o600).unwrap()).write_all(b"one\n").unwrap();
        (&append(&mnt, Path::new("new/log/x.log"), 0o600).unwrap()).write_all(b"two\n").unwrap();
        assert_eq!(fs::read_to_string(mnt.join("new/log/x.log")).unwrap(), "one\ntwo\n");
        assert!(append(&mnt, Path::new("work/a/x.log"), 0o600).is_err(), "a file where a folder belongs");

        // Opening: the same parts.
        assert!(matches!(open(&mnt, Path::new("log/door.log")).unwrap(), Found::Link));
        assert!(open(&mnt, Path::new("linked/x")).is_err());
        let Found::Folder(work) = open(&mnt, Path::new("work")).unwrap() else { panic!("work is a folder") };
        assert_eq!(work.at(), Path::new("work"));
        // A folder lists its names, links too, and opens each without following one.
        assert_eq!(work.names().unwrap(), ["a", "link", "sub"]);
        assert_eq!(work.names().unwrap(), ["a", "link", "sub"], "read again from the start");
        assert!(matches!(work.open(OsStr::new("link")).unwrap(), Found::Link));
        let Found::File(mut a) = work.open(OsStr::new("a")).unwrap() else { panic!("a is a file") };
        let mut text = String::new();
        a.read_to_string(&mut text).unwrap();
        assert_eq!(text, "a");
        assert!(matches!(work.open(OsStr::new("none")).unwrap(), Found::Missing));
        // Making: never a folder or a file that is there, a link least of all.
        assert!(work.make(OsStr::new("link"), 0o755).is_err() && work.create(OsStr::new("link"), 0o644).is_err());
        assert!(work.make(OsStr::new("sub"), 0o755).is_err() && work.create(OsStr::new("a"), 0o644).is_err());
        let made = work.make(OsStr::new("made"), 0o755).unwrap();
        (&made.create(OsStr::new("f"), 0o644).unwrap()).write_all(b"new").unwrap();
        assert_eq!(fs::read_to_string(mnt.join("work/made/f")).unwrap(), "new");
        assert!(fs::read_dir(outside.join("folder")).unwrap().next().is_none());
    }

    #[test]
    fn a_pipe_in_place_of_a_file_never_hangs() {
        let dir = TempDir::new("halti-nofollow").unwrap();
        fs::create_dir_all(dir.0.join("home")).unwrap();
        let pipe = CString::new(dir.0.join("home/f").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0);
        assert!(fs::symlink_metadata(dir.0.join("home/f")).unwrap().file_type().is_fifo());
        assert_eq!(read(&dir.0, Path::new("home/f")).unwrap(), None);
        assert!(matches!(open(&dir.0, Path::new("home/f")).unwrap(), Found::Other));
        assert!(append(&dir.0, Path::new("home/f"), 0o600).is_err());
        assert_eq!(write(&dir.0, Path::new("home/f"), b"x").unwrap(), [PathBuf::from("home/f")]);
        assert_eq!(fs::read_to_string(dir.0.join("home/f")).unwrap(), "x");
    }
}
