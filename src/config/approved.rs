//! The approved copy of a person's settings, one file per user: written by root through sudo, so a
//! program running as the person can't change it, and trusted only while it and every folder above
//! it say so. A debug build keeps it in its own config folder, owned by the person, and writes it
//! itself under its hook: no debug build or test names the system folders.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use halti_core::platform::Os;

use crate::util::sha256_hex;
use crate::ws::OS;
use crate::{names, util};

/// The most bytes the copy, or the person's file, may have: far more than the settings take.
pub const MOST: u64 = 16 << 10;

/// Where a user's approved copy is, and who must own it and each folder up to `top`.
pub struct Place {
    pub dir: PathBuf,
    pub file: PathBuf,
    pub owner: u32,
    pub top: PathBuf,
}

impl Place {
    /// This user's: under the system folder, owned by root, every folder up to `/` checked. A debug
    /// build's is in its config folder, owned by the person, checked up to that folder.
    pub fn real() -> Place {
        let uid = unsafe { libc::getuid() };
        if cfg!(halti_dev) {
            let config = util::config_dir();
            return Place::at(&config.join("approved"), uid, uid, &config);
        }
        let dir = match OS {
            Os::Macos => names::APPROVED_MACOS,
            Os::Linux => names::APPROVED_LINUX,
        };
        Place::at(Path::new(dir), uid, 0, Path::new("/"))
    }

    /// `<uid>.toml` in `dir`.
    pub fn at(dir: &Path, uid: u32, owner: u32, top: &Path) -> Place {
        Place { dir: dir.to_path_buf(), file: dir.join(format!("{uid}.toml")), owner, top: top.to_path_buf() }
    }

    /// Who alone may change it, as the screens say.
    pub fn who(&self) -> &'static str {
        if self.owner == 0 { "root" } else { "you" }
    }
}

/// What is in the copy's place.
#[derive(PartialEq, Eq, Debug)]
pub enum Found {
    Missing,
    /// A link, not a plain file, or it or a folder above it could be changed by someone else.
    Unsafe,
    /// Safe, but not settings halti could have written: why, in a few words.
    Unreadable(String),
    Text(String),
}

/// The copy, opened without following a link or waiting, and its folders checked up to `top`.
pub fn read(place: &Place) -> Found {
    let file = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&place.file) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Found::Missing,
        Err(_) => return Found::Unsafe,
    };
    let Ok(meta) = file.metadata() else { return Found::Unsafe };
    if !meta.is_file() || !safe(&meta, place.owner) || !folders_safe(place) {
        return Found::Unsafe;
    }
    let mut bytes = Vec::new();
    if file.take(MOST + 1).read_to_end(&mut bytes).is_err() {
        return Found::Unsafe;
    }
    if bytes.len() as u64 > MOST {
        return Found::Unreadable("it is larger than 16 KiB".to_string());
    }
    match String::from_utf8(bytes) {
        Ok(text) => Found::Text(text),
        Err(_) => Found::Unreadable("it isn't text".to_string()),
    }
}

/// Only its owner can change it: owned by `owner`, with no write for group or others.
fn safe(meta: &fs::Metadata, owner: u32) -> bool {
    meta.uid() == owner && meta.mode() & 0o022 == 0
}

/// Every folder from the copy's up to `top`: a folder, not a link, and safe.
pub fn folders_safe(place: &Place) -> bool {
    let mut at = place.dir.as_path();
    loop {
        match fs::symlink_metadata(at) {
            Ok(meta) if meta.is_dir() && safe(&meta, place.owner) => {}
            _ => return false,
        }
        if at == place.top.as_path() {
            return true;
        }
        let Some(up) = at.parent() else { return false };
        at = up;
    }
}

/// The Keychain name of the Touch ID approval record made under this approved copy: one made under
/// an older copy has another name, and is never read.
pub fn record_key(anchor: &str) -> String {
    format!("{}{}", names::CONFIG_KEY_PREFIX, &sha256_hex(anchor.as_bytes())[..16])
}

/// What sudo's tee does, done here by a debug build under its hook: the folder 0755 and the file
/// 0644 whatever the umask, as sudo makes them, and the file written in place. Release builds don't
/// contain this.
#[cfg(halti_dev)]
pub fn write_here(place: &Place, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fs::DirBuilder::new().recursive(true).mode(0o755).create(&place.dir)?;
    fs::set_permissions(&place.dir, fs::Permissions::from_mode(0o755))?;
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o644).open(&place.file)?;
    file.set_permissions(fs::Permissions::from_mode(0o644))?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;
    use crate::util::TempDir;

    const TEXT: &str = "[paths]\nworkspaces = \"~/work/ws\"\n";

    /// A copy in a test folder, owned by this user as a debug build's is.
    fn place(dir: &TempDir) -> Place {
        let uid = unsafe { libc::getuid() };
        let approved = dir.0.join("approved");
        fs::create_dir(&approved).unwrap();
        fs::set_permissions(&approved, fs::Permissions::from_mode(0o755)).unwrap();
        Place::at(&approved, uid, uid, &dir.0)
    }

    fn mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The copy as the folder's owner writes it.
    fn write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        mode(path, 0o644);
    }

    #[test]
    #[cfg(halti_dev)]
    fn a_debug_build_writes_its_copy_as_tee_would() {
        let dir = TempDir::new("halti-approved-write").unwrap();
        let place = Place::at(&dir.0.join("approved"), 501, unsafe { libc::getuid() }, &dir.0);
        write_here(&place, TEXT.as_bytes()).unwrap();
        assert_eq!(read(&place), Found::Text(TEXT.to_string()));
        assert!(place.file.ends_with("approved/501.toml"));
        write_here(&place, b"[paths]\n").unwrap();
        assert_eq!(read(&place), Found::Text("[paths]\n".to_string()), "written over, in place");
    }

    #[test]
    fn a_copy_only_its_owner_can_change_is_read() {
        let dir = TempDir::new("halti-approved").unwrap();
        let place = place(&dir);
        assert_eq!(read(&place), Found::Missing);
        write(&place.file, TEXT.as_bytes());
        assert_eq!(read(&place), Found::Text(TEXT.to_string()));
        // Group-writable, the file or a folder above it.
        mode(&place.file, 0o664);
        assert_eq!(read(&place), Found::Unsafe);
        mode(&place.file, 0o644);
        mode(&place.dir, 0o775);
        assert_eq!(read(&place), Found::Unsafe);
        mode(&place.dir, 0o755);
        mode(&dir.0, 0o777);
        assert_eq!(read(&place), Found::Unsafe, "the top folder is checked too");
        mode(&dir.0, 0o700);
        assert_eq!(read(&place), Found::Text(TEXT.to_string()));
        // Someone else's: a file owned by another uid can't be made here, so the copy names another owner instead.
        let other = Place::at(&place.dir, place.owner + 1, place.owner + 1, &place.top);
        write(&other.file, TEXT.as_bytes());
        assert_eq!(read(&other), Found::Unsafe);
    }

    #[test]
    fn a_link_too_large_or_not_text_is_not_trusted() {
        let dir = TempDir::new("halti-approved-links").unwrap();
        let place = place(&dir);
        let elsewhere = dir.0.join("elsewhere.toml");
        write(&elsewhere, TEXT.as_bytes());
        symlink(&elsewhere, &place.file).unwrap();
        assert_eq!(read(&place), Found::Unsafe, "a link to the file is not followed");
        fs::remove_file(&place.file).unwrap();

        let real = dir.0.join("real");
        fs::rename(&place.dir, &real).unwrap();
        symlink(&real, &place.dir).unwrap();
        write(&real.join(place.file.file_name().unwrap()), TEXT.as_bytes());
        assert_eq!(read(&place), Found::Unsafe, "nor is a link to the folder");
        fs::remove_file(&place.dir).unwrap();
        fs::rename(&real, &place.dir).unwrap();
        assert_eq!(read(&place), Found::Text(TEXT.to_string()));

        fs::write(&place.file, "#".repeat(17 << 10)).unwrap();
        assert_eq!(read(&place), Found::Unreadable("it is larger than 16 KiB".to_string()));
        fs::write(&place.file, b"# \xff\n").unwrap();
        assert_eq!(read(&place), Found::Unreadable("it isn't text".to_string()));
        assert!(!folders_safe(&Place::at(&place.dir, 0, place.owner, Path::new("/nowhere"))), "a folder not under top");
    }

    #[test]
    #[cfg(halti_dev)]
    fn a_debug_build_keeps_its_copy_in_its_own_config_folder() {
        let place = Place::real();
        assert!(place.file.starts_with(util::config_dir()) && place.top == util::config_dir(), "{}", place.file.display());
        assert_eq!((place.owner, place.who()), (unsafe { libc::getuid() }, "you"));
    }

    #[test]
    fn a_record_key_is_named_after_the_copy() {
        let key = record_key(TEXT);
        assert!(key.starts_with("config.") && key.len() == 23 && key[7..].bytes().all(|b| b.is_ascii_hexdigit()), "{key}");
        assert_ne!(key, record_key("[paths]\n"));
    }
}
