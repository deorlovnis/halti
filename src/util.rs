//! Small helpers shared by several commands.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{env, fs, process};

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::legacy;
use crate::names;

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Debug builds keep their files apart from an installed halti's, so a test build never reads or
/// changes the real index, policies and boxes.
pub const DEV_CONFIG_DIR: &str = ".config/halti-dev";
pub const DEV_STORE_ROOT: &str = "Library/Application Support/halti-dev";

/// The home folder. Release builds take it from the passwd entry and ignore `HOME`, so the
/// environment can't move halti's files; debug builds honour `HOME`, which tests set. Empty when
/// there's no absolute one (a uid without a passwd entry), and then `main` refuses to run, since
/// every path would be relative to the current folder.
pub fn home() -> PathBuf {
    #[cfg(halti_dev)]
    if let Some(home) = env::var_os("HOME").map(PathBuf::from).filter(|h| h.is_absolute()) {
        return home;
    }
    passwd_home().filter(|h| h.is_absolute()).unwrap_or_default()
}

/// The home folder in the passwd entry of the user halti runs as.
fn passwd_home() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;

    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 4096];
    loop {
        let err = unsafe { libc::getpwuid_r(libc::getuid(), &mut entry, buf.as_mut_ptr(), buf.len(), &mut found) };
        match err {
            0 => break,
            libc::ERANGE if buf.len() < 1 << 20 => buf.resize(buf.len() * 2, 0),
            _ => return None,
        }
    }
    if found.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

pub fn config_dir() -> PathBuf {
    home().join(if cfg!(halti_dev) { DEV_CONFIG_DIR } else { names::CONFIG_DIR })
}

/// Box stores, mount points and locks (`box/`) and downloads.
pub fn store_root() -> PathBuf {
    home().join(if cfg!(halti_dev) { DEV_STORE_ROOT } else { names::STORE_ROOT })
}

/// The two names of a user-facing environment variable: `HALTI_<suffix>`, then the old
/// `CRED_<suffix>`. Refresh scripts get both, since their bytes are pinned.
pub fn env_names(suffix: &str) -> [String; 2] {
    [format!("HALTI_{suffix}"), format!("{}{suffix}", legacy::ENV_PREFIX)]
}

/// A user-facing environment variable: `HALTI_<suffix>`, or else the old `CRED_<suffix>`. Release
/// builds read only the suffixes on the list in tests/source.rs, none of which picks where
/// halti keeps its files or what protects them.
pub fn env_var(suffix: &str) -> Option<OsString> {
    env_names(suffix).iter().find_map(env::var_os)
}

/// A test hook's variable, such as `HALTI_TEST_APPROVE`. Only debug builds have this, so nothing
/// in the environment can switch a release build's protections off or move its files.
#[cfg(halti_dev)]
pub fn dev_var(name: &str) -> Option<OsString> {
    env::var_os(name)
}

/// Expand a leading "~/" to the home directory.
pub fn expand_home(path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => home().join(rest),
        None => PathBuf::from(path),
    }
}

/// A private temporary directory (mode 700), removed when dropped.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(prefix: &str) -> Result<Self> {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let n = COUNT.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!("{prefix}-{}-{n}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        Ok(Self(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runs `read` with SIGINT ignored, then puts back what was there. rpassword reads Ctrl-C as a key
/// and raises SIGINT itself before it says the read was interrupted: by default that ends halti
/// there and then, with the terminal left raw and an unfinished workspace's record left behind.
/// The terminal sends no SIGINT of its own while rpassword reads, so no other Ctrl-C is lost. While
/// sudo runs, Ctrl-C ends sudo alone, which puts SIGINT back to default for itself.
pub fn sigint_ignored<T>(read: impl FnOnce() -> T) -> T {
    let before = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
    let got = read();
    if before != libc::SIG_ERR {
        unsafe { libc::signal(libc::SIGINT, before) };
    }
    got
}

/// Put stdin, stdout and stderr back in blocking mode. A program that shared the terminal
/// (`container`'s progress display, say) can leave it non-blocking, and then a long print fails
/// with EAGAIN, which panics before any prompt is shown.
pub fn blocking_stdio() {
    for fd in 0..3 {
        set_blocking(fd);
    }
}

fn set_blocking(fd: i32) {
    // The values of <fcntl.h> on macOS.
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    #[cfg(target_os = "linux")]
    const O_NONBLOCK: i32 = 0o4000;
    #[cfg(not(target_os = "linux"))]
    const O_NONBLOCK: i32 = 0x0004;
    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags >= 0 && flags & O_NONBLOCK != 0 {
            fcntl(fd, F_SETFL, flags & !O_NONBLOCK);
        }
    }
}

unsafe extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn the_passwd_home_is_a_folder() {
        let home = super::passwd_home().unwrap();
        assert!(home.is_absolute() && home.is_dir(), "{}", home.display());
    }

    #[test]
    fn debug_builds_keep_their_own_files() {
        assert!(super::config_dir().ends_with(super::DEV_CONFIG_DIR) && super::store_root().ends_with(super::DEV_STORE_ROOT));
    }

    #[test]
    fn environment_variables_have_the_new_name_first() {
        assert_eq!(super::env_names("WARN_DAYS"), ["HALTI_WARN_DAYS".to_string(), format!("{}WARN_DAYS", crate::legacy::ENV_PREFIX)]);
    }

    /// What rpassword does on Ctrl-C, raising SIGINT, ends the read and not the process, and what
    /// SIGINT did before is back after.
    #[test]
    fn ctrl_c_at_a_prompt_ends_the_question_not_halti() {
        let was = unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
        let (raised, during) = super::sigint_ignored(|| unsafe { (libc::raise(libc::SIGINT), libc::signal(libc::SIGINT, libc::SIG_IGN)) });
        let after = unsafe { libc::signal(libc::SIGINT, was) };
        assert_eq!((raised, during, after), (0, libc::SIG_IGN, libc::SIG_DFL));
    }

    #[test]
    fn a_non_blocking_descriptor_blocks_again() {
        let (mut a, _b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        assert_eq!(a.read(&mut [0; 1]).unwrap_err().kind(), ErrorKind::WouldBlock);
        super::set_blocking(a.as_raw_fd());
        // Blocking again: a read waits, so only the timeout ends it.
        a.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        assert_eq!(a.read(&mut [0; 1]).unwrap_err().kind(), ErrorKind::WouldBlock);
        let started = std::time::Instant::now();
        let _ = a.read(&mut [0; 1]);
        assert!(started.elapsed() >= Duration::from_millis(40));
    }
}
