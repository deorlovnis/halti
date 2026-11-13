//! Keeping what a passphrase command handles out of core dumps and, where this system allows, out of
//! swap: the passphrase, the key Argon2id derives from it with all its memory, the seed and the
//! workspace's keys. Only the commands that read a passphrase do this, once, before reading it.
//!
//! Locking is for the whole process (`mlockall`), since those buffers are made inside core and the
//! crates it is built on, where nothing can lock them one by one. It is tried only where the
//! locked-memory limit leaves room for Argon2id: once locking covers future memory, an allocation
//! past the limit fails.

/// The least locked-memory limit locking is tried under: Argon2id's 64 MiB, the program, and room to spare.
const ROOM: libc::rlim_t = 256 << 20;

/// Turns core dumps off for this process (on Linux it can't be dumped or attached to either), then
/// locks its memory if the limit leaves room. Where locking fails, nothing is left half locked.
pub fn harden() {
    let off = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &off) };
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0)
    };
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0 || !room_for_argon2(limit.rlim_cur) {
        return;
    }
    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
        unsafe { libc::munlockall() };
    }
}

/// Whether a locked-memory limit leaves room for what a passphrase command allocates.
fn room_for_argon2(limit: libc::rlim_t) -> bool {
    limit == libc::RLIM_INFINITY || limit >= ROOM
}

#[cfg(test)]
mod tests {
    use super::*;

    // `harden` itself runs only in the commands' own processes (tests/e2e.rs): in this one it
    // would lock the memory of every test.

    #[test]
    fn memory_is_locked_only_where_the_limit_leaves_room_for_argon2() {
        assert!(room_for_argon2(libc::RLIM_INFINITY) && room_for_argon2(256 << 20) && room_for_argon2(1 << 40));
        assert!(!room_for_argon2(0) && !room_for_argon2(8 << 20) && !room_for_argon2(64 << 20));
    }
}
