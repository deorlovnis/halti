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

/// Unlocks the process's memory again, for a process that lives on once the keys it read are
/// wiped: one that runs a box, whose allocations over hours could pass the locked-memory limit and
/// fail. Core dumps stay off. Nothing happens where nothing was locked.
pub fn release() {
    unsafe { libc::munlockall() };
}

/// Locks the pages that hold `len` bytes at `at` in memory, so they never reach swap: the keys of a
/// workspace that stays open. On a Mac `mlockall` doesn't exist, and this is what keeps them out;
/// a page or two, well within any limit. False if the system refused.
pub fn lock_pages(at: *const u8, len: usize) -> bool {
    let page = match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        size if size > 0 => size as usize,
        _ => return false,
    };
    let start = at as usize / page * page;
    let end = (at as usize + len).div_ceil(page) * page;
    unsafe { libc::mlock(start as *const libc::c_void, end - start) == 0 }
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
    fn the_pages_of_a_value_can_be_locked() {
        let keys = Box::new([7u8; 96]);
        assert!(lock_pages(keys.as_ptr(), keys.len()));
        assert!(lock_pages(keys.as_ptr(), 1), "one byte locks its page");
    }

    #[test]
    fn memory_is_locked_only_where_the_limit_leaves_room_for_argon2() {
        assert!(room_for_argon2(libc::RLIM_INFINITY) && room_for_argon2(256 << 20) && room_for_argon2(1 << 40));
        assert!(!room_for_argon2(0) && !room_for_argon2(8 << 20) && !room_for_argon2(64 << 20));
    }
}
