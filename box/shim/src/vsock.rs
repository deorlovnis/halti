//! The door and the exec service over vsock, for a VM whose host dials in on a vsock port instead
//! of through a Unix socket published into the VM (`serve --vsock`).
//!
//! `Stream` is a connected socket held by its descriptor. What the pool, `bridge` and the exec
//! service do with one (read, write, half-close, non-blocking) works on any stream socket, so it
//! is tested on Unix socket pairs on every system. `Listener`, which makes vsock sockets, is
//! Linux only, and only a VM has the device it needs.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd};

/// The peer id the host's connections arrive with: the well-known id of the host
/// (`VMADDR_CID_HOST`). A program in the box that dials the shim's own ports arrives with the
/// VM's id, or the local one (1).
pub const HOST_CID: u32 = 2;

/// Whether a connection from `peer` may be served. Only the host may: a program in the box that
/// reached the door's port would pose as halti, and one that reached the exec port could run
/// anything as root.
pub fn from_host(peer: u32) -> bool {
    peer == HOST_CID
}

/// The connections of `accepted` (each with its peer's id) that `from_host` allows; the others
/// are dropped, which closes them. Accept errors are passed on.
pub fn host_only<S>(accepted: impl Iterator<Item = io::Result<(S, u32)>>) -> impl Iterator<Item = io::Result<S>> {
    accepted.filter_map(|a| match a {
        Ok((stream, peer)) if from_host(peer) => Some(Ok(stream)),
        Ok(_) => None,
        Err(e) => Some(Err(e)),
    })
}

/// A connected stream socket of any family.
pub struct Stream(File);

impl From<OwnedFd> for Stream {
    fn from(fd: OwnedFd) -> Self {
        Self(File::from(fd))
    }
}

impl Stream {
    pub fn try_clone(&self) -> io::Result<Self> {
        self.0.try_clone().map(Self)
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Read => libc::SHUT_RD,
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Both => libc::SHUT_RDWR,
        };
        // SAFETY: shutdown(2) on a descriptor this value owns; it touches no memory.
        cvt(unsafe { libc::shutdown(self.0.as_raw_fd(), how) })
    }

    pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        let fd = self.0.as_raw_fd();
        // SAFETY: fcntl(2) reading and setting the status flags of a descriptor this value owns.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        let flags = if on { flags | libc::O_NONBLOCK } else { flags & !libc::O_NONBLOCK };
        // SAFETY: as above.
        cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) })
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn cvt(result: libc::c_int) -> io::Result<()> {
    if result == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// A vsock socket listening on a port of this VM, for connections from any peer: `host_only`
/// sorts them.
#[cfg(target_os = "linux")]
pub struct Listener(OwnedFd);

#[cfg(target_os = "linux")]
impl Listener {
    /// The kind of socket the host's connections arrive on: a byte stream.
    const SOCKET_TYPE: libc::c_int = libc::SOCK_STREAM;

    pub fn bind(port: u32) -> io::Result<Self> {
        use std::os::fd::FromRawFd;
        let context = |e: io::Error| io::Error::new(e.kind(), format!("listening on vsock port {port}: {e}"));
        // SAFETY: socket(2) returns a new descriptor, which `OwnedFd` then owns alone.
        let fd = unsafe { libc::socket(libc::AF_VSOCK, Self::SOCKET_TYPE | libc::SOCK_CLOEXEC, 0) };
        if fd == -1 {
            return Err(context(io::Error::last_os_error()));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: sockaddr_vm is plain integers, for which all zeroes is a valid value.
        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_port = port;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        let len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        // SAFETY: the address is a live sockaddr_vm of the length given.
        cvt(unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) }).map_err(context)?;
        // SAFETY: listen(2) on the descriptor bound above.
        cvt(unsafe { libc::listen(fd.as_raw_fd(), 128) }).map_err(context)?;
        Ok(Self(fd))
    }

    /// The next connection and its peer's id.
    pub fn accept(&self) -> io::Result<(Stream, u32)> {
        use std::os::fd::FromRawFd;
        // SAFETY: as in `bind`.
        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        // SAFETY: accept4(2) writes at most `len` bytes of the peer's address into `addr`, and
        // returns a new descriptor, which `OwnedFd` then owns alone.
        let fd = unsafe { libc::accept4(self.0.as_raw_fd(), (&raw mut addr).cast(), &mut len, libc::SOCK_CLOEXEC) };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok((Stream::from(unsafe { OwnedFd::from_raw_fd(fd) }), addr.svm_cid))
    }

    /// Every connection from now on, with its peer's id.
    pub fn incoming(self) -> impl Iterator<Item = io::Result<(Stream, u32)>> + Send {
        std::iter::repeat_with(move || self.accept())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn a_connection_from_inside_the_box_is_refused() {
        // The VM's own id (3 in a Mac trial), the local id and an unassigned one, against the host.
        assert!(from_host(HOST_CID));
        for inside in [0, 1, 3, 4, u32::MAX] {
            assert!(!from_host(inside), "peer {inside} is not the host");
        }
        let accepted = vec![Ok(("box", 3)), Ok(("host", HOST_CID)), Err(io::Error::other("busy")), Ok(("local", 1)), Ok(("host again", HOST_CID))];
        let kept: Vec<String> = host_only(accepted.into_iter()).map(|a| a.map_or_else(|e| format!("error {e}"), str::to_string)).collect();
        assert_eq!(kept, ["host", "error busy", "host again"]);
    }

    #[test]
    fn a_stream_reads_writes_and_half_closes() {
        let (a, b) = UnixStream::pair().unwrap();
        let (mut a, mut b) = (Stream::from(OwnedFd::from(a)), Stream::from(OwnedFd::from(b)));
        a.write_all(b"ping").unwrap();
        a.shutdown(Shutdown::Write).unwrap();
        let mut got = Vec::new();
        b.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"ping");

        let mut copy = b.try_clone().unwrap();
        copy.write_all(b"pong").unwrap();
        let mut reply = [0u8; 4];
        a.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"pong");

        b.set_nonblocking(true).unwrap();
        let mut byte = [0u8];
        assert!(matches!(copy.read(&mut byte), Ok(0)), "the other side shut its writing half");
        let (c, _keep) = UnixStream::pair().unwrap();
        let c = Stream::from(OwnedFd::from(c));
        c.set_nonblocking(true).unwrap();
        assert_eq!((&c.0).read(&mut byte).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        c.set_nonblocking(false).unwrap();
    }
}
