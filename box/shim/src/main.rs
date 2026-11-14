//! The shim: the guest side of a halti box's door. Its names, in the VM and on the Mac's command
//! line, are in `names`.
//!
//! A box has no network. halti, on the Mac, dials connections into the Unix socket this daemon
//! listens on (`serve`, the VM's init process); programs in the box talk to local listeners
//! instead, and each of their connections is paired with one of those idle connections from the
//! Mac. The first line sent to the Mac says which listener the program came to:
//!
//! - `proxy`: TCP 127.0.0.1:3128, the HTTP proxy (`serve --bridges`: port 3128 on every address,
//!   so Docker's containers reach it at their bridge's gateway)
//! - `names::DOOR_KIND`: TCP 127.0.0.2:80, `halti.internal` (halti itself)
//! - `mcp`:   `LOCAL_SOCK`, which the shim's `mcp` command (halti's MCP server over stdio) dials
//!
//! After that line the bytes go both ways until both sides are done (half-close aware).
//!
//! In a VM whose host dials in over vsock, `boot` is the VM's first process instead (see `boot`):
//! it starts `serve --vsock`, where the door is a vsock port (`names::DOOR_PORT`) in place of the
//! Unix socket, and the exec service (`exec`) listens on `names::EXEC_PORT`. Both serve only the
//! host (`vsock::from_host`). Nothing starts these modes in a box that Apple's `container` runs.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use std::{env, fs, process, thread};

// Used by `serve --vsock` and `boot`, which only Linux builds; tested on every system.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod boot;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod exec;
mod names;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod vsock;

const RUN_DIR: &str = names::RUN_DIR;
const DOOR_SOCK: &str = names::DOOR_SOCKET;
const LOCAL_SOCK: &str = names::LOCAL_SOCKET;
const PROXY_ADDR: (&str, u16) = ("127.0.0.1", 3128);
/// The proxy for a box with Docker: a container has a network namespace of its own, where
/// 127.0.0.1 is the container itself, so it can only reach the proxy at an address of the VM on
/// its bridge. The VM has no network device, so every address is still inside it.
const PROXY_ALL: (&str, u16) = ("0.0.0.0", 3128);
const HALTI_ADDR: (&str, u16) = ("127.0.0.2", 80);

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args[..] {
        ["serve"] => serve(PROXY_ADDR),
        ["serve", "--bridges"] => serve(PROXY_ALL),
        ["serve", "--vsock"] => serve_vsock(PROXY_ADDR),
        ["serve", "--vsock", "--bridges"] => serve_vsock(PROXY_ALL),
        ["boot"] => boot::main(false),
        ["boot", "--bridges"] => boot::main(true),
        ["mcp"] => UnixStream::connect(LOCAL_SOCK)
            .map_err(|e| io::Error::new(e.kind(), format!("connecting to {LOCAL_SOCK}: {e}")))
            .and_then(|sock| relay(sock, io::stdin(), io::stdout())),
        _ => {
            eprintln!("usage: {} serve [--vsock] [--bridges] | boot [--bridges] | mcp", names::SHIM);
            process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("{}: {e}", names::SHIM);
        process::exit(1);
    }
}

/// A byte stream that can be duplicated and half-closed: TCP, Unix or vsock.
trait Conn: Read + Write + Send + Sized + 'static {
    fn dup(&self) -> io::Result<Self>;
    fn shut(&self, how: Shutdown) -> io::Result<()>;
    fn nonblocking(&self, on: bool) -> io::Result<()>;
}

impl Conn for TcpStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shut(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
    fn nonblocking(&self, on: bool) -> io::Result<()> {
        self.set_nonblocking(on)
    }
}

impl Conn for UnixStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shut(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
    fn nonblocking(&self, on: bool) -> io::Result<()> {
        self.set_nonblocking(on)
    }
}

impl Conn for vsock::Stream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shut(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
    fn nonblocking(&self, on: bool) -> io::Result<()> {
        self.set_nonblocking(on)
    }
}

/// The idle connections the Mac has dialed in, waiting for a client. `H` is a Unix stream when
/// the door dials the published socket, a vsock stream when it dials the door's port.
struct Pool<H> {
    idle: Mutex<VecDeque<H>>,
    arrived: Condvar,
}

impl<H> Default for Pool<H> {
    fn default() -> Self {
        Self { idle: Mutex::default(), arrived: Condvar::default() }
    }
}

impl<H: Conn> Pool<H> {
    fn put(&self, host: H) {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).push_back(host);
        self.arrived.notify_one();
    }

    /// The oldest idle connection that is still open, waiting for one if there is none.
    fn take(&self) -> H {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match idle.pop_front() {
                Some(mut host) => {
                    if still_open(&mut host) {
                        return host;
                    }
                }
                None => idle = self.arrived.wait(idle).unwrap_or_else(|e| e.into_inner()),
            }
        }
    }
}

/// An idle connection has nothing to read; end-of-file, or data nobody asked for, means the Mac
/// side is gone or confused (and the connection is dropped, so a byte consumed here is no loss).
fn still_open<H: Conn>(host: &mut H) -> bool {
    let mut byte = [0u8];
    if host.nonblocking(true).is_err() {
        return false;
    }
    let idle = matches!(host.read(&mut byte), Err(e) if e.kind() == io::ErrorKind::WouldBlock);
    idle && host.nonblocking(false).is_ok()
}

/// Copy `from` to `to` until `from` ends. A clean end is passed on as a half-close, so the other
/// direction can still finish; an error tears both down so the other direction stops too.
fn pump<R: Conn, W: Conn>(mut from: R, mut to: W) {
    let how = if io::copy(&mut from, &mut to).is_ok() { Shutdown::Write } else { Shutdown::Both };
    let _ = to.shut(how);
    if how == Shutdown::Both {
        let _ = from.shut(Shutdown::Both);
    }
}

/// Copy both ways between two streams until each direction has ended.
fn bridge<A: Conn, B: Conn>(a: A, b: B) -> io::Result<()> {
    let (a2, b2) = (a.dup()?, b.dup()?);
    let forward = thread::spawn(move || pump(a, b2));
    pump(b, a2);
    let _ = forward.join();
    Ok(())
}

/// Pair one client with an idle connection from the Mac, tell the Mac which listener the client
/// came to, and carry the bytes.
fn serve_client<C: Conn, H: Conn>(client: C, kind: &str, pool: &Pool<H>) -> io::Result<()> {
    let host = loop {
        let mut host = pool.take();
        if host.write_all(format!("{kind}\n").as_bytes()).is_ok() {
            break host;
        }
    };
    bridge(client, host)
}

/// A thread per client, so one slow or broken client never holds up the rest.
fn accept_loop<C: Conn, H: Conn>(incoming: impl Iterator<Item = io::Result<C>>, kind: &'static str, pool: Arc<Pool<H>>) {
    for client in incoming {
        match client {
            Ok(client) => {
                let pool = pool.clone();
                thread::spawn(move || {
                    let _ = serve_client(client, kind, &pool);
                });
            }
            // e.g. out of file descriptors: wait for some to free up
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// Everything the Mac dials in goes into the pool.
fn collect_hosts<H: Conn>(hosts: impl Iterator<Item = io::Result<H>>, pool: Arc<Pool<H>>) {
    for host in hosts {
        match host {
            Ok(host) => pool.put(host),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn bind_unix(path: &str, mode: u32) -> io::Result<UnixListener> {
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path).map_err(|e| io::Error::new(e.kind(), format!("listening on {path}: {e}")))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

fn bind_tcp(addr: (&str, u16)) -> io::Result<TcpListener> {
    TcpListener::bind(addr).map_err(|e| io::Error::new(e.kind(), format!("listening on {}:{}: {e}", addr.0, addr.1)))
}

/// The init process of the VM: the listeners, and the pool the Mac fills. Returns only on a
/// startup error; client trouble never ends it.
fn serve(proxy: (&str, u16)) -> io::Result<()> {
    run_dir()?;
    // Only root may connect to the door socket: a program in the box must not pose as the Mac.
    let door = bind_unix(DOOR_SOCK, 0o600)?;
    listen(std::iter::repeat_with(move || door.accept().map(|(host, _)| host)), proxy)
}

/// `serve --vsock`, started by `boot`: the door is a vsock port, and the exec service listens on
/// another. Both take connections from the host only.
#[cfg(target_os = "linux")]
fn serve_vsock(proxy: (&str, u16)) -> io::Result<()> {
    run_dir()?;
    let door = vsock::Listener::bind(names::DOOR_PORT)?;
    let exec = vsock::Listener::bind(names::EXEC_PORT)?;
    thread::spawn(move || exec::accept_loop(vsock::host_only(exec.incoming()), Arc::new(exec::Users::guest())));
    listen(vsock::host_only(door.incoming()), proxy)
}

#[cfg(not(target_os = "linux"))]
fn serve_vsock(_proxy: (&str, u16)) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "serve --vsock runs only in a Linux VM"))
}

fn run_dir() -> io::Result<()> {
    fs::create_dir_all(RUN_DIR)?;
    fs::set_permissions(RUN_DIR, fs::Permissions::from_mode(0o755))
}

/// The box's listeners, and the pool that the door's connections (`hosts`) fill.
fn listen<H: Conn>(hosts: impl Iterator<Item = io::Result<H>> + Send + 'static, proxy: (&str, u16)) -> io::Result<()> {
    let pool = Arc::new(Pool::default());
    let local = bind_unix(LOCAL_SOCK, 0o666)?;
    let proxy = bind_tcp(proxy)?;
    let halti = bind_tcp(HALTI_ADDR)?;

    let p = pool.clone();
    thread::spawn(move || collect_hosts(hosts, p));
    let p = pool.clone();
    thread::spawn(move || accept_loop(local.incoming(), "mcp", p));
    let p = pool.clone();
    thread::spawn(move || accept_loop(proxy.incoming(), "proxy", p));
    accept_loop(halti.incoming(), names::DOOR_KIND, pool);
    Ok(())
}

/// `mcp`: carry `input` and `output` (an MCP client's stdio) over `sock`, which the
/// daemon pairs with halti's MCP server. Ends when the server hangs up.
fn relay(sock: UnixStream, mut input: impl Read + Send + 'static, mut output: impl Write) -> io::Result<()> {
    let mut up = sock.try_clone()?;
    thread::spawn(move || {
        let _ = io::copy(&mut input, &mut up);
        // stdin ended: tell the server, which answers what is left and hangs up
        let _ = up.shutdown(Shutdown::Write);
    });
    let mut down = sock;
    let mut buf = [0u8; 16 * 1024];
    loop {
        match down.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                output.write_all(&buf[..n])?;
                output.flush()?;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    /// A connected pair standing in for (halti's end, the pool's end) of a dialed-in connection.
    fn dialed() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (client, listener.accept().unwrap().0)
    }

    #[test]
    fn pairs_a_client_with_a_host_and_names_the_kind() {
        let pool = Pool::default();
        let (mac, shim_end) = dialed();
        pool.put(shim_end);
        let (mut program, client) = tcp_pair();
        let handle = thread::spawn(move || serve_client(client, "proxy", &pool));

        let mut mac = BufReader::new(mac);
        let mut line = String::new();
        mac.read_line(&mut line).unwrap();
        assert_eq!(line, "proxy\n");

        program.write_all(b"CONNECT example.com:443\n").unwrap();
        line.clear();
        mac.read_line(&mut line).unwrap();
        assert_eq!(line, "CONNECT example.com:443\n");

        mac.get_mut().write_all(b"200\n").unwrap();
        let mut reply = [0u8; 4];
        program.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"200\n");

        drop(program);
        mac.get_mut().shutdown(Shutdown::Both).unwrap();
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn half_close_still_lets_the_reply_through() {
        let pool = Pool::default();
        let (mac, shim_end) = dialed();
        pool.put(shim_end);
        let (mut program, client) = tcp_pair();
        thread::spawn(move || serve_client(client, names::DOOR_KIND, &pool));

        program.write_all(b"request").unwrap();
        program.shutdown(Shutdown::Write).unwrap();

        // the Mac reads the kind line and the request up to end-of-file, then answers
        let mut mac = mac;
        let mut got = String::new();
        mac.read_to_string(&mut got).unwrap();
        assert_eq!(got, format!("{}\nrequest", names::DOOR_KIND));
        mac.write_all(b"response").unwrap();
        mac.shutdown(Shutdown::Write).unwrap();

        let mut reply = String::new();
        program.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "response");
    }

    #[test]
    fn skips_hosts_that_have_gone() {
        let pool = Pool::default();
        let (gone, gone_shim) = dialed();
        drop(gone);
        pool.put(gone_shim);
        let (mut mac, live_shim) = dialed();
        pool.put(live_shim);

        let (_program, client) = tcp_pair();
        thread::spawn(move || serve_client(client, "mcp", &pool));

        let mut line = [0u8; 4];
        mac.read_exact(&mut line).unwrap();
        assert_eq!(&line, b"mcp\n");
    }

    #[test]
    fn waits_for_a_host_to_arrive() {
        let pool = Arc::new(Pool::default());
        let (mut program, client) = tcp_pair();
        let p = pool.clone();
        thread::spawn(move || serve_client(client, "proxy", &p));
        thread::sleep(Duration::from_millis(100));

        let (mut mac, shim_end) = dialed();
        pool.put(shim_end);
        program.write_all(b"x").unwrap();
        let mut got = [0u8; 7];
        mac.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"proxy\nx");
    }

    #[test]
    fn a_client_that_vanishes_does_not_stop_the_listener() {
        let pool = Arc::new(Pool::default());
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let p = pool.clone();
        thread::spawn(move || accept_loop(listener.incoming(), "proxy", p));

        let mut macs = Vec::new();
        for _ in 0..2 {
            let (mac, shim_end) = dialed();
            pool.put(shim_end);
            macs.push(mac);
            // connect, send a little, and go
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(b"junk").unwrap();
            drop(c);
        }
        for mac in &mut macs {
            let mut got = String::new();
            BufReader::new(mac).read_line(&mut got).unwrap();
            assert_eq!(got, "proxy\n");
        }
    }

    #[test]
    fn relay_carries_stdio_both_ways_and_ends_with_the_server() {
        let (server, sock) = dialed();
        let (mut stdin_w, stdin_r) = dialed();
        let (stdout_w, mut stdout_r) = dialed();
        let handle = thread::spawn(move || relay(sock, stdin_r, stdout_w));

        stdin_w.write_all(b"{\"id\":1}\n").unwrap();
        let mut server = BufReader::new(server);
        let mut line = String::new();
        server.read_line(&mut line).unwrap();
        assert_eq!(line, "{\"id\":1}\n");

        server.get_mut().write_all(b"{\"result\":1}\n").unwrap();
        let mut reply = [0u8; 13];
        stdout_r.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"{\"result\":1}\n");

        // stdin ends: the server sees end-of-file, and hanging up ends the relay
        stdin_w.shutdown(Shutdown::Write).unwrap();
        let mut rest = String::new();
        server.read_line(&mut rest).unwrap();
        assert_eq!(rest, "");
        drop(server);
        handle.join().unwrap().unwrap();
    }

    /// The door's connections arrive as vsock streams in a VM that boots itself; the pool, the
    /// check for gone hosts and the bridge work on them as on Unix streams. A Unix socket pair
    /// stands in for the vsock socket, which only a VM has.
    #[test]
    fn the_pool_works_over_either_socket_type() {
        use std::os::fd::OwnedFd;
        let vsock = |s: UnixStream| vsock::Stream::from(OwnedFd::from(s));
        let pool = Arc::new(Pool::<vsock::Stream>::default());
        let (gone, gone_shim) = dialed();
        drop(gone);
        pool.put(vsock(gone_shim));
        let (mac, shim_end) = dialed();
        pool.put(vsock(shim_end));

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let p = pool.clone();
        thread::spawn(move || accept_loop(listener.incoming(), "proxy", p));
        let mut program = TcpStream::connect(addr).unwrap();
        program.write_all(b"request").unwrap();
        program.shutdown(Shutdown::Write).unwrap();

        let mut mac = mac;
        let mut got = String::new();
        mac.read_to_string(&mut got).unwrap();
        assert_eq!(got, "proxy\nrequest");
        mac.write_all(b"response").unwrap();
        mac.shutdown(Shutdown::Write).unwrap();
        let mut reply = String::new();
        program.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "response");

        // and the hosts can come from any iterator of streams, as the vsock listener gives them
        let (mut mac, shim_end) = dialed();
        let p = pool.clone();
        thread::spawn(move || collect_hosts(std::iter::once(Ok(vsock(shim_end))), p));
        let (_program, client) = tcp_pair();
        thread::spawn(move || serve_client(client, names::DOOR_KIND, &pool));
        let mut line = [0u8; 6];
        mac.read_exact(&mut line).unwrap();
        assert_eq!(&line, b"halti\n");
    }
}
