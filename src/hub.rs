//! The hub: `halti hub serve`, a listener that phones and machines reach over TLS, with a table of
//! who may use it. It carries what they send each other; it holds no key of any workspace and
//! nothing that can say yes. The wire it speaks is in `wire`, the table's rules in `table`.
//!
//! It runs as a user of its own, which can open no workspace: the service unit is in
//! `service/halti-hub.service`. Its files are in `hub/` in that user's config folder, which only
//! that user can open:
//!
//! - `tls-key.pem`: the TLS key, made at the first start. Its pin, the SHA-256 of its public key's
//!   DER, is what clients learn when they pair. A new key means pairing everything again.
//! - `table.json`: the rows of the table, rewritten whole at each change.
//! - `admin.sock`: the socket `halti pair`, `halti devices` and `halti revoke` reach the running hub
//!   through, as the same user (see `admin`).
//!
//! Pairings under way, the renewal nonces used, the key renewal nonces are made with, how many
//! connections are open, and all that the hub carries between machines and phones (`relay`) live in
//! memory only.
//!
//! A change the table can't write down is not reported as made. One that would let a token work, a
//! pairing or a renewal, is undone and refused. One that stops a token (a revoke, a `token
//! conflict` mark, a row deleted at day 90) holds in memory, `halti revoke` says that a restart
//! would undo it, and the hub tries the write again at every later call.

mod admin;
mod listen;
pub mod pin;
mod relay;
mod table;
pub mod wire;

#[cfg(test)]
pub mod testing;
#[cfg(test)]
mod tests;

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};
use rustls::ServerConfig;
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::util;
use relay::Relay;
use table::{Row, Table};

pub use admin::{devices, pair, revoke};
pub use listen::STATE_BODY_MAX;
pub use relay::{ITEMS_MAX, REPORT_IDS_MAX, REPORT_MAX};

/// What the hub's certificate names. Clients check only its key.
const CERT_NAME: &str = "halti-hub";
/// The protocol offered with ALPN.
const ALPN: &[u8] = b"http/1.1";
/// Ports the hub never listens on: a box's door connects to these, so a door taken over could reach
/// a hub there on the same machine.
const DOOR_PORTS: [u16; 3] = [53, 80, 443];
/// How long a machine's call for what phones sent it waits for something to come, at most.
pub const INBOX_WAIT: Duration = Duration::from_secs(25);
/// How long a phone's call to be told what waits is held, at most, when nothing changes.
pub const WAIT_HOLD: Duration = Duration::from_secs(240);

/// How often an agent's notice may end a phone's held call to be told what waits: once in `gap` for
/// a phone, and in `window`, `per_box` times for one box and `per_machine` times for one machine.
/// A request ends it at once, whatever these say.
#[derive(Clone, Copy, Debug)]
pub struct AgentLimits {
    pub gap: Duration,
    pub window: Duration,
    pub per_box: usize,
    pub per_machine: usize,
}

pub const AGENT_LIMITS: AgentLimits = AgentLimits { gap: Duration::from_secs(10), window: Duration::from_secs(3600), per_box: 6, per_machine: 20 };

/// The time, as the hub counts days. Tests pass one they move by hand.
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// The running hub's state, shared by the listener's threads and the admin socket's.
pub struct Hub {
    dir: PathBuf,
    pin: [u8; 32],
    /// What renewal nonces are made with: drawn at each start, so a restart ends the ones given out.
    nonce_key: [u8; 32],
    /// Where clients reach it, as the pairing string says.
    address: String,
    clock: Arc<dyn Clock>,
    table: Mutex<Table>,
    /// Woken at every change to the table, for a `halti pair` that waits for its claim.
    changed: Condvar,
    /// What it carries between machines and phones.
    relay: Mutex<Relay>,
    /// Woken when a phone sends a machine something, or a row is revoked.
    sent: Condvar,
    /// How long a machine's call for what phones sent it waits; tests make it shorter.
    inbox_wait: Duration,
    /// The phones' held calls to be told what waits.
    waits: Mutex<Waits>,
    /// Woken when what a phone may see could have changed, or a phone calls again.
    stirred: Condvar,
    /// How long such a call is held; tests make it shorter.
    wait_hold: Duration,
    /// How often an agent's notice may end such a call; tests make them shorter.
    agent_limits: AgentLimits,
}

/// Which held call of each phone is its newest, how often the hub was stirred, and each phone's
/// wake-ups for agents' notices.
#[derive(Default)]
struct Waits {
    newest: std::collections::HashMap<String, u64>,
    stirs: u64,
    agents: std::collections::HashMap<String, listen::Agents>,
}

/// The table's file.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    rows: Vec<Row>,
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Hub {
    /// The hub whose files are in `dir`, its table read from there.
    fn open(dir: &Path, address: &str, pin: [u8; 32], clock: Arc<dyn Clock>) -> Result<Hub> {
        let path = dir.join("table.json");
        let table = match fs::read(&path) {
            Ok(bytes) => {
                let stored: Stored = serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))?;
                if stored.version != 1 {
                    bail!("{} was written by another version of halti", path.display());
                }
                Table::from_rows(stored.rows).map_err(|why| anyhow::anyhow!("reading {}: {why}", path.display()))?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Table::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Hub {
            dir: dir.to_path_buf(),
            pin,
            nonce_key: util::random(),
            address: address.to_string(),
            clock,
            table: Mutex::new(table),
            changed: Condvar::new(),
            relay: Mutex::default(),
            sent: Condvar::new(),
            inbox_wait: INBOX_WAIT,
            waits: Mutex::default(),
            stirred: Condvar::new(),
            wait_hold: WAIT_HOLD,
            agent_limits: AGENT_LIMITS,
        })
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Wakes the phones' held calls to look again.
    fn stir(&self) {
        locked(&self.waits).stirs += 1;
        self.stirred.notify_all();
    }

    /// Runs `f` on the table at the hub's time, writes the rows down if they changed, and wakes
    /// whoever waits for a change.
    fn with_table<T>(&self, f: impl FnOnce(&mut Table, Timestamp) -> T) -> T {
        self.with_table_written(f).0
    }

    /// As `with_table`, and whether the file now holds every change: false when the write failed.
    /// That is said on stderr, and the changes stay in memory; every later call tries the write
    /// again.
    fn with_table_written<T>(&self, f: impl FnOnce(&mut Table, Timestamp) -> T) -> (T, bool) {
        let mut table = locked(&self.table);
        let now = self.now();
        let out = f(&mut table, now);
        let written = self.write(&mut table);
        drop(table);
        self.changed.notify_all();
        (out, written)
    }

    /// As `with_table`, for a change that lets a token work: a pairing or a renewal. If `f` made it
    /// and it can't be written down, it is undone and None comes back, so nobody is told of a token
    /// that a restart would forget.
    fn grant<T, E>(&self, f: impl FnOnce(&mut Table, Timestamp) -> Result<T, E>) -> Option<Result<T, E>> {
        let mut table = locked(&self.table);
        let before = table.clone();
        let now = self.now();
        let out = f(&mut table, now);
        let written = self.write(&mut table);
        if out.is_ok() && !written {
            *table = before;
        }
        drop(table);
        self.changed.notify_all();
        (out.is_err() || written).then_some(out)
    }

    /// Writes the rows down if they changed since the last write that worked; whether the file
    /// holds them.
    fn write(&self, table: &mut Table) -> bool {
        if !table.take_dirty() {
            return true;
        }
        match self.save(table) {
            Ok(()) => true,
            Err(e) => {
                util::warn(&format!("{e:#}"));
                table.set_dirty();
                false
            }
        }
    }

    fn save(&self, table: &Table) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&Stored { version: 1, rows: table.rows() })?;
        util::replace_private(&self.dir.join("table.json"), &bytes)
    }
}

/// The hub's folder, made if it isn't there, and open to this user alone.
fn folder() -> Result<PathBuf> {
    let dir = util::config_dir().join("hub");
    DirBuilder::new().recursive(true).mode(0o700).create(&dir).with_context(|| format!("making {}", dir.display()))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).with_context(|| format!("securing {}", dir.display()))?;
    Ok(dir)
}

/// The hub's TLS key, read from its file, or made and written there the first time.
fn tls_key(dir: &Path) -> Result<KeyPair> {
    let path = dir.join("tls-key.pem");
    match fs::read_to_string(&path) {
        Ok(pem) => return KeyPair::from_pem(&pem).with_context(|| format!("reading {}", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("making the hub's TLS key")?;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).with_context(|| format!("writing {}", path.display()))?;
    file.write_all(key.serialize_pem().as_bytes()).and_then(|()| file.sync_all()).with_context(|| format!("writing {}", path.display()))?;
    Ok(key)
}

/// The pin of a key: the SHA-256 of its public key's DER.
fn pin_of(key: &KeyPair) -> [u8; 32] {
    Sha256::digest(key.subject_public_key_info()).into()
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// TLS 1.3 only, with a certificate made now for `key`: its dates and name check nothing, since a
/// client checks only the key.
fn server_config(key: &KeyPair) -> Result<Arc<ServerConfig>> {
    let mut params = CertificateParams::new(vec![CERT_NAME.to_string()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CERT_NAME);
    params.distinguished_name = dn;
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(20 * 365);
    let cert = params.self_signed(key).context("making the hub's certificate")?;
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], der)?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// Whether only a private network reaches this address: loopback, the private ranges, link-local,
/// and the shared range that Tailscale uses. An unspecified one (`0.0.0.0`, `::`) is every address.
fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// What `--listen` and `--address` say: where to listen, and where clients reach it. A warning to
/// show comes too, for an address the internet may reach.
fn addresses(listen: &str, address: Option<&str>) -> Result<(SocketAddr, String, Option<String>)> {
    let at: SocketAddr = listen.parse().map_err(|_| anyhow::anyhow!("--listen takes an IP address and a port, e.g. 10.0.0.5:8443 or [fd00::5]:8443"))?;
    if DOOR_PORTS.contains(&at.port()) {
        bail!("the hub doesn't listen on port {}: a box's door connects to it. use another, e.g. 8443", at.port());
    }
    let address = match address {
        Some(given) => {
            wire::check_address(given).map_err(anyhow::Error::msg)?;
            given.to_string()
        }
        None if at.ip().is_unspecified() => bail!("{at} isn't an address phones and machines can reach: say which with --address HOST:PORT"),
        None => at.to_string(),
    };
    let warning = (!private(at.ip())).then(|| format!("{at} may be reached from the internet. a private network (WireGuard, Tailscale) keeps the hub's listener off it"));
    Ok((at, address, warning))
}

/// `halti hub serve --listen ADDR`: runs the hub until it is stopped.
pub fn serve(listen: &str, address: Option<&str>) -> Result<()> {
    let (at, address, warning) = addresses(listen, address)?;
    if let Some(warning) = warning {
        util::warn(&warning);
    }
    let dir = folder()?;
    let Some(admin) = crate::keep::bind(&dir.join("admin.sock"))? else { bail!("a hub runs already as this user ({})", dir.display()) };
    let key = tls_key(&dir)?;
    let pin = pin_of(&key);
    let config = server_config(&key)?;
    let hub = Arc::new(Hub::open(&dir, &address, pin, Arc::new(SystemClock))?);
    let listener = TcpListener::bind(at).with_context(|| format!("listening on {at}"))?;
    util::say(&format!("hub listening on {at}, reached at {address}"));
    util::say(&format!("pin {}", util::hex(&pin)));
    let admin_hub = hub.clone();
    thread::spawn(move || admin::serve(admin_hub, admin));
    listen::run(hub, listener, config, listen::Limits::HUB);
    Ok(())
}
