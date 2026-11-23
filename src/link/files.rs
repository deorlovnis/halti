//! The link's folder: `link/` in halti's config folder, open to the box-running user alone, on the
//! system volume so the link can start after a boot with every workspace closed. Its files:
//!
//! - `machine-key.pem`: the machine key, a P-256 key for key agreement, as PKCS#8. `halti hub join`
//!   makes it if there is none and keeps one that is there; only `halti hub leave` deletes it. The
//!   hub and the phones know its public half; the link never reads it. Text for a phone is sealed
//!   with it (`sealing_key`) to the phone's second key, which `trusted.json` keeps.
//! - `link.json`: the hub's address and pin, the name the hub knows this machine by, the machine
//!   token, and a new token a renewal was sent for and not yet seen to work. `halti hub join`,
//!   `halti hub leave` and the link change it one at a time under `link.lock`, and the link writes
//!   only over what it read there.
//! - `trusted.json`: the devices this machine trusts (`halti devices trust`), each with its keys
//!   and the workspaces it may answer for. Open workspaces read it at each signed answer or stop;
//!   `devices trust`, `devices untrust` and the link change it, one at a time under `trusted.lock`.
//! - `refused`: the word the hub last refused the machine token with, while it does.
//! - `link.sock`: the running link's socket (`super::run`).
//!
//! Every file is written whole, 0600, and put in place with a rename.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use halti_core::device::{self, DeviceKey};
use halti_core::ids::WsName;
use halti_core::sealed::{AgreementKey, SecretKey};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::hub::wire;
use crate::requests::Trusted;
use crate::util;

/// What `link.json` holds.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Joined {
    pub version: u32,
    /// Where the hub is: `HOST:PORT`.
    pub address: String,
    /// The SHA-256 of the hub's TLS public key, in hex.
    pub pin: String,
    /// The name the hub knows this machine by.
    pub name: String,
    pub token: String,
    /// A token a renewal was sent for: tried first, since the hub may have taken it.
    pub next: Option<String>,
}

impl Joined {
    pub fn pin(&self) -> Result<[u8; 32]> {
        wire::unhex(&self.pin).ok_or_else(|| anyhow::anyhow!("link.json's pin isn't 32 bytes of hex"))
    }
}

/// A device this machine trusts, as `trusted.json` keeps it: its keys in hex.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub signing_key: String,
    pub agreement_key: String,
    /// The signing key's signature over the agreement key.
    pub key_signature: String,
    pub ws: Vec<WsName>,
}

impl Entry {
    /// The device as an open workspace checks against it, if its keys read and its signing key
    /// vouches for its agreement key.
    pub fn trusted(&self) -> Option<Trusted> {
        let signing = util::unhex(&self.signing_key)?;
        let agreement = util::unhex(&self.agreement_key)?;
        let key = DeviceKey::from_spki(&signing).ok()?;
        device::check_agreement_key(&agreement).ok()?;
        key.verify(&wire::keys_bytes(&signing, &agreement), &util::unhex(&self.key_signature)?).ok()?;
        Some(Trusted { name: self.name.clone(), key, fingerprint: wire::fingerprint(&signing), ws: self.ws.iter().map(|ws| ws.to_string()).collect() })
    }

    /// Its second key, which text for it is sealed to, if its keys read and its signing key vouches
    /// for this one.
    pub fn second_key(&self) -> Option<AgreementKey> {
        self.trusted()?;
        AgreementKey::from_spki(&util::unhex(&self.agreement_key)?).ok()
    }

    /// The workspaces it may answer for, as text.
    pub fn ws_names(&self) -> Vec<String> {
        self.ws.iter().map(|ws| ws.to_string()).collect()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    devices: Vec<Entry>,
}

/// The link's folder.
#[derive(Clone, Debug)]
pub struct Folder {
    path: PathBuf,
}

impl Folder {
    /// This user's.
    pub fn here() -> Folder {
        Folder { path: util::config_dir().join("link") }
    }

    #[cfg(test)]
    pub fn at(path: &Path) -> Folder {
        Folder { path: path.to_path_buf() }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn socket(&self) -> PathBuf {
        self.file("link.sock")
    }

    /// Makes the folder if it isn't there, open to this user alone.
    pub fn make(&self) -> Result<()> {
        DirBuilder::new().recursive(true).mode(0o700).create(&self.path).with_context(|| format!("making {}", self.path.display()))?;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700)).with_context(|| format!("securing {}", self.path.display()))
    }

    /// What `link.json` says, or None if this machine hasn't joined a hub.
    pub fn joined(&self) -> Result<Option<Joined>> {
        let path = self.file("link.json");
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let joined: Joined = serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))?;
        if joined.version != 1 {
            bail!("{} was written by another version of halti", path.display());
        }
        Ok(Some(joined))
    }

    pub fn write_joined(&self, joined: &Joined) -> Result<()> {
        self.make()?;
        let _lock = Locked::take(&self.file("link.lock"))?;
        util::replace_private(&self.file("link.json"), &serde_json::to_vec_pretty(joined)?)
    }

    /// Writes `to` in place of `from`, if `link.json` still says `from`: whether it did. A leave or
    /// a join since is left as it is.
    pub fn change_joined(&self, from: &Joined, to: &Joined) -> Result<bool> {
        self.make()?;
        let _lock = Locked::take(&self.file("link.lock"))?;
        if self.joined()?.as_ref() != Some(from) {
            return Ok(false);
        }
        util::replace_private(&self.file("link.json"), &serde_json::to_vec_pretty(to)?)?;
        Ok(true)
    }

    /// The machine key, if there is one.
    pub fn machine_key(&self) -> Result<Option<KeyPair>> {
        let path = self.file("machine-key.pem");
        match fs::read_to_string(&path) {
            Ok(pem) => Ok(Some(KeyPair::from_pem(&pem).with_context(|| format!("reading {}", path.display()))?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// The machine key, if there is one, as text is sealed with: the same key from the same file.
    /// The link calls this for each thing it seals, so every copy of the key it makes is wiped:
    /// the file is read here, not through rcgen, whose `KeyPair` keeps a copy it doesn't wipe.
    pub fn sealing_key(&self) -> Result<Option<SecretKey>> {
        let path = self.file("machine-key.pem");
        // `fs::read` sizes the buffer from the file's length, so it isn't grown and copied.
        let pem = match fs::read(&path) {
            Ok(pem) => Zeroizing::new(pem),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let unreadable = || anyhow!("{} isn't a P-256 key in the form halti writes", path.display());
        let der = pkcs8_of_pem(&pem).ok_or_else(unreadable)?;
        Ok(Some(SecretKey::from_pkcs8(&der).map_err(|_| unreadable())?))
    }

    /// The machine key that is there, or one made now; and whether it was made.
    pub fn keep_machine_key(&self) -> Result<(KeyPair, bool)> {
        if let Some(key) = self.machine_key()? {
            return Ok((key, false));
        }
        self.make()?;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("making the machine key")?;
        util::replace_private(&self.file("machine-key.pem"), key.serialize_pem().as_bytes())?;
        Ok((key, true))
    }

    /// The devices this machine trusts. A trust list that doesn't read is an error: nothing is
    /// trusted from it.
    pub fn trust(&self) -> Result<Vec<Entry>> {
        let path = self.file("trusted.json");
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let stored: Stored = serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))?;
        if stored.version != 1 {
            bail!("{} was written by another version of halti", path.display());
        }
        Ok(stored.devices)
    }

    /// Changes the trust list with `change`, which says whether it changed anything, while no other
    /// halti does; written down only if it did.
    pub fn change_trust<T>(&self, change: impl FnOnce(&mut Vec<Entry>) -> (T, bool)) -> Result<T> {
        self.make()?;
        let _lock = Locked::take(&self.file("trusted.lock"))?;
        let mut devices = self.trust()?;
        let (out, changed) = change(&mut devices);
        if changed {
            util::replace_private(&self.file("trusted.json"), &serde_json::to_vec_pretty(&Stored { version: 1, devices })?)?;
        }
        Ok(out)
    }

    /// The word the hub last refused the machine token with, while it does.
    pub fn refused(&self) -> Option<String> {
        fs::read_to_string(self.file("refused")).ok().map(|word| word.trim().to_string())
    }

    pub fn set_refused(&self, word: &str) {
        let _ = util::replace_private(&self.file("refused"), format!("{word}\n").as_bytes());
    }

    pub fn clear_refused(&self) {
        let _ = fs::remove_file(self.file("refused"));
    }

    /// Forgets the hub: its address and pin, the machine token and the machine key. The devices this
    /// machine trusts are kept. Whether this machine had joined one.
    pub fn leave(&self) -> Result<bool> {
        self.make()?;
        let _lock = Locked::take(&self.file("link.lock"))?;
        let mut had = false;
        for name in ["link.json", "machine-key.pem", "refused"] {
            match fs::remove_file(self.file(name)) {
                Ok(()) => had |= name != "refused",
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("removing {}", self.file(name).display())),
            }
        }
        Ok(had)
    }
}

/// The DER inside a PEM private key as rcgen writes it, with every copy made on the way wiped; none
/// if it isn't one. Anything longer than a P-256 key in halti's form doesn't fit.
fn pkcs8_of_pem(pem: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    const BEGIN: &[u8] = b"-----BEGIN PRIVATE KEY-----";
    const END: &[u8] = b"-----END PRIVATE KEY-----";
    let pem = pem.trim_ascii();
    let body = pem.strip_prefix(BEGIN)?.strip_suffix(END)?;
    // Sized once, so it isn't grown and copied.
    let mut text = Zeroizing::new(Vec::with_capacity(body.len()));
    text.extend(body.iter().filter(|b| !b.is_ascii_whitespace()));
    let mut der = Zeroizing::new([0; 192]);
    let len = base64::engine::general_purpose::STANDARD.decode_slice(&*text, &mut *der).ok()?;
    Some(Zeroizing::new(der[..len].to_vec()))
}

/// An exclusive lock on a file, held until dropped.
struct Locked(File);

impl Locked {
    fn take(path: &Path) -> Result<Locked> {
        let file = OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(path).with_context(|| format!("opening {}", path.display()))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error()).with_context(|| format!("locking {}", path.display()));
        }
        Ok(Locked(file))
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
