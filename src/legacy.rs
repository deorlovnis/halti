//! Names from before halti was renamed from cred, which an install made by cred still holds.
//! halti itself writes none of them (its own are in `names`); they are kept so the migration of
//! such an install can read what cred wrote, and so the two installs can live on one Mac
//! meanwhile without halti touching cred's items, files, images or VMs.
//!
//! Three are shared with `names` on purpose and permanent: the key labels, which the migration
//! relies on to copy sealed files and chained logs over as they are, and a masking pattern.

// --- Permanent, shared by both installs ---

/// The domain label of `seal::derive`. Every box's sealed CA (`door/ca.sealed`) and sealed
/// browser sessions (`browser/<site>.sealed`) are keyed through it: change one byte and none of
/// them opens again. Permanent.
pub const SEAL_LABEL: &[u8] = b"cred box key v1";

/// The domain label of the key that chains a box's `log/door.log` (`boxes::derive`), and so of
/// its `_loghead` item. Change one byte and every existing log fails `box log --verify` from its
/// first line. Permanent.
pub const LOG_KEY_LABEL: &[u8] = b"cred box key derivation stub\0";

/// A word in the audit log's `SENSITIVE_KEYS`: query keys containing it (`credential`, `creds`)
/// have their values masked. A pattern, not the product's name; dropping it would unmask them.
/// Permanent.
pub const MASK_KEYWORD: &str = "cred";

/// The prefix of the environment variables halti still reads after `HALTI_` (`util::env_var`)
/// and exports beside `HALTI_` to refresh scripts, whose bytes are pinned by their approvals
/// (`util::env_names`). Read for one transition; it names nothing on disk.
pub const ENV_PREFIX: &str = "CRED_";

// --- What a cred install wrote, for the migration to read ---

/// The codesign identifier cred's install.sh signed with: part of the designated requirement
/// that every Keychain "Always Allow" entry of that install stores.
pub const CODESIGN_IDENTIFIER: &str = "com.deorlovnis.cred";

/// The signing identity cred's install.sh used.
pub const SIGN_IDENTITY: &str = "cred code signing";

/// The Keychain service prefix of every item cred wrote, `cred:<resource>/<field>`: values,
/// `_policy`, `box.<name>/_key`, `_loghead`, `_sessions` and `_audit/hmac`.
pub const KEYCHAIN_PREFIX: &str = "cred:";

/// cred's config folder under the home directory: index.json, audit.log, policy/, box/ and
/// refresh scripts.
pub const CONFIG_DIR: &str = ".config/cred";

/// cred's store root under the home directory: box stores, mount points, locks and downloads.
pub const STORE_ROOT: &str = "Library/Application Support/cred";

/// The images cred's box policies pin by digest, and what their shims were built with.
pub const AGENT_IMAGE: &str = "cred-agent";
pub const AGENT_IMAGE_JVM: &str = "cred-agent-jvm";
pub const AGENT_IMAGE_RUST: &str = "cred-agent-rust";
pub const BROWSER_IMAGE: &str = "cred-browser";
pub const SHIM: &str = "cred-shim";
pub const SHIM_PATH: &str = "/usr/local/bin/cred-shim";
pub const DOOR_SOCKET: &str = "/run/cred/door.sock";
pub const LOCAL_SOCKET: &str = "/run/cred/local.sock";
pub const DOOR_KIND: &str = "cred";
pub const STANDIN: &str = "cred-managed";
pub const MCP_SERVER_KEY: &str = "cred";

/// The VM names cred gives a box's agent and browser VMs (`cred-box-<id>`, `cred-browser-<id>`).
/// halti never starts, joins or stops these.
pub const BOX_VM_PREFIX: &str = "cred-box-";
pub const BROWSER_VM_PREFIX: &str = "cred-browser-";

/// Where cred's images hold the box CA.
pub const CA_CERT: &str = "/usr/local/share/ca-certificates/cred-box.crt";

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte for byte: each of these is a key label, or a Keychain, disk or image name of an
    /// install made by cred, which the migration has to find as cred left it.
    #[test]
    fn the_old_names_are_unchanged() {
        assert_eq!(SEAL_LABEL, b"cred box key v1");
        assert_eq!(LOG_KEY_LABEL, b"cred box key derivation stub\0");
        assert_eq!((MASK_KEYWORD, ENV_PREFIX), ("cred", "CRED_"));
        assert_eq!((CODESIGN_IDENTIFIER, SIGN_IDENTITY), ("com.deorlovnis.cred", "cred code signing"));
        assert_eq!((KEYCHAIN_PREFIX, CONFIG_DIR, STORE_ROOT), ("cred:", ".config/cred", "Library/Application Support/cred"));
        assert_eq!([AGENT_IMAGE, AGENT_IMAGE_JVM, AGENT_IMAGE_RUST, BROWSER_IMAGE], ["cred-agent", "cred-agent-jvm", "cred-agent-rust", "cred-browser"]);
        assert_eq!((SHIM, SHIM_PATH), ("cred-shim", "/usr/local/bin/cred-shim"));
        assert_eq!((DOOR_SOCKET, LOCAL_SOCKET, DOOR_KIND), ("/run/cred/door.sock", "/run/cred/local.sock", "cred"));
        assert_eq!((STANDIN, MCP_SERVER_KEY), ("cred-managed", "cred"));
        assert_eq!((BOX_VM_PREFIX, BROWSER_VM_PREFIX), ("cred-box-", "cred-browser-"));
        assert_eq!(CA_CERT, "/usr/local/share/ca-certificates/cred-box.crt");
    }
}
