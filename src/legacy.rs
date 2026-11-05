//! Names from before halti was renamed from cred, which an existing install still depends on.
//! Every kept "cred" is here, with what depends on it; code elsewhere uses these constants,
//! never the literal.
//!
//! Each one is either permanent, or moves with the M1 workspace migration (EMA-60), which carries
//! the Keychain items, the config folder and the stores over to halti's names, re-pins box images
//! and retires the guest names below. Until then, renaming one of these loses data or breaks
//! every box an existing install has.
//!
//! Some are only used outside this crate: install.sh, the Containerfiles and box/shim (whose
//! copies of the guest names are in box/shim/src/legacy.rs). They're listed so this file stays
//! the one list of what still says cred.

// --- Permanent ---

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

/// The codesign identifier install.sh signs with. It is part of the designated requirement that
/// every Keychain "Always Allow" entry stores, so changing it asks again for each item.
/// install.sh has its own copy. Permanent.
#[allow(dead_code)]
pub const CODESIGN_IDENTIFIER: &str = "com.deorlovnis.cred";

// --- Until the M1 workspace migration (EMA-60) ---

/// The Keychain service prefix, `cred:<resource>/<field>`, of every item: values, `_policy`,
/// `box.<name>/_key` (a box's store key: lose it and the box is gone), `_loghead`, `_sessions`
/// and `_audit/hmac`. Moves with EMA-60, which copies the items over.
pub const KEYCHAIN_PREFIX: &str = "cred:";

/// The config folder under the home directory: index.json, audit.log, policy/, box/, and the
/// refresh scripts that approved policies name by path (a dangling one blocks every re-approval).
/// Moves with EMA-60.
pub const CONFIG_DIR: &str = ".config/cred";

/// The store root under the home directory: box stores, mount points and locks (`box/`) and
/// downloads (`downloads/`). A box that is open holds its lock here. Moves with EMA-60.
pub const STORE_ROOT: &str = "Library/Application Support/cred";

/// The prefix of the user-facing environment variables halti still reads after `HALTI_`
/// (`util::env_var`) and exports beside `HALTI_` to refresh scripts, whose bytes are pinned by
/// their approvals (`util::env_names`). Moves with EMA-60.
pub const ENV_PREFIX: &str = "CRED_";

/// The signing identity install.sh falls back to when neither `HALTI_SIGN_IDENTITY` nor
/// "halti code signing" exists: a new certificate changes every Keychain item's designated
/// requirement. install.sh has its own copy. Moves with EMA-60.
#[allow(dead_code)]
pub const SIGN_IDENTITY: &str = "cred code signing";

// The guest contract: compiled into the shim of every agent image that a box policy pins by
// digest (install.sh doesn't re-pin), so the host has to keep speaking it until EMA-60 re-pins.

/// The agent image. Box policies pin `cred-agent@sha256:...` in their approved text, and the
/// local tags `cred-agent:<hex>` resolve those pins. Moves with EMA-60.
pub const AGENT_IMAGE: &str = "cred-agent";

/// The JVM and Rust flavors of the agent image, pinned the same way. Built by install.sh only.
/// Move with EMA-60.
#[allow(dead_code)]
pub const AGENT_IMAGE_JVM: &str = "cred-agent-jvm";
#[allow(dead_code)]
pub const AGENT_IMAGE_RUST: &str = "cred-agent-rust";

/// The browser VM's image. Not pinned, but it carries the same shim and so the same contract.
/// Moves with EMA-60.
pub const BROWSER_IMAGE: &str = "cred-browser";

/// The shim's binary, the agent VM's entrypoint (`cred-shim serve`) and the command of the MCP
/// server in box homes (`cred-shim mcp`). box/shim keeps its crate name for it. Moves with EMA-60.
pub const SHIM: &str = "cred-shim";

/// Where the images install the shim. Containerfiles only. Moves with EMA-60.
#[allow(dead_code)]
pub const SHIM_PATH: &str = "/usr/local/bin/cred-shim";

/// The socket in the VM that the door dials into, published with `--publish-socket` and compiled
/// into the shim. Moves with EMA-60.
pub const DOOR_SOCKET: &str = "/run/cred/door.sock";

/// The socket in the VM that `cred-shim mcp` dials (shim only). Moves with EMA-60.
#[allow(dead_code)]
pub const LOCAL_SOCKET: &str = "/run/cred/local.sock";

/// The kind line the shim sends for connections to 127.0.0.2:80, which go to halti itself (the
/// model gateway). Moves with EMA-60.
pub const DOOR_KIND: &str = "cred";

/// What a box holds in place of the model key, which the door's gateway swaps for the real one.
/// Box homes and the agents' own configs hold it (Henki/pith too), and the trinity interface
/// register names it. Moves with EMA-60.
pub const STANDIN: &str = "cred-managed";

/// The MCP server's key in box homes' `.claude.json`, so the tools the agent sees stay
/// `mcp__cred__*` (permission rules, memories and skills in the box name them). Moves with EMA-60.
pub const MCP_SERVER_KEY: &str = "cred";

// --- Boxes started by cred, still running when halti was installed ---

/// The VM name prefixes cred gave a box's agent and browser VMs (`cred-box-<id>`,
/// `cred-browser-<id>`). Looking for a running box accepts them too, so halti joins or refuses a
/// box cred started instead of starting a second VM for it. Move with EMA-60.
pub const BOX_VM_PREFIX: &str = "cred-box-";
pub const BROWSER_VM_PREFIX: &str = "cred-browser-";

/// Where the box CA is installed in the agent's VM, which NODE_EXTRA_CA_CERTS names. A box cred
/// started has it only there, and halti joins such a box without installing the CA again, so
/// the path stays. Moves with EMA-60.
pub const CA_CERT: &str = "/usr/local/share/ca-certificates/cred-box.crt";

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte for byte: each of these is a key label, a Keychain or disk name, or baked into a
    /// pinned image, so any edit loses data or breaks boxes (see above).
    #[test]
    fn the_kept_names_are_unchanged() {
        assert_eq!(SEAL_LABEL, b"cred box key v1");
        assert_eq!(LOG_KEY_LABEL, b"cred box key derivation stub\0");
        assert_eq!(MASK_KEYWORD, "cred");
        assert_eq!(CODESIGN_IDENTIFIER, "com.deorlovnis.cred");
        assert_eq!(KEYCHAIN_PREFIX, "cred:");
        assert_eq!(CONFIG_DIR, ".config/cred");
        assert_eq!(STORE_ROOT, "Library/Application Support/cred");
        assert_eq!(ENV_PREFIX, "CRED_");
        assert_eq!(SIGN_IDENTITY, "cred code signing");
        assert_eq!([AGENT_IMAGE, AGENT_IMAGE_JVM, AGENT_IMAGE_RUST, BROWSER_IMAGE], ["cred-agent", "cred-agent-jvm", "cred-agent-rust", "cred-browser"]);
        assert_eq!((SHIM, SHIM_PATH), ("cred-shim", "/usr/local/bin/cred-shim"));
        assert_eq!((DOOR_SOCKET, LOCAL_SOCKET, DOOR_KIND), ("/run/cred/door.sock", "/run/cred/local.sock", "cred"));
        assert_eq!((STANDIN, MCP_SERVER_KEY), ("cred-managed", "cred"));
        assert_eq!((BOX_VM_PREFIX, BROWSER_VM_PREFIX), ("cred-box-", "cred-browser-"));
        assert_eq!(CA_CERT, "/usr/local/share/ca-certificates/cred-box.crt");
    }
}
