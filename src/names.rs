//! halti's own names: everything a fresh install writes to the Keychain, to disk, into images and
//! onto a VM's command line. Code uses these constants, never the literals.
//!
//! An install depends on every one of them (a renamed Keychain prefix loses the values, a renamed
//! image breaks the box policies that pin it), so a change here is a migration, not an edit. The
//! names an older install wrote under the old product name are in `legacy`, for the migration to
//! read.
//!
//! Some are used only outside this crate: install.sh, the Containerfiles and box/shim (whose
//! copies of the guest names are in box/shim/src/names.rs). They're listed so this file stays the
//! one list.

/// The codesign identifier install.sh signs with. It is part of the designated requirement that
/// every Keychain "Always Allow" entry stores, so changing it asks again for each item.
/// install.sh has its own copy.
#[allow(dead_code)]
pub const CODESIGN_IDENTIFIER: &str = "com.deorlovnis.halti";

/// The signing identity install.sh signs with unless `HALTI_SIGN_IDENTITY` says otherwise: a new
/// certificate changes every Keychain item's designated requirement. install.sh has its own copy.
#[allow(dead_code)]
pub const SIGN_IDENTITY: &str = "halti code signing";

/// The Keychain service prefix, `halti:<resource>/<field>`, of every item: values, `_policy`,
/// `box.<name>/_key` (a box's store key: lose it and the box is gone), `_loghead`, `_sessions`
/// and `_audit/hmac`.
pub const KEYCHAIN_PREFIX: &str = "halti:";

/// The config folder under the home directory: index.json, audit.log, policy/, box/, and the
/// refresh scripts that approved policies name by path (a dangling one blocks every re-approval).
pub const CONFIG_DIR: &str = ".config/halti";

/// The store root under the home directory: box stores, mount points and locks (`box/`),
/// downloads (`downloads/`) and workspaces (`ws/`). A box that is open holds its lock here.
pub const STORE_ROOT: &str = "Library/Application Support/halti";

/// The workspaces folder under the store root: each workspace's key file, wrap, sealed manifest
/// and pin, and the directory of their names. Lose it and the workspaces are gone.
pub const WS_DIR: &str = "ws";

// The guest contract: compiled into the shim of every agent image that a box policy pins by
// digest (install.sh doesn't re-pin), so the host has to keep speaking it.

/// The agent image. Box policies pin `halti-agent@sha256:...` in their approved text, and the
/// local tags `halti-agent:<hex>` resolve those pins.
pub const AGENT_IMAGE: &str = "halti-agent";

/// The JVM and Rust flavors of the agent image, pinned the same way. Built by install.sh only.
#[allow(dead_code)]
pub const AGENT_IMAGE_JVM: &str = "halti-agent-jvm";
#[allow(dead_code)]
pub const AGENT_IMAGE_RUST: &str = "halti-agent-rust";

/// The browser VM's image. Not pinned, but it carries the same shim and so the same contract.
pub const BROWSER_IMAGE: &str = "halti-browser";

/// The shim's binary, the agent VM's entrypoint (`halti-shim serve`) and the command of the MCP
/// server in box homes (`halti-shim mcp`). box/shim's crate is named after it.
pub const SHIM: &str = "halti-shim";

/// Where the images install the shim. Containerfiles only.
#[allow(dead_code)]
pub const SHIM_PATH: &str = "/usr/local/bin/halti-shim";

/// The socket in the VM that the door dials into, published with `--publish-socket` and compiled
/// into the shim.
pub const DOOR_SOCKET: &str = "/run/halti/door.sock";

/// The socket in the VM that `halti-shim mcp` dials (shim only).
#[allow(dead_code)]
pub const LOCAL_SOCKET: &str = "/run/halti/local.sock";

/// The kind line the shim sends for connections to 127.0.0.2:80, which go to halti itself (the
/// model gateway).
pub const DOOR_KIND: &str = "halti";

/// What a box holds in place of the model key, which the door's gateway swaps for the real one.
/// Box homes and the agents' own configs hold it, and other agents built for boxes send it too.
pub const STANDIN: &str = "halti-managed";

/// The MCP server's key in box homes' `.claude.json`, so the tools the agent sees are
/// `mcp__halti__*` (permission rules, memories and skills in the box name them).
pub const MCP_SERVER_KEY: &str = "halti";

/// The VM name prefixes of a box's agent and browser VMs (`halti-box-<id>`, `halti-browser-<id>`).
pub const BOX_VM_PREFIX: &str = "halti-box-";
pub const BROWSER_VM_PREFIX: &str = "halti-browser-";

/// Where the box CA is installed in the agent's VM, which NODE_EXTRA_CA_CERTS names.
pub const CA_CERT: &str = "/usr/local/share/ca-certificates/halti-box.crt";

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte for byte: each of these is a Keychain or disk name, or baked into a pinned image, so
    /// any edit loses data or breaks boxes (see above).
    #[test]
    fn the_names_are_unchanged() {
        assert_eq!((CODESIGN_IDENTIFIER, SIGN_IDENTITY), ("com.deorlovnis.halti", "halti code signing"));
        assert_eq!((KEYCHAIN_PREFIX, CONFIG_DIR, STORE_ROOT, WS_DIR), ("halti:", ".config/halti", "Library/Application Support/halti", "ws"));
        assert_eq!([AGENT_IMAGE, AGENT_IMAGE_JVM, AGENT_IMAGE_RUST, BROWSER_IMAGE], ["halti-agent", "halti-agent-jvm", "halti-agent-rust", "halti-browser"]);
        assert_eq!((SHIM, SHIM_PATH), ("halti-shim", "/usr/local/bin/halti-shim"));
        assert_eq!((DOOR_SOCKET, LOCAL_SOCKET, DOOR_KIND), ("/run/halti/door.sock", "/run/halti/local.sock", "halti"));
        assert_eq!((STANDIN, MCP_SERVER_KEY), ("halti-managed", "halti"));
        assert_eq!((BOX_VM_PREFIX, BROWSER_VM_PREFIX), ("halti-box-", "halti-browser-"));
        assert_eq!(CA_CERT, "/usr/local/share/ca-certificates/halti-box.crt");
    }
}
