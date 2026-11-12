//! The guest contract: the shim's half of the names in halti's src/names.rs, which says what
//! depends on each. Every agent image a box policy pins by digest has a shim built with these,
//! and the host names them on the VM's command line, so a change here is a re-pin of every image.

/// This binary's name (`[[bin]]` of the crate), the VM's entrypoint and the command of the MCP
/// server in box homes. Installed as /usr/local/bin/halti-shim.
pub const SHIM: &str = "halti-shim";
/// Where the sockets below live.
pub const RUN_DIR: &str = "/run/halti";
/// The socket the door on the Mac dials into (published by `container`).
pub const DOOR_SOCKET: &str = "/run/halti/door.sock";
/// The socket `halti-shim mcp` dials.
pub const LOCAL_SOCKET: &str = "/run/halti/local.sock";
/// The kind line for connections to 127.0.0.2:80, which go to halti itself.
pub const DOOR_KIND: &str = "halti";

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte for byte: the pinned images' shims were built with these.
    #[test]
    fn the_guest_names_are_unchanged() {
        assert_eq!((SHIM, RUN_DIR), ("halti-shim", "/run/halti"));
        assert_eq!((DOOR_SOCKET, LOCAL_SOCKET, DOOR_KIND), ("/run/halti/door.sock", "/run/halti/local.sock", "halti"));
    }
}
