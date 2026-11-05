//! The guest contract from before halti was renamed from cred: the shim's half of the names in
//! halti's src/legacy.rs, which says what depends on each. Every agent image a box policy pins
//! by digest has a shim built with these, and the host names them on the VM's command line, so
//! they stay until the M1 workspace migration (EMA-60) re-pins the images.

/// This binary's name (`[[bin]]` of the crate), the VM's entrypoint and the command of the MCP
/// server in box homes. Installed as /usr/local/bin/cred-shim.
pub const SHIM: &str = "cred-shim";
/// Where the sockets below live.
pub const RUN_DIR: &str = "/run/cred";
/// The socket the door on the Mac dials into (published by `container`).
pub const DOOR_SOCKET: &str = "/run/cred/door.sock";
/// The socket `cred-shim mcp` dials.
pub const LOCAL_SOCKET: &str = "/run/cred/local.sock";
/// The kind line for connections to 127.0.0.2:80, which go to halti itself.
pub const DOOR_KIND: &str = "cred";

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte for byte: the pinned images' shims were built with these.
    #[test]
    fn the_guest_names_are_unchanged() {
        assert_eq!((SHIM, RUN_DIR), ("cred-shim", "/run/cred"));
        assert_eq!((DOOR_SOCKET, LOCAL_SOCKET, DOOR_KIND), ("/run/cred/door.sock", "/run/cred/local.sock", "cred"));
    }
}
