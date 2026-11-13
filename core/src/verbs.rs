//! What the commands mean, apart from how they are typed or printed.

mod items;
mod policies;
mod resolve;
mod sequence;
mod ws;

pub use items::{Nonces, Put, State, Stored, Which, ws_items, ws_remove, ws_set};
pub use policies::{Was, ws_approvals, ws_approve};
pub use resolve::resolve_name;
pub use sequence::{Draws, Host, Opened};
pub use ws::{Deleted, Fresh, Listed, Machine, Workspace, ws_delete, ws_list, ws_new, ws_open};
