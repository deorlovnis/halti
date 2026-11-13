//! What the commands mean, apart from how they are typed or printed.

mod boxes;
mod items;
mod policies;
mod resolve;
mod sequence;
mod ws;

pub use boxes::{BoxGone, BoxNonces, ws_box_new, ws_box_rm};
pub use items::{Nonces, Put, State, Stored, Which, ws_items, ws_remove, ws_set};
pub use policies::{Was, ws_approvals, ws_approve};
pub use resolve::resolve_name;
pub use sequence::{Draws, Host, Opened};
pub use ws::{Deleted, Fresh, Listed, Machine, Reader, ws_delete, ws_list, ws_new, ws_open};
