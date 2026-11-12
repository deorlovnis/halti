//! What the commands mean, apart from how they are typed or printed.

mod resolve;
mod sequence;
mod ws;

pub use resolve::resolve_name;
pub use sequence::{Draws, Host, Opened};
pub use ws::{Deleted, Fresh, Listed, Machine, Workspace, ws_delete, ws_list, ws_new, ws_open};
