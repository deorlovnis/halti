//! What the commands mean, apart from how they are typed or printed.

mod resolve;
mod sequence;

pub use resolve::resolve_name;
pub use sequence::{Draws, Host, Opened, create_key, open};
