//! Halti's workspace rules. A workspace is one client's sealed compartment: its stored values,
//! policies, logs and boxes belong to it and to no other. This crate holds what that means, apart
//! from any one machine:
//!
//! - It does no I/O. Files, stored values and locks reach it as traits (`store`), which the
//!   binary implements for each OS and the tests implement in memory.
//! - It has no code for one OS, and its own code never reads the environment, the clock or the
//!   current folder: what it needs is an argument. (Its errors are carried by anyhow, which asks
//!   the standard library whether to keep a stack trace. That changes an error's debug text only,
//!   never a decision. The cipher and hash crates under `crypto` may each ask the CPU once per
//!   process which instructions it has. That changes their speed only, never a result.)
//! - It keeps no state between calls. Nothing here is "the current workspace": a handle is bound
//!   to one workspace when it is made and stays there.
//!
//! tests/source.rs in the binary's crate checks the first two by reading this source, and of the
//! third that nothing here outlives a call: no item that is one for the whole process.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod ids;
pub mod key;
pub mod platform;
pub mod refusal;
pub mod store;
pub mod verbs;

#[cfg(test)]
mod contract;
#[cfg(test)]
mod fakes;
