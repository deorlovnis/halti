//! The cryptography a workspace rests on: a key pair anyone can seal to (`kem`), sealing under a
//! key already shared (`aead`), policy signatures (`sign`), and the one key derivation all of them
//! go through (`kdf`). `key` builds a workspace's own keys from these.
//!
//! Nothing here draws randomness or reads a clock: random bytes are arguments the caller drew, so
//! the same inputs always give the same bytes.
//!
//! The byte formats and the suite tag are provisional. They may change until the combined key has
//! been compared with one made by a hardware key; after that, a change is a new suite tag or a new
//! format byte, never new meaning for an old one.
//!
//! Secrets are wiped on drop, as far as the language allows: a move can leave a copy behind, and
//! so can the insides of the crates this is built on.

pub mod aead;
pub mod kem;
pub mod sign;

pub(crate) mod kdf;

#[cfg(test)]
pub(crate) mod vectors;
