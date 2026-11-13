//! Salt MPC disaster recovery, offline: fetch encrypted shard records from the
//! on-chain registry, decrypt them with the work EOA private keys, and
//! reconstruct account private keys from the threshold of DKLS23 shares.
//!
//! Used by the desktop app's GUI and its headless CLI mode so they cannot drift.

pub mod checksum;
pub mod crypto;
pub mod decrypt;
pub mod keyshare;
pub mod networks;
pub mod paths;
pub mod reconstruct;
pub mod registry;
pub mod robo;
pub mod types;

pub use alloy_primitives::Address;

#[cfg(test)]
mod test_helpers;
