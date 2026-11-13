//! Data shapes shared by the CLI, the desktop app and the on-disk JSON files.
//! Field names are camelCase so the JSON written by the previous TypeScript
//! implementation stays readable and vice versa.

use alloy_primitives::{Address, Bytes, B256};
use serde::{Deserialize, Serialize};

use crate::checksum;

/// One shard record from the registry for a given work EOA.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedShardRecord {
    pub index: u64,
    /// AES-GCM(iv || ct) of the compressed MPC public key.
    pub salt_account: Bytes,
    /// ECIES ciphertext (to the EOA key) of the OPRF output the AES key derives from.
    pub evaluation: Bytes,
    pub tx_hashes: Vec<B256>,
    /// AES-GCM(iv || ct) of the gzipped keyshare, reassembled from chunk logs.
    pub ciphertext: Bytes,
}

/// Everything the registry holds for one work EOA on one network.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedShardDump {
    pub chain_id: u64,
    #[serde(with = "checksum")]
    pub registry: Address,
    #[serde(with = "checksum")]
    pub eoa: Address,
    pub records: Vec<EncryptedShardRecord>,
}

/// A Salt account seen while scanning shard records, without decrypting shares.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredAccount {
    /// Compressed MPC public key, lowercase 0x hex.
    pub public_key: String,
    #[serde(with = "checksum")]
    pub evm_address: Address,
    #[serde(with = "checksum::vec")]
    pub eoas: Vec<Address>,
    pub record_count: u32,
}

/// A decrypted DKLS keyshare plus provenance. Also the on-disk JSON format
/// (`salt-keyshare-<account>-<eoa>.json`) accepted by `reconstruct --share`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedKeyshare {
    pub keyshare_base64: String,
    /// Compressed MPC public key, lowercase 0x hex.
    pub public_key: String,
    #[serde(with = "checksum")]
    pub evm_address: Address,
    /// Owning work EOA; zero address for raw keyshare files with no provenance.
    #[serde(with = "checksum")]
    pub eoa: Address,
    /// Registry record index; -1 for raw keyshare files.
    pub record_index: i64,
}

impl std::fmt::Debug for DecryptedKeyshare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedKeyshare")
            .field("keyshare_base64", &"<redacted>")
            .field("public_key", &self.public_key)
            .field("evm_address", &self.evm_address)
            .field("eoa", &self.eoa)
            .field("record_index", &self.record_index)
            .finish()
    }
}

/// Metadata about a keyshare, safe to show in a UI (no share material).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyshareInfo {
    pub public_key: String,
    #[serde(with = "checksum")]
    pub evm_address: Address,
    #[serde(with = "checksum")]
    pub eoa: Address,
    pub record_index: i64,
    /// DKLS party id when known (read from the share itself).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party_id: Option<u8>,
    /// Wallet quorum (`threshold`-of-`total_parties`) read from the share.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_parties: Option<u8>,
}

impl From<&DecryptedKeyshare> for KeyshareInfo {
    fn from(share: &DecryptedKeyshare) -> Self {
        Self {
            public_key: share.public_key.clone(),
            evm_address: share.evm_address,
            eoa: share.eoa,
            record_index: share.record_index,
            party_id: None,
            threshold: None,
            total_parties: None,
        }
    }
}

/// A reconstructed private key at a derivation path.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReconstructedKey {
    pub path: String,
    /// 0x-prefixed 32-byte hex.
    pub private_key: String,
    /// Compressed public key, 0x-prefixed hex.
    pub public_key: String,
    #[serde(with = "checksum")]
    pub evm_address: Address,
}

impl std::fmt::Debug for ReconstructedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReconstructedKey")
            .field("path", &self.path)
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .field("evm_address", &self.evm_address)
            .finish()
    }
}

impl Drop for ReconstructedKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.private_key);
    }
}

impl Drop for DecryptedKeyshare {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.keyshare_base64);
    }
}
