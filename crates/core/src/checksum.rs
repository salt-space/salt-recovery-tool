//! Serde helpers that write addresses EIP-55 checksummed (and read any case).

use alloy_primitives::Address;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize<S: Serializer>(address: &Address, s: S) -> Result<S::Ok, S::Error> {
    address.to_checksum(None).serialize(s)
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Address, D::Error> {
    Address::deserialize(d)
}

pub mod vec {
    use super::*;

    pub fn serialize<S: Serializer>(addresses: &[Address], s: S) -> Result<S::Ok, S::Error> {
        addresses
            .iter()
            .map(|a| a.to_checksum(None))
            .collect::<Vec<_>>()
            .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Address>, D::Error> {
        Vec::<Address>::deserialize(d)
    }
}
