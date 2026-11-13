use alloy_primitives::{address, Address};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const PAGE_SIZE: u64 = 500;
pub const HKDF_INFO: &[u8] = b"salt-keyshare-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub const ALL: [Network; 2] = [Network::Mainnet, Network::Testnet];

    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "MAINNET",
            Network::Testnet => "TESTNET",
        }
    }

    pub fn chain_id(self) -> u64 {
        match self {
            Network::Mainnet => 42161,
            Network::Testnet => 421614,
        }
    }

    pub fn registry(self) -> Address {
        match self {
            Network::Mainnet => address!("2bc34033e00cfcdcf58fcc8c389dc76ce93e25f3"),
            Network::Testnet => address!("1aaf2396e754712c22d17e5968f38a9ede431b71"),
        }
    }

    pub fn default_rpc_url(self) -> &'static str {
        match self {
            Network::Mainnet => "https://arb1.arbitrum.io/rpc",
            Network::Testnet => "https://sepolia-rollup.arbitrum.io/rpc",
        }
    }
}

impl FromStr for Network {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "MAINNET" => Ok(Network::Mainnet),
            "TESTNET" => Ok(Network::Testnet),
            other => anyhow::bail!("unknown network: {other} (MAINNET or TESTNET)"),
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_is_rejected_by_cli_and_gui_inputs() {
        for name in ["STAGING", "staging"] {
            assert!(name.parse::<Network>().is_err());
        }
        assert!(serde_json::from_str::<Network>("\"STAGING\"").is_err());
        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
    }
}
