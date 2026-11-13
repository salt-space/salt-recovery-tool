//! Read encrypted shard records from a `SaltShardRegistryV3` contract.
//!
//! Only three RPC methods are used (`eth_chainId`, `eth_call`,
//! `eth_getTransactionReceipt`), so this talks JSON-RPC directly instead of
//! pulling in a provider stack.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolCall, SolEvent};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::future::try_join_all;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};

use crate::networks::PAGE_SIZE;
use crate::types::{EncryptedShardDump, EncryptedShardRecord};

sol! {
    struct ShardRecord {
        bytes saltAccount;
        bytes32[] txHashes;
        bytes evaluation;
    }

    function getShardCount(address eoa) external view returns (uint256);
    function getShards(address eoa, uint256 offset, uint256 limit)
        external view returns (ShardRecord[] page);

    event ShardStored(
        address indexed eoa,
        bytes indexed saltAccount,
        uint8 chunkIndex,
        uint8 totalChunks,
        bytes shard
    );
}

pub struct RpcClient {
    http: reqwest::Client,
    url: String,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<Value>,
}

impl RpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            url: url.into(),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("RPC request to {} failed", self.url))?;
        let status = response.status();
        if !status.is_success() {
            bail!("RPC {} returned HTTP {status}", self.url);
        }
        let parsed: RpcResponse<T> = response
            .json()
            .await
            .with_context(|| format!("RPC {method}: invalid JSON response"))?;
        if let Some(error) = parsed.error {
            bail!("RPC {method} error: {error}");
        }
        parsed
            .result
            .ok_or_else(|| anyhow!("RPC {method}: empty result"))
    }

    pub async fn chain_id(&self) -> Result<u64> {
        let hex: String = self.call("eth_chainId", json!([])).await?;
        u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .with_context(|| format!("eth_chainId returned {hex}"))
    }

    async fn eth_call(&self, to: Address, data: Vec<u8>) -> Result<Bytes> {
        self.call(
            "eth_call",
            json!([{ "to": to, "data": Bytes::from(data) }, "latest"]),
        )
        .await
    }
}

#[derive(Deserialize)]
struct Log {
    address: Address,
    topics: Vec<B256>,
    data: Bytes,
}

#[derive(Deserialize)]
struct Receipt {
    logs: Vec<Log>,
}

pub struct RegistryReader {
    rpc: RpcClient,
    registry: Address,
}

impl RegistryReader {
    pub fn new(rpc: RpcClient, registry: Address) -> Self {
        Self { rpc, registry }
    }

    pub async fn shard_count(&self, eoa: Address) -> Result<u64> {
        let data = getShardCountCall { eoa }.abi_encode();
        let out = self.rpc.eth_call(self.registry, data).await?;
        let count: U256 =
            getShardCountCall::abi_decode_returns(&out).context("decoding getShardCount result")?;
        u64::try_from(count).map_err(|_| anyhow!("shard count out of range"))
    }

    /// Records `[offset, offset + limit)` without their chunk payloads.
    pub async fn shards_page(&self, eoa: Address, offset: u64, limit: u64) -> Result<Vec<Head>> {
        let data = getShardsCall {
            eoa,
            offset: U256::from(offset),
            limit: U256::from(limit),
        }
        .abi_encode();
        let out = self.rpc.eth_call(self.registry, data).await?;
        let page: Vec<ShardRecord> =
            getShardsCall::abi_decode_returns(&out).context("decoding getShards result")?;
        Ok(page
            .into_iter()
            .enumerate()
            .map(|(i, r)| Head {
                index: offset + i as u64,
                salt_account: r.saltAccount,
                tx_hashes: r.txHashes,
                evaluation: r.evaluation,
            })
            .collect())
    }

    /// Reassemble a record's ciphertext from the `ShardStored` log of each chunk tx.
    pub async fn read_chunks(&self, tx_hashes: &[B256]) -> Result<Bytes> {
        let chunks = try_join_all(tx_hashes.iter().map(|h| self.chunk(*h))).await?;
        Ok(Bytes::from(chunks.concat()))
    }

    async fn chunk(&self, tx_hash: B256) -> Result<Vec<u8>> {
        let receipt: Option<Receipt> = self
            .rpc
            .call("eth_getTransactionReceipt", json!([tx_hash]))
            .await?;
        let receipt = receipt.ok_or_else(|| anyhow!("no receipt for transaction {tx_hash}"))?;
        let log = receipt
            .logs
            .iter()
            .find(|l| l.address == self.registry)
            .ok_or_else(|| anyhow!("no ShardStored log found in transaction {tx_hash}"))?;
        let event = ShardStored::decode_raw_log(log.topics.iter().copied(), &log.data)
            .with_context(|| format!("decoding ShardStored log in {tx_hash}"))?;
        Ok(event.shard.to_vec())
    }

    /// Every record for `eoa`, with ciphertexts, ordered by index ascending.
    pub async fn fetch_all(&self, eoa: Address, chain_id: u64) -> Result<EncryptedShardDump> {
        let mut heads = Vec::new();
        let mut end = self.shard_count(eoa).await?;
        while end > 0 {
            let offset = end.saturating_sub(PAGE_SIZE);
            heads.extend(self.shards_page(eoa, offset, end - offset).await?);
            end = offset;
        }
        heads.sort_by_key(|h| h.index);

        let mut records = Vec::with_capacity(heads.len());
        for head in heads {
            let ciphertext = self.read_chunks(&head.tx_hashes).await?;
            records.push(EncryptedShardRecord {
                index: head.index,
                salt_account: head.salt_account,
                evaluation: head.evaluation,
                tx_hashes: head.tx_hashes,
                ciphertext,
            });
        }

        Ok(EncryptedShardDump {
            chain_id,
            registry: self.registry,
            eoa,
            records,
        })
    }
}

/// A shard record as returned by `getShards`, before its chunks are read.
pub struct Head {
    pub index: u64,
    pub salt_account: Bytes,
    pub tx_hashes: Vec<B256>,
    pub evaluation: Bytes,
}

/// Fetch every encrypted shard record the registry holds for `eoa`.
pub async fn fetch_encrypted_shards(
    rpc_url: &str,
    registry: Address,
    chain_id: u64,
    eoa: Address,
) -> Result<EncryptedShardDump> {
    let rpc = RpcClient::new(rpc_url);
    let actual = rpc.chain_id().await?;
    if actual != chain_id {
        bail!("RPC {} is chain {actual}, expected {chain_id}", rpc.url());
    }
    RegistryReader::new(rpc, registry)
        .fetch_all(eoa, chain_id)
        .await
}
