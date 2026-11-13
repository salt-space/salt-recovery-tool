//! Primitives for opening shard records, matching what Salt's backend used to
//! seal them: ECIES (eciesjs defaults: secp256k1, uncompressed ephemeral key,
//! HKDF-SHA256, AES-256-GCM with 16-byte nonce) around the OPRF output,
//! HKDF-SHA256 to an AES-256-GCM key, and 12-byte-IV-prefixed AES-GCM payloads.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use alloy_primitives::Address;
use anyhow::{anyhow, bail, Context, Result};
use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;
use std::io::Read;
use zeroize::{Zeroize, Zeroizing};

use crate::networks::HKDF_INFO;

/// A work EOA private key. Zeroized on drop.
#[derive(Clone)]
pub struct PrivateKey(Zeroizing<[u8; 32]>);

impl PrivateKey {
    /// Parse `0x`-prefixed or bare 64-hex-char private key.
    pub fn parse(hex_str: &str) -> Result<Self> {
        let trimmed = hex_str.trim();
        let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        let mut bytes = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(stripped, bytes.as_mut_slice())
            .map_err(|_| anyhow!("private key must be 32 bytes of hex"))?;
        // Reject zero / out-of-range keys up front.
        k256::SecretKey::from_slice(bytes.as_slice())
            .map_err(|_| anyhow!("invalid private key"))?;
        Ok(Self(bytes))
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn address(&self) -> Address {
        let secret = k256::SecretKey::from_slice(self.0.as_slice()).expect("validated in parse");
        let point = secret.public_key().to_encoded_point(false);
        Address::from_raw_public_key(&point.as_bytes()[1..])
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey(<redacted>, {})", self.address())
    }
}

/// EVM address for a secp256k1 public key in compressed (33-byte) or
/// uncompressed (65-byte) SEC1 encoding.
pub fn evm_address_from_public_key(public_key: &[u8]) -> Result<Address> {
    let key = k256::PublicKey::from_sec1_bytes(public_key)
        .map_err(|_| anyhow!("not a valid secp256k1 public key"))?;
    let point = key.to_encoded_point(false);
    Ok(Address::from_raw_public_key(&point.as_bytes()[1..]))
}

/// Parse a `0x`-prefixed compressed public key, returning the 33 bytes.
pub fn parse_compressed_public_key(hex_str: &str) -> Result<[u8; 33]> {
    let stripped = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    let mut bytes = [0u8; 33];
    hex::decode_to_slice(stripped, &mut bytes)
        .map_err(|_| anyhow!("public key must be 33 bytes of hex (compressed)"))?;
    if !matches!(bytes[0], 0x02 | 0x03) {
        bail!("public key must be compressed (0x02/0x03 prefix)");
    }
    evm_address_from_public_key(&bytes)?;
    Ok(bytes)
}

pub fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// ECIES-decrypt the record's `evaluation` with the EOA private key.
pub fn unwrap_evaluation(
    private_key: &PrivateKey,
    evaluation: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    ecies::decrypt(private_key.bytes(), evaluation)
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("ECIES decryption failed"))
}

/// HKDF-SHA256(oprf_output, salt = lowercase eoa, info = HKDF_INFO) -> AES-256 key.
pub fn derive_aes_key(oprf_output: &[u8], eoa: Address) -> Aes256Gcm {
    let salt = format!("{eoa:#x}"); // lowercase 0x-prefixed
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), oprf_output);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, key.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Aes256Gcm::new(key.as_slice().into())
}

/// Decrypt `iv(12) || ciphertext || tag` with AES-256-GCM.
pub fn aes_decrypt(payload: &[u8], key: &Aes256Gcm) -> Result<Zeroizing<Vec<u8>>> {
    if payload.len() < 12 + 16 {
        bail!("AES-GCM payload too short");
    }
    let (iv, body) = payload.split_at(12);
    key.decrypt(Nonce::from_slice(iv), body)
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("AES-GCM decryption failed"))
}

pub fn gunzip(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .context("gunzip failed")?;
    Ok(out)
}

/// Wipe a `String`'s buffer (for hex keys held transiently).
pub fn wipe(s: &mut String) {
    s.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    const HARDHAT_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn address_from_private_key() {
        let key = PrivateKey::parse(HARDHAT_KEY).unwrap();
        assert_eq!(
            key.address().to_checksum(None),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
        assert!(PrivateKey::parse("0x00").is_err());
        assert!(
            PrivateKey::parse(&"00".repeat(32)).is_err(),
            "zero key rejected"
        );
    }

    #[test]
    fn address_from_compressed_and_uncompressed_public_key() {
        let key = PrivateKey::parse(HARDHAT_KEY).unwrap();
        let secret = k256::SecretKey::from_slice(key.bytes()).unwrap();
        let compressed = secret.public_key().to_encoded_point(true);
        let uncompressed = secret.public_key().to_encoded_point(false);
        assert_eq!(compressed.as_bytes().len(), 33);
        assert_eq!(
            evm_address_from_public_key(compressed.as_bytes()).unwrap(),
            key.address()
        );
        assert_eq!(
            evm_address_from_public_key(uncompressed.as_bytes()).unwrap(),
            key.address()
        );
        let mut bad_prefix = [0u8; 33];
        bad_prefix[0] = 0x05;
        assert!(evm_address_from_public_key(&bad_prefix).is_err());
        assert!(evm_address_from_public_key(&[0x04; 20]).is_err());
    }

    #[test]
    fn ecies_roundtrip_with_eciesjs_defaults() {
        // Vector produced by eciesjs 0.5 (uncompressed ephemeral key, 16-byte nonce).
        let sk = "79909678f028c2f7ad863ef6d1e58dba572fde501b6576016c6afd774289d07d";
        let ct = "04ae2efec4a49e1265ae4a96189d55c421690f74b2199e6ac506a00de0a3959a9fefcfaea4f8b2b55b3da6cc8f75dadc7248d07637087c9622510b0d0f610585ed0060c976d08c3a2076edb3671fe3665023fe22845bf48d089d5f718a9b1c131585fe6cf0b4224216e8ddf2dddaff4aa035df9ac51d632d249d57291c68e7c76e";
        let key = PrivateKey::parse(sk).unwrap();
        let pt = unwrap_evaluation(&key, &hex::decode(ct).unwrap()).unwrap();
        assert_eq!(
            hex::encode(pt.as_slice()),
            "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc"
        );
    }
}
