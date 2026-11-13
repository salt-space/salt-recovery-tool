//! Derive Robo Guardian work-EOA keys from an encrypted or plaintext Robo Guardian secret.
//!
//! Paths match MetaMask: `m/44'/60'/0'/0/{i}`. No Salt SDK dependency.

use anyhow::{anyhow, bail, Result};
use coins_bip32::prelude::*;
use coins_bip39::{English, Mnemonic};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::crypto::{hex0x, PrivateKey};

/// Robo Guardian accounts derived by default. Salt quorums use `threshold - 1` Robo Guardians
/// next to the owner (2-of-3 → 1, 3-of-5 → 2, 4-of-7 → 3), so 3 covers all of
/// them; unused ones simply hold no shard records.
pub const ROBO_ACCOUNTS: usize = 3;

/// Soft cap on derived accounts (CLI `--count`).
pub const MAX_ROBO_ACCOUNTS: usize = 10;

/// One derived Robo Guardian account.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoboAccount {
    pub index: u32,
    pub path: String,
    pub address: String,
    pub private_key: String,
}

/// Detect encrypted Robo Guardian secret (hex / `0x…`) vs plaintext mnemonic/seed.
pub fn is_encrypted_secret(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        return true;
    }
    let hex_only = trimmed.bytes().all(|b| b.is_ascii_hexdigit());
    if hex_only && trimmed.len() > 50 {
        return true;
    }
    if is_mnemonic_phrase(trimmed) {
        return false;
    }
    hex_only && trimmed.len() > 20
}

fn is_mnemonic_phrase(input: &str) -> bool {
    let words: Vec<&str> = input.split_whitespace().collect();
    words.len() >= 12
        && words
            .iter()
            .all(|w| w.bytes().all(|b| b.is_ascii_alphabetic()))
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

fn try_decode_mnemonic(hex_str: &str) -> Option<String> {
    let bytes = hex::decode(hex_str).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?.trim();
    if is_mnemonic_phrase(text) {
        Some(text.to_string())
    } else {
        None
    }
}

/// ECIES-decrypt ciphertext with the proposer EOA private key.
pub fn decrypt_robo_secret(owner: &PrivateKey, ciphertext_hex: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = hex::decode(strip_0x(ciphertext_hex.trim()))
        .map_err(|_| anyhow!("encrypted Robo Guardian secret must be hex"))?;
    ecies::decrypt(owner.bytes(), &cipher)
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("ECIES decryption failed (wrong proposer EOA key or ciphertext?)"))
}

/// Derive `count` MetaMask-path EOAs from a mnemonic or raw seed hex.
pub fn derive_robo_accounts(seed_or_mnemonic: &str, count: usize) -> Result<Vec<RoboAccount>> {
    if count == 0 || count > MAX_ROBO_ACCOUNTS {
        bail!("count must be 1..={MAX_ROBO_ACCOUNTS}");
    }
    let trimmed = seed_or_mnemonic.trim();
    let seed = if is_mnemonic_phrase(trimmed) {
        let mnemonic = Mnemonic::<English>::new_from_phrase(trimmed)
            .map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
        // Empty passphrase — MetaMask / ethers default (`None` ≡ "").
        let seed = mnemonic
            .to_seed(None)
            .map_err(|e| anyhow!("BIP39 seed: {e}"))?;
        Zeroizing::new(seed.to_vec())
    } else {
        let hex = strip_0x(trimmed);
        let bytes =
            hex::decode(hex).map_err(|_| anyhow!("seed must be hex or a BIP39 mnemonic"))?;
        if bytes.is_empty() {
            bail!("empty seed");
        }
        Zeroizing::new(bytes)
    };

    let master = XPriv::root_from_seed(seed.as_slice(), None)
        .map_err(|e| anyhow!("BIP32 master key: {e}"))?;

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let path = format!("m/44'/60'/0'/0/{i}");
        let derived = master
            .derive_path(path.as_str())
            .map_err(|e| anyhow!("derive {path}: {e}"))?;
        // coins-bip32 0.8: XPriv is AsRef<SigningKey>; no private_key() helper.
        let sk_bytes = AsRef::<SigningKey>::as_ref(&derived).to_bytes();
        let pk = PrivateKey::parse(&hex::encode(sk_bytes.as_slice()))?;
        out.push(RoboAccount {
            index: i as u32,
            path,
            address: format!("{:#x}", pk.address()),
            private_key: hex0x(pk.bytes()),
        });
    }
    Ok(out)
}

/// Decrypt if needed, then derive Robo Guardian accounts.
///
/// `owner_key` is required when `secret` looks encrypted; ignored for plaintext.
pub fn recover_robo_accounts(
    owner_key: Option<&PrivateKey>,
    secret: &str,
    count: usize,
) -> Result<Vec<RoboAccount>> {
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        bail!("Robo Guardian secret is required");
    }

    let material = if is_encrypted_secret(trimmed) {
        let owner = owner_key.ok_or_else(|| {
            anyhow!(
                "proposer EOA private key is required to decrypt an encrypted Robo Guardian secret"
            )
        })?;
        let decrypted = decrypt_robo_secret(owner, trimmed)?;
        if let Some(mnemonic) = try_decode_mnemonic(&hex::encode(decrypted.as_slice())) {
            mnemonic
        } else {
            let hex = hex::encode(decrypted.as_slice());
            if hex.len() != 128 {
                bail!(
                    "decrypted Robo Guardian secret is not a mnemonic or 64-byte seed (got {} bytes)",
                    decrypted.len()
                );
            }
            hex
        }
    } else if is_mnemonic_phrase(trimmed) {
        trimmed.to_string()
    } else {
        strip_0x(trimmed).to_string()
    };

    derive_robo_accounts(&material, count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
    // MetaMask / Hardhat account #0
    const EXPECTED_ADDR0: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const EXPECTED_PK0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn mnemonic_derives_metamask_account0() {
        let accounts = derive_robo_accounts(TEST_MNEMONIC, 1).unwrap();
        assert_eq!(accounts[0].address, EXPECTED_ADDR0);
        assert_eq!(accounts[0].private_key, EXPECTED_PK0);
        assert_eq!(accounts[0].path, "m/44'/60'/0'/0/0");
    }

    #[test]
    fn mnemonic_derives_distinct_indices() {
        let accounts = derive_robo_accounts(TEST_MNEMONIC, 3).unwrap();
        assert_ne!(accounts[0].address, accounts[1].address);
        assert_ne!(accounts[1].address, accounts[2].address);
    }

    #[test]
    fn plaintext_mnemonic_needs_no_owner() {
        let accounts = recover_robo_accounts(None, TEST_MNEMONIC, 1).unwrap();
        assert_eq!(accounts[0].address, EXPECTED_ADDR0);
    }

    #[test]
    fn encrypted_requires_owner() {
        let err = recover_robo_accounts(None, &format!("0x{}", "ab".repeat(40)), 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("proposer EOA"), "{err}");
    }

    #[test]
    fn ecies_roundtrip_then_derive() {
        let owner = PrivateKey::parse(EXPECTED_PK0).unwrap();
        let seed = Mnemonic::<English>::new_from_phrase(TEST_MNEMONIC)
            .unwrap()
            .to_seed(None)
            .unwrap();
        let owner_sk = k256::SecretKey::from_slice(owner.bytes()).unwrap();
        let pubkey = owner_sk.public_key().to_encoded_point(false);
        let ciphertext = ecies::encrypt(pubkey.as_bytes(), seed.as_slice()).unwrap();
        let secret = hex0x(&ciphertext);

        let accounts = recover_robo_accounts(Some(&owner), &secret, 1).unwrap();
        assert_eq!(accounts[0].address, EXPECTED_ADDR0);

        let wrong =
            PrivateKey::parse("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
                .unwrap();
        assert!(recover_robo_accounts(Some(&wrong), &secret, 1).is_err());
    }

    #[test]
    fn is_encrypted_heuristics() {
        assert!(is_encrypted_secret(&format!("0x{}", "aa".repeat(32))));
        assert!(!is_encrypted_secret(TEST_MNEMONIC));
    }
}
