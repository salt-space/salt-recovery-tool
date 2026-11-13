//! Combine DKLS23 keyshares into the root private key and BIP32-tweak soft
//! children. Everything stays in memory; shares are never written to disk.

use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use derivation_path::DerivationPath;
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use sl_dkls23::{key_export::combine_shares, keygen::Keyshare};
use zeroize::Zeroizing;

use crate::crypto::{evm_address_from_public_key, parse_compressed_public_key};
use crate::paths::expand_derivation_paths;
use crate::types::{DecryptedKeyshare, ReconstructedKey};

/// Party id, quorum and root public key of a share, read without reconstructing.
pub struct Inspected {
    pub party_id: u8,
    /// Shares needed to reconstruct (the `t` in t-of-n).
    pub threshold: u8,
    pub total_parties: u8,
    /// Compressed SEC1 encoding.
    pub public_key: [u8; 33],
}

pub struct LoadedShare {
    pub party_id: u8,
    keyshare: Keyshare,
}

fn parse_keyshare(bytes: &[u8]) -> Result<Keyshare> {
    Keyshare::from_bytes(bytes).ok_or_else(|| anyhow!("not a valid DKLS23 keyshare"))
}

fn compressed(point: &ProjectivePoint) -> [u8; 33] {
    let enc = point.to_affine().to_encoded_point(true);
    enc.as_bytes()
        .try_into()
        .expect("compressed point is 33 bytes")
}

pub fn inspect_keyshare(bytes: &[u8]) -> Result<Inspected> {
    let keyshare = parse_keyshare(bytes)?;
    Ok(Inspected {
        party_id: keyshare.party_id,
        threshold: keyshare.threshold,
        total_parties: keyshare.total_parties,
        public_key: compressed(&keyshare.public_key()),
    })
}

fn validate_account_public_key(expected: &str, actual: &[u8; 33]) -> Result<()> {
    if parse_compressed_public_key(expected)? != *actual {
        bail!("keyshare root public key does not match account public key");
    }
    Ok(())
}

/// Inspect a share only after binding its embedded root to the account metadata.
pub(crate) fn inspect_account_keyshare(bytes: &[u8], public_key: &str) -> Result<Inspected> {
    let inspected = inspect_keyshare(bytes)?;
    validate_account_public_key(public_key, &inspected.public_key)?;
    Ok(inspected)
}

/// Decode a keyshare file's content: JSON with `keyshareBase64`, raw share
/// bytes, or base64 text.
pub fn decode_keyshare_bytes(content: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let trimmed = content.trim_ascii();
    if trimmed.first() == Some(&b'{') {
        let json: serde_json::Value = serde_json::from_slice(trimmed).context("not valid JSON")?;
        let b64 = json
            .get("keyshareBase64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("JSON has no keyshareBase64 string"))?;
        return STANDARD
            .decode(b64.trim())
            .map(Zeroizing::new)
            .context("keyshareBase64 is not valid base64");
    }
    if Keyshare::from_bytes(trimmed).is_some() {
        return Ok(Zeroizing::new(trimmed.to_vec()));
    }
    STANDARD
        .decode(trimmed)
        .map(Zeroizing::new)
        .context("not raw keyshare bytes, base64, or JSON")
}

pub fn load_share(bytes: &[u8], party_id_override: Option<u8>) -> Result<LoadedShare> {
    let keyshare = parse_keyshare(bytes)?;
    Ok(LoadedShare {
        party_id: party_id_override.unwrap_or(keyshare.party_id),
        keyshare,
    })
}

/// The raw DKLS share bytes of a decrypted keyshare.
pub fn keyshare_bytes(share: &DecryptedKeyshare) -> Result<Zeroizing<Vec<u8>>> {
    STANDARD
        .decode(&share.keyshare_base64)
        .map(Zeroizing::new)
        .context("keyshareBase64 is not valid base64")
}

pub fn load_shares_from_keyshares(shares: &[DecryptedKeyshare]) -> Result<Vec<LoadedShare>> {
    shares
        .iter()
        .map(|s| {
            let loaded = load_share(&keyshare_bytes(s)?, None)?;
            validate_account_public_key(&s.public_key, &compressed(&loaded.keyshare.public_key()))?;
            Ok(loaded)
        })
        .collect()
}

/// Reconstruct the root key and derive each requested path (`m` = root).
pub fn reconstruct(shares: &[LoadedShare], paths: &[String]) -> Result<Vec<ReconstructedKey>> {
    let Some(first) = shares.first() else {
        bail!("at least one keyshare must be supplied");
    };
    for (i, a) in shares.iter().enumerate() {
        if shares[i + 1..].iter().any(|b| b.party_id == a.party_id) {
            bail!("duplicate party id {}", a.party_id);
        }
    }

    let reference = &first.keyshare;
    let root_public_key = reference.public_key();
    let x_all = reference.x_i_list();

    for share in shares {
        if share.keyshare.public_key() != root_public_key {
            bail!(
                "keyshare for party {} has a different root public key",
                share.party_id
            );
        }
        if share.keyshare.root_chain_code() != reference.root_chain_code() {
            bail!(
                "keyshare for party {} has a different root chain code",
                share.party_id
            );
        }
        if usize::from(share.party_id) >= x_all.len() {
            bail!(
                "party id {} is outside the keyshare participant set",
                share.party_id
            );
        }
    }

    let mut x_i_list = Vec::with_capacity(shares.len());
    let mut s_i_list = Vec::with_capacity(shares.len());
    for share in shares {
        let id = usize::from(share.party_id);
        x_i_list.push((x_all[id], reference.get_rank(share.party_id) as usize));
        s_i_list.push(share.keyshare.s_i());
    }

    let root_private_key = Zeroizing::new(
        combine_shares(&x_i_list, &s_i_list, &root_public_key).ok_or_else(|| {
            anyhow!("could not reconstruct root private key: insufficient, mismatched or invalid keyshares")
        })?,
    );

    let paths = expand_derivation_paths(paths)?;

    paths
        .iter()
        .map(|path| {
            if path == "m" {
                return key_at(path, &root_private_key, &root_public_key);
            }
            let parsed = DerivationPath::from_str(path)
                .with_context(|| format!("invalid derivation path: {path}"))?;
            let (offset, expected_public) = reference
                .derive_with_offset(&parsed)
                .map_err(|e| anyhow!("child derivation failed for {path}: {e:?}"))?;
            let child_private: Zeroizing<Scalar> = Zeroizing::new(*root_private_key + offset);
            if ProjectivePoint::GENERATOR * *child_private != expected_public {
                bail!(
                    "child private key verification failed for {path}: derived public key mismatch"
                );
            }
            key_at(path, &child_private, &expected_public)
        })
        .collect()
}

fn key_at(path: &str, private: &Scalar, public: &ProjectivePoint) -> Result<ReconstructedKey> {
    let key_bytes = Zeroizing::new(private.to_bytes());
    let pk = compressed(public);
    Ok(ReconstructedKey {
        path: path.to_string(),
        private_key: format!("0x{}", hex::encode(key_bytes.as_slice())),
        public_key: format!("0x{}", hex::encode(pk)),
        evm_address: evm_address_from_public_key(&pk)?,
    })
}

/// Convenience: reconstruct straight from decrypted keyshares.
pub fn reconstruct_private_keys(
    shares: &[DecryptedKeyshare],
    paths: &[String],
) -> Result<Vec<ReconstructedKey>> {
    let loaded = load_shares_from_keyshares(shares)?;
    reconstruct(&loaded, paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::hex0x, test_helpers::keyshare, Address};

    fn share(root: u64, party_id: u8) -> DecryptedKeyshare {
        let raw = keyshare(root, party_id, &[]);
        let inspected = inspect_keyshare(&raw).unwrap();
        DecryptedKeyshare {
            keyshare_base64: STANDARD.encode(raw),
            public_key: hex0x(&inspected.public_key),
            evm_address: evm_address_from_public_key(&inspected.public_key).unwrap(),
            eoa: Address::ZERO,
            record_index: -1,
        }
    }

    #[test]
    fn rejects_mislabeled_in_memory_shares_before_reconstruction() {
        let advertised = share(11, 0);
        let mut shares = [share(7, 0), share(7, 1)];
        for s in &mut shares {
            s.public_key = advertised.public_key.clone();
            s.evm_address = advertised.evm_address;
        }
        let error = reconstruct_private_keys(&shares, &[]).unwrap_err();
        assert!(error
            .to_string()
            .contains("root public key does not match account public key"));
    }

    #[test]
    fn matching_metadata_preserves_root_and_soft_derivation() {
        let shares = [share(7, 0), share(7, 1)];
        let keys = reconstruct_private_keys(&shares, &["m".into(), "m/0".into()]).unwrap();
        assert_eq!(keys[0].private_key, format!("0x{:064x}", 7));
        assert_eq!(keys[0].public_key, shares[0].public_key);
        assert_eq!(keys[0].evm_address, shares[0].evm_address);
        // Independently cross-checked with @scure/bip32: root scalar 7, chain code [42; 32].
        assert_eq!(
            keys[1].private_key,
            "0xd1d60ab34cfec6a61d2657361681ef4300a71fb8ba9c85ed6d44c0bce48391ec"
        );
    }
}
