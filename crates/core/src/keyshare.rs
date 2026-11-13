//! Keyshare files on disk. Two formats are accepted:
//!
//! - JSON export `{ keyshareBase64, publicKey, evmAddress, eoa, recordIndex }`
//!   written by `srt decrypt --out` or the desktop app.
//! - Raw base64 keyshare text (e.g. salt-signer-sdk's `keyshare-N.txt`). It
//!   carries no metadata, so the root public key and party id are read from
//!   the DKLS share itself.

use alloy_primitives::Address;
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::path::Path;
use zeroize::Zeroizing;

use crate::crypto::{evm_address_from_public_key, hex0x, parse_compressed_public_key};
use crate::reconstruct::{inspect_account_keyshare, inspect_keyshare, keyshare_bytes};
use crate::types::{DecryptedKeyshare, KeyshareInfo};

/// UI-safe info, after verifying the share belongs to the declared account.
pub fn keyshare_info(share: &DecryptedKeyshare) -> Result<KeyshareInfo> {
    let inspected = inspect_account_keyshare(&keyshare_bytes(share)?, &share.public_key)?;
    let mut info = KeyshareInfo::from(share);
    info.public_key = hex0x(&inspected.public_key);
    info.evm_address = evm_address_from_public_key(&inspected.public_key)?;
    info.party_id = Some(inspected.party_id);
    info.threshold = Some(inspected.threshold);
    info.total_parties = Some(inspected.total_parties);
    Ok(info)
}

/// Default export name: `salt-keyshare-<account>-<eoa>.json`.
pub fn keyshare_file_name(share: &DecryptedKeyshare) -> String {
    format!(
        "salt-keyshare-{}-{}.json",
        share.evm_address.to_checksum(None),
        share.eoa.to_checksum(None)
    )
}

pub fn serialize_keyshare_file(share: &DecryptedKeyshare) -> String {
    serde_json::to_string_pretty(share).expect("keyshare serializes")
}

fn is_base64(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Parse a JSON export. `evmAddress` is recomputed from `publicKey`; `eoa` and
/// `recordIndex` are optional so older exports still load.
/// The embedded DKLS root must match `publicKey`.
pub fn parse_keyshare_file(json: &str, source: &str) -> Result<DecryptedKeyshare> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|_| anyhow!("{source}: not valid JSON"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("{source}: expected a JSON object"))?;

    let keyshare_base64 = obj
        .get("keyshareBase64")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("{source}: missing keyshareBase64"))?;
    if !is_base64(keyshare_base64) {
        bail!("{source}: keyshareBase64 is not base64");
    }

    let public_key = obj
        .get("publicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!("{source}: publicKey must be a compressed secp256k1 key (0x02/0x03 + 64 hex)")
        })?;
    let bytes = parse_compressed_public_key(public_key).map_err(|e| anyhow!("{source}: {e}"))?;

    let eoa = obj
        .get("eoa")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Address>().ok())
        .unwrap_or(Address::ZERO);
    let record_index = obj
        .get("recordIndex")
        .and_then(|v| v.as_i64())
        .unwrap_or(-1);

    let share = DecryptedKeyshare {
        keyshare_base64: keyshare_base64.to_string(),
        public_key: format!("0x{}", hex::encode(bytes)),
        evm_address: evm_address_from_public_key(&bytes)?,
        eoa,
        record_index,
    };
    keyshare_info(&share).map_err(|e| anyhow!("{source}: {e}"))?;
    Ok(share)
}

pub fn is_json_keyshare_file(content: &str) -> bool {
    content.trim_start().starts_with('{')
}

/// Build a keyshare record from raw base64 text and its (separately read)
/// root public key. No provenance: zero EOA, record index -1.
pub fn raw_keyshare_from_base64(
    content: &str,
    public_key: &[u8; 33],
    source: &str,
) -> Result<DecryptedKeyshare> {
    let keyshare_base64: String = content.split_whitespace().collect();
    if keyshare_base64.is_empty() {
        bail!("{source}: file is empty");
    }
    if !is_base64(&keyshare_base64) {
        bail!("{source}: not a base64 keyshare or a JSON export");
    }
    let share = DecryptedKeyshare {
        keyshare_base64,
        public_key: format!("0x{}", hex::encode(public_key)),
        evm_address: evm_address_from_public_key(public_key)?,
        eoa: Address::ZERO,
        record_index: -1,
    };
    keyshare_info(&share).map_err(|e| anyhow!("{source}: {e}"))?;
    Ok(share)
}

/// Load a keyshare file in either format. Returns the share and UI-safe info
/// (with party id and quorum read from the share).
pub fn load_keyshare_file(path: &Path) -> Result<(DecryptedKeyshare, KeyshareInfo)> {
    let source = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let content = Zeroizing::new(
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    );

    if is_json_keyshare_file(&content) {
        let share = parse_keyshare_file(&content, &source)?;
        let info = keyshare_info(&share)?;
        return Ok((share, info));
    }

    let compact: String = content.split_whitespace().collect();
    if !is_base64(&compact) {
        bail!("{source}: not a base64 keyshare or a JSON export");
    }
    let raw = Zeroizing::new(
        STANDARD
            .decode(&compact)
            .map_err(|_| anyhow!("{source}: not a base64 keyshare or a JSON export"))?,
    );
    let inspected = inspect_keyshare(&raw).map_err(|e| anyhow!("{source}: {e}"))?;
    let share = raw_keyshare_from_base64(&content, &inspected.public_key, &source)?;
    let info = keyshare_info(&share)?;
    Ok((share, info))
}

/// Every share must belong to the same Salt account and be distinct.
pub fn assert_same_account(shares: &[DecryptedKeyshare]) -> Result<()> {
    let Some(first) = shares.first() else {
        bail!("No keyshares supplied");
    };
    for share in shares {
        if share.public_key != first.public_key {
            bail!(
                "Keyshares belong to different Salt accounts ({} vs {})",
                first.evm_address.to_checksum(None),
                share.evm_address.to_checksum(None)
            );
        }
    }
    for (i, a) in shares.iter().enumerate() {
        if shares[i + 1..]
            .iter()
            .any(|b| b.keyshare_base64 == a.keyshare_base64)
        {
            bail!("The same keyshare was supplied more than once; each share must be distinct");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;
    use crate::test_helpers::keyshare;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    fn account(seed: u8) -> (String, Address) {
        let key = PrivateKey::parse(&format!("{:064x}", seed)).unwrap();
        let secret = k256::SecretKey::from_slice(key.bytes()).unwrap();
        let pk = secret.public_key().to_encoded_point(true);
        (format!("0x{}", hex::encode(pk.as_bytes())), key.address())
    }

    fn share() -> DecryptedKeyshare {
        let (public_key, evm_address) = account(7);
        DecryptedKeyshare {
            keyshare_base64: STANDARD.encode(keyshare(7, 0, &[])),
            public_key,
            evm_address,
            eoa: PrivateKey::parse(&"42".repeat(32)).unwrap().address(),
            record_index: 3,
        }
    }

    #[test]
    fn round_trip_keeps_documented_fields() {
        let s = share();
        let json = serialize_keyshare_file(&s);
        let positions: Vec<usize> = [
            "keyshareBase64",
            "publicKey",
            "evmAddress",
            "eoa\"",
            "recordIndex",
        ]
        .iter()
        .map(|k| json.find(&format!("\"{k}")).expect(k))
        .collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "field order: {json}"
        );
        assert_eq!(json.matches(':').count(), 5, "exactly five fields: {json}");
        assert_eq!(parse_keyshare_file(&json, "f").unwrap(), s);
    }

    #[test]
    fn recomputes_address_and_normalises_case() {
        let s = share();
        let (_, other_addr) = account(11);
        let tampered = serde_json::json!({
            "keyshareBase64": s.keyshare_base64,
            "publicKey": s.public_key.to_uppercase().replacen("0X", "0x", 1),
            "evmAddress": other_addr.to_checksum(None),
            "eoa": s.eoa.to_checksum(None),
            "recordIndex": 3,
        });
        let parsed = parse_keyshare_file(&tampered.to_string(), "f").unwrap();
        assert_eq!(parsed.public_key, s.public_key);
        assert_eq!(parsed.evm_address, s.evm_address);
    }

    #[test]
    fn rejects_json_and_metadata_for_a_different_embedded_account() {
        let mut s = share();
        let (public_key, address) = account(11);
        s.public_key = public_key;
        s.evm_address = address;
        let error = parse_keyshare_file(&serialize_keyshare_file(&s), "mismatch.json").unwrap_err();
        let message = error.to_string();
        assert!(message.starts_with("mismatch.json: "), "{message}");
        assert!(
            message.contains("root public key does not match account public key"),
            "{message}"
        );
        assert!(keyshare_info(&s)
            .unwrap_err()
            .to_string()
            .contains("does not match"));
    }

    #[test]
    fn metadata_uses_the_verified_root_and_quorum() {
        let mut s = share();
        let expected = s.clone();
        s.public_key = s.public_key.to_uppercase().replacen("0X", "0x", 1);
        s.evm_address = Address::ZERO;
        let info = keyshare_info(&s).unwrap();
        assert_eq!(info.public_key, expected.public_key);
        assert_eq!(info.evm_address, expected.evm_address);
        assert_eq!(info.party_id, Some(0));
        assert_eq!(info.threshold, Some(2));
        assert_eq!(info.total_parties, Some(3));
    }

    #[test]
    fn rejects_invalid_dkls_material_in_json_and_metadata() {
        let mut s = share();
        s.keyshare_base64 = STANDARD.encode("not a DKLS share");
        assert!(
            parse_keyshare_file(&serialize_keyshare_file(&s), "bad.json")
                .unwrap_err()
                .to_string()
                .contains("not a valid DKLS23 keyshare")
        );
        assert!(keyshare_info(&s).is_err());
    }

    #[test]
    fn legacy_export_without_provenance() {
        let s = share();
        let json =
            serde_json::json!({ "keyshareBase64": s.keyshare_base64, "publicKey": s.public_key });
        let parsed = parse_keyshare_file(&json.to_string(), "f").unwrap();
        assert_eq!(parsed.eoa, Address::ZERO);
        assert_eq!(parsed.record_index, -1);
    }

    #[test]
    fn rejects_bad_files() {
        let (pk, _) = account(7);
        let cases = [
            ("nope", "not valid JSON"),
            ("\"just a string\"", "expected a JSON object"),
            (
                &format!(r#"{{"publicKey":"{pk}"}}"#),
                "missing keyshareBase64",
            ),
            (
                &format!(r#"{{"keyshareBase64":"!!","publicKey":"{pk}"}}"#),
                "not base64",
            ),
            (
                r#"{"keyshareBase64":"AAAA","publicKey":"0x04abcd"}"#,
                "33 bytes",
            ),
            (
                &format!(
                    r#"{{"keyshareBase64":"AAAA","publicKey":"0x02{}"}}"#,
                    "00".repeat(32)
                ),
                "not a valid secp256k1",
            ),
        ];
        for (json, msg) in cases {
            let err = parse_keyshare_file(json, "f.json").unwrap_err().to_string();
            assert!(err.starts_with("f.json: "), "{err}");
            assert!(err.contains(msg), "{err} should contain {msg}");
        }
    }

    #[test]
    fn file_name_uses_account_and_eoa() {
        let s = share();
        assert_eq!(
            keyshare_file_name(&s),
            format!(
                "salt-keyshare-{}-{}.json",
                s.evm_address.to_checksum(None),
                s.eoa.to_checksum(None)
            )
        );
    }

    #[test]
    fn raw_keyshare_handling() {
        assert!(is_json_keyshare_file("  {\"a\":1}"));
        assert!(!is_json_keyshare_file("QUJD\n"));

        let (pk, addr) = account(7);
        let pk_bytes = parse_compressed_public_key(&pk).unwrap();
        let encoded = STANDARD.encode(keyshare(7, 0, &[]));
        let wrapped = format!("{}\n{}\n", &encoded[..76], &encoded[76..]);
        let raw = raw_keyshare_from_base64(&wrapped, &pk_bytes, "k.txt").unwrap();
        assert_eq!(raw.keyshare_base64, encoded);
        assert_eq!(raw.public_key, pk);
        assert_eq!(raw.evm_address, addr);
        assert_eq!(raw.eoa, Address::ZERO);
        assert_eq!(raw.record_index, -1);

        let (other_pk, _) = account(11);
        let other_pk = parse_compressed_public_key(&other_pk).unwrap();
        assert!(raw_keyshare_from_base64(&wrapped, &other_pk, "k.txt")
            .unwrap_err()
            .to_string()
            .contains("does not match"));

        assert!(raw_keyshare_from_base64("  \n", &pk_bytes, "k.txt")
            .unwrap_err()
            .to_string()
            .contains("k.txt: file is empty"));
        assert!(raw_keyshare_from_base64("hello world!", &pk_bytes, "k.txt")
            .unwrap_err()
            .to_string()
            .contains("not a base64 keyshare"));
    }

    #[test]
    fn same_account_checks() {
        let s = share();
        let mut second = s.clone();
        second.keyshare_base64 = STANDARD.encode(keyshare(7, 1, &[]));
        assert!(assert_same_account(&[s.clone(), second]).is_ok());

        assert!(assert_same_account(&[])
            .unwrap_err()
            .to_string()
            .contains("No keyshares"));

        let (other_pk, other_addr) = account(11);
        let mut other = s.clone();
        other.public_key = other_pk;
        other.evm_address = other_addr;
        assert!(assert_same_account(&[s.clone(), other])
            .unwrap_err()
            .to_string()
            .contains("different Salt accounts"));

        assert!(assert_same_account(&[s.clone(), s.clone()])
            .unwrap_err()
            .to_string()
            .contains("more than once"));
    }
}
