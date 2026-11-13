//! Turn fetched shard records into decrypted keyshares, and list the Salt
//! accounts a set of work EOAs hold shares for.

use aes_gcm::Aes256Gcm;
use alloy_primitives::Address;
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::HashMap;

use crate::crypto::{
    aes_decrypt, derive_aes_key, evm_address_from_public_key, gunzip, hex0x, unwrap_evaluation,
    PrivateKey,
};
use crate::reconstruct::inspect_account_keyshare;
use crate::types::{
    DecryptedKeyshare, DiscoveredAccount, EncryptedShardDump, EncryptedShardRecord,
};

struct Unlocked<'a> {
    record: &'a EncryptedShardRecord,
    aes_key: Aes256Gcm,
    /// Compressed MPC public key, lowercase 0x hex.
    public_key: String,
}

fn assert_dump_owner(dump: &EncryptedShardDump, key: &PrivateKey) -> Result<Address> {
    let eoa = key.address();
    if eoa != dump.eoa {
        bail!(
            "Private key address {} does not match dump EOA {}",
            eoa.to_checksum(None),
            dump.eoa.to_checksum(None)
        );
    }
    Ok(eoa)
}

/// Derive each record's AES key and decrypt the small `saltAccount` field to
/// learn the MPC public key, without touching the keyshare ciphertext.
/// Records that fail to open are skipped. Newest (highest index) first.
fn unlock_records<'a>(
    dump: &'a EncryptedShardDump,
    key: &PrivateKey,
    eoa: Address,
) -> Vec<Unlocked<'a>> {
    let mut records: Vec<&EncryptedShardRecord> = dump.records.iter().collect();
    records.sort_by(|a, b| b.index.cmp(&a.index));

    records
        .into_iter()
        .filter_map(|record| {
            let oprf = unwrap_evaluation(key, &record.evaluation).ok()?;
            let aes_key = derive_aes_key(&oprf, eoa);
            let public_key = aes_decrypt(&record.salt_account, &aes_key).ok()?;
            // Anything that isn't a compressed secp256k1 point is not a Salt account.
            evm_address_from_public_key(&public_key).ok()?;
            Some(Unlocked {
                record,
                aes_key,
                public_key: hex0x(&public_key),
            })
        })
        .collect()
}

fn key_for<'k>(keys: &'k [PrivateKey], dump: &EncryptedShardDump) -> Result<&'k PrivateKey> {
    keys.iter()
        .find(|k| k.address() == dump.eoa)
        .ok_or_else(|| {
            anyhow!(
                "No private key supplied for dump EOA {}",
                dump.eoa.to_checksum(None)
            )
        })
}

/// Salt accounts whose shards the supplied EOAs hold, most widely held first.
pub fn discover_accounts(
    dumps: &[EncryptedShardDump],
    keys: &[PrivateKey],
) -> Result<Vec<DiscoveredAccount>> {
    let mut accounts: HashMap<String, DiscoveredAccount> = HashMap::new();
    let mut order: Vec<String> = Vec::new();

    for dump in dumps {
        let key = key_for(keys, dump)?;
        let eoa = assert_dump_owner(dump, key)?;
        for unlocked in unlock_records(dump, key, eoa) {
            match accounts.get_mut(&unlocked.public_key) {
                Some(existing) => {
                    existing.record_count += 1;
                    if !existing.eoas.contains(&eoa) {
                        existing.eoas.push(eoa);
                    }
                }
                None => {
                    let bytes = hex::decode(&unlocked.public_key[2..]).expect("hex0x output");
                    order.push(unlocked.public_key.clone());
                    accounts.insert(
                        unlocked.public_key.clone(),
                        DiscoveredAccount {
                            evm_address: evm_address_from_public_key(&bytes)?,
                            public_key: unlocked.public_key,
                            eoas: vec![eoa],
                            record_count: 1,
                        },
                    );
                }
            }
        }
    }

    let mut result: Vec<DiscoveredAccount> = order
        .into_iter()
        .map(|k| accounts.remove(&k).expect("inserted above"))
        .collect();
    // Stable sort keeps discovery order among equals.
    result.sort_by(|a, b| b.eoas.len().cmp(&a.eoas.len()));
    Ok(result)
}

/// Decrypt one keyshare from `dump`. With `public_key`, the newest record for
/// that account; without, the newest record overall, failing if the EOA holds
/// shares of more than one account.
/// An opened payload must contain a valid DKLS share for its declared account.
pub fn decrypt_shard_dump(
    dump: &EncryptedShardDump,
    key: &PrivateKey,
    public_key: Option<&str>,
) -> Result<DecryptedKeyshare> {
    open_shard_dump(dump, key, public_key)?
        .ok_or_else(|| anyhow!("No shard record decrypted with the supplied private key"))
}

/// Like [`decrypt_shard_dump`], but `Ok(None)` when no record opens.
fn open_shard_dump(
    dump: &EncryptedShardDump,
    key: &PrivateKey,
    public_key: Option<&str>,
) -> Result<Option<DecryptedKeyshare>> {
    let eoa = assert_dump_owner(dump, key)?;
    let wanted = public_key.map(|p| p.trim().to_ascii_lowercase());

    let mut opened: Vec<(String, String, i64)> = Vec::new(); // (public_key, base64, index)
    for unlocked in unlock_records(dump, key, eoa) {
        if let Some(wanted) = &wanted {
            if &unlocked.public_key != wanted {
                continue;
            }
        }
        let Ok(compressed) = aes_decrypt(&unlocked.record.ciphertext, &unlocked.aes_key) else {
            continue;
        };
        let Ok(plain) = gunzip(&compressed) else {
            continue;
        };
        // Inconsistent account metadata is an integrity error, not a reason to
        // silently fall back to an older share.
        inspect_account_keyshare(&plain, &unlocked.public_key).with_context(|| {
            format!(
                "invalid keyshare in record {} for EOA {}",
                unlocked.record.index,
                eoa.to_checksum(None)
            )
        })?;
        opened.push((
            unlocked.public_key.clone(),
            STANDARD.encode(plain.as_slice()),
            unlocked.record.index as i64,
        ));
        if wanted.is_some() {
            break;
        }
    }

    if opened.is_empty() {
        return Ok(None);
    }

    if wanted.is_none() {
        let mut distinct: Vec<&str> = Vec::new();
        for (pk, _, _) in &opened {
            if !distinct.contains(&pk.as_str()) {
                distinct.push(pk);
            }
        }
        if distinct.len() > 1 {
            bail!(
                "Multiple Salt accounts decrypted; choose one public key: {}",
                distinct.join(", ")
            );
        }
    }

    let (public_key, keyshare_base64, record_index) = opened.swap_remove(0);
    let bytes = hex::decode(&public_key[2..]).expect("hex0x output");
    Ok(Some(DecryptedKeyshare {
        evm_address: evm_address_from_public_key(&bytes)?,
        keyshare_base64,
        public_key,
        eoa,
        record_index,
    }))
}

/// Decrypt one keyshare per dump, matching each dump to its private key.
///
/// With `public_key`, EOAs that hold no share of that account are skipped
/// (e.g. Robo Guardian accounts a smaller quorum never used); at least one must open.
/// Without it, every dump must decrypt.
pub fn decrypt_shard_dumps(
    dumps: &[EncryptedShardDump],
    keys: &[PrivateKey],
    public_key: Option<&str>,
) -> Result<Vec<DecryptedKeyshare>> {
    let mut shares = Vec::with_capacity(dumps.len());
    for dump in dumps {
        let key = key_for(keys, dump)?;
        match (open_shard_dump(dump, key, public_key)?, public_key) {
            (Some(share), _) => shares.push(share),
            (None, Some(_)) => {}
            (None, None) => bail!(
                "No shard record decrypted with the private key for {}",
                dump.eoa.to_checksum(None)
            ),
        }
    }
    if shares.is_empty() {
        bail!("No shard record for the selected account decrypted with the supplied keys");
    }
    Ok(shares)
}

#[cfg(test)]
mod tests {
    //! Records are sealed here the way Salt's backend seals them, then opened
    //! with the production code above:
    //!   evaluation  = ECIES(eoa pubkey, oprf_output)
    //!   aes_key     = HKDF-SHA256(oprf_output, salt = lowercase eoa, info)
    //!   saltAccount = iv || AES-GCM(aes_key, compressed MPC pubkey)
    //!   ciphertext  = iv || AES-GCM(aes_key, gzip(keyshare))
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use alloy_primitives::{address, Bytes, B256};
    use hkdf::Hkdf;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::Sha256;
    use std::io::Write;

    use crate::test_helpers::keyshare;

    struct Signer {
        key: PrivateKey,
        eoa: Address,
    }

    struct Account {
        root: u64,
        public_key: [u8; 33],
        evm_address: Address,
    }

    fn signer(byte: &str) -> Signer {
        let key = PrivateKey::parse(&byte.repeat(32)).unwrap();
        let eoa = key.address();
        Signer { key, eoa }
    }

    fn account(seed: u32) -> Account {
        let key = PrivateKey::parse(&format!("{seed:064x}")).unwrap();
        let secret = k256::SecretKey::from_slice(key.bytes()).unwrap();
        let pk = secret.public_key().to_encoded_point(true);
        Account {
            root: u64::from(seed),
            public_key: pk.as_bytes().try_into().unwrap(),
            evm_address: key.address(),
        }
    }

    fn hex_pk(a: &Account) -> String {
        hex0x(&a.public_key)
    }

    fn aes_encrypt(key: &Aes256Gcm, plain: &[u8], seed: u8) -> Bytes {
        let iv = [seed; 12];
        let mut out = iv.to_vec();
        out.extend(key.encrypt(Nonce::from_slice(&iv), plain).unwrap());
        Bytes::from(out)
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn record(owner: &Signer, acct: &Account, marker: &[u8], index: u64) -> EncryptedShardRecord {
        sealed_record(owner, acct, &keyshare(acct.root, 0, marker), index)
    }

    fn sealed_record(
        owner: &Signer,
        acct: &Account,
        keyshare: &[u8],
        index: u64,
    ) -> EncryptedShardRecord {
        let oprf: Vec<u8> = (0..32).map(|i| (i as u8) ^ (index as u8)).collect();
        let secret = k256::SecretKey::from_slice(owner.key.bytes()).unwrap();
        let eoa_pk = secret.public_key().to_encoded_point(true);
        let evaluation = ecies::encrypt(eoa_pk.as_bytes(), &oprf).unwrap();

        let salt = format!("{:#x}", owner.eoa);
        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &oprf);
        let mut key = [0u8; 32];
        hk.expand(crate::networks::HKDF_INFO, &mut key).unwrap();
        let aes = Aes256Gcm::new((&key).into());

        EncryptedShardRecord {
            index,
            salt_account: aes_encrypt(&aes, &acct.public_key, 1),
            evaluation: Bytes::from(evaluation),
            tx_hashes: vec![B256::with_last_byte(index as u8)],
            ciphertext: aes_encrypt(&aes, &gzip(keyshare), 2),
        }
    }

    fn dump(owner: &Signer, records: Vec<EncryptedShardRecord>) -> EncryptedShardDump {
        EncryptedShardDump {
            chain_id: 421614,
            registry: address!("1111111111111111111111111111111111111111"),
            eoa: owner.eoa,
            records,
        }
    }

    fn b64(acct: &Account, marker: &str) -> String {
        STANDARD.encode(keyshare(acct.root, 0, marker.as_bytes()))
    }

    #[test]
    fn decrypts_record_with_provenance() {
        let alice = signer("a1");
        let x = account(1001);
        let d = dump(&alice, vec![record(&alice, &x, b"keyshare-x-alice", 0)]);
        let share = decrypt_shard_dump(&d, &alice.key, None).unwrap();
        assert_eq!(share.keyshare_base64, b64(&x, "keyshare-x-alice"));
        assert_eq!(share.public_key, hex_pk(&x));
        assert_eq!(share.evm_address, x.evm_address);
        assert_eq!(share.eoa, alice.eoa);
        assert_eq!(share.record_index, 0);
    }

    #[test]
    fn rejects_account_mismatch_without_falling_back_to_older_record() {
        let alice = signer("a1");
        let x = account(1001);
        let d = dump(
            &alice,
            vec![
                record(&alice, &x, b"old", 4),
                sealed_record(&alice, &x, &keyshare(2002, 0, &[]), 9),
            ],
        );
        let public_key = hex_pk(&x);
        // Discovery is metadata-only; the binding must be checked at decrypt.
        let accounts = discover_accounts(std::slice::from_ref(&d), &[alice.key.clone()]).unwrap();
        assert_eq!(accounts[0].public_key, public_key);
        for selected in [None, Some(public_key.as_str())] {
            let error = decrypt_shard_dump(&d, &alice.key, selected).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("record 9"), "{message}");
            assert!(
                message.contains("root public key does not match account public key"),
                "{message}"
            );
        }
        assert!(decrypt_shard_dumps(&[d], &[alice.key], Some(&public_key)).is_err());
    }

    #[test]
    fn rejects_invalid_dkls_bytes_before_accepting_a_share() {
        let alice = signer("a1");
        let x = account(1001);
        let d = dump(
            &alice,
            vec![sealed_record(&alice, &x, b"not a DKLS share", 0)],
        );
        let error = decrypt_shard_dump(&d, &alice.key, Some(&hex_pk(&x))).unwrap_err();
        assert!(format!("{error:#}").contains("not a valid DKLS23 keyshare"));
    }

    #[test]
    fn matching_account_shares_reconstruct_the_selected_root() {
        let (alice, bob) = (signer("a1"), signer("b2"));
        let x = account(1001);
        let dumps = [
            dump(
                &alice,
                vec![sealed_record(&alice, &x, &keyshare(x.root, 0, &[]), 0)],
            ),
            dump(
                &bob,
                vec![sealed_record(&bob, &x, &keyshare(x.root, 1, &[]), 0)],
            ),
        ];
        let shares = decrypt_shard_dumps(&dumps, &[alice.key, bob.key], Some(&hex_pk(&x))).unwrap();
        let recovered = crate::reconstruct::reconstruct_private_keys(&shares, &[]).unwrap();
        assert_eq!(recovered[0].private_key, format!("0x{:064x}", x.root));
        assert_eq!(recovered[0].public_key, hex_pk(&x));
        assert_eq!(recovered[0].evm_address, x.evm_address);
    }

    #[test]
    fn prefers_newest_record_regardless_of_order() {
        let alice = signer("a1");
        let x = account(1001);
        let d = dump(
            &alice,
            vec![record(&alice, &x, b"new", 9), record(&alice, &x, b"old", 4)],
        );
        let share = decrypt_shard_dump(&d, &alice.key, None).unwrap();
        assert_eq!(share.record_index, 9);
        assert_eq!(share.keyshare_base64, b64(&x, "new"));
    }

    #[test]
    fn skips_records_the_key_cannot_open() {
        let (alice, bob) = (signer("a1"), signer("b2"));
        let x = account(1001);
        let d = dump(
            &alice,
            vec![record(&bob, &x, b"bobs", 5), record(&alice, &x, b"mine", 1)],
        );
        assert_eq!(
            decrypt_shard_dump(&d, &alice.key, None)
                .unwrap()
                .record_index,
            1
        );
    }

    #[test]
    fn owner_mismatch_and_nothing_decrypts() {
        let (alice, bob) = (signer("a1"), signer("b2"));
        let x = account(1001);
        let d = dump(&alice, vec![record(&alice, &x, b"x", 0)]);
        let err = decrypt_shard_dump(&d, &bob.key, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match dump EOA"), "{err}");

        let foreign = dump(&alice, vec![record(&bob, &x, b"bobs", 0)]);
        let err = decrypt_shard_dump(&foreign, &alice.key, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("No shard record decrypted"), "{err}");
    }

    #[test]
    fn multiple_accounts_need_a_public_key() {
        let alice = signer("a1");
        let (x, y) = (account(1001), account(2002));
        let d = dump(
            &alice,
            vec![record(&alice, &x, b"x", 0), record(&alice, &y, b"y", 1)],
        );
        let err = decrypt_shard_dump(&d, &alice.key, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Multiple Salt accounts decrypted"), "{err}");

        let upper = hex_pk(&y).to_uppercase().replacen("0X", "0x", 1);
        let share = decrypt_shard_dump(&d, &alice.key, Some(&upper)).unwrap();
        assert_eq!(share.public_key, hex_pk(&y));
        assert_eq!(share.keyshare_base64, b64(&y, "y"));
    }

    #[test]
    fn discover_lists_accounts_most_widely_held_first() {
        let (alice, bob) = (signer("a1"), signer("b2"));
        let (x, y) = (account(1001), account(2002));
        let a = dump(
            &alice,
            vec![
                record(&alice, &y, b"y-a", 0),
                record(&alice, &x, b"x-a-old", 1),
                record(&alice, &x, b"x-a", 2),
            ],
        );
        let b = dump(&bob, vec![record(&bob, &x, b"x-b", 0)]);
        let keys = [bob.key.clone(), alice.key.clone()];
        let accounts = discover_accounts(&[a, b], &keys).unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].public_key, hex_pk(&x));
        assert_eq!(accounts[0].evm_address, x.evm_address);
        assert_eq!(accounts[0].eoas, vec![alice.eoa, bob.eoa]);
        assert_eq!(accounts[0].record_count, 3);
        assert_eq!(accounts[1].public_key, hex_pk(&y));
        assert_eq!(accounts[1].eoas, vec![alice.eoa]);
        assert_eq!(accounts[1].record_count, 1);

        let only_bob = dump(&bob, vec![record(&bob, &x, b"x", 0)]);
        let err = discover_accounts(&[only_bob], &[alice.key.clone()])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("No private key supplied for dump EOA"),
            "{err}"
        );
    }

    #[test]
    fn decrypt_dumps_matches_each_key() {
        let (alice, bob) = (signer("a1"), signer("b2"));
        let (x, y) = (account(1001), account(2002));
        let a = dump(
            &alice,
            vec![record(&alice, &x, b"x-a", 0), record(&alice, &y, b"y-a", 1)],
        );
        let b = dump(&bob, vec![record(&bob, &x, b"x-b", 0)]);
        let keys = [bob.key.clone(), alice.key.clone()];
        let shares = decrypt_shard_dumps(&[a, b], &keys, Some(&hex_pk(&x))).unwrap();
        assert_eq!(shares.len(), 2);
        assert_eq!(
            (shares[0].eoa, shares[0].keyshare_base64.as_str()),
            (alice.eoa, b64(&x, "x-a").as_str())
        );
        assert_eq!(
            (shares[1].eoa, shares[1].keyshare_base64.as_str()),
            (bob.eoa, b64(&x, "x-b").as_str())
        );
        assert!(shares.iter().all(|s| s.public_key == hex_pk(&x)));
    }

    #[test]
    fn decrypt_dumps_skips_keys_without_the_account() {
        let (owner, robo1, robo2) = (signer("a1"), signer("b2"), signer("c3"));
        let (x, y) = (account(1001), account(2002));
        let dumps = [
            dump(&owner, vec![record(&owner, &x, b"x-owner", 0)]),
            dump(&robo1, vec![record(&robo1, &x, b"x-robo1", 0)]),
            dump(&robo2, vec![record(&robo2, &y, b"y-robo2", 0)]),
        ];
        let keys = [owner.key.clone(), robo1.key.clone(), robo2.key.clone()];

        let shares = decrypt_shard_dumps(&dumps, &keys, Some(&hex_pk(&x))).unwrap();
        let eoas: Vec<Address> = shares.iter().map(|s| s.eoa).collect();
        assert_eq!(eoas, vec![owner.eoa, robo1.eoa]);

        let err = decrypt_shard_dumps(&dumps[..1], &keys, Some(&hex_pk(&y)))
            .unwrap_err()
            .to_string();
        assert!(err.contains("selected account"), "{err}");

        let unopenable = [
            dumps[0].clone(),
            dump(&robo2, vec![record(&owner, &x, b"not-robo2s", 0)]),
        ];
        let err = decrypt_shard_dumps(&unopenable, &keys, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("private key for"), "{err}");
    }
}
