//! Tauri commands for the recovery wizard. All key material (work EOA keys,
//! shard dumps, decrypted shares) lives in `Session` inside this process; the
//! webview only ever receives metadata and the final reconstructed keys.
//! The GUI never reads or writes keyshare files; that is CLI-only.

mod cli;

use std::path::PathBuf;
use std::sync::Mutex;

use salt_recovery_core::{
    crypto::PrivateKey,
    decrypt::{decrypt_shard_dumps, discover_accounts},
    keyshare::keyshare_info,
    networks::Network,
    reconstruct::reconstruct_private_keys,
    registry::{fetch_encrypted_shards, RpcClient},
    types::{
        DecryptedKeyshare, DiscoveredAccount, EncryptedShardDump, KeyshareInfo, ReconstructedKey,
    },
    Address,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

#[derive(Default)]
struct Session {
    private_keys: Vec<PrivateKey>,
    dumps: Vec<EncryptedShardDump>,
    shares: Vec<DecryptedKeyshare>,
}

type SessionState<'a> = State<'a, Mutex<Session>>;

fn lock<'a>(session: &'a SessionState<'_>) -> std::sync::MutexGuard<'a, Session> {
    session
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn err(e: impl std::fmt::Display) -> String {
    format!("{e:#}")
}

// --- Network settings persistence (no keys or recovery records) ---

#[derive(Serialize, Deserialize, Clone)]
struct RpcEndpoint {
    network: Network,
    url: String,
    #[serde(
        default,
        rename = "registryAddress",
        skip_serializing_if = "Option::is_none"
    )]
    registry_address: Option<Address>,
}

fn endpoints_file(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(err)?;
    std::fs::create_dir_all(&dir).map_err(err)?;
    Ok(dir.join("rpc-endpoints.json"))
}

fn parse_rpc_endpoints(text: &str) -> Vec<RpcEndpoint> {
    // Ignore retired networks (including STAGING) without discarding saved
    // endpoints for the networks that are still supported.
    serde_json::from_str::<Vec<serde_json::Value>>(text)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| serde_json::from_value(value).ok())
        .collect()
}

fn merge_rpc_endpoints(mut saved: Vec<RpcEndpoint>, updates: Vec<RpcEndpoint>) -> Vec<RpcEndpoint> {
    for update in updates {
        if let Some(existing) = saved
            .iter_mut()
            .find(|entry| entry.network == update.network)
        {
            *existing = update;
        } else {
            saved.push(update);
        }
    }
    saved
}

#[tauri::command]
fn load_rpc_endpoints(app: AppHandle) -> Result<Vec<RpcEndpoint>, String> {
    let path = endpoints_file(&app)?;
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(vec![]);
    };
    Ok(parse_rpc_endpoints(&text))
}

#[tauri::command]
fn save_rpc_endpoints(app: AppHandle, endpoints: Vec<RpcEndpoint>) -> Result<(), String> {
    let path = endpoints_file(&app)?;
    let saved = parse_rpc_endpoints(&std::fs::read_to_string(&path).unwrap_or_default());
    let endpoints = merge_rpc_endpoints(saved, endpoints);
    let text = serde_json::to_string_pretty(&endpoints).map_err(err)?;
    std::fs::write(path, text).map_err(err)
}

#[derive(Serialize)]
struct Validation {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[tauri::command]
async fn validate_rpc_endpoint(url: String) -> Validation {
    match RpcClient::new(url).chain_id().await {
        Ok(_) => Validation {
            valid: true,
            error: None,
        },
        Err(e) => Validation {
            valid: false,
            error: Some(err(e)),
        },
    }
}

// --- Fetch / decrypt / reconstruct --------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FetchedDump {
    eoa: String,
    record_count: usize,
}

fn resolve_registry(network: Network, override_address: Option<&str>) -> Result<Address, String> {
    let address = match override_address {
        Some(value) => {
            let value = value.trim();
            let message = "Registry address must be 0x followed by 40 hexadecimal characters";
            if !value.starts_with("0x") || value.len() != 42 {
                return Err(message.into());
            }
            value.parse::<Address>().map_err(|_| message.to_string())?
        }
        None => network.registry(),
    };
    if address == Address::ZERO {
        return Err("Registry address cannot be the zero address".into());
    }
    Ok(address)
}

#[tauri::command]
async fn fetch_shards(
    session: SessionState<'_>,
    network: Network,
    rpc_url: String,
    registry_address: Option<String>,
    mut eoa_private_keys: Vec<String>,
) -> Result<Vec<FetchedDump>, String> {
    let parsed: Result<Vec<PrivateKey>, _> = eoa_private_keys
        .iter()
        .map(|k| PrivateKey::parse(k))
        .collect();
    for k in eoa_private_keys.iter_mut() {
        salt_recovery_core::crypto::wipe(k);
    }
    let keys = parsed.map_err(err)?;
    if keys.is_empty() {
        return Err("Add at least one proposer EOA private key".into());
    }
    let registry = resolve_registry(network, registry_address.as_deref())?;

    let rpc = if rpc_url.trim().is_empty() {
        network.default_rpc_url().to_string()
    } else {
        rpc_url
    };
    let mut dumps = Vec::with_capacity(keys.len());
    for key in &keys {
        dumps.push(
            fetch_encrypted_shards(&rpc, registry, network.chain_id(), key.address())
                .await
                .map_err(err)?,
        );
    }

    let summary = dumps
        .iter()
        .map(|d| FetchedDump {
            eoa: d.eoa.to_checksum(None),
            record_count: d.records.len(),
        })
        .collect();
    let mut s = lock(&session);
    s.private_keys = keys;
    s.dumps = dumps;
    s.shares.clear();
    Ok(summary)
}

#[tauri::command]
fn discover_accounts_cmd(session: SessionState) -> Result<Vec<DiscoveredAccount>, String> {
    let s = lock(&session);
    if s.dumps.is_empty() {
        return Err("No shard records fetched in this session".into());
    }
    discover_accounts(&s.dumps, &s.private_keys).map_err(err)
}

#[tauri::command]
fn decrypt_shards(
    session: SessionState,
    public_key: Option<String>,
) -> Result<Vec<KeyshareInfo>, String> {
    let mut s = lock(&session);
    if s.dumps.is_empty() {
        return Err("No shard records fetched in this session".into());
    }
    let shares =
        decrypt_shard_dumps(&s.dumps, &s.private_keys, public_key.as_deref()).map_err(err)?;
    let infos = shares
        .iter()
        .map(keyshare_info)
        .collect::<anyhow::Result<Vec<_>>>()
        .map_err(err)?;
    s.shares = shares;
    Ok(infos)
}

#[tauri::command]
fn reconstruct(session: SessionState, paths: Vec<String>) -> Result<Vec<ReconstructedKey>, String> {
    let s = lock(&session);
    if s.shares.is_empty() {
        return Err("No keyshares in this session".into());
    }
    reconstruct_private_keys(&s.shares, &paths).map_err(err)
}

#[tauri::command]
fn clear_session(session: SessionState) {
    *lock(&session) = Session::default();
}

#[tauri::command]
fn derive_robo_accounts(
    owner_key: Option<String>,
    secret: String,
    count: usize,
) -> Result<Vec<salt_recovery_core::robo::RoboAccount>, String> {
    let mut owner_raw = owner_key;
    let owner = match owner_raw.as_mut() {
        Some(raw) if !raw.trim().is_empty() => {
            let key = PrivateKey::parse(raw).map_err(err);
            salt_recovery_core::crypto::wipe(raw);
            Some(key?)
        }
        _ => None,
    };
    salt_recovery_core::robo::recover_robo_accounts(owner.as_ref(), &secret, count).map_err(err)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run_gui() {
    tauri::Builder::default()
        .manage(Mutex::new(Session::default()))
        .invoke_handler(tauri::generate_handler![
            load_rpc_endpoints,
            save_rpc_endpoints,
            validate_rpc_endpoint,
            fetch_shards,
            discover_accounts_cmd,
            decrypt_shards,
            reconstruct,
            clear_session,
            derive_robo_accounts,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Salt Recovery Tool");
}

/// Process entry: headless CLI when argv has a subcommand, otherwise the GUI.
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    if cli::wants_cli(&args) {
        attach_console();
        if let Err(err) = cli::run_from_env() {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
        return;
    }
    run_gui();
}

/// On Windows the release binary is a WINDOW subsystem app; attach the parent
/// console (or allocate one) so `fetch|decrypt|reconstruct` can print.
fn attach_console() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{
            AllocConsole, AttachConsole, ATTACH_PARENT_PROCESS,
        };
        unsafe {
            if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
                AllocConsole();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_network_does_not_discard_other_saved_endpoints() {
        let endpoints = parse_rpc_endpoints(
            r#"[
                {"network":"MAINNET","url":"https://mainnet.example/rpc"},
                {"network":"STAGING","url":"https://staging.example/rpc"},
                {"network":"TESTNET","url":"https://testnet.example/rpc"}
            ]"#,
        );
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].network, Network::Mainnet);
        assert_eq!(endpoints[0].url, "https://mainnet.example/rpc");
        assert_eq!(endpoints[1].network, Network::Testnet);
        assert_eq!(endpoints[1].url, "https://testnet.example/rpc");
    }

    #[test]
    fn registry_override_defaults_and_invalid_addresses() {
        let custom = "0x1111111111111111111111111111111111111111";
        for network in Network::ALL {
            assert_eq!(resolve_registry(network, None).unwrap(), network.registry());
            assert_eq!(
                resolve_registry(network, Some(custom)).unwrap(),
                custom.parse::<Address>().unwrap()
            );
            for invalid in [
                "",
                "0x123",
                "not an address",
                "0x0000000000000000000000000000000000000000",
            ] {
                assert!(resolve_registry(network, Some(invalid)).is_err());
            }
        }
    }

    #[test]
    fn legacy_rpc_settings_use_the_default_registry() {
        let endpoints =
            parse_rpc_endpoints(r#"[{"network":"TESTNET","url":"https://testnet.example/rpc"}]"#);
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].registry_address, None);
        assert!(!serde_json::to_string(&endpoints)
            .unwrap()
            .contains("registryAddress"));
    }

    #[test]
    fn saving_and_resetting_a_registry_preserves_the_other_network() {
        let saved = parse_rpc_endpoints(
            r#"[
            {"network":"MAINNET","url":"https://mainnet.example/rpc","registryAddress":"0x1111111111111111111111111111111111111111"},
            {"network":"TESTNET","url":"https://testnet.example/rpc"}
        ]"#,
        );
        let update = parse_rpc_endpoints(
            r#"[
            {"network":"TESTNET","url":"https://custom.example/rpc","registryAddress":"0x2222222222222222222222222222222222222222"}
        ]"#,
        );
        let merged = merge_rpc_endpoints(saved, update);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].url, "https://mainnet.example/rpc");
        assert_eq!(
            merged[0].registry_address.unwrap(),
            "0x1111111111111111111111111111111111111111"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            merged[1].registry_address.unwrap(),
            "0x2222222222222222222222222222222222222222"
                .parse::<Address>()
                .unwrap()
        );
        let reset =
            parse_rpc_endpoints(r#"[{"network":"TESTNET","url":"https://custom.example/rpc"}]"#);
        let reset = merge_rpc_endpoints(merged, reset);
        let reloaded = parse_rpc_endpoints(&serde_json::to_string(&reset).unwrap());
        assert_eq!(reloaded.len(), 2);
        assert!(reloaded[0].registry_address.is_some());
        assert_eq!(reloaded[1].registry_address, None);
        assert_eq!(reloaded[1].url, "https://custom.example/rpc");
    }
}
