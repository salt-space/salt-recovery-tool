//! Headless CLI mode for the same `salt-recovery-tool` binary as the GUI.
//!
//! Invoked when argv starts with `fetch`, `decrypt`, `reconstruct`, or `robo`
//! (before any Tauri/WebView init).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use salt_recovery_core::{
    crypto::{hex0x, PrivateKey},
    decrypt::{decrypt_shard_dump, discover_accounts},
    keyshare::{assert_same_account, load_keyshare_file, serialize_keyshare_file},
    networks::Network,
    reconstruct::{
        decode_keyshare_bytes, inspect_keyshare, keyshare_bytes, load_share, reconstruct,
    },
    registry::fetch_encrypted_shards,
    robo::{is_encrypted_secret, recover_robo_accounts, MAX_ROBO_ACCOUNTS, ROBO_ACCOUNTS},
    types::EncryptedShardDump,
    Address,
};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "salt-recovery-tool",
    version,
    about = "Salt Recovery Tool — GUI by default; fetch | decrypt | reconstruct | robo for headless use"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Fetch every encrypted shard record the registry holds for a proposer or Robo Guardian EOA.
    Fetch(FetchArgs),
    /// Decrypt a fetched dump with the proposer EOA or Robo Guardian private key.
    Decrypt(DecryptArgs),
    /// Combine decrypted keyshares into the root key and soft-derived children.
    Reconstruct(ReconstructArgs),
    /// Derive Robo Guardian EOA keys from an encrypted or plaintext Robo Guardian secret.
    Robo(RoboArgs),
}

#[derive(Args, Debug)]
struct FetchArgs {
    /// Network to fetch from: MAINNET or TESTNET.
    #[arg(long, default_value = "TESTNET")]
    network: Network,
    #[arg(long)]
    rpc: Option<String>,
    /// Override the shard registry contract address. Omit to use the network default.
    #[arg(long)]
    registry: Option<Address>,
    #[arg(long)]
    eoa: Address,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct DecryptArgs {
    #[arg(long = "in")]
    input: PathBuf,
    #[arg(long, env = "SRT_PRIVATE_KEY", hide_env_values = true)]
    private_key: String,
    #[arg(long)]
    public_key: Option<String>,
    #[arg(long, conflicts_with = "list")]
    out: Option<PathBuf>,
    #[arg(long)]
    list: bool,
}

#[derive(Args, Debug)]
struct ReconstructArgs {
    /// Keyshare file (JSON or raw base64). `PARTY_ID:FILE` overrides party id.
    #[arg(long = "share", required = true)]
    shares: Vec<String>,
    /// Soft path or range (`m`, `m/0`, `m/0..49`, `m/0..m/49`). Repeatable. Max 50 paths total.
    #[arg(long = "path")]
    paths: Vec<String>,
    #[arg(long, conflicts_with = "paths")]
    inspect: bool,
}

#[derive(Args, Debug)]
struct RoboArgs {
    /// Proposer EOA private key (required when --secret is encrypted).
    #[arg(long, env = "SRT_OWNER_KEY", hide_env_values = true)]
    owner_key: Option<String>,
    /// Encrypted hex, BIP39 mnemonic, or raw seed hex.
    #[arg(long)]
    secret: String,
    /// Robo Guardian accounts to derive (1..=10). The default 3 covers every Salt
    /// signer configuration (2-of-3 uses 1 Robo Guardian, 3-of-5 uses 2, 4-of-7 uses 3).
    #[arg(long, default_value_t = ROBO_ACCOUNTS)]
    count: usize,
}

/// True when argv asks for headless mode (skip the GUI).
pub fn wants_cli(args: &[String]) -> bool {
    let cleaned = strip_cargo_tauri_noise(args);
    let Some(first) = cleaned.get(1).map(String::as_str) else {
        return false;
    };
    matches!(
        first,
        "fetch"
            | "decrypt"
            | "reconstruct"
            | "robo"
            | "help"
            | "-h"
            | "--help"
            | "-V"
            | "--version"
    )
}

/// `tauri dev` / `cargo run` sometimes leave their own flags on the app argv
/// (e.g. `fetch --no-default-features --color always --`). Drop those so clap
/// only sees our subcommand flags.
fn strip_cargo_tauri_noise(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            continue;
        }
        if a == "--no-default-features"
            || a == "--all-features"
            || a == "--frozen"
            || a == "--locked"
        {
            i += 1;
            continue;
        }
        if a == "--color" {
            i += 1;
            if i < args.len() && matches!(args[i].as_str(), "always" | "never" | "auto") {
                i += 1;
            }
            continue;
        }
        if let Some(rest) = a.strip_prefix("--color=") {
            if matches!(rest, "always" | "never" | "auto") {
                i += 1;
                continue;
            }
        }
        out.push(args[i].clone());
        i += 1;
    }
    out
}

/// Run headless CLI from process args. Prints to stdout/stderr.
pub fn run_from_env() -> Result<()> {
    let args = strip_cargo_tauri_noise(&std::env::args().collect::<Vec<_>>());
    let cli = Cli::try_parse_from(args).unwrap_or_else(|e| e.exit());
    run(cli)
}

fn run(cli: Cli) -> Result<()> {
    let out = run_captured(cli)?;
    print!("{out}");
    Ok(())
}

fn run_captured(cli: Cli) -> Result<String> {
    match cli.command {
        Command::Fetch(args) => fetch(args),
        Command::Decrypt(args) => decrypt(args),
        Command::Reconstruct(args) => reconstruct_cmd(args),
        Command::Robo(args) => robo_cmd(args),
    }
}

fn fetch(args: FetchArgs) -> Result<String> {
    let rpc = args
        .rpc
        .unwrap_or_else(|| args.network.default_rpc_url().to_string());
    let registry = args.registry.unwrap_or_else(|| args.network.registry());
    if registry == Address::ZERO {
        return Err(anyhow!("Registry address cannot be the zero address"));
    }
    let dump = tokio::runtime::Runtime::new()?.block_on(fetch_encrypted_shards(
        &rpc,
        registry,
        args.network.chain_id(),
        args.eoa,
    ))?;
    std::fs::write(&args.out, serde_json::to_string_pretty(&dump)? + "\n")
        .with_context(|| format!("writing {}", args.out.display()))?;
    Ok(format!(
        "wrote {} encrypted shard record(s) for {} to {}\n",
        dump.records.len(),
        dump.eoa.to_checksum(None),
        args.out.display()
    ))
}

fn decrypt(mut args: DecryptArgs) -> Result<String> {
    let key = PrivateKey::parse(&args.private_key);
    salt_recovery_core::crypto::wipe(&mut args.private_key);
    let key = key?;

    let dump: EncryptedShardDump = serde_json::from_str(
        &std::fs::read_to_string(&args.input)
            .with_context(|| format!("reading {}", args.input.display()))?,
    )
    .with_context(|| format!("{} is not a shard dump", args.input.display()))?;

    if args.list {
        let accounts = discover_accounts(std::slice::from_ref(&dump), std::slice::from_ref(&key))?;
        let mut out = String::new();
        if accounts.is_empty() {
            out.push_str(&format!(
                "no Salt account found for {}\n",
                dump.eoa.to_checksum(None)
            ));
        }
        for a in accounts {
            out.push_str(&format!(
                "{}  public_key={}  records={}\n",
                a.evm_address.to_checksum(None),
                a.public_key,
                a.record_count
            ));
        }
        return Ok(out);
    }

    let out_path = args
        .out
        .ok_or_else(|| anyhow!("--out is required (or pass --list)"))?;
    let share = decrypt_shard_dump(&dump, &key, args.public_key.as_deref())?;
    write_private(&out_path, &(serialize_keyshare_file(&share) + "\n"))?;
    Ok(format!(
        "wrote keyshare for {} ({}) to {}\n",
        share.evm_address.to_checksum(None),
        share.public_key,
        out_path.display()
    ))
}

fn reconstruct_cmd(args: ReconstructArgs) -> Result<String> {
    if args.inspect {
        let mut out = String::new();
        for spec in &args.shares {
            let (_, file) = split_spec(spec);
            let content = Zeroizing::new(
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?,
            );
            let bytes =
                decode_keyshare_bytes(&content).with_context(|| file.display().to_string())?;
            let info = inspect_keyshare(&bytes).with_context(|| file.display().to_string())?;
            out.push_str(&format!("file={}\n", file.display()));
            out.push_str(&format!("party_id={}\n", info.party_id));
            out.push_str(&format!(
                "quorum={}-of-{}\n",
                info.threshold, info.total_parties
            ));
            out.push_str(&format!("root_public_key={}\n", hex0x(&info.public_key)));
        }
        return Ok(out);
    }

    let mut loaded = Vec::with_capacity(args.shares.len());
    let mut metas = Vec::with_capacity(args.shares.len());
    for spec in &args.shares {
        let (party_id, file) = split_spec(spec);
        let (share, _) = load_keyshare_file(&file)?;
        let bytes = keyshare_bytes(&share)?;
        loaded.push(load_share(&bytes, party_id).with_context(|| file.display().to_string())?);
        metas.push(share);
    }
    assert_same_account(&metas)?;

    let mut out = String::new();
    for key in reconstruct(&loaded, &args.paths)? {
        out.push_str(&format!("derivation_path={}\n", key.path));
        out.push_str(&format!("private_key={}\n", key.private_key));
        out.push_str(&format!("public_key={}\n", key.public_key));
        out.push_str(&format!(
            "evm_address={}\n",
            key.evm_address.to_checksum(None)
        ));
    }
    Ok(out)
}

fn robo_cmd(mut args: RoboArgs) -> Result<String> {
    let count = args.count;
    if count == 0 || count > MAX_ROBO_ACCOUNTS {
        return Err(anyhow!(
            "--count must be 1..={MAX_ROBO_ACCOUNTS} (got {count})"
        ));
    }

    if is_encrypted_secret(&args.secret)
        && args
            .owner_key
            .as_ref()
            .map_or(true, |s| s.trim().is_empty())
    {
        return Err(anyhow!(
            "--owner-key is required when --secret is an encrypted Robo Guardian secret"
        ));
    }

    let owner = match args.owner_key.as_mut() {
        Some(raw) if !raw.trim().is_empty() => {
            let key = PrivateKey::parse(raw);
            salt_recovery_core::crypto::wipe(raw);
            Some(key?)
        }
        _ => None,
    };

    let accounts = recover_robo_accounts(owner.as_ref(), &args.secret, count)?;
    let mut out = String::new();
    out.push_str("MetaMask Compatible Ethereum Addresses (Robo Guardians):\n");
    out.push_str(&format!("{}\n", "=".repeat(50)));
    for a in accounts {
        out.push_str(&format!("Account {} -> Path: {}\n", a.index, a.path));
        out.push_str(&format!("Address:   {}\n", a.address));
        out.push_str(&format!("PK:   {}\n\n", a.private_key));
    }
    Ok(out)
}

fn split_spec(spec: &str) -> (Option<u8>, PathBuf) {
    if let Some((id, file)) = spec.split_once(':') {
        if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(id) = id.parse::<u8>() {
                return (Some(id), PathBuf::from(file));
            }
        }
    }
    (None, PathBuf::from(spec))
}

fn write_private(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {} (exists?)", path.display()))?;
    file.write_all(content.as_bytes())?;
    Ok(())
}
