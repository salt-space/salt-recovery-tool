# Salt Recovery Tool: developer summary and spec

Version 0.2.3 · Updated 2026-11-13 · repository `salt-recovery-tool`

## 1. What this is

Salt Recovery Tool is a desktop app, with a built-in command-line mode, for disaster recovery of Salt MPC accounts. Given the private keys of an account's signers (proposer and Robo Guardian EOAs), it:

1. **Fetches** the encrypted shard records those EOAs own from the on-chain Salt shard registry (Arbitrum).
2. **Decrypts** them locally into DKLS23 keyshares.
3. **Reconstructs** the account's root private key and any soft-derived child keys from a threshold of those keyshares.

It needs no Salt API, no VOPRF server and no Salt SDK. Only the fetch step touches the network, and only to read public chain data through an Arbitrum RPC. Decrypt and reconstruct run offline.

Reconstructing turns an MPC account into a plain single-key wallet. The tool is meant for one-time disaster recovery: move funds and rotate the account afterwards. The UI says this on the result screen.

**In one sentence for developers:** one Rust binary (Tauri 2) containing a recovery core, a GUI wizard (React in the system webview) and a headless CLI, with encrypted dumps and decrypted keyshares held in the Rust session; input keys, derived Robo Guardian keys and recovered private keys also pass through the UI.

## 2. Glossary

| Term | Meaning |
|---|---|
| Salt account | An MPC wallet. Its private signing key is shared across signers with DKLS23; the root public key identifies the account. |
| Signer EOA | A signer's ordinary Ethereum key. Salt encrypts each signer's keyshare to it. |
| Proposer EOA | An Ethereum account allowed to propose transactions, held by a person or bot. Robo Guardian seed recovery requires the proposer EOA key that the Robo Guardian secret was encrypted to. |
| Robo Guardian signer | A signer whose EOA is derived from a Robo Guardian seed at MetaMask path `m/44'/60'/0'/0/i`. |
| Robo Guardian secret | The Robo Guardian seed, shown in Salt encrypted to the proposer EOA's public key (ECIES), or as a plaintext mnemonic / seed. |
| Shard registry | `SaltShardRegistryV3` contract. Stores per-EOA shard records; ciphertext lives in event logs. |
| Shard record | One encrypted keyshare for one EOA: `saltAccount`, `evaluation`, `txHashes`, plus the ciphertext reassembled from logs. |
| Keyshare | One signer's DKLS23 share. Its header records `party_id`, `threshold` and `total_parties`. |
| Quorum / signer configuration | `t-of-n`: recovery needs at least `t` distinct shares out of `n` signer shares. Salt uses 2-of-3, 3-of-5 and 4-of-7. |
| Soft derivation | Non-hardened BIP32 child paths such as `m/0/1`. The only kind MPC shares can produce. |

## 3. Architecture

```text
                         salt-recovery-tool (one binary)
 ┌──────────────────────────────────────────────────────────────────────┐
 │  main.rs ── argv has fetch|decrypt|reconstruct|robo? ──yes──► cli.rs │
 │                 │ no                                        (stdout) │
 │                 ▼                                                    │
 │            lib.rs: Tauri app                                         │
 │            ┌───────────────────────────┐   invoke()   ┌────────────┐ │
 │            │ #[tauri::command]s        │◄────────────►│  Webview   │ │
 │            │ Session (Mutex):          │   inputs &   │  React UI  │ │
 │            │   private_keys, dumps,    │   results    │ src/main-  │ │
 │            │   decrypted shares        │              │ view       │ │
 │            └─────────────┬─────────────┘              └────────────┘ │
 │                          ▼                                           │
 │            crates/core (salt-recovery-core)                          │
 │            registry · crypto · decrypt · keyshare · paths ·          │
 │            reconstruct · robo · networks · types                     │
 └──────────────────────────┬───────────────────────────────────────────┘
                            │ JSON-RPC (eth_chainId, eth_call,
                            ▼          eth_getTransactionReceipt)
                   Arbitrum RPC ──► SaltShardRegistryV3
```

### 3.1 Components

| Path | Role |
|---|---|
| `crates/core` | `salt-recovery-core`, a pure Rust library with all recovery logic and the unit tests. No UI, no Tauri. |
| `src-tauri/src/main.rs` | Entry point. Calls `lib::run()`. |
| `src-tauri/src/lib.rs` | `run()` chooses CLI or GUI. GUI: Tauri builder, in-memory `Session`, the Tauri commands. |
| `src-tauri/src/cli.rs` | Headless mode (clap): `fetch`, `decrypt`, `reconstruct`, `robo`. Runs before any Tauri/webview init. |
| `src-tauri/build.rs` | Tauri build script. Also warns when a release build is still in Tauri dev mode. |
| `src/mainview` | React 19 + Vite UI. `App.tsx` (wizard and action feedback), `rpc.ts` (typed `invoke` wrappers), `types.ts` (IPC shapes), `SecretInput.tsx`, `CopyPrivateKeyButton.tsx`, styles and Chakra theme. |
| `scripts/dev.mjs` | `npm run dev` entry: GUI via `tauri dev`, or a CLI subcommand via `cargo run` without Vite. |
| `.github/workflows/build.yml` | Three-OS build matrix producing binaries and installers (also called by the Release workflow). |
| `.github/workflows/release.yml` | Manual cut: tag `vX.Y.Z`, notes from `CHANGELOG.md`, attach the three-OS artifacts. |

### 3.2 One binary, two modes

`lib::run()` inspects argv. If the first argument is `fetch`, `decrypt`, `reconstruct`, `robo`, `help`, `-h`/`--help` or `-V`/`--version`, it runs the clap CLI and exits. Otherwise it starts the Tauri GUI. On Windows the release binary uses the GUI subsystem, so the CLI path attaches to the parent console (or allocates one) before printing.

GUI and CLI call the same `salt-recovery-core` functions, so they cannot drift apart. Only the CLI reads and writes dump and keyshare files; the GUI keeps everything in memory.

## 4. Recovery pipeline (Recover Option 1: proposer EOA private keys)

Option 1 on Recover starts with proposer EOA private keys entered directly. Robo Guardian keys are not required if the supplied proposer keys provide enough distinct signer shares. Fetch success alone does not prove that this threshold is met. Option 2 (section 5) derives the Robo Guardian keys from a Robo Guardian seed, then runs the same pipeline.

```text
 signer keys ───┐
                ▼
 [Fetch]   registry.getShardCount / getShards (paged)
           + ShardStored logs from each chunk tx      ──► EncryptedShardDump per EOA
                ▼
 [Decrypt] evaluation ──ECIES(EOA key)──► OPRF output
           OPRF ──HKDF-SHA256(salt=lowercase EOA, info="salt-keyshare-v1")──► AES-256-GCM key
           saltAccount ──AES-GCM──► MPC public key   (account discovery)
           ciphertext  ──AES-GCM──► gzip ──► DKLS23 keyshare
                ▼
 [Reconstruct] threshold keyshares ──combine_shares──► root scalar
               root + BIP32 soft offset(path) ──► child keys (verified)
```

### 4.1 Fetch (`registry.rs`, `networks.rs`)

- Checks `eth_chainId` against the selected network before reading anything.
- `getShardCount(eoa)`, then `getShards(eoa, offset, limit)` in pages of 500, walking from the newest page back.
- Each record's keyshare ciphertext is split across transactions. For every hash in `txHashes`, the tool reads the receipt, takes the `ShardStored` log emitted by the registry, and concatenates the `shard` chunks.
- Output is one `EncryptedShardDump` per EOA: `{ chainId, registry, eoa, records: [{ index, saltAccount, evaluation, txHashes, ciphertext }] }`, sorted by index (0 = oldest).
- The GUI receives only `{ eoa, recordCount }` for each supplied key, including zero-record results. It adds the signer label captured when the fetch started. A failed fetch reports an error; the UI does not turn failed requests into successful zero-record rows.
- It talks raw JSON-RPC with `reqwest` and `alloy-sol-types` for ABI encoding. Only three RPC methods are needed, so there is no provider stack.

| Network | Chain | Chain id | Registry | Default RPC |
|---|---|---|---|---|
| MAINNET | Arbitrum One | 42161 | `0x2bc34033e00cfcdcf58fcc8c389dc76ce93e25f3` | `https://arb1.arbitrum.io/rpc` |
| TESTNET | Arbitrum Sepolia | 421614 | `0x1aaf2396e754712c22d17e5968f38a9ede431b71` | `https://sepolia-rollup.arbitrum.io/rpc` |

Only MAINNET and TESTNET are selectable in the GUI and accepted by the CLI. Saved endpoint settings are decoded per entry, so a retired STAGING entry is ignored without discarding valid settings for the supported networks.

### 4.2 Decrypt (`crypto.rs`, `decrypt.rs`)

This mirrors how Salt's backend sealed the records:

1. `evaluation` is ECIES-decrypted with the EOA private key, giving the OPRF output. The ECIES parameters match `eciesjs` defaults (secp256k1, uncompressed ephemeral key, HKDF-SHA256, AES-256-GCM with a 16-byte nonce). A test vector produced by eciesjs 0.5 guards this.
2. HKDF-SHA256 of the OPRF output, with salt = the lowercase `0x` EOA address and info = `salt-keyshare-v1`, gives a 32-byte AES key.
3. `saltAccount` (12-byte IV + AES-GCM) decrypts to the account's compressed MPC public key. This is enough to **discover** which Salt accounts an EOA holds shares for, without opening the large ciphertext.
4. `ciphertext` decrypts and gunzips into the DKLS23 keyshare bytes.
5. `inspect_account_keyshare` parses the DKLS23 share and checks that its embedded root public key matches the account public key decrypted from `saltAccount`. Invalid shares and account mismatches are integrity errors.

Rules:

- Records are tried newest first. With a chosen account public key, the newest record for that account wins.
- Records the key cannot open are skipped (a dump can contain other signers' records).
- `discover_accounts` groups records by the public key decrypted from `saltAccount` across all EOAs, most widely held first. The UI shows these on the Decrypt step. Discovery has not yet verified the embedded DKLS share or read its quorum.
- `decrypt_shard_dumps` with a chosen account skips EOAs that hold no share of it (e.g. unused Robo Guardian signers) and requires at least one share to open. An invalid DKLS share or account mismatch fails immediately instead of falling back to an older record. Without a chosen account (CLI single-dump decrypt), every dump must decrypt, and multiple accounts in one dump require `--public-key`.

### 4.3 Reconstruct (`reconstruct.rs`, `paths.rs`)

- Shares are parsed with `sl-dkls23` pinned to rev `20f748e0` (the same revision as the original reconstruct tool).
- Each decrypted share's declared `publicKey` must match the root public key embedded in its DKLS bytes before it is accepted for reconstruction. The same check runs when reading JSON keyshare files and when producing UI metadata. Raw keyshare files derive their account public key from the share itself.
- Checks: at least one share, no duplicate party ids, same root public key and root chain code, party ids inside the participant set.
- `combine_shares` takes each share's `x_i` and rank plus `s_i` and returns the root private key. It fails with a clear error when the shares are insufficient or mismatched.
- For a soft path, `derive_with_offset` returns the BIP32 tweak and the expected child public key. The child key is `root + offset`, and it is checked against `G · child` before being returned.
- Paths: one per line or `--path`. Ranges expand inclusively: `m/2..10`, or with a full end path, `m/0/1..m/0/10`. Hardened paths are rejected. At most 50 paths per run. Empty input means `m` (the root).
- Output per path: derivation path, private key, compressed public key and checksummed EVM address.

### 4.4 Signer configuration from the shares

Every DKLS23 keyshare header stores `party_id`, `threshold` and `total_parties` (sl-dkls23 `keygen/keyshare/details.rs`). `inspect_keyshare` reads them. `keyshare_info` validates the account binding and attaches them to the metadata the UI receives for decrypted shares, and `reconstruct --inspect` prints them for JSON exports and raw base64 files. The UI shows a `2-of-3 signer configuration` badge and warns when fewer shares than the threshold were decrypted. The quorum comes from the share, not from the number of supplied keys or registry records.

For a 2-of-3 wallet recovered with two shares, the Reconstruct step says **"2 shares available. Recovery requires 2 of this account's 3 signer shares."** beside the signer-configuration badge. Discovery instead reports, for example, **"2 encrypted records found for 2 supplied signer keys"**. Neither supplied-key counts nor empty Robo Guardian fetches establish the signer configuration.

If an account changed quorum, newer shares carry the new numbers. Decrypt picks the newest record per EOA, so the badge normally reflects the current quorum.

## 5. Robo Guardian recovery (Recover Option 2: Robo Guardian seed, `robo.rs`)

Recovery pairs a proposer EOA with `threshold − 1` Robo Guardian signers: 2-of-3 uses 1 Robo Guardian, 3-of-5 uses 2 and 4-of-7 uses 3. Robo Guardian EOAs are derived from one Robo Guardian seed.

Flow:

1. The user enters the proposer EOA private key and the Robo Guardian secret.
2. If the secret looks encrypted (`0x…` or long hex), it is ECIES-decrypted with the proposer EOA key. The plaintext is either a UTF-8 BIP39 mnemonic or a 64-byte seed. A plaintext mnemonic or seed hex is used as is.
3. The first **3** accounts are derived at `m/44'/60'/0'/0/{0,1,2}` (BIP39 with an empty passphrase, via `coins-bip39` / `coins-bip32`). This matches MetaMask and the original Python helper.
4. **Use these keys** fills Option 1 with `Proposer EOA`, `Robo Guardian 1`, `Robo Guardian 2`, `Robo Guardian 3`.
5. Fetch and decrypt run as usual. Robo Guardians the wallet never used hold no records and are skipped. The Decrypt step lists holders by role ("Signers: Proposer EOA, Robo Guardian 1") and reports encrypted records found for the supplied signer keys. These counts are not the wallet quorum. After decryption, the Reconstruct step shows the signer configuration read from the shares, with separate counts for shares available and shares required for recovery.

The user never has to know the quorum. An earlier version had a manual quorum picker and derived only `threshold − 1` Robo Guardians without the proposer EOA. Feedback called it too complex, so it was replaced by always deriving 3 and detecting the quorum (section 4.4).

## 6. User interface

### 6.1 Numbered recovery steps

The wizard has five connected, numbered steps: **1 Recover → 2 Fetch → 3 Decrypt → 4 Reconstruct → 5 Result**. Reached steps and connectors are purple; future steps are grey and disabled. The current step has a ring and a bold label, plus `aria-current="step"`. Each button has an accessible name such as "Step 2 of 5: Fetch" and a visible keyboard focus indicator.

Only steps already reached are navigable. Back and step navigation preserve entered data. Completing a step with fresh data makes later steps unreachable until they are redone. The step strip scrolls horizontally in narrow windows. Network, RPC URL and the editable shard registry address sit in the network selector. Changing the network or registry after a fetch discards fetched records, shares and recovered keys, then returns to Recover.

### 6.2 Input methods and terminology

Recover options:

| Option | Input | Continues to |
|---|---|---|
| 1. Proposer EOA private keys | Proposer keys already held, with a live address preview; enough distinct shares are required | Fetch → Decrypt → Reconstruct |
| 2. Robo Guardian seed | Proposer EOA key + Robo Guardian secret, derive 3 Robo Guardians | Fills Option 1, then Fetch |

User-facing labels, help and errors use **proposer EOA** for a proposer signer (human or bot). Derived signer rows retain distinct **Robo Guardian 1**, **Robo Guardian 2** and **Robo Guardian 3** labels. Manually entered keys are numbered as **Proposer EOA 1**, **Proposer EOA 2**, etc.; the app cannot infer which manually entered key belongs to a Robo Guardian. **Use these keys** transfers the proposer and derived Robo Guardian keys into Option 1.

### 6.3 Per-signer fetch results

The Fetch step shows a table with the signer label and full EOA address, fetch status, and record count. Every successfully fetched signer appears, including those with no records. For example:

| Signer | Fetch status | Records found |
|---|---|---|
| Proposer EOA | Fetched | 1 record found |
| Robo Guardian 1 | Fetched | 1 record found |
| Robo Guardian 2 | Fetched | No records found |
| Robo Guardian 3 | Fetched | No records found |

Zero-record Robo Guardian rows say **"This Robo Guardian may not be used by your wallet."** The accompanying explanation gives the mapping **2-of-3: 1 Robo Guardian; 3-of-5: 2 Robo Guardians; 4-of-7: 3 Robo Guardians**. A zero count can also reflect a key or network mismatch, so the table does not label a Robo Guardian definitely unused or infer a quorum. Labels are captured with each fetch so editing inputs later does not relabel old fetch results. Addresses wrap and the table can scroll horizontally in narrow windows.

### 6.4 Account and share counts

On Decrypt, each discovered account lists its EVM address, public key, encrypted record count, matching supplied-key count, and signer labels or addresses. Counts use explicit wording such as **"2 encrypted records found for 2 supplied signer keys"**, followed by **"Signers: Proposer EOA, Robo Guardian 1"**. They are not displayed as a misleading "2 of 2" fraction. Multiple records can belong to one signer, and singular/plural wording follows the counts.

The signer configuration is confirmed after decryption. Reconstruct and Result show the confirmed `t-of-n signer configuration` badge. Reconstruct separately states shares available and the threshold required for recovery, lists the supplying signers, and shows a missing-share error beside its action buttons when the threshold is not met. The Rust reconstruction code remains responsible for validating whether the shares can be combined.

### 6.5 Feedback beside action buttons

`StepActions` in `App.tsx` groups each step's buttons with its progress, success and error feedback. Messages appear directly above the relevant buttons, including Robo Guardian derivation/fill status, fetch and RPC failures, account scanning, no-account results, decryption, and reconstruction. The old global messages above the step card are removed. Errors take precedence over status text, preventing a failed scan from also showing a misleading empty-result message.

Normal Back/step navigation and manual input-method changes clear old transient messages. The error region uses `role="alert"`; status uses `role="status"`; both use `aria-atomic="true"` for screen-reader announcements. Static warnings about exposed keys stay with the relevant key material.

### 6.6 Copying recovered private keys

Each recovered-key card uses `CopyPrivateKeyButton.tsx`. Clicking **Copy private key** calls `navigator.clipboard.writeText` with that card's key. While the promise is pending, the button is disabled and a nearby status says **"Copying…"**. Only a successful write displays **"Copied to clipboard."**, beside that button for three seconds.

Rejected writes and unavailable clipboard access show **"Could not copy. Try again or select and copy the key manually."** beside the same button. Retrying clears the previous feedback. Each card keeps its own state, and its reset timer is cancelled on state changes or unmount. Copy status and errors use live regions for accessibility. The three-second reset clears the acknowledgement, not the system clipboard.

### 6.7 Session and runtime boundaries

Every GUI flow runs in memory. The GUI has no keyshare import or export: saving decrypted keyshares (`decrypt --out`) and reconstructing from keyshare files (`reconstruct --share`) are CLI-only, for power users.

Opening the Vite dev server in a normal browser renders the UI, but recovery commands report that the Rust backend is not available. There is no standalone web recovery version: fetch, decryption and reconstruction require the Rust backend.

### 6.8 Choosing accounts with derivation paths

The Reconstruct step defaults to `m` (root only), with a guide titled **"Which accounts do you want to recover?"**. It explains that paths identify the original Salt account or child accounts created from it. An examples table maps `m` to the root, `m/0` to child index 0, and `m/1` to child index 1. Users should add a child's recorded path and check its recovered address against the intended account.

The textarea accepts one path per line and is associated with the guide and hint using `aria-describedby`. Expandable help explains that `m/0..4` covers five child accounts, including both ends, and that `m/0/1..m/0/10` covers indices 1–10 under `m/0`. The root must be included separately when a range is used. The 50-path limit and rejection of hardened paths remain enforced by the core.

### 6.9 Registry overrides and network settings

Each network displays its full **Shard registry address** in an editable, wrapping field beside the RPC URL. The UI identifies default versus custom addresses and validates a nonzero `0x` address with 40 hexadecimal characters. **Reset to default** restores the selected network's built-in registry and removes its saved override while retaining the RPC URL and the other network's settings.

RPC URLs and registry drafts are kept separately for MAINNET and TESTNET. Settings are loaded once at startup; network switching does not start competing asynchronous loads. Fetch saves the current network settings and sends `registryAddress` explicitly to `fetch_shards`. Reset also saves immediately. Failed saves leave the current values usable for this session and show feedback beside the settings controls.

The existing `rpc-endpoints.json` file now stores `{ network, url, registryAddress? }` entries. Missing `registryAddress` means the network default, so older RPC-only files remain valid. Saving merges the selected network into existing settings instead of replacing the whole list. No registry override is stored when the selected address equals the default.

Rust validates the optional registry address, falls back to `Network::registry()` only when it is omitted, and passes the selected address to `fetch_encrypted_shards`. CLI `fetch --registry ADDR` already supports the same override; omitting it uses the network default, independently of GUI preferences. Both reject the zero address, retain the chain-id check and require a compatible shard-registry contract. Encrypted dumps retain the actual registry used.

Changing the network or registry invalidates downstream recovery state and clears the Rust session. Connection controls and step navigation are disabled while fetching, discovering accounts, decrypting, reconstructing or clearing that session, preventing an in-flight result from appearing under a different selected registry.

## 7. Security model

- **Keyshare material stays in Rust.** Encrypted dumps and decrypted keyshares stay in the Rust `Session`. Proposer EOA keys entered in the webview are sent on fetch; Robo Guardian secret derivation also sends its proposer key and secret to Rust. The UI retains entered keys for navigation and receives derived Robo Guardian keys and recovered private keys, along with public metadata. Copying a recovered key explicitly writes it to the system clipboard.
- **Account binding.** A share's embedded DKLS root public key must match the declared account during decryption, JSON import, metadata inspection and reconstruction. A mismatch is an explicit error, including when an older matching record exists. Discovery alone is not sufficient validation of the share.
- **Zeroization.** `PrivateKey` is `Zeroizing<[u8; 32]>`. `DecryptedKeyshare` and `ReconstructedKey` zeroize on drop. Key strings received over IPC or CLI are wiped after parsing.
- **No temp files.** The Electrobun version handed keyshares to a subprocess through a temp directory. Everything is now in-process.
- **Disk writes** only happen on explicit user action, and keyshare files only from the CLI. `decrypt --out` creates decrypted keyshares with mode 0600 and never overwrites (`create_new`). The GUI has no command that reads or writes keyshare files. `fetch --out` writes the encrypted dump as an ordinary file and overwrites it, since it holds nothing that opens without the EOA key. The app persists only per-network RPC URLs and optional registry overrides, under the app data directory; no private keys or recovery records are included.
- **Webview lockdown.** The CSP allows `connect-src ipc: http://ipc.localhost` only, so the webview cannot reach the network itself; all RPC goes through Rust. The capability set is `core:default`, and the app ships no file-dialog or filesystem plugin.
- **Chain id check** before every fetch, so a wrong RPC can't silently read another chain.
- **User-facing warnings** on sensitive screens (derived Robo Guardian keys, recovered keys).

## 8. CLI reference

```text
salt-recovery-tool fetch       --network MAINNET|TESTNET [--rpc URL] [--registry ADDR]
                               --eoa 0x… --out dump.json
salt-recovery-tool decrypt     --in dump.json --private-key 0x…|SRT_PRIVATE_KEY
                               [--public-key 0x02…] (--out share.json | --list)
salt-recovery-tool reconstruct --share a.json --share [PARTY_ID:]b.json --path m --path m/0..49
salt-recovery-tool reconstruct --inspect --share keyshare-0.txt     # party_id, quorum, root key
salt-recovery-tool robo        [--owner-key 0x…|SRT_OWNER_KEY] --secret "…" [--count 3]
```

The existing CLI flag `--owner-key` and environment variable `SRT_OWNER_KEY` accept the proposer EOA private key. Their names are retained for compatibility; user-facing descriptions use proposer EOA.

From a checkout, `npm run dev <subcommand> …` runs the CLI without starting Vite. npm swallows `--help`, so use `npm run dev fetch help` or `npm run dev -- fetch --help`.

## 9. Build, CI and release

| Command | What it does |
|---|---|
| `npm run dev` | `tauri dev`: Vite on :5173 plus the app window, hot reload. |
| `npm run dev <cmd> …` | CLI subcommand via `cargo run`, no Vite. |
| `npm run build` | `tauri build`: builds the web UI, enables production mode, compiles release and bundles installers for the host OS. |
| `npm run build:macos-universal` | Same, with `--target universal-apple-darwin` (Intel + Apple Silicon). |
| `npm test` / `npm run typecheck` | Rust unit tests / `tsc --noEmit`. |

- Release binaries embed the Vite output from `build/dist`. `tauri build` also enables `tauri/custom-protocol`, which switches Tauri to production mode. A plain `cargo build --release` stays in dev mode (the GUI would load `http://localhost:5173`), and `build.rs` prints a warning. For a bare binary without bundles: `npm run build:web`, then `cargo build --release -p salt-recovery-tool --features tauri/custom-protocol`.
- Release profile: LTO, one codegen unit, stripped.
- Minimum toolchain: Rust 1.90, declared as `rust-version` in `Cargo.toml` (the highest any locked dependency requires; build and tests are checked on it). Node 24 in CI; Vite 7 needs at least 20.19 or 22.12. Tauri 2 comes with the repo: the crate through Cargo, the `tauri` command through npm.
- The CLI needs neither Node.js nor a display. On Linux it still needs the WebKitGTK/GTK packages, because GUI and CLI are one binary and it links them at startup. `npm run dev` without a subcommand starts the GUI and fails without a display; `cargo build` and `npm run dev <subcommand>` work over SSH.
- CI (`build.yml`) runs on pushes to `main` and on demand, on Ubuntu 22.04, macOS and Windows: typecheck, tests, build, then uploads `salt-recovery-tool-linux-x64`, `-macos-universal` and `-win-x64` (bare binary plus deb/rpm/AppImage, dmg, msi/nsis). PRs and comments do not trigger these workflows. Jobs only accept the canonical public repository on `main`; the repository Actions policy must also be enforced to block PR-authored workflow changes. Actions are on Node 24-native versions (`checkout@v5`, `setup-node@v5` with Node 24, `upload-artifact@v6`).
- A GitHub Release is a separate manual workflow (`release.yml`, Actions → Release, `main` only). It checks that `package.json`, `Cargo.toml` and `src-tauri/tauri.conf.json` agree and that `CHANGELOG.md` has a `## X.Y.Z` section, calls `build.yml`, then creates `vX.Y.Z` with that changelog section plus a download table, attaching the three-OS artifacts, `THIRD_PARTY_LICENSES.zip` and `SHA256SUMS.txt`. Draft by default; fails if the tag or release already exists. Version is read from the repo, not typed in.
- macOS bundles are ad-hoc signed (`signingIdentity: "-"`). This avoids the "app is damaged" error on Apple Silicon, but first launch still needs right-click → Open. Windows and macOS builds are not notarized or code-signed with a real identity.
- Tauri cannot cross-compile desktop apps, so each OS builds on its own runner.

Public release setup, repository policy and download-channel decisions are documented in [public-release.md](public-release.md). GitHub Releases distributes installers and portable binaries; no package or web-hosted recovery build is published.

## 10. Testing and verification

36 Rust unit tests in `crates/core` and 4 in the desktop adapter:

| Module | Tests | Covers |
|---|---|---|
| `crypto` | 3 | Address derivation, public key formats, ECIES vector produced by eciesjs 0.5. |
| `decrypt` | 11 | Provenance, newest-first, foreign records, EOA ownership mismatch, multi-account discovery, per-key matching, missing account records, invalid DKLS bytes, account-binding rejection without fallback, matching-account reconstruction. |
| `keyshare` | 10 | JSON round trip, address recomputation, legacy exports, bad files, raw base64, same-account checks, embedded-root binding and validated metadata/quorum. |
| `networks` | 1 | Reject STAGING in CLI parsing and GUI deserialization; retain MAINNET and TESTNET. |
| Desktop network settings | 4 | Retired-network migration, legacy RPC-only settings, default/custom registry validation, and per-network save/reset preservation. |
| `paths` | 3 | Literals, short and long ranges, 50-path cap, hardened rejection. |
| `reconstruct` | 2 | Reject mislabeled in-memory shares; preserve root reconstruction and soft derivation for matching shares. |
| `robo` | 6 | Hardhat mnemonic vector (`0xf39f…2266`), distinct indices, plaintext without a proposer key, encrypted secrets requiring that key, ECIES round trip, wrong-key rejection, encryption heuristics. |

Manual acceptance checks used during the port:

- ECIES interop between the Rust `ecies` crate and eciesjs, in both directions and against a real on-chain record.
- Rust fetch output byte-identical to the previous TypeScript dump.
- `reconstruct` matching the original binary for every share set and path (known test shares: `m/0` → `0x18C9…3e2C`), and the GUI flows for directly entered signer keys and for the keyshare-file option (since removed from the GUI).

For the 0.2.2 UI changes, typechecking and the production web build passed. Browser smoke checks with synthetic command responses covered:

- Numbered-step progression, Back/step navigation, refetch invalidation, keyboard access and narrow layouts.
- Per-signer fetch labels and counts, zero/multiple records, fetch failures, manual-key and Robo Guardian seed input, and labels retained with old fetch results.
- Action feedback placement, empty-account results, retries, input-method changes and missing-share errors.
- Proposer EOA terminology and distinct Robo Guardian labels across the recovery flow.
- Discovery counts versus confirmed 2-of-3, 3-of-5 and 4-of-7 quorums, including singular counts and insufficient shares.
- Clipboard contents using synthetic keys, per-card confirmation, keyboard activation, the three-second reset, pending writes, rejected/unavailable clipboard access, retry and navigation cleanup.

For the 0.2.3 guidance and registry update, 40 Rust tests, typechecking and the production web build passed. Synthetic browser checks covered both input methods through reconstruction, MAINNET/TESTNET selection, Robo Guardian labels, root-only defaults, child paths, keyboard-operated expanded help, narrow layouts and copy confirmation. The added network/settings tests cover rejecting STAGING, preserving saved endpoints, legacy settings, registry validation and reset behavior. Browser checks also cover per-network overrides, reload persistence, resetting after a fetch and blocked connection edits during an in-flight fetch. CLI checks against a local simulated RPC verified default and custom registry targets on both chains, wrong-chain rejection and zero-address rejection.

These browser checks were run during implementation; they are not a checked-in automated GUI suite or live recovery tests. Desktop-platform clipboard integration still needs native-app release verification.

## 11. Design decisions

1. **Tauri + Rust instead of Electrobun + Bun.** The first version (Sept 6) used Electrobun, TypeScript tools and a separate Rust reconstruct binary. It shipped as an app folder of about 120 MB (launcher, Bun runtime, JS, Rust binary; over 600 MB with bundled Chromium) behind a self-extracting installer, needed native Windows to build for Windows, and passed keyshares to the Rust binary through temp files. Tauri gives a single native binary per OS (the Linux release binary was about 9 MB at migration time), plus AppImage/deb/rpm/dmg/msi bundles, a compiled backend and in-process secrets. The reconstruct code was already Rust, so porting fetch and decrypt was small. Tauri 2 is also a safer bet for a recovery tool that must still build years from now.
2. **All logic in `crates/core`.** GUI and CLI are thin callers, and tests run without Tauri.
3. **One binary for GUI and CLI.** An earlier split (`srt` CLI + app) was merged, so users download one file. An in-app CLI panel was tried and removed.
4. **Raw JSON-RPC, no provider stack.** Three RPC methods don't justify a full Ethereum client.
5. **No Salt SDK dependency.** Registry ABI, networks and crypto parameters are pinned in this repo. Offline export was removed from `salt-sdk`, and key export from `salt-signer-sdk`, so recovery lives in one auditable place.
6. **File formats kept compatible** with the TypeScript version (camelCase JSON), so earlier dumps and keyshare exports still load.
7. **Path ranges with a 50-path cap.** Covers bulk checks without accidental huge runs.
8. **Robo Guardian: derive 3, detect quorum from shares** (section 5), instead of asking the user or trial-decrypting.
9. **Universal macOS build and ad-hoc signing** for one DMG across Intel and Apple Silicon, without a paid Apple identity.

## 12. Known limitations and next steps

- No real code signing or notarization (SmartScreen / Gatekeeper prompts on first launch).
- `icon.png` is a placeholder.
- Hardened derivation paths can't be reconstructed from MPC shares (a property of soft derivation, not a bug).
- Option 1 decrypted shares carry party ids to the UI, but no screen shows them yet.
- Reconstruction has synthetic-share regression tests; broader real-share fixture coverage remains useful.
- No checked-in automated GUI suite; browser checks use synthetic data, and native-app release verification is still required.

## 13. Timeline

| Date | Milestone |
|---|---|
| 2026-09-06 | Initial Electrobun app with TypeScript fetch/decrypt tools and Rust reconstruct; CI via GitHub Actions. |
| 2026-09-12 | Rewrite to Tauri + Rust (`crates/core`, `src-tauri`), React UI kept. |
| 2026-09-13 | Single binary for GUI and CLI; derivation path ranges; Node 24 CI; ad-hoc macOS signing; universal macOS build. |
| 2026-09-19 | Robo Guardian seed derive (core, CLI, Option 3); rustls security update. |
| 2026-09-27 | Dev-mode release warning and build docs; Robo Guardian simplified to derive 3 with signer configuration read from shares. |
| 2026-10-09 | GUI made in-memory only: removed the existing-keyshares option and the decrypted keyshare download (and the dialog plugin). Keyshare files are CLI-only; Robo Guardian seed is now Option 2. |
| 2026-10-11 | Manual Release workflow: tag `vX.Y.Z` from the repo version, notes from `CHANGELOG.md`, attach the three-OS builds. |
| 2026-10-24 | Version 0.2.1: embedded DKLS root/account binding enforced during decryption, import, metadata inspection and reconstruction; 35 core tests. |
| 2026-10-28 | Version 0.2.2: numbered steps, per-signer fetch breakdown, action-local feedback, proposer EOA terminology, explicit record/share counts and clipboard acknowledgement. |
| 2026-11-04 | Version 0.2.3: editable per-network registry addresses with reset, MAINNET/TESTNET only, consistent Robo Guardian terminology, clearer signer configuration and derivation-path guidance. |
| 2026-11-13 | Prepare the public v0.2.3 source snapshot, `main`-based release workflows, GitHub Releases downloads, Actions event policy and redistribution notices. |

## 14. Changelog

### 0.2.3 (2026-11-04)

- Prepare public distribution through `salt-space/salt-recovery-tool`, with a single initial commit, GitHub Releases downloads, `main`-based workflows, an administrator-applied Actions event policy, and licence notices.
#### Changed

- GUI: expose each network's shard registry address beside its RPC URL. Allow
  editing and resetting to the built-in default, save overrides per network,
  and clear fetched recovery results when the network or registry changes.
- Validate registry overrides and clarify the existing CLI `fetch --registry`
  option; omitting it uses the chosen network's default. The chain-id check
  remains required even with a custom registry.
- Remove STAGING from the GUI and CLI network choices. Ignore saved STAGING
  endpoints while preserving settings for MAINNET and TESTNET.
- Use "Robo Guardian" / "Robo Guardians" consistently in user-facing labels,
  guidance, errors, CLI help, and current documentation.
- Clarify that Option 1 can recover with proposer EOA keys alone when they
  provide enough distinct shares; Robo Guardian keys are not always required.
- Explain "signer configuration" and the shares needed for recovery instead
  of the ambiguous "wallet type" wording.
- Explain root and child derivation paths with examples, start with root-only
  recovery (`m`), and place ranges / deeper paths in expandable help.
- Update the README and developer specification, including its PDF.

The full list is in [`CHANGELOG.md`](../CHANGELOG.md).

### 0.2.2 (2026-10-28)

- Connected, numbered recovery steps with reached/current state, keyboard access and disabled future steps.
- Per-signer fetch rows with labels, addresses, status and record counts, plus accurate Robo Guardian-usage guidance.
- Progress, success and errors beside the relevant action buttons, with accessible announcements.
- Consistent proposer EOA terminology in the UI, errors, CLI help and usage documentation; distinct Robo Guardian labels.
- Explicit record and supplied-key counts before decryption; confirmed quorum and available/required shares afterwards.
- Per-key clipboard confirmation for three seconds, with pending, failure and retry feedback.
- Updated developer specification and matching PDF, including account-binding validation and current tests.

### 0.2.1 (2026-10-24)

- Validate that every DKLS share's embedded root public key matches its declared Salt account during decryption, import, metadata inspection and reconstruction. Mismatches fail explicitly, preventing recovery of another account's key.

### 0.2.0 (October 2026)

- **GUI is in-memory only.** Removed the **Existing keyshares** recover option and **Download decrypted keyshares**. Keyshare files are read and written only by the CLI (`reconstruct --share`, `decrypt --out`).
- Removed the `import_shares`, `pick_keyshare_file` and `export_shares` app commands and the `tauri-plugin-dialog` dependency, so the app ships no file-dialog or filesystem plugin.
- **Robo Guardian seed** is now Option 2 on the Recover step (was Option 3).
- Minimum Rust 1.90 declared in `Cargo.toml`; README prerequisites cover the CLI and headless use.
- Manual Release workflow tags `vX.Y.Z` and copies `CHANGELOG.md` onto the GitHub Releases page.
- CLI and file formats unchanged.

### 0.1.0 (September 2026)

First release: Tauri + Rust GUI and headless CLI in one binary; fetch, decrypt and reconstruct; Recover options for work EOA keys, existing keyshare files and Robo Guardian seed; decrypted keyshare download from the GUI; Linux, macOS universal and Windows builds.

## 15. Repository map

```text
.github/workflows/build.yml   CI matrix (linux-x64, macos-universal, win-x64)
.github/workflows/release.yml Manual GitHub Release (tag + CHANGELOG.md notes)
.github/scripts/release-info.sh Version check and changelog-section extract
Cargo.toml                    workspace (crates/core, src-tauri), release profile
crates/core/src/
  lib.rs                      module list
  networks.rs                 MAINNET/TESTNET, registry, HKDF info, page size
  registry.rs                 JSON-RPC client, getShards paging, ShardStored chunks
  crypto.rs                   PrivateKey, ECIES unwrap, HKDF, AES-GCM, gunzip, wipe
  decrypt.rs                  account discovery, record decryption
  keyshare.rs                 keyshare file formats, keyshare_info, same-account checks
  reconstruct.rs              DKLS23 combine, soft child derivation, inspect
  paths.rs                    path lists and ranges (max 50)
  robo.rs                     Robo Guardian secret decrypt + MetaMask-path derivation
  types.rs                    dump, keyshare and key types (camelCase JSON)
  checksum.rs                 checksummed address serde
src-tauri/
  src/main.rs, lib.rs, cli.rs entry, GUI commands, headless CLI
  build.rs                    Tauri build + dev-mode release warning
  tauri.conf.json             window, CSP, bundle targets, macOS ad-hoc signing
  capabilities/default.json   core:default only
src/mainview/                 React UI (App.tsx, rpc.ts, types.ts, styles.css, theme)
  SecretInput.tsx             masked key input with Show/Hide
  CopyPrivateKeyButton.tsx    clipboard write and per-key acknowledgement/errors
scripts/dev.mjs               npm run dev → GUI or CLI
docs/dev-spec.md              developer specification (source)
docs/salt-recovery-tool-dev-spec.pdf  printable version of this specification
```
