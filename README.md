# Salt Recovery Tool

Desktop app (with a built-in headless CLI) for Salt MPC disaster recovery.

The tool has three stages:

1. Fetch encrypted shard records from the Salt shard registry.
2. Decrypt those records locally with the available signer private keys (proposer EOAs or Robo Guardian EOAs).
3. Reconstruct root or soft-derived private keys from threshold DKLS shares.

No Salt API or VOPRF server is required for recovery. A
[Tauri](https://tauri.app) desktop app runs the Rust `salt-recovery-core`. The
same `salt-recovery-tool` binary opens the GUI by default, or runs headless when
invoked with `fetch`, `decrypt`, `reconstruct`, or `robo` (or `help`, `--help`,
`--version`). Encrypted records and decrypted keyshares stay in the Rust session.
Keys entered into the GUI pass through the webview to Rust; the UI also receives
derived Robo Guardian keys and recovered private keys. The GUI never saves keys
or keyshare files. Copying a private key puts it on the system clipboard.
Network settings (RPC URLs and registry overrides) are saved under the app data
directory.

Architecture, security model and design decisions are written up in
[`docs/dev-spec.md`](docs/dev-spec.md) (PDF:
[`docs/salt-recovery-tool-dev-spec.pdf`](docs/salt-recovery-tool-dev-spec.pdf)).
Release notes are in [`CHANGELOG.md`](CHANGELOG.md).

## Download

Download installers and portable binaries from the
[official GitHub Releases page](https://github.com/salt-space/salt-recovery-tool/releases).
Choose a published release and expand **Assets**. Node.js and Rust are only
needed when building from source.

| Platform | Download |
| --- | --- |
| Windows x64 | `-setup.exe` or `.msi`; portable `salt-recovery-tool-win-x64.exe` |
| macOS, Intel and Apple Silicon | Universal `.dmg`; portable `salt-recovery-tool-macos-universal` |
| Linux x64 | `.AppImage`, `.deb`, or `.rpm`; portable `salt-recovery-tool-linux-x64` |

Each release includes `SHA256SUMS.txt`, `THIRD_PARTY_LICENSES.zip` and release
notes. Compare the file's SHA-256 hash with the checksum from the same release:

```bash
# Linux
sha256sum <downloaded-file>
# macOS
shasum -a 256 <downloaded-file>
```

```powershell
# Windows PowerShell
Get-FileHash .\<downloaded-file> -Algorithm SHA256
```

macOS builds are ad-hoc signed and not notarized; Windows builds are not signed
with a publisher certificate. The Linux portable binary requires the libraries
listed under [Prerequisites](#prerequisites). The CLI and GUI use the same binary.
GitHub Releases is the distribution channel for this repository; it does not
publish an npm package, container image, IPFS build or browser recovery app.

## Video walkthroughs (v0.2.3)

These narrated demonstrations use synthetic keys and simulated recovery records.
Both videos include English subtitles.

### Option 1: Proposer EOA private keys

Recover a Salt account using proposer EOA private keys you already hold.

https://github.com/user-attachments/assets/ca040489-d78e-4ffb-8ca1-423c6e3b614b

### Option 2: Robo Guardian secret

Derive the Robo Guardian keys from your secret, then recover the Salt account
using those keys together with your proposer EOA private key.

https://github.com/user-attachments/assets/808f1b03-b020-4b73-a55f-2fdba4aa0f86

## Two ways to run this

| | GUI | Headless CLI (same binary) |
|---|---|---|
| What | Wizard UI | `salt-recovery-tool fetch \| decrypt \| reconstruct \| robo` |
| Local | `npm run dev` | `npm run dev fetch …` / `decrypt …` / `reconstruct …` / `robo …` |
| Ship | AppImage / bare `salt-recovery-tool(.exe)` / `.dmg` | Same file: pass a subcommand, no window |
| Needs a display | Yes | No: works over SSH |

Both modes share one core. Only the CLI reads and writes dump and keyshare
files. Details below.

## Prerequisites

The GUI and the CLI are the same binary, so building either one needs the same
Rust toolchain and, on Linux, the same system libraries. Node.js is only needed
for the GUI and for the `npm run …` wrappers.

| Requirement | GUI | Headless CLI |
|---|---|---|
| Rust, stable, **1.90 or newer** | Yes | Yes |
| Linux system packages (below) | Yes | Yes: to build, and to run (the binary links them) |
| Node.js and npm: **Node 24** (what CI uses), at least 20.19 or 22.12 | Yes | Only for `npm run dev <subcommand>`; not for `cargo build` |
| A display (X11 or Wayland) | Yes | No |

**Rust.** Install with [rustup](https://rustup.rs). 1.90 is the oldest
toolchain the locked dependencies allow, and the build and tests pass on it;
`Cargo.toml` sets `rust-version = "1.90"`, so an older toolchain fails with a
clear message.

**Tauri** needs no separate install, and must be Tauri 2 (Tauri 1 is not
supported). The `tauri` Rust crate comes from Cargo (`2.11` in `Cargo.lock`).
The `tauri` command used by `npm run dev` and `npm run build` comes from
`npm install` (`@tauri-apps/cli` 2.11).

**Node.js** 24 is what CI and development use. Vite 7, which builds the UI,
needs at least 20.19 or 22.12.

**System packages:**

- Linux: Tauri's WebKitGTK/GTK development packages. On Debian/Ubuntu
  (including WSL2 with WSLg):

  ```bash
  sudo apt install pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev \
    libayatana-appindicator3-dev libxdo-dev patchelf
  ```

  These are needed for CLI-only use too: the binary is built against them, and
  it links WebKitGTK and GTK at startup even when no window opens. To build the
  `.rpm` and AppImage bundles with `npm run build`, also install
  `rpm file libfuse2` (CI does).

  `dconf-WARNING ... transport "disabled"` lines in the terminal are harmless
  GTK noise under WSLg.
- macOS: Xcode command-line tools.
- Windows: Visual Studio Build Tools (C++ workload) and WebView2 (preinstalled
  on Windows 10/11).

See also [Tauri's prerequisites](https://tauri.app/start/prerequisites/).

## Layout

```
crates/core      salt-recovery-core: fetch, decrypt, keyshare files, reconstruct, robo (+ unit tests)
src-tauri        desktop app + headless CLI (Tauri when no subcommand)
src/mainview     React UI (Vite)
```

## Desktop app

Install the [prerequisites](#prerequisites) first. The GUI needs a display; on
a headless machine, use the [CLI](#headless-cli).

### Run locally

```bash
npm install
npm run dev          # tauri dev: vite on :5173 + GUI window, hot reload
```

The first `cargo` build takes a few minutes; later runs are incremental. Changes
under `src/mainview` hot-reload; changes under `crates/` or `src-tauri/` rebuild
and relaunch.

Opening `http://localhost:5173` in a normal browser renders the UI but every
action reports that the Rust backend is not available.

```bash
npm run typecheck    # tsc --noEmit (UI)
npm test             # cargo test for core + app
```

### Using the app

The network, Arbitrum RPC URL and **Shard registry address** live in the
network selector. MAINNET and TESTNET each have their own settings. The full
registry address is editable; **Reset to default** restores the built-in
registry for that network and removes its saved override. The RPC URL is kept.

Valid overrides are saved when you fetch. Changing the network or registry
clears earlier fetched records and recovered results, so fetch again before
continuing. These controls are locked while a recovery operation is running.
The RPC's chain id is still checked against the chosen network before fetching,
including when a custom registry is used.

The Recover step offers two options:

- **Option 1: Proposer EOA private keys.** Enter the proposer EOA private keys
  you already have, fetch their encrypted recovery records, choose the Salt
  account, and decrypt in memory. Robo Guardian keys are not required if the
  supplied proposer keys provide enough distinct signer shares for recovery.
  Fetching records alone does not establish that this threshold is met.
- **Option 2: Robo Guardian seed.** Proposer EOA private key plus the Robo Guardian secret
  (encrypted or plaintext). The first 3 Robo Guardian accounts are derived at MetaMask
  paths `m/44'/60'/0'/0/{0,1,2}`, which covers the supported signer configurations
  (2-of-3 uses 1 Robo Guardian alongside the proposer, 3-of-5 uses 2,
  4-of-7 uses 3). **Use these keys** fills
  Option 1 with the proposer EOA and the Robo Guardian keys. Robo Guardians the wallet doesn't
  use hold no shards and are skipped at decrypt.

The signer configuration is read from the decrypted keyshares and shown on
Reconstruct and Result. For example, `2-of-3` means that two of the account's
three signer shares are needed for recovery. Reconstruct also shows how many
shares are available and who supplied them.

Decrypted keyshares stay in memory for the session. The GUI can't import or
export keyshare files: to save them (`decrypt --out`) or reconstruct from files
you already hold (`reconstruct --share`), use the [headless CLI](#headless-cli).

A derivation path identifies the root account or a child account created from
it. The GUI starts with `m`, which recovers only the original (root) account.
Add the original path of each child account on a separate line:

| Path | Account to recover |
|---|---|
| `m` | Original (root) Salt account |
| `m/0` | Child account at index 0 |
| `m/1` | Child account at index 1 |

Each path produces a different address; use the recorded child path and check
the recovered address against the account you want to access. Expanded help
in the GUI explains ranges: `m/0..4` covers five child accounts (`m/0` through
`m/4`), while `m/0/1..m/0/10` covers indices 1–10 under `m/0`.
Only non-hardened (soft) paths are supported, with a maximum of 50 per run.

Changing the network after fetching discards fetched records and returns to
Recover.

## Building installers

Tauri packages for the **host platform only**.

```bash
npm install
npm run build                 # host platform only
# macOS Intel + Apple Silicon (requires both Rust targets):
rustup target add aarch64-apple-darwin x86_64-apple-darwin
npm run build:macos-universal # → target/universal-apple-darwin/release/…
```

Release binaries embed the Vite output from `build/dist`; `tauri build` runs
`npm run build:web` for you, and a missing `build/dist` fails the build.
`tauri build` also enables the `tauri/custom-protocol` feature, which switches
Tauri to production mode. To build with cargo directly (binary only, no
bundles), do both steps yourself:

```bash
npm run build:web
cargo build --release -p salt-recovery-tool --features tauri/custom-protocol
```

A plain `cargo build --release` stays in Tauri dev mode: the GUI expects the
Vite dev server on `http://localhost:5173`, and the build prints a warning.

| Host | Files | Notes |
|---|---|---|
| Linux x64 | `salt-recovery-tool`, `deb/*.deb`, `rpm/*.rpm`, `appimage/*.AppImage` | AppImage is portable; bare binary is the GUI+CLI. |
| macOS universal | `salt-recovery-tool`, `dmg/*_universal.dmg`, `macos/*.app` | Fat binary (Intel + Apple Silicon). Ad-hoc signed (`signingIdentity: "-"`). First open may need right-click → Open (Gatekeeper); not notarized. |
| Windows x64 | `salt-recovery-tool.exe`, `msi/*.msi`, `nsis/*-setup.exe` | Bare `.exe` is portable (needs WebView2). |

Icons: regenerate with `npx tauri icon icon.png` after replacing the placeholder.

### CI and GitHub releases

The public repository uses `main`. `.github/workflows/build.yml` runs on pushes
to `main`, by maintainer dispatch, or when called by the release workflow. It
runs typechecking and locked Rust tests, then builds Linux, macOS universal and
Windows artifacts. It has no pull-request or comment triggers, and jobs accept
only this repository's `main` branch.

External pull requests do not receive CI runs. An administrator must also apply
the checked-in Actions event policy so a PR cannot introduce a new trigger and
bypass the workflow configuration. See [Public release operations](docs/public-release.md).

To publish version **0.2.3**, push the initial `main` commit and select **Actions →
Release → Run workflow → main**, keeping **Create a draft release** selected.
The workflow reads the existing versions, requires the matching changelog entry,
builds all three platforms, and creates the draft `v0.2.3` release with installers,
portable binaries, licence notices and checksums. Review the draft and publish it.
The tag points to the same commit; creating a release does not add a Git commit.
Do not create `v0.2.3` manually first: the workflow rejects an existing tag or release.

For subsequent releases, update all version and lock files plus `CHANGELOG.md`
before running the workflow. A push builds artifacts; it does not automatically
publish a GitHub Release.

## Headless CLI

See the [CLI reference (PDF)](docs/salt-recovery-tool-cli-reference.pdf)
for command syntax and recovery examples.

The CLI needs Rust and, on Linux, the system packages from
[Prerequisites](#prerequisites). It doesn't need a display, and Node.js is only
needed for the `npm run` wrappers.

### Build and run with Cargo

This is the simplest route, and the one to use on a headless machine or over
SSH. From the repository root:

```bash
# once (or after Rust changes)
cargo build -p salt-recovery-tool

# then anytime
./target/debug/salt-recovery-tool fetch --help
./target/debug/salt-recovery-tool fetch --network TESTNET --eoa 0x… --out dump.json
./target/debug/salt-recovery-tool reconstruct --share a.json --share b.json --path m/0
```

Debug builds don't embed the UI (their GUI expects `npm run dev`'s Vite server),
but the CLI subcommands work standalone. After `npm run build` (release):

```bash
./target/release/salt-recovery-tool fetch --help
```

### Over SSH or without a display

`npm run dev` with no subcommand starts the **GUI**, which needs a display.
Over SSH without X forwarding it fails with X11 or GTK errors (for example
`Failed to initialize GTK`). Setting up X11 forwarding or a virtual display is
out of scope for this README.

The CLI doesn't need a display. The Cargo commands above work over SSH, and so
does `npm run dev <subcommand>`, which runs `cargo run` and never starts the
GUI.

### With npm

From a checkout, `npm run dev` with a subcommand runs the CLI; it skips Vite and
runs the debug binary through `cargo run`:

```bash
npm run dev fetch help   # CLI help — see note below
npm run dev fetch --network TESTNET --eoa 0x… --out dump.json
npm run dev decrypt --in dump.json --private-key 0x… --list
npm run dev reconstruct --share a.json --share b.json --path m --path m/0..49
npm run dev robo --secret "word1 … word12"
```

**Why not `npm run dev fetch --help`?** npm treats `--help` / `-h` as *its own*
flags and never starts our script (you get “Run arbitrary package scripts”
instead). Workarounds that do reach the app:

```bash
npm run dev fetch help           # word "help" → --help inside our wrapper
npm run dev -- fetch --help      # npm's "--" means "rest is for the script"
npm run dev -- fetch -h
```

`npm run fetch-encrypted-shards`, `decrypt-shards`, `reconstruct-private-keys`
and `derive-robo` are aliases for the same four subcommands.

Only fetch needs network access; decrypt and reconstruct can run offline.

### Step 1: fetch

```bash
salt-recovery-tool fetch --network MAINNET --eoa 0xEoaA... --out dump-a.json
```

`--network MAINNET|TESTNET` (default `TESTNET`), optional `--rpc` / `--registry`.

#### Override the registry address (CLI)

To use a different registry without opening the GUI, pass its contract address:

```bash
salt-recovery-tool fetch --network TESTNET \
  --registry "$REGISTRY_ADDRESS" --eoa "$SIGNER_ADDRESS" --out shards.json
```

Set `REGISTRY_ADDRESS` to the desired `0x` contract address and `SIGNER_ADDRESS`
to the signer EOA whose recovery records you want.

**Omit `--registry` to use the network default:**

```bash
salt-recovery-tool fetch --network TESTNET \
  --eoa "$SIGNER_ADDRESS" --out shards.json
```

CLI flags apply to that invocation and do not load or change the GUI's saved
settings. A custom registry must be compatible
with the Salt shard-registry contract interface; it does not bypass the RPC
chain-id check. Zero addresses are rejected.

The dump contains only encrypted data and records the registry actually used;
`--out` overwrites an existing file.

### Step 2: decrypt

```bash
salt-recovery-tool decrypt --in dump-a.json --private-key 0x… --list
salt-recovery-tool decrypt --in dump-a.json --private-key 0x… --public-key 0x02… --out share-a.json
```

Prefer `SRT_PRIVATE_KEY` instead of `--private-key` to keep keys out of shell
history. Outputs are mode 0600 and never overwrite.

### Step 3: reconstruct

```bash
salt-recovery-tool reconstruct --share share-a.json --share share-b.json --path m --path m/0..49
salt-recovery-tool reconstruct --inspect --share keyshare-0.txt
```

`--path` accepts a soft path or a range. Short form `m/2..10`, or full paths
when needed (`m/0/1..m/0/10`, `m/0..m/49`). Max 50 paths total. `--share`
accepts JSON exports or raw base64; `PARTY_ID:FILE` overrides the party id.
Private keys are printed to stdout only.

### Optional: derive Robo Guardian EOAs

```bash
salt-recovery-tool robo --secret "word1 word2 … word12"
salt-recovery-tool robo --owner-key 0x… --secret 0xencrypted…
```

Derives 3 Robo Guardian accounts by default, enough for any Salt signer configuration
(`--count` changes that, 1–10). Encrypted secrets need the proposer EOA private
key via `--owner-key` (or `SRT_OWNER_KEY`). Prints address/PK pairs at
`m/44'/60'/0'/0/{i}`; fetch and decrypt with the proposer EOA and each Robo Guardian key,
and `reconstruct --inspect` prints the share's `quorum=` (e.g. `2-of-3`).

### Cross-check

Each `evm_address` should match the Salt app (and `salt-signer-sdk`'s
`npm run addresses`) for that derivation path.

## Feedback and licensing

Use [GitHub Issues](https://github.com/salt-space/salt-recovery-tool/issues) for
reproducible bugs and feature requests. See [SUPPORT.md](SUPPORT.md) before
sharing recovery diagnostics. Wiki, Discussions, Projects and GitHub Packages
are not support channels for this repository.

The project's own source is MIT-licensed; dependency terms are separate. See
[LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
