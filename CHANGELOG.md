# Changelog

## 0.2.3 (2026-11-04)

### Changed

- Prepare the public `salt-space/salt-recovery-tool` distribution: GitHub Releases
  downloads, a `main`-based release workflow, no external PR CI, and dependency
  licence notices. The public repository starts with a single source snapshot.
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

## 0.2.2 (2026-10-28)

### Changed

- GUI: replace the recovery navigation pills with connected, numbered steps
  (1–5). Highlight progress and the current step, keep upcoming steps disabled,
  and preserve keyboard access and navigation back to reached steps.
- GUI: show fetch results for each signer, including its role, EOA address,
  fetch status, and record count. Explain Robo usage for 2-of-3, 3-of-5, and
  4-of-7 wallets without inferring the wallet type from empty fetch results.
- GUI: place progress, success, and error messages directly above each step's
  action buttons, including empty account results and missing-share errors.
  Announce feedback to screen readers and clear it when switching input methods.
- Standardize user-facing signer terminology to "proposer EOA" across the GUI,
  error messages, CLI help, and usage documentation; keep Robo labels distinct.
- GUI: distinguish records found for supplied signer keys from the wallet quorum.
  Replace ambiguous "2 of 2" counts with explicit record, key, and available-share
  counts; show the confirmed wallet type and recovery threshold after decryption.
- GUI: acknowledge copied private keys beside the copy button for three seconds.
  Show a local error if clipboard access fails and announce feedback to screen readers.
- Refresh the developer specification and its PDF with the current UI behavior,
  account-binding validation, and test coverage.

## 0.2.1 (2026-10-24)

### Fixed

- Prevent recovery of a different Salt account's key by validating each DKLS
  keyshare's embedded root public key against the declared account during
  decryption, import, and reconstruction. Mismatches now return an explicit error.

## 0.2.0 (2026-10-09)

The GUI now runs every flow in memory and never reads or writes keyshare
files. Keyshare files are for power users, through the CLI.

### Removed

- GUI: the **Existing keyshares** option on the Recover step (loading keyshare
  files). Use `reconstruct --share` in the CLI instead.
- GUI: **Download decrypted keyshares** on the Reconstruct step. Use
  `decrypt --out` in the CLI instead.
- The `import_shares`, `pick_keyshare_file` and `export_shares` app commands,
  and the `tauri-plugin-dialog` dependency (with `rfd` and `tauri-plugin-fs`).
  The app no longer ships a file-dialog or filesystem plugin.

### Changed

- **Robo seed** is now Option 2 on the Recover step (it was Option 3).
- The Reconstruct step says the keyshares were decrypted in memory and always
  lists which signers supplied them.
- `Cargo.toml` declares the minimum Rust version, `rust-version = "1.90"`.
- README: prerequisites now have their own section covering both the GUI and
  the CLI, and the CLI section explains headless and SSH use.
- Manual **Release** GitHub Action: tags `vX.Y.Z` from the repo version,
  copies that section of `CHANGELOG.md` onto the GitHub Releases page, and
  attaches the Linux, macOS and Windows builds.

The CLI (`fetch`, `decrypt`, `reconstruct`, `robo`) and the dump and keyshare
file formats are unchanged.

## 0.1.0 (2026-09-27)

First release.

- One binary per OS (Tauri 2 + Rust): a GUI wizard, plus a headless CLI with
  `fetch`, `decrypt`, `reconstruct` and `robo`.
- Fetch encrypted shard records from the Salt shard registry on MAINNET,
  TESTNET or STAGING, after checking the RPC's chain id.
- Decrypt shard records in memory with work EOA private keys, and pick the
  Salt account to recover.
- Reconstruct root and soft-derived private keys, with path ranges (up to 50
  paths per run).
- Recover options: work EOA private keys, existing keyshare files, and Robo
  seed. Robo seed derives 3 Robo accounts, and the wallet type is read from
  the keyshares.
- Download decrypted keyshares from the GUI (mode 0600, never overwriting).
- Builds for Linux (AppImage, deb, rpm), macOS universal (ad-hoc signed) and
  Windows (msi, nsis).
