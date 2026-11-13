/**
 * Shapes returned by the Rust commands (see src-tauri/src/lib.rs and
 * crates/core/src/types.rs). Only metadata crosses the IPC boundary: keyshare
 * material never leaves the Rust process, and work EOA keys are sent once, on
 * fetch. Reconstructed keys are the product of the tool and are returned.
 */

export type NetworkName = 'MAINNET' | 'TESTNET';

export interface NetworkConfig {
  chainId: number;
  registryAddress: string;
  defaultRpcUrl: string;
}

/** Built-in defaults mirrored from crates/core/src/networks.rs; the GUI can override the registry. */
export const NETWORKS: Record<NetworkName, NetworkConfig> = {
  MAINNET: {
    chainId: 42161,
    registryAddress: '0x2bc34033e00cfcdcf58fcc8c389dc76ce93e25f3',
    defaultRpcUrl: 'https://arb1.arbitrum.io/rpc',
  },
  TESTNET: {
    chainId: 421614,
    registryAddress: '0x1aaf2396e754712c22d17e5968f38a9ede431b71',
    defaultRpcUrl: 'https://sepolia-rollup.arbitrum.io/rpc',
  },
};

export interface RpcEndpoint {
  network: NetworkName;
  url: string;
  /** Omitted when the network's built-in registry should be used. */
  registryAddress?: string;
}

/** Per-EOA summary of a fetch; the records themselves stay in Rust. */
export interface FetchedDump {
  eoa: string;
  recordCount: number;
}

export interface DiscoveredAccount {
  publicKey: string;
  evmAddress: string;
  eoas: string[];
  recordCount: number;
}

/** A keyshare held in the Rust session, without the share bytes. */
export interface KeyshareInfo {
  publicKey: string;
  evmAddress: string;
  /** Owning work EOA; zero address for raw keyshare files. */
  eoa: string;
  /** Registry record index; -1 for raw keyshare files. */
  recordIndex: number;
  /** DKLS party id when read from the share itself. */
  partyId?: number;
  /** Wallet quorum read from the share: `threshold`-of-`totalParties`. */
  threshold?: number;
  totalParties?: number;
}

export interface ReconstructedKey {
  path: string;
  privateKey: string;
  publicKey: string;
  evmAddress: string;
}

/** Derived Robo Guardian work EOA from Option 2 / `robo` CLI. */
export interface RoboAccount {
  index: number;
  path: string;
  address: string;
  privateKey: string;
}

/**
 * Robo Guardian accounts to derive. Salt quorums use threshold − 1 Robo Guardians next to the
 * owner (2-of-3 → 1, 3-of-5 → 2, 4-of-7 → 3), so 3 covers every supported signer configuration.
 */
export const ROBO_ACCOUNT_COUNT = 3;
