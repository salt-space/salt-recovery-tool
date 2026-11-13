import { invoke } from '@tauri-apps/api/core';
import type {
  DiscoveredAccount,
  FetchedDump,
  KeyshareInfo,
  NetworkName,
  ReconstructedKey,
  RoboAccount,
  RpcEndpoint,
} from './types';

const inTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
const NO_BACKEND =
  'The Rust backend is not available: open this UI through the desktop app (npm run dev), not in a browser.';

type Outcome<T> = { value: T; error?: undefined } | { value?: undefined; error: string };

/**
 * Invoke a Rust command. Command errors (rejected with a string) and transport
 * failures both come back as `error`, so the UI always has something to show.
 */
async function tryInvoke<T>(command: string, args: Record<string, unknown> = {}): Promise<Outcome<T>> {
  if (!inTauri) return { error: NO_BACKEND };
  try {
    return { value: await invoke<T>(command, args) };
  } catch (err) {
    return { error: typeof err === 'string' ? err : err instanceof Error ? err.message : String(err) };
  }
}

export async function loadRpcEndpoints(): Promise<RpcEndpoint[]> {
  const r = await tryInvoke<RpcEndpoint[]>('load_rpc_endpoints');
  return r.value ?? [];
}

export async function saveRpcEndpoints(endpoints: RpcEndpoint[]): Promise<boolean> {
  if (!inTauri) return true;
  const r = await tryInvoke<null>('save_rpc_endpoints', { endpoints });
  return !r.error;
}

export async function validateRpcEndpoint(url: string): Promise<{ valid: boolean; error?: string }> {
  if (!inTauri) return { valid: true };
  const r = await tryInvoke<{ valid: boolean; error?: string }>('validate_rpc_endpoint', { url });
  return r.value ?? { valid: false, error: r.error };
}

export async function fetchShards(params: {
  network: NetworkName;
  rpcUrl: string;
  registryAddress: string;
  eoaPrivateKeys: string[];
}): Promise<{ dumps: FetchedDump[]; error?: string }> {
  const r = await tryInvoke<FetchedDump[]>('fetch_shards', params);
  return { dumps: r.value ?? [], error: r.error };
}

export async function discoverAccounts(): Promise<{ accounts: DiscoveredAccount[]; error?: string }> {
  const r = await tryInvoke<DiscoveredAccount[]>('discover_accounts_cmd');
  return { accounts: r.value ?? [], error: r.error };
}

export async function decryptShards(publicKey?: string): Promise<{ shares: KeyshareInfo[]; error?: string }> {
  const r = await tryInvoke<KeyshareInfo[]>('decrypt_shards', { publicKey: publicKey ?? null });
  return { shares: r.value ?? [], error: r.error };
}

export async function reconstruct(params: { paths: string[] }): Promise<{ keys: ReconstructedKey[]; error?: string }> {
  const r = await tryInvoke<ReconstructedKey[]>('reconstruct', params);
  return { keys: r.value ?? [], error: r.error };
}

export async function deriveRoboAccounts(params: {
  ownerKey?: string;
  secret: string;
  count: number;
}): Promise<{ accounts: RoboAccount[]; error?: string }> {
  const r = await tryInvoke<RoboAccount[]>('derive_robo_accounts', {
    ownerKey: params.ownerKey ?? null,
    secret: params.secret,
    count: params.count,
  });
  return { accounts: r.value ?? [], error: r.error };
}

export async function clearSession(): Promise<void> {
  await tryInvoke<null>('clear_session');
}
