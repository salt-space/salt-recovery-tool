import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { FiTrash2 } from 'react-icons/fi';
import { getAddress, isAddress, zeroAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  NETWORKS,
  ROBO_ACCOUNT_COUNT,
  type DiscoveredAccount,
  type FetchedDump,
  type KeyshareInfo,
  type NetworkName,
  type ReconstructedKey,
  type RoboAccount,
} from './types';
import { SecretInput } from './SecretInput';
import { CopyPrivateKeyButton } from './CopyPrivateKeyButton';
import {
  clearSession,
  decryptShards,
  deriveRoboAccounts,
  discoverAccounts,
  fetchShards,
  loadRpcEndpoints,
  reconstruct,
  saveRpcEndpoints,
  validateRpcEndpoint,
} from './rpc';
import './styles.css';

const STEPS = ['recover', 'fetch', 'decrypt', 'reconstruct', 'result'] as const;
type Step = (typeof STEPS)[number];

const STEP_LABELS: Record<Step, string> = {
  recover: 'Recover',
  fetch: 'Fetch',
  decrypt: 'Decrypt',
  reconstruct: 'Reconstruct',
  result: 'Result',
};

/** How the user supplies key material on the Recover step. */
type RecoverMode = 'keys' | 'robo';

interface SignerInput {
  id: number;
  privateKey: string;
  /** Role shown instead of "Proposer EOA N" (e.g. "Proposer EOA", "Robo Guardian 1"). */
  label?: string;
  isRobo?: boolean;
}

/** Public fetch metadata plus the signer's label at the time of the fetch. */
interface FetchedSigner extends FetchedDump {
  label: string;
  isRobo: boolean;
}

interface ConnectionSettings {
  rpcUrl: string;
  registryAddress: string;
}

function defaultConnection(network: NetworkName): ConnectionSettings {
  return {
    rpcUrl: NETWORKS[network].defaultRpcUrl,
    registryAddress: NETWORKS[network].registryAddress,
  };
}

export function App() {
  const [step, setStep] = useState<Step>('recover');
  // Steps the user has reached in this session; only these are navigable.
  const [reached, setReached] = useState<ReadonlySet<Step>>(
    () => new Set<Step>(['recover'])
  );
  const [mode, setMode] = useState<RecoverMode>('keys');
  const [network, setNetwork] = useState<NetworkName>('TESTNET');
  const [connections, setConnections] = useState<Record<NetworkName, ConnectionSettings>>({
    MAINNET: defaultConnection('MAINNET'),
    TESTNET: defaultConnection('TESTNET'),
  });
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [settingsStatus, setSettingsStatus] = useState('');
  const [sessionBusy, setSessionBusy] = useState(false);
  const { rpcUrl, registryAddress } = connections[network];
  const registryIsDefault = registryAddress.trim().toLowerCase() ===
    NETWORKS[network].registryAddress.toLowerCase();
  const registryError = !isAddress(registryAddress.trim(), { strict: false })
    ? 'Enter 0x followed by 40 hexadecimal characters.'
    : registryAddress.trim().toLowerCase() === zeroAddress
      ? 'The registry cannot be the zero address.'
      : '';
  const [signers, setSigners] = useState<SignerInput[]>([
    { id: Date.now(), privateKey: '' },
  ]);
  // Salt accounts found in the fetched records; null = not scanned yet.
  const [accounts, setAccounts] = useState<DiscoveredAccount[] | null>(null);
  // Public key of the account chosen for decryption.
  const [publicKey, setPublicKey] = useState('');
  const [paths, setPaths] = useState('m');
  const [dumps, setDumps] = useState<FetchedSigner[]>([]);
  const [shares, setShares] = useState<KeyshareInfo[]>([]);
  const [keys, setKeys] = useState<ReconstructedKey[]>([]);
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [roboOwnerKey, setRoboOwnerKey] = useState('');
  const [roboSecret, setRoboSecret] = useState('');
  const [roboAccounts, setRoboAccounts] = useState<RoboAccount[]>([]);
  const [roboBusy, setRoboBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    loadRpcEndpoints().then((endpoints) => {
      if (cancelled) return;
      setConnections((current) => {
        const loaded = { ...current };
        for (const endpoint of endpoints) {
          if (!Object.prototype.hasOwnProperty.call(NETWORKS, endpoint.network)) continue;
          loaded[endpoint.network] = {
            rpcUrl: endpoint.url,
            registryAddress: endpoint.registryAddress ?? NETWORKS[endpoint.network].registryAddress,
          };
        }
        return loaded;
      });
      setSettingsLoaded(true);
    });
    return () => { cancelled = true; };
  }, []);

  // Scan for accounts the first time the Decrypt step is shown for a fetch.
  useEffect(() => {
    if (step === 'decrypt' && accounts === null && dumps.length > 0) {
      void loadAccounts();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, accounts, dumps]);

  const signerAddresses = useMemo(
    () =>
      signers.map((signer) => {
        try {
          return privateKeyToAccount(asHex(signer.privateKey)).address;
        } catch {
          return '';
        }
      }),
    [signers]
  );
  const validSignerCount = signerAddresses.filter(Boolean).length;

  const roboOwnerAddress = useMemo(() => {
    try {
      return privateKeyToAccount(asHex(roboOwnerKey)).address;
    } catch {
      return '';
    }
  }, [roboOwnerKey]);

  /** Lowercase EOA address -> role label, for signers filled from Option 2. */
  const signerRoles = useMemo(() => {
    const roles = new Map<string, string>();
    signers.forEach((signer, index) => {
      const address = signerAddresses[index];
      if (address && signer.label) roles.set(address.toLowerCase(), signer.label);
    });
    return roles;
  }, [signers, signerAddresses]);

  function roleOf(address: string): string {
    return signerRoles.get(address.toLowerCase()) ?? address;
  }

  const wallet = walletType(shares);

  const stepIndex = STEPS.indexOf(step);

  /** Move forward after completing a step. */
  function advanceTo(next: Step) {
    setStep(next);
    setReached((current) => new Set([...current, next]));
  }

  /** Jump to an already-reached step (step navigation / Back). Keeps entered data. */
  function goTo(target: Step) {
    if (!reached.has(target)) return;
    setError('');
    setStatus('');
    setStep(target);
  }

  /** Nearest reached step before the current one. */
  function goBack() {
    for (let i = stepIndex - 1; i >= 0; i -= 1) {
      const candidate = STEPS[i]!;
      if (reached.has(candidate)) {
        goTo(candidate);
        return;
      }
    }
  }

  /**
   * Complete a step that produced fresh data. Anything derived downstream is
   * now stale, so steps after `next` become unreachable again.
   */
  function completeStep(next: Step) {
    const nextIndex = STEPS.indexOf(next);
    setStep(next);
    setReached(
      (current) =>
        new Set([
          ...[...current].filter((s) => STEPS.indexOf(s) < nextIndex),
          next,
        ])
    );
  }

  function updateSigner(id: number, privateKey: string) {
    setSigners((current) =>
      current.map((signer) =>
        signer.id === id ? { ...signer, privateKey } : signer
      )
    );
  }

  function removeSigner(id: number) {
    setSigners((current) =>
      current.length > 1 ? current.filter((signer) => signer.id !== id) : current
    );
  }

  function changeRecoverMode(next: RecoverMode) {
    setMode(next);
    setError('');
    setStatus('');
  }

  async function onNetworkChange(next: NetworkName) {
    if (next === network || sessionBusy || !settingsLoaded) return;
    setNetwork(next);
    setSettingsStatus('');
    await invalidateFetchedRecords(`Switched to ${next}. Fetch again to use this network's registry.`);
  }

  async function invalidateFetchedRecords(message: string) {
    if (dumps.length === 0) return;
    setDumps([]);
    setAccounts(null);
    setPublicKey('');
    setShares([]);
    setKeys([]);
    setError('');
    setStatus(message);
    setStep('recover');
    setReached(new Set<Step>(['recover']));
    setSessionBusy(true);
    try {
      await clearSession();
    } finally {
      setSessionBusy(false);
    }
  }

  function updateRpcUrl(value: string) {
    setConnections((current) => ({ ...current, [network]: { ...current[network], rpcUrl: value } }));
    setSettingsStatus('');
  }

  async function updateRegistry(value: string) {
    if (sessionBusy || !settingsLoaded) return;
    setConnections((current) => ({ ...current, [network]: { ...current[network], registryAddress: value } }));
    setSettingsStatus('');
    await invalidateFetchedRecords('Registry address changed. Fetch again to use the new registry.');
  }

  async function persistConnection(value: ConnectionSettings) {
    return saveRpcEndpoints([{
      network,
      url: value.rpcUrl,
      registryAddress: value.registryAddress.trim().toLowerCase() === NETWORKS[network].registryAddress.toLowerCase()
        ? undefined
        : value.registryAddress.trim(),
    }]);
  }

  async function resetRegistry() {
    if (sessionBusy || !settingsLoaded) return;
    const reset = { ...connections[network], registryAddress: NETWORKS[network].registryAddress };
    await updateRegistry(reset.registryAddress);
    setSessionBusy(true);
    try {
      const saved = await persistConnection(reset);
      setSettingsStatus(saved
        ? `Default registry restored for ${network}.`
        : 'Default registry restored for this session; settings could not be saved.');
    } finally {
      setSessionBusy(false);
    }
  }

  async function onFetch() {
    if (sessionBusy || !settingsLoaded) return;
    setSessionBusy(true);
    try {
      if (registryError) {
        setError(`Check the registry address: ${registryError}`);
        return;
      }
      const privateKeys = signers
        .map((signer) => signer.privateKey.trim())
        .filter(Boolean);
      if (privateKeys.length === 0) {
        setError('Enter at least one proposer EOA private key');
        return;
      }
      // Keep results tied to the inputs used for this fetch, even if the user
      // goes back and edits their keys before viewing the results again.
      const fetchedSigners = new Map(
        signers.map((signer, index) => [
          signerAddresses[index]?.toLowerCase(),
          {
            label: signer.label ?? `Proposer EOA ${index + 1}`,
            isRobo: signer.isRobo ?? false,
          },
        ])
      );
      setError('');

      setStatus(`Checking ${network} RPC endpoint...`);
      const check = await validateRpcEndpoint(rpcUrl);
      if (!check.valid) {
        setStatus('');
        setError(
          `RPC endpoint did not respond${check.error ? `: ${check.error}` : ''}. Fix the RPC URL in the top-right corner.`
        );
        return;
      }
      const saved = await persistConnection(connections[network]);
      setSettingsStatus(saved ? '' : 'Using these settings for this session; settings could not be saved.');

      setStatus('Fetching encrypted shard records...');
      const result = await fetchShards({
        network,
        rpcUrl,
        registryAddress: registryAddress.trim(),
        eoaPrivateKeys: privateKeys,
      });
      setStatus('');
      if (result.error) {
        setError(result.error);
        return;
      }
      setDumps(
        result.dumps.map((dump, index) => ({
          ...dump,
          ...(fetchedSigners.get(dump.eoa.toLowerCase()) ?? {
            label: `Proposer EOA ${index + 1}`,
            isRobo: false,
          }),
        }))
      );
      setAccounts(null);
      setPublicKey('');
      setShares([]);
      setKeys([]);
      completeStep('fetch');
    } finally {
      setSessionBusy(false);
    }
  }

  async function loadAccounts() {
    setSessionBusy(true);
    try {
      setError('');
      setStatus('Scanning records for Salt accounts...');
      const result = await discoverAccounts();
      setStatus('');
      if (result.error) {
        setError(result.error);
        setAccounts([]);
        return;
      }
      setAccounts(result.accounts);
      // Preselect when there is only one account, or when the previous choice
      // is still present after a re-scan.
      const stillPresent = result.accounts.some((a) => a.publicKey === publicKey);
      if (!stillPresent) {
        setPublicKey(
          result.accounts.length === 1 ? result.accounts[0]!.publicKey : ''
        );
      }
    } finally {
      setSessionBusy(false);
    }
  }

  async function onDecrypt() {
    setSessionBusy(true);
    try {
      if (!publicKey) {
        setError('Select the Salt account to decrypt');
        return;
      }
      setError('');
      setStatus('Decrypting shard records in memory...');
      const result = await decryptShards(publicKey);
      setStatus('');
      if (result.error) {
        setError(result.error);
        return;
      }
      setShares(result.shares);
      setKeys([]);
      completeStep('reconstruct');
    } finally {
      setSessionBusy(false);
    }
  }

  async function onDeriveRobo() {
    setError('');
    setRoboBusy(true);
    setStatus('Deriving Robo Guardian EOAs...');
    const result = await deriveRoboAccounts({
      ownerKey: roboOwnerKey.trim() || undefined,
      secret: roboSecret,
      count: ROBO_ACCOUNT_COUNT,
    });
    setRoboBusy(false);
    setStatus('');
    if (result.error) {
      setError(result.error);
      setRoboAccounts([]);
      return;
    }
    setRoboAccounts(result.accounts);
    setStatus(`Derived ${result.accounts.length} Robo Guardian accounts.`);
  }

  function useDerivedKeys() {
    if (roboAccounts.length === 0) return;
    const now = Date.now();
    const robos: SignerInput[] = roboAccounts.map((account) => ({
      id: now + account.index + 1,
      privateKey: account.privateKey,
      label: `Robo Guardian ${account.index + 1}`,
      isRobo: true,
    }));
    const owner: SignerInput[] = roboOwnerAddress
      ? [{ id: now, privateKey: roboOwnerKey.trim(), label: 'Proposer EOA' }]
      : [];
    setSigners([...owner, ...robos]);
    setMode('keys');
    setError('');
    setStatus(
      owner.length
        ? `Filled the proposer EOA and ${robos.length} Robo Guardian keys. Fetch to find the recovery records held by these signers.`
        : `Filled ${robos.length} Robo Guardian keys. Add the proposer EOA private key too: Robo Guardian keys alone cannot provide enough shares for recovery.`
    );
  }

  async function onReconstruct() {
    setSessionBusy(true);
    try {
      setError('');
      setStatus('Reconstructing private keys...');
      const result = await reconstruct({
        paths: paths
          .split(/\r?\n/)
          .map((path) => path.trim())
          .filter(Boolean),
      });
      setStatus('');
      if (result.error) {
        setError(result.error);
        return;
      }
      setKeys(result.keys);
      completeStep('result');
    } finally {
      setSessionBusy(false);
    }
  }

  async function reset() {
    setSessionBusy(true);
    try {
      await clearSession();
      setDumps([]);
      setShares([]);
      setKeys([]);
      setAccounts(null);
      setPublicKey('');
      setError('');
      setStatus('');
      setStep('recover');
      setReached(new Set<Step>(['recover']));
    } finally {
      setSessionBusy(false);
    }
  }

  return (
    <main className="shell">
      <header className="topbar">
        <section className="hero">
          <p className="eyebrow">Salt Recovery Tool</p>
          <h1>Recover Salt MPC accounts without Salt servers.</h1>
          <p>
            Recover your Salt account using proposer EOA private keys you
            already have, or a proposer EOA private key and a Robo Guardian
            secret. Fetch the encrypted recovery records and recover your keys
            locally.
          </p>
        </section>

        <aside className="network-picker" aria-label="Network">
          <div className="field compact">
            <span>Network</span>
            <div className="segmented" role="radiogroup" aria-label="Network">
              {(Object.keys(NETWORKS) as NetworkName[]).map((name) => (
                <button
                  key={name}
                  type="button"
                  role="radio"
                  aria-checked={network === name}
                  className={network === name ? 'active' : ''}
                  onClick={() => onNetworkChange(name)}
                  disabled={sessionBusy || !settingsLoaded}
                >
                  {name}
                </button>
              ))}
            </div>
          </div>
          <label className="field compact">
            <span>Arbitrum RPC URL</span>
            <input
              value={rpcUrl}
              onChange={(event) => updateRpcUrl(event.target.value)}
              disabled={sessionBusy || !settingsLoaded}
              spellCheck={false}
            />
          </label>
          <label className="field compact">
            <span id="registry-label">Shard registry address</span>
            <textarea
              className="registry-address"
              rows={2}
              value={registryAddress}
              onChange={(event) => void updateRegistry(event.target.value)}
              disabled={sessionBusy || !settingsLoaded}
              spellCheck={false}
              autoCapitalize="none"
              aria-labelledby="registry-label"
              aria-invalid={!!registryError}
              aria-describedby="registry-help registry-error"
            />
          </label>
          <div className="registry-actions">
            <span className="muted tiny">{registryIsDefault ? 'Default address' : 'Custom address'}</span>
            <button
              type="button"
              className="secondary small"
              onClick={resetRegistry}
              disabled={registryIsDefault || sessionBusy || !settingsLoaded}
            >
              Reset to default
            </button>
          </div>
          <div id="registry-error" className="registry-error" role="alert">
            {registryError}
          </div>
          <p className="muted tiny" id="registry-help">
            Registry on {network} · Chain {NETWORKS[network].chainId}.
            Overrides are saved when you fetch.
          </p>
          <p className="muted tiny" role="status" aria-live="polite">
            {settingsStatus}
          </p>
        </aside>
      </header>

      <nav className="steps" aria-label="Recovery steps">
        <ol>
          {STEPS.map((name, index) => (
            <li
              key={name}
              className={reached.has(name) ? 'reached' : undefined}
            >
              <button
                type="button"
                disabled={!reached.has(name) || sessionBusy}
                aria-current={step === name ? 'step' : undefined}
                aria-label={`Step ${index + 1} of ${STEPS.length}: ${STEP_LABELS[name]}`}
                onClick={() => goTo(name)}
              >
                <span className="step-number" aria-hidden="true">
                  {index + 1}
                </span>
                <span className="step-label">{STEP_LABELS[name]}</span>
              </button>
            </li>
          ))}
        </ol>
      </nav>

      {step === 'recover' && (
        <section className="card">
          <h2>Recover</h2>
          <p className="muted">
            Choose what you have. Nothing entered here is written to disk.
          </p>

          <div className="mode-list" role="radiogroup" aria-label="Recovery input">
            <label className={`mode${mode === 'keys' ? ' selected' : ''}`}>
              <input
                type="radio"
                name="recover-mode"
                value="keys"
                checked={mode === 'keys'}
                onChange={() => changeRecoverMode('keys')}
              />
              <div>
                <strong>Option 1: Proposer EOA private keys</strong>
                <p className="muted">
                  Use the proposer EOA private keys you already have. No Robo
                  Guardian secret is needed; recovery requires enough distinct
                  signer shares for your account.
                </p>
              </div>
            </label>
            <label className={`mode${mode === 'robo' ? ' selected' : ''}`}>
              <input
                type="radio"
                name="recover-mode"
                value="robo"
                checked={mode === 'robo'}
                onChange={() => changeRecoverMode('robo')}
              />
              <div>
                <strong>Option 2: Robo Guardian seed</strong>
                <p className="muted">
                  Use a proposer EOA private key and the Robo Guardian secret
                  to derive the Robo Guardian keys. The app detects your signer
                  configuration and shows how many shares are needed for recovery.
                </p>
              </div>
            </label>
          </div>

          {mode === 'keys' && (
            <>
              <h3>Proposer EOA private keys</h3>
              <p className="muted">
                Enter one proposer EOA private key per signer. These keys open
                the signers&apos; recovery records; they are not the Salt account
                private key you are recovering. Keys stay in this app session only.
              </p>
              <p className="muted">
                You do not need Robo Guardian private keys if the proposer keys
                you supply provide enough distinct shares. After decryption,
                the app shows how many shares you have and how many are required.
              </p>
              {signers.map((signer, index) => (
                <div className="signer" key={signer.id}>
                  <SecretInput
                    label={
                      signer.label
                        ? `${signer.label} private key`
                        : `Proposer EOA private key ${index + 1}`
                    }
                    value={signer.privateKey}
                    onChange={(event) =>
                      updateSigner(signer.id, event.target.value)
                    }
                    placeholder="0x..."
                    action={
                      <button
                        type="button"
                        className="secondary icon"
                        onClick={() => removeSigner(signer.id)}
                        disabled={signers.length <= 1}
                        aria-label={`Remove ${signer.label ?? `proposer EOA ${index + 1}`}`}
                        title="Remove this key"
                      >
                        <FiTrash2 aria-hidden />
                      </button>
                    }
                  />
                  <p className="muted">
                    {signerAddresses[index] || 'Enter a valid private key'}
                  </p>
                </div>
              ))}
              <StepActions error={error} status={status}>
                <button
                  type="button"
                  className="secondary"
                  onClick={() =>
                    setSigners((current) => [
                      ...current,
                      { id: Date.now(), privateKey: '' },
                    ])
                  }
                >
                  Add key
                </button>
                <button
                  type="button"
                  onClick={onFetch}
                  disabled={validSignerCount === 0 || !!registryError || sessionBusy || !settingsLoaded}
                >
                  Fetch encrypted shards
                </button>
              </StepActions>
            </>
          )}

          {mode === 'robo' && (
            <>
              <h3>Robo Guardian seed</h3>
              <p className="muted">
                Enter the proposer EOA private key and paste the Robo Guardian
                secret from Salt, or a recovery phrase / seed you already have.
                For an encrypted secret, use the proposer key it was encrypted to.
              </p>
              <p className="muted">
                The app derives {ROBO_ACCOUNT_COUNT} Robo Guardian keys to cover
                the supported signer configurations. For example, 2-of-3 means
                two signer shares out of three are needed for recovery. Your
                configuration is confirmed after decryption.
              </p>
              <SecretInput
                label="Proposer EOA private key"
                value={roboOwnerKey}
                onChange={(event) => setRoboOwnerKey(event.target.value)}
                placeholder="0x…"
              />
              <p className="muted">
                {roboOwnerAddress || 'Enter a valid private key'}
              </p>
              <label className="field">
                <span>Robo Guardian secret</span>
                <textarea
                  value={roboSecret}
                  onChange={(event) => setRoboSecret(event.target.value)}
                  placeholder="Encrypted 0x… or BIP39 mnemonic"
                />
              </label>
              <StepActions error={error} status={status}>
                <button
                  type="button"
                  onClick={onDeriveRobo}
                  disabled={!roboSecret.trim() || roboBusy}
                >
                  Derive Robo Guardian accounts
                </button>
                <button
                  type="button"
                  className="secondary"
                  onClick={useDerivedKeys}
                  disabled={roboAccounts.length === 0}
                >
                  Use these keys
                </button>
              </StepActions>
              {roboAccounts.length > 0 && (
                <div className="robo-results">
                  <div className="alert warning">
                    Private keys are shown below. Treat them like wallet
                    secrets.
                  </div>
                  {roboAccounts.map((account) => (
                    <div className="result" key={account.path}>
                      <strong>
                        Robo Guardian {account.index + 1} · {account.path}
                      </strong>
                      <p className="muted">{account.address}</p>
                      <code>{account.privateKey}</code>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </section>
      )}

      {step === 'fetch' && (
        <section className="card">
          <h2>Encrypted records</h2>
          <p className="muted">
            Fetch results for each supplied signer on {network}.
          </p>
          <div className="fetch-results">
            <table aria-label="Encrypted records by signer">
              <thead>
                <tr>
                  <th scope="col">Signer / EOA address</th>
                  <th scope="col">Fetch status</th>
                  <th scope="col">Records found</th>
                </tr>
              </thead>
              <tbody>
                {dumps.map((dump, index) => (
                  <tr key={`${dump.eoa}-${index}`}>
                    <th scope="row">
                      {dump.label}
                      <span className="fetch-address">{dump.eoa}</span>
                    </th>
                    <td>
                      <span className="fetch-status">Fetched</span>
                    </td>
                    <td>
                      <span
                        className={dump.recordCount > 0 ? 'records-found' : 'muted'}
                      >
                        {dump.recordCount === 0
                          ? 'No records found'
                          : `${dump.recordCount} ${dump.recordCount === 1 ? 'record' : 'records'} found`}
                      </span>
                      {dump.isRobo && dump.recordCount === 0 && (
                        <p className="fetch-note">
                          This Robo Guardian may not be used by your wallet.
                        </p>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {dumps.some((dump) => dump.isRobo) && (
            <div className="fetch-help">
              <strong>How many Robo Guardians are needed alongside a proposer?</strong>
              <p>2-of-3: 1 Robo Guardian · 3-of-5: 2 Robo Guardians · 4-of-7: 3 Robo Guardians.</p>
              <p>
                Not every wallet uses all three derived Robo Guardians. An empty result
                can mean a Robo Guardian is unused, or that the key or network does not
                match. Your signer configuration is confirmed after decryption.
              </p>
            </div>
          )}
          <StepActions error={error} status={status}>
            <button type="button" className="secondary" onClick={goBack} disabled={sessionBusy}>
              Back
            </button>
            <button type="button" onClick={() => advanceTo('decrypt')}>
              Continue to decrypt
            </button>
          </StepActions>
        </section>
      )}

      {step === 'decrypt' && (
        <section className="card">
          <h2>Decrypt shards</h2>
          <p className="muted">
            These Salt accounts have shard records owned by your signer keys.
            Pick the account to recover; only its keyshares are decrypted. The
            signer configuration (such as 2-of-3) is confirmed after decryption.
          </p>
          {accounts !== null && accounts.length > 0 && (
            <div className="account-list" role="radiogroup">
              {accounts.map((account) => {
                const selected = publicKey === account.publicKey;
                return (
                  <label
                    key={account.publicKey}
                    className={`account${selected ? ' selected' : ''}`}
                  >
                    <input
                      type="radio"
                      name="salt-account"
                      value={account.publicKey}
                      checked={selected}
                      onChange={() => setPublicKey(account.publicKey)}
                    />
                    <div className="account-body">
                      <p className="address">{account.evmAddress}</p>
                      <code>{account.publicKey}</code>
                      <p className="muted">
                        {account.recordCount} encrypted{' '}
                        {account.recordCount === 1 ? 'record' : 'records'} found for{' '}
                        {account.eoas.length} supplied signer{' '}
                        {account.eoas.length === 1 ? 'key' : 'keys'}.
                      </p>
                      <p className="muted">
                        Signers: {account.eoas.map(roleOf).join(', ')}
                      </p>
                    </div>
                  </label>
                );
              })}
            </div>
          )}
          <StepActions
            error={error}
            status={
              status ||
              (accounts !== null && accounts.length === 0
                ? 'No Salt account could be opened with the supplied signer keys. Check the keys on the Recover step and fetch again.'
                : '')
            }
          >
            <button type="button" className="secondary" onClick={goBack} disabled={sessionBusy}>
              Back
            </button>
            <button
              type="button"
              className="secondary"
              onClick={loadAccounts}
              disabled={accounts === null || sessionBusy}
            >
              Rescan
            </button>
            <button type="button" onClick={onDecrypt} disabled={!publicKey || sessionBusy}>
              Decrypt in memory
            </button>
          </StepActions>
        </section>
      )}

      {step === 'reconstruct' && (
        <section className="card">
          <h2>Reconstruct</h2>
          <p>
            Decrypted {shares.length} keyshare(s) in memory for{' '}
            {shares[0]?.evmAddress ?? 'the selected account'}.
          </p>
          {wallet && (
            <div className="wallet-type">
              <span className="wallet-badge">{wallet.label} signer configuration</span>
              <span className="muted">
                {shares.length} {shares.length === 1 ? 'share' : 'shares'}{' '}
                available. Recovery requires {wallet.threshold} of this
                account&apos;s {wallet.totalParties} signer shares. Supplied by{' '}
                {shares.map((share) => roleOf(share.eoa)).join(', ')}.
              </span>
            </div>
          )}
          <div className="path-guide" id="path-guide">
            <h3>Which accounts do you want to recover?</h3>
            <p>
              A derivation path identifies the original Salt account or a child
              account created from it. Keep <code>m</code> to recover only the
              original (root) account. Add a child account&apos;s original path
              if you also want to recover that account.
            </p>
            <table aria-label="Derivation path examples">
              <thead>
                <tr><th scope="col">Path</th><th scope="col">Account to recover</th></tr>
              </thead>
              <tbody>
                <tr><th scope="row"><code>m</code></th><td>The original (root) Salt account.</td></tr>
                <tr><th scope="row"><code>m/0</code></th><td>The child account at index 0.</td></tr>
                <tr><th scope="row"><code>m/1</code></th><td>The child account at index 1.</td></tr>
              </tbody>
            </table>
            <p>
              Each path produces a different address. Use the recorded path for
              each child account and check the recovered address against the
              account you want to access.
            </p>
          </div>
          <label className="field">
            <span>Derivation paths, one per line</span>
            <textarea
              aria-describedby="path-guide path-hint"
              value={paths}
              onChange={(event) => setPaths(event.target.value)}
              placeholder={'m\nm/0\nm/1'}
            />
            <p className="field-hint" id="path-hint">
              Leave <code>m</code> for the original account. Add each child path
              on a new line. You can recover up to 50 paths at a time.
            </p>
          </label>
          <details className="path-details">
            <summary>Recovering several child accounts or using deeper paths</summary>
            <p>
              <code>m/0..4</code> recovers five child accounts: <code>m/0</code>
              {' '}through <code>m/4</code>, including both ends. Include
              {' '}<code>m</code> on its own line if you also need the root account.
            </p>
            <p>
              For deeper paths, <code>m/0/1..m/0/10</code> recovers indices 1
              through 10 under <code>m/0</code>. Only non-hardened (soft) paths
              are supported; paths containing an apostrophe or <code>h</code>
              {' '}are not supported.
            </p>
          </details>
          <StepActions
            error={
              error ||
              (wallet && shares.length < wallet.threshold
                ? `A ${wallet.label} wallet needs ${wallet.threshold} shares to reconstruct. Add the missing signer keys on the Recover step.`
                : '')
            }
            status={status}
          >
            <button type="button" className="secondary" onClick={goBack} disabled={sessionBusy}>
              Back
            </button>
            <button type="button" onClick={onReconstruct} disabled={sessionBusy}>
              Reconstruct private keys
            </button>
          </StepActions>
        </section>
      )}

      {step === 'result' && (
        <section className="card">
          <h2>Recovered keys</h2>
          {wallet && (
            <div className="wallet-type">
              <span className="wallet-badge">{wallet.label} signer configuration</span>
              <span className="muted">{shares[0]?.evmAddress}</span>
            </div>
          )}
          <div className="alert warning">
            Reconstructing collapses MPC into single-key wallets. Move funds and
            rotate the account after this one-time disaster recovery.
          </div>
          {keys.map((key) => (
            <div className="result" key={key.path}>
              <strong>{key.path}</strong>
              <p className="address">{getAddress(key.evmAddress)}</p>
              <code>{key.privateKey}</code>
              <CopyPrivateKeyButton privateKey={key.privateKey} />
            </div>
          ))}
          <StepActions error={error} status={status}>
            <button type="button" className="secondary" onClick={goBack} disabled={sessionBusy}>
              Back
            </button>
            <button type="button" onClick={reset} disabled={sessionBusy}>
              Clear session
            </button>
          </StepActions>
        </section>
      )}
    </main>
  );
}

/** Keep action feedback beside its controls, with live announcements. */
function StepActions({
  error,
  status,
  children,
}: {
  error: string;
  status: string;
  children: ReactNode;
}) {
  return (
    <div className="step-actions">
      <div role="alert" aria-atomic="true">
        {error && <div className="alert error">{error}</div>}
      </div>
      <div role="status" aria-atomic="true">
        {!error && status && <div className="alert">{status}</div>}
      </div>
      <div className="actions">{children}</div>
    </div>
  );
}

function asHex(value: string): `0x${string}` {
  const trimmed = value.trim();
  return (trimmed.startsWith('0x') ? trimmed : `0x${trimmed}`) as `0x${string}`;
}

/** Quorum read from the shares themselves, e.g. `2-of-3`. */
function walletType(
  shares: KeyshareInfo[]
): { threshold: number; totalParties: number; label: string } | null {
  const share = shares.find(
    (s) => s.threshold !== undefined && s.totalParties !== undefined
  );
  if (!share) return null;
  return {
    threshold: share.threshold!,
    totalParties: share.totalParties!,
    label: `${share.threshold}-of-${share.totalParties}`,
  };
}
