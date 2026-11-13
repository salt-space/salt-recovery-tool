import { useEffect, useState } from 'react';

type CopyState = 'idle' | 'copying' | 'copied' | 'error';

export function CopyPrivateKeyButton({ privateKey }: { privateKey: string }) {
  const [state, setState] = useState<CopyState>('idle');

  useEffect(() => {
    if (state !== 'copied') return;
    const timer = window.setTimeout(() => setState('idle'), 3000);
    return () => window.clearTimeout(timer);
  }, [state]);

  async function copy() {
    setState('copying');
    try {
      await navigator.clipboard.writeText(privateKey);
      setState('copied');
    } catch {
      setState('error');
    }
  }

  return (
    <div className="copy-action">
      <button
        type="button"
        className="secondary"
        disabled={state === 'copying'}
        onClick={copy}
      >
        Copy private key
      </button>
      <span className="copy-status" role="status" aria-atomic="true">
        {state === 'copying' && 'Copying…'}
        {state === 'copied' && 'Copied to clipboard.'}
      </span>
      <span className="copy-error" role="alert" aria-atomic="true">
        {state === 'error' &&
          'Could not copy. Try again or select and copy the key manually.'}
      </span>
    </div>
  );
}
