import { useState, type InputHTMLAttributes, type ReactNode } from 'react';

interface SecretInputProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  /** Extra control shown after the Show/Hide toggle (e.g. a remove button). */
  action?: ReactNode;
}

export function SecretInput({ label, action, ...props }: SecretInputProps) {
  const [shown, setShown] = useState(false);

  return (
    <label className="field">
      <span>{label}</span>
      <div className="secret-row">
        <input {...props} type={shown ? 'text' : 'password'} />
        <button
          type="button"
          className="secondary small"
          onClick={() => setShown((value) => !value)}
        >
          {shown ? 'Hide' : 'Show'}
        </button>
        {action}
      </div>
    </label>
  );
}
