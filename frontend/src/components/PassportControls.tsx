import { useEffect, useRef, useState } from 'react';
import { PassportError, passportOperation, type PassportOperation, type PassportResult } from '../xPassport';

const errors: Record<string, string> = {
  'helper-unavailable': 'The Ubuntu helper is missing or disconnected. Check its installation.',
  'unsupported-helper': 'This operation needs the current proving helper. The compatibility-only helper cannot manage passports.',
  'passport-unavailable': 'No usable passport is selected. It may be missing, logged out, expired or invalid. A fresh X check can create a replacement.',
  'helper-busy': 'Another proof or passport operation is running. Wait for it to finish or cancel it.',
  'policy-unavailable': 'The approved policy is unavailable. Check the helper installation.',
  'keyring-unavailable': 'Open your Ubuntu desktop session and its Secret Service keyring.',
  'keyring-unconfigured': 'Configure a persistent Ubuntu login keyring first.',
  'keyring-locked': 'Unlock your Ubuntu login keyring, then retry. Enter its password only in Ubuntu’s keyring prompt.',
  'holder-key-missing': 'The original holder key is missing. It will not be silently replaced.',
  'job-cancelled': 'The operation was cancelled. An operation already committed by the helper may remain applied; check its status.',
  'job-deadline-expired': 'The helper operation took too long. Check status before retrying.',
};

export function PassportControls({ disabled, installed, onBusy, onRefresh }: {
  disabled: boolean; installed: boolean; onBusy: (busy: boolean) => void; onRefresh: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PassportResult>();
  const [error, setError] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteHolder, setDeleteHolder] = useState(false);
  const [lastOperation, setLastOperation] = useState<PassportOperation>();
  const abort = useRef<AbortController | undefined>(undefined);
  const [clock, setClock] = useState(Date.now());
  useEffect(() => {
    const timer = setInterval(() => setClock(Date.now()), 1000);
    return () => { clearInterval(timer); abort.current?.abort(); };
  }, []);
  async function run(operation: PassportOperation) {
    if (abort.current || busy || disabled || !installed || (operation === 'delete_passports' && !confirmDelete)) return;
    const controller = new AbortController();
    abort.current = controller;
    setBusy(true); onBusy(true); setResult(undefined); setError(''); setLastOperation(operation);
    try {
      const value = await passportOperation(operation, { signal: controller.signal,
        ...(operation === 'delete_passports' ? { deleteHolder } : {}) });
      if (!controller.signal.aborted) { setResult(value); setConfirmDelete(false); setDeleteHolder(false); }
    } catch (value) {
      if (!controller.signal.aborted) setError(value instanceof PassportError ? value.code : 'helper-operation-failed');
    } finally {
      if (abort.current === controller) { abort.current = undefined; setBusy(false); onBusy(false); }
    }
  }
  const blocked = disabled || busy || !installed;
  const summary = result && (result.status === 'checked' || result.status === 'synthetic') ? result : undefined;
  const expired = !!summary && summary.expiresAt * 1000 <= clock;
  return <details className="passport-controls">
    <summary>Saved passport</summary>
    <p>Proof evidence stays in your Ubuntu helper. Checking it does not open X or request browsing access. Using it still requires proof that you hold its key.</p>
    <button disabled={blocked} onClick={() => { void run('passport_status'); }}>Check saved passport</button>
    <button className="secondary" disabled={blocked} onClick={onRefresh}>Open a fresh X check</button>
    <p>A refresh needs a new X check and approval. Your current passport stays selected until its replacement passes. Failed refreshes preserve it.</p>
    <div role="status" aria-live="polite">
      {busy && <p>Checking the Ubuntu helper… Keep this page open.</p>}
      {expired ? <p>This observation has expired. Run a fresh X check before using it.</p> : summary && <>
        <h2>{summary.status === 'synthetic' ? 'Synthetic saved evidence checked' : 'Saved passport evidence checked'}</h2>
        <p>{summary.status === 'synthetic' ? 'This is a laboratory test, not verified account ownership.' : 'The helper rechecked the retained proofs and current policy. This is a dated observation; no post disclosure was made.'}</p>
        <p>Observed: {new Date(summary.observedAt * 1000).toLocaleString()}. Expires: {new Date(summary.expiresAt * 1000).toLocaleString()}.</p>
        {summary.status === 'checked' && <p>Available facts: account control{summary.facts.includes('followers-over-10000') ? ', more than 10,000 followers' : ''}.</p>}
      </>}
      {result?.status === 'logged-out' && <p>Passport logged out locally. Evidence and the holder key are retained. This does not log out of X.</p>}
      {result?.status === 'deleted' && <p>Saved passport files were deleted. Other copies are not revoked, and X remains signed in.</p>}
      {error && <><p>{errors[error] ?? 'The helper could not complete this operation. Check its installation and try checking status.'}</p>
        {lastOperation === 'delete_passports' && <p>Some proof files may already have been removed. If key deletion failed, unlock the keyring and retry explicit deletion.</p>}</>}
    </div>
    <button className="secondary" disabled={blocked} onClick={() => { void run('logout'); }}>Log out of passport</button>
    <p>Local logout clears the selected passport; it keeps evidence and its key. Reconnecting requires a fresh X check.</p>
    <fieldset disabled={blocked}>
      <legend>Delete saved passports</legend>
      <label><input type="checkbox" checked={confirmDelete} onChange={e => setConfirmDelete(e.target.checked)} />I want to delete all saved passport files in this helper.</label>
      <label><input type="checkbox" checked={deleteHolder} onChange={e => setDeleteHolder(e.target.checked)} />Also delete the holder key from my Ubuntu keyring.</label>
      <p>Deletion cannot be undone here. Copies elsewhere remain subject to their original expiry and policy.</p>
      <button disabled={!confirmDelete} onClick={() => { void run('delete_passports'); }}>Delete saved passports</button>
    </fieldset>
  </details>;
}
