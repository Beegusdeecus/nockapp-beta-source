import { useState } from 'react';
import { bundleOperation, type CountStatus } from '../bundleDiscussion';

export function CountEnrollment({ operation = bundleOperation }: { operation?: <T>(op: 'count-status' | 'count-begin' | 'count-check-post' | 'count-recover' | 'count-cancel', body: Record<string, unknown>) => Promise<T> } = {}) {
  const [username, setUsername] = useState('');const [consent, setConsent] = useState(false);const [post, setPost] = useState('');
  const [status, setStatus] = useState<CountStatus>();const [busy, setBusy] = useState(false);const [error, setError] = useState('');
  async function run(op: 'count-status' | 'count-begin' | 'count-check-post' | 'count-recover' | 'count-cancel') {
    if (busy) return;setBusy(true);setError('');
    try { setStatus(await operation<CountStatus>(op, op === 'count-begin' ? { username, approve_public_profile_lookup: true }
      : op === 'count-check-post' ? { post, approve_source_check: true } : {})); }
    catch (e) { setError(e instanceof Error ? e.message : 'Enrollment unavailable. Saved receipts are preserved.'); }
    finally { setBusy(false); }
  }
  return <section aria-label="Count credential enrollment"><h2>Connect X for optional count proofs</h2>
    <p>Your secret and credential stay on this computer. The approved enclave sees your X account during verification and checks its public post through TwitterAPI.io. X and TwitterAPI.io can observe relevant activity and requests; this does not make network activity untraceable.</p>
    <p>Later proofs can keep your account and exact follower count hidden. Posting without a credential remains available.</p>
    <label>X username<input value={username} onChange={e => setUsername(e.target.value.replace(/^@/, ''))} disabled={busy} /></label>
    <label><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} />Allow this public profile lookup</label>
    <button disabled={busy || !consent || !/^[A-Za-z0-9_]{1,15}$/.test(username)} onClick={() => void run('count-begin')}>Prepare public ownership post</button>
    <button disabled={busy} onClick={() => void run('count-status')}>Read saved credential status</button>
    {status && <p role="status">{status.state} · {status.credential_saved ? 'credential stored locally; current validity is checked when used' : 'not yet saved'}</p>}
    {status?.username && <p>Saved enrollment for @{status.username}.</p>}
    {status && ['pending', 'issued', 'committed', 'receipt-saved', 'activation-pending-finality'].includes(status.state) &&
      <p>Enrollment is not finished. Recover the saved enrollment to check progress; keep the same ownership post.</p>}
    {status?.post_text && <><p>Publish this exact text on your own X account:</p><pre>{status.post_text}</pre>
      <label>Ownership post ID or URL<input value={post} onChange={e => setPost(e.target.value)} disabled={busy} /></label>
      <button disabled={busy || !post} onClick={() => void run('count-check-post')}>Check this public post and issue credential</button></>}
    <button disabled={busy} onClick={() => void run('count-recover')}>Recover saved enrollment</button>
    <button disabled={busy} onClick={() => void run('count-cancel')}>Cancel pending enrollment</button>
    {error && <p role="alert">{error}</p>}
  </section>;
}
