import { StrictMode, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { api } from './platform/browser';
import { PUBLIC_POST_VERSION, publicProjection, type PublicOperation, type PublicSummary } from './publicPostFlow';
import './tokens.css';
import './x-connect.css';
import './public-post.css';

const errors: Record<string, string> = {
  'helper-unavailable': 'The public-post helper is missing or disconnected. Check its installation and approved issuer configuration, then check saved progress.',
  'unsupported-helper': 'The helper reply did not match the public-post protocol. No verification was accepted. Check the helper installation.',
  'operation-unavailable': 'The operation could not finish. Unlock your Ubuntu keyring if needed, then check saved progress or recover. Keep pending recovery data.',
  'helper-busy': 'Another enrollment operation is running. Wait for it to finish, then check saved progress.',
  'recovery-needed': 'Waiting stopped. An operation may already have committed. Check saved progress and recover before starting again.',
  'page-update-required': 'The page and background versions differ. Reload the extension, then reopen this page.',
  'message-schema': 'The request was not accepted. Check the displayed handle, consent and post link.',
  'detection-expired': 'Automatic checking reached this challenge’s deadline or polling limit. Check saved progress and recover before starting again.',
  'background-disconnected': 'The extension background disconnected. Reopen this page and check saved progress; recovery stays in the helper.',
};
const progress: Record<string, string> = { status: 'Checking saved progress…', begin: 'Preparing your private request and public challenge…',
  'poll-registration': 'Looking for your exact public challenge and completing verification…',
  'check-post': 'Checking the public post and saving the credential…', recover: 'Recovering the same enrollment…',
  cancel: 'Requesting confirmed cancellation…', forget: 'Removing the saved credential locally…' };

function PublicPost() {
  const installed = !!api()?.runtime?.id;
  const port = useRef<chrome.runtime.Port | undefined>(undefined);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [summary, setSummary] = useState<PublicSummary>();
  const [username, setUsername] = useState('');
  const [post, setPost] = useState('');
  const inFlight = useRef(false);
  const attempts = useRef(0);
  const [watchConsent, setWatchConsent] = useState(false);
  const [watching, setWatching] = useState(false);
  const [profileConsent, setProfileConsent] = useState(false);
  const [postConsent, setPostConsent] = useState(false);
  const [confirmForget, setConfirmForget] = useState(false);
  const [copied, setCopied] = useState(false);
  const [clock, setClock] = useState(Date.now());
  useEffect(() => { const timer = setInterval(() => setClock(Date.now()), 1000); return () => clearInterval(timer); }, []);
  useEffect(() => { setPost(''); setPostConsent(false); setCopied(false); }, [summary?.postText]);
  useEffect(() => {
    if (!installed) return;
    const connected = api().runtime.connect({ name: 'zkid-public-post' }); port.current = connected;
    let outdated = false;
    const greetingTimer = setTimeout(() => { outdated = true; setReady(false); setError('page-update-required'); }, 10_000);
    connected.onMessage.addListener((input: unknown) => {
      if (!input || typeof input !== 'object') return;
      const value = input as Record<string, unknown>;
      if (value.version !== PUBLIC_POST_VERSION || value.verified !== false) {
        clearTimeout(greetingTimer);
        outdated = true;
        setReady(false); setBusy(''); inFlight.current = false; setWatching(false); setError('page-update-required'); return;
      }
      if (outdated) return;
      clearTimeout(greetingTimer);
      setReady(true);
      if (value.state === 'busy' && typeof value.operation === 'string' && value.operation in progress) { setBusy(value.operation); setError(''); }
      else if (value.state === 'error') { inFlight.current = false; setWatching(false); setBusy(''); setError(typeof value.code === 'string' && value.code in errors ? value.code : 'operation-unavailable'); }
      else if (value.state === 'result' && value.summary && typeof value.summary === 'object') {
        const result = publicProjection(value.summary);
        if (!result) { inFlight.current = false; setWatching(false); setBusy(''); setError('unsupported-helper'); return; }
        // This is a public progress projection, never a credential or badge.
        inFlight.current = false;
        if (!['awaiting-post', 'pending'].includes(result.state)) setWatching(false);
        setSummary(result);
        if (typeof result.username === 'string') setUsername(result.username);
        setBusy(''); setError(''); setCopied(false); setPostConsent(false); setConfirmForget(false);
      }
    });
    connected.onDisconnect.addListener(() => { clearTimeout(greetingTimer); void api().runtime.lastError; port.current = undefined; inFlight.current = false; setWatching(false); setReady(false); setBusy(''); setError('background-disconnected'); });
    return () => { clearTimeout(greetingTimer); port.current = undefined; connected.disconnect(); };
  }, [installed]);
  const send = (op: PublicOperation | 'stop', body: Record<string, unknown> = {}) => {
    if (!ready || !port.current || (inFlight.current && op !== 'stop')) return;
    setError('');
    if (op === 'begin') { setProfileConsent(false); attempts.current = 0; setWatching(watchConsent); setWatchConsent(false); }
    else if (op !== 'poll-registration') setWatching(false);
    inFlight.current = op !== 'stop';
    setBusy(op === 'stop' ? '' : op);
    if (op === 'check-post') setPostConsent(false);
    try { port.current.postMessage({ version: PUBLIC_POST_VERSION, op, body }); }
    catch { inFlight.current = false; setWatching(false); setBusy(''); setError('background-disconnected'); }
  };
  useEffect(() => {
    if (!watching || !ready || busy || !summary?.expiresAt || !['awaiting-post', 'pending'].includes(summary.state)) return;
    const deadline = summary.expiresAt * 1000;
    if (Date.now() >= deadline || attempts.current >= 20) {
      setWatching(false); setError('detection-expired'); return;
    }
    // The issuer enforces its own durable cooldown and total request budget.
    // This page never retries uncertainty or creates a replacement enrollment.
    const wait = Math.min(deadline - Date.now(), Math.max(5_000, (summary.nextCheckAt ?? 0) * 1000 - Date.now()));
    const timer = setTimeout(() => {
      if (Date.now() >= deadline) { setWatching(false); setError('detection-expired'); return; }
      attempts.current += 1;
      send('poll-registration', { approve_source_check: true });
    }, wait);
    return () => clearTimeout(timer);
  }, [watching, ready, busy, summary]);
  const blocked = !installed || !ready || !!busy;
  const pending = summary?.username !== undefined;
  const expired = !!summary?.expiresAt && summary.expiresAt * 1000 <= clock;
  const canBegin = !pending || summary?.state === 'begin-recovery-required';
  return <main className="x-connect public-post">
    <a className="brand" href={installed ? api().runtime.getURL('sidepanel.html') : '/sidepanel.html'}>nockapp.</a>
    <h1>Connect X with a public post</h1>
    <p className="status-label">Research candidate · test mode</p>
    <p>Your desktop creates a private identity secret. Publish its fresh challenge on X, then the attested issuer checks it through TwitterAPI.io. The issuer sees your account at enrollment, but never your eventual public app ID.</p>
    <p>TwitterAPI.io is a trusted third-party source. This flow reads no browser cookies or login headers and requests no X browsing permissions. Publish manually on X; NockApp does not post for you.</p>
    {!installed && <p role="alert">Open this page from the installed extension. Browser preview cannot access the desktop helper.</p>}
    <button disabled={blocked} onClick={() => send('status')}>Check saved progress</button>
    <p>Saved keys and recovery stay in your Ubuntu helper. Optional discussion facts require a separately configured verifier.</p>
    <section aria-live="polite">
      {busy && <p role="status">{progress[busy]}</p>}
      {error && <p role="alert">{errors[error]}</p>}
      {summary?.state === 'credential-saved' && <><h2>Credential saved · test mode</h2><p>Your credential is saved privately. Showing a fact on a discussion requires a separate proof check. This status check has not disclosed any fact on a post.</p></>}
      {summary?.state === 'receipt-saved' && <p>The received credential and receipt are saved. Recover to resolve activation before starting a new enrollment.</p>}
      {summary?.state === 'activation-pending-finality' && <p>Your credential receipt is saved privately. Activation is waiting for Base Sepolia finality. Use Recover later; publishing the challenge again is unnecessary.</p>}
      {summary?.state === 'activation-replaced-or-revoked' && <p>The finalized issuer state marks this saved activation replaced or revoked. It has not been promoted to an active credential. Keep the receipt while resolving recovery.</p>}
      {summary?.state === 'begin-recovery-required' && <p>The same private request is saved. Approve the lookup below to retry its start without creating another identity.</p>}
      {summary?.state === 'cancelled' && <p>The helper confirmed cancellation or removed an unreceived local request. A saved incumbent credential was not deleted.</p>}
      {summary?.state === 'forgotten' && <p>The local credential was removed. Other copies were not remotely revoked.</p>}
      {summary && ['expired', 'failed', 'aborted'].includes(summary.state) && <p>This enrollment is {summary.state}. Keep recovery until its status is resolved; request confirmed cancellation before a fresh enrollment.</p>}
    </section>
    {canBegin && <fieldset disabled={blocked}>
      <legend>{summary?.state === 'begin-recovery-required' ? 'Resume the saved start' : summary?.credentialSaved ? 'Fresh registration or replacement' : 'Start enrollment'}</legend>
      <label>X handle <input aria-label="X handle" autoComplete="off" maxLength={15} value={username} disabled={pending} onChange={e => setUsername(e.target.value.replace(/^@/, ''))} /></label>
      <label className="disclosure"><input type="checkbox" checked={profileConsent} onChange={e => setProfileConsent(e.target.checked)} />I approve looking up this public X profile through TwitterAPI.io.</label>
      <label className="disclosure"><input type="checkbox" checked={watchConsent} onChange={e => setWatchConsent(e.target.checked)} />I approve automatic checks of this account’s public posts for up to ten minutes, verification through TwitterAPI.io, and private credential activation. A successful replacement revokes the old identity after receipt.</label>
      <button disabled={!profileConsent || !watchConsent || !/^[A-Za-z0-9_]{1,15}$/.test(username)} onClick={() => send('begin', { username, approve_public_profile_lookup: true })}>{summary?.state === 'begin-recovery-required' ? 'Resume saved start' : 'Create public challenge'}</button>
    </fieldset>}
    {summary?.postText && <section aria-label="Public challenge">
      <h2>Publish this exact text</h2>
      <label>Challenge text <textarea aria-label="Challenge text" readOnly value={summary.postText} /></label>
      <button disabled={blocked} onClick={() => { void navigator.clipboard.writeText(summary.postText!).then(() => setCopied(true)).catch(() => setCopied(false)); }}>{copied ? 'Copied' : 'Copy challenge'}</button>
      <a className="manual-post" href="https://x.com/compose/post" target="_blank" rel="noreferrer noopener">Open X to publish manually</a>
      {summary.expiresAt && <p>{expired ? 'This challenge has expired.' : `Publish within ${Math.max(0, Math.ceil((summary.expiresAt * 1000 - clock) / 1000))} seconds.`} Deadline: {new Date(summary.expiresAt * 1000).toLocaleString()}.</p>}
      {watching && <p role="status">Waiting for your public challenge. Keep this page open; no post link is needed.</p>}
      {!watching && !expired && ['awaiting-post', 'pending'].includes(summary.state) && <fieldset disabled={blocked}>
        <legend>Resume automatic checking</legend>
        <label className="disclosure"><input type="checkbox" checked={watchConsent} onChange={e => setWatchConsent(e.target.checked)} />I approve resuming bounded public-post checks and private credential activation for this saved challenge.</label>
        <button disabled={!watchConsent} onClick={() => { attempts.current = 0; setWatchConsent(false); setWatching(true); setError(''); }}>Resume automatic checking</button>
      </fieldset>}
      <details><summary>Manual post-link fallback</summary>
      <fieldset disabled={blocked || watching || expired || !['awaiting-post', 'pending'].includes(summary.state)}>
        <legend>Check the published post</legend>
        <label>Public X post link <input aria-label="Public X post link" type="url" maxLength={512} value={post} onChange={e => { setPost(e.target.value); setPostConsent(false); }} /></label>
        <label className="disclosure"><input type="checkbox" checked={postConsent} onChange={e => setPostConsent(e.target.checked)} />I approve checking this public post and account, saving the credential privately and activating it. A successful replacement revokes the old identity after receipt.</label>
        <button disabled={!postConsent || !post.trim()} onClick={() => send('check-post', { post: post.trim(), approve_source_check: true })}>Check my public post</button>
      </fieldset>
      </details>
    </section>}
    {pending && <div className="recovery-actions">
      <button disabled={blocked || summary?.state === 'begin-recovery-required'} onClick={() => send('recover')}>Recover saved enrollment</button>
      <button className="secondary" disabled={blocked} onClick={() => send('cancel')}>Request confirmed cancellation</button>
      <p>If activation already committed, recover the new credential. Disconnecting or closing this page is not confirmed cancellation.</p>
    </div>}
    {(!!busy || watching) && <button className="secondary" onClick={() => send('stop')}>Stop waiting</button>}
    {!!summary?.credentialSaved && !pending && <fieldset disabled={blocked}>
      <legend>Local deletion</legend>
      <label className="disclosure"><input type="checkbox" checked={confirmForget} onChange={e => setConfirmForget(e.target.checked)} />I want to remove this saved credential from this computer. This does not revoke other copies.</label>
      <button disabled={!confirmForget} onClick={() => send('forget', { confirm_local_deletion: true })}>Forget local credential</button>
    </fieldset>}
    {error === 'page-update-required' && <button onClick={() => api().runtime.reload()}>Reload NockApp extension</button>}
    <details><summary>Helper setup and limits</summary><p>This flow needs the separate public-post helper <code>com.nockapp.zkid</code>, an unlocked Ubuntu keyring and independently approved issuer configuration. The older helper cannot handle this protocol. Image approval, live deployment and real-account acceptance remain open.</p><a href={installed ? api().runtime.getURL('x-connect.html') : '/x-connect.html'}>Earlier private-proof research flow</a></details>
  </main>;
}

createRoot(document.getElementById('root')!).render(<StrictMode><PublicPost /></StrictMode>);
