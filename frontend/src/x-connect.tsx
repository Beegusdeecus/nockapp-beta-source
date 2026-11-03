import { api, isFirefox } from './platform/browser';
import { StrictMode, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { X_ORIGINS, X_FLOW_VERSION, SOURCE_ERROR_CODES, LOGIN_NETWORK_ERRORS, PROOF_STAGES, type LoginDiagnostic } from './xSourceFlow';
import './tokens.css';
import './x-connect.css';
import { PassportControls } from './components/PassportControls';

const states = ['idle', 'helper-check', 'login', 'context-ready', 'probing', 'proving', 'finished', 'passport-ready', 'synthetic-ready', 'error', 'cancelled'];
const progress: Record<string, string> = {
  starting: 'Starting the private check…', keyring: 'Checking your Ubuntu keyring…',
  notarize: 'Authenticating the notary and making the private X request…',
  'prepare-source': 'Preparing the authenticated response…', 'request-proof': 'Proving the request belongs to this session…',
  'http-proof': 'Proving the response format…', 'json-proof': 'Proving the account and follower fields…',
  'nock-proof': 'Proving the follower threshold locally…', 'independent-verification': 'Independently verifying all evidence…',
  'save-passport': 'Saving your holder-bound passport privately…',
};
const errors: Record<string, string> = {
  'extension-update-required': 'The page and extension background versions differ. Reload NockApp using the button below, then open Connect X again.',
  'permission-required': 'X access was not granted. Start again and approve only the displayed X hosts.',
  'helper-unavailable': 'The Ubuntu helper is missing or disconnected. Install it for this extension ID, then start again.',
  'background-disconnected': 'The connection page lost contact with the extension background. Start again; if you rebuilt the extension, reload its add-on first.',
  'unsupported-helper': 'The helper version is unsupported. Update it before trying again.',
  'login-window-unavailable': 'The X login window could not open. Start again from this extension page.',
  'flow-expired': 'This connection attempt expired. Start again to capture a fresh login context.',
  'login-expired': 'X rejected the session. Log in again on X, then retry.',
  'endpoint-forbidden': 'X refused this current-user endpoint. No account verification is available from this result.',
  'rate-limited': 'X rate-limited the request. Wait before starting another attempt.',
  'source-connection-failed': 'The local helper could not connect to X using the required TLS profile. Check connectivity and retry.',
  'unsupported-http-status': 'X returned an HTTP status this current-user endpoint cannot use. The source check did not establish account ownership.',
  'response-schema': 'The endpoint did not return the required account ID and follower count in the expected object.',
  'response-content-type': 'The endpoint returned an unsupported response content type.',
  'source-query-error': 'X returned an error for the current-user query. No account evidence was accepted.',
  'current-user-unavailable': 'X did not return the authenticated current user in the expected query result.',
  'keyring-unavailable': 'The Ubuntu Secret Service is unavailable. Open your Ubuntu desktop session and try again.',
  'keyring-unconfigured': 'Set up a persistent Ubuntu login keyring before trying again.',
  'keyring-locked': 'Unlock your Ubuntu login keyring in the desktop, then try again. Enter its password only in Ubuntu’s keyring prompt.',
  'holder-key-missing': 'The saved holder key is missing. Restore access to the original keyring; NockApp will not silently replace it.',
  'holder-key-mismatch': 'The holder key does not match this passport. Restore the original keyring.',
  'helper-busy': 'Another local proof or passport operation is running. Wait for it to finish or cancel it.',
  'notary-or-source-unavailable': 'The notary or X is unreachable. Check the configured notary connection and try again.',
  'notary-policy-rejected': 'The notary failed the installed attestation policy. An operator must review the image and trust configuration.',
  'policy-unavailable': 'The approved verification policy is missing or unavailable. Review the helper installation.',
  'proof-deadline-expired': 'Proof generation took too long. Try again with enough available memory and CPU.',
  'job-deadline-expired': 'The local operation expired. Start again with a fresh session.',
  'proof-failed': 'Local proof generation failed. No new passport was accepted.',
  'independent-verification-failed': 'Independent verification failed. No new passport was accepted.',
  'unsupported-response': 'X returned a response outside the supported format or size. No new passport was accepted.',
};

function ConnectX() {
  const [state, setState] = useState('idle');
  const [code, setCode] = useState('');
  const [host, setHost] = useState('');
  const [bytes, setBytes] = useState<number>();
  const [sourceStatus, setSourceStatus] = useState<number>();
  const [disclosure, setDisclosure] = useState(false);
  const [diagnostics, setDiagnostics] = useState<LoginDiagnostic[]>([]);
  const [backgroundReady, setBackgroundReady] = useState(false);
  const [proofMode, setProofMode] = useState(false);
  const [laboratory, setLaboratory] = useState(false);
  const [proofStage, setProofStage] = useState('starting');
  const [expiresAt, setExpiresAt] = useState<number>();
  const [passportBusy, setPassportBusy] = useState(false);
  const port = useRef<chrome.runtime.Port | undefined>(undefined);
  const installed = !!api()?.runtime?.id;
  const browserName = isFirefox() ? 'Firefox' : 'Chrome';
  useEffect(() => {
    if (!installed) return;
    const connected = api().runtime.connect({ name: 'x-source-flow' });
    let outdated = false;
    port.current = connected;
    connected.onMessage.addListener((value: unknown) => {
      if (!value || typeof value !== 'object') return;
      const message = value as Record<string, unknown>;
      if (typeof message.state !== 'string' || !states.includes(message.state)) return;
      const accepted = message.state === 'passport-ready' && message.proofMode === true && message.laboratory === false;
      if (message.verified !== accepted || message.passportAvailable !== accepted) return;
      if (message.flowVersion !== X_FLOW_VERSION) {
        outdated = true; setBackgroundReady(false); setState('error'); setCode('extension-update-required'); return;
      }
      if (outdated) return;
      setBackgroundReady(true);
      setState(message.state);
      setProofMode(message.proofMode === true);
      setLaboratory(message.laboratory === true);
      if (typeof message.proofStage === 'string' && PROOF_STAGES.includes(message.proofStage)) setProofStage(message.proofStage);
      if (Number.isSafeInteger(message.expiresAt) && Number(message.expiresAt) > 0) setExpiresAt(Number(message.expiresAt));
      setCode(typeof message.code === 'string' ? message.code : '');
      if (Number.isInteger(message.sourceHttpStatus) && Number(message.sourceHttpStatus) >= 100 && Number(message.sourceHttpStatus) <= 599) setSourceStatus(Number(message.sourceHttpStatus));
      if (message.sourceHost === 'api.x.com' || message.sourceHost === 'x.com') setHost(message.sourceHost);
      if (Number.isInteger(message.responseBytes) && Number(message.responseBytes) > 0 && Number(message.responseBytes) <= 32_768) setBytes(Number(message.responseBytes));
      const diagnostic = message.loginDiagnostic;
      if (diagnostic && typeof diagnostic === 'object') {
        const value = diagnostic as Record<string, unknown>;
        if (value.source === 'request' || value.source === 'page' || value.source === 'script') {
          const clean: LoginDiagnostic = { source: value.source };
          if (Number.isInteger(value.httpStatus) && Number(value.httpStatus) >= 100 && Number(value.httpStatus) <= 599) clean.httpStatus = Number(value.httpStatus);
          if (typeof value.networkError === 'string' && LOGIN_NETWORK_ERRORS.includes(value.networkError)) clean.networkError = value.networkError;
          if (clean.httpStatus || clean.networkError) setDiagnostics((previous) => [...previous, clean].slice(-5));
        }
      }
    });
    connected.onDisconnect.addListener(() => { void api().runtime.lastError; port.current = undefined; setBackgroundReady(false); if (!outdated) { setState('error'); setCode('background-disconnected'); } });
    return () => { port.current = undefined; connected.disconnect(); };
  }, [installed]);
  async function start() {
    if (!backgroundReady) return;
    try {
      if (!await api().permissions.request({ origins: X_ORIGINS })) { setState('error'); setCode('permission-required'); return; }
      port.current?.postMessage({ op: 'start' });
    } catch { setState('error'); setCode('permission-required'); }
  }
  const active = ['helper-check', 'login', 'context-ready', 'probing', 'proving'].includes(state);
  return <main className="x-connect">
    <a className="brand" href={installed ? api().runtime.getURL('sidepanel.html') : '/sidepanel.html'}>nockapp.</a>
    <h1>Connect X</h1>
    <p className="status-label">{proofMode ? laboratory ? 'Synthetic test · account verification unavailable' : 'Private X verification' : 'Source feasibility · verification unavailable'}</p>
    <p>{proofMode ? 'Authenticate your own X account, prove the follower threshold on this Ubuntu computer, and retain the verified evidence privately. Nothing is disclosed on a post by default.' : 'The installed helper is checked before login. A compatibility-only helper can check X’s response format, but cannot create a proof, badge or passport.'}</p>
    {!installed && <p role="alert">Open this page from the installed Ubuntu browser extension. The browser preview cannot connect to a local helper.</p>}
    {state === 'idle' && <>
      <p>NockApp will open a dedicated X window and temporarily capture its session headers. Enter passwords and MFA only on the genuine X website. Headers are kept in memory and sent to your Ubuntu helper only after your confirmation. Access to X’s public script host is used only to show connection errors, without reading script contents.</p>
      <p>Cookies, tokens and private responses are not stored in extension storage or reports. After checking the installed helper, NockApp will explain and request approval for the operation it supports.</p>
      <button disabled={!installed || !backgroundReady || passportBusy} onClick={() => { void start(); }}>Connect X</button>
    </>}
    <section aria-live="polite" aria-atomic="true">
      {state === 'helper-check' && <p>Checking the local Ubuntu helper…</p>}
      {state === 'login' && <><h2>Authenticate on X</h2><p>Use the X window with its visible address bar to log in and complete MFA. After X shows your signed-in account, open account settings below. Only this flow’s X tab is monitored; other tabs are excluded. This attempt expires after five minutes.</p><button onClick={() => port.current?.postMessage({ op: 'show-login' })}>Show X sign-in window</button><button className="secondary" onClick={() => port.current?.postMessage({ op: 'open-settings' })}>Open X account settings</button></>}
      {state === 'context-ready' && <>
        <h2>Login context captured</h2>
        <p>Account ownership is still unverified. Capture has stopped. Confirm within ten minutes to send the minimum session headers to your local helper, then directly to <strong>{host}</strong>.</p>
        {proofMode ? <>
          <p>The helper will check fresh AWS attestation against your installed policy, make the request through MPC-TLS, generate proofs here, and run a separate verifier. X receives its session headers. The notary receives encrypted protocol traffic and commitments; the verifier receives proofs and public bindings. The exact account ID and follower count stay private. Network timing and lengths remain visible.</p>
          <p>Your Ubuntu keyring must be unlocked. Accepted evidence expires after one day; follower count is a dated observation. Reusing credentials may link activity.</p>
          {laboratory && <p role="note">This helper is configured for synthetic tests. It cannot verify a real account or issue a verified passport.</p>}
          <label className="disclosure"><input type="checkbox" checked={disclosure} onChange={(e) => setDisclosure(e.target.checked)} />I approve private notarization, local proof generation and independent verification.</label>
          <button disabled={!disclosure} onClick={() => port.current?.postMessage({ op: 'prove' })}>Generate private proof</button>
        </> : <>
          <label className="disclosure"><input type="checkbox" checked={disclosure} onChange={(e) => setDisclosure(e.target.checked)} />I approve this private read-only source check. No data will be sent to a notary or verifier in this step.</label>
          <button disabled={!disclosure} onClick={() => port.current?.postMessage({ op: 'probe' })}>Check current-user endpoint</button>
        </>}
      </>}
      {state === 'probing' && <p>Checking the authenticated response format locally…</p>}
      {state === 'proving' && <><h2>Verification in progress</h2><p>{progress[proofStage]}</p><p>No new passport has been accepted yet. Keep this page open.</p></>}
      {state === 'passport-ready' && <><h2>Passport ready</h2><p>The installed independent verifier accepted your account evidence and holder-bound passport. It is stored privately by the Ubuntu helper. No post disclosure has been made.</p>{expiresAt && <p>Expires: {new Date(expiresAt * 1000).toLocaleString()}.</p>}<p>This screen is a completion notice. Passport use requires a fresh helper check and proof that you hold its key.</p></>}
      {state === 'synthetic-ready' && <><h2>Synthetic proof test passed</h2><p>The local pipeline accepted synthetic evidence. No real account was verified and no verified passport was issued.</p></>}
      {state === 'finished' && <><h2>Candidate response observed</h2><p>The endpoint returned the expected ID and follower-count fields in the same object{bytes ? ` (${bytes} response bytes)` : ''}. This is a compatibility observation. Account ownership and the claim remain unverified until genuine notarization and proof verification are implemented and pass.</p></>}
      {state === 'error' && <p role="alert">{errors[code] ?? 'The operation failed. No new passport was accepted. A previously saved passport is preserved. Review the helper installation before retrying.'}</p>}
      {state === 'error' && SOURCE_ERROR_CODES.includes(code) && <p role="status" aria-label="Source check result">Source check{host ? ` at ${host}` : ''}: {sourceStatus ? `HTTP ${sourceStatus} · ` : ''}<code>{code}</code></p>}
      {state === 'cancelled' && <p>Connection cancelled. The helper and capture have stopped.</p>}
    </section>
    {(active || diagnostics.length > 0) && <section className="login-diagnostics" aria-label="X login connection status">
      <h2>Connection status</h2>
      {diagnostics.length === 0 ? <p>No browser request statuses received yet. This does not explain X’s login failure. No login fields, headers or request bodies are read for this status.</p>
        : <ul>{diagnostics.map((item, index) => <li key={index}>{item.source === 'request' ? 'X request' : item.source === 'page' ? 'X page' : 'X script'}: {item.httpStatus ? `HTTP ${item.httpStatus}` : item.networkError}</li>)}</ul>}
      {diagnostics.some((item) => item.httpStatus === 429) && <p>X is rate-limiting a request. Wait before another attempt.</p>}
      <p>These are connection statuses only. HTTP 200 does not establish successful login or account verification.</p>
    </section>}
    {active && <button className="secondary" onClick={() => port.current?.postMessage({ op: 'cancel' })}>Cancel connection</button>}
    {code === 'extension-update-required' ? <button onClick={() => api().runtime.reload()}>Reload NockApp extension</button>
      : ['error', 'cancelled', 'finished', 'synthetic-ready', 'passport-ready'].includes(state) && <button onClick={() => window.location.reload()}>Start again</button>}
    <p className="session-note">Closing this flow stops capture and disconnects the helper. X may keep you signed in to this {browserName} profile. Closing the login window does not clear X cookies or log you out.</p>
    <PassportControls installed={installed} disabled={active} onBusy={setPassportBusy} onRefresh={() => window.location.reload()} />
    <details><summary>Install the local helper</summary><p>Use the Ubuntu proving-helper package and independently approved policy described in <code>nockapp/research/nock-mpc/source-auth/X-UBUNTU-PACKAGE.md</code>. {isFirefox() ? 'Install for Firefox ID nockapp@beegus.local.' : 'Install for the exact extension ID from chrome://extensions.'} Replacing a compatibility-only helper requires the installer’s explicit replacement option. No sudo is needed. Keep the same installed extension to preserve its discussion data.</p></details>
  </main>;
}

createRoot(document.getElementById('root')!).render(<StrictMode><ConnectX /></StrictMode>);
