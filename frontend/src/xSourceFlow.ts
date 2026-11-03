import { api, isFirefox } from './platform/browser';
/** Capture stays in memory. Only the independently installed proof helper may accept a passport. */
export const X_ORIGINS = ['https://x.com/*', 'https://api.x.com/*', 'https://abs.twimg.com/*'];
export const NATIVE_HOST = 'com.nockapp.helper';
export const X_FLOW_VERSION = 'private-proof-7';
export const X_SOURCE_PROFILE = 'nockapp-x-viewer-feasibility-v2';
export const PROOF_BRIDGE_PROFILE = 'nockapp-x-private-proof-bridge-v1';
export const PROOF_CONSENT = 'nockapp-x-private-notarization-and-proof-v1';
export const PROOF_STAGES = ['starting', 'keyring', 'notarize', 'prepare-source', 'request-proof', 'http-proof',
  'json-proof', 'nock-proof', 'independent-verification', 'save-passport'];
export const PROOF_ERRORS = ['private-process-unavailable', 'source-preparation-failed', 'proof-deadline-expired',
  'proof-failed', 'source-size', 'notary-or-source-unavailable', 'notary-policy-rejected', 'unsupported-response',
  'registration-rejected', 'owner-operation-rejected', 'helper-busy', 'helper-operation-failed',
  'independent-verification-failed', 'passport-unavailable', 'policy-unavailable', 'job-cancelled',
  'job-deadline-expired', 'message-schema', 'keyring-unavailable', 'keyring-unconfigured', 'keyring-locked',
  'holder-key-missing', 'holder-key-invalid', 'holder-state-invalid', 'holder-busy', 'holder-storage-failed'];
export const SOURCE_ERROR_CODES = ['login-expired', 'endpoint-forbidden', 'rate-limited', 'source-connection-failed',
  'response-size', 'response-schema', 'account-id-format', 'account-id-mismatch', 'follower-count-format',
  'ambiguous-json', 'response-json', 'response-depth', 'response-framing', 'unsupported-response-framing',
  'unsupported-response-encoding', 'response-content-type', 'response-headers-size', 'unsupported-http-status',
  'request-session-context', 'request-size', 'unsupported-endpoint', 'source-response-unavailable',
  'source-query-error', 'current-user-unavailable'];
const SETTINGS = ['https://api.x.com/1.1/account/settings.json*', 'https://x.com/i/api/1.1/account/settings.json*'];
export const LOGIN_NETWORK_ERRORS = ['net::ERR_BLOCKED_BY_CLIENT', 'net::ERR_BLOCKED_BY_ADMINISTRATOR',
  'net::ERR_CONNECTION_RESET', 'net::ERR_CONNECTION_CLOSED', 'net::ERR_CONNECTION_TIMED_OUT',
  'net::ERR_TIMED_OUT', 'net::ERR_NAME_NOT_RESOLVED', 'net::ERR_NETWORK_CHANGED',
  'net::ERR_HTTP2_PROTOCOL_ERROR', 'net::ERR_QUIC_PROTOCOL_ERROR', 'net::ERR_CERT_AUTHORITY_INVALID',
  'net::ERR_CERT_DATE_INVALID', 'net::ERR_PROXY_CONNECTION_FAILED', 'net::ERR_TUNNEL_CONNECTION_FAILED',
  'net::ERR_SSL_PROTOCOL_ERROR', 'net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH', 'net::ERR_ADDRESS_UNREACHABLE',
  'net::ERR_CONNECTION_REFUSED', 'net::ERR_INTERNET_DISCONNECTED', 'net::ERR_NETWORK_ACCESS_DENIED',
  'net::ERR_ABORTED', 'network-error'];
export type LoginDiagnostic = { source: 'request' | 'page' | 'script'; httpStatus?: number; networkError?: string };
type Context = { cookie: string; csrf: string; authorization: string };
type State = 'idle' | 'helper-check' | 'login' | 'context-ready' | 'probing' | 'proving' | 'finished' | 'passport-ready' | 'synthetic-ready' | 'error' | 'cancelled';
const id = () => crypto.randomUUID().replaceAll('-', '');
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

export function captureContext(details: chrome.webRequest.OnBeforeSendHeadersDetails): Context | undefined {
  const url = new URL(details.url);
  if (details.method !== 'GET' || !((url.origin === 'https://api.x.com' && url.pathname === '/1.1/account/settings.json')
      || (url.origin === 'https://x.com' && url.pathname === '/i/api/1.1/account/settings.json'))) return;
  if (!details.requestHeaders || details.requestHeaders.length > 128) return;
  const values: Record<string, string> = {};
  for (const header of details.requestHeaders) {
    const key = header.name.toLowerCase();
    if (!['cookie', 'x-csrf-token', 'authorization'].includes(key)) continue;
    if (key in values || !header.value || header.value.length > 16_384 || /[^\x20-\x7e]/.test(header.value)) return;
    values[key] = header.value;
  }
  if (!values.authorization?.startsWith('Bearer ') || !values['x-csrf-token'] || !values.cookie) return;
  const cookies: Record<string, string> = {};
  for (const piece of values.cookie.split(';')) {
    const split = piece.trim().indexOf('=');
    const key = piece.trim().slice(0, split);
    if (!['auth_token', 'ct0'].includes(key)) continue;
    if (split < 1 || key in cookies || !piece.trim().slice(split + 1)) return;
    cookies[key] = piece.trim().slice(split + 1);
  }
  if (!cookies.auth_token || cookies.ct0 !== values['x-csrf-token']) return;
  return { cookie: `auth_token=${cookies.auth_token}; ct0=${cookies.ct0}`, csrf: cookies.ct0, authorization: values.authorization };
}

export function attachXSourceFlow(ui: chrome.runtime.Port) {
  let state: State = 'idle';
  let native: chrome.runtime.Port | undefined;
  let windowId: number | undefined;
  let loginTabId: number | undefined;
  let context: Context | undefined;
  let proofMode = false;
  let laboratory = false;
  const endpoint = 'browser-viewer-v2';
  let pending = '';
  let active = true;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let listening = false;
  const publish = (next: State, code?: string, extra: Record<string, unknown> = {}) => {
    state = next;
    try { ui.postMessage({ state, code, flowVersion: X_FLOW_VERSION, proofMode, laboratory,
      verified: false, passportAvailable: false, ...extra }); } catch { /* UI has closed. */ }
  };
  const stopCapture = () => {
    if (listening) {
      api().webRequest.onBeforeSendHeaders.removeListener(onHeadersListener);
      api().webRequest.onCompleted.removeListener(onLoginResponse);
      api().webRequest.onErrorOccurred.removeListener(onLoginNetworkError);
    }
    listening = false;
  };
  const cleanup = () => {
    active = false; clearTimeout(timer); context = undefined; stopCapture();
    api().windows.onRemoved.removeListener(onWindowRemoved);
    api().tabs.onRemoved.removeListener(onTabRemoved);
    const closing = native; native = undefined;
    closing?.disconnect();
    // Close only our login tab; preserve any unrelated tabs the user added to
    // the normal browser window. Chrome closes the window if it becomes empty.
    if (loginTabId !== undefined) void api().tabs.remove(loginTabId).catch(() => {});
    else if (windowId !== undefined) void api().windows.remove(windowId).catch(() => {});
    windowId = undefined; loginTabId = undefined;
    void api().permissions.remove({ origins: X_ORIGINS }).catch(() => {});
  };
  const fail = (code: string, extra: Record<string, unknown> = {}) => { publish('error', code, extra); cleanup(); };
  const deadline = (ms: number) => {
    clearTimeout(timer); timer = setTimeout(() => { if (active) fail('flow-expired'); }, ms);
  };
  function onHeadersListener(details: chrome.webRequest.OnBeforeSendHeadersDetails) {
    void onHeaders(details);
    return undefined;
  }
  function diagnosticSource(details: chrome.webRequest.WebRequestDetails): LoginDiagnostic['source'] | undefined {
    if (!active || state !== 'login' || details.tabId !== loginTabId) return;
    const url = new URL(details.url);
    const xHost = url.origin === 'https://x.com' || url.origin === 'https://api.x.com';
    if (details.type === 'xmlhttprequest' && xHost) return 'request';
    if (details.type === 'main_frame' && url.origin === 'https://x.com') return 'page';
    if (details.type === 'script' && (xHost || url.origin === 'https://abs.twimg.com')) return 'script';
  }
  function onLoginResponse(details: chrome.webRequest.OnCompletedDetails) {
    const source = diagnosticSource(details);
    if (source && Number.isInteger(details.statusCode) && details.statusCode >= 100 && details.statusCode <= 599) {
      // Only a fixed category and numeric status leave this callback. No
      // header/body extraInfoSpec, URL/query, identifier or response is retained.
      publish('login', undefined, { loginDiagnostic: { source, httpStatus: details.statusCode } });
    }
  }
  function onLoginNetworkError(details: chrome.webRequest.OnErrorOccurredDetails) {
    const source = diagnosticSource(details);
    if (source) publish('login', undefined, { loginDiagnostic: { source,
      networkError: LOGIN_NETWORK_ERRORS.includes(details.error) ? details.error : 'network-error' } });
  }
  async function onHeaders(details: chrome.webRequest.OnBeforeSendHeadersDetails) {
    if (!active || state !== 'login' || details.tabId !== loginTabId) return;
    try {
      const tab = await api().tabs.get(details.tabId);
      if (!active || state !== 'login' || windowId === undefined || tab.windowId !== windowId) return;
      const captured = captureContext(details);
      if (!captured) return;
      context = captured;
      stopCapture(); deadline(10 * 60_000);
      publish('context-ready', undefined, { sourceHost: 'api.x.com' });
    } catch { /* A tab can close during capture. No payload or raw error is logged. */ }
  }
  function onWindowRemoved(closed: number) {
    if (active && closed === windowId) { publish('cancelled', 'login-window-closed'); cleanup(); }
  }
  function onTabRemoved(closed: number) {
    if (active && closed === loginTabId) { publish('cancelled', 'login-window-closed'); cleanup(); }
  }
  async function onNative(message: unknown) {
    if (!active || !record(message) || message.id !== pending) return;
    if (state !== 'proving' && (message.verified !== false || message.passport_issuance_allowed !== false)) { fail('unsupported-helper'); return; }
    if (state === 'helper-check') {
      proofMode = message.status === 'ready' && message.protocol === 2 && message.bridge_profile === PROOF_BRIDGE_PROFILE
        && message.consent_profile === PROOF_CONSENT && message.proving_available === true
        && message.passport_available === true && typeof message.laboratory === 'boolean';
      laboratory = proofMode && message.laboratory === true;
      if (!proofMode && (message.status !== 'ready' || message.protocol !== 1 || message.source_profile !== X_SOURCE_PROFILE || message.stage !== 'source-feasibility'
          || message.proving_available !== false || message.passport_available !== false || message.source_probe_available !== true)) {
        fail('unsupported-helper'); return;
      }
      try {
        publish('login'); deadline(300_000);
        api().windows.onRemoved.addListener(onWindowRemoved);
        api().tabs.onRemoved.addListener(onTabRemoved);
        // Get the tab ID and register observers before any X navigation so the
        // initial page itself tests whether browser events reach this flow.
        const opened = await api().windows.create({ url: 'about:blank', type: 'normal', width: 1050, height: 850 });
        if (!active) { if (opened?.id !== undefined) void api().windows.remove(opened.id).catch(() => {}); return; }
        windowId = opened?.id;
        if (windowId === undefined) { fail('login-window-unavailable'); return; }
        loginTabId = opened?.tabs?.[0]?.id ?? (await api().tabs.query({ windowId }))[0]?.id;
        if (!active) return;
        if (loginTabId === undefined) { fail('login-window-unavailable'); return; }
        listening = true;
        api().webRequest.onBeforeSendHeaders.addListener(onHeadersListener,
          { urls: SETTINGS, tabId: loginTabId, types: ['xmlhttprequest'] }, isFirefox() ? ['requestHeaders'] : ['requestHeaders', 'extraHeaders']);
        // Metadata only across the already approved hosts in this exact tab.
        // Do not assume X keeps its onboarding API/script paths unchanged.
        // Never request bodies, headers or error payloads for diagnostics.
        const statusFilter = { urls: X_ORIGINS, tabId: loginTabId,
          types: ['main_frame', 'xmlhttprequest', 'script'] as chrome.webRequest.ResourceType[] };
        api().webRequest.onCompleted.addListener(onLoginResponse, statusFilter);
        api().webRequest.onErrorOccurred.addListener(onLoginNetworkError, statusFilter);
        await api().tabs.update(loginTabId, { url: 'https://x.com/i/flow/login' });
      } catch { fail('login-window-unavailable'); }
    } else if (state === 'proving') {
      if (message.type === 'progress' && message.verified === false && message.passport_issuance_allowed === false
          && typeof message.stage === 'string' && PROOF_STAGES.includes(message.stage)) {
        publish('proving', undefined, { proofStage: message.stage }); return;
      }
      const now = Math.floor(Date.now() / 1000);
      const expectedStatus = laboratory ? 'synthetic-archive-ready' : 'passport-ready';
      const facts = message.facts;
      if (message.status === expectedStatus && message.laboratory === laboratory
          && message.verified === !laboratory && message.passport_issuance_allowed === !laboratory
          && message.holder_bound === true && message.disclosure === 'none'
          && Array.isArray(facts) && (JSON.stringify(facts) === '["account-controlled"]'
            || JSON.stringify(facts) === '["account-controlled","followers-over-10000"]')
          && Number.isSafeInteger(message.observed_at) && Number(message.observed_at) > 0
          && Number(message.observed_at) <= now + 5 && Number.isSafeInteger(message.expires_at)
          && Number(message.expires_at) > now && Number(message.expires_at) > Number(message.observed_at)
          && Number(message.expires_at) <= Number(message.observed_at) + 86400) {
        publish(laboratory ? 'synthetic-ready' : 'passport-ready', undefined, {
          verified: !laboratory, passportAvailable: !laboratory, facts: [...facts],
          observedAt: message.observed_at, expiresAt: message.expires_at,
        });
        cleanup(); return;
      }
      fail(message.status === 'rejected' && message.verified === false && message.passport_issuance_allowed === false
        && typeof message.code === 'string' && [...SOURCE_ERROR_CODES, ...PROOF_ERRORS].includes(message.code)
        ? message.code : 'independent-verification-failed');
    } else if (state === 'probing') {
      // Forward a whitelist of nonsensitive summary fields. No native payload is
      // persisted, logged or interpreted as a credential/verified badge.
      if (message.status === 'candidate-schema-observed' && message.account_control_established === false
          && message.notarized === false && message.stable_account_id_present === true
          && message.same_object_follower_count_present === true
          && Number.isInteger(message.response_body_bytes) && Number(message.response_body_bytes) <= 32_768
          && Number(message.response_body_bytes) > 0 && message.http_status === 200) {
        publish('finished', 'candidate-schema-observed', { responseBytes: message.response_body_bytes });
        cleanup(); return;
      }
      const summary = Number.isInteger(message.http_status) && Number(message.http_status) >= 100 && Number(message.http_status) <= 599
        ? { sourceHttpStatus: Number(message.http_status) } : {};
      fail(typeof message.code === 'string' && SOURCE_ERROR_CODES.includes(message.code) ? message.code : 'source-response-unavailable', summary);
    }
  }
  const onUi = async (message: unknown) => {
    if (!active || !record(message) || Object.keys(message).length !== 1) return;
    if (message.op === 'cancel') { publish('cancelled'); cleanup(); return; }
    if (message.op === 'start' && state === 'idle') {
      publish('helper-check'); deadline(10_000);
      try {
        if (!await api().permissions.contains({ origins: X_ORIGINS })) { fail('permission-required'); return; }
        if (!active) return;
        native = api().runtime.connectNative(NATIVE_HOST);
        native.onMessage.addListener(onNative);
        native.onDisconnect.addListener(() => { void api().runtime.lastError; if (active) fail('helper-unavailable'); });
        pending = id(); native.postMessage({ id: pending, op: 'capabilities' });
      } catch { fail('helper-unavailable'); }
    } else if (message.op === 'show-login' && state === 'login' && loginTabId !== undefined) {
      await api().tabs.update(loginTabId, { active: true });
      if (active && windowId !== undefined) await api().windows.update(windowId, { focused: true });
    } else if (message.op === 'open-settings' && state === 'login' && loginTabId !== undefined) {
      await api().tabs.update(loginTabId, { url: 'https://x.com/settings/account' });
      if (active && windowId !== undefined) await api().windows.update(windowId, { focused: true });
    } else if (message.op === 'prove' && proofMode && state === 'context-ready' && context && native) {
      publish('proving', undefined, { proofStage: 'starting' }); deadline(180_000);
      const privateContext = context; context = undefined;
      pending = id(); native.postMessage({ id: pending, op: 'prove_x', consent: PROOF_CONSENT, context: privateContext });
    } else if (message.op === 'probe' && !proofMode && state === 'context-ready' && context && native) {
      publish('probing'); deadline(30_000);
      const privateContext = context; context = undefined;
      pending = id(); native.postMessage({ id: pending, op: 'probe_x', endpoint, context: privateContext });
    }
  };
  ui.onMessage.addListener((message: unknown) => { void onUi(message).catch(() => fail('flow-unavailable')); });
  ui.onDisconnect.addListener(cleanup);
  publish('idle');
}
