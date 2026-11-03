import { test, expect } from '@playwright/test';
import { attachXSourceFlow, captureContext, X_FLOW_VERSION, X_SOURCE_PROFILE, PROOF_BRIDGE_PROFILE, PROOF_CONSENT, PROOF_STAGES } from '../src/xSourceFlow';

type Details = chrome.webRequest.OnBeforeSendHeadersDetails;
class Signal<T> {
  listeners = new Set<(value: T) => unknown>();
  registrations: unknown[][] = [];
  addListener = (callback: (value: T) => unknown, ...options: unknown[]) => { this.listeners.add(callback); this.registrations.push(options); };
  removeListener = (callback: (value: T) => unknown) => { this.listeners.delete(callback); };
  emit = async (value: T) => { await Promise.all([...this.listeners].map((callback) => callback(value))); };
}
const fixtureHeaders = () => [
  { name: 'Cookie', value: 'tracking=discard;auth_token=synthetic_private_auth;ct0=synthetic_private_csrf' },
  { name: 'x-csrf-token', value: 'synthetic_private_csrf' },
  { name: 'Authorization', value: 'Bearer synthetic_private_bearer' },
];
function details(update: Partial<Details> = {}): Details {
  return { url: 'https://api.x.com/1.1/account/settings.json', method: 'GET', tabId: 1,
    requestId: 'synthetic', frameId: 0, parentFrameId: -1, timeStamp: 1, type: 'xmlhttprequest', documentLifecycle: 'active', frameType: 'outermost_frame',
    requestHeaders: fixtureHeaders(), ...update };
}
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

function environment() {
  const uiMessages: Record<string, unknown>[] = [];
  const nativeMessages: Record<string, unknown>[] = [];
  const removedWindows: number[] = [];
  const removedTabs: number[] = [];
  const navigations: unknown[] = [];
  const openedWindows: unknown[] = [];
  const focusedWindows: unknown[] = [];
  const revoked: unknown[] = [];
  const headers = new Signal<Details>();
  const completed = new Signal<chrome.webRequest.OnCompletedDetails>();
  const networkErrors = new Signal<chrome.webRequest.OnErrorOccurredDetails>();
  const removed = new Signal<number>();
  const tabRemoved = new Signal<number>();
  let disconnected = false;
  const ui = { onMessage: new Signal<unknown>(), onDisconnect: new Signal<undefined>(),
    postMessage: (value: Record<string, unknown>) => uiMessages.push(value) };
  const native = { onMessage: new Signal<unknown>(), onDisconnect: new Signal<undefined>(),
    postMessage: (value: Record<string, unknown>) => nativeMessages.push(value),
    disconnect: () => { disconnected = true; } };
  const api = {
    runtime: { connectNative: () => native, lastError: undefined },
    tabs: { onRemoved: tabRemoved, get: async (tabId: number) => ({ windowId: [1, 2].includes(tabId) ? 12 : 99 }),
      query: async () => [{ id: 1 }], remove: async (value: number) => { removedTabs.push(value); },
      update: async (tabId: number, update: unknown) => { navigations.push({ tabId, update }); } },
    windows: { onRemoved: removed, create: async (options: unknown) => { openedWindows.push(options); return { id: 12, tabs: [{ id: 1 }] }; },
      update: async (windowId: number, update: unknown) => { focusedWindows.push({ windowId, update }); }, remove: async (value: number) => { removedWindows.push(value); } },
    permissions: { contains: async () => true, remove: async (value: unknown) => { revoked.push(value); return true; } },
    webRequest: { onBeforeSendHeaders: headers, onCompleted: completed, onErrorOccurred: networkErrors },
  };
  Object.defineProperty(globalThis, 'chrome', { value: api, configurable: true });
  attachXSourceFlow(ui as unknown as chrome.runtime.Port);
  return { ui, native, api, headers, completed, networkErrors, removed, tabRemoved, uiMessages, nativeMessages, removedWindows, removedTabs, navigations, openedWindows, focusedWindows, revoked,
    disconnected: () => disconnected,
    start: async (proof = false, laboratory = false) => {
      await ui.onMessage.emit({ op: 'start' }); await tick();
      if (proof) {
        await native.onMessage.emit({ id: nativeMessages[0].id, status: 'ready', verified: false,
          passport_issuance_allowed: false, protocol: 2, bridge_profile: PROOF_BRIDGE_PROFILE,
          consent_profile: PROOF_CONSENT, proving_available: true, passport_available: true, laboratory });
        return;
      }
      await native.onMessage.emit({ id: nativeMessages[0].id, status: 'ready', verified: false,
        passport_issuance_allowed: false, stage: 'source-feasibility', protocol: 1, source_profile: X_SOURCE_PROFILE,
        source_probe_available: true, proving_available: false, passport_available: false });
    },
    close: async () => { await ui.onDisconnect.emit(undefined); Reflect.deleteProperty(globalThis, 'chrome'); },
  };
}

test('capture accepts only current-user settings headers and strips unrelated cookies', () => {
  expect(captureContext(details())).toEqual({ cookie: 'auth_token=synthetic_private_auth; ct0=synthetic_private_csrf',
    csrf: 'synthetic_private_csrf', authorization: 'Bearer synthetic_private_bearer' });
  for (const url of ['https://evil.test/1.1/account/settings.json', 'https://api.x.com/1.1/users/show.json',
    'https://api.x.com.evil.test/1.1/account/settings.json', 'https://api.x.com/1.1/account/settings.json/extra']) {
    expect(captureContext(details({ url }))).toBeUndefined();
  }
  expect(captureContext(details({ method: 'POST' }))).toBeUndefined();
});

function proofResult(laboratory = false): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { status: laboratory ? 'synthetic-archive-ready' : 'passport-ready', verified: !laboratory,
    passport_issuance_allowed: !laboratory, laboratory, holder_bound: true, disclosure: 'none',
    facts: ['account-controlled', 'followers-over-10000'], observed_at: now - 1, expires_at: now + 86399 };
}

test('proof helper needs its distinct disclosure operation; progress and accepted summary contain no secrets', async () => {
  const e = environment();
  try {
    await e.start(true); await e.headers.emit(details()); await tick();
    expect(e.uiMessages.at(-1)).toMatchObject({ proofMode: true, laboratory: false, state: 'context-ready', verified: false });
    await e.ui.onMessage.emit({ op: 'probe' }); await tick();
    expect(e.nativeMessages).toHaveLength(1);
    await e.ui.onMessage.emit({ op: 'prove' }); await tick();
    const request = e.nativeMessages.at(-1)!;
    expect(request).toMatchObject({ op: 'prove_x', consent: PROOF_CONSENT,
      context: { csrf: 'synthetic_private_csrf' } });
    expect(request).not.toHaveProperty('endpoint');
    for (const stage of PROOF_STAGES) {
      await e.native.onMessage.emit({ id: request.id, type: 'progress', stage, verified: false,
        passport_issuance_allowed: false, secret: 'synthetic_private_progress' });
      expect(e.uiMessages.at(-1)).toMatchObject({ state: 'proving', proofStage: stage, verified: false, passportAvailable: false });
    }
    await e.native.onMessage.emit({ id: request.id, ...proofResult(), private: 'synthetic_private_result' });
    expect(e.uiMessages.at(-1)).toMatchObject({ state: 'passport-ready', verified: true, passportAvailable: true });
    expect(JSON.stringify(e.uiMessages)).not.toContain('synthetic_private');
    expect(e.disconnected()).toBe(true);
    expect(e.headers.listeners.size).toBe(0);
  } finally { await e.close(); }
});

test('synthetic proof results stay synthetic and cannot become a verified passport', async () => {
  for (const relabel of [false, true]) {
    const e = environment();
    try {
      await e.start(true, true); await e.headers.emit(details()); await tick();
      await e.ui.onMessage.emit({ op: 'prove' }); await tick();
      await e.native.onMessage.emit({ id: e.nativeMessages.at(-1)?.id, ...proofResult(!relabel) });
      expect(e.uiMessages.at(-1)).toMatchObject({ state: relabel ? 'error' : 'synthetic-ready', verified: false, passportAvailable: false });
    } finally { await e.close(); }
  }
});

test('proof completion rejects unbound, expired, future, overlong and unsupported claims', async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const change of [{ holder_bound: false }, { expires_at: now - 1 }, { observed_at: now + 60 },
    { expires_at: now + 172800 }, { facts: ['account-controlled', 'exact-followers'] }, { verified: false },
    { disclosure: 'public' }, { laboratory: true }, { observed_at: 'synthetic_private_time' }]) {
    const e = environment();
    try {
      await e.start(true); await e.headers.emit(details()); await tick();
      await e.ui.onMessage.emit({ op: 'prove' }); await tick();
      await e.native.onMessage.emit({ id: e.nativeMessages.at(-1)?.id, ...proofResult(), ...change });
      expect(e.uiMessages.at(-1)).toMatchObject({ state: 'error', verified: false, passportAvailable: false });
      expect(JSON.stringify(e.uiMessages)).not.toContain('synthetic_private');
    } finally { await e.close(); }
  }
});

test('proof cancellation closes the native port and ignores a late accepted result', async () => {
  const e = environment();
  try {
    await e.start(true); await e.headers.emit(details()); await tick();
    await e.ui.onMessage.emit({ op: 'prove' }); await tick();
    await e.ui.onMessage.emit({ op: 'cancel' }); await tick();
    await e.native.onMessage.emit({ id: e.nativeMessages.at(-1)?.id, ...proofResult() });
    expect(e.uiMessages.at(-1)).toMatchObject({ state: 'cancelled', verified: false });
    expect(e.disconnected()).toBe(true); expect(e.revoked).toHaveLength(1);
  } finally { await e.close(); }
});

test('proof helper cannot request the old source-only consent or pass arbitrary errors to the UI', async () => {
  const e = environment();
  try {
    await e.ui.onMessage.emit({ op: 'start' }); await tick();
    await e.native.onMessage.emit({ id: e.nativeMessages[0].id, status: 'ready', protocol: 2, verified: false,
      passport_issuance_allowed: false, bridge_profile: PROOF_BRIDGE_PROFILE, consent_profile: 'old-consent',
      proving_available: true, passport_available: true, laboratory: false });
    expect(e.uiMessages.at(-1)).toMatchObject({ state: 'error', code: 'unsupported-helper' });
    expect(e.openedWindows).toHaveLength(0);
  } finally { await e.close(); }
  for (const code of ['keyring-locked', 'synthetic_private_error']) {
    const e = environment();
    try {
      await e.start(true); await e.headers.emit(details()); await tick();
      await e.ui.onMessage.emit({ op: 'prove' }); await tick();
      await e.native.onMessage.emit({ id: e.nativeMessages.at(-1)?.id, status: 'rejected', code,
        verified: false, passport_issuance_allowed: false, body: 'synthetic_private_response' });
      expect(e.uiMessages.at(-1)).toMatchObject({ state: 'error', code: code === 'keyring-locked' ? code : 'independent-verification-failed' });
      expect(JSON.stringify(e.uiMessages)).not.toContain('synthetic_private');
    } finally { await e.close(); }
  }
});

test('ambiguous headers, cookie substitution and header injection are rejected', () => {
  const sets = [
    [...fixtureHeaders(), { name: 'cookie', value: 'extra=synthetic' }],
    fixtureHeaders().map((h) => h.name === 'x-csrf-token' ? { ...h, value: 'wrong' } : h),
    fixtureHeaders().map((h) => h.name === 'Authorization' ? { ...h, value: 'Bearer x\r\nInjected: x' } : h),
    fixtureHeaders().map((h) => h.name === 'Cookie' ? { ...h, value: h.value + ';ct0=another' } : h),
  ];
  for (const requestHeaders of sets) expect(captureContext(details({ requestHeaders }))).toBeUndefined();
});

test('only the dedicated login window supplies context; capture stops before private source request', async () => {
  const e = environment();
  try {
    await e.start();
    await e.headers.emit(details({ tabId: 99 })); await tick();
    expect(e.uiMessages.at(-1)?.state).toBe('login');
    await e.headers.emit(details({ tabId: 2 })); await tick();
    expect(e.uiMessages.at(-1)?.state).toBe('login');
    await e.headers.emit(details()); await tick();
    expect(e.uiMessages.at(-1)?.state).toBe('context-ready');
    expect(e.headers.listeners.size).toBe(0);
    expect(e.nativeMessages).toHaveLength(1);
    expect(JSON.stringify(e.uiMessages)).not.toContain('synthetic_private');
    await e.ui.onMessage.emit({ op: 'probe' }); await tick();
    expect(e.nativeMessages.at(-1)).toMatchObject({ op: 'probe_x', endpoint: 'browser-viewer-v2' });
    expect(e.nativeMessages.at(-1)?.context).toHaveProperty('csrf', 'synthetic_private_csrf');
    await e.native.onMessage.emit({ id: e.nativeMessages.at(-1)?.id, verified: false, passport_issuance_allowed: false,
      status: 'candidate-schema-observed', account_control_established: false, notarized: false,
      stable_account_id_present: true, same_object_follower_count_present: true, http_status: 200, response_body_bytes: 210 });
    expect(e.uiMessages.at(-1)).toMatchObject({ state: 'finished', verified: false, passportAvailable: false });
    expect(e.disconnected()).toBe(true); expect(e.removedTabs).toEqual([1]); expect(e.removedWindows).toEqual([]);
    expect(e.revoked).toHaveLength(1);
  } finally { await e.close(); }
});

test('cancellation after capture clears access without sending session headers to the helper', async () => {
  const e = environment();
  try {
    await e.start(); await e.headers.emit(details()); await tick();
    await e.ui.onMessage.emit({ op: 'cancel' }); await tick();
    await e.ui.onMessage.emit({ op: 'probe' }); await tick();
    expect(e.nativeMessages).toHaveLength(1);
    expect(e.headers.listeners.size).toBe(0); expect(e.removed.listeners.size).toBe(0);
    expect(e.uiMessages.at(-1)?.state).toBe('cancelled');
    expect(e.disconnected()).toBe(true);
  } finally { await e.close(); }
});

test('window closure, UI closure and helper failure all stop interception', async () => {
  for (const action of ['window', 'tab', 'ui', 'helper']) {
    const e = environment();
    try {
      await e.start();
      if (action === 'window') await e.removed.emit(12);
      if (action === 'tab') await e.tabRemoved.emit(1);
      if (action === 'ui') await e.ui.onDisconnect.emit(undefined);
      if (action === 'helper') await e.native.onDisconnect.emit(undefined);
      expect(e.headers.listeners.size).toBe(0);
      expect(e.completed.listeners.size).toBe(0);
      expect(e.networkErrors.listeners.size).toBe(0);
      expect(e.removed.listeners.size).toBe(0);
      expect(e.tabRemoved.listeners.size).toBe(0);
      expect(e.disconnected()).toBe(true);
      expect(e.uiMessages.every((m) => m.verified === false && m.passportAvailable === false)).toBe(true);
    } finally { await e.close(); }
  }
});

test('a helper cannot upgrade this stage into a verified credential', async () => {
  const e = environment();
  try {
    await e.ui.onMessage.emit({ op: 'start' }); await tick();
    await e.native.onMessage.emit({ id: e.nativeMessages[0].id, status: 'ready', verified: true, passport_issuance_allowed: true });
    expect(e.uiMessages.at(-1)).toMatchObject({ state: 'error', code: 'unsupported-helper', verified: false });
    expect(e.headers.listeners.size).toBe(0);
  } finally { await e.close(); }
});

test('an old or mismatched helper source profile cannot receive session context', async () => {
  for (const source_profile of [undefined, 'nockapp-x-source-feasibility-v1']) {
    const e = environment();
    try {
      await e.ui.onMessage.emit({ op: 'start' }); await tick();
      await e.native.onMessage.emit({ id: e.nativeMessages[0].id, status: 'ready', verified: false,
        passport_issuance_allowed: false, stage: 'source-feasibility', protocol: 1, source_profile,
        source_probe_available: true, proving_available: false, passport_available: false });
      expect(e.uiMessages.at(-1)).toMatchObject({ state: 'error', code: 'unsupported-helper' });
      expect(e.headers.listeners.size).toBe(0);
      expect(e.openedWindows).toEqual([]);
      expect(e.nativeMessages).toHaveLength(1);
    } finally { await e.close(); }
  }
});

test('source failures expose only a fixed code and bounded HTTP status, never native error content', async () => {
  for (const source of [
    { code: 'unsupported-http-status', http_status: 404, expected: 'unsupported-http-status', status: 404 },
    { code: 'synthetic_private_error', http_status: 'synthetic_private_status', expected: 'source-response-unavailable', status: undefined },
  ]) {
    const e = environment();
    try {
      await e.start(); await e.headers.emit(details()); await tick();
      await e.ui.onMessage.emit({ op: 'probe' }); await tick();
      await e.native.onMessage.emit({ id: e.nativeMessages.at(-1)?.id, verified: false, passport_issuance_allowed: false,
        status: 'rejected', code: source.code, http_status: source.http_status,
        response_body: 'synthetic_private_body', error: 'synthetic_private_error', headers: fixtureHeaders() });
      expect(e.uiMessages.at(-1)).toMatchObject({ state: 'error', code: source.expected });
      expect(e.uiMessages.at(-1)?.sourceHttpStatus).toBe(source.status);
      expect(JSON.stringify(e.uiMessages)).not.toContain('synthetic_private');
    } finally { await e.close(); }
  }
});

test('login uses a visible-address window and settings navigation stays on its managed tab', async () => {
  const e = environment();
  try {
    await e.start();
    expect(e.openedWindows).toEqual([{ url: 'about:blank', type: 'normal', width: 1050, height: 850 }]);
    await e.ui.onMessage.emit({ op: 'open-settings' }); await tick();
    expect(e.navigations).toEqual([{ tabId: 1, update: { url: 'https://x.com/i/flow/login' } },
      { tabId: 1, update: { url: 'https://x.com/settings/account' } }]);
    expect(e.nativeMessages).toHaveLength(1);
    await e.ui.onMessage.emit({ op: 'cancel' });
    await e.ui.onMessage.emit({ op: 'open-settings' }); await tick();
    expect(e.navigations).toHaveLength(2);
    expect(e.removedWindows).toEqual([]);
    expect(e.removedTabs).toEqual([1]);
  } finally { await e.close(); }
});

test('the background identifies its version and focuses only its existing login tab without navigating', async () => {
  const e = environment();
  try {
    expect(e.uiMessages[0]).toMatchObject({ flowVersion: X_FLOW_VERSION, state: 'idle' });
    await e.ui.onMessage.emit({ op: 'show-login' }); await tick();
    expect(e.navigations).toEqual([]);
    await e.start();
    await e.ui.onMessage.emit({ op: 'show-login' }); await tick();
    expect(e.navigations).toEqual([{ tabId: 1, update: { url: 'https://x.com/i/flow/login' } },
      { tabId: 1, update: { active: true } }]);
    expect(e.focusedWindows).toEqual([{ windowId: 12, update: { focused: true } }]);
    expect(e.nativeMessages).toHaveLength(1);
    await e.ui.onMessage.emit({ op: 'cancel' });
    await e.ui.onMessage.emit({ op: 'show-login' }); await tick();
    expect(e.navigations).toHaveLength(2);
    expect(e.focusedWindows).toHaveLength(1);
  } finally { await e.close(); }
});

test('a failed permission check cannot start capture or open the helper', async () => {
  const e = environment();
  e.api.permissions.contains = async () => false;
  try {
    await e.ui.onMessage.emit({ op: 'start' }); await tick();
    expect(e.nativeMessages).toHaveLength(0);
    expect(e.uiMessages.at(-1)).toMatchObject({ state: 'error', code: 'permission-required' });
    expect(e.headers.listeners.size).toBe(0);
  } finally { await e.close(); }
});

test('Firefox uses supported header options and the same managed-tab capture and cancellation rules', async () => {
  const e = environment();
  Object.defineProperty(globalThis, 'browser', { value: { ...e.api, sidebarAction: { open: async () => {} } }, configurable: true });
  try {
    await e.start();
    expect(e.headers.registrations[0][1]).toEqual(['requestHeaders']);
    expect(e.headers.registrations[0][0]).toMatchObject({ tabId: 1 });
    await e.headers.emit(details({ tabId: 2 })); await tick();
    expect(e.uiMessages.at(-1)?.state).toBe('login');
    await e.headers.emit(details()); await tick();
    expect(e.uiMessages.at(-1)?.state).toBe('context-ready');
    expect(e.nativeMessages).toHaveLength(1);
    await e.ui.onMessage.emit({ op: 'cancel' }); await tick();
    expect(e.headers.listeners.size).toBe(0);
    expect(e.revoked).toHaveLength(1);
    expect(JSON.stringify(e.uiMessages)).not.toContain('synthetic_private');
  } finally { await e.close(); Reflect.deleteProperty(globalThis, 'browser'); }
});

function loginResponse(update: Partial<chrome.webRequest.OnCompletedDetails> = {}): chrome.webRequest.OnCompletedDetails {
  return { ...details({ url: 'https://x.com/i/api/1.1/onboarding/task.json?flow_token=synthetic_private_query' }),
    statusCode: 403, statusLine: 'HTTP/1.1 403 synthetic_private_status_line', fromCache: false,
    responseHeaders: [{ name: 'Set-Cookie', value: 'synthetic_private_response_cookie' }], ...update };
}

test('sign-in diagnostics disclose only category and status, never login headers, body or URL', async () => {
  const e = environment();
  try {
    await e.start();
    await e.completed.emit(loginResponse());
    expect(e.uiMessages.at(-1)?.loginDiagnostic).toEqual({ source: 'request', httpStatus: 403 });
    expect(JSON.stringify(e.uiMessages)).not.toContain('synthetic_private');
    expect(JSON.stringify(e.uiMessages)).not.toContain('onboarding');
    expect(e.nativeMessages).toHaveLength(1);
    // The listener has a filter argument only; no responseHeaders or other
    // sensitive extraInfoSpec is requested from the browser.
    expect(e.completed.registrations[0]).toHaveLength(1);
    expect(e.networkErrors.registrations[0]).toHaveLength(1);
    expect(e.completed.registrations[0][0]).toMatchObject({ tabId: 1 });
    expect(e.headers.registrations[0][0]).toMatchObject({ tabId: 1 });
  } finally { await e.close(); }
});

test('network errors are whitelisted and arbitrary error text cannot leak identifiers', async () => {
  const e = environment();
  try {
    await e.start();
    const base = { ...details({ url: 'https://api.x.com/1.1/onboarding/task.json' }), fromCache: false };
    await e.networkErrors.emit({ ...base, error: 'net::ERR_CONNECTION_RESET' });
    expect(e.uiMessages.at(-1)?.loginDiagnostic).toEqual({ source: 'request', networkError: 'net::ERR_CONNECTION_RESET' });
    await e.networkErrors.emit({ ...base, error: 'untrusted synthetic_private_error_payload' });
    expect(e.uiMessages.at(-1)?.loginDiagnostic).toEqual({ source: 'request', networkError: 'network-error' });
    expect(JSON.stringify(e.uiMessages)).not.toContain('synthetic_private');
  } finally { await e.close(); }
});

test('status observation covers new onboarding routes and initial pages without widening header capture', async () => {
  const e = environment();
  try {
    await e.start();
    const cases = [
      { url: 'https://x.com/i/jf/onboarding/web?synthetic_private_query', type: 'main_frame', source: 'page' },
      { url: 'https://x.com/i/jf/api/confirm?synthetic_private_query', type: 'xmlhttprequest', source: 'request' },
      { url: 'https://api.x.com/2/onboarding/confirm?synthetic_private_query', type: 'xmlhttprequest', source: 'request' },
      { url: 'https://abs.twimg.com/new-login/bootstrap.js?synthetic_private_query', type: 'script', source: 'script' },
    ] as const;
    for (const { url, type, source } of cases) {
      await e.completed.emit(loginResponse({ url, type, statusCode: 200 }));
      expect(e.uiMessages.at(-1)?.loginDiagnostic).toEqual({ source, httpStatus: 200 });
      expect(captureContext(details({ url }))).toBeUndefined();
    }
    expect(e.headers.registrations[0][0]).toMatchObject({ urls: [
      'https://api.x.com/1.1/account/settings.json*', 'https://x.com/i/api/1.1/account/settings.json*',
    ] });
    expect(JSON.stringify(e.uiMessages)).not.toContain('synthetic_private');
    expect(e.nativeMessages).toHaveLength(1);
  } finally { await e.close(); }
});

test('diagnostics exclude other tabs and hosts, and stop when context is captured', async () => {
  const e = environment();
  try {
    await e.start();
    const before = e.uiMessages.length;
    for (const change of [{ tabId: 2 }, { tabId: 99 }, { url: 'https://evil.test/1.1/onboarding/task.json' },
      { tabId: -1 }, { url: 'https://api.x.com.evil.test/1.1/onboarding/task.json' }]) {
      await e.completed.emit(loginResponse(change));
    }
    expect(e.uiMessages).toHaveLength(before);
    await e.completed.emit(loginResponse({ type: 'script', url: 'https://abs.twimg.com/responsive-web/client-web/login.synthetic.js', statusCode: 404 }));
    expect(e.uiMessages.at(-1)?.loginDiagnostic).toEqual({ source: 'script', httpStatus: 404 });
    await e.headers.emit(details()); await tick();
    expect(e.completed.listeners.size).toBe(0);
    expect(e.networkErrors.listeners.size).toBe(0);
    const captured = e.uiMessages.length;
    await e.completed.emit(loginResponse());
    expect(e.uiMessages).toHaveLength(captured);
  } finally { await e.close(); }
});
