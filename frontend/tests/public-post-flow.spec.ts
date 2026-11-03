import { test, expect } from '@playwright/test';
import { attachPublicPostFlow, PUBLIC_POST_HOST, PUBLIC_POST_PROFILE, PUBLIC_POST_VERSION, PUBLIC_CHALLENGE,
  publicProjection, publicSummary } from '../src/publicPostFlow';

class Signal<T> {
  listeners = new Set<(value: T) => unknown>();
  addListener = (fn: (value: T) => unknown) => { this.listeners.add(fn); };
  removeListener = (fn: (value: T) => unknown) => { this.listeners.delete(fn); };
  emit = async (value: T) => { await Promise.all([...this.listeners].map(fn => fn(value))); };
}
function environment() {
  const uiMessages: Record<string, unknown>[] = [];
  const ports: { onMessage: Signal<unknown>; onDisconnect: Signal<undefined>; messages: Record<string, unknown>[]; disconnected: boolean; disconnect: () => void; postMessage: (v: Record<string, unknown>) => void }[] = [];
  const hosts: string[] = [];
  const forbidden = () => { throw new Error('No browsing/storage access is allowed'); };
  const ui = { onMessage: new Signal<unknown>(), onDisconnect: new Signal<undefined>(), postMessage: (v: Record<string, unknown>) => uiMessages.push(v) };
  Object.defineProperty(globalThis, 'chrome', { configurable: true, value: {
    runtime: { connectNative: (host: string) => {
      hosts.push(host);
      const port = { onMessage: new Signal<unknown>(), onDisconnect: new Signal<undefined>(), messages: [] as Record<string, unknown>[],
        disconnected: false, disconnect() { this.disconnected = true; }, postMessage(value: Record<string, unknown>) { this.messages.push(value); } };
      ports.push(port); return port;
    }, lastError: { message: 'synthetic_private_error' } },
    storage: { local: { set: forbidden }, session: { set: forbidden } }, permissions: { request: forbidden },
    webRequest: { onBeforeSendHeaders: { addListener: forbidden } }, tabs: { create: forbidden },
  } });
  attachPublicPostFlow(ui as unknown as chrome.runtime.Port);
  return { ui, uiMessages, ports, hosts,
    send: (op: string, body: Record<string, unknown> = {}) => ui.onMessage.emit({ version: PUBLIC_POST_VERSION, op, body }),
    close: async () => { await ui.onDisconnect.emit(undefined); Reflect.deleteProperty(globalThis, 'chrome'); } };
}
function summary() { return { state: 'awaiting-post', credential_saved: false, laboratory: true, verified: false,
  username: 'synthetic_user', post_text: PUBLIC_CHALLENGE + 'ab'.repeat(32), expires_at: Math.floor(Date.now() / 1000) + 600 }; }
function reply(port: { messages: Record<string, unknown>[] }, result: unknown = summary()) {
  return { profile: PUBLIC_POST_PROFILE, id: port.messages[0].id, status: 'ok', result, laboratory: true, verified: false };
}

test('finalized activation states retain private receipt recovery after the source deadline', () => {
  for (const state of ['activation-pending-finality', 'activation-replaced-or-revoked']) {
    const pending = { ...summary(), state, expires_at: Math.floor(Date.now() / 1000) - 1200 };
    expect(publicSummary(pending, 'recover')).toMatchObject({ state, credentialSaved: false, username: 'synthetic_user' });
    expect(publicSummary({ ...pending, active: true }, 'recover')).toBeUndefined();
    const { username: _username, post_text: _text, expires_at: _expiry, ...missing } = pending;
    expect(publicSummary(missing, 'recover')).toBeUndefined();
  }
});

test('public page attachment does not query the helper or use X permissions/capture/storage', async () => {
  const e = environment();
  try { expect(e.uiMessages).toEqual([{ version: PUBLIC_POST_VERSION, state: 'ready', verified: false }]); expect(e.ports).toHaveLength(0); }
  finally { await e.close(); }
});

test('only exact consented public-post operations can reach the distinct host', async () => {
  const e = environment();
  try {
    for (const [op, body] of [['begin', { username: 'synthetic_user', approve_public_profile_lookup: false }],
      ['poll-registration', { approve_source_check: false }], ['poll-registration', { approve_source_check: true, session: {} }],
      ['check-post', { post: '12345', approve_source_check: true, session: {} }], ['present', { proof: {} }],
      ['begin', { username: 'synthetic_user', approve_public_profile_lookup: true, trust: {} }],
      ['forget', { confirm_local_deletion: false }]] as const) await e.send(op, body);
    expect(e.ports).toHaveLength(0);
    await e.send('begin', { username: 'synthetic_user', approve_public_profile_lookup: true });
    expect(e.hosts).toEqual([PUBLIC_POST_HOST]);expect(e.ports[0].messages[0]).toMatchObject({ profile: PUBLIC_POST_PROFILE, operation: 'begin' });
  } finally { await e.close(); }
});

test('attested helper progress is projected without a credential, session or ID', async () => {
  const e = environment();
  try {
    await e.send('begin', { username: 'synthetic_user', approve_public_profile_lookup: true });
    const port = e.ports[0];await port.onMessage.emit(reply(port));
    expect(port.disconnected).toBe(true);
    expect(e.uiMessages.at(-1)).toEqual({ version: PUBLIC_POST_VERSION, state: 'result', verified: false,
      summary: { state: 'awaiting-post', credentialSaved: false, username: 'synthetic_user',
        postText: summary().post_text, expiresAt: summary().expires_at } });
  } finally { await e.close(); }
});

test('wrong profiles, IDs, verified flags and private extra fields fail closed without forwarding', async () => {
  const mutations: ((v: Record<string, unknown>) => void)[] = [v => { v.profile = 'legacy'; }, v => { v.id = '00'.repeat(16); },
    v => { v.verified = true; }, v => { v.laboratory = false; }, v => { v.headers = 'synthetic_private'; },
    v => { (v.result as Record<string, unknown>).session = 'synthetic_private'; },
    v => { (v.result as Record<string, unknown>).post_text = 'synthetic_private'; }];
  for (const mutate of mutations) {
    const e = environment();
    try {
      await e.send('status');const port = e.ports[0];const value = reply(port);mutate(value);await port.onMessage.emit(value);
      expect(e.uiMessages.at(-1)).toMatchObject({ state: 'error', code: 'unsupported-helper', verified: false });
      expect(JSON.stringify(e.uiMessages)).not.toContain('synthetic_private');expect(port.disconnected).toBe(true);
    } finally { await e.close(); }
  }
});

test('duplicate clicks and late results cannot run another effect or overwrite recovery state', async () => {
  const e = environment();
  try {
    await e.send('begin', { username: 'synthetic_user', approve_public_profile_lookup: true });
    await e.send('begin', { username: 'synthetic_user', approve_public_profile_lookup: true });
    expect(e.ports).toHaveLength(1);
    const old = e.ports[0];await e.send('stop');expect(old.disconnected).toBe(true);
    expect(e.uiMessages.at(-1)).toMatchObject({ state: 'error', code: 'recovery-needed' });
    await e.send('status');await old.onMessage.emit(reply(old));expect(e.uiMessages.at(-1)).toMatchObject({ state: 'busy' });
    const current = e.ports[1];await current.onMessage.emit(reply(current, { ...summary(), state: 'receipt-saved' }));
    expect(e.uiMessages.at(-1)).toMatchObject({ state: 'result', summary: { state: 'receipt-saved' } });
  } finally { await e.close(); }
});

test('closing the page and native disconnect never claim remote cancellation or echo errors', async () => {
  const e = environment();
  await e.send('status');const port = e.ports[0];await port.onDisconnect.emit(undefined);
  expect(e.uiMessages.at(-1)).toMatchObject({ state: 'error', code: 'helper-unavailable' });
  expect(JSON.stringify(e.uiMessages)).not.toContain('synthetic_private');await e.send('status');
  await e.close();expect(e.ports[1].disconnected).toBe(true);
  expect(e.uiMessages.some(v => (v.summary as { state?: string })?.state === 'cancelled')).toBe(false);
});

test('only one page can own an active native operation', async () => {
  const first = environment();await first.send('status');const second = environment();
  try {
    await second.send('status');expect(second.ports).toHaveLength(0);
    expect(second.uiMessages.at(-1)).toMatchObject({ code: 'helper-busy' });
    await first.ui.onDisconnect.emit(undefined);await second.send('status');expect(second.ports).toHaveLength(1);
  } finally { await second.close();await first.close(); }
});

test('local deletion cannot be represented as remote revocation', async () => {
  const e = environment();
  try {
    await e.send('forget', { confirm_local_deletion: true });const port = e.ports[0];
    await port.onMessage.emit(reply(port, { profile: 'nockapp-zkid-protected-domain-desktop-lab-v1', ready: false, remote_revocation: false }));
    expect(e.uiMessages.at(-1)).toMatchObject({ state: 'result', summary: { state: 'forgotten', credentialSaved: false } });
  } finally { await e.close(); }
});

test('unbounded/forged challenges and unsafe projections are rejected', () => {
  expect(publicSummary({ ...summary(), expires_at: Math.floor(Date.now() / 1000) + 3600 })).toBeUndefined();
  expect(publicProjection({ state: 'awaiting-post', credentialSaved: false, username: 'synthetic_user', postText: 'private', expiresAt: 1 })).toBeUndefined();
  expect(publicProjection({ state: 'credential-saved', credentialSaved: true, local_zkid: 'private' })).toBeUndefined();
});

test('automatic discovery accepts only bounded public schedule hints and literal consent', async () => {
  const e = environment();
  try {
    await e.send('poll-registration', { approve_source_check: true });
    const port = e.ports[0];
    expect(port.messages[0]).toMatchObject({ operation: 'poll-registration', body: { approve_source_check: true } });
    const value = { ...summary(), next_check_at: Math.floor(Date.now() / 1000) + 30 };
    await port.onMessage.emit(reply(port, value));
    expect(e.uiMessages.at(-1)).toMatchObject({ state: 'result', summary: { nextCheckAt: value.next_check_at } });
    expect(publicSummary(summary(), 'poll-registration')).toBeUndefined();
    for (const next_check_at of [true, '123', NaN, value.expires_at + 31, value.expires_at - 601]) {
      expect(publicSummary({ ...value, next_check_at }, 'poll-registration')).toBeUndefined();
    }
    expect(publicProjection({ state: 'credential-saved', credentialSaved: true, nextCheckAt: 1 })).toBeUndefined();
  } finally { await e.close(); }
});
