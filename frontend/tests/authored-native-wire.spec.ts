import { test, expect } from '@playwright/test';
import { attachAuthoredDiscussion, AUTHORED_VERSION } from '../src/authoredDiscussion';

function setup() {
  const calls: any[] = [];const native: { send: (value: unknown) => void; oldSend?: (value: unknown) => void; request?: any }[] = [];
  Object.defineProperty(globalThis, 'chrome', { configurable: true, value: { runtime: { connectNative: (host: string) => {
    expect(host).toBe('com.nockapp.zkid');const entry = { send: (_v: unknown) => {}, oldSend: undefined as undefined | ((v: unknown) => void), request: undefined as any };native.push(entry);
    return { onMessage: { addListener: (fn: (v: unknown) => void) => { entry.send = fn;entry.oldSend = fn; }, removeListener: () => { entry.send = () => {}; } },
      onDisconnect: { addListener: () => {}, removeListener: () => {} }, disconnect: () => {}, postMessage: (m: any) => { calls.push(m);entry.request = m; } };
  } } } });
  const ui = () => {
    const replies: any[] = [];let receive = (_v: unknown) => {};let disconnect = () => {};
    const port = { onMessage: { addListener: (fn: typeof receive) => { receive = fn; } }, onDisconnect: { addListener: (fn: typeof disconnect) => { disconnect = fn; } }, postMessage: (m: any) => replies.push(m) };
    attachAuthoredDiscussion(port as unknown as chrome.runtime.Port);
    return { replies, receive: (v: unknown) => receive(v), disconnect: () => disconnect() };
  };
  const capability = { version: AUTHORED_VERSION, operation: 'bundle-capabilities', body: {} };
  const reply = (entry: typeof native[number]) => ({ profile: entry.request.profile, id: entry.request.id, status: 'ok', result: { configured: false, experimental: true }, laboratory: true, verified: false });
  return { calls, native, ui, capability, reply };
}

test('v4 wire uses a distinct native namespace and accepts no caller-selected trust or private fields', () => {
  const s = setup();const ui = s.ui();
  try {
    ui.receive({ ...s.capability, body: { trust: 'PRIVATE' } });expect(s.calls).toHaveLength(0);
    ui.receive(s.capability);expect(s.calls).toHaveLength(1);expect(s.calls[0].operation).toBe('authored-bundle-capabilities');
    s.native[0].send(s.reply(s.native[0]));expect(ui.replies.at(-1)).toEqual({ version: AUTHORED_VERSION, result: { configured: false, experimental: true } });
  } finally { ui.disconnect();Reflect.deleteProperty(globalThis, 'chrome'); }
});

test('disconnect releases only its own operation; stale native replies cannot release or overwrite another operation', () => {
  const s = setup();const first = s.ui();const second = s.ui();const third = s.ui();
  try {
    first.receive(s.capability);second.receive(s.capability);expect(second.replies.at(-1).error).toBe('helper-busy');expect(s.calls).toHaveLength(1);
    const stale = s.native[0].oldSend!;first.disconnect();second.receive(s.capability);expect(s.calls).toHaveLength(2);
    stale(s.reply(s.native[0]));expect(first.replies).toEqual([]);third.receive(s.capability);expect(third.replies.at(-1).error).toBe('helper-busy');
    s.native[1].send(s.reply(s.native[1]));expect(second.replies.at(-1).result).toEqual({ configured: false, experimental: true });
    third.receive(s.capability);expect(s.calls).toHaveLength(3);s.native[2].send(s.reply(s.native[2]));expect(third.replies.at(-1).result.configured).toBe(false);
  } finally { first.disconnect();second.disconnect();third.disconnect();Reflect.deleteProperty(globalThis, 'chrome'); }
});

test('malformed and duplicate native replies cannot emit private material or a second success', () => {
  const s = setup();const ui = s.ui();
  try {
    ui.receive(s.capability);const deliver = s.native[0].oldSend!;deliver({ ...s.reply(s.native[0]), result: { configured: false, experimental: true, credential: 'PRIVATE-MARKER' } });
    expect(ui.replies).toEqual([{ version: AUTHORED_VERSION, error: 'unsupported-helper' }]);deliver(s.reply(s.native[0]));expect(ui.replies).toHaveLength(1);
    expect(JSON.stringify(ui.replies)).not.toContain('PRIVATE-MARKER');
  } finally { ui.disconnect();Reflect.deleteProperty(globalThis, 'chrome'); }
});

test('earlier page ports reject fresh publication, renewal and source lookup before the native host', async () => {
  const { attachBundleDiscussion, BUNDLE_VERSION } = await import('../src/bundleDiscussion');
  const { attachBaseDiscussion, BASE_VERSION } = await import('../src/baseDiscussion');
  let calls = 0;Object.defineProperty(globalThis, 'chrome', { configurable: true, value: { runtime: { connectNative: () => { calls++;throw new Error('Must reject'); } } } });
  try {
    for (const [attach, version, operations] of [[attachBundleDiscussion, BUNDLE_VERSION, ['bundle-publish', 'bundle-renew', 'bundle-recover', 'count-begin', 'count-check-post']],
      [attachBaseDiscussion, BASE_VERSION, ['base-publish', 'base-recover']]] as const) {
      let receive = (_v: unknown) => {};const replies: any[] = [];
      attach({ onMessage: { addListener: (fn: typeof receive) => { receive = fn; } }, onDisconnect: { addListener: () => {} }, postMessage: (v: unknown) => replies.push(v) } as unknown as chrome.runtime.Port);
      const post = { kind: 'thread', id: '11111111-1111-4111-8111-111111111111', created_at: 1793494800, thread_id: null, title: 'Earlier post', body: 'Exact public text', references: [], claims: [] };
      const bodies: Record<string, object> = {
        'bundle-publish': { post, selection: { credential_kind: 0, facts: [], threshold: null }, approve_publication: true },
        'bundle-recover': { post_id: post.id },
        'base-recover': { post_id: post.id },
        'bundle-renew': { post_id: post.id, expected_submission_id: 'ab'.repeat(32), approve_fresh_proof: true },
        'count-begin': { username: 'synthetic_user', approve_public_profile_lookup: true },
        'count-check-post': { post: '123456789', approve_source_check: true },
        'base-publish': { post, facts: [], approve_publication: true },
      };
      for (const operation of operations) receive({ version, operation, body: bodies[operation] });
      expect(replies).toHaveLength(operations.length);expect(replies.every(v => v.error === 'message-schema')).toBe(true);
    }
    expect(calls).toBe(0);
  } finally { Reflect.deleteProperty(globalThis, 'chrome'); }
});
