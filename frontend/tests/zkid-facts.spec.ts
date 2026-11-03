import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { attachZkidFacts, factOperation, factProjection, FACT_VERSION, type PendingPost, type FactAccepted } from '../src/zkidFacts';
import { validWirePost, wirePayload, validZkidReference, sortedFacts, type WirePost } from '../src/zkidWire';
import { publishZkidThread, publishZkidComment, recoverZkidPost, inspectZkidPost } from '../src/zkidPublishing';
import { LocalForumRepository, FORUM_KEY } from '../src/data/repository';
import type { ZkidFact, ZkidReference } from '../src/model';
import { isDraftRequest } from '../src/data/drafts';

class Signal {
  listeners = new Set<(v: any) => void>();
  addListener = (fn: (v: any) => void) => { this.listeners.add(fn); };
  removeListener = (fn: (v: any) => void) => { this.listeners.delete(fn); };
  emit = (v?: any) => { for (const fn of [...this.listeners]) fn(v); };
}
function repo() {
  const values = new Map<string, unknown>();let failAfterWrite = false;
  return { values, failNextWrite: () => { failAfterWrite = true; }, repository: new LocalForumRepository({
    get: async <T>(key: string) => structuredClone(values.get(key)) as T | undefined,
    set: async (key, value) => { values.set(key, structuredClone(value));if (failAfterWrite && key === FORUM_KEY) { failAfterWrite = false;throw new Error('Synthetic lost write reply'); } },
    keys: async prefix => [...values.keys()].filter(k => k.startsWith(prefix)),
  }) };
}
async function locked(run: () => Promise<void>) {
  const old = Object.getOwnPropertyDescriptor(navigator, 'locks');
  Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: (_: string, work: () => Promise<unknown>) => work() } });
  try { await run(); } finally { if (old) Object.defineProperty(navigator, 'locks', old);else Reflect.deleteProperty(navigator, 'locks'); }
}
function intent(): WirePost { return { kind: 'thread', id: crypto.randomUUID(), created_at: Date.now(), thread_id: null,
  title: 'Synthetic', body: 'Synthetic body', references: [], claims: [] }; }
function accepted(reference: ZkidReference): FactAccepted {
  const now = Math.floor(Date.now() / 1000), start = Math.floor(now / 3600) * 3600;
  return { state: 'accepted', reference, observed_at: start, expires_at: start + 86400, checked_at: now,
    archival_only: true, laboratory: true, verified: false };
}
/** Synthetic native replies only. Real native/crypto acceptance is separate. */
function environment() {
  const nativeCalls: any[] = [];const ports: any[] = [];const hosts: string[] = [];
  const receipts = new Map<string, { post: WirePost; facts: ZkidFact[] }>();
  let pending: PendingPost | undefined;let nonce = '';let malformed: ((v: any) => any) | undefined;let completionFails = false;
  const direct = () => {
    const sent: any[] = [];const clientMessages = new Signal(), workerMessages = new Signal(), closed = new Signal();
    const worker = { onMessage: workerMessages, onDisconnect: closed, postMessage: (v: any) => queueMicrotask(() => clientMessages.emit(v)) };
    attachZkidFacts(worker as unknown as chrome.runtime.Port);
    const client = { onMessage: clientMessages, onDisconnect: closed, postMessage: (v: any) => { sent.push(v);queueMicrotask(() => workerMessages.emit(v)); },
      disconnect: () => closed.emit(), sent };
    return client;
  };
  const original = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
  Object.defineProperty(globalThis, 'chrome', { configurable: true, value: { runtime: { connect: direct,
    connectNative: (host: string) => {
      hosts.push(host);const onMessage = new Signal(), onDisconnect = new Signal();
      const port = { onMessage, onDisconnect, disconnected: false, disconnect() { this.disconnected = true; }, postMessage(m: any) {
        nativeCalls.push(m);queueMicrotask(() => {
          let result: any;const b = m.body;
          if (m.operation === 'post-capabilities') result = { configured: true, profile: 'nockapp-zkid-post-reference-v1', identity_disclosed: false, laboratory: true, verified: false };
          else if (m.operation === 'post-status') result = pending ? { ...pending, laboratory: true, verified: false } : { state: 'empty', laboratory: true, verified: false };
          else if (m.operation === 'post-use') {
            if (pending && wirePayload(pending.post) !== wirePayload(b.post)) { result = undefined; }
            else { pending = { state: 'accepted', post: b.post, facts: sortedFacts(b.facts) };nonce ||= crypto.randomUUID().replaceAll('-', '') + 'ab'.repeat(16);
              receipts.set(nonce, { post: b.post, facts: pending.facts });result = accepted({ profile: 'nockapp-zkid-post-reference-v1', nonce, facts: pending.facts }); }
          } else if (m.operation === 'post-recover' || m.operation === 'post-retry') result = pending && accepted({ profile: 'nockapp-zkid-post-reference-v1', nonce, facts: pending.facts });
          else if (m.operation === 'post-inspect') {
            const row = receipts.get(b.nonce);
            if (row && wirePayload(row.post) === wirePayload(b.post) && JSON.stringify(row.facts) === JSON.stringify(sortedFacts(b.facts)))
              result = accepted({ profile: 'nockapp-zkid-post-reference-v1', nonce: b.nonce, facts: row.facts });
          } else if (m.operation === 'post-complete') {
            if (!completionFails) { pending = undefined;nonce = '';result = { state: 'completed', laboratory: true, verified: false }; }
          }
          const reply = result ? { profile: m.profile, id: m.id, status: 'ok', result, laboratory: true, verified: false }
            : { profile: m.profile, id: m.id, status: 'rejected', code: 'native-operation-unavailable', recoverable: true, laboratory: true, verified: false };
          onMessage.emit(malformed ? malformed(reply) : reply);
        });
      } };
      ports.push(port);return port;
    } } } });
  return { nativeCalls, ports, hosts, direct, receipts, getPending: () => pending,
    malform: (f?: (v: any) => any) => { malformed = f; }, loseCompletion: () => { completionFails = true; },
    close: () => { for (const p of ports) p.disconnect();if (original) Object.defineProperty(globalThis, 'chrome', original);else Reflect.deleteProperty(globalThis, 'chrome'); } };
}

test('new wire matches independent Python Unicode/legacy-parent scope vectors', () => {
  const fixture = JSON.parse(readFileSync('tests/fixtures/zkid-post-scope.json', 'utf8'));
  for (const v of fixture.vectors) {
    expect(validWirePost(v.post)).toBe(true);expect(wirePayload(v.post)).toBe(v.payload);
    expect(createHash('sha256').update(wirePayload(v.post)).digest('hex')).toBe(v.sha256);
  }
  expect(validWirePost({ ...intent(), body: '\ud800' })).toBe(false);
  expect(validZkidReference({ profile: 'nockapp-x-post-fact-v1', nonce: 'ab'.repeat(32), facts: ['account-controlled'] })).toBe(false);
});

test('selected new joint facts store only a distinct reference, inspect and keep Anonymous shape', async () => locked(async () => {
  const e = environment(), r = repo();
  try {
    const p = await publishZkidThread(r.repository, { title: ' Synthetic ', body: ' Chosen body https://example.test/ ', references: [] }, ['followers-at-least-10000', 'account-controlled']);
    expect(p.author.credentials).toEqual([]);expect(validZkidReference(p.author.zkid)).toBe(true);expect(p.author.passport).toBeUndefined();
    expect(e.nativeCalls.map(v => v.operation)).toEqual(['post-use', 'post-inspect', 'post-complete']);
    expect(e.nativeCalls[0].body).toMatchObject({ approve_identity_disclosure: false, approve_facts: ['account-controlled', 'followers-at-least-10000'] });
    expect(JSON.stringify(r.values.get(FORUM_KEY))).not.toMatch(/proof|verified|holder|certificate|checked_at|secret/);
    expect((await inspectZkidPost(p, p.author.zkid!)).archival_only).toBe(true);
    await expect(inspectZkidPost({ ...p, body: 'edited' }, p.author.zkid!)).rejects.toThrow();
    await expect(inspectZkidPost({ ...p, id: crypto.randomUUID() }, p.author.zkid!)).rejects.toThrow();
    expect(e.hosts.every(h => h === 'com.nockapp.zkid')).toBe(true);expect(e.ports.every(p => p.disconnected)).toBe(true);
  } finally { e.close(); }
}));

test('lost local write reply recovers SAME UUID once, preserving display-number allocation', async () => locked(async () => {
  const e = environment(), r = repo();
  try {
    await r.repository.load();r.failNextWrite();
    await expect(publishZkidThread(r.repository, { title: 'Saved once', body: 'Keep original identity', references: [] }, ['account-controlled'])).rejects.toThrow('lost write');
    const before = await r.repository.load(), pending = e.getPending()!;
    const saved = await recoverZkidPost(r.repository, pending, false);
    const after = await r.repository.load();expect(after.threads).toHaveLength(before.threads.length);
    expect(after.nextPostNumber).toBe(before.nextPostNumber);expect(saved.id).toBe(pending.post.id);
    expect(e.nativeCalls.filter(v => v.operation === 'post-use')).toHaveLength(1);
  } finally { e.close(); }
}));

test('completion uncertainty never reports a durable post as failed or duplicates it on recovery', async () => locked(async () => {
  const e = environment(), r = repo();e.loseCompletion();
  try {
    const saved = await publishZkidThread(r.repository, { title: 'Durable', body: 'Saved before ack', references: [] }, ['account-controlled']);
    const count = (await r.repository.load()).threads.length;
    expect((await recoverZkidPost(r.repository, e.getPending()!, false)).id).toBe(saved.id);
    expect((await r.repository.load()).threads).toHaveLength(count);
  } finally { e.close(); }
}));

test('new comments can bind existing opaque legacy thread IDs without renumbering/migration', async () => locked(async () => {
  const e = environment(), r = repo();
  try {
    const before = await r.repository.load(), parent = before.threads[0];
    const p = await publishZkidComment(r.repository, { threadId: parent.id, body: 'New proof in existing conversation' }, ['account-controlled']);
    expect(p.threadId).toBe(parent.id);expect((await r.repository.load()).threads).toEqual(before.threads);
    expect((await inspectZkidPost(p, p.author.zkid!)).state).toBe('accepted');
  } finally { e.close(); }
}));

test('private fields/verified flags/wrong IDs fail closed with no local publication', async () => locked(async () => {
  const e = environment(), r = repo();
  try {
    const before = await r.repository.load();
    for (const f of [(v: any) => ({ ...v, verified: true }), (v: any) => ({ ...v, id: '00'.repeat(16) }),
                    (v: any) => ({ ...v, result: { ...v.result, proof: 'PRIVATE-SYNTHETIC-MARKER' } })]) {
      e.malform(f);await expect(publishZkidThread(r.repository, { title: 'Must fail', body: 'Draft survives', references: [] }, ['account-controlled'])).rejects.toThrow();
      expect((await r.repository.load()).threads).toEqual(before.threads);
    }
  } finally { e.close(); }
}));

test('worker rejects caller trust/proofs/empty facts before native access; disconnect releases ownership', async () => {
  const e = environment();
  try {
    const port = e.direct(), replies: any[] = [];port.onMessage.addListener(v => replies.push(v));
    for (const body of [{ post: intent(), facts: [], approve_facts: [], approve_identity_disclosure: false },
                        { post: intent(), facts: ['account-controlled'], approve_facts: ['account-controlled'], approve_identity_disclosure: false, trust: {} }]) {
      port.postMessage({ version: FACT_VERSION, operation: 'post-use', body });await new Promise(r => setTimeout(r, 0));
    }
    expect(e.nativeCalls).toEqual([]);expect(replies.every(v => v.error === 'message-schema')).toBe(true);
    port.disconnect();port.postMessage({ version: FACT_VERSION, operation: 'post-status', body: {} });await new Promise(r => setTimeout(r, 0));
    expect(e.nativeCalls).toEqual([]);
    expect((await factOperation<{ state: string }>('post-status')).state).toBe('empty');
  } finally { e.close(); }
});

test('new drafts validate fact choices while preserving legacy fields and exact threshold distinction', () => {
  const draft = { title: '', body: 'draft', credentials: [], zkidFacts: ['followers-at-least-10000'] };
  expect(isDraftRequest({ type: 'save-draft', key: 'thread:123', draft })).toBe(true);
  expect(isDraftRequest({ type: 'save-draft', key: 'thread:123', draft: { ...draft, zkidFacts: ['followers-over-10000'] } })).toBe(false);
  expect(factProjection('post-available', { facts: ['account-controlled'], observed_at: 1, expires_at: 86401,
    availability_only: true, laboratory: true, verified: false })).toBe(false);
});
