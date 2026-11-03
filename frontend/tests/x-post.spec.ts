import { test, expect } from '@playwright/test';
import type { Comment, Thread } from '../src/model';
import { postScope, validPostFacts } from '../src/postScope';
import { publishComment, publishThread, inspectPost } from '../src/xPost';
import { FORUM_KEY, LocalForumRepository } from '../src/data/repository';
import { PROOF_BRIDGE_PROFILE, PROOF_CONSENT } from '../src/xSourceFlow';

function repository() {
  const values = new Map<string, unknown>();
  return { values, repo: new LocalForumRepository({ get: async <T>(key: string) => structuredClone(values.get(key)) as T | undefined,
    set: async (key, value) => { values.set(key, structuredClone(value)); }, keys: async prefix => [...values.keys()].filter(k => k.startsWith(prefix)) }) };
}
async function locks(work: () => Promise<void>) {
  const previous = Object.getOwnPropertyDescriptor(navigator, 'locks');
  Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: (_key: string, run: () => Promise<unknown>) => run() } });
  try { await work(); } finally { if (previous) Object.defineProperty(navigator, 'locks', previous); else Reflect.deleteProperty(navigator, 'locks'); }
}
function native(supported = true) {
  const calls: Record<string, unknown>[] = [];
  const actions = new Map<string, { scope: unknown; fact: unknown }>();
  Object.defineProperty(globalThis, 'chrome', { configurable: true, value: { runtime: { connectNative: () => {
    let receive: (message: unknown) => void;
    return { onMessage: { addListener: (listener: typeof receive) => { receive = listener; } },
      onDisconnect: { addListener: () => {} }, disconnect: () => {}, postMessage: (message: Record<string, unknown>) => {
        calls.push(message);
        queueMicrotask(() => {
          if (message.op === 'capabilities') { receive({ id: message.id, status: 'ready', protocol: 2,
            bridge_profile: PROOF_BRIDGE_PROFILE, consent_profile: PROOF_CONSENT, proving_available: true,
            passport_available: true, scoped_post_use_available: supported, laboratory: true, verified: false, passport_issuance_allowed: false }); return; }
          let challenge = String(message.challenge ?? crypto.randomUUID().replaceAll('-', '') + 'ab'.repeat(16));
          if (message.op === 'use_passport') actions.set(challenge, { scope: message.scope, fact: message.fact });
          const saved = actions.get(challenge);
          if (!saved || saved.scope !== message.scope || saved.fact !== message.fact) {
            receive({ id: message.id, status: 'rejected', code: 'helper-operation-failed', verified: false, passport_issuance_allowed: false }); return;
          }
          const now = Math.floor(Date.now() / 1000);
          receive({ id: message.id, status: message.op === 'use_passport' ? 'synthetic-action-accepted' : 'synthetic-post-checked',
            laboratory: true, verified: false, passport_issuance_allowed: false, holder_bound: true,
            fact: message.fact, audience: 'ab'.repeat(32), challenge, observed_at: now - 1, expires_at: now + 86000,
            verified_at: now, ...(message.op === 'inspect_post' ? { archival_only: true, fresh: false } : {}) });
        });
      } };
  } } } });
  return { calls, close: () => Reflect.deleteProperty(globalThis, 'chrome') };
}

test('post scope binds identity, time, text, thread, links and displayed demo claims', async () => {
  const post: Comment = { id: crypto.randomUUID(), createdAt: Date.now(), postNumber: '1', threadId: 'thread-a',
    body: 'Synthetic post', references: [{ url: 'https://example.test/' }], author: { credentials: [] } };
  const original = await postScope(post);
  for (const change of [{ id: crypto.randomUUID() }, { createdAt: post.createdAt + 1 }, { body: 'Changed post' },
    { threadId: 'thread-b' }, { references: [{ url: 'https://different.test/' }] }, { author: { credentials: [{ kind: 'x-account' as const }] } }]) {
    expect(await postScope({ ...post, ...change })).not.toBe(original);
  }
  expect(await postScope({ ...post, postNumber: '999' })).toBe(original);
  const thread: Thread = { ...post, title: 'Synthetic title' };
  Reflect.deleteProperty(thread, 'threadId');
  expect(await postScope(thread)).not.toBe(await postScope({ ...thread, title: 'Other title' }));
});

test('anonymous posting never opens a native port and preserves the existing author shape', async () => locks(async () => {
  const { repo } = repository();
  const old = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
  Object.defineProperty(globalThis, 'chrome', { configurable: true, value: { runtime: { connectNative: () => { throw new Error('Unexpected native access'); } } } });
  try {
    const thread = await publishThread(repo, { title: 'Anonymous', body: 'No passport needed.', references: [] });
    expect(thread.author).toEqual({ credentials: [] });
    const comment = await publishComment(repo, { threadId: thread.id, body: 'Anonymous reply.' });
    expect(comment.author).toEqual({ credentials: [] });
  } finally { if (old) Object.defineProperty(globalThis, 'chrome', old); else Reflect.deleteProperty(globalThis, 'chrome'); }
}));

test('selected facts require scoped native use and durable storage contains only references', async () => locks(async () => {
  const e = native(); const { repo, values } = repository();
  try {
    const thread = await publishThread(repo, { title: '  Signed synthetic title  ', body: ' Synthetic body https://example.test/ ', references: [] },
      ['account-controlled', 'followers-over-10000']);
    expect(thread.author.passport).toHaveLength(2);
    const uses = e.calls.filter(v => v.op === 'use_passport');
    expect(uses).toHaveLength(2);
    expect(uses.every(v => v.scope === uses[0].scope)).toBe(true);
    expect(uses[0].scope).toBe(await postScope(thread));
    expect(validPostFacts(thread.author.passport)).toBe(true);
    expect(JSON.stringify(values.get(FORUM_KEY))).not.toMatch(/verified|holder_key|holder_public_key|expires_at|auth_token/);
    const checked = await inspectPost(thread, thread.author.passport![0]);
    expect(checked.status).toBe('synthetic-post-checked');
    await expect(inspectPost({ ...thread, body: 'Edited after signing' }, thread.author.passport![0])).rejects.toThrow();
    await expect(inspectPost({ ...thread, id: crypto.randomUUID() }, thread.author.passport![0])).rejects.toThrow();
    expect((await repo.load()).threads.find(v => v.id === thread.id)?.author.passport).toEqual(thread.author.passport);
    await expect(repo.createThread({ title: thread.title, body: thread.body, references: thread.references,
      identity: { id: thread.id, createdAt: thread.createdAt }, passport: thread.author.passport })).rejects.toThrow('duplicate');
  } finally { e.close(); }
}));

test('unsupported helpers and cancellation cannot silently save an unverified requested fact', async () => locks(async () => {
  const e = native(false); const { repo } = repository();
  try {
    const before = await repo.load();
    await expect(publishThread(repo, { title: 'Do not save', body: 'Keep my draft', references: [] }, ['account-controlled'])).rejects.toThrow('Update');
    expect((await repo.load()).threads).toEqual(before.threads);
    const controller = new AbortController(); controller.abort();
    await expect(publishComment(repo, { threadId: before.threads[0].id, body: 'Cancelled' }, ['account-controlled'], controller.signal)).rejects.toThrow('cancelled');
    expect((await repo.load()).comments).toEqual(before.comments);
  } finally { e.close(); }
}));

test('proof references cannot contain an acceptance boolean, global holder ID or duplicate fact', () => {
  const reference = { profile: 'nockapp-x-post-fact-v1', fact: 'account-controlled', challenge: 'ab'.repeat(32) };
  expect(validPostFacts([reference])).toBe(true);
  for (const values of [[{ ...reference, verified: true }], [{ ...reference, holder_key: 'ab'.repeat(32) }],
    [reference, reference], [{ ...reference, fact: 'exact-followers' }], [{ ...reference, challenge: '00'.repeat(32) }]]) {
    expect(validPostFacts(values)).toBe(false);
  }
});
