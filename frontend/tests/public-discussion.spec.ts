import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { publicProjection, validPublicBody, validPublicRow, validPublicSubmission, attachPublicDiscussion, publicOperation, PublicOperationError, PUBLIC_VERSION, PUBLIC_PORT } from '../src/publicDiscussion';
const fixture = JSON.parse(readFileSync(new URL('./fixtures/public-native-contract-v6-20261101.json', import.meta.url), 'utf8'));
const vector = (op: string) => fixture.vectors.find((v: any) => v.operation === op);

test('public UI errors distinguish a read from an uncertain mutation without echoing native text or retrying', async () => {
  let listener: (value: unknown) => void = () => {};let error = 'recovery-needed';let sends = 0;
  Object.assign(globalThis, { chrome: { runtime: { connect: () => ({
    onMessage: { addListener: (fn: (value: unknown) => void) => { listener = fn; } },
    onDisconnect: { addListener: () => {} }, disconnect: () => {},
    postMessage: () => { sends++;listener({ version: PUBLIC_VERSION, error }); },
  }) } } });
  try {
    await expect(publicOperation('public-page', { after: 0, limit: 4 })).rejects.toThrow('Your saved data is safe');
    await expect(publicOperation('public-source-recover', { approve_source_check: true })).rejects.toThrow('Check the saved operation');
    error = 'PRIVATE-ARBITRARY-NATIVE-TEXT';
    await expect(publicOperation('public-page', { after: 0, limit: 4 })).rejects.toThrow('Public operation unavailable');
    expect(sends).toBe(3);
  } finally { Reflect.deleteProperty(globalThis, 'chrome'); }
});

test('actual native-v6 public contract admits real projections and consented exact bodies', () => {
  expect(fixture.profile).toBe('nockapp-public-browser-contract-v6-synthetic');
  for (const v of fixture.vectors) {
    expect(validPublicBody(v.operation, v.body), `${v.operation} body`).toBe(true);
    expect(publicProjection(v.operation, v.result, v.body), `${v.operation} result`).toBe(true);
  }
});
test('expired badge recovery needs exact separate consent and exposes only a public window status', () => {
  const body = { post_id: vector('public-prepare').body.post.id, approve_publication: true };
  expect(validPublicBody('public-publish', { ...body, approve_optional_badge_failure: true })).toBe(true);
  for (const value of [false, 1, 'true']) expect(validPublicBody('public-publish', { ...body, approve_optional_badge_failure: value })).toBe(false);
  expect(validPublicBody('public-finish', { ...body, approve_optional_badge_failure: true })).toBe(false);
  const row = vector('public-prepare').result;
  expect(validPublicSubmission({ ...row, follower_window: 'expired' })).toBe(true);
  expect(validPublicSubmission({ ...row, follower_window: 'private-credential' })).toBe(false);
  expect(validPublicSubmission({ ...row, follower_window: 'expired', expires_at: 123 })).toBe(false);
  const caps = { ...vector('public-capabilities').result, verifier_release: 10, publication_mode: 'tickets', refund_payout_configured: false,
    follower_proof_configured: true, source_enrollment_configured: true };
  expect(publicProjection('public-capabilities', caps)).toBe(true);
  expect(publicProjection('public-capabilities', { ...caps, verifier_release: '10' })).toBe(false);
});
test('valid authored text survives two selected but missing badges and retains canonical unavailable numbers', () => {
  const page = vector('public-numbers');const row = page.result.posts[0];
  expect(validPublicRow(row)).toBe(true);expect(row.display).toEqual({ address: null, followers: null, history: null });
  expect(vector('public-prepare').body.selection).toEqual({ address: true, followers_threshold: 10000 });
  for (const state of ['invalid', 'content-unavailable', 'verification-unavailable']) {
    const invalid = Object.fromEntries(Object.entries(row).filter(([k]) => ['post_number', 'bundle_hash', 'indexed_at', 'block_number', 'block_hash', 'transaction_hash', 'canonical_indexed'].includes(k)));
    expect(validPublicRow({ ...invalid, state, proofs_verified: false })).toBe(true);
    expect(validPublicRow({ ...invalid, state, proofs_verified: true })).toBe(false);
    expect(validPublicRow({ ...invalid, state, proofs_verified: false, display: row.display })).toBe(false);
  }
  expect(validPublicRow(page.result.posts[1])).toBe(true);
});
test('v6 public rows reject private fields, hidden dates, forged verdicts and permanent IDs', () => {
  const row = vector('public-numbers').result.posts[0];
  for (const change of [{ secret: 'PRIVATE' }, { public_id: 'stable-id' }, { authorship_checked: false }, { proofs_verified: false },
    { verifier_profile: 'nockapp-public-verifier-v5' }, { display: { ...row.display, followers: { threshold: 10, issued_at: 1, expires_at: 2 } } },
    { post: { ...row.post, holder_secret: 'PRIVATE' } }]) expect(validPublicRow({ ...row, ...change })).toBe(false);
  const followers = { threshold: 10000, qualified_when_indexed: true, indexed_at: row.indexed_at, credential_profile: 'nockapp-renewal-count-v3' };
  expect(validPublicRow({ ...row, display: { ...row.display, followers }, historical_follower_evidence: followers })).toBe(true);
  const address = '0x' + '12'.repeat(20);
  expect(validPublicRow({ ...row, display: { ...row.display, address } })).toBe(true);
  expect(validPublicRow({ ...row, display: { ...row.display, address, followers }, historical_follower_evidence: followers })).toBe(true);
});
test('private paths, endpoints, credential state and unconsented actions cannot reach native helpers', () => {
  for (const [operation, body] of [
    ['public-ticket-prepare', { approve_purchase: false }], ['public-ticket-recover', { recovery: 'PRIVATE' }],
    ['public-identity-options', { directory: '/tmp/forbidden' }], ['public-adopt-identity', { source_id: '12'.repeat(32), approve_key_reuse: false }],
    ['public-ticket-payment', { ...vector('public-ticket-payment').body, approved: true }], ['public-numbers', { numbers: [1, 1] }],
    ['public-numbers', { numbers: [0] }], ['public-numbers', { numbers: [true] }],
    ['public-prepare', { ...vector('public-prepare').body, post: { ...vector('public-prepare').body.post, credential: {} } }],
    ['public-attach-history', { post_id: vector('public-prepare').body.post.id, records: [], approve_linking: true }],
    ['sign-arbitrary-transaction', {}], ['authored-bundle-publish', {}],
  ] as [string, Record<string, unknown>][]) expect(validPublicBody(operation, body), operation).toBe(false);
});
test('purchase calldata binds the exact prepared pack and payments cannot credit themselves', () => {
  const q = vector('public-ticket-prepare');expect(publicProjection(q.operation, q.result, q.body)).toBe(true);
  for (const change of [{ to: '0x' + '12'.repeat(20), arbitrary: true }, { data: q.result.transaction.data + '00' }, { data: '0x12345678' + q.result.pack_hash.slice(2) },
    { chain_id: 1 }, { value: '0x0' }]) expect(publicProjection(q.operation, { ...q.result, transaction: { ...q.result.transaction, ...change } }, q.body)).toBe(false);
  const payment = vector('public-ticket-payment');expect(publicProjection(payment.operation, payment.result, { ...payment.body, pack_hash: '0x' + '12'.repeat(32) })).toBe(false);
  const recovery = vector('public-ticket-recover');expect(publicProjection(recovery.operation, { ...recovery.result, token: {} }, recovery.body)).toBe(false);
});
test('canonical read ordering, exact outbox intent and protocol versions cannot be silently changed', () => {
  const v = vector('public-numbers');
  for (const change of [{ posts: [...v.result.posts].reverse() }, { posts: [v.result.posts[0]] }, { requested_numbers: ['2', '999'] },
    { whole_log_complete: true }, { profile: 'nockapp-public-page-v5' }, { credential: {} }, { next_number: '1000' },
    { finalized_block: { ...v.result.finalized_block, number: '0x0' } }]) expect(publicProjection(v.operation, { ...v.result, ...change }, v.body)).toBe(false);
  const p = vector('public-prepare');expect(publicProjection(p.operation, p.result, { ...p.body, post: { ...p.body.post, body: 'Changed after consent' } })).toBe(false);
  expect(validPublicSubmission({ ...p.result, phase: 'submitted' })).toBe(false);
  const saved = vector('public-outbox');expect(publicProjection(saved.operation, { ...saved.result, entries: saved.result.entries.map((v: any) => ({ ...v, verification_current: true })) }, saved.body)).toBe(false);
  const check = vector('public-check');expect(publicProjection(check.operation, { ...check.result, verification_current: false }, check.body)).toBe(false);
});

function harness() {
  const uiListeners = new Set<(v: unknown) => void>();const nativeListeners = new Set<(v: unknown) => void>();const disconnected = new Set<() => void>();
  const sent: any[] = [];const replies: any[] = [];let dials = 0;let closed = 0;
  const noop = () => {};
  Object.defineProperty(globalThis, 'chrome', { configurable: true, value: { runtime: {
    connectNative: () => { dials++;return { postMessage: (v: any) => sent.push(v), disconnect: () => { closed++; },
      onMessage: { addListener: (fn: (v: unknown) => void) => nativeListeners.add(fn), removeListener: (fn: (v: unknown) => void) => nativeListeners.delete(fn) },
      onDisconnect: { addListener: noop, removeListener: noop } }; },
  } } });
  const ui = { onMessage: { addListener: (fn: (v: unknown) => void) => uiListeners.add(fn) },
    onDisconnect: { addListener: (fn: () => void) => disconnected.add(fn) }, postMessage: (v: any) => replies.push(v) } as unknown as chrome.runtime.Port;
  attachPublicDiscussion(ui);
  return { sent, replies, dials: () => dials, closed: () => closed,
    send: (operation: string, body: Record<string, unknown>) => uiListeners.forEach(fn => fn({ version: PUBLIC_VERSION, operation, body })),
    reply: (result: unknown, changes = {}) => nativeListeners.forEach(fn => fn({ profile: 'nockapp-zkid-public-post-native-v1', id: sent.at(-1).id,
      status: 'ok', laboratory: true, verified: false, result, ...changes })),
    close: () => { disconnected.forEach(fn => fn());Reflect.deleteProperty(globalThis, 'chrome'); } };
}
test('bridge sends only public namespace, correlates replies and releases its slot after failure', () => {
  const h = harness();
  try {
    h.send('public-ticket-prepare', { approve_purchase: false });expect(h.dials()).toBe(0);
    h.send('public-capabilities', {});expect(h.sent[0].operation).toBe('public-capabilities');
    h.reply(vector('public-capabilities').result, { id: '00'.repeat(16) });expect(h.replies.at(-1).error).toBe('unsupported-helper');
    h.send('public-capabilities', {});h.reply(vector('public-capabilities').result);
    expect(h.replies.at(-1).result.verifier_release).toBe(6);expect(h.closed()).toBe(2);
    h.send('public-ticket-status', {});h.reply({ ...vector('public-ticket-status').result, secret: 'PRIVATE' });
    expect(h.replies.at(-1).error).toBe('unsupported-helper');expect(JSON.stringify(h.replies)).not.toContain('PRIVATE');
  } finally { h.close(); }
});
test('disconnect releases global public operation ownership and drops late replies', () => {
  const h = harness();h.send('public-capabilities', {});h.close();const count = h.replies.length;
  h.reply(vector('public-capabilities').result);expect(h.replies).toHaveLength(count);
  const next = harness();try { next.send('public-capabilities', {});expect(next.sent).toHaveLength(1);next.reply(vector('public-capabilities').result); } finally { next.close(); }
});
// Built background is also checked in background.spec.ts; constant is pinned here.
test('public port is a distinct protocol, with no reinterpretation of v4 traffic', () => {
  expect(PUBLIC_PORT).toBe('nockapp-permissionless-discussion');expect(PUBLIC_VERSION).toBe('nockapp-permissionless-discussion-10');
});

test('actual cursor-page vectors preserve empty ranges and cannot skip or invent allocations', () => {
  const current = JSON.parse(readFileSync(new URL('./fixtures/public-page-contract-v6-20261101-v2.json', import.meta.url), 'utf8'));
  const pages = current.vectors.filter((v: any) => v.operation === 'public-page');expect(pages).toHaveLength(2);
  for (const v of pages) {
    expect(validPublicBody(v.operation, v.body)).toBe(true);expect(publicProjection(v.operation, v.result, v.body)).toBe(true);
    for (const change of [{ next_after: 99 }, { after: 2 }, { more: !v.result.more }, { posts: [...v.result.posts, ...v.result.posts] }]) {
      if (v.result.posts.length === 0 && 'posts' in change) continue;
      expect(publicProjection(v.operation, { ...v.result, ...change }, v.body)).toBe(false);
    }
  }
  expect(validPublicBody('public-page', { after: true, limit: 4 })).toBe(false);
  expect(validPublicBody('public-page', { after: -1, limit: 4 })).toBe(false);
  expect(validPublicBody('public-page', { after: 0, limit: 8 })).toBe(false);
});


test('concurrent views wait before native dispatch and closing a queued mutation cancels it', async () => {
  const natives: {sent:any[];listeners:Set<(v:unknown)=>void>}[]=[];
  Object.defineProperty(globalThis,'chrome',{configurable:true,value:{runtime:{connectNative:()=>{
    const n={sent:[] as any[],listeners:new Set<(v:unknown)=>void>()};natives.push(n);
    return {postMessage:(v:any)=>n.sent.push(v),disconnect:()=>{},onMessage:{addListener:(f:any)=>n.listeners.add(f),removeListener:(f:any)=>n.listeners.delete(f)},onDisconnect:{addListener:()=>{},removeListener:()=>{}}};
  }}}});
  const channels: {send:(op:string,body?:Record<string,unknown>)=>void;close:()=>void;replies:any[]}[]=[];
  const channel=()=>{
    let message:(v:unknown)=>void=()=>{};let disconnect:()=>void=()=>{};const replies:any[]=[];
    attachPublicDiscussion({onMessage:{addListener:(f:any)=>message=f},onDisconnect:{addListener:(f:any)=>disconnect=f},postMessage:(v:any)=>replies.push(v)} as any,undefined,true);
    const c={send:(operation:string,body={})=>message({version:PUBLIC_VERSION,operation,body}),close:()=>disconnect(),replies};channels.push(c);return c;
  };
  const reply=(index:number,op:string)=>{const n=natives[index];for(const f of [...n.listeners])f({profile:'nockapp-zkid-public-post-native-v1',id:n.sent[0].id,status:'ok',laboratory:true,verified:false,result:vector(op).result});};
  try {
    const first=channel();first.send('public-ticket-status');
    const cancelled=channel();cancelled.send('public-ticket-prepare',{approve_purchase:true});cancelled.close();
    const next=channel();next.send('public-ticket-status');expect(natives).toHaveLength(1);expect(next.replies).toEqual([]);
    reply(0,'public-ticket-status');await Promise.resolve();expect(natives).toHaveLength(2);
    expect(natives.flatMap(n=>n.sent).map(m=>m.operation)).toEqual(['public-ticket-status','public-ticket-status']);
    reply(1,'public-ticket-status');expect(next.replies[0].result).toEqual(vector('public-ticket-status').result);
    expect(cancelled.replies).toEqual([]);
    const blocking=channel();blocking.send('public-ticket-status');
    const queued=Array.from({length:9},()=>{const c=channel();c.send('public-ticket-status');return c;});
    expect(queued.slice(0,8).every(c=>c.replies.length===0)).toBe(true);expect(queued[8].replies).toEqual([{version:PUBLIC_VERSION,error:'helper-busy'}]);
    expect(natives).toHaveLength(3);
  } finally {for(const c of channels)c.close();await Promise.resolve();Reflect.deleteProperty(globalThis,'chrome');}
});

test('a page with an old background gets a specific reload action without retrying its operation', async () => {
  let listener:(v:unknown)=>void=()=>{};let sends=0;
  Object.defineProperty(globalThis,'chrome',{configurable:true,value:{runtime:{connect:()=>({onMessage:{addListener:(f:any)=>listener=f},onDisconnect:{addListener:()=>{}},disconnect:()=>{},postMessage:()=>{sends++;listener({version:'nockapp-permissionless-discussion-6',error:'message-schema'});}})}}});
  try {
    const error=await publicOperation('public-ticket-recover').catch(e=>e);
    expect(error).toBeInstanceOf(PublicOperationError);if(!(error instanceof PublicOperationError))throw Error('Expected a typed update error');expect(error.code).toBe('extension-update-required');expect(error.message).toContain('Reload the extension itself');expect(sends).toBe(1);
  } finally {Reflect.deleteProperty(globalThis,'chrome');}
});
