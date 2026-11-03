import { test, expect } from '@playwright/test';
import { storage } from '../src/platform/storage';
import { acknowledgePublicIntent, preparePublicIntent, publicIntents, PUBLIC_INTENTS_KEY, type PublicIntent } from '../src/data/publicIntents';

async function isolated(work: (values: Map<string, unknown>) => Promise<void>) {
  const values = new Map<string, unknown>([['legacy-v4-marker', { preserve: true }]]);const old = { ...storage };const locks = Object.getOwnPropertyDescriptor(navigator, 'locks');
  let queue: Promise<unknown> = Promise.resolve();
  Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: <T>(_key: string, f: () => Promise<T>) => { const result = queue.then(f);queue = result.catch(() => undefined);return result; } } });
  storage.get = async <T>(key: string) => structuredClone(values.get(key)) as T | undefined;
  storage.set = async (key, value) => { values.set(key, structuredClone(value)); };
  try { await work(values);expect(values.get('legacy-v4-marker')).toEqual({ preserve: true }); }
  finally { Object.assign(storage, old);if (locks) Object.defineProperty(navigator, 'locks', locks);else Reflect.deleteProperty(navigator, 'locks'); }
}
function intent(): PublicIntent { return { scope: { protocol: 5, chain_id: 84532, application: '0x' + '12'.repeat(32), contract: '0x' + '34'.repeat(20) },
  draft_key: 'thread:public-v5:synthetic', post: { kind: 'thread', id: crypto.randomUUID(), created_at: 1793011200, title: 'Exact intent', body: 'Only this text', references: [] },
  selection: { address: false, followers_threshold: null }, thread: null, references: [], acknowledged: false, released: false }; }

test('public intents serialize concurrent capture and reuse one exact UUID without rewriting later caller data', async () => isolated(async () => {
  const first = intent();const other = intent();const pending = preparePublicIntent(first);first.post.body = 'Changed after call';
  const a = await pending;const b = await preparePublicIntent(other);expect(a.post.id).toBe(b.post.id);expect(a.post.body).toBe('Only this text');
  a.post.body = 'Changed return object';expect((await publicIntents())[0].post.body).toBe('Only this text');
  await expect(preparePublicIntent({ ...other, post: { ...other.post, body: 'Newer draft' } })).rejects.toThrow('Recover the saved post');
  await expect(preparePublicIntent({ ...other, selection: { address: true, followers_threshold: null } })).rejects.toThrow('Recover the saved post');
}));
test('release requires durable acknowledgement and preserves the original alongside an explicitly new post', async () => isolated(async () => {
  const first = await preparePublicIntent(intent());await expect(acknowledgePublicIntent(first.post.id, true)).rejects.toThrow('Recover');
  await acknowledgePublicIntent(first.post.id);await acknowledgePublicIntent(first.post.id, true);
  const second = await preparePublicIntent(intent());expect(second.post.id).not.toBe(first.post.id);expect(await publicIntents()).toHaveLength(2);
}));
test('other application intents are retained independently and malformed state never becomes an empty wallet', async () => isolated(async values => {
  const first = await preparePublicIntent(intent());const changed = intent();changed.scope.application = '0x' + '56'.repeat(32);
  await preparePublicIntent(changed);expect(await publicIntents()).toHaveLength(2);expect((await publicIntents())[0]).toEqual(first);
  values.set(PUBLIC_INTENTS_KEY, [{ ...first, private_key: 'forbidden' }]);const before = structuredClone(values.get(PUBLIC_INTENTS_KEY));
  await expect(publicIntents()).rejects.toThrow('preserved');await expect(preparePublicIntent(intent())).rejects.toThrow('preserved');expect(values.get(PUBLIC_INTENTS_KEY)).toEqual(before);
}));
test('oversized native payload or private fields reject before persisting an unrecoverable intent', async () => isolated(async values => {
  const huge = intent();huge.post.body = 'x'.repeat(6000);huge.post.references = Array.from({ length: 3 }, () => ['https://example.invalid/' + 'a'.repeat(1000), null]);
  await expect(preparePublicIntent(huge)).rejects.toThrow('Invalid public intent');
  await expect(preparePublicIntent({ ...intent(), post: { ...intent().post, secret: 'forbidden' } } as unknown as PublicIntent)).rejects.toThrow('Invalid public intent');
  expect(values.has(PUBLIC_INTENTS_KEY)).toBe(false);
}));
