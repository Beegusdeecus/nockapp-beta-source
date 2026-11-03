import { test, expect } from '@playwright/test';
import { FORUM_KEY, LocalForumRepository, resolvePost } from '../src/data/repository';
import type { StorageAdapter } from '../src/platform/storage';

function memoryAdapter(initial: Record<string, unknown> = {}): StorageAdapter & { values: Map<string, unknown> } {
  const values = new Map(Object.entries(structuredClone(initial)));
  return {
    values,
    async get<T>(key: string) { return structuredClone(values.get(key)) as T | undefined; },
    async set(key, value) { values.set(key, structuredClone(value)); },
    async keys(prefix) { return [...values.keys()].filter((key) => key.startsWith(prefix)); },
  };
}
async function withNodeLocks(work: () => Promise<void>) {
  const previous = Object.getOwnPropertyDescriptor(navigator, 'locks');
  Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: <T>(_key: string, fn: () => Promise<T>) => fn() } });
  try { await work(); }
  finally { if (previous) Object.defineProperty(navigator, 'locks', previous); else Reflect.deleteProperty(navigator, 'locks'); }
}

test('upgrade refuses to replace old content if its backup cannot be saved', async () => withNodeLocks(async () => {
  const legacy = {
    schema: 1, identity: { id: 'anon_old', credentials: [] },
    threads: [{ id: 't', title: 'Keep my thread', body: 'Original synthetic content.', author: { id: 'anon_old', credentials: [] }, createdAt: 1, references: [] }], comments: [],
  };
  const adapter = memoryAdapter({ [FORUM_KEY]: legacy });
  const set = adapter.set;
  adapter.set = async (key, value) => {
    if (key.startsWith('nockapp:backup:')) throw new Error('Synthetic backup quota failure');
    return set(key, value);
  };
  await expect(new LocalForumRepository(adapter).load()).rejects.toThrow('backup quota failure');
  expect(adapter.values.get(FORUM_KEY)).toEqual(legacy);
}));

test('post IDs identify flat posts; general threads support zero references and selected credentials only', async () => withNodeLocks(async () => {
  const repo = new LocalForumRepository(memoryAdapter());
  const thread = await repo.createThread({ title: 'An unlinked discussion', body: 'No X link is required by the data model.', references: [] });
  const comment = await repo.reply({ threadId: thread.id, body: `>>${thread.postNumber} A flat comment.`, credentials: [{ kind: 'followers-1k' }], ...{ parentId: 'not-a-real-parent' } });
  expect(thread.references).toEqual([]);
  expect(thread.author).toEqual({ credentials: [] });
  expect(comment.author.credentials).toEqual([{ kind: 'followers-1k' }]);
  expect(comment).not.toHaveProperty('parentId');
  expect(comment.postNumber).not.toBe(thread.postNumber);
  const reloaded = await repo.load();
  expect(resolvePost(reloaded, comment.postNumber)).toEqual({ thread, target: comment });
  expect(reloaded.nextPostNumber).toBe(Number(comment.postNumber) + 1);
}));
