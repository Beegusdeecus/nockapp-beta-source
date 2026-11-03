import type { ZkidFact } from '../model';
import { exclusive, storage } from '../platform/storage';
import { exact, object, validWirePost, validZkidFacts, sortedFacts, wirePayload, type WirePost } from '../zkidWire';

const KEY = 'nockapp:base:submission-intents:v1';
export type SharedIntent = { draft_key: string; post: WirePost; facts: ZkidFact[]; released: boolean };
export async function sharedIntents(): Promise<SharedIntent[]> {
  const saved = await storage.get<unknown>(KEY);
  if (saved === undefined) return [];
  if (!Array.isArray(saved) || saved.length > 100 || !saved.every(v => object(v)
    && exact(v, ['draft_key', 'post', 'facts', 'released']) && typeof v.draft_key === 'string' && /^(thread|reply):shared:/.test(v.draft_key)
    && validWirePost(v.post) && v.post.claims.length === 0 && validZkidFacts(v.facts)
    && JSON.stringify(v.facts) === JSON.stringify(sortedFacts(v.facts)) && typeof v.released === 'boolean')
    || new Set(saved.map(v => v.post.id)).size !== saved.length) throw new Error('Saved shared submissions could not be read. Their data has been preserved.');
  return saved as SharedIntent[];
}
export function prepareSharedIntent(draftKey: string, post: WirePost, facts: ZkidFact[]): Promise<SharedIntent> {
  return exclusive(KEY, async () => {
    const rows = await sharedIntents();const pending = rows.find(r => r.draft_key === draftKey && !r.released);
    if (pending) {
      if (wirePayload({ ...post, id: pending.post.id, created_at: pending.post.created_at }) !== wirePayload(pending.post)
        || JSON.stringify(facts) !== JSON.stringify(pending.facts)) throw new Error('Recover the saved submission for this draft before publishing changed text. Your edits are preserved.');
      return pending;
    }
    if (rows.length >= 100) throw new Error('Shared submission storage is full. Your draft is preserved.');
    const row = { draft_key: draftKey, post, facts, released: false };
    await storage.set(KEY, [...rows, row]);return row;
  });
}
export function releaseSharedIntent(postId: string): Promise<void> {
  return exclusive(KEY, async () => {
    const rows = await sharedIntents();const row = rows.find(r => r.post.id === postId);
    if (!row) throw new Error('Saved shared submission is unavailable. Your draft is preserved.');
    row.released = true;await storage.set(KEY, rows);
  });
}
