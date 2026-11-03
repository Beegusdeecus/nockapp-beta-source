import { exclusive, storage } from '../platform/storage';
import { exact, object, validWirePost, wirePayload, type WirePost } from '../zkidWire';
import { validSelection, type Selection } from '../bundleDiscussion';

const KEY = 'nockapp:bundle:submission-intents:v3';
export type Intent = { draft_key: string; post: WirePost; selection: Selection; acknowledged: boolean; released: boolean };
export async function bundleIntents(): Promise<Intent[]> {
  const rows = await storage.get<unknown>(KEY);
  if (rows === undefined) return [];
  if (!Array.isArray(rows) || rows.length > 100 || !rows.every(v => object(v) && exact(v, ['draft_key', 'post', 'selection', 'acknowledged', 'released'])
    && typeof v.draft_key === 'string' && /^(thread|reply):bundle:/.test(v.draft_key) && validWirePost(v.post) && !v.post.claims.length
    && validSelection(v.selection) && typeof v.acknowledged === 'boolean' && typeof v.released === 'boolean')
    || new Set(rows.map(r => r.post.id)).size !== rows.length) throw new Error('Saved v3 submissions could not be read. Their data is preserved.');
  return rows as Intent[];
}
export function prepareBundleIntent(draft_key: string, post: WirePost, selection: Selection): Promise<Intent> {
  return exclusive(KEY, async () => {
    const rows = await bundleIntents();const old = rows.find(r => r.draft_key === draft_key && !r.released);
    if (old) {
      if (wirePayload({ ...post, id: old.post.id, created_at: old.post.created_at }) !== wirePayload(old.post)
        || JSON.stringify(old.selection) !== JSON.stringify(selection)) throw new Error('Recover the saved submission first, then choose Use edited draft. Your edits are preserved.');
      return old;
    }
    if (rows.length >= 100) throw new Error('Saved submission storage is full. Your draft is preserved.');
    const row = { draft_key, post, selection, acknowledged: false, released: false };await storage.set(KEY, [...rows, row]);return row;
  });
}
export function markBundleIntent(id: string, release = false): Promise<void> {
  return exclusive(KEY, async () => {
    const rows = await bundleIntents();const row = rows.find(r => r.post.id === id);
    if (!row) throw new Error('Saved intent is unavailable; your draft is preserved.');
    if (release && !row.acknowledged) throw new Error('Recover the submission before releasing its draft binding.');
    row.acknowledged = true;if (release) row.released = true;await storage.set(KEY, rows);
  });
}
