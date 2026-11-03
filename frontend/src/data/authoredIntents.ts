import { exclusive, storage } from '../platform/storage';
import { exact, object, validWirePost, wirePayload, type WirePost } from '../zkidWire';
import { validAuthoredSelection as validSelection } from '../authoredDiscussion';
import { canonicalAscii, type AddressSelection as Selection, type PostSigningScope } from '../authoredWallet';

const KEY = 'nockapp:authored:submission-intents:v4';
export type Intent = { scope: PostSigningScope; draft_key: string; post: WirePost; selection: Selection; acknowledged: boolean; released: boolean };
export async function authoredIntents(): Promise<Intent[]> {
  const rows = await storage.get<unknown>(KEY);
  if (rows === undefined) return [];
  if (!Array.isArray(rows) || rows.length > 100 || !rows.every(v => object(v) && exact(v, ['scope', 'draft_key', 'post', 'selection', 'acknowledged', 'released'])
    && object(v.scope) && exact(v.scope, ['chain_id', 'application', 'contract']) && v.scope.chain_id === 84532
    && typeof v.scope.application === 'string' && /^0x[0-9a-f]{64}$/.test(v.scope.application) && !/^0x0+$/.test(v.scope.application)
    && typeof v.scope.contract === 'string' && /^0x[0-9a-f]{40}$/.test(v.scope.contract) && !/^0x0+$/.test(v.scope.contract)
    && typeof v.draft_key === 'string' && /^(thread|reply):authored:/.test(v.draft_key) && validWirePost(v.post) && !v.post.claims.length
    && validSelection(v.selection) && typeof v.acknowledged === 'boolean' && typeof v.released === 'boolean')
    || new Set(rows.map(r => r.post.id)).size !== rows.length) throw new Error('Saved v4 submissions could not be read. Their data is preserved.');
  return rows as Intent[];
}
export function prepareAuthoredIntent(draft_key: string, post: WirePost, selection: Selection, scope: PostSigningScope): Promise<Intent> {
  if (!validWirePost(post) || post.claims.length || !validSelection(selection) || new TextEncoder().encode(wirePayload(post)).length > 8192
    || !object(scope) || !exact(scope, ['chain_id', 'application', 'contract']) || scope.chain_id !== 84532
    || !/^0x[0-9a-f]{64}$/.test(scope.application) || /^0x0+$/.test(scope.application)
    || !/^0x[0-9a-f]{40}$/.test(scope.contract) || /^0x0+$/.test(scope.contract) || !/^(thread|reply):authored:/.test(draft_key))
    throw new Error('The draft cannot be signed in this application. Check its title, text and size; your draft is preserved.');
  const capturedPost = structuredClone(post);const capturedSelection = structuredClone(selection);const capturedScope = structuredClone(scope);
  return exclusive(KEY, async () => {
    const rows = await authoredIntents();const old = rows.find(r => r.draft_key === draft_key && canonicalAscii(r.scope) === canonicalAscii(capturedScope) && !r.released);
    if (old) {
      if (wirePayload({ ...capturedPost, id: old.post.id, created_at: old.post.created_at }) !== wirePayload(old.post)
        || canonicalAscii(old.selection) !== canonicalAscii(capturedSelection)) throw new Error('Recover the saved submission first, then choose Use edited draft. Your edits are preserved.');
      return old;
    }
    if (rows.length >= 100) throw new Error('Saved submission storage is full. Your draft is preserved.');
    const row = { scope: capturedScope, draft_key, post: capturedPost, selection: capturedSelection, acknowledged: false, released: false };await storage.set(KEY, [...rows, row]);return row;
  });
}
export function markAuthoredIntent(id: string, release = false): Promise<void> {
  return exclusive(KEY, async () => {
    const rows = await authoredIntents();const row = rows.find(r => r.post.id === id);
    if (!row) throw new Error('Saved intent is unavailable; your draft is preserved.');
    if (release && !row.acknowledged) throw new Error('Recover the submission before releasing its draft binding.');
    row.acknowledged = true;if (release) row.released = true;await storage.set(KEY, rows);
  });
}

export function belongsToScope(intent: Intent, scope: PostSigningScope): boolean { return canonicalAscii(intent.scope) === canonicalAscii({ chain_id: scope.chain_id, application: scope.application, contract: scope.contract }); }
