/** Exact public-v5 intent persists BEFORE any native mutation; no keys/proofs. */
import { exclusive, storage } from '../platform/storage';
import { object, exact } from '../zkidWire';
import { canonicalAscii } from '../authoredWallet';
import { validPublicBody, validPublicScope, type PublicPost, type PublicReference, type PublicSelection, type PublicScope } from '../publicDiscussion';
export const PUBLIC_INTENTS_KEY = 'nockapp:public:submission-intents:v5';
export type PublicIntent = { scope: PublicScope; draft_key: string; post: PublicPost; selection: PublicSelection; thread: PublicReference | null;
  references: PublicReference[]; acknowledged: boolean; released: boolean };
const validKey = (v: unknown): v is string => typeof v === 'string' && /^(thread|reply):public-v5:/.test(v) && v.length <= 1024;
export function intentBody(v: PublicIntent) { return { post: v.post, selection: v.selection, thread: v.thread, references: v.references, approve_publication: true }; }
function valid(v: unknown): v is PublicIntent {
  return object(v) && exact(v, ['scope', 'draft_key', 'post', 'selection', 'thread', 'references', 'acknowledged', 'released'])
    && validPublicScope(v.scope) && validKey(v.draft_key) && typeof v.acknowledged === 'boolean' && typeof v.released === 'boolean'
    && !(v.released && !v.acknowledged) && Array.isArray(v.references)
    && (v.thread === null || object(v.thread) && v.thread.contract === v.scope.contract && v.thread.chain_id === v.scope.chain_id)
    && validPublicBody('public-prepare', { post: v.post, selection: v.selection, thread: v.thread, references: v.references, approve_publication: true });
}
export async function publicIntents(): Promise<PublicIntent[]> {
  const v = await storage.get<unknown>(PUBLIC_INTENTS_KEY);
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > 40 || !v.every(valid) || new Set(v.map(r => r.post.id)).size !== v.length)
    throw new Error('Saved public submissions could not be read. Their data is preserved.');
  return v;
}
export function samePublicScope(a: PublicScope, b: PublicScope) { return canonicalAscii(a) === canonicalAscii(b); }
export function preparePublicIntent(value: PublicIntent): Promise<PublicIntent> {
  const captured = structuredClone(value);
  if (!valid(captured) || captured.acknowledged || captured.released) return Promise.reject(new Error('Invalid public intent. Your draft is preserved.'));
  return exclusive(PUBLIC_INTENTS_KEY, async () => {
    const rows = await publicIntents();const old = rows.find(r => r.draft_key === captured.draft_key && samePublicScope(r.scope, captured.scope) && !r.released);
    if (old) {
      const normalized = { ...captured, post: { ...captured.post, id: old.post.id, created_at: old.post.created_at } };
      if (canonicalAscii(intentBody(normalized)) !== canonicalAscii(intentBody(old))) throw new Error('Recover the saved post, then choose Use edited draft. Your edits are preserved.');
      return structuredClone(old);
    }
    if (rows.length >= 40 || rows.some(r => r.post.id === captured.post.id)) throw new Error('Public submission storage is full or this identifier already exists. Saved data is preserved.');
    await storage.set(PUBLIC_INTENTS_KEY, [...rows, captured]);return structuredClone(captured);
  });
}
export function acknowledgePublicIntent(id: string, release = false): Promise<void> {
  return exclusive(PUBLIC_INTENTS_KEY, async () => {
    const rows = await publicIntents();const row = rows.find(r => r.post.id === id);
    if (!row || release && !row.acknowledged) throw new Error('Recover the saved public post before releasing its draft binding.');
    row.acknowledged = true;if (release) row.released = true;await storage.set(PUBLIC_INTENTS_KEY, rows);
  });
}
