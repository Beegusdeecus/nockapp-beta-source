import type { Comment, Thread, ZkidFact, ZkidReference } from './model';

export const ZKID_REFERENCE = 'nockapp-zkid-post-reference-v1';
export const ZKID_FACTS: ZkidFact[] = ['account-controlled', 'followers-at-least-10000'];
export const zkidFactLabel = (fact: ZkidFact) => fact === 'account-controlled' ? 'X account control' : 'At least 10,000 followers';
export const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
export const exact = (v: Record<string, unknown>, keys: string[]) => Object.keys(v).sort().join('|') === [...keys].sort().join('|');
export const hex = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) && !/^0+$/.test(v);
const uuid = (v: unknown) => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const text = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max && !/[\uD800-\uDFFF]/u.test(v);
export const validZkidFacts = (v: unknown, empty = true): v is ZkidFact[] => Array.isArray(v) && (empty || v.length > 0)
  && v.length <= 2 && new Set(v).size === v.length && v.every(f => ZKID_FACTS.includes(f));
export const sortedFacts = (facts: ZkidFact[]): ZkidFact[] => [...facts].sort();
export function validZkidReference(v: unknown): v is ZkidReference {
  return object(v) && exact(v, ['profile', 'nonce', 'facts']) && v.profile === ZKID_REFERENCE && hex(v.nonce)
    && validZkidFacts(v.facts, false) && JSON.stringify(v.facts) === JSON.stringify(sortedFacts(v.facts));
}
export type WirePost = { kind: 'thread' | 'comment'; id: string; created_at: number; thread_id: string | null;
  title: string | null; body: string; references: [string, string | null][]; claims: [string, string | null][] };
export function validWirePost(v: unknown): v is WirePost {
  if (!object(v) || !exact(v, ['kind', 'id', 'created_at', 'thread_id', 'title', 'body', 'references', 'claims'])
      || !['thread', 'comment'].includes(String(v.kind)) || !uuid(v.id) || !Number.isSafeInteger(v.created_at) || Number(v.created_at) <= 0
      || !text(v.body, 6000) || v.body !== v.body.trim()
      || (v.kind === 'thread' ? !text(v.title, 120) || v.title !== v.title.trim() || v.thread_id !== null : v.title !== null || !text(v.thread_id, 128))
      || !Array.isArray(v.references) || v.references.length > 64
      || !v.references.every(r => Array.isArray(r) && r.length === 2 && text(r[0], 2048)
        && (r[1] === null || typeof r[1] === 'string' && /^[1-9][0-9]{0,19}$/.test(r[1])))
      || !Array.isArray(v.claims) || v.claims.length > 4
      || !v.claims.every(c => Array.isArray(c) && c.length === 2 && ['x-account', 'followers-1k', 'followers-10k', 'followed-by'].includes(c[0])
        && (c[1] === null || text(c[1], 64))) || new Set(v.claims.map(c => c[0])).size !== v.claims.length) return false;
  return true;
}
export function wirePost(post: Thread | Comment): WirePost {
  const value: WirePost = { kind: 'threadId' in post ? 'comment' : 'thread', id: post.id, created_at: post.createdAt,
    thread_id: 'threadId' in post ? post.threadId : null, title: 'title' in post ? post.title : null, body: post.body,
    references: post.references.map(r => [r.url, r.postId ?? null]), claims: post.author.credentials.map(c => [c.kind, c.account ?? null]) };
  if (!validWirePost(value)) throw new Error('This post cannot be bound to a public-post credential. Your draft is preserved.');
  return value;
}
export function wirePayload(v: WirePost): string {
  if (!validWirePost(v)) throw new Error('Invalid public-post intent.');
  return JSON.stringify(['NOCKAPP/ZKID/POST-SCOPE/v1', v.kind, v.id, v.created_at, v.thread_id, v.title, v.body, v.references, v.claims]);
}
