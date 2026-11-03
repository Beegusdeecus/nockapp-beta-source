import type { Comment, PassportFact, PostFactReference, Thread } from './model';

export const PASSPORT_FACTS: PassportFact[] = ['account-controlled', 'followers-over-10000'];
export const factLabel = (fact: PassportFact) => fact === 'account-controlled' ? 'X account control' : 'More than 10,000 followers';
export const validFacts = (value: unknown): value is PassportFact[] => Array.isArray(value) && value.length <= 2
  && new Set(value).size === value.length && value.every(v => PASSPORT_FACTS.includes(v));
export function validPostFacts(value: unknown): value is PostFactReference[] {
  return Array.isArray(value) && value.length <= 2 && validFacts(value.map(v => v?.fact))
    && new Set(value.map(v => v?.challenge)).size === value.length && value.every(v => v && typeof v === 'object'
      && Object.keys(v).sort().join(',') === 'challenge,fact,profile' && v.profile === 'nockapp-x-post-fact-v1'
      && typeof v.challenge === 'string' && /^[0-9a-f]{64}$/.test(v.challenge) && !/^0+$/.test(v.challenge));
}
export function postScopePayload(post: Thread | Comment): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(post.id)
      || !Number.isSafeInteger(post.createdAt) || post.createdAt <= 0) throw new Error('Invalid signed post identity.');
  // Arrays define an unambiguous order. References, text, context, identity and
  // visible demo claims are bound; the signature references themselves are not.
  return JSON.stringify(['NOCKAPP/X/POST-SCOPE/v1', 'threadId' in post ? 'comment' : 'thread',
    post.id, post.createdAt, 'threadId' in post ? post.threadId : null, 'title' in post ? post.title : null,
    post.body, post.references.map(r => [r.url, r.postId ?? null]),
    post.author.credentials.map(c => [c.kind, c.account ?? null])]);
}
export async function postScope(post: Thread | Comment): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(postScopePayload(post)));
  return Array.from(new Uint8Array(digest), v => v.toString(16).padStart(2, '0')).join('');
}
