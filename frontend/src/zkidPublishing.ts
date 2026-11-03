import type { Comment, CredentialClaim, Thread, ZkidFact, ZkidReference } from './model';
import type { CommentInput, ForumRepository, ThreadInput } from './data/repository';
import { extractReferences } from './urls';
import { factOperation, type FactAccepted, type PendingPost } from './zkidFacts';
import { validWirePost, validZkidFacts, sortedFacts, wirePayload, wirePost, type WirePost } from './zkidWire';

export async function storeAcceptedPost(repo: ForumRepository, post: WirePost, result: FactAccepted, signal?: AbortSignal): Promise<Thread | Comment> {
  if (!validWirePost(post) || signal?.aborted || result.expires_at * 1000 <= Date.now()) throw new Error('The post check expired or stopped. Saved recovery and your draft are preserved.');
  // Bind a recovered reference to the actual intent, and recheck current expiry/
  // registry before the local write. A generic recovery reply alone is insufficient.
  result = await factOperation<FactAccepted>('post-inspect', { post, facts: result.reference.facts, nonce: result.reference.nonce }, signal);
  if (signal?.aborted || result.expires_at * 1000 <= Date.now()) throw new Error('The post check expired or stopped.');
  const common = { body: post.body, credentials: post.claims.map(([kind, account]) => ({ kind, ...(account === null ? {} : { account }) })) as CredentialClaim[],
    identity: { id: post.id, createdAt: post.created_at }, zkid: result.reference };
  const saved = post.kind === 'thread' ? await repo.createThread({ ...common, title: post.title!,
    references: post.references.map(([url, postId]) => ({ url, ...(postId === null ? {} : { postId }) })) })
    : await repo.reply({ ...common, threadId: post.thread_id! });
  if (wirePayload(wirePost(saved)) !== wirePayload(post)) throw new Error('The saved post changed. Keep helper recovery for inspection.');
  // Local publication is durable first. A lost completion ACK must not turn a
  // saved post into a failure/retry with a different UUID. Recovery is idempotent.
  try { await factOperation('post-complete', { post, facts: result.reference.facts, nonce: result.reference.nonce, confirm_published: true }, signal); }
  catch { /* Exact helper intent remains available in the recovery controls. */ }
  return saved;
}
async function publish(repo: ForumRepository, post: WirePost, selected: ZkidFact[], signal?: AbortSignal) {
  if (!validZkidFacts(selected, false)) throw new Error('Choose supported public-post facts.');
  const facts = sortedFacts(selected);
  const result = await factOperation<FactAccepted>('post-use', { post, facts, approve_facts: facts, approve_identity_disclosure: false }, signal);
  return storeAcceptedPost(repo, post, result, signal);
}
export async function publishZkidThread(repo: ForumRepository, input: ThreadInput, facts: ZkidFact[], signal?: AbortSignal): Promise<Thread> {
  const thread: Thread = { id: crypto.randomUUID(), createdAt: Date.now(), postNumber: '0', title: input.title.trim(), body: input.body.trim(),
    references: extractReferences(input.body.trim(), input.references), author: { credentials: input.credentials ?? [] } };
  return await publish(repo, wirePost(thread), facts, signal) as Thread;
}
export async function publishZkidComment(repo: ForumRepository, input: CommentInput, facts: ZkidFact[], signal?: AbortSignal): Promise<Comment> {
  const comment: Comment = { id: crypto.randomUUID(), createdAt: Date.now(), postNumber: '0', threadId: input.threadId, body: input.body.trim(),
    references: extractReferences(input.body.trim()), author: { credentials: input.credentials ?? [] } };
  return await publish(repo, wirePost(comment), facts, signal) as Comment;
}
export async function recoverZkidPost(repo: ForumRepository, pending: PendingPost, retry: boolean, signal?: AbortSignal) {
  const result = await factOperation<FactAccepted>(retry ? 'post-retry' : pending.state === 'prepared' || pending.state === 'challenge-saved' ? 'post-use' : 'post-recover',
    retry || pending.state === 'prepared' || pending.state === 'challenge-saved'
      ? { post: pending.post, facts: pending.facts, approve_facts: pending.facts, approve_identity_disclosure: false } : {}, signal);
  if (JSON.stringify(result.reference.facts) !== JSON.stringify(pending.facts)) throw new Error('Saved fact selection does not match.');
  return storeAcceptedPost(repo, pending.post, result, signal);
}
export function inspectZkidPost(post: Thread | Comment, reference: ZkidReference, signal?: AbortSignal) {
  return factOperation<FactAccepted>('post-inspect', { post: wirePost(post), facts: reference.facts, nonce: reference.nonce }, signal);
}
