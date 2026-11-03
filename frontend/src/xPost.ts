import type { Comment, PassportFact, PostFactReference, Thread } from './model';
import type { CommentInput, ForumRepository, ThreadInput } from './data/repository';
import { extractReferences } from './urls';
import { postScope, validFacts } from './postScope';
import { PassportError, passportOperation, type PostFactResult } from './xPassport';

function operationError(value: unknown): Error {
  const messages: Record<string, string> = {
    'keyring-locked': 'Unlock your Ubuntu keyring, then retry the post. Your draft is preserved.',
    'keyring-unavailable': 'Open your Ubuntu desktop keyring before posting a passport fact.',
    'holder-key-missing': 'The original holder key is missing. Restore it, or remove passport facts to post anonymously.',
    'unsupported-helper': 'Update the proving helper before using post facts, or remove the facts to post anonymously.',
    'passport-unavailable': 'No usable passport is selected. Refresh it, or remove passport facts to post anonymously.',
    'helper-busy': 'Another helper operation is running. Wait and retry; your draft is preserved.',
    'job-cancelled': 'Passport use was cancelled. Your draft is preserved.',
  };
  return new Error(value instanceof PassportError ? messages[value.code]
    ?? 'The helper did not accept the passport fact. Your draft is preserved; you can remove the fact to post anonymously.'
    : 'The passport check failed. Your draft is preserved.');
}
async function references(post: Thread | Comment, facts: PassportFact[], signal?: AbortSignal): Promise<PostFactReference[]> {
  if (!validFacts(facts)) throw new Error('Choose supported passport facts.');
  const scope = await postScope(post);
  const result: PostFactReference[] = [];
  for (const fact of facts) {
    try {
      const accepted = await passportOperation('use_passport', { scope, fact, signal });
      if (!['post-used', 'synthetic-post-used'].includes(accepted.status)) throw new Error('Unsupported fact result');
      result.push({ profile: 'nockapp-x-post-fact-v1', fact, challenge: (accepted as PostFactResult).challenge });
    } catch (error) { throw operationError(error); }
  }
  if (signal?.aborted) throw operationError(new PassportError('job-cancelled'));
  return result;
}
export async function publishThread(repo: ForumRepository, input: ThreadInput, facts: PassportFact[] = [], signal?: AbortSignal): Promise<Thread> {
  if (!facts.length) return repo.createThread(input);
  const title = input.title.trim(), body = input.body.trim();
  if (!title || title.length > 120 || !body || body.length > 6000) throw new Error('Check the title and post length before signing.');
  const identity = { id: crypto.randomUUID(), createdAt: Date.now() };
  const normalized = { ...input, title, body, references: extractReferences(body, input.references) };
  const intent: Thread = { ...identity, ...normalized, postNumber: '0', author: { credentials: input.credentials ?? [] } };
  const passport = await references(intent, facts, signal);
  return repo.createThread({ ...normalized, identity, passport });
}
export async function publishComment(repo: ForumRepository, input: CommentInput, facts: PassportFact[] = [], signal?: AbortSignal): Promise<Comment> {
  if (!facts.length) return repo.reply(input);
  const body = input.body.trim();
  if (!body || body.length > 6000) throw new Error('Check the post length before signing.');
  const identity = { id: crypto.randomUUID(), createdAt: Date.now() };
  const intent: Comment = { ...identity, threadId: input.threadId, body, postNumber: '0',
    references: extractReferences(body), author: { credentials: input.credentials ?? [] } };
  const passport = await references(intent, facts, signal);
  return repo.reply({ ...input, body, identity, passport });
}
export async function inspectPost(post: Thread | Comment, reference: PostFactReference, signal?: AbortSignal): Promise<PostFactResult> {
  const result = await passportOperation('inspect_post', { scope: await postScope(post), fact: reference.fact,
    challenge: reference.challenge, signal });
  if (result.status !== 'post-checked' && result.status !== 'synthetic-post-checked') throw new PassportError('unsupported-helper');
  return result;
}
