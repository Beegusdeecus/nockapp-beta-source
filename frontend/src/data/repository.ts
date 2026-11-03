import type { Author, Comment, CredentialClaim, ExternalReference, ForumData, PostFactReference, PostIdentity, ReferenceResults, Thread, ZkidReference } from '../model';
import { validZkidReference, wirePayload, wirePost } from '../zkidWire';
import { validPostFacts } from '../postScope';
import { exclusive, storage, type StorageAdapter } from '../platform/storage';
import { extractReferences } from '../urls';
import { seedData } from './seed';

// Keep the original storage address so installed extensions migrate in place.
export const FORUM_KEY = 'nockapp:forum:v1';
export interface ThreadInput { title: string; body: string; references: ExternalReference[]; credentials?: CredentialClaim[]; identity?: PostIdentity; passport?: PostFactReference[]; zkid?: ZkidReference }
export interface CommentInput { threadId: string; body: string; credentials?: CredentialClaim[]; identity?: PostIdentity; passport?: PostFactReference[]; zkid?: ZkidReference }
export interface ForumRepository {
  load(): Promise<ForumData>;
  createThread(input: ThreadInput): Promise<Thread>;
  reply(input: CommentInput): Promise<Comment>;
}

export function findReferences(data: ForumData, postId: string): ReferenceResults {
  return {
    threads: data.threads.filter((t) => t.references.some((r) => r.postId === postId)).sort((a, b) => b.createdAt - a.createdAt),
    comments: data.comments.filter((c) => c.references.some((r) => r.postId === postId)).flatMap((comment) => {
      const thread = data.threads.find((t) => t.id === comment.threadId);
      return thread ? [{ comment, thread }] : [];
    }).sort((a, b) => b.comment.createdAt - a.comment.createdAt),
  };
}
export function resolvePost(data: ForumData, number: string): { thread: Thread; target: Thread | Comment } | undefined {
  const thread = data.threads.find((t) => t.postNumber === number);
  if (thread) return { thread, target: thread };
  const comment = data.comments.find((c) => c.postNumber === number);
  const parent = comment && data.threads.find((t) => t.id === comment.threadId);
  return comment && parent ? { thread: parent, target: comment } : undefined;
}

export function validCredentials(value: unknown): value is CredentialClaim[] {
  return Array.isArray(value) && value.length <= 4 && value.every((c: CredentialClaim) => c
    && ['x-account', 'followers-1k', 'followers-10k', 'followed-by'].includes(c.kind)
    && (c.account === undefined || typeof c.account === 'string'));
}
function failure(): never { throw new Error('Saved demo data could not be read. It has been preserved. See Settings for recovery instructions.'); }

type LegacyThread = Omit<Thread, 'postNumber'>;
type LegacyComment = Omit<Comment, 'postNumber'> & { parentId?: string };
interface LegacyData { schema: 1; threads: LegacyThread[]; comments: LegacyComment[] }

function validate(data: unknown): asserts data is ForumData | LegacyData {
  if (!data || typeof data !== 'object') failure();
  const d = data as ForumData | LegacyData;
  const refs = (r: ExternalReference[]) => Array.isArray(r) && r.every((v) => {
    if (!v || typeof v.url !== 'string' || (v.postId !== undefined && (typeof v.postId !== 'string' || !/^\d{1,20}$/.test(v.postId)))) return false;
    try { const url = new URL(v.url); return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password; } catch { return false; }
  });
  const item = (v: LegacyThread | LegacyComment) => v && typeof v.id === 'string' && v.id.length > 0
    && typeof v.body === 'string' && v.author && validCredentials(v.author.credentials)
    && (v.author.passport === undefined || validPostFacts(v.author.passport))
    && (v.author.zkid === undefined || validZkidReference(v.author.zkid))
    && typeof v.createdAt === 'number' && Number.isFinite(v.createdAt) && refs(v.references);
  if (![1, 2].includes(d.schema) || !Array.isArray(d.threads) || !Array.isArray(d.comments)
    || !d.threads.every((t) => item(t) && typeof t.title === 'string')
    || !d.comments.every((c) => item(c) && typeof c.threadId === 'string')) failure();
  const items = [...d.threads, ...d.comments];
  if (new Set(items.map((v) => v.id)).size !== items.length) failure();
  const threadIds = new Set(d.threads.map((t) => t.id));
  if (d.comments.some((c) => !threadIds.has(c.threadId))) failure();
  if (d.schema === 2) {
    if (!Number.isSafeInteger(d.nextPostNumber) || d.nextPostNumber < 1) failure();
    const numbers = items.map((v) => (v as Thread | Comment).postNumber);
    if (numbers.some((n) => typeof n !== 'string' || !/^[1-9]\d{0,15}$/.test(n) || !Number.isSafeInteger(Number(n)) || Number(n) >= d.nextPostNumber)
      || new Set(numbers).size !== numbers.length || d.comments.some((c) => 'parentId' in c)) failure();
  } else {
    const comments = new Map(d.comments.map((c) => [c.id, c]));
    for (const c of d.comments) {
      const seen = new Set([c.id]);
      let parentId = c.parentId;
      if (parentId !== undefined && (typeof parentId !== 'string' || !parentId)) failure();
      while (parentId) {
        const parent = comments.get(parentId);
        if (!parent || parent.threadId !== c.threadId || seen.has(parentId)) failure();
        seen.add(parentId); parentId = parent.parentId;
      }
    }
  }
}

export function upgradeLegacy(data: LegacyData): ForumData {
  const ordered = [...data.threads, ...data.comments].sort((a, b) => a.createdAt - b.createdAt);
  const numbers = new Map(ordered.map((p, i) => [p.id, String(100001 + i)]));
  const author = (a: Author): Author => ({ credentials: a.credentials,
    ...(a.passport ? { passport: a.passport } : {}), ...(a.zkid ? { zkid: a.zkid } : {}) });
  return {
    schema: 2, nextPostNumber: 100001 + ordered.length,
    threads: data.threads.map((t) => ({ ...t, postNumber: numbers.get(t.id)!, author: author(t.author) })),
    comments: data.comments.map(({ parentId: _oldParent, ...c }) => ({ ...c, postNumber: numbers.get(c.id)!, author: author(c.author) })),
  };
}

function selectedAuthor(credentials: CredentialClaim[] = [], passport?: PostFactReference[], zkid?: ZkidReference): Author {
  if (!validCredentials(credentials)) throw new Error('Choose valid optional demo credentials.');
  if (passport !== undefined && !validPostFacts(passport)) throw new Error('Choose valid passport facts.');
  if (zkid !== undefined && (!validZkidReference(zkid) || passport?.length)) throw new Error('Choose one supported credential flow for this post.');
  return { credentials: structuredClone(credentials), ...(passport?.length ? { passport: structuredClone(passport) } : {}),
    ...(zkid ? { zkid: structuredClone(zkid) } : {}) };
}
function identity(data: ForumData, input: { identity?: PostIdentity; passport?: PostFactReference[]; zkid?: ZkidReference }): PostIdentity {
  if (!input.identity && !input.passport?.length && !input.zkid) return { id: crypto.randomUUID(), createdAt: Date.now() };
  const value = input.identity;
  if (!value || (!input.passport?.length && !input.zkid) || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.id)
      || !Number.isSafeInteger(value.createdAt) || value.createdAt <= 0 || value.createdAt > Date.now() + 300000
      || [...data.threads, ...data.comments].some(v => v.id === value.id)) throw new Error('Invalid or duplicate signed post identity.');
  return { id: value.id, createdAt: value.createdAt };
}
function allocate(data: ForumData): string {
  if (!Number.isSafeInteger(data.nextPostNumber + 1)) throw new Error('The local post ID range is exhausted.');
  return String(data.nextPostNumber++);
}

export class LocalForumRepository implements ForumRepository {
  constructor(private readonly adapter: StorageAdapter = storage) {}
  private async read(): Promise<ForumData> {
    const saved = await this.adapter.get<unknown>(FORUM_KEY);
    if (saved === undefined) {
      const data = seedData(); await this.adapter.set(FORUM_KEY, data); return data;
    }
    validate(saved);
    if (saved.schema === 2) return saved;
    const migrated = upgradeLegacy(saved);
    validate(migrated);
    // The immutable, unique backup must succeed before changing the old snapshot.
    await this.adapter.set(`nockapp:backup:v1:${Date.now()}:${crypto.randomUUID()}`, saved);
    await this.adapter.set(FORUM_KEY, migrated);
    return migrated;
  }
  load(): Promise<ForumData> { return exclusive('forum', () => this.read()); }
  createThread(input: ThreadInput): Promise<Thread> {
    return exclusive('forum', async () => {
      const title = input.title.trim(); const body = input.body.trim();
      if (!title || title.length > 120 || !body || body.length > 6000) throw new Error('Add a title (up to 120 characters) and an opening comment (up to 6,000 characters).');
      const data = await this.read();
      const author = selectedAuthor(input.credentials, input.passport, input.zkid), references = extractReferences(body, input.references);
      const existing = input.zkid && input.identity && data.threads.find(v => v.id === input.identity!.id);
      if (existing) {
        const intended: Thread = { ...existing, ...input.identity!, title, body, references, author };
        if (wirePayload(wirePost(existing)) !== wirePayload(wirePost(intended)) || JSON.stringify(existing.author) !== JSON.stringify(author))
          throw new Error('A different post already uses that saved identity. Recovery has been preserved.');
        return existing; // Lost local write reply: SAME signed post, no second allocation.
      }
      const thread: Thread = { ...identity(data, input), postNumber: allocate(data), title, body,
        author, references };
      data.threads.unshift(thread);
      await this.adapter.set(FORUM_KEY, data); return thread;
    });
  }
  reply(input: CommentInput): Promise<Comment> {
    return exclusive('forum', async () => {
      const body = input.body.trim();
      if (!body || body.length > 6000) throw new Error('Write a comment of up to 6,000 characters.');
      const data = await this.read();
      if (!data.threads.some((t) => t.id === input.threadId)) throw new Error('This thread is unavailable. Your draft is still saved.');
      const author = selectedAuthor(input.credentials, input.passport, input.zkid), references = extractReferences(body);
      const existing = input.zkid && input.identity && data.comments.find(v => v.id === input.identity!.id);
      if (existing) {
        const intended: Comment = { ...existing, ...input.identity!, threadId: input.threadId, body, references, author };
        if (wirePayload(wirePost(existing)) !== wirePayload(wirePost(intended)) || JSON.stringify(existing.author) !== JSON.stringify(author))
          throw new Error('A different post already uses that saved identity. Recovery has been preserved.');
        return existing;
      }
      const comment: Comment = { threadId: input.threadId, body, ...identity(data, input), postNumber: allocate(data),
        author, references };
      data.comments.push(comment);
      await this.adapter.set(FORUM_KEY, data); return comment;
    });
  }
}
export const forum: ForumRepository = new LocalForumRepository();
