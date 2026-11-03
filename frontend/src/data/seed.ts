import type { Author, ForumData, PostReference } from '../model';

export const DEMO_POST: PostReference = { postId: '1900000000000000001', url: 'https://x.com/i/status/1900000000000000001' };
export const OTHER_POST: PostReference = { postId: '1900000000000000002', url: 'https://x.com/i/status/1900000000000000002' };
export const EMPTY_POST = 'https://x.com/i/status/1900000000000000099';

export function seedData(): ForumData {
  const now = Date.now();
  const anon = (credentials: Author['credentials'] = []): Author => ({ credentials });
  return {
    schema: 2, nextPostNumber: 100010,
    threads: [
      { id: 'thread-conversation', postNumber: '100006', title: 'What if the best part of a post is the conversation after it?',
        body: 'A timeline is good at getting your attention. Less good at giving an idea room to breathe.\n\nWould you rather discuss the argument without knowing who made it? I’m curious what changes when the follower count disappears.',
        author: anon([{ kind: 'followers-1k' }]), createdAt: now - 42 * 60_000, references: [DEMO_POST] },
      { id: 'thread-context', postNumber: '100003', title: 'A little more context, a little less noise.',
        body: 'The same link can mean very different things in different conversations. This thread is a place to compare interpretations, rather than compete for the last word.',
        author: anon(), createdAt: now - 3 * 3_600_000, references: [DEMO_POST, OTHER_POST] },
      { id: 'thread-identity', postNumber: '100001', title: 'Anonymity doesn’t have to mean starting from zero.',
        body: 'You might want to show that you understand a subject without handing over your name. What would a useful, minimal credential look like?\n\nAll badges in this prototype are fictional demo data.',
        author: anon([{ kind: 'x-account' }]), createdAt: now - 6 * 3_600_000, references: [OTHER_POST] },
    ],
    comments: [
      { id: 'comment-pace', postNumber: '100007', threadId: 'thread-conversation', body: 'Slowing down would be a feature. A good reply should outlive the first ten minutes.', author: anon(), createdAt: now - 31 * 60_000, references: [] },
      { id: 'comment-reference', postNumber: '100008', threadId: 'thread-conversation', body: '>>100007 Exactly. This is the post that got me thinking about it. The discussion deserves its own space.', author: anon([{ kind: 'followers-10k' }]), createdAt: now - 24 * 60_000, references: [DEMO_POST] },
      { id: 'comment-room', postNumber: '100009', threadId: 'thread-conversation', body: 'Keep the source in view, but give people room to disagree without performing for an audience.', author: anon(), createdAt: now - 18 * 60_000, references: [] },
      { id: 'comment-context', postNumber: '100005', threadId: 'thread-context', body: '>>100006 Worth reading alongside the original. I think the interesting question is what we lose when everything becomes a quote-post.', author: anon([{ kind: 'followed-by', account: 'demo_researcher' }]), createdAt: now - 2 * 3_600_000, references: [DEMO_POST] },
      { id: 'comment-identity', postNumber: '100002', threadId: 'thread-identity', body: 'This post is a useful example: prove a narrow claim, then let the words stand on their own. A badge should add context, not settle the argument.', author: anon([{ kind: 'x-account' }]), createdAt: now - 4 * 3_600_000, references: [DEMO_POST] },
      { id: 'comment-minimal', postNumber: '100004', threadId: 'thread-identity', body: '>>100002 And make every claim optional. Anonymous participation should remain the default.', author: anon(), createdAt: now - 3 * 3_600_000, references: [] },
    ],
  };
}
