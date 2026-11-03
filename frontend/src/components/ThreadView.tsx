import { useEffect, useRef } from 'react';
import type { ForumData, PostReference, View } from '../model';
import { forum } from '../data/repository';
import { AuthorLine } from './AuthorLine';
import { Composer } from './Composer';
import { References } from './References';
import { PostBody, PostId } from './PostBody';
import { Icon } from './Icon';
import { publishComment } from '../xPost';
import { publishZkidComment } from '../zkidPublishing';

export function ThreadView({ data, view, onSelect, onReference, onChange, onRefresh, onNotice }: {
  data: ForumData; view: Extract<View, { kind: 'thread' }>; onSelect: (post: PostReference) => void;
  onReference: (number: string) => void; onNotice: (message: string) => void;
  onChange: (view: Extract<View, { kind: 'thread' }>) => void; onRefresh: () => Promise<void>;
}) {
  const thread = data.threads.find((t) => t.id === view.threadId);
  const comments = data.comments.filter((c) => c.threadId === view.threadId).sort((a, b) => a.createdAt - b.createdAt || Number(a.postNumber) - Number(b.postNumber));
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (view.focusPostId) {
      const target = document.getElementById(`post-${view.focusPostId}`);
      target?.scrollIntoView({ block: 'center' });
      target?.focus({ preventScroll: true });
    } else heading.current?.focus({ preventScroll: true });
  }, [view.threadId, view.focusPostId, view]);

  if (!thread) return <div className="empty-state"><Icon name="message" size={26} /><h2>Thread unavailable</h2><p>It may have been removed. Go back to the post’s references to keep exploring.</p></div>;
  return <div className="thread-view">
    <article id={`post-${thread.id}`} tabIndex={-1} className={`opening-post ${view.focusPostId === thread.id ? 'highlighted' : ''}`} aria-label={`Thread No.${thread.postNumber}`}>
      <div className="eyebrow">THE CONVERSATION</div><h1 ref={heading} tabIndex={-1}>{thread.title}</h1>
      <PostId number={thread.postNumber} onCopied={onNotice} /><AuthorLine author={thread.author} time={thread.createdAt} post={thread} />
      <PostBody className="thread-body" body={thread.body} onReference={onReference} />
      <References references={thread.references} onSelect={onSelect} />
    </article>
    <div className="thread-actions"><span><Icon name="message" size={14} />{comments.length} {comments.length === 1 ? 'comment' : 'comments'}</span><button className="text-button" onClick={() => {
      document.querySelector('.composer')?.scrollIntoView({ block: 'end' });
      (document.querySelector('.composer textarea') as HTMLTextAreaElement | null)?.focus({ preventScroll: true });
    }}>Add a comment <Icon name="arrow" size={14} /></button></div>
    <section className="replies" aria-labelledby="comments-heading"><h2 id="comments-heading" className="section-label">Comments <span>{comments.length.toString().padStart(2, '0')}</span></h2>
      {view.focusPostId && view.focusPostId !== thread.id && !comments.some((c) => c.id === view.focusPostId) && <p role="status" className="error-inline">That post is unavailable. The surrounding thread is shown below.</p>}
      {!comments.length && <p className="small-empty">No comments yet. There’s room for your perspective.</p>}
      {comments.map((comment) => <article key={comment.id} id={`post-${comment.id}`} data-testid={comment.id} tabIndex={-1} className={`comment ${view.focusPostId === comment.id ? 'highlighted' : ''}`} aria-label={`Comment No.${comment.postNumber}`}>
        {view.focusPostId === comment.id && <div className="matched-label">REFERENCED COMMENT</div>}
        <PostId number={comment.postNumber} onCopied={onNotice} /><AuthorLine author={comment.author} time={comment.createdAt} post={comment} />
        <PostBody className="comment-body" body={comment.body} onReference={onReference} /><References references={comment.references} onSelect={onSelect} />
      </article>)}
    </section>
    <Composer key={thread.id} draftKey={`reply:${thread.id}:root`} legacyTargets={Object.fromEntries(comments.map((c) => [c.id, c.postNumber]))} mode="reply" onSubmit={async (draft, signal) => {
      if (draft.zkidFacts?.length && draft.passportFacts?.length) throw new Error('Choose one credential flow for this post. Your draft is preserved.');
      const input = { threadId: thread.id, body: draft.body, credentials: draft.credentials };
      const comment = draft.zkidFacts?.length ? await publishZkidComment(forum, input, draft.zkidFacts, signal)
        : await publishComment(forum, input, draft.passportFacts, signal);
      await onRefresh(); if (!signal.aborted) { onChange({ ...view, focusPostId: comment.id }); onNotice('Your comment is saved on this device.'); }
    }} />
  </div>;
}
