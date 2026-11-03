import { useCallback, useEffect, useRef, useState } from 'react';
import { baseOperation, type BaseIdentity, type DiscussionPage, type SharedPost, type Submission } from '../baseDiscussion';
import { sharedIntents, type SharedIntent } from '../data/sharedIntents';
import { zkidFactLabel } from '../zkidWire';
import { parsePostUrl } from '../urls';
import { LegacyDrafts } from './LegacyDrafts';
import { PostBody, PostId } from './PostBody';
import { getSelection, subscribeSelection, windowKey } from '../platform/selection';
import type { Selection } from '../model';

const date = (v: number) => new Date(v * 1000).toLocaleString();
export function LegacySharedDiscussion() {
  const [identity, setIdentity] = useState<BaseIdentity>();
  const [posts, setPosts] = useState<SharedPost[]>([]);
  const [intents, setIntents] = useState<SharedIntent[]>([]);
  const [outbox, setOutbox] = useState<Submission[]>([]);
  const [thread, setThread] = useState<string>();
  const [selected, setSelected] = useState('');
  const [input, setInput] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [more, setMore] = useState(false);
  const [complete, setComplete] = useState(false);
  const mounted = useRef(true);
  const working = useRef(false);
  const identityRef = useRef<BaseIdentity | undefined>(undefined);
  const rowsRef = useRef<SharedPost[]>([]);
  const refresh = useCallback(async (append = false) => {
    if (working.current) return;
    working.current = true;setBusy(true);setError('');
    try {
      const local = await sharedIntents();if (mounted.current) setIntents(local);
      const caps = await baseOperation<{ configured: boolean; identity?: BaseIdentity }>('base-capabilities');
      if (!caps.configured || !caps.identity) throw new Error('Shared discussions need the configured Ubuntu Base helper. Saved device discussions remain available.');
      if (identityRef.current && JSON.stringify(identityRef.current) !== JSON.stringify(caps.identity)) throw new Error('The installed shared service identity changed. Reopen the panel after checking the update.');
      identityRef.current = caps.identity;
      if (mounted.current) setIdentity(caps.identity);
      const saved: Submission[] = [];let cursor = 0;
      for (let i = 0; i < 13; i++) {
        const box = await baseOperation<{ entries: Submission[]; next_after: number; more: boolean }>('base-outbox', { after: cursor, limit: 8 });
        saved.push(...box.entries);if (!box.more) break;
        if (box.next_after <= cursor) throw new Error('Saved submission page is unavailable.');
        cursor = box.next_after;
      }
      if (mounted.current) setOutbox(saved);
      const page = await baseOperation<DiscussionPage>('base-discussion', { after: append ? Number(rowsRef.current.at(-1)?.post_number ?? 0) : 0, limit: 20 });
      if (JSON.stringify(page.identity) !== JSON.stringify(caps.identity)) throw new Error('Shared discussion identity mismatch.');
      if (!mounted.current) return;
      const rows = append ? [...rowsRef.current, ...page.posts] : page.posts;
      rowsRef.current = rows;setPosts(rows);setIdentity(caps.identity);setOutbox(saved);setIntents(local);
      setMore(page.more);setComplete(page.sync_complete);
    } catch (e) {
      if (mounted.current) { rowsRef.current = [];setPosts([]);setComplete(false);setMore(false);setError(e instanceof Error ? e.message : 'Shared discussions could not be independently checked.'); }
    } finally { working.current = false;if (mounted.current) setBusy(false); }
  }, []);
  useEffect(() => { mounted.current = true;void refresh();return () => { mounted.current = false; }; }, [refresh]);
  useEffect(() => {
    let active = true;let unsubscribe = () => {};let received = false;
    const accept = (selection: Selection) => {
      if (!active) return;received = true;
      const url = selection.kind === 'post' ? selection.post.url : '';
      setInput(url);setSelected(url);setThread(undefined);
    };
    void windowKey().then(async key => {
      if (!active) return;unsubscribe = subscribeSelection(key, accept);
      const value = await getSelection(key);if (value && !received) accept(value);
    }).catch(() => undefined);
    return () => { active = false;unsubscribe(); };
  }, []);

  async function recover(id: string) {
    if (working.current) return;
    working.current = true;setBusy(true);setError('');
    try {
      if (!outbox.some(r => r.post.id === id)) throw new Error('This browser intent was not saved by the earlier helper. Its draft is retained; copy it into a new private-authorship post.');
      const result = await baseOperation<Submission>('base-check-existing', { post_id: id });
      // Retain the draft binding after recovery. Re-submitting an unchanged
      // draft then returns this UUID and lets the composer clear it safely.
      if (mounted.current) { setOutbox(rows => [...rows.filter(r => r.post.id !== id), result]);setNotice(`Submission ${result.status.state}.`); }
    } catch (e) { if (mounted.current) setError(e instanceof Error ? e.message : 'Recovery is unavailable.'); }
    finally { working.current = false;if (mounted.current) setBusy(false); }
  }
  const active = posts.find(p => p.post.id === thread && p.post.kind === 'thread');
  const threads = posts.filter(p => p.post.kind === 'thread' && (!selected || p.post.references.some(r => r[0] === selected)
    || posts.some(c => c.post.thread_id === p.post.id && c.post.references.some(r => r[0] === selected))));
  const saved: Submission[] = [...outbox, ...intents.filter(i => !outbox.some(r => r.post.id === i.post.id)).map(i => ({ post: i.post, facts: i.facts,
    status: { state: 'recoverable' as const }, submission_id: '', phase: 'prepared', experimental: true as const }))];
  function reference(number: string) {
    const target = posts.find(p => p.post_number === number);
    if (!target) { setNotice(`No.${number} is unavailable in the loaded finalized history. Load more or refresh.`);return; }
    setThread(target.post.kind === 'thread' ? target.post.id : target.post.thread_id!);
    requestAnimationFrame(() => document.getElementById(`shared-post-${target.post.id}`)?.scrollIntoView({ block: 'center' }));
  }
  function renderPost(row: SharedPost) {
    return <article id={`shared-post-${row.post.id}`} key={row.post.id} className="result-row" tabIndex={-1}>
      <PostId number={row.post_number} onCopied={setNotice} /><strong> Anonymous</strong><p>Finalized · {date(row.accepted_at)} · Experimental</p>
      {row.post.title && <h2>{row.post.title}</h2>}<PostBody body={row.post.body} className="post-body" onReference={reference} />
      {row.facts.length > 0 && <div><p>Test proof: {row.facts.map(zkidFactLabel).join(' · ')}. Valid when published.</p>
        <p>Observed {date(row.observed_at!)} · Expires {date(row.credential_expiry!)} · Current status: {row.credential_status === 'valid-at-current-registry' ? 'valid at checked registry' : row.credential_status === 'expired' ? 'expired' : 'unknown after registry update'}</p></div>}
      {row.post.references.map(([url]) => <p key={url}><a href={/^https?:\/\//.test(url) ? url : undefined} target="_blank" rel="noopener noreferrer">{url}</a></p>)}
    </article>;
  }
  return <div className="app shared-discussion"><header className="app-header"><strong>nockapp. · Shared</strong><span>Experimental · Base Sepolia</span></header>
    <section className="source-bar"><p>Posts and selected proofs are public. Anonymous ordinary posting needs no X credential.</p>

      <form onSubmit={e => { e.preventDefault();try { setSelected(input.trim() ? parsePostUrl(input).url : '');setThread(undefined);setError(''); } catch { setError('Enter a valid X post URL.'); } }}>
        <label>Selected X post<input aria-label="Shared X post URL" value={input} onChange={e => setInput(e.target.value)} placeholder="Optional X link; press Enter" /></label>
      </form><button className="secondary" disabled={busy} onClick={() => void refresh()}>Refresh shared discussions</button>
      {identity && <p>Chain 84532 · Contract {identity.contract}</p>}
    </section><main>
      <LegacyDrafts prefixes={['draft:thread:shared:', 'draft:reply:shared:']} />
      {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}{busy && <p role="status">Checking shared state…</p>}
      {identity && <><p>{complete ? 'Loaded posts independently checked through the finalized chain head.' : 'History scan is incomplete; refresh to continue.'}</p>
        <p>Earlier discussions are read only. New posts use Private authorship. Acceptance checks never resubmit a post.</p>
        {thread && <button className="text-button" onClick={() => setThread(undefined)}>Back to shared threads</button>}
        {active && <>{renderPost(active)}{posts.filter(p => p.post.kind === 'comment' && p.post.thread_id === thread).map(renderPost)}</>}
        {thread && !active && <p>The opening post is unavailable in loaded finalized history. Refresh or load more before replying.</p>}
        {!thread && threads.map(row => <div key={row.post.id}>{renderPost(row)}<button className="secondary" onClick={() => setThread(row.post.id)}>Open shared thread No.{row.post_number}</button></div>)}
        {more && <button className="secondary" disabled={busy} onClick={() => void refresh(true)}>Load more finalized posts</button>}

      </>}
      <section aria-label="Shared submission outbox"><h2>Saved shared submissions</h2><p>Check existing acceptance reads Base without resubmitting. It preserves your current draft. Statuses show the last independent check.</p>
        {saved.map(row => <article key={row.post.id} className="result-row"><strong>{row.post.title || 'Comment'}</strong><p>{row.post.body}</p>
          <p>{row.status.state}{row.status.state === 'finalized' ? ` · No.${row.status.post_number}` : ''}</p>
          {row.status.checked_at && <p>Checked {date(row.status.checked_at)}</p>}
          <button className="secondary" disabled={busy} onClick={() => void recover(row.post.id)}>Check existing acceptance</button></article>)}
      </section>
    </main></div>;
}
