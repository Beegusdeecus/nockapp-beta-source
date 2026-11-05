import { CanonicalForum } from './components/CanonicalForum';
import { api } from './platform/browser';
import { useCallback, useEffect, useLayoutEffect, useRef, useState, type FormEvent } from 'react';
import type { ForumData, Navigation, PostReference, Selection, View } from './model';
import { findReferences, FORUM_KEY, forum, resolvePost } from './data/repository';
import { DEMO_POST } from './data/seed';
import { exclusive, isExtension, storage, subscribeStorage } from './platform/storage';
import { getSelection, saveNavigation, subscribeSelection, windowKey } from './platform/selection';
import { parsePostUrl } from './urls';
import { AuthorLine } from './components/AuthorLine';
import { Composer } from './components/Composer';
import { Icon } from './components/Icon';
import { ThreadView } from './components/ThreadView';
import { publishThread } from './xPost';
import { publishZkidThread } from './zkidPublishing';
import { ZkidRecovery } from './components/ZkidRecovery';
import { SharedDiscussion } from './components/SharedDiscussion';

const initialNavigation = (): Navigation => ({ stack: [{ kind: 'home' }], updatedAt: 0, scroll: {} });
const viewKey = (view: View) => view.kind === 'home' ? 'home' : `${view.kind}:${view.post.postId}${view.kind === 'thread' ? `:${view.threadId}` : ''}`;

function loadNavigation(value: unknown): Navigation {
  if (!value || typeof value !== 'object') return initialNavigation();
  const nav = value as Navigation;
  if (!Array.isArray(nav.stack) || !nav.stack.length || typeof nav.updatedAt !== 'number' || !nav.scroll || typeof nav.scroll !== 'object') return initialNavigation();
  const stack: View[] = [];
  for (const v of nav.stack) {
    if (!v || !['home', 'results', 'thread', 'create'].includes(v.kind)) return initialNavigation();
    if (v.kind !== 'home') {
      try { if (parsePostUrl(v.post.url).postId !== v.post.postId) return initialNavigation(); } catch { return initialNavigation(); }
      if (v.kind === 'thread') {
        const legacy = v as typeof v & { focusCommentId?: unknown };
        const focus = v.focusPostId ?? legacy.focusCommentId;
        if (typeof v.threadId !== 'string' || (focus !== undefined && typeof focus !== 'string')) return initialNavigation();
        stack.push({ kind: 'thread', post: v.post, threadId: v.threadId, focusPostId: focus });
      } else stack.push(v);
    } else stack.push(v);
  }
  return { ...nav, stack };
}

export default function App() { return location.pathname.endsWith('/legacy.html') ? <LegacyApp/> : <CanonicalForum/>; }

function LegacyApp() {
  const [shared, setShared] = useState(false);
  const [opened, setOpened] = useState(false);
  const chosen = useRef(false);
  useEffect(() => {
    let active = true;
    void storage.get<string>('nockapp:discussion-mode:v1').then(mode => {
      if (active && !chosen.current && mode === 'shared') { setOpened(true);setShared(true); }
    }).catch(() => undefined);
    return () => { active = false; };
  }, []);
  return <div className="discussion-shell"><nav className="discussion-mode" aria-label="Discussion storage">
    <button type="button" aria-pressed={shared} onClick={() => { chosen.current = true;setOpened(true);setShared(true);void storage.set('nockapp:discussion-mode:v1', 'shared').catch(() => undefined); }}>Shared · Base Sepolia</button>
    <button type="button" aria-pressed={!shared} onClick={() => { chosen.current = true;setShared(false);void storage.set('nockapp:discussion-mode:v1', 'local').catch(() => undefined); }}>Saved on this device</button>
  </nav><div className="discussion-content" hidden={shared}><SavedApp /></div>{opened && <div className="discussion-content" hidden={!shared}><SharedDiscussion /></div>}</div>;
}

function SavedApp() {
  const [data, setData] = useState<ForumData>();
  const [nav, setNav] = useState<Navigation>(initialNavigation);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [settings, setSettings] = useState(false);
  const [input, setInput] = useState('');
  const [urlError, setUrlError] = useState('');
  const [bootAttempt, setBootAttempt] = useState(0);
  const navRef = useRef(nav);
  const keyRef = useRef('');
  const main = useRef<HTMLElement>(null);
  const urlInput = useRef<HTMLInputElement>(null);
  const settingsDialog = useRef<HTMLDialogElement>(null);
  const resultHeading = useRef<HTMLHeadingElement>(null);
  const view = nav.stack[nav.stack.length - 1];
  const post = view.kind === 'home' ? undefined : view.post;
  const previous = nav.stack.at(-2);
  const backLabel = previous?.kind === 'thread' ? 'Back to thread' : previous?.kind === 'results' ? 'Back to references' : 'Back';

  const refresh = useCallback(async () => {
    try { setData(await forum.load()); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not refresh discussions. Saved data has been preserved.'); }
  }, []);
  const commit = useCallback((next: Navigation) => {
    navRef.current = next; setNav(next);
    if (keyRef.current) void exclusive(`navigation:${keyRef.current}`, () => saveNavigation(keyRef.current, next)).catch(() => setError('Navigation could not be saved. Keep this panel open and try again.'));
  }, []);

  const acceptSelection = useCallback((selection: Selection) => {
    const current = navRef.current;
    const active = current.stack[current.stack.length - 1];
    setInput(selection.kind === 'post' ? selection.post.url : ''); setUrlError('');
    if (selection.kind === 'post' && active.kind !== 'home' && active.post.postId === selection.post.postId) {
      commit({ ...current, updatedAt: selection.at }); return;
    }
    const next: View = selection.kind === 'post' ? { kind: 'results', post: selection.post } : { kind: 'home' };
    // Opening another selected post has the same back-history behavior as Enter.
    // Preserve the last conversation rather than replacing its navigation stack.
    commit({ stack: current.updatedAt ? [...current.stack, next] : [next], updatedAt: selection.at, scroll: { ...current.scroll } });
  }, [commit]);

  useEffect(() => {
    let active = true;
    let unsubscribeSelection = () => {};
    let unsubscribeData = () => {};
    setReady(false); setError('');
    void (async () => {
      const key = await windowKey();
      keyRef.current = key;
      // Subscribe before the initial read so a gesture during panel startup is
      // never lost. Delay applying it until navigation restoration is complete.
      let pendingSelection: Selection | undefined;
      let restored = false;
      unsubscribeSelection = subscribeSelection(key, (selection) => {
        if (!active) return;
        if (restored) acceptSelection(selection); else pendingSelection = selection;
      });
      const [saved, db, selected] = await Promise.all([storage.get<Navigation>(`navigation:${key}`), forum.load(), getSelection(key)]);
      if (!active) return;
      const restoredNav = loadNavigation(saved);
      navRef.current = restoredNav; setNav(restoredNav); setData(db);
      restored = true;
      const latest = pendingSelection ?? selected;
      if (latest && latest.at >= restoredNav.updatedAt) acceptSelection(latest);
      unsubscribeData = subscribeStorage(FORUM_KEY, () => { void refresh().catch(() => setError('Could not refresh discussions. Saved data has been preserved.')); });
      setReady(true);
    })().catch((e) => { if (active) setError(e instanceof Error ? e.message : 'Could not open local storage. Try again.'); });
    return () => { active = false; unsubscribeSelection(); unsubscribeData(); };
  }, [acceptSelection, refresh, bootAttempt]);

  useEffect(() => {
    const dialog = settingsDialog.current;
    if (settings && dialog && !dialog.open) dialog.showModal();
    if (!settings && dialog?.open) dialog.close();
  }, [settings]);

  function rememberScroll(): Record<string, number> {
    return { ...navRef.current.scroll, [viewKey(navRef.current.stack.at(-1)!)]: main.current?.scrollTop ?? 0 };
  }
  function push(next: View) {
    const current = navRef.current;
    commit({ stack: [...current.stack, next], updatedAt: Date.now(), scroll: rememberScroll() });
    setError('');
  }
  function back() {
    const current = navRef.current;
    if (current.stack.length > 1) commit({ stack: current.stack.slice(0, -1), updatedAt: Date.now(), scroll: rememberScroll() });
  }
  function selectPost(selected: PostReference) {
    push({ kind: 'results', post: selected }); setUrlError(''); setInput(selected.url);
  }
  function selectInternalPost(number: string) {
    if (!data || !post) return;
    const result = resolvePost(data, number);
    if (!result) { setNotice(`Post No.${number} was not found in this local demo.`); return; }
    push({ kind: 'thread', post, threadId: result.thread.id, focusPostId: result.target.id });
  }
  function submitUrl(event: FormEvent) {
    event.preventDefault();
    try { selectPost(parsePostUrl(input)); } catch (e) { setUrlError((e as Error).message); urlInput.current?.focus(); }
  }
  useEffect(() => { setInput(post?.url ?? ''); setUrlError(''); }, [post?.url]);
  useLayoutEffect(() => {
    if (!ready) return;
    const scroll = navRef.current.scroll[viewKey(view)] ?? 0;
    if (main.current) main.current.scrollTop = scroll;
    if (view.kind === 'results' || view.kind === 'home') resultHeading.current?.focus({ preventScroll: true });
  }, [view.kind, post?.postId, view.kind === 'thread' ? view.threadId : '', ready]);

  const matches = data && post ? findReferences(data, post.postId) : undefined;
  const count = matches ? matches.threads.length + matches.comments.length : 0;

  return <div className="app-shell">
    <a href="#main" className="skip-link">Skip to discussion</a>
    <header className="app-header"><a className="wordmark" href="#" aria-label="NockApp home" onClick={(e) => { e.preventDefault(); push({ kind: 'home' }); }}>nockapp<span>.</span></a><div className="header-actions"><button className="text-button" onClick={() => { if (isExtension) void api().tabs.create({ url: api().runtime.getURL('public-post.html') }); else setNotice('Connect X requires the installed Ubuntu browser extension and local helper.'); }}>Connect X</button><span className="identity-indicator" title="Anonymous participation · no account identity displayed"><i />anon</span><button className="icon-button" onClick={() => setSettings(true)} aria-label="Settings"><Icon name="settings" size={18} /></button></div></header>
    <section className="selected-post" aria-label="Selected post">
      <div className="post-topline"><label className="eyebrow" htmlFor="post-url">SELECTED POST</label><span className="reference-count">{post ? `${count} ${count === 1 ? 'reference' : 'references'}` : 'LOCAL DEMO'}</span></div>
      <form className="url-form" onSubmit={submitUrl}><Icon name="x" size={16} /><input ref={urlInput} id="post-url" aria-label="X post URL" type="text" inputMode="url" autoComplete="off" spellCheck={false} value={input} onChange={(e) => { setInput(e.target.value); setUrlError(''); }} placeholder="Paste an X post link, then Enter" aria-invalid={!!urlError} aria-describedby={urlError ? 'url-error' : 'url-hint'} />
        {post && <><button type="button" className="icon-button" aria-label="Copy post URL" title="Copy the loaded post URL" onClick={() => { void navigator.clipboard.writeText(post.url).then(() => setNotice('Post URL copied.')).catch(() => setError('Could not copy. Select the post URL and copy it manually.')); }}><Icon name="copy" size={14} /></button><a className="icon-button" href={post.url} target="_blank" rel="noopener noreferrer" aria-label="Open original post" title="Open the loaded post"><Icon name="external" size={14} /></a></>}
      </form>
      <p id="url-hint" className="source-note">{input !== (post?.url ?? '') ? 'Press Enter to load this link.' : 'Opens from your X post. Paste another link and press Enter.'}</p>
      {urlError && <p id="url-error" className="url-error" role="alert">{urlError}</p>}
    </section>
    {nav.stack.length > 1 && <nav className="back-nav" aria-label="Discussion navigation"><button className="text-button" onClick={back}><Icon name="back" size={14} />{backLabel}</button><span>{view.kind === 'thread' ? 'THREAD' : view.kind === 'create' ? 'NEW THREAD' : 'REFERENCES'}</span></nav>}
    <main id="main" ref={main} tabIndex={-1} onScroll={() => {
      if (ready && main.current) navRef.current.scroll[viewKey(view)] = main.current.scrollTop;
    }}>
      {error && <div className="error-box" role="alert"><strong>Something needs attention</strong><p>{error}</p><button className="text-button" onClick={() => { if (!ready) setBootAttempt((n) => n + 1); else { setError(''); void refresh().catch((e: Error) => setError(e.message)); } }}>Try again <Icon name="arrow" size={14} /></button></div>}
      {!ready && !error && <div className="loading-state" role="status"><div className="skeleton" /><div className="skeleton short" /><p>Opening your local discussions…</p></div>}
      {ready && data && view.kind === 'home' && <div className="welcome"><div className="eyebrow">A LITTLE LESS NOISE</div><h1 ref={resultHeading} tabIndex={-1}>The post is just<br />the beginning<span>.</span></h1><p className="welcome-description">A space for the conversation after the post. Bring a link. Leave your name behind.</p><div className="instruction-list"><div><span>01</span><p>Open an X post and click the<br /><strong>NockApp extension icon.</strong></p></div><div><span>02</span><p>The post link fills in automatically.<br /><strong>Your discussions appear here.</strong></p></div><div><span>03</span><p>Want to select a different post?<br /><button className="inline-button" onClick={() => urlInput.current?.focus()}>Paste its link above and press Enter.</button></p></div></div><div className="demo-invitation"><span className="eyebrow">TAKE A LOOK AROUND</span><p>Try a fictional conversation.<br />No X account needed.</p><button className="secondary full" onClick={() => selectPost(DEMO_POST)}>Explore demo discussion <Icon name="arrow" /></button></div><p className="privacy-note">No account. No browsing history.<br />Everything stays on this device.</p></div>}
      {ready && data && view.kind === 'results' && matches && <div className="results-view"><div className="results-heading"><div><div className="eyebrow">AROUND THIS POST</div><h1 ref={resultHeading} tabIndex={-1}>The discussion<span>.</span></h1></div><button className="icon-button outlined" aria-label="Start anonymous discussion" title="Start anonymous discussion" onClick={() => push({ kind: 'create', post: view.post })}><Icon name="plus" size={19} /></button></div>
        {count === 0 ? <div className="empty-state"><span className="empty-mark">“</span><h2>A conversation starts<br />with one person.</h2><p>No references to this post yet.<br />Leave the first thought, anonymously.</p><button className="primary full" onClick={() => push({ kind: 'create', post: view.post })}>Start anonymous discussion <Icon name="arrow" /></button></div> : <>
          <section aria-labelledby="threads-heading"><h2 className="section-label" id="threads-heading">Threads referencing this post <span>{matches.threads.length.toString().padStart(2, '0')}</span></h2>{!matches.threads.length && <p className="small-empty">No threads yet. This post appears in replies below.</p>}{matches.threads.map((thread) => <button className="result-row thread-result" key={thread.id} onClick={() => push({ kind: 'thread', post: view.post, threadId: thread.id })}><span className="post-id">No.{thread.postNumber}</span><h3>{thread.title}</h3><p className="excerpt">{thread.body}</p><AuthorLine author={thread.author} time={thread.createdAt} post={thread} /><span className="row-bottom"><span><Icon name="message" size={12} />{data.comments.filter((c) => c.threadId === thread.id).length} comments</span><Icon name="arrow" size={14} /></span></button>)}</section>
          <section className="comment-results" aria-labelledby="comments-heading"><h2 className="section-label" id="comments-heading">Comments referencing this post <span>{matches.comments.length.toString().padStart(2, '0')}</span></h2>{!matches.comments.length && <p className="small-empty">No comment references yet.</p>}{matches.comments.map(({ comment, thread }) => <button className="result-row comment-result" key={comment.id} onClick={() => push({ kind: 'thread', post: view.post, threadId: thread.id, focusPostId: comment.id })}><div className="parent-thread">IN {thread.title}</div><span className="post-id">No.{comment.postNumber}</span><p className="comment-excerpt">{comment.body}</p><AuthorLine author={comment.author} time={comment.createdAt} post={comment} /><span className="jump-label">Jump to comment <Icon name="arrow" size={13} /></span></button>)}</section><button className="secondary full start-bottom" onClick={() => push({ kind: 'create', post: view.post })}><Icon name="plus" size={14} />Start anonymous discussion</button>
        </>}
      </div>}
      {ready && data && view.kind === 'create' && <div className="create-view"><div className="eyebrow">MAKE ROOM FOR AN IDEA</div><h1>Start a conversation<span>.</span></h1><p className="create-description">The selected post is already linked. Add your perspective; your name stays out of it.</p><Composer key={`create:${view.post.postId}`} draftKey={`thread:${view.post.postId}`} mode="thread" onSubmit={async (draft, signal) => {
        if (draft.zkidFacts?.length && draft.passportFacts?.length) throw new Error('Choose one credential flow for this post. Your draft is preserved.');
        const input = { title: draft.title, body: draft.body, references: [view.post], credentials: draft.credentials };
        const thread = draft.zkidFacts?.length ? await publishZkidThread(forum, input, draft.zkidFacts, signal)
          : await publishThread(forum, input, draft.passportFacts, signal);
        await refresh();
        if (signal.aborted) return;
        const current = navRef.current;
        commit({ ...current, stack: [...current.stack.slice(0, -1), { kind: 'thread', post: view.post, threadId: thread.id }], updatedAt: Date.now() });
        setNotice('Your anonymous thread is saved on this device.');
      }} /></div>}
      {ready && data && view.kind === 'thread' && <ThreadView data={data} view={view} onSelect={selectPost} onRefresh={refresh} onReference={selectInternalPost} onNotice={setNotice} onChange={(next) => {
        const current = navRef.current;
        commit({ ...current, stack: [...current.stack.slice(0, -1), next], updatedAt: Date.now() });
      }} />}
      {ready && data && <ZkidRecovery onSaved={refresh} />}
    </main>
    <footer className="app-footer"><span>Words first. Names optional.</span><span>v0.2</span></footer>
    {notice && <div className="toast" role="status"><span><Icon name="check" size={14} />{notice}</span><button className="icon-button" aria-label="Dismiss notification" onClick={() => setNotice('')}><Icon name="close" size={14} /></button></div>}
    <dialog ref={settingsDialog} aria-labelledby="settings-title" onCancel={() => setSettings(false)} onClose={() => setSettings(false)} className="settings-dialog"><div className="dialog-header"><span className="eyebrow">YOUR SPACE</span><button className="icon-button" aria-label="Close settings" onClick={() => setSettings(false)}><Icon name="close" /></button></div><h2 id="settings-title">Private by design<span>.</span></h2><section><h3>Anonymous participation</h3><p>Authors appear as Anonymous. Only threads and comments have visible IDs. Optional demo credentials are chosen separately for each post; none are shown by default.</p></section><section><h3>Local demo, real interactions</h3><p>Threads, replies and drafts are saved {isExtension ? 'in Chrome local storage' : 'in this browser’s local storage'}. They are not shared with anyone.</p><p>Only links you explicitly select are processed. No scraping, analytics or network requests. Opening an original link uses your browser normally.</p></section><section><h3>Credentials are demo data</h3><p>Every badge is fictional and marked “Demo”. No proof is generated or verified. The credential verifier interface is reserved for a future backend.</p></section><section><h3>Storage & recovery</h3><p>Data stays until you remove the extension or clear its storage. Corrupt data is preserved rather than overwritten. To start over, back up anything you need, then remove and reload the unpacked extension.</p></section><button className="secondary full" onClick={() => setSettings(false)}>Back to the conversation <Icon name="arrow" /></button></dialog>
  </div>;
}
