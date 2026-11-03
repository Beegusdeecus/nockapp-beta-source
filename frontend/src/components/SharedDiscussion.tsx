import { useCallback, useEffect, useRef, useState } from 'react';
import { bundleOperation, type Identity, type Page, type Row, type Submission } from '../bundleDiscussion';
import { bundleIntents, type Intent } from '../data/bundleIntents';
import { parsePostUrl } from '../urls';
import { LegacySharedDiscussion } from './LegacySharedDiscussion';
import { PostBody, PostId } from './PostBody';
import { getSelection, subscribeSelection, windowKey } from '../platform/selection';
import { PublicArchive } from './PublicArchive';
import { LegacyDrafts } from './LegacyDrafts';
import { AuthoredSharedDiscussion } from './AuthoredSharedDiscussion';
import { PublicDiscussion } from './PublicDiscussion';
import { storage } from '../platform/storage';

const date = (v: number) => new Date(v * 1000).toLocaleString();
export function SharedDiscussion() {
  const [mode, setMode] = useState('v4');const [ready, setReady] = useState(false);const selected = useRef(false);
  useEffect(() => { let active = true;void storage.get<string>('nockapp:shared-protocol:v1').then(v => {
    if (active && !selected.current && ['public-v5', 'v3', 'base'].includes(v ?? '')) setMode(v!);
  }).catch(() => undefined).finally(() => { if (active) setReady(true); });return () => { active = false; }; }, []);
  const choose = (v: string) => { selected.current = true;setMode(v);void storage.set('nockapp:shared-protocol:v1', v).catch(() => undefined); };
  return <div className="shared-mode-shell"><div className="discussion-mode">
    <button aria-pressed={mode === 'public-v5'} onClick={() => choose('public-v5')}>Public · permissionless v5</button>
    <button aria-pressed={mode === 'v4'} onClick={() => choose('v4')}>Private authorship · v4</button>
    <button aria-pressed={mode === 'v3'} onClick={() => choose('v3')}>Shared offchain · v3</button>
    <button aria-pressed={mode === 'base'} onClick={() => choose('base')}>Earlier Base prototype</button></div>
    <div className="shared-mode-content">{ready && (mode === 'public-v5' ? <PublicDiscussion /> : mode === 'v4' ? <AuthoredSharedDiscussion /> : mode === 'v3' ? <>
      <p>Earlier v3 namespace. Saved posts and drafts are preserved. Older posts have no private authorship binding.</p><BundleDiscussion /></> : <>
      <p>Earlier full-content namespace. Records and drafts retain their original format and numbers.</p><LegacySharedDiscussion /></>)}</div></div>;
}
function BundleDiscussion() {
  const [identity, setIdentity] = useState<Identity>();const identityRef = useRef<Identity | undefined>(undefined);
  const [rows, setRows] = useState<Row[]>([]);const [page, setPage] = useState<Page>();
  const [thread, setThread] = useState<string>();const threadRef = useRef<string | undefined>(undefined);
  const [outbox, setOutbox] = useState<Submission[]>([]);const [intents, setIntents] = useState<Intent[]>([]);
  const [busy, setBusy] = useState(true);const working = useRef(false);const mounted = useRef(true);const generation = useRef(0);
  const [error, setError] = useState('');const [notice, setNotice] = useState('');const [stale, setStale] = useState(false);
  const [input, setInput] = useState('');const [selected, setSelected] = useState('');
  function sameIdentity(v: Identity) { if (JSON.stringify(v) !== JSON.stringify(identityRef.current)) throw new Error('The shared installation changed. Reopen after checking the update.'); }
  const syncOutbox = useCallback(async () => {
    const all: Submission[] = [];let after = 0;
    for (let i = 0; i < 13; i++) {
      const box = await bundleOperation<{ entries: Submission[]; next_after: number; more: boolean }>('bundle-outbox', { after, limit: 8 });
      all.push(...box.entries);if (!box.more) break;if (box.next_after <= after) throw new Error('Outbox page incomplete.');after = box.next_after;
    }
    if (mounted.current) { setOutbox(all);setIntents(await bundleIntents()); }
  }, []);
  async function load(hash?: string, after = 0, append = false) {
    if (working.current) return false;working.current = true;setBusy(true);setError('');const request = ++generation.current;
    try {
      const result = await bundleOperation<Page>(hash ? 'bundle-thread' : 'bundle-threads', hash ? { thread_id: hash, after, limit: 8 } : { after, limit: 8 });sameIdentity(result.identity);
      if (!mounted.current || request !== generation.current) return false;
      threadRef.current = hash;setThread(hash);setPage(result);setStale(false);setRows(old => append ? [...old, ...result.posts].slice(-128) : result.posts);
      return true;
    } catch (e) { if (mounted.current) { setStale(true);setError(e instanceof Error ? e.message : 'History unavailable. Last entries are retained.'); } return false; }
    finally { working.current = false;if (mounted.current) setBusy(false); }
  }
  useEffect(() => {
    mounted.current = true;let active = true;
    void (async () => {
      try {
        setIntents(await bundleIntents());
        const caps = await bundleOperation<{ configured: boolean; identity?: Identity; count_enrollment_configured?: boolean }>('bundle-capabilities');
        if (!active) return;if (!caps.configured || !caps.identity) throw new Error('Shared offchain discussions need the configured Ubuntu v3 helper. Saved device discussions remain available.');
        identityRef.current = caps.identity;setIdentity(caps.identity);await syncOutbox();if (active) await load();
      } catch (e) { if (active) { setBusy(false);setError(e instanceof Error ? e.message : 'Shared posting is unavailable.'); } }
    })();
    return () => { active = false;mounted.current = false;generation.current++; };
  }, [syncOutbox]);
  useEffect(() => {
    let active = true;let received = false;let unsubscribe = () => {};
    const accept = (url: string) => { if (active) { setInput(url);setSelected(url);received = true; } };
    void windowKey().then(async key => {
      if (!active) return;unsubscribe = subscribeSelection(key, s => accept(s.kind === 'post' ? s.post.url : ''));
      const value = await getSelection(key);if (value && !received) accept(value.kind === 'post' ? value.post.url : '');
    }).catch(() => undefined);return () => { active = false;unsubscribe(); };
  }, []);
  const scope = identity ? `${identity.chain_id}:${identity.contract}` : 'unconfigured';
  async function recover(id: string) {
    if (working.current) return;setBusy(true);working.current = true;setError('');
    try {
      if (!outbox.some(r => r.post.id === id)) throw new Error('This browser intent was not saved by the earlier helper. Its draft is retained; copy it into a new private-authorship post.');
      const result = await bundleOperation<Submission>('bundle-check-existing', { post_id: id });
      setOutbox(old => [...old.filter(r => r.post.id !== id), result]);
    } catch (e) { setError(e instanceof Error ? e.message : 'Recovery unavailable.'); } finally { working.current = false;setBusy(false); }
  }
  async function reference(number: string) {
    if (busy || !Number.isSafeInteger(Number(number))) return;
    try {
      const result = await bundleOperation<{ identity: Identity; posts: Row[] }>('bundle-numbers', { numbers: [Number(number)] });sameIdentity(result.identity);
      const row = result.posts[0];if (!row.canonical_accepted || !row.thread_id) { setNotice(`No.${number}: acceptance is unavailable or not established.`);return; }
      if (!await load(row.thread_id)) return;setRows(old => old.some(p => p.post_number === number) ? old : [...old, row].sort((a, b) => Number(a.post_number) - Number(b.post_number)));
      setNotice(`Referenced No.${number}. This may be outside the loaded page.`);
    } catch (e) { setError(e instanceof Error ? e.message : 'Reference unavailable.'); }
  }
  function render(row: Row, i: number) {
    return <article key={row.post_number ?? `gap:${row.ordinal ?? i}`} className="result-row" tabIndex={-1}>
      {row.post_number && <PostId number={row.post_number} onCopied={setNotice} />}<strong> Anonymous</strong><p>Experimental · {row.canonical_accepted ? 'Canonical finalized acceptance' : 'Acceptance unavailable'}</p>
      {row.post ? <>{row.post.title && <h2>{row.post.title}</h2>}<PostBody body={row.post.body} className="post-body" onReference={n => void reference(n)} />
        {row.post.references.map(([url]) => <p key={url}><a href={/^https?:\/\//.test(url) ? url : undefined} target="_blank" rel="noopener noreferrer">{url}</a></p>)}</> : <p>{row.state === 'content-unavailable' ? 'Content unavailable. Base preserves the commitment and number, not the missing text.' : 'Index or acceptance gap. This is not an empty entry.'}</p>}
      {row.credential_kind !== undefined && row.credential_kind > 0 && (row.credential_evidence_checked ? <>
        <p>Test proof · valid when published: {row.selection?.facts.map(f => f === 'followers-more-than' ? `follower count > ${row.selection!.threshold}` : f === 'follower-count' ? `exact follower count: ${row.disclosed_follower_count}` : f === 'account-controlled' ? 'X account control' : 'at least 10,000 followers').join(' · ')}</p>
        <p>Observed {date(row.observed_at!)} · Expires {date(row.credential_expiry!)} · Current status: {row.credential_status === 'valid-at-current-registry' ? 'valid at checked registry' : row.credential_status === 'expired' ? 'expired' : 'unknown after registry update'}</p>
      </> : <p>No verified credential badge: {row.state === 'verification-failed' ? 'evidence failed verification' : 'evidence unavailable'}.</p>)}
      {!thread && row.thread_id && <button className="secondary" disabled={busy} onClick={() => { void load(row.thread_id); }}>Open shared thread No.{row.post_number}</button>}
    </article>;
  }
  const saved: Submission[] = [...outbox, ...intents.filter(i => !outbox.some(o => o.post.id === i.post.id)).map(i => ({ post: i.post, selection: i.selection, phase: 'prepared', status: { state: 'recoverable' as const }, submission_id: '', experimental: true as const }))];
  const visible = thread ? rows : rows.filter(r => !selected || !r.post || r.post.references.some(([url]) => url === selected));
  return <div className="app shared-discussion"><header className="app-header"><strong>nockapp. · Shared offchain</strong><span>Experimental · Base Sepolia</span></header>
    <section className="source-bar"><p>Ordinary anonymous posts need no X credential. Text and selected proofs are public in replicated storage; Base establishes acceptance, order and commitments.</p>
      <p>Replication acknowledgments do not guarantee permanent availability. Providers and network timing can link activity.</p>
      {identity && <p>Configured retention: {Math.floor(identity.storage.retention_seconds / 86400)} days. Losing every copy makes content unavailable.</p>}
      <form onSubmit={e => { e.preventDefault();try { setSelected(input ? parsePostUrl(input).url : ''); } catch { setError('Enter an X post URL or clear the filter.'); } }}><label>Selected post<input value={input} onChange={e => setInput(e.target.value)} /></label><button>Filter loaded openings</button></form>
      {selected && <p>Filtering only loaded openings. Other threads or comments mentioning this X post may exist.</p>}
    </section><main>
      <LegacyDrafts prefixes={identity ? [`draft:thread:bundle:${scope}:`, `draft:reply:bundle:${scope}:`] : ['draft:thread:bundle:', 'draft:reply:bundle:']} />
      <button disabled={busy} onClick={() => { void syncOutbox().then(() => load(threadRef.current)).catch(e => setError(String(e))); }}>Refresh shared discussions</button>
      {identity && <button disabled={busy} onClick={() => { void bundleOperation('bundle-clear-cache', { confirm_cache_clear: true }).then(() => { setNotice('Public cache cleared. Drafts, outbox and shared replicas remain.');return load(threadRef.current); }).catch(e => setError(String(e))); }}>Clear public cache and rebuild</button>}
      {identity && <PublicArchive identity={identity} numbers={visible.filter(r => r.canonical_accepted && r.post_number).map(r => r.post_number!)}
        disabled={busy} onBusy={value => { working.current = value;setBusy(value); }} onRestored={() => load(threadRef.current)} />}
      {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}{stale && <p>Last loaded entries are retained; their status has not been refreshed.</p>}
      {identity && <><p>Earlier discussions are read only. New posts use Private authorship. Saved submissions are checked without resubmitting them.</p>
        {thread && <button disabled={busy} onClick={() => { void load(); }}>Back to shared threads</button>}
        {page && <p>{page.listing_complete ? 'Canonical listing checked for this scope.' : 'Partial listing; earlier coverage is not claimed.'} {page.canonical_total_count} canonical entries · {page.index_gaps.length} index gaps.</p>}
        {!page && <p>History has not been checked. No claim of an empty discussion is made.</p>}{visible.map(render)}{page?.canonical_total_count === '0' && page.listing_complete && <p>{thread ? 'This thread has no canonical acceptance.' : 'No accepted shared threads at the checked block.'}</p>}
        {page && !visible.length && page.canonical_total_count !== '0' && <p>No matching content in this downloaded page. This does not establish an empty discussion.</p>}
        {page?.more && <button disabled={busy} onClick={() => void load(thread, page.next_after, true)}>Load next verified page</button>}<p>At most 128 entries are kept in this view. Downloads are selective.</p>

      </>}
      <section aria-label="Shared submission outbox"><h2>Saved shared submissions</h2><p>Check existing acceptance reads Base without creating or resubmitting a post. Last-known numbers during an outage are historical, not fresh confirmation.</p>
        {saved.map(row => <article key={row.post.id} className="result-row"><strong>{row.post.title || 'Comment'}</strong><p>{row.post.body}</p><p>{row.status.state}{row.status.state === 'finalized' ? ` · No.${row.status.post_number}` : ''}</p>
          {row.renewal_count !== undefined && <p>Fresh proof attempts: {row.renewal_count}. Earlier attempt bytes are retained locally.</p>}
          {row.status.recovery_action === 'check-credential-or-selection' && <p>The selected proof could not be created. Check your saved credential and selected facts; equality does not satisfy a strict threshold. No exact count is disclosed by this notice.</p>}
          {row.status.last_known?.post_number && <p>Last known No.{row.status.last_known.post_number}; current acceptance check unavailable.</p>}
          <button disabled={busy} onClick={() => void recover(row.post.id)}>Check existing acceptance</button>

        </article>)}
      </section>
    </main></div>;
}
