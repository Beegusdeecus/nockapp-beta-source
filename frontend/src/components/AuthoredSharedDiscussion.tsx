import { useCallback, useEffect, useRef, useState } from 'react';
import { authoredOperation as bundleOperation, type AuthoredIdentity as Identity, type Page, type Row, type Submission } from '../authoredDiscussion';
import { canonicalAscii, type AddressSelection as Selection } from '../authoredWallet';
import { api } from '../platform/browser';
import { authoredIntents as bundleIntents, markAuthoredIntent as markBundleIntent, prepareAuthoredIntent as prepareBundleIntent, belongsToScope, type Intent } from '../data/authoredIntents';
import type { Draft } from '../data/drafts';
import type { WirePost } from '../zkidWire';
import { parsePostUrl } from '../urls';
import { AuthoredComposer as BundleComposer } from './AuthoredComposer';
import { CountEnrollment } from './CountEnrollment';
import { PostBody, PostId } from './PostBody';
import { getSelection, subscribeSelection, windowKey } from '../platform/selection';
import { PublicArchive } from './PublicArchive';
import { SelectedHistory } from './SelectedHistory';

const date = (v: number) => new Date(v * 1000).toLocaleString();
export function AuthoredSharedDiscussion() {
  const [identity, setIdentity] = useState<Identity>();const identityRef = useRef<Identity | undefined>(undefined);
  const [rows, setRows] = useState<Row[]>([]);const [page, setPage] = useState<Page>();
  const [thread, setThread] = useState<string>();const threadRef = useRef<string | undefined>(undefined);
  const [rootUuid, setRootUuid] = useState<string>();const [creating, setCreating] = useState(false);
  const [outbox, setOutbox] = useState<Submission[]>([]);const [intents, setIntents] = useState<Intent[]>([]);
  const [busy, setBusy] = useState(true);const working = useRef(false);const mounted = useRef(true);const generation = useRef(0);
  const [error, setError] = useState('');const [notice, setNotice] = useState('');const [stale, setStale] = useState(false);
  const [input, setInput] = useState('');const [selected, setSelected] = useState('');const [countOpen, setCountOpen] = useState(false);const [historyOpen, setHistoryOpen] = useState(false);
  const [countConfigured, setCountConfigured] = useState(false);const [renewConsent, setRenewConsent] = useState<Record<string, boolean>>({});
  function sameIdentity(v: Identity) { if (canonicalAscii(v) !== canonicalAscii(identityRef.current)) throw new Error('The shared installation changed. Reopen after checking the update.'); }
  async function currentIntents() { const rows = await bundleIntents();return identityRef.current ? rows.filter(r => belongsToScope(r, identityRef.current!)) : []; }
  const syncOutbox = useCallback(async () => {
    const all: Submission[] = [];let after = 0;
    for (let i = 0; i < 13; i++) {
      const box = await bundleOperation<{ entries: Submission[]; next_after: number; more: boolean }>('bundle-outbox', { after, limit: 8 });
      all.push(...box.entries);if (!box.more) break;if (box.next_after <= after) throw new Error('Outbox page incomplete.');after = box.next_after;
    }
    if (mounted.current) { setOutbox(all);setIntents(await currentIntents()); }
  }, []);
  async function load(hash?: string, after = 0, append = false) {
    if (working.current) return false;working.current = true;setBusy(true);setError('');const request = ++generation.current;
    try {
      const result = await bundleOperation<Page>(hash ? 'bundle-thread' : 'bundle-threads', hash ? { thread_id: hash, after, limit: 8 } : { after, limit: 8 });sameIdentity(result.identity);
      if (!mounted.current || request !== generation.current) return false;
      const sameThread = threadRef.current === hash;threadRef.current = hash;setThread(hash);setPage(result);setStale(false);setRows(old => append ? [...old, ...result.posts].slice(-128) : result.posts);
      const post = result.posts.find(r => r.post)?.post;if (!sameThread || post) setRootUuid(hash && post ? post.kind === 'thread' ? post.id : post.thread_id! : undefined);return true;
    } catch (e) { if (mounted.current) { setStale(true);setError(e instanceof Error ? e.message : 'History unavailable. Last entries are retained.'); } return false; }
    finally { working.current = false;if (mounted.current) setBusy(false); }
  }
  useEffect(() => {
    mounted.current = true;let active = true;
    void (async () => {
      try {
        setIntents(await currentIntents());
        const caps = await bundleOperation<{ configured: boolean; identity?: Identity; count_enrollment_configured?: boolean }>('bundle-capabilities');
        if (!active) return;if (!caps.configured || !caps.identity) throw new Error('Shared posting is unavailable. Configure the Ubuntu v4 helper. Saved device discussions remain available.');
        identityRef.current = caps.identity;setIdentity(caps.identity);setCountConfigured(!!caps.count_enrollment_configured);await syncOutbox();if (active) await load();
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
  const draftKey = thread ? `reply:authored:${scope}:${thread}:root` : `thread:authored:${scope}:${selected || 'all'}`;
  async function submit(draft: Draft, selection: Selection) {
    if (!identity || working.current) throw new Error('Wait for the helper check. Your draft is preserved.');
    const post: WirePost = { kind: thread ? 'comment' : 'thread', id: crypto.randomUUID(), created_at: Math.floor(Date.now() / 1000), thread_id: thread ? rootUuid! : null,
      title: thread ? null : draft.title.trim(), body: draft.body.trim(), references: selected ? [[selected, parsePostUrl(selected).postId]] : [], claims: [] };
    if (thread && !rootUuid) throw new Error('Thread metadata is unavailable; restore a verified bundle before replying.');
    working.current = true;setBusy(true);
    try {
      const intent = await prepareBundleIntent(draftKey, post, selection, { chain_id: identity.chain_id, application: identity.application, contract: identity.contract });setIntents(await currentIntents());
      const result = await bundleOperation<Submission>('bundle-publish', { post: intent.post, selection: intent.selection, approve_publication: true });
      await markBundleIntent(intent.post.id);if (mounted.current) { setIntents(await currentIntents());setOutbox(old => [...old.filter(r => r.post.id !== result.post.id), result]);
        setNotice(result.phase === 'wallet-needed' ? 'Post saved. Choose Authorize with MetaMask in the saved submissions below.' : 'Submission saved. Recover checks the same post against Base.'); }
      return intent.post.id;
    } finally { working.current = false;if (mounted.current) setBusy(false); }
  }
  async function recover(id: string) {
    if (working.current) return;setBusy(true);working.current = true;setError('');
    try {
      const intent = (await currentIntents()).find(i => i.post.id === id);
      const result = intent ? await bundleOperation<Submission>('bundle-publish', { post: intent.post, selection: intent.selection, approve_publication: true })
        : await bundleOperation<Submission>('bundle-recover', { post_id: id });
      if (intent) await markBundleIntent(id);setOutbox(old => [...old.filter(r => r.post.id !== id), result]);setIntents(await currentIntents());
    } catch (e) { setError(e instanceof Error ? e.message : 'Recovery unavailable.'); } finally { working.current = false;setBusy(false); }
  }
  async function renew(row: Submission) {
    if (working.current || !renewConsent[row.post.id]) return;working.current = true;setBusy(true);setError('');
    try {
      const result = await bundleOperation<Submission>('bundle-renew', { post_id: row.post.id, expected_submission_id: row.submission_id, approve_fresh_proof: true });
      if (mounted.current) { setOutbox(old => [...old.filter(r => r.post.id !== row.post.id), result]);setRenewConsent(old => ({ ...old, [row.post.id]: false }));
        setNotice('Fresh proof attempt saved for the same post. Earlier public bytes remain retained. Recover reuses the new attempt.'); }
    } catch { if (mounted.current) setError('Renewal unavailable. The helper must check finalized expiry and absence of acceptance. Use Recover if the earlier attempt may have been accepted. Saved data remains.'); }
    finally { working.current = false;if (mounted.current) setBusy(false); }
  }
  async function initializeIdentity() {
    if (working.current || !identity) return;working.current = true;setBusy(true);setError('');
    try { await bundleOperation('bundle-initialize-identity', { approve_private_key_setup: true });if (mounted.current) setNotice('Private signing identity ready. Existing credentials and keys are preserved. Recover any saved post to continue.'); }
    catch { if (mounted.current) setError('Identity setup unavailable. Unlock the local keyring or recover existing enrollment first. No replacement key was created.'); }
    finally { working.current = false;if (mounted.current) setBusy(false); }
  }
  async function reference(number: string) {
    if (busy || !Number.isSafeInteger(Number(number))) return;
    try {
      const result = await bundleOperation<{ identity: Identity; posts: Row[] }>('bundle-numbers', { numbers: [Number(number)] });sameIdentity(result.identity);
      const row = result.posts[0];if (!row.canonical_accepted || !row.thread_id) { setNotice(`No.${number}: acceptance is unavailable or not established.`);return; }
      if (!await load(row.thread_id)) return;setRows(old => old.some(p => p.post_number === number) ? old : [...old, row].sort((a, b) => Number(a.post_number) - Number(b.post_number)));
      if (row.post) setRootUuid(row.post.kind === 'thread' ? row.post.id : row.post.thread_id!);setNotice(`Referenced No.${number}. This may be outside the loaded page.`);
    } catch (e) { setError(e instanceof Error ? e.message : 'Reference unavailable.'); }
  }
  function render(row: Row, i: number) {
    return <article key={row.post_number ?? `gap:${row.ordinal ?? i}`} className="result-row" tabIndex={-1}>
      {row.post_number && <PostId number={row.post_number} onCopied={setNotice} />}<strong> Anonymous</strong><p>Experimental · {row.canonical_accepted ? 'Canonical finalized acceptance' : 'Acceptance unavailable'}</p>
      {row.post ? <>{row.post.title && <h2>{row.post.title}</h2>}<PostBody body={row.post.body} className="post-body" onReference={n => void reference(n)} />
        {row.post.references.map(([url]) => <p key={url}><a href={/^https?:\/\//.test(url) ? url : undefined} target="_blank" rel="noopener noreferrer">{url}</a></p>)}</> : <p>{row.state === 'content-unavailable' ? 'Content unavailable. Base preserves the commitment and number, not the missing text.' : 'Index or acceptance gap. This is not an empty entry.'}</p>}
      <p>{row.authorship_checked && !stale ? 'Test proof · private authorship checked for this exact post' : 'No current verified authorship claim: evidence unavailable, invalid or awaiting refresh.'}</p>
      {row.selection?.address && (row.address_evidence_checked && row.authorship_checked && !stale
        ? <p>Test proof · address authorized this post: <span className="public-address">{row.public_address}</span></p>
        : <p>No verified address badge.</p>)}
      {row.selection?.followers_threshold !== undefined && row.selection.followers_threshold !== null && (row.credential_evidence_checked && row.authorship_checked && !stale ? <>
        <p>Test proof · followers &gt; {row.selection.followers_threshold} when observed; account and exact count hidden.</p>
        <p>Observed {date(row.observed_at!)} · Expires {date(row.credential_expiry!)} · Revocation: {row.credential_status === 'valid-at-current-registry' ? 'valid at checked registry' : row.credential_status === 'expired' ? 'credential expired' : 'unknown after registry update'}. This is not a continuously current count.</p>
      </> : <p>No verified follower badge: evidence unavailable, invalid or awaiting refresh.</p>)}
      {!thread && row.thread_id && <button className="secondary" disabled={busy} onClick={() => { setCreating(false);void load(row.thread_id); }}>Open shared thread No.{row.post_number}</button>}
    </article>;
  }
  const saved: Submission[] = [...outbox, ...intents.filter(i => !outbox.some(o => o.post.id === i.post.id)).map(i => ({ post: i.post, selection: i.selection, phase: 'prepared', status: { state: 'recoverable' as const, checked_at: 0, authorship_checked: false, address_evidence_checked: false, credential_evidence_checked: false }, submission_id: '', renewal_count: 0, experimental: true as const }))];
  const visible = thread ? rows : rows.filter(r => !selected || !r.post || r.post.references.some(([url]) => url === selected));
  return <div className="app shared-discussion"><header className="app-header"><strong>nockapp. · Private authorship</strong><span>Experimental · Base Sepolia</span></header>
    <section className="source-bar"><p>Ordinary anonymous posts need no X credential. Text and selected proofs are public in replicated storage; Base establishes acceptance, order and commitments.</p>
      <p>Replication acknowledgments do not guarantee permanent availability. Providers and network timing can link activity.</p>
      {identity && <p>Configured retention: {Math.floor(identity.storage.retention_seconds / 86400)} days. Losing every copy makes content unavailable.</p>}
      {identity && <section aria-label="Private signing identity"><button disabled={busy} onClick={() => void initializeIdentity()}>Set up private signing identity</button>
        <p>This creates a private signing key on your computer or reuses your existing credential key. MetaMask and an X credential are optional for ordinary posts.</p>
        <details><summary>Authorship and key recovery</summary><p>Authorship proves authorization by a secret's controller, not exclusive human composition. Shared or stolen keys confer authority.</p>
          <p>Restore the same protected key from your own secure backup to prove earlier authorship. Losing every copy makes those private claims unrecoverable; MetaMask alone cannot restore this separate key. A replacement key does not inherit old authorship. Existing posts without bindings cannot gain them retroactively.</p></details></section>}
      {countConfigured && <button onClick={() => setCountOpen(v => !v)}>Connect X for optional count proofs</button>}{countOpen && <CountEnrollment operation={bundleOperation} />}
      <form onSubmit={e => { e.preventDefault();try { setSelected(input ? parsePostUrl(input).url : ''); } catch { setError('Enter an X post URL or clear the filter.'); } }}><label>Selected post<input value={input} onChange={e => setInput(e.target.value)} /></label><button>Filter loaded openings</button></form>
      {selected && <p>Filtering only loaded openings. Other threads or comments mentioning this X post may exist.</p>}
    </section><main>
      <button disabled={busy} onClick={() => { void syncOutbox().then(() => load(threadRef.current)).catch(e => setError(String(e))); }}>Refresh shared discussions</button>
      {identity && <button disabled={busy} onClick={() => { void bundleOperation('bundle-clear-cache', { confirm_cache_clear: true }).then(() => { setNotice('Public cache cleared. Drafts, outbox and shared replicas remain.');return load(threadRef.current); }).catch(e => setError(String(e))); }}>Clear public cache and rebuild</button>}
      {identity && <><button disabled={busy} onClick={() => setHistoryOpen(v => !v)}>Prove selected past posts</button>{historyOpen && <SelectedHistory identity={identity} />}</>}
      {identity && <PublicArchive operation={bundleOperation} identity={identity} numbers={visible.filter(r => r.canonical_accepted && r.post_number).map(r => r.post_number!)}
        disabled={busy} onBusy={value => { working.current = value;setBusy(value); }} onRestored={() => load(threadRef.current)} />}
      {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}{stale && <p>Last loaded entries are retained; their status has not been refreshed.</p>}
      {identity && <>{thread || creating ? <button disabled={busy} onClick={() => { setCreating(false);void load(); }}>Back to shared threads</button> : <button className="primary" disabled={busy} onClick={() => setCreating(true)}>Start shared thread</button>}
        {page && <p>{page.listing_complete ? 'Canonical listing checked for this scope.' : 'Partial listing; earlier coverage is not claimed.'} {page.canonical_total_count} canonical entries · {page.index_gaps.length} index gaps.</p>}
        {!page && <p>History has not been checked. No claim of an empty discussion is made.</p>}{!creating && visible.map(render)}{!creating && page?.canonical_total_count === '0' && page.listing_complete && <p>{thread ? 'This thread has no canonical acceptance.' : 'No accepted shared threads at the checked block.'}</p>}
        {!creating && page && !visible.length && page.canonical_total_count !== '0' && <p>No matching content in this downloaded page. This does not establish an empty discussion.</p>}
        {page?.more && <button disabled={busy} onClick={() => void load(thread, page.next_after, true)}>Load next verified page</button>}<p>At most 128 entries are kept in this view. Downloads are selective.</p>
        {(creating || thread && rootUuid) && <BundleComposer key={draftKey} draftKey={draftKey} reply={!!thread} onSubmit={submit} />}
      </>}
      <section aria-label="Shared submission outbox"><h2>Saved shared submissions</h2><p>Recover reuses the saved submission. Last-known numbers during an outage are historical, not fresh confirmation.</p>
        {saved.map(row => <article key={row.post.id} className="result-row"><strong>{row.post.title || 'Comment'}</strong><p>{row.post.body}</p><p>{row.status.state}{row.status.state === 'finalized' ? ` · No.${row.status.post_number}` : ''}</p>
          {row.renewal_count !== undefined && <p>Fresh proof attempts: {row.renewal_count}. Earlier attempt bytes are retained locally.</p>}
          {row.status.recovery_action === 'set-up-private-signing-identity' && <p>Use Set up private signing identity, then recover this saved post. Existing keys and credentials are preserved.</p>}
          {row.status.recovery_action === 'sign-with-wallet' && <button disabled={busy} onClick={() => void api().tabs.create({ url: api().runtime.getURL(`wallet-post.html#post=${row.post.id}`) }).catch(() => setError('Could not open the wallet screen. The saved post is preserved.'))}>Authorize with MetaMask</button>}
          {row.status.recovery_action === 'renew-expired-authorization' && <><p>This proof authorization expired. A fresh attempt requires finalized chain expiry and no accepted submission or post UUID. Earlier uploads can remain public.</p>
            <label><input type="checkbox" checked={!!renewConsent[row.post.id]} disabled={busy} onChange={e => setRenewConsent(old => ({ ...old, [row.post.id]: e.target.checked }))} />Allow a fresh public proof for this saved post</label>
            <button disabled={busy || !renewConsent[row.post.id]} onClick={() => void renew(row)}>Create fresh proof after finalized expiry</button></>}
          {row.status.last_known?.post_number && <p>Last known No.{row.status.last_known.post_number}; current acceptance check unavailable.</p>}
          <button disabled={busy} onClick={() => void recover(row.post.id)}>Recover submission</button>
          {intents.some(i => i.post.id === row.post.id && i.acknowledged && !i.released) && <button disabled={busy} onClick={() => void markBundleIntent(row.post.id, true).then(async () => { setIntents(await currentIntents());setNotice('Saved submission retained. Your edited draft can now create a new post.'); })}>Use edited draft for a new post</button>}
        </article>)}
      </section>
    </main></div>;
}
