import { useEffect, useRef, useState } from 'react';
import { canonicalAscii } from '../authoredWallet';
import { publicOperation, type PublicScope, type PublicSubmission, type PublicRow, type PublicReference, type PublicPage, type PublicSelection } from '../publicDiscussion';
import { acknowledgePublicIntent, intentBody, preparePublicIntent, publicIntents, samePublicScope, type PublicIntent } from '../data/publicIntents';
import type { Draft } from '../data/drafts';
import { parsePostUrl } from '../urls';
import { getSelection, subscribeSelection, windowKey } from '../platform/selection';
import { api } from '../platform/browser';
import { PublicComposer } from './PublicComposer';
import { PostBody, PostId } from './PostBody';
import { downloadPublicBundle, publishDirect, publishPublicBundleHash } from '../publicDirect';
import { PublicSourceEnrollment } from './PublicSourceEnrollment';
import { PublicContentArchive } from './PublicContentArchive';

type Capabilities = { scope: PublicScope; source_enrollment_configured: boolean; follower_proof_configured: boolean;
  anonymous_ticket_packs: boolean; publication_mode?: 'direct' | 'tickets' };
type Options = { identity_record_present: boolean; sources: { source_id: string; kind: string; identity_record_present: boolean; pending_recovery: boolean }[] };
type Tickets = { available: number; reserved: number; purchase_pending: boolean; pack_size: number; pack_price_wei: string; can_purchase: boolean; can_redeem: boolean };
const captureRef = (row: PublicRow, scope: PublicScope): PublicReference => ({ protocol: 5, chain_id: scope.chain_id, contract: scope.contract, number: row.post_number, bundle_hash: row.bundle_hash! });
export function PublicDiscussion() {
  const [caps, setCaps] = useState<Capabilities>();const scope = useRef<PublicScope | undefined>(undefined);
  const [options, setOptions] = useState<Options>();const [tickets, setTickets] = useState<Tickets>();
  const [rows, setRows] = useState<PublicRow[]>([]);const [page, setPage] = useState<PublicPage>();const [stale, setStale] = useState(false);
  const [freshNumbers, setFreshNumbers] = useState<Set<string>>(new Set());
  const threadRef = useRef<PublicRow | undefined>(undefined);
  const [outbox, setOutbox] = useState<PublicSubmission[]>([]);const [intents, setIntents] = useState<PublicIntent[]>([]);
  const [thread, setThread] = useState<PublicRow>();const [creating, setCreating] = useState(false);
  const [input, setInput] = useState('');const [selected, setSelected] = useState('');
  const selectedRef = useRef('');
  const [error, setError] = useState('');const [localError, setLocalError] = useState('');const [notice, setNotice] = useState('');const [busy, setBusy] = useState(true);
  const [loading, setLoading] = useState('Connecting to the installed helper…');
  const [history, setHistory] = useState('');const [linkConsent, setLinkConsent] = useState(false);
  const [createConsent, setCreateConsent] = useState(false);const [reuseConsent, setReuseConsent] = useState(false);
  const [identityNotice, setIdentityNotice] = useState('');
  const [payerConsent, setPayerConsent] = useState(false);
  const [publicHash, setPublicHash] = useState('');
  const working = useRef(false);const mounted = useRef(true);const generation = useRef(0);
  function acceptScope(v: PublicScope) { if (!scope.current || !samePublicScope(v, scope.current)) throw new Error('The public installation changed. Reopen after reviewing the update.'); }
  async function syncOutbox() {
    const entries: PublicSubmission[] = [];let after = 0;
    for (let i = 0; i < 10; i++) {
      const p = await publicOperation<{ entries: PublicSubmission[]; next_after: number | null }>('public-outbox', { after, limit: 4 });
      for (const row of p.entries) { const { submission_id: _id, ...where } = row.core.context;acceptScope(where); }
      entries.push(...p.entries);if (p.next_after === null) break;after = p.next_after;
    }
    const saved = (await publicIntents()).filter(r => scope.current && samePublicScope(r.scope, scope.current));
    if (mounted.current) { setOutbox(entries);setIntents(saved); }
  }
  async function readPage(after: number, append: boolean) {
    const result = await publicOperation<PublicPage>('public-page', { after, limit: 4 });
    let root = threadRef.current;
    if (root) {
      const checked = await publicOperation<{ posts: PublicRow[] }>('public-numbers', { numbers: [Number(root.post_number)] });
      const found = checked.posts[0];
      if (found.bundle_hash !== root.bundle_hash || !found.proofs_verified || found.post?.kind !== 'thread') throw new Error('The thread root is no longer independently verified. Saved content is retained.');
      root = found;
    }
    if (mounted.current) { setPage(result);setStale(false);setFreshNumbers(new Set([...result.requested_numbers, ...(root ? [root.post_number] : [])]));
      if (root) { setThread(root);threadRef.current = root; }
      setRows(old => append ? [...old.filter(r => !result.posts.some(n => n.post_number === r.post_number)), ...result.posts].slice(-128) : result.posts); }
  }
  async function action(work: () => Promise<void>, reads = false) {
    if (working.current) return;working.current = true;setBusy(true);setError('');
    try { await work(); } catch (e) { if (mounted.current) { setError(e instanceof Error ? e.message : 'Public operation unavailable. Saved state is preserved.');if (reads) setStale(true); } }
    finally { working.current = false;if (mounted.current) setBusy(false); }
  }
  async function setupIdentity(work: () => Promise<unknown>) {
    await action(async () => {
      setIdentityNotice('Setting up your private authorship identity…');
      try {
        await work();setOptions(await publicOperation<Options>('public-identity-options'));
        setIdentityNotice('');
      } catch (e) {
        setIdentityNotice('Setup was not confirmed. Reopen this view to check for a saved identity before trying again. Existing keys and recovery records are preserved.');
        throw e;
      } finally { setCreateConsent(false);setReuseConsent(false); }
    });
  }
  function initialize() {
    const request = ++generation.current;
    void action(async () => {
      setLoading('Connecting to the installed helper…');
      const c = await publicOperation<Capabilities>('public-capabilities');if (!mounted.current || request !== generation.current) return;
      scope.current = c.scope;setCaps(c);
      setLoading('Checking your saved identity and posts…');
      // The native bridge serializes requests. Check local state first, so a
      // slow chain/content read cannot hide the identity and recovery controls.
      const [identity, saved] = await Promise.allSettled([
        publicOperation<Options>('public-identity-options').then(value => { if (mounted.current && request === generation.current) setOptions(value);return value; }), syncOutbox(),
      ]);
      if (!mounted.current || request !== generation.current) return;
      setLocalError([
        ...(identity.status === 'rejected' ? ['Private authorship setup is unavailable.'] : []),
        ...(saved.status === 'rejected' ? ['Saved public posts are unavailable. Saved data is preserved.'] : []),
      ].join(' '));
      setLoading('Loading public posts and checking their proofs…');
      try { await readPage(0, false); }
      catch { if (mounted.current) { setStale(true);setError('Public records could not be refreshed. Your saved posts are safe. Use Refresh current public page to try again.'); } }
    }, true).finally(() => { if (mounted.current) setLoading(''); });
  }
  useEffect(() => {
    mounted.current = true;initialize();
    return () => { mounted.current = false;generation.current++; };
  }, []);
  useEffect(() => {
    let active = true;let received = false;let unsubscribe = () => {};
    const accept = (url: string) => { if (active) {
      if (selectedRef.current !== url) { threadRef.current = undefined;setThread(undefined);setCreating(false); }
      selectedRef.current = url;setInput(url);setSelected(url);received = true;
    } };
    void windowKey().then(async key => {
      if (!active) return;unsubscribe = subscribeSelection(key, s => accept(s.kind === 'post' ? s.post.url : ''));
      const initial = await getSelection(key);if (initial && !received) accept(initial.kind === 'post' ? initial.post.url : '');
    }).catch(() => undefined);return () => { active = false;unsubscribe(); };
  }, []);
  function checkSubmission(result: PublicSubmission, intent?: PublicIntent) {
    const { submission_id: _id, ...where } = result.core.context;acceptScope(where);
    if (intent && canonicalAscii({ post: result.core.post, selection: result.core.selection, thread: result.core.thread, references: result.core.references })
      !== canonicalAscii({ post: intent.post, selection: intent.selection, thread: intent.thread, references: intent.references })) throw new Error('The saved public intent changed. Your draft is preserved.');
  }
  async function continueIntent(intent: PublicIntent) {
    if (!scope.current || !samePublicScope(scope.current, intent.scope)) throw new Error('This saved intent belongs to another public deployment.');
    const prepared = await publicOperation<PublicSubmission>('public-prepare', intentBody(intent));checkSubmission(prepared, intent);
    await acknowledgePublicIntent(intent.post.id);
    if (intent.selection.followers_threshold !== null && prepared.bundle_hash === null) {
      // An unavailable optional proof cannot prevent signing otherwise valid text.
      try { await publicOperation('public-attach-followers', { post_id: intent.post.id, approve_follower_disclosure: true }); } catch { /* Independent reader omits the missing badge. */ }
    }
    if (intent.selection.address && prepared.bundle_hash === null) {
      setNotice('Post saved. Exact-post wallet authorization is needed before continuing. Open the separate public wallet screen to authorize it.');
      await syncOutbox();return;
    }
    const finished = await publicOperation<PublicSubmission>('public-finish', { post_id: intent.post.id, approve_publication: true });checkSubmission(finished, intent);
    if (caps?.publication_mode === 'direct') {
      setNotice('Exact public post saved. Export its public bundle, upload it to the configured origin, then explicitly pay Base gas.');
      await syncOutbox();return;
    }
    const result = await publicOperation<PublicSubmission>('public-publish', { post_id: intent.post.id, approve_publication: true });checkSubmission(result, intent);
    setNotice(result.last_known?.state === 'finalized' ? `Public post No.${result.last_known.post_number} independently checked.` : 'Saved exact publication. Check this operation before retrying.');
    await syncOutbox();
  }
  const scopeKey = caps ? `${caps.scope.application}:${caps.scope.contract}` : 'unconfigured';
  const draftKey = thread ? `reply:public-v5:${scopeKey}:${thread.bundle_hash}:root` : `thread:public-v5:${scopeKey}:${selected || 'all'}`;
  async function submit(draft: Draft, selection: PublicSelection) {
    if (!caps || !options || working.current) throw new Error('Wait for the private authorship check. Your draft is preserved.');
    working.current = true;setBusy(true);setError('');
    try {
      const value: PublicIntent = { scope: caps.scope, draft_key: draftKey,
        post: { kind: thread ? 'comment' : 'thread', id: crypto.randomUUID(), created_at: Math.floor(Date.now() / 1000), title: thread ? null : draft.title.trim(),
          body: draft.body.trim(), references: selected ? [[selected, parsePostUrl(selected).postId]] : [] }, selection,
        thread: thread ? captureRef(thread, caps.scope) : null, references: [], acknowledged: false, released: false };
      const intent = await preparePublicIntent(value);setIntents((await publicIntents()).filter(r => samePublicScope(r.scope, caps.scope)));
      await continueIntent(intent);return intent.post.id;
    } finally { working.current = false;if (mounted.current) setBusy(false); }
  }
  async function openRow(row: PublicRow, freshlyFetched = false) {
    if ((!freshlyFetched && (stale || !freshNumbers.has(row.post_number))) || !row.proofs_verified || row.relationship_state !== 'valid') throw new Error('Independently refresh this post before opening its thread.');
    let root = row;
    if (row.post?.kind === 'comment') {
      if (!row.thread?.number) throw new Error('The root number is unavailable. Read the original root before replying.');
      const p = await publicOperation<{ posts: PublicRow[] }>('public-numbers', { numbers: [Number(row.thread.number)] });root = p.posts[0];
      if (root.bundle_hash !== row.thread.bundle_hash) throw new Error('The thread commitment changed.');
    }
    if (root.state !== 'finalized' || !root.proofs_verified || root.post?.kind !== 'thread') throw new Error('The thread root is not independently verified.');
    threadRef.current = root;setThread(root);setCreating(false);setFreshNumbers(new Set([row.post_number, root.post_number]));setStale(false);
  }
  async function reference(number: string) {
    if (!Number.isSafeInteger(Number(number))) throw new Error('Post number is unsupported.');
    const result = await publicOperation<{ posts: PublicRow[] }>('public-numbers', { numbers: [Number(number)] });
    const row = result.posts[0];await openRow(row,true);setNotice(`Opened the thread for No.${number}. Only loaded comments are shown.`);
  }
  async function attachHistory(row: PublicSubmission) {
    if (!linkConsent || !caps || !/^[1-9][0-9]*(?:\s*,\s*[1-9][0-9]*){0,14}$/.test(history)) throw new Error('Select up to 15 distinct earlier post numbers and explicitly approve linking.');
    const numbers = history.split(',').map(v => Number(v.trim()));if (new Set(numbers).size !== numbers.length || numbers.some(n => !Number.isSafeInteger(n))) throw new Error('Earlier post numbers must be distinct supported integers.');
    const refs: PublicReference[] = [];
    for (let i = 0; i < numbers.length; i += 4) {
      const p = await publicOperation<{ posts: PublicRow[] }>('public-numbers', { numbers: numbers.slice(i, i + 4) });
      for (const old of p.posts) { if (!old.proofs_verified || old.state !== 'finalized') throw new Error('An earlier post is unavailable or invalid. No history claim was attached.');refs.push(captureRef(old, caps.scope)); }
    }
    const result = await publicOperation<PublicSubmission>('public-attach-history', { post_id: row.core.post.id, records: refs, approve_linking: true });checkSubmission(result);
    setLinkConsent(false);setNotice('Selected authorship proof attached to this exact saved post. Publication remains a separate action.');await syncOutbox();
  }
  const known = thread ? rows.filter(r => r.post?.kind === 'comment' && r.thread?.bundle_hash === thread.bundle_hash) : rows.filter(r => !selected || !r.post || r.post.references.some(ref => ref[0] === selected));
  const shown = thread ? [thread, ...known.filter(r => r.post_number !== thread.post_number)].sort((a, b) => Number(a.post_number) - Number(b.post_number)) : known;
  const pendingIds = intents.filter(i => !outbox.some(o => o.core.post.id === i.post.id));
  return <section className="public-discussion" aria-label="Public permissionless discussions">
    <h2>Public discussions</h2><p>Base Sepolia test beta · Indexing commits bytes; the local verifier checks their meaning.</p>
    <form className="shared-selected-post" onSubmit={e => { e.preventDefault();try { const value = input.trim() ? parsePostUrl(input).url : '';selectedRef.current = value;setSelected(value);setInput(value);threadRef.current = undefined;setThread(undefined); } catch { setError('Enter an individual X post URL. Your current view is preserved.'); } }}>
      <label>Selected post<input value={input} onChange={e => setInput(e.target.value)} /></label><button>Load selected post</button>
    </form>
    <p>Reading is free. Source filters cover loaded records only; unavailable records cannot be classified. No complete-history claim is made.</p>
    {(error || localError) && <p role="alert">{[error, localError].filter(Boolean).join(' ')}</p>}{notice && <p role="status">{notice}</p>}
    {busy && <p aria-live="polite">{loading || 'Working… Keep this view open. Saved actions will not be submitted twice.'}</p>}
    {!caps && !busy && <button onClick={initialize}>Reconnect to installed app</button>}
    {stale && <p>Last loaded content is retained. Its proof badges are hidden until an independent refresh succeeds.</p>}
    {caps && <>
      <div className="public-actions"><button disabled={!options?.identity_record_present} onClick={() => { threadRef.current = undefined;setThread(undefined);setCreating(true); }}>Start public thread</button>
        <button disabled={busy} onClick={() => void action(() => readPage(page?.after ?? 0, false), true)}>Refresh current public page</button>
        {page?.more && <button disabled={busy} onClick={() => void action(() => readPage(page.next_after, true), true)}>Load next four public records</button>}
        {thread && <button onClick={() => { threadRef.current = undefined;setThread(undefined); }}>Back to loaded records</button>}</div>
      {(creating || thread) && <PublicComposer key={draftKey} draftKey={draftKey} reply={!!thread} direct={caps.publication_mode === 'direct'} onSubmit={submit} />}
      <PublicContentArchive scope={caps.scope} disabled={busy}/>
      <details><summary>Private authorship setup and recovery</summary>
        <p>Twitter and MetaMask are optional. Keep a secure copy of your authorship secret: losing every copy loses control. Restoring it does not restore missing credentials or tickets. Shared or stolen keys confer the same authority.</p>
        {!options ? <p>{busy ? 'Checking private authorship setup…' : 'Private authorship setup is unavailable. Reopen this view to retry. Public reading remains available.'}</p> : options.identity_record_present ? <p>A protected authorship record is present.</p> : <>
          {options.sources.some(s => s.identity_record_present || s.pending_recovery) ?
            <p>An existing private key or saved recovery needs your attention. To keep your existing identity, approve reuse and choose its key below. A key with pending recovery must be recovered first.</p> : <>
              <label><input type="checkbox" checked={createConsent} onChange={e => setCreateConsent(e.target.checked)} />I approve creating a private authorship key on this computer</label>
              <button disabled={busy || !createConsent} onClick={() => void setupIdentity(() => publicOperation('public-initialize-identity', { approve_private_key_setup: true }))}>Create private authorship identity</button>
            </>}
          {!!options?.sources.length && <><label><input type="checkbox" checked={reuseConsent} onChange={e => setReuseConsent(e.target.checked)} />I approve reusing the selected existing private key</label>
            {options.sources.map((s, i) => <button key={s.source_id} disabled={busy || !reuseConsent || !s.identity_record_present || s.pending_recovery} onClick={() => void setupIdentity(() =>
              publicOperation('public-adopt-identity', { source_id: s.source_id, approve_key_reuse: true })
            )}>Reuse existing {s.kind} key {i + 1}</button>)}</>}
        </>}
        {identityNotice && <p aria-live="polite">{identityNotice}</p>}
      </details>
      {caps.source_enrollment_configured && <PublicSourceEnrollment busy={busy} identityPresent={!!options?.identity_record_present} run={work=>action(work)} />}
      {caps.anonymous_ticket_packs && <details><summary>Prepaid publication tickets</summary><p>The operator can refuse redemption or lose prepaid funds. Blind tickets do not hide IP addresses, timing or small anonymity sets.</p>
        <button disabled={busy} onClick={()=>void api().tabs.create({url:api().runtime.getURL('public-tickets.html')}).catch(()=>setError('Could not open ticket purchases. Saved state is preserved.'))}>Buy or recover tickets</button>
        <button disabled={busy} onClick={() => void action(async () => setTickets(await publicOperation<Tickets>('public-ticket-status')))}>Check ticket inventory</button>
        {tickets && <><p>{tickets.available} available · {tickets.reserved} reserved · {tickets.pack_size} tickets per pack · pack price {tickets.pack_price_wei} wei</p>
          {tickets.purchase_pending && <button disabled={busy} onClick={() => void action(async () => { await publicOperation('public-ticket-recover');setTickets(await publicOperation<Tickets>('public-ticket-status')); })}>Recover paid ticket pack</button>}
          <p>Purchases and cancellation use the separate ticket wallet screen.</p></>}
      </details>}
      {caps.publication_mode === 'direct' && <p>Direct-payment test: prepaid tickets are not configured. {!caps.source_enrollment_configured && 'Follower enrollment is not configured. '}Gas payment exposes your wallet address and can link posts. The payer is not proof of authorship. Read and author verification still run locally.</p>}
      <section aria-label="Public submission outbox"><h3>Saved public posts</h3>
        {caps.publication_mode === 'direct' && <label><input type="checkbox" checked={payerConsent} onChange={e=>setPayerConsent(e.target.checked)} />I approve revealing the gas payer's address and linking payments. I will approve at most 0.001 Base Sepolia test ETH in total wallet fees.</label>}
        {caps.publication_mode === 'direct' && <details><summary>Pay gas for a public bundle</summary>
          <p>You can pay for someone else's exported post. The helper must download the exact public bytes and verify their authorship and deployment first. Paying does not establish that you authored the post.</p>
          <label>Public bundle hash<input value={publicHash} onChange={e=>setPublicHash(e.target.value)} placeholder="0x… SHA-256" disabled={busy} /></label>
          <button disabled={busy || !payerConsent || !publicHash.trim()} onClick={()=>void action(async()=>{
            const hash=await publishPublicBundleHash(publicHash.trim(),caps.scope,payerConsent);setPayerConsent(false);
            setNotice(`Wallet submitted ${hash}. Publication is not yet verified. Refresh public records after finality for an independent check.`);
          })}>Verify public bundle and pay gas</button>
        </details>}
        {outbox.map(row => <article key={row.core.post.id}><h4>{row.core.post.title ?? 'Comment'}</h4><p>{row.core.post.body}</p>
          <p>{row.phase} · {row.last_known ? `Last known ${row.last_known.state}${row.last_known.post_number ? ` · No.${row.last_known.post_number}` : ''}` : 'Not independently checked'}</p>
          {row.core.selection.address && !row.bundle_hash && <><p>Exact-post wallet authorization is needed.</p><button disabled={busy} onClick={() => void api().tabs.create({url:api().runtime.getURL(`public-wallet.html#post=${row.core.post.id}`)}).catch(()=>setError('Could not open the public wallet screen. The saved post is preserved.'))}>Authorize saved public post</button></>}
          {row.bundle_hash && <button disabled={busy} onClick={() => void action(async () => { const result = await publicOperation<PublicSubmission>('public-check', { post_id: row.core.post.id });checkSubmission(result);setNotice(`Current check: ${result.last_known?.state}`);await syncOutbox(); })}>Check saved public post</button>}
          {row.bundle_hash && caps.publication_mode === 'direct' && <>
            <button disabled={busy} onClick={()=>void action(async()=>{await downloadPublicBundle(row,caps.scope);setNotice('Exported only the exact public bundle. Upload it using the reviewed storage action before paying gas.');})}>Export public bundle</button>
            <button disabled={busy || !payerConsent} onClick={()=>void action(async()=>{
              const result=await publicOperation<PublicSubmission>('public-check',{post_id:row.core.post.id});checkSubmission(result);
              if (result.last_known?.state!=='not-indexed') {setNotice(`Current check: ${result.last_known?.state}. No new wallet request.`);await syncOutbox();return;}
              const hash=await publishDirect(row,caps.scope,payerConsent);setPayerConsent(false);
              setNotice(`Wallet submitted ${hash}. Use Check saved public post after finality; a transaction hash does not establish verified publication.`);
              await syncOutbox();
            })}>Verify public upload and pay gas</button>
          </>}
          <button disabled={busy} onClick={() => void action(async () => {
            const intent = intents.find(i => i.post.id === row.core.post.id);
            if (intent) await continueIntent(intent);
            else if (row.bundle_hash && caps.publication_mode === 'direct') setNotice('Exact public post retained. Export it or check its existing wallet submission.');
            else if (row.bundle_hash) { const result = await publicOperation<PublicSubmission>('public-publish', { post_id: row.core.post.id, approve_publication: true });checkSubmission(result);await syncOutbox(); }
            else throw new Error('Recover the original saved browser intent before continuing this unsigned post.');
          })}>Resume exact public post</button>
          {!row.bundle_hash && <details><summary>Link selected earlier authorship</summary><p>This publicly links only the selected original posts to this exact new post. Unbound old posts and different keys cannot qualify.</p>
            <label>Earlier post numbers<input value={history} onChange={e => setHistory(e.target.value)} placeholder="1, 2" /></label>
            <label><input type="checkbox" checked={linkConsent} onChange={e => setLinkConsent(e.target.checked)} />I approve linking these selected posts</label>
            <button disabled={busy || !linkConsent} onClick={() => void action(() => attachHistory(row))}>Attach selected authorship proof</button></details>}
          {intents.some(i => i.post.id === row.core.post.id && i.acknowledged && !i.released) && <button disabled={busy} onClick={() => void action(async () => { await acknowledgePublicIntent(row.core.post.id, true);await syncOutbox();setNotice('Saved post retained. Your edited draft can now create a different post.'); })}>Use edited draft for a new public post</button>}
        </article>)}
        {pendingIds.map(i => <article key={i.post.id}><p>{i.post.title ?? 'Comment'} · preparation recovery required</p><button disabled={busy} onClick={() => void action(() => continueIntent(i))}>Recover exact public preparation</button></article>)}
      </section>
      <section aria-label="Loaded public records"><h3>{thread ? 'Thread · loaded comments' : 'Loaded canonical records'}</h3>
        {!shown.length && <p>No matching posts in the loaded records. Other pages or unavailable content may contain more.</p>}
        {shown.map(row => <article key={row.post_number} className="shared-post"><PostId number={row.post_number} onCopied={setNotice} />
          {row.state === 'finalized' && row.proofs_verified && row.post ? <><p>Anonymous {!stale && freshNumbers.has(row.post_number) ? <span>· Test proof · private authorship checked</span> : <span>· Previously loaded; independent refresh needed</span>}</p>
            {row.post.title && <h3>{row.post.title}</h3>}<PostBody body={row.post.body} className="post-body" onReference={n => void action(() => reference(n), true)} />
            {!stale && freshNumbers.has(row.post_number) && row.display?.address && <p>Test · Ethereum address {row.display.address}</p>}
            {!stale && freshNumbers.has(row.post_number) && row.display?.followers && <p>Test · Followers greater than {row.display.followers.threshold.toLocaleString()} when indexed</p>}
            {!stale && freshNumbers.has(row.post_number) && row.display?.history && <p>Test · Common authorship of selected posts {row.display.history.map(r => `No.${r.number}`).join(', ')}</p>}
            <button disabled={busy || stale || !freshNumbers.has(row.post_number) || row.relationship_state !== 'valid'} onClick={() => void action(() => openRow(row), true)}>Open public thread</button>
          </> : <p>{row.state} · no verified authorship or badges</p>}
        </article>)}
        <p>At most 128 loaded records are retained in this view. Other records are not deleted or claimed unavailable.</p>
      </section>
    </>}
  </section>;
}
