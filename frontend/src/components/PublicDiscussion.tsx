import { useEffect, useRef, useState } from 'react';
import { canonicalAscii } from '../authoredWallet';
import { publicOperation, PublicOperationError, type PublicScope, type PublicSubmission, type PublicRow, type PublicReference, type PublicPage, type PublicSelection } from '../publicDiscussion';
import { acknowledgePublicIntent, intentBody, preparePublicIntent, publicIntents, samePublicScope, type PublicIntent } from '../data/publicIntents';
import { readDraft, clearDraftIfUnchanged, type Draft } from '../data/drafts';
import { parsePostUrl } from '../urls';
import { getSelection, subscribeSelection, windowKey } from '../platform/selection';
import { api } from '../platform/browser';
import { PublicComposer } from './PublicComposer';
import { PostBody, PostId } from './PostBody';
import { downloadPublicBundle, publishDirect, publishPublicBundleHash } from '../publicDirect';
import { PublicSourceEnrollment } from './PublicSourceEnrollment';
import { PublicContentArchive } from './PublicContentArchive';
import { forumURL } from '../canonicalForum';
import { PublicationProgress } from './PublicationProgress';

export type Capabilities = { scope: PublicScope; source_enrollment_configured: boolean; follower_proof_configured: boolean;
  anonymous_ticket_packs: boolean; publication_mode?: 'direct' | 'tickets' };
type Options = { identity_record_present: boolean; sources: { source_id: string; kind: string; identity_record_present: boolean; pending_recovery: boolean }[] };
type Tickets = { available: number; reserved: number; purchase_pending: boolean; pack_size: number; pack_price_wei: string; can_purchase: boolean; can_redeem: boolean };
const captureRef = (row: PublicRow, scope: PublicScope): PublicReference => ({ protocol: 5, chain_id: scope.chain_id, contract: scope.contract, number: row.post_number, bundle_hash: row.bundle_hash! });
export function PublicDiscussion({mode='legacy',root,onPublished,initialCapabilities}:{mode?:'legacy'|'editor'|'settings';root?:PublicRow;onPublished?:(number:string)=>void;initialCapabilities?:Capabilities}) {
  const [caps, setCaps] = useState<Capabilities>();const scope = useRef<PublicScope | undefined>(undefined);
  const [options, setOptions] = useState<Options>();const [tickets, setTickets] = useState<Tickets>();
  const [ticketsOpen,setTicketsOpen]=useState(false);const [ticketInventoryError,setTicketInventoryError]=useState(false);
  const [ticketNeededFor,setTicketNeededFor]=useState<string>();
  const [rows, setRows] = useState<PublicRow[]>([]);const [page, setPage] = useState<PublicPage>();const [stale, setStale] = useState(false);
  const [freshNumbers, setFreshNumbers] = useState<Set<string>>(new Set());
  const threadRef = useRef<PublicRow | undefined>(undefined);
  const [outbox, setOutbox] = useState<PublicSubmission[]>([]);const [outboxUnavailable,setOutboxUnavailable]=useState(false);const [intents, setIntents] = useState<PublicIntent[]>([]);
  const [thread, setThread] = useState<PublicRow>();const [creating, setCreating] = useState(false);
  const [input, setInput] = useState('');const [selected, setSelected] = useState('');
  const selectedRef = useRef('');
  const [error, setError] = useState('');const [localError, setLocalError] = useState('');const [notice, setNotice] = useState('');const [busy, setBusy] = useState(true);
  const [loading, setLoading] = useState('Connecting to the installed helper…');
  const [publicationStage,setPublicationStage]=useState<number>();const [publicationStarted,setPublicationStarted]=useState(0);
  const [publishedResult,setPublishedResult]=useState<PublicSubmission>();const [publishedBadges,setPublishedBadges]=useState<PublicRow>();
  const [monitorNotice,setMonitorNotice]=useState('');
  const checkedPublications=useRef(new Set<string>());const [publicationChecks,setPublicationChecks]=useState<Record<string,'checking'|'checked'|'unavailable'>>({});const [publishedNumber,setPublishedNumber]=useState<string>();
  const publishedCallback=useRef(onPublished);publishedCallback.current=onPublished;
  function published(result:PublicSubmission){if(result.last_known?.state==='finalized'&&result.last_known.post_number&&(root?result.core.thread?.bundle_hash===root.bundle_hash:!result.core.thread)){setPublishedNumber(result.last_known.post_number);setPublishedResult(result);setPublicationStage(undefined);publishedCallback.current?.(result.last_known.post_number);}}
  const [history, setHistory] = useState('');const [linkConsent, setLinkConsent] = useState(false);
  const [createConsent, setCreateConsent] = useState(false);const [reuseConsent, setReuseConsent] = useState(false);
  const [identityNotice, setIdentityNotice] = useState('');
  const [payerConsent, setPayerConsent] = useState(false);
  const [publicHash, setPublicHash] = useState('');
  const working = useRef(false);const mounted = useRef(true);const generation = useRef(0);
  function acceptScope(v: PublicScope) { if (!scope.current || !samePublicScope(v, scope.current)) throw new Error('The public installation changed. Reopen after reviewing the update.'); }
  async function syncOutbox() {
    try {
    const entries: PublicSubmission[] = [];let after = 0;
    for (let i = 0; i < 10; i++) {
      const p = await publicOperation<{ entries: PublicSubmission[]; next_after: number | null }>('public-outbox', { after, limit: 4 });
      for (const row of p.entries) { const { submission_id: _id, ...where } = row.core.context;acceptScope(where); }
      entries.push(...p.entries);if (p.next_after === null) break;after = p.next_after;
    }
    const saved = (await publicIntents()).filter(r => scope.current && samePublicScope(r.scope, scope.current));
    if (mounted.current) { setOutbox(entries);setIntents(saved); }
      if(mounted.current){setOutboxUnavailable(false);setLocalError(old=>old.replace('Saved public posts are unavailable. Saved data is preserved.','').replace('Publication status could not be restored. Keep this view open; your draft and ticket assignment are preserved.','').trim());}
    } catch(error) { if(mounted.current)setOutboxUnavailable(true);throw error; }
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
    setLoading(reads?'Checking finalized public records and proofs…':'Checking this saved operation…');
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
      const c = initialCapabilities ?? await publicOperation<Capabilities>('public-capabilities');if (!mounted.current || request !== generation.current) return;
      scope.current = c.scope;setCaps(c);
      if(root){threadRef.current=root;setThread(root);}else if(mode==='editor')setCreating(true);
      setLoading('Checking your private authorship setup…');
      // The native bridge serializes requests. Check local state first, so a
      // slow chain/content read cannot hide the identity and recovery controls.
      const [identity, saved] = await Promise.allSettled([
        publicOperation<Options>('public-identity-options').then(value => { if (mounted.current && request === generation.current) setOptions(value);return value; }), mode==='settings'?Promise.resolve():syncOutbox(),
      ]);
      if (!mounted.current || request !== generation.current) return;
      setLocalError([
        ...(identity.status === 'rejected' ? ['Private authorship setup is unavailable.'] : []),
        ...(saved.status === 'rejected' ? ['Saved public posts are unavailable. Saved data is preserved.'] : []),
      ].join(' '));
      if(mode!=='legacy')return;
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
    const accept = (url: string) => { if (active && mode==='legacy') {
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
    try {
    setPublicationStarted(Math.floor(Date.now()/1000));setPublicationStage(0);
    setLoading('Saving the exact post and its disclosure choices…');
    const prepared = await publicOperation<PublicSubmission>('public-prepare', intentBody(intent));checkSubmission(prepared, intent);
    await acknowledgePublicIntent(intent.post.id);
    if (intent.history && prepared.bundle_hash === null) {
      setPublicationStage(1);setLoading('Proving authorship of your selected earlier posts…');
      try {
        const attached = await publicOperation<PublicSubmission>('public-attach-history', { post_id: intent.post.id, records: intent.history.records, approve_linking: true });checkSubmission(attached, intent);
      } catch { throw Error('The selected authorship proof could not be prepared. Your exact post and selected history are saved. If wallet authorization already started, recover it on the wallet screen. This action did not publish or spend a ticket.'); }
    }
    if (intent.selection.followers_threshold !== null && prepared.bundle_hash === null) {
      setPublicationStage(1);setLoading('Checking your saved follower credential and preparing its private proof…');
      try { await publicOperation('public-attach-followers', { post_id: intent.post.id, approve_follower_disclosure: true }); }
      catch { throw Error('The follower proof could not be prepared. This comment has not been submitted and no publication ticket has been spent. Your exact comment is saved. Check your follower credential before retrying.'); }
    }
    if (intent.selection.address && prepared.bundle_hash === null) {
      setNotice('Post saved. Exact-post wallet authorization is needed before continuing. Open the separate public wallet screen to authorize it.');
      await syncOutbox();setPublicationStage(undefined);return;
    }
    setPublicationStage(1);setLoading('Signing and verifying this exact public post…');
    const finished = await publicOperation<PublicSubmission>('public-finish', { post_id: intent.post.id, approve_publication: true });checkSubmission(finished, intent);
    if (caps?.publication_mode === 'direct') {
      setNotice('Exact public post saved. Export its public bundle, upload it to the configured origin, then explicitly pay Base gas.');
      await syncOutbox();setPublicationStage(undefined);return;
    }
    setPublicationStage(2);setLoading('Uploading your exact comment and submitting it using one ticket. Waiting for the service response…');
    const result = await publicOperation<PublicSubmission>('public-publish', { post_id: intent.post.id, approve_publication: true });checkSubmission(result, intent);
    setNotice(result.last_known?.state === 'finalized' ? `Public post No.${result.last_known.post_number} independently checked.` : 'Post submitted. The app checks finalized inclusion automatically while this view is open. Do not publish it again.');
    await syncOutbox();published(result);setPublicationStage(undefined);
    } catch(error) {
      // A failed response can follow a completed native write. Read the exact
      // local outbox before deciding what is unfinished; never resend here.
      try { await syncOutbox(); } catch { setLocalError('Publication status could not be restored. Keep this view open; your draft and ticket assignment are preserved.'); }
      setPublicationStage(undefined);throw error;
    }
  }
  const scopeKey = caps ? `${caps.scope.application}:${caps.scope.contract}` : 'unconfigured';
  const draftKey = thread ? `reply:public-v5:${scopeKey}:${thread.bundle_hash}:root` : `thread:public-v5:${scopeKey}:${selected || 'all'}`;
  async function submit(draft: Draft, selection: PublicSelection, historyNumbers: number[]) {
    if (!caps || !options || working.current) throw new Error('Wait for the private authorship check. Your draft is preserved.');
    working.current = true;setBusy(true);setError('');
    setLoading('Saving your exact publication request…');
    try {
      if(caps.anonymous_ticket_packs){
        setPublicationStarted(Math.floor(Date.now()/1000));setPublicationStage(0);setLoading('Checking publication tickets before preparing your comment…');
        let inventory:Tickets;
        try{inventory=await publicOperation<Tickets>('public-ticket-status');setTickets(inventory);}
        catch{throw Error('Ticket availability could not be checked. Your comment is still a draft; no publication was prepared.');}
        if(inventory.available<1)throw Error('No publication tickets available. Buy or recover tickets; your comment is still a draft.');
      }
      const historyRefs: PublicReference[] = [];
      for (let i = 0; i < historyNumbers.length; i += 4) {
        setLoading('Checking the selected earlier posts…');
        const numbers = historyNumbers.slice(i, i + 4);
        const page = await publicOperation<PublicPage>('public-numbers', { numbers });
        if (page.posts.length !== numbers.length || page.posts.some((r, j) => r.post_number !== String(numbers[j]) || !r.proofs_verified || r.state !== 'finalized'))
          throw Error('An earlier post is unavailable or invalid. Your draft is preserved; no publication was prepared.');
        historyRefs.push(...page.posts.map(r => captureRef(r, caps!.scope)));
      }
      const value: PublicIntent = { scope: caps.scope, draft_key: draftKey,
        post: { kind: thread ? 'comment' : 'thread', id: crypto.randomUUID(), created_at: Math.floor(Date.now() / 1000), title: thread ? null : draft.title.trim(),
          body: draft.body.trim(), references: selected ? [[selected, parsePostUrl(selected).postId]] : [] }, selection,
        thread: thread ? captureRef(thread, caps.scope) : null, references: [], acknowledged: false, released: false, ...(historyRefs.length ? { history: { profile: 'nockapp-public-history-plan-v1' as const, records: historyRefs, approve_linking: true as const } } : {}) };
      const intent = await preparePublicIntent(value);setIntents((await publicIntents()).filter(r => samePublicScope(r.scope, caps.scope)));
      await continueIntent(intent);return intent.post.id;
    } catch(error){
      if(mounted.current){setError(error instanceof Error?error.message:'Publication unavailable. Your draft is preserved.');
      }
      return null;
    } finally { working.current = false;if (mounted.current){setBusy(false);setPublicationStage(undefined);} }
  }
  async function publishSaved(row:PublicSubmission,approveOptionalBadgeFailure=false){
    try{
      const result=await publicOperation<PublicSubmission>('public-publish',{post_id:row.core.post.id,approve_publication:true,
        ...(approveOptionalBadgeFailure?{approve_optional_badge_failure:true}:{})});
      checkSubmission(result);
      if(canonicalAscii(result.core)!==canonicalAscii(row.core)||result.bundle_hash!==row.bundle_hash)throw Error('The saved publication changed. Keep its original operation.');
      setTicketNeededFor(old=>old===row.core.post.id?undefined:old);await syncOutbox();published(result);
    }catch(error){
      if(error instanceof PublicOperationError&&error.code==='publication-ticket-needed')setTicketNeededFor(row.core.post.id);
      throw error;
    }
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
  const inThisView=(r:PublicSubmission)=>mode==='legacy'||(root?r.core.thread?.bundle_hash===root.bundle_hash:!r.core.thread);
  const checkKey=(r:PublicSubmission)=>`${r.core.post.id}:${r.bundle_hash}`;
  const recentCompleted=new Set(outbox.filter(r=>!!r.last_attempt&&r.last_known?.state==='finalized').slice(-5).map(r=>r.core.post.id));
  const pendingChecks=outbox.filter(r=>!!r.bundle_hash&&r.last_known?.state!=='invalid'&&(
    !!r.last_attempt&&(r.last_known?.state!=='finalized'||recentCompleted.has(r.core.post.id))
    ||inThisView(r)&&!r.last_attempt&&r.last_known?.state!=='finalized'&&mode!=='legacy'&&!checkedPublications.current.has(checkKey(r))
  )).map(r=>r.core.post.id).sort().join(',');
  useEffect(()=>{
    if(!pendingChecks)return;
    let live=true;let checking=false;let cursor=0;const ids=pendingChecks.split(',');const controller=new AbortController();
    const check=async()=>{
      if(!live||checking||working.current||document.visibilityState==='hidden')return;checking=true;
      const id=ids[cursor++%ids.length];const previous=outbox.find(r=>r.core.post.id===id);
      try{
        if(!previous)return;
        setPublicationChecks(old=>({...old,[id]:'checking'}));
        const result=await publicOperation<PublicSubmission>('public-check',{post_id:id},controller.signal);checkSubmission(result);
        if(result.bundle_hash!==previous.bundle_hash||canonicalAscii(result.core)!==canonicalAscii(previous.core))throw Error('Publication status did not match the original comment.');
        if(live){
          if(result.last_known?.state==='finalized'){
            // Restore the canonical number without signing or another index.
            // The versioned native helper may repair exact finalized bytes.
            // Preserve released intents and newer drafts.
            if(mode!=='legacy'){
              const intent=(await publicIntents()).find(i=>i.post.id===id);if(intent&&!intent.released){
                checkSubmission(result,intent);const draft=await readDraft(intent.draft_key);
                if(draft.title.trim()===(intent.post.title??'')&&draft.body.trim()===intent.post.body&&draft.credentials.length===0&&!draft.passportFacts?.length&&!draft.zkidFacts?.length)await clearDraftIfUnchanged(intent.draft_key,draft);
                if(intent.acknowledged&&!intent.released)await acknowledgePublicIntent(id,true);
              }
            }
            if(live&&!working.current&&previous.last_known?.state!=='finalized'){setNotice(`Published as No.${result.last_known.post_number}. Publication restored automatically.`);if(mode!=='legacy')published(result);}
          }
          if(live){checkedPublications.current.add(checkKey(result));setPublicationChecks(old=>({...old,[id]:'checked'}));setOutbox(old=>old.map(r=>r.core.post.id===id&&r.bundle_hash===result.bundle_hash?result:r));setMonitorNotice('');}
        }
      }catch{if(live){setPublicationChecks(old=>({...old,[id]:'unavailable'}));setMonitorNotice('Publication status is temporarily unavailable. Checking again automatically; no ticket will be spent again.');}}
      finally{checking=false;}
    };
    const visible=()=>{if(document.visibilityState==='visible')void check();};
    const timer=setInterval(()=>void check(),30000);document.addEventListener('visibilitychange',visible);void check();
    return()=>{live=false;clearInterval(timer);document.removeEventListener('visibilitychange',visible);controller.abort();};
  },[pendingChecks,busy]);

  useEffect(()=>{
    if(!publishedResult?.last_known?.post_number||publishedResult.core.selection.followers_threshold===null)return;
    let live=true;const controller=new AbortController();let checking=false;setPublishedBadges(undefined);
    const check=async()=>{if(checking||document.visibilityState==='hidden')return;checking=true;try{
      const page=await publicOperation<PublicPage>('public-numbers',{numbers:[Number(publishedResult.last_known!.post_number)]},controller.signal);
      const row=page.posts[0];if(row?.bundle_hash===publishedResult.bundle_hash&&row.state==='finalized'&&row.proofs_verified&&live)setPublishedBadges(row);
    }catch{/* Keep the check pending and retry; never claim a missing badge from a failed read. */}finally{checking=false;}};
    void check();const timer=setInterval(()=>void check(),30000);const visible=()=>{if(document.visibilityState==='visible')void check();};document.addEventListener('visibilitychange',visible);
    return()=>{live=false;controller.abort();clearInterval(timer);document.removeEventListener('visibilitychange',visible);};
  },[publishedResult]);

  useEffect(()=>{
    if(mode==='legacy'||!outboxUnavailable)return;
    const retry=()=>{if(!working.current&&document.visibilityState==='visible')void syncOutbox().catch(()=>undefined);};
    const timer=setInterval(retry,30000);document.addEventListener('visibilitychange',retry);
    return()=>{clearInterval(timer);document.removeEventListener('visibilitychange',retry);};
  },[mode,outboxUnavailable]);

  useEffect(()=>{
    if(!caps?.anonymous_ticket_packs||!ticketsOpen||busy||tickets||ticketInventoryError)return;
    let live=true;
    void(async()=>{
      try{const value=await publicOperation<Tickets>('public-ticket-status');if(live)setTickets(value);}
      catch{if(live)setTicketInventoryError(true);}
    })();
    return()=>{live=false;};
  },[caps?.anonymous_ticket_packs,ticketsOpen,busy,tickets,ticketInventoryError]);
  useEffect(()=>{
    const refresh=()=>{if((ticketsOpen||mode==='editor')&&document.visibilityState==='visible'){setTicketInventoryError(false);setTickets(undefined);setTicketNeededFor(undefined);}};
    window.addEventListener('focus',refresh);document.addEventListener('visibilitychange',refresh);
    return()=>{window.removeEventListener('focus',refresh);document.removeEventListener('visibilitychange',refresh);};
  },[ticketsOpen,mode]);
  const shown = thread ? [thread, ...known.filter(r => r.post_number !== thread.post_number)].sort((a, b) => Number(a.post_number) - Number(b.post_number)) : known;
  const pendingIds = intents.filter(i => !outbox.some(o => o.core.post.id === i.post.id));
  const unfinished=outbox.filter(row=>row.last_known?.state!=='finalized'&&inThisView(row));
  const interrupted=pendingIds.filter(i=>root?i.thread?.bundle_hash===root.bundle_hash:!i.thread);
  if(mode!=='legacy')return <section className="public-discussion forum-workflow" aria-label={mode==='settings'?'Account and storage settings':'Publish a post'}>
    {(error||localError)&&<p role="alert">{error||localError}</p>}{notice&&<p role="status">{notice}</p>}
    {busy&&(publicationStage!==undefined?<PublicationProgress stage={publicationStage} message={loading} startedAt={publicationStarted}/>:<section aria-live="polite"><progress aria-label="Publication progress"/><p>{loading}</p></section>)}
    {caps&&<>
      {(mode==='settings'||!options?.identity_record_present)&&<div className="forum-identity">      <details><summary>Private authorship setup and recovery</summary>
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
</div>}
      {mode==='settings'?<>
        {caps.source_enrollment_configured&&<PublicSourceEnrollment busy={busy} identityPresent={!!options?.identity_record_present} run={work=>action(work)}/>}
        <PublicContentArchive scope={caps.scope} disabled={busy}/>
      </>:<>

        {monitorNotice&&<p role="status">{monitorNotice}</p>}
        {outboxUnavailable&&<section aria-live="polite"><progress aria-label="Restoring publication records"/><p>Restoring publication status automatically. New publication is paused; your draft and ticket assignment are preserved.</p></section>}
        {unfinished.map(row=><section className="forum-pending" key={row.core.post.id} aria-label="Unfinished publication">
          <h3>{row.core.post.kind==='comment'?'Your comment':'Your thread'}</h3>
          <p>{row.core.thread?.number?`Reply to thread No.${row.core.thread.number}`:'New thread'}{row.core.post.title?` · ${row.core.post.title}`:''}</p>
          <PostBody body={row.core.post.body} className="post-body" onReference={n=>void api().tabs.create({url:forumURL(n)})}/>
          {intents.find(i=>i.post.id===row.core.post.id)?.history&&<p>Selected authorship links: {intents.find(i=>i.post.id===row.core.post.id)!.history!.records.map(r=>`No.${r.number}`).join(', ')}.</p>}
          {row.bundle_hash&&!row.last_attempt&&['closing','expired'].includes(row.follower_window??'')&&<p role="status">The saved follower proof has run out of time. You can publish these exact bytes, but the follower badge may be missing. The original ticket assignment stays with this comment.</p>}
          {(row.last_attempt||row.phase==='submitted')&&row.last_known?.state!=='invalid'?<PublicationProgress stage={3} indexed={!!row.last_known?.post_number}
            startedAt={row.last_attempt?.requested_at??row.core.post.created_at} checkedAt={row.last_known?.checked_at}
            checking={publicationChecks[row.core.post.id]==='checking'}
            message={publicationChecks[row.core.post.id]==='unavailable'?'Status temporarily unavailable. Your comment is saved; checking again automatically.':row.last_known?.post_number?`Indexed as No.${row.last_known.post_number}. Checking and delivering the exact public files; no extra ticket is needed.`:'Publishing: waiting for finalized inclusion. This is checked automatically.'}/>:<p role="status">{row.last_known?.state==='invalid'?'The indexed post failed verification. Its ticket assignment is preserved.':row.bundle_hash&&publicationChecks[row.core.post.id]==='unavailable'?'Status unavailable. Checking again automatically; no new publication is being sent.':row.bundle_hash&&publicationChecks[row.core.post.id]!=='checked'?'Checking whether this exact comment was already published…':row.phase==='wallet-needed'?'Not submitted. This post needs your wallet authorization.':'Not submitted by this app. Review the exact text above before publishing.'}</p>}
          {row.last_attempt?.transaction_hash&&<a href={`https://sepolia.basescan.org/tx/${row.last_attempt.transaction_hash}`} target="_blank" rel="noopener">View submitted transaction</a>}
          {row.bundle_hash&&!row.last_attempt&&row.phase!=='submitted'&&row.last_known?.state!=='invalid'&&publicationChecks[row.core.post.id]!=='checked'&&<progress aria-label="Recovering publication status"/>}
          {row.core.selection.address&&!row.bundle_hash&&<button disabled={busy} onClick={()=>void api().tabs.create({url:api().runtime.getURL(`public-wallet.html#post=${row.core.post.id}`)})}>Authorize this post in MetaMask</button>}
          {row.phase!=='submitted'&&!row.last_attempt&&row.last_known?.state!=='invalid'&&(!row.bundle_hash||publicationChecks[row.core.post.id]==='checked')&&<button disabled={busy} onClick={()=>void action(async()=>{
            if(ticketNeededFor===row.core.post.id){await api().tabs.create({url:api().runtime.getURL('public-tickets.html')});return;}
            if(row.bundle_hash&&['closing','expired'].includes(row.follower_window??'')){
              await publishSaved(row,true);return;
            }
            const intent=intents.find(i=>i.post.id===row.core.post.id);if(intent)await continueIntent(intent);
            else if(row.bundle_hash)await publishSaved(row);
            else throw Error('The original publication request is unavailable. Your draft is preserved.');
          })}>{ticketNeededFor===row.core.post.id?'Buy or recover tickets':row.bundle_hash&&['closing','expired'].includes(row.follower_window??'')?'Publish even if badge is missing':row.core.post.kind==='comment'?'Publish this comment':'Publish this thread'}</button>}

          {!row.bundle_hash&&!intents.find(i=>i.post.id===row.core.post.id)?.history&&<details><summary>Prove earlier authorship</summary>
            <label>Earlier post numbers<input value={history} onChange={e=>setHistory(e.target.value)} placeholder="1, 2"/></label>
            <label><input type="checkbox" checked={linkConsent} onChange={e=>setLinkConsent(e.target.checked)}/>I approve linking these selected posts</label>
            <button disabled={busy||!linkConsent} onClick={()=>void action(()=>attachHistory(row))}>Attach selected authorship proof</button>
          </details>}
        </section>)}
        {interrupted.map(i=><section className="forum-pending" key={i.post.id} aria-label="Unsubmitted publication">
          <h3>{i.post.kind==='comment'?'Your unsubmitted comment':'Your unsubmitted thread'}</h3>
          <p>{i.thread?.number?`Reply to thread No.${i.thread.number}`:'New thread'}{i.post.title?` · ${i.post.title}`:''}</p>
          <PostBody body={i.post.body} className="post-body" onReference={n=>void api().tabs.create({url:forumURL(n)})}/>
          <p>No submission was confirmed. This action prepares and publishes only the exact text above.</p>
          <button disabled={busy||outboxUnavailable} onClick={()=>void action(()=>continueIntent(i))}>{i.post.kind==='comment'?'Publish this comment':'Publish this thread'}</button>
        </section>)}
        {options?.identity_record_present&&!busy&&!outboxUnavailable&&!unfinished.length&&!interrupted.length&&<PublicComposer key={draftKey} draftKey={draftKey} reply={!!root} direct={caps.publication_mode==='direct'} availableTickets={tickets?.available} onNeedTickets={()=>void api().tabs.create({url:api().runtime.getURL('public-tickets.html')})} onSubmit={submit}/>}
        {(unfinished.length>0||interrupted.length>0)&&<p>Resolve the publication above before writing another. Your draft is preserved.</p>}

        {publishedNumber&&<section className="forum-success" aria-label="Completed publication"><p>Published as <a href={forumURL(publishedNumber)}>No.{publishedNumber}</a>. Finalized and independently checked.</p>
          {publishedResult?.core.selection.followers_threshold!==null&&publishedResult&&<p>{!publishedBadges?'Checking the published follower badge…':publishedBadges.display?.followers?`Follower badge verified: followers greater than ${publishedBadges.display.followers.threshold}.`:'Your comment is published, but its follower badge could not be verified. Do not publish again to fix it.'}</p>}
        </section>}
      </>}
    </>}
  </section>;
  return <section className="public-discussion" aria-label="Public permissionless discussions">
    <h2>Public discussions</h2><p>Base Sepolia test beta · Indexing commits bytes; the local verifier checks their meaning.</p>
    <form className="shared-selected-post" onSubmit={e => { e.preventDefault();try { const value = input.trim() ? parsePostUrl(input).url : '';selectedRef.current = value;setSelected(value);setInput(value);threadRef.current = undefined;setThread(undefined); } catch { setError('Enter an individual X post URL. Your current view is preserved.'); } }}>
      <label>Selected post<input value={input} onChange={e => setInput(e.target.value)} /></label><button>Load selected post</button>
    </form>
    <p>Reading is free. Source filters cover loaded records only; unavailable records cannot be classified. No complete-history claim is made.</p>
    {(error || localError) && <p role="alert">{[error, localError].filter(Boolean).join(' ')}</p>}{notice && <p role="status">{notice}</p>}
    {busy && <div aria-live="polite"><progress aria-label="Current app action"/><p>{loading || 'Working… Keep this view open. Saved actions will not be submitted twice.'}</p></div>}
    {!caps && !busy && <button onClick={initialize}>Reconnect to installed app</button>}
    {stale && <p>Last loaded content is retained. Its proof badges are hidden until an independent refresh succeeds.</p>}
    {caps && <>
      <div className="public-actions"><button disabled={!options?.identity_record_present} onClick={() => { threadRef.current = undefined;setThread(undefined);setCreating(true); }}>Start public thread</button>
        <button disabled={busy} onClick={() => void action(() => readPage(page?.after ?? 0, false), true)}>Refresh current public page</button>
        {page?.more && <button disabled={busy} onClick={() => void action(() => readPage(page.next_after, true), true)}>Load next four public records</button>}
        {thread && <button onClick={() => { threadRef.current = undefined;setThread(undefined); }}>Back to loaded records</button>}</div>
      {(creating || thread) && <PublicComposer key={draftKey} draftKey={draftKey} reply={!!thread} direct={caps.publication_mode === 'direct'} availableTickets={tickets?.available} onNeedTickets={()=>void api().tabs.create({url:api().runtime.getURL('public-tickets.html')})} onSubmit={submit} />}
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
      {caps.anonymous_ticket_packs && <details onToggle={event=>{if(event.currentTarget.open){setTicketInventoryError(false);setTickets(undefined);}setTicketsOpen(event.currentTarget.open);}}><summary>Prepaid publication tickets</summary><p>The operator can refuse redemption or lose prepaid funds. Blind tickets do not hide IP addresses, timing or small anonymity sets.</p>
        <button disabled={busy} onClick={()=>void api().tabs.create({url:api().runtime.getURL('public-tickets.html')}).catch(()=>setError('Could not open ticket purchases. Saved state is preserved.'))}>Buy or recover tickets</button>
        {ticketInventoryError&&<><p>Ticket availability could not be checked. Your saved purchases are preserved.</p><button disabled={busy} onClick={()=>setTicketInventoryError(false)}>Retry ticket availability</button></>}
        {tickets && <><p>{tickets.available} available · {tickets.reserved} assigned to posts · {tickets.pack_size} tickets per pack · pack price {tickets.pack_price_wei} wei</p>
          <p>Assigned tickets include completed posts and unfinished submissions. Each stays tied to its original post and cannot pay for a different one.</p>
          {tickets.purchase_pending&&<p>A separate ticket purchase is still saved. Its new tickets appear here only after payment verification and pack recovery.</p>}
          {tickets.purchase_pending && <button disabled={busy} onClick={() => void action(async () => { await publicOperation('public-ticket-recover');setTickets(await publicOperation<Tickets>('public-ticket-status')); })}>Recover paid ticket pack</button>}
          <p>Purchases and cancellation use the separate ticket wallet screen.</p></>}
      </details>}
      {caps.publication_mode === 'direct' && <p>Direct-payment test: prepaid tickets are not configured. {!caps.source_enrollment_configured && 'Follower enrollment is not configured. '}Gas payment exposes your wallet address and can link posts. The payer is not proof of authorship. Read and author verification still run locally.</p>}
      <section aria-label="Public submission outbox"><h3>Saved public posts</h3>
        {monitorNotice&&<p role="status">{monitorNotice}</p>}
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
          <p>{row.last_known?.state==='finalized'?`Published as No.${row.last_known.post_number} · independently verified`
            :row.phase==='submitted'&&row.last_known?.state==='not-indexed'?'Submitted · waiting for finalized inclusion. Checked automatically while this view is open.'
            :`${row.phase} · ${row.last_known?row.last_known.state:'Not independently checked'}`}</p>
          {(row.phase==='submitted'||!!row.last_attempt)&&<progress max={1} value={row.last_known?.state==='finalized'?1:undefined} aria-label={`Publication progress: ${row.core.post.title??'Comment'}`}/>}
          {row.last_known?.state==='finalized'&&row.last_known.post_number&&<button disabled={busy} onClick={()=>void action(()=>reference(row.last_known!.post_number!),true)}>View published post No.{row.last_known.post_number}</button>}
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
          {!row.bundle_hash && !intents.find(i=>i.post.id===row.core.post.id)?.history && <details><summary>Link selected earlier authorship</summary><p>This publicly links only the selected original posts to this exact new post. Unbound old posts and different keys cannot qualify.</p>
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
