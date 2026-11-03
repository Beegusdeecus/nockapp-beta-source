import { useEffect, useRef, useState, type FormEvent } from 'react';
import { readDraft, writeDraft, clearDraftIfUnchanged, type Draft } from '../data/drafts';
import { Icon } from './Icon';
import { credentialLabel, DEMO_CREDENTIALS } from '../credentials';
import { PASSPORT_FACTS, factLabel } from '../postScope';
import { passportOperation, type PassportSummary } from '../xPassport';
import { isExtension } from '../platform/storage';
import { factOperation, type FactAvailable } from '../zkidFacts';
import { ZKID_FACTS, zkidFactLabel } from '../zkidWire';

export function Composer({ draftKey, mode, legacyTargets, onSubmit, shared = false }: {
  draftKey: string; mode: 'thread' | 'reply'; legacyTargets?: Record<string, string>; shared?: boolean; onSubmit: (draft: Draft, signal: AbortSignal) => Promise<void>;
}) {
  const [draft, setDraft] = useState<Draft>({ title: '', body: '', credentials: [] });
  const [ready, setReady] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [draftStatus, setDraftStatus] = useState('Draft saved on this device');
  const [passport, setPassport] = useState<PassportSummary>();
  const [checking, setChecking] = useState(false);
  const [passportError, setPassportError] = useState('');
  const [zkid, setZkid] = useState<FactAvailable>();
  const [zkidError, setZkidError] = useState('');
  const statusAbort = useRef<AbortController | undefined>(undefined);
  const signingAbort = useRef<AbortController | undefined>(undefined);
  const textarea = useRef<HTMLTextAreaElement>(null);
  const generation = useRef(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    let active = true;
    setReady(false); setError('');
    readDraft(draftKey, legacyTargets).then((d) => { if (active) { setDraft(d); setReady(true); } }).catch(() => { if (active) setError('Could not load your draft. Try reopening the panel.'); });
    return () => { active = false; mounted.current = false; statusAbort.current?.abort(); signingAbort.current?.abort(); };
  }, [draftKey]);
  function update(next: Draft) {
    setDraft(next); setError(''); setDraftStatus('Saving draft…');
    const version = ++generation.current;
    void writeDraft(draftKey, next).then(() => { if (mounted.current && generation.current === version) setDraftStatus('Draft saved on this device'); }).catch(() => {
      if (mounted.current) { setError('Draft could not be saved. Keep this panel open and try again.'); setDraftStatus('Draft not saved'); }
    });
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!ready || saving || checking || signingAbort.current) return;
    const controller = new AbortController(); signingAbort.current = controller;
    setSaving(true); setError('');
    try {
      await onSubmit(draft, controller.signal);
      // Discussion save has succeeded; draft cleanup must not turn a successful
      // post into a retry that could publish the same message twice.
      if (!shared && mounted.current) { setDraft({ title: '', body: '', credentials: [] }); setDraftStatus('Draft saved on this device'); }
      try {
        if (shared) {
          const cleared = await clearDraftIfUnchanged(draftKey, draft);
          if (cleared && mounted.current) { setDraft({ title: '', body: '', credentials: [] });setDraftStatus('Draft saved on this device'); }
        } else await writeDraft(draftKey, { title: '', body: '', credentials: [] });
      }
      catch { if (mounted.current) setError('Your post was saved, but its old draft could not be cleared.'); }
    } catch (e) { if (mounted.current) setError(e instanceof Error ? e.message : 'Could not save. Your draft is still here.'); }
    finally { signingAbort.current = undefined; if (mounted.current) setSaving(false); }
  }
  async function checkPassport() {
    if (checking || saving || !isExtension || statusAbort.current) return;
    const controller = new AbortController(); statusAbort.current = controller;
    setChecking(true); setPassport(undefined); setPassportError('');
    try {
      const result = await passportOperation('passport_status', { signal: controller.signal });
      if (result.status !== 'checked' && result.status !== 'synthetic') throw new Error('Passport unavailable');
      if (mounted.current && !controller.signal.aborted) setPassport(result);
    } catch { if (mounted.current && !controller.signal.aborted) setPassportError('No usable passport is available. Use Connect X, or leave these facts off.'); }
    finally { statusAbort.current = undefined; if (mounted.current) setChecking(false); }
  }
  async function checkZkid() {
    if (checking || saving || !isExtension || statusAbort.current) return;
    const controller = new AbortController();statusAbort.current = controller;setChecking(true);setZkid(undefined);setZkidError('');
    try {
      const caps = await factOperation<{ configured: boolean }>('post-capabilities', {}, controller.signal);
      if (!caps.configured) throw new Error('not configured');
      const value = await factOperation<FactAvailable>('post-available', {}, controller.signal);
      if (mounted.current && !controller.signal.aborted) setZkid(value);
    } catch { if (mounted.current && !controller.signal.aborted) setZkidError('No public-post credential is available. Check the separate helper, verifier and unlocked keyring, or leave these facts off.'); }
    finally { statusAbort.current = undefined;if (mounted.current) setChecking(false); }
  }
  return <form className={`composer ${mode}`} onSubmit={submit} aria-label={mode === 'thread' ? 'Create thread' : 'Write a comment'}>
    {mode === 'reply' && <div className="composer-heading">Add a comment to this thread</div>}
    {mode === 'thread' && <label>Thread title<input autoFocus required maxLength={120} value={draft.title} disabled={!ready || saving} onChange={(e) => update({ ...draft, title: e.target.value })} placeholder="Give the conversation a starting point" /></label>}
    <label className={mode === 'reply' ? 'reply-label' : ''}>{mode === 'thread' ? 'Opening comment' : <span className="sr-only">Your comment</span>}<textarea ref={textarea} aria-label={mode === 'thread' ? 'Opening comment' : 'Your comment'} required maxLength={6000} rows={mode === 'thread' ? 7 : 4} value={draft.body} disabled={!ready || saving} onChange={(e) => update({ ...draft, body: e.target.value })} placeholder={mode === 'thread' ? 'What’s on your mind? Add links for more context.' : 'Write a flat comment. Use >>123456 to reference a post, or paste an X link.'} /></label>
    <div className="composer-meta"><span>Posting as <strong>Anonymous</strong></span><span>{draft.body.length.toLocaleString()}/6,000</span></div>
    {shared && <details className="credential-options"><summary>Optional credential facts</summary><p>Off by default for each post. Your computer generates the proof. Selected facts and their proof become public. These experimental fixed facts require a compatible saved credential.</p><fieldset disabled={!ready || saving}><legend className="sr-only">Shared post facts</legend>{ZKID_FACTS.map(fact => <label key={fact}><input type="checkbox" checked={draft.zkidFacts?.includes(fact) ?? false} onChange={e => update({ ...draft, zkidFacts: e.target.checked ? [...(draft.zkidFacts ?? []), fact] : draft.zkidFacts?.filter(v => v !== fact) })} />{zkidFactLabel(fact)}</label>)}</fieldset></details>}
    {!shared && <><details className="credential-options"><summary>Optional demo credentials{draft.credentials.length ? ` (${draft.credentials.length} selected)` : ''}</summary><p>Choose what to show on this post. These badges are fictional demo data.</p><fieldset disabled={!ready || saving}><legend className="sr-only">Credentials to display</legend>{DEMO_CREDENTIALS.map((claim) => <label key={claim.kind}><input type="checkbox" checked={draft.credentials.some((c) => c.kind === claim.kind)} onChange={(event) => update({ ...draft, credentials: event.target.checked ? [...draft.credentials, claim] : draft.credentials.filter((c) => c.kind !== claim.kind) })} />Demo · {credentialLabel(claim)}</label>)}</fieldset></details>
    <details className="credential-options zkid-facts"><summary>Optional public-post facts{draft.zkidFacts?.length ? ` (${draft.zkidFacts.length} selected)` : ''}</summary>
      <p>Use the credential from Connect X for this post only. Publication needs a fresh anonymous proof bound to this text and context. No account or app identity is displayed.</p>
      <button type="button" className="secondary" disabled={!ready || saving || checking || !isExtension} onClick={() => { void checkZkid(); }}>{checking ? 'Checking facts…' : 'Check public-post credential facts'}</button>
      {zkid && <p>Test credential only. Availability is not verification; the independent verifier checks the actual proof when posting.</p>}
      {zkidError && <p role="status">{zkidError}</p>}
      <fieldset disabled={!ready || saving || checking}><legend className="sr-only">Public-post facts for this post</legend>
        {ZKID_FACTS.map(fact => <label key={fact}><input type="checkbox" checked={draft.zkidFacts?.includes(fact) ?? false}
          disabled={!draft.zkidFacts?.includes(fact) && (!zkid?.facts.includes(fact) || !!draft.passportFacts?.length)}
          onChange={e => update({ ...draft, zkidFacts: e.target.checked ? [...(draft.zkidFacts ?? []), fact] : draft.zkidFacts?.filter(v => v !== fact) })} />{zkidFactLabel(fact)}</label>)}
      </fieldset><p>All badges remain Test. Source observations expire; a changed revocation registry makes old proofs unavailable. Keep interrupted posts in Saved public-post publication below.</p>
    </details>
    <details className="credential-options passport-facts"><summary>Optional passport facts{draft.passportFacts?.length ? ` (${draft.passportFacts.length} selected)` : ''}</summary>
      <p>Earlier passport helper. Use one credential flow per post; existing legacy references stay supported.</p>
      <p>Choose facts only for this post. Posting requires a fresh holder signature bound to its text and context. Your exact account ID and follower count are not shown. Reuse may still link activity.</p>
      <button type="button" className="secondary" disabled={!ready || saving || checking || !isExtension} onClick={() => { void checkPassport(); }}>{checking ? 'Checking passport…' : 'Check available passport facts'}</button>
      {passport?.status === 'synthetic' && <p>Laboratory passport: selected facts will be labelled Test, never Verified.</p>}
      {!isExtension && <p>The installed Ubuntu extension and proving helper are required.</p>}
      {passportError && <p role="status">{passportError}</p>}
      <fieldset disabled={!ready || saving || checking}><legend className="sr-only">Passport facts for this post</legend>
        {PASSPORT_FACTS.map(fact => <label key={fact}><input type="checkbox" checked={draft.passportFacts?.includes(fact) ?? false}
          disabled={!draft.passportFacts?.includes(fact) && (!passport?.facts.includes(fact) || !!draft.zkidFacts?.length)} onChange={event => update({ ...draft,
            passportFacts: event.target.checked ? [...(draft.passportFacts ?? []), fact] : draft.passportFacts?.filter(v => v !== fact) })} />{factLabel(fact)}</label>)}
      </fieldset>
      <p>Follower status is a dated observation. Every displayed passport badge is checked by the local helper against retained evidence; a saved choice is not verification.</p>
    </details></>}
    {draft.body.length > 6000 && <p className="error-inline" role="status">Your recovered drafts are combined here. Split or shorten them to 6,000 characters before posting; the originals remain saved.</p>}
    {error && <p className="error-inline" role="alert">{error}</p>}
    {shared && <p>Publishing sends this post to Base Sepolia. Posts and selected proofs are public and may be retained permanently.</p>}
    <button className="primary full" type="submit" disabled={!ready || saving || checking || !draft.body.trim() || draft.body.length > 6000 || (mode === 'thread' && !draft.title.trim())}>{saving ? draft.passportFacts?.length ? 'Checking holder signature…' : 'Saving…' : mode === 'thread' ? 'Publish anonymous thread' : 'Post anonymous comment'}<Icon name="arrow" /></button>
    <p className="draft-status" role="status">{ready ? draftStatus : 'Loading your draft…'}</p>
  </form>;
}
