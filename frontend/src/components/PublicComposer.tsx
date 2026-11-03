import { useEffect, useState } from 'react';
import { clearDraftIfUnchanged, readDraft, writeDraft, type Draft } from '../data/drafts';
import { acknowledgePublicIntent, publicIntents } from '../data/publicIntents';
import type { PublicSelection } from '../publicDiscussion';

export function PublicComposer({ draftKey, reply, direct = false, onSubmit }: { draftKey: string; reply: boolean; direct?: boolean;
  onSubmit: (draft: Draft, selection: PublicSelection) => Promise<string> }) {
  const [draft, setDraft] = useState<Draft>({ title: '', body: '', credentials: [] });
  const [ready, setReady] = useState(false);const [busy, setBusy] = useState(false);const [error, setError] = useState('');
  const [address, setAddress] = useState(false);const [followers, setFollowers] = useState(false);const [threshold, setThreshold] = useState('10000');
  useEffect(() => {
    let active = true;
    void readDraft(draftKey).then(async d => {
      if (!d.title && !d.body) for (const r of await publicIntents()) if (r.draft_key === draftKey && r.acknowledged && !r.released) await acknowledgePublicIntent(r.post.id, true);
      if (active) { setDraft(d);setReady(true); }
    }).catch(() => { if (active) setError('Could not read the public draft. Saved data is preserved.'); });
    return () => { active = false; };
  }, [draftKey]);
  function update(value: Draft) { setDraft(value);void writeDraft(draftKey, value).catch(() => setError('Draft save failed. Keep this panel open.')); }
  return <form className="composer" aria-label={reply ? 'Write a public comment' : 'Create public thread'} onSubmit={e => {
    e.preventDefault();if (!ready || busy) return;
    void (async () => {
      setBusy(true);setError('');
      try {
        if (followers && (!/^(0|[1-9][0-9]*)$/.test(threshold) || !Number.isSafeInteger(Number(threshold)) || Number(threshold) >= Number.MAX_SAFE_INTEGER))
          throw new Error('Enter a whole-number threshold from 0 to 9007199254740990. Equality does not satisfy greater than.');
        const id = await onSubmit(draft, { address, followers_threshold: followers ? Number(threshold) : null });
        if (await clearDraftIfUnchanged(draftKey, draft)) {
          await acknowledgePublicIntent(id, true);setDraft({ title: '', body: '', credentials: [] });setAddress(false);setFollowers(false);
        }
      } catch (e) { setError(e instanceof Error ? e.message : 'Publication unavailable. Your draft is preserved.'); }
      finally { setBusy(false); }
    })();
  }}>
    {!reply && <label>Thread title<input required maxLength={120} disabled={!ready || busy} value={draft.title} onChange={e => update({ ...draft, title: e.target.value })} /></label>}
    <label>{reply ? 'Your comment' : 'Opening comment'}<textarea aria-label={reply ? 'Your comment' : 'Opening comment'} required maxLength={6000} disabled={!ready || busy} value={draft.body} onChange={e => update({ ...draft, body: e.target.value })} /></label>
    <p>Anonymous · Private authorship on every post · Draft saved on this device</p>
    <details><summary>Optional public disclosures</summary>
      <label><input type="checkbox" checked={address} disabled={busy} onChange={e => setAddress(e.target.checked)} />Show my Ethereum address, authorized with MetaMask</label>
      {address && <p>Reusing an address links those posts. The exact saved post needs separate wallet authorization before publication.</p>}
      <label><input type="checkbox" checked={followers} disabled={busy} onChange={e => setFollowers(e.target.checked)} />Prove followers greater than a threshold</label>
      {followers && <><label>Follower threshold<input inputMode="numeric" value={threshold} disabled={busy} onChange={e => setThreshold(e.target.value)} /></label>
        <p>Your account, exact count and credential dates stay hidden. A badge describes eligibility when indexed, not today's follower count.</p></>}
    </details>
    <p>{direct ? 'Save first, then export and upload the public bundle before paying gas. Direct payment exposes your wallet address and can link these posts.' : 'Publication spends a prepaid ticket.'} Text and public proofs may become downloadable before indexing, including if submission fails.</p>
    {error && <p role="alert">{error}</p>}
    <button className="primary" disabled={!ready || busy}>{busy ? 'Saving public post…' : direct ? 'Save exact public post' : reply ? 'Publish anonymous public comment' : 'Publish anonymous public thread'}</button>
  </form>;
}
