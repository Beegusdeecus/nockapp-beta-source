import { useEffect, useState } from 'react';
import { clearDraftIfUnchanged, readDraft, writeDraft, type Draft } from '../data/drafts';
import { authoredIntents, markAuthoredIntent } from '../data/authoredIntents';
import type { AddressSelection } from '../authoredWallet';

export function AuthoredComposer({ draftKey, reply, onSubmit }: { draftKey: string; reply: boolean;
  onSubmit: (draft: Draft, selection: AddressSelection) => Promise<string> }) {
  const [draft, setDraft] = useState<Draft>({ title: '', body: '', credentials: [] });
  const [ready, setReady] = useState(false);const [busy, setBusy] = useState(false);const [error, setError] = useState('');
  const [address, setAddress] = useState(false);const [followers, setFollowers] = useState(false);const [threshold, setThreshold] = useState('10000');
  useEffect(() => {
    let active = true;
    void readDraft(draftKey).then(async d => {
      if (!d.title && !d.body) for (const r of await authoredIntents()) if (r.draft_key === draftKey && r.acknowledged && !r.released) await markAuthoredIntent(r.post.id, true);
      if (active) { setDraft(d);setReady(true); }
    }).catch(() => { if (active) setError('Could not read the draft. Saved data is preserved.'); });
    return () => { active = false; };
  }, [draftKey]);
  function update(d: Draft) { setDraft(d);void writeDraft(draftKey, d).catch(() => setError('Draft save failed. Keep this panel open.')); }
  return <form className="composer" aria-label={reply ? 'Write a shared comment' : 'Create shared thread'} onSubmit={e => {
    e.preventDefault();if (!ready || busy) return;
    void (async () => {
      setBusy(true);setError('');
      try {
        if (followers && (!/^(0|[1-9][0-9]*)$/.test(threshold) || !Number.isSafeInteger(Number(threshold)) || Number(threshold) >= Number.MAX_SAFE_INTEGER))
          throw new Error('Enter a whole-number threshold from 0 to 9007199254740990. Equality does not satisfy greater than.');
        const id = await onSubmit(draft, { address, followers_threshold: followers ? Number(threshold) : null });
        if (await clearDraftIfUnchanged(draftKey, draft)) {
          await markAuthoredIntent(id, true);setDraft({ title: '', body: '', credentials: [] });setAddress(false);setFollowers(false);
        }
      } catch (e) { setError(e instanceof Error ? e.message : 'Publication unavailable. Your draft is preserved.'); }
      finally { setBusy(false); }
    })();
  }}>
    {!reply && <label>Thread title<input required maxLength={120} value={draft.title} disabled={!ready || busy} onChange={e => update({ ...draft, title: e.target.value })} /></label>}
    <label>{reply ? 'Your comment' : 'Opening comment'}<textarea aria-label={reply ? 'Your comment' : 'Opening comment'} required maxLength={6000} value={draft.body} disabled={!ready || busy} onChange={e => update({ ...draft, body: e.target.value })} /></label>
    <p>Posting as Anonymous · Private authorship on every post · Draft saved on this device</p>
    <details><summary>Optional public disclosures</summary>
      <label><input type="checkbox" checked={address} disabled={busy} onChange={e => setAddress(e.target.checked)} />Show my Base address, authorized with MetaMask</label>
      {address && <p>Your selected address will be public. Reusing it intentionally links those posts. A separate screen asks MetaMask to authorize this exact post.</p>}
      <label><input type="checkbox" checked={followers} disabled={busy} onChange={e => setFollowers(e.target.checked)} />Prove followers greater than a threshold</label>
      {followers && <><label>Follower threshold<input inputMode="numeric" value={threshold} disabled={busy} onChange={e => setThreshold(e.target.value)} /></label>
        <p>Your X account and exact count stay hidden. Equality does not satisfy greater than. The badge describes a credential observation, not a continuously current count.</p></>}
    </details>
    <p>Text and selected public proofs may reach replicated storage before Base acceptance, including on failed submissions.</p>
    {error && <p role="alert">{error}</p>}
    <button className="primary" disabled={!ready || busy}>{busy ? 'Saving submission…' : reply ? 'Publish anonymous comment' : 'Publish anonymous thread'}</button>
  </form>;
}
