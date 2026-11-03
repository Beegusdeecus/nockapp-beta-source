import { useEffect, useState } from 'react';
import { clearDraftIfUnchanged, readDraft, writeDraft, type Draft } from '../data/drafts';
import { bundleIntents, markBundleIntent } from '../data/bundleIntents';
import { ordinary, type Selection } from '../bundleDiscussion';

export function BundleComposer({ draftKey, reply, onSubmit }: { draftKey: string; reply: boolean;
  onSubmit: (draft: Draft, selection: Selection) => Promise<string> }) {
  const [draft, setDraft] = useState<Draft>({ title: '', body: '', credentials: [] });
  const [ready, setReady] = useState(false);const [busy, setBusy] = useState(false);const [error, setError] = useState('');
  const [mode, setMode] = useState('ordinary');const [account, setAccount] = useState(false);
  const [range, setRange] = useState(false);const [exactCount, setExact] = useState(false);const [threshold, setThreshold] = useState('10000');
  const [fixed, setFixed] = useState(false);
  useEffect(() => {
    let active = true;
    void readDraft(draftKey).then(async d => {
      if (!d.title && !d.body) for (const r of await bundleIntents()) if (r.draft_key === draftKey && r.acknowledged && !r.released) await markBundleIntent(r.post.id, true);
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
        let selection = ordinary;
        const facts = mode === 'count' ? [...(account ? ['account-controlled'] : []), ...(range ? ['followers-more-than'] : []), ...(exactCount ? ['follower-count'] : [])].sort()
          : mode === 'fixed' ? [...(account ? ['account-controlled'] : []), ...(fixed ? ['followers-at-least-10000'] : [])].sort() : [];
        if (facts.length) {
          if (mode === 'count' && range && (!/^(0|[1-9][0-9]*)$/.test(threshold) || !Number.isSafeInteger(Number(threshold)) || Number(threshold) >= Number.MAX_SAFE_INTEGER))
            throw new Error('Enter a whole-number threshold from 0 to 9007199254740990. The proof is strictly greater than this value.');
          selection = { credential_kind: mode === 'count' ? 2 : 1, facts, threshold: mode === 'count' && range ? Number(threshold) : null };
        }
        const id = await onSubmit(draft, selection);
        if (await clearDraftIfUnchanged(draftKey, draft)) {
          await markBundleIntent(id, true);setDraft({ title: '', body: '', credentials: [] });
          setMode('ordinary');setAccount(false);setRange(false);setExact(false);setFixed(false);
        }
      } catch (e) { setError(e instanceof Error ? e.message : 'Publication unavailable. Your draft is preserved.'); }
      finally { setBusy(false); }
    })();
  }}>
    {!reply && <label>Thread title<input required maxLength={120} value={draft.title} disabled={!ready || busy} onChange={e => update({ ...draft, title: e.target.value })} /></label>}
    <label>{reply ? 'Your comment' : 'Opening comment'}<textarea aria-label={reply ? 'Your comment' : 'Opening comment'} required maxLength={6000} value={draft.body} disabled={!ready || busy} onChange={e => update({ ...draft, body: e.target.value })} /></label>
    <p>Posting as Anonymous · Draft saved on this device</p>
    <details><summary>Optional credential facts</summary>
      <label>Credential version<select value={mode} disabled={busy} onChange={e => { setMode(e.target.value);setAccount(false);setRange(false);setExact(false);setFixed(false); }}>
        <option value="ordinary">Ordinary — no credential</option><option value="count">Authenticated count credential (v2)</option><option value="fixed">Existing fixed-fact credential (v1)</option>
      </select></label>
      {mode !== 'ordinary' && <label><input type="checkbox" checked={account} disabled={busy} onChange={e => setAccount(e.target.checked)} />X account control</label>}
      {mode === 'count' && <>
        <label><input type="checkbox" checked={range} disabled={busy} onChange={e => setRange(e.target.checked)} />Follower count greater than a threshold</label>
        {range && <label>Follower threshold<input inputMode="numeric" value={threshold} disabled={busy} onChange={e => setThreshold(e.target.value)} /></label>}
        <label><input type="checkbox" checked={exactCount} disabled={busy} onChange={e => setExact(e.target.checked)} />Publish my exact follower count</label>
        <p>The count stays hidden unless exact disclosure is selected. Equality does not satisfy “greater than”.</p>
      </>}
      {mode === 'fixed' && <><label><input type="checkbox" checked={fixed} disabled={busy} onChange={e => setFixed(e.target.checked)} />At least 10,000 followers</label><p>This older credential cannot prove an arbitrary threshold.</p></>}
    </details>
    <p>Text and selected proof evidence are publicly uploaded before Base acceptance. Failed submissions may already have public storage copies.</p>
    {error && <p role="alert">{error}</p>}
    <button className="primary" disabled={!ready || busy}>{busy ? 'Saving submission…' : reply ? 'Publish anonymous comment' : 'Publish anonymous thread'}</button>
  </form>;
}
