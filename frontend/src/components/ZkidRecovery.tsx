import { useEffect, useRef, useState } from 'react';
import { factOperation, type PendingPost } from '../zkidFacts';
import { zkidFactLabel } from '../zkidWire';
import { forum } from '../data/repository';
import { recoverZkidPost } from '../zkidPublishing';
import { isExtension } from '../platform/storage';

export function ZkidRecovery({ onSaved }: { onSaved: () => Promise<void> }) {
  const [pending, setPending] = useState<PendingPost>();const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);const [consent, setConsent] = useState(false);const [discard, setDiscard] = useState(false);
  const running = useRef<AbortController | undefined>(undefined);
  useEffect(() => () => running.current?.abort(), []);
  async function run(kind: 'status' | 'recover' | 'retry' | 'discard') {
    if (running.current || !isExtension) return;
    const controller = new AbortController();running.current = controller;setBusy(true);setMessage('');
    try {
      if (kind === 'status') {
        const value = await factOperation<PendingPost | { state: 'empty' }>('post-status', {}, controller.signal);
        setPending(value.state === 'empty' ? undefined : value);setMessage(value.state === 'empty' ? 'No saved public-post publication.' : 'The exact saved post is shown below.');
      } else if (kind === 'discard') {
        if (!discard) return;
        await factOperation('post-discard', { confirm_local_discard: true }, controller.signal);setPending(undefined);
        setMessage('Local post recovery removed. No remote proof or credential was revoked; your current draft was preserved.');
      } else {
        if (!pending || !consent) return;
        await recoverZkidPost(forum, pending, kind === 'retry', controller.signal);await onSaved();setPending(undefined);
        setMessage('The original post is saved once. Your current draft was preserved; check the discussion before posting it again.');
      }
    } catch { if (!controller.signal.aborted) setMessage('The operation did not finish. Keep saved recovery and your draft. Check progress, unlock the keyring, or retry the same saved proof explicitly.'); }
    finally { running.current = undefined;setBusy(false);setConsent(false);setDiscard(false); }
  }
  return <details className="credential-options zkid-recovery"><summary>Saved public-post publication</summary>
    <p>Closing or stopping does not cancel remote acceptance. Recover the exact saved post; drafts and legacy passports remain separate.</p>
    <button disabled={busy || !isExtension} onClick={() => { void run('status'); }}>Check saved post publication</button>
    {pending && <section aria-label="Saved post intent"><p>{pending.post.title ?? 'Saved comment'} · {pending.state}</p>
      <blockquote style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{pending.post.body}</blockquote>
      <p>{pending.facts.map(zkidFactLabel).join(' · ')}</p>
      <label><input type="checkbox" checked={consent} disabled={busy} onChange={e => setConsent(e.target.checked)} />I approve these saved facts and publishing this exact saved post without disclosing my identity.</label>
      <button disabled={busy || !consent} onClick={() => { void run('recover'); }}>Recover and publish saved post</button>
      {pending.state === 'proof-saved' && <button disabled={busy || !consent} onClick={() => { void run('retry'); }}>Explicitly retry same saved proof</button>}
      <label><input type="checkbox" checked={discard} disabled={busy} onChange={e => setDiscard(e.target.checked)} />Remove only this local post recovery; this does not revoke remote proofs or clear my draft.</label>
      <button disabled={busy || !discard} onClick={() => { void run('discard'); }}>Discard local post recovery</button>
    </section>}
    {busy && <button onClick={() => { running.current?.abort();setMessage('Stopped waiting. Remote acceptance may still finish; inspect saved progress before retrying.'); }}>Stop waiting for post operation</button>}
    {message && <p role="status">{message}</p>}
  </details>;
}
