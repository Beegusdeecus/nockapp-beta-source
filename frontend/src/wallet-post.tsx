import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { useEffect, useState } from 'react';
import { authoredOperation, type AuthoredIdentity, type Submission } from './authoredDiscussion';
import { connectBaseWallet, signExactPost, validatePostWalletRequest } from './authoredWallet';
import './tokens.css';
import './styles.css';

function WalletPost() {
  const [identity, setIdentity] = useState<AuthoredIdentity>();const [row, setRow] = useState<Submission>();
  const [busy, setBusy] = useState(false);const [error, setError] = useState('');const [done, setDone] = useState(false);
  useEffect(() => {
    let active = true;
    void (async () => {
      const params = new URLSearchParams(location.hash.slice(1));const postId = params.get('post');
      if (params.size !== 1 || !postId || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(postId)) throw new Error('Open this screen from a saved NockApp post.');
      const caps = await authoredOperation<{ identity: AuthoredIdentity }>('bundle-capabilities');
      let selected: Submission | undefined;let after = 0;
      for (let i = 0; i < 13; i++) {
        const box = await authoredOperation<{ entries: Submission[]; next_after: number; more: boolean }>('bundle-outbox', { after, limit: 8 });
        selected = box.entries.find(r => r.post.id === postId);if (selected || !box.more) break;
        if (box.next_after <= after) throw new Error('Saved post listing is incomplete.');after = box.next_after;
      }
      if (!selected || selected.selection.address !== true) throw new Error('This saved post has no wallet disclosure request.');
      if (active) { setIdentity(caps.identity);setRow(selected); }
    })().catch(e => { if (active) setError(e instanceof Error ? e.message : 'Saved post unavailable.'); });
    return () => { active = false; };
  }, []);
  async function sign() {
    if (!identity || !row || busy) return;setBusy(true);setError('');
    try {
      // Account/network prompts finish before creating the 60-second signature request.
      const account = await connectBaseWallet();
      const raw = await authoredOperation<unknown>('bundle-address-request', { post_id: row.post.id, address: account, approve_address_disclosure: true });
      const request = await validatePostWalletRequest(raw, identity, row.post, row.selection, row.submission_id, account);
      const signature = await signExactPost(request);
      const result = await authoredOperation<Submission>('bundle-address-result', { post_id: row.post.id, submission_id: row.submission_id, request_sha256: request.request_sha256, signature });
      setRow(result);setDone(true);
    } catch (e) { setError(e instanceof Error ? e.message : 'Signature was not completed. Recover the same saved post in NockApp.'); }
    finally { setBusy(false); }
  }
  return <main className="wallet-authorization"><h1>Authorize this post</h1>
    <p>Your selected Base address will be public on this post. Your private zkID key and Twitter account stay hidden.</p>
    {row && <section aria-label="Post to authorize"><h2>{row.post.title ?? 'Comment'}</h2><p className="wallet-post-body">{row.post.body}</p>
      <p>{row.selection.followers_threshold === null ? 'No follower badge selected.' : `Prove followers greater than ${row.selection.followers_threshold}. Exact count stays hidden.`}</p></section>}
    <p>This signature authorizes this exact post and its selected proofs. It does not transfer funds or approve token spending.</p>
    {error && <p role="alert">{error}</p>}
    {done ? <p role="status">Authorization saved. Return to NockApp to check publication against Base.</p>
      : <button disabled={!row || busy} onClick={() => void sign()}>{busy ? 'Waiting for MetaMask…' : 'Connect MetaMask and authorize'}</button>}
    <p>Shared or stolen keys confer signing authority. Author proofs establish authorization, not exclusive human composition.</p>
  </main>;
}
createRoot(document.getElementById('root')!).render(<StrictMode><WalletPost /></StrictMode>);
