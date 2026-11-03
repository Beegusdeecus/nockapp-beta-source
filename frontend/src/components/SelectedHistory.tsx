import { useEffect, useRef, useState } from 'react';
import { authoredOperation, type AuthoredIdentity } from '../authoredDiscussion';
import { canonicalAscii } from '../authoredWallet';
import { historyHash, validHistoryNumbers, validHistoryRequest, validHistoryResponse, type HistoryRequest, type HistoryRequests, type HistoryResponse, type HistoryReceipt } from '../authoredHistory';

export function SelectedHistory({ identity }: { identity: AuthoredIdentity }) {
  const [numbers, setNumbers] = useState('');const [requests, setRequests] = useState<HistoryRequests['entries']>([]);
  const [incoming, setIncoming] = useState<HistoryRequest>();const [link, setLink] = useState(false);const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');const [notice, setNotice] = useState('');const [responseUrl, setResponseUrl] = useState<string>();
  const [result, setResult] = useState<HistoryReceipt>();const active = useRef(true);const running = useRef(false);const urls = useRef<string[]>([]);
  const scope = { protocol: 4, chain_id: identity.chain_id, application: identity.application, contract: identity.contract, registry: identity.registry, issuer_definition: identity.definition_hash };
  function sameScope(request: HistoryRequest) { if (canonicalAscii(request.scope) !== canonicalAscii(scope)) throw new Error('This request belongs to a different application.'); }
  async function sync() {
    const entries: HistoryRequests['entries'] = [];let after = 0;
    for (let i = 0; i < 13; i++) {
      const page = await authoredOperation<HistoryRequests>('bundle-history-requests', { after, limit: 8 });
      for (const r of page.entries) { sameScope(r.request);if (await historyHash(r.request) !== r.request_sha256) throw new Error('Saved request does not match its hash.'); }
      entries.push(...page.entries);if (!page.more) break;if (page.next_after <= after) throw new Error('Saved request listing is incomplete.');after = page.next_after;
    }
    if (active.current) setRequests(entries);
  }
  useEffect(() => { active.current = true;void sync().catch(() => { if (active.current) setError('Saved verification requests are unavailable. Data is preserved.'); });
    return () => { active.current = false;urls.current.forEach(url => URL.revokeObjectURL(url)); }; }, []);
  function url(value: unknown) { const u = URL.createObjectURL(new Blob([JSON.stringify(value)], { type: 'application/json' }));urls.current.push(u);return u; }
  async function run(work: () => Promise<void>) {
    if (running.current) return;running.current = true;setBusy(true);setError('');setNotice('');setResult(undefined);
    try { await work(); } catch (e) { if (active.current) setError(e instanceof Error ? e.message : 'History proof unavailable. Saved data is preserved.'); }
    finally { running.current = false;if (active.current) setBusy(false); }
  }
  async function create() {
    if (!/^[1-9][0-9]*(\s*,\s*[1-9][0-9]*)*$/.test(numbers.trim())) throw new Error('Enter distinct post numbers separated by commas.');
    const selected = numbers.split(',').map(v => Number(v.trim()));if (!validHistoryNumbers(selected)) throw new Error('Choose 1 to 16 distinct valid post numbers.');
    await authoredOperation<HistoryRequest>('bundle-history-request', { numbers: selected, approve_request: true });await sync();
    if (active.current) setNotice('Request saved. Send its file to the author, then check the response within 60 seconds.');
  }
  async function importRequest(file: File) {
    setLink(false);setIncoming(undefined);setResponseUrl(undefined);
    if (file.size > 16384) throw new Error('Request exceeds 16 KiB.');let value: unknown;
    try { value = JSON.parse(await file.text()); } catch { throw new Error('Unsupported request file. No private signing was attempted.'); }
    if (!validHistoryRequest(value)) throw new Error('Unsupported request. No private signing was attempted.');sameScope(value);
    if (active.current) setIncoming(value);
  }
  async function prove() {
    if (!incoming || !link) return;
    const response = await authoredOperation<HistoryResponse>('bundle-history-prove', { request: incoming, approve_linking: true });
    if (response.request_sha256 !== await historyHash(incoming)) throw new Error('The saved response does not match this request.');
    if (active.current) { setResponseUrl(url(response));setLink(false);setNotice('Response saved. It links only the selected posts. The requester must independently verify it.'); }
  }
  async function verify(file: File, request: HistoryRequests['entries'][number]) {
    if (file.size > 32768) throw new Error('Response exceeds 32 KiB.');let value: unknown;
    try { value = JSON.parse(await file.text()); } catch { throw new Error('Unsupported response file. No proof was checked.'); }
    if (!validHistoryResponse(value) || value.request_sha256 !== request.request_sha256 || canonicalAscii(value.request) !== canonicalAscii(request.request)) throw new Error('Response does not match this saved request.');
    const checked = await authoredOperation<HistoryReceipt>('bundle-history-verify', { response: value, request_sha256: request.request_sha256 });
    if (active.current) setResult(checked);
  }
  return <section aria-label="Selected past authorship"><h2>Prove selected past posts</h2>
    <p>The requester chooses exact post numbers and sends a fresh request. The author approves linking those posts, returns a response, and the requester checks it against Base. A request expires after 60 seconds; have both sides ready before creating one.</p>
    <p>This establishes authorization by the same secret's controller. It does not establish exclusive human composition. The files contain public proofs, not your private key or credential. Sharing a response deliberately links those selected posts; recipients can retain it.</p>
    <fieldset disabled={busy}><legend>Request a proof</legend><label>Post numbers to check<input value={numbers} onChange={e => setNumbers(e.target.value)} placeholder="For example: 12, 19" /></label>
      <button onClick={() => void run(create)}>Create 60-second verification request</button><button onClick={() => void run(sync)}>Recover saved verification requests</button>
      {requests.map(r => <article key={r.request_sha256}><p>Requested: {r.request.numbers.map(n => `No.${n}`).join(', ')} · Expires {new Date(r.request.challenge.expires_at * 1000).toLocaleTimeString()}</p>
        <button onClick={() => { const a = document.createElement('a');a.href = url(r.request);a.download = 'nockapp-authorship-request.json';a.click(); }}>Download verification request</button>
        <label>Check response for {r.request.numbers.map(n => `No.${n}`).join(', ')}<input type="file" accept="application/json,.json" onChange={e => {
          const file = e.target.files?.[0];e.target.value = '';if (file) void run(() => verify(file, r));
        }} /></label>{r.challenge_checked_at !== null && <p>Earlier response checked {new Date(r.challenge_checked_at * 1000).toLocaleString()}. Rechecking does not establish fresh possession.</p>}
      </article>)}
    </fieldset>
    <fieldset disabled={busy}><legend>Answer a request</legend><label>Load verification request<input type="file" accept="application/json,.json" onChange={e => {
      const file = e.target.files?.[0];e.target.value = '';if (file) void run(() => importRequest(file));
    }} /></label>
      {incoming && <><p>Selected posts to link: {incoming.numbers.map(n => `No.${n}`).join(', ')}.</p>
        <label><input type="checkbox" checked={link} onChange={e => setLink(e.target.checked)} />Allow this proof to link only these selected posts</label>
        <button disabled={!link} onClick={() => void run(prove)}>Approve linking or recover saved response</button></>}
      {responseUrl && <a href={responseUrl} download="nockapp-authorship-response.json">Download authorship response</a>}
    </fieldset>
    {result && <p role="status">Test proof · authorization checked for {result.post_numbers.map(n => `No.${n}`).join(', ')}. {result.current_possession_checked ? 'Fresh challenge response checked' : 'Earlier response rechecked; no fresh possession asserted'} at {new Date(result.challenge_checked_at * 1000).toLocaleString()}. No wallet endorsement is claimed.</p>}
    {notice && <p role="status">{notice}</p>}{error && <p role="alert">{error}</p>}
  </section>;
}
