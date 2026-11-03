import { useEffect, useState } from 'react';
import { credentialVerifier, type CredentialResult } from '../credentials';
import type { Author, Comment, CredentialClaim, PostFactReference, Thread, ZkidReference } from '../model';
import { wirePayload, wirePost, zkidFactLabel } from '../zkidWire';
import { inspectZkidPost } from '../zkidPublishing';
import type { FactAccepted } from '../zkidFacts';
import { factLabel, postScopePayload } from '../postScope';
import { inspectPost } from '../xPost';
import type { PostFactResult } from '../xPassport';
import { relativeTime } from '../urls';

function Badge({ claim }: { claim: CredentialClaim }) {
  const [result, setResult] = useState<CredentialResult>();
  useEffect(() => {
    let active = true;
    credentialVerifier.verify(claim).then((r) => { if (active) setResult(r); }).catch(() => { if (active) setResult({ status: 'unavailable', label: 'Credential unavailable' }); });
    return () => { active = false; };
  }, [claim]);
  if (!result || !['demo', 'verified'].includes(result.status)) return null;
  return <span className="badge" title={result.status === 'demo' ? 'Fictional demo credential. No cryptographic verification has occurred.' : 'Credential accepted by the configured verifier.'}>{result.status === 'demo' ? 'Demo · ' : ''}{result.label}</span>;
}
function PostBadge({ post, reference }: { post?: Thread | Comment; reference: PostFactReference }) {
  const [checked, setChecked] = useState<{ value: PostFactResult; payload: string }>();
  const [unavailable, setUnavailable] = useState(false);
  const [attempt, setAttempt] = useState(0);
  let payload = '';
  try { if (post) payload = postScopePayload(post); } catch { /* Invalid/imported identity cannot be verified. */ }
  // Never reuse the previous render's accepted result for edited post content.
  const result = checked?.payload === payload ? checked.value : undefined;
  useEffect(() => {
    const refresh = () => { setChecked(undefined); setAttempt(v => v + 1); };
    window.addEventListener('focus', refresh);
    return () => window.removeEventListener('focus', refresh);
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    setChecked(undefined); setUnavailable(false);
    if (!payload || !post) { setUnavailable(true); return; }
    void inspectPost(post, reference, controller.signal).then(value => {
      if (controller.signal.aborted) return;
      setChecked({ value, payload });
      timer = setTimeout(() => { setChecked(undefined); setUnavailable(true); }, Math.max(0, value.expiresAt * 1000 - Date.now()));
    }).catch(() => { if (!controller.signal.aborted) setUnavailable(true); });
    return () => { controller.abort(); clearTimeout(timer); };
  }, [payload, reference.challenge, reference.fact, attempt]);
  const synthetic = result?.status === 'synthetic-post-checked';
  const status = result ? synthetic ? 'synthetic' : 'verified' : unavailable ? 'unavailable' : 'pending';
  return <span className="badge passport-badge" data-verification={status}
    title={result ? `${synthetic ? 'Synthetic test; no real account was verified. ' : ''}Source observed ${new Date(result.observedAt * 1000).toLocaleString()}; expires ${new Date(result.expiresAt * 1000).toLocaleString()}. Retained proof and scoped holder signature checked by the installed helper. This is not fresh source data or a new holder signature.` : 'No verified passport fact is available while checking, expired, or unavailable.'}>
    {result ? `${synthetic ? 'Test' : 'Verified'} · ${factLabel(reference.fact)}` : unavailable ? 'Passport fact unavailable' : 'Checking passport fact…'}
  </span>;
}
function ZkidBadges({ post, reference }: { post?: Thread | Comment; reference: ZkidReference }) {
  let payload = '';
  try { if (post) payload = wirePayload(wirePost(post)) + JSON.stringify(reference); } catch { /* Imported/invalid post cannot inherit acceptance. */ }
  const [checked, setChecked] = useState<{ payload: string; value: FactAccepted }>();
  const [unavailable, setUnavailable] = useState(false);const [attempt, setAttempt] = useState(0);
  useEffect(() => { const refresh = () => { setChecked(undefined);setAttempt(v => v + 1); };
    window.addEventListener('focus', refresh);return () => window.removeEventListener('focus', refresh); }, []);
  useEffect(() => {
    const controller = new AbortController();let timer: ReturnType<typeof setTimeout>;
    setChecked(undefined);setUnavailable(false);
    if (!payload || !post) { setUnavailable(true);return; }
    void inspectZkidPost(post, reference, controller.signal).then(value => {
      if (controller.signal.aborted) return;
      setChecked({ payload, value });timer = setTimeout(() => { setChecked(undefined);setUnavailable(true); }, Math.max(0, value.expires_at * 1000 - Date.now()));
    }).catch(() => { if (!controller.signal.aborted) setUnavailable(true); });
    return () => { controller.abort();clearTimeout(timer); };
  }, [payload, attempt]);
  const value = checked?.payload === payload && checked.value.expires_at * 1000 > Date.now() ? checked.value : undefined;
  return <>{reference.facts.map(fact => <span key={fact} className="badge zkid-badge" data-verification={value ? 'synthetic' : unavailable ? 'unavailable' : 'pending'}
    title={value ? `Test only. Independent public-post proof checked ${new Date(value.checked_at * 1000).toLocaleString()}. Source observation ${new Date(value.observed_at * 1000).toLocaleString()}; expires ${new Date(value.expires_at * 1000).toLocaleString()}. Archival evidence, not fresh possession or source data. Registry changes can invalidate it.`
      : 'No accepted public-post fact is available while checking, expired or after a registry change.'}>
    {value ? `Test · ${zkidFactLabel(fact)}` : unavailable ? 'Public-post fact unavailable' : 'Checking public-post fact…'}
  </span>)}</>;
}
export function AuthorLine({ author, time, post }: { author: Author; time: number; post?: Thread | Comment }) {
  return <div className="author-line"><span className="author">Anonymous</span><span className="dot">·</span><time dateTime={new Date(time).toISOString()} title={new Date(time).toLocaleString()}>{relativeTime(time)}</time>{author.credentials.map((claim, i) => <Badge key={i} claim={claim} />)}
    {author.passport?.map(reference => <PostBadge key={`${reference.fact}:${reference.challenge}`} post={post} reference={reference} />)}
    {author.zkid && <ZkidBadges post={post} reference={author.zkid} />}</div>;
}
