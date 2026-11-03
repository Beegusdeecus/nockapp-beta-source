import { useId, useState } from 'react';
import { publicOperation, type PublicSourceState, type PublicSourceStatus } from '../publicDiscussion';
import { parsePostUrl } from '../urls';

const labels: Record<string,string> = {
  empty:'No follower credential is saved.', 'waiting-for-source-post':'Post the exact challenge below from your Twitter account.',
  'begin-recovery-required':'Recover the saved signup request before continuing.', pending:'The saved challenge is awaiting verification.',
  issued:'The credential response is saved on the service. Recover to finish.', committed:'Recover to check finality and finish saving.',
  'credential-saved':'Follower credential saved. Eligibility is checked independently for each post.',
  'activation-pending-finality':'Waiting for finalized issuer state. Use recovery later; do not start another signup.',
  'activation-replaced-or-revoked':'This credential is no longer active for new posts.',
  aborted:'The saved attempt was aborted. Confirm cancellation before starting again.',
  expired:'The challenge expired. Cancel the saved attempt before starting again.',
  failed:'The attempt could not finish. Recover or cancel it before starting again.', cancelled:'The saved attempt was cancelled. Existing credentials are retained.',
};

export function PublicSourceEnrollment({busy,identityPresent,run}: {busy:boolean;identityPresent:boolean;run:(work:()=>Promise<void>)=>Promise<void>}) {
  const challengeId=useId();
  const [username,setUsername]=useState('');const [post,setPost]=useState('');const [consent,setConsent]=useState(false);
  const [cancelConsent,setCancelConsent]=useState(false);const [result,setResult]=useState<PublicSourceState>();
  const [notice,setNotice]=useState('');
  const [local,setLocal]=useState<PublicSourceStatus>();
  async function accept(work:()=>Promise<PublicSourceState>) {
    setNotice('Checking Twitter verification progress…');
    try {setResult(await work());setNotice('');}
    catch (error) {
      setNotice('Verification was not confirmed. Check local follower credential, then recover a saved attempt instead of starting another.');
      throw error;
    } finally {setConsent(false);setCancelConsent(false);}
  }
  return <details><summary>Optional Twitter follower credential</summary>
    <p>A fresh public challenge is required for signup and renewal every six calendar months. Your local authorship identity stays the same.</p>
    <p>TwitterAPI.io and the enclave see the account during verification. Public post proofs hide the account and exact count; network timing can still correlate activity.</p>
    {!identityPresent && <><p>Create or recover your private authorship identity first.</p><p>Open Private authorship setup and recovery above. If an existing key is offered, use its separate reuse consent.</p></>}
    <button disabled={busy} onClick={()=>void run(async()=>setLocal(await publicOperation<PublicSourceStatus>('public-source-status')))}>Check local follower credential</button>
    {local && <p>{local.credential_record_present?'A credential record is saved locally; this alone does not prove current eligibility.':'No credential record is saved locally.'} {local.renewal_pending?'A saved verification attempt needs recovery.':''}</p>}
    <label>Twitter username<input value={username} onChange={e=>setUsername(e.target.value)} disabled={busy} autoComplete="off" /></label>
    <label><input type="checkbox" checked={consent} onChange={e=>setConsent(e.target.checked)} />I approve checking my Twitter profile and public verification challenge</label>
    {identityPresent && !busy && (!username.trim() ? <p>Enter your Twitter username to enable verification.</p> : !consent && <p>Tick the profile and challenge consent box to enable verification.</p>)}
    <button disabled={busy||!identityPresent||!consent||!username.trim()} onClick={()=>void run(()=>accept(()=>publicOperation<PublicSourceState>('public-source-begin',{
      username:username.trim().replace(/^@/,''),approve_source_check:true,
    })))}>Start Twitter verification</button>
    <button disabled={busy||!identityPresent||!consent} onClick={()=>void run(()=>accept(()=>publicOperation<PublicSourceState>('public-source-recover',{approve_source_check:true})))}>Recover saved Twitter verification</button>
    {notice && <p aria-live="polite">{notice}</p>}
    {result && <p role="status">{labels[result.state] ?? 'Verification needs recovery.'}</p>}
    {result?.post_text && <><label htmlFor={challengeId}>Exact public verification challenge</label><textarea id={challengeId} readOnly value={result.post_text} />
      <button disabled={busy} onClick={()=>void run(()=>navigator.clipboard.writeText(result.post_text!))}>Copy public verification challenge</button></>}
    <label>Verification post URL or ID<input value={post} onChange={e=>setPost(e.target.value)} disabled={busy} autoComplete="off" /></label>
    <button disabled={busy||!identityPresent||!consent||!post.trim()} onClick={()=>void run(()=>accept(()=>{
      const value=post.trim();const tweet_id=/^[1-9][0-9]{0,19}$/.test(value)?value:parsePostUrl(value).postId;
      return publicOperation<PublicSourceState>('public-source-check-post',{tweet_id,approve_source_check:true});
    }))}>Check my public verification post</button>
    <label><input type="checkbox" checked={cancelConsent} onChange={e=>setCancelConsent(e.target.checked)} />I approve cancelling the saved verification attempt</label>
    <button disabled={busy||!identityPresent||!cancelConsent} onClick={()=>void run(()=>accept(()=>publicOperation<PublicSourceState>('public-source-cancel',{approve_cancel:true})))}>Cancel saved Twitter verification</button>
    <p>Choose whether to show a follower threshold separately on each post. Both public badge choices remain off by default.</p>
  </details>;
}
