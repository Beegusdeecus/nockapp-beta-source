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
  const progressId=useId();
  const [username,setUsername]=useState('');const [post,setPost]=useState('');const [consent,setConsent]=useState(false);
  const [cancelConsent,setCancelConsent]=useState(false);const [result,setResult]=useState<PublicSourceState>();
  const [notice,setNotice]=useState('');
  const [local,setLocal]=useState<PublicSourceStatus>();
  const [uncertain,setUncertain]=useState(false);
  const [request,setRequest]=useState('');
  const cancellationNeeded=!!result&&['aborted','expired'].includes(result.state);
  const recoveryNeeded=uncertain||!!local?.renewal_pending||!!result&&!['empty','cancelled','credential-saved'].includes(result.state);
  const challengeReady=!!result?.post_text&&['waiting-for-source-post','pending'].includes(result.state)&&!uncertain;
  const finalizing=!!result&&['issued','committed','activation-pending-finality'].includes(result.state);
  const complete=result?.state==='credential-saved';
  const completed=uncertain?0:complete?3:finalizing?2:challengeReady?1:0;
  const explanation=request||(uncertain?'The last request was not confirmed. Recover the saved attempt before starting anything new.':cancellationNeeded?'This attempt cannot continue. Cancel it below before starting again.':complete?'Your credential is saved on this computer. You can choose a follower badge when writing a post.':finalizing?'The credential is not saved yet. Waiting for the issuer update to become final on Base Sepolia can take several minutes. Recover this saved attempt later; no new tweet is needed.':challengeReady?'Post the exact challenge, paste its tweet link below, then approve the check.':local?.renewal_pending?'A saved attempt exists. Recover it to find its current step.':'Start verification to get a fresh challenge. Twitter verification is optional for ordinary posts.');
  const consentControl=<label><input type="checkbox" checked={consent} onChange={e=>setConsent(e.target.checked)} />I approve checking my Twitter profile and public verification challenge</label>;
  async function accept(work:()=>Promise<PublicSourceState>,description='Recovering your saved verification and checking its progress…') {
    setRequest(description);
    setNotice('Checking Twitter verification progress…');
    try {const next=await work();setResult(next);setUncertain(false);setLocal(undefined);setNotice('');}
    catch (error) {
      setUncertain(true);
      setNotice('Verification was not confirmed. Check local follower credential, then recover a saved attempt instead of starting another.');
      throw error;
    } finally {setRequest('');setConsent(false);setCancelConsent(false);}
  }
  return <details><summary>Optional Twitter follower credential</summary>
    <p>A fresh public challenge is required for signup and renewal every six calendar months. Your local authorship identity stays the same.</p>
    <p>TwitterAPI.io and the enclave see the account during verification. Public post proofs hide the account and exact count; network timing can still correlate activity.</p>
    <section className="source-progress" aria-label="Twitter verification progress" aria-busy={!!request}>
      <ol><li>Post challenge</li><li>Check tweet</li><li>Finalize credential</li></ol>
      <progress max={3} value={request?undefined:completed} aria-label="Twitter verification completion" aria-describedby={progressId}/>
      <p id={progressId} aria-live="polite">{explanation}</p>
    </section>
    {!identityPresent && <><p>Create or recover your private authorship identity first.</p><p>Open Private authorship setup and recovery above. If an existing key is offered, use its separate reuse consent.</p></>}
    <button disabled={busy} onClick={()=>void run(async()=>setLocal(await publicOperation<PublicSourceStatus>('public-source-status')))}>Check local follower credential</button>
    {local && <p>{local.credential_record_present?'A credential record is saved locally; this alone does not prove current eligibility.':'No credential record is saved locally.'} {local.renewal_pending?'A saved verification attempt needs recovery.':''}</p>}
    <p className="source-next-step"><strong>Next: </strong>{!identityPresent?'Set up your private identity above.':cancellationNeeded?'Cancel this saved attempt below, then start again.':finalizing?'Wait for finality, then recover this saved verification.':challengeReady?'Post the challenge, then paste its link below.':recoveryNeeded?'Recover your saved verification. No username is needed.':complete?'You’re ready. Choose a follower badge when writing a post.':'Check for a saved attempt, or enter your username to start.'}</p>
    {!recoveryNeeded && <label>Twitter username<input value={username} onChange={e=>setUsername(e.target.value)} disabled={busy} autoComplete="off" /></label>}
    {!challengeReady&&consentControl}
    {identityPresent && !busy && !consent && !challengeReady && <p>Approve the profile check above to continue.</p>}
    {!recoveryNeeded && <button disabled={busy||!identityPresent||!consent||!username.trim()} onClick={()=>void run(()=>accept(()=>publicOperation<PublicSourceState>('public-source-begin',{
      username:username.trim().replace(/^@/,''),approve_source_check:true,
    }),'Resolving your profile and preparing a fresh challenge…'))}>Start Twitter verification</button>}
    {!cancellationNeeded&&<button disabled={busy||!identityPresent||!consent} onClick={()=>void run(()=>accept(()=>publicOperation<PublicSourceState>('public-source-recover',{approve_source_check:true})))}>Recover saved Twitter verification</button>}
    {notice && <p aria-live="polite">{notice}</p>}
    {result && <p role="status">{labels[result.state] ?? 'Verification needs recovery.'}</p>}
    {challengeReady && <><label htmlFor={challengeId}>Exact public verification challenge</label><textarea id={challengeId} readOnly value={result!.post_text!} />
      <button disabled={busy} onClick={()=>void run(()=>navigator.clipboard.writeText(result!.post_text!))}>Copy public verification challenge</button></>}
    {challengeReady && <><label>Verification post URL or ID<input value={post} onChange={e=>setPost(e.target.value)} disabled={busy} autoComplete="off" /></label>
    {consentControl}
    {!consent&&<p>Approve this check above to enable the button. You can use the tweet you already posted.</p>}
    <button disabled={busy||!identityPresent||!consent||!post.trim()} onClick={()=>void run(()=>accept(()=>{
      const value=post.trim();const tweet_id=/^[1-9][0-9]{0,19}$/.test(value)?value:parsePostUrl(value).postId;
      return publicOperation<PublicSourceState>('public-source-check-post',{tweet_id,approve_source_check:true});
    },'Checking your tweet through TwitterAPI.io inside the enclave…'))}>Check my public verification post</button></>}
    <details open={cancellationNeeded||undefined}><summary>Cancel this verification</summary>
    <label><input type="checkbox" checked={cancelConsent} onChange={e=>setCancelConsent(e.target.checked)} />I approve cancelling the saved verification attempt</label>
    <button disabled={busy||!identityPresent||!cancelConsent} onClick={()=>void run(()=>accept(()=>publicOperation<PublicSourceState>('public-source-cancel',{approve_cancel:true})))}>Cancel saved Twitter verification</button>
    </details>
    <p>Choose whether to show a follower threshold separately on each post. Both public badge choices remain off by default.</p>
  </details>;
}
