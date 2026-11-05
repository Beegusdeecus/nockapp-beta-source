import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { connectBaseWallet,canonicalAscii } from './authoredWallet';
import { publicOperation, type PublicScope, type PublicSubmission } from './publicDiscussion';
import { validatePublicWalletRequest, validPublicWalletShape, signPublicPost, type PublicWalletRequest } from './publicWallet';
import './tokens.css';
import './styles.css';

function PublicWallet() {
  const [scope, setScope] = useState<PublicScope>();const [row, setRow] = useState<PublicSubmission>();
  const [request, setRequest] = useState<PublicWalletRequest>();const [busy, setBusy] = useState(false);const [error, setError] = useState('');
  const [actionStatus,setActionStatus]=useState('Loading the exact saved post…');
  const [done, setDone] = useState(false);const [resetConsent, setResetConsent] = useState(false);
  useEffect(() => {
    let active = true;
    void (async () => {
      const match=location.hash.match(/^#post=([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/);
      if (!match) throw new Error('Open this screen from a saved public post.');
      const caps=await publicOperation<{scope:PublicScope}>('public-capabilities');let selected:PublicSubmission|undefined;let after=0;
      for (let n=0;n<10;n++) {
        const page=await publicOperation<{entries:PublicSubmission[];next_after:number|null}>('public-outbox',{after,limit:4});
        selected=page.entries.find(r=>r.core.post.id===match[1]);if(selected||page.next_after===null)break;after=page.next_after;
      }
      if(!selected||!selected.core.selection.address)throw new Error('This saved post has no address disclosure.');
      const {submission_id:_id,...where}=selected.core.context;
      if(where.protocol!==caps.scope.protocol||where.chain_id!==caps.scope.chain_id||where.contract!==caps.scope.contract||where.application!==caps.scope.application)throw new Error('Saved deployment changed.');
      if(active){setScope(caps.scope);setRow(selected);}
    })().catch(e=>{if(active)setError(e instanceof Error?e.message:'Saved public post unavailable.');});
    return()=>{active=false;};
  },[]);
  async function authorize() {
    if(!scope||!row||busy||row.bundle_hash)return;setBusy(true);setError('');
    try {
      // Finish the account/network prompt before starting the60-second window.
      setActionStatus('Connect your wallet and confirm Base Sepolia in MetaMask…');
      const account=await connectBaseWallet();
      setActionStatus('Checking the exact saved post, wallet address and signing context…');
      const raw=await publicOperation<unknown>('public-wallet-request',{post_id:row.core.post.id,address:account,approve_address_disclosure:true});
      if(!validPublicWalletShape(raw))throw new Error('Unsupported exact public wallet request.');setRequest(raw);
      const checked=await validatePublicWalletRequest(raw,scope,row.core,account);
      let result:PublicSubmission;
      setActionStatus('Saving the exact wallet authorization…');
      if(checked.signature_saved) result=await publicOperation<PublicSubmission>('public-wallet-finish',{post_id:row.core.post.id,request_sha256:checked.request_sha256,approve_save:true});
      else {
        setActionStatus('Review the exact-post signature in MetaMask. This does not send a payment.');
        const signature=await signPublicPost(checked);
        setActionStatus('Verifying and saving your exact authorization…');
        result=await publicOperation<PublicSubmission>('public-wallet-result',{post_id:row.core.post.id,request_sha256:checked.request_sha256,signature});
      }
      if(canonicalAscii(result.core)!==canonicalAscii(row.core))throw new Error('The saved post changed while authorizing. Keep the original request.');
      setRow(result);setDone(true);
    } catch(e){setError(e instanceof Error?e.message:'Authorization unavailable. Recover this saved post.');}
    finally{setBusy(false);}
  }
  async function recover() {
    if(!row||busy)return;setBusy(true);setError('');
    setActionStatus('Checking for the matching saved signature without opening MetaMask…');
    try {const result=await publicOperation<PublicSubmission>('public-wallet-recover',{post_id:row.core.post.id,approve_save:true});
      if(canonicalAscii(result.core)!==canonicalAscii(row.core))throw new Error('Saved core changed');setRow(result);setDone(true);}
    catch{setError('No matching saved wallet reply was recovered. Keep this post and authorize it with MetaMask if needed.');}
    finally{setBusy(false);}
  }
  async function reset() {
    if(!row||!request||!resetConsent||busy)return;setBusy(true);setError('');
    setActionStatus('Checking the exact expired request before resetting it…');
    try{await publicOperation('public-wallet-reset',{post_id:row.core.post.id,request_sha256:request.request_sha256,approve_fresh_request:true});setRequest(undefined);setResetConsent(false);}
    catch{setError('A reset is available only after this exact unfinished request expires. Completed bytes cannot change.');}
    finally{setBusy(false);}
  }
  return <main className="wallet-authorization"><h1>Authorize this exact public post</h1>
    <p>Your selected Ethereum address will be public. Reusing it links those posts. Your private authorship key and Twitter account stay hidden.</p>
    {row&&<section aria-label="Public post to authorize"><h2>{row.core.post.title??'Comment'}</h2><p className="wallet-post-body">{row.core.post.body}</p>
      <p>{row.core.selection.followers_threshold===null?'No follower badge selected.':`Selected follower threshold: greater than ${row.core.selection.followers_threshold}. Missing optional evidence is omitted independently.`}</p>
      <p>Base Sepolia index: {row.core.context.contract}</p>
      {row.core.thread&&<p>Thread root: No.{row.core.thread.number??'pending'} · {row.core.thread.bundle_hash}</p>}
      {row.core.post.references.map(([url],i)=><p key={i}>External reference: {url}</p>)}
      {row.core.references.map((r,i)=><p key={i}>Committed reference: No.{r.number} · {r.contract}</p>)}
      {request?.binding.history&&<p>Selected common authorship: {(JSON.parse(atob(request.binding.history)).records as {number:string;contract:string}[]).map(r=>`No.${r.number} (${r.contract})`).join(', ')}</p>}
    </section>}
    <p>This signature binds the exact content, author points, deployment, references and saved public evidence. It transfers no funds and grants no token spending approval.</p>
    {((!row&&!error)||busy)&&<section aria-label="Wallet authorization progress" aria-live="polite"><progress aria-label="Wallet authorization action"/><p>{actionStatus}</p></section>}
    {error&&<p role="alert">{error}</p>}
    {done?<p role="status">Authorization and exact final bundle saved. Return to NockApp to publish or independently check it. No gas transaction was sent here.</p>
      :row?.bundle_hash?<p role="status">This final bundle is already saved. Its committed bytes cannot receive a later wallet endorsement. Return to NockApp to check publication.</p>
      :<button disabled={!row||busy} onClick={()=>void authorize()}>{busy?'Waiting for MetaMask…':'Connect MetaMask and authorize saved public post'}</button>}
    {!done&&row&&!row.bundle_hash&&<button disabled={busy} onClick={()=>void recover()}>Recover a previously saved wallet reply</button>}
    {!done&&request?.expired&&!request.signature_saved&&<section><label><input type="checkbox" checked={resetConsent} onChange={e=>setResetConsent(e.target.checked)}/>I approve replacing this expired unfinished signing request</label>
      <button disabled={busy||!resetConsent} onClick={()=>void reset()}>Reset expired public authorization</button></section>}
  </main>;
}
createRoot(document.getElementById('root')!).render(<StrictMode><PublicWallet/></StrictMode>);
