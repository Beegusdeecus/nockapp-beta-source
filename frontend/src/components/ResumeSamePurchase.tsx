import { useEffect, useRef, useState } from 'react';
import { publicOperation } from '../publicDiscussion';
import { baseWalletProvider } from '../authoredWallet';
import { formatEth, type TicketOffer } from '../publicTickets';
import { validateSamePurchaseReview, checkSamePurchaseWallet, inspectSamePurchaseWallet, sendSamePurchase,
  readSamePurchaseRequest, sameWalletCall, SamePurchaseWalletError, SamePurchaseConnectionRequired,
  type SamePurchaseRequest, type SamePurchaseReview } from '../samePurchase';
import type { BulkPurchase } from '../bulkTickets';

export function ResumeSamePurchase({saved,offer,scope,onCheck,onBusy}:{saved:BulkPurchase;offer:TicketOffer;scope:string;onCheck:()=>void;onBusy:(active:boolean)=>void}){
  const [quote,setQuote]=useState<SamePurchaseReview>();const [busy,setBusy]=useState(false);const [expired,setExpired]=useState(false);
  const [request,setRequest]=useState<SamePurchaseRequest>();const [loading,setLoading]=useState(true);const [needsConnection,setNeedsConnection]=useState(false);
  const [message,setMessage]=useState('');const [error,setError]=useState('');const [diagnostic,setDiagnostic]=useState('');
  const locked=useRef(false);const mounted=useRef(true);const dispatchStarted=useRef(false);const step=useRef('read-saved-status');
  useEffect(()=>{
    mounted.current=true;void readSamePurchaseRequest(saved.batch_id).then(value=>{if(mounted.current)setRequest(value);})
      .catch(()=>{if(mounted.current)setError('Wallet tracking could not be read. Your saved purchase is preserved.');})
      .finally(()=>{if(mounted.current)setLoading(false);});
    return()=>{mounted.current=false;};
  },[saved.batch_id]);
  useEffect(()=>{
    setExpired(false);if(!quote)return;
    const timer=setTimeout(()=>setExpired(true),Math.max(0,quote.expires_at*1000-Date.now()));return()=>clearTimeout(timer);
  },[quote]);
  async function run(work:()=>Promise<void>){
    if(locked.current)return;locked.current=true;dispatchStarted.current=false;setBusy(true);setError('');setDiagnostic('');onBusy(true);
    try{await work();}catch(e){
      if(!mounted.current)return;
      const wallet=e instanceof SamePurchaseWalletError?e:undefined;
      setNeedsConnection(e instanceof SamePurchaseConnectionRequired||wallet?.code===4100);
      setMessage(dispatchStarted.current&&wallet?.code!==4001?'The wallet outcome is unknown. Payment checks continue; no request will be sent automatically.':dispatchStarted.current?'':'This step stopped before requesting a transaction. Your saved purchase is preserved.');
      setError(e instanceof Error?e.message:'The app could not authorize the saved purchase. No transaction was requested by this step.');
      setDiagnostic(JSON.stringify({profile:'nockapp-wallet-step-diagnostic-v1',step:step.current,transaction_requested:dispatchStarted.current,method:wallet?.method??null,code:wallet?.code??null,timeout:wallet?.timedOut??false}));
    }finally{locked.current=false;onBusy(false);if(mounted.current)setBusy(false);}
  }
  async function review(){
    step.current='review-original-purchase';setMessage('Checking the original ticket IDs, wallet code and network fee…');setQuote(undefined);
    const raw=await publicOperation('public-ticket-earlier-recovery',{parameters:scope,operation:'public-ticket-bulk-self-review',body:{batch_id:saved.batch_id,execution_fee_limit_wei:'100000000000000'}});
    const checked=await validateSamePurchaseReview(raw,saved,offer);if(!mounted.current)return;setQuote(checked);setMessage('');
  }
  async function connect(){
    step.current='connect-wallet';setMessage('Open MetaMask and connect the original paying account. This requests no payment.');
    await sameWalletCall(await baseWalletProvider(),'eth_requestAccounts');if(!mounted.current)return;setNeedsConnection(false);setMessage('MetaMask connected. Review the purchase before paying.');
  }
  async function checkWallet(){
    step.current='check-wallet-connection';setMessage('Checking MetaMask. No payment or signature will be requested…');
    if(!saved.payer)throw Error('The saved payer is unavailable. Keep this purchase.');
    await inspectSamePurchaseWallet(await baseWalletProvider(),saved.payer);if(!mounted.current)return;
    setNeedsConnection(false);setMessage('MetaMask connection checks passed. No payment was requested.');
  }
  async function pay(){
    if(!quote||expired)return;const q=quote;
    step.current='check-wallet-before-authorization';setMessage('Checking MetaMask before requesting any payment…');
    const provider=await baseWalletProvider();await checkSamePurchaseWallet(q,provider);if(!mounted.current)return;
    step.current='authorize-original-purchase';setMessage('Rechecking the original purchase before opening MetaMask…');
    const authorization=await publicOperation('public-ticket-earlier-recovery',{parameters:scope,operation:'public-ticket-bulk-self-arm',body:{quote:q,approve_resume:true}});
    if(!mounted.current)return;setQuote(undefined);
    step.current='check-wallet-before-send';setMessage('Final wallet checks. No transaction requested yet…');
    try{
      const transaction=await sendSamePurchase(q,authorization,provider,()=>{
        if(!mounted.current)throw Error('The review closed before the wallet request. Check the saved purchase.');
        dispatchStarted.current=true;step.current='request-wallet-transaction';
        setRequest({quote_sha256:q.quote_sha256,state:'requested',transaction_hash:null});setMessage('Open MetaMask and review this one payment.');
      });
      if(mounted.current){setRequest({quote_sha256:q.quote_sha256,state:'submitted',transaction_hash:transaction});setMessage('Transaction submitted. Checking payment and finality automatically…');}
    }catch(e){
      if(e instanceof SamePurchaseWalletError&&e.code===4001&&mounted.current)setRequest({quote_sha256:q.quote_sha256,state:'rejected',transaction_hash:null});
      throw e;
    }finally{onCheck();}
  }
  const pending=request&&request.state!=='rejected';
  return <section aria-label="Finish saved purchase" aria-busy={busy||loading}>
    {!quote&&!pending&&!loading&&<><p>Finish these same 50 tickets in one wallet transaction. The ticket IDs and purchase price stay unchanged.</p>
      <button className="primary" disabled={busy} onClick={()=>void run(review)}>{busy?'Checking saved purchase…':'Review saved purchase'}</button></>}
    {!quote&&pending&&<>
      <p>{request.transaction_hash?'Transaction submitted. Checking its payment and finality automatically.':'The wallet request has no confirmed outcome. Open MetaMask to check whether it is awaiting approval.'}</p>
      <button disabled={busy} onClick={onCheck}>Check payment status</button>
      <details><summary>Wallet request did not complete?</summary><p>Review the same ticket IDs again. Only one complete purchase can succeed; a failed duplicate can cost gas.</p>
        <button disabled={busy} onClick={()=>void run(review)}>Review same purchase again</button>
      </details></>}
    {quote&&<>
      <p><strong>50 tickets · {formatEth(quote.price_wei)} test ETH</strong></p>
      <p>Execution fee at most {formatEth(quote.execution_fee_wei)} test ETH. Base adds data and operator fees; approve only if MetaMask’s total network fee is at most 0.001 test ETH.</p>
      <p>MetaMask may show your own wallet as the destination. Its existing wallet code forwards the payment to the original purchase contract.</p>
      <p>If an earlier request also arrives, only one complete purchase can succeed. A failed duplicate can still cost gas.</p>
      <button className="primary" disabled={busy||needsConnection} onClick={()=>void run(expired?review:pay)}>{busy?'Working…':expired?'Review again':'Confirm in MetaMask'}</button>
      {!busy&&<button onClick={()=>{setQuote(undefined);setMessage('');}}>Back</button>}
    </>}
    {(busy||loading)&&<progress aria-label="Saved purchase review progress"/>}
    {message&&<p aria-live="polite">{message}</p>}
    {error&&<p role="alert">{error}</p>}
    {needsConnection&&<button disabled={busy} onClick={()=>void run(connect)}>Connect MetaMask</button>}
    {!loading&&<details><summary>Connection details</summary>
      <p>This check requests no transaction or signature.</p>
      <button disabled={busy} onClick={()=>void run(checkWallet)}>Check MetaMask connection</button>
      {diagnostic&&<textarea aria-label="Public wallet diagnostic" readOnly value={diagnostic}/>}
    </details>}
  </section>;
}
