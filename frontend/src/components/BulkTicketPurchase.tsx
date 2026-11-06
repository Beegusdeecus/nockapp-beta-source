import { useCallback, useEffect, useRef, useState } from 'react';
import { publicOperation, type PublicOperation, type TicketPaymentProgress } from '../publicDiscussion';
import { readWalletDiagnostic, walletFailure, type WalletDiagnostic } from '../data/ticketWalletTracking';
import { bulkPaymentDiagnostic } from '../data/bulkPaymentDiagnostic';
import { baseWalletProvider, connectBaseWallet } from '../authoredWallet';
import { observeTicketFinality } from '../data/ticketFinalityProgress';
import { formatEth, type TicketOffer } from '../publicTickets';
import { validateBulkPurchase, sendBulkPurchase, type BulkPurchase } from '../bulkTickets';
import { ResumeSamePurchase } from './ResumeSamePurchase';
import { api } from '../platform/browser';

export function BulkTicketPurchase({offer,onRefresh,onActive,canRefund=false,includePreparedPack=false,recoveryScope,initialPurchase,canResume=false}:{canResume?:boolean;initialPurchase?:BulkPurchase;recoveryScope?:string;offer:TicketOffer;onRefresh:()=>void;onActive:(active:boolean)=>void;canRefund?:boolean;includePreparedPack?:boolean}){
  const [saved,setSaved]=useState<BulkPurchase|undefined>(initialPurchase);const [loaded,setLoaded]=useState(!!initialPurchase);
  const [busy,setBusy]=useState(false);const [error,setError]=useState('');
  const [walletStatus,setWalletStatus]=useState<WalletDiagnostic>();const [copyStatus,setCopyStatus]=useState('');const [copyFallback,setCopyFallback]=useState(false);const trackingBusy=useRef(false);
  const [finalityPercent,setFinalityPercent]=useState<number>();
  const [status,setStatus]=useState('Checking your saved purchase…');const [chain,setChain]=useState<TicketPaymentProgress>();
  const locked=useRef(false);const mounted=useRef(true);const completed=useRef(false);const [retry,setRetry]=useState(0);
  const [reviewBusy,setReviewBusy]=useState(false);
  const reviewActivity=useCallback((active:boolean)=>{setReviewBusy(active);if(active)setError('');},[]);
  const latest=useRef<BulkPurchase|undefined>(initialPurchase);
  const price=(25n*BigInt(offer.manifest.terms.pack_price_wei)).toString();
  const compatible=!recoveryScope&&offer.manifest.terms.profile==='nockapp-public-prepaid-batch-offer-v3';
  const [consent,setConsent]=useState(false);const [paymentHash,setPaymentHash]=useState('');
  function call<T=unknown>(operation:PublicOperation,body:Record<string,unknown>={},signal?:AbortSignal):Promise<T>{
    return recoveryScope?publicOperation<T>('public-ticket-earlier-recovery',{parameters:recoveryScope,operation,body},signal)
      :publicOperation<T>(operation,body,signal);
  }
  async function accept(value:unknown){
    const next=await validateBulkPurchase(value,offer);
    latest.current=next;
    if(mounted.current){setSaved(next);setLoaded(true);onActive(!!next&&next.phase!=='complete');}
    if(next?.phase==='complete'&&!completed.current){completed.current=true;onRefresh();}
    return next;
  }
  async function run(work:()=>Promise<void>,signal?:AbortSignal){
    if(locked.current)return;locked.current=true;setBusy(true);setError('');
    try{await work();return true;}catch(e){if(mounted.current&&!signal?.aborted){setStatus('The action could not finish. Your saved purchase is preserved.');setError(e instanceof Error?e.message:'The saved purchase is preserved. Check its status; do not pay again.');}return false;}
    finally{locked.current=false;if(mounted.current)setBusy(false);}
  }
  useEffect(()=>{mounted.current=true;void run(async()=>{await accept(initialPurchase??await call('public-ticket-bulk-status'));});return()=>{mounted.current=false;};},[]);
  useEffect(()=>{
    if(reviewBusy||!saved||!['armed','importing'].includes(saved.phase))return;
    let alive=true;let checking=false;let timer:ReturnType<typeof setTimeout>|undefined;const controller=new AbortController();
    const check=async()=>{
      const current=latest.current;if(!alive||checking||!current||!['armed','importing'].includes(current.phase))return;
      clearTimeout(timer);
      if(locked.current){timer=setTimeout(()=>void check(),100);return;}
      if(document.visibilityState==='hidden'){timer=setTimeout(()=>void check(),30000);return;}
      if(current.phase==='armed'&&!trackingBusy.current){
        trackingBusy.current=true;void readWalletDiagnostic(current.batch_id,baseWalletProvider,current.profile==='nockapp-ticket-bulk-purchase-v1').then(value=>{if(alive)setWalletStatus(value);}).finally(()=>{trackingBusy.current=false;});
      }
      checking=true;
      const ok=await run(async()=>{
        if(current.phase==='armed'){
          setStatus('Checking the saved payment onchain. No payment will be repeated.');
          const progress=await call<TicketPaymentProgress>('public-ticket-bulk-progress',{batch_id:current.batch_id},controller.signal);
          if(!alive)return;
          const percent=await observeTicketFinality(current.batch_id,progress);if(!alive)return;setChain(progress);setFinalityPercent(percent);
          if(progress.state!=='finalized'){if(recoveryScope&&progress.state==='not-seen'&&Date.now()>=offer.manifest.terms.purchase_before*1000)onRefresh();return;}
        }
        setStatus(`Importing your paid tickets: ${current.imported_tickets} of 50 ready…`);
        await accept(await call('public-ticket-bulk-recover',{batch_id:current.batch_id,approve_import:true},controller.signal));
      },controller.signal);
      checking=false;
      if(alive)timer=setTimeout(()=>void check(),ok&&latest.current?.phase==='importing'?100:30000);
    };
    void check();const visible=()=>{if(document.visibilityState==='visible'){clearTimeout(timer);void check();}};
    document.addEventListener('visibilitychange',visible);
    return()=>{alive=false;controller.abort();clearTimeout(timer);document.removeEventListener('visibilitychange',visible);};
  },[saved?.batch_id,saved?.phase==='armed'||saved?.phase==='importing',retry,reviewBusy]);
  const complete=saved?.phase==='complete';const paid=!!saved?.transaction_hash;
  async function review(){
    if(!compatible||!consent||saved)return;
    setStatus('Saving the exact 50-ticket purchase before any wallet request…');
    await accept(await call('public-ticket-bulk-prepare',{ticket_count:50,approve_purchase:true}));
    setStatus('Purchase saved. Review the full transaction and network fee in MetaMask before approving.');
  }
  async function pay(){
    if(!compatible||!consent||saved?.phase!=='prepared')return;
    setStatus('Connecting to MetaMask. No payment has been requested yet…');
    const provider=await baseWalletProvider();const payer=await connectBaseWallet(provider);
    setStatus('Saving the one-payment fence…');
    const armed=await accept(await call('public-ticket-bulk-arm',{batch_id:saved.batch_id,payer,approve_payment:true}));
    if(!armed)throw Error('The saved payment could not be checked. Do not pay again.');
    setStatus('Review and approve this one transaction in MetaMask…');
    try{await sendBulkPurchase(armed,provider);}catch(e){throw Error(walletFailure(e));}
    setStatus('Wallet request saved. Checking payment and finality automatically…');
  }
  const investigation=saved?.phase==='armed'&&chain?.state==='not-seen'&&!!walletStatus&&['untracked','rejected','failed'].includes(walletStatus.state);
  async function copyDiagnostic(){
    if(!saved)return;
    try{await navigator.clipboard.writeText(bulkPaymentDiagnostic(saved,chain,walletStatus));setCopyStatus('Payment diagnostic copied. It contains public payment details only.');setCopyFallback(false);}
    catch{setCopyStatus('Copy was unavailable. Copy the public diagnostic from the box below.');setCopyFallback(true);}
  }
  const stage=complete?4:paid?3+(saved?.settled_tickets??0)/50:saved?.phase==='armed'?chain?.state==='finalized'?3:chain?.state==='confirming'?2+(finalityPercent??0)/100:1:0;
  if(recoveryScope){
    const absent=chain?.state==='not-seen'&&!paid;const confirming=chain?.state==='confirming';
    const deadline=new Date(offer.manifest.terms.purchase_before*1000).toLocaleString('en-AU',{timeZone:'Australia/Brisbane',timeZoneName:'short'});
    const title=error?'Payment could not be checked':complete?'Tickets ready':saved?.phase==='paused'?'Recovery paused':paid?'Getting your tickets':confirming?'Payment received':absent&&canResume?'Finish your saved purchase':busy&&absent?'Verifying your payment':absent?'Payment not found':'Checking your payment';
    return <section className="ticket-recovery" aria-label="Recover earlier purchase" aria-busy={busy||reviewBusy}>
      <h2>{title}</h2>
      <p className="recovery-summary" role="status">{error?'Your saved purchase is preserved. Its payment status could not be checked.':complete?`${saved!.imported_tickets} tickets recovered.`:paid?`${saved!.imported_tickets} of 50 tickets ready. This finishes automatically.`:confirming?'Waiting for chain finality. No further payment is needed.':reviewBusy?'Follow the wallet step below.':absent&&canResume?'No confirmed payment was found. You can finish the same saved purchase below.':busy&&absent?'Verifying the exact purchase, payer and finalized receipt…':absent?'Check MetaMask → Activity for the original 50-ticket purchase.':'Checking the original purchase. No wallet approval is needed.'}</p>
      {!reviewBusy&&!error&&(!absent||busy&&!canResume)&&!complete&&<progress max={paid?50:100} value={paid?saved?.imported_tickets:confirming?finalityPercent:undefined} aria-label="Purchase recovery progress"/>}
      {error&&<p role="alert">{error}</p>}
      {error&&!absent&&<button className="primary" disabled={busy} onClick={()=>{setError('');setRetry(v=>v+1);}}>Try again</button>}
      {absent&&canResume&&saved&&<ResumeSamePurchase saved={saved} offer={offer} scope={recoveryScope} onCheck={()=>setRetry(v=>v+1)} onBusy={reviewActivity}/>}
      {absent&&!canResume&&<>
        <form onSubmit={e=>{e.preventDefault();if(!saved||busy||!/^0x[0-9a-fA-F]{64}$/.test(paymentHash.trim()))return;void run(async()=>{
          setStatus('Verifying the payment for this exact purchase…');
          try{await accept(await call('public-ticket-bulk-record-payment',{batch_id:saved.batch_id,transaction_hash:paymentHash.trim().toLowerCase(),approve_recovery:true}));}
          catch{throw Error('That transaction could not be verified for this purchase. Check the original Base Sepolia payment in MetaMask. Your saved purchase is unchanged.');}
          setPaymentHash('');setRetry(v=>v+1);
        });}}>
          <label htmlFor="earlier-payment-hash">If it says Confirmed, paste its transaction hash</label>
          <input id="earlier-payment-hash" autoComplete="off" spellCheck={false} value={paymentHash} onChange={e=>setPaymentHash(e.target.value)} placeholder="0x…" disabled={busy}/>
          <button className="primary" type="submit" disabled={busy||!/^0x[0-9a-fA-F]{64}$/.test(paymentHash.trim())}>{busy?'Verifying payment…':'Verify payment'}</button>
        </form>
        <p>If MetaMask has no confirmed payment, there are no tickets to import yet. Don’t send another payment for this purchase.</p>
        <p>You can close this page. If it stays unpaid, reopen it after {deadline} for the final unpaid check.</p>
      </>}
      {saved?.phase==='paused'&&<button className="primary" disabled={busy} onClick={()=>void run(async()=>{await accept(await call('public-ticket-bulk-resume',{batch_id:saved.batch_id,approve_import:true}));setRetry(v=>v+1);})}>Recover remaining tickets</button>}
      <button onClick={()=>void api().tabs.getCurrent().then(tab=>tab?.id===undefined?undefined:api().tabs.remove(tab.id))}>Back to NockApp</button>
      <details className="recovery-details"><summary>Technical details</summary>
        <p>Original purchase: 50 tickets for {formatEth(price)} test ETH. Its saved data is retained.</p>
        {chain&&<p>Latest block {chain.latest_block.toLocaleString()}. Finalized block {chain.finalized_block.toLocaleString()}.{chain.payment_block!==null&&` Payment block ${chain.payment_block.toLocaleString()}.`}</p>}
        {walletStatus&&<p>{canResume?'The original wallet request had no reliable tracking result. Recovery above keeps the original ticket IDs.':walletStatus.message}</p>}
        {canResume&&saved&&<form onSubmit={e=>{e.preventDefault();void run(async()=>{await accept(await call('public-ticket-bulk-record-payment',{batch_id:saved.batch_id,transaction_hash:paymentHash.trim().toLowerCase(),approve_recovery:true}));setRetry(v=>v+1);});}}>
          <label>Original confirmed transaction hash<input value={paymentHash} onChange={e=>setPaymentHash(e.target.value)} placeholder="0x…"/></label>
          <button disabled={busy||!/^0x[0-9a-fA-F]{64}$/.test(paymentHash.trim())}>Verify payment</button>
        </form>}

        <p>Checks run automatically while this page is visible. An absent payment is not an authorization to resend it.</p>
        <button disabled={busy} onClick={()=>setRetry(v=>v+1)}>Check again</button>
        <button disabled={!saved} onClick={()=>void copyDiagnostic()}>Copy payment diagnostic</button>
        {copyStatus&&<p aria-live="polite">{copyStatus}</p>}
        {copyFallback&&saved&&<textarea aria-label="Public payment diagnostic" readOnly value={bulkPaymentDiagnostic(saved,chain,walletStatus)}/>}
      </details>
    </section>;
  }
  return <section aria-label={recoveryScope?"Recover earlier purchase":"Buy 50 publication tickets"}>
    {recoveryScope&&<><h2>Your earlier purchase</h2><p>We’re checking the original payment and recovering its tickets. No new payment will be requested.</p></>}
    <section className="ticket-price"><strong>50 tickets · {formatEth(price)} test ETH</strong><p>One payment, plus the network fee shown in MetaMask. Use tickets before {new Date(offer.manifest.terms.redeem_before*1000).toLocaleString('en-AU',{timeZone:'Australia/Brisbane',timeZoneName:'short'})}.</p></section>
    <section className="ticket-progress" aria-label="50-ticket purchase progress" aria-busy={busy}>
      <ol><li>Review</li><li>Pay once</li><li>Finalize</li><li>Imported</li></ol>
      {!investigation&&(!recoveryScope||chain?.state!=='not-seen')&&<progress max={4} value={!loaded?undefined:stage} aria-label="50-ticket purchase completion"/>}
      {loaded&&!investigation&&(!recoveryScope||chain?.state!=='not-seen')&&<p>Purchase steps: {Math.round(stage/4*100)}% complete.</p>}
      <p role="status">{investigation?'Payment needs investigation. No payment is confirmed for this purchase; waiting for more confirmations will not identify it.':complete?`Purchase complete. ${saved!.imported_tickets} tickets imported.${saved!.refunded_tickets?` ${saved!.refunded_tickets} tickets refunded.`:''} Current available tickets are shown below.`:saved?.phase==='paused'?'Ticket import paused. Finish the saved refund, or explicitly continue the remaining tickets.':paid?`Payment finalized. ${saved!.imported_tickets} of 50 tickets imported.`:saved?.phase==='armed'?chain?.state==='confirming'?'Payment found. Waiting for chain finality; do not pay again.':chain?.state==='finalized'?'Payment found in finalized chain. Verifying the complete batch before importing tickets…':chain?.state==='not-seen'?'Payment not found onchain yet. Your saved attempt is preserved; do not pay again.':status:status}</p>
      {saved?.phase==='armed'&&chain&&<>
        {chain.state==='confirming'&&chain.payment_block!==null&&<>
          <p>Finality target: payment block {chain.payment_block.toLocaleString()}. Finalized through {chain.finalized_block.toLocaleString()}. {(chain.payment_block-chain.finalized_block).toLocaleString()} blocks remain.</p>
          <progress max={100} value={finalityPercent} aria-label="Payment finality progress"/>
          <p>{finalityPercent===undefined?'Checking finality progress…':`Finality: ${finalityPercent}% of the block gap closed since this payment was first observed.`}</p>
        </>}
      </>}
    </section>
    {saved?.phase==='armed'&&chain?.state!=='finalized'&&walletStatus&&<p className="ticket-wallet-status">{walletStatus.message}</p>}
    {recoveryScope&&chain?.state==='not-seen'&&<p>No matching payment was found. This is not a wait for more confirmations. The original checkout can accept payment until {new Date(offer.manifest.terms.purchase_before*1000).toLocaleString('en-AU',{timeZone:'Australia/Brisbane',timeZoneName:'short'})}. After that deadline is finalized, the app can check whether the attempt safely ended unpaid.</p>}
    {investigation&&<><p>Your saved purchase is preserved. Do not buy another pack or send this payment again.</p><button className="primary" onClick={()=>void copyDiagnostic()}>Copy payment diagnostic</button></>}
    {copyStatus&&<p aria-live="polite">{copyStatus}</p>}
    {copyFallback&&saved&&<textarea aria-label="Public payment diagnostic" readOnly value={bulkPaymentDiagnostic(saved,chain,walletStatus)}/>}
    {error&&<p role="alert">{error}</p>}
    {includePreparedPack&&<p>Your saved two-ticket pack is included in these 50 tickets. Its recovery data is preserved; there is no separate two-ticket payment.</p>}
    {compatible&&loaded&&(!saved||saved.phase==='prepared')&&<section aria-label="Review 50-ticket purchase">
      <p>The operator holds prepaid funds and can refuse service or lose them. Once issued, tickets cannot be cancelled for a refund.</p>
      <label><input type="checkbox" checked={consent} disabled={busy} onChange={e=>setConsent(e.target.checked)}/>I accept this price, expiry and prepaid custody risk.</label>
      <button className="primary" disabled={busy||!consent} onClick={()=>void run(saved?pay:review)}>{busy?'Working…':saved?'Pay for 50 tickets in MetaMask':'Review 50 tickets'}</button>
    </section>}
    {!recoveryScope&&!compatible&&loaded&&(!saved||saved.phase==='prepared')&&<section role="note" aria-label="50-ticket checkout unavailable">
      <p><strong>New 50-ticket payments are temporarily unavailable.</strong></p>
      <p>The current checkout needs more calls than MetaMask’s default batch limit. A compatible payment upgrade is required. No payment was requested.</p>
      {saved&&<p>Your prepared purchase is preserved. Do not replace it or pay through another tab.</p>}
    </section>}
    {saved&&saved.phase!=='prepared'&&!complete&&<details><summary>Payment details</summary>
      {chain&&<p>Latest block {chain.latest_block.toLocaleString()} · Finalized block {chain.finalized_block.toLocaleString()}. {chain.state==='not-seen'?'No payment block is known for this saved pack.':'The finality target is the payment block.'}</p>}
      <p>Checks continue automatically every 30 seconds while this page is visible. A successful check that finds no payment is different from a failed check. Wallet status cannot authorize a second payment or import.</p>
      <button disabled={busy} onClick={()=>{setError('');setRetry(v=>v+1);}}>Check saved payment</button>
    </details>}
    {saved?.phase==='paused'&&<button className="primary" disabled={busy} onClick={()=>void run(async()=>{
      await accept(await call('public-ticket-bulk-resume',{batch_id:saved.batch_id,approve_import:true}));onRefresh();
    })}>Continue remaining tickets</button>}
    {!recoveryScope&&canRefund&&paid&&saved&&saved.phase!=='prepared'&&!complete&&<details><summary>Unissued-pack refund</summary>
      <p>This pauses import and opens the next unissued two-ticket pack in the existing refund screen. Cancellation needs your separate wallet signature. Payout depends on the shared reserve; it is not guaranteed.</p>
      <button disabled={busy} onClick={()=>void run(async()=>{
        await accept(await call('public-ticket-bulk-refund',{batch_id:saved.batch_id,approve_refund_preparation:true}));onRefresh();
      })}>Prepare one unissued pack for refund</button>
    </details>}
    {!loaded&&error&&<button disabled={busy} onClick={()=>void run(async()=>{await accept(await call('public-ticket-bulk-status'));})}>Check saved purchase</button>}
  </section>;
}
