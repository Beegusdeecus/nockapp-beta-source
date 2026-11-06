import { useEffect, useRef, useState } from 'react';
import { publicOperation, type TicketPaymentProgress } from '../publicDiscussion';
import { readWalletDiagnostic, type WalletDiagnostic } from '../data/ticketWalletTracking';
import { bulkPaymentDiagnostic } from '../data/bulkPaymentDiagnostic';
import { baseWalletProvider } from '../authoredWallet';
import { observeTicketFinality } from '../data/ticketFinalityProgress';
import { formatEth, type TicketOffer } from '../publicTickets';
import { validateBulkPurchase, type BulkPurchase } from '../bulkTickets';

export function BulkTicketPurchase({offer,onRefresh,onActive,canRefund=false,includePreparedPack=false}:{offer:TicketOffer;onRefresh:()=>void;onActive:(active:boolean)=>void;canRefund?:boolean;includePreparedPack?:boolean}){
  const [saved,setSaved]=useState<BulkPurchase>();const [loaded,setLoaded]=useState(false);
  const [busy,setBusy]=useState(false);const [error,setError]=useState('');
  const [walletStatus,setWalletStatus]=useState<WalletDiagnostic>();const [copyStatus,setCopyStatus]=useState('');const [copyFallback,setCopyFallback]=useState(false);const trackingBusy=useRef(false);
  const [finalityPercent,setFinalityPercent]=useState<number>();
  const [status,setStatus]=useState('Checking your saved purchase…');const [chain,setChain]=useState<TicketPaymentProgress>();
  const locked=useRef(false);const mounted=useRef(true);const completed=useRef(false);const [retry,setRetry]=useState(0);
  const latest=useRef<BulkPurchase|undefined>(undefined);
  const price=(25n*BigInt(offer.manifest.terms.pack_price_wei)).toString();
  async function accept(value:unknown){
    const next=await validateBulkPurchase(value,offer);
    latest.current=next;
    if(mounted.current){setSaved(next);setLoaded(true);onActive(!!next&&next.phase!=='complete');}
    if(next?.phase==='complete'&&!completed.current){completed.current=true;onRefresh();}
    return next;
  }
  async function run(work:()=>Promise<void>){
    if(locked.current)return;locked.current=true;setBusy(true);setError('');
    try{await work();return true;}catch(e){if(mounted.current){setStatus('The action could not finish. Your saved purchase is preserved.');setError(e instanceof Error?e.message:'The saved purchase is preserved. Check its status; do not pay again.');}return false;}
    finally{locked.current=false;if(mounted.current)setBusy(false);}
  }
  useEffect(()=>{mounted.current=true;void run(async()=>{await accept(await publicOperation('public-ticket-bulk-status'));});return()=>{mounted.current=false;};},[]);
  useEffect(()=>{
    if(!saved||!['armed','importing'].includes(saved.phase))return;
    let alive=true;let checking=false;let timer:ReturnType<typeof setTimeout>|undefined;const controller=new AbortController();
    const check=async()=>{
      const current=latest.current;if(!alive||checking||!current||!['armed','importing'].includes(current.phase))return;
      clearTimeout(timer);
      if(locked.current){timer=setTimeout(()=>void check(),100);return;}
      if(document.visibilityState==='hidden'){timer=setTimeout(()=>void check(),30000);return;}
      if(current.phase==='armed'&&!trackingBusy.current){
        trackingBusy.current=true;void readWalletDiagnostic(current.batch_id,baseWalletProvider).then(value=>{if(alive)setWalletStatus(value);}).finally(()=>{trackingBusy.current=false;});
      }
      checking=true;
      const ok=await run(async()=>{
        if(current.phase==='armed'){
          setStatus('Checking the saved payment onchain. No payment will be repeated.');
          const progress=await publicOperation<TicketPaymentProgress>('public-ticket-bulk-progress',{batch_id:current.batch_id},controller.signal);
          if(!alive)return;
          const percent=await observeTicketFinality(current.batch_id,progress);if(!alive)return;setChain(progress);setFinalityPercent(percent);
          if(progress.state!=='finalized')return;
        }
        setStatus(`Importing your paid tickets: ${current.imported_tickets} of 50 ready…`);
        await accept(await publicOperation('public-ticket-bulk-recover',{batch_id:current.batch_id,approve_import:true},controller.signal));
      });
      checking=false;
      if(alive)timer=setTimeout(()=>void check(),ok&&latest.current?.phase==='importing'?100:30000);
    };
    void check();const visible=()=>{if(document.visibilityState==='visible'){clearTimeout(timer);void check();}};
    document.addEventListener('visibilitychange',visible);
    return()=>{alive=false;controller.abort();clearTimeout(timer);document.removeEventListener('visibilitychange',visible);};
  },[saved?.batch_id,saved?.phase==='paused',retry]);
  const complete=saved?.phase==='complete';const paid=!!saved?.transaction_hash;
  const investigation=saved?.phase==='armed'&&chain?.state==='not-seen'&&!!walletStatus&&['untracked','rejected','failed'].includes(walletStatus.state);
  async function copyDiagnostic(){
    if(!saved)return;
    try{await navigator.clipboard.writeText(bulkPaymentDiagnostic(saved,chain,walletStatus));setCopyStatus('Payment diagnostic copied. It contains public payment details only.');setCopyFallback(false);}
    catch{setCopyStatus('Copy was unavailable. Copy the public diagnostic from the box below.');setCopyFallback(true);}
  }
  const stage=complete?4:paid?3+(saved?.settled_tickets??0)/50:saved?.phase==='armed'?chain?.state==='finalized'?3:chain?.state==='confirming'?2+(finalityPercent??0)/100:1:0;
  return <section aria-label="Buy 50 publication tickets">
    <section className="ticket-price"><strong>50 tickets · {formatEth(price)} test ETH</strong><p>One payment, plus the network fee shown in MetaMask. Use tickets before {new Date(offer.manifest.terms.redeem_before*1000).toLocaleString('en-AU',{timeZone:'Australia/Brisbane',timeZoneName:'short'})}.</p></section>
    <section className="ticket-progress" aria-label="50-ticket purchase progress" aria-busy={busy}>
      <ol><li>Review</li><li>Pay once</li><li>Finalize</li><li>Imported</li></ol>
      {!investigation&&<progress max={4} value={!loaded?undefined:stage} aria-label="50-ticket purchase completion"/>}
      {loaded&&!investigation&&<p>Purchase steps: {Math.round(stage/4*100)}% complete.</p>}
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
    {investigation&&<><p>Your saved purchase is preserved. Do not buy another pack or send this payment again.</p><button className="primary" onClick={()=>void copyDiagnostic()}>Copy payment diagnostic</button></>}
    {copyStatus&&<p aria-live="polite">{copyStatus}</p>}
    {copyFallback&&saved&&<textarea aria-label="Public payment diagnostic" readOnly value={bulkPaymentDiagnostic(saved,chain,walletStatus)}/>}
    {error&&<p role="alert">{error}</p>}
    {includePreparedPack&&<p>Your saved two-ticket pack is included in these 50 tickets. Its recovery data is preserved; there is no separate two-ticket payment.</p>}
    {loaded&&(!saved||saved.phase==='prepared')&&<section role="note" aria-label="50-ticket checkout unavailable">
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
      await accept(await publicOperation('public-ticket-bulk-resume',{batch_id:saved.batch_id,approve_import:true}));onRefresh();
    })}>Continue remaining tickets</button>}
    {canRefund&&paid&&saved&&saved.phase!=='prepared'&&!complete&&<details><summary>Unissued-pack refund</summary>
      <p>This pauses import and opens the next unissued two-ticket pack in the existing refund screen. Cancellation needs your separate wallet signature. Payout depends on the shared reserve; it is not guaranteed.</p>
      <button disabled={busy} onClick={()=>void run(async()=>{
        await accept(await publicOperation('public-ticket-bulk-refund',{batch_id:saved.batch_id,approve_refund_preparation:true}));onRefresh();
      })}>Prepare one unissued pack for refund</button>
    </details>}
    {!loaded&&error&&<button disabled={busy} onClick={()=>void run(async()=>{await accept(await publicOperation('public-ticket-bulk-status'));})}>Check saved purchase</button>}
  </section>;
}
