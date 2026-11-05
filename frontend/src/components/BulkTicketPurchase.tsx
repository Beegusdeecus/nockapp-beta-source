import { useEffect, useRef, useState } from 'react';
import { connectBaseWallet } from '../authoredWallet';
import { publicOperation, type TicketPaymentProgress } from '../publicDiscussion';
import { observeTicketFinality } from '../data/ticketFinalityProgress';
import { formatEth, type TicketOffer } from '../publicTickets';
import { requireAtomicWallet, sendBulkPurchase, validateBulkPurchase, type BulkPurchase } from '../bulkTickets';

export function BulkTicketPurchase({offer,onRefresh,onActive,canRefund=false,includePreparedPack=false}:{offer:TicketOffer;onRefresh:()=>void;onActive:(active:boolean)=>void;canRefund?:boolean;includePreparedPack?:boolean}){
  const [saved,setSaved]=useState<BulkPurchase>();const [loaded,setLoaded]=useState(false);const [consent,setConsent]=useState(false);
  const [reviewed,setReviewed]=useState<{batch:string;payer:string}>();const [busy,setBusy]=useState(false);const [error,setError]=useState('');
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
    try{await work();return true;}catch(e){if(mounted.current)setError(e instanceof Error?e.message:'The saved purchase is preserved. Check its status; do not pay again.');return false;}
    finally{locked.current=false;if(mounted.current)setBusy(false);}
  }
  useEffect(()=>{mounted.current=true;void run(async()=>{await accept(await publicOperation('public-ticket-bulk-status'));});return()=>{mounted.current=false;};},[]);
  async function review(){
    if(!consent)return;
    setStatus('Checking MetaMask supports one atomic payment…');
    const payer=await connectBaseWallet();await requireAtomicWallet(payer);
    setStatus('Saving all 50 blinded tickets before requesting any payment…');
    const next=await accept(await publicOperation('public-ticket-bulk-prepare',{ticket_count:50,approve_purchase:true,...(includePreparedPack?{include_prepared_pack:true}:{})}));
    if(!next||next.phase!=='prepared')throw Error('A saved purchase already exists. Check its progress; do not pay again.');
    setReviewed({batch:next.batch_id,payer});setStatus('Review 50 tickets, then confirm the total and network fee in MetaMask.');
  }
  async function pay(){
    if(!saved||!reviewed||reviewed.batch!==saved.batch_id||!consent)return;
    setReviewed(undefined);setStatus('Confirm one payment in MetaMask. Do not submit it again.');
    await requireAtomicWallet(reviewed.payer);
    let armed:BulkPurchase|undefined;
    try{
      armed=await accept(await publicOperation('public-ticket-bulk-arm',{batch_id:saved.batch_id,payer:reviewed.payer,approve_payment:true}));
      if(!armed)throw Error('The saved payment could not be confirmed.');
      try{await sendBulkPurchase(armed);}catch{throw Error('The wallet reply was not confirmed. Checking this saved payment; do not pay again.');}
    }finally{
      // Even a rejected/lost wallet reply cannot authorize another dispatch.
      await accept(await publicOperation('public-ticket-bulk-status'));setRetry(v=>v+1);
    }
  }
  useEffect(()=>{
    if(!saved||!['armed','importing'].includes(saved.phase))return;
    let alive=true;let timer:ReturnType<typeof setTimeout>|undefined;const controller=new AbortController();
    const check=async()=>{
      const current=latest.current;if(!alive||!current||!['armed','importing'].includes(current.phase))return;
      if(locked.current){timer=setTimeout(()=>void check(),100);return;}
      if(document.visibilityState==='hidden'){timer=setTimeout(()=>void check(),30000);return;}
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
      if(alive)timer=setTimeout(()=>void check(),ok&&latest.current?.phase==='importing'?100:30000);
    };
    void check();const visible=()=>{if(document.visibilityState==='visible'){clearTimeout(timer);void check();}};
    document.addEventListener('visibilitychange',visible);
    return()=>{alive=false;controller.abort();clearTimeout(timer);document.removeEventListener('visibilitychange',visible);};
  },[saved?.batch_id,saved?.phase==='paused',retry]);
  const complete=saved?.phase==='complete';const paid=!!saved?.transaction_hash;
  const stage=complete?4:paid?3+(saved?.settled_tickets??0)/50:saved?.phase==='armed'?chain?.state==='finalized'?3:chain?.state==='confirming'?2+(finalityPercent??0)/100:1:0;
  return <section aria-label="Buy 50 publication tickets">
    <section className="ticket-price"><strong>50 tickets · {formatEth(price)} test ETH</strong><p>One payment, plus the network fee shown in MetaMask. Use tickets before {new Date(offer.manifest.terms.redeem_before*1000).toLocaleString('en-AU',{timeZone:'Australia/Brisbane',timeZoneName:'short'})}.</p></section>
    <section className="ticket-progress" aria-label="50-ticket purchase progress" aria-busy={busy}>
      <ol><li>Review</li><li>Pay once</li><li>Finalize</li><li>Imported</li></ol>
      <progress max={4} value={!loaded?undefined:stage} aria-label="50-ticket purchase completion"/>
      {loaded&&<p>Purchase steps: {Math.round(stage/4*100)}% complete.</p>}
      <p role="status">{complete?`Purchase complete. ${saved!.imported_tickets} tickets imported.${saved!.refunded_tickets?` ${saved!.refunded_tickets} tickets refunded.`:''} Current available tickets are shown below.`:saved?.phase==='paused'?'Ticket import paused. Finish the saved refund, or explicitly continue the remaining tickets.':paid?`Payment finalized. ${saved!.imported_tickets} of 50 tickets imported.`:saved?.phase==='armed'?chain?.state==='confirming'?'Payment found. Waiting for chain finality; do not pay again.':chain?.state==='finalized'?'Payment found in finalized chain. Verifying the complete batch before importing tickets…':chain?.state==='not-seen'?'Payment not found onchain yet. Your saved attempt is preserved; do not pay again.':status:status}</p>
      {saved?.phase==='armed'&&chain&&<>
        {chain.state==='confirming'&&chain.payment_block!==null&&<>
          <p>Finality target: payment block {chain.payment_block.toLocaleString()}. Finalized through {chain.finalized_block.toLocaleString()}. {(chain.payment_block-chain.finalized_block).toLocaleString()} blocks remain.</p>
          <progress max={100} value={finalityPercent} aria-label="Payment finality progress"/>
          <p>{finalityPercent===undefined?'Checking finality progress…':`Finality: ${finalityPercent}% of the block gap closed since this payment was first observed.`}</p>
        </>}
        {chain.state==='not-seen'&&<p>Finality percentage starts once the payment is found. Check MetaMask activity if it remains missing.</p>}
        <p>Latest block {chain.latest_block.toLocaleString()} · Finalized block {chain.finalized_block.toLocaleString()}. The target is your payment block, not the latest block. Checks update automatically every 30 seconds while this page is visible. Finality advances in batches; percentages are not a time estimate.</p>
      </>}
    </section>
    {error&&<p role="alert">{error}</p>}
    {includePreparedPack&&<p>Your saved two-ticket pack is included in these 50 tickets. Its recovery data is preserved; there is no separate two-ticket payment.</p>}
    {loaded&&(!saved||saved.phase==='prepared')&&<>
      <p>The operator holds prepaid funds and can refuse service or lose them. Tickets do not hide your IP address or purchase timing. Issued tickets cannot be refunded. Unissued-pack refunds follow the existing capped reserve policy.</p>
      <label><input type="checkbox" checked={consent} disabled={busy} onChange={e=>{setConsent(e.target.checked);setReviewed(undefined);}}/>I accept the price, expiry and prepaid custody risk for 50 tickets.</label>
      {reviewed?<><p>Total: {formatEth(price)} test ETH plus the network fee. Paying wallet: {reviewed.payer}.</p>
        <button className="primary" disabled={busy||!consent} onClick={()=>void run(pay)}>Pay for 50 tickets in MetaMask</button></>
        :<button className="primary" disabled={busy||!consent} onClick={()=>void run(review)}>{busy?'Preparing your purchase…':'Review 50 tickets'}</button>}
    </>}
    {saved&&saved.phase!=='prepared'&&!complete&&<button disabled={busy} onClick={()=>{setError('');setRetry(v=>v+1);}}>Check saved payment</button>}
    {saved?.phase==='paused'&&<button className="primary" disabled={busy} onClick={()=>void run(async()=>{
      await accept(await publicOperation('public-ticket-bulk-resume',{batch_id:saved.batch_id,approve_import:true}));onRefresh();
    })}>Continue remaining tickets</button>}
    {canRefund&&saved&&saved.phase!=='prepared'&&!complete&&<details><summary>Unissued-pack refund</summary>
      <p>This pauses import and opens the next unissued two-ticket pack in the existing refund screen. Cancellation needs your separate wallet signature. Payout depends on the shared reserve; it is not guaranteed.</p>
      <button disabled={busy} onClick={()=>void run(async()=>{
        await accept(await publicOperation('public-ticket-bulk-refund',{batch_id:saved.batch_id,approve_refund_preparation:true}));onRefresh();
      })}>Prepare one unissued pack for refund</button>
    </details>}
    {!loaded&&error&&<button disabled={busy} onClick={()=>void run(async()=>{await accept(await publicOperation('public-ticket-bulk-status'));})}>Check saved purchase</button>}
  </section>;
}
