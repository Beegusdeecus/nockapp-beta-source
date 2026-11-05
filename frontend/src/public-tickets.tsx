import { StrictMode, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { connectBaseWallet } from './authoredWallet';
import { publicOperation, PublicOperationError, type PublicScope, type TicketPaymentProgress } from './publicDiscussion';
import { api } from './platform/browser';
import { validateTicketOffer, validateTicketPurchase, quoteTicketPayment, admitTicketSend, sendTicketPayment,
  ticketDigest, parseEth, formatEth, validateTicketRefund, signTicketRefund,
  type TicketOffer, type TicketPending, type PaymentQuote, type ArmedPurchase } from './publicTickets';
import './tokens.css';
import './styles.css';
import './public-tickets.css';
import { validateRefundState, validateRefundResult, type RefundState } from './publicRefunds';
import { BulkTicketPurchase } from './components/BulkTicketPurchase';

function Tickets() {
  const [bulkEnabled,setBulkEnabled]=useState(false);const [quantity,setQuantity]=useState('50');const [bulkActive,setBulkActive]=useState(false);
  const [offer,setOffer]=useState<TicketOffer>();const [pending,setPending]=useState<TicketPending>();
  const [refundState,setRefundState]=useState<RefundState>();const [refundVerified,setRefundVerified]=useState(false);
  const [quote,setQuote]=useState<PaymentQuote>();const [feeLimit,setFeeLimit]=useState('');const [hash,setHash]=useState('');
  const [purchaseConsent,setPurchaseConsent]=useState(false);const [feeConsent,setFeeConsent]=useState(false);
  const [cancelConsent,setCancelConsent]=useState(false);const [closeConsent,setCloseConsent]=useState(false);const [refundConsent,setRefundConsent]=useState(false);
  const [inventory,setInventory]=useState<{available:number;reserved:number;purchase_pending:boolean}>();
  const [paymentProgress,setPaymentProgress]=useState<TicketPaymentProgress>();
  const [progressError,setProgressError]=useState(false);const [finishing,setFinishing]=useState(false);
  const [actionStatus,setActionStatus]=useState('Checking your saved purchase…');
  const [needsReload,setNeedsReload]=useState(false);const [refreshProgress,setRefreshProgress]=useState(0);
  const [updateRequired,setUpdateRequired]=useState(false);const [progressReason,setProgressReason]=useState('');
  const [busy,setBusy]=useState(false);const locked=useRef(false);const [error,setError]=useState('');const [notice,setNotice]=useState('');
  async function load() {
    const caps=await publicOperation<{scope:PublicScope;refund_payout_configured?:boolean;verifier_release:number}>('public-capabilities');
    const next=await validateTicketOffer(await publicOperation('public-ticket-offer'),caps.scope);
    const state=await publicOperation<TicketPending>('public-ticket-pending');
    if(state.purchase)validateTicketPurchase(state.purchase,next);
    const refunds=caps.refund_payout_configured===true?await validateRefundState(await publicOperation('public-ticket-refund-state'),next,state):undefined;
    const counts=await publicOperation<{available:number;reserved:number;purchase_pending:boolean}>('public-ticket-status');
    setInventory(counts);setNeedsReload(false);setUpdateRequired(false);
    setBulkEnabled(caps.verifier_release>=11);
    setRefundState(refunds);
    setOffer(next);setPending(state);setQuote(undefined);setFeeConsent(false);return {offer:next,pending:state,inventory:counts,refunds};
  }
  useEffect(()=>{void run(async()=>{await load();},'Checking your saved purchase and ticket inventory…');},[]);
  async function run(work:()=>Promise<void>,description='Checking this saved operation…') {
    if(locked.current)return;locked.current=true;setBusy(true);setError('');setNotice('');setActionStatus(description);
    try{await work();}catch(e){
      setFinishing(false);setError(e instanceof Error?e.message:'Could not confirm this step. Your saved purchase is preserved.');
      if(e instanceof PublicOperationError&&e.code==='extension-update-required'){setUpdateRequired(true);setNeedsReload(true);return;}
      try{await load();}catch{setNeedsReload(true);}
    }finally{locked.current=false;setBusy(false);setActionStatus('');}
  }
  async function refresh() {await load();setNotice('Saved purchase state refreshed. No wallet action was requested.');}
  async function reviewPurchase() {
    if(!purchaseConsent||!offer||!pending)return;
    setActionStatus('Saving this exact ticket pack…');
    if(!pending.purchase)await publicOperation('public-ticket-prepare',{approve_purchase:true});
    const saved=await load();
    if(!saved.pending.purchase)throw Error('Could not confirm the saved pack. No wallet transaction was requested.');
    if(saved.pending.payment_intent||saved.pending.purchase.payment_tx){setNotice('This purchase already has a saved payment attempt. Finish it below; do not pay again.');return;}
    const purchase=validateTicketPurchase(saved.pending.purchase,saved.offer);
    setActionStatus('Connecting to MetaMask and checking the exact price, contract and network fees…');
    const account=await connectBaseWallet();
    setQuote(await quoteTicketPayment(purchase,account,parseEth(feeLimit)));
    setFeeConsent(false);setPurchaseConsent(false);
  }
  async function review(cancel=false) {
    if(!offer||!pending?.purchase||cancel&&!cancelConsent)return;
    const p=validateTicketPurchase(pending.purchase,offer);const account=await connectBaseWallet();
    const reviewed=await quoteTicketPayment(p,account,parseEth(feeLimit),undefined,cancel?pending.payment_intent??undefined:undefined);
    setQuote(reviewed);setFeeConsent(false);
  }
  async function send() {
    if(!quote||!feeConsent||!offer)return;
    const q=quote;setQuote(undefined);setFeeConsent(false);
    if(q.kind==='purchase')setFinishing(true);
    setActionStatus(q.kind==='purchase'?'Confirm this exact purchase in MetaMask. It will be sent at most once.':'Confirm the reviewed same-nonce cancellation in MetaMask.');
    try{
      let armed:ArmedPurchase|undefined;
      if(q.kind==='purchase')armed=admitTicketSend(await publicOperation('public-ticket-arm',{
        pack_hash:q.purchase.pack_hash,payer:q.payer,nonce:q.nonce,approve_payment:true}),q);
      const transactionHash=await sendTicketPayment(q,armed);
      if(q.kind==='purchase')await publicOperation('public-ticket-payment',{pack_hash:q.purchase.pack_hash,transaction_hash:transactionHash});
      setNotice(q.kind==='purchase'?'Transaction hash saved. Wait for finality, then recover the paid tickets.'
        :`Cancellation submitted (${transactionHash}). Check finalized recovery before closing the old attempt.`);
    }catch(e){
      if(q.kind!=='purchase')throw e;
      setNotice('The wallet reply was not confirmed. Checking only this saved pack onchain; no payment will be sent again.');
    }finally{await load();}
  }
  async function find() {
    const r=await publicOperation<{search_state:string;receipt_status?:string}>('public-ticket-find');await load();
    setNotice(r.search_state==='transaction-found'?(r.receipt_status==='0x1'?'Finalized transaction found. Recover tickets to verify payment and import the pack.':'Finalized failed transaction found. A relayed payment may still arrive; do not pay again.')
      :r.search_state==='nonce-consumed-by-other-transaction'?'The saved nonce was used for another transaction. A relayed payment may still arrive; do not pay again.'
        :'Payment remains uncertain or not finalized. Do not pay again.');
  }
  async function recordHash() {
    if(!pending?.purchase||!/^0x[0-9a-f]{64}$/.test(hash))throw Error('Enter the original transaction hash, not wallet keys or recovery words.');
    await publicOperation('public-ticket-payment',{pack_hash:pending.purchase.pack_hash,transaction_hash:hash});await load();setHash('');
    setNotice('Matching transaction hash saved. Recover tickets to check finalized payment.');
  }
  async function close() {
    if(!closeConsent||!pending?.purchase||!pending.payment_intent||!offer)return;
    const digest=await ticketDigest(pending.payment_intent);
    const result=await publicOperation<{parameters:string;closed_attempt:{intent:unknown}}>('public-ticket-close-attempt',{
      pack_hash:pending.purchase.pack_hash,payment_intent_sha256:digest,approve_close_attempt:true});
    if(result.parameters!==offer.parameters||await ticketDigest(result.closed_attempt.intent)!==digest)throw Error('Closed attempt does not match the reviewed intent.');
    await load();setCloseConsent(false);setCancelConsent(false);setNotice('Expired unpaid attempt closed. The saved pack and recovery evidence are preserved.');
  }
  async function recover() {
    setActionStatus('Verifying the finalized payment and securely importing your signed tickets…');
    const before=inventory?.available??0;const size=offer?.manifest.terms.pack_size??0;
    try{await publicOperation('public-ticket-recover');}
    catch(error){
      const saved=await load();
      if(!saved.pending.purchase&&size>0&&saved.inventory.available>=before+size){
        setFinishing(false);setNotice('Purchase complete. The saved ticket import was recovered without another payment.');return;
      }
      throw error;
    }
    await load();setFinishing(false);setNotice('Purchase complete. Your tickets are ready.');
  }
  async function finishSavedPurchase() {
    const expected=pending?.purchase?.pack_hash;if(!expected)return;
    setActionStatus('Checking this exact saved purchase…');
    const saved=await load();
    if(saved.pending.purchase?.pack_hash!==expected)throw Error('Saved purchase changed. Inventory refreshed; no new payment was sent.');
    if(saved.refunds?.pending)throw Error('A refund is pending for this pack. Continue its saved refund instead.');
    if(!saved.pending.purchase.payment_tx){
      if(saved.pending.payment_intent?.profile!=='nockapp-ticket-wallet-payment-intent-v2')throw Error('This older saved purchase needs its original transaction hash under Advanced recovery.');
      setActionStatus('Verifying the finalized receipt against your exact saved pack and payer…');
      const found=await publicOperation<{search_state:string;receipt_status?:string}>('public-ticket-find');
      await load();
      if(found.search_state!=='transaction-found'||found.receipt_status!=='0x1')throw Error('The finalized payment could not yet be verified. Your saved purchase is preserved.');
    }
    await recover();
  }
  const watchedPack=pending?.purchase?.pack_hash;
  const hasPaymentAttempt=!!pending?.payment_intent||!!pending?.purchase?.payment_tx;
  useEffect(()=>{
    if(!watchedPack||!hasPaymentAttempt||busy)return;
    let alive=true;let checking=false;const controller=new AbortController();
    const check=async()=>{
      if(!alive||checking||document.visibilityState==='hidden')return;checking=true;
      try{
        const value=await publicOperation<TicketPaymentProgress>('public-ticket-progress',{pack_hash:watchedPack},controller.signal);
        if(alive){setPaymentProgress(value);setProgressError(false);}
      }catch(error){if(alive){
        setPaymentProgress(undefined);setProgressError(true);setFinishing(false);
        const code=error instanceof PublicOperationError?error.code:'operation-unavailable';
        setProgressReason(code==='helper-busy'?'The installed app is finishing another operation. This saved check will wait and retry.':`Payment check could not finish (${code}). Your saved purchase is preserved.`);
        if(code==='extension-update-required'){setUpdateRequired(true);setNeedsReload(true);setFinishing(false);setError(error instanceof Error?error.message:'Reload the NockApp extension.');}
      }}
      finally{checking=false;}
    };
    void check();const timer=setInterval(()=>void check(),30000);
    const visible=()=>{if(document.visibilityState==='visible')void check();};document.addEventListener('visibilitychange',visible);
    return()=>{alive=false;controller.abort();clearInterval(timer);document.removeEventListener('visibilitychange',visible);};
  },[watchedPack,hasPaymentAttempt,busy,refreshProgress]);
  useEffect(()=>{
    if(finishing&&!busy&&paymentProgress&&paymentProgress.pack_hash===watchedPack&&paymentProgress.state==='finalized'&&!refundState?.pending)
      void run(finishSavedPurchase,'Checking the finalized payment and retrieving your tickets…');
  },[finishing,busy,paymentProgress,watchedPack,refundState?.pending]);

  async function refund() {
    if(!refundConsent||!offer||!pending?.purchase)return;
    setFinishing(false);setActionStatus('Checking the refund authorization and original paying wallet…');
    const p=validateTicketPurchase(pending.purchase,offer);const account=await connectBaseWallet();
    const r=await validateTicketRefund(await publicOperation('public-ticket-refund-request'),offer,p,account);
    setActionStatus('Review permanent pack cancellation in MetaMask. No refund is confirmed yet.');
    const signature=await signTicketRefund(r);
    setActionStatus('Recording this exact cancellation and checking refund progress…');
    try {
      const reply=await publicOperation('public-ticket-refund-result',{request_sha256:r.request_sha256,signature});
      if(refundState)showRefund(reply,{pack_hash:p.pack_hash,payment_transaction:p.payment_tx!,payer:r.address});
      else setNotice('Cancellation recorded. Payout is not confirmed; this is not a completed refund.');
      setRefundConsent(false);
    }finally{await load();}
  }
  function showRefund(reply:unknown,expected:{pack_hash:string;payment_transaction?:string;payer?:string;transaction_hash?:string}) {
    if(!refundState)throw Error('Pinned refund policy unavailable.');
    const result=validateRefundResult(reply,refundState,expected);setRefundVerified(result.payout_confirmed);
    setNotice(result.payout_confirmed?`Refund confirmed by the local verifier using finalized public chain evidence: ${formatEth(result.amount_wei)} ETH to ${result.payer}. Transaction: ${result.transaction_hash}.`
      :'Payout is not confirmed. Cancellation authorization is saved; resume the refund without another wallet signature.');
  }
  async function refundCheck(pack:string,resume=false,transaction?:string) {
    try {
      showRefund(await publicOperation(resume?'public-ticket-refund-recover':'public-ticket-refund-status',{pack_hash:pack}),
        {pack_hash:pack,...(pending?.purchase?.pack_hash===pack&&pending.purchase.payment_tx?{payment_transaction:pending.purchase.payment_tx}:{}),
          ...(transaction?{transaction_hash:transaction}:{})});
    }finally{await load();}
  }
  const p=pending?.purchase;const intent=pending?.payment_intent;const t=offer?.manifest.terms;
  const showBulk=bulkEnabled&&quantity==='50'&&!p&&!refundState?.pending;
  const currentProgress=paymentProgress?.pack_hash===p?.pack_hash?paymentProgress:undefined;
  const ready=!!inventory&&!p&&inventory.available>0&&!needsReload;
  const completed=ready||refundVerified?4:currentProgress?.state==='finalized'?3:currentProgress?.state==='confirming'?2:p?1:0;
  const summary=busy?actionStatus:updateRequired?'Reload NockApp itself: this page and its background are from different versions.':refundVerified?notice:refundState?.pending?(notice||'Refund authorization is saved. Continue the same refund below; no new wallet signature is needed.'):needsReload?'Saved state could not be checked. Reload it before doing anything else.':ready?`${inventory!.available} tickets ready to use.`
    :hasPaymentAttempt?progressError?progressReason
      :currentProgress?.state==='finalized'?finishing?'Payment finalized. Finishing this purchase…':'Payment finalized. Get your paid tickets below.'
      :currentProgress?.state==='confirming'?'Payment found. Waiting for chain finality; no further payment is needed.'
      :currentProgress?.state==='not-seen'?'Waiting for this saved payment to appear onchain. No payment will be repeated.'
      :'Checking the saved payment onchain…'
    :quote?'Review the exact payment below, then confirm it in MetaMask.':'Review the pack price and spending limit before paying.';
  const purchaseControls=<section aria-label="Review ticket purchase">
    <p>The operator holds prepaid funds and can refuse service or lose them. Once tickets are issued, this pack cannot be cancelled for a refund.</p>
    <label><input type="checkbox" checked={purchaseConsent} onChange={e=>setPurchaseConsent(e.target.checked)}/>I accept this shared pack, price, expiry and prepaid custody risk.</label>
    <label>Maximum execution fee (ETH)<input value={feeLimit} onChange={e=>{setFeeLimit(e.target.value);setQuote(undefined);setFeeConsent(false);}} inputMode="decimal" placeholder="Your spending cap"/></label>
    <p>This is a cap, not a charge. Base data and operator fees are additional; review the full fee in MetaMask.</p>
    <button className="primary" disabled={busy||!purchaseConsent||!feeLimit||!pending||pending.closed_attempts>=8} onClick={()=>void run(reviewPurchase,'Preparing the exact pack and reviewing wallet fees…')}>Review ticket purchase</button>
  </section>;
  return <main className="wallet-authorization ticket-wallet"><h1>Publication tickets</h1>
    <p>Buy a pack to publish anonymously. Your paying wallet is public on Base Sepolia; no Twitter account is needed to buy.</p>
    {bulkEnabled&&!p&&!refundState?.pending&&<label>Tickets to buy<select value={quantity} disabled={bulkActive||busy} onChange={e=>setQuantity(e.target.value)}><option value="50">50 tickets in one payment</option><option value="2">2 tickets</option></select></label>}
    {showBulk&&offer&&<BulkTicketPurchase offer={offer} onActive={setBulkActive} canRefund={!!refundState} onRefresh={()=>void run(async()=>{await load();},'Refreshing your ticket inventory…')}/>}
    {showBulk&&refundState&&<p>The shared refund reserve is capped at {formatEth(refundState.policy.principal_budget_wei)} ETH across at most {refundState.policy.max_refunds} packs. It may not cover your whole purchase; funding and payout are not guaranteed.</p>}
    {!showBulk&&t&&<section className="ticket-price" aria-label="Shared ticket offer"><strong>{t.pack_size} tickets · {formatEth(t.pack_price_wei)} test ETH</strong><p>Plus network fees. Use tickets before {new Date(t.redeem_before*1000).toLocaleString('en-AU',{timeZone:'Australia/Brisbane',timeZoneName:'short'})}.</p></section>}
    {!showBulk&&<section className="ticket-progress" aria-label="Ticket purchase progress" aria-busy={busy}>
      <ol><li>Review</li><li>Pay</li><li>Finalize</li><li>Tickets ready</li></ol>
      <progress max={4} value={busy||!offer&&!error?undefined:completed} aria-label="Ticket purchase completion"/>
      <p role="status">{summary}</p>
      {hasPaymentAttempt&&currentProgress&&<p className="ticket-blocks">Finalized block {currentProgress.finalized_block.toLocaleString()} · Latest block {currentProgress.latest_block.toLocaleString()}
        {currentProgress.payment_block!==null&&<> · Payment block {currentProgress.payment_block.toLocaleString()} ({(currentProgress.payment_block-currentProgress.finalized_block).toLocaleString()} blocks ahead of the finalized checkpoint)</>}</p>}
      {hasPaymentAttempt&&<p>Chain status updates automatically every 30 seconds while this page is visible. Finality advances in batches; there is no fixed countdown.</p>}
    </section>}
    {error&&<p role="alert">{error}</p>}{notice&&<p className="ticket-notice">{notice}</p>}
    {inventory&&<p>{inventory.available} available · {inventory.reserved} assigned to posts <span>(includes completed posts)</span></p>}
    {updateRequired?<button className="primary" disabled={busy} onClick={()=>api().runtime.reload()}>Reload NockApp extension</button>
      :needsReload&&<button className="primary" disabled={busy} onClick={()=>void run(refresh,'Checking the saved purchase without a wallet action…')}>Check saved purchase</button>}
    {!needsReload&&ready&&<>
      <button className="primary" disabled={busy} onClick={()=>void run(async()=>{const tab=await api().tabs.getCurrent();if(tab?.id!==undefined)await api().tabs.remove(tab.id);},'Returning to NockApp…')}>Back to NockApp</button>
      {!showBulk&&<details><summary>Buy another pack</summary>{!quote&&purchaseControls}</details>}
    </>}
    {!showBulk&&!needsReload&&offer&&pending&&!ready&&!hasPaymentAttempt&&!quote&&purchaseControls}
    {!needsReload&&p&&hasPaymentAttempt&&!quote&&!refundState?.pending&&<section aria-label="Finish saved purchase">
      <p>This finishes only your saved pack. It verifies the payment and imports the paid tickets; it does not open MetaMask or send another payment. Issuance permanently prevents cancellation of this pack.</p>
      <button className="primary" disabled={busy||finishing} onClick={()=>{setError('');setFinishing(true);setRefreshProgress(n=>n+1);}}>{finishing?'Finishing automatically…':'Get my tickets'}</button>
    </section>}
    {!needsReload&&refundState?.pending&&<section aria-label="Continue saved refund"><p>Ticket issuance is paused for this saved refund. Continue its exact existing operation without another wallet signature.</p>
      <button className="primary" disabled={busy} onClick={()=>void run(()=>refundCheck(refundState.pending!.pack_hash,true),'Recovering the saved refund and checking its finalized payout…')}>Continue refund</button></section>}
    {quote&&<section aria-label="Reviewed wallet transaction">
      <h2>{quote.kind==='purchase'?'Confirm your purchase':'Review cancellation'}</h2>
      <p>Pack price: {formatEth(BigInt(quote.transaction.value).toString())} test ETH. Execution fee at most {formatEth(quote.execution_fee_wei)} ETH with these parameters.</p>
      <label><input type="checkbox" checked={feeConsent} onChange={e=>setFeeConsent(e.target.checked)}/>I approve this exact transaction and execution fee, and will review additional fees in MetaMask.</label>
      <p>{quote.kind==='purchase'?'After this one payment, the app waits for finality and retrieves your tickets automatically. Keep this tab open.':'This sends a zero-value same-nonce transaction to the saved payer. Cancellation can cost gas and does not establish that the original purchase is unpaid.'}</p>
      <button className="primary" disabled={busy||!feeConsent} onClick={()=>void run(send,'Waiting for your decision in MetaMask…')}>{quote.kind==='purchase'?'Pay in MetaMask':'Send same-nonce cancellation'}</button>
    </section>}
    <details className="ticket-advanced"><summary>Advanced recovery, refunds and payment details</summary>
      <p>Keep the saved purchase if anything fails. A missing wallet reply does not mean payment failed. Never send another payment to fix a missing response.</p>
      <button disabled={busy} onClick={()=>void run(refresh,'Reading your saved purchase…')}>Refresh saved purchase</button>
      {finishing&&<button disabled={busy} onClick={()=>setFinishing(false)}>Pause automatic finishing</button>}
      {hasPaymentAttempt&&<button disabled={busy} onClick={()=>setRefreshProgress(n=>n+1)}>Recheck chain status</button>}
      {t&&<>
        <p>Payment contract: {offer!.manifest.purchase_contract} · Recipient: {t.payment_recipient}</p>
        <p>Purchases close: {new Date(t.purchase_before*1000).toLocaleString('en-AU',{timeZone:'Australia/Brisbane',timeZoneName:'short'})}. Pack price: {t.pack_price_wei} wei.</p>
        <p>Blind tickets separate payment from later redemption; they do not hide IP addresses, timing or small anonymity sets. Tickets are not self-custodial money.</p>
        <p>Only unissued packs can request cancellation. Signing permanently cancels issuance if it has not already won. Buyer network fees are not returned; a signature alone does not confirm payout.</p>
      </>}
    {refundState&&<section aria-label="Refund policy and recovery"><p>Refund reserve: {refundState.policy.vault}. Lifetime reserve limit: {formatEth(refundState.policy.principal_budget_wei)} ETH across at most {refundState.policy.max_refunds} packs. Funding or service failure can delay or prevent payout.</p>
      <p>The refund authority is trusted to check payment and cancellation. It can misuse the capped reserve. The local verifier trusts the configured public RPC's chain and finality view.</p>
      <p>{refundState.completed.length} of {refundState.archive_limit} private refund recovery records retained. A full archive blocks further cancellation; recovery material is never evicted.</p>
      {refundState.pending&&<><p>Saved cancellation authorization: {refundState.pending.pack_hash}. A signature alone does not confirm cancellation or payout.</p>
        <button disabled={busy} onClick={()=>void run(()=>refundCheck(refundState.pending!.pack_hash,true))}>Resume saved refund without wallet</button>
        <button disabled={busy} onClick={()=>void run(()=>refundCheck(refundState.pending!.pack_hash))}>Check pending refund onchain</button></>}
      {refundState.completed.map(r=><div key={r.pack_hash}><p>Saved refund receipt for {r.pack_hash}: {formatEth(r.amount_wei)} ETH. This saved receipt has not been reverified in this view.</p>
        <button disabled={busy} onClick={()=>void run(()=>refundCheck(r.pack_hash,false,r.transaction_hash))}>Reverify saved refund {r.pack_hash.slice(0,10)}</button></div>)}</section>}
      {p&&<section aria-label="Saved ticket purchase"><p>Saved pack: {p.pack_hash}</p>
        <p>{pending!.closed_attempts} of {pending!.attempt_limit} terminal attempts retained. Reaching this bound blocks more attempts and preserves recovery material.</p>
        {intent&&<><p>Saved payer: {intent.payer} · nonce {intent.nonce}.</p>
          <button disabled={busy||finishing||intent.profile!=='nockapp-ticket-wallet-payment-intent-v2'} onClick={()=>void run(find,'Searching the exact saved payment…')}>Find finalized payment</button>
          <p>A relayer can pay after the wallet nonce changes. Closing an unpaid attempt requires a finalized unpaid check after purchases close.</p>
          <label><input type="checkbox" checked={closeConsent} onChange={e=>setCloseConsent(e.target.checked)}/>I request closure of this exact terminal unpaid attempt.</label>
          <button disabled={busy||finishing||!closeConsent||!offer||Date.now()<offer.manifest.terms.purchase_before*1000||intent.profile!=='nockapp-ticket-wallet-payment-intent-v2'} onClick={()=>void run(close,'Checking the finalized unpaid fence before closure…')}>Check and close expired unpaid attempt</button>
        </>}
        <label>Original transaction hash<input value={hash} onChange={e=>setHash(e.target.value)} maxLength={66}/></label>
        <button disabled={busy||finishing||!hash} onClick={()=>void run(recordHash,'Verifying the original transaction against this pack…')}>Recover by original transaction hash</button>
        {p.payment_tx&&<><p>Recorded transaction: {p.payment_tx}. A hash alone does not confirm payment.</p>
          <label><input type="checkbox" checked={refundConsent} disabled={finishing} onChange={e=>setRefundConsent(e.target.checked)}/>I permanently cancel issuance of this unissued paid pack; payout remains unconfirmed.</label>
          <button disabled={busy||finishing||!refundConsent||!!refundState?.pending||!!refundState&&refundState.completed.length>=refundState.archive_limit} onClick={()=>void run(refund,'Preparing explicit permanent cancellation…')}>Sign and record unissued-pack cancellation</button>
        </>}
        {intent?.profile==='nockapp-ticket-wallet-payment-intent-v2'&&<>
          <label>Cancellation execution-fee limit (ETH)<input value={feeLimit} onChange={e=>{setFeeLimit(e.target.value);setQuote(undefined);setFeeConsent(false);}} inputMode="decimal"/></label>
          <label><input type="checkbox" checked={cancelConsent} onChange={e=>setCancelConsent(e.target.checked)}/>I request a zero-value transfer to my own saved payer at the same nonce to cancel an uncertain send. This can cost gas.</label>
          <button disabled={busy||finishing||!feeLimit||!cancelConsent} onClick={()=>void run(()=>review(true),'Reviewing the same-nonce cancellation in MetaMask…')}>Review same-nonce cancellation</button>
        </>}
      </section>}
      {quote&&<p>Exact transaction: {quote.payer} → {quote.transaction.to}; nonce {quote.nonce}; data {quote.transaction.data}.</p>}
    </details>
  </main>;
}
createRoot(document.getElementById('root')!).render(<StrictMode><Tickets/></StrictMode>);
