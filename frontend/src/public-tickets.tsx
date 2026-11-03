import { StrictMode, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { connectBaseWallet } from './authoredWallet';
import { publicOperation, type PublicScope } from './publicDiscussion';
import { validateTicketOffer, validateTicketPurchase, quoteTicketPayment, admitTicketSend, sendTicketPayment,
  ticketDigest, parseEth, formatEth, validateTicketRefund, signTicketRefund,
  type TicketOffer, type TicketPending, type PaymentQuote, type ArmedPurchase } from './publicTickets';
import './tokens.css';
import './styles.css';
import './public-tickets.css';
import { validateRefundState, validateRefundResult, type RefundState } from './publicRefunds';

function Tickets() {
  const [offer,setOffer]=useState<TicketOffer>();const [pending,setPending]=useState<TicketPending>();
  const [refundState,setRefundState]=useState<RefundState>();
  const [quote,setQuote]=useState<PaymentQuote>();const [feeLimit,setFeeLimit]=useState('');const [hash,setHash]=useState('');
  const [purchaseConsent,setPurchaseConsent]=useState(false);const [feeConsent,setFeeConsent]=useState(false);
  const [cancelConsent,setCancelConsent]=useState(false);const [closeConsent,setCloseConsent]=useState(false);const [refundConsent,setRefundConsent]=useState(false);
  const [busy,setBusy]=useState(false);const locked=useRef(false);const [error,setError]=useState('');const [notice,setNotice]=useState('');
  async function load() {
    const caps=await publicOperation<{scope:PublicScope;refund_payout_configured?:boolean}>('public-capabilities');
    const next=await validateTicketOffer(await publicOperation('public-ticket-offer'),caps.scope);
    const state=await publicOperation<TicketPending>('public-ticket-pending');
    if(state.purchase)validateTicketPurchase(state.purchase,next);
    const refunds=caps.refund_payout_configured===true?await validateRefundState(await publicOperation('public-ticket-refund-state'),next,state):undefined;
    setRefundState(refunds);
    setOffer(next);setPending(state);setQuote(undefined);setFeeConsent(false);return {offer:next,pending:state};
  }
  useEffect(()=>{let alive=true;void load().catch(()=>{if(alive)setError('The configured ticket offer or saved purchase is unavailable. Saved state is preserved.');});return()=>{alive=false;};},[]);
  async function run(work:()=>Promise<void>) {
    if(locked.current)return;locked.current=true;setBusy(true);setError('');setNotice('');
    try{await work();}catch(e){setError(e instanceof Error?e.message:'Ticket operation unavailable. Keep the saved purchase.');}
    finally{locked.current=false;setBusy(false);}
  }
  async function refresh() {await load();setNotice('Saved purchase state refreshed. No wallet action was requested.');}
  async function prepare() {
    if(!purchaseConsent||!offer)return;
    await publicOperation('public-ticket-prepare',{approve_purchase:true});await load();setPurchaseConsent(false);
    setNotice('Exact ticket pack saved locally. Review payment before opening a wallet transaction.');
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
    try{
      let armed:ArmedPurchase|undefined;
      if(q.kind==='purchase')armed=admitTicketSend(await publicOperation('public-ticket-arm',{
        pack_hash:q.purchase.pack_hash,payer:q.payer,nonce:q.nonce,approve_payment:true}),q);
      const transactionHash=await sendTicketPayment(q,armed);
      if(q.kind==='purchase')await publicOperation('public-ticket-payment',{pack_hash:q.purchase.pack_hash,transaction_hash:transactionHash});
      setNotice(q.kind==='purchase'?'Transaction hash saved. Wait for finality, then recover the paid tickets.'
        :`Cancellation submitted (${transactionHash}). Check finalized recovery before closing the old attempt.`);
    }finally{await load();}
  }
  async function find() {
    const r=await publicOperation<{search_state:string;receipt_status?:string}>('public-ticket-find');await load();
    setNotice(r.search_state==='transaction-found'?(r.receipt_status==='0x1'?'Finalized transaction found. Recover tickets to verify payment and import the pack.':'Finalized failed transaction found. You may request closure below.')
      :r.search_state==='nonce-consumed-by-other-transaction'?'The saved nonce was used for another transaction. You may request closure below.'
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
    await load();setCloseConsent(false);setCancelConsent(false);setNotice('Saved attempt closed. The same ticket pack is preserved. A new payment requires a separate review.');
  }
  async function recover() {await publicOperation('public-ticket-recover');await load();setNotice('Ticket inventory recovered. Return to NockApp to publish.');}
  async function refund() {
    if(!refundConsent||!offer||!pending?.purchase)return;
    const p=validateTicketPurchase(pending.purchase,offer);const account=await connectBaseWallet();
    const r=await validateTicketRefund(await publicOperation('public-ticket-refund-request'),offer,p,account);
    const signature=await signTicketRefund(r);
    try {
      const reply=await publicOperation('public-ticket-refund-result',{request_sha256:r.request_sha256,signature});
      if(refundState)showRefund(reply,{pack_hash:p.pack_hash,payment_transaction:p.payment_tx!,payer:r.address});
      else setNotice('Cancellation recorded. Payout is not confirmed; this is not a completed refund.');
      setRefundConsent(false);
    }finally{await load();}
  }
  function showRefund(reply:unknown,expected:{pack_hash:string;payment_transaction?:string;payer?:string;transaction_hash?:string}) {
    if(!refundState)throw Error('Pinned refund policy unavailable.');
    const result=validateRefundResult(reply,refundState,expected);
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
  return <main className="wallet-authorization ticket-wallet"><h1>Prepaid publication tickets</h1>
    <p>Base Sepolia test ETH. Buying exposes the paying wallet onchain. Blind tickets separate that payment from later redemption; they do not hide IP addresses, timing or small anonymity sets.</p>
    <p>The operator holds prepaid funds and can refuse service or lose them. Tickets are not self-custodial money. No Twitter account or NockApp identity is needed to buy.</p>
    {t&&<section aria-label="Shared ticket offer"><p>{t.pack_size} tickets for {formatEth(t.pack_price_wei)} ETH ({t.pack_price_wei} wei), plus network fees.</p>
      <p>Payment contract: {offer.manifest.purchase_contract}</p><p>Recipient: {t.payment_recipient}</p>
      <p>Purchases close: {new Date(t.purchase_before*1000).toLocaleString('en-AU',{timeZone:'Australia/Brisbane',timeZoneName:'short'})}. Redeem before: {new Date(t.redeem_before*1000).toLocaleString('en-AU',{timeZone:'Australia/Brisbane',timeZoneName:'short'})}.</p>
      <p>Only unissued packs can request cancellation. Signing authorizes permanent cancellation; the service records it only if issuance has not already won. {refundState?'A refund returns the full pack price to the original payer; buyer network fees are not returned.':'Refund payout is not yet confirmed by this workflow.'}</p></section>}
    {refundState&&<section aria-label="Refund policy and recovery"><p>Refund reserve: {refundState.policy.vault}. Lifetime reserve limit: {formatEth(refundState.policy.principal_budget_wei)} ETH across at most {refundState.policy.max_refunds} packs. Funding or service failure can delay or prevent payout.</p>
      <p>The refund authority is trusted to check payment and cancellation. It can misuse the capped reserve. The local verifier trusts the configured public RPC's chain and finality view.</p>
      <p>{refundState.completed.length} of {refundState.archive_limit} private refund recovery records retained. A full archive blocks further cancellation; recovery material is never evicted.</p>
      {refundState.pending&&<><p>Saved cancellation authorization: {refundState.pending.pack_hash}. A signature alone does not confirm cancellation or payout.</p>
        <button disabled={busy} onClick={()=>void run(()=>refundCheck(refundState.pending!.pack_hash,true))}>Resume saved refund without wallet</button>
        <button disabled={busy} onClick={()=>void run(()=>refundCheck(refundState.pending!.pack_hash))}>Check pending refund onchain</button></>}
      {refundState.completed.map(r=><div key={r.pack_hash}><p>Saved refund receipt for {r.pack_hash}: {formatEth(r.amount_wei)} ETH. This saved receipt has not been reverified in this view.</p>
        <button disabled={busy} onClick={()=>void run(()=>refundCheck(r.pack_hash,false,r.transaction_hash))}>Reverify saved refund {r.pack_hash.slice(0,10)}</button></div>)}</section>}
    {error&&<p role="alert">{error}</p>}{notice&&<p role="status">{notice}</p>}
    <button disabled={busy} onClick={()=>void run(refresh)}>Refresh saved purchase</button>
    {offer&&pending&&!p&&<section><label><input type="checkbox" checked={purchaseConsent} onChange={e=>setPurchaseConsent(e.target.checked)}/>I accept this shared pack, price, expiry and prepaid custody risk.</label>
      <button disabled={busy||!purchaseConsent} onClick={()=>void run(prepare)}>Prepare this ticket pack</button></section>}
    {p&&<section aria-label="Saved ticket purchase"><p>Saved pack: {p.pack_hash}</p>
      <p>{pending.closed_attempts} of {pending.attempt_limit} terminal attempts retained. Reaching this bound blocks more attempts and preserves recovery material.</p>
      {intent&&<><p>Saved payer: {intent.payer} · nonce {intent.nonce}. A missing wallet response does not mean payment failed.</p>
        <button disabled={busy||intent.profile!=='nockapp-ticket-wallet-payment-intent-v2'} onClick={()=>void run(find)}>Find finalized payment</button>
        <label><input type="checkbox" checked={closeConsent} onChange={e=>setCloseConsent(e.target.checked)}/>I request closure of this exact terminal unpaid attempt.</label>
        <button disabled={busy||!closeConsent||intent.profile!=='nockapp-ticket-wallet-payment-intent-v2'} onClick={()=>void run(close)}>Check and close failed attempt</button></>}
      <label>Original transaction hash<input value={hash} onChange={e=>setHash(e.target.value)} maxLength={66}/></label>
      <button disabled={busy||!hash} onClick={()=>void run(recordHash)}>Recover by original transaction hash</button>
      {p.payment_tx&&<><p>Recorded transaction: {p.payment_tx}. This alone does not confirm payment.</p><button disabled={busy||!!refundState?.pending} onClick={()=>void run(recover)}>Recover paid tickets</button>
        <label><input type="checkbox" checked={refundConsent} onChange={e=>setRefundConsent(e.target.checked)}/>I permanently cancel issuance of this unissued paid pack; payout remains unconfirmed.</label>
        <button disabled={busy||!refundConsent||!!refundState?.pending||!!refundState&&refundState.completed.length>=refundState.archive_limit} onClick={()=>void run(refund)}>Sign and record unissued-pack cancellation</button></>}
      <label>Execution-fee limit (ETH)<input value={feeLimit} onChange={e=>{setFeeLimit(e.target.value);setQuote(undefined);setFeeConsent(false);}} inputMode="decimal" placeholder="Enter your limit"/></label>
      <p>This limit covers execution gas only. Base also charges L1 data and potentially operator fees. Review the full fee and exact transaction in MetaMask before confirming. Failed or cancellation transactions can cost gas.</p>
      {!intent&&!p.payment_tx&&<button disabled={busy||!feeLimit||pending.closed_attempts>=8} onClick={()=>void run(()=>review())}>Connect MetaMask and review payment</button>}
      {intent?.profile==='nockapp-ticket-wallet-payment-intent-v2'&&<><label><input type="checkbox" checked={cancelConsent} onChange={e=>setCancelConsent(e.target.checked)}/>I request a zero-value transfer to my own saved payer at the same nonce to cancel an uncertain send. This can cost gas.</label>
        <button disabled={busy||!feeLimit||!cancelConsent} onClick={()=>void run(()=>review(true))}>Review same-nonce cancellation</button></>}
    </section>}
    {quote&&<section aria-label="Reviewed wallet transaction"><p>{quote.kind==='purchase'?'Purchase':'Cancellation'} from {quote.payer} to {quote.transaction.to}; nonce {quote.nonce}.</p>
      <p>Value: {formatEth(BigInt(quote.transaction.value).toString())} ETH. Execution fee at most {formatEth(quote.execution_fee_wei)} ETH with these parameters.</p>
      <p>Data: {quote.transaction.data}</p><label><input type="checkbox" checked={feeConsent} onChange={e=>setFeeConsent(e.target.checked)}/>I approve this exact transaction and execution fee, and will review additional fees in MetaMask.</label>
      <button disabled={busy||!feeConsent} onClick={()=>void run(send)}>{quote.kind==='purchase'?'Pay for this exact ticket pack':'Send same-nonce cancellation'}</button></section>}
    <p>Keep the saved purchase if anything fails. Refresh and recover; do not create another payment to resolve a missing response.</p>
  </main>;
}
createRoot(document.getElementById('root')!).render(<StrictMode><Tickets/></StrictMode>);
