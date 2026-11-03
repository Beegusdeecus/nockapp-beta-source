import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { validateTicketOffer, validateTicketPurchase, validTicketPending, quoteTicketPayment, admitTicketSend, sendTicketPayment,
  validateTicketRefund, signTicketRefund, parseEth } from '../src/publicTickets';
import { publicProjection, validPublicBody, attachPublicDiscussion, PUBLIC_VERSION } from '../src/publicDiscussion';
import type { WalletProvider } from '../src/publicWallet';
const f=JSON.parse(readFileSync(new URL('./fixtures/public-tickets-v6-20261101.json',import.meta.url),'utf8'));
function provider(changes:Record<string,unknown>={}) {
  const calls:{method:string;params?:unknown[]}[]=[];
  const p:WalletProvider={request:async r=>{
    calls.push(structuredClone(r));if(r.method in changes)return changes[r.method];
    if(['eth_accounts','eth_requestAccounts'].includes(r.method))return[f.rpc.payer];
    if(r.method==='eth_chainId')return'0x14a34';
    if(r.method==='eth_getBlockByNumber')return f.rpc.anchor;
    if(r.method==='eth_getCode')return f.rpc.runtime;
    if(r.method==='eth_call')return f.rpc.contract_calls[(r.params![0] as any).data];
    if(r.method==='eth_getTransactionCount')return '0x'+f.armed.payment_intent.nonce.toString(16);
    if(r.method==='eth_estimateGas')return'0xea60';if(r.method==='eth_gasPrice')return'0x3b9aca00';
    if(r.method==='eth_sendTransaction')return f.paid.payment_tx;
    if(r.method==='eth_signTypedData_v4')return f.refund_signature;
    throw Error('unexpected wallet method');
  }};return {p,calls};
}
async function prepared(){const offer=await validateTicketOffer(f.offer,f.scope);return{offer,purchase:validateTicketPurchase(f.prepared,offer)};}
async function time(work:()=>Promise<void>){const old=Date.now;Date.now=()=>f.now*1000;try{await work();}finally{Date.now=old;}}

test('actual native offer, pending states, payment and refund projections are public and exact',async()=>{
  for(const v of [f.empty,f.pending_prepared,f.pending_armed,f.pending_paid,f.complete])expect(validTicketPending(v)).toBe(true);
  for(const [op,value,body] of [['public-ticket-offer',f.offer,{}],['public-ticket-pending',f.pending_paid,{}],
    ['public-ticket-arm',f.armed,f.arm_body],['public-ticket-payment',f.paid,f.payment_body],['public-ticket-find',f.found,{}],
    ['public-ticket-refund-request',f.refund_request,{}]] as [string,any,any][]){
    expect(validPublicBody(op,body),op).toBe(true);expect(publicProjection(op,value,body),op).toBe(true);
    expect(publicProjection(op,{...value,secret:'forbidden'},body),op).toBe(false);
  }
  const {offer,purchase}=await prepared();expect(Object.isFrozen(offer.manifest.terms)).toBe(true);expect(purchase.pack_hash).toBe(f.prepared.pack_hash);
});
test('changed shared price, key, scope, currency and native transaction cannot reach payment admission',async()=>{
  for(const change of [(v:any)=>v.manifest.terms.pack_price_wei='1',(v:any)=>v.manifest.terms.profile='nockapp-public-prepaid-offer-v1',
    (v:any)=>v.manifest.terms.ticket_spki='AA==',(v:any)=>v.manifest.purchase_contract='0x'+'12'.repeat(20)]){
    const bad=structuredClone(f.offer);change(bad);await expect(validateTicketOffer(bad,f.scope)).rejects.toThrow();
  }
  const {offer}=await prepared();
  for(const change of [{value:'0x1'},{to:'0x'+'12'.repeat(20)},{data:'0x'},{chain_id:1}])
    expect(()=>validateTicketPurchase({...f.prepared,transaction:{...f.prepared.transaction,...change}},offer)).toThrow();
  await expect(validateTicketOffer(f.offer,{...f.scope,application:'0x'+'12'.repeat(32)})).rejects.toThrow();
});
test('only the reviewed quote and one-shot native dispatch can send the exact purchase',async()=>time(async()=>{
  const {purchase}=await prepared();const {p,calls}=provider();
  const q=await quoteTicketPayment(purchase,f.rpc.payer,parseEth('0.001'),p);
  await expect(sendTicketPayment(q,f.armed,p)).rejects.toThrow('dispatch');
  const armed=admitTicketSend(f.armed,q);const other=await quoteTicketPayment(purchase,f.rpc.payer,parseEth('0.001'),p);
  await expect(sendTicketPayment(other,armed,p)).rejects.toThrow('dispatch');
  expect(await sendTicketPayment(q,armed,p)).toBe(f.paid.payment_tx);
  const send=calls.filter(r=>r.method==='eth_sendTransaction');expect(send).toHaveLength(1);
  expect(send[0].params).toEqual([q.transaction]);expect(q.transaction.data).toBe(f.prepared.transaction.data);
  expect(q.transaction.value).toBe(f.prepared.transaction.value);expect(BigInt(q.transaction.gas)).toBeLessThanOrEqual(200000n);
  await expect(sendTicketPayment(q,armed,p)).rejects.toThrow();expect(calls.filter(r=>r.method==='eth_sendTransaction')).toHaveLength(1);
  expect(calls.some(r=>r.method==='eth_signTypedData_v4')).toBe(false);
}));
test('numeric MetaMask replies and padded hex produce the same exact one-shot ticket purchase',async()=>time(async()=>{
  for(const replies of [
    {eth_getTransactionCount:f.armed.payment_intent.nonce,eth_estimateGas:60000,eth_gasPrice:1000000000},
    {eth_getTransactionCount:'0x00'+f.armed.payment_intent.nonce.toString(16).toUpperCase(),eth_estimateGas:'0x00EA60',eth_gasPrice:'0x003B9ACA00'},
  ]) {
    const {purchase}=await prepared();const {p,calls}=provider(replies);
    const quote=await quoteTicketPayment(purchase,f.rpc.payer,parseEth('0.001'),p);
    expect(quote.nonce).toBe(f.armed.payment_intent.nonce);
    expect(quote.transaction).toMatchObject({nonce:'0x'+quote.nonce.toString(16),gas:'0x11940',gasPrice:'0x3b9aca00',
      value:f.prepared.transaction.value,data:f.prepared.transaction.data,to:f.prepared.transaction.to});
    const armed=admitTicketSend(f.armed,quote);expect(await sendTicketPayment(quote,armed,p)).toBe(f.paid.payment_tx);
    await expect(sendTicketPayment(quote,armed,p)).rejects.toThrow('dispatch');
    expect(calls.filter(r=>r.method==='eth_sendTransaction')).toHaveLength(1);
  }
}));
test('unsafe wallet numbers and coercible values cannot prepare a ticket payment',async()=>time(async()=>{
  const {purchase}=await prepared();
  for(const field of ['eth_getTransactionCount','eth_estimateGas','eth_gasPrice']) {
    for(const value of [Number.MAX_SAFE_INTEGER+1,-1,-0,1.5,NaN,Infinity,'1','0x','0x'+'1'.repeat(65),null,true,{valueOf:()=>1}]) {
      const {p,calls}=provider({[field]:value});
      await expect(quoteTicketPayment(purchase,f.rpc.payer,parseEth('0.001'),p)).rejects.toThrow();
      expect(calls.some(r=>r.method==='eth_sendTransaction')).toBe(false);
    }
  }
}));
test('an invalid nonce on final recheck consumes the ticket dispatch without sending or retrying',async()=>time(async()=>{
  const {purchase}=await prepared();const quote=await quoteTicketPayment(purchase,f.rpc.payer,parseEth('0.001'),provider().p);
  const armed=admitTicketSend(f.armed,quote);const {p,calls}=provider({eth_getTransactionCount:Number.MAX_SAFE_INTEGER+1});
  await expect(sendTicketPayment(quote,armed,p)).rejects.toThrow('invalid transaction nonce');
  await expect(sendTicketPayment(quote,armed,provider().p)).rejects.toThrow('dispatch');
  expect(calls.some(r=>r.method==='eth_sendTransaction')).toBe(false);
}));
test('code, account, nonce and fee-limit failures prevent a send, including late reply ambiguity',async()=>time(async()=>{
  const {purchase}=await prepared();
  for(const changes of [{'eth_getCode':'0x00'},{'eth_accounts':['0x'+'12'.repeat(20)]},{'eth_chainId':'0x1'},{'eth_estimateGas':'0xffffff'}]){
    const {p,calls}=provider(changes);await expect(quoteTicketPayment(purchase,f.rpc.payer,parseEth('0.001'),p)).rejects.toThrow();
    expect(calls.some(r=>r.method==='eth_sendTransaction')).toBe(false);
  }
  await expect(quoteTicketPayment(purchase,f.rpc.payer,'1',provider().p)).rejects.toThrow('limit');
  for(const changes of [{'eth_getTransactionCount':'0x123'},{'eth_sendTransaction':'lost-response'}]){
    const q=await quoteTicketPayment(purchase,f.rpc.payer,parseEth('0.001'),provider().p);const armed=admitTicketSend(f.armed,q);
    const {p,calls}=provider(changes);await expect(sendTicketPayment(q,armed,p)).rejects.toThrow();
    await expect(sendTicketPayment(q,armed,p)).rejects.toThrow('dispatch');expect(calls.filter(r=>r.method==='eth_sendTransaction').length).toBeLessThanOrEqual(1);
  }
}));
test('cancellation sends zero only to the saved payer with the same nonce and cannot auto-repeat',async()=>time(async()=>{
  for(const replies of [{},{eth_getTransactionCount:f.armed.payment_intent.nonce,eth_gasPrice:1000000000}]) {
    const {purchase}=await prepared();const {p,calls}=provider(replies);
    const q=await quoteTicketPayment(purchase,f.rpc.payer,parseEth('0.001'),p,f.armed.payment_intent);
    expect(q.kind).toBe('cancel');expect(q.transaction).toMatchObject({to:f.rpc.payer,value:'0x0',data:'0x',nonce:'0x'+f.arm_body.nonce.toString(16)});
    await sendTicketPayment(q,undefined,p);await expect(sendTicketPayment(q,undefined,p)).rejects.toThrow();
    expect(calls.filter(r=>r.method==='eth_sendTransaction')).toHaveLength(1);
  }
}));
test('refund signatures bind exact original payer, offer, payment and irreversible cancellation purpose',async()=>{
  const {offer}=await prepared();const purchase=validateTicketPurchase(f.pending_paid.purchase,offer);
  const r=await validateTicketRefund(f.refund_request,offer,purchase,f.rpc.payer);const {p,calls}=provider();
  expect(await signTicketRefund(r,p)).toBe(f.refund_signature);
  expect(JSON.parse(calls.at(-1)!.params![1] as string)).toEqual(f.refund_request.typed_data);
  expect(calls.map(r=>r.method)).toEqual(['eth_accounts','eth_chainId','eth_signTypedData_v4']);
  await expect(signTicketRefund(r,p)).rejects.toThrow();
  const bad=structuredClone(f.refund_request);bad.typed_data.message.paymentTransaction='0x'+'12'.repeat(32);
  await expect(validateTicketRefund(bad,offer,purchase,f.rpc.payer)).rejects.toThrow();
  await expect(validateTicketRefund(f.refund_request,offer,purchase,'0x'+'12'.repeat(20))).rejects.toThrow();
});
test('fee amounts use exact decimal arithmetic and reject ambiguous or excessive values',()=>{
  expect(parseEth('0.000000000000000001')).toBe('1');expect(parseEth('1.000000000000000001')).toBe('1000000000000000001');
  for(const s of ['0','1e-3','-1',' 1','00.1','0.0000000000000000001'])expect(()=>parseEth(s)).toThrow();
});
test('ticket-page authority cannot reach post signing or identity and side panel cannot arm payments',()=>{
  for(const role of ['tickets','sidepanel','post']){
    const listeners:((m:unknown)=>void)[]=[];const replies:any[]=[];
    const ui={onMessage:{addListener:(fn:(m:unknown)=>void)=>listeners.push(fn)},onDisconnect:{addListener:()=>{}},postMessage:(m:any)=>replies.push(m)} as unknown as chrome.runtime.Port;
    attachPublicDiscussion(ui,role==='post'?'22222222-2222-4222-8222-222222222222':undefined,role==='tickets');
    const operations=role==='tickets'?[['public-initialize-identity',{approve_private_key_setup:true}],['public-outbox',{after:0,limit:4}]]
      :[['public-ticket-arm',f.arm_body],['public-ticket-refund-request',{}],['public-ticket-refund-recover',{pack_hash:f.prepared.pack_hash}],['public-ticket-refund-status',{pack_hash:f.prepared.pack_hash}]];
    for(const [operation,body] of operations)listeners.forEach(fn=>fn({version:PUBLIC_VERSION,operation,body}));
    expect(replies).toHaveLength(operations.length);expect(replies.every(r=>r.error==='message-schema')).toBe(true);
  }
});
