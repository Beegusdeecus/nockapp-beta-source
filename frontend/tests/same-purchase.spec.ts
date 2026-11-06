import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { validateTicketOffer, ticketDigest } from '../src/publicTickets';
import { validateBulkPurchase } from '../src/bulkTickets';
import { validPublicBody, publicProjection } from '../src/publicDiscussion';
import { samePurchaseCalldata, validSamePurchaseReview, validateSamePurchaseReview, sendSamePurchase, readSamePurchaseRequest, sameWalletCall, SamePurchaseWalletError, SAME_IMPLEMENTATION } from '../src/samePurchase';
import { storage } from '../src/platform/storage';
const f=JSON.parse(readFileSync(new URL('./fixtures/same-purchase-v1.json',import.meta.url),'utf8'));
const original={...storage};const originalLocks=Object.getOwnPropertyDescriptor(navigator,'locks');let data:Map<string,unknown>;
test.beforeEach(()=>{data=new Map();Object.defineProperty(navigator,'locks',{configurable:true,value:{request:async<T>(_name:string,work:()=>Promise<T>)=>work()}});storage.get=async<T>(key:string)=>data.get(key)as T;storage.set=async(key,value)=>{data.set(key,structuredClone(value));};});
test.afterEach(()=>{Object.assign(storage,original);if(originalLocks)Object.defineProperty(navigator,'locks',originalLocks);else Reflect.deleteProperty(navigator,'locks');});
let reviewNumber=0;
async function reviewed(){const offer=await validateTicketOffer(f.offer,f.scope);const b=await validateBulkPurchase(f.purchase,offer);if(!b)throw Error('fixture');const raw=structuredClone(f.review);raw.checked_through.hash='0x'+(++reviewNumber).toString(16).padStart(64,'0');raw.quote_sha256=await ticketDigest(Object.fromEntries(Object.entries(raw).filter(([k])=>k!=='quote_sha256')));return validateSamePurchaseReview(raw,b,offer);}
function provider(overrides:Record<string,unknown>={}){
  const calls:{method:string;params?:unknown[]}[]=[];
  return {calls,request:async(r:{method:string;params?:unknown[]})=>{calls.push(structuredClone(r));if(r.method in overrides)return overrides[r.method];
    if(r.method==='eth_accounts')return[f.review.payer];if(r.method==='eth_chainId')return'0x14a34';
    if(r.method==='eth_getCode')return r.params?.[0]===SAME_IMPLEMENTATION?f.implementation_runtime:'0xef0100'+SAME_IMPLEMENTATION.slice(2);
    if(r.method==='eth_getTransactionCount')return Number(BigInt(f.review.transaction.nonce));
    if(r.method==='eth_getBalance')return'0x1000000000000000000';if(r.method==='eth_call')return'0x';
    if(r.method==='eth_sendTransaction')return f.transaction_hash;throw Error('Unexpected wallet call '+r.method);
  }};
}
async function clock<T>(work:()=>Promise<T>){const now=Date.now;Date.now=()=>f.now*1000;try{return await work();}finally{Date.now=now;}}
test('native-generated quote binds exact original25pack calldata, price, payer and revert mode',async()=>clock(async()=>{
  const q=await reviewed();expect(validSamePurchaseReview(q)).toBe(true);expect(samePurchaseCalldata(f.purchase)).toBe(q.transaction.data);
  expect(validPublicBody('public-ticket-bulk-self-review',{batch_id:f.purchase.batch_id,execution_fee_limit_wei:'100000000000000'})).toBe(true);
  expect(publicProjection('public-ticket-bulk-self-review',q,{batch_id:f.purchase.batch_id,execution_fee_limit_wei:'100000000000000'})).toBe(true);
  const offer=await validateTicketOffer(f.offer,f.scope);const b=(await validateBulkPurchase(f.purchase,offer))!;
  for(const change of [{payer:'0x'+'12'.repeat(20)},{parameters:'ab'.repeat(32)},{transaction:{...q.transaction,data:q.transaction.data.slice(0,-2)+'01'}}]){
    const bad={...q,...change};bad.quote_sha256=await ticketDigest(Object.fromEntries(Object.entries(bad).filter(([k])=>k!=='quote_sha256')));
    await expect(validateSamePurchaseReview(bad,b,offer)).rejects.toThrow('does not match');
  }
}));
test('one reviewed resume sends only the same self-call and never upgrades the account',async()=>clock(async()=>{
  const q=await reviewed();const p=provider();const authorization={profile:'nockapp-same-purchase-dispatch-v1',quote:q,dispatch_authorized:true};
  expect(await sendSamePurchase(q,authorization,p)).toBe(f.transaction_hash);
  const send=p.calls.filter(c=>c.method==='eth_sendTransaction');expect(send).toHaveLength(1);expect(send[0].params).toEqual([q.transaction]);
  expect(p.calls.some(c=>/wallet_sendCalls|sign|switchEthereumChain|addEthereumChain/i.test(c.method))).toBe(false);
  await expect(sendSamePurchase(q,authorization,p)).rejects.toThrow('does not match');
  expect(p.calls.filter(c=>c.method==='eth_sendTransaction')).toHaveLength(1);
}));
test('changed wallet code, account, nonce and malformed authorization prevent any send',async()=>clock(async()=>{
  const q=await reviewed();const auth={profile:'nockapp-same-purchase-dispatch-v1',quote:q,dispatch_authorized:true};
  for(const overrides of [{eth_chainId:'0x1'},{eth_getCode:'0x'},{eth_accounts:['0x'+'12'.repeat(20)]},{eth_getTransactionCount:'0xabcdef'},{eth_getBalance:'0x0'}]){
    const p=provider(overrides);await expect(sendSamePurchase(q,auth,p)).rejects.toThrow();expect(p.calls.some(c=>c.method==='eth_sendTransaction')).toBe(false);
  }
  const p=provider();await expect(sendSamePurchase(q,{...auth,quote:{...q,price_wei:'1'}},p)).rejects.toThrow('does not match');expect(p.calls).toEqual([]);
}));
test('concurrent resume clicks and lost replies preserve the dispatch fence',async()=>clock(async()=>{
  const q=await reviewed();const p=provider();const auth={profile:'nockapp-same-purchase-dispatch-v1',quote:q,dispatch_authorized:true};
  const results=await Promise.allSettled([sendSamePurchase(q,auth,p),sendSamePurchase(q,auth,p)]);
  expect(results.filter(r=>r.status==='fulfilled')).toHaveLength(1);expect(p.calls.filter(c=>c.method==='eth_sendTransaction')).toHaveLength(1);
}));

test('unknown wallet result is saved as an attempted request and cannot auto-send again',async()=>clock(async()=>{
  const q=await reviewed();const p=provider({eth_sendTransaction:null});const auth={profile:'nockapp-same-purchase-dispatch-v1',quote:q,dispatch_authorized:true};
  await expect(sendSamePurchase(q,auth,p)).rejects.toThrow('outcome is unknown');
  await expect(sendSamePurchase(q,auth,p)).rejects.toThrow('does not match');
  expect(p.calls.filter(c=>c.method==='eth_sendTransaction')).toHaveLength(1);
  expect(await readSamePurchaseRequest(q.batch_id)).toMatchObject({quote_sha256:q.quote_sha256,state:'requested',transaction_hash:null});
}));

test('a plain MetaMask error before submission keeps its method/code and never marks a request',async()=>clock(async()=>{
  const q=await reviewed();const p=provider();const originalRequest=p.request;
  p.request=async r=>{if(r.method==='eth_getCode')throw{code:-32602,message:'private provider text must not be shown'};return originalRequest(r);};
  let started=false;
  await expect(sendSamePurchase(q,{profile:'nockapp-same-purchase-dispatch-v1',quote:q,dispatch_authorized:true},p,()=>{started=true;}))
    .rejects.toMatchObject({method:'eth_getCode',code:-32602});
  expect(started).toBe(false);expect(await readSamePurchaseRequest(q.batch_id)).toBeUndefined();
  expect(p.calls.some(c=>c.method==='eth_sendTransaction')).toBe(false);
}));

test('explicit rejection differs from a lost reply and retains older tracking/hash data',async()=>clock(async()=>{
  const legacy={profile:'nockapp-same-purchase-display-v1',batch_id:f.purchase.batch_id,quote_sha256:'ab'.repeat(32),transaction_hash:f.transaction_hash};
  data.set('nockapp:ticket:same-purchase-display:v1',legacy);
  const q=await reviewed();const p=provider();const originalRequest=p.request;
  p.request=async r=>{if(r.method==='eth_sendTransaction')throw{code:4001,message:'rejected'};return originalRequest(r);};
  await expect(sendSamePurchase(q,{profile:'nockapp-same-purchase-dispatch-v1',quote:q,dispatch_authorized:true},p)).rejects.toMatchObject({code:4001});
  expect(await readSamePurchaseRequest(q.batch_id)).toMatchObject({state:'rejected',transaction_hash:null});
  expect(data.get('nockapp:ticket:same-purchase-display:v1')).toEqual(legacy);
}));

test('the legacy pre-send marker remains an unknown outcome, never an authorization to resend',async()=>clock(async()=>{
  const q=await reviewed();data.set('nockapp:ticket:same-purchase-display:v1',{profile:'nockapp-same-purchase-display-v1',batch_id:q.batch_id,quote_sha256:q.quote_sha256,transaction_hash:null});
  expect(await readSamePurchaseRequest(q.batch_id)).toMatchObject({state:'requested'});
  const p=provider();await expect(sendSamePurchase(q,{profile:'nockapp-same-purchase-dispatch-v1',quote:q,dispatch_authorized:true},p)).rejects.toThrow('may already');
  expect(p.calls.some(c=>c.method==='eth_sendTransaction')).toBe(false);
}));

test('read-only wallet timeouts are short and provider payloads never appear in UI errors',async()=>{
  const originalTimeout=globalThis.setTimeout;const waits:number[]=[];
  globalThis.setTimeout=((work:()=>void,ms:number)=>{waits.push(ms);return originalTimeout(work,1);})as typeof setTimeout;
  try{await expect(sameWalletCall({request:()=>new Promise(()=>{})},'eth_getBalance')).rejects.toMatchObject({method:'eth_getBalance',timedOut:true});}
  finally{globalThis.setTimeout=originalTimeout;}
  expect(waits).toEqual([15000]);
  const e=new SamePurchaseWalletError('eth_accounts',-32002);expect(e.message).toContain('existing request');
});
