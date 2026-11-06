import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { validBulkPurchase, validateBulkPurchase, requireAtomicWallet, sendBulkPurchase, type BulkPurchase } from '../src/bulkTickets';
import { validateTicketOffer, ticketDigest } from '../src/publicTickets';
import { validPublicBody, publicProjection } from '../src/publicDiscussion';
import { TICKET_WALLET_KEY, readWalletDiagnostic } from '../src/data/ticketWalletTracking';
import { storage } from '../src/platform/storage';
const originalStorage={...storage};const originalLocks=Object.getOwnPropertyDescriptor(navigator,'locks');
test.beforeEach(()=>{Object.defineProperty(navigator,'locks',{configurable:true,value:{request:async<T>(_key:string,work:()=>Promise<T>)=>work()}});const data=new Map<string,unknown>();storage.get=async<T>(key:string)=>data.get(key) as T;storage.set=async(key,value)=>{data.set(key,structuredClone(value));};});
test.afterEach(()=>{Object.assign(storage,originalStorage);if(originalLocks)Object.defineProperty(navigator,'locks',originalLocks);else Reflect.deleteProperty(navigator,'locks');});
const f=JSON.parse(readFileSync(new URL('./fixtures/public-tickets-v6-20261101.json',import.meta.url),'utf8'));
async function sample(seed:number){
  const offer=await validateTicketOffer(f.offer,f.scope);
  const calls=Array.from({length:25},(_,i)=>({to:offer.manifest.purchase_contract,value:'0x'+BigInt(offer.manifest.terms.pack_price_wei).toString(16),data:'0x9c9a1061'+(seed+i).toString(16).padStart(64,'0')}));
  const raw:BulkPurchase={profile:'nockapp-ticket-bulk-purchase-v1',phase:'armed',batch_id:await ticketDigest({parameters:offer.parameters,packs:calls.map(c=>'0x'+c.data.slice(-64))}),ticket_count:50,pack_count:25,imported_tickets:0,settled_tickets:0,refunded_tickets:0,payer:f.rpc.payer,transaction_hash:null,total_price_wei:(25n*BigInt(offer.manifest.terms.pack_price_wei)).toString(),calls,dispatch_authorized:true};
  return {offer,raw};
}
function provider(payer:string,status='supported',lost=false){
  const calls:{method:string;params?:unknown[]}[]=[];
  return {calls,request:async(input:{method:string;params?:unknown[]})=>{
    calls.push(input);
    if(input.method==='eth_accounts')return[payer];if(input.method==='eth_chainId')return'0x14a34';
    if(input.method==='wallet_getCapabilities')return{'0x14a34':{atomic:{status}}};
    if(input.method==='wallet_sendCalls'){if(lost)throw Error('synthetic-wallet-reply-lost');return{id:(input.params![0] as any).id};}
    throw Error('Unexpected wallet method');
  }};
}
test('50 tickets dispatch one exact atomic payment, with no transaction loop or second dispatch',async()=>{
  const {offer,raw}=await sample(100);const admitted=await validateBulkPurchase(raw,offer);expect(admitted).toBeDefined();
  const p=provider(f.rpc.payer);await sendBulkPurchase(admitted!,p);
  const sends=p.calls.filter(c=>c.method==='wallet_sendCalls');expect(sends).toHaveLength(1);
  expect(sends[0].params).toEqual([{version:'2.0.0',id:expect.stringMatching(/^0x[0-9a-f]{64}$/),chainId:'0x14a34',from:f.rpc.payer,atomicRequired:true,calls:raw.calls}]);
  await expect(sendBulkPurchase(admitted!,p)).rejects.toThrow('saved payment');
  expect(p.calls.some(c=>c.method==='eth_sendTransaction')).toBe(false);
});
test('lost wallet reply stays uncertain and cannot trigger a second send or sequential fallback',async()=>{
  const {offer,raw}=await sample(200);const admitted=await validateBulkPurchase(raw,offer);const p=provider(f.rpc.payer,'supported',true);
  await expect(sendBulkPurchase(admitted!,p)).rejects.toThrow('synthetic-wallet-reply-lost');
  await expect(sendBulkPurchase(admitted!,p)).rejects.toThrow('saved payment');
  expect(p.calls.filter(c=>c.method==='wallet_sendCalls')).toHaveLength(1);expect(p.calls.some(c=>c.method==='eth_sendTransaction')).toBe(false);
});
test('unsupported or upgrade-required atomic wallets cannot silently become 25 payments or be upgraded',async()=>{
  for(const status of ['unsupported','ready']){
    const p=provider(f.rpc.payer,status);await expect(requireAtomicWallet(f.rpc.payer,p)).rejects.toThrow('has not enabled');
    expect(p.calls.map(c=>c.method)).toEqual(['wallet_getCapabilities']);
  }
});
test('batch scope, total, private fields and exact native consent are validated',async()=>{
  const {offer,raw}=await sample(300);expect(validBulkPurchase(raw)).toBe(true);
  for(const change of [{total_price_wei:'1'},{batch_id:'f'.repeat(64)},{calls:raw.calls.map(c=>({...c,to:'0x'+'12'.repeat(20)}))}])
    await expect(validateBulkPurchase({...raw,...change},offer)).rejects.toThrow('reviewed ticket offer');
  expect(validBulkPurchase({...raw,requests:['PRIVATE']})).toBe(false);
  await expect(sendBulkPurchase(raw,provider(f.rpc.payer))).rejects.toThrow('saved payment');
  expect(validPublicBody('public-ticket-bulk-prepare',{ticket_count:50,approve_purchase:true})).toBe(true);
  expect(validPublicBody('public-ticket-bulk-prepare',{ticket_count:50,approve_purchase:1})).toBe(false);
  expect(publicProjection('public-ticket-bulk-arm',raw,{batch_id:raw.batch_id,payer:raw.payer})).toBe(true);
  expect(publicProjection('public-ticket-bulk-status',raw)).toBe(false);
  expect(publicProjection('public-ticket-bulk-arm',{...raw,dispatch_authorized:false},{batch_id:raw.batch_id,payer:raw.payer})).toBe(false);
});

test('concurrent dispatch callers cannot send the same batch twice after asynchronous wallet checks',async()=>{
  const {offer,raw}=await sample(400);const a=await validateBulkPurchase(raw,offer),b=await validateBulkPurchase(raw,offer);const p=provider(f.rpc.payer);
  const results=await Promise.allSettled([sendBulkPurchase(a!,p),sendBulkPurchase(b!,p)]);
  expect(results.filter(r=>r.status==='fulfilled')).toHaveLength(1);
  expect(p.calls.filter(c=>c.method==='wallet_sendCalls')).toHaveLength(1);
});

test('tracking ID is durable before the wallet sees a request and survives its lost reply',async()=>{
 const {offer,raw}=await sample(500);const admitted=await validateBulkPurchase(raw,offer);const p=provider(f.rpc.payer,'supported',true);const request=p.request;
 p.request=async input=>{if(input.method==='wallet_sendCalls'){const saved=await storage.get<any>(TICKET_WALLET_KEY);expect(saved.id).toBe((input.params![0] as any).id);expect(saved.batch).toBe(raw.batch_id);}return request(input);};
 await expect(sendBulkPurchase(admitted!,p)).rejects.toThrow('synthetic-wallet-reply-lost');
 const saved=await storage.get<any>(TICKET_WALLET_KEY);expect(saved.id).toMatch(/^0x[0-9a-f]{64}$/);
 const status=await readWalletDiagnostic(raw.batch_id,async()=>({request:async input=>{expect(input.method).toBe('wallet_getCallsStatus');expect(input.params).toEqual([saved.id]);return{id:saved.id,chainId:'0x14a34',atomic:true,status:100};}}));
 expect(status.state).toBe('pending');expect(p.calls.filter(c=>c.method==='wallet_sendCalls')).toHaveLength(1);
});
test('failed durable storage stops before any payment request reaches the wallet',async()=>{
 const {offer,raw}=await sample(600);const admitted=await validateBulkPurchase(raw,offer);const p=provider(f.rpc.payer);storage.set=async()=>{throw Error('synthetic-disk-full');};
 await expect(sendBulkPurchase(admitted!,p)).rejects.toThrow('No wallet payment was requested');expect(p.calls.some(c=>c.method==='wallet_sendCalls')).toBe(false);
});

test('earlier checkout recovery never admits preparation, rearming or a replacement batch',async()=>{
  const {offer,raw}=await sample(700);delete raw.dispatch_authorized;
  const body={parameters:offer.parameters,operation:'public-ticket-bulk-recover',body:{batch_id:raw.batch_id,approve_import:true}};
  expect(validPublicBody('public-ticket-earlier-recovery',body)).toBe(true);
  expect(publicProjection('public-ticket-earlier-recovery',raw,body)).toBe(true);
  expect(publicProjection('public-ticket-earlier-recovery',{...raw,batch_id:'ab'.repeat(32)},body)).toBe(false);
  for(const operation of ['public-ticket-bulk-arm','public-ticket-bulk-prepare','public-ticket-payment','public-ticket-earlier-recovery']){
    expect(validPublicBody('public-ticket-earlier-recovery',{...body,operation})).toBe(false);
  }
  const snapshot={profile:'nockapp-earlier-ticket-purchases-v1',purchases:[{parameters:offer.parameters,offer,purchase:raw}]};
  expect(publicProjection('public-ticket-earlier-status',snapshot)).toBe(true);
  expect(publicProjection('public-ticket-earlier-status',{...snapshot,purchases:[...snapshot.purchases,...snapshot.purchases]})).toBe(false);
  expect(publicProjection('public-ticket-earlier-status',{...snapshot,purchases:[{...snapshot.purchases[0],parameters:'ab'.repeat(32)}]})).toBe(false);
  expect(publicProjection('public-ticket-earlier-status',{...snapshot,purchases:[{...snapshot.purchases[0],purchase:{...raw,dispatch_authorized:true}}]})).toBe(false);
});

test('ticket page snapshot keeps strict admission and exact payment-hash binding',async()=>{
  const {offer,raw}=await sample(900);delete raw.dispatch_authorized;
  const capabilities={configured:true,protocol:5,scope:f.scope,verifier_release:12,publication_mode:'tickets',anonymous_ticket_packs:true,follower_proof_configured:true,source_enrollment_configured:true,historical_issuer_views:true,refund_payout_configured:false,ticket_page_snapshot:true};
  const t=offer.manifest.terms;
  const inventory={profile:'nockapp-protected-ticket-wallet-v1',initialized:true,available:0,reserved:6,purchase_pending:true,can_purchase:false,can_redeem:true,pack_size:2,pack_price_wei:t.pack_price_wei,purchase_before:t.purchase_before,redeem_before:t.redeem_before,refund_policy:t.refund_policy,prepaid_custody:true};
  const snapshot={profile:'nockapp-ticket-page-v1',capabilities,offer,bulk:{profile:raw.profile,phase:'none'},pending:f.empty,refund:null,inventory,earlier:{profile:'nockapp-earlier-ticket-purchases-v1',purchases:[{parameters:offer.parameters,offer,purchase:raw}]}};
  expect(publicProjection('public-ticket-page',snapshot)).toBe(true);
  expect(publicProjection('public-ticket-page',{...snapshot,inventory:{...inventory,initialized:false}})).toBe(false);
  expect(publicProjection('public-ticket-page',{...snapshot,capabilities:{...capabilities,ticket_page_snapshot:false}})).toBe(false);
  const body={batch_id:raw.batch_id,transaction_hash:f.paid.payment_tx,approve_recovery:true};
  expect(validPublicBody('public-ticket-bulk-record-payment',body)).toBe(true);
  expect(validPublicBody('public-ticket-bulk-record-payment',{...body,approve_recovery:false})).toBe(false);
  expect(publicProjection('public-ticket-bulk-record-payment',{...raw,phase:'importing',transaction_hash:f.paid.payment_tx},body)).toBe(true);
  expect(publicProjection('public-ticket-bulk-record-payment',{...raw,transaction_hash:'0x'+'ab'.repeat(32)},body)).toBe(false);
  if(process.env.NOCKAPP_FROZEN_TICKET_PAGE){
    const actual=JSON.parse(readFileSync(process.env.NOCKAPP_FROZEN_TICKET_PAGE,'utf8'));
    expect(actual.empty_private_mounts&&actual.keyring_disabled&&!actual.owner_helper_invoked).toBe(true);
    expect(publicProjection('public-capabilities',actual.capabilities)).toBe(true);
    expect(publicProjection('public-ticket-page',actual.snapshot)).toBe(true);
  }
});
