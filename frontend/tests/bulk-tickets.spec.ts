import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { validBulkPurchase, validateBulkPurchase, requireAtomicWallet, sendBulkPurchase, type BulkPurchase } from '../src/bulkTickets';
import { validateTicketOffer, ticketDigest } from '../src/publicTickets';
import { validPublicBody, publicProjection } from '../src/publicDiscussion';
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
    if(input.method==='wallet_sendCalls'){if(lost)throw Error('synthetic-wallet-reply-lost');return{id:'0x'+'ab'.repeat(32)};}
    throw Error('Unexpected wallet method');
  }};
}
test('50 tickets dispatch one exact atomic payment, with no transaction loop or second dispatch',async()=>{
  const {offer,raw}=await sample(100);const admitted=await validateBulkPurchase(raw,offer);expect(admitted).toBeDefined();
  const p=provider(f.rpc.payer);await sendBulkPurchase(admitted!,p);
  const sends=p.calls.filter(c=>c.method==='wallet_sendCalls');expect(sends).toHaveLength(1);
  expect(sends[0].params).toEqual([{version:'2.0.0',chainId:'0x14a34',from:f.rpc.payer,atomicRequired:true,calls:raw.calls}]);
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
