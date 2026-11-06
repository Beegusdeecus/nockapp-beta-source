import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { canonicalAscii } from '../src/authoredWallet';
import { validateTicketOffer, ticketDigest, validTicketOffer } from '../src/publicTickets';
import { validateBulkPurchase, validBulkPurchase, bulkPackHashes, sendBulkPurchase, type BulkPurchase } from '../src/bulkTickets';
import { bulkPaymentDiagnostic } from '../src/data/bulkPaymentDiagnostic';
import { readWalletDiagnostic, TICKET_WALLET_KEY } from '../src/data/ticketWalletTracking';
import { storage } from '../src/platform/storage';
const f=JSON.parse(readFileSync(new URL('./fixtures/public-tickets-v6-20261101.json',import.meta.url),'utf8'));
const savedStorage={...storage};const savedLocks=Object.getOwnPropertyDescriptor(navigator,'locks');
test.beforeEach(()=>{
  const data=new Map<string,unknown>();storage.get=async<T>(k:string)=>data.get(k) as T;
  storage.set=async(k,v)=>{data.set(k,structuredClone(v));};
  Object.defineProperty(navigator,'locks',{configurable:true,value:{request:async<T>(_k:string,work:()=>Promise<T>)=>work()}});
});
test.afterEach(()=>{Object.assign(storage,savedStorage);if(savedLocks)Object.defineProperty(navigator,'locks',savedLocks);else Reflect.deleteProperty(navigator,'locks');});
async function fixture(seed:number){
  const rawOffer=structuredClone(f.offer);
  Object.assign(rawOffer.manifest.terms,{profile:'nockapp-public-prepaid-batch-offer-v3',payment_receipt_version:2,packs_per_payment:25});
  rawOffer.parameters=createHash('sha256').update('nockapp-ticket-offer-manifest-v3\0'+canonicalAscii(rawOffer.manifest)).digest('hex');
  const offer=await validateTicketOffer(rawOffer,f.scope);
  const packs=Array.from({length:25},(_,i)=>'0x'+(seed+i).toString(16).padStart(64,'0'));
  const total=(25n*BigInt(offer.manifest.terms.pack_price_wei)).toString();
  const raw:BulkPurchase={profile:'nockapp-ticket-bulk-purchase-v2',phase:'armed',batch_id:await ticketDigest({parameters:offer.parameters,packs}),
    ticket_count:50,pack_count:25,imported_tickets:0,settled_tickets:0,refunded_tickets:0,payer:f.rpc.payer,transaction_hash:null,total_price_wei:total,
    calls:[{to:offer.manifest.purchase_contract,value:'0x'+BigInt(total).toString(16),data:'0xfe0ff097'+packs.map(p=>p.slice(2)).join('')}],dispatch_authorized:true};
  return {rawOffer,offer,raw,packs};
}
test('one-call checkout needs no account upgrade or atomic-batch capability',async()=>{
  const {offer,raw,packs}=await fixture(1100);const checked=await validateBulkPurchase(raw,offer);
  expect(bulkPackHashes(checked!)).toEqual(packs);
  const calls:string[]=[];const provider={request:async({method,params}:{method:string;params?:unknown[]})=>{
    calls.push(method);if(method==='eth_accounts')return[f.rpc.payer];if(method==='eth_chainId')return'0x14a34';
    if(method==='wallet_sendCalls'){
      const request=params![0] as any;expect(request.calls).toEqual(raw.calls);expect(request.atomicRequired).toBe(false);
      expect(request.calls).toHaveLength(1);return{id:request.id};
    }
    throw Error('Unexpected wallet call');
  }};
  await sendBulkPurchase(checked!,provider);await expect(sendBulkPurchase(checked!,provider)).rejects.toThrow('saved payment');
  expect(calls).toEqual(['eth_accounts','eth_chainId','wallet_sendCalls']);
  expect(JSON.parse(bulkPaymentDiagnostic(raw)).first_pack_hash).toBe(packs[0]);
});
test('legacy and one-call offer scopes cannot be mixed or inferred',async()=>{
  const {rawOffer,offer,raw}=await fixture(1200);const legacy=await validateTicketOffer(f.offer,f.scope);
  await expect(validateBulkPurchase(raw,legacy)).rejects.toThrow('reviewed ticket offer');
  const wrongDomain={...rawOffer,parameters:createHash('sha256').update('nockapp-ticket-offer-manifest-v1\0'+canonicalAscii(rawOffer.manifest)).digest('hex')};
  await expect(validateTicketOffer(wrongDomain,f.scope)).rejects.toThrow('deployment changed');
  expect(validTicketOffer({...rawOffer,manifest:{...rawOffer.manifest,terms:{...rawOffer.manifest.terms,payment_receipt_version:1}}})).toBe(false);
  await expect(validateBulkPurchase({...raw,profile:'nockapp-ticket-bulk-purchase-v1'},offer)).rejects.toThrow();
});
test('truncated, duplicate, zero, reordered and incorrectly priced commitments fail closed',async()=>{
  const {offer,raw,packs}=await fixture(1300);const call=raw.calls[0];
  for(const data of [call.data.slice(0,-64),'0xfe0ff097'+Array(25).fill(packs[0].slice(2)).join(''),'0xfe0ff097'+'0'.repeat(1600)])
    expect(validBulkPurchase({...raw,calls:[{...call,data}]})).toBe(false);
  for(const change of [{value:'0x1'},{to:'0x'+'12'.repeat(20)},{data:'0xfe0ff097'+[...packs].reverse().map(p=>p.slice(2)).join('')}])
    await expect(validateBulkPurchase({...raw,calls:[{...call,...change}]},offer)).rejects.toThrow('reviewed ticket offer');
});
test('lost response keeps one-call payment fenced after a fresh admission',async()=>{
  const {offer,raw}=await fixture(1400);let sends=0;
  const provider={request:async({method}:{method:string})=>{
    if(method==='eth_accounts')return[f.rpc.payer];if(method==='eth_chainId')return'0x14a34';
    if(method==='wallet_sendCalls'){sends++;throw Error('synthetic-lost-reply');}throw Error('unexpected');
  }};
  await expect(sendBulkPurchase((await validateBulkPurchase(raw,offer))!,provider)).rejects.toThrow('synthetic-lost-reply');
  await expect(sendBulkPurchase((await validateBulkPurchase(raw,offer))!,provider)).rejects.toThrow('saved payment');
  expect(sends).toBe(1);
  const saved=await storage.get<any>(TICKET_WALLET_KEY);
  const diagnostic=await readWalletDiagnostic(raw.batch_id,async()=>({request:async()=>({id:saved.id,chainId:'0x14a34',atomic:false,status:200})}),false);
  expect(diagnostic.state).toBe('included');
  expect((await readWalletDiagnostic(raw.batch_id,async()=>({request:async()=>({id:saved.id,chainId:'0x14a34',atomic:false,status:200})})) ).state).toBe('unavailable');
});
