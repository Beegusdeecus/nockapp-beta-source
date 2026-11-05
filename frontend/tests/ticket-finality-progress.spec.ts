import {test,expect} from '@playwright/test';
import {storage} from '../src/platform/storage';
import {observeTicketFinality,TICKET_FINALITY_KEY} from '../src/data/ticketFinalityProgress';
import type {TicketPaymentProgress} from '../src/publicDiscussion';
const progress=(f=100,target=110):TicketPaymentProgress=>({profile:'nockapp-ticket-payment-progress-v1',pack_hash:'0x'+'12'.repeat(32),state:'confirming',latest_block:120,finalized_block:f,payment_block:target});
async function isolated(work:(data:Map<string,unknown>)=>Promise<void>){
 const old={...storage};const locks=Object.getOwnPropertyDescriptor(navigator,'locks');const data=new Map<string,unknown>([['private-state-sentinel',{preserve:true}]]);
 Object.defineProperty(navigator,'locks',{configurable:true,value:{request:async<T>(_name:string,f:()=>Promise<T>)=>f()}});
 storage.get=async<T>(key:string)=>structuredClone(data.get(key)) as T;storage.set=async(key,value)=>{data.set(key,structuredClone(value));};
 try{await work(data);expect(data.get('private-state-sentinel')).toEqual({preserve:true});}finally{Object.assign(storage,old);if(locks)Object.defineProperty(navigator,'locks',locks);else Reflect.deleteProperty(navigator,'locks');}
}
test('finality measures the observed payment gap, survives a new observer and never reaches100 before verified finality',async()=>isolated(async()=>{
 expect(await observeTicketFinality('ab'.repeat(32),progress())).toBe(0);
 expect(await observeTicketFinality('ab'.repeat(32),progress(105))).toBe(50);
 expect(await observeTicketFinality('ab'.repeat(32),progress(109))).toBe(90);
 expect(await observeTicketFinality('ab'.repeat(32),{...progress(),state:'finalized',payment_block:null})).toBe(100);
 expect(await observeTicketFinality('ab'.repeat(32),{...progress(),state:'not-seen',payment_block:null})).toBeUndefined();
}));
test('foreign batches, changed payment blocks, malformed caches and checkpoint regression start a new display baseline',async()=>isolated(async data=>{
 await observeTicketFinality('ab'.repeat(32),progress());expect(await observeTicketFinality('cd'.repeat(32),progress(105))).toBe(0);
 expect(await observeTicketFinality('cd'.repeat(32),progress(106,115))).toBe(0);
 expect(await observeTicketFinality('cd'.repeat(32),progress(100,115))).toBe(0);
 data.set(TICKET_FINALITY_KEY,{profile:'forged',start:-10000});expect(await observeTicketFinality('cd'.repeat(32),progress(105))).toBe(0);
 expect(Object.keys(data.get(TICKET_FINALITY_KEY)as object).sort()).toEqual(['batch','pack_hash','profile','start','target']);
}));
test('failed display storage cannot block finalized payment recovery or invent progress for missing payments',async()=>isolated(async()=>{
 storage.set=async()=>{throw Error('synthetic-full-display-storage');};
 expect(await observeTicketFinality('ab'.repeat(32),progress())).toBeUndefined();
 expect(await observeTicketFinality('ab'.repeat(32),{...progress(),state:'finalized',payment_block:null})).toBe(100);
}));
