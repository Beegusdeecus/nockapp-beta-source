import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {canonicalAscii} from '../src/authoredWallet';
import {parseHistoryNumbers,assertHistoryBinding,assertHistoryExport} from '../src/publicHistory';
import type {PublicIntent} from '../src/data/publicIntents';
import type {PublicExport} from '../src/publicDiscussion';
const f=JSON.parse(readFileSync(new URL('./fixtures/public-wallet-evidence-v6-20261101.json',import.meta.url),'utf8'));
function intent():PublicIntent {
  const c=f.request.binding.core;const records=JSON.parse(atob(f.request.binding.history)).records;
  return {scope:f.scope,draft_key:'thread:public-v5:synthetic-history',post:c.post,selection:c.selection,thread:c.thread,references:c.references,
    acknowledged:true,released:false,history:{profile:'nockapp-public-history-plan-v1',records,approve_linking:true}};
}
async function exported(binding:any):Promise<PublicExport>{
  const bytes=new TextEncoder().encode(canonicalAscii({unsigned:{core:binding.core,evidence:{history:binding.history}}}));
  const hash='0x'+[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
  return {profile:'nockapp-public-submission-v5',scope:f.scope,bundle_hash:hash,bundle_base64:btoa(String.fromCharCode(...bytes)),calldata:'0xd9caa3d2'+hash.slice(2),contains_private_key:false,personal_wallet_required:false};
}
test('history input is bounded, distinct and exact',()=>{
  expect(parseHistoryNumbers('')).toEqual([]);expect(parseHistoryNumbers(' 1, 7 ')).toEqual([1,7]);
  for(const s of ['0','01','1,1','1e3','9007199254740992',Array.from({length:16},(_,i)=>i+1).join(',')])expect(()=>parseHistoryNumbers(s)).toThrow();
});
test('actual native history wallet vector matches only the exact consented core and records',()=>{
  const v=intent();expect(()=>assertHistoryBinding(v,f.request.binding)).not.toThrow();
  for(const mutate of [(b:any)=>b.history=null,(b:any)=>b.core.post.body+='changed',(b:any)=>b.core.context.application='0x'+'12'.repeat(32),
    (b:any)=>{const h=JSON.parse(atob(b.history));h.records[0].bundle_hash='0x'+'12'.repeat(32);b.history=btoa(canonicalAscii(h));}]){
    const b=structuredClone(f.request.binding);mutate(b);expect(()=>assertHistoryBinding(v,b)).toThrow('selected authorship links');
  }
  const legacy={...v};delete legacy.history;expect(()=>assertHistoryBinding(legacy,{not:'reinterpreted'})).not.toThrow();
});
test('export checks actual bytes and rejects a missing selected history claim even with a self-consistent hash',async()=>{
  const v=intent();const good=await exported(f.request.binding);await expect(assertHistoryExport(v,good)).resolves.toBeUndefined();
  await expect(assertHistoryExport(v,{...good,bundle_hash:'0x'+'12'.repeat(32)})).rejects.toThrow();
  const missing=await exported({...f.request.binding,history:null});await expect(assertHistoryExport(v,missing)).rejects.toThrow('selected authorship links');
});
test('publication and wallet transport enforce saved history even when called outside the composer',async()=>{
  const {storage}=await import('../src/platform/storage');const {publicOperation,PUBLIC_VERSION}=await import('../src/publicDiscussion');
  const old={...storage};const chrome=Object.getOwnPropertyDescriptor(globalThis,'chrome');const calls:string[]=[];
  const v=intent();const missing=await exported({...f.request.binding,history:null});
  storage.get=async<T>()=>[v] as T;let wallet=false;
  Object.defineProperty(globalThis,'chrome',{configurable:true,value:{runtime:{connect:()=>{
    let listener:(v:unknown)=>void=()=>{};return {onMessage:{addListener:(f:(v:unknown)=>void)=>{listener=f;}},onDisconnect:{addListener:()=>{}},disconnect:()=>{},
      postMessage:(m:any)=>{calls.push(m.operation);listener({version:PUBLIC_VERSION,result:wallet?{...f.request,binding:{...f.request.binding,history:null}}:missing});}};
  }}}});
  try {
    await expect(publicOperation('public-publish',{post_id:v.post.id,approve_publication:true})).rejects.toThrow('selected authorship links');
    expect(calls).toEqual(['public-export-submission']);
    await expect(publicOperation('public-direct-ready',{post_id:v.post.id,approve_publication:true,approve_public_payer:true})).rejects.toThrow('selected authorship links');
    expect(calls).toEqual(['public-export-submission','public-export-submission']);wallet=true;
    await expect(publicOperation('public-wallet-request',{post_id:v.post.id,address:f.request.address,approve_address_disclosure:true})).rejects.toThrow();
    expect(calls).toEqual(['public-export-submission','public-export-submission','public-wallet-request']);
  } finally {Object.assign(storage,old);if(chrome)Object.defineProperty(globalThis,'chrome',chrome);else Reflect.deleteProperty(globalThis,'chrome');}
});
