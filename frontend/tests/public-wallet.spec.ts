import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { validatePublicWalletRequest, validPublicWalletShape, signPublicPost, type PublicWalletRequest, type WalletProvider } from '../src/publicWallet';
import { validPublicBody, publicProjection, attachPublicDiscussion, PUBLIC_VERSION } from '../src/publicDiscussion';
const f=JSON.parse(readFileSync(new URL('./fixtures/public-wallet-v6-20261101.json',import.meta.url),'utf8'));
async function clock(work:()=>Promise<void>){const old=Date.now;Date.now=()=>1000*(f.request_time+1);try{await work();}finally{Date.now=old;}}

test('actual native v5 EIP712 request reconstructs exact core, author points and evidence hashes',async()=>{
  expect(validPublicWalletShape(f.request)).toBe(true);expect(validPublicBody('public-wallet-request',f.request_body)).toBe(true);
  expect(publicProjection('public-wallet-request',f.request,f.request_body)).toBe(true);
  expect(publicProjection('public-wallet-result',f.saved,f.result_body)).toBe(true);
  const checked=await validatePublicWalletRequest(f.request,f.scope,f.prepared.core,f.request.address,f.request_time+1);
  expect(Object.isFrozen(checked)).toBe(true);expect(Object.isFrozen(checked.binding.core)).toBe(true);
  expect(checked.typed_data.primaryType).toBe('NockAppPostAuthorizationV5');
});
test('changed content, deployment, author/evidence commitments and secret fields never reach signing',async()=>{
  for(const mutate of [
    (q:any)=>q.binding.core.post.body='Changed after consent',
    (q:any)=>q.binding.author.exact='12'.repeat(48),
    (q:any)=>q.typed_data.message.historyEvidenceHash='0x'+'12'.repeat(32),
    (q:any)=>q.typed_data.domain.verifyingContract='0x'+'12'.repeat(20),
    (q:any)=>q.binding.secret='forbidden',
    (q:any)=>q.typed_data.domain.version='4',
    (q:any)=>q.binding.followers=btoa(JSON.stringify({profile:'legacy-date-disclosing-count-v2',issued_at:1})),
  ]){
    const q=structuredClone(f.request);mutate(q);
    await expect(validatePublicWalletRequest(q,f.scope,f.prepared.core,f.request.address,f.request_time+1)).rejects.toThrow();
  }
  const copy=structuredClone(f.request);const pending=validatePublicWalletRequest(copy,f.scope,f.prepared.core,f.request.address,f.request_time+1);
  copy.binding.core.post.body='Mutated while hashing';expect((await pending).binding.core.post.body).toBe(f.prepared.core.post.body);
});
test('raw requests cannot bypass admission and a validated request signs only the exact v5 message',async()=>clock(async()=>{
  const calls:any[]=[];const provider:WalletProvider={request:async r=>{calls.push(r);return r.method==='eth_accounts'?[f.request.address]:r.method==='eth_chainId'?'0x14a34':f.signature;}};
  await expect(signPublicPost(f.request as PublicWalletRequest,provider)).rejects.toThrow('Validate');expect(calls).toEqual([]);
  const q=await validatePublicWalletRequest(f.request,f.scope,f.prepared.core,f.request.address,f.request_time+1);
  expect(await signPublicPost(q,provider)).toBe(f.signature);
  expect(calls.map(c=>c.method)).toEqual(['eth_accounts','eth_chainId','eth_signTypedData_v4']);
  expect(calls[2].params[0]).toBe(f.request.address);expect(JSON.parse(calls[2].params[1])).toEqual(f.request.typed_data);
}));
test('account/network changes and a wallet check crossing expiry cannot open a signing prompt',async()=>clock(async()=>{
  for(const mode of ['account','chain','expires']){
    const methods:string[]=[];const q=await validatePublicWalletRequest(f.request,f.scope,f.prepared.core,f.request.address,f.request_time+1);
    const p:WalletProvider={request:async r=>{methods.push(r.method);if(r.method==='eth_accounts')return[mode==='account'?'0x'+'12'.repeat(20):f.request.address];
      if(mode==='expires')Date.now=()=>Number(q.typed_data.message.deadline)*1000;return mode==='chain'?'0x1':'0x14a34';}};
    await expect(signPublicPost(q,p)).rejects.toThrow();expect(methods).not.toContain('eth_signTypedData_v4');Date.now=()=>1000*(f.request_time+1);
  }
}));
test('a saved old signature can be recovered but cannot trigger another signing prompt',async()=>clock(async()=>{
  const saved={...structuredClone(f.request),signature_saved:true,expired:true};
  const q=await validatePublicWalletRequest(saved,f.scope,f.prepared.core,f.request.address,Number(f.request.typed_data.message.deadline)+1);
  await expect(signPublicPost(q,{request:async()=>{throw Error('must not connect');}})).rejects.toThrow('Validate');
}));
test('dedicated wallet port cannot publish, initialize keys, buy tickets or address another post',()=>{
  const events=new Set<(v:any)=>void>();const sent:any[]=[];const replies:any[]=[];let disconnect=()=>{};
  Object.defineProperty(globalThis,'chrome',{configurable:true,value:{runtime:{connectNative:()=>({onMessage:{addListener:()=>{},removeListener:()=>{}},onDisconnect:{addListener:()=>{},removeListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>sent.push(m)})}}});
  const ui={onMessage:{addListener:(fn:any)=>events.add(fn)},onDisconnect:{addListener:(fn:any)=>{disconnect=fn;}},postMessage:(m:any)=>replies.push(m)} as unknown as chrome.runtime.Port;
  attachPublicDiscussion(ui,f.prepared.core.post.id);
  try{
    for(const [operation,body] of [['public-publish',{post_id:f.prepared.core.post.id,approve_publication:true}],['public-ticket-prepare',{approve_purchase:true}],
      ['public-initialize-identity',{approve_private_key_setup:true}],['public-wallet-request',{...f.request_body,post_id:'33333333-3333-4333-8333-333333333333'}]])
      for(const fn of events)fn({version:PUBLIC_VERSION,operation,body});
    expect(sent).toEqual([]);expect(replies).toHaveLength(4);
    for(const fn of events)fn({version:PUBLIC_VERSION,operation:'public-wallet-request',body:f.request_body});expect(sent).toHaveLength(1);
  }finally{disconnect();Reflect.deleteProperty(globalThis,'chrome');}
});

test('current native vectors bind actual hidden-date and selected-history proof bytes, including Unicode',async()=>{
  for(const name of ['public-wallet-v6-20261101-v2.json','public-wallet-evidence-v6-20261101.json']){
    const v=JSON.parse(readFileSync(new URL('./fixtures/'+name,import.meta.url),'utf8'));
    expect(validPublicWalletShape(v.request),name).toBe(true);
    const request=await validatePublicWalletRequest(v.request,v.scope,v.prepared.core,v.request.address,v.request_time+1);
    expect(request.request_sha256).toBe(v.request.request_sha256);
    if(name.includes('evidence')){expect(request.binding.followers).not.toBeNull();expect(request.binding.history).not.toBeNull();
      const bad=structuredClone(v.request);bad.binding.history=bad.binding.followers;
      await expect(validatePublicWalletRequest(bad,v.scope,v.prepared.core,v.request.address,v.request_time+1)).rejects.toThrow();
    }
  }
});
