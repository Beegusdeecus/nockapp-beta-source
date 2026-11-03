import { test,expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { publishDirect, publishPublicBundleHash } from '../src/publicDirect';
import { publicProjection,validPublicBody,PUBLIC_VERSION,type PublicSubmission } from '../src/publicDiscussion';
const vectors=JSON.parse(readFileSync(new URL('./fixtures/public-native-contract-v6-20261101.json',import.meta.url),'utf8')).vectors;
const row:PublicSubmission=vectors.find((v:any)=>v.operation==='public-outbox').result.entries.find((v:any)=>v.bundle_hash!==null);
const {submission_id:_id,...scope}=row.core.context;
const ready={scope,bundle_hash:row.bundle_hash!,calldata:'0xd9caa3d2'+row.bundle_hash!.slice(2),public_readback_checked:true,payer_address_public:true};
const payer='0x'+'12'.repeat(20);const txHash='0x'+'34'.repeat(32);
function harness(changes:Record<string,unknown>={},reply:unknown=ready) {
  const oldChrome=Object.getOwnPropertyDescriptor(globalThis,'chrome');const oldNavigator=Object.getOwnPropertyDescriptor(globalThis,'navigator');
  const storage:Record<string,unknown>={};const calls:{method:string;params?:unknown[]}[]=[];const native:string[]=[];
  let lock:Promise<unknown>=Promise.resolve();
  Object.defineProperty(globalThis,'navigator',{configurable:true,value:{locks:{request:(_key:string,fn:()=>Promise<unknown>)=>{
    const result=lock.then(fn);lock=result.catch(()=>undefined);return result;
  }}}});
  Object.defineProperty(globalThis,'chrome',{configurable:true,value:{storage:{local:{
    get:async(k:string)=>({[k]:storage[k]}),set:async(v:Record<string,unknown>)=>Object.assign(storage,structuredClone(v)),remove:async(k:string)=>{delete storage[k];}
  }},runtime:{connect:()=>{
    const listeners:((v:unknown)=>void)[]=[];
    return {onMessage:{addListener:(f:(v:unknown)=>void)=>listeners.push(f)},onDisconnect:{addListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>{
      native.push(m.operation);for(const f of listeners)f({version:PUBLIC_VERSION,result:reply});
    }};
  }}}});
  const provider={request:async(r:{method:string;params?:unknown[]})=>{
    calls.push(structuredClone(r));
    if(r.method in changes){const v=changes[r.method];if(v instanceof Error)throw v;return v;}
    if(['eth_requestAccounts','eth_accounts'].includes(r.method))return[payer];
    if(r.method==='eth_chainId')return'0x14a34';if(r.method==='eth_getTransactionCount')return'0x7';
    if(r.method==='eth_estimateGas')return'0x186a0';if(r.method==='eth_getBalance')return'0x38d7ea4c68000';
    if(r.method==='eth_sendTransaction')return txHash;throw Error('unexpected wallet request');
  }};
  return {storage,calls,native,provider,close:()=>{
    for(const [key,old] of [['chrome',oldChrome],['navigator',oldNavigator]] as const)
      if(old)Object.defineProperty(globalThis,key,old);else Reflect.deleteProperty(globalThis,key);
  }};
}
test('direct profile and operations require exact public schemas and consent',()=>{
  const c={...vectors.find((v:any)=>v.operation==='public-capabilities').result,verifier_release:8,
    anonymous_ticket_packs:false,publication_mode:'direct',historical_issuer_views:false,follower_proof_configured:false};
  expect(publicProjection('public-capabilities',c)).toBe(true);
  for(const change of [{anonymous_ticket_packs:true},{historical_issuer_views:true},{publication_mode:'tickets'},{secret:'forbidden'}])
    expect(publicProjection('public-capabilities',{...c,...change})).toBe(false);
  const body={post_id:row.core.post.id,approve_publication:true,approve_public_payer:true};
  expect(validPublicBody('public-direct-ready',body)).toBe(true);
  expect(validPublicBody('public-direct-ready',{...body,approve_public_payer:false})).toBe(false);
  expect(validPublicBody('public-direct-ready',{...body,endpoint:'https://example.com'})).toBe(false);
  for(const change of [{calldata:'0x12345678'+row.bundle_hash!.slice(2)},{public_readback_checked:false},{payer_address_public:false},{secret:'forbidden'}])
    expect(publicProjection('public-direct-ready',{...ready,...change})).toBe(false);
});
test('only one exact zero-value Base submission follows verified storage and public-payer consent',async()=>{
  const h=harness();try{
    await expect(publishDirect(row,scope,false,h.provider)).rejects.toThrow('Approve');expect(h.native).toEqual([]);
    expect(await publishDirect(row,scope,true,h.provider)).toBe(txHash);
    const sent=h.calls.filter(v=>v.method==='eth_sendTransaction');expect(sent).toHaveLength(1);
    expect(sent[0].params).toEqual([expect.objectContaining({from:payer,to:scope.contract,data:ready.calldata,chainId:'0x14a34',value:'0x0',nonce:'0x7'})]);
    expect(Object.values(h.storage)[0]).toEqual(expect.objectContaining({transaction_hash:txHash,bundle_hash:row.bundle_hash}));
    await expect(publishDirect(row,scope,true,h.provider)).rejects.toThrow('already saved');
    expect(h.calls.filter(v=>v.method==='eth_sendTransaction')).toHaveLength(1);
  }finally{h.close();}
});
test('padded and upper-case wallet quantities normalize without changing transaction or fee bounds',async()=>{
  const h=harness({'eth_getTransactionCount':'0x0007','eth_estimateGas':'0x0186A0','eth_getBalance':'0x0038D7EA4C68000'});
  try {
    expect(await publishPublicBundleHash(row.bundle_hash!,scope,true,h.provider)).toBe(txHash);
    expect(h.calls.find(v=>v.method==='eth_sendTransaction')!.params).toEqual([expect.objectContaining({
      nonce:'0x7',gas:'0x1d4c1',value:'0x0',data:ready.calldata,maxFeePerGas:'0x5f5e100',maxPriorityFeePerGas:'0xf4240'
    })]);
  } finally { h.close(); }
});
test('invalid wallet quantity types and excessive padded gas identify the failure before saving or sending',async()=>{
  for(const [method,field] of [['eth_getTransactionCount','transaction nonce'],['eth_estimateGas','gas estimate'],['eth_getBalance','balance']]) {
    for(const value of [-1, -0, 1.5, Number.MAX_SAFE_INTEGER+1, NaN, Infinity, null, {}, '12', '-0x1', '0x', '0x'+'f'.repeat(65)]) {
      const h=harness({[method]:value});try {
        await expect(publishPublicBundleHash(row.bundle_hash!,scope,true,h.provider)).rejects.toThrow(`invalid ${field}`);
        expect(h.calls.some(v=>v.method==='eth_sendTransaction')).toBe(false);expect(Object.keys(h.storage)).toEqual([]);
      } finally { h.close(); }
    }
  }
  const h=harness({'eth_estimateGas':'0x00030D41'});try {
    await expect(publishPublicBundleHash(row.bundle_hash!,scope,true,h.provider)).rejects.toThrow('200001 gas');
    expect(h.calls.some(v=>v.method==='eth_sendTransaction')).toBe(false);expect(Object.keys(h.storage)).toEqual([]);
  } finally { h.close(); }
});
test('observed MetaMask numeric nonce and safe numeric quantities preserve exact transaction values',async()=>{
  for(const changes of [
    {'eth_getTransactionCount':1},
    {'eth_getTransactionCount':1,'eth_estimateGas':75012,'eth_getBalance':1000000000000000},
  ]) {
    const h=harness(changes);try {
      expect(await publishPublicBundleHash(row.bundle_hash!,scope,true,h.provider)).toBe(txHash);
      const tx=h.calls.find(v=>v.method==='eth_sendTransaction')!.params![0] as Record<string,unknown>;
      expect(tx.nonce).toBe('0x1');expect(tx.to).toBe(scope.contract);expect(tx.data).toBe(ready.calldata);
      expect(tx.value).toBe('0x0');expect(tx.maxFeePerGas).toBe('0x5f5e100');
      expect(BigInt(tx.gas as string)).toBeLessThanOrEqual(240000n);
    } finally { h.close(); }
  }
});
test('missing readback, changed deployment and excessive gas or low funds cannot send',async()=>{
  for(const reply of [{...ready,public_readback_checked:false},{...ready,scope:{...scope,contract:'0x'+'56'.repeat(20)}}]){
    const h=harness({},reply);try{await expect(publishDirect(row,scope,true,h.provider)).rejects.toThrow();expect(h.calls).toEqual([]);}finally{h.close();}
  }
  for(const changes of [{'eth_estimateGas':'0xffffff'},{'eth_getBalance':'0x0'},{'eth_accounts':['0x'+'56'.repeat(20)]}]){
    const h=harness(changes);try{await expect(publishDirect(row,scope,true,h.provider)).rejects.toThrow();expect(h.calls.some(v=>v.method==='eth_sendTransaction')).toBe(false);expect(Object.keys(h.storage)).toEqual([]);}finally{h.close();}
  }
});
test('lost or malformed wallet replies retain the intent, while explicit rejection permits another decision',async()=>{
  for(const outcome of [new Error('lost wallet reply'),'malformed']){
    const h=harness({'eth_sendTransaction':outcome});try{
      await expect(publishDirect(row,scope,true,h.provider)).rejects.toThrow('unknown');
      expect(Object.keys(h.storage)).toHaveLength(1);
      await expect(publishDirect(row,scope,true,h.provider)).rejects.toThrow('already saved');
      expect(h.calls.filter(v=>v.method==='eth_sendTransaction')).toHaveLength(1);
    }finally{h.close();}
  }
  const h=harness({'eth_sendTransaction':Object.assign(new Error('declined'),{code:4001})});try{
    await expect(publishDirect(row,scope,true,h.provider)).rejects.toThrow('declined');expect(Object.keys(h.storage)).toHaveLength(0);
  }finally{h.close();}
});
test('concurrent direct clicks cannot make two wallet sends',async()=>{
  const h=harness();try{
    const results=await Promise.allSettled([publishDirect(row,scope,true,h.provider),publishDirect(row,scope,true,h.provider)]);
    expect(results.map(v=>v.status)).toEqual(['fulfilled','rejected']);expect(h.calls.filter(v=>v.method==='eth_sendTransaction')).toHaveLength(1);
  }finally{h.close();}
});
test('an independent payer submits only the native-verified public hash without claiming an authored outbox post',async()=>{
  const h=harness();try{
    expect(await publishPublicBundleHash(row.bundle_hash!,scope,true,h.provider)).toBe(txHash);
    expect(h.native).toEqual(['public-direct-public-ready']);
    expect(h.calls.find(v=>v.method==='eth_sendTransaction')!.params).toEqual([expect.objectContaining({data:ready.calldata,value:'0x0',to:scope.contract})]);
    expect(Object.values(h.storage)[0]).not.toHaveProperty('post_id');
    await expect(publishDirect(row,scope,true,h.provider)).rejects.toThrow('already saved');
    expect(h.calls.filter(v=>v.method==='eth_sendTransaction')).toHaveLength(1);
  }finally{h.close();}
});
test('unconsented, malformed or substituted public hashes cannot reach the payer wallet',async()=>{
  const h=harness();try{
    for(const value of ['0x'+'00'.repeat(32),'../private-file',row.bundle_hash!.slice(2)])
      await expect(publishPublicBundleHash(value,scope,true,h.provider)).rejects.toThrow('exact public bundle');
    await expect(publishPublicBundleHash(row.bundle_hash!,scope,false,h.provider)).rejects.toThrow('Approve');
    expect(h.native).toEqual([]);expect(h.calls).toEqual([]);
  }finally{h.close();}
  const changed=harness({}, {...ready,bundle_hash:'0x'+'56'.repeat(32),calldata:'0xd9caa3d2'+'56'.repeat(32)});try{
    await expect(publishPublicBundleHash(row.bundle_hash!,scope,true,changed.provider)).rejects.toThrow();expect(changed.calls).toEqual([]);
  }finally{changed.close();}
});
