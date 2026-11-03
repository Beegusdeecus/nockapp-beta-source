import { test, expect, chromium } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
const fixture=JSON.parse(readFileSync(new URL('./fixtures/public-wallet-v6-20261101.json',import.meta.url),'utf8'));

// Actual built React/provider/stream, synthetic native and external MetaMask port.
for(const altered of [false,true])test(`public v5 wallet page ${altered?'rejects changed author before sign':'signs only exact saved native request after consent'}`,async()=>{
  const profile=await mkdtemp(resolve(tmpdir(),'nockapp-public-wallet-ui-'));const path=resolve('dist');
  const context=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${path}`,`--load-extension=${path}`,'--no-sandbox']});
  try{
    const worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker');
    await worker.evaluate(({f,altered})=>{
      const calls:any[]=[];Object.assign(globalThis,{publicWalletNativeCalls:calls});
      chrome.runtime.connectNative=(()=>{
        const listeners=new Set<(v:unknown)=>void>();
        return{onMessage:{addListener:(fn:(v:unknown)=>void)=>listeners.add(fn),removeListener:(fn:(v:unknown)=>void)=>listeners.delete(fn)},
          onDisconnect:{addListener:()=>{},removeListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>{
            calls.push(structuredClone(m));let result;
            if(m.operation==='public-capabilities')result={configured:true,protocol:5,scope:f.scope,follower_proof_configured:false,verifier_release:6,anonymous_ticket_packs:true,source_enrollment_configured:false,historical_issuer_views:true};
            else if(m.operation==='public-outbox')result={entries:[f.prepared],next_after:null};
            else if(m.operation==='public-wallet-request'){result=structuredClone(f.request);if(altered)result.binding.author.exact='12'.repeat(48);}
            else if(m.operation==='public-wallet-result')result=f.saved;
            else throw Error('Unexpected wallet-page operation');
            queueMicrotask(()=>listeners.forEach(fn=>fn({profile:m.profile,id:m.id,status:'ok',result,laboratory:true,verified:false})));
          }};
      }) as unknown as typeof chrome.runtime.connectNative;
    },{f:fixture,altered});
    await context.addInitScript(f=>{
      Date.now=()=>1000*(f.request_time+1);const calls:any[]=[];Object.assign(globalThis,{publicMetaMaskCalls:calls});const original=chrome.runtime.connect.bind(chrome.runtime);
      chrome.runtime.connect=((...args:any[])=>{
        if(typeof args[0]!=='string')return(original as any)(...args);calls.push({connect:args[0]});const listeners=new Set<(v:unknown)=>void>();
        return{name:'',onMessage:{addListener:(fn:(v:unknown)=>void)=>listeners.add(fn)},onDisconnect:{addListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>{
          const r=m.data;if(!r?.method)return;calls.push(structuredClone(r));let result;
          if(r.method==='metamask_getProviderState')result={isUnlocked:true,chainId:'0x14a34',networkVersion:'84532',accounts:[f.request.address]};
          else if(['eth_requestAccounts','eth_accounts'].includes(r.method))result=[f.request.address];
          else if(r.method==='eth_chainId')result='0x14a34';else if(r.method==='eth_signTypedData_v4')result=f.signature;else throw Error('Unexpected wallet method');
          queueMicrotask(()=>listeners.forEach(fn=>fn({name:m.name,data:{jsonrpc:'2.0',id:r.id,result}})));
        }};
      }) as typeof chrome.runtime.connect;
    },fixture);
    const page=await context.newPage();const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(`chrome-extension://${new URL(worker.url()).host}/public-wallet.html#post=${fixture.prepared.core.post.id}`);
    const sign=page.getByRole('button',{name:'Connect MetaMask and authorize saved public post'});await expect(sign).toBeEnabled();
    expect(await page.evaluate(()=>(globalThis as any).publicMetaMaskCalls)).toEqual([]);await expect(page.getByText(fixture.prepared.core.post.body,{exact:true})).toBeVisible();
    await sign.click();if(altered)await expect(page.getByRole('alert')).toContainText('commitment');else await expect(page.getByRole('status')).toContainText('exact final bundle saved');
    const methods=await page.evaluate(()=>(globalThis as any).publicMetaMaskCalls);const typed=methods.find((r:any)=>r.method==='eth_signTypedData_v4');
    if(altered)expect(typed).toBeUndefined();else{expect(JSON.parse(typed.params[1])).toEqual(fixture.request.typed_data);expect(typed.params[0]).toBe(fixture.request.address);}
    expect(methods[0]).toEqual({connect:'nkbihfbeogaeaoehlefnkodbefgpgknn'});expect(methods.some((r:any)=>r.method==='eth_sendTransaction')).toBe(false);expect(errors).toEqual([]);
    const native=await worker.evaluate(()=>(globalThis as any).publicWalletNativeCalls);
    expect(native.some((r:any)=>r.operation==='public-publish')).toBe(false);
    if(!altered)expect(native.find((r:any)=>r.operation==='public-wallet-result').body).toEqual(fixture.result_body);
  }finally{await context.close();await rm(profile,{recursive:true,force:true});}
});
