import { test, expect, chromium } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
const f=JSON.parse(readFileSync(new URL('./fixtures/public-refunds-v7-20261101.json',import.meta.url),'utf8'));

// Real built page/SDK/background admission; native ports and MetaMask simulated.
for(const release of [7,9])for(const mode of ['resume','lost-reply','wrong-payout','saved-receipt'])test(`native-v${release} refund page ${mode}`,async()=>{
  const profile=await mkdtemp(resolve(tmpdir(),'nockapp-refunds-ui-'));const path=resolve('dist');
  const context=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${path}`,`--load-extension=${path}`,'--no-sandbox']});
  try{
    const worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker');
    await worker.evaluate(({f,mode,release})=>{
      const calls:any[]=[];let state=mode==='saved-receipt'?f.state_completed:mode==='lost-reply'?f.state_before:f.state_pending;
      let pending=mode==='saved-receipt'?f.pending_completed:f.pending_paid;Object.assign(globalThis,{refundNativeCalls:calls});
      chrome.runtime.connectNative=(()=>{
        const listeners=new Set<(v:unknown)=>void>();const disconnects=new Set<()=>void>();
        return {onMessage:{addListener:(fn:(v:unknown)=>void)=>listeners.add(fn),removeListener:(fn:(v:unknown)=>void)=>listeners.delete(fn)},
          onDisconnect:{addListener:(fn:()=>void)=>disconnects.add(fn),removeListener:(fn:()=>void)=>disconnects.delete(fn)},disconnect:()=>{},postMessage:(m:any)=>{
            calls.push(structuredClone(m));let result;
            if(m.operation==='public-capabilities')result=release===7?f.capabilities:{...f.capabilities,
              verifier_release:9,publication_mode:'tickets',follower_proof_configured:true,source_enrollment_configured:true,
              historical_issuer_views:true};
            else if(m.operation==='public-ticket-offer')result=f.offer;
            else if(m.operation==='public-ticket-pending')result=pending;
            else if(m.operation==='public-ticket-refund-state')result=state;
            else if(m.operation==='public-ticket-refund-request')result=f.refund_request;
            else if(m.operation==='public-ticket-refund-result'){
              state=f.state_pending;queueMicrotask(()=>disconnects.forEach(fn=>fn()));return;
            }else if(m.operation==='public-ticket-refund-recover'){
              result=mode==='wrong-payout'?{...f.payout,amount_wei:'1'}:f.payout;
              if(mode!=='wrong-payout'){state=f.state_completed;pending=f.pending_completed;}
            }else if(m.operation==='public-ticket-refund-status')result=f.payout;
            else throw Error('Unexpected refund-page operation');
            queueMicrotask(()=>listeners.forEach(fn=>fn({profile:m.profile,id:m.id,status:'ok',result,laboratory:true,verified:false})));
          }};
      }) as unknown as typeof chrome.runtime.connectNative;
    },{f,mode,release});
    await context.addInitScript(f=>{
      if(!chrome.runtime?.connect)return;
      const calls:any[]=[];Object.assign(globalThis,{refundWalletCalls:calls});const original=chrome.runtime.connect.bind(chrome.runtime);
      chrome.runtime.connect=((...args:any[])=>{
        if(typeof args[0]!=='string')return(original as any)(...args);
        calls.push({connect:args[0]});const listeners=new Set<(v:unknown)=>void>();
        return {name:'',onMessage:{addListener:(fn:(v:unknown)=>void)=>listeners.add(fn)},onDisconnect:{addListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>{
          const r=m.data;if(!r?.method)return;calls.push(structuredClone(r));let result;
          if(r.method==='metamask_getProviderState')result={isUnlocked:true,chainId:'0x14a34',networkVersion:'84532',accounts:[f.payout.payer]};
          else if(['eth_requestAccounts','eth_accounts'].includes(r.method))result=[f.payout.payer];
          else if(r.method==='eth_chainId')result='0x14a34';
          else if(r.method==='eth_signTypedData_v4')result='0x'+'11'.repeat(65);
          else throw Error('Unexpected wallet method in refund recovery');
          queueMicrotask(()=>listeners.forEach(fn=>fn({name:m.name,data:{jsonrpc:'2.0',id:r.id,result}})));
        }};
      }) as typeof chrome.runtime.connect;
    },f);
    const page=await context.newPage();const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(`chrome-extension://${new URL(worker.url()).host}/public-tickets.html`);
    await expect(page.getByRole('region',{name:'Refund policy and recovery'})).toBeVisible();
    expect(await page.evaluate(()=>(globalThis as any).refundWalletCalls)).toEqual([]);
    if(mode==='saved-receipt'){
      await expect(page.getByText(/This saved receipt has not been reverified/)).toBeVisible();
      await expect(page.getByRole('status')).toHaveCount(0);
      await page.getByRole('button',{name:/Reverify saved refund/}).click();
    }else{
      if(mode==='lost-reply'){
        await page.getByRole('checkbox',{name:/I permanently cancel issuance/}).check();
        await page.getByRole('button',{name:'Sign and record unissued-pack cancellation'}).click();
        await expect(page.getByRole('alert')).toBeVisible();
      }
      await expect(page.getByRole('button',{name:'Recover paid tickets'})).toBeDisabled();
      await page.getByRole('button',{name:'Resume saved refund without wallet'}).click();
    }
    if(mode==='wrong-payout'){
      await expect(page.getByRole('alert')).toContainText('does not match');
      await expect(page.getByRole('status')).toHaveCount(0);
      await expect(page.getByText(`Saved pack: ${f.payout.pack_hash}`,{exact:true})).toBeVisible();
    }else{
      await expect(page.getByRole('status')).toContainText('Refund confirmed by the local verifier');
      await expect(page.getByRole('status')).toContainText(f.payout.transaction_hash);
      await expect(page.getByRole('button',{name:'Prepare this ticket pack'})).toBeVisible();
    }
    const wallet=await page.evaluate(()=>(globalThis as any).refundWalletCalls);
    expect(wallet.filter((m:any)=>m.method==='eth_signTypedData_v4')).toHaveLength(mode==='lost-reply'?1:0);
    expect(wallet.some((m:any)=>m.method==='eth_sendTransaction')).toBe(false);
    if(mode!=='lost-reply')expect(wallet).toEqual([]);
    const calls=await worker.evaluate(()=>(globalThis as any).refundNativeCalls);
    expect(calls.filter((m:any)=>m.operation==='public-ticket-refund-result')).toHaveLength(mode==='lost-reply'?1:0);
    expect(calls.filter((m:any)=>m.operation==='public-ticket-refund-recover')).toHaveLength(mode==='saved-receipt'?0:1);
    expect(calls.every((m:any)=>m.operation==='public-capabilities'||m.operation.startsWith('public-ticket-'))).toBe(true);
    for(const m of calls.filter((m:any)=>['public-ticket-refund-status','public-ticket-refund-recover'].includes(m.operation)))expect(m.body).toEqual({pack_hash:f.payout.pack_hash});
    if(mode!=='wrong-payout'){
      await page.reload();await expect(page.getByText(/This saved receipt has not been reverified/)).toBeVisible();
      await expect(page.getByRole('status')).toHaveCount(0);
    }
    expect(errors).toEqual([]);
  }finally{await context.close();await rm(profile,{recursive:true,force:true});}
});
