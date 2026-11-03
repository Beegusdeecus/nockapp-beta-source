import { test, expect, chromium } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
const fixture=JSON.parse(readFileSync(new URL('./fixtures/public-tickets-v6-20261101.json',import.meta.url),'utf8'));

// Real built React/provider stream; public native vectors and simulated ports.
for(const mode of ['purchase','numeric-purchase','lost-response','bad-code','refund','renewal-cancellation'])test(`ticket wallet page ${mode}`,async()=>{
  const refund=mode==='refund'||mode==='renewal-cancellation';
  const profile=await mkdtemp(resolve(tmpdir(),'nockapp-tickets-ui-'));const path=resolve('dist');
  const context=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${path}`,`--load-extension=${path}`,'--no-sandbox']});
  try{
    const worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker');
    await worker.evaluate(({f,mode})=>{
      const calls:any[]=[];let state=f.empty;Object.assign(globalThis,{ticketNativeCalls:calls});
      chrome.runtime.connectNative=(()=>{
        const listeners=new Set<(v:unknown)=>void>();
        return {onMessage:{addListener:(fn:(v:unknown)=>void)=>listeners.add(fn),removeListener:(fn:(v:unknown)=>void)=>listeners.delete(fn)},
          onDisconnect:{addListener:()=>{},removeListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>{
            calls.push(structuredClone(m));let result;
            if(m.operation==='public-capabilities')result={configured:true,protocol:5,scope:f.scope,
              follower_proof_configured:mode==='renewal-cancellation',verifier_release:mode==='renewal-cancellation'?9:6,
              anonymous_ticket_packs:true,source_enrollment_configured:mode==='renewal-cancellation',historical_issuer_views:true,
              ...(mode==='renewal-cancellation'?{publication_mode:'tickets',refund_payout_configured:false}:{})};
            else if(m.operation==='public-ticket-offer')result=f.offer;
            else if(m.operation==='public-ticket-pending')result=state;
            else if(m.operation==='public-ticket-prepare'){state=f.pending_prepared;result=f.prepared;}
            else if(m.operation==='public-ticket-arm'){state=f.pending_armed;result=f.armed;}
            else if(m.operation==='public-ticket-payment'){state=f.pending_paid;result=f.paid;}
            else if(m.operation==='public-ticket-find'){state=f.pending_paid;result=f.found;}
            else if(m.operation==='public-ticket-recover'){state=f.complete;result=f.recovered;}
            else if(m.operation==='public-ticket-refund-request')result=f.refund_request;
            else if(m.operation==='public-ticket-refund-result')result={state:'cancellation-recorded',payout_confirmed:false};
            else throw Error('Unexpected ticket-page operation');
            queueMicrotask(()=>listeners.forEach(fn=>fn({profile:m.profile,id:m.id,status:'ok',result,laboratory:true,verified:false})));
          }};
      }) as unknown as typeof chrome.runtime.connectNative;
    },{f:fixture,mode});
    await context.addInitScript(({f,mode})=>{
      if(!chrome.runtime?.connect)return;
      Date.now=()=>f.now*1000;const calls:any[]=[];Object.assign(globalThis,{ticketWalletCalls:calls});
      const original=chrome.runtime.connect.bind(chrome.runtime);
      chrome.runtime.connect=((...args:any[])=>{
        if(typeof args[0]!=='string')return(original as any)(...args);
        calls.push({connect:args[0]});const listeners=new Set<(v:unknown)=>void>();
        return {name:'',onMessage:{addListener:(fn:(v:unknown)=>void)=>listeners.add(fn)},onDisconnect:{addListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>{
          const r=m.data;if(!r?.method)return;calls.push(structuredClone(r));let result;
          if(r.method==='metamask_getProviderState')result={isUnlocked:true,chainId:'0x14a34',networkVersion:'84532',accounts:[f.rpc.payer]};
          else if(['eth_requestAccounts','eth_accounts'].includes(r.method))result=[f.rpc.payer];
          else if(r.method==='eth_chainId')result='0x14a34';
          else if(r.method==='eth_getBlockByNumber')result=f.rpc.anchor;
          else if(r.method==='eth_getCode')result=mode==='bad-code'?'0x00':f.rpc.runtime;
          else if(r.method==='eth_call')result=f.rpc.contract_calls[r.params[0].data];
          else if(r.method==='eth_getTransactionCount')result=mode==='numeric-purchase'?f.arm_body.nonce:'0x'+f.arm_body.nonce.toString(16);
          else if(r.method==='eth_estimateGas')result=mode==='numeric-purchase'?60000:'0xea60';
          else if(r.method==='eth_gasPrice')result=mode==='numeric-purchase'?1000000000:'0x3b9aca00';
          else if(r.method==='eth_sendTransaction')result=mode==='lost-response'?'response-lost':f.paid.payment_tx;
          else if(r.method==='eth_signTypedData_v4')result=f.refund_signature;
          else throw Error('Unexpected ticket wallet method');
          queueMicrotask(()=>listeners.forEach(fn=>fn({name:m.name,data:{jsonrpc:'2.0',id:r.id,result}})));
        }};
      }) as typeof chrome.runtime.connect;
    },{f:fixture,mode});
    const page=await context.newPage();const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(`chrome-extension://${new URL(worker.url()).host}/public-tickets.html`);
    await expect(page.getByRole('checkbox',{name:/I accept this shared pack/})).toBeVisible();
    expect(await page.evaluate(()=>(globalThis as any).ticketWalletCalls)).toEqual([]);
    await page.getByRole('checkbox',{name:/I accept this shared pack/}).check();await page.getByRole('button',{name:'Prepare this ticket pack'}).click();
    await expect(page.getByText(`Saved pack: ${fixture.prepared.pack_hash}`,{exact:true})).toBeVisible();
    await page.getByRole('textbox',{name:'Execution-fee limit (ETH)'}).fill('0.001');
    await page.getByRole('button',{name:'Connect MetaMask and review payment'}).click();
    if(mode==='bad-code')await expect(page.getByRole('alert')).toContainText('code changed');
    else{
      await expect(page.getByRole('region',{name:'Reviewed wallet transaction'})).toBeVisible();
      await page.getByRole('checkbox',{name:/I approve this exact transaction/}).check();
      await page.getByRole('button',{name:'Pay for this exact ticket pack'}).click();
      if(mode==='lost-response'){
        await expect(page.getByRole('alert')).toContainText('transaction hash');
        await expect(page.getByRole('button',{name:'Pay for this exact ticket pack'})).toHaveCount(0);
        await expect(page.getByRole('button',{name:'Connect MetaMask and review payment'})).toHaveCount(0);
        await page.getByRole('button',{name:'Find finalized payment'}).click();
      }
      await expect(page.getByRole('button',{name:'Recover paid tickets'})).toBeVisible();
      if(refund){
        await expect(page.getByRole('region',{name:'Refund policy and recovery'})).toHaveCount(0);
        await page.getByRole('checkbox',{name:/I permanently cancel issuance/}).check();
        await page.getByRole('button',{name:'Sign and record unissued-pack cancellation'}).click();
        await expect(page.getByRole('status')).toContainText('Payout is not confirmed');
      }else{
        await page.getByRole('button',{name:'Recover paid tickets'}).click();
        await expect(page.getByRole('status')).toContainText('Ticket inventory recovered');
      }
    }
    const methods=await page.evaluate(()=>(globalThis as any).ticketWalletCalls);
    const sends=methods.filter((r:any)=>r.method==='eth_sendTransaction');expect(sends).toHaveLength(mode==='bad-code'?0:1);
    if(sends.length)expect(sends[0].params[0]).toMatchObject({from:fixture.rpc.payer,to:fixture.prepared.transaction.to,
      value:fixture.prepared.transaction.value,data:fixture.prepared.transaction.data,chainId:'0x14a34',nonce:'0x'+fixture.arm_body.nonce.toString(16)});
    const signatures=methods.filter((r:any)=>r.method==='eth_signTypedData_v4');expect(signatures).toHaveLength(refund?1:0);
    if(signatures.length)expect(JSON.parse(signatures[0].params[1])).toEqual(fixture.refund_request.typed_data);
    expect(methods[0]).toEqual({connect:'nkbihfbeogaeaoehlefnkodbefgpgknn'});expect(errors).toEqual([]);
    const native=await worker.evaluate(()=>(globalThis as any).ticketNativeCalls);
    expect(native.every((r:any)=>r.operation==='public-capabilities'||r.operation.startsWith('public-ticket-'))).toBe(true);
    expect(native.filter((r:any)=>r.operation==='public-ticket-arm')).toHaveLength(mode==='bad-code'?0:1);
    if(mode==='renewal-cancellation')expect(native.some((r:any)=>r.operation==='public-ticket-refund-state')).toBe(false);
  }finally{await context.close();await rm(profile,{recursive:true,force:true});}
});
