import { test, expect, chromium } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
const f=JSON.parse(readFileSync(new URL('./fixtures/same-purchase-v1.json',import.meta.url),'utf8'));
for(const mode of ['success','cancel','unknown','unknown-reload','changed-wallet','authorization-only','read-error','post-authorization-error','native-error','connection-required','pending-wallet-request','interrupted-poll'])test(`installed same-purchase resume ${mode}`,async({},testInfo)=>{
  const dir=await mkdtemp(resolve(tmpdir(),'nockapp-same-purchase-'));const path=resolve('dist');
  const context=await chromium.launchPersistentContext(dir,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${path}`,`--load-extension=${path}`,'--no-sandbox']});
  try{
    const worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker');
    await worker.evaluate(({f,mode})=>{
      const state:any={bulk:structuredClone(f.purchase),paid:false,available:0,calls:[],armed:false};if(mode==='authorization-only')state.bulk.resume_payment_attempted=true;Object.assign(globalThis,{sameFixture:state});
      chrome.runtime.onMessage.addListener((m:any)=>{if(m.sameFixturePaid)state.paid=true;});
      const caps={configured:true,protocol:5,scope:f.scope,verifier_release:12,publication_mode:'tickets',anonymous_ticket_packs:true,follower_proof_configured:true,source_enrollment_configured:true,historical_issuer_views:true,refund_payout_configured:false,ticket_page_snapshot:true,same_purchase_resume:true};
      const pending={profile:'nockapp-public-ticket-purchase-state-v1',purchase:null,payment_intent:null,closed_attempts:0,attempt_limit:8};
      chrome.runtime.connectNative=(()=>{const listeners=new Set<(v:any)=>void>();return{onMessage:{addListener:(fn:(v:any)=>void)=>listeners.add(fn),removeListener:(fn:(v:any)=>void)=>listeners.delete(fn)},onDisconnect:{addListener:()=>{},removeListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>{
        state.calls.push(structuredClone(m));let result;
        if(m.operation==='public-capabilities')result=caps;
        else if(m.operation==='public-ticket-page')result={profile:'nockapp-ticket-page-v1',capabilities:caps,offer:f.offer,bulk:{profile:f.purchase.profile,phase:'none'},pending,refund:null,
          inventory:{profile:'nockapp-protected-ticket-wallet-v1',initialized:true,available:state.available,reserved:6,purchase_pending:state.bulk.phase!=='complete',can_purchase:false,can_redeem:true,pack_size:2,pack_price_wei:f.offer.manifest.terms.pack_price_wei,purchase_before:f.offer.manifest.terms.purchase_before,redeem_before:f.offer.manifest.terms.redeem_before,refund_policy:f.offer.manifest.terms.refund_policy,prepaid_custody:true},
          earlier:{profile:'nockapp-earlier-ticket-purchases-v1',purchases:state.bulk.phase==='complete'?[]:[{parameters:f.offer.parameters,offer:f.offer,purchase:state.bulk}]}};
        else if(m.operation==='public-ticket-earlier-recovery'){
          if(m.body.parameters!==f.offer.parameters)throw Error('Scope changed');const body=m.body.body;
          if(m.body.operation==='public-ticket-bulk-progress')result={profile:'nockapp-ticket-payment-progress-v1',batch_id:f.purchase.batch_id,pack_hash:'0x'+f.purchase.calls[0].data.slice(-64),state:state.paid?'finalized':'not-seen',latest_block:120,finalized_block:110,payment_block:null};
          else if(m.body.operation==='public-ticket-bulk-self-review')result=f.review;
          else if(m.body.operation==='public-ticket-bulk-self-arm'){
            if(mode==='native-error'){queueMicrotask(()=>listeners.forEach(fn=>fn({profile:m.profile,id:m.id,status:'rejected',code:'native-operation-unavailable',recoverable:true,laboratory:true,verified:false})));return;}
            if(state.armed||JSON.stringify(body.quote)!==JSON.stringify(f.review)||body.approve_resume!==true)throw Error('Unexpected authorization');state.armed=true;state.bulk.resume_payment_attempted=true;
            result={profile:'nockapp-same-purchase-dispatch-v1',quote:f.review,dispatch_authorized:true};
          }else if(m.body.operation==='public-ticket-bulk-recover'){
            if(!state.paid)throw Error('Not paid');state.bulk.phase=state.bulk.imported_tickets===48?'complete':'importing';state.bulk.imported_tickets+=2;state.bulk.settled_tickets+=2;state.bulk.transaction_hash=f.transaction_hash;state.available=state.bulk.imported_tickets;result=state.bulk;
          }else throw Error('Unexpected operation '+m.body.operation);
        }else throw Error('Unexpected operation '+m.operation);
        const reply=()=>listeners.forEach(fn=>fn({profile:m.profile,id:m.id,status:'ok',result:structuredClone(result),laboratory:true,verified:false}));
        if(mode==='interrupted-poll'&&m.body?.operation==='public-ticket-bulk-progress'&&state.calls.filter((v:any)=>v.body?.operation==='public-ticket-bulk-progress').length>1)setTimeout(reply,200);else queueMicrotask(reply);
      }};})as any;
    },{f,mode});
    await context.addInitScript(({f,mode})=>{
      if(!chrome.runtime?.connect)return;Date.now=()=>f.now*1000;
      let connected=mode!=='connection-required';const original=chrome.runtime.connect.bind(chrome.runtime);const requests:any[]=[];Object.assign(globalThis,{sameWalletRequests:requests});
      chrome.runtime.connect=((...args:any[])=>{
        if(typeof args[0]!=='string')return(original as any)(...args);const listeners=new Set<(v:any)=>void>();return{onMessage:{addListener:(fn:(v:any)=>void)=>listeners.add(fn)},onDisconnect:{addListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>{
          const r=m.data;if(!r?.method)return;requests.push(structuredClone(r));let result;
          if(mode==='pending-wallet-request'&&r.method==='eth_accounts'||r.method==='eth_getCode'&&(mode==='read-error'||mode==='post-authorization-error'&&requests.filter(x=>x.method==='eth_getCode').length>2)){
            queueMicrotask(()=>listeners.forEach(fn=>fn({name:m.name,data:{jsonrpc:'2.0',id:r.id,error:{code:mode==='pending-wallet-request'?-32002:-32602,message:'PRIVATE PROVIDER TEXT'}}})));return;
          }
          if(r.method==='metamask_getProviderState')result={isUnlocked:true,chainId:'0x14a34',networkVersion:'84532',accounts:[f.review.payer]};
          else if(r.method==='eth_requestAccounts'){connected=true;result=[f.review.payer];}
          else if(r.method==='eth_accounts')result=connected?[f.review.payer]:[];
          else if(r.method==='eth_chainId')result='0x14a34';
          else if(r.method==='eth_getCode')result=mode==='changed-wallet'?'0x':r.params[0]===f.review.implementation?f.implementation_runtime:'0xef0100'+f.review.implementation.slice(2);
          else if(r.method==='eth_getTransactionCount')result=Number(BigInt(f.review.transaction.nonce));
          else if(r.method==='eth_getBalance')result='0x1000000000000000000';
          else if(r.method==='eth_call')result='0x';
          else if(r.method==='eth_sendTransaction'){
            if(mode==='cancel'){queueMicrotask(()=>listeners.forEach(fn=>fn({name:m.name,data:{jsonrpc:'2.0',id:r.id,error:{code:4001,message:'owner declined'}}})));return;}
            if(mode!=='unknown-reload')void chrome.runtime.sendMessage({sameFixturePaid:true});result=mode.startsWith('unknown')?null:f.transaction_hash;
          }else throw Error('Unexpected wallet request '+r.method);
          queueMicrotask(()=>listeners.forEach(fn=>fn({name:m.name,data:{jsonrpc:'2.0',id:r.id,result}})));
        }};
      })as any;
    },{f,mode});
    const page=await context.newPage();await page.goto(`chrome-extension://${new URL(worker.url()).host}/public-tickets.html`);
    await expect(page.getByRole('heading',{name:'Finish your saved purchase',exact:true})).toBeVisible();
    expect(await page.evaluate(()=>(globalThis as any).sameWalletRequests)).toEqual([]);
    if(mode==='interrupted-poll'){
      await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));
      await expect.poll(()=>worker.evaluate(()=>(globalThis as any).sameFixture.calls.filter((v:any)=>v.body?.operation==='public-ticket-bulk-progress').length)).toBe(2);
    }
    await page.getByRole('button',{name:'Review saved purchase',exact:true}).click();
    await expect(page.getByText('50 tickets · 0.0025 test ETH',{exact:true})).toBeVisible();
    if(mode==='interrupted-poll')expect(await page.getByText('Payment could not be checked',{exact:true}).count()).toBe(0);
    if(mode==='success')await page.screenshot({path:testInfo.outputPath('saved-purchase-review.png'),fullPage:true});
    if(mode==='authorization-only'){
      expect(await page.getByText('The saved wallet request is being checked automatically.',{exact:false}).count()).toBe(0);
      expect(await page.evaluate(()=>(globalThis as any).sameWalletRequests.some((r:any)=>r.method==='eth_sendTransaction'))).toBe(false);return;
    }
    await page.getByRole('button',{name:'Confirm in MetaMask',exact:true}).click({clickCount:2});
    if(mode==='cancel')await expect(page.getByText('Cancelled in MetaMask. Your saved purchase is preserved.')).toBeVisible();
    else if(mode==='unknown-reload'){
      await expect(page.getByText('The wallet request has no confirmed outcome. Open MetaMask to check whether it is awaiting approval.')).toBeVisible();
      expect(await page.evaluate(()=>(globalThis as any).sameWalletRequests.filter((r:any)=>r.method==='eth_sendTransaction').length)).toBe(1);
      await page.reload();await expect(page.getByText('The wallet request has no confirmed outcome. Open MetaMask to check whether it is awaiting approval.')).toBeVisible();
      expect(await page.evaluate(()=>(globalThis as any).sameWalletRequests.some((r:any)=>r.method==='eth_sendTransaction'))).toBe(false);return;
    }
    else if(mode==='changed-wallet')await expect(page.getByRole('alert')).toContainText('wallet account code changed');
    else if(['read-error','post-authorization-error','native-error','pending-wallet-request','connection-required'].includes(mode)){
      await expect(page.getByRole('alert')).toBeVisible();
      await expect(page.getByText('This step stopped before requesting a transaction. Your saved purchase is preserved.')).toBeVisible();
      expect(await page.getByText('The saved wallet request is being checked automatically.',{exact:false}).count()).toBe(0);
      expect(await page.getByText('PRIVATE PROVIDER TEXT',{exact:false}).count()).toBe(0);
      await page.getByText('Connection details',{exact:true}).click();
      const diagnostic=JSON.parse(await page.getByLabel('Public wallet diagnostic').inputValue());expect(diagnostic.transaction_requested).toBe(false);
      if(mode.includes('error')&&mode!=='native-error')expect(diagnostic).toMatchObject({method:'eth_getCode',code:-32602});
      if(mode==='pending-wallet-request')await expect(page.getByRole('alert')).toContainText('existing request');
      if(mode==='connection-required'){
        await page.getByRole('button',{name:'Connect MetaMask',exact:true}).click();await expect(page.getByText('MetaMask connected. Review the purchase before paying.')).toBeVisible();
        await page.getByRole('button',{name:'Check MetaMask connection',exact:true}).click();await expect(page.getByText('MetaMask connection checks passed. No payment was requested.')).toBeVisible();
      }
    }
    else await expect(page.getByRole('status')).toContainText('50 tickets ready to use.',{timeout:20000});
    const calls=await page.evaluate(()=>(globalThis as any).sameWalletRequests);
    const sent=['success','cancel','unknown','interrupted-poll'].includes(mode);
    expect(calls.filter((r:any)=>r.method==='eth_sendTransaction')).toHaveLength(sent?1:0);
    if(sent)expect(calls.find((r:any)=>r.method==='eth_sendTransaction').params).toEqual([f.review.transaction]);
    expect(calls.filter((r:any)=>r.method==='eth_requestAccounts')).toHaveLength(mode==='connection-required'?1:0);
    expect(calls.some((r:any)=>r.method==='eth_call')).toBe(false);
    expect(calls.some((r:any)=>/wallet_sendCalls|signTypedData|signAuthorization|wallet_switchEthereumChain/.test(r.method))).toBe(false);
    const native=await worker.evaluate(()=>(globalThis as any).sameFixture.calls);
    expect(native.some((r:any)=>/bulk-prepare|bulk-arm/.test(r.body?.operation??r.operation))).toBe(false);
    expect(native.filter((r:any)=>r.body?.operation==='public-ticket-bulk-self-arm')).toHaveLength(['changed-wallet','read-error','pending-wallet-request','connection-required'].includes(mode)?0:1);
  }finally{await context.close();await rm(dir,{recursive:true,force:true});}
});
