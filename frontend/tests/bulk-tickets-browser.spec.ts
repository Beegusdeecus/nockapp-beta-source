import { test, expect, chromium } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalAscii } from '../src/authoredWallet';
const fixture=JSON.parse(readFileSync(new URL('./fixtures/public-tickets-v6-20261101.json',import.meta.url),'utf8'));
for(const mode of ['purchase','lost-wallet','lost-import','saved-armed','unsupported','prepared-single','crash-slot-release','older-single','not-seen','wallet-pending','wallet-rejected','wallet-status-unavailable','lost-wallet-pending','one-call-purchase','one-call-lost-reply','one-call-lost-import','legacy-blocked','earlier-unpaid','earlier-paid','earlier-hash','earlier-wrong-hash','invalid-migrated-status'])test(`50-ticket browser flow ${mode}`,async({},testInfo)=>{
  const f=structuredClone(fixture);const oneCall=mode.startsWith('one-call-')||['legacy-blocked','invalid-migrated-status'].includes(mode);
  if(['legacy-blocked','invalid-migrated-status'].includes(mode))f.offer.manifest.terms.pack_price_wei='100000000000000';
  if(oneCall){Object.assign(f.offer.manifest.terms,{profile:'nockapp-public-prepaid-batch-offer-v3',payment_receipt_version:2,packs_per_payment:25});f.offer.parameters=createHash('sha256').update('nockapp-ticket-offer-manifest-v3\0'+canonicalAscii(f.offer.manifest)).digest('hex');}
  const oldCalls=Array.from({length:25},(_,i)=>({to:f.offer.manifest.purchase_contract,value:'0x'+BigInt(f.offer.manifest.terms.pack_price_wei).toString(16),data:'0x9c9a1061'+(i+1).toString(16).padStart(64,'0')}));
  const calls=oneCall?[{to:f.offer.manifest.purchase_contract,value:'0x'+(25n*BigInt(f.offer.manifest.terms.pack_price_wei)).toString(16),data:'0xfe0ff097'+oldCalls.map(c=>c.data.slice(-64)).join('')}]:oldCalls;
  if(['prepared-single','crash-slot-release'].includes(mode))calls[0].data=f.prepared.transaction.data;
  const batch_id=createHash('sha256').update(canonicalAscii({parameters:f.offer.parameters,packs:oldCalls.map(c=>'0x'+c.data.slice(-64))})).digest('hex');
  const base={profile:oneCall?'nockapp-ticket-bulk-purchase-v2':'nockapp-ticket-bulk-purchase-v1',phase:'prepared',batch_id,ticket_count:50,pack_count:25,imported_tickets:0,settled_tickets:0,refunded_tickets:0,payer:null,transaction_hash:null,total_price_wei:(25n*BigInt(f.offer.manifest.terms.pack_price_wei)).toString(),calls};
  const profile=await mkdtemp(resolve(tmpdir(),'nockapp-bulk-tickets-'));const path=resolve('dist');
  const context=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${path}`,`--load-extension=${path}`,'--no-sandbox']});
  try{
    const worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker');
    await worker.evaluate(async({f,base,mode})=>{
      const earlier=mode.startsWith('earlier-');const state:any={single:['prepared-single','crash-slot-release','older-single'].includes(mode)?structuredClone(f.pending_prepared):structuredClone(f.empty),bulk:!['purchase','unsupported','prepared-single','older-single','one-call-purchase','one-call-lost-reply','one-call-lost-import','legacy-blocked','invalid-migrated-status'].includes(mode)?{...base,phase:'armed',payer:f.rpc.payer}:undefined,finalBlock:100,finalized:!['saved-armed','crash-slot-release','not-seen'].includes(mode),available:0,lost:false,calls:[]};Object.assign(globalThis,{bulkTest:state});
      if(['wallet-pending','wallet-rejected','wallet-status-unavailable','lost-wallet-pending'].includes(mode))await chrome.storage.local.set({'nockapp:ticket:wallet-display:v1':{profile:'nockapp-ticket-wallet-display-v2',batch:base.batch_id,id:'0x'+'ab'.repeat(32),error:mode==='wallet-rejected'?4001:null}});
      chrome.runtime.connectNative=(()=>{
        const listeners=new Set<(v:unknown)=>void>();
        return {onMessage:{addListener:(fn:(v:unknown)=>void)=>listeners.add(fn),removeListener:(fn:(v:unknown)=>void)=>listeners.delete(fn)},onDisconnect:{addListener:()=>{},removeListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>{
          state.calls.push(structuredClone(m));let result:any;
          const replyId=m.id;const replyProfile=m.profile;
          if(m.operation==='public-ticket-earlier-recovery'){
            if(m.body.parameters!==f.offer.parameters||!/public-ticket-bulk-(status|progress|recover|resume|record-payment)$/.test(m.body.operation))throw Error('Recovery scope changed');
            m={...m,operation:m.body.operation,body:m.body.body};
          }
          if(m.operation==='public-ticket-earlier-status'){
            result={profile:'nockapp-earlier-ticket-purchases-v1',purchases:earlier?[{parameters:f.offer.parameters,offer:f.offer,purchase:state.bulk}]:[]};
            queueMicrotask(()=>listeners.forEach(fn=>fn({profile:replyProfile,id:replyId,status:'ok',result:structuredClone(result),laboratory:true,verified:false})));return;
          }
          const capabilities={configured:true,protocol:5,scope:f.scope,verifier_release:mode==='older-single'?10:12,publication_mode:'tickets',anonymous_ticket_packs:true,follower_proof_configured:true,source_enrollment_configured:true,historical_issuer_views:true,refund_payout_configured:false};if(earlier)Object.assign(capabilities,{ticket_page_snapshot:true});
          const inventory=()=>({profile:'nockapp-protected-ticket-wallet-v1',available:state.available,reserved:6,purchase_pending:(mode==='legacy-blocked'||earlier)||!!state.single.purchase||!!state.bulk&&state.bulk.phase!=='complete',initialized:mode!=='invalid-migrated-status',
            can_purchase:mode!=='legacy-blocked'&&!earlier,can_redeem:true,pack_size:2,pack_price_wei:f.offer.manifest.terms.pack_price_wei,purchase_before:f.offer.manifest.terms.purchase_before,redeem_before:f.offer.manifest.terms.redeem_before,refund_policy:f.offer.manifest.terms.refund_policy,prepaid_custody:true});
          const earlierPurchases=()=>({profile:'nockapp-earlier-ticket-purchases-v1',purchases:earlier&&state.bulk?.phase!=='complete'?[{parameters:f.offer.parameters,offer:f.offer,purchase:state.bulk}]:[]});
          if(m.operation==='public-ticket-page'){
            result={profile:'nockapp-ticket-page-v1',capabilities,offer:f.offer,bulk:{profile:base.profile,phase:'none'},pending:state.single,refund:null,inventory:inventory(),earlier:earlierPurchases()};
            queueMicrotask(()=>listeners.forEach(fn=>fn({profile:replyProfile,id:replyId,status:'ok',result:structuredClone(result),laboratory:true,verified:false})));return;
          }
          if(m.operation==='public-capabilities')result=capabilities;
          else if(m.operation==='public-ticket-offer')result=f.offer;
          else if(m.operation==='public-ticket-pending')result=state.single;
          else if(m.operation==='public-ticket-status')result=inventory();
          else if(m.operation==='public-ticket-bulk-status')result=(earlier&&!state.calls.at(-1)?.body?.parameters?undefined:state.bulk)??{profile:base.profile,phase:'none'};
          else if(m.operation==='public-ticket-bulk-prepare'){state.bulk??=structuredClone(base);result=state.bulk;}
          else if(m.operation==='public-ticket-bulk-arm'){state.single=structuredClone(f.empty);if(state.bulk.phase!=='prepared')throw Error('Duplicate dispatch');state.bulk={...state.bulk,phase:'armed',payer:m.body.payer};result={...state.bulk,dispatch_authorized:true};}
          else if(m.operation==='public-ticket-bulk-progress')result={profile:'nockapp-ticket-payment-progress-v1',batch_id:base.batch_id,pack_hash:'0x'+(mode.startsWith('one-call-')?base.calls[0].data.slice(10,74):base.calls[0].data.slice(-64)),state:['earlier-unpaid','earlier-hash','earlier-wrong-hash','not-seen','wallet-pending','wallet-rejected','wallet-status-unavailable','lost-wallet-pending'].includes(mode)?'not-seen':state.finalized?'finalized':'confirming',latest_block:120,finalized_block:state.finalized?115:state.finalBlock,payment_block:mode==='not-seen'||mode.startsWith('earlier-')||state.finalized?null:110};
          else if(m.operation==='public-ticket-bulk-record-payment'){
            if(mode==='earlier-wrong-hash'){queueMicrotask(()=>listeners.forEach(fn=>fn({profile:replyProfile,id:replyId,status:'rejected',code:'native-operation-unavailable',recoverable:true,laboratory:true,verified:false})));return;}
            if(m.body.transaction_hash!==f.paid.payment_tx||!m.body.approve_recovery)throw Error('Wrong payment');
            state.bulk={...state.bulk,phase:'importing',transaction_hash:f.paid.payment_tx};result=state.bulk;
          }
          else if(m.operation==='public-ticket-bulk-recover'){
            state.single=structuredClone(f.empty);state.bulk={...state.bulk,phase:state.bulk.imported_tickets>=48?'complete':'importing',imported_tickets:state.bulk.imported_tickets+2,settled_tickets:state.bulk.settled_tickets+2,transaction_hash:f.paid.payment_tx};state.available=state.bulk.imported_tickets;result=state.bulk;
            if(['lost-import','one-call-lost-import'].includes(mode)&&!state.lost){state.lost=true;queueMicrotask(()=>listeners.forEach(fn=>fn({profile:m.profile,id:m.id,status:'rejected',code:'native-operation-unavailable',recoverable:true,laboratory:true,verified:false})));return;}
          }else throw Error('Unexpected bulk native operation: '+m.operation);
          queueMicrotask(()=>listeners.forEach(fn=>fn({profile:m.profile,id:m.id,status:'ok',result:structuredClone(result),laboratory:true,verified:false})));
        }};
      }) as any;
    },{f,base,mode});
    await context.addInitScript(({f,mode})=>{
      if(!chrome.runtime?.connect)return;
      Date.now=()=>f.now*1000;const calls:any[]=[];Object.assign(globalThis,{bulkWalletCalls:calls});const original=chrome.runtime.connect.bind(chrome.runtime);
      chrome.runtime.connect=((...args:any[])=>{
        if(typeof args[0]!=='string')return(original as any)(...args);
        const listeners=new Set<(v:unknown)=>void>();return{onMessage:{addListener:(fn:(v:unknown)=>void)=>listeners.add(fn)},onDisconnect:{addListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>{
          const r=m.data;if(!r?.method)return;calls.push(structuredClone(r));let result;
          if(r.method==='metamask_getProviderState')result={isUnlocked:true,chainId:'0x14a34',networkVersion:'84532',accounts:[f.rpc.payer]};
          else if(['eth_accounts','eth_requestAccounts'].includes(r.method))result=[f.rpc.payer];
          else if(r.method==='eth_chainId')result='0x14a34';
          else if(r.method==='wallet_getCapabilities')result={'0x14a34':{atomic:{status:mode==='unsupported'?'ready':'supported'}}};
          else if(r.method==='wallet_sendCalls'){
            if(['lost-wallet','wallet-rejected','lost-wallet-pending','one-call-lost-reply'].includes(mode)){queueMicrotask(()=>listeners.forEach(fn=>fn({name:m.name,data:{jsonrpc:'2.0',id:r.id,error:{code:mode==='wallet-rejected'?4001:-32000,message:'synthetic-private-error-not-for-display'}}})));return;}
            result={id:r.params[0].id};
          }else if(r.method==='wallet_getCallsStatus'){
            if(mode==='wallet-status-unavailable'||mode==='wallet-rejected'){queueMicrotask(()=>listeners.forEach(fn=>fn({name:m.name,data:{jsonrpc:'2.0',id:r.id,error:{code:-32000,message:'synthetic-unavailable'}}})));return;}
            result={version:'2.0.0',id:r.params[0],chainId:'0x14a34',atomic:true,status:100};
          }else throw Error('Unexpected bulk wallet operation');
          queueMicrotask(()=>listeners.forEach(fn=>fn({name:m.name,data:{jsonrpc:'2.0',id:r.id,result}})));
        }};
      }) as any;
    },{f,mode});
    const page=await context.newPage();await page.goto(`chrome-extension://${new URL(worker.url()).host}/public-tickets.html`);
    if(mode.startsWith('earlier-')){
      if(mode!=='earlier-paid'){
        await expect(page.getByRole('heading',{name:'Payment not found',exact:true})).toBeVisible();
        await expect(page.getByRole('status')).toContainText('Check MetaMask');
        await expect(page.getByText('Purchase steps: 25% complete.')).toHaveCount(0);
        await expect(page.getByText('Payment needs investigation.',{exact:false})).toHaveCount(0);
        expect(await page.locator('body').innerText()).not.toContain('Latest block');
        if(mode==='earlier-unpaid')await page.screenshot({path:testInfo.outputPath('simple-recovery.png'),fullPage:true});
        if(mode==='earlier-hash'||mode==='earlier-wrong-hash'){
          await page.getByLabel('If it says Confirmed, paste its transaction hash').fill(f.paid.payment_tx);
          await page.getByRole('button',{name:'Verify payment',exact:true}).click();
          if(mode==='earlier-wrong-hash'){
            await expect(page.getByRole('alert')).toContainText('could not be verified for this purchase');
            await expect(page.getByText('0 available · 6 assigned to posts')).toBeVisible();
          }
        }
      }
      if(mode==='earlier-paid'||mode==='earlier-hash')await expect(page.getByText('50 available · 6 assigned to posts')).toBeVisible({timeout:20000});
      await expect(page.getByRole('button',{name:/Review.*tickets|Pay for/})).toHaveCount(0);
      expect(await page.evaluate(()=>(globalThis as any).bulkWalletCalls)).toEqual([]);
      const requests=await worker.evaluate(()=>(globalThis as any).bulkTest.calls);
      expect(requests.some((r:any)=>/prepare|arm/.test(r.operation))).toBe(false);
      expect(requests.some((r:any)=>['public-ticket-offer','public-ticket-pending','public-ticket-status','public-ticket-earlier-status'].includes(r.operation))).toBe(false);
      expect(requests.filter((r:any)=>r.operation==='public-ticket-earlier-recovery').every((r:any)=>r.body.parameters===f.offer.parameters)).toBe(true);
      return;
    }
    if(mode==='legacy-blocked'){
      await expect(page.getByRole('status')).toContainText('No unfinished 50-ticket checkout was found.');
      await expect(page.getByText('0 available · 6 assigned to posts')).toBeVisible();
      await expect(page.getByRole('button',{name:/Review.*tickets|Pay for/})).toHaveCount(0);
      expect(await page.evaluate(()=>(globalThis as any).bulkWalletCalls)).toEqual([]);
      expect((await worker.evaluate(()=>(globalThis as any).bulkTest.calls)).some((r:any)=>/prepare|arm|recover/.test(r.operation))).toBe(false);
      await worker.evaluate(()=>{(globalThis as any).bulkTest.available=2;});await page.reload();
      await expect(page.getByRole('status')).toContainText('No unfinished 50-ticket checkout was found.');
      await expect(page.getByText('2 available · 6 assigned to posts')).toBeVisible();
      await expect(page.getByText('Buy another pack',{exact:true})).toHaveCount(0);
      return;
    }
    if(mode==='invalid-migrated-status'){
      await expect(page.getByRole('alert')).toContainText('unsupported response');
      const before=await worker.evaluate(()=>(globalThis as any).bulkTest.calls);
      expect(before.filter((r:any)=>r.operation==='public-ticket-status')).toHaveLength(1);
      expect(before.filter((r:any)=>r.operation==='public-capabilities')).toHaveLength(1);
      expect(await page.evaluate(()=>(globalThis as any).bulkWalletCalls)).toEqual([]);
      return;
    }
    if(oneCall){
      await page.getByRole('checkbox',{name:'I accept this price, expiry and prepaid custody risk.'}).check();
      await page.getByRole('button',{name:'Review 50 tickets',exact:true}).click();
      await page.getByRole('button',{name:'Pay for 50 tickets in MetaMask',exact:true}).click();
      if(mode==='one-call-lost-import'){
        await expect(page.getByRole('alert')).toBeVisible();
        await page.getByText('Payment details',{exact:true}).click();
        await page.getByRole('button',{name:'Check saved payment',exact:true}).click();
      }
      await expect(page.getByRole('status')).toContainText('50 tickets ready to use.');
      const wallet=await page.evaluate(()=>(globalThis as any).bulkWalletCalls);
      const sends=wallet.filter((r:any)=>r.method==='wallet_sendCalls');expect(sends).toHaveLength(1);
      expect(sends[0].params[0].calls).toEqual(calls);expect(sends[0].params[0].atomicRequired).toBe(false);
      expect(wallet.some((r:any)=>['wallet_getCapabilities','wallet_upgradeAccount','eth_sendTransaction'].includes(r.method))).toBe(false);
      const native=await worker.evaluate(()=>(globalThis as any).bulkTest.calls);
      expect(native.filter((r:any)=>r.operation==='public-ticket-bulk-arm')).toHaveLength(1);
      await page.reload();await expect(page.getByRole('status')).toContainText('50 tickets ready to use.');
      expect((await page.evaluate(()=>(globalThis as any).bulkWalletCalls)).filter((r:any)=>r.method==='wallet_sendCalls')).toHaveLength(0);
      return;
    }
    if(mode==='not-seen'){
      await expect(page.getByRole('status')).toContainText('Payment needs investigation');
      await expect(page.getByRole('progressbar',{name:'50-ticket purchase completion'})).toHaveCount(0);
      await page.evaluate(()=>{Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async(v:string)=>{Object.assign(globalThis,{copiedDiagnostic:v});}}});});
      await page.getByRole('button',{name:'Copy payment diagnostic',exact:true}).click();
      const diagnostic=JSON.parse(await page.evaluate(()=>(globalThis as any).copiedDiagnostic));
      expect(diagnostic.batch_id).toBe(batch_id);expect(diagnostic.first_pack_hash).toBe('0x'+calls[0].data.slice(-64));
      expect(Object.keys(diagnostic)).not.toContain('calls');expect(Object.keys(diagnostic)).not.toContain('requests');
      await expect(page.getByText('Unissued-pack refund',{exact:true})).toHaveCount(0);
      await expect(page.getByRole('progressbar',{name:'Payment finality progress'})).toHaveCount(0);
      expect(await page.evaluate(()=>(globalThis as any).bulkWalletCalls)).toEqual([]);return;
    }
    if(mode==='older-single'){
      await expect(page.getByRole('button',{name:'Review ticket purchase',exact:true})).toBeVisible();
      await expect(page.getByRole('button',{name:'Review 50 tickets',exact:true})).toHaveCount(0);
      expect((await worker.evaluate(()=>(globalThis as any).bulkTest.calls)).some((r:any)=>r.operation==='public-ticket-bulk-prepare')).toBe(false);return;
    }
    async function checkSaved(){const button=page.getByRole('button',{name:'Check saved payment',exact:true});if(!await button.isVisible())await page.getByText('Payment details',{exact:true}).click();await button.click();}
    if(['saved-armed','crash-slot-release'].includes(mode)){
      await expect(page.getByRole('status')).toContainText('Waiting for chain finality');
      expect(await page.evaluate(()=>(globalThis as any).bulkWalletCalls)).toEqual([]);
      await expect(page.getByText('Finality target: payment block 110.',{exact:false})).toContainText('10 blocks remain');
      await expect(page.getByRole('progressbar',{name:'Payment finality progress'})).toHaveAttribute('value','0');
      await worker.evaluate(()=>{(globalThis as any).bulkTest.finalBlock=105;});
      await checkSaved();
      await expect(page.getByRole('progressbar',{name:'Payment finality progress'})).toHaveAttribute('value','50');
      await expect(page.getByText('Finality target: payment block 110.',{exact:false})).toContainText('5 blocks remain');
      await page.reload();
      await expect(page.getByRole('progressbar',{name:'Payment finality progress'})).toHaveAttribute('value','50');
      await worker.evaluate(()=>{(globalThis as any).bulkTest.finalized=true;});await checkSaved();
    }else if(['purchase','unsupported','prepared-single'].includes(mode)){
      await expect(page.getByRole('note',{name:'50-ticket checkout unavailable'})).toContainText('temporarily unavailable');
      expect(await page.evaluate(()=>(globalThis as any).bulkWalletCalls)).toEqual([]);
      const calls=await worker.evaluate(()=>(globalThis as any).bulkTest.calls);
      expect(calls.some((r:any)=>['public-ticket-bulk-prepare','public-ticket-bulk-arm'].includes(r.operation))).toBe(false);return;
    }else if(['wallet-pending','wallet-rejected','wallet-status-unavailable','lost-wallet-pending'].includes(mode)){
      const expected=mode==='wallet-rejected'?'MetaMask rejected the payment request':['wallet-pending','lost-wallet-pending'].includes(mode)?'MetaMask is still processing the payment':'MetaMask payment status is unavailable';
      await expect(page.getByText(expected,{exact:false})).toBeVisible();
      await expect(page.getByRole('button',{name:'Pay for 50 tickets in MetaMask',exact:true})).toHaveCount(0);
      expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
      await page.screenshot({path:testInfo.outputPath('payment-status.png'),fullPage:true});
      await page.reload();await expect(page.getByText(expected,{exact:false})).toBeVisible();
      expect((await page.evaluate(()=>(globalThis as any).bulkWalletCalls)).some((r:any)=>r.method==='wallet_sendCalls')).toBe(false);
      expect((await worker.evaluate(()=>(globalThis as any).bulkTest.calls)).filter((r:any)=>r.operation==='public-ticket-bulk-recover')).toHaveLength(0);return;
    }else if(mode==='lost-import'){
      await expect(page.getByRole('alert')).toBeVisible();await checkSaved();
    }
    await expect(page.getByRole('status')).toContainText('50 tickets ready to use.');
    await expect(page.getByRole('progressbar',{name:'Ticket purchase completion',exact:true})).toHaveAttribute('value','4');
    const wallet=await page.evaluate(()=>(globalThis as any).bulkWalletCalls);expect(wallet.filter((r:any)=>r.method==='wallet_sendCalls')).toHaveLength(0);
    expect(wallet.some((r:any)=>r.method==='eth_sendTransaction')).toBe(false);
    const native=await worker.evaluate(()=>(globalThis as any).bulkTest.calls);expect(native.filter((r:any)=>r.operation==='public-ticket-bulk-arm')).toHaveLength(0);
    if(mode==='prepared-single'){
      const prepared=native.find((r:any)=>r.operation==='public-ticket-bulk-prepare');expect(prepared.body.include_prepared_pack).toBe(true);
    }
    // A completed purchase is historical. Spending its tickets must not turn
    // that receipt into a claim that 50 are still available, or repay it.
    await worker.evaluate(()=>{(globalThis as any).bulkTest.available=0;});
    await page.reload();
    await expect(page.getByRole('status')).toContainText('50 tickets imported');
    await expect(page.getByText('0 available · 6 assigned to posts')).toBeVisible();
    await expect(page.getByRole('button',{name:'Pay for 50 tickets in MetaMask',exact:true})).toHaveCount(0);
    expect((await page.evaluate(()=>(globalThis as any).bulkWalletCalls)).filter((r:any)=>r.method==='wallet_sendCalls')).toHaveLength(0);
  }finally{await context.close();await rm(profile,{recursive:true,force:true});}
});
