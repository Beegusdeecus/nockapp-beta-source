import { test, expect, chromium } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalAscii } from '../src/authoredWallet';
const fixture=JSON.parse(readFileSync(new URL('./fixtures/public-tickets-v6-20261101.json',import.meta.url),'utf8'));
for(const mode of ['purchase','lost-wallet','lost-import','saved-armed','unsupported','prepared-single','crash-slot-release','older-single','not-seen'])test(`50-ticket browser flow ${mode}`,async()=>{
  const f=fixture;const calls=Array.from({length:25},(_,i)=>({to:f.offer.manifest.purchase_contract,value:'0x'+BigInt(f.offer.manifest.terms.pack_price_wei).toString(16),data:'0x9c9a1061'+(i+1).toString(16).padStart(64,'0')}));
  if(['prepared-single','crash-slot-release'].includes(mode))calls[0].data=f.prepared.transaction.data;
  const batch_id=createHash('sha256').update(canonicalAscii({parameters:f.offer.parameters,packs:calls.map(c=>'0x'+c.data.slice(-64))})).digest('hex');
  const base={profile:'nockapp-ticket-bulk-purchase-v1',phase:'prepared',batch_id,ticket_count:50,pack_count:25,imported_tickets:0,settled_tickets:0,refunded_tickets:0,payer:null,transaction_hash:null,total_price_wei:(25n*BigInt(f.offer.manifest.terms.pack_price_wei)).toString(),calls};
  const profile=await mkdtemp(resolve(tmpdir(),'nockapp-bulk-tickets-'));const path=resolve('dist');
  const context=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${path}`,`--load-extension=${path}`,'--no-sandbox']});
  try{
    const worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker');
    await worker.evaluate(({f,base,mode})=>{
      const state:any={single:['prepared-single','crash-slot-release','older-single'].includes(mode)?structuredClone(f.pending_prepared):structuredClone(f.empty),bulk:['saved-armed','crash-slot-release','not-seen'].includes(mode)?{...base,phase:'armed',payer:f.rpc.payer}:undefined,finalBlock:100,finalized:!['saved-armed','crash-slot-release','not-seen'].includes(mode),available:0,lost:false,calls:[]};Object.assign(globalThis,{bulkTest:state});
      chrome.runtime.connectNative=(()=>{
        const listeners=new Set<(v:unknown)=>void>();
        return {onMessage:{addListener:(fn:(v:unknown)=>void)=>listeners.add(fn),removeListener:(fn:(v:unknown)=>void)=>listeners.delete(fn)},onDisconnect:{addListener:()=>{},removeListener:()=>{}},disconnect:()=>{},postMessage:(m:any)=>{
          state.calls.push(structuredClone(m));let result;
          if(m.operation==='public-capabilities')result={configured:true,protocol:5,scope:f.scope,verifier_release:['prepared-single','crash-slot-release'].includes(mode)?12:11,publication_mode:'tickets',anonymous_ticket_packs:true,follower_proof_configured:true,source_enrollment_configured:true,historical_issuer_views:true,refund_payout_configured:false};
          else if(m.operation==='public-ticket-offer')result=f.offer;
          else if(m.operation==='public-ticket-pending')result=state.single;
          else if(m.operation==='public-ticket-status')result={profile:'nockapp-protected-ticket-wallet-v1',available:state.available,reserved:6,purchase_pending:!!state.single.purchase||!!state.bulk&&state.bulk.phase!=='complete',initialized:true,
            can_purchase:true,can_redeem:true,pack_size:2,pack_price_wei:f.offer.manifest.terms.pack_price_wei,purchase_before:f.offer.manifest.terms.purchase_before,redeem_before:f.offer.manifest.terms.redeem_before,refund_policy:f.offer.manifest.terms.refund_policy,prepaid_custody:true};
          else if(m.operation==='public-ticket-bulk-status')result=state.bulk??{profile:base.profile,phase:'none'};
          else if(m.operation==='public-ticket-bulk-prepare'){state.bulk??=structuredClone(base);result=state.bulk;}
          else if(m.operation==='public-ticket-bulk-arm'){state.single=structuredClone(f.empty);if(state.bulk.phase!=='prepared')throw Error('Duplicate dispatch');state.bulk={...state.bulk,phase:'armed',payer:m.body.payer};result={...state.bulk,dispatch_authorized:true};}
          else if(m.operation==='public-ticket-bulk-progress')result={profile:'nockapp-ticket-payment-progress-v1',batch_id:base.batch_id,pack_hash:'0x'+base.calls[0].data.slice(-64),state:mode==='not-seen'?'not-seen':state.finalized?'finalized':'confirming',latest_block:120,finalized_block:state.finalized?115:state.finalBlock,payment_block:mode==='not-seen'||state.finalized?null:110};
          else if(m.operation==='public-ticket-bulk-recover'){
            state.single=structuredClone(f.empty);state.bulk={...state.bulk,phase:state.bulk.imported_tickets>=48?'complete':'importing',imported_tickets:state.bulk.imported_tickets+2,settled_tickets:state.bulk.settled_tickets+2,transaction_hash:f.paid.payment_tx};state.available=state.bulk.imported_tickets;result=state.bulk;
            if(mode==='lost-import'&&!state.lost){state.lost=true;queueMicrotask(()=>listeners.forEach(fn=>fn({profile:m.profile,id:m.id,status:'rejected',code:'native-operation-unavailable',recoverable:true,laboratory:true,verified:false})));return;}
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
            if(mode==='lost-wallet'){queueMicrotask(()=>listeners.forEach(fn=>fn({name:m.name,data:{jsonrpc:'2.0',id:r.id,error:{code:-32000,message:'synthetic-lost-reply'}}})));return;}
            result={id:'0x'+'ab'.repeat(32)};
          }else throw Error('Unexpected bulk wallet operation');
          queueMicrotask(()=>listeners.forEach(fn=>fn({name:m.name,data:{jsonrpc:'2.0',id:r.id,result}})));
        }};
      }) as any;
    },{f,mode});
    const page=await context.newPage();await page.goto(`chrome-extension://${new URL(worker.url()).host}/public-tickets.html`);
    if(mode==='not-seen'){
      await expect(page.getByRole('status')).toContainText('Payment not found onchain yet');
      await expect(page.getByText('Finality percentage starts once the payment is found.',{exact:false})).toBeVisible();
      await expect(page.getByRole('progressbar',{name:'Payment finality progress'})).toHaveCount(0);
      expect(await page.evaluate(()=>(globalThis as any).bulkWalletCalls)).toEqual([]);return;
    }
    if(mode==='older-single'){
      await expect(page.getByRole('button',{name:'Review ticket purchase',exact:true})).toBeVisible();
      await expect(page.getByRole('button',{name:'Review 50 tickets',exact:true})).toHaveCount(0);
      expect((await worker.evaluate(()=>(globalThis as any).bulkTest.calls)).some((r:any)=>r.operation==='public-ticket-bulk-prepare')).toBe(false);return;
    }
    if(['saved-armed','crash-slot-release'].includes(mode)){
      await expect(page.getByRole('status')).toContainText('Waiting for chain finality');
      expect(await page.evaluate(()=>(globalThis as any).bulkWalletCalls)).toEqual([]);
      await expect(page.getByText('Finality target: payment block 110.',{exact:false})).toContainText('10 blocks remain');
      await expect(page.getByRole('progressbar',{name:'Payment finality progress'})).toHaveAttribute('value','0');
      await worker.evaluate(()=>{(globalThis as any).bulkTest.finalBlock=105;});
      await page.getByRole('button',{name:'Check saved payment',exact:true}).click();
      await expect(page.getByRole('progressbar',{name:'Payment finality progress'})).toHaveAttribute('value','50');
      await expect(page.getByText('Finality target: payment block 110.',{exact:false})).toContainText('5 blocks remain');
      await page.reload();
      await expect(page.getByRole('progressbar',{name:'Payment finality progress'})).toHaveAttribute('value','50');
      await worker.evaluate(()=>{(globalThis as any).bulkTest.finalized=true;});await page.getByRole('button',{name:'Check saved payment',exact:true}).click();
    }else{
      await page.getByRole('checkbox',{name:/I accept the price, expiry/}).check();await page.getByRole('button',{name:'Review 50 tickets',exact:true}).click();
      if(mode==='unsupported'){
        await expect(page.getByRole('alert')).toContainText('has not enabled');
        expect((await worker.evaluate(()=>(globalThis as any).bulkTest.calls)).some((r:any)=>r.operation==='public-ticket-bulk-prepare')).toBe(false);return;
      }
      await page.getByRole('button',{name:'Pay for 50 tickets in MetaMask',exact:true}).click();
      if(mode==='lost-import'){await expect(page.getByRole('alert')).toBeVisible();await page.getByRole('button',{name:'Check saved payment',exact:true}).click();}
    }
    await expect(page.getByRole('status')).toContainText('Purchase complete. 50 tickets imported.');
    await expect(page.getByRole('progressbar',{name:'50-ticket purchase completion'})).toHaveAttribute('value','4');
    const wallet=await page.evaluate(()=>(globalThis as any).bulkWalletCalls);expect(wallet.filter((r:any)=>r.method==='wallet_sendCalls')).toHaveLength(['saved-armed','crash-slot-release'].includes(mode)?0:1);
    expect(wallet.some((r:any)=>r.method==='eth_sendTransaction')).toBe(false);
    const native=await worker.evaluate(()=>(globalThis as any).bulkTest.calls);expect(native.filter((r:any)=>r.operation==='public-ticket-bulk-arm')).toHaveLength(['saved-armed','crash-slot-release'].includes(mode)?0:1);
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
