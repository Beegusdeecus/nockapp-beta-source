import { test, expect, chromium, type Worker } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
const vectors=JSON.parse(readFileSync(new URL('./fixtures/public-page-contract-v6-20261101-v2.json',import.meta.url),'utf8'));
async function fixture(w:Worker,missingRoot=false,recovery=''){
  await w.evaluate(async({vectors,missingRoot,recovery})=>{
    const get=(op:string)=>structuredClone(vectors.vectors.find((v:any)=>v.operation===op).result);
    const page=get('public-numbers');const root=page.posts[0];root.post.title='A public thread';root.post.body='Opening public message';root.post_number='1';
    root.display.followers={threshold:10,qualified_when_indexed:true,indexed_at:root.indexed_at,credential_profile:'nockapp-renewal-count-v3'};
    root.historical_follower_evidence=root.display.followers;
    const ref={protocol:5,chain_id:84532,contract:get('public-capabilities').scope.contract,number:'1',bundle_hash:root.bundle_hash};
    const reply=(n:number)=>({...structuredClone(root),post_number:String(n),bundle_hash:'0x'+String(n).padStart(2,'0').repeat(32),thread:ref,historical_follower_evidence:null,display:{address:null,followers:null,history:null},post:{...root.post,kind:'comment',title:null,body:'Reply number '+n,id:`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`}});
    const unavailable={...Object.fromEntries(Object.entries(root).filter(([k])=>['bundle_hash','indexed_at','block_number','block_hash','transaction_hash','canonical_indexed'].includes(k))),post_number:'2',state:'content-unavailable',proofs_verified:false};
    const rows=[root,unavailable,reply(3),reply(4),reply(5),reply(6)];
    if(missingRoot){rows[0]={...unavailable,post_number:'1'};for(const r of rows.slice(2))r.relationship_state='unverified';}
    const state={calls:[] as any[],rows,entries:[] as any[],availableTickets:2,history:{} as Record<string,any>,exports:{} as Record<string,any>,historyLost:false,fail:false,hold:false,release:()=>{}};Object.assign(globalThis,{forumFixture:state});
    const saved=get('public-prepare');saved.core.post={...reply(7).post,body:'The exact interrupted comment'};saved.core.thread=ref;saved.core.selection={address:false,followers_threshold:null};saved.bundle_hash='0x'+'55'.repeat(32);saved.phase='bundle-saved';
    if(['pending','pending-then-final','unavailable','edited-draft'].includes(recovery))saved.last_attempt={requested_at:Math.floor(Date.now()/1000)};
    if(recovery==='finalized-no-badge')saved.core.selection.followers_threshold=0;
    if(recovery.startsWith('expired')){saved.core.selection.followers_threshold=0;saved.follower_window='expired';state.availableTickets=0;}
    if(recovery&& !['lost-reply','selected-history','lost-history','omit-history','bad-history'].includes(recovery))state.entries.push(saved);
    Object.assign(state,{statusReady:false});
    if(recovery==='edited-draft'){
      const scope=get('public-capabilities').scope;const key=`reply:public-v5:${scope.application}:${scope.contract}:${root.bundle_hash}:root`;
      await chrome.storage.local.set({'nockapp:public:submission-intents:v5':[{scope,draft_key:key,post:saved.core.post,selection:saved.core.selection,thread:ref,references:[],acknowledged:true,released:false}],['draft:'+key]:{title:'',body:'My newer edited draft',credentials:[]}});
    }
    chrome.runtime.connectNative=(()=>{
      const listeners=new Set<(v:unknown)=>void>();return {onMessage:{addListener:(f:any)=>listeners.add(f),removeListener:(f:any)=>listeners.delete(f)},onDisconnect:{addListener:()=>{},removeListener:()=>{}},disconnect:()=>{},postMessage:async(m:any)=>{
        state.calls.push(structuredClone(m));let result:any;
        if(m.operation==='public-capabilities'){
          result=get(m.operation);
          if(recovery.startsWith('expired'))Object.assign(result,{verifier_release:10,publication_mode:'tickets',follower_proof_configured:true,source_enrollment_configured:true,historical_issuer_views:true,refund_payout_configured:false});
        }
        else if(m.operation==='public-identity-options')result={identity_record_present:true,sources:[]};
        else if(m.operation==='public-ticket-status')result={...structuredClone(vectors.vectors.filter((v:any)=>v.operation===m.operation).at(-1).result),available:state.availableTickets,reserved:6};
        else if(m.operation==='public-outbox')result={entries:state.entries.map(r=>({...r,verification_current:false})),next_after:null};
        else if(m.operation==='public-page'||m.operation==='public-numbers'){
          const numbers=m.operation==='public-page'?state.rows.filter(r=>Number(r.post_number)>m.body.after).slice(0,m.body.limit).map(r=>Number(r.post_number)):m.body.numbers;
          result={...page,posts:numbers.map((n:number)=>state.rows.find(r=>r.post_number===String(n))??{post_number:String(n),state:'unassigned',canonical_indexed:false,proofs_verified:false}),requested_numbers:numbers.map(String),next_number:String(state.rows.length+1),checked_records:numbers.filter((n:number)=>n<=state.rows.length).length};
          if(m.operation==='public-page')Object.assign(result,{after:m.body.after,next_after:m.body.after+numbers.length,more:m.body.after+numbers.length<state.rows.length});
        }else if(m.operation==='public-prepare'){
          result=get('public-prepare');Object.assign(result.core,{post:m.body.post,selection:m.body.selection,thread:m.body.thread,references:m.body.references});result.phase='prepared';const previous=state.entries.find(r=>r.core.post.id===m.body.post.id);if(previous)result=previous;else state.entries.push(result);
        }else if(m.operation==='public-attach-history'){
          result=state.entries.find(r=>r.core.post.id===m.body.post_id);state.history[m.body.post_id]=m.body.records;
          if(recovery==='lost-history'&&!state.historyLost){state.historyLost=true;queueMicrotask(()=>listeners.forEach(f=>f({profile:m.profile,id:m.id,status:'rejected',code:'native-operation-unavailable',recoverable:true,laboratory:true,verified:false})));return;}
        }else if(m.operation==='public-export-submission'){
          result=state.exports[m.body.post_id];
        }else if(m.operation==='public-finish'||m.operation==='public-publish'||m.operation==='public-check'){
          if(m.operation==='public-publish'&&recovery==='expired-no-ticket'){
            queueMicrotask(()=>listeners.forEach(f=>f({profile:m.profile,id:m.id,status:'rejected',code:'publication-ticket-needed',recoverable:true,laboratory:true,verified:false})));return;
          }
          result=state.entries.find(r=>r.core.post.id===m.body.post_id);result.bundle_hash??='0x'+'55'.repeat(32);result.verification_current=m.operation!=='public-finish';
          if(m.operation==='public-finish'){
            result.phase='bundle-saved';
            if(state.history[m.body.post_id]){
              const canonical=(v:any):string=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
              const records=recovery==='omit-history'?[]:state.history[m.body.post_id];
              const evidence=records.length?btoa(canonical({profile:'nockapp-attached-historical-authorship-v5',records,proof:{synthetic:true}})):null;
              const bytes=new TextEncoder().encode(canonical({unsigned:{core:result.core,evidence:{history:evidence}},authorship:{synthetic:true}}));
              result.bundle_hash='0x'+[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
              state.exports[m.body.post_id]={profile:'nockapp-public-submission-v5',scope:get('public-capabilities').scope,bundle_hash:result.bundle_hash,bundle_base64:btoa(String.fromCharCode(...bytes)),calldata:'0xd9caa3d2'+result.bundle_hash.slice(2),contains_private_key:false,personal_wallet_required:false};
            }
          }
          else if(m.operation==='public-publish'){
            result.phase=recovery==='lost-reply'?'bundle-saved':'submitted';result.last_attempt={requested_at:Math.floor(Date.now()/1000)};
            result.last_known={state:'not-indexed',post_number:null,checked_at:Math.floor(Date.now()/1000)};
          }else {
            const final=['finalized','finalized-no-badge','edited-draft','lost-reply'].includes(recovery)||['pending-then-final','unavailable','outbox-unavailable'].includes(recovery)&&(state as any).statusReady;
            result.last_known={state:final?'finalized':'not-indexed',post_number:final?'7':null,checked_at:Math.floor(Date.now()/1000)};
            if(final&&!state.rows.some(r=>r.post_number==='7'))state.rows.push({...reply(7),bundle_hash:result.bundle_hash,post:result.core.post,indexed_at:Math.max(Math.floor(Date.now()/1000),result.core.post.created_at)});
          }
        }else throw Error('Unexpected forum operation '+m.operation);
        const send=()=>listeners.forEach(f=>f((state.fail&&m.operation.startsWith('public-page')||m.operation==='public-publish'&&recovery==='lost-reply'||m.operation==='public-outbox'&&recovery==='outbox-unavailable'&&!(state as any).statusReady||m.operation==='public-check'&&recovery==='unavailable'&&!(state as any).statusReady)?{profile:m.profile,id:m.id,status:'rejected',code:'native-operation-unavailable',recoverable:true,laboratory:true,verified:false}:{profile:m.profile,id:m.id,status:'ok',result,laboratory:true,verified:false}));
        if(state.hold&&m.operation==='public-page')state.release=send;else queueMicrotask(send);
      }};
    }) as unknown as typeof chrome.runtime.connectNative;
  },{vectors,missingRoot,recovery});
}
for(const mode of ['feed-and-thread','missing-root','automatic-check','reply','progressive-thread','unassigned','refresh-keeps-posts','failed-refresh-keeps-posts'] as const)test(`canonical forum ${mode}`,async()=>{
  const profile=await mkdtemp(resolve(tmpdir(),'nockapp-canonical-'));const path=resolve('dist');
  const c=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,viewport:{width:390,height:844},args:[`--disable-extensions-except=${path}`,`--load-extension=${path}`,'--no-sandbox']});
  try{
    const w=c.serviceWorkers()[0]??await c.waitForEvent('serviceworker');await fixture(w,mode==='missing-root');const base=`chrome-extension://${new URL(w.url()).host}`;const p=await c.newPage();
    if(mode==='automatic-check')await w.evaluate(()=>{(globalThis as any).forumFixture.hold=true;});
    if(mode==='refresh-keeps-posts'||mode==='failed-refresh-keeps-posts')await p.clock.install();
    await p.goto(base+'/sidepanel.html');
    if(mode==='automatic-check'){
      await expect(p.getByRole('progressbar',{name:'Loading verified posts'})).toBeVisible();await expect(p.getByRole('region',{name:'Canonical posts'}).locator('article')).toHaveCount(0);
      await expect.poll(()=>w.evaluate(()=>(globalThis as any).forumFixture.calls.some((r:any)=>r.operation==='public-page'))).toBe(true);await w.evaluate(()=>{(globalThis as any).forumFixture.hold=false;(globalThis as any).forumFixture.release();});
    }
    await expect(p.getByRole('link',{name:'Open post No.4',exact:true})).toBeVisible();
    await expect(p.getByText('Post unavailable — its files could not be downloaded.',{exact:true}).first()).toBeVisible();
    await expect(p.getByText('Saved public posts',{exact:true})).toHaveCount(0);await expect(p.getByRole('button',{name:/check|refresh/i})).toHaveCount(0);
    const initial=await w.evaluate(()=>(globalThis as any).forumFixture.calls);expect(initial.map((r:any)=>r.operation)).toEqual(['public-capabilities','public-page']);
    expect(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
    if(mode==='automatic-check')return;
    if(mode==='failed-refresh-keeps-posts'){
      await w.evaluate(()=>{(globalThis as any).forumFixture.fail=true;});await p.clock.fastForward(31000);
      await expect(p.getByRole('alert')).toContainText('Previously checked posts remain visible');
      await expect(p.getByRole('link',{name:'Open post No.4',exact:true})).toBeVisible();
      await w.evaluate(()=>{(globalThis as any).forumFixture.fail=false;});await p.getByRole('button',{name:'Retry loading',exact:true}).click();
      await expect(p.getByRole('alert')).toHaveCount(0);return;
    }
    if(mode==='refresh-keeps-posts'){
      await w.evaluate(()=>{(globalThis as any).forumFixture.hold=true;});await p.clock.fastForward(31000);
      await expect(p.getByRole('progressbar',{name:'Loading verified posts'})).toBeVisible();await expect(p.getByRole('link',{name:'Open post No.4',exact:true})).toBeVisible();
      await expect.poll(()=>w.evaluate(()=>(globalThis as any).forumFixture.calls.filter((r:any)=>r.operation==='public-page').length)).toBe(2);
      await w.evaluate(()=>{const s=(globalThis as any).forumFixture;s.hold=false;s.release();});await expect(p.getByRole('progressbar',{name:'Loading verified posts'})).toHaveCount(0);return;
    }
    if(mode==='unassigned'){
      await p.goto(base+'/forum.html?post=999#post-999');await expect(p.getByText('This number has not been published.',{exact:true})).toBeVisible();return;
    }
    if(mode==='progressive-thread'){
      await w.evaluate(()=>{const s=(globalThis as any).forumFixture;for(let n=7;n<=12;n++){const r=structuredClone(s.rows[5]);r.post_number=String(n);r.bundle_hash='0x'+String(n).padStart(2,'0').repeat(32);r.post.body='Reply number '+n;r.post.id=`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;s.rows.push(r);}s.hold=true;});
      await p.goto(base+'/forum.html?post=11#post-11');
      await expect(p.getByRole('heading',{name:'Thread No.1',exact:true})).toBeVisible();await expect(p.getByText('Reply number 11',{exact:true})).toBeVisible();
      await expect(p.getByRole('progressbar',{name:'Loading verified posts'})).toBeVisible();
      await expect.poll(()=>w.evaluate(()=>(globalThis as any).forumFixture.calls.some((r:any)=>r.operation==='public-page'&&r.body.after===4))).toBe(true);
      await w.evaluate(()=>{const s=(globalThis as any).forumFixture;s.hold=false;s.release();});
      await expect(p.getByText('10 replies · checked through post No.12.',{exact:false})).toBeVisible();return;
    }
    if(mode==='feed-and-thread'){
      await expect(p.getByText('Followers > 10',{exact:true})).toBeVisible();await p.getByRole('button',{name:'Next',exact:true}).click();await expect(p.getByRole('link',{name:'Open post No.6',exact:true})).toBeVisible();
      const offset=await w.evaluate(()=>(globalThis as any).forumFixture.calls.length);
      const opened=c.waitForEvent('page');await p.getByRole('link',{name:'Open post No.6',exact:true}).click();const tab=await opened;
      await expect(tab).toHaveURL(base+'/forum.html?post=6#post-6');await expect(tab.getByRole('heading',{name:'Thread No.1',exact:true})).toBeVisible();
      await expect(tab.getByText('4 replies · checked through post No.6.',{exact:false})).toBeVisible();await expect(tab.getByRole('region',{name:'Thread posts'}).locator('article')).toHaveCount(5);
      const reads=(await w.evaluate(()=>(globalThis as any).forumFixture.calls)).slice(offset);
      expect(reads.filter((r:any)=>r.operation==='public-numbers').map((r:any)=>r.body.numbers)).toEqual([[5,6,7,8],[1,2,3,4]]);expect(reads.filter((r:any)=>r.operation==='public-page')).toHaveLength(0);expect(reads.filter((r:any)=>r.operation==='public-capabilities')).toHaveLength(1);
      await expect(tab.getByRole('textbox',{name:'Your comment',exact:true})).toBeVisible();await expect(tab.getByText('Saved public posts',{exact:true})).toHaveCount(0);
      await tab.reload();await expect(tab.getByRole('link',{name:'Open post No.6',exact:true})).toBeVisible();
      const names=(await w.evaluate(()=>(globalThis as any).forumFixture.calls)).map((r:any)=>r.operation);expect(names.some((n:string)=>n==='public-publish')).toBe(false);
      await p.getByRole('textbox',{name:'Post number',exact:true}).fill('3');const lookup=c.waitForEvent('page');await p.getByRole('button',{name:'Go',exact:true}).click();await expect(await lookup).toHaveURL(base+'/forum.html?post=3#post-3');
      await tab.screenshot({path:'/tmp/nockapp-canonical-thread-20261105.png',fullPage:true});
    }else{
      await p.goto(base+'/forum.html?post=3#post-3');
      if(mode==='missing-root'){
        await expect(p.getByText('The full thread cannot be reconstructed',{exact:false})).toBeVisible();await expect(p.getByRole('textbox',{name:'Your comment',exact:true})).toHaveCount(0);
        await expect(p.getByText('Reply number 3',{exact:true})).toBeVisible();await expect(p.getByText('Post unavailable — its files could not be downloaded.',{exact:true}).first()).toBeVisible();
      }else{
        await expect(p.getByRole('textbox',{name:'Your comment',exact:true})).toBeVisible();await p.getByRole('textbox',{name:'Your comment',exact:true}).fill('A new anonymous reply');
        for(const label of ['Show my Ethereum address, authorized with MetaMask','Prove followers greater than a threshold'])await expect(p.getByLabel(label)).not.toBeChecked();
        await p.getByRole('button',{name:'Publish anonymous public comment',exact:true}).click();await expect(p.getByText('Publishing: waiting for finalized inclusion.',{exact:false})).toBeVisible();
        const calls=await w.evaluate(()=>(globalThis as any).forumFixture.calls);const prep=calls.find((r:any)=>r.operation==='public-prepare');expect(prep.body.post.kind).toBe('comment');expect(prep.body.thread.number).toBe('1');expect(prep.body.selection).toEqual({address:false,followers_threshold:null});expect(calls.filter((r:any)=>r.operation==='public-publish')).toHaveLength(1);
      }
    }
  }finally{await c.close();await rm(profile,{recursive:true,force:true});}
});


for(const recovery of ['finalized','finalized-no-badge','pending','unsent','unavailable','outbox-unavailable','edited-draft','lost-reply'])test(`publication status recovers automatically: ${recovery}`,async()=>{
  const profile=await mkdtemp(resolve(tmpdir(),'nockapp-publication-recovery-'));const path=resolve('dist');
  const c=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${path}`,`--load-extension=${path}`,'--no-sandbox']});
  try{
    const w=c.serviceWorkers()[0]??await c.waitForEvent('serviceworker');await fixture(w,false,recovery);const p=await c.newPage();
    if(['unavailable','outbox-unavailable'].includes(recovery))await p.clock.install();
    await p.goto(`chrome-extension://${new URL(w.url()).host}/forum.html?post=3#post-3`);
    if(recovery==='lost-reply'){
      await p.getByRole('textbox',{name:'Your comment',exact:true}).fill('The exact interrupted comment');
      await p.getByRole('button',{name:'Publish anonymous public comment',exact:true}).click();
    }
    if(recovery==='outbox-unavailable'){
      await expect(p.getByRole('progressbar',{name:'Restoring publication records'})).toBeVisible();await expect(p.getByRole('button',{name:'Publish anonymous public comment',exact:true})).toHaveCount(0);
      await w.evaluate(()=>{(globalThis as any).forumFixture.statusReady=true;});await p.clock.fastForward(31000);
      await expect(p.getByRole('region',{name:'Thread posts'}).getByRole('link',{name:'Open post No.7',exact:true})).toBeVisible();
    }else if(['pending','unsent','unavailable'].includes(recovery)){
      const panel=p.getByRole('region',{name:'Unfinished publication'});await expect(panel).toContainText('The exact interrupted comment');await expect(panel).toContainText('Reply to thread No.1');
      await expect(p.getByRole('button',{name:/Continue this publication|Continue interrupted publication/})).toHaveCount(0);
      await expect(p.getByRole('button',{name:'Publish anonymous public comment',exact:true})).toHaveCount(0);
      if(recovery==='unsent'){
        await expect(panel.getByRole('button',{name:'Publish this comment',exact:true})).toBeVisible();
        await expect(panel).toContainText('Not submitted by this app');
      }else {
        await expect(panel.getByRole('button',{name:'Publish this comment',exact:true})).toHaveCount(0);
        if(recovery==='unavailable'){
          await expect(panel).toContainText('Status temporarily unavailable');
          await w.evaluate(()=>{(globalThis as any).forumFixture.statusReady=true;});await p.clock.fastForward(31000);
          await expect(p.getByRole('region',{name:'Thread posts'}).getByText('The exact interrupted comment',{exact:true})).toBeVisible();
        }else await expect(panel).toContainText('Publishing: waiting for finalized inclusion');
      }
    }else {
      await expect(p.getByRole('region',{name:'Thread posts'}).getByRole('link',{name:'Open post No.7',exact:true})).toBeVisible();
      await expect(p.getByRole('region',{name:'Unfinished publication'})).toHaveCount(0);
      const draft=p.getByRole('textbox',{name:'Your comment',exact:true});await expect(draft).toHaveValue(recovery==='edited-draft'?'My newer edited draft':'');
      if(recovery==='finalized-no-badge')await expect(p.getByRole('region',{name:'Completed publication'})).toContainText('follower badge could not be verified');
      if(['edited-draft','lost-reply'].includes(recovery)){
        const intents=await w.evaluate(async()=>(await chrome.storage.local.get('nockapp:public:submission-intents:v5'))['nockapp:public:submission-intents:v5']as any[]);
        expect(intents).toHaveLength(1);expect(intents[0].released).toBe(true);
      }
    }
    const calls=await w.evaluate(()=>(globalThis as any).forumFixture.calls);
    expect(calls.some((r:any)=>r.operation==='public-check')).toBe(true);
    expect(calls.filter((r:any)=>r.operation==='public-publish')).toHaveLength(recovery==='lost-reply'?1:0);
    expect(calls.filter((r:any)=>r.operation==='public-prepare')).toHaveLength(recovery==='lost-reply'?1:0);
    expect(calls.filter((r:any)=>r.operation.startsWith('public-ticket-'))).toHaveLength(recovery==='lost-reply'?1:0);
  }finally{await c.close();await rm(profile,{recursive:true,force:true});}
});

test('pending comment shows progress and finalizes automatically without reload or another ticket', async()=>{
  const profile=await mkdtemp(resolve(tmpdir(),'nockapp-publish-progress-'));const extension=resolve('dist');
  const c=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`]});
  try{
    const w=c.serviceWorkers()[0]??await c.waitForEvent('serviceworker');await fixture(w,false,'pending-then-final');const p=await c.newPage();await p.clock.install();
    await p.goto(`chrome-extension://${new URL(w.url()).host}/forum.html?post=3#post-3`);
    const panel=p.getByRole('region',{name:'Unfinished publication'});await expect(panel).toContainText('The exact interrupted comment');
    await expect(panel.getByRole('progressbar',{name:'Publication stages completed'})).toHaveAttribute('value','3');
    await expect(panel).toContainText('No reliable confirmation countdown');await expect(panel).toContainText('Elapsed');
    await p.clock.fastForward(31000);await expect(panel).toContainText('Last checked');
    await panel.screenshot({path:'/tmp/nockapp-publication-progress-pending.png'});
    await w.evaluate(()=>{(globalThis as any).forumFixture.statusReady=true;});await p.clock.fastForward(31000);
    await expect(p.getByRole('region',{name:'Completed publication'})).toContainText('Finalized and independently checked');
    await expect(p.getByRole('region',{name:'Thread posts'}).getByRole('link',{name:'Open post No.7',exact:true})).toBeVisible();
    const calls=await w.evaluate(()=>(globalThis as any).forumFixture.calls);expect(calls.filter((r:any)=>r.operation==='public-check').length).toBeGreaterThan(1);
    expect(calls.filter((r:any)=>r.operation==='public-publish'||r.operation.startsWith('public-ticket-'))).toHaveLength(0);
  }finally{await c.close();await rm(profile,{recursive:true,force:true});}
});

for(const scenario of ['ticket-preflight','expired','expired-no-ticket'])test(`saved publication recovery ${scenario}`,async()=>{
  const profile=await mkdtemp(resolve(tmpdir(),'nockapp-publication-recovery-'));const extension=resolve('dist');
  const c=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,viewport:{width:390,height:844},args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`,'--no-sandbox']});
  try{
    const w=c.serviceWorkers()[0]??await c.waitForEvent('serviceworker');await fixture(w,false,scenario==='ticket-preflight'?'':scenario);
    const p=await c.newPage();await p.goto(`chrome-extension://${new URL(w.url()).host}/forum.html?post=3#post-3`);
    if(scenario==='ticket-preflight'){
      await p.getByRole('textbox',{name:'Your comment',exact:true}).fill('Keep my exact draft when tickets are empty');
      await p.getByText('Optional public disclosures',{exact:true}).click();await p.getByLabel('Prove followers greater than a threshold').check();
      await p.getByLabel('Follower threshold',{exact:true}).fill('0');
      await w.evaluate(()=>{(globalThis as any).forumFixture.availableTickets=0;});
      await p.getByRole('button',{name:'Publish anonymous public comment',exact:true}).click();
      await expect(p.getByRole('alert')).toContainText('No publication tickets available');
      await expect(p.getByRole('textbox',{name:'Your comment',exact:true})).toHaveValue('Keep my exact draft when tickets are empty');
      await expect(p.getByRole('button',{name:'Buy or recover tickets',exact:true})).toBeVisible();
      const calls=await w.evaluate(()=>(globalThis as any).forumFixture.calls);
      expect(calls.filter((r:any)=>r.operation==='public-ticket-status')).toHaveLength(1);
      expect(calls.some((r:any)=>['public-prepare','public-attach-followers','public-finish','public-publish','public-ticket-prepare','public-ticket-arm'].includes(r.operation))).toBe(false);
    }else{
      const card=p.getByRole('region',{name:'Unfinished publication'});
      await expect(card).toContainText('The exact interrupted comment');await expect(card).toContainText('follower badge may be missing');
      const publish=card.getByRole('button',{name:'Publish even if badge is missing',exact:true});await expect(publish).toBeEnabled();
      expect((await w.evaluate(()=>(globalThis as any).forumFixture.calls)).some((r:any)=>r.operation==='public-publish')).toBe(false);
      await card.screenshot({path:`/tmp/nockapp-${scenario}-recovery.png`});await publish.click();
      if(scenario==='expired-no-ticket'){
        await expect(p.getByRole('alert')).toContainText('No ticket is available for this comment');
        await expect(card.getByRole('button',{name:'Buy or recover tickets',exact:true})).toBeVisible();
      }else await expect(card).toContainText('Publishing: waiting for finalized inclusion');
      const calls=await w.evaluate(()=>(globalThis as any).forumFixture.calls);const attempts=calls.filter((r:any)=>r.operation==='public-publish');
      expect(attempts).toHaveLength(1);expect(attempts[0].body.approve_optional_badge_failure).toBe(true);
      expect(calls.some((r:any)=>['public-prepare','public-attach-followers','public-finish','public-ticket-prepare','public-ticket-arm','public-ticket-status'].includes(r.operation))).toBe(false);
      const saved=await w.evaluate(()=>(globalThis as any).forumFixture.entries[0]);expect(saved.bundle_hash).toBe('0x'+'55'.repeat(32));
      if(scenario==='expired-no-ticket')expect(saved.last_attempt).toBeNull();
    }
  }finally{await c.close();await rm(profile,{recursive:true,force:true});}
});

for(const mode of ['selected-history','lost-history','omit-history','bad-history'])test(`selected history composer ${mode}`,async()=>{
  const profile=await mkdtemp(resolve(tmpdir(),'nockapp-history-'));const path=resolve('dist');
  const c=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${path}`,`--load-extension=${path}`,'--no-sandbox']});
  try {
    const w=c.serviceWorkers()[0]??await c.waitForEvent('serviceworker');await fixture(w,false,mode);
    const p=await c.newPage();await p.goto(`chrome-extension://${new URL(w.url()).host}/forum.html?post=1#post-1`);
    await p.getByRole('textbox',{name:'Your comment',exact:true}).fill('Selected history stays with this exact post');
    await p.getByText('Prove earlier authorship',{exact:true}).click();
    await p.getByLabel('Earlier post numbers',{exact:true}).fill(mode==='bad-history'?'2':'1, 3');
    await p.getByLabel('I approve linking these selected posts',{exact:true}).check();
    await p.getByRole('button',{name:'Publish anonymous public comment',exact:true}).click();
    if(mode==='bad-history'){
      await expect(p.getByText('An earlier post is unavailable or invalid.',{exact:false})).toBeVisible();
      const calls=await w.evaluate(()=>(globalThis as any).forumFixture.calls);expect(calls.some((r:any)=>r.operation==='public-prepare')).toBe(false);return;
    }
    if(mode==='lost-history'){
      await expect(p.getByText('The selected authorship proof could not be prepared.',{exact:false})).toBeVisible();
      const before=await w.evaluate(()=>(globalThis as any).forumFixture.calls.length);await p.reload();
      await expect(p.getByRole('button',{name:'Publish this comment',exact:true})).toBeVisible();
      expect((await w.evaluate(()=>(globalThis as any).forumFixture.calls)).slice(before).some((r:any)=>['public-attach-history','public-publish'].includes(r.operation))).toBe(false);
      await p.getByRole('button',{name:'Publish this comment',exact:true}).click();
    }
    if(mode==='omit-history')await expect(p.getByText('The selected authorship links do not match the saved post.',{exact:false})).toBeVisible();
    else await expect(p.getByText('Publishing: waiting for finalized inclusion.',{exact:false})).toBeVisible();
    const calls=await w.evaluate(()=>(globalThis as any).forumFixture.calls);const claims=calls.filter((r:any)=>r.operation==='public-attach-history');
    expect(claims).toHaveLength(mode==='lost-history'?2:1);expect(claims[0].body.records.map((r:any)=>r.number)).toEqual(['1','3']);
    if(mode==='lost-history')expect(claims[0].body).toEqual(claims[1].body);
    expect(calls.filter((r:any)=>r.operation==='public-publish')).toHaveLength(mode==='omit-history'?0:1);
    expect(calls.filter((r:any)=>r.operation==='public-export-submission')).toHaveLength(1);
  } finally {await c.close();await rm(profile,{recursive:true,force:true});}
});
