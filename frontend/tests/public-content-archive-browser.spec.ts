import {test,expect,chromium} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';
import {canonicalAscii} from '../src/authoredWallet';
const f=JSON.parse(readFileSync(new URL('./fixtures/public-content-archive-v5-20261103.json',import.meta.url),'utf8'));
// Actual built side panel/native bridge; public native responses are fixtures.
for(const mode of ['roundtrip','tampered','partial','old-helper','large-import'])test(`public content archive controls ${mode}`,async()=>{
 const dir=await mkdtemp(resolve(tmpdir(),'nockapp-public-archive-'));const path=resolve('dist');
 const context=await chromium.launchPersistentContext(dir,{channel:'chromium',headless:true,viewport:{width:390,height:844},args:[`--disable-extensions-except=${path}`,`--load-extension=${path}`,'--no-sandbox']});
 try{
  const worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker');
  await worker.evaluate(({f,mode})=>{
   const calls:any[]=[];Object.assign(globalThis,{archiveNativeCalls:calls});
   chrome.runtime.connectNative=(()=>{
    const listeners=new Set<(v:unknown)=>void>();
    return {onMessage:{addListener:(fn:(v:unknown)=>void)=>listeners.add(fn),removeListener:(fn:(v:unknown)=>void)=>listeners.delete(fn)},
     onDisconnect:{addListener:()=>{},removeListener:()=>{}},disconnect:()=>{},postMessage:async(m:any)=>{
      // Opening the shared-mode chooser also probes the older helper. Reject
      // that separate bootstrap; it cannot execute private/legacy operations.
      if(!m.operation.startsWith('public-')){
       queueMicrotask(()=>listeners.forEach(fn=>fn({profile:m.profile,id:m.id,status:'rejected',code:'native-operation-unavailable',recoverable:true,laboratory:true,verified:false})));return;
      }
      calls.push(structuredClone(m));let result;
      if(m.operation==='public-capabilities')result={configured:true,protocol:5,scope:f.archive.scope,follower_proof_configured:false,
       verifier_release:8,publication_mode:'direct',anonymous_ticket_packs:false,source_enrollment_configured:false,historical_issuer_views:false};
      else if(m.operation==='public-identity-options')result={identity_record_present:false,sources:[]};
      else if(m.operation==='public-outbox')result={entries:[],next_after:null};
      else if(m.operation==='public-page'||m.operation==='public-numbers'){
       result={...f.public_page};if(m.operation==='public-numbers'){delete result.after;delete result.next_after;delete result.more;}
      }else if(m.operation==='public-archive-capabilities'){
       if(mode==='old-helper'){queueMicrotask(()=>listeners.forEach(fn=>fn({profile:m.profile,id:m.id,status:'rejected',code:'native-operation-unavailable',recoverable:true,laboratory:true,verified:false})));return;}
       result=f.capabilities;
      }else if(m.operation==='public-archive-export-object')result=f.export;
      else if(m.operation==='public-archive-import-object'){
       const ordered=(v:any):any=>Array.isArray(v)?v.map(ordered):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,ordered(v[k])])):v;
       const raw=new TextEncoder().encode(JSON.stringify(ordered(m.body.archive)));
       const digest='0x'+[...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(v=>v.toString(16).padStart(2,'0')).join('');
       result={...f.restore,archive_sha256:digest,present_hashes:[m.body.archive.objects[0].bundle_hash]};
      }else if(m.operation==='public-archive-cache-status')result={...f.status,bundle_hashes:m.body.bundle_hashes,
        present_hashes:mode==='partial'?[]:m.body.bundle_hashes,complete:mode!=='partial'};
      else throw Error('Unexpected private, wallet or publication operation');
      queueMicrotask(()=>listeners.forEach(fn=>fn({profile:m.profile,id:m.id,status:'ok',result,laboratory:true,verified:false})));
     }};
   }) as unknown as typeof chrome.runtime.connectNative;
  },{f,mode});
  const page=await context.newPage();const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(`chrome-extension://${new URL(worker.url()).host}/sidepanel.html`);
  await page.getByRole('button',{name:'Shared · Base Sepolia'}).click();
  await page.getByRole('button',{name:'Public · permissionless v5',exact:true}).click();
  await expect(page.getByText('Public discussions',{exact:true})).toBeVisible();
  await page.getByText('Public content archive',{exact:true}).click();
  const panel=page.locator('details').filter({has:page.locator('summary',{hasText:'Public content archive'})});
  if(mode==='old-helper'){
   await expect(panel.getByRole('alert')).toBeVisible();await expect(panel.getByRole('button',{name:'Download public content archive'})).toHaveCount(0);
  }else{
   await expect(panel.getByLabel('Public post numbers',{exact:true})).toBeVisible();
   if(mode==='roundtrip'){
    await panel.getByLabel('Public post numbers',{exact:true}).fill('1');
    await expect(panel.getByRole('button',{name:'Download public content archive'})).toBeDisabled();
    await panel.getByRole('checkbox',{name:/I approve downloading/}).check();
    const event=page.waitForEvent('download');await panel.getByRole('button',{name:'Download public content archive'}).click();
    const download=await event;expect(readFileSync((await download.path())!,'utf8')).toBe(canonicalAscii(f.archive));
    await expect(panel.getByRole('status')).toContainText('Downloaded 1 public bundle');
   }
   const value=structuredClone(f.archive);if(mode==='tampered')value.objects[0].bundle_base64=btoa('altered public bytes');
   if(mode==='large-import'){
    const raw=new Uint8Array(65536).fill(1);const h='0x'+[...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(v=>v.toString(16).padStart(2,'0')).join('');
    value.objects=[{bundle_hash:h,bundle_base64:Buffer.from(raw).toString('base64')}];
   }
   await panel.getByLabel('Public content archive file').setInputFiles({name:'archive.json',mimeType:'application/json',buffer:Buffer.from(canonicalAscii(value))});
   await expect(panel.getByRole('button',{name:'Import public content archive'})).toBeDisabled();
   await panel.getByRole('checkbox',{name:/I approve importing public bytes/}).check();await panel.getByRole('button',{name:'Import public content archive'}).click();
   if(mode==='tampered')await expect(panel.getByRole('alert')).toContainText('does not match');
   else await expect(panel.getByRole('status')).toContainText(mode==='partial'?'Restore is incomplete.':'Content restored.');
  }
  const calls=await worker.evaluate(()=>(globalThis as any).archiveNativeCalls);
  expect(calls.filter((c:any)=>c.operation==='public-archive-import-object')).toHaveLength(['roundtrip','partial','large-import'].includes(mode)?1:0);
  if(mode==='large-import'){
   const message=calls.find((c:any)=>c.operation==='public-archive-import-object');expect(JSON.stringify(message).length).toBeGreaterThan(32768);
   expect(JSON.stringify(message).length).toBeLessThan(98304);
  }
  expect(calls.every((c:any)=>['public-capabilities','public-identity-options','public-outbox','public-page','public-numbers'].includes(c.operation)||c.operation.startsWith('public-archive-'))).toBe(true);
  expect(errors).toEqual([]);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth)).toBe(true);
 }finally{await context.close();await rm(dir,{recursive:true,force:true});}
});
