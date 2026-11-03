import { useEffect,useRef,useState } from 'react';
import { publicOperation,type PublicScope,type PublicRow } from '../publicDiscussion';
import { canonicalAscii } from '../authoredWallet';
import { ARCHIVE_PROFILE,MAX_ARCHIVE_BYTES,parseArchive,verifyArchive,type ArchiveCapabilities,type ArchiveExport,type ArchiveStatus } from '../publicContentArchive';

export function PublicContentArchive({scope,disabled}:{scope:PublicScope;disabled:boolean}) {
  const [caps,setCaps]=useState<ArchiveCapabilities>();const [numbers,setNumbers]=useState('');const [file,setFile]=useState<File>();
  const [exportConsent,setExportConsent]=useState(false);const [importConsent,setImportConsent]=useState(false);
  const [busy,setBusy]=useState(false);const locked=useRef(false);const [error,setError]=useState('');const [notice,setNotice]=useState('');
  const active=useRef<AbortController|undefined>(undefined);const mounted=useRef(true);const downloadUrl=useRef<string|undefined>(undefined);
  useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;active.current?.abort();if(downloadUrl.current)URL.revokeObjectURL(downloadUrl.current);};},[]);
  const same=(value:PublicScope)=>{if(canonicalAscii(value)!==canonicalAscii(scope))throw Error('The public installation changed. Reopen before continuing.');};
  async function run(work:(signal:AbortSignal)=>Promise<void>){if(locked.current||disabled)return;locked.current=true;setBusy(true);setError('');setNotice('');
    const controller=new AbortController();active.current=controller;
    try{await work(controller.signal);}catch(e){if(mounted.current)setError(e instanceof Error?e.message:'Public archive unavailable. Existing private state is preserved.');}
    finally{active.current=undefined;locked.current=false;if(mounted.current)setBusy(false);}}
  async function discover(signal:AbortSignal){
    let value:ArchiveCapabilities;
    try{value=await publicOperation<ArchiveCapabilities>('public-archive-capabilities',{},signal);}
    catch{throw Error('Public archive support is unavailable. Check or update the local helper, then retry.');}
    same(value.scope);if(!signal.aborted)setCaps(value);
  }
  async function download(signal:AbortSignal){
    if(!caps||!exportConsent)return;
    const tokens=numbers.split(',').map(v=>v.trim());
    if(tokens.length<1||tokens.length>4||tokens.some(v=>!(/^[1-9][0-9]{0,15}$/.test(v))||Number(v)>=2**53)||new Set(tokens).size!==tokens.length)
      throw Error('Enter one to four different public post numbers, separated by commas.');
    const rows=await publicOperation<{posts:PublicRow[]}>('public-numbers',{numbers:tokens.map(Number)},signal);
    if(rows.posts.length!==tokens.length||rows.posts.some((row,i)=>row.post_number!==tokens[i]||!row.canonical_indexed||!row.bundle_hash))
      throw Error('A selected public commitment is unavailable. No archive was downloaded.');
    const objects=[];
    for(const row of rows.posts){const value=await publicOperation<ArchiveExport>('public-archive-export-object',{
      number:Number(row.post_number),bundle_hash:row.bundle_hash,approve_public_export:true},signal);same(value.scope);
      objects.push({bundle_hash:value.bundle_hash,bundle_base64:value.bundle_base64});}
    objects.sort((a,b)=>a.bundle_hash<b.bundle_hash?-1:a.bundle_hash>b.bundle_hash?1:0);
    // Different canonical numbers cannot duplicate a hash; refuse instead of
    // silently changing the selected archive if a helper violates that rule.
    const archive=await verifyArchive({profile:ARCHIVE_PROFILE,scope,objects},scope);
    if(signal.aborted)throw Error('Archive export stopped. No file was downloaded.');
    const raw=new TextEncoder().encode(canonicalAscii(archive));const url=URL.createObjectURL(new Blob([raw],{type:'application/json'}));
    downloadUrl.current=url;const link=document.createElement('a');link.href=url;link.download='nockapp-public-content.json';link.click();setTimeout(()=>{URL.revokeObjectURL(url);if(downloadUrl.current===url)downloadUrl.current=undefined;},1000);
    setExportConsent(false);setNotice(`Downloaded ${objects.length} public bundle${objects.length===1?'':'s'}. The file contains content, not a verification verdict.`);
  }
  async function restore(signal:AbortSignal){
    if(!caps?.cache_import_configured||!file||!importConsent)return;
    if(file.size<=0||file.size>MAX_ARCHIVE_BYTES)throw Error('Select a public content archive of at most384 KiB. Nothing was imported.');
    // Admit the whole file before the first message or cache write.
    const archive=await parseArchive(new Uint8Array(await file.arrayBuffer()),scope);
    if(signal.aborted)throw Error('Archive import stopped before writing.');
    let uncertain=false;
    for(const row of archive.objects){try{await publicOperation('public-archive-import-object',{
      archive:{profile:ARCHIVE_PROFILE,scope,objects:[row]},approve_public_import:true},signal);}catch{if(signal.aborted)throw Error('Archive import stopped. Some public cache bytes may remain.');uncertain=true;break;}}
    const status=await publicOperation<ArchiveStatus>('public-archive-cache-status',{bundle_hashes:archive.objects.map(v=>v.bundle_hash)},signal);same(status.scope);
    setImportConsent(false);
    setNotice(`${status.present_hashes.length} of ${archive.objects.length} public bundles are currently in the cache.${uncertain?' An import response was unavailable.':''} ${status.complete?'Content restored.':'Restore is incomplete.'} Refresh public posts for chain and proof verification. Keep the archive file; cache entries can be evicted.`);
  }
  return <details onToggle={e=>{if(e.currentTarget.open&&!caps&&!locked.current)void run(discover);}}>
    <summary>Public content archive</summary>
    <p>Save up to four selected public bundles. This does not back up your private identity, credentials, tickets or drafts, and does not prove that archived posts are valid. Reading restored content still needs the configured trust and public chain RPC.</p>
    {!caps&&<><p>The local helper must support public archives. Opening this section checks support without unlocking a wallet.</p>
      <button disabled={busy||disabled} onClick={()=>void run(discover)}>Check archive support</button></>}
    {error&&<p role="alert">{error}</p>}{notice&&<p role="status">{notice}</p>}
    {caps&&<>
      <label>Public post numbers<input value={numbers} onChange={e=>{setNumbers(e.target.value);setExportConsent(false);}} disabled={busy||disabled} placeholder="1, 2"/></label>
      <label><input type="checkbox" checked={exportConsent} onChange={e=>setExportConsent(e.target.checked)} disabled={busy||disabled}/>I approve downloading only these selected public records.</label>
      <button disabled={busy||disabled||!exportConsent||!numbers} onClick={()=>void run(download)}>Download public content archive</button>
      <label>Public content archive file<input type="file" accept="application/json,.json" disabled={busy||disabled||!caps.cache_import_configured} onChange={e=>{setFile(e.target.files?.[0]);setImportConsent(false);setNotice('');}}/></label>
      <label><input type="checkbox" checked={importConsent} onChange={e=>setImportConsent(e.target.checked)} disabled={busy||disabled||!caps.cache_import_configured}/>I approve importing public bytes into the bounded content cache. This may evict other cached public content.</label>
      <button disabled={busy||disabled||!caps.cache_import_configured||!file||!importConsent} onClick={()=>void run(restore)}>Import public content archive</button>
    </>}
  </details>;
}
