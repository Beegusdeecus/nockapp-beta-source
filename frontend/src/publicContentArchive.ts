/** Content bytes only. Imported files never supply verification or chain trust. */
import { exact, object } from './zkidWire';
import { canonicalAscii } from './authoredWallet';
import type { PublicScope } from './publicDiscussion';

export const ARCHIVE_PROFILE='nockapp-public-content-archive-v5';
export const MAX_ARCHIVE_BYTES=384*1024;
const hash=(v:unknown):v is string=>typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v)&&!/^0x0+$/.test(v);
const scope=(v:unknown):v is PublicScope=>object(v)&&exact(v,['protocol','chain_id','application','contract'])&&v.protocol===5&&v.chain_id===84532
  &&hash(v.application)&&typeof v.contract==='string'&&/^0x[0-9a-f]{40}$/.test(v.contract)&&!/^0x0+$/.test(v.contract);
const same=(a:PublicScope,b:PublicScope)=>canonicalAscii(a)===canonicalAscii(b);
export type ArchiveObject={bundle_hash:string;bundle_base64:string};
export type PublicArchive={profile:typeof ARCHIVE_PROFILE;scope:PublicScope;objects:ArchiveObject[]};
export type ArchiveCapabilities={profile:'nockapp-public-archive-capabilities-v5';scope:PublicScope;max_objects:4;max_object_bytes:65536;
  max_archive_bytes:393216;native_objects_per_message:1;cache_import_configured:boolean;chain_RPC_still_required:true};
export type ArchiveExport=ArchiveObject&{profile:'nockapp-public-archive-object-v5';scope:PublicScope;post_number:string;canonical_indexed:true;proofs_verified:false};
export type ArchiveStatus={profile:'nockapp-public-archive-cache-status-v5';scope:PublicScope;bundle_hashes:string[];present_hashes:string[];
  complete:boolean;proofs_or_chain_verified:false;cache_entries_evictable:true};
function data(v:unknown):Uint8Array<ArrayBuffer>|undefined {
  if(typeof v!=='string'||!v.length||v.length>87384)return;
  try{const raw=atob(v);if(!raw.length||raw.length>65536||btoa(raw)!==v)return;return Uint8Array.from(raw,c=>c.charCodeAt(0));}catch{return;}
}
const hashes=(v:unknown):v is string[]=>Array.isArray(v)&&v.length>=1&&v.length<=4&&v.every(hash)&&v.every((h,i)=>i===0||h>v[i-1]);
export function validArchive(v:unknown,limit=4):v is PublicArchive {
  return object(v)&&exact(v,['profile','scope','objects'])&&v.profile===ARCHIVE_PROFILE&&scope(v.scope)&&Array.isArray(v.objects)
    &&v.objects.length>=1&&v.objects.length<=limit&&v.objects.every((r,i,a)=>object(r)&&exact(r,['bundle_hash','bundle_base64'])&&hash(r.bundle_hash)
      &&!!data(r.bundle_base64)&&(i===0||r.bundle_hash>(a[i-1] as ArchiveObject).bundle_hash));
}
export function validArchiveCapabilities(v:unknown):v is ArchiveCapabilities {
  return object(v)&&exact(v,['profile','scope','max_objects','max_object_bytes','max_archive_bytes','native_objects_per_message','cache_import_configured','chain_RPC_still_required'])
    &&v.profile==='nockapp-public-archive-capabilities-v5'&&scope(v.scope)&&v.max_objects===4&&v.max_object_bytes===65536&&v.max_archive_bytes===MAX_ARCHIVE_BYTES
    &&v.native_objects_per_message===1&&typeof v.cache_import_configured==='boolean'&&v.chain_RPC_still_required===true;
}
export function validArchiveExport(v:unknown):v is ArchiveExport {
  return object(v)&&exact(v,['profile','scope','post_number','bundle_hash','bundle_base64','canonical_indexed','proofs_verified'])
    &&v.profile==='nockapp-public-archive-object-v5'&&scope(v.scope)&&typeof v.post_number==='string'&&/^[1-9][0-9]{0,15}$/.test(v.post_number)
    &&Number(v.post_number)<2**53&&hash(v.bundle_hash)&&!!data(v.bundle_base64)&&v.canonical_indexed===true&&v.proofs_verified===false;
}
export function validArchiveRestore(v:unknown):boolean {
  return object(v)&&exact(v,['profile','scope','archive_sha256','objects','restored','complete','present_hashes','proofs_or_chain_verified','cache_entries_evictable'])
    &&v.profile===ARCHIVE_PROFILE&&scope(v.scope)&&hash(v.archive_sha256)&&v.objects===1&&(v.restored===0||v.restored===1)
    &&Array.isArray(v.present_hashes)&&v.present_hashes.length===v.restored&&v.present_hashes.every(hash)&&v.complete===(v.restored===1)
    &&v.proofs_or_chain_verified===false&&v.cache_entries_evictable===true;
}
export function validArchiveStatus(v:unknown):v is ArchiveStatus {
  return object(v)&&exact(v,['profile','scope','bundle_hashes','present_hashes','complete','proofs_or_chain_verified','cache_entries_evictable'])
    &&v.profile==='nockapp-public-archive-cache-status-v5'&&scope(v.scope)&&hashes(v.bundle_hashes)&&Array.isArray(v.present_hashes)
    &&v.present_hashes.every((h,i,a)=>hash(h)&&(v.bundle_hashes as string[]).includes(h)&&(i===0||h>a[i-1]))
    &&v.complete===(v.present_hashes.length===v.bundle_hashes.length)&&v.proofs_or_chain_verified===false&&v.cache_entries_evictable===true;
}
export async function verifyArchive(v:unknown,expected:PublicScope):Promise<PublicArchive> {
  const copy=structuredClone(v);
  if(!validArchive(copy)||!same(copy.scope,expected))throw Error('The archive does not match this public installation.');
  for(const row of copy.objects){const raw=data(row.bundle_base64)!;
    const h='0x'+[...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(b=>b.toString(16).padStart(2,'0')).join('');
    if(h!==row.bundle_hash)throw Error('Archive content does not match its hash. Nothing was imported.');}
  if(new TextEncoder().encode(canonicalAscii(copy)).length>MAX_ARCHIVE_BYTES)throw Error('Public archive exceeds the supported size.');
  return copy;
}
export async function parseArchive(raw:Uint8Array,expected:PublicScope):Promise<PublicArchive> {
  if(!raw.length||raw.length>MAX_ARCHIVE_BYTES)throw Error('Select a public content archive of at most384 KiB.');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);const parsed:unknown=JSON.parse(text);
  if(canonicalAscii(parsed)!==text)throw Error('The public archive is not canonically encoded. Nothing was imported.');
  return verifyArchive(parsed,expected);
}
