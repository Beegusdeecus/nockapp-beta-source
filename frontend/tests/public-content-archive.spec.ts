import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {canonicalAscii} from '../src/authoredWallet';
import {parseArchive,verifyArchive,validArchive,MAX_ARCHIVE_BYTES} from '../src/publicContentArchive';
import {validPublicBody,publicProjection} from '../src/publicDiscussion';
const f=JSON.parse(readFileSync(new URL('./fixtures/public-content-archive-v5-20261103.json',import.meta.url),'utf8'));
const bytes=(v:unknown)=>new TextEncoder().encode(canonicalAscii(v));
test('production Python archive and native projections cross the exact browser schemas',async()=>{
  expect(await parseArchive(bytes(f.archive),f.archive.scope)).toEqual(f.archive);
  for(const [op,result,body] of [
    ['public-archive-capabilities',f.capabilities,{}],
    ['public-archive-export-object',f.export,{number:1,bundle_hash:f.export.bundle_hash,approve_public_export:true}],
    ['public-archive-import-object',f.restore,{archive:f.archive,approve_public_import:true}],
    ['public-archive-cache-status',f.status,{bundle_hashes:f.status.bundle_hashes}],
  ] as [string,any,any][]){
    expect(validPublicBody(op,body),op).toBe(true);expect(publicProjection(op,result,body),op).toBe(true);
    expect(publicProjection(op,{...result,verified:true},body),op).toBe(false);
    expect(validPublicBody(op,{...body,path:'/caller'}),op).toBe(false);
  }
});
test('whole archive validation rejects swapped bytes, wrong scope, claims and duplicates',async()=>{
  for(const change of [(v:any)=>v.objects[0].bundle_base64=btoa('changed'),(v:any)=>v.scope.contract='0x'+'12'.repeat(20),
    (v:any)=>v.objects[0].verified=true,(v:any)=>v.objects.push({...v.objects[0]}),(v:any)=>v.private_key='forbidden']){
    const v=structuredClone(f.archive);change(v);await expect(parseArchive(bytes(v),f.archive.scope)).rejects.toThrow();
  }
  await expect(parseArchive(new Uint8Array(MAX_ARCHIVE_BYTES+1),f.archive.scope)).rejects.toThrow();
  await expect(parseArchive(new TextEncoder().encode(canonicalAscii(f.archive)+'\n'),f.archive.scope)).rejects.toThrow();
  expect(validPublicBody('public-archive-import-object',{archive:f.archive,approve_public_import:false})).toBe(false);
});
test('large public objects use one bounded native import instead of increasing the general frame',async()=>{
  const raw=new Uint8Array(65536).fill(1);const hash='0x'+[...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(v=>v.toString(16).padStart(2,'0')).join('');
  const value={...f.archive,objects:[{bundle_hash:hash,bundle_base64:btoa(String.fromCharCode(...raw))}]};
  expect(validArchive(value,1)).toBe(true);expect(validPublicBody('public-archive-import-object',{archive:value,approve_public_import:true})).toBe(true);
  expect(bytes({archive:value,approve_public_import:true}).length).toBeLessThan(98304);
  expect(await verifyArchive(value,f.archive.scope)).toEqual(value);
  expect(publicProjection('public-archive-cache-status',{...f.status,proofs_or_chain_verified:true},{bundle_hashes:f.status.bundle_hashes})).toBe(false);
});
