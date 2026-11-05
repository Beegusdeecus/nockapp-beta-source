import {test,expect} from '@playwright/test';
import {publicProjection,validPublicBody} from '../src/publicDiscussion';
import {readFileSync} from 'node:fs';

const vectors=JSON.parse(readFileSync(new URL('./fixtures/public-page-contract-v6-20261101-v2.json',import.meta.url),'utf8')).vectors;
const state={profile:'nockapp-renewal-enrollment-v3',state:'waiting-for-source-post',credential_saved:false,post_text:'testing:'+'ab'.repeat(32)};
test('renewal requests require exact consented fields and never accept source facts or endpoints',()=>{
  for(const [op,body] of [
    ['public-source-status',{}],['public-source-finality',{}],['public-source-begin',{username:'synthetic_user',approve_source_check:true}],
    ['public-source-check-post',{tweet_id:'3141592653589793',approve_source_check:true}],
    ['public-source-recover',{approve_source_check:true}],['public-source-cancel',{approve_cancel:true}],
  ] as const) {
    expect(validPublicBody(op,body)).toBe(true);
    for(const extra of [{account_id:'42'},{followers:9999},{endpoint:'https://evil.example'}, {secret:'12'.repeat(32)}])
      expect(validPublicBody(op,{...body,...extra})).toBe(false);
  }
  expect(validPublicBody('public-source-begin',{username:'x.com/user',approve_source_check:true})).toBe(false);
  expect(validPublicBody('public-source-begin',{username:'synthetic_user',approve_source_check:false})).toBe(false);
  expect(validPublicBody('public-source-check-post',{tweet_id:'-1',approve_source_check:true})).toBe(false);
  expect(validPublicBody('public-source-recover',{})).toBe(false);
});
test('public finality progress rejects fabricated activation, dates and inconsistent block ranges',()=>{
  const pending={profile:'nockapp-public-source-finality-v1',chain_id:84532,latest_block:120,finalized_block:100,
    latest_revision:8,finalized_revision:7,target_block:110,pending:true};
  expect(publicProjection('public-source-finality',pending)).toBe(true);
  expect(publicProjection('public-source-finality',{...pending,finalized_block:115,finalized_revision:8,target_block:null,pending:false})).toBe(true);
  for(const change of [{chain_id:1},{finalized_block:121},{target_block:99},{target_block:121},{target_block:null},
    {latest_revision:7},{pending:false},{credential_saved:true},{issued_at:1},{account_id:'42'}])
    expect(publicProjection('public-source-finality',{...pending,...change})).toBe(false);
});
test('renewal projection admits only challenge and coarse recovery state',()=>{
  expect(publicProjection('public-source-begin',state)).toBe(true);
  expect(publicProjection('public-source-recover',{...state,state:'credential-saved',credential_saved:true,post_text:null})).toBe(true);
  expect(publicProjection('public-source-status',{profile:'nockapp-public-source-status-v1',credential_record_present:true,renewal_pending:false})).toBe(true);
  for(const extra of [{issued_at:1793011200},{renew_by:1800000000},{followers:99999},{account_id:'42'},{secret:'12'.repeat(32)}])
    expect(publicProjection('public-source-begin',{...state,...extra})).toBe(false);
  for(const change of [{state:'unknown'},{credential_saved:true},{post_text:'arbitrary script'},
    {state:'credential-saved',credential_saved:true}]) expect(publicProjection('public-source-begin',{...state,...change})).toBe(false);
});
test('configured renewal capabilities bind both proof and historical verification with explicit payer mode',()=>{
  const base=vectors.find((v:any)=>v.operation==='public-capabilities').result;
  for(const mode of ['direct','tickets']) {
    const c={...base,verifier_release:9,publication_mode:mode,anonymous_ticket_packs:mode==='tickets',
      follower_proof_configured:true,source_enrollment_configured:true,historical_issuer_views:true,refund_payout_configured:false};
    expect(publicProjection('public-capabilities',c)).toBe(true);
    for(const change of [{source_enrollment_configured:false},{historical_issuer_views:false},{follower_proof_configured:false},
      {anonymous_ticket_packs:mode!=='tickets'}, {publication_mode:'unknown'}])
      expect(publicProjection('public-capabilities',{...c,...change})).toBe(false);
  }
});
