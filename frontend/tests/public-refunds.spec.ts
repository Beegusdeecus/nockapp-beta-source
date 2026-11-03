import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { validateTicketOffer } from '../src/publicTickets';
import { validRefundState, validRefundResult, validateRefundState, validateRefundResult } from '../src/publicRefunds';
import { publicProjection, validPublicBody } from '../src/publicDiscussion';
const f=JSON.parse(readFileSync(new URL('./fixtures/public-refunds-v7-20261101.json',import.meta.url),'utf8'));
async function state(){return validateRefundState(f.state_pending,await validateTicketOffer(f.offer,f.scope),f.pending_paid);}

test('actual native-v7 public policy, progress, payout and saved archive projections are exact',async()=>{
  expect(publicProjection('public-capabilities',f.capabilities,{})).toBe(true);
  for(const value of [f.state_before,f.state_pending,f.state_completed]){
    expect(validRefundState(value)).toBe(true);expect(publicProjection('public-ticket-refund-state',value,{})).toBe(true);
    expect(validRefundState({...value,signature:'forbidden'})).toBe(false);
  }
  const s=await state();expect(Object.isFrozen(s.policy)).toBe(true);
  const expected={pack_hash:f.payout.pack_hash,payment_transaction:f.payout.payment_transaction,payer:f.payout.payer};
  expect(validateRefundResult(f.progress,s,expected).payout_confirmed).toBe(false);
  expect(validateRefundResult(f.payout,s,expected).payout_confirmed).toBe(true);
  for(const op of ['public-ticket-refund-status','public-ticket-refund-recover']){
    expect(validPublicBody(op,{pack_hash:f.payout.pack_hash})).toBe(true);
    expect(validPublicBody(op,{pack_hash:f.payout.pack_hash,signature:'forbidden'})).toBe(false);
    expect(publicProjection(op,f.payout,{pack_hash:f.payout.pack_hash})).toBe(true);
    expect(publicProjection(op,f.payout,{pack_hash:'0x'+'12'.repeat(32)})).toBe(false);
  }
});
test('changed offer, policy digest, private projection or unrelated saved authorization reject',async()=>{
  const offer=await validateTicketOffer(f.offer,f.scope);
  for(const change of [(v:any)=>v.policy.pack_price_wei='1',(v:any)=>v.policy_sha256='12'.repeat(32),
    (v:any)=>v.policy.parameters='12'.repeat(32),(v:any)=>v.pending.pack_hash='0x'+'12'.repeat(32),
    (v:any)=>v.pending.signature='forbidden',(v:any)=>v.completed=Array(9).fill(f.state_completed.completed[0])]){
    const bad=structuredClone(f.state_pending);change(bad);await expect(validateRefundState(bad,offer,f.pending_paid)).rejects.toThrow();
  }
  expect(validRefundState({...f.state_completed,completed:[{...f.state_completed.completed[0],verification_current:true}]})).toBe(false);
  expect(publicProjection('public-capabilities',{...f.capabilities,verifier_release:6},{})).toBe(false);
  expect(publicProjection('public-capabilities',{...f.capabilities,refund_payout_configured:false},{})).toBe(false);
});
test('server-style booleans cannot become native verified payout or clear uncertainty',async()=>{
  const s=await state();const expected={pack_hash:f.payout.pack_hash,payer:f.payout.payer,payment_transaction:f.payout.payment_transaction};
  for(const bad of [{state:'refunded',payout_confirmed:true},{...f.progress,payout_confirmed:true},
    {...f.payout,payer:'0x'+'12'.repeat(20)},{...f.payout,amount_wei:'1'},{...f.payout,vault:'0x'+'12'.repeat(20)},
    {...f.payout,payment_transaction:'0x'+'12'.repeat(32)},{...f.payout,pack_hash:'0x'+'12'.repeat(32)}])
    expect(()=>validateRefundResult(bad,s,expected)).toThrow();
  expect(()=>validateRefundResult(f.payout,structuredClone(s),expected)).toThrow();
  expect(()=>validateRefundResult(f.payout,s,{...expected,transaction_hash:'0x'+'12'.repeat(32)})).toThrow();
  expect(validRefundResult({...f.payout,signature:'forbidden'})).toBe(false);
  expect(publicProjection('public-ticket-refund-result',{state:'cancellation-recorded',payout_confirmed:false},{})).toBe(true);
});
