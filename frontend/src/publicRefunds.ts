/** Public native-v7 refund projections. Chain verification runs in the pinned helper. */
import { exact, object } from './zkidWire';
import { ticketDigest, type TicketOffer, type TicketPending } from './publicTickets';
const hash = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) && !/^0+$/.test(v);
const h32 = (v: unknown): v is string => typeof v === 'string' && v.startsWith('0x') && hash(v.slice(2));
const address = (v: unknown): v is string => typeof v === 'string' && /^0x[0-9a-f]{40}$/.test(v) && !/^0x0+$/.test(v);
const wei = (v: unknown): v is string => typeof v === 'string' && /^[1-9][0-9]{0,38}$/.test(v) && BigInt(v) < 2n ** 128n;
const integer = (v: unknown, min: number, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= max;
export type RefundPolicy = { profile:'nockapp-public-refund-vault-v1'; parameters:string; chain_id:84532; vault:string;
  runtime_sha256:string; authority:string; pack_price_wei:string; max_refunds:number; principal_budget_wei:string; gas:number };
export type RefundState = { profile:'nockapp-public-refund-state-v1'; policy:RefundPolicy; policy_sha256:string;
  pending:null|{pack_hash:string;request_sha256:string}; completed:{pack_hash:string;transaction_hash:string;amount_wei:string;verification_current:false}[];archive_limit:8 };
export type RefundPayout = { profile:'nockapp-ticket-refund-payout-v1';parameters:string;pack_hash:string;state:'refunded';payout_confirmed:true;
  payer:string;amount_wei:string;payment_transaction:string;vault:string;transaction_hash:string;block_number:string;block_hash:string };
export type RefundProgress = { profile:'nockapp-public-refund-progress-v1';parameters:string;pack_hash:string;state:'not-confirmed';payout_confirmed:false };
export function validRefundPolicy(v:unknown):v is RefundPolicy {
  return object(v) && exact(v,['profile','parameters','chain_id','vault','runtime_sha256','authority','pack_price_wei','max_refunds','principal_budget_wei','gas'])
    && v.profile==='nockapp-public-refund-vault-v1' && hash(v.parameters) && v.chain_id===84532 && address(v.vault)
    && hash(v.runtime_sha256) && address(v.authority) && wei(v.pack_price_wei) && integer(v.max_refunds,1,4096)
    && wei(v.principal_budget_wei) && BigInt(v.principal_budget_wei)===BigInt(v.pack_price_wei)*BigInt(v.max_refunds) && integer(v.gas,21000,200000);
}
export function validRefundState(v:unknown):v is RefundState {
  if(!object(v) || !validRefundPolicy(v.policy))return false;
  const policy=v.policy;
  return object(v) && exact(v,['profile','policy','policy_sha256','pending','completed','archive_limit'])
    && v.profile==='nockapp-public-refund-state-v1' && validRefundPolicy(v.policy) && hash(v.policy_sha256) && v.archive_limit===8
    && (v.pending===null || object(v.pending) && exact(v.pending,['pack_hash','request_sha256']) && h32(v.pending.pack_hash) && hash(v.pending.request_sha256))
    && Array.isArray(v.completed) && v.completed.length<=8 && v.completed.every(r=>object(r) && exact(r,['pack_hash','transaction_hash','amount_wei','verification_current'])
      && h32(r.pack_hash) && h32(r.transaction_hash) && wei(r.amount_wei) && r.amount_wei===policy.pack_price_wei && r.verification_current===false)
    && new Set(v.completed.map(r=>r.pack_hash)).size===v.completed.length;
}
export function validRefundResult(v:unknown):v is RefundPayout|RefundProgress {
  if(!object(v) || !hash(v.parameters) || !h32(v.pack_hash))return false;
  if(v.payout_confirmed===false)return exact(v,['profile','parameters','pack_hash','state','payout_confirmed'])
    && v.profile==='nockapp-public-refund-progress-v1' && v.state==='not-confirmed';
  return exact(v,['profile','parameters','pack_hash','state','payout_confirmed','payer','amount_wei','payment_transaction','vault','transaction_hash','block_number','block_hash'])
    && v.profile==='nockapp-ticket-refund-payout-v1' && v.state==='refunded' && v.payout_confirmed===true && address(v.payer) && wei(v.amount_wei)
    && h32(v.payment_transaction) && address(v.vault) && h32(v.transaction_hash) && h32(v.block_hash)
    && typeof v.block_number==='string' && /^0x[1-9a-f][0-9a-f]{0,63}$/.test(v.block_number);
}
const states = new WeakSet<object>();
export async function validateRefundState(raw:unknown,offer:TicketOffer,pending:TicketPending):Promise<RefundState> {
  raw=structuredClone(raw);
  if(!validRefundState(raw) || raw.policy.parameters!==offer.parameters || raw.policy.pack_price_wei!==offer.manifest.terms.pack_price_wei
    || await ticketDigest(raw.policy)!==raw.policy_sha256 || raw.pending!==null && raw.pending.pack_hash!==pending.purchase?.pack_hash)
    throw Error('Refund policy or saved authorization does not match this installed offer and purchase.');
  raw.completed.forEach(Object.freeze);Object.freeze(raw.completed);if(raw.pending)Object.freeze(raw.pending);Object.freeze(raw.policy);Object.freeze(raw);
  states.add(raw);return raw;
}
export function validateRefundResult(raw:unknown,state:RefundState,expected:{pack_hash:string;payment_transaction?:string;payer?:string;transaction_hash?:string}):RefundPayout|RefundProgress {
  if(!states.has(state) || !validRefundResult(raw) || raw.parameters!==state.policy.parameters || raw.pack_hash!==expected.pack_hash)
    throw Error('Refund result does not match this saved pack and pinned policy.');
  if(raw.payout_confirmed && (raw.vault!==state.policy.vault || raw.amount_wei!==state.policy.pack_price_wei
    || expected.payment_transaction!==undefined && raw.payment_transaction!==expected.payment_transaction
    || expected.payer!==undefined && raw.payer!==expected.payer || expected.transaction_hash!==undefined && raw.transaction_hash!==expected.transaction_hash))
    throw Error('Refund payout does not match the reviewed payment, payer or saved receipt.');
  return structuredClone(raw);
}
