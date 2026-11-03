/** Public selected-history files. Only fixed post scopes; no holder root/key. */
import { exact, object } from './zkidWire';
import { canonicalAscii } from './authoredWallet';
export type HistoryScope = { protocol: 4; chain_id: 84532; application: string; contract: string; registry: string; issuer_definition: string };
export type HistoryRequest = { profile: 'nockapp-selected-authorship-request-v4'; scope: HistoryScope; numbers: number[]; bundle_hashes: string[];
  challenge: { profile: 'nockapp-selected-authorship-challenge-v4'; purpose: 'prove-selected-post-authorization'; intent_sha256: string[]; nonce: string; audience: string; created_at: number; expires_at: number; disclose_address: false } };
export type HistoryResponse = { profile: 'nockapp-selected-authorship-response-v4'; request_sha256: string; request: HistoryRequest;
  proof: { profile: 'nockapp-private-authorship-v4'; response: string; statements: { scope: { kind: 'post'; intent_sha256: string }; pseudonym: string; nonce_commitment: string }[] } };
export type HistoryReceipt = { profile: 'nockapp-selected-authorship-verification-v4'; request_sha256: string; protocol: 4; authorization_checked: true;
  post_numbers: number[]; bundle_hashes: string[]; public_address: null; wallet_claim_endorsement_checked: false; scope: HistoryScope; checked_at: number;
  checkpoint: { number: string; hash: string }; challenge_checked_at: number; current_possession_checked: boolean; recovered: boolean };
export type HistoryRequests = { profile: 'nockapp-selected-authorship-requests-v4'; entries: { request: HistoryRequest; request_sha256: string; challenge_checked_at: number | null }[]; next_after: number; more: boolean };
const hex = (v: unknown, n = 64): v is string => typeof v === 'string' && new RegExp(`^[0-9a-f]{${n}}$`).test(v) && !/^0+$/.test(v);
const hash = (v: unknown): v is string => typeof v === 'string' && /^0x[0-9a-f]{64}$/.test(v) && !/^0x0+$/.test(v);
const address = (v: unknown): v is string => typeof v === 'string' && /^0x[0-9a-f]{40}$/.test(v) && !/^0x0+$/.test(v);
const integer = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
export const validHistoryNumbers = (v: unknown): v is number[] => Array.isArray(v) && v.length >= 1 && v.length <= 16 && v.every(n => integer(n) && n > 0) && new Set(v).size === v.length;
function scope(v: unknown): v is HistoryScope { return object(v) && exact(v, ['protocol', 'chain_id', 'application', 'contract', 'registry', 'issuer_definition'])
  && v.protocol === 4 && v.chain_id === 84532 && hash(v.application) && address(v.contract) && address(v.registry) && hex(v.issuer_definition); }
export function validHistoryRequest(v: unknown): v is HistoryRequest {
  if (!object(v) || !exact(v, ['profile', 'scope', 'numbers', 'bundle_hashes', 'challenge']) || v.profile !== 'nockapp-selected-authorship-request-v4'
    || !scope(v.scope) || !validHistoryNumbers(v.numbers) || !Array.isArray(v.bundle_hashes) || v.bundle_hashes.length !== v.numbers.length || !v.bundle_hashes.every(hash)) return false;
  const c = v.challenge;
  return object(c) && exact(c, ['profile', 'purpose', 'intent_sha256', 'nonce', 'audience', 'created_at', 'expires_at', 'disclose_address'])
    && c.profile === 'nockapp-selected-authorship-challenge-v4' && c.purpose === 'prove-selected-post-authorization' && c.disclose_address === false
    && Array.isArray(c.intent_sha256) && c.intent_sha256.length === v.numbers.length && c.intent_sha256.every(h => hex(h)) && new Set(c.intent_sha256).size === c.intent_sha256.length
    && hex(c.nonce) && hex(c.audience) && integer(c.created_at) && integer(c.expires_at) && c.expires_at - c.created_at === 60
    && new TextEncoder().encode(JSON.stringify(v)).length <= 16384;
}
export function validHistoryResponse(v: unknown): v is HistoryResponse {
  if (!object(v) || !exact(v, ['profile', 'request_sha256', 'request', 'proof']) || v.profile !== 'nockapp-selected-authorship-response-v4'
    || !hex(v.request_sha256) || !validHistoryRequest(v.request)) return false;
  const p = v.proof;
  return object(p) && exact(p, ['profile', 'response', 'statements']) && p.profile === 'nockapp-private-authorship-v4' && hex(p.response)
    && Array.isArray(p.statements) && p.statements.length === v.request.numbers.length && p.statements.every((st, i) => object(st)
      && exact(st, ['scope', 'pseudonym', 'nonce_commitment']) && object(st.scope) && exact(st.scope, ['kind', 'intent_sha256'])
      && st.scope.kind === 'post' && st.scope.intent_sha256 === (v.request as HistoryRequest).challenge.intent_sha256[i] && hex(st.pseudonym, 96) && hex(st.nonce_commitment, 96))
    && new TextEncoder().encode(JSON.stringify(v)).length <= 32768;
}
export function historyBody(op: string, b: Record<string, unknown>) {
  if (op === 'bundle-history-request') return exact(b, ['numbers', 'approve_request']) && validHistoryNumbers(b.numbers) && b.approve_request === true;
  if (op === 'bundle-history-prove') return exact(b, ['request', 'approve_linking']) && validHistoryRequest(b.request) && b.approve_linking === true;
  if (op === 'bundle-history-verify') return exact(b, ['response', 'request_sha256']) && validHistoryResponse(b.response) && hex(b.request_sha256) && b.response.request_sha256 === b.request_sha256;
  return op === 'bundle-history-requests' && exact(b, ['after', 'limit']) && integer(b.after) && b.after <= 100 && integer(b.limit) && b.limit >= 1 && b.limit <= 8;
}
export function historyProjection(op: string, v: unknown, b: Record<string, unknown>): boolean {
  if (op === 'bundle-history-request') return validHistoryRequest(v) && canonicalAscii(v.numbers) === canonicalAscii(b.numbers);
  if (op === 'bundle-history-prove') return validHistoryResponse(v) && canonicalAscii(v.request) === canonicalAscii(b.request);
  if (!object(v)) return false;
  if (op === 'bundle-history-requests') return exact(v, ['profile', 'entries', 'next_after', 'more']) && v.profile === 'nockapp-selected-authorship-requests-v4'
    && Array.isArray(v.entries) && v.entries.length <= Number(b.limit) && v.entries.every(r => object(r) && exact(r, ['request', 'request_sha256', 'challenge_checked_at'])
      && validHistoryRequest(r.request) && hex(r.request_sha256) && (r.challenge_checked_at === null || integer(r.challenge_checked_at)
        && r.request.challenge.created_at <= r.challenge_checked_at && r.challenge_checked_at < r.request.challenge.expires_at))
    && v.next_after === Number(b.after) + v.entries.length && typeof v.more === 'boolean';
  if (op !== 'bundle-history-verify' || !validHistoryResponse(b.response)) return false;
  const request = b.response.request;
  return exact(v, ['profile', 'request_sha256', 'protocol', 'authorization_checked', 'post_numbers', 'bundle_hashes', 'public_address', 'wallet_claim_endorsement_checked', 'scope', 'checked_at', 'checkpoint', 'challenge_checked_at', 'current_possession_checked', 'recovered'])
    && v.profile === 'nockapp-selected-authorship-verification-v4' && v.request_sha256 === b.request_sha256 && v.protocol === 4 && v.authorization_checked === true
    && scope(v.scope) && validHistoryNumbers(v.post_numbers) && Array.isArray(v.bundle_hashes) && v.bundle_hashes.every(hash)
    && canonicalAscii(v.scope) === canonicalAscii(request.scope) && canonicalAscii(v.post_numbers) === canonicalAscii(request.numbers)
    && canonicalAscii(v.bundle_hashes) === canonicalAscii(request.bundle_hashes) && v.public_address === null && v.wallet_claim_endorsement_checked === false
    && integer(v.checked_at) && integer(v.challenge_checked_at) && request.challenge.created_at <= v.challenge_checked_at && v.challenge_checked_at < request.challenge.expires_at
    && v.checked_at >= v.challenge_checked_at && typeof v.recovered === 'boolean' && v.current_possession_checked === !v.recovered
    && object(v.checkpoint) && exact(v.checkpoint, ['number', 'hash']) && typeof v.checkpoint.number === 'string' && /^0x[0-9a-f]+$/.test(v.checkpoint.number) && hash(v.checkpoint.hash);
}
export async function historyHash(v: unknown): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalAscii(v)));
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
}
