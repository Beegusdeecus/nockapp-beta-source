import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { historyBody, historyProjection, historyHash, validHistoryRequest, validHistoryResponse } from '../src/authoredHistory';
const f = JSON.parse(readFileSync(new URL('./fixtures/authored-history-contract-20261101.json', import.meta.url), 'utf8'));

test('actual public native history files match browser schemas and canonical request hash', async () => {
  expect(f.actual_native_tls_evm_history).toBe(true);expect(f.chain31337_remapped_to84532_for_ui_schema_only).toBe(true);
  expect(validHistoryRequest(f.request)).toBe(true);expect(validHistoryResponse(f.response)).toBe(true);
  expect(await historyHash(f.request)).toBe(f.response.request_sha256);
  expect(historyProjection('bundle-history-request', f.request, { numbers: [1, 2] })).toBe(true);
  expect(historyProjection('bundle-history-prove', f.response, { request: f.request })).toBe(true);
  expect(historyProjection('bundle-history-requests', f.requests, { after: 0, limit: 8 })).toBe(true);
  for (const receipt of [f.receipt, f.recovered_receipt]) expect(historyProjection('bundle-history-verify', receipt, { response: f.response, request_sha256: f.response.request_sha256 })).toBe(true);
});

test('history requests require exact selected scope, public fields, consent and bounded numbers', () => {
  expect(historyBody('bundle-history-request', { numbers: [1, 2], approve_request: true })).toBe(true);
  for (const numbers of [[], [1, 1], [true], Array.from({ length: 17 }, (_, i) => i + 1), [Number.MAX_SAFE_INTEGER + 1]]) expect(historyBody('bundle-history-request', { numbers, approve_request: true })).toBe(false);
  expect(historyBody('bundle-history-prove', { request: f.request, approve_linking: false })).toBe(false);
  expect(historyBody('bundle-history-prove', { request: f.request, approve_linking: true, private_key: 'PRIVATE' })).toBe(false);
  for (const change of [(r: any) => { r.secret = 'PRIVATE'; }, (r: any) => { r.challenge.disclose_address = true; },
    (r: any) => { r.challenge.purpose = 'Sign arbitrary data'; }, (r: any) => { r.scope.chain_id = 1; },
    (r: any) => { r.challenge.expires_at++; }, (r: any) => { r.challenge.audience = '00'.repeat(32); }]) {
    const r = structuredClone(f.request);change(r);expect(validHistoryRequest(r)).toBe(false);
  }
});

test('history response cannot export a holder root, unrelated proof scope or unexpected secret field', () => {
  for (const change of [(r: any) => { r.credential = 'PRIVATE'; }, (r: any) => { r.proof.private_key = 'PRIVATE'; },
    (r: any) => { r.proof.statements[0].scope = { kind: 'signing-identity' }; }, (r: any) => { r.proof.statements[0].scope.intent_sha256 = '12'.repeat(32); },
    (r: any) => { r.proof.statements[0].credential = {}; }, (r: any) => { r.proof.response = 'secret'; }]) {
    const r = structuredClone(f.response);change(r);expect(validHistoryResponse(r)).toBe(false);
  }
  expect(historyProjection('bundle-history-prove', f.response, { request: { ...f.request, numbers: [2, 1] } })).toBe(false);
});

test('verified history verdicts bind the exact recipient request and keep old checks distinct from fresh presence', () => {
  for (const change of [{ authorization_checked: false }, { current_possession_checked: false }, { public_address: '0x' + '12'.repeat(20) },
    { post_numbers: [2, 1] }, { request_sha256: 'ab'.repeat(32) }, { challenge_checked_at: f.request.challenge.expires_at },
    { scope: { ...f.request.scope, application: '0x' + '12'.repeat(32) } }, { private_key: 'PRIVATE' }]) {
    expect(historyProjection('bundle-history-verify', { ...f.receipt, ...change }, { response: f.response, request_sha256: f.response.request_sha256 })).toBe(false);
  }
  expect(f.recovered_receipt.current_possession_checked).toBe(false);expect(f.recovered_receipt.challenge_checked_at).toBe(f.receipt.challenge_checked_at);
  expect(historyProjection('bundle-history-verify', { ...f.recovered_receipt, current_possession_checked: true }, { response: f.response, request_sha256: f.response.request_sha256 })).toBe(false);
});
