import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { canonicalAscii, connectBaseWallet, signExactPost, validatePostWalletRequest, validPostWalletRequestShape } from '../src/authoredWallet';
import { projection, validBody } from '../src/authoredDiscussion';
const fixture = JSON.parse(readFileSync(new URL('./fixtures/authored-wallet-contract-20261101.json', import.meta.url), 'utf8'));
const NOW = 1793494801;
const fresh = () => structuredClone(fixture);
const validate = (f = fresh()) => validatePostWalletRequest(f.request, f.scope, f.post, f.selection, f.submission_id, fixture.request.address, NOW);

test('wallet hashes match the actual Python protocol including Unicode and strict threshold selection', async () => {
  const f = fresh();expect(f.synthetic_public_proof).toBe(true);expect(f.network_used).toBe(false);
  expect(canonicalAscii({ profile: 'nockapp-authored-post-intent-v4', context: { ...f.scope, protocol: 4, submission_id: f.submission_id }, post: f.post, disclosures: f.selection })).toBe(f.canonical_intent);
  const req = await validate(f);expect(req.request_sha256).toBe(f.request.request_sha256);
  expect(Object.isFrozen(req.typed_data.message)).toBe(true);expect(projection('bundle-address-request', f.request)).toBe(true);
});

test('changed post, disclosure, application, contract, submission or account cannot be signed', async () => {
  for (const change of [(f: any) => { f.post.body += '!'; }, (f: any) => { f.post.title += '!'; },
    (f: any) => { f.selection.followers_threshold++; }, (f: any) => { f.selection.address = false; },
    (f: any) => { f.scope.application = '0x' + '78'.repeat(32); }, (f: any) => { f.scope.contract = '0x' + '78'.repeat(20); },
    (f: any) => { f.submission_id = 'ef'.repeat(32); }, (f: any) => { f.request.address = '0x' + '78'.repeat(20); },
    (f: any) => { f.request.request_sha256 = 'ef'.repeat(32); }]) {
    const f = fresh();change(f);await expect(validate(f)).rejects.toThrow();
  }
});

test('projection rejects private fields, arbitrary nested values, other EIP712 schemas and impossible windows', () => {
  for (const change of [(r: any) => { r.secret = 'PRIVATE'; }, (r: any) => { r.typed_data.message.intentHash = { secret: 'PRIVATE' }; },
    (r: any) => { r.typed_data.message.purpose = 'Permit spending'; }, (r: any) => { r.typed_data.message.value = 100; },
    (r: any) => { r.typed_data.primaryType = 'Permit'; }, (r: any) => { r.typed_data.domain.chainId = 8453; },
    (r: any) => { r.typed_data.domain.name = 'Other application'; }, (r: any) => { r.typed_data.domain.verifyingContract = {}; },
    (r: any) => { r.typed_data.types.NockAppPostAuthorization.push({ name: 'private_key', type: 'string' }); },
    (r: any) => { r.typed_data.message.deadline++; }, (r: any) => { r.authorization_expires_at = r.typed_data.message.deadline + 1; }]) {
    const r = fresh().request;change(r);expect(validPostWalletRequestShape(r)).toBe(false);expect(projection('bundle-address-request', r)).toBe(false);
  }
});

test('expired, future and shortened credential windows are rejected before wallet access', async () => {
  const f = fresh();
  await expect(validatePostWalletRequest(f.request, f.scope, f.post, f.selection, f.submission_id, f.request.address, 1793494850)).rejects.toThrow();
  f.request.expired = true;await expect(validate(f)).rejects.toThrow();
  f.request.expired = false;f.request.typed_data.message.issuedAt += 20;f.request.typed_data.message.deadline += 20;await expect(validate(f)).rejects.toThrow();
});

test('MetaMask connection switches only to Base Sepolia, and refusal never reaches signing', async () => {
  const calls: string[] = [];let chain = '0x1';
  const p = { request: async (r: { method: string; params?: unknown[] }) => {
    calls.push(r.method);
    if (r.method === 'eth_requestAccounts') return [fresh().request.address];
    if (r.method === 'eth_chainId') return chain;
    if (r.method === 'wallet_switchEthereumChain') { expect(r.params).toEqual([{ chainId: '0x14a34' }]);chain = '0x14a34';return null; }
    throw new Error('Unexpected wallet method');
  } };
  expect(await connectBaseWallet(p)).toBe(fresh().request.address);
  expect(calls).toEqual(['eth_requestAccounts', 'eth_chainId', 'wallet_switchEthereumChain', 'eth_chainId']);
  await expect(connectBaseWallet({ request: async () => { throw new Error('User declined'); } })).rejects.toThrow('User declined');
});

test('raw requests cannot bypass validation; validated request is frozen and account/network are checked again', async () => {
  let calls = 0;const p = { request: async () => { calls++;throw new Error('Must not contact wallet'); } };
  await expect(signExactPost(fresh().request, p)).rejects.toThrow();expect(calls).toBe(0);
  const f = fresh();const offset = Math.floor(Date.now() / 1000) - NOW;
  f.request.typed_data.message.issuedAt += offset;f.request.typed_data.message.deadline += offset;f.request.authorization_expires_at += offset;
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalAscii(f.request.typed_data)));
  f.request.request_sha256 = [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
  const req = await validatePostWalletRequest(f.request, f.scope, f.post, f.selection, f.submission_id, f.request.address);
  f.request.typed_data.message.purpose = 'Changed after validation';expect(req.typed_data.message.purpose).not.toBe(f.request.typed_data.message.purpose);
  const methods: string[] = [];
  const provider = { request: async (r: { method: string; params?: unknown[] }) => {
    methods.push(r.method);if (r.method === 'eth_accounts') return [req.address];if (r.method === 'eth_chainId') return '0x14a34';
    expect(r.method).toBe('eth_signTypedData_v4');expect(r.params).toEqual([req.address, JSON.stringify(req.typed_data)]);return '0x' + '12'.repeat(65);
  } };
  expect(await signExactPost(req, provider)).toBe('0x' + '12'.repeat(65));expect(methods).toEqual(['eth_accounts', 'eth_chainId', 'eth_signTypedData_v4']);
  for (const changed of ['account', 'network']) await expect(signExactPost(req, { request: async r => r.method === 'eth_accounts'
    ? [changed === 'account' ? '0x' + '78'.repeat(20) : req.address] : '0x1' })).rejects.toThrow('account or network changed');
});

test('wallet IPC permits fixed post operations and rejects arbitrary commands and extra consent fields', () => {
  expect(validBody('bundle-initialize-identity', { approve_private_key_setup: true })).toBe(true);
  expect(validBody('bundle-initialize-identity', { approve_private_key_setup: false })).toBe(false);
  expect(validBody('eth_signTypedData_v4', { data: fresh().request.typed_data })).toBe(false);
  expect(validBody('bundle-address-request', { post_id: fresh().post.id, address: fresh().request.address, approve_address_disclosure: true, private_key: 'PRIVATE' })).toBe(false);
});

test('public helper results are correlated to the requested post, disclosure, submission and outbox page', () => {
  const f = fresh();const row = { post: f.post, selection: f.selection, submission_id: f.submission_id, phase: 'wallet-needed', renewal_count: 0, experimental: true,
    status: { state: 'recoverable', checked_at: NOW, authorship_checked: false, address_evidence_checked: false, credential_evidence_checked: false } };
  const body = { post: f.post, selection: f.selection, approve_publication: true };
  expect(projection('bundle-publish', row, body)).toBe(true);
  expect(projection('bundle-publish', { ...row, post: { ...f.post, body: 'Wrong saved text' } }, body)).toBe(false);
  expect(projection('bundle-publish', { ...row, selection: { ...f.selection, address: false } }, body)).toBe(false);
  expect(projection('bundle-recover', row, { post_id: '22222222-2222-4222-8222-222222222222' })).toBe(false);
  expect(projection('bundle-renew', row, { post_id: f.post.id, expected_submission_id: f.submission_id })).toBe(false);
  expect(projection('bundle-address-result', row, { post_id: f.post.id, submission_id: 'ef'.repeat(32) })).toBe(false);
  expect(projection('bundle-address-request', f.request, { address: '0x' + '78'.repeat(20) })).toBe(false);
  expect(projection('bundle-outbox', { entries: [row], next_after: 2, more: false, experimental: true }, { after: 0, limit: 8 })).toBe(false);
  for (const status of [{ ...row.status, content_state: { secret: 'PRIVATE' } }, { ...row.status, checked_at: -1 },
    { ...row.status, last_known: { state: { secret: 'PRIVATE' }, checked_at: NOW } }]) expect(projection('bundle-recover', { ...row, status })).toBe(false);
});

test('wallet checks that overrun the signing window cannot trigger an expired signing prompt', async () => {
  const f = fresh();const original = Date.now;Date.now = () => NOW * 1000;
  try {
    const req = await validate(f);const calls: string[] = [];
    await expect(signExactPost(req, { request: async r => {
      calls.push(r.method);if (r.method === 'eth_accounts') return [req.address];
      Date.now = () => req.authorization_expires_at * 1000;return '0x14a34';
    } })).rejects.toThrow('expired while checking');
    expect(calls).toEqual(['eth_accounts', 'eth_chainId']);
  } finally { Date.now = original; }
});
