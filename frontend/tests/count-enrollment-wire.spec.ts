import { test, expect } from '@playwright/test';
import { bundleProjection } from '../src/bundleDiscussion';
import type { BundleOperation } from '../src/bundleDiscussion';
import { readFileSync } from 'node:fs';

function pending(state = 'pending') {
  return { state, credential_saved: false, laboratory: true, verified: false, username: 'synthetic_user',
    post_text: 'testing:' + 'ab'.repeat(32), expires_at: Math.floor(Date.now() / 1000) + 600 };
}

test('count recovery accepts public pending and finality states without making them saved credentials', () => {
  for (const state of ['pending', 'issued', 'committed', 'receipt-saved', 'activation-pending-finality', 'activation-replaced-or-revoked']) {
    expect(bundleProjection('count-recover', pending(state))).toBe(true);
    expect(bundleProjection('count-recover', { ...pending(state), credential_saved: true })).toBe(true);
    const { username: _username, ...missing } = pending(state);
    expect(bundleProjection('count-recover', missing)).toBe(false);
  }
});

test('count recovery retains the source challenge after its deadline', () => {
  expect(bundleProjection('count-recover', { ...pending('activation-pending-finality'), expires_at: Math.floor(Date.now() / 1000) - 1200 })).toBe(true);
});

test('count projections reject impossible saved states and secret or arbitrary challenge fields', () => {
  const empty = { state: 'empty', credential_saved: false, laboratory: true, verified: false };
  expect(bundleProjection('count-status', empty)).toBe(true);
  for (const value of [{ ...empty, credential_saved: true }, { ...empty, state: 'credential-saved' },
    { ...pending(), post_text: 'PRIVATE-MARKER' }, { ...pending(), local_zkid: 'PRIVATE-MARKER' },
    { ...pending(), session: {} }, { ...pending(), credential: {} },
    { ...pending(), expires_at: Math.floor(Date.now() / 1000) + 3600 }]) {
    expect(bundleProjection('count-status', value)).toBe(false);
  }
});

test('count polling requires a bounded public scheduling hint only while awaiting a post', () => {
  const value = pending('awaiting-post');
  expect(bundleProjection('count-poll-registration', value)).toBe(false);
  expect(bundleProjection('count-poll-registration', { ...value, next_check_at: value.expires_at - 30 })).toBe(true);
  expect(bundleProjection('count-poll-registration', { ...value, next_check_at: value.expires_at + 31 })).toBe(false);
  expect(bundleProjection('count-recover', { ...pending(), next_check_at: value.expires_at })).toBe(false);
});

test('actual helper recovery/display projections remain compatible without exposing private session fields', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/count-enrollment-contract-20261031.json', import.meta.url), 'utf8'));
  expect(fixture.actual_count_recovery_and_display).toBe(true);expect(fixture.network_used).toBe(false);
  expect(fixture.cases).toHaveLength(10);
  for (const item of fixture.cases) {
    expect(bundleProjection(item.operation as BundleOperation, item.result), item.name).toBe(true);
    for (const key of ['session', 'account_id', 'credential', 'local_zkid', 'holder']) expect(item.result).not.toHaveProperty(key);
  }
});
