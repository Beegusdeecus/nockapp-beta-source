import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { projection, validAuthoredRow } from '../src/authoredDiscussion';
const fixture = JSON.parse(readFileSync(new URL('./fixtures/authored-read-contract-20261101.json', import.meta.url), 'utf8'));
const body = { after: 0, limit: 8 };

test('actual Python desktop public projections retain strict v4 author/address/count and history completeness schemas', () => {
  expect(fixture.source_chain_id).toBe(31337);expect(fixture.identity_chain_remapped_for_ui).toBe(true);
  expect(fixture.real_native_tls_and_local_evm).toBe(true);expect(fixture.network_or_owner_credentials_used).toBe(false);
  for (const field of ['page', 'evidence_unavailable_page', 'content_unavailable_page']) expect(projection('bundle-threads', fixture[field], body), field).toBe(true);
  expect(projection('bundle-capabilities', fixture.capabilities)).toBe(true);
  expect(projection('bundle-numbers', fixture.numbers, { numbers: [1, 2] })).toBe(true);
  expect(projection('bundle-outbox', fixture.outbox, { after: 0, limit: 8 })).toBe(true);
  expect(projection('bundle-recover', fixture.ordinary_status, { post_id: fixture.ordinary_status.post.id })).toBe(true);
  expect(projection('bundle-recover', fixture.selected_status, { post_id: fixture.selected_status.post.id })).toBe(true);
});

test('ordinary posts still require checked author evidence; failed proof never becomes a verified badge', () => {
  const ordinary = fixture.page.posts.find((p: any) => p.credential_kind === 0);
  expect(validAuthoredRow(ordinary)).toBe(true);
  for (const change of [{ authorship_checked: false }, { public_address: '0x' + '12'.repeat(20) }, { address_evidence_checked: true }, { public_id: null }, { secret: 'PRIVATE' }]) expect(validAuthoredRow({ ...ordinary, ...change })).toBe(false);
  const missing = fixture.evidence_unavailable_page.posts.find((p: any) => p.credential_kind === 0);
  expect(validAuthoredRow(missing)).toBe(true);expect(missing.authorship_checked).toBe(false);
  expect(projection('bundle-threads', { ...fixture.evidence_unavailable_page, page_evidence_complete: true }, body)).toBe(false);
});

test('v4 rows reject unrelated wallet/count badges, exact counts, permanent IDs and incompatible legacy schema', () => {
  const selected = fixture.page.posts.find((p: any) => p.credential_kind === 2);
  for (const change of [{ address_evidence_checked: false }, { public_address: null }, { credential_evidence_checked: false },
    { disclosed_follower_count: 10001 }, { selection: { address: true, followers_threshold: null } },
    { selection: { credential_kind: 2, facts: ['followers-more-than'], threshold: 10000 } },
    { public_address: { secret: 'PRIVATE' } }, { authorship_checked: 'true' }]) expect(validAuthoredRow({ ...selected, ...change })).toBe(false);
  expect(projection('bundle-threads', { ...fixture.page, identity: { ...fixture.page.identity, protocol: 3 } }, body)).toBe(false);
  expect(projection('bundle-threads', { ...fixture.page, credential: 'PRIVATE' }, body)).toBe(false);
});

test('canonical pagination cannot silently drop rows, reorder numbers or erase gaps and missing content', () => {
  for (const change of [{ posts: [] }, { next_after: 0 }, { more: true }, { listing_complete: false }, { index_gaps: [1] },
    { posts: [fixture.page.posts[1], fixture.page.posts[0]] }]) expect(projection('bundle-threads', { ...fixture.page, ...change }, body)).toBe(false);
  expect(projection('bundle-threads', { ...fixture.content_unavailable_page, page_content_complete: true }, body)).toBe(false);
  expect(projection('bundle-numbers', fixture.numbers, { numbers: [2, 1] })).toBe(false);
});

test('thread scopes reject other roots and a catalog cannot be relabeled as a thread', () => {
  const body = { thread_id: fixture.thread.thread_id, after: 0, limit: 8 };
  expect(projection('bundle-thread', fixture.thread, body)).toBe(true);
  expect(projection('bundle-thread', { ...fixture.page, scope: 'thread', thread_id: body.thread_id, thread_accepted: true }, body)).toBe(false);
  const item = structuredClone(fixture.page);item.posts[0].post.kind = 'comment';item.posts[0].post.title = null;item.posts[0].post.thread_id = fixture.thread.posts[0].post.id;
  expect(projection('bundle-threads', item, { after: 0, limit: 8 })).toBe(false);
});
