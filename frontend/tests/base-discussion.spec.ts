import { test as base, expect, chromium, type Page, type Worker } from '@playwright/test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import type { WirePost } from '../src/zkidWire';

const test = base.extend<{ extension: { panel: Page; worker: Worker } }>({
  extension: async ({}, use) => {
    const profile = await mkdtemp(resolve(tmpdir(), 'nockapp-base-ui-'));
    const path = resolve('dist');
    const context = await chromium.launchPersistentContext(profile, { channel: 'chromium', headless: true,
      viewport: { width: 390, height: 844 }, args: [`--disable-extensions-except=${path}`, `--load-extension=${path}`, '--no-sandbox'] });
    try {
      const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
      const panel = await context.newPage();await panel.goto(`chrome-extension://${new URL(worker.url()).host}/legacy.html`);
      await expect(panel.getByRole('button', { name: 'Explore demo discussion' })).toBeVisible();
      await use({ panel, worker });
    } finally { await context.close();await rm(profile, { recursive: true, force: true }); }
  },
});

/** Synthetic helper projection only. Actual crypto/EVM/TLS checks are Python tests. */
async function installFixture(worker: Worker, failFirst = false, malformed = false) {
  await worker.evaluate(({ failFirst, malformed }) => {
    const identity = { profile: 'nockapp-base-service-identity-v1', protocol: 'nockapp-base-post-v1', chain_id: 84532,
      contract: '0x' + '12'.repeat(20), registry: '0x' + '34'.repeat(20), application: '0x' + '56'.repeat(32),
      definition_hash: '78'.repeat(32), native_sha256: '9a'.repeat(32) };
    const opening: WirePost = { kind: 'thread', id: '11111111-1111-4111-8111-111111111111', created_at: 1793350000,
      thread_id: null, title: 'From another computer (fixture)', body: 'Shared opening >>2', references: [], claims: [] };
    type Saved = { post: WirePost; facts: string[]; submission_id: string; phase: string; experimental: boolean;
      status: { state: string; checked_at: number; transaction_hash: string; post_number: string | null } };
    const state = { requests: [] as { operation: string; body: Record<string, unknown> }[], rows: [] as Saved[], failFirst, malformed };
    Object.assign(globalThis, { baseFixture: state });
    const publicPost = (post: WirePost, n: string, submission: string) => ({ post, post_number: n, facts: [], state: 'finalized',
      submission_id: submission, valid_when_published: true, accepted_at: Math.floor(Date.now() / 1000) - 5,
      observed_at: null, credential_expiry: null, credential_status: 'not-requested', public_id: null, laboratory_only: true });
    chrome.runtime.connectNative = (() => {
      const listeners = new Set<(v: unknown) => void>();
      return { onMessage: { addListener: (f: (v: unknown) => void) => listeners.add(f), removeListener: (f: (v: unknown) => void) => listeners.delete(f) },
        onDisconnect: { addListener: () => {}, removeListener: () => {} }, disconnect: () => {},
        postMessage: (m: { id: string; profile: string; operation: string; body: Record<string, unknown> }) => {
          state.requests.push(structuredClone({ operation: m.operation, body: m.body }));
          let result: unknown;
          if (m.operation === 'base-capabilities') result = { configured: true, identity, experimental: true };
          else if (m.operation === 'base-discussion') {
            const all = [publicPost(opening, '1', 'ab'.repeat(32)), ...state.rows.filter(r => r.status.state === 'finalized')
              .map(r => publicPost(r.post, r.status.post_number!, r.submission_id))];
            const posts = all.filter(r => Number(r.post_number) > Number(m.body.after));
            result = { identity, posts, unavailable: [], next_after: posts.length ? Number(posts.at(-1)!.post_number) : m.body.after,
              more: false, sync_complete: true, checkpoint: { number: '0x10', hash: '0x' + 'cd'.repeat(32) }, experimental: true };
            if (state.malformed) Object.assign(result!, { credential: 'PRIVATE-MARKER' });
          } else if (m.operation === 'base-outbox') result = { entries: state.rows, next_after: state.rows.length, more: false, experimental: true };
          else if (m.operation === 'base-publish' || m.operation === 'base-check-existing') {
            const post = m.body.post as WirePost | undefined;const id = post?.id ?? m.body.post_id;
            let row = state.rows.find(r => r.post.id === id);
            if (!row && post) {
              row = { post, facts: m.body.facts as string[], submission_id: 'ef'.repeat(32), phase: 'submitted', experimental: true,
                status: { state: 'pending', checked_at: Math.floor(Date.now() / 1000), transaction_hash: '0x' + '01'.repeat(32), post_number: null } };
              state.rows.push(row);
            } else if (row) {
              row.status.state = row.status.state === 'pending' ? 'confirmed' : 'finalized';
              row.status.post_number = row.status.state === 'finalized' ? '2' : null;
            }
            result = row;
            if (state.failFirst) {
              state.failFirst = false;
              queueMicrotask(() => listeners.forEach(f => f({ profile: m.profile, id: m.id, status: 'rejected',
                code: 'native-operation-unavailable', recoverable: true, laboratory: true, verified: false })));
              return;
            }
          }
          queueMicrotask(() => listeners.forEach(f => f({ profile: m.profile, id: m.id, status: 'ok', result: structuredClone(result), laboratory: true, verified: false })));
        } };
    }) as unknown as typeof chrome.runtime.connectNative;
  }, { failFirst, malformed });
}

test('unconfigured shared helper preserves device discussions and offers no publishing form', async ({ extension: { panel } }) => {
  await panel.getByRole('button', { name: 'Shared · Base Sepolia' }).click();
  await expect(panel.getByRole('alert')).toContainText('Shared posting is unavailable');
  await expect(panel.getByRole('button', { name: 'Start shared thread' })).toHaveCount(0);
  await panel.getByRole('button', { name: 'Saved on this device' }).click();
  await expect(panel.getByRole('button', { name: 'Explore demo discussion' })).toBeVisible();
});

test('earlier full-content history stays readable and cannot create fresh posts or source enrollment', async ({ extension: { panel, worker } }) => {
  const before = await panel.evaluate(async () => (await chrome.storage.local.get('nockapp:forum:v1'))['nockapp:forum:v1']);
  await installFixture(worker);await panel.getByRole('button', { name: 'Shared · Base Sepolia' }).click();await panel.getByRole('button', { name: 'Earlier Base prototype' }).click();
  await expect(panel.getByText('From another computer (fixture)', { exact: true })).toBeVisible();await panel.getByRole('button', { name: 'Open shared thread No.1' }).click();
  for (const name of ['Start shared thread', 'Publish anonymous thread', 'Publish anonymous comment']) await expect(panel.getByRole('button', { name, exact: true })).toHaveCount(0);
  await expect(panel.getByRole('link', { name: 'Connect X for optional credential facts' })).toHaveCount(0);
  expect(await panel.evaluate(async () => (await chrome.storage.local.get('nockapp:forum:v1'))['nockapp:forum:v1'])).toEqual(before);
});

test('earlier saved submissions check existing acceptance and preserve newer private drafts', async ({ extension: { panel, worker } }) => {
  await installFixture(worker);
  await worker.evaluate(async () => {
    (globalThis as any).baseFixture.rows.push({ post: { kind: 'thread', id: '22222222-2222-4222-8222-222222222222', created_at: 1793350000, thread_id: null,
      title: 'Earlier saved request', body: 'Original public text', references: [], claims: [] }, facts: [], submission_id: 'ef'.repeat(32), phase: 'submitted', experimental: true,
      status: { state: 'pending', checked_at: 1793350011, transaction_hash: '0x' + '01'.repeat(32), post_number: null } });
    await chrome.storage.local.set({ 'draft:thread:shared:all': { title: 'Later edits', body: 'Newer private draft edits', credentials: [] } });
  });
  await panel.getByRole('button', { name: 'Shared · Base Sepolia' }).click();await panel.getByRole('button', { name: 'Earlier Base prototype' }).click();
  const box = panel.getByRole('region', { name: 'Shared submission outbox' });await box.getByRole('button', { name: 'Check existing acceptance' }).click();
  await expect(box.getByText('confirmed', { exact: true })).toBeVisible();await box.getByRole('button', { name: 'Check existing acceptance' }).click();await expect(box.getByText('finalized · No.2', { exact: true })).toBeVisible();
  await panel.getByRole('button', { name: 'View saved drafts from this earlier version' }).click();await expect(panel.getByText('Newer private draft edits', { exact: true })).toBeVisible();
  const requests = await worker.evaluate(() => (globalThis as any).baseFixture.requests);expect(requests.filter((r: any) => r.operation === 'base-publish')).toHaveLength(0);
  expect(requests.filter((r: any) => r.operation === 'base-check-existing')).toHaveLength(2);
});

test('unexpected helper fields cannot enter shared history or badges', async ({ extension: { panel, worker } }) => {
  await installFixture(worker, false, true);await panel.getByRole('button', { name: 'Shared · Base Sepolia' }).click();await panel.getByRole('button', { name: 'Earlier Base prototype' }).click();
  await expect(panel.getByRole('alert')).toBeVisible();
  await expect(panel.getByText('From another computer (fixture)', { exact: true })).toHaveCount(0);
  await expect(panel.getByText('PRIVATE-MARKER', { exact: false })).toHaveCount(0);
});


test('earlier local drafts stay accessible even when no old helper is configured', async ({ extension: { panel, worker } }) => {
  await worker.evaluate(async () => { await chrome.storage.local.set({ 'draft:thread:shared:all': { title: 'Offline earlier draft', body: 'Keep offline draft text', credentials: [] } }); });
  await panel.getByRole('button', { name: 'Shared · Base Sepolia' }).click();await panel.getByRole('button', { name: 'Earlier Base prototype' }).click();
  await panel.getByRole('button', { name: 'View saved drafts from this earlier version' }).click();await expect(panel.getByText('Keep offline draft text', { exact: true })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Publish anonymous thread', exact: true })).toHaveCount(0);
});
