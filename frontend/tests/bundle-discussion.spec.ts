import { test as base, expect, chromium, type Page, type Worker } from '@playwright/test';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

const test = base.extend<{ extension: { panel: Page; worker: Worker } }>({
  extension: async ({}, use) => {
    const profile = await mkdtemp(resolve(tmpdir(), 'nockapp-bundle-ui-'));
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

// These are synthetic native projections; they test UI boundaries, not cryptography or live storage.
async function fixture(worker: Worker, options: { unsupportedCheck?: boolean; lost?: boolean; unavailable?: boolean; malformed?: boolean; gaps?: boolean; evidence?: 'missing' | 'checked'; tamper?: boolean; holdRead?: boolean; holdArchive?: boolean; expired?: boolean; renewReject?: boolean; malformedCount?: boolean } = {}) {
  await worker.evaluate(options => {
    const h = (n: string) => '0x' + n.repeat(32);
    const identity = { profile: 'nockapp-bundle-service-identity-v3', protocol: 3, chain_id: 84532,
      contract: '0x' + '12'.repeat(20), registry: '0x' + '34'.repeat(20), application: h('56'),
      definition_hash: '78'.repeat(32), native_sha256: '9a'.repeat(32), count_native_sha256: 'bc'.repeat(32),
      bundle_profile: 'nockapp-public-discussion-bundle-v3', storage: { replicas: [{ name: 'replica-one', failure_domain: 'region-one' },
        { name: 'replica-two', failure_domain: 'region-two' }], retention_seconds: 90 * 86400, max_bundle_bytes: 32768, permanent_availability_proven: false } };
    const post = { kind: 'thread', id: '11111111-1111-4111-8111-111111111111', created_at: 1793350000,
      thread_id: null, title: 'Shared bundle fixture', body: 'Public synthetic opening', references: [], claims: [] };
    const ordinary = { credential_kind: 0, facts: [], threshold: null };
    const row = { submission_id: 'ab'.repeat(32), post_id: h('11'), thread_id: h('11'), bundle_hash: h('22'), registry_hash: h('33'), registry_sequence: 0,
      post_number: '1', accepted_at: 1793350010, observed_at: 0, credential_expiry: 0, credential_kind: 0,
      block_hash: h('44'), block_number: 16, transaction_hash: h('55'), canonical_accepted: true, ordinal: 1,
      post, selection: ordinary, state: 'finalized', content_integrity_checked: true, credential_evidence_checked: false,
      valid_when_published: true, credential_status: 'not-requested', disclosed_follower_count: null, public_id: null, content_source: 'replica-one', experimental: true };
    const state = { requests: [] as { operation: string; body: Record<string, unknown> }[], rows: [] as any[], options, failRead: false };
    Object.assign(globalThis, { bundleFixture: state });
    chrome.runtime.connectNative = (() => {
      const listeners = new Set<(v: unknown) => void>();
      return { onMessage: { addListener: (f: (v: unknown) => void) => listeners.add(f), removeListener: (f: (v: unknown) => void) => listeners.delete(f) },
        onDisconnect: { addListener: () => {}, removeListener: () => {} }, disconnect: () => {},
        postMessage: (m: { id: string; profile: string; operation: string; body: Record<string, unknown> }) => {
          state.requests.push(structuredClone({ operation: m.operation, body: m.body }));
          let result: any;let reject = false;
          if (m.operation === 'bundle-capabilities') result = { configured: true, identity, count_enrollment_configured: true, experimental: true };
          else if (m.operation === 'bundle-outbox') result = { entries: state.rows, next_after: state.rows.length, more: false, experimental: true };
          else if (m.operation === 'bundle-threads' || m.operation === 'bundle-thread') {
            let item: any = structuredClone(row);
            if (state.options.unavailable) {
              for (const key of ['selection', 'disclosed_follower_count', 'public_id', 'content_source', 'experimental']) delete item[key];
              Object.assign(item, { post: null, state: 'content-unavailable', content_integrity_checked: false, valid_when_published: null, credential_status: 'unavailable' });
            }
            if (state.options.evidence) {
              Object.assign(item, { credential_kind: 2, observed_at: 1793340000, credential_expiry: 1793440000,
                selection: { credential_kind: 2, facts: ['followers-more-than'], threshold: 12345 },
                credential_evidence_checked: state.options.evidence === 'checked',
                state: state.options.evidence === 'checked' ? 'finalized' : 'evidence-unavailable',
                valid_when_published: state.options.evidence === 'checked' ? true : null,
                credential_status: state.options.evidence === 'checked' ? 'unknown-after-registry-update' : 'unavailable' });
              if (state.options.evidence === 'missing') for (const key of ['disclosed_follower_count', 'public_id', 'content_source', 'experimental']) delete item[key];
            }
            if (state.options.gaps) item = { ordinal: 1, state: 'index-gap', canonical_accepted: false, post: null };
            result = { identity, posts: [item], scope: m.operation === 'bundle-thread' ? 'thread' : 'thread-catalog',
              thread_id: m.body.thread_id ?? null, thread_accepted: m.body.thread_id ? true : null, canonical_total_count: '1', last_canonical_number: '1',
              after: 0, next_after: 1, more: false, index_gaps: state.options.gaps ? [1] : [], page_complete: !state.options.gaps,
              listing_complete: !state.options.gaps, global_listing_complete: false, page_content_complete: !state.options.gaps && !state.options.unavailable,
              content_complete: !state.options.gaps && !state.options.unavailable, page_evidence_complete: !state.options.gaps && state.options.evidence !== 'missing',
              checkpoint: { number: '0x10', hash: h('44') }, experimental: true };
            if (state.options.malformed) result.credential = 'PRIVATE-MARKER';
            reject = state.failRead;
          } else if (m.operation === 'bundle-renew') {
            result = state.rows.find(r => r.post.id === m.body.post_id);reject = !!state.options.renewReject;
            if (!reject) { result.submission_id = 'de'.repeat(32);result.renewal_count = 1;result.status = { state: 'pending', checked_at: 1793350020, transaction_hash: h('66'), post_number: null }; }
          } else if (m.operation === 'bundle-publish' || m.operation === 'bundle-check-existing') {
            let saved = state.rows.find(r => r.post.id === ((m.body.post as any)?.id ?? m.body.post_id));
            if (!saved) { saved = { post: m.body.post, selection: m.body.selection, submission_id: 'ef'.repeat(32), phase: 'submitted',
              status: { state: 'pending', checked_at: 1793350011, transaction_hash: h('66'), post_number: null }, experimental: true };state.rows.push(saved); }
            else saved.status = { state: 'finalized', checked_at: 1793350020, transaction_hash: h('66'), post_number: '2' };
            if (state.options.expired) saved.status = { state: 'recoverable', checked_at: 1793350011, recovery_action: 'renew-expired-proof' };
            result = state.options.tamper ? { ...saved, selection: { ...saved.selection, threshold: 12346 } } : saved;if (state.options.lost) { state.options.lost = false;reject = true; }
          } else if (m.operation === 'bundle-export-public') result = { profile: 'nockapp-public-bundle-archive-v1',
            scope: { chain_id: 84532, contract: identity.contract, application: identity.application },
            record: { post_number: String(m.body.post_number), bundle_hash: h('22'), bundle_base64: 'e30=' }, experimental: true };
          else if (m.operation === 'bundle-import-public') result = { post_number: (m.body.record as any).post_number,
            bundle_hash: (m.body.record as any).bundle_hash, cached: true, verification_required: true, experimental: true };
          else if (m.operation === 'bundle-clear-cache') result = { cleared_bundles: 1, remote_records_deleted: false, drafts_deleted: false, experimental: true };
          else if (m.operation === 'count-status') result = { state: 'empty', credential_saved: false, laboratory: true, verified: false };
          else if (m.operation === 'count-begin' || m.operation === 'count-recover') result = {
            state: m.operation === 'count-begin' ? 'awaiting-post' : 'pending', credential_saved: false, laboratory: true, verified: false,
            username: 'synthetic_user', post_text: state.options.malformedCount ? 'PRIVATE-MARKER' : 'testing:' + 'ab'.repeat(32),
            expires_at: Math.floor(Date.now() / 1000) + 600 };
          if (m.operation === 'bundle-check-existing' && state.options.unsupportedCheck) reject = true;
          const deliver = () => queueMicrotask(() => listeners.forEach(f => f(reject ? { profile: m.profile, id: m.id, status: 'rejected', code: 'native-operation-unavailable', recoverable: true, laboratory: true, verified: false }
            : { profile: m.profile, id: m.id, status: 'ok', result: structuredClone(result), laboratory: true, verified: false })));
          if (m.operation === 'bundle-threads' && state.options.holdRead) Object.assign(globalThis, { releaseBundleHistory: deliver });
          else if (m.operation === 'bundle-import-public' && state.options.holdArchive) Object.assign(globalThis, { releaseArchiveImport: deliver });else deliver();
        } };
    }) as unknown as typeof chrome.runtime.connectNative;
  }, options);
}
async function open(panel: Page) { await panel.getByRole('button', { name: 'Shared · Base Sepolia' }).click();await panel.getByRole('button', { name: 'Shared offchain · v3' }).click(); }
async function requests(worker: Worker) { return worker.evaluate(() => Reflect.get(globalThis, 'bundleFixture').requests as { operation: string; body: any }[]); }

test('missing replicated content preserves canonical number and does not claim empty history', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { unavailable: true });await open(panel);
  await expect(panel.getByText('Content unavailable. Base preserves the commitment and number, not the missing text.')).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Copy reference to post No.1' })).toBeVisible();
  await expect(panel.getByText('No accepted shared threads', { exact: false })).toHaveCount(0);
});
test('index gaps are explicit and never imply an empty discussion', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { gaps: true });await open(panel);await expect(panel.getByText('Index or acceptance gap. This is not an empty entry.')).toBeVisible();
  await expect(panel.getByText('Partial listing;', { exact: false })).toBeVisible();
});
test('failed refresh retains previous entries with stale status', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await expect(panel.getByText('Shared bundle fixture', { exact: true })).toBeVisible();
  await worker.evaluate(() => { Reflect.get(globalThis, 'bundleFixture').failRead = true; });
  await panel.getByRole('button', { name: 'Refresh shared discussions' }).click();await expect(panel.getByRole('alert')).toBeVisible();
  await expect(panel.getByText('Shared bundle fixture', { exact: true })).toBeVisible();await expect(panel.getByText('Last loaded entries are retained;', { exact: false })).toBeVisible();
});
test('unexpected helper fields are rejected without rendering their content', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { malformed: true });await open(panel);await expect(panel.getByRole('alert')).toBeVisible();
  await expect(panel.getByText('Shared bundle fixture', { exact: true })).toHaveCount(0);await expect(panel.getByText('PRIVATE-MARKER', { exact: false })).toHaveCount(0);
});
for (const evidence of ['missing', 'checked'] as const) test(`credential badge requires checked evidence: ${evidence}`, async ({ extension: { panel, worker } }) => {
  await fixture(worker, { evidence });await open(panel);await expect(panel.getByText('Shared bundle fixture', { exact: true })).toBeVisible();
  if (evidence === 'missing') { await expect(panel.getByText('No verified credential badge: evidence unavailable.')).toBeVisible();await expect(panel.getByText('Test proof · valid when published:', { exact: false })).toHaveCount(0); }
  else { await expect(panel.getByText('Test proof · valid when published: follower count > 12345')).toBeVisible();await expect(panel.getByText('unknown after registry update', { exact: false })).toBeVisible(); }
  await expect(panel.getByText('exact follower count:', { exact: false })).toHaveCount(0);
});
test('public archive is explicit and partial, excludes drafts, and restoration triggers independent refresh', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await worker.evaluate(async () => { await chrome.storage.local.set({ 'draft:thread:bundle:84532:0x1212121212121212121212121212121212121212:all': { title: 'Earlier draft', body: 'PRIVATE-DRAFT-ARCHIVE-MARKER', credentials: [] } }); });await open(panel);
  await panel.getByRole('button', { name: 'View saved drafts from this earlier version' }).click();
  await panel.getByText('Public history archive', { exact: true }).click();
  expect((await requests(worker)).some(r => r.operation.includes('public'))).toBe(false);
  await panel.getByRole('button', { name: 'Prepare archive of loaded public posts' }).click();
  const download = panel.getByRole('link', { name: 'Download public archive' });await expect(download).toBeVisible();
  const saved = panel.waitForEvent('download');await download.click();
  const file = await saved;const text = await readFile((await file.path())!, 'utf8');
  expect(text).not.toContain('PRIVATE-DRAFT-ARCHIVE-MARKER');const document = JSON.parse(text);
  expect(document.partial).toBe(true);expect(document.records).toHaveLength(1);expect(document.records[0].post_number).toBe('1');
  const before = (await requests(worker)).filter(r => r.operation === 'bundle-threads').length;
  await panel.getByLabel('Restore public archive').setInputFiles({ name: 'public.json', mimeType: 'application/json', buffer: Buffer.from(text) });
  await expect(panel.getByRole('region', { name: 'Public history archive' }).getByRole('status')).toContainText('1 public records cached');
  await expect.poll(async () => (await requests(worker)).filter(r => r.operation === 'bundle-threads').length).toBeGreaterThan(before);
  await expect(panel.getByText('PRIVATE-DRAFT-ARCHIVE-MARKER', { exact: true })).toBeVisible();
  const imported = (await requests(worker)).filter(r => r.operation === 'bundle-import-public');expect(imported).toHaveLength(1);
  expect(Object.keys(imported[0].body).sort()).toEqual(['confirm_public_archive_import', 'record', 'scope']);
  expect((await requests(worker)).some(r => r.operation === 'bundle-publish' || r.operation.startsWith('count-'))).toBe(false);
});

test('archive wrong application, duplicate numbers and oversized files reject before native access', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await expect(panel.getByText('Shared bundle fixture', { exact: true })).toBeVisible();
  await panel.getByText('Public history archive', { exact: true }).click();
  const scope = { chain_id: 84532, contract: '0x' + '12'.repeat(20), application: '0x' + '56'.repeat(32) };
  const record = { post_number: '1', bundle_hash: '0x' + '22'.repeat(32), bundle_base64: 'e30=' };
  const archive = { profile: 'nockapp-public-bundle-archive-v1', scope, partial: true, records: [record], missing_post_numbers: [] };
  for (const value of [{ ...archive, scope: { ...scope, chain_id: 1 } }, { ...archive, records: [record, record] },
    { ...archive, credential: 'PRIVATE-MARKER' }]) {
    await panel.getByLabel('Restore public archive').setInputFiles({ name: 'bad.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(value)) });
    await expect(panel.getByRole('region', { name: 'Public history archive' }).getByRole('status')).toContainText('Unsupported archive');
  }
  await panel.getByLabel('Restore public archive').setInputFiles({ name: 'huge.json', mimeType: 'application/json', buffer: Buffer.alloc(8 * 1024 * 1024 + 1, ' ') });
  await expect(panel.getByRole('region', { name: 'Public history archive' }).getByRole('status')).toContainText('8 MiB limit');
  expect((await requests(worker)).some(r => r.operation === 'bundle-import-public')).toBe(false);
});

test('stopping an archive releases the helper and does not start later records or a false refresh', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { holdArchive: true });await open(panel);await expect(panel.getByText('Shared bundle fixture', { exact: true })).toBeVisible();
  await panel.getByText('Public history archive', { exact: true }).click();
  const record = { post_number: '1', bundle_hash: '0x' + '22'.repeat(32), bundle_base64: 'e30=' };
  const text = JSON.stringify({ profile: 'nockapp-public-bundle-archive-v1', partial: true, missing_post_numbers: [],
    scope: { chain_id: 84532, contract: '0x' + '12'.repeat(20), application: '0x' + '56'.repeat(32) },
    records: [record, { ...record, post_number: '2' }] });
  const before = (await requests(worker)).filter(r => r.operation === 'bundle-threads').length;
  await panel.getByLabel('Restore public archive').setInputFiles({ name: 'public.json', mimeType: 'application/json', buffer: Buffer.from(text) });
  await expect.poll(() => worker.evaluate(() => typeof Reflect.get(globalThis, 'releaseArchiveImport'))).toBe('function');
  await panel.getByRole('button', { name: 'Stop archive work' }).click();
  await expect(panel.getByRole('region', { name: 'Public history archive' }).getByRole('status')).toContainText('Archive work stopped');
  await worker.evaluate(() => Reflect.get(globalThis, 'releaseArchiveImport')());
  await expect(panel.getByRole('button', { name: 'Refresh shared discussions' })).toBeEnabled();
  expect((await requests(worker)).filter(r => r.operation === 'bundle-import-public')).toHaveLength(1);
  expect((await requests(worker)).filter(r => r.operation === 'bundle-threads')).toHaveLength(before);
});


test('earlier v3 is read only, keeps local history, and offers no fresh composer, renewal or source enrollment', async ({ extension: { panel, worker } }) => {
  const before = await panel.evaluate(async () => (await chrome.storage.local.get('nockapp:forum:v1'))['nockapp:forum:v1']);
  await fixture(worker);await open(panel);await expect(panel.getByText('Shared bundle fixture', { exact: true })).toBeVisible();
  await expect(panel.getByText('Earlier discussions are read only.', { exact: false })).toBeVisible();
  await panel.getByRole('button', { name: 'Open shared thread No.1', exact: true }).click();
  for (const name of ['Start shared thread', 'Publish anonymous thread', 'Publish anonymous comment', 'Connect X for optional count proofs', 'Create fresh proof after finalized expiry']) await expect(panel.getByRole('button', { name, exact: true })).toHaveCount(0);
  expect((await requests(worker)).some(r => ['bundle-publish', 'bundle-renew'].includes(r.operation) || r.operation.startsWith('count-'))).toBe(false);
  expect(await panel.evaluate(async () => (await chrome.storage.local.get('nockapp:forum:v1'))['nockapp:forum:v1'])).toEqual(before);
});

test('earlier browser-only intents and drafts survive reload without being republished', async ({ extension: { panel, worker } }) => {
  await fixture(worker);
  const old = { draft_key: 'thread:bundle:84532:0x1212121212121212121212121212121212121212:all', post: { kind: 'thread', id: '22222222-2222-4222-8222-222222222222', created_at: 1793350000,
    thread_id: null, title: 'Earlier pending intent', body: 'Original unsubmitted text', references: [], claims: [] }, selection: { credential_kind: 0, facts: [], threshold: null }, acknowledged: false, released: false };
  await worker.evaluate(async old => { await chrome.storage.local.set({ 'nockapp:bundle:submission-intents:v3': [old], ['draft:' + old.draft_key]: { title: 'Newer edited draft', body: 'Keep this newer private text', credentials: [] } }); }, old);
  await open(panel);await panel.reload();const box = panel.getByRole('region', { name: 'Shared submission outbox' });
  await box.getByRole('button', { name: 'Check existing acceptance' }).click();await expect(panel.getByRole('alert')).toContainText('not saved by the earlier helper');
  expect((await requests(worker)).some(r => r.operation === 'bundle-publish' || r.operation === 'bundle-check-existing')).toBe(false);
  await panel.getByRole('button', { name: 'View saved drafts from this earlier version' }).click();await expect(panel.getByText('Keep this newer private text', { exact: true })).toBeVisible();
  const saved = await worker.evaluate(async () => (await chrome.storage.local.get('nockapp:bundle:submission-intents:v3'))['nockapp:bundle:submission-intents:v3']);expect(saved).toEqual([old]);
});

test('earlier helper outbox can be checked without fresh publish, renewal or draft mutation', async ({ extension: { panel, worker } }) => {
  await fixture(worker);
  await worker.evaluate(() => { (globalThis as any).bundleFixture.rows.push({ post: { kind: 'thread', id: '22222222-2222-4222-8222-222222222222', created_at: 1793350000,
    thread_id: null, title: 'Earlier saved request', body: 'Public saved text', references: [], claims: [] }, selection: { credential_kind: 0, facts: [], threshold: null }, submission_id: 'ef'.repeat(32), phase: 'submitted',
    status: { state: 'pending', checked_at: 1793350011, transaction_hash: '0x' + '66'.repeat(32), post_number: null }, experimental: true }); });
  await open(panel);await panel.getByRole('region', { name: 'Shared submission outbox' }).getByRole('button', { name: 'Check existing acceptance' }).click();
  await expect(panel.getByRole('region', { name: 'Shared submission outbox' }).getByText('finalized · No.2', { exact: true })).toBeVisible();
  expect((await requests(worker)).some(r => r.operation === 'bundle-publish' || r.operation === 'bundle-renew')).toBe(false);
  expect((await requests(worker)).filter(r => r.operation === 'bundle-check-existing')).toHaveLength(1);
});


test('older helpers that do not implement acceptance-only checking fail closed without a legacy retry', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { unsupportedCheck: true });
  await worker.evaluate(() => { (globalThis as any).bundleFixture.rows.push({ post: { kind: 'thread', id: '22222222-2222-4222-8222-222222222222', created_at: 1793350000,
    thread_id: null, title: 'Earlier saved request', body: 'Retained text', references: [], claims: [] }, selection: { credential_kind: 0, facts: [], threshold: null }, submission_id: 'ef'.repeat(32), phase: 'submitted',
    status: { state: 'pending', checked_at: 1793350011, transaction_hash: '0x' + '66'.repeat(32), post_number: null }, experimental: true }); });
  await open(panel);await panel.getByRole('region', { name: 'Shared submission outbox' }).getByRole('button', { name: 'Check existing acceptance' }).click();await expect(panel.getByRole('alert')).toBeVisible();
  const calls = await requests(worker);expect(calls.filter(r => r.operation === 'bundle-check-existing')).toHaveLength(1);
  expect(calls.some(r => ['bundle-recover', 'bundle-publish', 'bundle-renew'].includes(r.operation))).toBe(false);
  await expect(panel.getByRole('region', { name: 'Shared submission outbox' }).getByText('Retained text', { exact: true })).toBeVisible();
});
