import { test as base, expect, chromium, type Page, type Worker } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
const history = JSON.parse(readFileSync(new URL('./fixtures/authored-history-contract-20261101.json', import.meta.url), 'utf8'));
const contract = JSON.parse(readFileSync(new URL('./fixtures/authored-read-contract-20261101.json', import.meta.url), 'utf8'));
const test = base.extend<{ extension: { panel: Page; worker: Worker } }>({
  extension: async ({}, use) => {
    const profile = await mkdtemp(resolve(tmpdir(), 'nockapp-authored-discussion-ui-'));const path = resolve('dist');
    const context = await chromium.launchPersistentContext(profile, { channel: 'chromium', headless: true, viewport: { width: 390, height: 844 },
      args: [`--disable-extensions-except=${path}`, `--load-extension=${path}`, '--no-sandbox'] });
    try {
      const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');const panel = await context.newPage();
      await panel.goto(`chrome-extension://${new URL(worker.url()).host}/legacy.html`);await expect(panel.getByRole('button', { name: 'Explore demo discussion' })).toBeVisible();
      await use({ panel, worker });
    } finally { await context.close();await rm(profile, { recursive: true, force: true }); }
  },
});
type Options = { history?: boolean; malformedCount?: boolean; lost?: boolean; evidenceMissing?: boolean; contentMissing?: boolean; invalid?: boolean; tamper?: boolean; expired?: boolean; oldProtocol?: boolean; hold?: boolean };
// Strict frontend fixtures, not native proof verification or live acceptance.
async function fixture(worker: Worker, options: Options = {}) {
  await worker.evaluate(({ f, options, history }) => {
    const state = { requests: [] as any[], rows: [] as any[], options, failRead: false, historyRequests: [] as any[], historyVerified: false };Object.assign(globalThis, { authoredFixture: state });
    const flags = { authorship_checked: false, address_evidence_checked: false, credential_evidence_checked: false };
    chrome.runtime.connectNative = (() => {
      const listeners = new Set<(v: unknown) => void>();
      return { name: '', onMessage: { addListener: (fn: (v: unknown) => void) => listeners.add(fn), removeListener: (fn: (v: unknown) => void) => listeners.delete(fn) },
        onDisconnect: { addListener: () => {}, removeListener: () => {} }, disconnect: () => {}, postMessage: (m: any) => {
          if (!m.operation.startsWith('authored-')) throw new Error('New UI used the legacy native namespace');
          m = { ...m, wire_operation: m.operation, operation: m.operation.slice(9) };state.requests.push(structuredClone(m));let result: any;let rejected = false;
          if (m.operation === 'bundle-history-requests') result = { profile: 'nockapp-selected-authorship-requests-v4', entries: state.historyRequests, next_after: state.historyRequests.length, more: false };
          else if (m.operation === 'bundle-history-request') {
            if (!state.historyRequests.length) state.historyRequests.push({ request: history.request, request_sha256: history.response.request_sha256, challenge_checked_at: null });
            result = history.request;
          } else if (m.operation === 'bundle-history-prove') result = history.response;
          else if (m.operation === 'bundle-history-verify') {
            result = state.historyVerified ? history.recovered_receipt : history.receipt;state.historyVerified = true;
          } else if (m.operation === 'bundle-capabilities') {
            result = structuredClone(f.capabilities);if (options.oldProtocol) { result.identity.protocol = 3;result.identity.profile = 'nockapp-bundle-service-identity-v3'; }
          } else if (m.operation === 'bundle-initialize-identity') result = { profile: 'nockapp-protected-authorship-desktop-v4', state: 'ready', protocol: 4, pending_post: false, wallet_bound: false };
          else if (m.operation === 'bundle-outbox') result = { entries: state.rows.map(r => ({ ...r, status: r.status.state === 'finalized'
            ? { state: 'recoverable', checked_at: 1793494800, recovery_action: 'refresh-independent-verification', last_known: { state: 'finalized', checked_at: 1793494800, post_number: r.status.post_number, transaction_hash: r.status.transaction_hash }, ...flags } : r.status })),
            next_after: state.rows.length, more: false, experimental: true };
          else if (m.operation === 'bundle-threads' || m.operation === 'bundle-thread') {
            result = structuredClone(options.evidenceMissing ? f.evidence_unavailable_page : options.contentMissing ? f.content_unavailable_page : m.operation === 'bundle-thread' ? f.thread : f.page);
            if (options.invalid) result.secret = 'PRIVATE-MARKER';rejected = state.failRead;
          } else if (m.operation === 'bundle-numbers') { result = structuredClone(f.numbers);result.posts = m.body.numbers.map((n: number) => f.numbers.posts.find((p: any) => p.post_number === String(n))); }
          else if (m.operation === 'bundle-publish' || m.operation === 'bundle-recover') {
            let row = state.rows.find(r => r.post.id === (m.body.post?.id ?? m.body.post_id));
            if (!row) { row = { post: m.body.post, selection: m.body.selection, phase: m.body.selection.address ? 'wallet-needed' : 'submitted', submission_id: 'ef'.repeat(32), renewal_count: 0, experimental: true,
              status: { state: m.body.selection.address ? 'recoverable' : 'pending', checked_at: 1793494800, ...flags, ...(m.body.selection.address ? { recovery_action: 'sign-with-wallet' } : { transaction_hash: '0x' + '66'.repeat(32), post_number: null }) } };state.rows.push(row); }
            else row.status = { state: 'finalized', checked_at: 1793494800, transaction_hash: '0x' + '66'.repeat(32), post_number: '3', authorship_checked: true,
              address_evidence_checked: row.selection.address, credential_evidence_checked: row.selection.followers_threshold !== null };
            if (options.expired) row.status = { state: 'recoverable', checked_at: 1793494800, ...flags, recovery_action: 'renew-expired-authorization' };
            result = structuredClone(row);if (options.tamper) result.post.body = 'PRIVATE-MARKER';
            if (options.lost) { options.lost = false;rejected = true; }
          } else if (m.operation === 'bundle-renew') {
            const row = state.rows.find(r => r.post.id === m.body.post_id);row.submission_id = 'de'.repeat(32);row.renewal_count++;
            row.status = { state: 'pending', checked_at: 1793494800, transaction_hash: '0x' + '66'.repeat(32), ...flags };result = structuredClone(row);options.expired = false;
          } else if (m.operation === 'count-status') result = { state: 'empty', credential_saved: false, laboratory: true, verified: false };
          else if (m.operation === 'count-begin' || m.operation === 'count-recover') result = { state: 'pending', credential_saved: false, laboratory: true, verified: false,
            username: 'synthetic_user', post_text: options.malformedCount ? 'PRIVATE-MARKER' : 'testing:' + 'ab'.repeat(32), expires_at: Math.floor(Date.now() / 1000) + 600 };
          else if (m.operation === 'bundle-clear-cache') result = { cleared_bundles: 1, remote_records_deleted: false, drafts_deleted: false, experimental: true };
          else if (m.operation === 'bundle-export-public') result = { profile: 'nockapp-public-bundle-archive-v1', scope: { chain_id: 84532, contract: f.capabilities.identity.contract, application: f.capabilities.identity.application },
            record: { post_number: String(m.body.post_number), bundle_hash: '0x' + '22'.repeat(32), bundle_base64: 'e30=' }, experimental: true };
          else throw new Error('Unexpected native operation: ' + m.operation);
          const deliver = () => queueMicrotask(() => listeners.forEach(fn => fn(rejected ? { profile: m.profile, id: m.id, status: 'rejected', code: 'native-operation-unavailable', recoverable: true, laboratory: true, verified: false }
            : { profile: m.profile, id: m.id, status: 'ok', result, laboratory: true, verified: false })));
          if (options.hold && m.operation === 'bundle-threads') Object.assign(globalThis, { releaseAuthoredHistory: deliver });else deliver();
        } };
    }) as unknown as typeof chrome.runtime.connectNative;
  }, { f: options.history ? history.public_read : contract, options, history });
}
async function open(panel: Page) { await panel.getByRole('button', { name: 'Shared · Base Sepolia' }).click(); }
async function compose(panel: Page) {
  await panel.getByRole('button', { name: 'Start shared thread' }).click();await panel.getByLabel('Thread title', { exact: true }).fill('New authored post');
  await panel.getByLabel('Opening comment', { exact: true }).fill('Only this exact new content');
}
const requests = (worker: Worker) => worker.evaluate(() => (globalThis as any).authoredFixture.requests as { operation: string; body: any }[]);

test('main shared view defaults to v4, ordinary posts use private authorship with both disclosures off', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await expect(panel.getByRole('button', { name: 'Private authorship · v4' })).toHaveAttribute('aria-pressed', 'true');
  await expect(panel.getByText('Test proof · private authorship checked', { exact: false })).toHaveCount(2);
  await compose(panel);await panel.getByText('Optional public disclosures', { exact: true }).click();
  for (const name of ['Show my Base address, authorized with MetaMask', 'Prove followers greater than a threshold']) await expect(panel.getByLabel(name)).not.toBeChecked();
  await panel.getByRole('button', { name: 'Publish anonymous thread', exact: true }).click();
  await expect(panel.getByRole('region', { name: 'Shared submission outbox' }).getByText('pending', { exact: true })).toBeVisible();
  const sent = (await requests(worker)).filter(r => r.operation === 'bundle-publish');expect(sent).toHaveLength(1);expect(sent[0].body.selection).toEqual({ address: false, followers_threshold: null });
  expect((await requests(worker)).some(r => r.operation.startsWith('count-') || r.operation.includes('address-'))).toBe(false);
  await expect(panel.getByLabel('Opening comment', { exact: true })).toHaveValue('');
  const keys = await worker.evaluate(async () => Object.keys(await chrome.storage.local.get(null)));
  expect(keys).toContain('nockapp:authored:submission-intents:v4');expect(keys).not.toContain('nockapp:bundle:submission-intents:v3');
});

test('address and strict follower threshold are independent, reset after saving, and exact count is never offered', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await compose(panel);await panel.getByText('Optional public disclosures', { exact: true }).click();
  await panel.getByLabel('Prove followers greater than a threshold').check();await panel.getByLabel('Follower threshold', { exact: true }).fill('12345');
  await expect(panel.getByLabel('Show my Base address, authorized with MetaMask')).not.toBeChecked();await expect(panel.getByText('Publish my exact follower count', { exact: true })).toHaveCount(0);
  await panel.getByRole('button', { name: 'Publish anonymous thread', exact: true }).click();
  await expect(panel.getByRole('region', { name: 'Shared submission outbox' }).getByText('pending', { exact: true })).toBeVisible();
  expect((await requests(worker)).find(r => r.operation === 'bundle-publish')!.body.selection).toEqual({ address: false, followers_threshold: 12345 });
  await expect(panel.getByLabel('Prove followers greater than a threshold')).not.toBeChecked();
});

test('wallet choice saves the post before an explicit dedicated MetaMask screen is opened', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await compose(panel);await panel.getByText('Optional public disclosures', { exact: true }).click();
  await panel.getByLabel('Show my Base address, authorized with MetaMask').check();await panel.getByRole('button', { name: 'Publish anonymous thread', exact: true }).click();
  const authorize = panel.getByRole('button', { name: 'Authorize with MetaMask' });await expect(authorize).toBeVisible();
  expect(panel.context().pages().some(p => p.url().includes('/wallet-post.html'))).toBe(false);const promise = panel.context().waitForEvent('page');await authorize.click();const wallet = await promise;
  const sent = (await requests(worker)).find(r => r.operation === 'bundle-publish')!;
  await expect(wallet).toHaveURL(new RegExp(`/wallet-post.html#post=${sent.body.post.id}$`));expect(sent.body.selection).toEqual({ address: true, followers_threshold: null });await wallet.close();
});

test('lost reply and edited draft survive reload; recovery reuses exact intent without duplicating UUID', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { lost: true });await open(panel);await compose(panel);await panel.getByRole('button', { name: 'Publish anonymous thread', exact: true }).click();
  await expect(panel.getByRole('alert')).toBeVisible();await panel.getByLabel('Opening comment', { exact: true }).fill('Newer draft must stay');await panel.reload();
  await panel.getByRole('region', { name: 'Shared submission outbox' }).getByRole('button', { name: 'Recover submission' }).click();
  await expect(panel.getByRole('region', { name: 'Shared submission outbox' }).getByText('finalized · No.3', { exact: true })).toBeVisible();
  await panel.getByRole('button', { name: 'Start shared thread' }).click();await expect(panel.getByLabel('Opening comment', { exact: true })).toHaveValue('Newer draft must stay');
  const sent = (await requests(worker)).filter(r => r.operation === 'bundle-publish');expect(sent).toHaveLength(2);expect(sent[0].body).toEqual(sent[1].body);
});

for (const option of ['evidenceMissing', 'contentMissing', 'invalid', 'oldProtocol'] as const) test(`unverified ${option} never becomes an authorship, address or follower badge`, async ({ extension: { panel, worker } }) => {
  await fixture(worker, { [option]: true });await open(panel);
  if (option === 'invalid' || option === 'oldProtocol') await expect(panel.getByRole('alert')).toBeVisible();else await expect(panel.getByText('2 canonical entries', { exact: false })).toBeVisible();
  await expect(panel.getByText('Test proof · private authorship checked', { exact: false })).toHaveCount(0);
  await expect(panel.getByText('Test proof · address authorized', { exact: false })).toHaveCount(0);await expect(panel.getByText('Test proof · followers >', { exact: false })).toHaveCount(0);
  await expect(panel.getByText('PRIVATE-MARKER', { exact: false })).toHaveCount(0);
  expect((await requests(worker)).filter(r => r.operation === 'bundle-publish')).toHaveLength(0);
});

test('failed refresh keeps old content with stale claims and never silently displays cached verified badges', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await expect(panel.getByText('Test proof · private authorship checked', { exact: false })).toHaveCount(2);
  await worker.evaluate(() => { (globalThis as any).authoredFixture.failRead = true; });await panel.getByRole('button', { name: 'Refresh shared discussions' }).click();
  await expect(panel.getByRole('alert')).toBeVisible();await expect(panel.getByText('Last loaded entries are retained', { exact: false })).toBeVisible();
  await expect(panel.getByText('Test proof · private authorship checked', { exact: false })).toHaveCount(0);await expect(panel.getByText('Test proof · address authorized', { exact: false })).toHaveCount(0);
});

test('identity creation is explicit, count enrollment stays opt in, and privacy/key-loss limits are explained', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await expect(panel.getByRole('button', { name: 'Set up private signing identity' })).toBeEnabled();
  expect((await requests(worker)).some(r => r.operation === 'bundle-initialize-identity' || r.operation.startsWith('count-'))).toBe(false);
  await panel.getByRole('button', { name: 'Set up private signing identity' }).click();await expect(panel.getByRole('status')).toContainText('Private signing identity ready');
  expect((await requests(worker)).find(r => r.operation === 'bundle-initialize-identity')!.body).toEqual({ approve_private_key_setup: true });
  await panel.getByText('Authorship and key recovery', { exact: true }).click();await expect(panel.getByText('A replacement key does not inherit', { exact: false })).toBeVisible();
  await panel.getByRole('button', { name: 'Connect X for optional count proofs' }).click();await panel.getByRole('button', { name: 'Read saved credential status' }).click();
  await expect(panel.getByRole('region', { name: 'Count credential enrollment' }).getByRole('status')).toContainText('empty');
  expect((await requests(worker)).some(r => r.operation === 'count-begin')).toBe(false);
});

test('expired attempt requires separate fresh-proof consent and preserves original post intent', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { expired: true });await open(panel);await compose(panel);await panel.getByRole('button', { name: 'Publish anonymous thread', exact: true }).click();
  const box = panel.getByRole('region', { name: 'Shared submission outbox' });const renew = box.getByRole('button', { name: 'Create fresh proof after finalized expiry' });
  await expect(renew).toBeDisabled();await box.getByLabel('Allow a fresh public proof for this saved post').check();await renew.click();
  await expect(box.getByText('pending', { exact: true })).toBeVisible();const sent = await requests(worker);
  const before = sent.find(r => r.operation === 'bundle-publish')!;const after = sent.find(r => r.operation === 'bundle-renew')!;
  expect(after.body).toEqual({ post_id: before.body.post.id, expected_submission_id: 'ef'.repeat(32), approve_fresh_proof: true });
});

test('both optional disclosures can be selected without changing ordinary private author requirements', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await compose(panel);await panel.getByText('Optional public disclosures', { exact: true }).click();
  await panel.getByLabel('Show my Base address, authorized with MetaMask').check();await panel.getByLabel('Prove followers greater than a threshold').check();
  await panel.getByLabel('Follower threshold', { exact: true }).fill('0');await panel.getByRole('button', { name: 'Publish anonymous thread', exact: true }).click();
  await expect(panel.getByRole('button', { name: 'Authorize with MetaMask' })).toBeVisible();
  expect((await requests(worker)).find(r => r.operation === 'bundle-publish')!.body.selection).toEqual({ address: true, followers_threshold: 0 });
  await expect(panel.getByLabel('Show my Base address, authorized with MetaMask')).not.toBeChecked();await expect(panel.getByLabel('Prove followers greater than a threshold')).not.toBeChecked();
});

test('invalid strict thresholds preserve the draft and never reach native publication', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await compose(panel);await panel.getByText('Optional public disclosures', { exact: true }).click();await panel.getByLabel('Prove followers greater than a threshold').check();
  for (const value of ['-1', '1.5', '1e3', '9007199254740991']) {
    await panel.getByLabel('Follower threshold', { exact: true }).fill(value);await panel.getByRole('button', { name: 'Publish anonymous thread', exact: true }).click();
    await expect(panel.getByRole('alert')).toContainText('whole-number threshold');await expect(panel.getByLabel('Opening comment', { exact: true })).toHaveValue('Only this exact new content');
  }
  expect((await requests(worker)).some(r => r.operation === 'bundle-publish')).toBe(false);
});

test('a saved intent from another application is retained and cannot be silently republished in the current one', async ({ extension: { panel, worker } }) => {
  await fixture(worker);
  const old = { scope: { chain_id: 84532, contract: contract.capabilities.identity.contract, application: '0x' + '11'.repeat(32) },
    draft_key: `thread:authored:84532:${contract.capabilities.identity.contract}:all`, post: contract.page.posts[0].post,
    selection: { address: false, followers_threshold: null }, acknowledged: false, released: false };
  await worker.evaluate(async old => { await chrome.storage.local.set({ 'nockapp:authored:submission-intents:v4': [old] }); }, old);
  await open(panel);await expect(panel.getByRole('region', { name: 'Shared submission outbox' }).locator('article')).toHaveCount(0);
  await compose(panel);await panel.getByRole('button', { name: 'Publish anonymous thread', exact: true }).click();
  await expect(panel.getByRole('region', { name: 'Shared submission outbox' }).getByText('pending', { exact: true })).toBeVisible();
  const saved = await worker.evaluate(async () => (await chrome.storage.local.get('nockapp:authored:submission-intents:v4'))['nockapp:authored:submission-intents:v4']);
  expect(saved).toHaveLength(2);if (!Array.isArray(saved)) throw new Error('Saved intent list unavailable');expect(saved[0]).toEqual(old);
  const sent = (await requests(worker)).find(r => r.operation === 'bundle-publish')!;expect(sent.body.post.id).not.toBe(old.post.id);
});

test('opening a verified thread keeps comments flat and binds the new comment to that exact root', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await panel.getByRole('button', { name: 'Open shared thread No.1', exact: true }).click();
  await expect(panel.getByRole('form', { name: 'Write a shared comment' })).toBeVisible();
  await panel.getByLabel('Your comment', { exact: true }).fill('Flat comment >>1');await panel.getByRole('button', { name: 'Publish anonymous comment', exact: true }).click();
  await expect(panel.getByRole('region', { name: 'Shared submission outbox' }).getByText('pending', { exact: true })).toBeVisible();
  const sent = (await requests(worker)).find(r => r.operation === 'bundle-publish')!;
  expect(sent.body.post.kind).toBe('comment');expect(sent.body.post.thread_id).toBe(contract.thread.posts[0].post.id);expect(sent.body.post.title).toBeNull();expect(sent.body.post).not.toHaveProperty('parent_id');
  expect(sent.body.selection).toEqual({ address: false, followers_threshold: null });
});

test('source enrollment requires profile consent and displays only the saved public ownership challenge', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await panel.getByRole('button', { name: 'Connect X for optional count proofs' }).click();
  const enrollment = panel.getByRole('region', { name: 'Count credential enrollment' });await enrollment.getByLabel('X username').fill('synthetic_user');
  const begin = enrollment.getByRole('button', { name: 'Prepare public ownership post' });await expect(begin).toBeDisabled();
  await enrollment.getByLabel('Allow this public profile lookup').check();await begin.click();
  await expect(enrollment.getByText('testing:' + 'ab'.repeat(32), { exact: true })).toBeVisible();
  const sent = (await requests(worker)).find(r => r.operation === 'count-begin')!;expect(sent.body).toEqual({ username: 'synthetic_user', approve_public_profile_lookup: true });
  expect((sent as any).wire_operation).toBe('authored-count-begin');
  await expect(enrollment.getByText('approved enclave sees your X account', { exact: false })).toBeVisible();
});

test('main v4 navigation stays locked until its initial independent history response arrives', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { hold: true });await open(panel);await expect(panel.getByRole('button', { name: 'Start shared thread' })).toBeDisabled();
  await expect.poll(() => worker.evaluate(() => typeof (globalThis as any).releaseAuthoredHistory)).toBe('function');
  await worker.evaluate(() => { (globalThis as any).releaseAuthoredHistory(); });await expect(panel.getByRole('button', { name: 'Start shared thread' })).toBeEnabled();
});

test('main v4 stays within a narrow sidebar and archive exports use the v4 native namespace', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await expect(panel.getByRole('button', { name: 'Start shared thread' })).toBeEnabled();
  for (const width of [320, 390, 450]) { await panel.setViewportSize({ width, height: 844 });expect(await panel.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true); }
  await panel.getByText('Public history archive', { exact: true }).click();await panel.getByRole('button', { name: 'Prepare archive of loaded public posts' }).click();
  await expect(panel.getByRole('link', { name: 'Download public archive' })).toBeVisible();
  const sent = (await requests(worker)).filter(r => r.operation === 'bundle-export-public');expect(sent).toHaveLength(2);
  expect(sent.every((r: any) => r.wire_operation === 'authored-bundle-export-public')).toBe(true);
});

test('invalid trimmed post cannot poison durable intents; correcting it publishes the preserved draft', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await compose(panel);await panel.getByLabel('Thread title', { exact: true }).fill('   ');
  await panel.getByRole('button', { name: 'Publish anonymous thread', exact: true }).click();await expect(panel.getByRole('alert')).toContainText('draft cannot be signed');
  expect((await requests(worker)).some(r => r.operation === 'bundle-publish')).toBe(false);
  const saved = await worker.evaluate(async () => (await chrome.storage.local.get('nockapp:authored:submission-intents:v4'))['nockapp:authored:submission-intents:v4']);expect(saved).toBeUndefined();
  await expect(panel.getByLabel('Opening comment', { exact: true })).toHaveValue('Only this exact new content');
  await panel.getByLabel('Thread title', { exact: true }).fill('Corrected title');await panel.getByRole('button', { name: 'Publish anonymous thread', exact: true }).click();
  await expect(panel.getByRole('region', { name: 'Shared submission outbox' }).getByText('pending', { exact: true })).toBeVisible();
});


test('selected history needs explicit linking and independently checks the recipient-bound response file', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { history: true });await open(panel);await panel.getByRole('button', { name: 'Prove selected past posts', exact: true }).click();
  const region = panel.getByRole('region', { name: 'Selected past authorship' });
  await region.getByLabel('Post numbers to check').fill('1, 2');await region.getByRole('button', { name: 'Create 60-second verification request' }).click();
  await expect(region.getByRole('button', { name: 'Download verification request' })).toBeVisible();
  await region.getByLabel('Load verification request').setInputFiles({ name: 'request.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(history.request)) });
  const prove = region.getByRole('button', { name: 'Approve linking or recover saved response' });await expect(prove).toBeDisabled();
  expect((await requests(worker)).some(r => r.operation === 'bundle-history-prove')).toBe(false);
  await region.getByLabel('Allow this proof to link only these selected posts').check();await prove.click();
  const link = region.getByRole('link', { name: 'Download authorship response' });await expect(link).toBeVisible();
  const download = panel.waitForEvent('download');await link.click();const file = await download;
  const fs = await import('node:fs/promises');const value = JSON.parse(await fs.readFile((await file.path())!, 'utf8'));
  expect(value).toEqual(history.response);expect(value).not.toHaveProperty('private_key');
  await region.getByLabel('Check response for No.1, No.2').setInputFiles({ name: 'response.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(value)) });
  await expect(region.getByRole('status').filter({ hasText: 'Test proof' })).toContainText('Fresh challenge response checked');
  await region.getByLabel('Check response for No.1, No.2').setInputFiles({ name: 'response.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(value)) });
  await expect(region.getByRole('status').filter({ hasText: 'Test proof' })).toContainText('Earlier response rechecked; no fresh possession asserted');
  const sent = await requests(worker);expect(sent.find(r => r.operation === 'bundle-history-prove')!.body).toEqual({ request: history.request, approve_linking: true });
});

test('wrong-scope, private, oversized or unmatched history files reject before native proof work', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { history: true });await open(panel);await panel.getByRole('button', { name: 'Prove selected past posts', exact: true }).click();const region = panel.getByRole('region', { name: 'Selected past authorship' });
  for (const value of [{ ...history.request, private_key: 'PRIVATE-MARKER' }, { ...history.request, scope: { ...history.request.scope, contract: '0x' + '12'.repeat(20) } }]) {
    await region.getByLabel('Load verification request').setInputFiles({ name: 'bad.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(value)) });await expect(region.getByRole('alert')).toBeVisible();
  }
  await region.getByLabel('Load verification request').setInputFiles({ name: 'private.json', mimeType: 'application/json', buffer: Buffer.from('PRIVATE-MARKER not JSON') });await expect(region.getByRole('alert')).toContainText('Unsupported request file');
  await region.getByLabel('Load verification request').setInputFiles({ name: 'large.json', mimeType: 'application/json', buffer: Buffer.alloc(16385, ' ') });await expect(region.getByRole('alert')).toContainText('16 KiB');
  await expect(region.getByText('PRIVATE-MARKER', { exact: false })).toHaveCount(0);expect((await requests(worker)).some(r => ['bundle-history-prove', 'bundle-history-verify'].includes(r.operation))).toBe(false);
});

test('v4 enrollment preserves the challenge through pending recovery and rejects malformed public challenges', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await panel.getByRole('button', { name: 'Connect X for optional count proofs' }).click();const region = panel.getByRole('region', { name: 'Count credential enrollment' });
  await region.getByLabel('X username').fill('synthetic_user');await region.getByLabel('Allow this public profile lookup').check();await region.getByRole('button', { name: 'Prepare public ownership post' }).click();
  await region.getByRole('button', { name: 'Recover saved enrollment' }).click();await expect(region.getByText('testing:' + 'ab'.repeat(32), { exact: true })).toBeVisible();
  await fixture(worker, { malformedCount: true });await region.getByRole('button', { name: 'Recover saved enrollment' }).click();await expect(region.getByRole('alert')).toBeVisible();await expect(region.getByText('PRIVATE-MARKER', { exact: false })).toHaveCount(0);
});
