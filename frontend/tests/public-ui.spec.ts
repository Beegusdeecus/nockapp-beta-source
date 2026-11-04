import { test as base, expect, chromium, type Page, type Worker } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
const vectors = JSON.parse(readFileSync(new URL('./fixtures/public-page-contract-v6-20261101-v2.json', import.meta.url), 'utf8'));
const test = base.extend<{ extension: { panel: Page; worker: Worker } }>({
  extension: async ({}, use) => {
    const profile = await mkdtemp(resolve(tmpdir(), 'nockapp-public-v6-ui-'));const path = resolve('dist');
    const context = await chromium.launchPersistentContext(profile, { channel: 'chromium', headless: true, viewport: { width: 390, height: 844 },
      args: [`--disable-extensions-except=${path}`, `--load-extension=${path}`, '--no-sandbox'] });
    try {
      const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');const panel = await context.newPage();
      await panel.goto(`chrome-extension://${new URL(worker.url()).host}/sidepanel.html`);await expect(panel.getByRole('button', { name: 'Explore demo discussion' })).toBeVisible();
      await use({ panel, worker });
    } finally { await context.close();await rm(profile, { recursive: true, force: true }); }
  },
});
// UI/transport fixtures only: these mutations do not synthesize real proofs.
async function fixture(worker: Worker, options: { lost?: boolean; junk?: boolean; emptyIdentity?: boolean; legacy?: boolean; legacyKind?: 'author-v4' | 'domain-v1'; failIdentitySetup?: boolean; badRead?: boolean; direct?: boolean; renewal?: boolean; lostSource?: boolean; failIdentityOptions?: boolean; failOutbox?: boolean } = {}) {
  await worker.evaluate(({ vectors, options }) => {
    const get = (op: string) => structuredClone(vectors.vectors.find((v: any) => v.operation === op).result);
    const template = get('public-numbers');const initial = template.posts[0];
    const state = { requests: [] as any[], entries: [] as any[], records: [initial] as any[], lost: !!options.lost,
      failRead: !!options.badRead, identity: !options.emptyIdentity, legacy: !!options.legacy,
      sourcePending:false,sourceSaved:false,lostSource:!!options.lostSource };
    if (options.junk) for (let n = 2; n <= 6; n++) state.records.push({ ...Object.fromEntries(Object.entries(initial).filter(([k]) =>
      ['bundle_hash', 'indexed_at', 'block_number', 'block_hash', 'transaction_hash', 'canonical_indexed'].includes(k))),
      post_number: String(n), state: 'content-unavailable', proofs_verified: false });
    Object.assign(globalThis, { publicFixture: state });
    chrome.runtime.connectNative = (() => {
      const listeners = new Set<(v: unknown) => void>();const lostListeners = new Set<() => void>();
      return { onMessage: { addListener: (f: (v: unknown) => void) => listeners.add(f), removeListener: (f: (v: unknown) => void) => listeners.delete(f) },
        onDisconnect: { addListener: (f: () => void) => lostListeners.add(f), removeListener: (f: () => void) => lostListeners.delete(f) }, disconnect: () => {}, postMessage: (m: any) => {
          if (!m.operation.startsWith('public-')) { for (const f of listeners) f({ profile: m.profile, id: m.id, status: 'rejected', code: 'native-operation-unavailable', recoverable: true, laboratory: true, verified: false });return; }
          state.requests.push(structuredClone(m));let result: any;let reject = false;const now = Math.floor(Date.now() / 1000);
          if (m.operation === 'public-capabilities') {
            result = get(m.operation);
            if (options.direct) Object.assign(result,{verifier_release:8,publication_mode:'direct',anonymous_ticket_packs:false,historical_issuer_views:false,follower_proof_configured:false});
            if (options.renewal) Object.assign(result,{verifier_release:9,publication_mode:options.direct?'direct':'tickets',
              anonymous_ticket_packs:!options.direct,historical_issuer_views:true,follower_proof_configured:true,
              source_enrollment_configured:true,refund_payout_configured:false});
          }
          else if(m.operation==='public-source-status')result={profile:'nockapp-public-source-status-v1',credential_record_present:state.sourceSaved,renewal_pending:state.sourcePending};
          else if(['public-source-begin','public-source-recover','public-source-check-post','public-source-cancel'].includes(m.operation)) {
            if(m.operation==='public-source-begin')state.sourcePending=true;
            if(m.operation==='public-source-check-post'){state.sourcePending=false;state.sourceSaved=true;}
            if(m.operation==='public-source-cancel')state.sourcePending=false;
            result={profile:'nockapp-renewal-enrollment-v3',state:m.operation==='public-source-cancel'?'cancelled':state.sourceSaved?'credential-saved':state.sourcePending?'waiting-for-source-post':'empty',
              credential_saved:state.sourceSaved&&m.operation!=='public-source-cancel',post_text:state.sourcePending?'testing:'+'ab'.repeat(32):null};
            if(m.operation==='public-source-begin'&&state.lostSource){state.lostSource=false;for(const f of lostListeners)f();return;}
          }
          else if (m.operation === 'public-identity-options') { reject = !!options.failIdentityOptions;result = { identity_record_present: state.identity, sources: state.legacy ? [{ source_id: '34'.repeat(32), kind: options.legacyKind ?? 'author-v4', identity_record_present: true, pending_recovery: false }] : [] }; }
          else if (['public-initialize-identity', 'public-adopt-identity'].includes(m.operation)) { reject = !!options.failIdentitySetup;if (!reject) state.identity = true;result = get('public-initialize-identity'); }
          else if (m.operation === 'public-ticket-status') result = vectors.vectors.filter((v: any) => v.operation === m.operation).at(-1).result;
          else if (m.operation === 'public-outbox') { reject = !!options.failOutbox;result = { entries: state.entries.slice(m.body.after, m.body.after + m.body.limit).map(r => ({ ...r, verification_current: false })),
            next_after: m.body.after + m.body.limit < state.entries.length ? m.body.after + m.body.limit : null }; }
          else if (m.operation === 'public-page' || m.operation === 'public-numbers') {
            if (state.failRead) reject = true;
            const numbers = m.operation === 'public-page' ? state.records.filter(r => Number(r.post_number) > m.body.after).slice(0, m.body.limit).map(r => Number(r.post_number)) : m.body.numbers;
            result = { ...template, posts: numbers.map((n: number) => state.records.find(r => r.post_number === String(n)) ?? { post_number: String(n), state: 'unassigned', canonical_indexed: false, proofs_verified: false }),
              requested_numbers: numbers.map(String), next_number: String(state.records.length + 1), checked_records: numbers.filter((n: number) => n <= state.records.length).length };
            if (m.operation === 'public-page') Object.assign(result, { after: m.body.after, next_after: m.body.after + numbers.length, more: m.body.after + numbers.length < state.records.length });
          } else if (m.operation === 'public-prepare') {
            result = state.entries.find(r => r.core.post.id === m.body.post.id);
            if (!result) {
              result = get('public-prepare');Object.assign(result.core, { post: m.body.post, selection: m.body.selection, thread: m.body.thread, references: m.body.references ?? [] });
              result.phase = m.body.selection.address ? 'wallet-needed' : m.body.selection.followers_threshold === null ? 'prepared' : 'proofs-needed';
              state.entries.push(result);
            }
          } else if (m.operation === 'public-attach-followers') reject = true;
          else if (m.operation === 'public-attach-history') result = state.entries.find(r => r.core.post.id === m.body.post_id);
          else if (['public-finish', 'public-publish', 'public-check'].includes(m.operation)) {
            result = state.entries.find(r => r.core.post.id === m.body.post_id);
            if (!result) reject = true;
            else {
              result.bundle_hash ??= '0x' + '45'.repeat(32);if (result.phase !== 'submitted') result.phase = 'bundle-saved';
              if (m.operation === 'public-publish') {
                let existing = state.records.find(r => r.post?.id === result.core.post.id);
                if (!existing) { existing = { ...structuredClone(initial), post: result.core.post, thread: result.core.thread,
                  bundle_hash: result.bundle_hash, post_number: String(state.records.length + 1), indexed_at: Math.max(now, result.core.post.created_at) };state.records.push(existing); }
                result.phase = 'submitted';result.last_attempt = { requested_at: now, transaction_hash: '0x' + '56'.repeat(32) };
                result.last_known = { state: 'finalized', post_number: existing.post_number, checked_at: now };result.verification_current = true;
                if (state.lost) { state.lost = false;for (const f of lostListeners) f();return; }
              } else if (m.operation === 'public-check') result.verification_current = true;
            }
          } else reject = true;
          const reply = reject ? { profile: m.profile, id: m.id, status: 'rejected', code: 'native-operation-unavailable', recoverable: true, laboratory: true, verified: false }
            : { profile: m.profile, id: m.id, status: 'ok', result: structuredClone(result), laboratory: true, verified: false };
          for (const f of listeners) f(reply);
        } };
    }) as unknown as typeof chrome.runtime.connectNative;
  }, { vectors, options });
}
async function open(panel: Page) { await panel.getByRole('button', { name: 'Shared · Base Sepolia' }).click();await panel.getByRole('button', { name: 'Public · permissionless v5', exact: true }).click();await expect(panel.getByRole('button', { name: 'Start public thread', exact: true })).toBeVisible(); }
async function compose(panel: Page) { await panel.getByRole('button', { name: 'Start public thread', exact: true }).click();await panel.getByLabel('Thread title', { exact: true }).fill('Public new post');await panel.getByLabel('Opening comment', { exact: true }).fill('Exact new public text'); }
const requests = (worker: Worker) => worker.evaluate(() => (globalThis as any).publicFixture.requests as { operation: string; body: any }[]);

test('public candidate publishes ordinary authored text with separate default-off disclosures and durable intents', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await compose(panel);await panel.getByText('Optional public disclosures', { exact: true }).click();
  for (const label of ['Show my Ethereum address, authorized with MetaMask', 'Prove followers greater than a threshold']) await expect(panel.getByLabel(label)).not.toBeChecked();
  await panel.getByRole('button', { name: 'Publish anonymous public thread', exact: true }).click();
  await expect(panel.getByRole('status')).toContainText('Public post No.2 independently checked');
  const sent = await requests(worker);expect(sent.filter(r => r.operation === 'public-publish')).toHaveLength(1);
  expect(sent.find(r => r.operation === 'public-prepare')?.body.selection).toEqual({ address: false, followers_threshold: null });
  expect(sent.some(r => r.operation === 'public-ticket-status')).toBe(false);
  await expect(panel.getByLabel('Opening comment', { exact: true })).toHaveValue('');
  const saved = await worker.evaluate(async () => (await chrome.storage.local.get('nockapp:public:submission-intents:v5'))['nockapp:public:submission-intents:v5'] as { acknowledged: boolean; released: boolean }[]);
  expect(saved).toHaveLength(1);expect(saved[0].acknowledged).toBe(true);expect(saved[0].released).toBe(true);
});
test('missing optional follower evidence does not block authored publication or invent a badge', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await compose(panel);await panel.getByText('Optional public disclosures', { exact: true }).click();
  await panel.getByLabel('Prove followers greater than a threshold').check();await panel.getByLabel('Follower threshold', { exact: true }).fill('12');
  await panel.getByRole('button', { name: 'Publish anonymous public thread', exact: true }).click();await expect(panel.getByRole('status')).toContainText('No.2');
  const sent = await requests(worker);expect(sent.filter(r => r.operation === 'public-attach-followers')).toHaveLength(1);expect(sent.filter(r => r.operation === 'public-publish')).toHaveLength(1);
  await panel.getByRole('button', { name: 'Refresh current public page' }).click();await expect(panel.getByRole('region', { name: 'Loaded public records' })).toContainText('Exact new public text');
  await expect(panel.getByText('Test · Followers greater than', { exact: false })).toHaveCount(0);
});
test('address choice saves an exact post and waits for authorization without silently publishing it', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await compose(panel);await panel.getByText('Optional public disclosures', { exact: true }).click();await panel.getByLabel('Show my Ethereum address, authorized with MetaMask').check();
  await panel.getByRole('button', { name: 'Publish anonymous public thread', exact: true }).click();await expect(panel.getByRole('status')).toContainText('Post saved');
  const sent = await requests(worker);expect(sent.filter(r => r.operation === 'public-prepare')).toHaveLength(1);expect(sent.some(r => ['public-publish', 'public-finish'].includes(r.operation))).toBe(false);
  await expect(panel.getByRole('region', { name: 'Public submission outbox' })).toContainText('wallet-needed');
  const opened=panel.context().waitForEvent('page');await panel.getByRole('button',{name:'Authorize saved public post',exact:true}).click();
  const wallet=await opened;await expect(wallet).toHaveURL(new RegExp(`/public-wallet.html#post=${sent.find(r=>r.operation==='public-prepare')!.body.post.id}$`));await wallet.close();
});
test('lost publication reply preserves edits and recovers the same saved post after reload', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { lost: true });await open(panel);await compose(panel);await panel.getByRole('button', { name: 'Publish anonymous public thread', exact: true }).click();
  await expect(panel.getByRole('alert')).toContainText('saved');await panel.getByLabel('Opening comment', { exact: true }).fill('Newer private draft');
  await panel.reload();await expect(panel.getByRole('button', { name: 'Public · permissionless v5' })).toHaveAttribute('aria-pressed', 'true');
  await panel.getByRole('button', { name: 'Start public thread', exact: true }).click();await expect(panel.getByLabel('Opening comment', { exact: true })).toHaveValue('Newer private draft');
  await panel.getByRole('button', { name: 'Resume exact public post' }).click();await expect(panel.getByRole('status')).toContainText('No.2');
  const sent = await requests(worker);const attempts = sent.filter(r => r.operation === 'public-prepare');expect(new Set(attempts.map(r => r.body.post.id)).size).toBe(1);
  await expect(panel.getByLabel('Opening comment', { exact: true })).toHaveValue('Newer private draft');
  const count = await worker.evaluate(() => (globalThis as any).publicFixture.records.length);expect(count).toBe(2);
});
test('public paging is bounded and preserves unavailable canonical allocations', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { junk: true });await open(panel);
  const list = panel.getByRole('region', { name: 'Loaded public records' });await expect(list.getByRole('button', { name: 'Copy reference to post No.4' })).toBeVisible();
  await expect(list).toContainText('content-unavailable');await panel.getByRole('button', { name: 'Load next four public records' }).click();
  await expect(list.getByRole('button', { name: 'Copy reference to post No.6' })).toBeVisible();
  expect((await requests(worker)).filter(r => r.operation === 'public-page').map(r => r.body)).toEqual([{ after: 0, limit: 4 }, { after: 4, limit: 4 }]);
});
test('failed independent refresh retains content but removes current badge claims', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await expect(panel.getByText('Test proof · private authorship checked', { exact: false })).toBeVisible();
  await worker.evaluate(() => { (globalThis as any).publicFixture.failRead = true; });await panel.getByRole('button', { name: 'Refresh current public page' }).click();
  await expect(panel.getByText('Test proof · private authorship checked', { exact: false })).toHaveCount(0);await expect(panel.getByRole('region', { name: 'Loaded public records' })).toContainText('Exact fixture text');
  await expect(panel.getByText('Last loaded content is retained.', { exact: false })).toBeVisible();
});
for (const failed of ['identity', 'outbox', 'both'] as const) test(`public reading survives unavailable local ${failed} checks`, async ({ extension: { panel, worker } }) => {
  await fixture(worker, { failIdentityOptions: failed !== 'outbox', failOutbox: failed !== 'identity' });await open(panel);
  const list = panel.getByRole('region', { name: 'Loaded public records' });
  await expect(list).toContainText('Exact fixture text');
  await expect(list.getByText('Test proof · private authorship checked', { exact: false })).toBeVisible();
  await expect(panel.getByRole('alert')).toContainText('unavailable');
  await expect(panel.getByText('Last loaded content is retained.', { exact: false })).toHaveCount(0);
  await panel.getByText('Private authorship setup and recovery', { exact: true }).click();
  if (failed !== 'outbox') {
    await expect(panel.getByText('Private authorship setup is unavailable. Reopen this view to retry. Public reading remains available.', { exact: true })).toBeVisible();
    await expect(panel.getByRole('button', { name: 'Create private authorship identity' })).toHaveCount(0);
    await expect(panel.getByRole('button', { name: 'Start public thread', exact: true })).toBeDisabled();
  } else await expect(panel.getByText('A protected authorship record is present.')).toBeVisible();
  await panel.getByRole('button', { name: 'Refresh current public page' }).click();
  await expect(list.getByText('Test proof · private authorship checked', { exact: false })).toBeVisible();
  const sent = await requests(worker);
  expect(sent.filter(r => r.operation === 'public-page')).toHaveLength(2);
  expect(sent.some(r => ['public-initialize-identity', 'public-adopt-identity', 'public-prepare', 'public-ticket-status'].includes(r.operation))).toBe(false);
});
test('failed initial public read still loads private setup without claiming verification', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { badRead: true });await open(panel);
  await expect(panel.getByRole('alert')).toBeVisible();
  await expect(panel.getByText('Test proof · private authorship checked', { exact: false })).toHaveCount(0);
  await panel.getByText('Private authorship setup and recovery', { exact: true }).click();
  await expect(panel.getByText('A protected authorship record is present.')).toBeVisible();
  const sent = await requests(worker);
  expect(sent.some(r => r.operation === 'public-outbox')).toBe(true);
  expect(sent.some(r => r.operation === 'public-initialize-identity')).toBe(false);
});
test('identity reuse is a separate explicit choice and public reading does not unlock tickets', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { emptyIdentity: true, legacy: true });await open(panel);await panel.getByText('Private authorship setup and recovery', { exact: true }).click();
  await expect(panel.getByText('An existing private key or saved recovery needs your attention.', { exact: false })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Create private authorship identity' })).toHaveCount(0);
  const reuse = panel.getByRole('button', { name: 'Reuse existing author-v4 key 1' });await expect(reuse).toBeDisabled();
  await panel.getByLabel('I approve reusing the selected existing private key').check();await reuse.click();await expect(panel.getByText('A protected authorship record is present.')).toBeVisible();
  const sent = await requests(worker);expect(sent.filter(r => r.operation === 'public-adopt-identity')).toHaveLength(1);expect(sent.some(r => ['public-initialize-identity', 'public-ticket-status'].includes(r.operation))).toBe(false);
});

test('existing domain key setup explains the blocked creation path and enables Twitter only after explicit reuse', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { emptyIdentity: true, legacy: true, legacyKind: 'domain-v1', renewal: true, direct: true });await open(panel);
  await panel.getByText('Optional Twitter follower credential', { exact: true }).click();
  await panel.getByLabel('Twitter username', { exact: true }).fill('synthetic_user');
  const consent = panel.getByLabel('I approve checking my Twitter profile and public verification challenge', { exact: true });
  await consent.check();const start = panel.getByRole('button', { name: 'Start Twitter verification', exact: true });
  await expect(start).toBeDisabled();
  await panel.getByText('Private authorship setup and recovery', { exact: true }).click();
  await expect(panel.getByRole('button', { name: 'Create private authorship identity' })).toHaveCount(0);
  const reuse = panel.getByRole('button', { name: 'Reuse existing domain-v1 key 1', exact: true });
  await expect(reuse).toBeDisabled();await panel.getByLabel('I approve reusing the selected existing private key').check();
  await reuse.click();await expect(panel.getByText('A protected authorship record is present.')).toBeVisible();
  await expect(start).toBeEnabled();
  const sent = await requests(worker);
  expect(sent.filter(r => r.operation === 'public-adopt-identity')).toHaveLength(1);
  expect(sent.some(r => r.operation === 'public-initialize-identity' || r.operation.startsWith('public-source-'))).toBe(false);
});

test('unconfirmed identity creation shows recovery guidance beside its button and does not retry', async ({ extension: { panel, worker } }) => {
  await fixture(worker, { emptyIdentity: true, failIdentitySetup: true });await open(panel);
  await panel.getByText('Private authorship setup and recovery', { exact: true }).click();
  const consent = panel.getByLabel('I approve creating a private authorship key on this computer');
  await consent.check();await panel.getByRole('button', { name: 'Create private authorship identity', exact: true }).click();
  await expect(panel.getByText('Setup was not confirmed.', { exact: false })).toBeVisible();
  await expect(consent).not.toBeChecked();
  await expect(panel.getByText('A protected authorship record is present.')).toHaveCount(0);
  expect((await requests(worker)).filter(r => r.operation === 'public-initialize-identity')).toHaveLength(1);
});

test('public comments are flat, bind the verified root and preserve hidden date and author identity rules', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await panel.getByRole('button', { name: 'Open public thread', exact: true }).click();
  await panel.getByLabel('Your comment', { exact: true }).fill('>>1 A flat public comment');await panel.getByRole('button', { name: 'Publish anonymous public comment', exact: true }).click();
  await expect(panel.getByRole('status')).toContainText('No.2');await panel.getByRole('button', { name: 'Refresh current public page' }).click();
  const list = panel.getByRole('region', { name: 'Loaded public records' });await expect(list).toContainText('A flat public comment');
  const prepare = (await requests(worker)).find(r => r.operation === 'public-prepare');expect(prepare?.body.post.kind).toBe('comment');
  expect(prepare?.body.thread).toMatchObject({ protocol: 5, number: '1' });expect(prepare?.body.post).not.toHaveProperty('parent_id');
  expect(prepare?.body.post).not.toHaveProperty('author_id');await expect(list.getByText('Test · Followers greater than', { exact: false })).toHaveCount(0);
  await expect(list.locator(':scope > article')).toHaveCount(2);
});
test('manual source edits load only on Enter and never fetch a Twitter account', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);
  const before = (await requests(worker)).length;await panel.getByRole('textbox', { name: 'Selected post', exact: true }).fill('https://x.com/i/status/1900000000000000001');
  expect((await requests(worker)).length).toBe(before);await panel.getByRole('textbox', { name: 'Selected post', exact: true }).press('Enter');
  await compose(panel);await panel.getByRole('button', { name: 'Publish anonymous public thread', exact: true }).click();await expect(panel.getByRole('status')).toContainText('No.2');
  const prepare = (await requests(worker)).find(r => r.operation === 'public-prepare');expect(prepare?.body.post.references).toEqual([['https://x.com/i/status/1900000000000000001', '1900000000000000001']]);
  expect((await requests(worker)).some(r => /source|count-begin|twitter/i.test(r.operation))).toBe(false);
});

test('a changed root at refresh retains old text but cannot preserve a fresh thread badge', async ({ extension: { panel, worker } }) => {
  await fixture(worker);await open(panel);await panel.getByRole('button', { name: 'Open public thread', exact: true }).click();
  await worker.evaluate(() => { (globalThis as any).publicFixture.records[0].bundle_hash = '0x' + '78'.repeat(32); });
  await panel.getByRole('button', { name: 'Refresh current public page' }).click();await expect(panel.getByRole('alert')).toContainText('thread root');
  const list = panel.getByRole('region', { name: 'Loaded public records' });await expect(list).toContainText('Exact fixture text');
  await expect(list.getByText('Test proof · private authorship checked', { exact: false })).toHaveCount(0);
});

// UI fixture only; actual proofs and installed-native integration are checked separately.
test('optional Twitter setup requires identity and fresh consent and does not enable public badges',async({extension:{panel,worker}})=>{
  await fixture(worker,{direct:true,renewal:true,emptyIdentity:true});await open(panel);
  await panel.getByText('Optional Twitter follower credential',{exact:true}).click();
  await expect(panel.getByRole('button',{name:'Start Twitter verification',exact:true})).toBeDisabled();
  expect((await requests(worker)).some(r=>r.operation.startsWith('public-source-'))).toBe(false);
  await panel.getByText('Private authorship setup and recovery',{exact:true}).click();
  await panel.getByLabel('I approve creating a private authorship key on this computer').check();
  await panel.getByRole('button',{name:'Create private authorship identity',exact:true}).click();
  await panel.getByLabel('Twitter username',{exact:true}).fill('@synthetic_user');
  const consent=panel.getByLabel('I approve checking my Twitter profile and public verification challenge',{exact:true});
  await expect(consent).not.toBeChecked();await consent.check();
  await panel.getByRole('button',{name:'Start Twitter verification',exact:true}).click();
  await expect(panel.getByLabel('Exact public verification challenge',{exact:true})).toHaveValue('testing:'+'ab'.repeat(32));
  await expect(consent).not.toBeChecked();
  await panel.getByLabel('Verification post URL or ID',{exact:true}).fill('https://x.com/synthetic_user/status/3141592653589793');
  const check=panel.getByRole('button',{name:'Check my public verification post',exact:true});await expect(check).toBeDisabled();
  await consent.check();await check.click();await expect(panel.getByRole('status')).toContainText('Follower credential saved');
  const sent=await requests(worker);
  expect(sent.find(r=>r.operation==='public-source-begin')?.body).toEqual({username:'synthetic_user',approve_source_check:true});
  expect(sent.find(r=>r.operation==='public-source-check-post')?.body).toEqual({tweet_id:'3141592653589793',approve_source_check:true});
  await compose(panel);await panel.getByText('Optional public disclosures',{exact:true}).click();
  await expect(panel.getByLabel('Show my Ethereum address, authorized with MetaMask')).not.toBeChecked();
  await expect(panel.getByLabel('Prove followers greater than a threshold')).not.toBeChecked();
});
test('lost Twitter signup reply requires explicit recovery and never automatically starts again',async({extension:{panel,worker}})=>{
  await fixture(worker,{renewal:true,lostSource:true});await open(panel);
  await panel.getByText('Optional Twitter follower credential',{exact:true}).click();
  await panel.getByLabel('Twitter username',{exact:true}).fill('synthetic_user');
  const consent=panel.getByLabel('I approve checking my Twitter profile and public verification challenge',{exact:true});
  await consent.check();await panel.getByRole('button',{name:'Start Twitter verification',exact:true}).click();
  await expect(panel.getByRole('alert')).toBeVisible();await expect(consent).not.toBeChecked();
  await expect(panel.getByText('Verification was not confirmed.',{exact:false})).toBeVisible();
  await expect(panel.getByRole('button',{name:'Start Twitter verification',exact:true})).toHaveCount(0);
  await expect(panel.getByLabel('Twitter username',{exact:true})).toHaveCount(0);
  await expect(panel.getByLabel('Verification post URL or ID',{exact:true})).toHaveCount(0);
  await expect(panel.getByText('Recover your saved verification. No username is needed.',{exact:false})).toBeVisible();
  expect((await requests(worker)).filter(r=>r.operation==='public-source-begin')).toHaveLength(1);
  await consent.check();await panel.getByRole('button',{name:'Recover saved Twitter verification',exact:true}).click();
  await expect(panel.getByLabel('Exact public verification challenge',{exact:true})).toHaveValue('testing:'+'ab'.repeat(32));
  await expect(panel.getByText('Verification was not confirmed.',{exact:false})).toHaveCount(0);
  const sent=await requests(worker);expect(sent.filter(r=>r.operation==='public-source-begin')).toHaveLength(1);
  expect(sent.filter(r=>r.operation==='public-source-recover')).toHaveLength(1);
});

test('direct mode saves exact default-off authored intent without ticket or publication service requests',async({extension:{panel,worker}})=>{
  await fixture(worker,{direct:true});await open(panel);
  await expect(panel.getByText('Direct-payment test:',{exact:false})).toBeVisible();
  await expect(panel.getByText('Prepaid publication tickets',{exact:true})).toHaveCount(0);
  await compose(panel);await panel.getByText('Optional public disclosures',{exact:true}).click();
  await expect(panel.getByLabel('Show my Ethereum address, authorized with MetaMask')).not.toBeChecked();
  await expect(panel.getByLabel('Prove followers greater than a threshold')).not.toBeChecked();
  await panel.getByRole('button',{name:'Save exact public post',exact:true}).click();
  await expect(panel.getByRole('status')).toContainText('Exact public post saved');
  const sent=await requests(worker);expect(sent.some(r=>r.operation.startsWith('public-ticket-')||r.operation==='public-publish')).toBe(false);
  expect(sent.find(r=>r.operation==='public-prepare')?.body.selection).toEqual({address:false,followers_threshold:null});
  await expect(panel.getByRole('button',{name:'Export public bundle',exact:true})).toBeVisible();
  const pay=panel.getByRole('button',{name:'Verify public upload and pay gas',exact:true});await expect(pay).toBeDisabled();
  await panel.getByLabel('I approve revealing the gas payer', {exact:false}).check();await expect(pay).toBeEnabled();
  await panel.getByRole('button',{name:'Resume exact public post',exact:true}).click();
  await expect(panel.getByRole('status')).toContainText('Exact public post saved');
  expect((await requests(worker)).some(r=>r.operation==='public-publish')).toBe(false);
});
