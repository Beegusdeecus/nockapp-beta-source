import { test as base, expect, chromium, type BrowserContext, type Page, type Worker } from '@playwright/test';
import { mkdtemp, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';

const test = base.extend<{ extension: { context: BrowserContext; page: Page; worker: Worker; id: string } }>({
  extension: async ({}, use) => {
    const profile = await mkdtemp(resolve(tmpdir(), 'nockapp-zkid-facts-ui-'));
    const context = await chromium.launchPersistentContext(profile, { channel: 'chromium', headless: true,
      args: [`--disable-extensions-except=${resolve('dist')}`, `--load-extension=${resolve('dist')}`, '--no-sandbox'] });
    try {
      const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');const id = new URL(worker.url()).host;
      const page = await context.newPage();await use({ context, page, worker, id });
    } finally { await context.close();await rm(profile, { recursive: true, force: true }); }
  },
});
async function helper(worker: Worker, options: { unavailable?: boolean; dropUseReply?: boolean; rejected?: boolean } = {}) {
  await worker.evaluate(options => {
    const state = { calls: [] as { operation: string; body: any }[], pending: undefined as any, receipts: new Map<string, any>(), drop: options.dropUseReply };
    Object.assign(globalThis, { zkidUiState: state });
    const fingerprint = (p: any) => JSON.stringify([p.kind, p.id, p.created_at, p.thread_id, p.title, p.body, p.references, p.claims]);
    const accepted = (nonce: string, facts: string[]) => {
      const now = Math.floor(Date.now() / 1000), start = Math.floor(now / 3600) * 3600;
      return { state: 'accepted', reference: { profile: 'nockapp-zkid-post-reference-v1', nonce, facts },
        observed_at: start, expires_at: start + 86400, checked_at: now, archival_only: true, laboratory: true, verified: false };
    };
    chrome.runtime.connectNative = (() => {
      if (options.unavailable) throw new Error('synthetic unavailable');
      const messages = new Set<(v: any) => void>(), disconnects = new Set<() => void>();let closed = false;
      return { onMessage: { addListener: (f: any) => messages.add(f), removeListener: (f: any) => messages.delete(f) },
        onDisconnect: { addListener: (f: any) => disconnects.add(f), removeListener: (f: any) => disconnects.delete(f) },
        disconnect: () => { closed = true; }, postMessage: (m: any) => {
          state.calls.push({ operation: m.operation, body: m.body });
          queueMicrotask(() => {
            const b = m.body;let result: any;
            if (m.operation === 'post-capabilities') result = { configured: true, profile: 'nockapp-zkid-post-reference-v1', identity_disclosed: false, laboratory: true, verified: false };
            else if (m.operation === 'post-available') { const now = Math.floor(Date.now() / 1000), start = Math.floor(now / 3600) * 3600;
              result = { facts: ['account-controlled', 'followers-at-least-10000'], observed_at: start, expires_at: start + 86400, availability_only: true, laboratory: true, verified: false }; }
            else if (m.operation === 'post-status') result = state.pending ? { ...state.pending, laboratory: true, verified: false } : { state: 'empty', laboratory: true, verified: false };
            else if (m.operation === 'post-use' && !options.rejected) {
              if (!state.pending || fingerprint(state.pending.post) === fingerprint(b.post)) {
                const nonce = state.pending?.nonce ?? crypto.randomUUID().replaceAll('-', '') + 'ab'.repeat(16);
                state.pending = { state: 'accepted', post: b.post, facts: b.facts, nonce };
                state.receipts.set(nonce, { post: b.post, facts: b.facts });result = accepted(nonce, b.facts);
                if (state.drop) { state.drop = false;for (const f of disconnects) f();return; }
              }
            } else if (m.operation === 'post-recover' || m.operation === 'post-retry') {
              if (state.pending) result = accepted(state.pending.nonce, state.pending.facts);
            } else if (m.operation === 'post-inspect') {
              const r = state.receipts.get(b.nonce);
              if (r && fingerprint(r.post) === fingerprint(b.post) && JSON.stringify(r.facts) === JSON.stringify(b.facts)) result = accepted(b.nonce, b.facts);
            } else if (m.operation === 'post-complete') { state.pending = undefined;result = { state: 'completed', laboratory: true, verified: false }; }
            else if (m.operation === 'post-discard') { state.pending = undefined;result = { state: 'discarded', remote_revocation: false, laboratory: true, verified: false }; }
            if (m.operation === 'post-status' && state.pending) { result = { ...state.pending, laboratory: true, verified: false };delete result.nonce; }
            const reply = result ? { profile: m.profile, id: m.id, status: 'ok', result, laboratory: true, verified: false }
              : { profile: m.profile, id: m.id, status: 'rejected', code: 'native-operation-unavailable', recoverable: true, laboratory: true, verified: false };
            if (!closed) for (const f of messages) f(reply);
          });
        } };
    }) as unknown as typeof chrome.runtime.connectNative;
  }, options);
}
async function composer(page: Page, id: string) {
  await page.goto(`chrome-extension://${id}/legacy.html`);
  await page.getByRole('button', { name: 'Explore demo discussion' }).click();
  await page.locator('.thread-result').first().click();
  return page.getByRole('form', { name: 'Write a comment' });
}

test('new facts are default-off, anonymous posting makes no new native call, unavailable helper preserves drafts', async ({ extension }) => {
  const { page, worker, id } = extension;await helper(worker, { unavailable: true });const form = await composer(page, id);
  await form.locator('textarea').fill('Ordinary anonymous comment');
  await form.getByRole('button', { name: 'Post anonymous comment' }).click();
  await expect(page.locator('.comment').last()).toContainText('Ordinary anonymous comment');
  expect(await worker.evaluate(() => Reflect.get(globalThis, 'zkidUiState').calls)).toEqual([]);
  await form.locator('textarea').fill('Keep this private draft');await form.locator('.zkid-facts summary').click();
  expect(await form.locator('.zkid-facts input:checked').count()).toBe(0);
  await form.getByRole('button', { name: 'Check public-post credential facts' }).click();
  await expect(form).toContainText('No public-post credential is available');
  await expect(form.locator('textarea')).toHaveValue('Keep this private draft');
  expect(await worker.evaluate(() => chrome.permissions.contains({ origins: ['https://x.com/*'] }))).toBe(false);
});

test('actual built panel posts joint synthetic references, rechecks Test badges and clears selections after success', async ({ extension }) => {
  const { page, worker, id } = extension;await helper(worker);const form = await composer(page, id);
  await form.locator('textarea').fill('New public-post fact comment');await form.locator('.zkid-facts summary').click();
  await form.getByRole('button', { name: 'Check public-post credential facts' }).click();
  await form.locator('.zkid-facts').getByLabel('X account control', { exact: true }).check();
  await form.locator('.zkid-facts').getByLabel('At least 10,000 followers', { exact: true }).check();
  await form.getByRole('button', { name: 'Post anonymous comment' }).click();
  const comment = page.locator('.comment').last();await expect(comment).toContainText('New public-post fact comment');
  await expect(comment.locator('.zkid-badge')).toHaveCount(2);await expect(comment).toContainText('Test · At least 10,000 followers');
  await expect(comment.locator('.author')).toHaveText('Anonymous');expect(await form.locator('.zkid-facts input:checked').count()).toBe(0);
  const stored = await worker.evaluate(async () => (await chrome.storage.local.get('nockapp:forum:v1'))['nockapp:forum:v1'] as { comments: any[] });
  const saved = stored.comments.find((p: any) => p.body === 'New public-post fact comment');expect(saved.author.zkid.facts).toHaveLength(2);
  expect(JSON.stringify(saved.author)).not.toMatch(/proof|verified|holder|certificate|expiry/);
  await worker.evaluate(async (postId) => {
    const key = 'nockapp:forum:v1', d = (await chrome.storage.local.get(key))[key] as { comments: any[] };d.comments.find((p: any) => p.id === postId).body = 'Edited after consent';await chrome.storage.local.set({ [key]: d });
  }, saved.id);
  await expect(page.locator(`[data-testid="${saved.id}"] .zkid-badge`).first()).toHaveText('Public-post fact unavailable');
});

test('lost native reply keeps exact saved intent and recovery publishes once without overwriting edited draft', async ({ extension }) => {
  const { page, worker, id } = extension;await helper(worker, { dropUseReply: true });const form = await composer(page, id);
  await form.locator('textarea').fill('Original saved consent');await form.locator('.zkid-facts summary').click();
  await form.getByRole('button', { name: 'Check public-post credential facts' }).click();await form.locator('.zkid-facts').getByLabel('X account control', { exact: true }).check();
  await form.getByRole('button', { name: 'Post anonymous comment' }).click();await expect(form.getByRole('alert')).toContainText('preserved');
  await form.locator('textarea').fill('Newer edits must remain');
  const recovery = page.locator('.zkid-recovery');await recovery.locator('summary').click();
  await recovery.getByRole('button', { name: 'Check saved post publication' }).click();
  await expect(recovery.getByRole('blockquote')).toHaveText('Original saved consent');
  await expect(recovery.getByRole('button', { name: 'Recover and publish saved post' })).toBeDisabled();
  await recovery.getByLabel('I approve these saved facts and publishing this exact saved post without disclosing my identity.').check();
  await recovery.getByRole('button', { name: 'Recover and publish saved post' }).click();
  await expect(recovery).toContainText('original post is saved once');await expect(form.locator('textarea')).toHaveValue('Newer edits must remain');
  expect(await page.locator('.comment').filter({ hasText: 'Original saved consent' }).count()).toBe(1);
  const calls = await worker.evaluate(() => Reflect.get(globalThis, 'zkidUiState').calls);
  expect(calls.filter((v: any) => v.operation === 'post-use')).toHaveLength(1);expect(calls.some((v: any) => v.operation === 'post-recover')).toBe(true);
});

test('wrong extension page cannot reach new post adapter or native helper', async ({ extension }) => {
  const { page, worker, id } = extension;await helper(worker);
  await page.goto(`chrome-extension://${id}/public-post.html`);
  await page.evaluate(() => { const p = chrome.runtime.connect({ name: 'zkid-post-facts' });p.postMessage({ version: 'zkid-post-facts-1', operation: 'post-status', body: {} });setTimeout(() => p.disconnect(), 10); });
  await page.waitForTimeout(100);expect(await worker.evaluate(() => Reflect.get(globalThis, 'zkidUiState').calls)).toEqual([]);
});
