import { test as base, expect, chromium, type BrowserContext, type Page, type Worker } from '@playwright/test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { PUBLIC_POST_VERSION, PUBLIC_CHALLENGE } from '../src/publicPostFlow';

const test = base.extend<{ extension: { context: BrowserContext; page: Page; worker: Worker; id: string } }>({
  extension: async ({}, use) => {
    const profile = await mkdtemp(resolve(tmpdir(), 'nockapp-public-post-ui-'));
    const extension = resolve('dist');
    const context = await chromium.launchPersistentContext(profile, { channel: 'chromium', headless: true,
      viewport: { width: 390, height: 844 }, args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`, '--no-sandbox'] });
    try {
      const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
      const page = await context.newPage();const id = new URL(worker.url()).host;
      await use({ context, page, worker, id });
    } finally { await context.close();await rm(profile, { recursive: true, force: true }); }
  },
});

async function mockPage(page: Page, options: { expired?: boolean; beginRecovery?: boolean; wrongVersion?: boolean; waitForBegin?: boolean; silentGreeting?: boolean; discovery?: 'waiting' | 'failure' | 'saved' } = {}) {
  await page.addInitScript(({ version, prefix, expired, beginRecovery, wrongVersion, waitForBegin, silentGreeting, discovery }) => {
    const calls: unknown[] = [];Object.assign(window, { publicCalls: calls });
    const summary = { state: beginRecovery ? 'begin-recovery-required' : 'awaiting-post', credentialSaved: false,
      username: 'synthetic_user', ...(beginRecovery ? {} : { postText: prefix + 'ab'.repeat(32), expiresAt: Math.floor(Date.now() / 1000) + (expired ? -1 : 600) }) };
    let listener: (value: unknown) => void = () => {};
    Object.assign(window, { emitPublic: (value: unknown) => listener(value) });
    chrome.runtime.connect = (() => ({
      onMessage: { addListener: (fn: typeof listener) => { listener = fn;if (!silentGreeting) queueMicrotask(() => fn({ version: wrongVersion ? 'old' : version, state: 'ready', verified: false })); } },
      onDisconnect: { addListener: () => {} }, disconnect: () => {},
      postMessage: (value: { op: string }) => {
        calls.push(value);
        if (value.op === 'stop') { listener({ version, state: 'error', code: 'recovery-needed', verified: false });return; }
        listener({ version, state: 'busy', operation: value.op, verified: false });
        if (value.op === 'begin' && waitForBegin) return;
        if (value.op === 'poll-registration' && discovery === 'failure') { queueMicrotask(() => listener({ version, state: 'error', code: 'operation-unavailable', verified: false })); return; }
        queueMicrotask(() => listener({ version, state: 'result', verified: false,
          summary: value.op === 'poll-registration' ? discovery === 'waiting' ? { ...summary, nextCheckAt: Math.floor(Date.now() / 1000) + 30 } : { state: 'credential-saved', credentialSaved: true }
            : value.op === 'check-post' ? { state: 'credential-saved', credentialSaved: true }
            : value.op === 'cancel' ? { state: 'cancelled', credentialSaved: false }
            : value.op === 'forget' ? { state: 'forgotten', credentialSaved: false } : summary }));
      },
    })) as unknown as typeof chrome.runtime.connect;
  }, { version: PUBLIC_POST_VERSION, prefix: PUBLIC_CHALLENGE, ...options });
}

test('Connect X opens the new actual extension page and unavailable helper never requests X access', async ({ extension }) => {
  const { page, worker, context, id } = extension;
  await worker.evaluate(() => {
    Object.assign(globalThis, { publicNativeCalls: [] });
    chrome.runtime.connectNative = ((host: string) => { (Reflect.get(globalThis, 'publicNativeCalls') as string[]).push(host);throw new Error('synthetic unavailable'); }) as typeof chrome.runtime.connectNative;
  });
  await page.goto(`chrome-extension://${id}/legacy.html`);
  const opened = context.waitForEvent('page');await page.getByRole('button', { name: 'Connect X', exact: true }).click();
  const ui = await opened;await ui.waitForLoadState();expect(ui.url()).toBe(`chrome-extension://${id}/public-post.html`);
  await expect(ui.getByRole('heading', { name: 'Connect X with a public post' })).toBeVisible();
  await expect(ui.getByRole('button', { name: 'Create public challenge' })).toBeDisabled();
  expect(await worker.evaluate(() => Reflect.get(globalThis, 'publicNativeCalls'))).toEqual([]);
  await ui.getByRole('textbox', { name: 'X handle', exact: true }).fill('synthetic_user');
  await ui.getByRole('checkbox', { name: 'I approve looking up this public X profile through TwitterAPI.io.' }).check();
  await ui.getByRole('checkbox', { name: /I approve automatic checks/ }).check();
  await ui.getByRole('button', { name: 'Create public challenge' }).click();
  await expect(ui.getByRole('alert')).toContainText('helper is missing or disconnected');
  expect(await worker.evaluate(() => Reflect.get(globalThis, 'publicNativeCalls'))).toEqual(['com.nockapp.zkid']);
  expect(await worker.evaluate(() => chrome.permissions.contains({ origins: ['https://x.com/*'] }))).toBe(false);
  expect(await worker.evaluate(() => chrome.storage.local.get(null))).not.toHaveProperty('public-post');
});

test('public challenge has separate profile/post consent and completion stays a test notice', async ({ extension }) => {
  const { page, id } = extension;await mockPage(page);await page.goto(`chrome-extension://${id}/public-post.html`);
  await page.getByRole('textbox', { name: 'X handle', exact: true }).fill('synthetic_user');
  await page.getByRole('checkbox', { name: 'I approve looking up this public X profile through TwitterAPI.io.' }).check();
  await page.getByRole('checkbox', { name: /I approve automatic checks/ }).check();
  await page.getByRole('button', { name: 'Create public challenge' }).click();
  await expect(page.getByRole('textbox', { name: 'Challenge text', exact: true })).toHaveValue(PUBLIC_CHALLENGE + 'ab'.repeat(32));
  await expect(page.getByRole('button', { name: 'Create public challenge' })).toHaveCount(0);
  expect(await page.getByRole('textbox', { name: 'Challenge text', exact: true }).evaluate(element => {
    const style = getComputedStyle(element);
    const luminance = (color: string) => color.match(/[\d.]+/g)!.slice(0, 3).map(Number).map(v => {
      const s = v / 255; return s <= .04045 ? s / 12.92 : ((s + .055) / 1.055) ** 2.4;
    }).reduce((sum, v, i) => sum + v * [.2126, .7152, .0722][i], 0);
    const a = luminance(style.color); const b = luminance(style.backgroundColor);
    return (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
  })).toBeGreaterThanOrEqual(4.5);
  await expect(page.getByRole('link', { name: 'Open X to publish manually' })).toHaveAttribute('href', 'https://x.com/compose/post');
  await page.getByRole('button', { name: 'Stop waiting' }).click();
  await page.getByText('Manual post-link fallback', { exact: true }).click();
  await page.getByRole('textbox', { name: 'Public X post link' }).fill('https://x.com/synthetic_user/status/12345');
  await expect(page.getByRole('button', { name: 'Check my public post' })).toBeDisabled();
  await page.getByRole('checkbox', { name: /I approve checking this public post/ }).check();
  await page.getByRole('button', { name: 'Check my public post' }).click();
  await expect(page.getByRole('heading', { name: 'Credential saved · test mode' })).toBeVisible();
  await expect(page.getByText('Research candidate · test mode')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Forget local credential' })).toBeDisabled();
  const calls = await page.evaluate(() => Reflect.get(window, 'publicCalls'));
  expect(calls).toMatchObject([{ op: 'begin', body: { username: 'synthetic_user', approve_public_profile_lookup: true } },
    { op: 'stop' }, { op: 'check-post', body: { approve_source_check: true } }]);
  for (const width of [320, 390, 450]) {
    await page.setViewportSize({ width, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  }
});

test('expired challenge blocks paid check while recovery and confirmed cancellation remain available', async ({ extension }) => {
  const { page, id } = extension;await mockPage(page, { expired: true });await page.goto(`chrome-extension://${id}/public-post.html`);
  await page.getByRole('button', { name: 'Check saved progress' }).click();
  await expect(page.getByText('This challenge has expired.', { exact: false })).toBeVisible();
  await page.getByText('Manual post-link fallback', { exact: true }).click();
  await expect(page.getByRole('button', { name: 'Check my public post' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Recover saved enrollment' })).toBeEnabled();
  await page.getByRole('button', { name: 'Request confirmed cancellation' }).click();
  await expect(page.getByText(/The helper confirmed cancellation/)).toBeVisible();
});

test('saved start uses the same helper handle and requires renewed explicit lookup consent', async ({ extension }) => {
  const { page, id } = extension;await mockPage(page, { beginRecovery: true });await page.goto(`chrome-extension://${id}/public-post.html`);
  await page.getByRole('button', { name: 'Check saved progress' }).click();
  await expect(page.getByRole('textbox', { name: 'X handle', exact: true })).toHaveValue('synthetic_user');
  await expect(page.getByRole('textbox', { name: 'X handle', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Resume saved start' })).toBeDisabled();
  await page.getByRole('checkbox', { name: /I approve looking up/ }).check();
  await page.getByRole('checkbox', { name: /I approve automatic checks/ }).check();
  await page.getByRole('button', { name: 'Resume saved start' }).click();
  expect(await page.evaluate(() => Reflect.get(window, 'publicCalls'))).toMatchObject([{ op: 'status' }, { op: 'begin', body: { username: 'synthetic_user' } }]);
});

test('stale flow versions and arbitrary progress payloads cannot become page content', async ({ extension }) => {
  const { page, id } = extension;await mockPage(page, { wrongVersion: true });await page.goto(`chrome-extension://${id}/public-post.html`);
  await expect(page.getByRole('alert')).toContainText('page and background versions differ');
  await page.evaluate(({ version }) => (Reflect.get(window, 'emitPublic') as (v: unknown) => void)(
    { version, state: 'result', verified: false, summary: { state: 'awaiting-post', credentialSaved: false,
      username: 'synthetic_user', postText: 'synthetic_private_payload', expiresAt: 1 } }), { version: PUBLIC_POST_VERSION });
  await expect(page.locator('body')).not.toContainText('synthetic_private_payload');
  await expect(page.getByRole('button', { name: 'Create public challenge' })).toBeDisabled();
});

test('stopping an in-flight start asks for recovery and never claims cancellation', async ({ extension }) => {
  const { page, id } = extension;await mockPage(page, { waitForBegin: true });await page.goto(`chrome-extension://${id}/public-post.html`);
  await page.getByRole('textbox', { name: 'X handle', exact: true }).fill('synthetic_user');
  await page.getByRole('checkbox', { name: /I approve looking up/ }).check();
  await page.getByRole('checkbox', { name: /I approve automatic checks/ }).check();
  await page.getByRole('button', { name: 'Create public challenge' }).click();
  await expect(page.getByRole('status')).toContainText('Preparing your private request');
  await page.getByRole('button', { name: 'Stop waiting' }).click();
  await expect(page.getByRole('alert')).toContainText('An operation may already have committed');
  await expect(page.getByRole('button', { name: 'Check saved progress' })).toBeEnabled();
  await expect(page.getByText(/The helper confirmed cancellation/)).toHaveCount(0);
  expect(await page.evaluate(() => Reflect.get(window, 'publicCalls'))).toMatchObject([{ op: 'begin' }, { op: 'stop' }]);
});

test('an older silent background has a bounded reload state without querying the helper', async ({ extension }) => {
  const { page, id } = extension;await page.clock.install();await mockPage(page, { silentGreeting: true });
  await page.goto(`chrome-extension://${id}/public-post.html`);
  await expect(page.getByRole('heading', { name: 'Connect X with a public post' })).toBeVisible();
  await page.clock.runFor(10_001);
  await expect(page.getByRole('alert')).toContainText('page and background versions differ');
  await expect(page.getByRole('button', { name: 'Reload NockApp extension' })).toBeVisible();
  expect(await page.evaluate(() => Reflect.get(window, 'publicCalls'))).toEqual([]);
});

async function beginWatching(page: Page) {
  await page.getByRole('textbox', { name: 'X handle', exact: true }).fill('synthetic_user');
  await page.getByRole('checkbox', { name: /I approve looking up/ }).check();
  await expect(page.getByRole('button', { name: 'Create public challenge' })).toBeDisabled();
  await page.getByRole('checkbox', { name: /I approve automatic checks/ }).check();
  await page.getByRole('button', { name: 'Create public challenge' }).click();
  await expect(page.getByText(/Waiting for your public challenge/)).toBeVisible();
}

test('consented enrollment detects and saves automatically with no post URL or second click', async ({ extension }) => {
  const { page, id } = extension;await page.clock.install();await mockPage(page);
  await page.goto(`chrome-extension://${id}/public-post.html`);await beginWatching(page);
  await page.clock.runFor(5_100);
  await expect(page.getByRole('heading', { name: 'Credential saved · test mode' })).toBeVisible();
  await page.clock.runFor(60_000);
  expect(await page.evaluate(() => Reflect.get(window, 'publicCalls'))).toMatchObject([
    { op: 'begin' }, { op: 'poll-registration', body: { approve_source_check: true } }]);
  expect(await page.evaluate(() => (Reflect.get(window, 'publicCalls') as unknown[]).length)).toBe(2);
});

test('automatic polling obeys issuer cooldown and stops when requested', async ({ extension }) => {
  const { page, id } = extension;await page.clock.install();await mockPage(page, { discovery: 'waiting' });
  await page.goto(`chrome-extension://${id}/public-post.html`);await beginWatching(page);
  await page.clock.runFor(5_100);
  const count = () => page.evaluate(() => (Reflect.get(window, 'publicCalls') as unknown[]).length);
  expect(await count()).toBe(2);
  await page.clock.runFor(20_000);expect(await count()).toBe(2);
  await page.clock.runFor(10_000);expect(await count()).toBe(3);
  await page.getByRole('button', { name: 'Stop waiting' }).click();
  await page.clock.runFor(90_000);expect(await count()).toBe(4); // stop only, no more source calls
  await expect(page.getByRole('alert')).toContainText('An operation may already have committed');
});

test('polling is bounded to twenty attempts and saved progress never resumes it without consent', async ({ extension }) => {
  const { page, id } = extension;await page.clock.install();await mockPage(page, { discovery: 'waiting' });
  await page.goto(`chrome-extension://${id}/public-post.html`);
  await page.getByRole('button', { name: 'Check saved progress' }).click();
  await page.clock.runFor(10_000);
  expect(await page.evaluate(() => (Reflect.get(window, 'publicCalls') as unknown[]).length)).toBe(1);
  await expect(page.getByRole('button', { name: 'Resume automatic checking', exact: true })).toBeDisabled();
  await page.getByRole('checkbox', { name: /I approve resuming bounded/ }).check();
  await page.getByRole('button', { name: 'Resume automatic checking', exact: true }).click();
  // Advance in response-sized steps so each synthetic reply schedules the next poll.
  for (let i = 0; i < 20; i++) await page.clock.runFor(i === 0 ? 5_100 : 30_100);
  await expect(page.getByRole('alert')).toContainText('deadline or polling limit');
  await page.clock.runFor(60_000);
  const calls = await page.evaluate(() => Reflect.get(window, 'publicCalls') as { op: string }[]);
  expect(calls.filter(v => v.op === 'poll-registration')).toHaveLength(20);
  expect(calls.some(v => ['check-post', 'cancel', 'begin'].includes(v.op))).toBe(false);
});

test('source failure stops automatic checks and retains recovery; expiry cannot start a query', async ({ extension }) => {
  const { page, id } = extension;await page.clock.install();await mockPage(page, { discovery: 'failure' });
  await page.goto(`chrome-extension://${id}/public-post.html`);await beginWatching(page);
  await page.clock.runFor(5_100);
  await expect(page.getByRole('alert')).toContainText('The operation could not finish');
  await page.clock.runFor(610_000);
  expect(await page.evaluate(() => (Reflect.get(window, 'publicCalls') as unknown[]).length)).toBe(2);
  await expect(page.getByRole('button', { name: 'Recover saved enrollment' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Resume automatic checking', exact: true })).toHaveCount(0);
});
