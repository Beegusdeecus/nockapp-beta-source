import { test as base, expect, chromium, type BrowserContext, type Page, type Worker } from '@playwright/test';
import { mkdtemp, rm, mkdir, unlink, copyFile, cp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { X_FLOW_VERSION, X_SOURCE_PROFILE, PROOF_BRIDGE_PROFILE, PROOF_CONSENT } from '../src/xSourceFlow';

type Fixtures = { extension: { context: BrowserContext; panel: Page; worker: Worker; id: string; profile: string } };
const test = base.extend<Fixtures>({
  extension: async ({}, use) => {
    const profile = await mkdtemp(resolve(tmpdir(), 'nockapp-extension-test-'));
    const extensionPath = resolve(process.env.NOCKAPP_EXTENSION_TEST_PATH ?? 'dist');
    const context = await chromium.launchPersistentContext(profile, {
      channel: 'chromium', headless: true, viewport: { width: 390, height: 844 },
      args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`, '--enable-unsafe-extension-debugging', '--no-sandbox'],
    });
    try {
      const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
      const id = new URL(worker.url()).host;
      const panel = await context.newPage();
      await panel.goto(`chrome-extension://${id}/legacy.html`);
      await expect(panel.getByRole('button', { name: 'Explore demo discussion' })).toBeVisible();
      await use({ context, panel, worker, id, profile });
    } finally { await context.close(); await rm(profile, { recursive: true, force: true }); }
  },
});

async function demo(panel: Page) { await panel.getByRole('button', { name: 'Explore demo discussion' }).click(); }
async function selectUrl(panel: Page, url: string) {
  await panel.getByRole('textbox', { name: 'X post URL' }).fill(url);
  await panel.getByRole('textbox', { name: 'X post URL' }).press('Enter');
}

test('a stale background is explained and extension reload requires an explicit click', async ({ extension }) => {
  const opened = await extension.context.newPage();
  await opened.addInitScript(() => {
    Object.assign(window, { reloadRequested: false, permissionRequested: false });
    chrome.runtime.reload = () => { Object.assign(window, { reloadRequested: true }); };
    chrome.permissions.request = async () => { Object.assign(window, { permissionRequested: true }); return true; };
    chrome.runtime.connect = (() => ({
      onMessage: { addListener: (listener: (value: unknown) => void) => {
        queueMicrotask(() => listener({ state: 'idle', verified: false, passportAvailable: false }));
      } },
      onDisconnect: { addListener: () => {} },
      disconnect: () => {}, postMessage: () => {},
    })) as unknown as typeof chrome.runtime.connect;
  });
  await opened.goto(`chrome-extension://${extension.id}/x-connect.html`);
  await expect(opened.getByRole('alert')).toContainText('background versions differ');
  await expect(opened.getByRole('button', { name: 'Connect X', exact: true })).toHaveCount(0);
  expect(await opened.evaluate(() => Reflect.get(window, 'reloadRequested'))).toBe(false);
  expect(await opened.evaluate(() => Reflect.get(window, 'permissionRequested'))).toBe(false);
  await opened.getByRole('button', { name: 'Reload NockApp extension' }).click();
  expect(await opened.evaluate(() => Reflect.get(window, 'reloadRequested'))).toBe(true);
  await opened.close();
});

test('source failure UI displays sanitized status/code and excludes arbitrary native content', async ({ extension }) => {
  for (const code of ['unsupported-http-status', 'synthetic_private_error']) {
    const opened = await extension.context.newPage();
    await opened.addInitScript(({ version, errorCode }) => {
      chrome.runtime.connect = (() => ({
        onMessage: { addListener: (listener: (value: unknown) => void) => queueMicrotask(() => listener({
          flowVersion: version, state: 'error', verified: false, passportAvailable: false,
          code: errorCode, sourceHttpStatus: 404, sourceHost: 'api.x.com',
          body: 'synthetic_private_body', headers: 'synthetic_private_headers',
        })) },
        onDisconnect: { addListener: () => {} }, disconnect: () => {}, postMessage: () => {},
      })) as unknown as typeof chrome.runtime.connect;
    }, { version: X_FLOW_VERSION, errorCode: code });
    await opened.goto(`chrome-extension://${extension.id}/x-connect.html`);
    await expect(opened.getByRole('alert')).toBeVisible();
    if (code === 'unsupported-http-status') {
      await expect(opened.getByRole('status', { name: 'Source check result' })).toHaveText('Source check at api.x.com: HTTP 404 · unsupported-http-status');
    } else {
      await expect(opened.getByRole('status', { name: 'Source check result' })).toHaveCount(0);
    }
    await expect(opened.locator('body')).not.toContainText('synthetic_private');
    await opened.close();
  }
});

test('proof consent UI separates notarization from the old source check and keeps synthetic results unverified', async ({ extension }) => {
  const opened = await extension.context.newPage();
  await opened.addInitScript(({ version }) => {
    let receive: (message: unknown) => void;
    Object.assign(window, { proofRequests: [] });
    const send = (state: string, extra: Record<string, unknown> = {}) => receive({
      state, flowVersion: version, verified: false, passportAvailable: false,
      proofMode: true, laboratory: true, sourceHost: 'api.x.com', ...extra,
    });
    chrome.runtime.connect = (() => ({
      onMessage: { addListener: (listener: (value: unknown) => void) => {
        receive = listener; queueMicrotask(() => send('context-ready'));
      } }, onDisconnect: { addListener: () => {} }, disconnect: () => {},
      postMessage: (message: { op: string }) => {
        Reflect.get(window, 'proofRequests').push(message);
        if (message.op === 'prove') send('proving', { proofStage: 'independent-verification' });
      },
    })) as unknown as typeof chrome.runtime.connect;
    Object.assign(window, { completeSyntheticProof: () => send('synthetic-ready') });
  }, { version: X_FLOW_VERSION });
  await opened.goto(`chrome-extension://${extension.id}/x-connect.html`);
  const prove = opened.getByRole('button', { name: 'Generate private proof' });
  await expect(prove).toBeDisabled();
  await expect(opened.getByRole('button', { name: 'Check current-user endpoint' })).toHaveCount(0);
  await expect(opened.locator('body')).toContainText('Confirm within ten minutes');
  await expect(opened.locator('body')).toContainText('cannot verify a real account');
  await opened.getByRole('checkbox').check();
  await prove.click();
  await expect(opened.getByRole('heading', { name: 'Verification in progress' })).toBeVisible();
  await expect(opened.locator('body')).toContainText('Independently verifying all evidence');
  await expect(opened.getByRole('heading', { name: 'Passport ready', exact: true })).toHaveCount(0);
  expect(await opened.evaluate(() => Reflect.get(window, 'proofRequests'))).toEqual([{ op: 'prove' }]);
  await opened.evaluate(() => Reflect.get(window, 'completeSyntheticProof')());
  await expect(opened.getByRole('heading', { name: 'Synthetic proof test passed' })).toBeVisible();
  await expect(opened.locator('body')).toContainText('no verified passport was issued');
  await opened.close();
});

test('passport controls require a fresh helper check and explicit deletion without browsing permission', async ({ extension }) => {
  const page = await extension.context.newPage();
  await page.addInitScript(({ profile, consent }) => {
    Object.assign(window, { passportRequests: [], passportPermissionRequests: 0 });
    chrome.permissions.request = async () => { Reflect.set(window, 'passportPermissionRequests', 1); return true; };
    chrome.runtime.connectNative = (() => {
      let receive: (message: unknown) => void;
      return { onMessage: { addListener: (listener: typeof receive) => { receive = listener; } },
        onDisconnect: { addListener: () => {} }, disconnect: () => {},
        postMessage: (message: { id: string; op: string }) => {
          Reflect.get(window, 'passportRequests').push(message);
          if (message.op === 'capabilities') queueMicrotask(() => receive({ id: message.id, status: 'ready', protocol: 2,
            bridge_profile: profile, consent_profile: consent, proving_available: true, passport_available: true,
            laboratory: false, verified: false, passport_issuance_allowed: false }));
          else Reflect.set(window, 'finishPassportOperation', () => {
            const now = Math.floor(Date.now() / 1000);
            receive(message.op === 'passport_status' ? { id: message.id, status: 'passport-ready', laboratory: false,
              verified: true, passport_issuance_allowed: true, holder_bound: true, disclosure: 'none',
              facts: ['account-controlled'], observed_at: now - 1, expires_at: now + 86399 }
              : { id: message.id, status: message.op === 'logout' ? 'logged-out' : 'deleted', verified: false, passport_issuance_allowed: false });
          });
        } };
    }) as unknown as typeof chrome.runtime.connectNative;
  }, { profile: PROOF_BRIDGE_PROFILE, consent: PROOF_CONSENT });
  await page.goto(`chrome-extension://${extension.id}/x-connect.html`);
  await page.getByText('Saved passport', { exact: true }).click();
  await expect(page.getByRole('button', { name: 'Delete saved passports', exact: true })).toBeDisabled();
  await expect(page.getByRole('checkbox')).toHaveCount(2);
  for (const checkbox of await page.getByRole('checkbox').all()) await expect(checkbox).not.toBeChecked();
  await page.getByRole('button', { name: 'Check saved passport' }).click();
  await expect(page.getByRole('button', { name: 'Connect X', exact: true })).toBeDisabled();
  await expect(page.getByRole('heading', { name: 'Saved passport evidence checked' })).toHaveCount(0);
  await page.evaluate(() => Reflect.get(window, 'finishPassportOperation')());
  await expect(page.getByRole('heading', { name: 'Saved passport evidence checked' })).toBeVisible();
  await expect(page.locator('body')).toContainText('Available facts: account control');
  await page.getByRole('button', { name: 'Log out of passport' }).click();
  await page.evaluate(() => Reflect.get(window, 'finishPassportOperation')());
  await expect(page.locator('body')).toContainText('Passport logged out locally');
  await page.getByRole('checkbox', { name: 'I want to delete all saved passport files in this helper.' }).check();
  await page.getByRole('button', { name: 'Delete saved passports', exact: true }).click();
  const requests = await page.evaluate(() => Reflect.get(window, 'passportRequests'));
  expect(requests.at(-1)).toMatchObject({ op: 'delete_passports', delete_holder: false });
  await page.evaluate(() => Reflect.get(window, 'finishPassportOperation')());
  await expect(page.locator('body')).toContainText('Saved passport files were deleted');
  expect(await page.evaluate(() => Reflect.get(window, 'passportPermissionRequests'))).toBe(0);
  await page.close();
});

test('actual browser events deliver initial-page and new-route statuses only from the managed tab', async () => {
  const root = await mkdtemp(resolve(tmpdir(), 'nockapp-status-events-'));
  let context: BrowserContext | undefined;
  try {
    // Pregrant the same three hosts only in this disposable test copy. The
    // production manifest and permission-consent tests remain unchanged.
    const path = resolve(root, 'extension');
    await cp(resolve(process.env.NOCKAPP_EXTENSION_TEST_PATH ?? 'dist'), path, { recursive: true });
    const manifestPath = resolve(path, 'manifest.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    manifest.host_permissions = manifest.optional_host_permissions;
    delete manifest.optional_host_permissions;
    await writeFile(manifestPath, JSON.stringify(manifest));
    context = await chromium.launchPersistentContext(resolve(root, 'profile'), {
      channel: 'chromium', headless: true,
      args: [`--disable-extensions-except=${path}`, `--load-extension=${path}`, '--no-sandbox'],
    });
    // All X requests are synthetic browser responses; no live X data or login.
    await context.route('https://x.com/**', async (route) => {
      if (route.request().resourceType() === 'document') {
        await route.fulfill({ contentType: 'text/html', body: '<button id="submit">Synthetic request</button><script>document.querySelector("#submit").onclick=()=>fetch("/i/jf/api/confirm?synthetic_private_query",{method:"POST",body:"synthetic_private_body"})</script>' });
      } else {
        await route.fulfill({ status: route.request().url().endsWith('/after-other') ? 401 : 403,
          contentType: 'application/json', body: '{"error":"synthetic_private_response"}' });
      }
    });
    const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
    // Synthetic native capabilities isolate the real browser event wiring.
    // Installed helper IPC is tested separately above.
    await worker.evaluate((sourceProfile) => {
      chrome.runtime.connectNative = (() => {
        let listener: (value: unknown) => void = () => {};
        return { onMessage: { addListener: (value: typeof listener) => { listener = value; } },
          onDisconnect: { addListener: () => {} }, disconnect: () => {},
          postMessage: (value: { id: string }) => queueMicrotask(() => listener({ id: value.id, status: 'ready',
            verified: false, passport_issuance_allowed: false, protocol: 1, stage: 'source-feasibility', source_profile: sourceProfile,
            source_probe_available: true, proving_available: false, passport_available: false })) };
      }) as unknown as typeof chrome.runtime.connectNative;
    }, X_SOURCE_PROFILE);
    const ui = await context.newPage();
    await ui.goto(`chrome-extension://${new URL(worker.url()).host}/x-connect.html`);
    await ui.getByRole('button', { name: 'Connect X', exact: true }).click();
    const statuses = ui.getByRole('region', { name: 'X login connection status' });
    await expect(statuses).toContainText('X page: HTTP 200');
    const login = context.pages().find((page) => page.url().startsWith('https://x.com/'))!;
    await login.locator('#submit').click();
    await expect(statuses).toContainText('X request: HTTP 403');
    const other = await context.newPage();
    await other.goto('https://x.com/i/jf/onboarding/web');
    await Promise.all([other.waitForResponse((response) => response.url().includes('/i/jf/api/confirm')), other.locator('#submit').click()]);
    await login.evaluate(() => fetch('/after-other').then(() => undefined));
    await expect(statuses).toContainText('X request: HTTP 401');
    await expect(statuses.locator('li')).toHaveCount(3);
    expect(await ui.locator('body').innerText()).not.toContain('synthetic_private');
    await ui.getByRole('button', { name: 'Cancel connection' }).click();
    await expect.poll(() => login.isClosed()).toBe(true);
    expect(other.isClosed()).toBe(false);
  } finally {
    await context?.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('loads actual MV3 worker, least permissions and seeded references without network', async ({ extension }) => {
  const { panel, worker } = extension;
  const requests: string[] = [];
  panel.on('request', (req) => { if (/^https?:/.test(req.url())) requests.push(req.url()); });
  expect(await worker.evaluate(() => chrome.runtime.getManifest().permissions)).toEqual(['sidePanel', 'activeTab', 'contextMenus', 'storage', 'nativeMessaging', 'webRequest']);
  expect(await worker.evaluate(() => chrome.runtime.getManifest().host_permissions)).toBeUndefined();
  expect(await worker.evaluate(() => chrome.runtime.getManifest().optional_host_permissions)).toEqual(['https://x.com/*', 'https://api.x.com/*', 'https://abs.twimg.com/*']);
  expect(await worker.evaluate(() => chrome.permissions.getAll())).not.toHaveProperty('origins', expect.arrayContaining(['https://x.com/*']));
  await demo(panel);
  await expect(panel.getByText('5 references', { exact: true })).toBeVisible();
  await expect(panel.locator('.thread-result')).toHaveCount(2);
  await expect(panel.locator('.comment-result')).toHaveCount(3);
  await expect(panel.getByText('Demo · 1k+ followers', { exact: true })).toBeVisible();
  await expect(panel.getByRole('link', { name: 'Open original post' })).toHaveAttribute('href', 'https://x.com/i/status/1900000000000000001');
  expect(requests).toEqual([]);
});

test('installed extension talks to the installed Python native helper and rejects unsupported operations', async ({ extension }) => {
  const { panel, id } = extension;
  const helperName = `com.nockapp.test_${process.pid}`;
  const installed: { registration: string; directory: string }[] = [];
  const registration = resolve(extension.profile, 'NativeMessagingHosts', `${helperName}.json`);
  try {
    // Chromium looks under its actual --user-data-dir/NativeMessagingHosts.
    // Keep installation and registration entirely inside the temporary profile.
    const program = `import importlib.util,json,sys\nfrom pathlib import Path\np=Path(sys.argv[4]).resolve()\ns=importlib.util.spec_from_file_location('installer',p)\nm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nprint(json.dumps(m.install(sys.argv[1],home=Path(sys.argv[2]),name=sys.argv[3])))`;
    const installer = resolve(process.env.NOCKAPP_HELPER_INSTALLER_PATH ?? '../nockapp/tools/install-x-helper.py');
    installed.push(JSON.parse(execFileSync('/usr/bin/python3', ['-c', program, id, resolve(extension.profile, 'helper-home'), helperName, installer], { encoding: 'utf8' })));
    await mkdir(resolve(extension.profile, 'NativeMessagingHosts'), { recursive: true });
    await copyFile(installed[0].registration, registration);
    const request = async (op: string) => panel.evaluate(({ name, operation }) => new Promise<Record<string, unknown>>((done) => {
      chrome.runtime.sendNativeMessage(name, { id: crypto.randomUUID().replaceAll('-', ''), op: operation }, (response: unknown) => {
        const error = chrome.runtime.lastError;
        done(error ? { error: error.message } : response as Record<string, unknown>);
      });
    }), { name: helperName, operation: op });
    expect(await request('capabilities')).toMatchObject({ status: 'ready', protocol: 1, stage: 'source-feasibility', source_profile: X_SOURCE_PROFILE,
      verified: false, passport_available: false, proving_available: false });
    expect(await request('issue_passport')).toMatchObject({ status: 'rejected', verified: false, passport_issuance_allowed: false });
    const opened = await extension.context.newPage();
    await opened.goto(`chrome-extension://${id}/x-connect.html`);
    await expect(opened.getByRole('heading', { name: 'Connect X', exact: true })).toBeVisible();
    await expect(opened.getByText('Source feasibility · verification unavailable')).toBeVisible();
    await expect(opened.getByRole('button', { name: 'Check current-user endpoint' })).toHaveCount(0);
    const stored = await extension.worker.evaluate(() => chrome.storage.local.get(null));
    expect(JSON.stringify(stored)).not.toMatch(/synthetic_private|auth_token|x-csrf-token/);
    await opened.close();
  } finally {
    await unlink(registration).catch(() => {});
    for (const item of installed) {
      await unlink(item.registration);
      await rm(item.directory, { recursive: true });
    }
  }
});

test('actual Chromium native IPC reaches the installed frozen protocol-2 package', async ({ extension }) => {
  test.skip(!process.env.NOCKAPP_PROOF_PACKAGE || !process.env.NOCKAPP_PROOF_POLICY || !process.env.NOCKAPP_PROOF_MANIFEST,
    'Requires an explicitly selected frozen helper package, approved public policy and independent manifest hash');
  test.setTimeout(60_000);
  // Installer homes must be beneath /home. This owned temporary tree is not a
  // live browser profile/keyring and is removed after the browser disconnects.
  await mkdir(resolve('artifacts'), { recursive: true });
  const home = await mkdtemp(resolve('artifacts/proof-native-'));
  const helperName = `com.nockapp.test_proof_${process.pid}`;
  const registration = resolve(extension.profile, 'NativeMessagingHosts', `${helperName}.json`);
  try {
    const program = `import importlib.util,json,sys\nfrom pathlib import Path\np=Path(sys.argv[1]).resolve()\ns=importlib.util.spec_from_file_location('manager',p/'manage.py')\nm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\npolicy=json.loads(Path(sys.argv[3]).read_text())\nprint(json.dumps(m.install(p,sys.argv[2],policy,sys.argv[4],home=Path(sys.argv[5]),name=sys.argv[6])))`;
    const installed = JSON.parse(execFileSync('/usr/bin/python3', ['-I', '-B', '-c', program,
      resolve(process.env.NOCKAPP_PROOF_PACKAGE!), process.env.NOCKAPP_PROOF_MANIFEST!,
      resolve(process.env.NOCKAPP_PROOF_POLICY!), extension.id, home, helperName], { encoding: 'utf8', timeout: 40_000 }));
    await mkdir(resolve(extension.profile, 'NativeMessagingHosts'), { recursive: true });
    await copyFile(installed.registration, registration);
    const response = await extension.panel.evaluate((name) => new Promise<Record<string, unknown>>((done) => {
      chrome.runtime.sendNativeMessage(name, { id: crypto.randomUUID().replaceAll('-', ''), op: 'capabilities' }, (value: unknown) => {
        const error = chrome.runtime.lastError;
        done(error ? { error: error.message } : value as Record<string, unknown>);
      });
    }), helperName);
    expect(response).toMatchObject({ status: 'ready', protocol: 2, bridge_profile: PROOF_BRIDGE_PROFILE,
      consent_profile: PROOF_CONSENT, proving_available: true, passport_available: true,
      laboratory: false, verified: false, passport_issuance_allowed: false });
    const stored = await extension.worker.evaluate(() => chrome.storage.local.get(null));
    expect(JSON.stringify(stored)).not.toMatch(/auth_token|x-csrf-token|holder-public|passport-ready/);
  } finally {
    await unlink(registration).catch(() => {});
    await rm(home, { recursive: true, force: true });
  }
});

test('manual Twitter URL matches the same results; invalid links preserve current context', async ({ extension }) => {
  const { panel } = extension;
  await selectUrl(panel, 'https://twitter.com/anyone/status/1900000000000000001?s=20');
  await expect(panel.getByText('5 references', { exact: true })).toBeVisible();
  await selectUrl(panel, 'https://x.com/home');
  await expect(panel.getByRole('alert')).toContainText('not an individual post');
  await expect(panel.locator('.thread-result')).toHaveCount(2);
  await selectUrl(panel, 'https://evil.test/a/status/123');
  await expect(panel.getByRole('alert')).toContainText('x.com or twitter.com');
  await expect(panel.getByRole('textbox', { name: 'X post URL' })).toBeFocused();
});

test('comment jump opens parent with surrounding replies, highlight and keyboard focus; back restores results', async ({ extension }) => {
  const { panel } = extension;
  await demo(panel);
  const row = panel.locator('.comment-result').filter({ hasText: 'This post is a useful example' });
  await row.click();
  await expect(panel.getByRole('heading', { level: 1 })).toHaveText('Anonymity doesn’t have to mean starting from zero.');
  const comment = panel.getByTestId('comment-identity');
  await expect(comment).toHaveClass(/highlighted/);
  await expect(comment).toBeFocused();
  await expect(panel.getByTestId('comment-minimal')).toBeVisible();
  await panel.getByRole('button', { name: 'Back to references' }).click();
  await expect(panel.locator('.comment-result')).toHaveCount(3);
  expect(await panel.locator('main').evaluate((el) => el.scrollTop)).toBeGreaterThan(0);
});

test('empty post creates a thread; opening post is referenced and discussion persists on reopen', async ({ extension }) => {
  const { panel, context, id } = extension;
  await selectUrl(panel, 'https://x.com/name/status/1900000000000000099');
  await expect(panel.getByText('No references to this post yet.')).toBeVisible();
  await panel.getByRole('button', { name: 'Start anonymous discussion', exact: true }).last().click();
  await panel.getByRole('textbox', { name: 'Thread title' }).fill('A fresh anonymous conversation');
  await panel.getByRole('textbox', { name: 'Opening comment' }).fill('Here is my opening thought, with another link https://x.com/another/status/1900000000000000002');
  await panel.getByRole('button', { name: 'Publish anonymous thread' }).click();
  await expect(panel.getByRole('heading', { level: 1 })).toHaveText('A fresh anonymous conversation');
  await expect(panel.locator('.thread-view .reference-link')).toHaveCount(2);
  await panel.close();
  const reopened = await context.newPage();
  await reopened.goto(`chrome-extension://${id}/legacy.html`);
  await expect(reopened.getByRole('heading', { level: 1 })).toHaveText('A fresh anonymous conversation');
  await reopened.getByRole('button', { name: 'Back to references' }).click();
  await expect(reopened.getByText('1 reference', { exact: true })).toBeVisible();
  await expect(reopened.locator('.thread-result')).toHaveCount(1);
});

test('flat comment with a textual ID and X reference persists with back context intact', async ({ extension }) => {
  const { panel } = extension;
  await demo(panel);
  await panel.locator('.thread-result').first().click();
  await panel.getByRole('textbox', { name: 'Your comment' }).fill('>>100007 A flat thought. https://twitter.com/demo/status/1900000000000000099?s=12');
  await panel.getByRole('button', { name: 'Post anonymous comment' }).click();
  const saved = panel.locator('.comment').filter({ hasText: 'A flat thought.' });
  await expect(saved).not.toHaveClass(/nested/);
  await expect(saved).toHaveClass(/highlighted/);
  await expect(panel.getByRole('textbox', { name: 'Your comment' })).toHaveValue('');
  await panel.reload();
  await expect(saved).toBeVisible();
  await saved.getByRole('button', { name: 'Go to post No.100007' }).click();
  await expect(panel.getByTestId('comment-pace')).toBeFocused();
  await expect(panel.getByTestId('comment-pace')).toHaveClass(/highlighted/);
  await saved.getByRole('button', { name: /1900000000000000099/ }).click();
  await expect(panel.getByText('1 reference', { exact: true })).toBeVisible();
  await expect(panel.locator('.comment-result')).toHaveCount(1);
  await panel.getByRole('button', { name: 'Back to thread', exact: true }).click();
  await expect(panel.getByRole('heading', { level: 1 })).toHaveText('What if the best part of a post is the conversation after it?');
});

test('reply and thread drafts survive navigation and panel reload', async ({ extension }) => {
  const { panel } = extension;
  await demo(panel);
  await panel.locator('.thread-result').first().click();
  await panel.getByRole('textbox', { name: 'Your comment' }).fill('A reply I have not sent yet.');
  await expect(panel.getByText('Draft saved on this device')).toBeVisible();
  await panel.getByRole('button', { name: 'Back to references' }).click();
  await panel.locator('.thread-result').first().click();
  await expect(panel.getByRole('textbox', { name: 'Your comment' })).toHaveValue('A reply I have not sent yet.');
  await panel.reload();
  await expect(panel.getByRole('textbox', { name: 'Your comment' })).toHaveValue('A reply I have not sent yet.');
  await panel.getByRole('button', { name: 'Back to references' }).click();
  await panel.getByRole('button', { name: 'Start anonymous discussion', exact: true }).first().click();
  await panel.getByRole('textbox', { name: 'Thread title' }).fill('An unfinished idea');
  await panel.getByRole('textbox', { name: 'Opening comment' }).fill('Still thinking.');
  await panel.reload();
  await expect(panel.getByRole('textbox', { name: 'Thread title' })).toHaveValue('An unfinished idea');
  await expect(panel.getByRole('textbox', { name: 'Opening comment' })).toHaveValue('Still thinking.');
});

test('gesture selection updates an already-open panel and stays isolated by window', async ({ extension }) => {
  const { panel, worker } = extension;
  await worker.evaluate(async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.storage.session.set({ [`selection:${tab.windowId}`]: { kind: 'post', post: { postId: '1900000000000000001', url: 'https://x.com/i/status/1900000000000000001' }, at: Date.now(), nonce: 'first-gesture' } });
  });
  await expect(panel.getByText('5 references', { exact: true })).toBeVisible();
  await worker.evaluate(async () => {
    await chrome.storage.session.set({ 'selection:99999': { kind: 'help', at: Date.now(), nonce: 'another-window' } });
  });
  await expect(panel.getByText('5 references', { exact: true })).toBeVisible();
  await worker.evaluate(async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.storage.session.set({ [`selection:${tab.windowId}`]: { kind: 'help', at: Date.now(), nonce: 'timeline' } });
  });
  await expect(panel.getByRole('button', { name: 'Explore demo discussion' })).toBeVisible();
});

test('actual Chrome sidePanel.open succeeds from an extension-page user gesture', async ({ extension }) => {
  const { panel } = extension;
  await panel.evaluate(() => {
    const button = document.createElement('button'); button.textContent = 'Test native panel open';
    button.id = 'native-open';
    button.onclick = () => {
      // The open call itself occurs before any await, just like production.
      chrome.sidePanel.open({ windowId: chrome.windows.WINDOW_ID_CURRENT }).then(() => { button.textContent = 'Native panel opened'; }).catch((e: Error) => { button.textContent = e.message; });
    };
    document.body.prepend(button);
  });
  await panel.locator('#native-open').click();
  await expect(panel.locator('#native-open')).toHaveText('Native panel opened');
});

test('native toolbar action gets the selected post using activeTab; browsing alone does not change it', async ({ extension }) => {
  const { panel, context, id } = extension;
  await context.route('https://x.com/**', (route) => route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>Synthetic X fixture</title><a href="https://x.com/demo/status/1900000000000000001">Synthetic permalink</a>' }));
  const tab = await context.newPage();
  await tab.goto('https://x.com/demo/status/1900000000000000001?s=20');
  const browserCdp = await context.browser()!.newBrowserCDPSession();
  const { targetInfos } = await browserCdp.send('Target.getTargets', { filter: [{ type: 'tab', exclude: false }] });
  const target = targetInfos.find((t) => t.url === tab.url());
  expect(target).toBeDefined();
  await browserCdp.send('Extensions.triggerAction', { id, targetId: target!.targetId });
  await expect(panel.getByText('5 references', { exact: true })).toBeVisible();
  await expect(panel.getByRole('textbox', { name: 'X post URL' })).toHaveValue('https://x.com/i/status/1900000000000000001');
  await tab.goto('https://x.com/demo/status/1900000000000000099');
  await expect(panel.getByText('5 references', { exact: true })).toBeVisible();
  await browserCdp.send('Extensions.triggerAction', { id, targetId: target!.targetId });
  await expect(panel.getByText('0 references', { exact: true })).toBeVisible();
  await expect(panel.getByRole('textbox', { name: 'X post URL' })).toHaveValue('https://x.com/i/status/1900000000000000099');
  await panel.getByRole('button', { name: 'Back to references' }).click();
  await expect(panel.getByText('5 references', { exact: true })).toBeVisible();
  await expect(panel.getByRole('textbox', { name: 'X post URL' })).toHaveValue('https://x.com/i/status/1900000000000000001');
  await tab.goto('https://x.com/home');
  await browserCdp.send('Extensions.triggerAction', { id, targetId: target!.targetId });
  await expect(panel.getByRole('button', { name: 'Explore demo discussion' })).toBeVisible();
});

test('two simultaneous panels retain both posts instead of overwriting stale snapshots', async ({ extension }) => {
  const { panel, context, id, worker } = extension;
  const second = await context.newPage();
  await second.goto(`chrome-extension://${id}/legacy.html`);
  await expect(second.getByRole('button', { name: 'Explore demo discussion' })).toBeVisible();
  async function prepare(page: Page, suffix: string) {
    await selectUrl(page, `https://x.com/demo/status/19000000000000000${suffix}`);
    await page.getByRole('button', { name: 'Start anonymous discussion', exact: true }).last().click();
    await page.getByRole('textbox', { name: 'Thread title' }).fill(`Concurrent thread ${suffix}`);
    await page.getByRole('textbox', { name: 'Opening comment' }).fill('A public synthetic concurrent submission.');
  }
  await Promise.all([prepare(panel, '91'), prepare(second, '92')]);
  await Promise.all([panel.getByRole('button', { name: 'Publish anonymous thread' }).click(), second.getByRole('button', { name: 'Publish anonymous thread' }).click()]);
  await expect(panel.getByRole('heading', { level: 1 })).toHaveText('Concurrent thread 91');
  await expect(second.getByRole('heading', { level: 1 })).toHaveText('Concurrent thread 92');
  const saved = await worker.evaluate(async () => (await chrome.storage.local.get('nockapp:forum:v1'))['nockapp:forum:v1'] as { threads: { title: string; postNumber: string }[]; comments: { postNumber: string }[] });
  expect(saved.threads.filter((t) => t.title.startsWith('Concurrent thread'))).toHaveLength(2);
  const numbers = [...saved.threads, ...saved.comments].map((p) => p.postNumber);
  expect(new Set(numbers).size).toBe(numbers.length);
});

test('failed discussion save keeps the form and draft; retry succeeds without duplicate posts', async ({ extension }) => {
  const { panel } = extension;
  await selectUrl(panel, 'https://x.com/demo/status/1900000000000000099');
  await panel.getByRole('button', { name: 'Start anonymous discussion', exact: true }).last().click();
  await panel.getByRole('textbox', { name: 'Thread title' }).fill('A recoverable save');
  await panel.getByRole('textbox', { name: 'Opening comment' }).fill('The draft should survive a synthetic storage failure.');
  await expect(panel.getByText('Draft saved on this device')).toBeVisible();
  await panel.evaluate(() => {
    const original = chrome.storage.local.set.bind(chrome.storage.local);
    chrome.storage.local.set = ((items: Record<string, unknown>) => {
      return items['nockapp:forum:v1'] ? Promise.reject(new Error('Synthetic storage quota exceeded.')) : original(items);
    }) as typeof chrome.storage.local.set;
  });
  await panel.getByRole('button', { name: 'Publish anonymous thread' }).click();
  await expect(panel.getByRole('alert')).toContainText('Synthetic storage quota exceeded');
  await expect(panel.getByRole('textbox', { name: 'Opening comment' })).toHaveValue('The draft should survive a synthetic storage failure.');
  await panel.reload();
  await expect(panel.getByRole('textbox', { name: 'Thread title' })).toHaveValue('A recoverable save');
  await panel.getByRole('button', { name: 'Publish anonymous thread' }).click();
  await expect(panel.getByRole('heading', { level: 1 })).toHaveText('A recoverable save');
  await panel.getByRole('button', { name: 'Back to references' }).click();
  await expect(panel.locator('.thread-result')).toHaveCount(1);
});

test('corrupt storage is reported without replacing it', async ({ extension }) => {
  const { panel, worker } = extension;
  await worker.evaluate(() => chrome.storage.local.set({ 'nockapp:forum:v1': { schema: 99, marker: 'preserve-me' } }));
  await panel.reload();
  await expect(panel.getByRole('alert')).toContainText('Saved demo data could not be read');
  expect(await worker.evaluate(async () => (await chrome.storage.local.get('nockapp:forum:v1'))['nockapp:forum:v1'])).toEqual({ schema: 99, marker: 'preserve-me' });
  await panel.getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(panel.getByRole('dialog')).toBeVisible();
  await panel.keyboard.press('Escape');
  await expect(panel.getByRole('button', { name: 'Settings', exact: true })).toBeFocused();
});

test('responsive panel has no horizontal overflow at 320–450px; settings traps and returns focus', async ({ extension }) => {
  const { panel } = extension;
  await demo(panel);
  for (const width of [320, 390, 450]) {
    await panel.setViewportSize({ width, height: 844 });
    expect(await panel.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    expect(await panel.locator('main').evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
  }
  await panel.setViewportSize({ width: 390, height: 844 });
  await mkdir('artifacts', { recursive: true });
  await panel.screenshot({ path: `artifacts/panel-${Date.now()}.png` });
  await panel.getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(panel.getByRole('dialog')).toContainText('No proof is generated or verified');
  await panel.keyboard.press('Escape');
  await expect(panel.getByRole('button', { name: 'Settings', exact: true })).toBeFocused();
  await panel.locator('.thread-result').first().click();
  for (const width of [320, 390, 450]) {
    await panel.setViewportSize({ width, height: 844 });
    expect(await panel.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    expect(await panel.locator('main').evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
  }
  await panel.setViewportSize({ width: 390, height: 844 });
  const quote = panel.getByRole('button', { name: 'Go to post No.100007' });
  await quote.focus(); await quote.press('Enter');
  await expect(panel.getByTestId('comment-pace')).toBeFocused();
  expect(await panel.evaluate(() => window.scrollY)).toBe(0);
  await panel.screenshot({ path: `artifacts/thread-${Date.now()}.png` });
});

test('only one selected-post bar; typing, pasting and blurring do not load until Enter', async ({ extension }) => {
  const { panel } = extension;
  await demo(panel);
  const input = panel.getByRole('textbox', { name: 'X post URL' });
  await expect(panel.getByRole('region', { name: 'Selected post' })).toHaveCount(1);
  await expect(input).toHaveCount(1);
  await expect(input).toHaveValue('https://x.com/i/status/1900000000000000001');
  await expect(panel.getByText('ANONYMOUS BY DEFAULT', { exact: true })).toHaveCount(0);
  await input.fill('https://twitter.com/demo/status/1900000000000000099?s=20');
  await panel.getByRole('heading', { level: 1 }).click();
  await expect(panel.getByText('5 references', { exact: true })).toBeVisible();
  await expect(panel.locator('.thread-result')).toHaveCount(2);
  await input.press('Enter');
  await expect(panel.getByText('0 references', { exact: true })).toBeVisible();
  await expect(input).toHaveValue('https://x.com/i/status/1900000000000000099');
});

test('references jump to comments and cross-thread openings, with focus, highlight and back history', async ({ extension }) => {
  const { panel } = extension;
  await demo(panel);
  await panel.locator('.thread-result').first().click();
  const comments = panel.locator('.comment');
  await expect(comments).toHaveCount(3);
  const offsets = await comments.evaluateAll((items) => items.map((item) => item.getBoundingClientRect().left));
  expect(new Set(offsets).size).toBe(1);
  await expect(panel.getByRole('button', { name: /^Reply to/ })).toHaveCount(0);
  await panel.getByRole('button', { name: 'Go to post No.100007' }).click();
  await expect(panel.getByTestId('comment-pace')).toBeFocused();
  await expect(panel.getByTestId('comment-pace')).toHaveClass(/highlighted/);
  await panel.getByRole('textbox', { name: 'Your comment' }).fill('>>100001 >>100002 >>999999 Different contexts, one flat comment.');
  await panel.getByRole('button', { name: 'Post anonymous comment' }).click();
  const newComment = panel.locator('.comment').filter({ hasText: 'Different contexts, one flat comment.' });
  await newComment.getByRole('button', { name: 'Go to post No.999999' }).click();
  await expect(panel.getByRole('status').filter({ hasText: 'was not found' })).toBeVisible();
  await newComment.getByRole('button', { name: 'Go to post No.100001' }).click();
  await expect(panel.getByRole('heading', { level: 1 })).toHaveText('Anonymity doesn’t have to mean starting from zero.');
  await expect(panel.getByRole('article', { name: 'Thread No.100001', exact: true })).toHaveClass(/highlighted/);
  await expect(panel.getByRole('article', { name: 'Thread No.100001', exact: true })).toBeFocused();
  await panel.getByRole('button', { name: 'Back to thread' }).click();
  await newComment.getByRole('button', { name: 'Go to post No.100002' }).click();
  await expect(panel.getByTestId('comment-identity')).toBeFocused();
  await expect(panel.getByTestId('comment-identity')).toHaveClass(/highlighted/);
  await panel.getByRole('button', { name: 'Back to thread' }).click();
  await expect(panel.getByRole('heading', { level: 1 })).toHaveText('What if the best part of a post is the conversation after it?');
  await expect(panel.getByRole('textbox', { name: 'X post URL' })).toHaveValue('https://x.com/i/status/1900000000000000001');
});

test('authors stay Anonymous; demo credentials are opted into per post and persisted with drafts', async ({ extension }) => {
  const { panel } = extension;
  await selectUrl(panel, 'https://x.com/demo/status/1900000000000000099');
  await panel.getByRole('button', { name: 'Start anonymous discussion', exact: true }).last().click();
  await panel.getByRole('textbox', { name: 'Thread title' }).fill('Optional context');
  await panel.getByRole('textbox', { name: 'Opening comment' }).fill('Only the credentials I selected should be displayed.');
  await panel.getByText('Optional demo credentials', { exact: true }).click();
  for (const checkbox of await panel.getByRole('checkbox').all()) await expect(checkbox).not.toBeChecked();
  await panel.getByRole('checkbox', { name: 'Demo · 1k+ followers', exact: true }).check();
  await panel.reload();
  await panel.getByText('Optional demo credentials (1 selected)', { exact: true }).click();
  await expect(panel.getByRole('checkbox', { name: 'Demo · 1k+ followers', exact: true })).toBeChecked();
  await panel.getByRole('button', { name: 'Publish anonymous thread' }).click();
  await expect(panel.locator('.opening-post .badge')).toHaveCount(1);
  await expect(panel.locator('.opening-post .badge')).toHaveText('Demo · 1k+ followers');
  await expect(panel.locator('body')).not.toContainText(/anon_\w+/);
  await expect(panel.locator('.opening-post .author')).toHaveText('Anonymous');
  await panel.getByRole('textbox', { name: 'Your comment' }).fill('No credentials on this comment.');
  await panel.getByRole('button', { name: 'Post anonymous comment' }).click();
  await expect(panel.locator('.comment .badge')).toHaveCount(0);
  await expect(panel.locator('.comment').filter({ hasText: 'No credentials on this comment.' })).toBeVisible();
  const numbers = await panel.locator('.thread-view .post-id').allTextContents();
  expect(numbers).toHaveLength(2);
  expect(new Set(numbers).size).toBe(2);
  expect(numbers.every((n) => /^No\.\d+$/.test(n))).toBe(true);
});

test('v1 upgrade preserves posts, navigation and all old drafts; flattening and recovery are idempotent', async ({ extension }) => {
  const { panel, context, id, worker } = extension;
  const post = { postId: '1900000000000000001', url: 'https://x.com/i/status/1900000000000000001' };
  const author = { id: 'anon_do_not_display', credentials: [{ kind: 'followers-1k' }] };
  const legacy = {
    schema: 1, identity: { id: 'anon_local', credentials: [] },
    threads: [{ id: 'legacy-thread', title: 'My existing discussion', body: 'The original opening stays intact.', author, createdAt: 1, references: [post] }],
    comments: [
      { id: 'legacy-a', threadId: 'legacy-thread', body: 'First comment.', author, createdAt: 2, references: [] },
      { id: 'legacy-b', threadId: 'legacy-thread', parentId: 'legacy-a', body: 'Former child comment.', author, createdAt: 3, references: [post] },
      { id: 'legacy-c', threadId: 'legacy-thread', parentId: 'legacy-b', body: 'Former grandchild comment.', author, createdAt: 4, references: [] },
    ],
  };
  await panel.close();
  await worker.evaluate(async ({ legacy, post }) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.storage.local.set({
      'nockapp:forum:v1': legacy,
      [`navigation:${tab.windowId}`]: { stack: [{ kind: 'results', post }, { kind: 'thread', post, threadId: 'legacy-thread', focusCommentId: 'legacy-b', replyToId: 'legacy-b' }], updatedAt: Date.now(), scroll: {} },
      'draft:reply:legacy-thread:root': { title: '', body: 'An existing root draft.' },
      'draft:reply:legacy-thread:legacy-a': { title: '', body: 'A first targeted draft.' },
      'draft:reply:legacy-thread:legacy-b': { title: '', body: 'A second targeted draft.' },
      'draft:thread:1900000000000000001': { title: 'An existing title draft', body: 'An existing opening draft.' },
    });
  }, { legacy, post });
  const updated = await context.newPage();
  await updated.goto(`chrome-extension://${id}/legacy.html`);
  await expect(updated.getByRole('heading', { level: 1 })).toHaveText('My existing discussion');
  await expect(updated.getByTestId('legacy-b')).toBeFocused();
  await expect(updated.locator('.comment')).toHaveCount(3);
  await expect(updated.locator('.nested')).toHaveCount(0);
  await expect(updated.locator('body')).not.toContainText('anon_');
  const recovered = 'An existing root draft.\n\n>>100002\nA first targeted draft.\n\n>>100003\nA second targeted draft.';
  await expect(updated.getByRole('textbox', { name: 'Your comment' })).toHaveValue(recovered);
  await updated.reload();
  await expect(updated.getByRole('textbox', { name: 'Your comment' })).toHaveValue(recovered);
  const saved = await worker.evaluate(async () => {
    const all = await chrome.storage.local.get(null);
    return { snapshot: all['nockapp:forum:v1'] as { schema: number; comments: { body: string; parentId?: string }[] }, backups: Object.entries(all).filter(([key]) => key.startsWith('nockapp:backup:v1:')).map(([, value]) => value) };
  });
  expect(saved.snapshot.schema).toBe(2);
  expect(saved.snapshot.comments.map((c) => c.body)).toEqual(legacy.comments.map((c) => c.body));
  expect(saved.snapshot.comments.every((c) => !('parentId' in c))).toBe(true);
  expect(saved.backups).toEqual([legacy]);
  await updated.getByRole('button', { name: 'Post anonymous comment' }).click();
  await expect(updated.getByRole('textbox', { name: 'Your comment' })).toHaveValue('');
  await updated.reload();
  await expect(updated.getByRole('textbox', { name: 'Your comment' })).toHaveValue('');
  await updated.getByRole('button', { name: 'Back to references' }).click();
  await updated.getByRole('button', { name: 'Start anonymous discussion', exact: true }).first().click();
  await expect(updated.getByRole('textbox', { name: 'Thread title' })).toHaveValue('An existing title draft');
  await expect(updated.getByRole('textbox', { name: 'Opening comment' })).toHaveValue('An existing opening draft.');
});

test('large recovered drafts are retained without truncation and cannot be posted above the limit', async ({ extension }) => {
  const { panel, worker } = extension;
  await worker.evaluate(async () => chrome.storage.local.set({
    'draft:reply:thread-conversation:root': { title: '', body: 'a'.repeat(4000) },
    'draft:reply:thread-conversation:comment-pace': { title: '', body: 'b'.repeat(4000) },
  }));
  await demo(panel);
  await panel.locator('.thread-result').first().click();
  const combined = `${'a'.repeat(4000)}\n\n>>100007\n${'b'.repeat(4000)}`;
  await expect(panel.getByRole('textbox', { name: 'Your comment' })).toHaveValue(combined);
  await expect(panel.getByRole('button', { name: 'Post anonymous comment' })).toBeDisabled();
  await expect(panel.getByText('Your recovered drafts are combined here.', { exact: false })).toBeVisible();
  await panel.reload();
  await expect(panel.getByRole('textbox', { name: 'Your comment' })).toHaveValue(combined);
  expect(await worker.evaluate(async () => (await chrome.storage.local.get('draft:reply:thread-conversation:comment-pace'))['draft:reply:thread-conversation:comment-pace'])).toEqual({ title: '', body: 'b'.repeat(4000) });
});


test('an immediate panel close still lets the worker finish the last draft edit', async ({ extension }) => {
  const { panel, context, id } = extension;
  await demo(panel);
  await panel.locator('.thread-result').first().click();
  await panel.getByRole('textbox', { name: 'Your comment' }).fill('The last edit must survive an immediate close.');
  await panel.close();
  const reopened = await context.newPage();
  await reopened.goto(`chrome-extension://${id}/legacy.html`);
  await expect(reopened.getByRole('textbox', { name: 'Your comment' })).toHaveValue('The last edit must survive an immediate close.');
});
