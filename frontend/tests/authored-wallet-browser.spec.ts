import { test, expect, chromium } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
const fixture = JSON.parse(readFileSync(new URL('./fixtures/authored-wallet-contract-20261101.json', import.meta.url), 'utf8'));

// Real built UI/provider/stream; the external MetaMask port and native server are explicit fixtures.
test('built wallet screen contacts MetaMask only on consent and sends the exact saved signature result', async () => {
  const profile = await mkdtemp(resolve(tmpdir(), 'nockapp-authored-wallet-ui-'));const path = resolve('dist');
  const context = await chromium.launchPersistentContext(profile, { channel: 'chromium', headless: true,
    args: [`--disable-extensions-except=${path}`, `--load-extension=${path}`, '--no-sandbox'] });
  try {
    const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
    await worker.evaluate(f => {
      const calls: any[] = [];Object.assign(globalThis, { authoredNativeCalls: calls });
      const identity = { ...f.scope, profile: 'nockapp-bundle-service-identity-v4', protocol: 4, registry: '0x' + '78'.repeat(20),
        definition_hash: '78'.repeat(32), native_sha256: '9a'.repeat(32), count_native_sha256: 'bc'.repeat(32), author_native_sha256: 'de'.repeat(32),
        bundle_profile: 'nockapp-public-discussion-bundle-v4', storage: { replicas: [{ name: 'replica-one', failure_domain: 'region-one' },
          { name: 'replica-two', failure_domain: 'region-two' }], retention_seconds: 90 * 86400, max_bundle_bytes: 32768, permanent_availability_proven: false } };
      const row = { post: f.post, selection: f.selection, submission_id: f.submission_id, phase: 'wallet-needed', renewal_count: 0, experimental: true,
        status: { state: 'recoverable', checked_at: 1793494801, recovery_action: 'sign-with-wallet', authorship_checked: false, address_evidence_checked: false, credential_evidence_checked: false } };
      chrome.runtime.connectNative = (() => {
        const listeners = new Set<(v: unknown) => void>();
        return { onMessage: { addListener: (fn: (v: unknown) => void) => listeners.add(fn), removeListener: (fn: (v: unknown) => void) => listeners.delete(fn) },
          onDisconnect: { addListener: () => {}, removeListener: () => {} }, disconnect: () => {},
          postMessage: (m: any) => {
            if (!m.operation.startsWith('authored-')) throw new Error('Wrong native namespace');
            m = { ...m, wire_operation: m.operation, operation: m.operation.slice(9) };calls.push(structuredClone(m));let result;
            if (m.operation === 'bundle-capabilities') result = { configured: true, identity, count_enrollment_configured: true, experimental: true };
            else if (m.operation === 'bundle-outbox') result = { entries: [row], next_after: 1, more: false, experimental: true };
            else if (m.operation === 'bundle-address-request') result = f.request;
            else if (m.operation === 'bundle-address-result') result = { ...row, phase: 'submitted' };
            else throw new Error('Unexpected native operation');
            queueMicrotask(() => listeners.forEach(fn => fn({ profile: m.profile, id: m.id, status: 'ok', result, laboratory: true, verified: false })));
          } };
      }) as unknown as typeof chrome.runtime.connectNative;
    }, fixture);
    await context.addInitScript(f => {
      Date.now = () => 1793494801000;
      const calls: any[] = [];Object.assign(globalThis, { metamaskPortCalls: calls });
      const original = chrome.runtime.connect.bind(chrome.runtime);
      chrome.runtime.connect = ((...args: any[]) => {
        if (typeof args[0] !== 'string') return (original as any)(...args);
        calls.push({ connect: args[0] });
        const listeners = new Set<(v: unknown) => void>();
        return { name: '', onMessage: { addListener: (fn: (v: unknown) => void) => listeners.add(fn) }, onDisconnect: { addListener: () => {} },
          disconnect: () => {}, postMessage: (m: any) => {
            const rpc = m.data;if (!rpc?.method) return;calls.push(structuredClone(rpc));
            let result;
            if (rpc.method === 'metamask_getProviderState') result = { isUnlocked: true, chainId: '0x14a34', networkVersion: '84532', accounts: [f.request.address] };
            else if (rpc.method === 'eth_requestAccounts' || rpc.method === 'eth_accounts') result = [f.request.address];
            else if (rpc.method === 'eth_chainId') result = '0x14a34';
            else if (rpc.method === 'eth_signTypedData_v4') result = '0x' + '12'.repeat(65);
            else throw new Error('Unexpected wallet method: ' + rpc.method);
            queueMicrotask(() => listeners.forEach(fn => fn({ name: m.name, data: { jsonrpc: '2.0', id: rpc.id, result } })));
          } };
      }) as typeof chrome.runtime.connect;
    }, fixture);
    const page = await context.newPage();const errors: string[] = [];page.on('pageerror', e => errors.push(e.message));
    await page.goto(`chrome-extension://${new URL(worker.url()).host}/wallet-post.html#post=${fixture.post.id}`);
    const button = page.getByRole('button', { name: 'Connect MetaMask and authorize' });await expect(button).toBeEnabled();
    expect(await page.evaluate(() => (globalThis as any).metamaskPortCalls)).toEqual([]);
    await expect(page.getByText(fixture.post.body, { exact: true })).toBeVisible();await button.click();
    await expect(page.getByRole('status')).toContainText('Authorization saved');expect(errors).toEqual([]);
    const calls = await page.evaluate(() => (globalThis as any).metamaskPortCalls);
    expect(calls[0]).toEqual({ connect: 'nkbihfbeogaeaoehlefnkodbefgpgknn' });
    const sign = calls.find((v: any) => v.method === 'eth_signTypedData_v4');
    expect(sign.params[0]).toBe(fixture.request.address);expect(JSON.parse(sign.params[1])).toEqual(fixture.request.typed_data);
    const native = await worker.evaluate(() => (globalThis as any).authoredNativeCalls);
    const result = native.find((v: any) => v.operation === 'bundle-address-result');
    expect(result.body).toEqual({ post_id: fixture.post.id, submission_id: fixture.submission_id, request_sha256: fixture.request.request_sha256, signature: '0x' + '12'.repeat(65) });
    expect(calls.every((v: any) => !v.method || ['metamask_getProviderState', 'eth_requestAccounts', 'eth_accounts', 'eth_chainId', 'eth_signTypedData_v4'].includes(v.method))).toBe(true);
  } finally { await context.close();await rm(profile, { recursive: true, force: true }); }
});
