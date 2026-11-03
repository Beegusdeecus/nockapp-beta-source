import { test, expect } from '@playwright/test';
import { passportOperation, PassportError } from '../src/xPassport';
import { PROOF_BRIDGE_PROFILE, PROOF_CONSENT } from '../src/xSourceFlow';

class Signal {
  listeners: ((message: unknown) => void)[] = [];
  addListener = (listener: (message: unknown) => void) => { this.listeners.push(listener); };
  emit(message: unknown) { for (const listener of this.listeners) listener(message); }
}
function environment() {
  const messages: Record<string, unknown>[] = [];
  let disconnected = false;
  const port = { onMessage: new Signal(), onDisconnect: new Signal(),
    postMessage: (message: Record<string, unknown>) => messages.push(message), disconnect: () => { disconnected = true; } };
  // Deliberately no permissions, windows, tabs or storage APIs.
  Object.defineProperty(globalThis, 'chrome', { configurable: true, value: { runtime: { connectNative: () => port } } });
  return { port, messages, disconnected: () => disconnected,
    capabilities: async (laboratory = false, changes: Record<string, unknown> = {}) => { await new Promise(resolve => setTimeout(resolve, 0)); port.onMessage.emit({
      id: messages[0].id, status: 'ready', protocol: 2, bridge_profile: PROOF_BRIDGE_PROFILE,
      consent_profile: PROOF_CONSENT, proving_available: true, passport_available: true,
      laboratory, verified: false, passport_issuance_allowed: false, ...changes }); },
    result: (value: Record<string, unknown>) => port.onMessage.emit({ id: messages.at(-1)?.id, ...value }),
    close: () => Reflect.deleteProperty(globalThis, 'chrome') };
}
function summary(laboratory = false) {
  const now = Math.floor(Date.now() / 1000);
  return { status: laboratory ? 'synthetic-archive-ready' : 'passport-ready', laboratory,
    verified: !laboratory, passport_issuance_allowed: !laboratory, holder_bound: true, disclosure: 'none',
    facts: ['account-controlled', 'followers-over-10000'], observed_at: now - 1, expires_at: now + 86399 };
}

test('passport checks negotiate a fresh restricted port without browsing access and return only dated facts', async () => {
  const e = environment();
  try {
    const result = passportOperation('passport_status');
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(e.messages[0].op).toBe('capabilities');
    await e.capabilities();
    expect(e.messages[1]).toEqual({ id: expect.any(String), op: 'passport_status' });
    expect(e.messages[1].id).not.toBe(e.messages[0].id);
    e.result({ ...summary(), secret: 'synthetic_private_response', holder_key: 'synthetic_private_holder' });
    const checked = await result;
    expect(checked).toMatchObject({ status: 'checked', facts: ['account-controlled', 'followers-over-10000'] });
    expect(JSON.stringify(checked)).not.toContain('synthetic_private');
    expect(e.disconnected()).toBe(true);
  } finally { e.close(); }
});

test('synthetic status stays synthetic and cannot be relabelled into production acceptance', async () => {
  for (const relabel of [false, true]) {
    const e = environment();
    try {
      const result = passportOperation('passport_status');
      await e.capabilities(true); e.result(summary(!relabel));
      if (relabel) await expect(result).rejects.toMatchObject({ code: 'unsupported-helper' });
      else await expect(result).resolves.toMatchObject({ status: 'synthetic' });
    } finally { e.close(); }
  }
});

test('expired, unbound, future and unsupported saved summaries fail closed', async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const changes of [{ expires_at: now - 1 }, { holder_bound: false }, { observed_at: now + 50 },
    { facts: ['exact-account-id'] }, { expires_at: now + 172800 }, { verified: false }]) {
    const e = environment();
    try {
      const result = passportOperation('passport_status');
      await e.capabilities(); e.result({ ...summary(), ...changes });
      await expect(result).rejects.toBeInstanceOf(PassportError);
    } finally { e.close(); }
  }
});

test('logout and explicit deletion use fixed schemas and reject misleading verified responses', async () => {
  for (const operation of ['logout', 'delete_passports'] as const) {
    const e = environment();
    try {
      const result = passportOperation(operation, operation === 'delete_passports' ? { deleteHolder: true } : {});
      await e.capabilities();
      expect(e.messages.at(-1)).toEqual({ id: expect.any(String), op: operation,
        ...(operation === 'delete_passports' ? { delete_holder: true } : {}) });
      e.result({ status: operation === 'logout' ? 'logged-out' : 'deleted', verified: false, passport_issuance_allowed: false });
      await expect(result).resolves.toEqual({ status: operation === 'logout' ? 'logged-out' : 'deleted' });
    } finally { e.close(); }
  }
  const e = environment();
  try {
    const result = passportOperation('delete_passports');
    await e.capabilities();
    expect(e.messages.at(-1)?.delete_holder).toBe(false);
    e.result({ status: 'deleted', verified: true, passport_issuance_allowed: true });
    await expect(result).rejects.toMatchObject({ code: 'unsupported-helper' });
  } finally { e.close(); }
});

test('old helpers, wrong IDs and arbitrary errors cannot become passport status', async () => {
  for (const old of [true, false]) {
    const e = environment();
    try {
      const result = passportOperation('passport_status');
      if (old) await e.capabilities(false, { protocol: 1 });
      else { await e.capabilities(); e.port.onMessage.emit({ id: '00'.repeat(16), ...summary() }); }
      await expect(result).rejects.toMatchObject({ code: 'unsupported-helper' });
    } finally { e.close(); }
  }
  for (const code of ['keyring-locked', 'synthetic_private_error']) {
    const e = environment();
    try {
      const result = passportOperation('delete_passports');
      await e.capabilities();
      e.result({ status: 'rejected', code, verified: false, passport_issuance_allowed: false, body: 'synthetic_private_body' });
      await expect(result).rejects.toMatchObject({ code: code === 'keyring-locked' ? code : 'helper-operation-failed' });
    } finally { e.close(); }
  }
});

test('page closure aborts native work and a late success cannot revive the result', async () => {
  const e = environment();
  try {
    const controller = new AbortController();
    const result = passportOperation('passport_status', { signal: controller.signal });
    await e.capabilities(); controller.abort(); e.result(summary());
    await expect(result).rejects.toMatchObject({ code: 'job-cancelled' });
    expect(e.disconnected()).toBe(true);
  } finally { e.close(); }
});
