import { api } from './platform/browser';
import type { ZkidFact, ZkidReference } from './model';
import { exact, object, validWirePost, validZkidFacts, validZkidReference, sortedFacts, hex, type WirePost } from './zkidWire';

export const FACT_VERSION = 'zkid-post-facts-1';
export const FACT_PORT = 'zkid-post-facts';
const NATIVE = 'nockapp-zkid-public-post-native-v1';
export type FactOperation = 'post-capabilities' | 'post-status' | 'post-available' | 'post-use' | 'post-retry' | 'post-recover'
  | 'post-inspect' | 'post-complete' | 'post-discard';
export type PendingPost = { state: 'prepared' | 'challenge-saved' | 'proof-saved' | 'accepted'; post: WirePost; facts: ZkidFact[] };
export type FactAccepted = { state: 'accepted'; reference: ZkidReference; observed_at: number; expires_at: number; checked_at: number;
  archival_only: true; laboratory: true; verified: false };
export type FactAvailable = { facts: ZkidFact[]; observed_at: number; expires_at: number; availability_only: true; laboratory: true; verified: false };
export class FactError extends Error {
  constructor(public code: string) { super('Public-post fact operation failed. Your draft and saved recovery are preserved.'); }
}
const flags = (v: Record<string, unknown>) => v.laboratory === true && v.verified === false;
const dates = (v: Record<string, unknown>) => Number.isSafeInteger(v.observed_at) && Number(v.observed_at) > 0
  && Number(v.observed_at) % 3600 === 0 && Number.isSafeInteger(v.expires_at) && Number(v.expires_at) - Number(v.observed_at) === 86400
  && Number(v.observed_at) <= Math.floor(Date.now() / 1000) + 5 && Number(v.expires_at) > Math.floor(Date.now() / 1000);
export function validFactBody(op: string, b: Record<string, unknown>): op is FactOperation {
  if (['post-capabilities', 'post-status', 'post-available', 'post-recover'].includes(op)) return exact(b, []);
  if (op === 'post-discard') return exact(b, ['confirm_local_discard']) && b.confirm_local_discard === true;
  const base = validWirePost(b.post) && validZkidFacts(b.facts, false);
  if (['post-use', 'post-retry'].includes(op)) return base && exact(b, ['post', 'facts', 'approve_facts', 'approve_identity_disclosure'])
    && JSON.stringify(b.approve_facts) === JSON.stringify(b.facts) && b.approve_identity_disclosure === false;
  if (op === 'post-inspect') return base && hex(b.nonce) && exact(b, ['post', 'facts', 'nonce']);
  return op === 'post-complete' && base && hex(b.nonce) && b.confirm_published === true && exact(b, ['post', 'facts', 'nonce', 'confirm_published']);
}
export function factProjection(op: FactOperation, value: unknown, body: Record<string, unknown> = {}): boolean {
  if (!object(value) || !flags(value)) return false;
  if (op === 'post-capabilities') return exact(value, ['configured', 'profile', 'identity_disclosed', 'laboratory', 'verified'])
    && typeof value.configured === 'boolean' && value.profile === 'nockapp-zkid-post-reference-v1' && value.identity_disclosed === false;
  if (op === 'post-status') return value.state === 'empty' ? exact(value, ['state', 'laboratory', 'verified'])
    : exact(value, ['state', 'post', 'facts', 'laboratory', 'verified']) && ['prepared', 'challenge-saved', 'proof-saved', 'accepted'].includes(String(value.state))
      && validWirePost(value.post) && validZkidFacts(value.facts, false) && JSON.stringify(value.facts) === JSON.stringify(sortedFacts(value.facts));
  if (op === 'post-available') return exact(value, ['facts', 'observed_at', 'expires_at', 'availability_only', 'laboratory', 'verified'])
    && validZkidFacts(value.facts, false) && value.availability_only === true && dates(value);
  if (op === 'post-complete') return exact(value, ['state', 'laboratory', 'verified']) && value.state === 'completed';
  if (op === 'post-discard') return exact(value, ['state', 'remote_revocation', 'laboratory', 'verified']) && value.state === 'discarded' && value.remote_revocation === false;
  return exact(value, ['state', 'reference', 'observed_at', 'expires_at', 'checked_at', 'archival_only', 'laboratory', 'verified'])
    && value.state === 'accepted' && validZkidReference(value.reference) && value.archival_only === true && dates(value)
    && Number.isSafeInteger(value.checked_at) && Number(value.checked_at) >= Math.floor(Date.now() / 1000) - 185
    && Number(value.checked_at) <= Math.floor(Date.now() / 1000) + 5 && Number(value.checked_at) >= Number(value.observed_at)
    && Number(value.checked_at) < Number(value.expires_at)
    && (body.facts === undefined || JSON.stringify(value.reference.facts) === JSON.stringify(sortedFacts(body.facts as ZkidFact[])))
    && (body.nonce === undefined || value.reference.nonce === body.nonce);
}

let active: symbol | undefined;
/** Called only for exact sidepanel admission in background.ts. */
export function attachZkidFacts(ui: chrome.runtime.Port) {
  let native: chrome.runtime.Port | undefined;let dispose: (() => void) | undefined;let connected = true;
  const owner = Symbol('zkid-post-fact');
  const emit = (value: object) => { if (connected) try { ui.postMessage({ version: FACT_VERSION, ...value }); } catch { connected = false;dispose?.(); } };
  ui.onDisconnect.addListener(() => { connected = false;dispose?.(); });
  ui.onMessage.addListener((m: unknown) => {
    if (!connected) return;
    if (native) return;
    if (!object(m) || !exact(m, ['version', 'operation', 'body']) || m.version !== FACT_VERSION || typeof m.operation !== 'string'
        || !object(m.body) || !validFactBody(m.operation, m.body) || new TextEncoder().encode(JSON.stringify(m)).length > 131072) {
      emit({ error: 'message-schema' });return;
    }
    if (active) { emit({ error: 'helper-busy' });return; }
    const op = m.operation;const body = m.body;const id = crypto.randomUUID().replaceAll('-', '');active = owner;
    let port: chrome.runtime.Port | undefined;let timer: ReturnType<typeof setTimeout>;
    const finish = (result?: unknown, error?: string) => { dispose?.();emit(error ? { error } : { result }); };
    const disconnect = () => { void api().runtime.lastError;finish(undefined, 'helper-unavailable'); };
    const reply = (v: unknown) => {
      if (!native || native !== port) return;
      if (!object(v) || new TextEncoder().encode(JSON.stringify(v)).length > 131072 || v.profile !== NATIVE || v.id !== id || !flags(v)) {
        finish(undefined, 'unsupported-helper');return;
      }
      if (v.status === 'rejected' && exact(v, ['profile', 'id', 'status', 'code', 'recoverable', 'laboratory', 'verified'])
          && v.code === 'native-operation-unavailable' && v.recoverable === true) { finish(undefined, 'recovery-needed');return; }
      if (v.status !== 'ok' || !exact(v, ['profile', 'id', 'status', 'result', 'laboratory', 'verified']) || !factProjection(op, v.result, body)) {
        finish(undefined, 'unsupported-helper');return;
      }
      finish(structuredClone(v.result));
    };
    dispose = () => {
      clearTimeout(timer);const old = native;native = undefined;
      old?.onMessage.removeListener(reply);old?.onDisconnect.removeListener(disconnect);old?.disconnect();
      if (active === owner) active = undefined;
    };
    try {
      port = api().runtime.connectNative('com.nockapp.zkid');native = port;
      port.onMessage.addListener(reply);port.onDisconnect.addListener(disconnect);
      timer = setTimeout(() => finish(undefined, 'recovery-needed'), 185000);
      port.postMessage({ profile: NATIVE, id, operation: op, body });
    } catch { finish(undefined, 'helper-unavailable'); }
  });
}

let queue: Promise<unknown> = Promise.resolve();
export function factOperation<T = unknown>(op: FactOperation, body: Record<string, unknown> = {}, signal?: AbortSignal): Promise<T> {
  const captured = structuredClone(body);
  const run = () => new Promise<T>((resolve, reject) => {
    if (!validFactBody(op, captured) || signal?.aborted) { reject(new FactError('message-schema'));return; }
    let port: chrome.runtime.Port | undefined;let settled = false;let timer: ReturnType<typeof setTimeout>;
    const done = (value?: T, error?: string) => {
      if (settled) return;settled = true;clearTimeout(timer);signal?.removeEventListener('abort', abort);port?.disconnect();
      if (error) reject(new FactError(error));else resolve(value!);
    };
    const abort = () => done(undefined, 'recovery-needed');signal?.addEventListener('abort', abort, { once: true });
    try {
      port = api().runtime.connect({ name: FACT_PORT });
      port.onDisconnect.addListener(() => { void api().runtime.lastError;done(undefined, 'helper-unavailable'); });
      port.onMessage.addListener((v: unknown) => {
        if (!object(v) || v.version !== FACT_VERSION) { done(undefined, 'page-update-required');return; }
        if (exact(v, ['version', 'error']) && typeof v.error === 'string'
            && ['helper-busy', 'helper-unavailable', 'recovery-needed', 'unsupported-helper', 'message-schema'].includes(v.error)) done(undefined, v.error);
        else if (exact(v, ['version', 'result']) && factProjection(op, v.result, captured)) done(v.result as T);
        else done(undefined, 'unsupported-helper');
      });
      timer = setTimeout(() => done(undefined, 'recovery-needed'), 190000);
      port.postMessage({ version: FACT_VERSION, operation: op, body: captured });
    } catch { done(undefined, 'helper-unavailable'); }
  });
  const result = queue.then(run);queue = result.catch(() => undefined);return result;
}
