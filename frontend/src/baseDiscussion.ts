import { api } from './platform/browser';
import type { ZkidFact } from './model';
import { exact, object, validWirePost, validZkidFacts, sortedFacts, hex, wirePayload, type WirePost } from './zkidWire';

export const BASE_VERSION = 'base-discussion-1-readonly-1';
export const BASE_PORT = 'base-discussion';
const NATIVE = 'nockapp-zkid-public-post-native-v1';
export type BaseOperation = 'base-capabilities' | 'base-outbox' | 'base-publish' | 'base-recover' | 'base-check-existing' | 'base-discussion';
export type SubmissionState = 'pending' | 'confirmed' | 'finalized' | 'failed' | 'recoverable';
export type BaseIdentity = { profile: string; protocol: string; chain_id: number; contract: string; registry: string;
  application: string; definition_hash: string; native_sha256: string };
export type Submission = { post: WirePost; facts: ZkidFact[]; submission_id: string; phase: string; experimental: true;
  status: { state: SubmissionState; transaction_hash?: string; post_number?: string | null; checked_at?: number } };
export type SharedPost = { post: WirePost; post_number: string; facts: ZkidFact[]; state: 'finalized'; submission_id: string;
  valid_when_published: true; accepted_at: number; observed_at: number | null; credential_expiry: number | null;
  credential_status: string; public_id: null; laboratory_only: true; publication_registry_hash?: string };
export type DiscussionPage = { identity: BaseIdentity; posts: SharedPost[]; unavailable: unknown[]; next_after: number;
  more: boolean; sync_complete: boolean; checkpoint: { number: string; hash: string }; experimental: true };
export class BaseError extends Error {
  constructor(public code: string) { super('Shared posting is unavailable. Your draft and saved submission are preserved; use Recover to retry.'); }
}
const flags = (v: Record<string, unknown>) => v.laboratory === true && v.verified === false;
const integer = (v: unknown, min = 0): v is number => Number.isSafeInteger(v) && Number(v) >= min;
const number = (v: unknown) => typeof v === 'string' && /^[1-9][0-9]{0,15}$/.test(v) && Number.isSafeInteger(Number(v));
const hash = (v: unknown) => typeof v === 'string' && /^0x[0-9a-f]{64}$/.test(v);
const uuid = (v: unknown) => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const selected = (v: unknown): v is ZkidFact[] => validZkidFacts(v) && JSON.stringify(v) === JSON.stringify(sortedFacts(v));
export function validBaseIdentity(v: unknown): v is BaseIdentity {
  return object(v) && exact(v, ['profile', 'protocol', 'chain_id', 'contract', 'registry', 'application', 'definition_hash', 'native_sha256'])
    && v.profile === 'nockapp-base-service-identity-v1' && v.protocol === 'nockapp-base-post-v1' && v.chain_id === 84532
    && [v.contract, v.registry].every(x => typeof x === 'string' && /^0x[0-9a-f]{40}$/.test(x) && !/^0x0+$/.test(x))
    && hash(v.application) && hex(v.definition_hash) && hex(v.native_sha256);
}
function validStatus(v: unknown): boolean {
  return object(v) && Object.keys(v).every(k => ['state', 'transaction_hash', 'post_number', 'checked_at'].includes(k))
    && ['pending', 'confirmed', 'finalized', 'failed', 'recoverable'].includes(String(v.state))
    && (v.checked_at === undefined || integer(v.checked_at, 1)) && (v.transaction_hash === undefined || hash(v.transaction_hash))
    && (v.state === 'finalized' ? hash(v.transaction_hash) && number(v.post_number) && integer(v.checked_at, 1)
      : v.post_number === undefined || v.post_number === null);
}
export function validSubmission(v: unknown): v is Submission {
  return object(v) && exact(v, ['post', 'facts', 'submission_id', 'phase', 'status', 'experimental']) && v.experimental === true
    && validWirePost(v.post) && v.post.claims.length === 0 && selected(v.facts) && hex(v.submission_id) && validStatus(v.status)
    && ['prepared', 'challenge-saved', 'proof-saved', 'submitted'].includes(String(v.phase));
}
function validSharedPost(v: unknown): v is SharedPost {
  if (!object(v) || !exact(v, ['post', 'post_number', 'facts', 'state', 'submission_id', 'valid_when_published', 'accepted_at',
    'observed_at', 'credential_expiry', 'credential_status', 'public_id', 'laboratory_only', ...(v.publication_registry_hash === undefined ? [] : ['publication_registry_hash'])])
    || !validWirePost(v.post) || v.post.claims.length !== 0 || !number(v.post_number) || !selected(v.facts) || !hex(v.submission_id)
    || v.state !== 'finalized' || v.valid_when_published !== true || !integer(v.accepted_at, 1) || v.public_id !== null || v.laboratory_only !== true) return false;
  return v.facts.length === 0 ? v.credential_status === 'not-requested' && v.observed_at === null && v.credential_expiry === null && v.publication_registry_hash === undefined
    : integer(v.observed_at, 1) && integer(v.credential_expiry, Number(v.observed_at) + 1) && hash(v.publication_registry_hash)
      && ['expired', 'valid-at-current-registry', 'unknown-after-registry-update'].includes(String(v.credential_status));
}
export function validBaseBody(op: string, b: Record<string, unknown>): op is BaseOperation {
  if (op === 'base-capabilities') return exact(b, []);
  if (op === 'base-recover' || op === 'base-check-existing') return exact(b, ['post_id']) && uuid(b.post_id);
  if (op === 'base-publish') return exact(b, ['post', 'facts', 'approve_publication']) && validWirePost(b.post)
    && b.post.claims.length === 0 && selected(b.facts) && b.approve_publication === true;
  return ['base-discussion', 'base-outbox'].includes(op) && exact(b, ['after', 'limit']) && integer(b.after)
    && integer(b.limit, 1) && Number(b.limit) <= (op === 'base-outbox' ? 8 : 20) && (op !== 'base-outbox' || Number(b.after) <= 100);
}
export function baseProjection(op: BaseOperation, v: unknown, body: Record<string, unknown> = {}): boolean {
  if (!object(v) || v.experimental !== true) return false;
  if (op === 'base-capabilities') return typeof v.configured === 'boolean' && (v.configured
    ? exact(v, ['configured', 'identity', 'experimental']) && validBaseIdentity(v.identity) : exact(v, ['configured', 'experimental']));
  if (op === 'base-publish' || op === 'base-recover' || op === 'base-check-existing') return validSubmission(v)
    && (body.post === undefined || validWirePost(body.post) && wirePayload(v.post) === wirePayload(body.post) && JSON.stringify(v.facts) === JSON.stringify(body.facts))
    && (body.post_id === undefined || v.post.id === body.post_id);
  if (op === 'base-outbox') return exact(v, ['entries', 'next_after', 'more', 'experimental']) && Array.isArray(v.entries)
    && v.entries.length <= 8 && v.entries.every(validSubmission) && integer(v.next_after) && typeof v.more === 'boolean'
    && v.next_after === Number(body.after) + v.entries.length;
  return exact(v, ['identity', 'posts', 'unavailable', 'next_after', 'more', 'sync_complete', 'checkpoint', 'experimental'])
    && validBaseIdentity(v.identity) && Array.isArray(v.posts) && v.posts.length <= Number(body.limit ?? 20) && v.posts.every(validSharedPost)
    && v.posts.every((p, i, all) => Number(p.post_number) > (i ? Number(all[i - 1].post_number) : Number(body.after ?? 0)))
    && integer(v.next_after) && v.next_after === (v.posts.length ? Number(v.posts.at(-1)!.post_number) : Number(body.after ?? 0))
    && typeof v.more === 'boolean' && typeof v.sync_complete === 'boolean' && object(v.checkpoint)
    && exact(v.checkpoint, ['number', 'hash']) && typeof v.checkpoint.number === 'string' && /^0x[0-9a-f]+$/.test(v.checkpoint.number)
    && hash(v.checkpoint.hash) && Array.isArray(v.unavailable) && v.unavailable.length <= 20
    && v.unavailable.every(x => object(x) && exact(x, ['submission_id', 'state', 'valid_when_published', 'credential_status'])
      && (x.submission_id === null || hex(x.submission_id)) && x.state === 'unavailable' && x.valid_when_published === false && x.credential_status === 'unavailable');
}

let active: symbol | undefined;
/** Called only for exact sidepanel admission in background.ts. */
export function attachBaseDiscussion(ui: chrome.runtime.Port) {
  let native: chrome.runtime.Port | undefined;let dispose: (() => void) | undefined;let connected = true;
  const owner = Symbol('zkid-post-fact');
  const emit = (value: object) => { if (connected) try { ui.postMessage({ version: BASE_VERSION, ...value }); } catch { connected = false;dispose?.(); } };
  ui.onDisconnect.addListener(() => { connected = false;dispose?.(); });
  ui.onMessage.addListener((m: unknown) => {
    if (!connected) return;
    if (native) return;
    if (!object(m) || !exact(m, ['version', 'operation', 'body']) || m.version !== BASE_VERSION || typeof m.operation !== 'string'
        || ['base-publish', 'base-recover'].includes(m.operation) || !object(m.body) || !validBaseBody(m.operation, m.body) || new TextEncoder().encode(JSON.stringify(m)).length > 131072) {
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
      if (v.status !== 'ok' || !exact(v, ['profile', 'id', 'status', 'result', 'laboratory', 'verified']) || !baseProjection(op, v.result, body)) {
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
export function baseOperation<T = unknown>(op: BaseOperation, body: Record<string, unknown> = {}, signal?: AbortSignal): Promise<T> {
  const captured = structuredClone(body);
  const run = () => new Promise<T>((resolve, reject) => {
    if (!validBaseBody(op, captured) || signal?.aborted) { reject(new BaseError('message-schema'));return; }
    let port: chrome.runtime.Port | undefined;let settled = false;let timer: ReturnType<typeof setTimeout>;
    const done = (value?: T, error?: string) => {
      if (settled) return;settled = true;clearTimeout(timer);signal?.removeEventListener('abort', abort);port?.disconnect();
      if (error) reject(new BaseError(error));else resolve(value!);
    };
    const abort = () => done(undefined, 'recovery-needed');signal?.addEventListener('abort', abort, { once: true });
    try {
      port = api().runtime.connect({ name: BASE_PORT });
      port.onDisconnect.addListener(() => { void api().runtime.lastError;done(undefined, 'helper-unavailable'); });
      port.onMessage.addListener((v: unknown) => {
        if (!object(v) || v.version !== BASE_VERSION) { done(undefined, 'page-update-required');return; }
        if (exact(v, ['version', 'error']) && typeof v.error === 'string'
            && ['helper-busy', 'helper-unavailable', 'recovery-needed', 'unsupported-helper', 'message-schema'].includes(v.error)) done(undefined, v.error);
        else if (exact(v, ['version', 'result']) && baseProjection(op, v.result, captured)) done(v.result as T);
        else done(undefined, 'unsupported-helper');
      });
      timer = setTimeout(() => done(undefined, 'recovery-needed'), 190000);
      port.postMessage({ version: BASE_VERSION, operation: op, body: captured });
    } catch { done(undefined, 'helper-unavailable'); }
  });
  const result = queue.then(run);queue = result.catch(() => undefined);return result;
}
