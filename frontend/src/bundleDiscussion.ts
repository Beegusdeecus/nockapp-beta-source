import { api } from './platform/browser';
import { exact, object, validWirePost, hex, wirePayload, type WirePost } from './zkidWire';
import { ARCHIVE_PROFILE, validArchiveRecord, validArchiveScope } from './bundleArchive';
import { publicSummary, type PublicSummary } from './publicPostFlow';

export const BUNDLE_VERSION = 'bundle-discussion-3-readonly-1';
export const BUNDLE_PORT = 'bundle-discussion';
const NATIVE = 'nockapp-zkid-public-post-native-v1';
export type Selection = { credential_kind: 0 | 1 | 2; facts: string[]; threshold: number | null };
export const ordinary: Selection = { credential_kind: 0, facts: [], threshold: null };
export type BundleOperation = 'bundle-capabilities' | 'bundle-outbox' | 'bundle-publish' | 'bundle-recover' | 'bundle-check-existing' | 'bundle-threads'
  | 'bundle-renew' | 'bundle-thread' | 'bundle-numbers' | 'bundle-clear-cache' | 'count-status' | 'count-begin' | 'count-check-post'
  | 'count-poll-registration' | 'count-recover' | 'count-cancel' | 'bundle-export-public' | 'bundle-import-public';
export type Identity = { profile: string; protocol: 3; chain_id: 84532; contract: string; registry: string; application: string;
  definition_hash: string; native_sha256: string; count_native_sha256: string | null; bundle_profile: string;
  storage: { replicas: { name: string; failure_domain: string }[]; retention_seconds: number; max_bundle_bytes: number; permanent_availability_proven: false } };
export type Status = { state: 'pending' | 'confirmed' | 'finalized' | 'failed' | 'recoverable'; transaction_hash?: string;
  post_number?: string | null; checked_at?: number; recovery_action?: 'renew-expired-proof' | 'check-credential-or-selection'; content_state?: string; credential_evidence_checked?: boolean; evidence_state?: string;
  last_known?: { state: string; transaction_hash: string; post_number: string | null; checked_at: number } };
export type Submission = { post: WirePost; selection: Selection; submission_id: string; phase: string; status: Status; renewal_count?: number; experimental: true };
export type Row = { ordinal?: number; state: string; post_number?: string; canonical_accepted: boolean; post?: WirePost | null;
  selection?: Selection; thread_id?: string; credential_kind?: number; content_integrity_checked?: boolean; credential_evidence_checked?: boolean;
  valid_when_published?: boolean | null; credential_status?: string; accepted_at?: number; observed_at?: number; credential_expiry?: number;
  disclosed_follower_count?: number | null };
export type Page = { identity: Identity; posts: Row[]; scope: string; thread_id: string | null; thread_accepted: boolean | null;
  canonical_total_count: string; last_canonical_number: string; after: number; next_after: number; more: boolean; index_gaps: number[];
  page_complete: boolean; listing_complete: boolean; page_content_complete: boolean; content_complete: boolean; page_evidence_complete: boolean;
  global_listing_complete: false; checkpoint: { number: string; hash: string }; experimental: true };
export type CountStatus = { state: Exclude<PublicSummary['state'], 'forgotten'>; credential_saved: boolean; username?: string; post_text?: string; expires_at?: number;
  next_check_at?: number; laboratory: true; verified: false };
export class BundleError extends Error {
  constructor(public code: string) { super('Shared posting is unavailable. Your draft and saved submission are preserved. Check the v3 helper or use Recover.'); }
}
const flags = (v: Record<string, unknown>) => v.laboratory === true && v.verified === false;
const integer = (v: unknown, min = 0): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= min;
const hash = (v: unknown): v is string => typeof v === 'string' && /^0x[0-9a-f]{64}$/.test(v);
const uuid = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const number = (v: unknown, zero = false): v is string => typeof v === 'string' && /^(0|[1-9][0-9]{0,15})$/.test(v) && integer(Number(v), zero ? 0 : 1);
const subset = (v: Record<string, unknown>, keys: string[]) => Object.keys(v).every(k => keys.includes(k));
export function validSelection(v: unknown): v is Selection {
  if (!object(v) || !exact(v, ['credential_kind', 'facts', 'threshold']) || ![0, 1, 2].includes(Number(v.credential_kind))
    || !integer(v.credential_kind) || !Array.isArray(v.facts) || v.facts.some(f => typeof f !== 'string')
    || new Set(v.facts).size !== v.facts.length || JSON.stringify(v.facts) !== JSON.stringify([...v.facts].sort())) return false;
  if (v.credential_kind === 0) return v.facts.length === 0 && v.threshold === null;
  const allowed = v.credential_kind === 1 ? ['account-controlled', 'followers-at-least-10000'] : ['account-controlled', 'followers-more-than', 'follower-count'];
  return v.facts.length >= 1 && v.facts.every(f => allowed.includes(f))
    && (v.facts.includes('followers-more-than') ? integer(v.threshold) && v.threshold < Number.MAX_SAFE_INTEGER : v.threshold === null);
}
export function validIdentity(v: unknown): v is Identity {
  if (!object(v) || !exact(v, ['profile', 'protocol', 'chain_id', 'contract', 'registry', 'application', 'definition_hash', 'native_sha256', 'count_native_sha256', 'bundle_profile', 'storage'])
    || v.profile !== 'nockapp-bundle-service-identity-v3' || v.protocol !== 3 || v.chain_id !== 84532
    || v.bundle_profile !== 'nockapp-public-discussion-bundle-v3' || !hash(v.application) || /^0x0+$/.test(v.application) || !hex(v.definition_hash) || !hex(v.native_sha256)
    || !(v.count_native_sha256 === null || hex(v.count_native_sha256))
    || ![v.contract, v.registry].every(x => typeof x === 'string' && /^0x[0-9a-f]{40}$/.test(x) && !/^0x0+$/.test(x))) return false;
  const s = v.storage;
  return object(s) && exact(s, ['replicas', 'retention_seconds', 'max_bundle_bytes', 'permanent_availability_proven'])
    && s.permanent_availability_proven === false && s.max_bundle_bytes === 32768 && integer(s.retention_seconds, 90 * 86400) && s.retention_seconds <= 365 * 86400
    && Array.isArray(s.replicas) && s.replicas.length >= 2 && s.replicas.length <= 4 && s.replicas.every(r => object(r)
      && exact(r, ['name', 'failure_domain']) && typeof r.name === 'string' && /^[a-z0-9][a-z0-9-]{2,63}$/.test(r.name)
      && typeof r.failure_domain === 'string' && r.failure_domain.length >= 3 && r.failure_domain.length <= 128)
    && new Set(s.replicas.map(r => r.name)).size === s.replicas.length && new Set(s.replicas.map(r => r.failure_domain)).size === s.replicas.length;
}
function status(v: unknown): boolean {
  if (!object(v) || !subset(v, ['state', 'transaction_hash', 'post_number', 'checked_at', 'content_state', 'credential_evidence_checked', 'evidence_state', 'last_known', 'recovery_action'])
    || !['pending', 'confirmed', 'finalized', 'failed', 'recoverable'].includes(String(v.state))
    || (v.recovery_action !== undefined && (v.state !== 'recoverable' || !['renew-expired-proof', 'check-credential-or-selection'].includes(String(v.recovery_action))))
    || (v.checked_at !== undefined && !integer(v.checked_at, 1)) || (v.transaction_hash !== undefined && !hash(v.transaction_hash))
    || (v.state === 'finalized' ? !number(v.post_number) || !hash(v.transaction_hash) : v.post_number !== undefined && v.post_number !== null)
    || (v.content_state !== undefined && v.content_state !== 'locally-retained')
    || (v.credential_evidence_checked !== undefined && typeof v.credential_evidence_checked !== 'boolean')
    || (v.evidence_state !== undefined && !['not-requested', 'checked-at-acceptance', 'verification-unavailable-or-failed'].includes(String(v.evidence_state)))) return false;
  return v.last_known === undefined || object(v.last_known) && exact(v.last_known, ['state', 'transaction_hash', 'post_number', 'checked_at'])
    && ['finalized', 'failed'].includes(String(v.last_known.state)) && hash(v.last_known.transaction_hash) && integer(v.last_known.checked_at, 1)
    && (v.last_known.post_number === null || number(v.last_known.post_number));
}
export function validSubmission(v: unknown): v is Submission {
  return object(v) && exact(v, ['post', 'selection', 'submission_id', 'phase', 'status', 'experimental', ...(v.renewal_count === undefined ? [] : ['renewal_count'])])
    && (v.renewal_count === undefined || integer(v.renewal_count, 1) && v.renewal_count <= 3) && v.experimental === true
    && validWirePost(v.post) && !v.post.claims.length && validSelection(v.selection) && hex(v.submission_id) && status(v.status)
    && ['prepared', 'challenge-saved', 'bundle-saved', 'submitted'].includes(String(v.phase));
}
const header = ['submission_id', 'post_id', 'thread_id', 'bundle_hash', 'registry_hash', 'registry_sequence', 'post_number', 'accepted_at', 'observed_at', 'credential_expiry', 'credential_kind', 'block_hash', 'block_number', 'transaction_hash'];
export function validRow(v: unknown): v is Row {
  if (!object(v)) return false;
  if (['index-gap', 'not-accepted', 'acceptance-unavailable'].includes(String(v.state))) return v.canonical_accepted === false
    && subset(v, ['ordinal', 'state', 'canonical_accepted', 'post', 'post_number']) && (v.post === undefined || v.post === null)
    && (v.ordinal === undefined || integer(v.ordinal, 1)) && (v.post_number === undefined || number(v.post_number));
  if (!subset(v, [...header, 'ordinal', 'state', 'canonical_accepted', 'post', 'content_integrity_checked', 'credential_evidence_checked',
    'valid_when_published', 'credential_status', 'selection', 'disclosed_follower_count', 'public_id', 'content_source', 'experimental'])
    || !header.every(k => k in v) || v.canonical_accepted !== true || !hex(v.submission_id) || !number(v.post_number)
    || !['post_id', 'thread_id', 'bundle_hash', 'registry_hash', 'block_hash', 'transaction_hash'].every(k => hash(v[k]))
    || !['registry_sequence', 'accepted_at', 'observed_at', 'credential_expiry', 'block_number'].every(k => integer(v[k]))
    || !integer(v.credential_kind) || Number(v.credential_kind) > 2 || (v.ordinal !== undefined && !integer(v.ordinal, 1))) return false;
  if (v.state === 'content-unavailable') return v.post === null && v.content_integrity_checked === false && v.credential_evidence_checked === false
    && v.valid_when_published === null && v.credential_status === 'unavailable' && v.selection === undefined
    && ['disclosed_follower_count', 'public_id', 'content_source', 'experimental'].every(k => v[k] === undefined);
  if (!validWirePost(v.post) || v.post.claims.length || v.content_integrity_checked !== true || !validSelection(v.selection)
    || v.selection.credential_kind !== v.credential_kind) return false;
  if (v.state === 'evidence-unavailable' || v.state === 'verification-failed') return v.credential_evidence_checked === false
    && v.valid_when_published === (v.state === 'evidence-unavailable' ? null : false)
    && v.credential_status === (v.state === 'evidence-unavailable' ? 'unavailable' : 'invalid')
    && ['disclosed_follower_count', 'public_id', 'content_source', 'experimental'].every(k => v[k] === undefined);
  return v.state === 'finalized' && v.valid_when_published === true && v.experimental === true && v.public_id === null
    && typeof v.content_source === 'string' && v.content_source.length <= 64
    && v.credential_evidence_checked === (v.credential_kind !== 0)
    && (v.credential_kind === 0 ? v.credential_status === 'not-requested' && v.observed_at === 0 && v.credential_expiry === 0
      : ['valid-at-current-registry', 'expired', 'unknown-after-registry-update'].includes(String(v.credential_status)))
    && (v.selection.facts.includes('follower-count') ? integer(v.disclosed_follower_count) : v.disclosed_follower_count === null);
}
function validPage(v: Record<string, unknown>, body: Record<string, unknown>, thread: boolean): boolean {
  if (!exact(v, ['identity', 'posts', 'scope', 'thread_id', 'thread_accepted', 'canonical_total_count', 'last_canonical_number', 'after', 'next_after', 'more', 'index_gaps', 'page_complete', 'listing_complete', 'global_listing_complete', 'page_content_complete', 'content_complete', 'page_evidence_complete', 'checkpoint', 'experimental'])
    || !validIdentity(v.identity) || !Array.isArray(v.posts) || !v.posts.every(validRow) || !number(v.canonical_total_count, true)
    || !number(v.last_canonical_number, true) || v.after !== body.after || !integer(v.next_after) || v.next_after !== Math.min(Number(v.canonical_total_count), Number(body.after) + Number(body.limit))
    || v.posts.length !== v.next_after - Number(body.after) || !v.posts.every((p, i) => p.ordinal === Number(body.after) + i + 1)
    || v.scope !== (thread ? 'thread' : 'thread-catalog') || (thread ? v.thread_id !== body.thread_id || typeof v.thread_accepted !== 'boolean' : v.thread_id !== null || v.thread_accepted !== null)
    || !Array.isArray(v.index_gaps) || v.index_gaps.some(n => !integer(n, 1) || n <= Number(body.after) || n > Number(v.next_after))
    || new Set(v.index_gaps).size !== v.index_gaps.length || v.more !== (v.next_after < Number(v.canonical_total_count))
    || v.global_listing_complete !== false || v.page_complete !== (v.index_gaps.length === 0)
    || v.listing_complete !== (body.after === 0 && v.next_after === Number(v.canonical_total_count) && v.index_gaps.length === 0)
    || !object(v.checkpoint) || !exact(v.checkpoint, ['number', 'hash']) || typeof v.checkpoint.number !== 'string' || !/^0x[0-9a-f]+$/.test(v.checkpoint.number) || !hash(v.checkpoint.hash)) return false;
  const gaps = v.index_gaps as number[];
  return v.experimental === true && v.posts.every(p => (p.ordinal !== undefined && gaps.includes(p.ordinal)) === (p.state === 'index-gap'))
    && v.page_content_complete === (!v.index_gaps.length && v.posts.every(p => p.content_integrity_checked === true))
    && v.content_complete === (v.listing_complete && v.posts.every(p => p.content_integrity_checked === true))
    && v.page_evidence_complete === (!v.index_gaps.length && v.posts.every(p => p.credential_kind === 0 || p.credential_evidence_checked === true));
}
export function validBundleBody(op: string, b: Record<string, unknown>): op is BundleOperation {
  if (op === 'bundle-capabilities' || ['count-status', 'count-recover', 'count-cancel'].includes(op)) return exact(b, []);
  if (op === 'bundle-publish') return exact(b, ['post', 'selection', 'approve_publication']) && validWirePost(b.post) && !b.post.claims.length && validSelection(b.selection) && b.approve_publication === true;
  if (op === 'bundle-renew') return exact(b, ['post_id', 'expected_submission_id', 'approve_fresh_proof']) && uuid(b.post_id) && hex(b.expected_submission_id) && b.approve_fresh_proof === true;
  if (op === 'bundle-recover' || op === 'bundle-check-existing') return exact(b, ['post_id']) && uuid(b.post_id);
  if (op === 'bundle-clear-cache') return exact(b, ['confirm_cache_clear']) && b.confirm_cache_clear === true;
  if (op === 'bundle-export-public') return exact(b, ['post_number', 'approve_public_export']) && integer(b.post_number, 1) && b.approve_public_export === true;
  if (op === 'bundle-import-public') return exact(b, ['scope', 'record', 'confirm_public_archive_import'])
    && validArchiveScope(b.scope) && validArchiveRecord(b.record) && b.confirm_public_archive_import === true;
  if (op === 'count-begin') return exact(b, ['username', 'approve_public_profile_lookup']) && typeof b.username === 'string' && /^[A-Za-z0-9_]{1,15}$/.test(b.username) && b.approve_public_profile_lookup === true;
  if (op === 'count-check-post') return exact(b, ['post', 'approve_source_check']) && typeof b.post === 'string' && b.post.length > 0 && b.post.length <= 512 && b.approve_source_check === true;
  if (op === 'count-poll-registration') return exact(b, ['approve_source_check']) && b.approve_source_check === true;
  if (op === 'bundle-numbers') return exact(b, ['numbers']) && Array.isArray(b.numbers) && b.numbers.length > 0 && b.numbers.length <= 8 && new Set(b.numbers).size === b.numbers.length && b.numbers.every(n => integer(n, 1));
  return ['bundle-outbox', 'bundle-threads', 'bundle-thread'].includes(op) && exact(b, op === 'bundle-thread' ? ['thread_id', 'after', 'limit'] : ['after', 'limit'])
    && integer(b.after) && integer(b.limit, 1) && b.limit <= 8 && (op !== 'bundle-outbox' || b.after <= 100) && (op !== 'bundle-thread' || hash(b.thread_id));
}
export function bundleProjection(op: BundleOperation, v: unknown, b: Record<string, unknown> = {}): boolean {
  if (!object(v)) return false;
  if (op.startsWith('count-')) return publicSummary(v, op === 'count-poll-registration' ? 'poll-registration' : undefined) !== undefined;
  if (v.experimental !== true) return false;
  if (op === 'bundle-capabilities') return v.configured === false ? exact(v, ['configured', 'experimental']) : v.configured === true
    && exact(v, ['configured', 'identity', 'count_enrollment_configured', 'experimental']) && validIdentity(v.identity) && typeof v.count_enrollment_configured === 'boolean';
  if (op === 'bundle-publish' || op === 'bundle-recover' || op === 'bundle-check-existing' || op === 'bundle-renew') return validSubmission(v)
    && (b.post === undefined || validWirePost(b.post) && wirePayload(v.post) === wirePayload(b.post) && JSON.stringify(v.selection) === JSON.stringify(b.selection))
    && (b.post_id === undefined || v.post.id === b.post_id)
    && (op !== 'bundle-renew' || v.renewal_count !== undefined && v.submission_id !== b.expected_submission_id);
  if (op === 'bundle-outbox') return exact(v, ['entries', 'next_after', 'more', 'experimental']) && Array.isArray(v.entries)
    && v.entries.length <= Number(b.limit) && v.entries.every(validSubmission) && v.next_after === Number(b.after) + v.entries.length && typeof v.more === 'boolean';
  if (op === 'bundle-clear-cache') return exact(v, ['cleared_bundles', 'remote_records_deleted', 'drafts_deleted', 'experimental']) && integer(v.cleared_bundles) && v.remote_records_deleted === false && v.drafts_deleted === false;
  if (op === 'bundle-export-public') return exact(v, ['profile', 'scope', 'record', 'experimental']) && v.profile === ARCHIVE_PROFILE
    && validArchiveScope(v.scope) && validArchiveRecord(v.record) && v.record.post_number === String(b.post_number);
  if (op === 'bundle-import-public') return exact(v, ['post_number', 'bundle_hash', 'cached', 'verification_required', 'experimental'])
    && object(b.record) && v.post_number === b.record.post_number && v.bundle_hash === b.record.bundle_hash
    && typeof v.cached === 'boolean' && v.verification_required === true;
  if (op === 'bundle-numbers') return exact(v, ['identity', 'posts', 'last_canonical_number', 'checkpoint', 'scope', 'global_listing_complete', 'experimental'])
    && validIdentity(v.identity) && v.scope === 'explicit-post-numbers' && v.global_listing_complete === false && Array.isArray(v.posts)
    && number(v.last_canonical_number, true) && object(v.checkpoint) && exact(v.checkpoint, ['number', 'hash'])
    && typeof v.checkpoint.number === 'string' && /^0x[0-9a-f]+$/.test(v.checkpoint.number) && hash(v.checkpoint.hash)
    && Array.isArray(b.numbers) && v.posts.length === b.numbers.length && v.posts.every((p, i) => validRow(p) && p.post_number === String((b.numbers as number[])[i]));
  return validPage(v, b, op === 'bundle-thread');
}

let active: symbol | undefined;
/** Called only for exact sidepanel admission in background.ts. */
export function attachBundleDiscussion(ui: chrome.runtime.Port) {
  let native: chrome.runtime.Port | undefined;let dispose: (() => void) | undefined;let connected = true;
  const owner = Symbol('zkid-post-fact');
  const emit = (value: object) => { if (connected) try { ui.postMessage({ version: BUNDLE_VERSION, ...value }); } catch { connected = false;dispose?.(); } };
  ui.onDisconnect.addListener(() => { connected = false;dispose?.(); });
  ui.onMessage.addListener((m: unknown) => {
    if (!connected) return;
    if (native) return;
    if (!object(m) || !exact(m, ['version', 'operation', 'body']) || m.version !== BUNDLE_VERSION || typeof m.operation !== 'string'
        || ['bundle-publish', 'bundle-renew', 'bundle-recover', 'count-begin', 'count-check-post', 'count-poll-registration'].includes(m.operation)
        || !object(m.body) || !validBundleBody(m.operation, m.body) || new TextEncoder().encode(JSON.stringify(m)).length > 131072) {
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
      if (v.status !== 'ok' || !exact(v, ['profile', 'id', 'status', 'result', 'laboratory', 'verified']) || !bundleProjection(op, v.result, body)) {
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
export function bundleOperation<T = unknown>(op: BundleOperation, body: Record<string, unknown> = {}, signal?: AbortSignal): Promise<T> {
  const captured = structuredClone(body);
  const run = () => new Promise<T>((resolve, reject) => {
    if (!validBundleBody(op, captured) || signal?.aborted) { reject(new BundleError('message-schema'));return; }
    let port: chrome.runtime.Port | undefined;let settled = false;let timer: ReturnType<typeof setTimeout>;
    const done = (value?: T, error?: string) => {
      if (settled) return;settled = true;clearTimeout(timer);signal?.removeEventListener('abort', abort);port?.disconnect();
      if (error) reject(new BundleError(error));else resolve(value!);
    };
    const abort = () => done(undefined, 'recovery-needed');signal?.addEventListener('abort', abort, { once: true });
    try {
      port = api().runtime.connect({ name: BUNDLE_PORT });
      port.onDisconnect.addListener(() => { void api().runtime.lastError;done(undefined, 'helper-unavailable'); });
      port.onMessage.addListener((v: unknown) => {
        if (!object(v) || v.version !== BUNDLE_VERSION) { done(undefined, 'page-update-required');return; }
        if (exact(v, ['version', 'error']) && typeof v.error === 'string'
            && ['helper-busy', 'helper-unavailable', 'recovery-needed', 'unsupported-helper', 'message-schema'].includes(v.error)) done(undefined, v.error);
        else if (exact(v, ['version', 'result']) && bundleProjection(op, v.result, captured)) done(v.result as T);
        else done(undefined, 'unsupported-helper');
      });
      timer = setTimeout(() => done(undefined, 'recovery-needed'), 190000);
      port.postMessage({ version: BUNDLE_VERSION, operation: op, body: captured });
    } catch { done(undefined, 'helper-unavailable'); }
  });
  const result = queue.then(run);queue = result.catch(() => undefined);return result;
}
