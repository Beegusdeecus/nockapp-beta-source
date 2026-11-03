import { historyBody, historyProjection } from './authoredHistory';
/** Version4 helper admission, independent of retained v3 wire/data. */
import { api } from './platform/browser';
import { exact, object, validWirePost, wirePayload, type WirePost } from './zkidWire';
import { validIdentity as legacyIdentity, validRow as legacyRow, validBundleBody, bundleProjection, type Identity as LegacyIdentity, type Row as LegacyRow, type Page as LegacyPage, type BundleOperation } from './bundleDiscussion';
import { canonicalAscii, validPostWalletRequestShape, type AddressSelection, type PostSigningScope } from './authoredWallet';
export const AUTHORED_PORT = 'nockapp-authored-discussion';
export const AUTHORED_VERSION = 'nockapp-authored-discussion-4';
const NATIVE = 'nockapp-zkid-public-post-native-v1';
const hex = (v: unknown, n = 64): v is string => typeof v === 'string' && new RegExp(`^[0-9a-f]{${n}}$`).test(v) && !/^0+$/.test(v);
const hash = (v: unknown): v is string => typeof v === 'string' && v.startsWith('0x') && hex(v.slice(2));
const uuid = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
export type AuthoredIdentity = PostSigningScope & { profile: 'nockapp-bundle-service-identity-v4'; protocol: 4; registry: string;
  definition_hash: string; native_sha256: string; count_native_sha256: string | null; author_native_sha256: string;
  bundle_profile: 'nockapp-public-discussion-bundle-v4'; storage: LegacyIdentity['storage'] };
export type Row = Omit<LegacyRow, 'selection'> & { selection?: AddressSelection; authorship_checked?: boolean; address_evidence_checked?: boolean; public_address?: string | null };
export type Page = Omit<LegacyPage, 'identity' | 'posts'> & { identity: AuthoredIdentity; posts: Row[] };
export type PostStatus = { state: 'pending' | 'confirmed' | 'finalized' | 'failed' | 'recoverable'; checked_at: number; post_number?: string | null; transaction_hash?: string; recovery_action?: string;
  authorship_checked: boolean; address_evidence_checked: boolean; credential_evidence_checked: boolean; last_known?: { state: string; checked_at: number; post_number?: string | null; transaction_hash?: string } };
export type Submission = { post: WirePost; selection: AddressSelection; submission_id: string; phase: string; status: PostStatus; renewal_count: number; experimental: true };
export type Operation = 'bundle-capabilities' | 'bundle-initialize-identity' | 'bundle-outbox' | 'bundle-publish' | 'bundle-recover' | 'bundle-renew' | 'bundle-address-request' | 'bundle-address-result' | 'bundle-threads' | 'bundle-thread' | 'bundle-numbers' | 'bundle-clear-cache' | 'bundle-export-public' | 'bundle-import-public'
  | 'bundle-history-request' | 'bundle-history-prove' | 'bundle-history-verify' | 'bundle-history-requests'
  | 'count-status' | 'count-begin' | 'count-check-post' | 'count-poll-registration' | 'count-recover' | 'count-cancel';
export function validAuthoredIdentity(v: unknown): v is AuthoredIdentity {
  if (!object(v) || v.profile !== 'nockapp-bundle-service-identity-v4' || v.protocol !== 4 || v.bundle_profile !== 'nockapp-public-discussion-bundle-v4' || !hex(v.author_native_sha256)) return false;
  const { author_native_sha256: _author, ...shared } = v;
  return legacyIdentity({ ...shared, profile: 'nockapp-bundle-service-identity-v3', protocol: 3, bundle_profile: 'nockapp-public-discussion-bundle-v3' });
}
export function validAuthoredSelection(v: unknown): v is AddressSelection { return object(v) && exact(v, ['address', 'followers_threshold']) && typeof v.address === 'boolean'
  && (v.followers_threshold === null || typeof v.followers_threshold === 'number' && Number.isSafeInteger(v.followers_threshold) && v.followers_threshold >= 0); }
function status(v: unknown): boolean {
  if (!object(v) || !Object.keys(v).every(k => ['state', 'checked_at', 'transaction_hash', 'post_number', 'recovery_action', 'last_known',
    'authorship_checked', 'address_evidence_checked', 'credential_evidence_checked', 'content_state'].includes(k))
    || !['pending', 'confirmed', 'finalized', 'failed', 'recoverable'].includes(String(v.state)) || !Number.isSafeInteger(v.checked_at) || Number(v.checked_at) < 0) return false;
  for (const key of ['authorship_checked', 'address_evidence_checked', 'credential_evidence_checked']) if (typeof v[key] !== 'boolean') return false;
  if (v.transaction_hash !== undefined && !hash(v.transaction_hash)) return false;
  if (v.post_number !== undefined && v.post_number !== null && !(typeof v.post_number === 'string' && /^[1-9][0-9]{0,15}$/.test(v.post_number) && Number(v.post_number) < Number.MAX_SAFE_INTEGER)) return false;
  if (v.state === 'finalized' && (!hash(v.transaction_hash) || typeof v.post_number !== 'string' || v.authorship_checked !== true)) return false;
  if (v.state !== 'finalized' && (v.authorship_checked || v.address_evidence_checked || v.credential_evidence_checked)) return false;
  if (v.content_state !== undefined && v.content_state !== 'locally-retained') return false;
  if (v.last_known !== undefined) {
    const old = v.last_known;
    if (!object(old) || !Object.keys(old).every(k => ['state', 'checked_at', 'transaction_hash', 'post_number'].includes(k))
      || !['finalized', 'failed'].includes(String(old.state)) || !Number.isSafeInteger(old.checked_at) || Number(old.checked_at) < 0
      || old.transaction_hash !== undefined && !hash(old.transaction_hash)
      || old.post_number !== undefined && old.post_number !== null && !(typeof old.post_number === 'string' && /^[1-9][0-9]{0,15}$/.test(old.post_number) && Number(old.post_number) < Number.MAX_SAFE_INTEGER)) return false;
  }
  return v.recovery_action === undefined || ['sign-with-wallet', 'recover-same-submission', 'renew-expired-authorization', 'set-up-private-signing-identity', 'refresh-independent-verification'].includes(String(v.recovery_action));
}
export function validSubmission(v: unknown): v is Submission { return object(v) && exact(v, ['post', 'selection', 'submission_id', 'phase', 'status', 'renewal_count', 'experimental'])
  && validWirePost(v.post) && !v.post.claims.length && validAuthoredSelection(v.selection) && hex(v.submission_id) && v.experimental === true
  && Number.isSafeInteger(v.renewal_count) && Number(v.renewal_count) >= 0 && Number(v.renewal_count) <= 3
  && ['prepared', 'authored', 'challenge-saved', 'wallet-needed', 'bundle-saved', 'submitted'].includes(String(v.phase)) && status(v.status); }
export function validBody(op: string, b: Record<string, unknown>): boolean {
  if (op.startsWith('bundle-history-')) return historyBody(op, b);
  if (op === 'bundle-capabilities') return exact(b, []);
  if (op === 'bundle-initialize-identity') return exact(b, ['approve_private_key_setup']) && b.approve_private_key_setup === true;
  if (op === 'bundle-outbox') return exact(b, ['after', 'limit']) && Number.isSafeInteger(b.after) && Number(b.after) >= 0 && Number(b.after) <= 100 && Number.isSafeInteger(b.limit) && Number(b.limit) >= 1 && Number(b.limit) <= 8;
  if (op === 'bundle-publish') return exact(b, ['post', 'selection', 'approve_publication']) && b.approve_publication === true && validWirePost(b.post) && !b.post.claims.length && validAuthoredSelection(b.selection);
  if (op === 'bundle-recover') return exact(b, ['post_id']) && uuid(b.post_id);
  if (op === 'bundle-renew') return exact(b, ['post_id', 'expected_submission_id', 'approve_fresh_proof']) && uuid(b.post_id) && hex(b.expected_submission_id) && b.approve_fresh_proof === true;
  if (op === 'bundle-address-request') return exact(b, ['post_id', 'address', 'approve_address_disclosure']) && uuid(b.post_id) && typeof b.address === 'string' && /^0x[0-9a-f]{40}$/.test(b.address) && b.approve_address_disclosure === true;
  if (op === 'bundle-address-result') return exact(b, ['post_id', 'submission_id', 'request_sha256', 'signature']) && uuid(b.post_id) && hex(b.submission_id) && hex(b.request_sha256) && typeof b.signature === 'string' && /^0x[0-9a-fA-F]{130}$/.test(b.signature);
  return sharedOperations.includes(op) && validBundleBody(op, b);
}
export function projection(op: string, v: unknown, body: Record<string, unknown> = {}): boolean {
  if (op.startsWith('bundle-history-')) return historyProjection(op, v, body);
  if (!object(v)) return false;
  if (['bundle-threads', 'bundle-thread', 'bundle-numbers'].includes(op)) return readProjection(op, v, body);
  if (sharedOperations.includes(op)) return bundleProjection(op as BundleOperation, v, body);
  if (op === 'bundle-capabilities') return v.configured === false ? exact(v, ['configured', 'experimental']) && v.experimental === true : exact(v, ['configured', 'identity', 'count_enrollment_configured', 'experimental']) && v.configured === true && v.experimental === true && typeof v.count_enrollment_configured === 'boolean' && validAuthoredIdentity(v.identity);
  if (op === 'bundle-initialize-identity') return exact(v, ['profile', 'state', 'wallet_bound', 'pending_post', 'protocol']) && v.profile === 'nockapp-protected-authorship-desktop-v4' && v.state === 'ready' && v.protocol === 4 && typeof v.wallet_bound === 'boolean' && typeof v.pending_post === 'boolean';
  if (op === 'bundle-outbox') return exact(v, ['entries', 'next_after', 'more', 'experimental']) && Array.isArray(v.entries) && v.entries.length <= 8 && v.entries.every(validSubmission) && Number.isSafeInteger(v.next_after) && Number(v.next_after) >= 0
    && (body.after === undefined || v.next_after === Number(body.after) + v.entries.length && v.entries.length <= Number(body.limit)) && typeof v.more === 'boolean' && v.experimental === true;
  if (op === 'bundle-address-request') return validPostWalletRequestShape(v) && (body.address === undefined || v.address === body.address);
  return validSubmission(v) && (body.post === undefined || validWirePost(body.post) && wirePayload(v.post) === wirePayload(body.post) && canonicalAscii(v.selection) === canonicalAscii(body.selection))
    && (body.post_id === undefined || v.post.id === body.post_id)
    && (op !== 'bundle-renew' || v.submission_id !== body.expected_submission_id)
    && (op !== 'bundle-address-result' || v.submission_id === body.submission_id);

}

const sharedOperations = ['bundle-threads', 'bundle-thread', 'bundle-numbers', 'bundle-clear-cache', 'bundle-export-public', 'bundle-import-public',
  'count-status', 'count-begin', 'count-check-post', 'count-poll-registration', 'count-recover', 'count-cancel'];
function oldIdentity(v: AuthoredIdentity) {
  const { author_native_sha256: _author, ...rest } = v;
  return { ...rest, profile: 'nockapp-bundle-service-identity-v3', protocol: 3, bundle_profile: 'nockapp-public-discussion-bundle-v3' };
}
function adaptedRow(v: unknown): Record<string, unknown> | undefined {
  if (!object(v)) return;
  if (['index-gap', 'not-accepted', 'acceptance-unavailable'].includes(String(v.state))) return legacyRow(v) ? v : undefined;
  const { authorship_checked, address_evidence_checked, public_address, selection, ...rest } = v;
  if ('public_id' in rest || typeof authorship_checked !== 'boolean' || typeof address_evidence_checked !== 'boolean') return;
  const finalized = v.state === 'finalized';
  if (authorship_checked !== finalized || public_address !== null && !(typeof public_address === 'string' && /^0x[0-9a-f]{40}$/.test(public_address) && !/^0x0+$/.test(public_address))) return;
  if (selection !== undefined && !validAuthoredSelection(selection)) return;
  if (finalized ? !validAuthoredSelection(selection) || address_evidence_checked !== selection.address || (public_address !== null) !== selection.address
    : address_evidence_checked || public_address !== null) return;
  const converted = { ...rest, ...(selection === undefined ? {} : { selection: { credential_kind: (selection as AddressSelection).followers_threshold === null ? 0 : 2,
    facts: (selection as AddressSelection).followers_threshold === null ? [] : ['account-controlled', 'followers-more-than'], threshold: (selection as AddressSelection).followers_threshold } }),
    ...(finalized ? { public_id: null } : {}) };
  return legacyRow(converted) && [0, 2].includes(Number(v.credential_kind)) ? converted : undefined;
}
export function validAuthoredRow(v: unknown): v is Row { return adaptedRow(v) !== undefined; }
function readProjection(op: string, v: Record<string, unknown>, body: Record<string, unknown>) {
  if (!validAuthoredIdentity(v.identity) || !Array.isArray(v.posts)) return false;
  const posts = v.posts.map(adaptedRow);if (posts.some(p => !p)) return false;
  if (op === 'bundle-thread' && v.posts.some(p => object(p) && p.canonical_accepted === true && p.thread_id !== body.thread_id)) return false;
  if (op === 'bundle-threads' && v.posts.some(p => object(p) && p.canonical_accepted === true && (p.thread_id !== p.post_id || object(p.post) && p.post.kind !== 'thread'))) return false;
  const converted = { ...v, identity: oldIdentity(v.identity), posts };
  if (op !== 'bundle-numbers') {
    // Legacy ordinary rows had no author proof; v4 completeness always needs it.
    const expected = Array.isArray(v.index_gaps) && !v.index_gaps.length && v.posts.every(p => object(p) && p.authorship_checked === true
      && (p.credential_kind === 0 || p.credential_evidence_checked === true) && (!object(p.selection) || !p.selection.address || p.address_evidence_checked === true));
    if (v.page_evidence_complete !== expected) return false;
    Object.assign(converted, { page_evidence_complete: Array.isArray(v.index_gaps) && !v.index_gaps.length && posts.every(p => p?.credential_kind === 0 || p?.credential_evidence_checked === true) });
  }
  return bundleProjection(op as BundleOperation, converted, body);
}

let active: symbol | undefined;
export function attachAuthoredDiscussion(ui: chrome.runtime.Port, walletOnly = false, walletPostId?: string) {
  let connected = true;let cleanup: (() => void) | undefined;
  ui.onDisconnect.addListener(() => { connected = false;cleanup?.(); });
  const emit = (value: object) => { if (connected) try { ui.postMessage({ version: AUTHORED_VERSION, ...value }); } catch { connected = false;cleanup?.(); } };
  ui.onMessage.addListener((m: unknown) => {
    if (!connected || cleanup) return;
    if (!object(m) || !exact(m, ['version', 'operation', 'body']) || m.version !== AUTHORED_VERSION || typeof m.operation !== 'string' || !object(m.body)
      || !validBody(m.operation, m.body) || new TextEncoder().encode(JSON.stringify(m)).length > 131072
      || walletOnly && !['bundle-capabilities', 'bundle-outbox', 'bundle-recover', 'bundle-address-request', 'bundle-address-result'].includes(m.operation)
      || walletOnly && ['bundle-recover', 'bundle-address-request', 'bundle-address-result'].includes(m.operation) && m.body.post_id !== walletPostId) { emit({ error: 'message-schema' });return; }
    if (active) { emit({ error: 'helper-busy' });return; }const owner = Symbol('authored-operation');active = owner;
    const id = crypto.randomUUID().replaceAll('-', '');let settled = false;let port: chrome.runtime.Port | undefined;let timer: ReturnType<typeof setTimeout>;
    const done = (v?: unknown, error?: string) => { if (settled) return;settled = true;cleanup?.();emit(error ? { error } : { result: v }); };
    const response = (v: unknown) => {
      if (settled || !connected || !port) return;
      if (!object(v) || v.profile !== NATIVE || v.id !== id || v.laboratory !== true || v.verified !== false || new TextEncoder().encode(JSON.stringify(v)).length > 131072) return done(undefined, 'unsupported-helper');
      if (v.status === 'rejected' && exact(v, ['profile', 'id', 'status', 'code', 'recoverable', 'laboratory', 'verified']) && v.code === 'native-operation-unavailable' && v.recoverable === true) return done(undefined, 'recovery-needed');
      if (v.status !== 'ok' || !exact(v, ['profile', 'id', 'status', 'result', 'laboratory', 'verified']) || !projection(m.operation as string, v.result, m.body as Record<string, unknown>)) return done(undefined, 'unsupported-helper');
      done(structuredClone(v.result));
    };
    const lost = () => { void api().runtime.lastError;done(undefined, 'helper-unavailable'); };
    cleanup = () => { settled = true;clearTimeout(timer);const old = port;port = undefined;old?.onMessage.removeListener(response);old?.onDisconnect.removeListener(lost);old?.disconnect();if (active === owner) active = undefined;cleanup = undefined; };
    try { port = api().runtime.connectNative('com.nockapp.zkid');port.onMessage.addListener(response);port.onDisconnect.addListener(lost);timer = setTimeout(() => done(undefined, 'recovery-needed'), 185000);port.postMessage({ profile: NATIVE, id, operation: 'authored-' + m.operation, body: m.body }); }
    catch { done(undefined, 'helper-unavailable'); }
  });
}
let queue: Promise<unknown> = Promise.resolve();
export function authoredOperation<T = unknown>(operation: Operation, supplied: Record<string, unknown> = {}, signal?: AbortSignal): Promise<T> {
  const body = structuredClone(supplied);
  const run = () => new Promise<T>((resolve, reject) => {
    if (!validBody(operation, body) || signal?.aborted) { reject(new Error('Invalid or cancelled post operation.'));return; }
    let port: chrome.runtime.Port | undefined;let timer: ReturnType<typeof setTimeout>;let settled = false;
    const done = (value?: unknown, error?: string) => { if (settled) return;settled = true;clearTimeout(timer);signal?.removeEventListener('abort', abort);port?.disconnect();if (error) reject(new Error(error));else resolve(value as T); };
    const abort = () => done(undefined, 'Operation stopped. Recover the saved post before trying again.');signal?.addEventListener('abort', abort, { once: true });
    try { port = api().runtime.connect({ name: AUTHORED_PORT });port.onDisconnect.addListener(() => { void api().runtime.lastError;done(undefined, 'The helper disconnected. Recover the saved post.'); });
      port.onMessage.addListener((v: unknown) => { if (!object(v) || v.version !== AUTHORED_VERSION) return done(undefined, 'Unsupported helper reply.');
        if (exact(v, ['version', 'result']) && projection(operation, v.result, body)) done(v.result);else done(undefined, 'Shared posting is unavailable. Check the configured Ubuntu v4 helper or recover the saved post.'); });
      timer = setTimeout(() => done(undefined, 'Shared posting is unavailable. Check the configured Ubuntu v4 helper or recover the saved post.'), 190000);port.postMessage({ version: AUTHORED_VERSION, operation, body });
    } catch { done(undefined, 'The configured Ubuntu helper is unavailable.'); }
  });
  const result = queue.then(run);queue = result.catch(() => undefined);return result;
}
