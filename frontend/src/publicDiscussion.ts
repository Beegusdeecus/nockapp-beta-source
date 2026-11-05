/** Versioned public-v6 browser/native admission. No private state or network API. */
import { api } from './platform/browser';
import { exact, object, validWirePost } from './zkidWire';
import { canonicalAscii } from './authoredWallet';
import { validPublicWalletShape } from './publicWallet';
import { validTicketOffer, validTicketPending, validArmedPurchase, validTicketAnchor, validClosedAttempt, validTicketRefundReply } from './publicTickets';
import { validRefundState, validRefundResult } from './publicRefunds';
import { validArchive, validArchiveCapabilities, validArchiveExport, validArchiveRestore, validArchiveStatus } from './publicContentArchive';
import { validBulkPurchase } from './bulkTickets';
export const PUBLIC_PORT = 'nockapp-permissionless-discussion';
export const PUBLIC_VERSION = 'nockapp-permissionless-discussion-12';
const NATIVE = 'nockapp-zkid-public-post-native-v1';
const integer = (v: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= max;
const hex = (v: unknown, size = 64): v is string => typeof v === 'string' && new RegExp(`^[0-9a-f]{${size}}$`).test(v) && !/^0+$/.test(v);
const hash = (v: unknown): v is string => typeof v === 'string' && v.startsWith('0x') && hex(v.slice(2));
const address = (v: unknown): v is string => typeof v === 'string' && v.startsWith('0x') && hex(v.slice(2), 40);
const uuid = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const number = (v: unknown): v is string => typeof v === 'string' && /^[1-9][0-9]{0,15}$/.test(v) && Number(v) < 2 ** 53;
const bounded = (v: unknown, limit: number) => new TextEncoder().encode(canonicalAscii(v)).length <= limit;
export type PublicScope = { protocol: 5; chain_id: 84532; application: string; contract: string };
export type PublicPost = { kind: 'thread' | 'comment'; id: string; created_at: number; title: string | null; body: string; references: [string, string | null][] };
export type PublicSelection = { address: boolean; followers_threshold: number | null };
export type PublicReference = { protocol: 4 | 5; chain_id: 84532; contract: string; number: string | null; bundle_hash: string };
export type PublicCore = { profile: 'nockapp-post-core-v5'; context: PublicScope & { submission_id: string }; post: PublicPost;
  thread: PublicReference | null; references: PublicReference[]; selection: PublicSelection };
export type PublicSubmission = { core: PublicCore; phase: string; bundle_hash: string | null; last_known: null | { state: string; post_number: string | null; checked_at: number };
  verification_current: boolean; last_attempt: null | { requested_at: number; transaction_hash?: string };
  follower_window?: 'not-selected' | 'not-attached' | 'legacy' | 'usable' | 'closing' | 'expired' | 'not-yet-valid' | 'unclassified' };
export type PublicRow = { post_number: string; state: string; canonical_indexed: boolean; proofs_verified: boolean;
  bundle_hash?: string; indexed_at?: number; post?: PublicPost; thread?: PublicReference | null; references?: PublicReference[];
  relationship_state?: string; display?: { address: string | null; followers: null | { threshold: number; qualified_when_indexed: true; indexed_at: number; credential_profile: string }; history: PublicReference[] | null } };
export type PublicPage = { verifier_version: string; posts: PublicRow[]; requested_numbers: string[]; next_number: string; next_after: number; after: number; more: boolean;
  finalized_block: { number: string; hash: string }; whole_log_complete: false };
export type PublicExport = { profile: 'nockapp-public-submission-v5'; scope: PublicScope; bundle_hash: string;
  bundle_base64: string; calldata: string; contains_private_key: false; personal_wallet_required: false };
export type DirectReady = { scope: PublicScope; bundle_hash: string; calldata: string; public_readback_checked: true; payer_address_public: true };
export type PublicSourceState = { profile: 'nockapp-renewal-enrollment-v3'; state: string; credential_saved: boolean; post_text: string | null };
export type PublicSourceStatus = { profile: 'nockapp-public-source-status-v1'; credential_record_present: boolean; renewal_pending: boolean };
export type PublicSourceFinality = { profile: 'nockapp-public-source-finality-v1'; chain_id: 84532;
  latest_block: number; finalized_block: number; latest_revision: number; finalized_revision: number;
  target_block: number | null; pending: boolean };
export type TicketPaymentProgress = { profile: 'nockapp-ticket-payment-progress-v1'; pack_hash: string;
  state: 'not-seen' | 'confirming' | 'finalized'; latest_block: number; finalized_block: number; payment_block: number | null };
export type PublicOperation = 'public-capabilities' | 'public-identity-options' | 'public-initialize-identity' | 'public-adopt-identity'
  | 'public-archive-capabilities' | 'public-archive-export-object' | 'public-archive-import-object' | 'public-archive-cache-status'
  | 'public-source-status' | 'public-source-finality' | 'public-source-begin' | 'public-source-check-post' | 'public-source-recover' | 'public-source-cancel'
  | 'public-ticket-status' | 'public-ticket-prepare' | 'public-ticket-payment' | 'public-ticket-recover'
  | 'public-ticket-bulk-status' | 'public-ticket-bulk-prepare' | 'public-ticket-bulk-arm' | 'public-ticket-bulk-progress' | 'public-ticket-bulk-recover'
  | 'public-ticket-bulk-resume' | 'public-ticket-bulk-refund'
  | 'public-ticket-offer' | 'public-ticket-pending' | 'public-ticket-arm' | 'public-ticket-intent' | 'public-ticket-find' | 'public-ticket-progress' | 'public-ticket-close-attempt'
  | 'public-ticket-refund-request' | 'public-ticket-refund-result'
  | 'public-ticket-refund-state' | 'public-ticket-refund-status' | 'public-ticket-refund-recover'
  | 'public-wallet-recover' | 'public-wallet-request' | 'public-wallet-result' | 'public-wallet-finish' | 'public-wallet-reset'
  | 'public-export-submission' | 'public-direct-ready' | 'public-direct-public-ready'
  | 'public-prepare' | 'public-finish' | 'public-publish' | 'public-check' | 'public-outbox' | 'public-numbers' | 'public-page' | 'public-attach-history' | 'public-attach-followers';
export function validPublicScope(v: unknown): v is PublicScope {
  return object(v) && exact(v, ['protocol', 'chain_id', 'application', 'contract']) && v.protocol === 5 && v.chain_id === 84532 && hash(v.application) && address(v.contract);
}
export function validPublicSelection(v: unknown): v is PublicSelection {
  return object(v) && exact(v, ['address', 'followers_threshold']) && typeof v.address === 'boolean'
    && (v.followers_threshold === null || integer(v.followers_threshold));
}
export function validPublicReference(v: unknown, historical = false): v is PublicReference {
  return object(v) && exact(v, ['protocol', 'chain_id', 'contract', 'number', 'bundle_hash']) && [4, 5].includes(Number(v.protocol))
    && typeof v.protocol === 'number' && v.chain_id === 84532 && address(v.contract) && hash(v.bundle_hash)
    && (v.number === null && !historical || number(v.number));
}
export function validPublicPost(v: unknown): v is PublicPost {
  return object(v) && exact(v, ['kind', 'id', 'created_at', 'title', 'body', 'references'])
    && validWirePost({ ...v, thread_id: v.kind === 'thread' ? null : 'canonical-reference', claims: [] })
    // The native wire projection uses a 64-hex digest for a comment's root.
    // Its exact value changes the signed bytes, but not their encoded size.
    && bounded(['NOCKAPP/ZKID/POST-SCOPE/v1', v.kind, v.id, v.created_at,
      v.kind === 'thread' ? null : 'f'.repeat(64), v.title, v.body, v.references, []], 8192);
}
export function validPublicCore(v: unknown): v is PublicCore {
  if (!object(v) || !exact(v, ['profile', 'context', 'post', 'thread', 'references', 'selection']) || v.profile !== 'nockapp-post-core-v5'
    || !object(v.context) || !exact(v.context, ['protocol', 'chain_id', 'application', 'contract', 'submission_id']) || !hex(v.context.submission_id)) return false;
  const { submission_id: _id, ...scope } = v.context;
  return validPublicScope(scope) && validPublicPost(v.post) && validPublicSelection(v.selection)
    && (v.post.kind === 'thread' ? v.thread === null : validPublicReference(v.thread) && v.thread.protocol === 5
      && v.thread.contract === scope.contract && v.thread.chain_id === scope.chain_id)
    && Array.isArray(v.references) && v.references.length <= 32 && v.references.every(r => validPublicReference(r, true))
    && new Set(v.references.map(canonicalAscii)).size === v.references.length && bounded(v, 16384);
}
export function validPublicBody(op: string, b: Record<string, unknown>): boolean {
  if(op==='public-ticket-bulk-status')return exact(b,[]);
  if(op==='public-ticket-bulk-prepare')return exact(b,['ticket_count','approve_purchase',...('include_prepared_pack'in b?['include_prepared_pack']:[])])&&(!('include_prepared_pack'in b)||b.include_prepared_pack===true)&&b.ticket_count===50&&b.approve_purchase===true;
  if(op==='public-ticket-bulk-arm')return exact(b,['batch_id','payer','approve_payment'])&&hex(b.batch_id)&&address(b.payer)&&b.approve_payment===true;
  if(op==='public-ticket-bulk-progress')return exact(b,['batch_id'])&&hex(b.batch_id);
  if(['public-ticket-bulk-recover','public-ticket-bulk-resume'].includes(op))return exact(b,['batch_id','approve_import'])&&hex(b.batch_id)&&b.approve_import===true;
  if(op==='public-ticket-bulk-refund')return exact(b,['batch_id','approve_refund_preparation'])&&hex(b.batch_id)&&b.approve_refund_preparation===true;
  if(op==='public-archive-capabilities')return exact(b,[]);
  if(op==='public-archive-export-object')return exact(b,['number','bundle_hash','approve_public_export'])&&integer(b.number,1)&&hash(b.bundle_hash)&&b.approve_public_export===true;
  if(op==='public-archive-import-object')return exact(b,['archive','approve_public_import'])&&b.approve_public_import===true&&validArchive(b.archive,1);
  if(op==='public-archive-cache-status')return exact(b,['bundle_hashes'])&&Array.isArray(b.bundle_hashes)&&b.bundle_hashes.length>=1&&b.bundle_hashes.length<=4
    &&b.bundle_hashes.every((h,i,a)=>hash(h)&&(i===0||h>a[i-1]));
  if (op === 'public-source-status' || op === 'public-source-finality') return exact(b, []);
  if (op === 'public-source-begin') return exact(b, ['username', 'approve_source_check']) && typeof b.username === 'string'
    && /^[A-Za-z0-9_]{1,15}$/.test(b.username) && b.approve_source_check === true;
  if (op === 'public-source-check-post') return exact(b, ['tweet_id', 'approve_source_check']) && typeof b.tweet_id === 'string'
    && /^[1-9][0-9]{0,19}$/.test(b.tweet_id) && b.approve_source_check === true;
  if (op === 'public-source-recover') return exact(b, ['approve_source_check']) && b.approve_source_check === true;
  if (op === 'public-source-cancel') return exact(b, ['approve_cancel']) && b.approve_cancel === true;
  if (['public-capabilities', 'public-identity-options', 'public-ticket-status', 'public-ticket-recover', 'public-ticket-offer',
    'public-ticket-pending','public-ticket-intent','public-ticket-find','public-ticket-refund-request','public-ticket-refund-state'].includes(op)) return exact(b, []);
  if (['public-ticket-refund-status','public-ticket-refund-recover'].includes(op)) return exact(b,['pack_hash']) && hash(b.pack_hash);
  if (op==='public-ticket-progress')return exact(b,['pack_hash'])&&hash(b.pack_hash);
  if (op==='public-ticket-arm') return exact(b,['pack_hash','payer','nonce','approve_payment']) && hash(b.pack_hash) && address(b.payer) && integer(b.nonce) && b.approve_payment===true;
  if (op==='public-ticket-close-attempt') return exact(b,['pack_hash','payment_intent_sha256','approve_close_attempt']) && hash(b.pack_hash) && hex(b.payment_intent_sha256) && b.approve_close_attempt===true;
  if (op==='public-ticket-refund-result') return exact(b,['request_sha256','signature']) && hex(b.request_sha256) && typeof b.signature==='string' && /^0x[0-9a-fA-F]{130}$/.test(b.signature);
  if (op === 'public-initialize-identity') return exact(b, ['approve_private_key_setup']) && b.approve_private_key_setup === true;
  if (op === 'public-adopt-identity') return exact(b, ['source_id', 'approve_key_reuse']) && hex(b.source_id) && b.approve_key_reuse === true;
  if (op === 'public-ticket-prepare') return exact(b, ['approve_purchase']) && b.approve_purchase === true;
  if (op === 'public-ticket-payment') return exact(b, ['pack_hash', 'transaction_hash']) && hash(b.pack_hash) && hash(b.transaction_hash);
  if (op === 'public-wallet-recover') return exact(b,['post_id','approve_save']) && uuid(b.post_id) && b.approve_save === true;
  if (op === 'public-wallet-request') return exact(b, ['post_id','address','approve_address_disclosure']) && uuid(b.post_id) && address(b.address) && b.approve_address_disclosure === true;
  if (op === 'public-wallet-result') return exact(b, ['post_id','request_sha256','signature']) && uuid(b.post_id) && hex(b.request_sha256) && typeof b.signature === 'string' && /^0x[0-9a-fA-F]{130}$/.test(b.signature);
  if (op === 'public-wallet-finish') return exact(b, ['post_id','request_sha256','approve_save']) && uuid(b.post_id) && hex(b.request_sha256) && b.approve_save === true;
  if (op === 'public-wallet-reset') return exact(b, ['post_id','request_sha256','approve_fresh_request']) && uuid(b.post_id) && hex(b.request_sha256) && b.approve_fresh_request === true;
  if (op === 'public-check') return exact(b, ['post_id']) && uuid(b.post_id);
  if (op === 'public-export-submission') return exact(b, ['post_id','approve_public_export']) && uuid(b.post_id) && b.approve_public_export === true;
  if (op === 'public-direct-ready') return exact(b, ['post_id','approve_publication','approve_public_payer']) && uuid(b.post_id)
    && b.approve_publication === true && b.approve_public_payer === true;
  if (op === 'public-direct-public-ready') return exact(b, ['bundle_hash','approve_publication','approve_public_payer']) && hash(b.bundle_hash)
    && b.approve_publication === true && b.approve_public_payer === true;
  if (['public-finish', 'public-publish'].includes(op)) return (exact(b, ['post_id', 'approve_publication'])
    || op === 'public-publish' && exact(b, ['post_id', 'approve_publication', 'approve_optional_badge_failure'])
    && b.approve_optional_badge_failure === true) && uuid(b.post_id) && b.approve_publication === true;
  if (op === 'public-attach-followers') return exact(b, ['post_id', 'approve_follower_disclosure']) && uuid(b.post_id) && b.approve_follower_disclosure === true;
  if (op === 'public-attach-history') return exact(b, ['post_id', 'records', 'approve_linking']) && uuid(b.post_id) && b.approve_linking === true
    && Array.isArray(b.records) && b.records.length >= 1 && b.records.length <= 15 && b.records.every(r => validPublicReference(r, true))
    && new Set(b.records.map(canonicalAscii)).size === b.records.length;
  if (op === 'public-outbox') return exact(b, ['after', 'limit']) && integer(b.after, 0, 40) && integer(b.limit, 1, 4);
  if (op === 'public-page') return exact(b, ['after', 'limit']) && integer(b.after) && integer(b.limit, 1, 4);
  if (op === 'public-numbers') return exact(b, ['numbers']) && Array.isArray(b.numbers) && b.numbers.length >= 1 && b.numbers.length <= 4
    && b.numbers.every(n => integer(n, 1)) && new Set(b.numbers).size === b.numbers.length;
  if (op === 'public-prepare') return exact(b, ['post', 'selection', 'thread', 'references', 'approve_publication']) && b.approve_publication === true
    && validPublicPost(b.post) && validPublicSelection(b.selection) && (b.post.kind === 'thread' ? b.thread === null : validPublicReference(b.thread) && b.thread.protocol === 5)
    && (b.references === null || Array.isArray(b.references) && b.references.length <= 32 && b.references.every(r => validPublicReference(r, true))
      && new Set(b.references.map(canonicalAscii)).size === b.references.length) && bounded(b, 16384);
  return false;
}
export function validPublicSubmission(v: unknown): v is PublicSubmission {
  if (!object(v) || !exact(v, ['core', 'phase', 'bundle_hash', 'last_known', 'verification_current', 'last_attempt', ...('follower_window' in v ? ['follower_window'] : [])]) || !validPublicCore(v.core)
    || 'follower_window' in v && !['not-selected','not-attached','legacy','usable','closing','expired','not-yet-valid','unclassified'].includes(String(v.follower_window))
    || !['prepared', 'proofs-needed', 'wallet-needed', 'bundle-saved', 'submitted'].includes(String(v.phase))
    || !(v.bundle_hash === null || hash(v.bundle_hash)) || typeof v.verification_current !== 'boolean'
    || (['bundle-saved', 'submitted'].includes(String(v.phase))) !== (v.bundle_hash !== null)) return false;
  const s = v.last_known;
  if (s !== null && (!object(s) || !exact(s, ['state', 'post_number', 'checked_at']) || !integer(s.checked_at)
    || !['not-indexed', 'finalized', 'invalid', 'content-unavailable', 'verification-unavailable'].includes(String(s.state))
    || (s.state === 'not-indexed' ? s.post_number !== null : !number(s.post_number)))) return false;
  if (v.verification_current && s === null) return false;
  const a = v.last_attempt;
  return a === null || object(a) && exact(a, ['requested_at', ...('transaction_hash' in a ? ['transaction_hash'] : [])])
    && integer(a.requested_at) && (!('transaction_hash' in a) || hash(a.transaction_hash));
}
function identity(v: Record<string, unknown>) {
  return exact(v, ['profile', 'state', 'wallet_bound', 'pending_post', 'protocol']) && v.profile === 'nockapp-protected-authorship-desktop-v5'
    && v.state === 'ready' && v.protocol === 5 && typeof v.wallet_bound === 'boolean' && typeof v.pending_post === 'boolean';
}
function ticketCounts(v: Record<string, unknown>) {
  return integer(v.available, 0, 64) && integer(v.reserved, 0, 64) && Number(v.available) + Number(v.reserved) <= 64 && typeof v.purchase_pending === 'boolean';
}
function ticketStatus(v: Record<string, unknown>, minimal = false) {
  const base = ['available', 'reserved', 'purchase_pending'];
  if (minimal && exact(v, ['profile', ...base])) return v.profile === 'nockapp-protected-ticket-wallet-v1' && ticketCounts(v);
  const initialized = v.initialized;
  return typeof initialized === 'boolean' && exact(v, [...base, ...(initialized ? ['profile'] : []), 'initialized', 'can_purchase', 'can_redeem',
    'pack_size', 'pack_price_wei', 'purchase_before', 'redeem_before', 'refund_policy', 'prepaid_custody']) && ticketCounts(v)
    && (!initialized ? v.available === 0 && v.reserved === 0 && v.purchase_pending === false : v.profile === 'nockapp-protected-ticket-wallet-v1')
    && typeof v.can_purchase === 'boolean' && typeof v.can_redeem === 'boolean' && integer(v.pack_size, 1, 32)
    && typeof v.pack_price_wei === 'string' && /^[1-9][0-9]{0,38}$/.test(v.pack_price_wei) && BigInt(v.pack_price_wei) < 2n ** 128n
    && integer(v.purchase_before, 1) && integer(v.redeem_before, Number(v.purchase_before) + 1)
    && v.refund_policy === 'unissued-only-durable-decision-v1' && v.prepaid_custody === true;
}
function purchase(v: Record<string, unknown>, b: Record<string, unknown>) {
  const t = v.transaction;
  return exact(v, ['profile', 'pack_hash', 'payment_tx', 'transaction']) && v.profile === 'nockapp-protected-ticket-wallet-v1'
    && hash(v.pack_hash) && (v.payment_tx === null || hash(v.payment_tx))
    && (b.pack_hash === undefined || v.pack_hash === b.pack_hash && v.payment_tx === b.transaction_hash)
    && object(t) && exact(t, ['chain_id', 'to', 'value', 'data']) && t.chain_id === 84532 && address(t.to)
    && typeof t.value === 'string' && /^0x[1-9a-f][0-9a-f]{0,31}$/.test(t.value)
    && t.data === '0x9c9a1061' + v.pack_hash.slice(2); // buy(bytes32), pinned native/EVM vector.
}
function follower(v: unknown, indexed: unknown) {
  return v === null || object(v) && exact(v, ['threshold', 'qualified_when_indexed', 'indexed_at', 'credential_profile'])
    && integer(v.threshold) && v.qualified_when_indexed === true && v.indexed_at === indexed
    && ['nockapp-renewal-count-v3', 'legacy-date-disclosing-count-v2'].includes(String(v.credential_profile));
}
export function validPublicRow(v: unknown): boolean {
  if (!object(v)) return false;
  if (v.state === 'unassigned') return exact(v, ['post_number', 'state', 'canonical_indexed', 'proofs_verified'])
    && number(v.post_number) && v.canonical_indexed === false && v.proofs_verified === false;
  const fields = ['post_number', 'bundle_hash', 'indexed_at', 'block_number', 'block_hash', 'transaction_hash', 'canonical_indexed', 'proofs_verified', 'state'];
  if (!number(v.post_number) || !hash(v.bundle_hash) || !integer(v.indexed_at) || !integer(v.block_number) || !hash(v.block_hash) || !hash(v.transaction_hash) || v.canonical_indexed !== true) return false;
  if (v.state !== 'finalized') return exact(v, fields) && ['content-unavailable', 'verification-unavailable', 'invalid'].includes(String(v.state)) && v.proofs_verified === false;
  return exact(v, [...fields, 'post', 'thread', 'references', 'authorship_checked', 'logical_key', 'display', 'historical_follower_evidence', 'verifier_profile', 'relationship_state'])
    && v.proofs_verified === true && v.authorship_checked === true && v.verifier_profile === 'nockapp-public-verifier-v6' && validPublicPost(v.post)
    && v.post.created_at <= Number(v.indexed_at) && hex(v.logical_key)
    && (v.thread === null && v.post.kind === 'thread' || validPublicReference(v.thread) && v.thread.protocol === 5 && v.post.kind === 'comment')
    && Array.isArray(v.references) && v.references.length <= 32 && v.references.every(r => validPublicReference(r, true))
    && ['valid', 'unverified'].includes(String(v.relationship_state)) && object(v.display) && exact(v.display, ['address', 'followers', 'history'])
    && (v.display.address === null || address(v.display.address)) && follower(v.display.followers, v.indexed_at)
    && follower(v.historical_follower_evidence, v.indexed_at)
    && canonicalAscii(v.historical_follower_evidence) === canonicalAscii(v.display.followers)
    && (v.display.history === null || Array.isArray(v.display.history) && v.display.history.length >= 1 && v.display.history.length <= 15
      && v.display.history.every(r => validPublicReference(r, true)));
}
export function publicProjection(op: string, v: unknown, b: Record<string, unknown> = {}): boolean {
  if(op==='public-archive-capabilities')return validArchiveCapabilities(v);
  if(op==='public-archive-export-object')return validArchiveExport(v)&&v.post_number===String(b.number)&&v.bundle_hash===b.bundle_hash;
  if(op==='public-archive-import-object'){
    if(!validArchiveRestore(v)||!object(v)||!validArchive(b.archive,1))return false;
    const expected=b.archive;
    return canonicalAscii(v.scope)===canonicalAscii(expected.scope)&&(v.present_hashes as string[]).every(h=>h===expected.objects[0].bundle_hash);
  }
  if(op==='public-archive-cache-status')return validArchiveStatus(v)&&canonicalAscii(v.bundle_hashes)===canonicalAscii(b.bundle_hashes);
  if (!object(v)) return false;
  if(op==='public-ticket-bulk-progress'){
    if(v.batch_id!==b.batch_id)return false;
    const {batch_id,...rest}=v;
    return exact(v,['profile','pack_hash','state','latest_block','finalized_block','payment_block','batch_id'])
      &&publicProjection('public-ticket-progress',rest,{pack_hash:rest.pack_hash});
  }
  if(op.startsWith('public-ticket-bulk-')){
    if(!validBulkPurchase(v))return false;
    if(v.phase==='none')return op==='public-ticket-bulk-status';
    if(op==='public-ticket-bulk-arm')return v.batch_id===b.batch_id&&v.payer===b.payer&&v.dispatch_authorized===true;
    return !('dispatch_authorized'in v)&&(op==='public-ticket-bulk-status'||op==='public-ticket-bulk-prepare'
      ||['public-ticket-bulk-recover','public-ticket-bulk-resume','public-ticket-bulk-refund'].includes(op)&&v.batch_id===b.batch_id);
  }
  if (op==='public-ticket-progress')return exact(v,['profile','pack_hash','state','latest_block','finalized_block','payment_block'])
    && v.profile==='nockapp-ticket-payment-progress-v1' && hash(v.pack_hash) && v.pack_hash===b.pack_hash
    && integer(v.latest_block) && integer(v.finalized_block) && v.finalized_block<=v.latest_block
    && (v.state==='confirming'?integer(v.payment_block,1)&&v.payment_block>v.finalized_block&&v.payment_block<=v.latest_block
      : ['not-seen','finalized'].includes(String(v.state))&&v.payment_block===null);
  if (op === 'public-source-finality') return exact(v, ['profile','chain_id','latest_block','finalized_block',
    'latest_revision','finalized_revision','target_block','pending']) && v.profile==='nockapp-public-source-finality-v1'
    && v.chain_id===84532 && integer(v.latest_block) && integer(v.finalized_block) && v.finalized_block<=v.latest_block
    && integer(v.latest_revision,1) && integer(v.finalized_revision,1) && v.finalized_revision<=v.latest_revision
    && typeof v.pending==='boolean' && (v.pending
      ? v.latest_revision>v.finalized_revision && integer(v.target_block,1)
        && v.target_block>v.finalized_block && v.target_block<=v.latest_block
      : v.latest_revision===v.finalized_revision && v.target_block===null);
  if (op === 'public-source-status') return exact(v, ['profile', 'credential_record_present', 'renewal_pending'])
    && v.profile === 'nockapp-public-source-status-v1' && typeof v.credential_record_present === 'boolean' && typeof v.renewal_pending === 'boolean';
  if (['public-source-begin', 'public-source-check-post', 'public-source-recover', 'public-source-cancel'].includes(op)) return exact(v, ['profile', 'state', 'credential_saved', 'post_text'])
    && v.profile === 'nockapp-renewal-enrollment-v3'
    && ['empty','waiting-for-source-post','begin-recovery-required','credential-saved','pending','issued','committed','aborted','expired','failed',
      'activation-pending-finality','activation-replaced-or-revoked','cancelled'].includes(String(v.state))
    && typeof v.credential_saved === 'boolean' && v.credential_saved === (v.state === 'credential-saved')
    && (v.post_text === null || typeof v.post_text === 'string' && /^testing:[0-9a-f]{64}$/.test(v.post_text))
    && (!['empty','begin-recovery-required','credential-saved','cancelled'].includes(String(v.state)) || v.post_text === null);
  if (op === 'public-export-submission') return exact(v, ['profile','scope','bundle_hash','bundle_base64','calldata','contains_private_key','personal_wallet_required'])
    && v.profile === 'nockapp-public-submission-v5' && validPublicScope(v.scope) && hash(v.bundle_hash)
    && typeof v.bundle_base64 === 'string' && v.bundle_base64.length > 0 && v.bundle_base64.length <= 87384
    && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v.bundle_base64)
    && v.calldata === '0xd9caa3d2' + v.bundle_hash.slice(2) && v.contains_private_key === false && v.personal_wallet_required === false;
  if (op === 'public-direct-ready' || op === 'public-direct-public-ready') return exact(v, ['scope','bundle_hash','calldata','public_readback_checked','payer_address_public'])
    && validPublicScope(v.scope) && hash(v.bundle_hash) && v.calldata === '0xd9caa3d2' + v.bundle_hash.slice(2)
    && (op !== 'public-direct-public-ready' || v.bundle_hash === b.bundle_hash)
    && v.public_readback_checked === true && v.payer_address_public === true;
  if (op==='public-ticket-offer') return validTicketOffer(v);
  if (op==='public-ticket-pending') return validTicketPending(v);
  if (op==='public-ticket-arm') return validArmedPurchase(v) && v.payment_intent.profile==='nockapp-ticket-wallet-payment-intent-v2'
    && v.pack_hash===b.pack_hash && v.payment_intent.payer===b.payer && v.payment_intent.nonce===b.nonce && v.payment_tx===null;
  if (op==='public-ticket-intent') return validArmedPurchase(v);
  if (op==='public-ticket-find') {
    const {search_state,checked_through,receipt_status,...a}=v;
    return exact(v,[...Object.keys(a),'search_state','checked_through',...(search_state==='transaction-found'?['receipt_status']:[])])
      && validArmedPurchase(a) && validTicketAnchor(checked_through)
      && (search_state==='transaction-found' ? a.payment_tx!==null && ['0x0','0x1'].includes(String(receipt_status))
        : ['not-finalized','nonce-consumed-by-other-transaction','nonce-consumed-unresolved'].includes(String(search_state)));
  }
  if (op==='public-ticket-close-attempt') return validClosedAttempt(v) && v.pack_hash===b.pack_hash;
  if (op==='public-ticket-refund-request') return validTicketRefundReply(v);
  if (op==='public-ticket-refund-state') return validRefundState(v);
  if (['public-ticket-refund-status','public-ticket-refund-recover'].includes(op)) return validRefundResult(v) && v.pack_hash===b.pack_hash;
  if (op==='public-ticket-refund-result') return validRefundResult(v) || exact(v,['state','payout_confirmed']) && v.state==='cancellation-recorded' && v.payout_confirmed===false;
  if (op === 'public-wallet-request') return validPublicWalletShape(v) && v.post_id === b.post_id && v.address === b.address;
  if (['public-wallet-result','public-wallet-finish','public-wallet-recover','public-wallet-reset'].includes(op)) return validPublicSubmission(v) && v.core.post.id === b.post_id
    && (op === 'public-wallet-reset' ? v.bundle_hash === null : v.bundle_hash !== null) && v.verification_current === false;
  if (op === 'public-capabilities') return exact(v, ['configured', 'protocol', 'scope', 'follower_proof_configured', 'verifier_release', 'anonymous_ticket_packs', 'source_enrollment_configured', 'historical_issuer_views',...([7,9,10,11,12].includes(Number(v.verifier_release))?['refund_payout_configured']:[]),...([8,9,10,11,12].includes(Number(v.verifier_release))?['publication_mode']:[])])
    && v.configured === true && v.protocol === 5 && validPublicScope(v.scope)
    && ([9,10,11,12].includes(v.verifier_release as number) ? ['direct','tickets'].includes(String(v.publication_mode)) && v.anonymous_ticket_packs === (v.publication_mode === 'tickets')
      && v.follower_proof_configured === true && v.source_enrollment_configured === true && v.historical_issuer_views === true
      && typeof v.refund_payout_configured === 'boolean' && (!v.refund_payout_configured || v.publication_mode === 'tickets')
      : v.verifier_release === 8 ? v.publication_mode === 'direct' && v.anonymous_ticket_packs === false
      && v.follower_proof_configured === false && v.source_enrollment_configured === false && v.historical_issuer_views === false
      : (v.verifier_release === 6 || v.verifier_release===7 && v.refund_payout_configured===true) && v.anonymous_ticket_packs === true)
    && typeof v.follower_proof_configured === 'boolean' && typeof v.source_enrollment_configured === 'boolean' && typeof v.historical_issuer_views === 'boolean';
  if (op === 'public-identity-options') return exact(v, ['identity_record_present', 'sources']) && typeof v.identity_record_present === 'boolean'
    && Array.isArray(v.sources) && v.sources.length <= 8 && v.sources.every(r => object(r) && exact(r, ['source_id', 'kind', 'identity_record_present', 'pending_recovery'])
      && hex(r.source_id) && ['author-v4', 'count-v2', 'domain-v1'].includes(String(r.kind)) && typeof r.identity_record_present === 'boolean' && typeof r.pending_recovery === 'boolean')
    && new Set(v.sources.map(r => r.source_id)).size === v.sources.length;
  if (['public-initialize-identity', 'public-adopt-identity'].includes(op)) return identity(v);
  if (op === 'public-ticket-status' || op === 'public-ticket-recover') return ticketStatus(v, op.endsWith('recover'));
  if (op==='public-ticket-payment' && validArmedPurchase(v)) return v.pack_hash===b.pack_hash && v.payment_tx===b.transaction_hash;
  if (['public-ticket-prepare', 'public-ticket-payment'].includes(op)) return purchase(v, b);
  if (op === 'public-page') {
    if (!exact(v, ['profile', 'posts', 'requested_numbers', 'next_number', 'finalized_block', 'whole_log_complete', 'checked_records', 'rpc_finality_trusted', 'verifier_profile', 'verifier_version', 'after', 'next_after', 'more'])
      || !integer(b.after) || !integer(b.limit, 1, 4) || v.after !== b.after || !Array.isArray(v.posts) || !number(v.next_number)
      || b.after >= Number(v.next_number) || v.posts.length !== Math.min(b.limit, Number(v.next_number) - 1 - b.after)
      || v.next_after !== b.after + v.posts.length || v.more !== (Number(v.next_after) < Number(v.next_number) - 1)) return false;
    const { after: _after, next_after: _next, more: _more, ...page } = v;
    const requested = Array.from({ length: v.posts.length }, (_, i) => Number(b.after) + i + 1);
    if (!requested.length) return page.profile === 'nockapp-public-page-v6' && page.verifier_profile === 'nockapp-public-verifier-v6' && hex(page.verifier_version)
      && page.whole_log_complete === false && page.rpc_finality_trusted === true && page.checked_records === 0
      && Array.isArray(page.requested_numbers) && !page.requested_numbers.length && object(page.finalized_block)
      && exact(page.finalized_block, ['number', 'hash']) && typeof page.finalized_block.number === 'string'
      && /^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(page.finalized_block.number) && hash(page.finalized_block.hash);
    return publicProjection('public-numbers', page, { numbers: requested });
  }
  if (op === 'public-numbers') return exact(v, ['profile', 'posts', 'requested_numbers', 'next_number', 'finalized_block', 'whole_log_complete', 'checked_records', 'rpc_finality_trusted', 'verifier_profile', 'verifier_version'])
    && v.profile === 'nockapp-public-page-v6' && v.verifier_profile === 'nockapp-public-verifier-v6' && hex(v.verifier_version)
    && number(v.next_number) && v.whole_log_complete === false && v.rpc_finality_trusted === true && integer(v.checked_records, 0, 32)
    && object(v.finalized_block) && exact(v.finalized_block, ['number', 'hash']) && typeof v.finalized_block.number === 'string'
    && /^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(v.finalized_block.number) && hash(v.finalized_block.hash)
    && Array.isArray(v.posts) && v.posts.length >= 1 && v.posts.length <= 4 && v.posts.every(validPublicRow)
    && v.posts.every(r => object(r) && (r.state === 'unassigned' ? Number(r.post_number) >= Number(v.next_number)
      : Number(r.post_number) < Number(v.next_number) && Number(r.block_number) <= Number(BigInt(String((v.finalized_block as Record<string, unknown>).number)))))
    && Array.isArray(b.numbers) && canonicalAscii(v.requested_numbers) === canonicalAscii(b.numbers.map(String))
    && canonicalAscii(v.posts.map(r => r.post_number)) === canonicalAscii(v.requested_numbers);
  if (op === 'public-outbox') return exact(v, ['entries', 'next_after']) && Array.isArray(v.entries) && integer(b.after, 0, 40) && integer(b.limit, 1, 4)
    && v.entries.length <= b.limit && v.entries.every(validPublicSubmission) && v.entries.every(r => r.verification_current === false)
    && (v.next_after === null || v.next_after === b.after + v.entries.length && integer(v.next_after, 1, 39) && v.entries.length === b.limit);
  return ['public-prepare', 'public-finish', 'public-publish', 'public-check', 'public-attach-history', 'public-attach-followers'].includes(op)
    && validPublicSubmission(v) && (b.post_id === undefined || v.core.post.id === b.post_id)
    && (!['public-finish', 'public-publish', 'public-check'].includes(op) || v.bundle_hash !== null)
    && (!['public-publish', 'public-check'].includes(op) || v.verification_current === true)
    && (op !== 'public-prepare' || canonicalAscii(v.core.post) === canonicalAscii(b.post) && canonicalAscii(v.core.selection) === canonicalAscii(b.selection)
      && canonicalAscii(v.core.thread) === canonicalAscii(b.thread) && canonicalAscii(v.core.references) === canonicalAscii(b.references ?? []));
}

let active: symbol | undefined;
const waiting: (()=>void)[]=[];
function nextPublicRequest(){if(!active)waiting.shift()?.();}
export const PUBLIC_NATIVE_HOST = 'com.nockapp.zkid.public';
const ORIGINAL_NATIVE_HOST = 'com.nockapp.zkid';
let admittedPublicHost: string | undefined;
export function attachPublicDiscussion(ui: chrome.runtime.Port, walletPostId?: string, ticketsOnly=false) {
  let connected = true;let cleanup: (() => void) | undefined;
  ui.onDisconnect.addListener(() => { connected = false;cleanup?.(); });
  const emit = (v: object) => { if (connected) try { ui.postMessage({ version: PUBLIC_VERSION, ...v }); } catch { connected = false;cleanup?.(); } };
  const receive=(m: unknown,deadline=performance.now()+185000)=>{
    if (!connected || cleanup) return;
    if (!object(m) || !exact(m, ['version', 'operation', 'body']) || m.version !== PUBLIC_VERSION || typeof m.operation !== 'string' || !object(m.body)
      || !validPublicBody(m.operation, m.body) || !bounded(m, m.operation==='public-archive-import-object'?98304:32768)
      || ticketsOnly && !(m.operation==='public-capabilities' || m.operation.startsWith('public-ticket-'))
      || !ticketsOnly && walletPostId===undefined && m.operation.startsWith('public-ticket-') && !['public-ticket-status','public-ticket-recover'].includes(m.operation)
      || walletPostId !== undefined && !['public-capabilities','public-outbox','public-wallet-request','public-wallet-result','public-wallet-finish','public-wallet-recover','public-wallet-reset'].includes(m.operation)
      || walletPostId !== undefined && m.operation.startsWith('public-wallet-') && m.body.post_id !== walletPostId
      || walletPostId === undefined && m.operation.startsWith('public-wallet-')) { emit({ error: 'message-schema' });return; }
    const remaining=deadline-performance.now();
    if(remaining<=0){emit({error:'helper-busy'});return;}
    if(active){
      if(waiting.length>=8){emit({error:'helper-busy'});return;}
      // Wait before the FIRST native dispatch. Never repeat or reroute a
      // request that timed out or received a reply. Closing its view cancels
      // queued work, including user-authorized mutations, before dispatch.
      const saved=structuredClone(m);let cancelled=false;
      const start=()=>{if(cancelled||!connected)return;cancelled=true;clearTimeout(timeout);cleanup=undefined;receive(saved,deadline);};
      const cancel=()=>{cancelled=true;clearTimeout(timeout);const i=waiting.indexOf(start);if(i>=0)waiting.splice(i,1);cleanup=undefined;};
      const timeout=setTimeout(()=>{cancel();emit({error:'helper-busy'});},remaining);
      cleanup=cancel;waiting.push(start);return;
    }
    const owner = Symbol('public-operation');active = owner;
    const id = crypto.randomUUID().replaceAll('-', '');let settled = false;let port: chrome.runtime.Port | undefined;let timer: ReturnType<typeof setTimeout>;
    const discovery = m.operation === 'public-capabilities';
    if (discovery) admittedPublicHost = undefined;
    let host = discovery ? PUBLIC_NATIVE_HOST : admittedPublicHost ?? PUBLIC_NATIVE_HOST;
    let received = false;let detach = () => {};
    const done = (v?: unknown, error?: string) => { if (settled) return;settled = true;cleanup?.();emit(error ? { error } : { result: v }); };
    const response = (v: unknown) => {
      if (settled || !connected || !port) return;
      try {
        if (!object(v) || v.profile !== NATIVE || v.id !== id || v.laboratory !== true || v.verified !== false || !bounded(v, 131072)) return done(undefined, 'unsupported-helper');
        if (v.status === 'rejected' && exact(v, ['profile', 'id', 'status', 'code', 'recoverable', 'laboratory', 'verified']) && v.recoverable === true) {
          if (v.code === 'native-operation-unavailable') return done(undefined, 'recovery-needed');
          if (m.operation === 'public-publish' && ['publication-follower-window-unavailable','publication-ticket-needed'].includes(String(v.code)))
            return done(undefined, String(v.code));
        }
        if (v.status !== 'ok' || !exact(v, ['profile', 'id', 'status', 'result', 'laboratory', 'verified']) || !publicProjection(String(m.operation), v.result, m.body as Record<string, unknown>)) return done(undefined, 'unsupported-helper');
        if (discovery) admittedPublicHost = host;
        done(structuredClone(v.result));
      } catch { done(undefined, 'unsupported-helper'); }
    };
    const lost = () => {
      void api().runtime.lastError;
      // Only the read-only discovery request may try an older installation.
      // Never reroute a mutation, a timeout or any operation after a reply.
      if (discovery && host === PUBLIC_NATIVE_HOST && !received) {
        const old=port;detach();port=undefined;old?.disconnect();host=ORIGINAL_NATIVE_HOST;dial();
      } else done(undefined, 'helper-unavailable');
    };
    const dial = () => {
      try {
        const connection=api().runtime.connectNative(host);port=connection;
        const onMessage=(v:unknown)=>{if(port===connection){received=true;response(v);}};
        const onDisconnect=()=>{if(port===connection)lost();};
        detach=()=>{connection.onMessage.removeListener(onMessage);connection.onDisconnect.removeListener(onDisconnect);};
        connection.onMessage.addListener(onMessage);connection.onDisconnect.addListener(onDisconnect);
        connection.postMessage({ profile: NATIVE, id, operation: m.operation, body: m.body });
      } catch { lost(); }
    };
    cleanup = () => { settled = true;clearTimeout(timer);const old = port;detach();port = undefined;old?.disconnect();if (active === owner) active = undefined;cleanup = undefined;queueMicrotask(nextPublicRequest); };
    timer = setTimeout(() => done(undefined, 'recovery-needed'), remaining);dial();
  };
  ui.onMessage.addListener(m=>receive(m));
}
let queue: Promise<unknown> = Promise.resolve();
export class PublicOperationError extends Error {
  constructor(readonly code:string,message:string){super(message);}
}
function rawPublicOperation<T = unknown>(operation: PublicOperation, supplied: Record<string, unknown> = {}, signal?: AbortSignal): Promise<T> {
  const body = structuredClone(supplied);
  const run = () => new Promise<T>((resolve, reject) => {
    try { if (!validPublicBody(operation, body) || signal?.aborted) throw new Error(); } catch { reject(new Error('Invalid or cancelled public operation.'));return; }
    let port: chrome.runtime.Port | undefined;let timer: ReturnType<typeof setTimeout>;let settled = false;
    const done = (v?: unknown, error?: string,code='operation-unavailable') => { if (settled) return;settled = true;clearTimeout(timer);signal?.removeEventListener('abort', abort);port?.disconnect();if (error) reject(new PublicOperationError(code,error));else resolve(v as T); };
    const abort = () => done(undefined, 'Operation stopped. Recover the saved purchase or post before retrying.');signal?.addEventListener('abort', abort, { once: true });
    try { port = api().runtime.connect({ name: PUBLIC_PORT });port.onDisconnect.addListener(() => { void api().runtime.lastError;done(undefined, 'The public helper disconnected. Recover the saved operation.'); });
      port.onMessage.addListener((v: unknown) => { try {
        if(object(v)&&typeof v.version==='string'&&/^nockapp-permissionless-discussion-[0-9]+$/.test(v.version)&&v.version!==PUBLIC_VERSION)
          return done(undefined,'NockApp background update required. Reload the extension itself; saved purchases and posts are preserved.','extension-update-required');
        if (object(v) && v.version === PUBLIC_VERSION && exact(v, ['version', 'error']) && typeof v.error === 'string') {
          const saved = ['public-capabilities','public-page','public-numbers','public-outbox','public-identity-options','public-source-status','public-source-finality','public-ticket-status'].includes(operation)
            ? 'Your saved data is safe. Try again when the service is available.'
            : 'Check the saved operation before trying again; do not repeat a payment.';
          const messages: Record<string, string> = {
            'helper-busy': 'Another action is still running. Wait for it to finish.',
            'helper-unavailable': 'The installed app is unavailable. Reopen this view. ' + saved,
            'recovery-needed': 'The action could not be confirmed. ' + saved,
            'publication-follower-window-unavailable': 'The saved follower proof has run out of time. Your exact comment and ticket assignment are preserved.',
            'publication-ticket-needed': 'No ticket is available for this comment. Buy or recover tickets; do not repeat an existing payment.',
            'unsupported-helper': 'The installed app returned an unsupported response. ' + saved,
          };
          if (Object.hasOwn(messages, v.error)) return done(undefined, messages[v.error],v.error);
        }
        if (!object(v) || v.version !== PUBLIC_VERSION || !exact(v, ['version', 'result']) || !publicProjection(operation, v.result, body)) return done(undefined, 'Public operation unavailable. Recover the saved purchase or post.');
        done(structuredClone(v.result));
      } catch { done(undefined, 'Unsupported public helper reply.'); } });
      timer = setTimeout(() => done(undefined, 'Public operation timed out. Recover the saved operation.'), 190000);port.postMessage({ version: PUBLIC_VERSION, operation, body });
    } catch { done(undefined, 'The configured public helper is unavailable.'); }
  });
  const result = queue.then(run);queue = result.catch(() => undefined);return result;
}

// Check selected links against the actual frozen public bytes before any publish
// or wallet authorization. No signing or publishing is performed by this check.
export async function publicOperation<T = unknown>(operation: PublicOperation, supplied: Record<string, unknown> = {}, signal?: AbortSignal): Promise<T> {
  const body = structuredClone(supplied);
  if (!['public-publish','public-direct-ready','public-export-submission','public-wallet-request'].includes(operation)) return rawPublicOperation<T>(operation,body,signal);
  if (!validPublicBody(operation,body) || signal?.aborted) throw Error('Invalid or cancelled public operation.');
  const { publicIntents } = await import('./data/publicIntents');
  const intent = (await publicIntents()).find(r => r.post.id === body.post_id);
  if (!intent?.history) return rawPublicOperation<T>(operation,body,signal);
  const { assertHistoryExport, assertHistoryBinding } = await import('./publicHistory');
  if (operation === 'public-publish' || operation === 'public-direct-ready') {
    const exported = await rawPublicOperation<PublicExport>('public-export-submission',{post_id:body.post_id,approve_public_export:true},signal);
    await assertHistoryExport(intent,exported);
  }
  const result = await rawPublicOperation<T>(operation,body,signal);
  if (operation === 'public-export-submission') await assertHistoryExport(intent,result as PublicExport);
  if (operation === 'public-wallet-request') assertHistoryBinding(intent,(result as {binding:unknown}).binding);
  return result;
}
