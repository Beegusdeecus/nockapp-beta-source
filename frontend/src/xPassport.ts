import { api } from './platform/browser';
import { NATIVE_HOST, PROOF_BRIDGE_PROFILE, PROOF_CONSENT, PROOF_ERRORS } from './xSourceFlow';
import type { PassportFact } from './model';
import { PASSPORT_FACTS } from './postScope';

export type PassportOperation = 'passport_status' | 'logout' | 'delete_passports' | 'use_passport' | 'inspect_post';
export type PassportSummary = { status: 'checked' | 'synthetic'; observedAt: number; expiresAt: number;
  facts: ('account-controlled' | 'followers-over-10000')[] };
export type PostFactResult = { status: 'post-used' | 'post-checked' | 'synthetic-post-used' | 'synthetic-post-checked';
  fact: PassportFact; challenge: string; observedAt: number; expiresAt: number; verifiedAt: number };
export type PassportResult = PassportSummary | PostFactResult | { status: 'logged-out' | 'deleted' };
export class PassportError extends Error {
  constructor(public readonly code: string) { super(code); }
}
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

/** One narrowly scoped operation per fresh port. No X permissions, capture,
 * trust configuration, paths, secrets or persisted browser credential state. */
type Options = { deleteHolder?: boolean; signal?: AbortSignal; scope?: string; fact?: PassportFact; challenge?: string };
let queue: Promise<unknown> = Promise.resolve();
export function passportOperation(operation: PassportOperation, options: Options = {}): Promise<PassportResult> {
  // Serialize this page's checks so a list of badges cannot race its own helper.
  const captured = { ...options };
  const result = queue.then(() => execute(operation, captured));
  queue = result.catch(() => undefined);
  return result;
}
function execute(operation: PassportOperation, options: Options): Promise<PassportResult> {
  return new Promise((resolve, reject) => {
    const scoped = operation === 'use_passport' || operation === 'inspect_post';
    const hex = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value) && !/^0+$/.test(value);
    if (!['passport_status', 'logout', 'delete_passports', 'use_passport', 'inspect_post'].includes(operation)
        || (options.deleteHolder !== undefined && (operation !== 'delete_passports' || typeof options.deleteHolder !== 'boolean'))
        || (scoped ? !hex(options.scope) || !options.fact || !PASSPORT_FACTS.includes(options.fact)
          || (operation === 'inspect_post' ? !hex(options.challenge) : options.challenge !== undefined)
          : options.scope !== undefined || options.fact !== undefined || options.challenge !== undefined)) {
      reject(new PassportError('message-schema')); return;
    }
    let port: chrome.runtime.Port | undefined;
    let settled = false;
    let checkingCapabilities = true;
    let laboratory = false;
    let pending = crypto.randomUUID().replaceAll('-', '');
    let timer: ReturnType<typeof setTimeout>;
    const finish = (result?: PassportResult, code?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', abort);
      port?.disconnect();
      if (result) resolve(result); else reject(new PassportError(code ?? 'helper-operation-failed'));
    };
    const abort = () => finish(undefined, 'job-cancelled');
    const deadline = (ms: number) => { clearTimeout(timer); timer = setTimeout(() => finish(undefined, 'job-deadline-expired'), ms); };
    if (options.signal?.aborted) { abort(); return; }
    options.signal?.addEventListener('abort', abort, { once: true });
    try {
      port = api().runtime.connectNative(NATIVE_HOST);
      port.onDisconnect.addListener(() => { void api().runtime.lastError; finish(undefined, 'helper-unavailable'); });
      port.onMessage.addListener((value: unknown) => {
        if (settled) return;
        if (!record(value) || JSON.stringify(value).length > 4096 || value.id !== pending) {
          finish(undefined, 'unsupported-helper'); return;
        }
        if (checkingCapabilities) {
          if (value.status !== 'ready' || value.protocol !== 2 || value.bridge_profile !== PROOF_BRIDGE_PROFILE
              || value.consent_profile !== PROOF_CONSENT || value.proving_available !== true
              || value.passport_available !== true || typeof value.laboratory !== 'boolean'
              || (scoped && value.scoped_post_use_available !== true)
              || value.verified !== false || value.passport_issuance_allowed !== false) {
            finish(undefined, 'unsupported-helper'); return;
          }
          checkingCapabilities = false;
          laboratory = value.laboratory;
          pending = crypto.randomUUID().replaceAll('-', '');
          deadline(185_000);
          try {
            port!.postMessage({ id: pending, op: operation,
              ...(operation === 'delete_passports' ? { delete_holder: options.deleteHolder === true } : {}),
              ...(scoped ? { scope: options.scope, fact: options.fact } : {}),
              ...(operation === 'inspect_post' ? { challenge: options.challenge } : {}) });
          } catch { finish(undefined, 'helper-unavailable'); }
          return;
        }
        if (value.type === 'progress' && (value.stage === 'starting' || (scoped && ['holder-possession', 'verify-action'].includes(String(value.stage)))) && value.verified === false
            && value.passport_issuance_allowed === false) return;
        if (value.status === 'rejected' && value.verified === false && value.passport_issuance_allowed === false) {
          finish(undefined, typeof value.code === 'string' && PROOF_ERRORS.includes(value.code) ? value.code : 'helper-operation-failed'); return;
        }
        if ((operation === 'logout' && value.status === 'logged-out') || (operation === 'delete_passports' && value.status === 'deleted')) {
          if (value.verified !== false || value.passport_issuance_allowed !== false) finish(undefined, 'unsupported-helper');
          else finish({ status: value.status });
          return;
        }
        const now = Math.floor(Date.now() / 1000);
        const facts = value.facts;
        const datesValid = Number.isSafeInteger(value.observed_at) && Number(value.observed_at) > 0 && Number(value.observed_at) <= now + 5
          && Number.isSafeInteger(value.expires_at) && Number(value.expires_at) > now
          && Number(value.expires_at) > Number(value.observed_at) && Number(value.expires_at) <= Number(value.observed_at) + 86400;
        if (scoped) {
          const archival = operation === 'inspect_post';
          if (value.status !== (laboratory ? 'synthetic-' : '') + (archival ? 'post-checked' : 'action-accepted')
              || value.laboratory !== laboratory || value.verified !== !laboratory || value.passport_issuance_allowed !== false
              || value.holder_bound !== true || value.fact !== options.fact || !hex(value.audience) || !hex(value.challenge)
              || (archival && (value.challenge !== options.challenge || value.archival_only !== true || value.fresh !== false))
              || !datesValid || !Number.isSafeInteger(value.verified_at) || Number(value.verified_at) < now - 185
              || Number(value.verified_at) > now + 5) { finish(undefined, 'unsupported-helper'); return; }
          finish({ status: laboratory ? archival ? 'synthetic-post-checked' : 'synthetic-post-used' : archival ? 'post-checked' : 'post-used',
            fact: options.fact!, challenge: value.challenge, observedAt: Number(value.observed_at),
            expiresAt: Number(value.expires_at), verifiedAt: Number(value.verified_at) });
          return;
        }
        if (operation === 'passport_status' && value.status === (laboratory ? 'synthetic-archive-ready' : 'passport-ready')
            && value.laboratory === laboratory && value.verified === !laboratory && value.passport_issuance_allowed === !laboratory
            && value.holder_bound === true && value.disclosure === 'none'
            && Array.isArray(facts) && (JSON.stringify(facts) === '["account-controlled"]'
              || JSON.stringify(facts) === '["account-controlled","followers-over-10000"]')
            && datesValid) {
          finish({ status: laboratory ? 'synthetic' : 'checked', observedAt: Number(value.observed_at),
            expiresAt: Number(value.expires_at), facts: [...facts] });
          return;
        }
        finish(undefined, 'unsupported-helper');
      });
      deadline(10_000);
      port.postMessage({ id: pending, op: 'capabilities' });
    } catch { finish(undefined, 'helper-unavailable'); }
  });
}
