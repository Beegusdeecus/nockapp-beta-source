import { api } from './platform/browser';

export const PUBLIC_POST_HOST = 'com.nockapp.zkid';
export const PUBLIC_POST_PROFILE = 'nockapp-zkid-public-post-native-v1';
export const PUBLIC_POST_VERSION = 'public-post-3';
export const PUBLIC_CHALLENGE = 'testing:';
export const PUBLIC_STATES = ['empty', 'credential-saved', 'receipt-saved', 'awaiting-post',
  'begin-recovery-required', 'pending', 'issued', 'committed', 'activation-pending-finality', 'activation-replaced-or-revoked',
  'aborted', 'expired', 'failed', 'cancelled', 'forgotten'] as const;
export type PublicSummary = { state: typeof PUBLIC_STATES[number]; credentialSaved: boolean;
  username?: string; postText?: string; expiresAt?: number; nextCheckAt?: number };
export type PublicOperation = 'status' | 'begin' | 'poll-registration' | 'check-post' | 'recover' | 'cancel' | 'forget';
type RecordValue = Record<string, unknown>;
const record = (value: unknown): value is RecordValue => !!value && typeof value === 'object' && !Array.isArray(value);
const exact = (value: RecordValue, keys: string[]) => Object.keys(value).sort().join('|') === [...keys].sort().join('|');
let active: symbol | undefined;

export function publicSummary(value: unknown, operation?: PublicOperation): PublicSummary | undefined {
  if (!record(value)) return;
  if (operation === 'forget') {
    if (exact(value, ['profile', 'ready', 'remote_revocation']) && value.profile === 'nockapp-zkid-protected-domain-desktop-lab-v1'
        && value.ready === false && value.remote_revocation === false) return { state: 'forgotten', credentialSaved: false };
    return;
  }
  const base = ['state', 'credential_saved', 'laboratory', 'verified'];
  const pending = 'username' in value;
  const post = 'post_text' in value || 'expires_at' in value;
  const polling = 'next_check_at' in value;
  const needsSession = ['receipt-saved', 'awaiting-post', 'pending', 'issued', 'committed', 'activation-pending-finality',
    'activation-replaced-or-revoked', 'aborted', 'expired', 'failed'].includes(String(value.state));
  if (!exact(value, [...base, ...(pending ? ['username'] : []), ...(post ? ['post_text', 'expires_at'] : []), ...(polling ? ['next_check_at'] : [])])
      || !PUBLIC_STATES.includes(value.state as PublicSummary['state']) || value.state === 'forgotten'
      || typeof value.credential_saved !== 'boolean' || value.laboratory !== true || value.verified !== false
      || (needsSession && (!pending || !post)) || (value.state === 'begin-recovery-required' && (!pending || post))
      || (['empty', 'credential-saved', 'cancelled'].includes(String(value.state)) && (pending || post))
      || (value.state === 'empty' && value.credential_saved !== false)
      || (value.state === 'credential-saved' && value.credential_saved !== true)
      || (polling && (value.state !== 'awaiting-post' || !Number.isSafeInteger(value.next_check_at)
        || Number(value.next_check_at) < Number(value.expires_at) - 600
        || Number(value.next_check_at) > Number(value.expires_at) + 30))
      || (operation === 'poll-registration' && value.state === 'awaiting-post' && !polling)
      || (pending && (typeof value.username !== 'string' || !/^[A-Za-z0-9_]{1,15}$/.test(value.username)))
      || (post && (!pending || typeof value.post_text !== 'string'
        || !new RegExp(`^${PUBLIC_CHALLENGE}[0-9a-f]{64}$`).test(value.post_text)
        || !Number.isSafeInteger(value.expires_at) || Number(value.expires_at) <= 0
        || Number(value.expires_at) > Math.floor(Date.now() / 1000) + 605))) return;
  return { state: value.state as PublicSummary['state'], credentialSaved: value.credential_saved,
    ...(pending ? { username: value.username as string } : {}),
    ...(post ? { postText: value.post_text as string, expiresAt: Number(value.expires_at) } : {}),
    ...(polling ? { nextCheckAt: Number(value.next_check_at) } : {}) };
}

export function publicProjection(value: unknown): PublicSummary | undefined {
  if (!record(value)) return;
  const pending = 'username' in value;
  const post = 'postText' in value || 'expiresAt' in value;
  const polling = 'nextCheckAt' in value;
  if (!exact(value, ['state', 'credentialSaved', ...(pending ? ['username'] : []), ...(post ? ['postText', 'expiresAt'] : []), ...(polling ? ['nextCheckAt'] : [])])) return;
  if (value.state === 'forgotten') return exact(value, ['state', 'credentialSaved']) && value.credentialSaved === false
    ? { state: 'forgotten', credentialSaved: false } : undefined;
  return publicSummary({ state: value.state, credential_saved: value.credentialSaved, laboratory: true, verified: false,
    ...(pending ? { username: value.username } : {}), ...(post ? { post_text: value.postText, expires_at: value.expiresAt } : {}),
    ...(polling ? { next_check_at: value.nextCheckAt } : {}) });
}

function validBody(operation: string, body: RecordValue): operation is PublicOperation {
  if (['status', 'recover', 'cancel'].includes(operation)) return exact(body, []);
  if (operation === 'poll-registration') return exact(body, ['approve_source_check']) && body.approve_source_check === true;
  if (operation === 'begin') return exact(body, ['username', 'approve_public_profile_lookup'])
    && typeof body.username === 'string' && /^[A-Za-z0-9_]{1,15}$/.test(body.username) && body.approve_public_profile_lookup === true;
  if (operation === 'check-post') return exact(body, ['post', 'approve_source_check'])
    && typeof body.post === 'string' && body.post.length > 0 && body.post.length <= 512 && body.approve_source_check === true;
  return operation === 'forget' && exact(body, ['confirm_local_deletion']) && body.confirm_local_deletion === true;
}

/** Only background.ts admits the exact extension public-post page. No X access,
 * capture, browsing events, storage, account secrets or proof interface here. */
export function attachPublicPostFlow(ui: chrome.runtime.Port) {
  let connected = true;
  let native: chrome.runtime.Port | undefined;
  let cleanup: (() => void) | undefined;
  const owner = Symbol('public-post-operation');
  const emit = (state: string, extra: RecordValue = {}) => {
    if (connected) {
      try { ui.postMessage({ version: PUBLIC_POST_VERSION, state, verified: false, ...extra }); }
      catch { connected = false; cleanup?.(); cleanup = undefined; }
    }
  };
  const stop = () => { cleanup?.(); cleanup = undefined; };
  ui.onDisconnect.addListener(() => { connected = false; stop(); });
  ui.onMessage.addListener((message: unknown) => {
    if (!record(message) || !exact(message, ['version', 'op', 'body']) || message.version !== PUBLIC_POST_VERSION) {
      if (!native) emit('error', { code: 'page-update-required' });
      return;
    }
    if (message.op === 'stop' && record(message.body) && exact(message.body, [])) {
      stop(); emit('error', { code: 'recovery-needed' }); return;
    }
    if (native) return; // One admitted effect at a time; duplicate clicks do nothing.
    if (active) { emit('error', { code: 'helper-busy' }); return; }
    if (typeof message.op !== 'string' || !record(message.body) || !validBody(message.op, message.body)) {
      emit('error', { code: 'message-schema' }); return;
    }
    const operation = message.op;
    const id = crypto.randomUUID().replaceAll('-', '');
    active = owner;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let port: chrome.runtime.Port | undefined;
    const fail = (code: string) => { stop(); emit('error', { code }); };
    const onDisconnect = () => { void api().runtime.lastError; fail('helper-unavailable'); };
    const onMessage = (value: unknown) => {
      if (native !== port || !native) return;
      try {
        if (!record(value) || JSON.stringify(value).length > 32768 || value.profile !== PUBLIC_POST_PROFILE || value.id !== id
            || value.laboratory !== true || value.verified !== false) { fail('unsupported-helper'); return; }
        if (value.status === 'rejected' && exact(value, ['profile', 'id', 'status', 'code', 'recoverable', 'laboratory', 'verified'])
            && value.code === 'native-operation-unavailable' && value.recoverable === true) { fail('operation-unavailable'); return; }
        if (value.status !== 'ok' || !exact(value, ['profile', 'id', 'status', 'result', 'laboratory', 'verified'])) {
          fail('unsupported-helper'); return;
        }
        const summary = publicSummary(value.result, operation);
        if (!summary) { fail('unsupported-helper'); return; }
        stop(); emit('result', { summary });
      } catch { fail('unsupported-helper'); }
    };
    cleanup = () => {
      if (timer) clearTimeout(timer);
      if (port) { port.onMessage.removeListener(onMessage); port.onDisconnect.removeListener(onDisconnect); }
      native = undefined;
      if (active === owner) active = undefined;
      port?.disconnect();
    };
    emit('busy', { operation });
    if (!connected) return;
    try {
      port = api().runtime.connectNative(PUBLIC_POST_HOST); native = port;
      port.onMessage.addListener(onMessage); port.onDisconnect.addListener(onDisconnect);
      timer = setTimeout(() => fail('recovery-needed'), 240_000);
      port.postMessage({ profile: PUBLIC_POST_PROFILE, id, operation, body: message.body });
    } catch { fail('helper-unavailable'); }
  });
  emit('ready');
}
