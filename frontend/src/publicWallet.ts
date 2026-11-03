/** Exact public-v5 EIP712 authorization. No arbitrary signing/transaction API. */
import { canonicalAscii, baseWalletProvider } from './authoredWallet';
import { exact, object } from './zkidWire';
import { validPublicCore, validPublicReference, type PublicCore, type PublicScope } from './publicDiscussion';
export type WalletProvider = { request(input: { method: string; params?: unknown[] }): Promise<unknown> };
type Field = { name: string; type: string };
export type PublicWalletRequest = { profile: 'nockapp-public-wallet-request-v6'; post_id: string; submission_id: string; address: string;
  request_sha256: string; expired: boolean; signature_saved: boolean; binding: { core: PublicCore; author: { exact: string; logical: string }; followers: string | null; history: string | null };
  typed_data: { types: Record<string, Field[]>; primaryType: string; domain: { name: string; version: string; chainId: number; verifyingContract: string }; message: Record<string, unknown> } };
const hash = (v: unknown, n = 64): v is string => typeof v === 'string' && new RegExp(`^[0-9a-f]{${n}}$`).test(v) && !/^0+$/.test(v);
const h32 = (v: unknown): v is string => typeof v === 'string' && v.startsWith('0x') && hash(v.slice(2));
const account = (v: unknown): v is string => typeof v === 'string' && /^0x[0-9a-f]{40}$/.test(v) && !/^0x0+$/.test(v);
const integer = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const DOMAIN = [['name', 'string'], ['version', 'string'], ['chainId', 'uint256'], ['verifyingContract', 'address']].map(([name, type]) => ({ name, type }));
const FIELDS = [['purpose', 'string'], ['application', 'bytes32'], ['coreHash', 'bytes32'], ['postAuthorHash', 'bytes32'], ['logicalAuthorHash', 'bytes32'],
  ['followerEvidenceHash', 'bytes32'], ['historyEvidenceHash', 'bytes32'], ['nonce', 'bytes32'], ['issuedAt', 'uint256'], ['deadline', 'uint256']].map(([name, type]) => ({ name, type }));
const PURPOSE = 'Authorize this exact NockApp post, its private author and selected public evidence';
const admitted = new WeakSet<object>();
const bytes = (v: string) => Uint8Array.from(v.match(/../g) ?? [], c => parseInt(c, 16));
const digest = async (v: Uint8Array) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(v)))].map(b => b.toString(16).padStart(2, '0')).join('');
const jsonHash = (v: unknown) => digest(new TextEncoder().encode(canonicalAscii(v)));
function blob(v: unknown, limit: number): Uint8Array {
  if (v === null) return new Uint8Array();
  if (typeof v !== 'string' || !v.length || v.length > 4 * Math.ceil(limit / 3) || !/^[A-Za-z0-9+/]*={0,2}$/.test(v)) throw new Error('Invalid public evidence encoding.');
  const raw = atob(v);if (!raw.length || raw.length > limit || btoa(raw) !== v) throw new Error('Invalid public evidence size.');
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
function evidence(v: unknown, kind: 'followers' | 'history'): boolean {
  if (v === null) return true;
  try {
    const raw = blob(v, kind === 'followers' ? 32768 : 16384);const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);const p = JSON.parse(text);
    const privateFields=new Set(['secret','private_key','holder_secret','local_zkid','twitter_account','followers_count','issued_at','renew_by','expires_at']);
    const publicOnly=(o:unknown,depth=0):boolean=>depth<=64 && (!o||typeof o!=='object'
      || Object.entries(o).every(([key,value])=>!privateFields.has(key)&&publicOnly(value,depth+1)));
    if (!object(p) || canonicalAscii(p) !== text || !publicOnly(p)) return false;
    if (kind === 'followers') return exact(p, ['profile', 'issuer_view', 'window_start', 'window_end', 'presentation'])
      && p.profile === 'nockapp-hidden-renewal-evidence-v3' && object(p.issuer_view) && object(p.presentation) && integer(p.window_start) && integer(p.window_end) && p.window_end - p.window_start === 60;
    return exact(p, ['profile', 'records', 'proof']) && p.profile === 'nockapp-attached-historical-authorship-v5'
      && Array.isArray(p.records) && p.records.length >= 1 && p.records.length <= 15 && p.records.every(r => validPublicReference(r, true)) && object(p.proof);
  } catch { return false; }
}
export function validPublicWalletShape(v: unknown): v is PublicWalletRequest {
  if (!object(v) || !exact(v, ['profile', 'post_id', 'submission_id', 'address', 'typed_data', 'request_sha256', 'expired', 'binding', 'signature_saved'])
    || v.profile !== 'nockapp-public-wallet-request-v6' || !hash(v.submission_id) || !account(v.address) || !hash(v.request_sha256)
    || typeof v.expired !== 'boolean' || typeof v.signature_saved !== 'boolean' || !object(v.binding)
    || !exact(v.binding, ['core', 'author', 'followers', 'history']) || !validPublicCore(v.binding.core) || !v.binding.core.selection.address
    || v.binding.core.post.id !== v.post_id || v.binding.core.context.submission_id !== v.submission_id || !object(v.binding.author)
    || !exact(v.binding.author, ['exact', 'logical']) || !hash(v.binding.author.exact, 96) || !hash(v.binding.author.logical, 96)
    || !evidence(v.binding.followers, 'followers') || !evidence(v.binding.history, 'history')
    || v.binding.core.selection.followers_threshold === null && v.binding.followers !== null) return false;
  const d = v.typed_data;
  if (!object(d) || !exact(d, ['types', 'primaryType', 'domain', 'message']) || d.primaryType !== 'NockAppPostAuthorizationV5' || !object(d.types)
    || !exact(d.types, ['EIP712Domain', 'NockAppPostAuthorizationV5']) || canonicalAscii(d.types.EIP712Domain) !== canonicalAscii(DOMAIN)
    || canonicalAscii(d.types.NockAppPostAuthorizationV5) !== canonicalAscii(FIELDS) || !object(d.domain)
    || !exact(d.domain, ['name', 'version', 'chainId', 'verifyingContract']) || d.domain.name !== 'NockApp Private Authorship' || d.domain.version !== '5'
    || d.domain.chainId !== 84532 || !account(d.domain.verifyingContract) || !object(d.message) || !exact(d.message, FIELDS.map(f => f.name))) return false;
  const m = d.message;
  return m.purpose === PURPOSE && ['application', 'coreHash', 'postAuthorHash', 'logicalAuthorHash', 'followerEvidenceHash', 'historyEvidenceHash', 'nonce'].every(k => h32(m[k]))
    && integer(m.issuedAt) && integer(m.deadline) && m.deadline - m.issuedAt === 60;
}
export async function validatePublicWalletRequest(v: unknown, scope: PublicScope, expected: PublicCore, selectedAccount: string,
  now = Math.floor(Date.now() / 1000)): Promise<PublicWalletRequest> {
  v=structuredClone(v);scope=structuredClone(scope);expected=structuredClone(expected);
  if (!validPublicWalletShape(v) || !validPublicCore(expected) || !account(selectedAccount) || v.address !== selectedAccount
    || canonicalAscii(v.binding.core) !== canonicalAscii(expected) || !integer(now)) throw new Error('The wallet request does not match this exact saved post.');
  const c = v.binding.core;const d = v.typed_data;const m = d.message;
  const { submission_id: _nonce, ...where } = c.context;
  if (canonicalAscii(where) !== canonicalAscii(scope) || d.domain.verifyingContract !== scope.contract || m.application !== scope.application
    || Number(m.issuedAt) > now || !v.signature_saved && (v.expired || now >= Number(m.deadline))) throw new Error('Wrong or expired public post authorization.');
  const hashes = await Promise.all([jsonHash(c), digest(bytes(v.binding.author.exact)), digest(bytes(v.binding.author.logical)),
    digest(blob(v.binding.followers, 32768)), digest(blob(v.binding.history, 16384))]);
  const names = ['coreHash', 'postAuthorHash', 'logicalAuthorHash', 'followerEvidenceHash', 'historyEvidenceHash'];
  if (names.some((name, i) => m[name] !== '0x' + hashes[i]) || v.request_sha256 !== await jsonHash(d)) throw new Error('The saved author or evidence commitment changed.');
  const value = structuredClone(v);const freeze = (o: unknown) => { if (o && typeof o === 'object') { Object.values(o).forEach(freeze);Object.freeze(o); } };
  freeze(value);admitted.add(value);return value;
}
async function call(p: WalletProvider, method: string, params?: unknown[]): Promise<unknown> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([p.request({ method, ...(params ? { params } : {}) }), new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('MetaMask did not reply. Recover this same saved post.')), 120000);
  })]); } finally { if (timer) clearTimeout(timer); }
}
export async function signPublicPost(request: PublicWalletRequest, provider?: WalletProvider): Promise<string> {
  if (!admitted.has(request) || request.signature_saved || request.expired || Math.floor(Date.now() / 1000) >= Number(request.typed_data.message.deadline)) throw new Error('Validate a fresh exact public request before signing.');
  const p = provider ?? await baseWalletProvider();const accounts = await call(p, 'eth_accounts');const chain = await call(p, 'eth_chainId');
  if (!Array.isArray(accounts) || !accounts.length || accounts.length>20 || typeof accounts[0]!=='string'
    || accounts[0].toLowerCase() !== request.address || chain !== '0x14a34') throw new Error('MetaMask account or network changed.');
  if (Math.floor(Date.now() / 1000) >= Number(request.typed_data.message.deadline)) throw new Error('The public request expired while checking MetaMask.');
  const signature = await call(p, 'eth_signTypedData_v4', [request.address, JSON.stringify(request.typed_data)]);
  if (typeof signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(signature)) throw new Error('Invalid MetaMask signature.');
  return signature;
}
