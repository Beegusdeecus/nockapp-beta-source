/** MetaMask EOA signing only after explicit UI action. No hosted signing page,
 * transaction API, key export, arbitrary typed-data API or site permissions. */
import { Buffer } from 'buffer';
import processShim from 'process/browser.js';
import { exact, object, validWirePost, type WirePost } from './zkidWire';

type Provider = { request(input: { method: string; params?: unknown[] }): Promise<unknown> };
export type AddressSelection = { address: boolean; followers_threshold: number | null };
export type PostSigningScope = { application: string; contract: string; chain_id: 84532 };
export type WalletRequest = { profile: 'nockapp-protected-authorship-desktop-v4'; state: 'awaiting-wallet-signature';
  address: string; typed_data: TypedData; request_sha256: string; expired: boolean; authorization_expires_at: number };
type Field = { name: string; type: string };
type TypedData = { types: Record<string, Field[]>; primaryType: string; domain: Record<string, unknown>; message: Record<string, unknown> };
const admitted = new WeakSet<object>();
function freeze(v: unknown): void { if (v && typeof v === 'object') { Object.values(v).forEach(freeze);Object.freeze(v); } }
const PURPOSE = 'Authorize this exact NockApp post and its selected public proofs';
const CHAIN = '0x14a34';
const hex = (v: unknown, n = 64): v is string => typeof v === 'string' && new RegExp(`^[0-9a-f]{${n}}$`).test(v) && !/^0+$/.test(v);
const account = (v: unknown): v is string => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v) && !/^0x0+$/.test(v);
const hash = (v: unknown): v is string => typeof v === 'string' && v.startsWith('0x') && hex(v.slice(2));
const domainFields: Field[] = [['name', 'string'], ['version', 'string'], ['chainId', 'uint256'], ['verifyingContract', 'address']].map(([name, type]) => ({ name, type }));
const postFields: Field[] = [['purpose', 'string'], ['application', 'bytes32'], ['postAuthorHash', 'bytes32'], ['intentHash', 'bytes32'],
  ['authorshipProofHash', 'bytes32'], ['credentialEvidenceHash', 'bytes32'], ['nonce', 'bytes32'], ['issuedAt', 'uint256'], ['deadline', 'uint256']].map(([name, type]) => ({ name, type }));

export function canonicalAscii(v: unknown): string {
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number') { if (!Number.isSafeInteger(v)) throw new Error('Invalid signed integer.');return String(v); }
  if (typeof v === 'string') return JSON.stringify(v).replace(/[\u007f-\uffff]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
  if (Array.isArray(v)) return '[' + v.map(canonicalAscii).join(',') + ']';
  if (object(v)) return '{' + Object.keys(v).sort().map(k => canonicalAscii(k) + ':' + canonicalAscii(v[k])).join(',') + '}';
  throw new Error('Invalid signed data.');
}
async function digest(v: unknown): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalAscii(v)));
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function fields(v: unknown, expected: Field[]) { return JSON.stringify(v) === JSON.stringify(expected); }

export function validPostWalletRequestShape(v: unknown): v is WalletRequest {
  if (!object(v) || !exact(v, ['profile', 'state', 'address', 'typed_data', 'request_sha256', 'expired', 'authorization_expires_at'])
    || v.profile !== 'nockapp-protected-authorship-desktop-v4' || v.state !== 'awaiting-wallet-signature'
    || !account(v.address) || v.address !== v.address.toLowerCase() || !hex(v.request_sha256) || typeof v.expired !== 'boolean'
    || !Number.isSafeInteger(v.authorization_expires_at) || Number(v.authorization_expires_at) <= 0) return false;
  const data = v.typed_data;
  if (!object(data) || !exact(data, ['types', 'primaryType', 'domain', 'message']) || data.primaryType !== 'NockAppPostAuthorization'
    || !object(data.types) || !exact(data.types, ['EIP712Domain', 'NockAppPostAuthorization'])
    || !fields(data.types.EIP712Domain, domainFields) || !fields(data.types.NockAppPostAuthorization, postFields)
    || !object(data.domain) || !exact(data.domain, ['name', 'version', 'chainId', 'verifyingContract'])
    || data.domain.name !== 'NockApp Private Authorship' || data.domain.version !== '4' || data.domain.chainId !== 84532
    || !account(data.domain.verifyingContract) || !object(data.message) || !exact(data.message, postFields.map(f => f.name))) return false;
  const m = data.message;
  return m.purpose === PURPOSE && hash(m.application) && ['postAuthorHash', 'intentHash', 'authorshipProofHash', 'credentialEvidenceHash', 'nonce'].every(k => hash(m[k]))
    && Number.isSafeInteger(m.issuedAt) && Number(m.issuedAt) >= 0 && Number.isSafeInteger(m.deadline)
    && Number(m.deadline) - Number(m.issuedAt) === 60 && Number(v.authorization_expires_at) <= Number(m.deadline);
}

export async function validatePostWalletRequest(v: unknown, scope: PostSigningScope, post: WirePost,
  selection: AddressSelection, submission: string, selectedAccount: string, now = Math.floor(Date.now() / 1000)): Promise<WalletRequest> {
  if (!validWirePost(post) || post.claims.length || !hex(submission) || !account(selectedAccount)
    || !object(selection) || selection.address !== true || !exact(selection, ['address', 'followers_threshold']) || !(selection.followers_threshold === null || Number.isSafeInteger(selection.followers_threshold) && selection.followers_threshold >= 0)
    || !object(scope) || scope.chain_id !== 84532 || !hash(scope.application) || !account(scope.contract)) throw new Error('Invalid post signing scope.');
  if (!validPostWalletRequestShape(v) || v.address !== selectedAccount.toLowerCase() || v.expired || v.authorization_expires_at <= now) throw new Error('The saved wallet request is unavailable or expired.');
  const data = v.typed_data;const m = data.message;
  if (data.domain.verifyingContract !== scope.contract || m.application !== scope.application
    || Number(m.issuedAt) > now + 5 || now >= Number(m.deadline)) throw new Error('Wrong or expired post authorization.');
  const intended = { profile: 'nockapp-authored-post-intent-v4', context: { protocol: 4, chain_id: 84532, application: scope.application,
    contract: scope.contract, submission_id: submission }, post, disclosures: selection };
  if (m.intentHash !== '0x' + await digest(intended) || v.request_sha256 !== await digest(data)) throw new Error('The wallet request does not match this exact post.');
  const request = structuredClone(v) as unknown as WalletRequest;freeze(request);admitted.add(request);return request;
}

let providerPromise: Promise<Provider> | undefined;
async function metaMask(): Promise<Provider> {
  if (!providerPromise) providerPromise = (async () => {
    const root = globalThis as unknown as { Buffer?: typeof Buffer; process?: unknown };
    root.Buffer ??= Buffer;root.process ??= processShim;
    const { default: create } = await import('metamask-extension-provider');
    return create() as unknown as Provider;
  })();
  return providerPromise;
}
async function bounded(provider: Provider, method: string, params?: unknown[]): Promise<unknown> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([provider.request({ method, ...(params ? { params } : {}) }), new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('MetaMask did not reply. Reopen the wallet and recover the saved request.')), 120000);
  })]); } finally { if (timer) clearTimeout(timer); }
}
export async function connectBaseWallet(provider?: Provider): Promise<string> {
  const p = provider ?? await metaMask();const accounts = await bounded(p, 'eth_requestAccounts');
  if (!Array.isArray(accounts) || !accounts.length || accounts.length > 20 || !account(accounts[0])) throw new Error('Choose a MetaMask Ethereum account.');
  let chain = await bounded(p, 'eth_chainId');
  if (chain !== CHAIN) { await bounded(p, 'wallet_switchEthereumChain', [{ chainId: CHAIN }]);chain = await bounded(p, 'eth_chainId'); }
  if (chain !== CHAIN) throw new Error('Select Base Sepolia in MetaMask before signing.');
  return accounts[0].toLowerCase();
}
export async function signExactPost(request: WalletRequest, provider?: Provider): Promise<string> {
  if (!admitted.has(request) || Math.floor(Date.now() / 1000) >= request.authorization_expires_at) throw new Error('Validate and recover the exact post request before signing.');
  const p = provider ?? await metaMask();const accounts = await bounded(p, 'eth_accounts');const chain = await bounded(p, 'eth_chainId');
  if (!Array.isArray(accounts) || !account(accounts[0]) || accounts[0].toLowerCase() !== request.address || chain !== CHAIN) throw new Error('The wallet account or network changed. Recover the saved post before signing.');
  if (Math.floor(Date.now() / 1000) >= request.authorization_expires_at) throw new Error('The authorization expired while checking MetaMask. Recover the saved post.');
  const signature = await bounded(p, 'eth_signTypedData_v4', [request.address, JSON.stringify(request.typed_data)]);
  if (typeof signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(signature)) throw new Error('MetaMask returned an invalid signature.');
  return signature;
}

// The pinned external-extension provider is shared; each protocol keeps its own
// exact-purpose admission and signing function. No arbitrary transaction API.
export { metaMask as baseWalletProvider };
