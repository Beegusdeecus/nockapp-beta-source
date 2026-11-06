/** Fixed shared ticket offers and one-shot wallet actions. No author/key API. */
import { keccak_256 } from '@noble/hashes/sha3'; // Already pinned1.8.0 in package-lock via MetaMask.
import { canonicalAscii, baseWalletProvider } from './authoredWallet';
import { exact, object } from './zkidWire';
import type { PublicScope } from './publicDiscussion';
import type { WalletProvider } from './publicWallet';
import { walletQuantity } from './walletQuantity';

const integer = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const hash = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) && !/^0+$/.test(v);
const h32 = (v: unknown): v is string => typeof v === 'string' && v.startsWith('0x') && hash(v.slice(2));
const address = (v: unknown): v is string => typeof v === 'string' && /^0x[0-9a-f]{40}$/.test(v) && !/^0x0+$/.test(v);
const wei = (v: unknown): v is string => typeof v === 'string' && /^[1-9][0-9]{0,38}$/.test(v) && BigInt(v) < 2n ** 128n;
const quantity = (v: unknown): v is string => typeof v === 'string' && /^0x(?:0|[1-9a-f][0-9a-f]{0,63})$/.test(v);
const hex = (v: Uint8Array) => [...v].map(b => b.toString(16).padStart(2, '0')).join('');
const bytes = (v: string) => Uint8Array.from(v.match(/../g) ?? [], c => parseInt(c, 16));
const utf8 = (v: string) => new TextEncoder().encode(v);
export const ticketDigest = async (v: unknown) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(canonicalAscii(v)))));
const taggedHash = async (tag: string, v: unknown) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(tag + '\0' + canonicalAscii(v)))));
const keccak = (v: Uint8Array) => '0x' + hex(keccak_256(v));
const selector = (v: string) => keccak(utf8(v)).slice(0, 10);
const word = (v: bigint | string) => '0x' + BigInt(v).toString(16).padStart(64, '0');
function freeze<T>(v: T): T { if (v && typeof v === 'object') { Object.values(v).forEach(freeze);Object.freeze(v); }return v; }
export type TicketOffer = { parameters: string; manifest: { terms: { profile: 'nockapp-public-prepaid-offer-v2' | 'nockapp-public-prepaid-batch-offer-v3'; payment_receipt_version?: 2; packs_per_payment?: 25; redemption_ledger: string;
  chain_id: 84532; application: string; index_contract: string; index_runtime_keccak: string; ticket_spki: string;
  pack_size: number; pack_price_wei: string; payment_recipient: string; purchase_before: number; redeem_before: number;
  max_bundle_bytes: number; max_gas: number; max_total_fee_wei: string; refund_policy: string }; purchase_contract: string; purchase_runtime_keccak: string } };
export type TicketPurchase = { profile: 'nockapp-protected-ticket-wallet-v1'; pack_hash: string; payment_tx: string | null;
  transaction: { chain_id: 84532; to: string; value: string; data: string } };
export type TicketIntent = { profile: 'nockapp-ticket-wallet-payment-intent-v1' | 'nockapp-ticket-wallet-payment-intent-v2'; payer: string; nonce: number;
  anchor?: { number: string; hash: string } };
export type ArmedPurchase = TicketPurchase & { payment_intent: TicketIntent; state: 'send-uncertain' | 'recorded' };
export type TicketPending = { profile: 'nockapp-public-ticket-purchase-state-v1'; purchase: TicketPurchase | null; payment_intent: TicketIntent | null;
  closed_attempts: number; attempt_limit: 8 };
export function validTicketOffer(v: unknown): v is TicketOffer {
  if (!object(v) || !exact(v, ['parameters', 'manifest']) || !hash(v.parameters) || !object(v.manifest)
    || !exact(v.manifest, ['terms', 'purchase_contract', 'purchase_runtime_keccak']) || !address(v.manifest.purchase_contract)
    || !h32(v.manifest.purchase_runtime_keccak) || !object(v.manifest.terms)) return false;
  const t = v.manifest.terms;
  const batch=t.profile==='nockapp-public-prepaid-batch-offer-v3';
  return exact(t, ['profile', 'redemption_ledger', 'chain_id', 'application', 'index_contract', 'index_runtime_keccak', 'ticket_spki',
    'pack_size', 'pack_price_wei', 'payment_recipient', 'purchase_before', 'redeem_before', 'max_bundle_bytes', 'max_gas', 'max_total_fee_wei', 'refund_policy', ...(batch?['payment_receipt_version','packs_per_payment']:[])])
    && (batch ? t.payment_receipt_version===2 && t.packs_per_payment===25 && t.pack_size===2
      : t.profile === 'nockapp-public-prepaid-offer-v2') && t.redemption_ledger === 'nockapp-ticket-publication-ledger-v2'
    && t.chain_id === 84532 && h32(t.application) && address(t.index_contract) && h32(t.index_runtime_keccak) && address(t.payment_recipient)
    && typeof t.ticket_spki === 'string' && t.ticket_spki.length <= 1368 && /^[A-Za-z0-9+/]+={0,2}$/.test(t.ticket_spki)
    && integer(t.pack_size) && t.pack_size >= 1 && t.pack_size <= 32 && wei(t.pack_price_wei)
    && (!batch || wei((25n*BigInt(t.pack_price_wei as string)).toString())) && wei(t.max_total_fee_wei)
    && integer(t.purchase_before) && t.purchase_before > 0 && integer(t.redeem_before) && t.redeem_before > t.purchase_before
    && t.max_bundle_bytes === 65536 && integer(t.max_gas) && t.max_gas >= 21000 && t.max_gas <= 1000000
    && t.refund_policy === 'unissued-only-durable-decision-v1';
}
export function validTicketPurchase(v: unknown): v is TicketPurchase {
  if (!object(v) || !exact(v, ['profile', 'pack_hash', 'payment_tx', 'transaction']) || v.profile !== 'nockapp-protected-ticket-wallet-v1'
    || !h32(v.pack_hash) || !(v.payment_tx === null || h32(v.payment_tx)) || !object(v.transaction)) return false;
  const t = v.transaction;
  return exact(t, ['chain_id', 'to', 'value', 'data']) && t.chain_id === 84532 && address(t.to) && quantity(t.value)
    && BigInt(t.value) > 0n && BigInt(t.value) < 2n ** 128n && t.data === '0x9c9a1061' + v.pack_hash.slice(2);
}
export function validTicketAnchor(v: unknown): v is { number: string; hash: string } {
  return object(v) && exact(v, ['number', 'hash']) && quantity(v.number) && BigInt(v.number) < 2n ** 53n && h32(v.hash);
}
export function validTicketIntent(v: unknown): v is TicketIntent {
  return object(v) && address(v.payer) && integer(v.nonce) && (v.profile === 'nockapp-ticket-wallet-payment-intent-v1'
    ? exact(v, ['profile', 'payer', 'nonce']) : v.profile === 'nockapp-ticket-wallet-payment-intent-v2'
      && exact(v, ['profile', 'payer', 'nonce', 'anchor']) && validTicketAnchor(v.anchor));
}
export function validArmedPurchase(v: unknown): v is ArmedPurchase {
  if (!object(v) || !exact(v, ['profile', 'pack_hash', 'payment_tx', 'transaction', 'payment_intent', 'state'])) return false;
  const { payment_intent, state, ...p } = v;
  return validTicketPurchase(p) && validTicketIntent(payment_intent) && state === (p.payment_tx === null ? 'send-uncertain' : 'recorded');
}
export function validTicketPending(v: unknown): v is TicketPending {
  return object(v) && exact(v, ['profile', 'purchase', 'payment_intent', 'closed_attempts', 'attempt_limit'])
    && v.profile === 'nockapp-public-ticket-purchase-state-v1' && v.attempt_limit === 8 && integer(v.closed_attempts) && v.closed_attempts <= 8
    && (v.purchase === null ? v.payment_intent === null && v.closed_attempts === 0
      : validTicketPurchase(v.purchase) && (v.payment_intent === null || validTicketIntent(v.payment_intent)));
}
const offers = new WeakSet<object>();const purchases = new WeakMap<object, TicketOffer>();
export async function validateTicketOffer(raw: unknown, scope: PublicScope): Promise<TicketOffer> {
  raw = structuredClone(raw);scope = structuredClone(scope);
  if (!validTicketOffer(raw)) throw Error('Unsupported shared ticket offer.');
  const t = raw.manifest.terms;
  if (t.application !== scope.application || t.index_contract !== scope.contract || t.chain_id !== scope.chain_id
    || raw.parameters !== await taggedHash(t.profile==='nockapp-public-prepaid-batch-offer-v3'?'nockapp-ticket-offer-manifest-v3':'nockapp-ticket-offer-manifest-v1', raw.manifest)) throw Error('Ticket offer or deployment changed.');
  const der = Uint8Array.from(atob(t.ticket_spki), c => c.charCodeAt(0));
  if (btoa(String.fromCharCode(...der)) !== t.ticket_spki) throw Error('Noncanonical ticket public key.');
  const key = await crypto.subtle.importKey('spki', der, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
  const alg = key.algorithm as RsaHashedKeyAlgorithm;
  if (alg.modulusLength !== 3072 || hex(alg.publicExponent) !== '010001'
    || hex(new Uint8Array(await crypto.subtle.exportKey('spki', key))) !== hex(der)) throw Error('Unsupported ticket public key.');
  const checked = freeze(raw);offers.add(checked);return checked;
}
export function validateTicketPurchase(raw: unknown, offer: TicketOffer): TicketPurchase {
  raw = structuredClone(raw);
  if (!offers.has(offer) || !validTicketPurchase(raw) || raw.transaction.to !== offer.manifest.purchase_contract
    || raw.transaction.value !== '0x' + BigInt(offer.manifest.terms.pack_price_wei).toString(16)) throw Error('Purchase does not match the exact shared offer.');
  const checked = freeze(raw);purchases.set(checked, offer);return checked;
}
export class WalletResponseTimeout extends Error {}
export async function walletCall(p: WalletProvider, method: string, params?: unknown[], timeoutMs=120000): Promise<unknown> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([p.request({ method, ...(params ? { params } : {}) }), new Promise((_, reject) => {
    timer = setTimeout(() => reject(new WalletResponseTimeout('Wallet response lost. Recover this saved attempt; do not pay again.')), timeoutMs);
  })]); } finally { if (timer) clearTimeout(timer); }
}
async function accountCheck(p: WalletProvider, payer: string) {
  const a = await walletCall(p, 'eth_accounts');const chain = await walletCall(p, 'eth_chainId');
  if (!Array.isArray(a) || !a.length || typeof a[0] !== 'string' || a[0].toLowerCase() !== payer || chain !== '0x14a34') throw Error('MetaMask account or network changed.');
}
async function contractCheck(p: WalletProvider, offer: TicketOffer) {
  const b = await walletCall(p, 'eth_getBlockByNumber', ['finalized', false]);
  if (!object(b) || !validTicketAnchor({ number: b.number, hash: b.hash })) throw Error('Finalized payment contract unavailable.');
  const code = await walletCall(p, 'eth_getCode', [offer.manifest.purchase_contract, b.number]);
  if (typeof code !== 'string' || !/^0x(?:[0-9a-f]{2}){1,16384}$/.test(code) || keccak(bytes(code.slice(2))) !== offer.manifest.purchase_runtime_keccak) throw Error('Pinned payment contract code changed.');
  const t = offer.manifest.terms;
  for (const [sig, expected] of [['PURCHASE_VERSION()', word(1n)], ['termsHash()', '0x' + await taggedHash('nockapp-ticket-offer-terms-v1', t)],
    ['recipient()', word(t.payment_recipient)], ['packPrice()', word(t.pack_price_wei)], ['purchaseBefore()', word(BigInt(t.purchase_before))]]) {
    if (await walletCall(p, 'eth_call', [{ to: offer.manifest.purchase_contract, data: selector(sig) }, b.number]) !== expected) throw Error('Pinned payment contract terms changed.');
  }
  const end = await walletCall(p, 'eth_getBlockByNumber', [b.number, false]);
  if (!object(end) || end.hash !== b.hash || end.number !== b.number) throw Error('Payment contract block changed.');
}
export type PaymentQuote = { kind: 'purchase' | 'cancel'; purchase: TicketPurchase; payer: string; nonce: number;
  transaction: { from: string; to: string; chainId: '0x14a34'; nonce: string; value: string; data: string; gas: string; gasPrice: string };
  execution_fee_wei: string; expires_at: number; payment_anchor: {number:string;hash:string} | null };
const quotes = new WeakSet<object>();const sends = new WeakMap<object, PaymentQuote>();
export async function quoteTicketPayment(purchase: TicketPurchase, payer: string, executionLimitWei: string, provider?: WalletProvider,
  cancelIntent?: TicketIntent): Promise<PaymentQuote> {
  const offer = purchases.get(purchase);
  cancelIntent=cancelIntent?structuredClone(cancelIntent):undefined;
  if (!offer || !address(payer) || !wei(executionLimitWei) || purchase.payment_tx !== null && !cancelIntent) throw Error('Prepare the exact unpaid pack before reviewing a payment.');
  const p = provider ?? await baseWalletProvider();await accountCheck(p, payer);
  if (cancelIntent && (!validTicketIntent(cancelIntent) || cancelIntent.profile!=='nockapp-ticket-wallet-payment-intent-v2' || cancelIntent.payer !== payer)) throw Error('Cancellation must use the saved payer, nonce and anchor.');
  await contractCheck(p, offer);
  const n = walletQuantity(await walletCall(p, 'eth_getTransactionCount', [payer, cancelIntent ? 'latest' : 'pending']), 'transaction nonce');
  if (BigInt(n) > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('Unsupported wallet nonce.');
  if (cancelIntent && BigInt(n) > BigInt(cancelIntent.nonce)) throw Error('This nonce is already mined. Check finalized recovery.');
  const nonce = cancelIntent?.nonce ?? Number(BigInt(n));
  const tx = { from: payer, to: cancelIntent ? payer : purchase.transaction.to, chainId: '0x14a34' as const,
    nonce: '0x' + nonce.toString(16), value: cancelIntent ? '0x0' : purchase.transaction.value, data: cancelIntent ? '0x' : purchase.transaction.data };
  const estimate = cancelIntent ? '0x5208' : walletQuantity(await walletCall(p, 'eth_estimateGas', [tx]), 'gas estimate');
  const price = walletQuantity(await walletCall(p, 'eth_gasPrice'), 'gas price');
  if (BigInt(estimate) < 21000n || BigInt(estimate) > 200000n || BigInt(price) === 0n) throw Error('Purchase gas quote exceeds the supported bound.');
  const gas = cancelIntent ? 21000n : (BigInt(estimate) * 120n + 99n) / 100n;const gasPrice = BigInt(price) * (cancelIntent ? 2n : 1n);
  if (gas > 200000n || gas * gasPrice > BigInt(executionLimitWei)) throw Error('Execution fee exceeds your chosen limit.');
  const quote: PaymentQuote = freeze({ kind: cancelIntent ? 'cancel' : 'purchase', purchase, payer, nonce,
    transaction: { ...tx, gas: '0x' + gas.toString(16), gasPrice: '0x' + gasPrice.toString(16) },
    execution_fee_wei: (gas * gasPrice).toString(), expires_at: Math.min(Math.floor(Date.now() / 1000) + 60,
      cancelIntent ? Number.MAX_SAFE_INTEGER : offer.manifest.terms.purchase_before), payment_anchor:cancelIntent?.anchor??null });
  quotes.add(quote);return quote;
}
export function admitTicketSend(raw: unknown, quote: PaymentQuote): ArmedPurchase {
  raw = structuredClone(raw);
  if (!quotes.has(quote) || quote.kind !== 'purchase' || !validArmedPurchase(raw) || raw.payment_tx !== null
    || raw.payment_intent.profile !== 'nockapp-ticket-wallet-payment-intent-v2' || raw.payment_intent.payer !== quote.payer
    || raw.payment_intent.nonce !== quote.nonce || raw.pack_hash !== quote.purchase.pack_hash
    || canonicalAscii(raw.transaction) !== canonicalAscii(quote.purchase.transaction)) throw Error('Saved dispatch does not match your reviewed payment.');
  quotes.delete(quote);const saved = freeze(raw);sends.set(saved, quote);return saved;
}
export async function sendTicketPayment(quote: PaymentQuote, armed?: ArmedPurchase, provider?: WalletProvider): Promise<string> {
  if (quote.kind === 'purchase' ? !armed || sends.get(armed) !== quote : !quotes.has(quote)) throw Error('A fresh reviewed dispatch is required.');
  // Consume before async checks: a disconnect or lost response never re-admits.
  if (armed) sends.delete(armed);quotes.delete(quote);
  if (Math.floor(Date.now() / 1000) >= quote.expires_at) throw Error('Payment review expired. Recover saved state before continuing.');
  const p = provider ?? await baseWalletProvider();await accountCheck(p, quote.payer);
  const anchor=armed?.payment_intent.anchor??quote.payment_anchor;
  if (anchor) {
    const a = anchor;const block = await walletCall(p, 'eth_getBlockByNumber', [a.number, false]);
    if (!object(block) || block.number !== a.number || block.hash !== a.hash) throw Error('The saved payment block changed. Recover this attempt.');
  }
  const n = walletQuantity(await walletCall(p, 'eth_getTransactionCount', [quote.payer, quote.kind === 'cancel' ? 'latest' : 'pending']), 'transaction nonce');
  if (quote.kind === 'cancel' ? BigInt(n) > BigInt(quote.nonce) : BigInt(n) !== BigInt(quote.nonce)) throw Error('The reviewed wallet nonce changed. Recover the saved attempt.');
  if (Math.floor(Date.now() / 1000) >= quote.expires_at) throw Error('Payment review expired. Recover saved state.');
  const h = await walletCall(p, 'eth_sendTransaction', [quote.transaction]);
  if (!h32(h)) throw Error('Wallet did not return a transaction hash. Recover this saved attempt.');return h;
}
export function parseEth(v: string): string {
  if (!/^(?:0|[1-9][0-9]{0,19})(?:\.[0-9]{1,18})?$/.test(v)) throw Error('Enter an exact ETH amount with at most18 decimal places.');
  const [whole, fraction = ''] = v.split('.');const amount = BigInt(whole) * 10n ** 18n + BigInt(fraction.padEnd(18, '0'));
  if (!wei(amount.toString())) throw Error('Choose a positive fee limit.');return amount.toString();
}
export function formatEth(v: string): string { const n = BigInt(v);return `${n / 10n ** 18n}.${(n % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '') || '0'}`; }
const REFUND_PURPOSE = 'Permanently cancel issuance of this paid ticket pack; refund only its original paying wallet';
function refundDataFor(parameters: string, contract: string, pack: string, payment: string | null) {
  return { types: { EIP712Domain: [['name', 'string'], ['version', 'string'], ['chainId', 'uint256'], ['verifyingContract', 'address']].map(([name, type]) => ({ name, type })),
    NockAppUnissuedPackRefundV1: [['purpose', 'string'], ['parameters', 'bytes32'], ['packHash', 'bytes32'], ['paymentTransaction', 'bytes32']].map(([name, type]) => ({ name, type })) },
    primaryType: 'NockAppUnissuedPackRefundV1', domain: { name: 'NockApp Prepaid Tickets', version: '1', chainId: 84532, verifyingContract: contract },
    message: { purpose: REFUND_PURPOSE, parameters: '0x' + parameters, packHash: pack, paymentTransaction: payment } };
}
export const refundData = (offer: TicketOffer, p: TicketPurchase) => refundDataFor(offer.parameters, offer.manifest.purchase_contract, p.pack_hash, p.payment_tx);
export type TicketRefund = { address: string; typed_data: ReturnType<typeof refundData>; request_sha256: string };
export function validTicketRefundReply(v: unknown): v is TicketRefund {
  if (!object(v) || !exact(v, ['address', 'typed_data', 'request_sha256']) || !address(v.address) || !hash(v.request_sha256)
    || !object(v.typed_data) || !object(v.typed_data.domain) || !object(v.typed_data.message)) return false;
  const m=v.typed_data.message;const c=v.typed_data.domain.verifyingContract;
  return address(c) && h32(m.parameters) && h32(m.packHash) && h32(m.paymentTransaction)
    && canonicalAscii(v.typed_data) === canonicalAscii(refundDataFor(m.parameters.slice(2),c,m.packHash,m.paymentTransaction));
}
export function validClosedAttempt(v: unknown): boolean {
  if (!object(v) || !exact(v,['state','parameters','pack_hash','closed_attempt']) || v.state!=='attempt-closed'
    || !hash(v.parameters) || !h32(v.pack_hash) || !object(v.closed_attempt)) return false;
  const c=v.closed_attempt;
  return exact(c,['profile','parameters','pack_hash','intent','transaction_hash','transaction_block','checked_through','outcome'])
    && c.profile==='nockapp-ticket-wallet-closed-payment-v1' && c.parameters===v.parameters && c.pack_hash===v.pack_hash
    && validTicketIntent(c.intent) && c.intent.profile==='nockapp-ticket-wallet-payment-intent-v2' && h32(c.transaction_hash)
    && validTicketAnchor(c.transaction_block) && validTicketAnchor(c.checked_through)
    && BigInt(c.intent.anchor!.number)<BigInt(c.transaction_block.number) && BigInt(c.transaction_block.number)<=BigInt(c.checked_through.number)
    && ['failed','other-transaction'].includes(String(c.outcome));
}
const refunds = new WeakSet<object>();
export async function validateTicketRefund(raw: unknown, offer: TicketOffer, purchase: TicketPurchase, payer: string): Promise<TicketRefund> {
  raw = structuredClone(raw);
  if (!offers.has(offer) || purchases.get(purchase) !== offer || !purchase.payment_tx || !object(raw)
    || !exact(raw, ['address', 'typed_data', 'request_sha256']) || !address(raw.address) || raw.address !== payer
    || !hash(raw.request_sha256) || canonicalAscii(raw.typed_data) !== canonicalAscii(refundData(offer, purchase))
    || raw.request_sha256 !== await ticketDigest(raw.typed_data)) throw Error('Cancellation is not bound to this paid pack and original payer.');
  const result = freeze(raw as TicketRefund);refunds.add(result);return result;
}
export async function signTicketRefund(request: TicketRefund, provider?: WalletProvider): Promise<string> {
  if (!refunds.has(request)) throw Error('Review the exact paid-pack cancellation first.');refunds.delete(request);
  const p = provider ?? await baseWalletProvider();await accountCheck(p, request.address);
  const s = await walletCall(p, 'eth_signTypedData_v4', [request.address, JSON.stringify(request.typed_data)]);
  if (typeof s !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(s)) throw Error('Invalid cancellation signature.');return s;
}
