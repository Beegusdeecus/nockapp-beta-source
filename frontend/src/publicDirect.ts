/** Explicit direct-payer fallback. Only submit(bytes32), zero value, Base Sepolia.
 * A saved pre-send intent survives timeouts/reloads; an uncertain send is never
 * automatically repeated. Canonical native verification remains authoritative.
 */
import { baseWalletProvider, connectBaseWallet } from './authoredWallet';
import { publicOperation, publicProjection, type PublicExport, type PublicScope, type PublicSubmission, type DirectReady } from './publicDiscussion';
import { samePublicScope } from './data/publicIntents';
import { api } from './platform/browser';
import { walletQuantity } from './walletQuantity';

type Provider = { request(input: { method: string; params?: unknown[] }): Promise<unknown> };
const transactionHash = (v: unknown): v is string => typeof v === 'string' && /^0x[0-9a-fA-F]{64}$/.test(v);
function match(scope: PublicScope, row: PublicSubmission, actual: PublicScope, hash: string) {
  const { submission_id: _id, ...savedScope } = row.core.context;
  if (!samePublicScope(scope, actual) || !samePublicScope(scope, savedScope) || row.bundle_hash !== hash)
    throw new Error('The saved post or public deployment changed. No wallet request was made.');
}
export async function publicBundleBytes(row: PublicSubmission, scope: PublicScope): Promise<Uint8Array> {
  const v = await publicOperation<PublicExport>('public-export-submission', { post_id: row.core.post.id, approve_public_export: true });
  if (!publicProjection('public-export-submission', v)) throw new Error('Invalid public export.');
  match(scope,row,v.scope,v.bundle_hash);
  const raw = Uint8Array.from(atob(v.bundle_base64), c => c.charCodeAt(0));
  const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(b=>b.toString(16).padStart(2,'0')).join('');
  if (!raw.length || raw.length > 65536 || '0x'+digest !== row.bundle_hash) throw new Error('The exported bytes do not match this saved post.');
  return raw;
}
export async function downloadPublicBundle(row: PublicSubmission, scope: PublicScope): Promise<void> {
  const raw = await publicBundleBytes(row,scope);
  const url = URL.createObjectURL(new Blob([new Uint8Array(raw)]));
  const link = document.createElement('a');link.href=url;link.download=row.bundle_hash!.slice(2)+'.json';link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
export async function publishDirect(row: PublicSubmission, scope: PublicScope, approvePublicPayer: boolean,
  provider?: Provider): Promise<string> {
  if (approvePublicPayer !== true || !row.bundle_hash) throw new Error('Approve public gas-payer visibility first.');
  match(scope,row,scope,row.bundle_hash);
  return submitDirect(row.bundle_hash,scope,approvePublicPayer,()=>publicOperation<DirectReady>('public-direct-ready',
    {post_id:row.core.post.id,approve_publication:true,approve_public_payer:true}),provider,row.core.post.id);
}
export async function publishPublicBundleHash(bundleHash: string, scope: PublicScope, approvePublicPayer: boolean,
  provider?: Provider): Promise<string> {
  if (!/^0x[0-9a-f]{64}$/.test(bundleHash) || /^0x0+$/.test(bundleHash)) throw new Error('Enter the exact public bundle SHA-256 hash, including 0x.');
  return submitDirect(bundleHash,scope,approvePublicPayer,()=>publicOperation<DirectReady>('public-direct-public-ready',
    {bundle_hash:bundleHash,approve_publication:true,approve_public_payer:true}),provider);
}
async function submitDirect(bundleHash: string, scope: PublicScope, approvePublicPayer: boolean,
  prepare:()=>Promise<DirectReady>, provider?:Provider, postId?:string):Promise<string> {
  if (approvePublicPayer !== true) throw new Error('Approve public gas-payer visibility first.');
  if (!navigator.locks) throw new Error('This browser cannot safely serialize wallet submissions.');
  const key = 'nockapp-public-direct-v1:'+scope.chain_id+':'+scope.contract+':'+bundleHash;
  return navigator.locks.request(key,async () => {
    const previous = (await api().storage.local.get(key))[key];
    if (previous !== undefined) throw new Error('A wallet attempt is already saved. Check the saved post and wallet activity before any new submission.');
    const ready = await prepare();
    if (!publicProjection('public-direct-ready',ready)) throw new Error('Public storage verification failed.');
    if (!samePublicScope(scope,ready.scope) || ready.bundle_hash !== bundleHash) throw new Error('The public bundle or deployment changed. No wallet request was made.');
    const p = provider ?? await baseWalletProvider();
    const from = await connectBaseWallet(p);
    const send = { from, to:scope.contract, chainId:'0x14a34', value:'0x0', data:ready.calldata };
    const nonce = walletQuantity(await p.request({method:'eth_getTransactionCount',params:[from,'pending']}),'transaction nonce');
    const estimate = walletQuantity(await p.request({method:'eth_estimateGas',params:[send]}),'gas estimate');
    const balance = walletQuantity(await p.request({method:'eth_getBalance',params:[from,'pending']}),'balance');
    if (BigInt(estimate)<21000n || BigInt(estimate)>200000n)
      throw new Error(`MetaMask estimated ${BigInt(estimate)} gas, outside this action's 21,000–200,000 limit. No transaction was requested.`);
    const gas = BigInt(estimate)*12n/10n+1n;
    if (gas>240000n || BigInt(balance)<gas*100000000n) throw new Error('Insufficient Base Sepolia test ETH or excessive gas.');
    // User reviews the total L2/L1/operator fee in MetaMask. The execution cap
    // alone does not bound all Base transaction fees.
    const tx = {...send,nonce,gas:'0x'+gas.toString(16),maxFeePerGas:'0x5f5e100',maxPriorityFeePerGas:'0xf4240',type:'0x2'};
    const accounts = await p.request({method:'eth_accounts'});
    const chain = await p.request({method:'eth_chainId'});
    if (chain!=='0x14a34' || !Array.isArray(accounts) || typeof accounts[0]!=='string' || accounts[0].toLowerCase()!==from)
      throw new Error('The wallet account or network changed.');
    const intent = {scope,...(postId ? {post_id:postId} : {}),bundle_hash:bundleHash,transaction:tx,requested_at:Date.now()};
    await api().storage.local.set({[key]:intent});
    let hash: unknown;
    try { hash = await p.request({method:'eth_sendTransaction',params:[tx]}); }
    catch (e) {
      // Only explicit user rejection establishes that no transaction was sent.
      if (e && typeof e==='object' && 'code' in e && e.code===4001) await api().storage.local.remove(key);
      throw new Error(e && typeof e==='object' && 'code' in e && e.code===4001
        ? 'Wallet request declined. Your saved post is unchanged.'
        : 'Wallet outcome unknown. Check the saved post and wallet activity; the attempt is retained.');
    }
    if (!transactionHash(hash)) throw new Error('Wallet outcome unknown. The saved attempt is retained.');
    await api().storage.local.set({[key]:{...intent,transaction_hash:hash}});
    return hash;
  });
}
