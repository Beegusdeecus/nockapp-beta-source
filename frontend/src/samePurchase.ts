/** Exact saved-pack recovery. No wallet upgrade, new packs or automatic resend. */
import { keccak_256 } from '@noble/hashes/sha3';
import { exact, object } from './zkidWire';
import { ticketDigest, walletCall, WalletResponseTimeout, type TicketOffer } from './publicTickets';
import { walletQuantity } from './walletQuantity';
import type { BulkPurchase } from './bulkTickets';
import type { WalletProvider } from './publicWallet';
import { storage, exclusive } from './platform/storage';
export const SAME_IMPLEMENTATION='0x63c0c19a282a1b52b07dd5a65b58948a07dae32b';
export const SAME_IMPLEMENTATION_HASH='0x83805f9ac7395294043b10c3b7c1839b7e4582a3e693028c36df84978b09d4e2';
const MODE='01'+'00'.repeat(31);const MAX_FEE=1000000000000000n;
const word=(n:bigint|number)=>BigInt(n).toString(16).padStart(64,'0');
const quantity=(v:unknown):v is string=>typeof v==='string'&&/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$/.test(v);
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const address=(v:unknown):v is string=>typeof v==='string'&&/^0x[0-9a-f]{40}$/.test(v);
const wei=(v:unknown):v is string=>typeof v==='string'&&/^[1-9][0-9]{0,38}$/.test(v);
export type SamePurchaseReview={profile:'nockapp-same-purchase-review-v1';parameters:string;batch_id:string;payer:string;
  transaction:{chainId:'0x14a34';from:string;to:string;value:string;data:string;nonce:string;gas:string;gasPrice:string};
  implementation:string;implementation_keccak:string;attempt_number:number;price_wei:string;execution_fee_limit_wei:string;execution_fee_wei:string;
  checked_through:{number:string;hash:string};expires_at:number;quote_sha256:string};
export function samePurchaseCalldata(b:BulkPurchase):string{
  if(b.profile!=='nockapp-ticket-bulk-purchase-v1'||b.calls.length!==25)throw Error('Only the original saved purchase can use this recovery.');
  const tuples=b.calls.map(c=>c.to.slice(2).padStart(64,'0')+word(BigInt(c.value))+word(96)+word(36)+c.data.slice(2)+'00'.repeat(28));
  const execution=word(32)+word(25)+tuples.map((_,i)=>word(25*32+i*192)).join('')+tuples.join('');
  return '0xe9ae5c53'+MODE+word(64)+word(execution.length/2)+execution;
}
export function validSamePurchaseReview(v:unknown):v is SamePurchaseReview{
  if(!object(v)||!exact(v,['profile','parameters','batch_id','payer','transaction','implementation','implementation_keccak','attempt_number','price_wei','execution_fee_limit_wei','execution_fee_wei','checked_through','expires_at','quote_sha256'])
    ||v.profile!=='nockapp-same-purchase-review-v1'||!hash(v.parameters)||!hash(v.batch_id)||!address(v.payer)
    ||v.implementation!==SAME_IMPLEMENTATION||v.implementation_keccak!==SAME_IMPLEMENTATION_HASH||!hash(v.quote_sha256)
    ||!Number.isSafeInteger(v.attempt_number)||Number(v.attempt_number)<1||Number(v.attempt_number)>8||!wei(v.price_wei)||!wei(v.execution_fee_limit_wei)||!wei(v.execution_fee_wei)||BigInt(v.execution_fee_limit_wei)>MAX_FEE
    ||!Number.isSafeInteger(v.expires_at)||Number(v.expires_at)<=0||!object(v.checked_through)||!exact(v.checked_through,['number','hash'])
    ||!quantity(v.checked_through.number)||typeof v.checked_through.hash!=='string'||!/^0x[0-9a-f]{64}$/.test(v.checked_through.hash))return false;
  const t=v.transaction;
  return object(t)&&exact(t,['chainId','from','to','value','data','nonce','gas','gasPrice'])&&t.chainId==='0x14a34'&&t.from===v.payer&&t.to===v.payer
    &&quantity(t.value)&&BigInt(t.value)===BigInt(v.price_wei)&&quantity(t.nonce)&&BigInt(t.nonce)<2n**64n
    &&quantity(t.gas)&&BigInt(t.gas)>=21000n&&BigInt(t.gas)<=2000000n&&quantity(t.gasPrice)&&BigInt(t.gasPrice)>0n
    &&typeof t.data==='string'&&/^0xe9ae5c53[0-9a-f]{11520}$/.test(t.data)
    &&BigInt(t.gas)*BigInt(t.gasPrice)===BigInt(v.execution_fee_wei)&&BigInt(v.execution_fee_wei)<=BigInt(v.execution_fee_limit_wei);
}
const reviewed=new WeakSet<object>();const consumed=new Set<string>();
export async function validateSamePurchaseReview(v:unknown,b:BulkPurchase,offer:TicketOffer):Promise<SamePurchaseReview>{
  if(!validSamePurchaseReview(v)||v.batch_id!==b.batch_id||v.parameters!==offer.parameters||v.payer!==b.payer
    ||v.price_wei!==b.total_price_wei||v.transaction.data!==samePurchaseCalldata(b)||v.expires_at<=Date.now()/1000||v.expires_at>Date.now()/1000+181)
    throw Error('The recovery review does not match your saved purchase. No transaction was requested.');
  const {quote_sha256,...rest}=v;if(await ticketDigest(rest)!==quote_sha256)throw Error('The payment review changed. Review it again.');
  const q=structuredClone(v);Object.values(q).forEach(o=>{if(o&&typeof o==='object')Object.freeze(o);});Object.freeze(q);reviewed.add(q);return q;
}
/** Only method names and numeric codes are shown; provider error text may contain private data. */
export class SamePurchaseWalletError extends Error {
  constructor(readonly method:string,readonly code:number|null,readonly timedOut=false){
    const action=code===4001?'Cancelled in MetaMask. Your saved purchase is preserved.':code===-32002?'Open MetaMask and finish or dismiss its existing request, then try again.':code===4100?'Connect the original paying account in MetaMask, then try again.':code===4200||code===-32601?'MetaMask does not support this wallet check.':code===-32602?'MetaMask rejected the request format. This needs an app fix.':timedOut?'MetaMask did not reply. Open the wallet to check its status.':'MetaMask could not complete this step. Open the wallet and check its connection.';
    super(action);this.name='SamePurchaseWalletError';
  }
}
export async function sameWalletCall(p:WalletProvider,method:string,params?:unknown[]):Promise<unknown>{
  try{return await walletCall(p,method,params,method==='eth_sendTransaction'||method==='eth_requestAccounts'?120000:15000);}
  catch(error){throw new SamePurchaseWalletError(method,object(error)&&Number.isSafeInteger(error.code)?Number(error.code):null,error instanceof WalletResponseTimeout);}
}
export class SamePurchaseConnectionRequired extends Error {}
export async function inspectSamePurchaseWallet(p:WalletProvider,payer:string):Promise<{nonce:string;balance:bigint}>{
  const [accounts,chain]=await Promise.all([sameWalletCall(p,'eth_accounts'),sameWalletCall(p,'eth_chainId')]);
  if(!Array.isArray(accounts)||!accounts.length)throw new SamePurchaseConnectionRequired('Connect MetaMask before confirming this purchase.');
  if(typeof accounts[0]!=='string'||accounts[0].toLowerCase()!==payer||chain!=='0x14a34')throw Error('Select the original paying wallet on Base Sepolia, then review again.');
  const [code,implementation,nonce,balance]=await Promise.all([
    sameWalletCall(p,'eth_getCode',[payer,'latest']),sameWalletCall(p,'eth_getCode',[SAME_IMPLEMENTATION,'latest']),
    sameWalletCall(p,'eth_getTransactionCount',[payer,'pending']),sameWalletCall(p,'eth_getBalance',[payer,'latest'])]);
  if(code!=='0xef0100'+SAME_IMPLEMENTATION.slice(2)||typeof implementation!=='string'||!/^0x[0-9a-f]{2,32768}$/.test(implementation)
    ||(implementation.length-2)%2!==0||'0x'+Array.from(keccak_256(Uint8Array.from(implementation.slice(2).match(/../g)??[],x=>parseInt(x,16))),b=>b.toString(16).padStart(2,'0')).join('')!==SAME_IMPLEMENTATION_HASH)
    throw Error('The wallet account code changed. No transaction was requested.');
  return {nonce:walletQuantity(nonce,'transaction nonce'),balance:BigInt(walletQuantity(balance,'balance'))};
}
export async function checkSamePurchaseWallet(q:SamePurchaseReview,p:WalletProvider):Promise<void>{
  if(!reviewed.has(q)||q.expires_at<=Date.now()/1000)throw Error('This payment review expired. Review it again.');
  const wallet=await inspectSamePurchaseWallet(p,q.payer);
  if(wallet.nonce!==q.transaction.nonce)throw Error('The wallet nonce changed. Review the purchase again.');
  if(wallet.balance<BigInt(q.price_wei)+BigInt(q.execution_fee_wei))throw Error('The wallet needs more test ETH for this purchase and gas.');
  if(q.expires_at<=Date.now()/1000)throw Error('This payment review expired. Review it again.');
}
export type SamePurchaseRequest={quote_sha256:string;state:'requested'|'submitted'|'rejected';transaction_hash:string|null};
const legacyDisplayKey='nockapp:ticket:same-purchase-display:v1';
const requestKey=(batch:string)=>'nockapp:ticket:same-purchase-requests:v1:'+batch;
function validRequest(v:unknown):v is SamePurchaseRequest{
  return object(v)&&exact(v,['quote_sha256','state','transaction_hash'])&&hash(v.quote_sha256)&&['requested','submitted','rejected'].includes(String(v.state))
    &&(v.transaction_hash===null||typeof v.transaction_hash==='string'&&/^0x[0-9a-f]{64}$/.test(v.transaction_hash))&&(v.state==='submitted')===(v.transaction_hash!==null);
}
async function requestHistory(batch:string):Promise<SamePurchaseRequest[]>{
  const value=await storage.get<unknown>(requestKey(batch));if(value===undefined)return[];
  if(!Array.isArray(value)||value.length>8||!value.every(validRequest)||new Set(value.map(r=>r.quote_sha256)).size!==value.length)
    throw Error('Wallet tracking could not be checked. Your saved purchase is preserved.');
  return value;
}
export async function readSamePurchaseRequest(batch:string):Promise<SamePurchaseRequest|undefined>{
  const history=await requestHistory(batch);if(history.length)return history.at(-1);
  const previous=await storage.get<unknown>(legacyDisplayKey);
  if(object(previous)&&previous.profile==='nockapp-same-purchase-display-v1'&&previous.batch_id===batch&&hash(previous.quote_sha256)
    &&(previous.transaction_hash===null||typeof previous.transaction_hash==='string'&&/^0x[0-9a-f]{64}$/.test(previous.transaction_hash)))
    return{quote_sha256:previous.quote_sha256,state:previous.transaction_hash?'submitted':'requested',transaction_hash:previous.transaction_hash as string|null};
}
async function updateRequest(batch:string,request:SamePurchaseRequest){
  const key=requestKey(batch);await exclusive(key,async()=>{
    const history=await requestHistory(batch);const at=history.findIndex(r=>r.quote_sha256===request.quote_sha256);
    if(at<0)throw Error('Wallet tracking changed. Check the saved purchase.');history[at]=request;await storage.set(key,history);
  });
}
export async function sendSamePurchase(q:SamePurchaseReview,authorization:unknown,p:WalletProvider,onRequest?:()=>void):Promise<string>{
  if(!reviewed.has(q)||consumed.has(q.quote_sha256)||!object(authorization)||!exact(authorization,['profile','quote','dispatch_authorized'])
    ||authorization.profile!=='nockapp-same-purchase-dispatch-v1'||authorization.dispatch_authorized!==true
    ||await ticketDigest(authorization.quote)!==await ticketDigest(q))throw Error('The saved recovery authorization does not match. No payment was requested.');
  await checkSamePurchaseWallet(q,p);
  // The native authorization just simulated the exact call and rechecked all25 paid slots.
  // A second eth_call through the wallet adds a compatibility failure, not authority.
  if(consumed.has(q.quote_sha256))throw Error('This exact request was already sent. Checking its existing outcome.');
  consumed.add(q.quote_sha256);
  const key=requestKey(q.batch_id);
  await exclusive(key,async()=>{
    const history=await requestHistory(q.batch_id);const previous=await storage.get<unknown>(legacyDisplayKey);
    if(history.some(r=>r.quote_sha256===q.quote_sha256)||object(previous)&&previous.quote_sha256===q.quote_sha256)
      throw Error('This recovery request may already have been sent. Check its payment status.');
    if(history.length>=8)throw Error('The saved purchase reached its wallet review limit. No transaction was requested.');
    await storage.set(key,[...history,{quote_sha256:q.quote_sha256,state:'requested',transaction_hash:null}]);
  });
  // This durable marker means the call may have started. Never infer a failed payment from a missing reply.
  onRequest?.();let result:unknown;
  try{result=await sameWalletCall(p,'eth_sendTransaction',[q.transaction]);}
  catch(error){
    if(error instanceof SamePurchaseWalletError&&error.code===4001){try{await updateRequest(q.batch_id,{quote_sha256:q.quote_sha256,state:'rejected',transaction_hash:null});}catch{/* Preserve the conservative requested marker. */}}
    throw error;
  }
  if(typeof result!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(result))throw Error('The wallet outcome is unknown. Your saved purchase is preserved; checks will continue.');
  try{await updateRequest(q.batch_id,{quote_sha256:q.quote_sha256,state:'submitted',transaction_hash:result.toLowerCase()});}catch{/* Native fence and original pack checks remain authoritative. */}
  return result.toLowerCase();
}
