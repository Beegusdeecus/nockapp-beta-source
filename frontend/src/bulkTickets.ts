import { exact, object } from './zkidWire';
import { baseWalletProvider } from './authoredWallet';
import { ticketDigest, walletCall, type TicketOffer } from './publicTickets';
import type { WalletProvider } from './publicWallet';
import { saveWalletTracking } from './data/ticketWalletTracking';

const address=(v:unknown):v is string=>typeof v==='string'&&/^0x[0-9a-f]{40}$/.test(v)&&!/^0x0+$/.test(v);
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v)&&!/^0+$/.test(v);
export type BulkPurchase={profile:'nockapp-ticket-bulk-purchase-v1';phase:'prepared'|'armed'|'importing'|'paused'|'complete';batch_id:string;
  ticket_count:50;pack_count:25;imported_tickets:number;settled_tickets:number;refunded_tickets:number;payer:string|null;transaction_hash:string|null;total_price_wei:string;
  calls:{to:string;value:string;data:string}[];dispatch_authorized?:true};
const admitted=new WeakSet<object>();
function freeze<T>(value:T):T{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;}
export function validBulkPurchase(v:unknown):v is BulkPurchase|{profile:'nockapp-ticket-bulk-purchase-v1';phase:'none'}{
  if(!object(v)||v.profile!=='nockapp-ticket-bulk-purchase-v1')return false;
  if(v.phase==='none')return exact(v,['profile','phase']);
  return exact(v,['profile','phase','batch_id','ticket_count','pack_count','imported_tickets','settled_tickets','refunded_tickets','payer','transaction_hash','total_price_wei','calls',...('dispatch_authorized'in v?['dispatch_authorized']:[])])
    &&['prepared','armed','importing','paused','complete'].includes(String(v.phase))&&hash(v.batch_id)&&v.ticket_count===50&&v.pack_count===25
    &&typeof v.imported_tickets==='number'&&Number.isInteger(v.imported_tickets)&&v.imported_tickets>=0&&v.imported_tickets<=50&&v.imported_tickets%2===0
    &&typeof v.settled_tickets==='number'&&Number.isInteger(v.settled_tickets)&&v.settled_tickets>=0&&v.settled_tickets<=50
    &&typeof v.refunded_tickets==='number'&&Number.isInteger(v.refunded_tickets)&&v.refunded_tickets>=0&&v.refunded_tickets%2===0
    &&v.imported_tickets+v.refunded_tickets===v.settled_tickets
    &&(v.phase==='complete')===(v.settled_tickets===50)
    &&(v.phase==='prepared'?v.payer===null&&v.transaction_hash===null&&v.imported_tickets===0:address(v.payer))
    &&(v.transaction_hash===null||typeof v.transaction_hash==='string'&&/^0x[0-9a-f]{64}$/.test(v.transaction_hash))
    &&(!['importing','complete'].includes(String(v.phase))||v.transaction_hash!==null)
    &&typeof v.total_price_wei==='string'&&/^[1-9][0-9]{0,38}$/.test(v.total_price_wei)
    &&(!('dispatch_authorized'in v)||v.dispatch_authorized===true&&v.phase==='armed')
    &&Array.isArray(v.calls)&&v.calls.length===25&&v.calls.every(c=>object(c)&&exact(c,['to','value','data'])&&address(c.to)
      &&typeof c.value==='string'&&/^0x[1-9a-f][0-9a-f]{0,31}$/.test(c.value)&&typeof c.data==='string'&&/^0x9c9a1061[0-9a-f]{64}$/.test(c.data))
    &&new Set(v.calls.map(c=>c.data)).size===25;
}
export async function validateBulkPurchase(v:unknown,offer:TicketOffer):Promise<BulkPurchase|undefined>{
  if(!validBulkPurchase(v))throw Error('Unsupported bulk purchase. Keep the saved operation.');
  if(v.phase==='none')return undefined;
  if(offer.manifest.terms.pack_size!==2||v.total_price_wei!==(25n*BigInt(offer.manifest.terms.pack_price_wei)).toString()
    ||v.calls.some(c=>c.to!==offer.manifest.purchase_contract||c.value!=='0x'+BigInt(offer.manifest.terms.pack_price_wei).toString(16))
    ||v.batch_id!==await ticketDigest({parameters:offer.parameters,packs:v.calls.map(c=>'0x'+c.data.slice(-64))}))
    throw Error('The batch does not match the reviewed ticket offer. No payment was requested.');
  const checked=freeze(structuredClone(v));admitted.add(checked);return checked;
}
export async function requireAtomicWallet(payer:string,p?:WalletProvider):Promise<void>{
  const provider=p??await baseWalletProvider();let v:unknown;
  try{v=await walletCall(provider,'wallet_getCapabilities',[payer,['0x14a34']]);}catch{throw Error('MetaMask could not confirm atomic purchase support. No payment was requested.');}
  if(!object(v)||!object(v['0x14a34'])||!object(v['0x14a34'].atomic)||v['0x14a34'].atomic.status!=='supported')
    throw Error('Your wallet has not enabled single-transaction purchases. No payment was requested. Enable smart-account batching in MetaMask, then review again.');
}
const dispatched=new Set<string>();
export async function sendBulkPurchase(armed:BulkPurchase,p?:WalletProvider):Promise<void>{
  if(!admitted.has(armed)||armed.phase!=='armed'||armed.dispatch_authorized!==true||!armed.payer||dispatched.has(armed.batch_id))
    throw Error('This saved payment may already have been requested. Check its status; do not pay again.');
  const provider=p??await baseWalletProvider();
  const [accounts,chain]=await Promise.all([walletCall(provider,'eth_accounts'),walletCall(provider,'eth_chainId')]);
  if(!Array.isArray(accounts)||typeof accounts[0]!=='string'||accounts[0].toLowerCase()!==armed.payer||chain!=='0x14a34')throw Error('Wallet account or network changed. Keep the saved purchase.');
  await requireAtomicWallet(armed.payer,provider);
  // Recheck after asynchronous wallet admission: two callers can arrive
  // before the first one has completed those reads. Claim synchronously.
  if(dispatched.has(armed.batch_id))throw Error('This saved payment may already have been requested. Check its status; do not pay again.');
  dispatched.add(armed.batch_id);
  // No sequential fallback, sendTransaction loop, retry or account upgrade.
  let result:unknown;
  try{result=await walletCall(provider,'wallet_sendCalls',[{version:'2.0.0',chainId:'0x14a34',from:armed.payer,atomicRequired:true,calls:armed.calls}]);}
  catch(error){try{await saveWalletTracking(armed.batch_id,undefined,error);}catch{/* Native one-shot state remains authoritative. */}throw error;}
  try{await saveWalletTracking(armed.batch_id,result);}catch{throw Error('The wallet replied, but its tracking ID could not be saved. Independent onchain checks continue; do not pay again.');}
}
