/** Public wallet diagnostics only; never payment, import or retry authority. */
import { storage, exclusive } from '../platform/storage';
import { exact, object } from '../zkidWire';
import { walletCall } from '../publicTickets';
import type { WalletProvider } from '../publicWallet';

export const TICKET_WALLET_KEY='nockapp:ticket:wallet-display:v1';
const PROFILE='nockapp-ticket-wallet-display-v2';
const validId=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=8194&&!/[\u0000-\u001f\u007f]/.test(v);
export type WalletDiagnostic={state:'untracked'|'pending'|'included'|'rejected'|'failed'|'unavailable';message:string;tracked:boolean};
export class PaymentTrackingError extends Error {}
const errorCode=(e:unknown)=>object(e)&&Number.isSafeInteger(e.code)?e.code as number:null;
export function walletFailure(error:unknown):string{
  if(error instanceof PaymentTrackingError)return error.message;
  const code=errorCode(error);
  if(code===4001)return 'MetaMask rejected the payment request. The saved attempt is still locked; no payment will be retried automatically.';
  if(code===5740)return 'MetaMask rejected the batch because it contains too many calls. This checkout needs a compatibility upgrade; waiting for confirmations will not fix that request.';
  if(code===5720)return 'MetaMask already knows this payment request ID. Check the existing request; do not send another.';
  if(code===-32602)return 'MetaMask rejected the payment request format. The saved attempt is preserved for investigation; do not pay again.';
  if(code===-32601||code===4200)return 'MetaMask does not support this payment request. The saved attempt is preserved; no second payment will be sent.';
  return `MetaMask did not confirm the payment request${code!==null?` (error ${code})`:''}. Its outcome is unknown; do not pay again.`;
}

/** Commit the app-chosen EIP-5792 ID BEFORE calling the wallet, not afterwards. */
export async function beginWalletTracking(batch:string):Promise<string>{
  return exclusive(TICKET_WALLET_KEY,async()=>{
    const previous=await storage.get<unknown>(TICKET_WALLET_KEY);
    if(object(previous)&&previous.batch===batch)
      throw new PaymentTrackingError('A wallet request was already prepared for this purchase. Check the saved payment; do not pay again.');
    const id='0x'+[...crypto.getRandomValues(new Uint8Array(32))].map(v=>v.toString(16).padStart(2,'0')).join('');
    await storage.set(TICKET_WALLET_KEY,{profile:PROFILE,batch,id,error:null});
    return id;
  });
}
export async function recordWalletReply(batch:string,id:string,result:unknown,error?:unknown):Promise<void>{
  if(result!==undefined&&(!object(result)||result.id!==id))
    throw new PaymentTrackingError('MetaMask returned a different payment tracking ID. The original ID is preserved; checking the saved payment without another send.');
  await exclusive(TICKET_WALLET_KEY,async()=>{
    const previous=await storage.get<unknown>(TICKET_WALLET_KEY);
    if(!object(previous)||previous.profile!==PROFILE||previous.batch!==batch||previous.id!==id)
      throw new PaymentTrackingError('Payment tracking changed. The saved purchase is preserved; do not pay again.');
    // Never persist arbitrary errors, receipts, call data, accounts or secrets.
    await storage.set(TICKET_WALLET_KEY,{profile:PROFILE,batch,id,error:errorCode(error)});
  });
}
export async function readWalletDiagnostic(batch:string,provider:()=>Promise<WalletProvider>):Promise<WalletDiagnostic>{
  const note=(state:WalletDiagnostic['state'],message:string,tracked=false)=>({state,message,tracked});
  let v:unknown;
  try{v=await storage.get(TICKET_WALLET_KEY);}catch{return note('unavailable','Wallet tracking could not be read. Independent onchain checks continue.');}
  if(!object(v)||!exact(v,['profile','batch','id','error'])||![PROFILE,'nockapp-ticket-wallet-display-v1'].includes(String(v.profile))||v.batch!==batch)
    return note('untracked','This older attempt has no wallet tracking ID. Waiting longer cannot tell us whether MetaMask sent it. Payment needs investigation; do not pay again.');
  if(v.id===null)return note(v.error===4001?'rejected':'unavailable',walletFailure({code:v.error}));
  if(!validId(v.id))return note('unavailable','Wallet tracking is unavailable. Independent onchain checks continue.');
  try{
    const status=await walletCall(await provider(),'wallet_getCallsStatus',[v.id]);
    if(!object(status)||status.id!==v.id||status.chainId!=='0x14a34'||status.atomic!==true||!Number.isInteger(status.status))throw Error('invalid-wallet-status');
    const code=status.status as number;
    if(code>=100&&code<200)return note('pending','MetaMask is still processing the payment. No onchain payment is confirmed yet.',true);
    if(code>=200&&code<300)return note('included','MetaMask reports payment included. Independently checking all 25 packs and chain finality before importing.',true);
    if(code>=400&&code<500)return note('failed','MetaMask reports the payment failed before inclusion. The saved attempt remains locked pending safe recovery.',true);
    if(code>=500&&code<700)return note('failed','MetaMask reports a failed transaction. Gas may have been spent. The saved attempt remains locked pending safe recovery.',true);
    throw Error('unknown-wallet-status');
  }catch{
    if(v.error===4001)return note('rejected',walletFailure({code:v.error}),true);
    if([4200,-32601,-32602,5740,5720].includes(v.error as number))return note('failed',walletFailure({code:v.error}),true);
    return note('unavailable','MetaMask payment status is unavailable. Independent onchain checks continue; do not pay again.',true);
  }
}
