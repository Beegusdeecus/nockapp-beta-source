/** Wallet diagnostics only: never payment, finality, import or retry authority. */
import { storage } from '../platform/storage';
import { exact, object } from '../zkidWire';
import { walletCall } from '../publicTickets';
import type { WalletProvider } from '../publicWallet';

export const TICKET_WALLET_KEY='nockapp:ticket:wallet-display:v1';
type Tracking={profile:'nockapp-ticket-wallet-display-v1';batch:string;id:string|null;error:number|null};
const validId=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=8194&&!/[\u0000-\u001f\u007f]/.test(v);
export function walletFailure(error:unknown):string{
  const code=object(error)&&Number.isSafeInteger(error.code)?error.code:null;
  if(code===4001)return 'MetaMask rejected the payment request. The saved attempt is still locked; no payment will be retried automatically.';
  if(code===-32601||code===4200)return 'MetaMask does not support this payment request. The saved attempt is preserved; no second payment will be sent.';
  return `MetaMask did not confirm the payment request${typeof code==='number'?` (error ${code})`:''}. Its outcome is unknown; do not pay again.`;
}
export async function saveWalletTracking(batch:string,result:unknown,error?:unknown):Promise<void>{
  const id=object(result)&&validId(result.id)?result.id:null;
  const code=object(error)&&Number.isSafeInteger(error.code)?error.code as number:null;
  // Never persist arbitrary wallet errors, receipts, call data or private fields.
  await storage.set(TICKET_WALLET_KEY,{profile:'nockapp-ticket-wallet-display-v1',batch,id,error:code} satisfies Tracking);
  if(result!==undefined&&!id)throw Error('MetaMask returned no usable payment tracking ID. Checking the saved payment onchain; do not pay again.');
}
export async function walletTrackingStatus(batch:string,provider:()=>Promise<WalletProvider>):Promise<string>{
  let v:unknown;
  try{v=await storage.get(TICKET_WALLET_KEY);}catch{return 'Wallet tracking could not be read. Independent onchain checks continue.';}
  if(!object(v)||!exact(v,['profile','batch','id','error'])||v.profile!=='nockapp-ticket-wallet-display-v1'||v.batch!==batch)
    return 'This saved attempt has no wallet tracking ID. Onchain checks continue, but cannot tell whether MetaMask is still holding the request.';
  if(v.id===null)return walletFailure({code:v.error});
  if(!validId(v.id))return 'Wallet tracking is unavailable. Independent onchain checks continue.';
  try{
    const status=await walletCall(await provider(),'wallet_getCallsStatus',[v.id]);
    if(!object(status)||status.id!==v.id||status.chainId!=='0x14a34'||status.atomic!==true||!Number.isInteger(status.status))throw Error('invalid-wallet-status');
    const code=status.status as number;
    if(code>=100&&code<200)return 'MetaMask is still processing the payment. No onchain payment is confirmed yet.';
    if(code>=200&&code<300)return 'MetaMask reports payment included. Independently checking all 25 packs and chain finality before importing.';
    if(code>=400&&code<500)return 'MetaMask reports the payment failed before inclusion. The saved attempt remains locked pending safe recovery.';
    if(code>=500&&code<700)return 'MetaMask reports a failed transaction. Gas may have been spent. The saved attempt remains locked pending safe recovery.';
    throw Error('unknown-wallet-status');
  }catch{return 'MetaMask payment status is unavailable. Independent onchain checks continue; do not pay again.';}
}
