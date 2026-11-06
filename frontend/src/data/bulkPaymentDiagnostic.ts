/** Copy only already-public payment commitments; no tickets or blind inputs. */
import { validBulkPurchase, type BulkPurchase } from '../bulkTickets';
import type { TicketPaymentProgress } from '../publicDiscussion';
import type { WalletDiagnostic } from './ticketWalletTracking';
export function bulkPaymentDiagnostic(p:BulkPurchase,chain?:TicketPaymentProgress,wallet?:WalletDiagnostic):string{
  if(!validBulkPurchase(p))throw Error('The saved payment details could not be checked.');
  const first='0x'+p.calls[0].data.slice(-64);
  return JSON.stringify({profile:'nockapp-public-payment-diagnostic-v1',chain_id:84532,batch_id:p.batch_id,first_pack_hash:first,
    payment_contract:p.calls[0].to,payer:p.payer,total_price_wei:p.total_price_wei,phase:p.phase,transaction_hash:p.transaction_hash,
    imported_tickets:p.imported_tickets,settled_tickets:p.settled_tickets,
    wallet_state:wallet?.state??'unavailable',chain:chain?.pack_hash===first?{state:chain.state,latest_block:chain.latest_block,finalized_block:chain.finalized_block,payment_block:chain.payment_block}:null});
}
