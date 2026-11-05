/** Public display checkpoint only. Never authorizes payment, import or retry. */
import { storage, exclusive } from '../platform/storage';
import { exact, object } from '../zkidWire';
import type { TicketPaymentProgress } from '../publicDiscussion';
export const TICKET_FINALITY_KEY='nockapp:ticket:finality-display:v1';
const integer=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
export async function observeTicketFinality(batch:string,p:TicketPaymentProgress):Promise<number|undefined>{
  if(p.state==='finalized')return 100;
  if(p.state!=='confirming'||!integer(p.payment_block)||!integer(p.finalized_block)||p.payment_block<=p.finalized_block)return undefined;
  const target=p.payment_block;
  // A missing/full display cache must never stop genuine payment recovery.
  try{return await exclusive(TICKET_FINALITY_KEY,async()=>{
    const old=await storage.get<unknown>(TICKET_FINALITY_KEY);
    const matches=object(old)&&exact(old,['profile','batch','pack_hash','target','start'])&&old.profile==='nockapp-ticket-finality-display-v1'
      &&old.batch===batch&&old.pack_hash===p.pack_hash&&old.target===target&&integer(old.start)&&old.start<=p.finalized_block&&old.start<target;
    const start=matches?old.start as number:p.finalized_block;
    if(!matches)await storage.set(TICKET_FINALITY_KEY,{profile:'nockapp-ticket-finality-display-v1',batch,pack_hash:p.pack_hash,target,start});
    return Math.min(99,Math.max(0,Math.floor(100*(p.finalized_block-start)/(target-start))));
  });}catch{return undefined;}
}
