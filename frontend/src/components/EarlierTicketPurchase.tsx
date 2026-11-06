import { useEffect, useState } from 'react';
import { publicOperation, type PublicScope } from '../publicDiscussion';
import { validateTicketOffer, type TicketOffer } from '../publicTickets';
import { validateBulkPurchase, type BulkPurchase } from '../bulkTickets';
import { BulkTicketPurchase } from './BulkTicketPurchase';

export type EarlierTicketSnapshot={purchases:{parameters:string;offer:unknown;purchase:unknown}[]};
export function EarlierTicketPurchase({scope,onRefresh,initial,canResume=false}:{canResume?:boolean;scope:PublicScope;onRefresh:()=>void;initial?:EarlierTicketSnapshot}){
  const [offers,setOffers]=useState<{offer:TicketOffer;purchase:BulkPurchase}[]>();const [error,setError]=useState('');const [retry,setRetry]=useState(0);
  useEffect(()=>{
    let alive=true;const controller=new AbortController();
    void(async()=>{
      try{
        const result=initial??await publicOperation<EarlierTicketSnapshot>('public-ticket-earlier-status',{},controller.signal);
        const checked:{offer:TicketOffer;purchase:BulkPurchase}[]=[];
        for(const row of result.purchases){
          const offer=await validateTicketOffer(row.offer,scope);
          const purchase=await validateBulkPurchase(row.purchase,offer);
          if(!purchase||row.parameters!==offer.parameters)throw Error('The saved purchase could not be matched to its original offer.');
          checked.push({offer,purchase});
        }
        if(alive){setOffers(checked);setError('');}
      }catch(e){if(alive)setError(e instanceof Error?e.message:'The earlier purchase could not be checked. It is preserved.');}
    })();
    return()=>{alive=false;controller.abort();};
  },[retry,initial]);
  return <section aria-label="Earlier purchase recovery">
    {!offers&&!error&&<><p role="status">Opening your original checkout…</p><progress aria-label="Loading earlier purchase"/></>}
    {error&&<><p role="alert">{error}</p><button onClick={()=>{setError('');setRetry(v=>v+1);}}>Check original checkout</button></>}
    {offers?.map(({offer,purchase})=><BulkTicketPurchase canResume={canResume} initialPurchase={purchase} key={offer.parameters} offer={offer} recoveryScope={offer.parameters} onActive={()=>{}} onRefresh={onRefresh}/>)}
    {offers?.length===0&&<p role="status">No unfinished 50-ticket checkout was found. Your saved purchase is preserved; another payment has not been requested.</p>}
  </section>;
}
