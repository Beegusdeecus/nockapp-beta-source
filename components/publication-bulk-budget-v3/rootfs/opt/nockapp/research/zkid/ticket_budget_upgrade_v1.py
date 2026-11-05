"""Trusted, pinned cumulative-cap upgrade for the SAME ticket journal.

No public RPC, key export, nonce reset, funding or transaction signing. All
submissions, fee records and ticket bindings survive an authenticated head CAS.
"""
from dataclasses import asdict
import copy,hashlib,json
from cryptography.exceptions import InvalidTag
from base_fees import BaseFees,policy as fee_policy
from base_transactions import Limits
from policy import canonical,digest,require
from ticket_publication_queue_v2 import TicketPublicationQueue,PROFILE as LEDGER

PROFILE='nockapp-ticket-cumulative-budget-upgrade-v1'

def validate(value,pin,backend):
    require(type(value) is dict and set(value)=={'profile','previous_backend_sha256','limits','fee_policy','old_context_sha256','new_context_sha256','purchase_ticket_count','incoming_payment_wei'}
        and value['profile']==PROFILE and digest(value)==pin and value['previous_backend_sha256']==digest(backend)
        and backend['role']=='publication','ticket-budget-upgrade-plan')
    old=backend['transaction'];limits=Limits(**value['limits']);limits.validate();fees=fee_policy(value['fee_policy'])
    previous=old['limits'];current=asdict(limits)
    require({k:v for k,v in previous.items()if k not in ('max_submissions','execution_budget')}==
        {k:v for k,v in current.items()if k not in ('max_submissions','execution_budget')},'ticket-budget-per-transaction-change')
    require(all(current[k]>=previous[k]for k in ('max_submissions','execution_budget')),'ticket-budget-decrease')
    require({k:v for k,v in old['fee_policy'].items()if k not in ('total_budget','funded_budget')}==
        {k:v for k,v in fees.items()if k not in ('total_budget','funded_budget')},'ticket-budget-fee-change')
    require(all(fees[k]>=old['fee_policy'][k]for k in ('total_budget','funded_budget'))
        and (current!=previous or fees!=old['fee_policy']),'ticket-budget-no-increase')
    offer=backend['offer']['terms'];contract=offer['index_contract']
    require(value['purchase_ticket_count']==50 and type(value['purchase_ticket_count']) is int and offer['pack_size']==2
        and value['incoming_payment_wei']==str(25*int(offer['pack_price_wei'])),'ticket-budget-purchase-scope')
    common={'profile':'nockapp-base-transaction-journal-v3','chain':84532,'signer':backend['key_bindings']['publication'],
        'contracts':{contract:[]},'code_hashes':{contract:old['runtime_sha256']},
        'application_binding':{'profile':LEDGER,'application':offer['application'],'index_contract':contract}}
    # Derive the selector through the same primitive as the queue, not input.
    from base_protocol import keccak
    common['contracts'][contract]=[keccak(b'submit(bytes32)')[:10]]
    old_context=canonical({**common,'limits':previous,'fee_policy':old['fee_policy']}).decode()
    new_context=canonical({**common,'limits':current,'fee_policy':fees}).decode()
    require(hashlib.sha256(old_context.encode()).hexdigest()==value['old_context_sha256']
        and hashlib.sha256(new_context.encode()).hexdigest()==value['new_context_sha256'],'ticket-budget-context-pin')
    return limits,fees,old_context,new_context

def resume(rpc,signer,path,backend,plan,pin,*,anchor):
    plan=copy.deepcopy(plan);limits,fees,old_context,new_context=validate(plan,pin,backend)
    require(signer.address==backend['key_bindings']['publication'],'ticket-budget-signer')
    terms=backend['offer']['terms'];contract=terms['index_contract'];code={contract:backend['transaction']['runtime_sha256']}
    def queue(selected,policy):
        return TicketPublicationQueue(rpc,signer,path,contract,terms['application'],selected,
            code_hashes=code,anchor=anchor,fee_policy=policy)
    try:
        result=queue(limits,fees);require(result.context==new_context,'ticket-budget-context-pin');return result
    except InvalidTag:pass # Only the exact reviewed old AEAD context may follow.
    result=queue(Limits(**backend['transaction']['limits']),backend['transaction']['fee_policy'])
    require(result.context==old_context,'ticket-budget-context-pin')
    previous=(result.context,result.limits,result.fees)
    try:
        with result._db() as db:
            meta=result._meta(db) # Authenticate all original ticket/fee/nonce rows first.
            count=plan['purchase_ticket_count']
            require(db.execute('SELECT count(*) FROM ticket_jobs').fetchone()[0]+count<=limits.max_submissions,'ticket-budget-purchase-capacity')
            spent,overrun=result._fee_usage(db)
            reserve=limits.max_gas*limits.max_fee_per_gas+fees['max_l1_fee']+fees['max_operator_fee']
            require(not overrun and spent+count*reserve<=fees['total_budget'],'ticket-budget-purchase-fees')
            head=rpc.call('eth_getBlockByNumber','latest',False)
            balance=int(rpc.call('eth_getBalance',signer.address,head['number']),16)
            observed=sum(json.loads(r['actual'])['total_wei']for r in db.execute('SELECT actual FROM fees')if r['actual'] is not None)
            require(balance+observed+int(plan['incoming_payment_wei'])<=fees['funded_budget'],'ticket-budget-purchase-funding')
            require(rpc.call('eth_getBlockByNumber',head['number'],False)['hash']==head['hash'],'ticket-budget-purchase-reorg')
            def mac(kind,record):
                return signer.authenticate(canonical({'profile':'nockapp-base-journal-record-v1','context':new_context,'kind':kind,'record':record}))
            for table,kind,key in [('submissions','submission','id'),('fees','fee','id'),('ticket_jobs','ticket-job-v2','bundle_hash')]:
                for row in list(db.execute('SELECT * FROM '+table)):
                    record={k:row[k]for k in row.keys()if k!='mac'}
                    db.execute('UPDATE '+table+' SET mac=? WHERE '+key+'=?',(mac(kind,record),row[key]))
            changed={'context':new_context,'first_nonce':meta['first_nonce'],'next_nonce':meta['next_nonce']}
            db.execute('UPDATE meta SET context=?,mac=? WHERE singleton=1',(new_context,mac('meta',changed)))
            result.context,result.limits,result.fees=new_context,limits,BaseFees(rpc,fees,chain_id=84532)
            result._meta(db)
        return result
    except Exception:
        result.context,result.limits,result.fees=previous
        raise
