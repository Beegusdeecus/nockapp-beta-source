"""Pinned finite refund-target expansion preserving the SAME managed ledger.

No key export, original boot/KMS rewrite, counter/budget reset, signing, funding
or retry. Old rows/first signatures/raw transactions remain exact. An uncertain
head CAS is resolved by attempting the exact new context on the next invocation.
"""
import copy,hashlib
from dataclasses import asdict
from cryptography.exceptions import InvalidTag
from policy import canonical,digest,require
from base_transactions import Limits
from ticket_offer_v1 import configured_offer
from ticket_offer_overlay_v1 import validate as overlay_validate
from ticket_refund_payout_v1 import RefundQueue,PROFILE,SELECTOR
from ticket_refund_scopes_v2 import ScopedRefundQueue,BINDING
from ticket_refund_vault_v1 import RefundVaultReader

def contexts(backend,plan):
    old=backend['refund_vault'];new=plan['refund_vault'];t=backend['transaction']
    common={'profile':'nockapp-base-transaction-journal-v3','chain':84532,
        'signer':backend['key_bindings']['refund'],'limits':t['limits'],'fee_policy':t['fee_policy']}
    before=canonical({**common,'contracts':{old['vault']:[SELECTOR]},'code_hashes':{old['vault']:old['runtime_sha256']},
        'application_binding':{'profile':PROFILE,'vault':old}}).decode()
    vaults={backend['offer_sha256']:old,plan['offer_sha256']:new}
    after=canonical({**common,'contracts':{v['vault']:[SELECTOR]for v in vaults.values()},
        'code_hashes':{v['vault']:v['runtime_sha256']for v in vaults.values()},
        'application_binding':{'profile':BINDING,'root_parameters':backend['offer_sha256'],'vaults':vaults,
            'global_max_refunds':old['max_refunds']}}).decode()
    return before,after

def validate(backend,backend_pin,plan,pin):
    require(backend.get('role')=='refund','refund-upgrade-role')
    plan=overlay_validate(plan,pin,backend,backend_pin);old,new=contexts(backend,plan)
    require(plan['transition']['old_context_sha256']==hashlib.sha256(old.encode()).hexdigest()
        and plan['transition']['new_context_sha256']==hashlib.sha256(new.encode()).hexdigest(),'refund-upgrade-context-pin')
    return plan,old,new

def resume(rpc,signer,path,backend,backend_pin,plan,pin,*,native,anchor):
    plan,before,after=validate(backend,backend_pin,plan,pin)
    require(signer.address==backend['key_bindings']['refund'],'refund-upgrade-signer')
    old_offer=configured_offer(backend['offer'],backend['offer_sha256'],native)
    new_offer=configured_offer(plan['offer'],plan['offer_sha256'],native)
    old_vault=backend['refund_vault'];new_vault=plan['refund_vault'];t=backend['transaction'];limits=Limits(**t['limits'])
    # A not-yet-finalized or differently configured vault cannot change the
    # authenticated journal context, even though no transaction is signed here.
    RefundVaultReader(rpc,new_offer,new_vault,plan['refund_vault_sha256']).check()
    args={'old_pin':backend['refund_vault_sha256'],'new_pin':plan['refund_vault_sha256'],
        'anchor':anchor,'fee_policy':t['fee_policy']}
    try:
        result=ScopedRefundQueue(rpc,signer,path,old_offer,old_vault,new_offer,new_vault,limits,**args)
        require(result.context==after,'refund-upgrade-context-pin');return result
    except InvalidTag:pass # Only the exact original authenticated context follows.
    old=RefundQueue(rpc,signer,path,old_offer,old_vault,limits,expected_hash=backend['refund_vault_sha256'],
        anchor=anchor,fee_policy=t['fee_policy'])
    require(old.context==before and asdict(old.limits)==t['limits']
        and old.fees.policy==t['fee_policy'],'refund-upgrade-context-pin')
    # Public configuration and original handles only. No second journal, nonce
    # authority or key is constructed by this view of the migration transaction.
    result=object.__new__(ScopedRefundQueue);result.__dict__=dict(old.__dict__)
    result._configure(signer,old_offer,old_vault,new_offer,new_vault,limits,**args)
    result.context=after;result.contracts={v['vault']:[SELECTOR]for v in result.vaults.values()}
    previous=(old.context,old.contracts)
    try:
        with old._db()as db:
            meta=old._meta(db) # Authenticate every existing record before changes.
            for table,kind,key in(('submissions','submission','id'),('fees','fee','id'),('refund_jobs','refund-job-v1','pack_hash')):
                for row in list(db.execute('SELECT *FROM '+table)):
                    record={k:row[k]for k in row.keys()if k!='mac'}
                    db.execute('UPDATE '+table+' SET mac=? WHERE '+key+'=?',(result._mac(kind,record),row[key]))
            changed={'context':after,'first_nonce':meta['first_nonce'],'next_nonce':meta['next_nonce']}
            db.execute('UPDATE meta SET context=?,mac=? WHERE singleton=1',(after,result._mac('meta',changed)))
            old.context,old.contracts=after,result.contracts
            result._meta(db)
        result._anchor_revision=old._anchor_revision
        return result
    except Exception:
        old.context,old.contracts=previous
        raise
