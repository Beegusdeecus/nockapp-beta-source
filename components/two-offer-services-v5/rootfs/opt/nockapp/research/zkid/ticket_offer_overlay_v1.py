"""Explicit installer-pinned second offer; original boot/key context is intact.

This public overlay is an authority proposal until reviewed and selected by the
trusted launcher. It cannot change keys, price, expiry, index, or spending caps.
No permission changes, encrypted-record rewriting, key recovery or network IO.
"""
import copy,hashlib
from policy import canonical,digest,require
from ticket_offer_v1 import OFFER_V2,configured_manifest_hash
from batch_checkout_v2.offer import PROFILE as BATCH,terms as batch_terms

PROFILE='nockapp-ticket-explicit-second-offer-v1'
FIELDS={'profile','base_backend_sha256','offer','offer_sha256'}

def pair(old,new):
    require(type(old)is dict and type(new)is dict,'ticket-overlay-offer')
    require(old['terms']['profile']==OFFER_V2 and new['terms']['profile']==BATCH,'ticket-overlay-version')
    batch_terms(new['terms'])
    previous=copy.deepcopy(new['terms']);previous['profile']=OFFER_V2
    for n in('payment_receipt_version','packs_per_payment'):del previous[n]
    require(previous['purchase_before']>=old['terms']['purchase_before'],'ticket-overlay-deadline')
    previous['purchase_before']=old['terms']['purchase_before']
    require(previous==old['terms'],'ticket-overlay-changed-authority')
    require(new['purchase_contract']!=old['purchase_contract']
        and new['purchase_runtime_keccak']!=old['purchase_runtime_keccak'],'ticket-overlay-distinct-contract')

def validate(value,pin,backend,backend_pin):
    # Lazy import avoids changing the old boot module's import-time admission.
    from ticket_backend_boot_v1 import validate as boot_validate,PROFILE as BOOT
    base=boot_validate(backend,backend_pin)
    extra={'refund_vault','refund_vault_sha256','transition'}if base['role']=='refund'else set()
    require(base['profile']==BOOT and type(value)is dict and set(value)==FIELDS|extra
        and value['profile']==PROFILE and digest(value)==pin
        and value['base_backend_sha256']==backend_pin,'ticket-overlay-plan')
    require(configured_manifest_hash(value['offer'])==value['offer_sha256']
        and value['offer_sha256']!=base['offer_sha256'],'ticket-overlay-offer-pin')
    pair(base['offer'],value['offer'])
    if base['role']=='refund':
        from ticket_refund_vault_v1 import scope_manifest
        new=scope_manifest(value['refund_vault'],value['offer'],value['offer_sha256'],value['refund_vault_sha256'])
        old=base['refund_vault']
        require(old['vault']!=new['vault']and all(old[k]==new[k]for k in
            ('authority','chain_id','pack_price_wei','max_refunds','principal_budget_wei','gas')),'ticket-overlay-refund-authority')
        t=value['transition'];require(type(t)is dict and set(t)=={'profile','old_context_sha256','new_context_sha256'}
            and t['profile']=='nockapp-ticket-refund-context-upgrade-v2','ticket-overlay-refund-transition')
        from ticket_offer_v1 import hex_value
        for k in('old_context_sha256','new_context_sha256'):hex_value('0x'+t[k],32)
        from ticket_refund_scope_upgrade_v2 import contexts
        before,after=contexts(base,value)
        require(t['old_context_sha256']==hashlib.sha256(before.encode()).hexdigest()
            and t['new_context_sha256']==hashlib.sha256(after.encode()).hexdigest(),'ticket-overlay-refund-context-pin')
    return copy.deepcopy(value)
