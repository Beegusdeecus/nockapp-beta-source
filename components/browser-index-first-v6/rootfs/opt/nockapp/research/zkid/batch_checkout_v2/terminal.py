"""Read-only terminal evidence; never cancels, clears, re-arms or pays.

An immutable contract's finalized deadline closes successful purchase execution.
This does NOT cancel queued wallet requests: those can still revert and cost gas.
The caller must separately match every pack and anchor to the encrypted journal.
"""
from policy import require
from ticket_offer_v1 import hex_value
from ticket_payment_v1 import FinalizedTicketPayment,_quantity
from ticket_payment_recovery_v2 import budgeted_rpc,check_anchor,require_unpaid
from ticket_wallet_v1 import payment_anchor


def unpaid_after_deadline(rpc,offer,packs,anchor,*,payment_type=FinalizedTicketPayment):
    require(type(packs) is list and len(packs) in (1,25),'batch-terminal-packs')
    for pack in packs:hex_value(pack,32)
    require(len(set(packs))==len(packs),'batch-terminal-packs')
    anchor=payment_anchor(anchor)
    rpc=budgeted_rpc(rpc,max_calls=64)
    final=payment_type(rpc,offer).preflight()
    end=payment_anchor({'number':final['number'],'hash':final['hash']})
    require(_quantity(final['timestamp'])>=offer.terms['purchase_before'],
        'batch-purchase-still-executable')
    require(_quantity(end['number'])>=_quantity(anchor['number']),'batch-terminal-order')
    check_anchor(rpc,anchor)
    for pack in packs:require_unpaid(rpc,offer,pack,final['number'])
    check_anchor(rpc,anchor);check_anchor(rpc,end)
    return {'profile':'nockapp-batch-terminal-unpaid-v1','parameters':offer.hash,
        'pack_hashes':list(packs),'armed_at':dict(anchor),'checked_through':dict(end),
        'purchase_before':offer.terms['purchase_before'],
        'outcome':'all-unpaid-after-immutable-deadline',
        'queued_requests_cancelled':False,'queued_requests_may_cost_gas':True}
