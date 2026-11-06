"""Bounded recovery of finalized payments made through wallet relayers.

Search the pinned contract's monotonic paid slot, then verify its canonical
receipt/event. Outer sender/nonce/calldata do not identify a delegated payer.
No send, close, replacement, account lookup or trusted browser receipt API.
"""
import copy
from base_evm import encode
from policy import require
from ticket_offer_v1 import hex_value
from ticket_payment_v1 import EVENT,FinalizedTicketPayment,_quantity
from ticket_payment_recovery_v2 import budgeted_rpc,check_anchor
from ticket_wallet_v1 import PAYMENT_INTENT_V2,payment_anchor


def verified_payment(rpc,offer,view,transaction_hash,*,payment_type=FinalizedTicketPayment):
    """Native-only validation against an immutable saved purchase projection."""
    intent=view['payment_intent']
    require(intent['profile']==PAYMENT_INTENT_V2,'ticket-payment-search-anchor-required')
    anchor=payment_anchor(intent['anchor'])
    payments=payment_type(rpc,offer)
    payment,payer=payments._verified(view['pack_hash'],transaction_hash)
    require(payment['parameters']==offer.hash and payer==intent['payer']
        and _quantity(payment['block_number'])>_quantity(anchor['number']),
        'ticket-payment-intent-mismatch')
    check_anchor(rpc,anchor)
    return payment,payer


def find_finalized_payment(rpc,offer,view,*,clock=None,pause=None,payment_type=FinalizedTicketPayment):
    rpc=budgeted_rpc(rpc,clock=clock,pause=pause,max_calls=112)
    intent=view['payment_intent']
    require(intent['profile']==PAYMENT_INTENT_V2,'ticket-payment-search-anchor-required')
    start=payment_anchor(intent['anchor']);check_anchor(rpc,start)
    final=payment_type(rpc,offer).preflight()
    end=payment_anchor({'number':final['number'],'hash':final['hash']})
    low,high=_quantity(start['number']),_quantity(end['number'])
    require(low<=high,'ticket-payment-search-range')

    def paid(height):
        value=rpc.call('eth_call',{'to':offer.manifest['purchase_contract'],
            'data':encode('paid(bytes32)',view['pack_hash'])},hex(height))
        require(value in ('0x'+'0'*64,'0x'+'0'*63+'1'),'ticket-payment-search-slot')
        return value.endswith('1')

    require(not paid(low),'ticket-payment-before-intent')
    if not paid(high):
        check_anchor(rpc,start);check_anchor(rpc,end)
        return {'state':'not-finalized','checked_through':copy.deepcopy(end)}
    for _ in range(53):
        if high-low<=1:break
        mid=(low+high)//2
        if paid(mid):high=mid
        else:low=mid
    require(high-low==1,'ticket-payment-search-budget')
    logs=rpc.call('eth_getLogs',{'address':offer.manifest['purchase_contract'],
        'fromBlock':hex(high),'toBlock':hex(high),'topics':[EVENT,view['pack_hash']]})
    require(type(logs) is list and len(logs)==1 and type(logs[0]) is dict,'ticket-payment-event')
    transaction_hash=hex_value(logs[0].get('transactionHash'),32)
    payment,payer=verified_payment(rpc,offer,view,transaction_hash,payment_type=payment_type)
    require(payment['block_number']==hex(high),'ticket-payment-search-inclusion')
    check_anchor(rpc,start);check_anchor(rpc,end)
    return {'state':'payment-found','payment':payment,'payer':payer,'checked_through':copy.deepcopy(end)}
