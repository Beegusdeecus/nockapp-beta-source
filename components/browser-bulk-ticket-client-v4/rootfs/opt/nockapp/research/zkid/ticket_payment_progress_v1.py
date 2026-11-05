"""Bounded public payment progress, never authority to issue or resend.

Only the configured immutable contract's paid slot and public chain headers.
Final receipt/payer checks remain in the existing saved-purchase recovery path.
"""
from base_evm import encode
from policy import require
from ticket_offer_v1 import hex_value
from ticket_payment_v1 import FinalizedTicketPayment,_quantity


def progress(rpc,offer,pack_hash):
    hex_value(pack_hash,32)
    payments=FinalizedTicketPayment(rpc,offer);final=payments.preflight()
    latest=rpc.call('eth_getBlockByNumber','latest',False)
    require(type(latest) is dict,'ticket-progress-block')
    f,h=_quantity(final['number']),_quantity(latest['number'])
    require(0<=f<=h<2**53,'ticket-progress-range')
    data=encode('paid(bytes32)',pack_hash)
    def paid(height):
        value=rpc.call('eth_call',{'to':offer.manifest['purchase_contract'],'data':data},hex(height))
        require(value in ('0x'+'0'*64,'0x'+'0'*63+'1'),'ticket-progress-paid-slot')
        return value.endswith('1')
    was_paid,is_paid=paid(f),paid(h)
    require(not was_paid or is_paid,'ticket-progress-regressed')
    target=None
    state='finalized' if was_paid else 'confirming' if is_paid else 'not-seen'
    if is_paid and not was_paid:
        low,high=f+1,h
        for _ in range(53):
            if low>=high:break
            middle=(low+high)//2
            if paid(middle):high=middle
            else:low=middle+1
        require(low==high and paid(low),'ticket-progress-target')
        target=low
    for block in (final,latest):
        observed=rpc.call('eth_getBlockByNumber',block['number'],False)
        require(type(observed) is dict and observed.get('hash')==block['hash']
            and observed.get('number')==block['number'],'ticket-progress-reorganized')
    return {'profile':'nockapp-ticket-payment-progress-v1','pack_hash':pack_hash,'state':state,
        'latest_block':h,'finalized_block':f,'payment_block':target}
