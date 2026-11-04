"""Client-only ticket spending around an installer-owned service channel.

The configured channel must authenticate the operator and correlate its reply.
This source coordinator is not an implementation of that TLS/install boundary.
No browser route accepts a supplied response or releases a reservation itself.
Public proof validity must still be independently checked by the public reader.
"""
import time
from policy import require
from ticket_offer_v1 import hex_value,OFFER_V2
from ticket_publication_queue_v2 import PROFILE,operation_id
from ticket_wallet_v1 import TicketWallet


class TicketPublisher:
    def __init__(self,wallet,submit,*,clock=None):
        require(isinstance(wallet,TicketWallet) and wallet.offer.terms['profile']==OFFER_V2
            and callable(submit),'ticket-publisher-configuration')
        self.wallet,self.submit,self.clock=wallet,submit,clock or (lambda:int(time.time()))

    def publish(self,bundle_hash,approve_publication):
        require(approve_publication is True,'consent-required');hex_value(bundle_hash,32)
        offer=self.wallet.offer;offer.check()
        token=self.wallet.reserve(bundle_hash,int(self.clock()))
        result=self.submit(token,bundle_hash) # Failure leaves the exact reservation untouched.
        require(type(result) is dict and set(result)=={'profile','parameters','bundle_hash','operation',
            'ticket_used','state','post_number','transaction_hash'} and result['profile']==PROFILE
            and result['parameters']==offer.hash and result['bundle_hash']==bundle_hash
            and result['operation']==operation_id(offer.terms['index_contract'],offer.terms['application'],bundle_hash)
            and type(result['ticket_used']) is bool and result['state'] in
                ('indexed','pending','recoverable','confirmed','finalized','failed','nonce-conflict'),'ticket-publisher-response')
        if result['transaction_hash'] is not None:hex_value(result['transaction_hash'],32)
        if result['state']=='indexed':
            n=result['post_number']
            require(type(n) is str and n.isascii() and n.isdigit() and str(int(n))==n
                and 0<int(n)<2**53,'ticket-publisher-number')
        else:
            require(result['post_number'] is None and result['transaction_hash'] is not None,'ticket-publisher-response')
        if result['ticket_used'] is False:
            # The permanent hash already belongs to another ticket (or was
            # indexed without this service). That operation can never charge
            # this ticket later; release only this exact local reservation.
            self.wallet._release_unconsumed(token,bundle_hash)
        return result
