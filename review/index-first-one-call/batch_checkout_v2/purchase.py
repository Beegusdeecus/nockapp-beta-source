"""Explicit one-call controller; never adopts or clears a legacy purchase.

Uses the existing encrypted journal, import cursor and permanent dispatch fence.
The configured offer and payment verifier select this code, never server replies.
Installation and migration are deliberately separate from this controller.
"""
import base64,zlib
from policy import require,canonical,strict_json
from ticket_bulk_purchase_v1 import BulkPurchase
from ticket_payment_recovery_v2 import check_anchor
from wallet import MAX_PLAIN
from .offer import BatchOffer
from .payment import FinalizedBatchPayment


class BatchPurchase(BulkPurchase):
    profile='nockapp-ticket-bulk-purchase-v2'
    payment_type=FinalizedBatchPayment
    max_plain=192*1024

    def __init__(self,tickets,rpc,payment):
        # Production uses an authenticated transport, not an in-process issuer.
        # Replies are checked against this offer by TicketWallet before import.
        require(isinstance(tickets.offer,BatchOffer)
            and callable(getattr(payment,'issue',None)),'batch-purchase-scope')
        super().__init__(tickets,rpc,payment)

    def prepare(self,now,approve_purchase,*,include_prepared_pack=False):
        scopes=getattr(self.tickets,'purchase_scopes',None)
        if scopes is None or self._read() is not None:
            return super().prepare(now,approve_purchase,include_prepared_pack=include_prepared_pack)
        with scopes.purchase_guard(50):
            return super().prepare(now,approve_purchase,include_prepared_pack=include_prepared_pack)

    def arm(self,batch_id,payer,approve_payment):
        scopes=getattr(self.tickets,'purchase_scopes',None)
        if scopes is None:return super().arm(batch_id,payer,approve_payment)
        with scopes.purchase_guard(50):return super().arm(batch_id,payer,approve_payment)

    def _save_record(self,b):
        envelope={'profile':self.profile,'phase':b['phase'],'encoding':'zlib-canonical-json-v1',
            'payload':base64.b64encode(zlib.compress(canonical(b))).decode('ascii')}
        require(len(canonical(envelope))<=MAX_PLAIN,'batch-envelope-capacity')
        self.tickets.wallet.save('pending',envelope)

    def _load_record(self):
        e=self.tickets.wallet.load('pending')
        require(type(e) is dict and set(e)=={'profile','phase','encoding','payload'}
            and e['profile']==self.profile and e['encoding']=='zlib-canonical-json-v1'
            and type(e['payload']) is str and len(e['payload'])<=MAX_PLAIN,'batch-envelope')
        try:
            packed=base64.b64decode(e['payload'],validate=True)
            decoder=zlib.decompressobj();raw=decoder.decompress(packed,self.max_plain+1)
        except (ValueError,zlib.error):require(False,'batch-envelope')
        require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
            and len(raw)<=self.max_plain,'batch-envelope-bound')
        b=strict_json(raw,max_bytes=self.max_plain)
        require(type(b) is dict and canonical(b)==raw and b.get('phase')==e['phase'],
            'batch-envelope-canonical')
        return b

    def _public(self,b):
        result=super()._public(b)
        if b is not None:
            result['calls']=[self.tickets.offer.transaction([p['pack_hash']for p in b['items']])]
        return result

    def _verify_atomic_receipt(self,b,tx):
        proof=self.payment_type(self.rpc,self.tickets.offer).verify_batch(
            [p['pack_hash']for p in b['items']],tx,b['payer'])
        require(int(proof['block_number'],16)>int(b['anchor']['number'],16),
            'batch-payment-before-intent')
        check_anchor(self.rpc,b['anchor'])
