"""Paid blind-pack issuance with a permanent issue-or-refund decision fence.

No listener or refund transaction execution. Journals are independent durable
authorities; a local DB/backup cannot replace them. No buyer account is stored.
"""
import base64
import copy
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from policy import canonical,require,strict_json,Rejected
from ticket_native_v1 import _decode
from ticket_offer_v1 import TicketOffer
from ticket_payment_v1 import FinalizedTicketPayment
from ticket_refund_v1 import authorize_refund

DECISION='nockapp-ticket-purchase-decision-v1'
REPLY='nockapp-ticket-purchase-reply-v1'


class PaidTicketIssuer:
    def __init__(self,offer,payments,decisions,results,private_key_der):
        require(isinstance(offer,TicketOffer) and isinstance(payments,FinalizedTicketPayment)
            and payments.offer.hash==offer.hash,'ticket-issuance-offer')
        require(type(private_key_der) is bytes and len(private_key_der)<=4096,'ticket-issuance-key')
        try:
            key=serialization.load_der_private_key(private_key_der,password=None)
            require(isinstance(key,rsa.RSAPrivateKey) and key.public_key().public_bytes(serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)==_decode(offer.terms['ticket_spki'],1024),'ticket-issuance-key')
        except Rejected:raise
        except Exception:raise Rejected('ticket-issuance-key') from None
        self.offer,self.payments,self.decisions,self.results=offer,payments,decisions,results
        self._key=base64.b64encode(private_key_der).decode('ascii')

    def _decide(self,pack,transaction_hash,mode):
        pack=self.offer.pack(pack);payment=self.payments.verify(pack,transaction_hash)
        record={'profile':DECISION,'mode':mode,'payment':payment}
        observed=self.decisions.create(payment['pack_hash'][2:],canonical(record))
        result=strict_json(observed,max_bytes=2048)
        require(canonical(result)==observed and result==record,'ticket-purchase-decision-conflict')
        self.payments.finish(payment)
        return pack,result

    def reserve_unissued_refund(self,pack,transaction_hash,signature):
        # A durable refund decision permanently forbids this pack's issuance.
        # The separate payout worker must recover ONE signed refund operation
        # to the original canonical payer; this method sends no money.
        payment=self.payments.verify(pack,transaction_hash)
        authorize_refund(self.offer,self.payments,payment,signature)
        _,decision=self._decide(pack,transaction_hash,'refund')
        return copy.deepcopy(decision)

    def issue(self,pack,transaction_hash):
        pack,decision=self._decide(pack,transaction_hash,'issue')
        key=decision['payment']['pack_hash'][2:]
        expected={'profile':REPLY,'parameters':self.offer.hash,'pack_hash':'0x'+key}
        saved=self.results.read(key)
        if saved is None:
            signatures=[self.offer.protocol.native._call('blind-sign',private_key=self._key,blinded=b)['signature']
                for b in pack['blinded']]
            record={**expected,'decision_sha256':hashlib.sha256(canonical(decision)).hexdigest(),'signatures':signatures}
            saved=self.results.create(key,canonical(record)) # Durably read back BEFORE exposing any signatures.
        record=strict_json(saved,max_bytes=32768)
        require(canonical(record)==saved and set(record)==set(expected)|{'decision_sha256','signatures'}
            and all(record[k]==v for k,v in expected.items())
            and record['decision_sha256']==hashlib.sha256(canonical(decision)).hexdigest()
            and type(record['signatures']) is list and len(record['signatures'])==len(pack['blinded']), 'ticket-issuance-record')
        for blinded,signature in zip(pack['blinded'],record['signatures']):
            raw=_decode(signature,384);number=int.from_bytes(raw,'big')
            require(len(raw)==384 and 0<number<self.offer.modulus
                and pow(number,65537,self.offer.modulus)==int.from_bytes(_decode(blinded,384),'big'),'ticket-issuance-record')
        self.payments.finish(decision['payment'])
        return {**expected,'signatures':copy.deepcopy(record['signatures'])}
