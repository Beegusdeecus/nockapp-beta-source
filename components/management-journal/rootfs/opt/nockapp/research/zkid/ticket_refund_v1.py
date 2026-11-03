"""Exact-purpose EOA consent for an unissued pack's irreversible refund fence.

Replay can only repeat the same cancellation; destination is always the original
canonical payer. No post, authorship key, ticket serial or redemption is included.
"""
from policy import require
from ticket_offer_v1 import TicketOffer,hex_value
from wallet_authorship import DOMAIN_FIELDS,verify_signature

PURPOSE='Permanently cancel issuance of this paid ticket pack; refund only its original paying wallet'


def refund_data(offer,pack_hash,transaction_hash):
    require(isinstance(offer,TicketOffer),'ticket-refund-offer');offer.check()
    hex_value(pack_hash,32);hex_value(transaction_hash,32)
    fields=[('purpose','string'),('parameters','bytes32'),('packHash','bytes32'),('paymentTransaction','bytes32')]
    return {'types':{'EIP712Domain':DOMAIN_FIELDS,
        'NockAppUnissuedPackRefundV1':[{'name':n,'type':t} for n,t in fields]},
        'primaryType':'NockAppUnissuedPackRefundV1',
        'domain':{'name':'NockApp Prepaid Tickets','version':'1','chainId':84532,
            'verifyingContract':offer.manifest['purchase_contract']},
        'message':{'purpose':PURPOSE,'parameters':'0x'+offer.hash,
            'packHash':pack_hash,'paymentTransaction':transaction_hash}}


def authorize_refund(offer,payments,payment,signature):
    tx=payments.rpc.call('eth_getTransactionByHash',payment['transaction_hash'])
    require(type(tx) is dict and tx.get('hash')==payment['transaction_hash']
        and tx.get('blockHash')==payment['block_hash'],'ticket-refund-payment')
    payer=hex_value(tx.get('from'),20)
    require(verify_signature(refund_data(offer,payment['pack_hash'],payment['transaction_hash']),payer,signature),
        'ticket-refund-not-authorized')
    payments.finish(payment)
