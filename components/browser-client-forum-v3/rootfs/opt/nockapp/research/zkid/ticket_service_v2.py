"""Separate narrow payment and publication RPC applications; no listener.

TLS identity is operator authentication, not Nitro attestation or proof truth.
Public transport accepts neither AWS credentials nor arbitrary signing requests.
"""
import copy
import re
import secrets

from policy import require
from ticket_issuance_v1 import PaidTicketIssuer
from ticket_native_v1 import _decode,PROFILE as TICKET_PROFILE,DOMAIN
from ticket_offer_v1 import hex_value
from ticket_publication_v2 import TicketPublicationWorker

RPC='nockapp-prepaid-service-rpc-v2'
MAX_REQUEST=102400
MAX_RESPONSE=65536


def request(offer_hash,service,operation,body):
    value={'profile':RPC,'offer_sha256':offer_hash,'service':service,
        'request_id':secrets.token_hex(16),'operation':operation,'body':copy.deepcopy(body)}
    validate_request(value,offer_hash,service)
    return value


def validate_request(value,offer_hash,service):
    require(type(value) is dict and set(value)=={'profile','offer_sha256','service','request_id','operation','body'}
        and value['profile']==RPC and value['offer_sha256']==offer_hash and value['service']==service
        and type(value['request_id']) is str and re.fullmatch(r'[0-9a-f]{32}',value['request_id']), 'ticket-rpc-envelope')
    b=value['body'];op=value['operation']
    require(type(op) is str and type(b) is dict,'ticket-rpc-operation')
    operations={'payment':{'parameters':set(),'issue':{'pack','transaction_hash'},
        'refund':{'pack','transaction_hash','signature'}},
        'publication':{'submit':{'ticket','bundle_hash'},'store':{'ticket','bundle_hash','bundle_base64'}}}
    require(service in operations and op in operations[service] and set(b)==operations[service][op],'ticket-rpc-operation')
    if op in ('issue','refund'):
        pack=b['pack']
        require(type(pack) is dict and set(pack)=={'profile','parameters','blinded'}
            and pack['profile']==TICKET_PROFILE and pack['parameters']==offer_hash
            and type(pack['blinded']) is list and 1<=len(pack['blinded'])<=32,'ticket-rpc-pack')
        for blinded in pack['blinded']:require(len(_decode(blinded,384))==384,'ticket-rpc-pack')
        hex_value(b['transaction_hash'],32)
        if op=='refund':require(type(b['signature']) is str and len(b['signature'])==132,'ticket-rpc-refund')
    if op in ('submit','store'):
        token=b['ticket'];size=32+len(DOMAIN)+64
        require(type(token) is dict and set(token)=={'profile','parameters','prepared','signature'}
            and token['profile']==TICKET_PROFILE and token['parameters']==offer_hash,'ticket-rpc-token')
        prepared=_decode(token['prepared'],size)
        require(len(prepared)==size and prepared[32:32+len(DOMAIN)]==DOMAIN
            and prepared[32+len(DOMAIN):32+len(DOMAIN)+32].hex()==offer_hash
            and len(_decode(token['signature'],384))==384,'ticket-rpc-token')
        hex_value(b['bundle_hash'],32)
        if op=='store':require(0<len(_decode(b['bundle_base64'],65536))<=65536,'ticket-rpc-content')
    return value


class _Application:
    def dispatch(self,message):
        validate_request(message,self.offer.hash,self.service)
        result={'profile':RPC,'offer_sha256':self.offer.hash,'service':self.service,'request_id':message['request_id']}
        try:
            value=self._operate(message['operation'],message['body'])
            require(type(value) is dict,'ticket-rpc-result')
            return {**result,'status':'ok','result':value}
        except Exception:
            # Never expose SDK diagnostics, private keys, request bodies or
            # credentials through exception strings or payload logging.
            return {**result,'status':'rejected','error':'operation-unavailable'}


class PaymentApplication(_Application):
    service='payment'
    def __init__(self,issuer):
        require(isinstance(issuer,PaidTicketIssuer),'ticket-rpc-payment');self.issuer=issuer;self.offer=issuer.offer
    def _operate(self,op,body):
        if op=='parameters':self.offer.check();return copy.deepcopy(self.offer.manifest)
        if op=='issue':return self.issuer.issue(**body)
        return self.issuer.reserve_unissued_refund(**body)


class PublicationApplication(_Application):
    service='publication'
    def __init__(self,worker):
        require(isinstance(worker,TicketPublicationWorker),'ticket-rpc-publication');self.worker=worker;self.offer=worker.offer
    def _operate(self,op,body):
        if op=='submit':return self.worker.submit(body['ticket'],body['bundle_hash'])
        return self.worker.store(body['ticket'],body['bundle_hash'],_decode(body['bundle_base64'],65536))
