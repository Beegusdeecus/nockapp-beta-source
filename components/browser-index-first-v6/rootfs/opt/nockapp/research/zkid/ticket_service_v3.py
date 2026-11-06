"""Versioned index-first RPC: raw bytes for sponsorship, no ticket for repair."""
import copy,secrets
from policy import require
from ticket_offer_v1 import hex_value
from ticket_native_v1 import _decode
from ticket_service_v2 import validate_request as legacy_validate,MAX_REQUEST,MAX_RESPONSE,RPC as LEGACY
from ticket_publication_v3 import IndexFirstPublicationWorker

RPC='nockapp-prepaid-service-rpc-v3'

def validate_request(value,offer_hash,service):
    require(type(value) is dict and set(value)=={'profile','offer_sha256','service','request_id','operation','body'}
        and value['profile']==RPC and value['offer_sha256']==offer_hash and value['service']==service=='publication',
        'ticket-v3-envelope')
    require(type(value['request_id']) is str and len(value['request_id'])==32
        and all(c in '0123456789abcdef'for c in value['request_id']),'ticket-v3-id')
    b=value['body'];op=value['operation']
    require(type(b) is dict and op in ('submit','store')
        and set(b)==({'ticket','bundle_hash','bundle_base64'}if op=='submit'else{'bundle_hash','bundle_base64'}),'ticket-v3-operation')
    hex_value(b['bundle_hash'],32);require(0<len(_decode(b['bundle_base64'],65536))<=65536,'ticket-v3-content')
    if op=='submit':
        legacy_validate({**value,'profile':LEGACY,'operation':'store'},offer_hash,service)
    return value

def request(offer_hash,operation,body):
    return validate_request({'profile':RPC,'offer_sha256':offer_hash,'service':'publication',
        'request_id':secrets.token_hex(16),'operation':operation,'body':copy.deepcopy(body)},offer_hash,'publication')

class PublicationApplicationV3:
    service='publication'
    validate=staticmethod(validate_request)
    def __init__(self,worker):
        require(type(worker) is IndexFirstPublicationWorker,'ticket-v3-worker')
        self.worker,self.offer=worker,worker.offer
    def dispatch(self,message):
        self.validate(message,self.offer.hash,self.service)
        result={k:message[k]for k in ('profile','offer_sha256','service','request_id')}
        try:
            b=message['body'];raw=_decode(b['bundle_base64'],65536)
            value=self.worker.submit(b['ticket'],b['bundle_hash'],raw)if message['operation']=='submit'else self.worker.store(b['bundle_hash'],raw)
            return {**result,'status':'ok','result':value}
        except Exception:return {**result,'status':'rejected','error':'operation-unavailable'}
