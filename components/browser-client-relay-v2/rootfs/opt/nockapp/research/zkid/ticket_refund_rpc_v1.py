"""Narrow versioned refund protocol/client. No backend signing imports."""
import copy
import re
import secrets
from policy import require
from ticket_offer_v1 import hex_value
from ticket_transport_v2 import TicketRemote,endpoint as old_endpoint

RPC='nockapp-refund-service-rpc-v1'
ENDPOINT='nockapp-refund-service-endpoint-v1'
MAX_REQUEST=4096
MAX_RESPONSE=8192

def endpoint(value):
    require(type(value) is dict and set(value)=={'profile','host','port','service','offer_sha256','policy_sha256'}
        and value['profile']==ENDPOINT and value['service']=='refund'
        and type(value['policy_sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['policy_sha256']), 'refund-endpoint')
    # Reuse the existing fixed host/port parser, not its persisted protocol.
    old_endpoint({'profile':'nockapp-prepaid-service-endpoint-v2','host':value['host'],'port':value['port'],
        'service':'payment','offer_sha256':value['offer_sha256']})
    return value

def validate(value,offer_hash,policy_hash):
    require(type(value) is dict and set(value)=={'profile','offer_sha256','policy_sha256','service','request_id','operation','body'}
        and value['profile']==RPC and value['offer_sha256']==offer_hash and value['policy_sha256']==policy_hash
        and value['service']=='refund' and type(value['request_id']) is str and re.fullmatch('[0-9a-f]{32}',value['request_id']), 'refund-rpc-envelope')
    op=value['operation'];b=value['body']
    require(type(op) is str and type(b) is dict and op in ('policy','submit','status')
        and set(b)==(set() if op=='policy' else {'pack_hash','signature'} if op=='submit' else {'pack_hash'}),'refund-rpc-operation')
    if op!='policy':hex_value(b['pack_hash'],32)
    if op=='submit':require(type(b['signature']) is str and re.fullmatch('0x[0-9a-fA-F]{130}',b['signature']),'refund-rpc-signature')

class RefundRemote(TicketRemote):
    _endpoint=staticmethod(endpoint)
    _correlation=('profile','offer_sha256','policy_sha256','service','request_id')
    _max_request=MAX_REQUEST
    _max_response=MAX_RESPONSE

    def _message(self,a,operation,body):
        message={'profile':RPC,'offer_sha256':a['offer_sha256'],'policy_sha256':a['policy_sha256'],'service':'refund',
            'request_id':secrets.token_hex(16),'operation':operation,'body':copy.deepcopy(body)}
        validate(message,a['offer_sha256'],a['policy_sha256']);return message
