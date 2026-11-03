"""Bounded independent APPLICATION verifier API, never issuer/native wallet API.

No listener is opened. An application-owned authenticated transport must invoke
this using installer-owned verifier configuration and separately scoped role.
No proof or app ID is forwarded to an issuer operation.
"""
from policy import Rejected,canonical,hex_string,require,strict_json
from post_scope import payload,facts

PROFILE='nockapp-zkid-post-verifier-rpc-v1'
MAX_REQUEST=131072
ERRORS={'post-schema','post-facts','post-context','post-proof-size','post-proof-shape','post-receipt',
        'post-expired','post-not-accepted','post-proof-changed','post-proof-conflict','post-archive',
        'action-not-outstanding','action-expired','registry-state-changed','registry-unavailable',
        'domain-issuer-changed','domain-proof-rejected','domain-native-rejected'}


def validate_request(message):
    require(type(message) is dict and set(message)=={'profile','id','operation','body'}
            and message['profile']==PROFILE and len(canonical(message))<=MAX_REQUEST,'message-schema')
    hex_string(message['id'],32);op=message['operation'];body=message['body']
    require(type(op) is str and op in ('challenge','accept','inspect') and type(body) is dict,'message-schema')
    required={'post','facts'}|({'nonce'} if op!='challenge' else set())|({'proof'} if op=='accept' else set())
    require(set(body)==required,'message-schema');payload(body['post']);facts(body['facts'])
    if op!='challenge':hex_string(body['nonce'],64)
    if op=='accept':require(type(body['proof']) is dict,'message-schema')
    return message


class PostApplication:
    def __init__(self,verifier):self.verifier=verifier

    def dispatch(self,message):
        ident='0'*32
        try:
            validate_request(message);ident=message['id'];op=message['operation'];body=message['body']
            args=[body['post'],body['facts']]
            if op!='challenge':args.append(body['nonce'])
            if op=='accept':args.append(body['proof'])
            result=getattr(self.verifier,op)(*args)
            return {'profile':PROFILE,'id':ident,'status':'ok','result':result,'laboratory':True,'verified':False}
        except Exception as error:
            code=error.args[0] if isinstance(error,Rejected) and error.args and error.args[0] in ERRORS else 'post-operation-unavailable'
            return {'profile':PROFILE,'id':ident,'status':'rejected','code':code,'laboratory':True,'verified':False}

    def dispatch_bytes(self,data):
        try:message=strict_json(data,max_bytes=MAX_REQUEST)
        except Exception:message=None
        return canonical(self.dispatch(message))
