"""Bounded issuer application API, to run INSIDE the measured trust boundary.

No socket/listener is opened here. Authentication, attestation, provisioned keys,
protected managed state and the bound channel remain separate deployment gates.
There is deliberately no proof-verification or public-ID input operation.
"""
import copy
import re

from policy import Session, Rejected, canonical, strict_json, require, hex_string, identifier

RPC='nockapp-zkid-issuer-rpc-research-v1'
MAX_REQUEST=65536
ERRORS={'message-schema','consent-required','source-profile-object','source-profile-type','registration-not-pending','registration-already-committed',
    'registration-delivery-unavailable','registration-not-found','registration-unavailable','session-expired',
    'registry-conflict','registry-state-changed','registry-capacity','replacement-raced','replacement-not-pending',
    'domain-native-rejected','domain-blind-request','source-challenge-mismatch','source-account-mismatch',
    'source-handle-mismatch','source-original-post-required','source-stale-post','source-user-status',
    'source-user-schema','source-account-unavailable','provider-unavailable','provider-rate-limit',
    'provider-http-error','api-spending-limit','account-handle','account-or-post-id',
    'source-discovery-schema','discovery-failed','discovery-limit','discovery-recovery-required'}


class IssuerApplication:
    def __init__(self,state,provider,clock):
        require(provider.budget_enforced is True,'provider-budget-required')
        self.state=state;self.provider=provider;self.clock=clock

    @staticmethod
    def session(body):
        require(type(body) is dict and set(body)==set(Session.__dataclass_fields__),'message-schema')
        session=Session(**body)
        require(session.request_scheme=='credx-bbs-domain-0.2.1','message-schema')
        return session

    @staticmethod
    def fields(body,expected):
        require(type(body) is dict and set(body)==set(expected),'message-schema')

    def operate(self,op,body):
        if op=='registry':
            self.fields(body,[])
            return self.state.backend.public_view()
        if op=='begin':
            self.fields(body,['request','desktop_nonce','username','approve_public_profile_lookup'])
            require(body['approve_public_profile_lookup'] is True,'consent-required')
            username=body['username']
            require(type(username) is str and re.fullmatch(r'[A-Za-z0-9_]{1,15}',username),'account-handle')
            hex_string(body['desktop_nonce'],64)
            # Reject malformed possession proofs BEFORE any paid source lookup.
            self.state.operate('validate_request',body['request'])
            saved=self.state.operate('find_begin',body['request'],body['desktop_nonce'],username,self.clock())['session']
            if saved is not None:session=Session(**saved)
            else:
                account=self.provider.resolve(username)
                session=self.state.operate('begin',body['request'],body['desktop_nonce'],account,username,self.clock())
            return {'session':session.__dict__,'post_text':session.post_text,'expires_at':session.created_at+600}
        if op in ('status','abort'):
            self.fields(body,['session','nonce'])
            session=self.session(body['session']);hex_string(body['nonce'],64)
            return self.state.operate(op,session,body['nonce'],self.clock())
        if op=='check-post':
            self.fields(body,['session','tweet_id','approve_source_check'])
            require(body['approve_source_check'] is True,'consent-required')
            session=self.session(body['session']);identifier(body['tweet_id'])
            status=self.state.operate('status',session,'00'*32,self.clock())
            if status['state']=='issued':
                return self.state.operate('recover_delivery',session,self.clock())
            require(status['state']=='pending','registration-unavailable')
            return self.state.operate('stage_provider',session,body['tweet_id'],self.provider,self.clock())
        if op=='discover-post':
            self.fields(body,['session','approve_source_check'])
            require(body['approve_source_check'] is True,'consent-required')
            session=self.session(body['session'])
            status=self.state.operate('status',session,'00'*32,self.clock())
            require(status['state'] in ('pending','issued','committed'),'registration-unavailable')
            if status['state']!='pending':
                return {'state':status['state'],'tweet_id':None,'next_poll_at':None,
                        'expires_at':session.created_at+600}
            reservation=self.state.operate('reserve_discovery',session,self.clock())
            if reservation['admitted']:
                try:found=self.provider.discover(session,self.clock)
                except Exception:
                    try:self.state.operate('fail_discovery',session,reservation['attempts'])
                    except Exception:pass  # CAS/abort uncertainty never authorizes a retry.
                    raise
                reservation=self.state.operate('finish_discovery',session,reservation['attempts'],found,self.clock())
            return {'state':'found' if reservation['tweet_id'] is not None else 'waiting',
                    'tweet_id':reservation['tweet_id'],'next_poll_at':reservation['next_poll_at'],
                    'expires_at':session.created_at+600}
        if op=='recover-delivery':
            self.fields(body,['session'])
            return self.state.operate('recover_delivery',self.session(body['session']),self.clock())
        if op=='commit':
            self.fields(body,['session','ack'])
            return self.state.operate('commit',self.session(body['session']),body['ack'],self.clock())
        if op=='witness':
            self.fields(body,['handle']);hex_string(body['handle'],64)
            _,core=self.state.load()
            result=core.native.call('witness',issuer=core._issuer,handle=body['handle'])
            return {'witness':result['witness'],'public':result['public'],'sequence':core.sequence,
                    'definition_hash':core.definition_hash}
        raise Rejected('message-schema')

    def dispatch(self,message):
        ident='0'*32
        try:
            require(type(message) is dict and set(message)=={'id','profile','operation','body'},'message-schema')
            hex_string(message['id'],32);ident=message['id']
            require(message['profile']==RPC and type(message['operation']) is str
                    and len(canonical(message))<=MAX_REQUEST,'message-schema')
            result=self.operate(message['operation'],message['body'])
            require(type(result) is dict and len(canonical(result))<=131072,'issuer-result-size')
            return {'id':ident,'profile':RPC,'status':'ok','result':copy.deepcopy(result),'laboratory':True,'verified':False}
        except Exception as error:
            code=error.args[0] if isinstance(error,Rejected) and error.args and type(error.args[0]) is str and error.args[0] in ERRORS else 'issuer-operation-failed'
            return {'id':ident,'profile':RPC,'status':'rejected','code':code,'laboratory':True,'verified':False}

    def dispatch_bytes(self,data):
        try:
            require(type(data) is bytes and 0<len(data)<=MAX_REQUEST,'message-schema')
            return canonical(self.dispatch(strict_json(data)))
        except Exception:
            return canonical({'id':'0'*32,'profile':RPC,'status':'rejected','code':'message-schema','laboratory':True,'verified':False})
