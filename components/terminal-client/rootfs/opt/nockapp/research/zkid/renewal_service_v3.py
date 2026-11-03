"""Strict renewal source operations inside the measured issuer boundary.

No listener, gas signer or publication approval. Provider is pinned/budgeted;
browser input cannot supply source bytes, counts, dates, keys or issuer state.
Transport attestation and the real runtime remain separate integration gates.
"""
import copy
import re
from domain_issuer import IssuerApplication
from domain_pipeline import definition_hash
from policy import canonical,hex_string,require
from renewal_policy_v3 import RenewalSession,RenewalProvider,PROFILE,POLICY_HASH
from renewal_native_v3 import public_view

RPC='nockapp-renewal-issuer-rpc-v3'
OPERATIONS=frozenset({'parameters','registry','begin','status','abort','check-post','discover-post','recover-delivery','commit','witness','activation-status'})

class StateAdapter:
    def __init__(self,state):self.state=state
    def operate(self,method,*args,**kwargs):return self.state.operate('renewal_'+method,*args,**kwargs)

class RenewalApplication(IssuerApplication):
    def __init__(self,state,provider,clock):
        require(isinstance(provider,RenewalProvider) and provider.budget_enforced is True,'renewal-provider-required')
        super().__init__(StateAdapter(state),provider,clock);self.protected=state;self.native=state.renewal_native

    @staticmethod
    def session(body):
        require(type(body) is dict and set(body)==set(RenewalSession.__dataclass_fields__),'message-schema');return RenewalSession(**body)

    def operate(self,op,body):
        require(op in OPERATIONS,'message-schema');s=self.protected
        if op=='parameters':
            self.fields(body,[]);return {'profile':PROFILE,'policy_sha256':POLICY_HASH,'native_sha256':self.native.sha256,'authority_definition':s.namespace}
        if op=='registry':self.fields(body,[]);return copy.deepcopy(s.backend.public_view())
        if op=='begin':
            self.fields(body,['request','desktop_nonce','username','approve_public_profile_lookup'])
            require(body['approve_public_profile_lookup'] is True,'consent-required');username=body['username']
            require(type(username) is str and re.fullmatch(r'[A-Za-z0-9_]{1,15}',username),'account-handle');hex_string(body['desktop_nonce'],64)
            self.state.operate('validate_request',body['request'])
            saved=self.state.operate('find_begin',body['request'],body['desktop_nonce'],username,self.clock())['session']
            if saved is None:
                account=self.provider.resolve(username);session=self.state.operate('begin',body['request'],body['desktop_nonce'],account,username,self.clock())
            else:session=RenewalSession(**saved)
            return {'session':session.__dict__,'post_text':session.post_text,'expires_at':session.created_at+600}
        if op=='witness':
            self.fields(body,['handle']);hex_string(body['handle'],64);_,core=s.load()
            result=self.native.call('witness',issuer=core._issuer,handle=body['handle'])
            return {'public':result['public'],'definition_hash':definition_hash(result['public']),
                'sequence':core.sequence,'authority_definition':s.namespace,'witness':result['witness']}
        if op=='activation-status':
            self.fields(body,['session']);session=self.session(body['session'])
            require(session.issuer_key==public_view(self.native,s.backend.public_view())['definition_hash'],'renewal-issuer-definition')
            return s.finalized_status(session)
        return super().operate(op,body)

    def dispatch(self,message):
        ident='0'*32
        try:
            require(type(message) is dict and set(message)=={'profile','id','operation','body'} and message['profile']==RPC
                and len(canonical(message))<=65536,'message-schema');hex_string(message['id'],32);ident=message['id']
            result=self.operate(message['operation'],message['body']);require(type(result) is dict and len(canonical(result))<=131072,'renewal-result-size')
            return {'profile':RPC,'id':ident,'status':'ok','result':result}
        except Exception:return {'profile':RPC,'id':ident,'status':'rejected','code':'renewal-operation-unavailable'}
