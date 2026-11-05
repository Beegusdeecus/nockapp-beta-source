"""Versioned count routes inside the single Base application, no new listener."""
import copy
import re

from count_pipeline import CountProvider,PROFILE
from count_policy import CountSession,POLICY_HASH
from count_protocol import PROTOCOL
from count_state import count_view
from domain_issuer import IssuerApplication
from domain_state import public_view
from policy import hex_string,require

APPROVAL='nockapp-base-count-approval-v2'
OPERATIONS=frozenset({'parameters','registry','begin','status','abort','check-post','discover-post',
    'recover-delivery','commit','witness','activation-status'})
POST_OPERATIONS=frozenset({'post-challenge','post-submit'})


def validate_count_approval(value):
    require(type(value) is dict and set(value)=={'profile','native_sha256','policy_sha256','schema_profile','protocol'}
        and value['profile']==APPROVAL and value['policy_sha256']==POLICY_HASH
        and value['schema_profile']==PROFILE and value['protocol']==PROTOCOL,'count-approval')
    hex_string(value['native_sha256'],64);require(any(bytes.fromhex(value['native_sha256'])),'count-approval')
    return value


def count_approval(native):
    return validate_count_approval({'profile':APPROVAL,'native_sha256':native.sha256.hex(),
        'policy_sha256':POLICY_HASH,'schema_profile':PROFILE,'protocol':PROTOCOL})


class CountStateAdapter:
    def __init__(self,state):self.protected=state
    def operate(self,method,*args,**kwargs):return self.protected.operate('count_'+method,*args,**kwargs)


class CountIssuerApplication(IssuerApplication):
    def __init__(self,state,provider,clock):
        require(isinstance(provider,CountProvider) and provider.budget_enforced is True,'count-provider-required')
        super().__init__(CountStateAdapter(state),provider,clock)
        self.protected_state=state;self.native=state.count_native;self.approval=count_approval(self.native)

    @staticmethod
    def session(body):
        require(type(body) is dict and set(body)==set(CountSession.__dataclass_fields__),'message-schema')
        return CountSession(**body)

    def operate(self,op,body):
        require(op in OPERATIONS,'message-schema')
        state=self.protected_state
        if op=='parameters':self.fields(body,[]);return copy.deepcopy(self.approval)
        if op=='registry':self.fields(body,[]);return count_view(self.native,state.backend.public_view())
        if op=='begin':
            self.fields(body,['request','desktop_nonce','username','approve_public_profile_lookup'])
            require(body['approve_public_profile_lookup'] is True,'consent-required')
            username=body['username']
            require(type(username) is str and re.fullmatch(r'[A-Za-z0-9_]{1,15}',username),'account-handle')
            hex_string(body['desktop_nonce'],64);self.state.operate('validate_request',body['request'])
            saved=self.state.operate('find_begin',body['request'],body['desktop_nonce'],username,self.clock())['session']
            if saved is not None:session=CountSession(**saved)
            else:
                account=self.provider.resolve(username)
                session=self.state.operate('begin',body['request'],body['desktop_nonce'],account,username,self.clock())
            return {'session':session.__dict__,'post_text':session.post_text,'expires_at':session.created_at+600}
        if op=='witness':
            self.fields(body,['handle']);hex_string(body['handle'],64)
            _,core=state.load()
            result=core.native.call('witness',issuer=core._issuer,handle=body['handle'])
            view=count_view(self.native,{'definition_hash':core.definition_hash,'public':result['public'],'sequence':core.sequence})
            return {'witness':result['witness'],**view}
        if op=='activation-status':
            self.fields(body,['session']);session=self.session(body['session'])
            view=count_view(self.native,state.backend.public_view())
            require(session.issuer_key==view['definition_hash'],'count-issuer-definition')
            result=state.finalized_status(session)
            if 'issuer_definition' in result:
                require(result['issuer_definition']==state.namespace,'count-issuer-definition')
                result={**result,'issuer_definition':view['definition_hash'],'authority_definition':state.namespace}
            return result
        return super().operate(op,body)
