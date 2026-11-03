"""Resume original fenced issuer state with v3 six-month source sessions.

One issuer/key/account map/handle pool across original, count-v2 and renewal-v3.
No initialize/reset route. All signing handles are burned before native signing;
only a verified replacement receipt changes the incumbent. Backend finality/CAS
and boot lease semantics are inherited unchanged, not replaced by local storage.
"""
import copy
import json
import re
import secrets
from cryptography.exceptions import InvalidTag
from count_state import CountCore,CountLeasedIssuer
from count_policy import CountSession,SCHEME as OLD_SCHEME
from domain_pipeline import definition_hash
from domain_state import LIMIT,public_view as original_view,restore,snapshot
from renewal_native_v3 import public_view
from renewal_policy_v3 import RenewalSession,RenewalProvider,SCHEME,PROFILE,POLICY_HASH,evaluate_renewal
from policy import Rejected,canonical,digest,hex_string,require,timestamp

STATE='nockapp-renewal-leased-private-state-v3'
OPERATIONS={'renewal_validate_request','renewal_find_begin','renewal_lookup_begin','renewal_begin','renewal_stage_fixture','renewal_stage_provider',
    'renewal_commit','renewal_recover_delivery','renewal_status','renewal_abort','renewal_reserve_discovery',
    'renewal_finish_discovery','renewal_fail_discovery'}


class RenewalCore(CountCore):
    def renewal_public_view(self):return public_view(self.renewal_native,original_view(self))

    @staticmethod
    def _renewal_session(session):
        require(type(session) is RenewalSession and session.request_scheme==SCHEME,'renewal-session-version')

    def renewal_validate_request(self,request):
        require(type(request) is dict and len(canonical(request))<=16384 and request.get('blind_claim_labels')==['secret'],'renewal-blind-request')
        require(self.renewal_native.call('validate-request',issuer=self._issuer,request=request)=={'valid':True},'renewal-blind-request')
        return {'valid':True}

    def renewal_find_begin(self,request,desktop_nonce,username,now):
        found=self.find_begin(request,desktop_nonce,username,now)
        if found['session'] is not None:RenewalSession(**found['session'])
        return found

    def renewal_lookup_begin(self,request,desktop_nonce,username,now):
        """Recover only an exact existing session, including expired/aborted ones.

        No source lookup, new session, persistence callback or expiry extension.
        A recovered expired session can use the ordinary authenticated abort.
        """
        self.renewal_validate_request(request);hex_string(desktop_nonce,64);timestamp(now)
        require(type(username) is str and re.fullmatch(r'[A-Za-z0-9_]{1,15}',username),'account-handle')
        with self._lock:
            matches=[p for p in self._pending.values() if p['request']==request
                and p['session'].desktop_nonce==desktop_nonce and p['session'].username==username]
            require(len(matches)<=1,'registration-unavailable')
            if not matches:return {'session':None}
            session=matches[0]['session'];self._renewal_session(session)
            require(now>=session.created_at,'session-expired')
            return {'session':copy.deepcopy(session.__dict__)}

    def renewal_begin(self,request,desktop_nonce,account_id,username,now):
        self.renewal_validate_request(request);hex_string(desktop_nonce,64)
        with self._lock:
            saved=self.renewal_find_begin(request,desktop_nonce,username,now)['session']
            if saved is not None:
                require(saved['account_id']==account_id,'source-account-mismatch');return RenewalSession(**saved)
            view=self.renewal_public_view()
            session=RenewalSession.create(desktop_nonce,digest(request),account_id,username,view['definition_hash'],now)
            self._pending[session.binding]={'session':session,'request':copy.deepcopy(request),'old':self._accounts.get(account_id),
                'issued':False,'acknowledged':False,'aborted':False}
            self._persist();return session

    def _renewal_stage(self,session,attrs):
        self._renewal_session(session)
        require(attrs['binding']==session.binding and attrs['policy']==POLICY_HASH,'renewal-source-binding')
        with self._lock:
            pending=self._pending_session(session);lease=self._base_lease
            require(not pending['issued'] and 'handle' not in pending,'issuance-replay')
            require(lease is not None and lease['cursor']<lease['end'],'reserved-batch-exhausted')
            pending['handle']=self._handles[lease['cursor']];lease['cursor']+=1;pending['base_sequence']=self.sequence
            self._persist() # Whole batch already burned at finalized boot; persist cursor before signing too.
            result=self.renewal_native.call('stage',issuer=self._issuer,request=pending['request'],handle=pending['handle'],attributes=attrs)
            pending.update(issued=True,attributes=copy.deepcopy(attrs),response={'bundle':result['bundle'],'attributes':copy.deepcopy(attrs)})
            self._persist();return copy.deepcopy(pending['response'])

    def renewal_stage_fixture(self,session,tweet_id,tweet_data,user_data,now):
        return self._renewal_stage(session,evaluate_renewal(session,tweet_id,tweet_data,user_data,now))

    def renewal_stage_provider(self,session,tweet_id,provider,now):
        self._renewal_session(session);session.check_time(now)
        require(isinstance(provider,RenewalProvider),'renewal-provider-required')
        pending=self._pending_session(session);require(not pending['issued'] and 'handle' not in pending,'issuance-replay')
        return self._renewal_stage(session,provider.check(session,tweet_id,now))

    def renewal_commit(self,session,ack,now):
        self._renewal_session(session);session.check_time(now)
        with self._lock:
            pending=self._pending_session(session)
            require(pending['issued'] and not pending['acknowledged'],'replacement-not-pending')
            require(self._accounts.get(session.account_id)==pending['old'],'replacement-raced')
            require(pending['base_sequence']==self.sequence,'registry-state-changed')
            before={k:v for k,v in self._issuer.items() if k!='revocation_registry'}
            result=self.renewal_native.call('commit',issuer=self._issuer,handle=pending['handle'],old_handle=pending['old'],ack=ack,attributes=pending['attributes'])
            require(before=={k:v for k,v in result['issuer'].items() if k!='revocation_registry'}
                and definition_hash(result['public'])==self.definition_hash,'renewal-key-continuity')
            self._issuer=result['issuer'];self.public=result['public'];self.sequence+=1
            self._accounts[session.account_id]=pending['handle'];pending['acknowledged']=True;pending.pop('response',None);self._persist()
            return {'profile':PROFILE,'registry_sequence':self.sequence,'replaced':pending['old'] is not None,
                'activation_pending_finality':True,'verified':False}

    def renewal_recover_delivery(self,session,now):self._renewal_session(session);return self.recover_delivery(session,now)
    def renewal_status(self,session,nonce,now):
        self._renewal_session(session);r=self.status(session,nonce,now);r['profile']=PROFILE;return r
    def renewal_abort(self,session,nonce,now):
        self._renewal_session(session);r=self.abort(session,nonce,now);r['profile']=PROFILE;return r
    def renewal_reserve_discovery(self,session,now):self._renewal_session(session);return self.reserve_discovery(session,now)
    def renewal_finish_discovery(self,session,attempts,found,now):self._renewal_session(session);return self.finish_discovery(session,attempts,found,now)
    def renewal_fail_discovery(self,session,attempts):self._renewal_session(session);return self.fail_discovery(session,attempts)


class RenewalLeasedIssuer(CountLeasedIssuer):
    def __init__(self,backend,key,namespace,native,finality,count_native,renewal_native):
        super().__init__(backend,key,namespace,native,finality,count_native);self.renewal_native=renewal_native

    def initialize(self,core):raise Rejected('renewal-state-resume-only')

    def _renewal_binding(self):return {'profile':PROFILE,'policy':POLICY_HASH,'native_sha256':self.renewal_native.sha256,'legacy_definition':self.namespace}
    def _renewal_aad(self,revision):return canonical({'profile':STATE,'namespace':self.namespace,'revision':revision})

    def _attach(self,core):
        core.__class__=RenewalCore;core.count_native=self.count_native;core.renewal_native=self.renewal_native;return core

    def _seal(self,core,revision):
        body=canonical({'profile':STATE,'core':snapshot(core),'lease':getattr(core,'_base_lease',None),
            'count':self._binding(),'renewal':self._renewal_binding()})
        require(len(body)<=LIMIT,'registry-capacity');nonce=secrets.token_bytes(12)
        return nonce+self._cipher.encrypt(nonce,body,self._renewal_aad(revision))

    def _open(self,revision,envelope):
        require(type(revision) is int and type(envelope) is bytes and 28<len(envelope)<=LIMIT+28,'registry-missing')
        try:plain=self._cipher.decrypt(envelope[:12],envelope[12:],self._renewal_aad(revision))
        except InvalidTag:return self._attach(super()._open(revision,envelope))
        try:
            data=json.loads(plain)
            require(set(data)=={'profile','core','lease','count','renewal'} and data['profile']==STATE
                and data['count']==self._binding() and data['renewal']==self._renewal_binding(),'renewal-state-profile')
            state=copy.deepcopy(data['core']);versioned={}
            for key,value in list(state['pending'].items()):
                scheme=value['session'].get('request_scheme')
                if scheme in (OLD_SCHEME,SCHEME):
                    session=(RenewalSession if scheme==SCHEME else CountSession)(**value['session'])
                    require(key==session.binding,'renewal-session-binding');versioned[key]={**value,'session':session};del state['pending'][key]
            core=self._attach(restore(state,self.native));core._pending.update(versioned);core._base_lease=data['lease']
            require(core.definition_hash==self.namespace,'issuer-definition');return core
        except Rejected:raise
        except Exception:raise Rejected('renewal-state-authentication') from None

    def operate(self,method,*args,**kwargs):
        if method not in OPERATIONS:return super().operate(method,*args,**kwargs)
        require(self.ready and self.poll_boot()['state']=='ready','issuer-not-ready')
        revision,core=self.load();cursor=[revision]
        def persist():cursor[0]=self.backend.compare_exchange(cursor[0],self._seal(core,cursor[0]+1),original_view(core))
        core._persist_callback=persist;return getattr(core,method)(*args,**kwargs)
