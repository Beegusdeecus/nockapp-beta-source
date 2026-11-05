"""Count-v2 extension of the existing leased issuer, without identity reset.

The authoritative registry keeps its original definition/key material. A fixed
native projection derives the count schema using those SAME keys and accumulator.
One account map, handle pool, lease cursor and sequence cover both versions.
"""
import copy
import json
import secrets

from cryptography.exceptions import InvalidTag

from base_finality import LeasedCore,LeasedIssuer
from count_pipeline import CountProvider,PROFILE
from count_policy import CountSession,SCHEME,POLICY_HASH,evaluate_count
from domain_pipeline import attributes,definition_hash
from domain_state import LIMIT,public_view,restore,snapshot
from policy import Rejected,canonical,digest,hex_string,require

STATE='nockapp-base-count-extension-private-state-v2'
OPERATIONS={'count_validate_request','count_find_begin','count_begin','count_stage_fixture','count_stage_provider',
    'count_commit','count_recover_delivery','count_status','count_abort','count_reserve_discovery',
    'count_finish_discovery','count_fail_discovery'}


def count_view(native,view):
    require(type(view) is dict and set(view)=={'definition_hash','public','sequence'}
        and definition_hash(view['public'])==view['definition_hash'],'count-legacy-view')
    projected=native.call('legacy-public-count-view',public=view['public'])
    public=projected['public']
    # The only permitted difference is the independently fixed schema. Keys,
    # issuer ID and accumulator must match the authoritative v1 public view.
    require({k:v for k,v in public.items() if k!='schema'}==
        {k:v for k,v in view['public'].items() if k!='schema'},'count-key-continuity')
    return {'definition_hash':definition_hash(public),'public':public,'sequence':view['sequence']}


class CountCore(LeasedCore):
    def count_public_view(self):return count_view(self.count_native,public_view(self))

    @staticmethod
    def _count_session(session):
        require(type(session) is CountSession and session.request_scheme==SCHEME,'count-session-version')

    def count_validate_request(self,request):
        require(type(request) is dict and len(canonical(request))<=16384
            and request.get('blind_claim_labels')==['secret'],'count-blind-request')
        result=self.count_native.call('legacy-validate-count-request',issuer=self._issuer,request=request)
        require(result.get('valid') is True,'count-blind-request');return {'valid':True}

    def count_find_begin(self,request,desktop_nonce,username,now):
        found=self.find_begin(request,desktop_nonce,username,now)
        if found['session'] is not None:CountSession(**found['session'])
        return found

    def count_begin(self,request,desktop_nonce,account_id,username,now):
        self.count_validate_request(request);hex_string(desktop_nonce,64)
        with self._lock:
            saved=self.count_find_begin(request,desktop_nonce,username,now)['session']
            if saved is not None:
                require(saved['account_id']==account_id,'source-account-mismatch');return CountSession(**saved)
            view=self.count_public_view()
            session=CountSession.create(desktop_nonce,digest(request),account_id,username,view['definition_hash'],now)
            self._pending[session.binding]={'session':session,'request':copy.deepcopy(request),
                'old':self._accounts.get(account_id),'issued':False,'acknowledged':False,'aborted':False}
            self._persist();return session

    def _count_stage(self,session,values):
        self._count_session(session)
        with self._lock:
            pending=self._pending_session(session)
            require(not pending['issued'] and 'handle' not in pending,'issuance-replay')
            lease=self._base_lease
            require(lease is not None and lease['cursor']<lease['end'],'reserved-batch-exhausted')
            pending['handle']=self._handles[lease['cursor']];lease['cursor']+=1
            pending['base_sequence']=self.sequence;self._persist()
            attrs=attributes(values,session.binding)
            result=self.count_native.call('legacy-stage-count',issuer=self._issuer,request=pending['request'],
                handle=pending['handle'],attributes=attrs)
            pending.update(issued=True,attributes=attrs,response={'bundle':result['bundle'],'attributes':copy.deepcopy(attrs)})
            self._persist();return copy.deepcopy(pending['response'])

    def count_stage_fixture(self,session,tweet_id,tweet_data,user_data,now):
        return self._count_stage(session,evaluate_count(session,tweet_id,tweet_data,user_data,now))

    def count_stage_provider(self,session,tweet_id,provider,now):
        self._count_session(session);require(isinstance(provider,CountProvider),'count-provider-required')
        pending=self._pending_session(session)
        require(not pending['issued'] and 'handle' not in pending,'issuance-replay')
        return self._count_stage(session,provider.check(session,tweet_id,now))

    def count_commit(self,session,ack,now):
        self._count_session(session);session.check_time(now)
        with self._lock:
            pending=self._pending_session(session)
            require(pending['issued'] and not pending['acknowledged'],'replacement-not-pending')
            require(self._accounts.get(session.account_id)==pending['old'],'replacement-raced')
            require(pending['base_sequence']==self.sequence,'registry-state-changed')
            before={key:value for key,value in self._issuer.items() if key!='revocation_registry'}
            result=self.count_native.call('legacy-commit-count',issuer=self._issuer,handle=pending['handle'],
                old_handle=pending['old'],ack=ack,attributes=pending['attributes'])
            require(before=={key:value for key,value in result['issuer'].items() if key!='revocation_registry'}
                and definition_hash(result['public'])==self.definition_hash,'count-key-continuity')
            self._issuer=result['issuer'];self.public=result['public'];self.sequence+=1
            self._accounts[session.account_id]=pending['handle'];pending['acknowledged']=True
            pending.pop('response',None);self._persist()
            return {'profile':PROFILE,'laboratory':True,'verified':False,'registry_sequence':self.sequence,
                'replaced':pending['old'] is not None}

    def count_recover_delivery(self,session,now):
        self._count_session(session);return self.recover_delivery(session,now)

    def count_status(self,session,nonce,now):
        self._count_session(session);result=self.status(session,nonce,now);result['profile']=PROFILE;return result

    def count_abort(self,session,nonce,now):
        self._count_session(session);result=self.abort(session,nonce,now);result['profile']=PROFILE;return result

    def count_reserve_discovery(self,session,now):
        self._count_session(session);return self.reserve_discovery(session,now)

    def count_finish_discovery(self,session,attempts,found,now):
        self._count_session(session);return self.finish_discovery(session,attempts,found,now)

    def count_fail_discovery(self,session,attempts):
        self._count_session(session);return self.fail_discovery(session,attempts)


class CountLeasedIssuer(LeasedIssuer):
    """Recovery-only upgrade: accepts authoritative v1 state, writes v2 state."""
    def __init__(self,backend,key,namespace,native,finality,count_native):
        super().__init__(backend,key,namespace,native,finality);self.count_native=count_native

    def initialize(self,core):raise Rejected('count-state-resume-only')

    def _binding(self):
        return {'profile':PROFILE,'policy':POLICY_HASH,'native_sha256':self.count_native.sha256.hex(),
            'legacy_definition':self.namespace}

    def _count_aad(self,revision):return canonical({'profile':STATE,'namespace':self.namespace,'revision':revision})

    def _attach(self,core):
        core.__class__=CountCore;core.count_native=self.count_native;return core

    def _seal(self,core,revision):
        body=canonical({'profile':STATE,'core':snapshot(core),'lease':getattr(core,'_base_lease',None),'count':self._binding()})
        require(len(body)<=LIMIT,'registry-capacity');nonce=secrets.token_bytes(12)
        return nonce+self._cipher.encrypt(nonce,body,self._count_aad(revision))

    def _open(self,revision,envelope):
        require(type(revision) is int and type(envelope) is bytes and 28<len(envelope)<=LIMIT+28,'registry-missing')
        try:plain=self._cipher.decrypt(envelope[:12],envelope[12:],self._count_aad(revision))
        except InvalidTag:
            return self._attach(super()._open(revision,envelope))
        try:
            data=json.loads(plain)
            require(set(data)=={'profile','core','lease','count'} and data['profile']==STATE
                and data['count']==self._binding(),'count-state-profile')
            # Preserve v1's exact restore checks; rehydrate only explicitly
            # tagged v2 sessions under the authenticated v2 extension binding.
            state=copy.deepcopy(data['core']);count_pending={}
            for binding,value in list(state['pending'].items()):
                if value['session'].get('request_scheme')==SCHEME:
                    session=CountSession(**value['session'])
                    require(binding==session.binding,'count-session-binding')
                    count_pending[binding]={**value,'session':session};del state['pending'][binding]
            core=self._attach(restore(state,self.native));core._pending.update(count_pending)
            core._base_lease=data['lease']
            require(core.definition_hash==self.namespace,'issuer-definition')
            return core
        except Rejected:raise
        except Exception:raise Rejected('count-state-authentication') from None

    def operate(self,method,*args,**kwargs):
        if method not in OPERATIONS:return super().operate(method,*args,**kwargs)
        require(self.ready and self.poll_boot()['state']=='ready','issuer-not-ready')
        revision,core=self.load();cursor=[revision]
        def persist():
            envelope=self._seal(core,cursor[0]+1)
            cursor[0]=self.backend.compare_exchange(cursor[0],envelope,public_view(core))
        core._persist_callback=persist;result=getattr(core,method)(*args,**kwargs)
        if method=='count_commit':result.update(activation_pending_finality=True,verified=False)
        return result
