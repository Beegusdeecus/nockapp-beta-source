"""Versioned installed renewal binding; publication remains independently chosen.

Contains public trust/config only. No browser-provided endpoint, authority,
credential, count/date, witness or AWS identity is accepted by this adapter.
"""
import copy
from pathlib import Path
import re

from base_protocol import keccak
from fixed_issuer_code_v1 import runtime as fixed_runtime
from policy import canonical,digest,require
from public_issuer_views import PublicIssuerViews
from public_reader_v6 import HistoricalPublicReader
from public_verified_cache import LazyVerifiedResultCache
from renewal_desktop_v3 import RenewalDesktop
from renewal_enrollment_v3 import RenewalEnrollment
from renewal_native_v3 import public_view
from renewal_policy_v3 import PROFILE as CREDENTIAL,POLICY_HASH
from renewal_transport_v3 import RenewalRemote,validate_approval,check_chain

PROFILE='nockapp-installed-public-renewal-v1'
STATUS='nockapp-public-source-status-v1'
STATE='nockapp-renewal-enrollment-v3'
STATES={'empty','waiting-for-source-post','begin-recovery-required','credential-saved',
    'pending','issued','committed','aborted','expired','failed','activation-pending-finality',
    'activation-replaced-or-revoked','cancelled'}


def validate(value):
    from public_installation import validate as base_validate,PROFILE as TICKETS,PROFILE_V7,PROFILE_DIRECT
    require(type(value) is dict and set(value)=={'profile','browser','installation','renewal_approval','registry_deployment_block'}
        and value['profile']==PROFILE and type(value['installation']) is dict
        and value['installation'].get('profile') in (TICKETS,PROFILE_V7,PROFILE_DIRECT),'public-renewal-install-config')
    base=base_validate(value['installation']);approved=validate_approval(value['renewal_approval'])
    expected=approved['identity'];chain=base['chain'];pins=base['binary_sha256']
    require(value['browser']==base['browser'] and expected['chain_id']==chain['chain_id']
        and expected['application']==chain['application'] and expected['contract']==chain['contract']
        and expected['definition_hash']==base['issuer']['definition_hash']
        and expected['domain_native_sha256']==pins['domain'] and expected['count_native_sha256']==pins['count']
        and expected['renewal_native_sha256']==pins['renewal'],'public-renewal-install-binding')
    height=value['registry_deployment_block']
    require(type(height) is int and 0<=height<2**53,'public-renewal-install-height')
    if base['profile']!=PROFILE_DIRECT:
        issuer=base['issuer']
        require(issuer['contract']==expected['registry'] and issuer['updater']==expected['updater']
            and issuer['deployment_block']==height
            and issuer['runtime_keccak']==keccak(fixed_runtime(expected['updater'],expected['definition_hash'])),
            'public-renewal-install-issuer')
    return copy.deepcopy(value)


class PublicRegistry:
    """Bounded public event retrieval for the private enrollment coordinator."""
    def __init__(self,views,index):self.views=views;self.index=index;self.definition=views.definition
    def public_at(self,tag):
        require(type(tag) is str and re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]*)',tag),'public-renewal-registry-tag')
        final=self.index.anchor();require(int(tag,16)<=int(final['number'],16),'public-renewal-unfinalized')
        block=self.index.rpc.call('eth_getBlockByNumber',tag,False)
        require(type(block) is dict and block['number']==tag,'public-renewal-registry-block')
        view=self.views.current(block);self.index.finish(final);return view

    def progress(self):
        """Public global registry progress, never credential activation evidence.

        No session, account, witness, credential or credential dates are read.
        An immutable fixed-contract revision locates its latest update within
        the unfinalized range; it is not a fixed confirmation-count threshold.
        """
        rpc=self.index.rpc;final=self.index.anchor()
        latest=rpc.call('eth_getBlockByNumber','latest',False)
        require(type(latest) is dict and type(latest.get('number')) is str
            and re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]*)',latest['number']), 'public-renewal-progress-block')
        f=int(final['number'],16);h=int(latest['number'],16)
        require(0<=f<=h<2**53,'public-renewal-progress-range')
        self.views._pins(f);self.views._pins(h)
        old=self.views._head(f);new=self.views._head(h)
        require(old[0]<=new[0] and (old[0]!=new[0] or old==new),'public-renewal-progress-head')
        target=None
        if old[0]!=new[0]:
            low,high=f+1,h
            for _ in range(53):
                if low>=high:break
                middle=(low+high)//2
                if self.views._head(middle)[0]>=new[0]:high=middle
                else:low=middle+1
            require(low==high and self.views._head(low)==new,'public-renewal-progress-target')
            target=low
        require(rpc.call('eth_getBlockByNumber',latest['number'],False)==latest,
            'public-renewal-progress-changed')
        self.index.finish(final)
        return {'profile':'nockapp-public-source-finality-v1','chain_id':84532,
            'latest_block':h,'finalized_block':f,'latest_revision':new[0],
            'finalized_revision':old[0],'target_block':target,'pending':target is not None}


class PublicRenewalApplication:
    def __init__(self,base,enrollment,approved):
        require(type(enrollment) is RenewalEnrollment and enrollment.author is base.desktop.author,
            'public-renewal-components')
        self.base=base;self.desktop=base.desktop;self.enrollment=enrollment
        self.approved=validate_approval(approved)

    def _state(self,result):
        require(type(result) is dict and set(result)=={'profile','state','credential_saved','post_text'}
            and result['profile']==STATE and result['state'] in STATES
            and type(result['credential_saved']) is bool and result['credential_saved']==(result['state']=='credential-saved')
            and (result['post_text'] is None or type(result['post_text']) is str
                and re.fullmatch(r'testing:[0-9a-f]{64}',result['post_text'])),'public-renewal-projection')
        return copy.deepcopy(result)

    def _ready(self):
        require(self.enrollment.remote.call('parameters',{})==self.enrollment.approved,'renewal-approval')
        check_chain(self.approved['identity'],self.desktop.index.rpc)

    def _attach(self,post_id):
        self._ready();d=self.desktop;source=self.enrollment.desktop
        final=d.index.anchor();original=d.reader.issuer_views.current(final)
        require(self.enrollment.remote.call('registry',{})==original,'renewal-registry-await-finality')
        handle=source.witness_handle()
        witness=self.enrollment.remote.call('witness',{'handle':handle})
        projected=public_view(source.native,original)
        require(type(witness) is dict and set(witness)=={'public','definition_hash','sequence','authority_definition','witness'}
            and witness['authority_definition']==source.authority_definition
            and {k:witness[k] for k in ('public','definition_hash','sequence')}==projected,'renewal-witness')
        def fence():
            d.index.finish(final)
            require(d.reader.issuer_views.current(final)==original,'renewal-registry-changed')
        return d.attach_renewal(post_id,source,original,witness,before_save=fence)

    def dispatch(self,operation,body):
        require(type(operation) is str and type(body) is dict,'public-renewal-schema')
        if operation=='public-source-finality':
            require(not body,'public-renewal-schema')
            return self.enrollment.registry.progress()
        if operation=='public-capabilities':
            result=self.base.dispatch(operation,body)
            return {**result,'verifier_release':9,'publication_mode':'direct' if self.desktop.relay is None else 'tickets',
                'anonymous_ticket_packs':self.desktop.relay is not None,'follower_proof_configured':True,
                'source_enrollment_configured':True,'historical_issuer_views':True,
                'refund_payout_configured':result.get('refund_payout_configured',False)}
        if operation=='public-source-status':
            require(not body,'public-renewal-schema');w=self.enrollment.desktop.wallet
            # Record presence only; do not unlock a keyring or imply eligibility.
            return {'profile':STATUS,'credential_record_present':w.read('credential.sealed',missing=True) is not None,
                'renewal_pending':w.read('pending.sealed',missing=True) is not None}
        if operation=='public-source-begin':
            require(set(body)=={'username','approve_source_check'} and body['approve_source_check'] is True,'consent-required')
            self._ready();return self._state(self.enrollment.begin(body['username'],True))
        if operation=='public-source-check-post':
            require(set(body)=={'tweet_id','approve_source_check'} and body['approve_source_check'] is True,'consent-required')
            self._ready();return self._state(self.enrollment.check_post(body['tweet_id'],True))
        if operation=='public-source-recover':
            require(set(body)=={'approve_source_check'} and body['approve_source_check'] is True,'consent-required')
            self._ready();return self._state(self.enrollment.recover())
        if operation=='public-source-cancel':
            require(set(body)=={'approve_cancel'} and body['approve_cancel'] is True,'consent-required')
            self._ready()
            if self.enrollment.cancel()['cancelled'] is not True:
                return self._state(self.enrollment._display('begin-recovery-required'))
            return self._state(self.enrollment._display('cancelled'))
        if operation=='public-attach-followers':
            require(set(body)=={'post_id','approve_follower_disclosure'} and body['approve_follower_disclosure'] is True,
                'consent-required')
            return self._attach(body['post_id'])
        require(not operation.startswith('public-source-'),'public-renewal-operation')
        return self.base.dispatch(operation,body)


def factory(value,root):
    from public_installation import factory as base_factory
    from public_installation import BINARIES
    from renewal_native_v3 import RenewalNative
    v=validate(value);base=base_factory(v['installation'],root);d=base.desktop
    approved=v['renewal_approval'];s=approved['identity'];data=Path(v['installation']['data_directory'])
    native=RenewalNative(Path(root)/BINARIES['renewal']);source=RenewalDesktop(data/'renewal-v3',s['definition_hash'],native)
    require(all(old.wallet.directory!=source.wallet.directory for old in d.author.legacy_sources),'public-renewal-wallet-overlap')
    d.author.legacy_sources=(*d.author.legacy_sources,source)
    views=PublicIssuerViews(d.index.rpc,s['registry'],keccak(fixed_runtime(s['updater'],s['definition_hash'])),
        s['updater'],s['definition_hash'],v['registry_deployment_block'],index_contract=s['contract'])
    d.reader=HistoricalPublicReader(d.index,d.content,d.author.native,renewal_native=native,issuer_views=views,
        issuer_authority=digest({'profile':PROFILE,'approval':approved,'deployment_block':v['registry_deployment_block']}),
        result_disk_cache=LazyVerifiedResultCache(data/'verified-renewal-results-v1'))
    enrollment=RenewalEnrollment(d.author,source,RenewalRemote(approved),{'profile':CREDENTIAL,'policy_sha256':POLICY_HASH,
        'native_sha256':native.sha256,'authority_definition':s['definition_hash']},d.index.rpc,PublicRegistry(views,d.index),clock=lambda:d.clock())
    return PublicRenewalApplication(base,enrollment,approved)
