"""Private renewal coordinator: durable receipt and independent finalized promotion.

Installer owns remote/approval/RPC/registry/paths. The remote must provide the
fresh attested encrypted issuer channel; this class does not create a listener
or authenticate an arbitrary caller-supplied remote. Public projection has no
account ID, holder root, credential, witness or exact credential dates.
"""
import copy
import secrets
import time
from base_finality import RPCFinality
from policy import hex_string,require
from renewal_policy_v3 import RenewalSession,PROFILE,POLICY_HASH


class RenewalEnrollment:
    def __init__(self,author,desktop,remote,approved,rpc,registry,*,clock=time.time):
        require(desktop in author.legacy_sources and author.binding['issuer_definition']==desktop.authority_definition,'renewal-author-config')
        require(type(approved) is dict and set(approved)=={'profile','policy_sha256','native_sha256','authority_definition'}
            and approved=={'profile':PROFILE,'policy_sha256':POLICY_HASH,'native_sha256':desktop.native.sha256,
                'authority_definition':desktop.authority_definition},'renewal-approval')
        require(registry.definition==desktop.authority_definition,'renewal-approval')
        self.author=author;self.desktop=desktop;self.remote=remote;self.approved=copy.deepcopy(approved)
        self.rpc=rpc;self.registry=registry;self.clock=clock;self.finality=RPCFinality(rpc)

    def _pending(self):return self.desktop._check(self.desktop.wallet.load('pending'))
    def _session(self,r):require(r['session'] is not None,'registration-session-missing');return RenewalSession(**r['session'])
    def _display(self,state,r=None):
        return {'profile':'nockapp-renewal-enrollment-v3','state':state,'credential_saved':state=='credential-saved',
            'post_text':None if r is None or r['session'] is None else self._session(r).post_text}

    def _recover_begin_session(self):
        r=self._pending()
        if r['session'] is not None:return True
        reply=self.remote.call('lookup-begin',{'request':r['request'],
            'desktop_nonce':r['desktop_nonce'],'username':r['username']})
        require(type(reply) is dict and set(reply)=={'session'},'renewal-begin-lookup')
        if reply['session'] is None:return False
        # record_session independently checks nonce, exact request commitment,
        # username, issuer definition and any already selected account binding.
        session=RenewalSession(**reply['session']);self.desktop.record_session(session)
        return True

    def begin(self,username,approve_public_profile_lookup):
        require(approve_public_profile_lookup is True,'consent-required')
        with self.author.transaction():
            require(self.remote.call('parameters',{})==self.approved,'renewal-approval')
            if self.desktop.wallet.read('pending.sealed',missing=True) is None:
                original=self.remote.call('registry',{})
                self.desktop.prepare(self.author,original,None,username,True)
            r=self._pending();require(r['username']==username,'registration-recovery-required')
            reply=self.remote.call('begin',{'request':r['request'],'desktop_nonce':r['desktop_nonce'],
                'username':username,'approve_public_profile_lookup':True})
            require(type(reply) is dict and set(reply)=={'session','post_text','expires_at'},'renewal-session')
            session=RenewalSession(**reply['session'])
            require(reply['post_text']==session.post_text and reply['expires_at']==session.created_at+600,'renewal-session')
            self.desktop.record_session(session);return self._display('waiting-for-source-post',self._pending())

    def _finish(self,r,status):
        session=self._session(r)
        if status['state']=='issued':
            if r['credential'] is None:
                issued=self.remote.call('recover-delivery',{'session':session.__dict__})
                self.desktop.receive(issued,self.remote.call('registry',{}));r=self._pending()
            self.remote.call('commit',{'session':session.__dict__,'ack':self.desktop.recover_ack()})
        elif status['state']!='committed':return self._display(status['state'],r)
        require(r['credential'] is not None,'registration-recovery-required')
        activation=self.remote.call('activation-status',{'session':session.__dict__})
        if activation=={'state':'pending-or-uncommitted','active':False}:return self._display('activation-pending-finality',r)
        require(type(activation) is dict and set(activation)=={'state','active','finalized_block','issuer_definition'}
            and activation['issuer_definition']==self.desktop.authority_definition
            and type(activation['active']) is bool and activation['state']==('active' if activation['active'] else 'replaced-or-revoked'),'renewal-activation')
        anchor=activation['finalized_block'];require(type(anchor) is str and anchor.startswith('0x'),'renewal-activation');hex_string(anchor[2:],64)
        block=self.rpc.call('eth_getBlockByHash',anchor,False);final=self.finality.finalized()
        require(block is not None and block['hash']==anchor and int(block['number'],16)<=int(final['number'],16)
            and self.rpc.call('eth_getBlockByNumber',block['number'],False)['hash']==anchor,'renewal-finality')
        if not activation['active']:return self._display('activation-replaced-or-revoked',r)
        original=self.registry.public_at(final['number'])
        if self.remote.call('registry',{})!=original:return self._display('activation-pending-finality',r)
        w=self.remote.call('witness',{'handle':self.desktop.witness_handle(pending=True)})
        view=self.desktop._view(original)
        require(type(w) is dict and set(w)=={'public','definition_hash','sequence','authority_definition','witness'}
            and w['authority_definition']==self.desktop.authority_definition,'renewal-witness')
        if {k:w[k] for k in ('public','definition_hash','sequence')}!=view:return self._display('activation-pending-finality',r)
        # Check the finalized anchor again before any incumbent local record is
        # replaced. Native activation separately checks signature/membership/key.
        def fence():
            self.finality.finalized()
            require(self.rpc.call('eth_getBlockByNumber',final['number'],False)['hash']==final['hash']
                and self.registry.public_at(final['number'])==original,'renewal-finality')
        self.desktop.promote(self.author,original,w,int(self.clock()),before_save=fence)
        return self._display('credential-saved')

    def recover(self):
        with self.author.transaction():
            if self.desktop.wallet.read('pending.sealed',missing=True) is None:
                status=self.desktop.status();return self._display('credential-saved' if status['ready'] else 'empty')
            r=self._pending()
            recovered_begin=r['session'] is None
            if recovered_begin:
                if not self._recover_begin_session():return self._display('begin-recovery-required')
                r=self._pending()
            session=self._session(r);nonce=secrets.token_hex(32)
            status=self.remote.call('status',{'session':session.__dict__,'nonce':nonce})
            require(status['profile']==PROFILE and status['binding']==session.binding and status['nonce']==nonce,'renewal-status')
            if recovered_begin and status['state']=='pending':return self._display('waiting-for-source-post',r)
            return self._finish(r,status)

    def check_post(self,tweet_id,approve_source_check):
        require(approve_source_check is True,'consent-required')
        with self.author.transaction():
            r=self._pending();session=self._session(r)
            issued=self.remote.call('check-post',{'session':session.__dict__,'tweet_id':tweet_id,'approve_source_check':True})
            if r['credential'] is None:self.desktop.receive(issued,self.remote.call('registry',{}))
            return self.recover()

    def cancel(self):
        with self.author.transaction():
            if not self._recover_begin_session():return {'cancelled':False}
            r=self._pending();session=self._session(r);nonce=secrets.token_hex(32)
            status=self.remote.call('abort',{'session':session.__dict__,'nonce':nonce})
            return self.desktop.confirm_remote_abort(status,nonce,int(self.clock()))
