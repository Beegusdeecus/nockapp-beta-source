"""Consented holder -> INDEPENDENT post verifier; issuer sees witness RPC only.

One encrypted pending post. Lost/uncertain acceptance is inspected, never silently
resubmitted or replaced. No proof/private identity reaches browser projections.
"""
import copy
import time

from domain_authority import _challenge
from domain_pipeline import PROFILE as CREDENTIAL
from policy import POLICY_HASH,Rejected,canonical,digest,hex_string,require,timestamp
from post_scope import PROFILE as REFERENCE,facts,payload,scope
from post_transport import PostClient,validate_approval

PROFILE='nockapp-zkid-protected-post-flow-v1'
PHASES={'prepared','challenge-saved','proof-saved','accepted'}


def validate_pair(issuer,verifier,native_sha):
    validate_approval(verifier);binding=verifier['binding']
    require(binding['definition_hash']==issuer['definition_hash']
            and binding['state_authority_sha256']==issuer['state_authority_sha256']
            and binding['native_sha256']==native_sha,'post-approval-mismatch')


class PostHolder:
    def __init__(self,bridge,verifier_approval):
        validate_pair(bridge._approved,verifier_approval,bridge.desktop.native.sha256.hex())
        self.bridge=bridge;self.desktop=bridge.desktop;self.client=PostClient(verifier_approval)
        self.binding=copy.deepcopy(verifier_approval['binding'])

    def _credential(self):
        value=self.desktop._check(self.desktop.wallet.load('credential'))
        require(value['definition_hash']==self.binding['definition_hash'],'issuer-not-approved')
        return value

    def _load(self,*,missing=False):
        if self.desktop.wallet.read('post.sealed',missing=True) is None:
            require(missing,'post-recovery-missing');return None
        record=self.desktop.wallet.load('post')
        require(type(record) is dict and set(record)=={'profile','binding_sha256','post','facts','holder_sha256','phase','challenge','proof'}
                and record['profile']==PROFILE and record['binding_sha256']==digest(self.binding)
                and record['phase'] in PHASES,'post-recovery')
        payload(record['post']);require(facts(record['facts'])==record['facts'],'post-recovery');hex_string(record['holder_sha256'],64)
        require((record['challenge'] is None)==(record['phase']=='prepared')
                and (record['proof'] is None)==(record['phase'] in ('prepared','challenge-saved')),'post-recovery')
        if record['challenge'] is not None:self._challenge(record,record['challenge'],fresh=False)
        if record['proof'] is not None:
            require(type(record['proof']) is dict and record['proof'].get('claimed_id') is None,'post-recovery')
        return record

    def _save(self,record):self.desktop.wallet.save('post',record)

    @staticmethod
    def _same(record,post,selected):
        require(record['post']==post and record['facts']==selected,'post-recovery-required')

    @staticmethod
    def _consent(post,selected,approved,identity):
        payload(post);chosen=facts(selected)
        require(type(approved) is list and approved==selected and type(identity) is bool and identity is False,'consent-required')
        return chosen

    def _challenge(self,record,value,*,fresh):
        _challenge(value)
        require(value['profile']==CREDENTIAL and value['identity'] is False and value['facts']==record['facts']
                and value['scope']==scope(record['post'],self.binding['audience'])
                and value['expires_at']-value['created_at']==60,'post-challenge')
        if fresh:
            now=int(time.time());require(now-5<=value['created_at']<=now+5 and now<value['expires_at'],'post-challenge')

    def _response(self,operation,body):
        response=self.client.request(operation,body)
        require(response['status']=='ok',response.get('code','post-operation-unavailable'))
        return response['result']

    def _inspect(self,post,selected,nonce):
        now=int(time.time());value=self._response('inspect',{'post':post,'facts':selected,'nonce':nonce})
        require(type(value) is dict and set(value)=={'profile','nonce','facts','observed_at','expires_at','checked_at',
                'laboratory','verified','fresh','archival_only'} and value['profile']==REFERENCE
                and value['nonce']==nonce and value['facts']==selected and value['laboratory'] is True
                and value['verified'] is False and value['fresh'] is False and value['archival_only'] is True,'post-result')
        for name in ('observed_at','expires_at','checked_at'):timestamp(value[name])
        require(value['observed_at']%3600==0 and value['expires_at']-value['observed_at']==86400
                and value['observed_at']<=value['checked_at']<value['expires_at']
                and now-65<=value['checked_at']<=int(time.time())+5 and int(time.time())<value['expires_at'],'post-result')
        return {'state':'accepted','reference':{'profile':REFERENCE,'nonce':nonce,'facts':selected},
                **{k:value[k] for k in ('observed_at','expires_at','checked_at')},
                'archival_only':True,'laboratory':True,'verified':False}

    def _accept(self,record):
        value=self._response('accept',{'post':record['post'],'facts':record['facts'],
            'nonce':record['challenge']['nonce'],'proof':record['proof']})
        require(type(value) is dict and set(value)=={'profile','nonce','facts','laboratory','verified','fresh','archival_only'}
                and value['profile']==REFERENCE and value['nonce']==record['challenge']['nonce'] and value['facts']==record['facts']
                and value['laboratory'] is True and value['verified'] is False and value['fresh'] is True
                and value['archival_only'] is False,'post-result')
        record['phase']='accepted';self._save(record)
        return self._inspect(record['post'],record['facts'],record['challenge']['nonce'])

    def use(self,post,selected,approve_facts,approve_identity_disclosure):
        chosen=self._consent(post,selected,approve_facts,approve_identity_disclosure)
        with self.desktop.transaction():
            require(self.desktop.wallet.read('pending.sealed',missing=True) is None,'registration-recovery-required')
            record=self._load(missing=True)
            if record is None:
                credential=self._credential()
                record={'profile':PROFILE,'binding_sha256':digest(self.binding),'post':copy.deepcopy(post),'facts':chosen,
                    'holder_sha256':digest(credential['local_zkid']),'phase':'prepared','challenge':None,'proof':None}
                self._save(record)  # Exact intent is encrypted BEFORE any verifier operation.
            self._same(record,post,chosen)
            if record['proof'] is not None:
                # Existing saved proof may already have been consumed. NEVER
                # silently resubmit it or sign under a different nonce/identity.
                return self.recover()
            require(digest(self._credential()['local_zkid'])==record['holder_sha256'],'post-holder-changed')
            if record['challenge'] is None:
                challenge=self._response('challenge',{'post':record['post'],'facts':chosen})
                self._challenge(record,challenge,fresh=True)
                record['challenge']=challenge;record['phase']='challenge-saved';self._save(record)
            require(int(time.time())<record['challenge']['expires_at'],'action-expired')
            proof=self.bridge.present(record['challenge'])
            require(type(proof) is dict and set(proof)=={'proof','claimed_id'} and proof['claimed_id'] is None,'post-identity-disclosure')
            record['proof']=proof;record['phase']='proof-saved';self._save(record)  # BEFORE acceptance.
            return self._accept(record)

    def recover(self):
        with self.desktop.transaction():
            record=self._load();require(record['proof'] is not None,'post-proof-not-saved')
            result=self._inspect(record['post'],record['facts'],record['challenge']['nonce'])
            record['phase']='accepted';self._save(record);return result

    def retry(self,post,selected,approve_facts,approve_identity_disclosure):
        chosen=self._consent(post,selected,approve_facts,approve_identity_disclosure)
        with self.desktop.transaction():
            record=self._load();self._same(record,post,chosen);require(record['proof'] is not None,'post-proof-not-saved')
            try:return self.recover()
            except Rejected as error:
                # Only an authenticated matching verifier response of NOT
                # accepted permits this EXPLICIT same-proof retry. Other network,
                # root/expiry/key failures retain recovery without an effect.
                require(error.args==('post-not-accepted',),'post-recovery-required')
                require(record['phase']=='proof-saved','post-authority-inconsistent')
            require(int(time.time())<record['challenge']['expires_at'],'action-expired')
            return self._accept(record)

    def inspect(self,post,selected,nonce):
        payload(post);chosen=facts(selected);hex_string(nonce,64)
        return self._inspect(post,chosen,nonce)  # No holder secret/keyring access.

    def status(self):
        with self.desktop.transaction():
            record=self._load(missing=True)
            if record is None:return {'state':'empty','laboratory':True,'verified':False}
            return {'state':record['phase'],'post':record['post'],'facts':record['facts'],
                    'laboratory':True,'verified':False}

    def complete(self,post,selected,nonce,confirm_published):
        require(confirm_published is True,'consent-required');payload(post);chosen=facts(selected);hex_string(nonce,64)
        with self.desktop.transaction():
            record=self._load();self._same(record,post,chosen)
            require(record['phase']=='accepted' and record['challenge']['nonce']==nonce,'post-recovery-required')
            self.desktop.wallet.delete('post')
            return {'state':'completed','laboratory':True,'verified':False}

    def discard(self,confirm_local_discard):
        require(confirm_local_discard is True,'consent-required')
        with self.desktop.transaction():
            if self._load(missing=True) is not None:self.desktop.wallet.delete('post')
            return {'state':'discarded','remote_revocation':False,'laboratory':True,'verified':False}

    def available(self):
        with self.desktop.transaction():
            record=self._credential();value=record['issuance_context']['attributes'];now=int(time.time())
            require(value['policy']==POLICY_HASH and value['source']=='twitterapi.io'
                    and value['start']<=now<value['expiry'] and value['controlled']==1,'post-credential-unavailable')
            selected=['account-controlled']+(['followers-at-least-10000'] if value['followers']==1 else [])
            return {'facts':selected,'observed_at':value['start'],'expires_at':value['expiry'],
                    'availability_only':True,'laboratory':True,'verified':False}
