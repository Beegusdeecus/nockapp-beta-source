"""Encrypted local protocol4 identity and exact-post authorization lifecycle.

No provider, source, Base, wallet RPC or publication calls. MetaMask receives
only purpose-bound typed data. Key/credential material stays in private pipes
and encrypted Wallet records; caller config/chain views are installer-owned.
"""
import copy
import secrets
import threading
import contextlib

from authorship import (AuthorshipNative,ownership_challenge,validate_intent,context as validate_context,
    selected_challenge,nonzero_hex)
from authored_count import present as present_count,verify as verify_count,trust as count_trust
from count_pipeline import definition_hash
from domain_desktop import exclusive
from policy import digest,require,timestamp
from wallet import Wallet
from wallet_authorship import (address,ownership_data,post_data,verify_ownership,verify_post_address)

PROFILE='nockapp-protected-authorship-desktop-v4'
KEY_CHALLENGE='nockapp-local-signing-key-possession-v4'


def binding(value):
    require(type(value) is dict and set(value)=={'protocol','chain_id','application','contract','issuer_definition'},'author-desktop-binding')
    validate_context({k:v for k,v in value.items() if k!='issuer_definition'}|{'submission_id':'01'*32})
    nonzero_hex(value['issuer_definition'],64)
    return copy.deepcopy(value)


def held_scalar(credential):
    claim=credential['credential']['claims'][1]
    require(type(claim) is dict and set(claim)=={'Scalar'} and type(claim['Scalar']) is dict
        and set(claim['Scalar'])=={'value'},'author-holder-claim')
    return claim['Scalar']['value']


class AuthorshipDesktop:
    identity_profile=PROFILE
    key_challenge_profile=KEY_CHALLENGE
    validate_binding=staticmethod(binding)
    def __init__(self,directory,configuration,native=None,*,legacy_sources=()):
        self.binding=self.validate_binding(configuration);self.native=native or AuthorshipNative();self.wallet=Wallet(directory)
        self.legacy_sources=tuple(legacy_sources)
        for source in self.legacy_sources:
            p=source.wallet.directory;own=self.wallet.directory
            require(not p.is_relative_to(own) and not own.is_relative_to(p),'author-wallet-overlap')
        self._lock=threading.RLock();self._depth=0

    @contextlib.contextmanager
    def transaction(self):
        with self._lock:
            with (self.wallet.controller_lock() if not self._depth else contextlib.nullcontext()):
                self._depth+=1
                try:yield
                finally:self._depth-=1

    def _load(self,*,missing=False):
        if self.wallet.read('credential.sealed',missing=True) is None:
            require(missing,'author-identity-missing');return None
        r=self.wallet.load('credential')
        require(type(r) is dict and set(r)=={'profile','binding','creation_native_sha256','identity','root','possession',
            'origin','wallet_binding'} and r['profile']==self.identity_profile and r['binding']==self.binding
            and type(r['identity']) is dict and set(r['identity'])=={'scalar'},'author-identity-record')
        nonzero_hex(r['creation_native_sha256'],64);nonzero_hex(r['root'],96)
        require(self.native.call('pseudonym',secret=r['identity']['scalar'],scope={'kind':'signing-identity'})['pseudonym']==r['root'],
            'author-identity-mismatch')
        p=r['possession']
        require(type(p) is dict and set(p)=={'challenge','proof'} and type(p['challenge']) is dict,'author-possession')
        c=p['challenge'];require(set(c)=={'profile','purpose','binding','nonce','created_at','expires_at'}
            and c['profile']==self.key_challenge_profile and c['purpose']=='establish-private-signing-key-control'
            and c['binding']==digest(self.binding) and c['expires_at']-c['created_at']==60,'author-possession')
        nonzero_hex(c['nonce'],64);timestamp(c['created_at']);timestamp(c['expires_at'])
        require(self.native.call('verify',proof=p['proof'],scopes=[{'kind':'signing-identity'}],context=digest(c))=={'accepted':True}
            and p['proof']['statements'][0]['pseudonym']==r['root'],'author-possession')
        certificate=r['wallet_binding']
        if certificate is not None:
            require(type(certificate) is dict and set(certificate)=={'profile','binding','challenge','where','root','proof','address','signature','accepted_at'}
                and certificate['profile']==PROFILE and certificate['binding']==self.binding and certificate['root']==r['root'],
                'author-wallet-certificate')
            self._ownership_context(certificate)
            require(verify_ownership(self.native,certificate['challenge'],certificate['where'],certificate['root'],certificate['proof'],
                certificate['address'],certificate['signature'],certificate['accepted_at']),'author-wallet-certificate')
        return r

    def _create(self,identity,root,origin,now):
        timestamp(now);self.wallet.initialize()
        challenge={'profile':self.key_challenge_profile,'purpose':'establish-private-signing-key-control','binding':digest(self.binding),
            'nonce':secrets.token_hex(32),'created_at':now,'expires_at':now+60}
        proof=self.native.call('prove',secret=identity['scalar'],scopes=[{'kind':'signing-identity'}],context=digest(challenge))['proof']
        require(proof['statements'][0]['pseudonym']==root and self.native.call('verify',proof=proof,
            scopes=[{'kind':'signing-identity'}],context=digest(challenge))=={'accepted':True},'author-possession')
        record={'profile':self.identity_profile,'binding':copy.deepcopy(self.binding),'creation_native_sha256':self.native.sha256,
            'identity':identity,'root':root,'possession':{'challenge':challenge,'proof':proof},'origin':origin,'wallet_binding':None}
        self.wallet.save('credential',record)
        require(self._load()['root']==root,'author-identity-mismatch')
        return self.status()

    @exclusive
    def initialize(self,now,approve_create):
        require(approve_create is True,'consent-required')
        if self._load(missing=True) is not None:return self.status()
        # A damaged, locked or existing legacy wallet must not cause a new key.
        for source in self.legacy_sources:
            require(source.wallet.read('pending.sealed',missing=True) is None,'author-legacy-recovery-required')
            require(source.wallet.read('credential.sealed',missing=True) is None,'author-key-adoption-required')
        require(self.wallet.metadata() is None,'author-identity-recovery-required')
        require(self.wallet.read('pending.sealed',missing=True) is None and self.wallet.read('post.sealed',missing=True) is None,
            'author-recovery-required')
        secret=self.native.call('generate')['secret']
        root=self.native.call('pseudonym',secret=secret,scope={'kind':'signing-identity'})['pseudonym']
        return self._create({'scalar':secret},root,{'kind':'created-locally'},now)

    @exclusive
    def adopt(self,source,now,approve_adoption):
        require(approve_adoption is True and source in self.legacy_sources,'author-adoption-consent')
        require(self._load(missing=True) is None and self.wallet.read('post.sealed',missing=True) is None
            and self.wallet.read('pending.sealed',missing=True) is None,'author-identity-exists')
        with source.transaction():
            require(source.wallet.read('pending.sealed',missing=True) is None,'author-legacy-recovery-required')
            record=source._check(source.wallet.load('credential'))
            # Adoption claims current key possession, not current eligibility.
            # Expiry/revocation must not silently replace an existing holder key.
            converted=self.native.call('normalize-held-scalar',scalar=held_scalar(record['credential']))
            require(converted['legacy_root']==record['local_zkid'],'author-adoption-mismatch')
            require(getattr(source,'authority_definition',record['definition_hash'])==self.binding['issuer_definition'],'author-issuer-mismatch')
            return self._create(converted['material'],converted['root'],
                {'kind':'adopted-holder','credential_profile':source.credential_profile,'definition_hash':record['definition_hash']},now)

    @exclusive
    def status(self):
        r=self._load(missing=True)
        return {'profile':self.identity_profile,'state':'empty' if r is None else 'ready','wallet_bound':r is not None and r['wallet_binding'] is not None,
            'pending_post':self.wallet.read('post.sealed',missing=True) is not None,'protocol':self.binding['protocol']}

    def _ownership_context(self,value):
        where=value['where'];challenge=value['challenge']
        validate_context(where)
        require(all(where[k]==self.binding[k] for k in ('protocol','chain_id','application','contract'))
            and where['submission_id']==challenge['nonce'] and challenge['audience']==self.binding['issuer_definition'],
            'author-ownership-context')

    def _ownership_pending(self,desktop):
        require(desktop in self.legacy_sources and getattr(desktop,'authority_definition',None)==self.binding['issuer_definition'],'author-count-wallet')
        record=desktop._check(desktop.wallet.load('pending'))
        require(record['session'] is None,'author-source-already-started')
        return record

    @exclusive
    def request_ownership(self,desktop,account,now,approve_wallet_binding):
        require(approve_wallet_binding is True,'consent-required');timestamp(now);identity=self._load();account=address(account)
        require(self.wallet.read('post.sealed',missing=True) is None,'author-post-recovery-required')
        require(identity['wallet_binding'] is None or self.wallet.read('pending.sealed',missing=True) is not None,
            'author-wallet-already-bound')
        with desktop.transaction():
            record=self._ownership_pending(desktop)
            converted=self.native.call('normalize-held-scalar',scalar=record['holder']['secret'])
            require(converted['root']==identity['root'] and record['request']==record['holder']['request'],'author-ownership-request-mismatch')
            request_hash=digest(record['request'])
        if self.wallet.read('pending.sealed',missing=True) is None:
            challenge=ownership_challenge(secrets.token_hex(32),request_hash,self.binding['issuer_definition'],now,now+60)
            where={k:v for k,v in self.binding.items() if k!='issuer_definition'}|{'submission_id':challenge['nonce']}
            proof=self.native.call('prove',secret=identity['identity']['scalar'],scopes=[{'kind':'signing-identity'}],context=digest(challenge))['proof']
            pending={'profile':PROFILE,'binding':copy.deepcopy(self.binding),'challenge':challenge,'where':where,
                'root':identity['root'],'proof':proof,'address':account}
            self.wallet.save('pending',pending)
        pending=self.wallet.load('pending')
        require(set(pending)=={'profile','binding','challenge','where','root','proof','address'} and pending['profile']==PROFILE
            and pending['binding']==self.binding and pending['root']==identity['root'] and pending['address']==account
            and pending['challenge']['request_sha256']==request_hash,'author-ownership-recovery-required')
        self._ownership_context(pending)
        data=ownership_data(pending['challenge'],pending['where'],pending['root'])
        return {'profile':PROFILE,'state':'awaiting-wallet-signature','address':account,'typed_data':data,
            'request_sha256':digest(data),'expired':not pending['challenge']['created_at']<=now<pending['challenge']['expires_at']}

    @exclusive
    def accept_ownership(self,desktop,signature,now):
        identity=self._load();pending=self.wallet.load('pending')
        old=identity['wallet_binding']
        if old is not None:
            require({k:old[k] for k in pending}==pending and old['signature']==signature,'author-ownership-certificate-conflict')
            self.wallet.delete('pending')
            return self.status()
        # Reconstruct and validate the entire saved request before accepting a reply.
        self.request_ownership(desktop,pending['address'],now,True)
        require(verify_ownership(self.native,pending['challenge'],pending['where'],pending['root'],pending['proof'],
            pending['address'],signature,now),'author-ownership-signature-invalid')
        certificate={**pending,'signature':signature,'accepted_at':now}
        if identity['wallet_binding'] is not None:
            old=identity['wallet_binding']
            require(old['challenge']==pending['challenge'] and old['signature']==signature,'author-ownership-certificate-conflict')
            certificate=old
        identity['wallet_binding']=certificate
        self.wallet.save('credential',identity)  # Save verified certificate BEFORE clearing pending.
        self.wallet.delete('pending')
        return self.status()

    def _matches(self,value):
        validate_intent(value)
        require(all(value['context'][k]==self.binding[k] for k in ('protocol','chain_id','application','contract')),'author-post-context')

    def _post(self):
        identity=self._load();r=self.wallet.load('post')
        require(type(r) is dict and set(r)=={'profile','binding','intent','author_proof','credential_evidence','address_request','address_signature'}
            and r['profile']==PROFILE and r['binding']==self.binding,'author-post-record')
        self._matches(r['intent']);require(self.native.verify_post(r['intent'],r['author_proof']),'author-post-record')
        from authorship import post_scope
        expected=self.native.call('pseudonym',secret=identity['identity']['scalar'],scope=post_scope(r['intent']))['pseudonym']
        require(r['author_proof']['statements'][0]['pseudonym']==expected,'author-post-key-mismatch')
        return r

    @exclusive
    def prepare_post(self,value,now,approve_publication):
        require(approve_publication is True,'consent-required');timestamp(now);self._matches(value)
        identity=self._load()
        if self.wallet.read('post.sealed',missing=True) is not None:
            r=self._post();require(r['intent']==value,'author-post-recovery-required')
        else:
            require(self.wallet.read('pending.sealed',missing=True) is None,'author-ownership-recovery-required')
            r={'profile':PROFILE,'binding':copy.deepcopy(self.binding),'intent':copy.deepcopy(value),
                'author_proof':self.native.authorize(identity['identity']['scalar'],value),'credential_evidence':None,
                'address_request':None,'address_signature':None}
            self.wallet.save('post',r)  # Persist exact proof BEFORE any external prompt or publication.
        return {'profile':PROFILE,'state':'authored','intent_sha256':digest(value)}

    @exclusive
    def prepare_count(self,desktop,public,account_id,username):
        identity=self._load()
        require(desktop in self.legacy_sources and getattr(desktop,'authority_definition',None)==self.binding['issuer_definition'],'author-count-wallet')
        from count_pipeline import CountPending
        from policy import identifier
        import re
        require(type(username) is str and re.fullmatch(r'[A-Za-z0-9_]{1,15}',username),'account-handle')
        if account_id is not None:identifier(account_id)
        with desktop.transaction():
            desktop.wallet.initialize()
            require(desktop.wallet.read('pending.sealed',missing=True) is None,'registration-already-pending')
            if desktop.wallet.read('credential.sealed',missing=True) is not None:
                old=desktop._check(desktop.wallet.load('credential'))
                held=self.native.call('normalize-held-scalar',scalar=held_scalar(old['credential']))
                require(held['root']==identity['root'],'author-key-adoption-required')
            prepared=self.native.call('prepare-count',public=public,secret=identity['identity']['scalar'])
            holder=CountPending(desktop.native,prepared['pending'],prepared['request'],secrets.token_hex(32),prepared['local_zkid'])
            record={'profile':desktop.desktop_profile,'binary_sha256':desktop.native.sha256.hex(),'definition_hash':definition_hash(public),
                'holder':holder.private,'request':holder.request,'desktop_nonce':holder.desktop_nonce,'local_zkid':holder.local_zkid,
                'account_id':account_id,'username':username,'public_definition':copy.deepcopy(public),'session':None,'credential':None,
                'ack':None,'attributes':None,**desktop._binding()}
            desktop.wallet.save('pending',record)
            return {'request':copy.deepcopy(holder.request),'desktop_nonce':holder.desktop_nonce}

    @exclusive
    def attach_count(self,desktop,view,witness,now,*,canonical_view=None,challenge=None):
        require(desktop in self.legacy_sources and getattr(desktop,'authority_definition',None)==self.binding['issuer_definition'],'author-count-wallet');r=self._post()
        require(r['intent']['disclosures']['followers_threshold'] is not None,'authored-count-not-selected')
        require(r['address_request'] is None,'author-wallet-proof-frozen')
        with desktop.transaction():
            record=desktop._check(desktop.wallet.load('credential'))
            require(view['definition_hash']==record['definition_hash']==definition_hash(view['public'])
                and witness['public']==view['public'],'registration-current-registry')
            refreshed=desktop.native.call('refresh',credential=record['credential'],public=view['public'],witness=witness['witness'])['credential']
            created=now if challenge is None else challenge['created_at']
            t=count_trust(r['intent'],view,created)
            if challenge is not None:require(challenge==t['legacy']['challenge'],'author-count-challenge')
            t['legacy']['now']=now
            p=present_count(self.native,refreshed,r['intent'],r['author_proof'],t)
            require(verify_count(self.native,p,r['intent'],r['author_proof'],t),'authored-count-invalid')
            committed_view=view
            if canonical_view is not None:
                from count_state import count_view
                require(canonical_view['definition_hash']==self.binding['issuer_definition']
                    and count_view(desktop.native,canonical_view)==view,'author-canonical-issuer-mismatch')
                committed_view=canonical_view
            r['credential_evidence']={'issuer_view':copy.deepcopy(committed_view),'challenge':copy.deepcopy(t['legacy']['challenge']),'presentation':p}
            self.wallet.save('post',r)
        return {'profile':PROFILE,'state':'credential-proof-ready','intent_sha256':digest(r['intent'])}

    @staticmethod
    def _evidence_ready(r):
        require((r['credential_evidence'] is None)==(r['intent']['disclosures']['followers_threshold'] is None),'author-credential-proof-required')

    @exclusive
    def request_address(self,account,now,approve_address_disclosure):
        require(approve_address_disclosure is True,'consent-required');timestamp(now);r=self._post();self._evidence_ready(r)
        require(r['intent']['disclosures']['address'] is True,'author-address-not-selected');account=address(account)
        if r['address_request'] is None:
            request={'address':account,'nonce':secrets.token_hex(32),'created_at':now,'expires_at':now+60}
            r['address_request']=request;self.wallet.save('post',r)
        else:
            request=r['address_request'];require(request['address']==account,'author-wallet-recovery-required')
        data=post_data(r['intent'],r['author_proof'],r['credential_evidence'],request['nonce'],request['created_at'],request['expires_at'])
        return {'profile':PROFILE,'state':'awaiting-wallet-signature','address':account,'typed_data':data,
            'request_sha256':digest(data),'expired':not request['created_at']<=now<request['expires_at']}

    @exclusive
    def accept_address(self,signature,now):
        r=self._post();self._evidence_ready(r);require(r['address_request'] is not None,'author-wallet-request-missing')
        require(r['address_signature'] is None or r['address_signature']==signature,'author-wallet-signature-conflict')
        if r['address_signature']==signature:
            return {'profile':PROFILE,'state':'wallet-signature-saved','intent_sha256':digest(r['intent'])}
        disclosure={**r['address_request'],'signature':signature}
        require(verify_post_address(self.native,r['intent'],r['author_proof'],r['credential_evidence'],disclosure,now),'author-wallet-signature-invalid')
        r['address_signature']=signature;self.wallet.save('post',r)
        return {'profile':PROFILE,'state':'wallet-signature-saved','intent_sha256':digest(r['intent'])}

    @exclusive
    def material(self):
        r=self._post();self._evidence_ready(r)
        disclosure=None
        if r['intent']['disclosures']['address']:
            require(r['address_request'] is not None and r['address_signature'] is not None,'author-wallet-signature-required')
            disclosure={**r['address_request'],'signature':r['address_signature']}
        else:require(r['address_request'] is None and r['address_signature'] is None,'author-address-not-selected')
        return copy.deepcopy({'intent':r['intent'],'authorship':r['author_proof'],'credential_evidence':r['credential_evidence'],
            'address_disclosure':disclosure})

    @exclusive
    def release_saved_post(self,coordinator,post_id,bundle_hash):
        """Clear only transient public signing material after the exact complete
        bundle has a durable owner-only outbox copy. This claims NO acceptance.
        The private identity/credential/keyring entries are never cleared."""
        from authored_bundle_desktop import AuthoredBundleDesktop
        from public_bundle_v4 import build,encode
        from base_protocol import sha
        require(isinstance(coordinator,AuthoredBundleDesktop) and coordinator.author is self,'author-outbox-owner')
        if self.wallet.read('post.sealed',missing=True) is None:return False
        saved=self._post()
        if saved['intent']['post']['id']!=post_id:return False
        value=build(self.material());require(sha(encode(value))==bundle_hash,'author-outbox-copy-mismatch')
        box=coordinator._read('outbox.json')
        require(box['profile']=='nockapp-authored-bundle-desktop-v4' and box['scope']==coordinator.scope,'author-outbox-copy-mismatch')
        candidates=[r for row in box['entries'] for r in [row,*row['previous_attempts']]]
        rows=[r for r in candidates if r['post']['id']==post_id and r['submission_id']==value['context']['submission_id']]
        require(len(rows)==1 and rows[0]['bundle'] is not None and encode(rows[0]['bundle'])==encode(value),
            'author-outbox-copy-mismatch')
        self.wallet.delete('post')
        return True

    @exclusive
    def retire_expired_post(self,reader,submission_id,*,coordinator=None):
        """Only a finalized negative canonical fence retires an incomplete
        old signing attempt. No identity/credential/key rotation is performed."""
        from authored_bundle_reader import AuthoredBundleReader
        from base_protocol import sha
        require(isinstance(reader,AuthoredBundleReader),'author-canonical-reader')
        if self.wallet.read('post.sealed',missing=True) is None:return False
        r=self._post();i=r['intent'];require(i['context']['submission_id']==submission_id,'author-renewal-conflict')
        require(reader.contract==self.binding['contract'] and reader.app==self.binding['application']
            and reader.chain_id==self.binding['chain_id'] and reader.registry.definition==self.binding['issuer_definition'],
            'author-canonical-reader')
        deadlines=[]
        if r['credential_evidence'] is not None:deadlines.append(r['credential_evidence']['challenge']['expires_at'])
        if r['address_request'] is not None:deadlines.append(r['address_request']['expires_at'])
        if coordinator is not None:
            from authored_bundle_desktop import AuthoredBundleDesktop
            require(isinstance(coordinator,AuthoredBundleDesktop) and coordinator.author is self,'author-outbox-owner')
            box=coordinator._outbox();candidates=[v for row in box['entries'] for v in [row,*row['previous_attempts']]]
            old=next((v for v in candidates if v['submission_id']==submission_id),None)
            require(old is not None and coordinator._intent(old)==i,'author-renewal-conflict')
            if old['challenge_response'] is not None:
                coordinator._expected_challenge(old,old['challenge_response'],fresh=False)
                deadlines.append(old['challenge_response']['challenge']['expires_at'])
        require(deadlines,'author-renewal-unavailable');final=reader._finalized()
        require(int(final['timestamp'],16)>=min(deadlines),'bundle-renewal-wait-finality')
        require(int(reader._call(reader.contract,'postNumbers(bytes32)','0x'+submission_id,tag=final['number']),16)==0
            and reader._call(reader.contract,'submissionsByPost(bytes32)',sha(i['post']['id'].encode()),tag=final['number'])=='0x'+'00'*32,
            'bundle-renewal-already-accepted')
        reader._finish(final);self.wallet.delete('post');return True

    @exclusive
    def prove_selected(self,intents,post_proofs,challenge,now,approve_linking,*,approve_address_disclosure=False):
        require(approve_linking is True and type(approve_address_disclosure) is bool
            and approve_address_disclosure==challenge.get('disclose_address'),'consent-required');timestamp(now)
        r=self._load();proof=self.native.claim(r['identity']['scalar'],intents,challenge)
        require(self.native.verify_claim(intents,post_proofs,challenge,proof,now),'author-history-mismatch')
        return {'profile':PROFILE,'proof':proof}
