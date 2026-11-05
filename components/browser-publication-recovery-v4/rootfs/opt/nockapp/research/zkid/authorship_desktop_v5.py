"""Protected v5 signing lifecycle; no network, plaintext key export or rotation.

Reuses the tested encrypted identity/keyring/holder-adoption machinery through
explicit version parameters. Older records stay in their own directories.
"""
import copy
import secrets
from pathlib import Path
from authorship import nonzero_hex
from authorship_desktop import AuthorshipDesktop
from authorship_v5 import address,hash32,validate_core,points,prove,verify
from count_state import count_view
from domain_desktop import exclusive
from policy import require,digest,timestamp
from public_bundle_v5 import unsigned,validate_unsigned,build,encode
import count_authorship_v5 as followers
import historical_authorship_v5 as history
import wallet_authorship_v5 as wallet

PROFILE='nockapp-protected-authorship-desktop-v5'

def binding(v):
    require(type(v) is dict and set(v)=={'protocol','chain_id','application','contract','issuer_definition'}
        and type(v['protocol']) is int and v['protocol']==5 and type(v['chain_id']) is int
        and v['chain_id'] in (31337,84532),'v5-author-binding')
    hash32(v['application']);address(v['contract']);nonzero_hex(v['issuer_definition'],64)
    return copy.deepcopy(v)


class AuthorshipDesktopV5(AuthorshipDesktop):
    identity_profile=PROFILE
    key_challenge_profile='nockapp-local-signing-key-possession-v5'
    validate_binding=staticmethod(binding)

    def __init__(self,*args,previous_authors=(),**kwargs):
        path=Path(args[0] if args else kwargs['directory'])
        require(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents))
            and not any(p.startswith('.env') for p in path.parts),'v5-author-directory')
        super().__init__(*args,**kwargs);self.previous_authors=tuple(previous_authors)
        for old in self.previous_authors:
            require(isinstance(old,AuthorshipDesktop) and old is not self
                and old.binding['issuer_definition']==self.binding['issuer_definition'],'v5-previous-author')
            a=old.wallet.directory;b=self.wallet.directory
            require(not a.is_relative_to(b) and not b.is_relative_to(a),'author-wallet-overlap')

    @exclusive
    def initialize(self,now,approve_create):
        require(approve_create is True,'consent-required')
        if self._load(missing=True) is not None:return self.status()
        for old in self.previous_authors:
            require(old.wallet.read('credential.sealed',missing=True) is None
                and old.wallet.read('pending.sealed',missing=True) is None
                and old.wallet.read('post.sealed',missing=True) is None,'v5-author-adoption-required')
        return super().initialize(now,approve_create)

    @exclusive
    def adopt_author(self,old,now,approve_adoption):
        require(approve_adoption is True and old in self.previous_authors,'author-adoption-consent')
        require(self._load(missing=True) is None and self.wallet.metadata() is None,'author-identity-exists')
        with old.transaction():
            require(old.wallet.read('pending.sealed',missing=True) is None,'author-legacy-recovery-required')
            r=old._load()
            # Preserve even an old unfinished post; copying key authority with
            # explicit consent does not publish or delete old signing material.
            return self._create(copy.deepcopy(r['identity']),r['root'],
                {'kind':'adopted-author','prior_binding_sha256':digest(old.binding)},now)

    def _matches(self,c):
        validate_core(c)
        require(all(c['context'][k]==self.binding[k] for k in ('protocol','chain_id','application','contract')),'v5-author-context')

    def _post(self):
        identity=self._load();r=self.wallet.load('post')
        require(type(r) is dict and set(r)=={'profile','binding','unsigned','address_request','bundle'}
            and r['profile']==PROFILE and r['binding']==self.binding,'v5-protected-post')
        u=validate_unsigned(r['unsigned']);self._matches(u['core'])
        require(u['author']==points(self.native,identity['identity']['scalar'],u['core']),'v5-author-key-mismatch')
        q=r['address_request']
        if q is not None:
            require(type(q) is dict and set(q)=={'address','nonce','created_at','expires_at','request_sha256'}
                and q['address']==wallet.address(q['address']),'v5-wallet-request')
            data=wallet.typed_data(u,q['nonce'],q['created_at'],q['expires_at'])
            require(q['request_sha256']==digest(data),'v5-wallet-request')
        if r['bundle'] is not None:
            require(r['bundle']['unsigned']==u and verify(self.native,u,r['bundle']['authorship']),'v5-saved-author')
        return r

    @exclusive
    def prepare_post(self,c,now,approve_publication):
        require(approve_publication is True,'consent-required');timestamp(now);self._matches(c);identity=self._load()
        require(c['post']['created_at']<=now,'v5-author-time')
        if self.wallet.read('post.sealed',missing=True) is not None:
            r=self._post();require(r['unsigned']['core']==c,'author-post-recovery-required')
        else:
            require(self.wallet.read('pending.sealed',missing=True) is None,'author-ownership-recovery-required')
            r={'profile':PROFILE,'binding':self.binding,'unsigned':unsigned(c,points(self.native,identity['identity']['scalar'],c)),
                'address_request':None,'bundle':None}
            self.wallet.save('post',r)
        return self.public_material()

    @exclusive
    def public_material(self):
        r=self._post()
        return copy.deepcopy({k:r[k] for k in ('unsigned','address_request','bundle')})

    @exclusive
    def attach_count(self,desktop,canonical_view,witness,now):
        require(desktop in self.legacy_sources and getattr(desktop,'authority_definition',None)==self.binding['issuer_definition'],'author-count-wallet')
        r=self._post();require(r['address_request'] is None and r['bundle'] is None,'author-wallet-proof-frozen')
        require(canonical_view['definition_hash']==self.binding['issuer_definition'],'author-issuer-mismatch')
        projected=count_view(desktop.native,canonical_view)
        with desktop.transaction():
            held=desktop._check(desktop.wallet.load('credential'))
            require(witness['public']==projected['public'] and held['definition_hash']==projected['definition_hash'],'registration-current-registry')
            credential=desktop.native.call('refresh',credential=held['credential'],public=projected['public'],witness=witness['witness'])['credential']
            u=r['unsigned'];e=followers.present(self.native,desktop.native,credential,u['core'],u['author'],canonical_view,now)
            u['evidence']['followers']=e
            require(followers.verify(self.native,desktop.native,u,canonical_view,now,now,canonical_view)['eligible_now'],'v5-count-proof')
            self.wallet.save('post',r)
        return self.public_material()

    @exclusive
    def attach_renewal(self,desktop,canonical_view,witness,now,*,before_save):
        from renewal_desktop_v3 import RenewalDesktop
        from renewal_native_v3 import public_view
        import renewal_evidence_v3 as renewal
        require(isinstance(desktop,RenewalDesktop) and desktop in self.legacy_sources
            and desktop.authority_definition==self.binding['issuer_definition'],'author-renewal-wallet')
        require(callable(before_save),'renewal-finality-fence')
        r=self._post();require(r['address_request'] is None and r['bundle'] is None,'author-wallet-proof-frozen')
        require(canonical_view['definition_hash']==self.binding['issuer_definition'],'author-issuer-mismatch')
        projected=public_view(desktop.native,canonical_view)
        with desktop.transaction():
            held=desktop._check(desktop.wallet.load('credential'))
            require(witness['public']==projected['public'] and held['definition_hash']==projected['definition_hash'],
                'registration-current-registry')
            credential=desktop.native.call('refresh',credential=held['credential'],public=projected['public'],witness=witness['witness'])['credential']
            u=r['unsigned'];u['evidence']['followers']=renewal.present(desktop.native,credential,u['core'],u['author'],canonical_view,now)
            renewal.verify(desktop.native,u,canonical_view,now)
            before_save()
            self.wallet.save('post',r)
        return self.public_material()

    @exclusive
    def attach_history(self,records,resolve,now,approve_linking):
        require(approve_linking is True,'consent-required');timestamp(now);r=self._post()
        require(r['address_request'] is None and r['bundle'] is None,'author-wallet-proof-frozen')
        identity=self._load();u=r['unsigned']
        u['evidence']['history']=history.prove(self.native,identity['identity']['scalar'],u['core'],u['author'],records,resolve)
        history.verify(self.native,u,now,resolve);self.wallet.save('post',r)
        return self.public_material()

    @staticmethod
    def _ready(r):
        # Selected optional evidence may be absent or unverifiable. The final
        # author proof still commits its exact bytes and disclosure choices.
        validate_unsigned(r['unsigned'])

    @exclusive
    def request_address(self,account,now,approve_address_disclosure):
        require(approve_address_disclosure is True,'consent-required');timestamp(now);r=self._post();self._ready(r)
        require(r['bundle'] is None,'v5-already-signed');account=wallet.address(account)
        if r['address_request'] is None:
            q={'address':account,'nonce':secrets.token_hex(32),'created_at':now,'expires_at':now+60}
            data=wallet.typed_data(r['unsigned'],q['nonce'],now,now+60);q['request_sha256']=digest(data)
            r['address_request']=q;self.wallet.save('post',r)
        else:
            q=r['address_request'];require(q['address']==account,'author-wallet-recovery-required')
            data=wallet.typed_data(r['unsigned'],q['nonce'],q['created_at'],q['expires_at'])
        return {'profile':PROFILE,'address':account,'typed_data':data,'request_sha256':q['request_sha256'],
            'expired':not q['created_at']<=now<q['expires_at']}

    @exclusive
    def accept_address(self,signature,now):
        r=self._post();q=r['address_request'];require(q is not None,'author-wallet-request-missing');self._ready(r)
        u=r['unsigned'];e=wallet.payload(q['address'],signature,q['nonce'],q['created_at'],q['expires_at'])
        if u['evidence']['wallet'] is not None:
            require(e==u['evidence']['wallet'],'author-wallet-signature-conflict')
        else:
            require(r['bundle'] is None,'v5-already-signed');u['evidence']['wallet']=e
            wallet.verify(u,now);self.wallet.save('post',r)
        return self.public_material()

    @exclusive
    def reset_unfinished_address(self,expected_request_sha256,now,approve_fresh_request):
        require(approve_fresh_request is True,'consent-required');timestamp(now);r=self._post();q=r['address_request']
        require(r['bundle'] is None and q is not None and q['request_sha256']==expected_request_sha256
            and now>=q['expires_at'],'v5-signing-reset-unavailable')
        # No complete final author proof has left this unfinished protected
        # record. Completed signed bundles can never use this reset path.
        r['address_request']=None;r['unsigned']['evidence']['wallet']=None;self.wallet.save('post',r)
        return self.public_material()

    @exclusive
    def material(self,now):
        r=self._post();self._ready(r)
        if r['bundle'] is None:
            u=r['unsigned']
            # Badge validity is checked independently at canonical indexing.
            # An unavailable/expired wallet reply must not block authored text.
            identity=self._load();r['bundle']=build(u,prove(self.native,identity['identity']['scalar'],u))
            self.wallet.save('post',r)  # Never regenerate randomized final proof on a lost reply.
        return copy.deepcopy(r['bundle'])

    @exclusive
    def release_saved_post(self,coordinator,post_id,bundle_hash):
        from public_desktop_v5 import PublicDesktopV5
        from base_protocol import sha
        require(isinstance(coordinator,PublicDesktopV5) and coordinator.author is self,'author-outbox-owner')
        if self.wallet.read('post.sealed',missing=True) is None:return False
        r=self._post();v=r['bundle'];require(v is not None,'v5-bundle-unsaved')
        require(v['unsigned']['core']['post']['id']==post_id and sha(encode(v))==bundle_hash,'author-outbox-copy-mismatch')
        box=coordinator._outbox();rows=[row for row in box['entries'] if row['core']['post']['id']==post_id]
        require(len(rows)==1 and rows[0]['bundle'] is not None and encode(rows[0]['bundle'])==encode(v),'author-outbox-copy-mismatch')
        self.wallet.delete('post');return True
