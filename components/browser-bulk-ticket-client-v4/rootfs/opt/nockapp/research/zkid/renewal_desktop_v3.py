"""Private same-author renewal wallet; no private browser projections.

The enrollment coordinator supplies independently authenticated FINALIZED issuer
views before promotion. A remote active/status boolean alone is insufficient.
Original credentials and the author's protected signing identity stay separate.
"""
import copy
import re
import secrets
from pathlib import Path
from domain_desktop import DomainDesktop,exclusive
from domain_pipeline import definition_hash
from authorship_desktop import held_scalar
from authorship_desktop_v5 import AuthorshipDesktopV5
from policy import digest,hex_string,identifier,require
from renewal_native_v3 import RenewalNative,public_view
from renewal_policy_v3 import PROFILE,POLICY_HASH,SCHEME,RenewalSession

DESKTOP='nockapp-protected-renewal-desktop-v3'


class RenewalDesktop(DomainDesktop):
    desktop_profile=DESKTOP;credential_profile=PROFILE;policy_hash=POLICY_HASH;session_type=RenewalSession;request_scheme=SCHEME

    def __init__(self,directory,authority_definition,native=None):
        path=Path(directory);hex_string(authority_definition,64)
        require(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents))
            and not any(p.startswith('.env') for p in path.parts),'renewal-wallet-directory')
        self.authority_definition=authority_definition
        super().__init__(path,native or RenewalNative())

    def _binding(self):return {'authority_definition':self.authority_definition}

    def _check(self,r):
        require(type(r) is dict and r.get('profile')==DESKTOP and r.get('binary_sha256')==self.native.sha256
            and r.get('authority_definition')==self.authority_definition,'renewal-wallet-profile')
        context=r.get('public_definition') if 'holder' in r else r['issuance_context']['public_definition']
        require(r['definition_hash']==definition_hash(context) and context['schema']['id']==PROFILE,'renewal-wallet-definition')
        return r

    def _view(self,original):
        require(original['definition_hash']==self.authority_definition,'renewal-authority')
        return public_view(self.native,original)

    def prepare(self,author,original,account_id,username,approve_renewal):
        require(approve_renewal is True and isinstance(author,AuthorshipDesktopV5) and self in author.legacy_sources,'consent-required')
        require(type(username) is str and re.fullmatch(r'[A-Za-z0-9_]{1,15}',username),'account-handle')
        if account_id is not None:identifier(account_id)
        with author.transaction(),self.transaction():
            identity=author._load();view=self._view(original);self.wallet.initialize()
            require(self.wallet.read('pending.sealed',missing=True) is None,'registration-already-pending')
            if self.wallet.read('credential.sealed',missing=True) is not None:
                old=self._check(self.wallet.load('credential'))
                converted=author.native.call('normalize-held-scalar',scalar=held_scalar(old['credential']))
                require(converted['root']==identity['root'],'renewal-author-key-conflict')
            p=self.native.call('prepare',public=view['public'],secret=identity['identity']['scalar'])
            r={'profile':DESKTOP,'binary_sha256':self.native.sha256,'authority_definition':self.authority_definition,
                'definition_hash':view['definition_hash'],'public_definition':copy.deepcopy(view['public']),
                'holder':p['pending'],'request':p['request'],'desktop_nonce':secrets.token_hex(32),
                'account_id':account_id,'username':username,'session':None,'credential':None,'ack':None,'attributes':None}
            self.wallet.save('pending',r)
            return {'request':copy.deepcopy(p['request']),'desktop_nonce':r['desktop_nonce']}

    @exclusive
    def receive(self,issued,original):
        r=self._check(self.wallet.load('pending'));view=self._view(original)
        require(r['session'] is not None and r['credential'] is None and view['definition_hash']==r['definition_hash'],'registration-context')
        s=RenewalSession(**r['session']);attrs=issued['attributes']
        require(attrs['binding']==s.binding and attrs['policy']==POLICY_HASH,'renewal-receipt-context')
        out=self.native.call('receive',pending=r['holder'],bundle=issued['bundle'],public=view['public'],attributes=attrs)
        r['credential']=out['credential'];r['ack']=out['ack'];r['attributes']=copy.deepcopy(attrs)
        self.wallet.save('pending',r);return copy.deepcopy(out['ack'])

    def promote(self,author,finalized_view,witness,now,*,before_save=None):
        require(isinstance(author,AuthorshipDesktopV5) and self in author.legacy_sources,'renewal-author-config')
        with author.transaction(),self.transaction():
            identity=author._load();r=self._check(self.wallet.load('pending'));view=self._view(finalized_view)
            require(r['credential'] is not None and view['definition_hash']==r['definition_hash'] and witness['public']==view['public'],'registration-current-registry')
            credential=self.native.call('refresh',credential=r['credential'],public=view['public'],witness=witness['witness'])['credential']
            require(self.native.call('activate',credential=credential,public=view['public'],expected_secret=identity['identity']['scalar'],now=now)=={'accepted':True},'registration-not-active')
            if before_save is not None:before_save()
            record={'profile':DESKTOP,'binary_sha256':self.native.sha256,'authority_definition':self.authority_definition,
                'definition_hash':r['definition_hash'],'credential':credential,
                'issuance_context':{'session':r['session'],'attributes':r['attributes'],'public_definition':r['public_definition']}}
            self.wallet.save('credential',record) # Preserve receipt + pending until durable private readback.
            require(self._check(self.wallet.load('credential'))==record,'renewal-wallet-readback')
            self.wallet.delete('pending');return {'profile':DESKTOP,'ready':True}

    @exclusive
    def status(self):
        ready=self.wallet.read('credential.sealed',missing=True) is not None
        if ready:self._check(self.wallet.load('credential'))
        return {'profile':DESKTOP,'ready':ready,'renewal_pending':self.wallet.read('pending.sealed',missing=True) is not None}
