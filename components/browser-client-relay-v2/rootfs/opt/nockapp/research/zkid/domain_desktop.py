"""Protected holder lifecycle for the source-connected composite candidate.

All credential/secret processing and promotion proofs remain on the desktop.
Only a blind request, session-bound receipt or explicitly requested public proof
leaves it. Real enrollment/transport acceptance is a separate unfinished gate.
"""
import copy
import contextlib
import functools
import re
import secrets
import threading

from domain_pipeline import Native, PendingHolder, HeldCredential, definition_hash, PROFILE
from policy import POLICY_HASH, Session, digest, require, timestamp, hex_string,identifier
from wallet import Wallet

DESKTOP = 'nockapp-zkid-protected-domain-desktop-lab-v1'


def exclusive(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
        with self.transaction(): return method(self,*args,**kwargs)
    return call


class DomainDesktop:
    desktop_profile=DESKTOP
    credential_profile=PROFILE
    policy_hash=POLICY_HASH
    session_type=Session
    pending_type=PendingHolder
    request_scheme='credx-bbs-domain-0.2.1'

    def __init__(self, directory, native=None):
        self.wallet = Wallet(directory)
        self.native = native if native is not None else Native()
        self._lock=threading.RLock();self._depth=0

    @contextlib.contextmanager
    def transaction(self):
        """Same-instance nested calls share one whole-operation wallet lock."""
        with self._lock:
            with (self.wallet.controller_lock() if not self._depth else contextlib.nullcontext()):
                self._depth+=1
                try:yield
                finally:self._depth-=1

    def _check(self, value):
        require(value.get('profile') == self.desktop_profile and value.get('binary_sha256') == self.native.sha256.hex()
                and all(value.get(k)==v for k,v in self._binding().items()),
                'domain-desktop-profile')
        return value

    def _binding(self):return {}

    def _activation_challenge(self,view,now):
        return {'profile':self.credential_profile,'nonce':secrets.token_hex(32),'scope':digest({'purpose':'local-activation-check'}),
            'facts':['account-controlled'],'identity':True,'registry_sequence':view['sequence'],
            'created_at':now,'expires_at':now+60}

    @exclusive
    def prepare(self, public, account_id, username):
        require(type(username) is str and re.fullmatch(r'[A-Za-z0-9_]{1,15}',username),'account-handle')
        if account_id is not None:identifier(account_id)
        self.wallet.initialize()
        require(self.wallet.read('pending.sealed',missing=True) is None,'registration-already-pending')
        if self.wallet.read('credential.sealed',missing=True) is not None:
            self._check(self.wallet.load('credential'))
        holder = self.pending_type.create(self.native,public)
        value = {'profile':self.desktop_profile,'binary_sha256':self.native.sha256.hex(),'definition_hash':definition_hash(public),
            'holder':holder.private,'request':holder.request,'desktop_nonce':holder.desktop_nonce,
            'local_zkid':holder.local_zkid,'account_id':account_id,'username':username,
            'public_definition':copy.deepcopy(public),'session':None,'credential':None,'ack':None,'attributes':None,**self._binding()}
        self.wallet.save('pending',value)
        return {'request':holder.request,'desktop_nonce':holder.desktop_nonce}

    @exclusive
    def resume_request(self):
        value = self._check(self.wallet.load('pending'))
        return {'request':copy.deepcopy(value['request']),'desktop_nonce':value['desktop_nonce']}

    @exclusive
    def record_session(self, session):
        value = self._check(self.wallet.load('pending'))
        require(type(session) is self.session_type and session.request_scheme == self.request_scheme
                and session.issuer_key == value['definition_hash']
                and session.commitment == digest(value['request']) and session.desktop_nonce == value['desktop_nonce']
                and (value['account_id'] is None or session.account_id == value['account_id'])
                and session.username == value['username'],
                'registration-session-mismatch')
        require(value['session'] is None or value['session'] == session.__dict__,'registration-session-mismatch')
        value['session'] = session.__dict__;value['account_id']=session.account_id
        self.wallet.save('pending',value)

    @exclusive
    def receive(self, issued, public):
        value = self._check(self.wallet.load('pending'))
        require(value['session'] is not None and definition_hash(public) == value['definition_hash'],
                'registration-context')
        # A repeated delivery must not silently replace the recovery credential.
        require(value['credential'] is None,'registration-already-received')
        holder = self.pending_type(self.native,value['holder'],value['request'],value['desktop_nonce'],value['local_zkid'])
        held,ack = holder.receive(issued,public,self.session_type(**value['session']))
        value['credential'] = held.private; value['ack'] = ack; value['attributes'] = copy.deepcopy(issued['attributes'])
        self.wallet.save('pending',value)  # Preserve recovery BEFORE returning ACK.
        return ack

    @exclusive
    def recover_ack(self):
        value = self._check(self.wallet.load('pending'))
        require(value['credential'] is not None and value['ack'] is not None,'registration-not-received')
        return copy.deepcopy(value['ack'])

    def _present(self, record, view, witness, challenge, now):
        self._check(record)
        require(view['definition_hash'] == record['definition_hash'] == definition_hash(view['public'])
                and witness['public'] == view['public'],'registration-current-registry')
        require(challenge['registry_sequence'] == view['sequence'],'registry-state-changed')
        current = self.native.call('refresh',credential=record['credential'],public=view['public'],witness=witness['witness'])
        trust = {'issuer':view['public'],'policy':self.policy_hash,'challenge':challenge,
                 'current_sequence':view['sequence'],'now':now}
        proof = self.native.call('present',credential=current['credential'],trust=trust)
        require(not challenge['identity'] or proof['claimed_id'] == record['local_zkid'],'domain-identity-substitution')
        result = self.native.call('verify',public_input=proof,trust=trust)
        require(result.get('accepted') is True,'registration-not-active')
        return proof,current['credential']

    @exclusive
    def promote(self, view, witness, now):
        value = self._check(self.wallet.load('pending'))
        require(value['credential'] is not None,'registration-not-received')
        challenge = self._activation_challenge(view,now)
        _,credential = self._present(value,view,witness,challenge,now)
        record = {'profile':self.desktop_profile,'binary_sha256':value['binary_sha256'],'definition_hash':value['definition_hash'],
            'credential':credential,'local_zkid':value['local_zkid'],
            'issuance_context':{'session':value['session'],'attributes':value['attributes'],
                                'public_definition':value['public_definition']},**self._binding()}
        self.wallet.save('credential',record)
        self.wallet.delete('pending')
        return {'profile':self.desktop_profile,'laboratory':True,'verified':False,'ready':True}

    @exclusive
    def present(self, view, witness, challenge, now):
        record = self._check(self.wallet.load('credential'))
        proof,credential = self._present(record,view,witness,challenge,now)
        record['credential'] = credential; self.wallet.save('credential',record)
        return proof

    @exclusive
    def witness_handle(self, *, pending=False):
        require(type(pending) is bool,'registration-context')
        value = self._check(self.wallet.load('pending' if pending else 'credential'))
        require(value['credential'] is not None,'registration-not-received')
        # Opaque handle is already known to the issuer. Never return a full
        # credential, scalar or local ID to the witness endpoint.
        return value['credential']['credential']['claims'][0]['Revocation']['value']

    @exclusive
    def cancel_before_receipt(self):
        value = self._check(self.wallet.load('pending'))
        require(value['credential'] is None and value['ack'] is None,'registration-recovery-required')
        self.wallet.delete('pending')

    @exclusive
    def confirm_remote_abort(self, status, expected_nonce, now):
        """Input MUST come from the helper's authenticated issuer connection.

        It is never accepted as a browser-supplied cancellation assertion.
        """
        value=self._check(self.wallet.load('pending'))
        hex_string(expected_nonce,64);timestamp(now)
        require(value['session'] is not None,'registration-context')
        binding=self.session_type(**value['session']).binding
        require(type(status) is dict and set(status)=={'profile','binding','state','nonce','observed_at',
                    'registry_sequence','laboratory','verified'}
                and status['profile']==self.credential_profile and status['binding']==binding and status['state']=='aborted'
                and status['nonce']==expected_nonce and status['laboratory'] is True and status['verified'] is False
                and type(status['observed_at']) is int and now-5<=status['observed_at']<=now+5,
                'registration-abort-unconfirmed')
        self.wallet.delete('pending')
        return {'profile':self.desktop_profile,'cancelled':True,'verified':False}

    @exclusive
    def forget_credential(self):
        require(self.wallet.read('pending.sealed',missing=True) is None,'registration-recovery-required')
        self._check(self.wallet.load('credential'))
        self.wallet.delete('credential')
        return {'profile':self.desktop_profile,'ready':False,'remote_revocation':False}
