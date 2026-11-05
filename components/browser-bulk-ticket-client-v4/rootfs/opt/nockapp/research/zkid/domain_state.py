"""Separate issuer and verifier roles over a trusted lab transaction authority.

The backend is an independently TRUSTED laboratory authority. A local database
on an untrusted EC2 parent is not production anti-rollback protection.
"""
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from domain_pipeline import LabDomainIssuer, definition_hash, PROFILE
from policy import POLICY_HASH, Session, Rejected, canonical, require, hex_string, timestamp

SNAPSHOT = 'nockapp-zkid-domain-encrypted-state-v1'
LIMIT = 262144
# The sole pre-issuance beta policy eligible for the explicit startup upgrade.
# This identifies the former full-wording policy; it is never a boot input.
PREVIOUS_UNISSUED_POLICY = '54c7cf6376795ee34eb3c8257c0ee74e34403503e22f8bc546a388fea061091f'


def snapshot(core):
    pending = {key:{**value,'session':value['session'].__dict__} for key,value in core._pending.items()}
    return {'profile':SNAPSHOT,'protocol':PROFILE,'policy':POLICY_HASH,'binary_sha256':core.native.sha256.hex(),
        'definition_hash':core.definition_hash,'issuer':core._issuer,'public':core.public,'handles':core._handles,
        'next':core._next,'sequence':core.sequence,'accounts':core._accounts,'pending':pending}


def restore(data, native):
    return _restore_policy(data, native, POLICY_HASH)


def _restore_policy(data, native, expected_policy):
    require(type(data) is dict and data.get('profile') == SNAPSHOT and data.get('protocol') == PROFILE
            and data.get('policy') == expected_policy and data.get('binary_sha256') == native.sha256.hex(),
            'domain-state-profile')
    core = object.__new__(LabDomainIssuer)
    core.native = native; core._issuer = data['issuer']; core.public = data['public']; core._handles = data['handles']
    core.definition_hash = definition_hash(core.public)
    require(core.definition_hash == data['definition_hash'],'domain-state-issuer')
    core._next = data['next']; core.sequence = data['sequence']; core._accounts = data['accounts']
    core._pending = {key:{**value,'session':Session(**value['session'])} for key,value in data['pending'].items()}
    core._actions = {}; core._lock = threading.RLock(); core._persist_callback = None
    return core


class PersistentDomainIssuer:
    production_antirollback = False

    def __init__(self, backend, key, namespace, native):
        require(type(key) is bytes and len(key) == 32 and type(namespace) is str and len(namespace) == 64,
                'domain-state-configuration')
        self.backend = backend; self._cipher = AESGCM(key); self.namespace = namespace; self.native = native

    def _aad(self, revision, *, policy=POLICY_HASH):
        return canonical({'profile':SNAPSHOT,'namespace':self.namespace,'revision':revision,'policy':policy})

    def _seal(self, core, revision):
        body = canonical(snapshot(core)); require(len(body) <= LIMIT,'domain-state-capacity')
        nonce = secrets.token_bytes(12)
        return nonce + self._cipher.encrypt(nonce,body,self._aad(revision))

    def initialize(self, core):
        require(core.definition_hash == self.namespace,'domain-state-issuer')
        self.backend.compare_exchange(None,self._seal(core,0),public_view(core))

    def load(self):
        revision,envelope = self.backend.read()
        require(type(revision) is int and type(envelope) is bytes and 28 < len(envelope) <= LIMIT + 28,'registry-missing')
        try:
            body = self._cipher.decrypt(envelope[:12],envelope[12:],self._aad(revision))
            core = restore(json.loads(body),self.native)
            require(core.definition_hash == self.namespace,'domain-state-issuer')
            return revision,core
        except Rejected: raise
        except Exception: raise Rejected('domain-state-authentication') from None

    def upgrade_unused_beta_policy(self):
        """One guarded policy transition; never initialize or replace a signer.

        Only the exact authenticated prior policy, with no consumed issuance
        index/account and all prior registrations explicitly aborted, qualifies.
        The same issuer keys/public definition/sequence are resealed atomically.
        Missing, corrupt, active or unknown-policy state cannot be upgraded.
        Normal load remains strict; no old credential is relabelled as new.
        """
        revision,envelope = self.backend.read()
        require(type(revision) is int and type(envelope) is bytes and 28 < len(envelope) <= LIMIT+28,
                'registry-missing')
        try:
            current = self._cipher.decrypt(envelope[:12],envelope[12:],self._aad(revision))
        except InvalidTag:
            try:
                previous = self._cipher.decrypt(envelope[:12],envelope[12:],
                    self._aad(revision,policy=PREVIOUS_UNISSUED_POLICY))
                core = _restore_policy(json.loads(previous),self.native,PREVIOUS_UNISSUED_POLICY)
            except Exception: raise Rejected('domain-state-authentication') from None
            require(core.definition_hash == self.namespace,'domain-state-issuer')
            require(self.backend.public_view() == public_view(core),'issuer-public-state')
            require(type(core._next) is int and core._next == 0
                    and type(core._accounts) is dict and not core._accounts
                    and all(type(value) is dict and value.get('aborted') is True
                            and value.get('issued') is False and value.get('acknowledged') is False
                            and 'response' not in value and 'handle' not in value
                            for value in core._pending.values()),'policy-upgrade-active-state')
            retired = len(core._pending)
            core._pending = {}
            self.backend.compare_exchange(revision,self._seal(core,revision+1),public_view(core))
            return {'upgraded':True,'retired_aborted_registrations':retired}
        except Exception: raise Rejected('domain-state-authentication') from None
        else:
            # An already-current state, including issued credentials, is left
            # untouched. Validate it fully rather than retrying a migration.
            core = restore(json.loads(current),self.native)
            require(core.definition_hash == self.namespace,'domain-state-issuer')
            return {'upgraded':False,'retired_aborted_registrations':0}

    def operate(self, method, *args, **kwargs):
        require(method in ('begin','find_begin','validate_request','stage_fixture','stage_provider','commit','recover_delivery',
                           'status','abort','reserve_discovery','finish_discovery','fail_discovery'),
                'domain-state-operation')
        revision,core = self.load(); cursor = [revision]
        def persist():
            envelope = self._seal(core,cursor[0] + 1)
            cursor[0] = self.backend.compare_exchange(cursor[0],envelope,public_view(core))
        core._persist_callback = persist
        # No action proof or public ZKID is ever an issuer operation.
        return getattr(core,method)(*args,**kwargs)


def public_view(core):
    return {'definition_hash':core.definition_hash,'public':core.public,'sequence':core.sequence}


class TrustedDomainStore:
    """Trusted LAB authority, not a database to put on an untrusted parent.

    Issuer publication atomically updates ciphertext and its public registry.
    Verifier action consumption checks that registry in the same transaction.
    Neither public view nor action methods receive a proof, public ID or key.
    Production needs equivalent authenticated managed transactions and roles.
    """
    production_antirollback = False

    def __init__(self, directory):
        root = Path(directory)
        require(root.is_absolute() and not root.is_symlink(),'registry-directory')
        root.mkdir(mode=0o700,parents=True,exist_ok=True)
        info = root.stat()
        require(info.st_uid == os.getuid() and not info.st_mode & 0o077,'registry-directory')
        path = root/'domain-state.sqlite'
        fd = os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077
                    and info.st_nlink == 1,'registry-file')
        finally: os.close(fd)
        self.db = sqlite3.connect(path,isolation_level=None,timeout=10)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,envelope BLOB NOT NULL,public BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS actions(nonce TEXT PRIMARY KEY,body BLOB NOT NULL,used INTEGER NOT NULL DEFAULT 0);
        ''')

    def read(self):
        row = self.db.execute('SELECT revision,envelope FROM state WHERE id=1').fetchone()
        return row if row is not None else (None,None)

    def public_view(self):
        row = self.db.execute('SELECT public FROM state WHERE id=1').fetchone()
        require(row is not None,'registry-missing')
        return json.loads(row[0])

    def compare_exchange(self, expected, envelope, public):
        require(type(envelope) is bytes and 28 < len(envelope) <= LIMIT + 28,'registry-envelope')
        require(set(public) == {'definition_hash','public','sequence'},'registry-public-projection')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            current,_ = self.read(); require(current == expected,'registry-conflict')
            revision = 0 if expected is None else expected + 1
            self.db.execute('INSERT OR REPLACE INTO state VALUES(1,?,?,?)',(revision,envelope,canonical(public)))
            self.db.execute('COMMIT'); return revision
        except Exception:
            self.db.execute('ROLLBACK'); raise

    def register_action(self, challenge):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            require(self.public_view()['sequence'] == challenge['registry_sequence'],'registry-state-changed')
            self.db.execute('INSERT INTO actions(nonce,body) VALUES(?,?)',(challenge['nonce'],canonical(challenge)))
            self.db.execute('COMMIT')
        except Exception:
            self.db.execute('ROLLBACK'); raise

    def action_record(self, nonce):
        return self.db.execute('SELECT body,used FROM actions WHERE nonce=?',(nonce,)).fetchone()

    def consume_action(self, challenge):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            record = self.action_record(challenge['nonce'])
            require(record and record[0] == canonical(challenge) and not record[1],'action-not-outstanding')
            require(self.public_view()['sequence'] == challenge['registry_sequence'],'registry-state-changed')
            self.db.execute('UPDATE actions SET used=1 WHERE nonce=?',(challenge['nonce'],))
            self.db.execute('COMMIT')
        except Exception:
            self.db.execute('ROLLBACK'); raise


class PersistentDomainVerifier:
    """Application verifier. No issuer encryption key or private core is held.

    Only public registry reads and nonce consumption reach the state authority.
    The actual proof and public identity stay in this independent verifier.
    """
    def __init__(self, backend, native, approved_definition):
        self.backend = backend; self.native = native; self.approved_definition = approved_definition

    def _view(self):
        view = self.backend.public_view()
        require(view['definition_hash'] == self.approved_definition
                and definition_hash(view['public']) == self.approved_definition,'domain-issuer-changed')
        return view

    def challenge(self, scope, facts, now, *, identity=False):
        hex_string(scope,64); timestamp(now)
        require(type(identity) is bool and type(facts) is list and 1 <= len(facts) <= 2
                and all(type(f) is str for f in facts) and len(set(facts)) == len(facts)
                and set(facts) <= {'account-controlled','followers-at-least-10000'},'presentation-facts')
        view = self._view()
        body = {'profile':PROFILE,'nonce':secrets.token_hex(32),'scope':scope,'facts':sorted(facts),'identity':identity,
                'registry_sequence':view['sequence'],'created_at':now,'expires_at':now+60}
        self.backend.register_action(body)
        return body

    def verify(self, proof, challenge, now):
        started=time.monotonic()
        record = self.backend.action_record(challenge['nonce'])
        require(record and record[0] == canonical(challenge) and not record[1],'action-not-outstanding')
        require(challenge['created_at'] <= now < challenge['expires_at'],'action-expired')
        view = self._view()
        require(view['sequence'] == challenge['registry_sequence'],'registry-state-changed')
        trust = {'issuer':view['public'],'policy':POLICY_HASH,'challenge':challenge,
                 'current_sequence':view['sequence'],'now':now}
        result = self.native.call('verify',public_input=proof,trust=trust)
        require(result.get('accepted') is True,'domain-proof-rejected')
        require(now+time.monotonic()-started < challenge['expires_at'],'action-expired')
        self.backend.consume_action(challenge)  # No proof/public ID is sent here.
        # A delayed remote commit may burn a nonce, but cannot authorize an
        # action after expiry. A timeout is never automatically retried.
        require(now+time.monotonic()-started < challenge['expires_at'],'action-expired')
        return {'profile':PROFILE,'laboratory':True,'verified':False,'hardware_verified':False,
                'cryptographic_proof_valid':True,'public_id_bound':challenge['identity'],'facts':challenge['facts'],
                'public_id':proof['claimed_id'] if challenge['identity'] else None}
