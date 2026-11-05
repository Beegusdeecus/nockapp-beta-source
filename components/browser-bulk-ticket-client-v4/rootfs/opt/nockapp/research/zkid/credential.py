"""Executable blind-credential research pipeline, explicitly laboratory only.

The production release gate is closed until measured issuer, secret provisioning,
rollback-resistant uniqueness and revocation have actually been implemented.
No local database or self-signed assertion is a replacement for those gates.
"""
from dataclasses import dataclass
import ctypes
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import sqlite3
import subprocess
import time

from policy import (PROFILE, SOURCE, POLICY_HASH, Rejected, Session, canonical,
                    digest, evaluate, hex_string, require, timestamp)

CRYPTO = Path(__file__).resolve().parent / 'crypto/target/release/nockapp-zkid-crypto'


def private_child():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
        os._exit(1)


class Crypto:
    def __init__(self, binary=CRYPTO):
        self._binary = Path(binary)
        self._digest = hashlib.sha256(self._binary.read_bytes()).digest()

    def call(self, op, **fields):
        require(hashlib.sha256(self._binary.read_bytes()).digest() == self._digest, 'crypto-binary-changed')
        data = canonical({'op': op, **fields})
        require(len(data) <= 32768, 'crypto-input-size')
        # Inputs/outputs, including synthetic keys, travel only through private
        # anonymous pipes. The caller controls which public projection is saved.
        try:
            result = subprocess.run([str(self._binary)], input=data, capture_output=True,
                timeout=10, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, preexec_fn=private_child)
            require(len(result.stdout) <= 16384 and not result.stderr and result.returncode == 0,
                    'crypto-rejected')
            value = json.loads(result.stdout)
            require(type(value) is dict and 'error' not in value, 'crypto-rejected')
            return value
        except Rejected:
            raise
        except Exception:
            raise Rejected('crypto-unavailable') from None


@dataclass(repr=False)
class Pending:
    secret: str
    blinding: str
    commitment: str
    nonce: str

    @classmethod
    def create(cls, crypto, secret=None):
        secret = secrets.token_hex(32) if secret is None else hex_string(secret,64)
        prepared = crypto.call('prepare', secret=secret)
        return cls(secret, prepared['blinding'], prepared['commitment'], secrets.token_hex(32))

    @property
    def local_zkid(self):
        # Local identity only. Presentations below do NOT prove a relation to a
        # disclosed SHA-256 ZKID; no Nockchain acceptance is claimed.
        return hashlib.sha256(b'NOCKAPP/ZKID/LOCAL/v1\0' + bytes.fromhex(self.secret)).hexdigest()

    def accept(self, crypto, issuer_key, attributes, signature):
        crypto.call('accept', public_key=issuer_key, attributes=attributes,
                    signature=signature, secret=self.secret, blinding=self.blinding)
        return Credential(issuer_key, list(attributes), signature, self.secret, self.blinding)


@dataclass(repr=False)
class Credential:
    issuer_key: str
    attributes: list
    signature: str
    secret: str
    blinding: str

    def present(self, crypto, challenge):
        require(type(challenge) is dict and set(challenge) == {'profile', 'nonce', 'scope', 'facts',
                'created_at', 'expires_at'}, 'presentation-challenge')
        require(challenge['profile'] == PROFILE, 'presentation-profile')
        indexes = indexes_for(challenge['facts'])
        require(all(self.attributes[i] == '1' for i in indexes if i >= 5), 'fact-unavailable')
        context = canonical(challenge).hex()
        proof = crypto.call('present', public_key=self.issuer_key, signature=self.signature,
            secret=self.secret, blinding=self.blinding, attributes=self.attributes,
            disclose=indexes, context=context)['proof']
        return {'profile': PROFILE, 'issuer_key': self.issuer_key, 'disclose': indexes,
                'attributes': [self.attributes[i] for i in indexes], 'proof': proof}


def indexes_for(facts):
    require(type(facts) is list and 1 <= len(facts) <= 2
            and all(type(f) is str for f in facts) and len(set(facts)) == len(facts)
            and set(facts) <= {'account-controlled', 'followers-at-least-10000'}, 'presentation-facts')
    return [0,1,2,3,4] + ([5] if 'account-controlled' in facts else []) + ([6] if 'followers-at-least-10000' in facts else [])


class LabIssuer:
    """Single trusted laboratory process. SQLite is NOT enclave anti-rollback.

    No constructor or relabelling switch for production. Its keys and account
    state may only be generated for synthetic tests. Source evaluation takes
    fixture bytes explicitly; this interface never claims genuine TLS evidence.
    """
    def __init__(self, crypto):
        self.crypto = crypto
        keys = crypto.call('keygen')
        self._key, self.public_key = keys['key'], keys['public_key']
        self.db = sqlite3.connect(':memory:', isolation_level=None)
        self.db.executescript('''
          CREATE TABLE sessions (binding TEXT PRIMARY KEY, body BLOB NOT NULL, used INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE accounts (account_id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
        ''')

    def begin(self, commitment, account_id, username, now, *, desktop_nonce):
        session = Session.create(desktop_nonce, commitment, account_id, username, self.public_key, now)
        self.db.execute('INSERT INTO sessions(binding,body) VALUES (?,?)',
                        (session.binding, canonical(session.__dict__)))
        return session

    def issue_fixture(self, session, tweet_id, tweet_data, user_data, now):
        attributes = evaluate(session, tweet_id, tweet_data, user_data, now)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            record = self.db.execute('SELECT body,used FROM sessions WHERE binding=?', (session.binding,)).fetchone()
            require(record is not None and record[0] == canonical(session.__dict__) and record[1] == 0,
                    'issuance-replay-or-substitution')
            old = self.db.execute('SELECT expires_at FROM accounts WHERE account_id=?', (session.account_id,)).fetchone()
            require(old is None or old[0] <= now, 'account-already-active')
            signature = self.crypto.call('issue', key=self._key, commitment=session.commitment,
                                         attributes=attributes)['signature']
            self.db.execute('UPDATE sessions SET used=1 WHERE binding=?', (session.binding,))
            self.db.execute('INSERT OR REPLACE INTO accounts VALUES (?,?)', (session.account_id, int(attributes[4])))
            self.db.execute('COMMIT')
            return attributes, signature
        except Exception:
            self.db.execute('ROLLBACK')
            raise


class LabVerifier:
    """Separate relying-party verifier with independently supplied issuer policy.

    Fresh issuance trust is NOT taken from a presentation. Lab results always
    report verified=false. Production must additionally enroll an attested key.
    Revocation here rejects the entire shared issuer key; individual unlinkable
    revocation and a durable external uniqueness ledger remain release blockers.
    """
    def __init__(self, crypto, approved_issuer, database=':memory:', *, revoked_keys=()):
        self.crypto = crypto
        self.issuer = hex_string(approved_issuer,192)
        self.revoked = frozenset(revoked_keys)
        self.db = sqlite3.connect(database, isolation_level=None)
        self.db.execute('CREATE TABLE IF NOT EXISTS actions (nonce TEXT PRIMARY KEY, body BLOB NOT NULL, used INTEGER NOT NULL DEFAULT 0)')

    def challenge(self, scope, facts, now):
        hex_string(scope,64)
        indexes_for(facts)
        timestamp(now)
        body = {'profile': PROFILE, 'nonce': secrets.token_hex(32), 'scope': scope,
                'facts': sorted(facts), 'created_at': now, 'expires_at': now + 60}
        self.db.execute('INSERT INTO actions(nonce,body) VALUES (?,?)', (body['nonce'],canonical(body)))
        return body

    def verify(self, presentation, challenge, now):
        require(self.issuer not in self.revoked, 'issuer-revoked')
        timestamp(now)
        require(type(presentation) is dict and set(presentation) == {'profile', 'issuer_key', 'disclose',
                'attributes', 'proof'} and presentation['profile'] == PROFILE, 'presentation-schema')
        require(presentation['issuer_key'] == self.issuer, 'issuer-not-approved')
        require(type(challenge) is dict and type(challenge.get('nonce')) is str, 'presentation-challenge')
        record = self.db.execute('SELECT body,used FROM actions WHERE nonce=?', (challenge['nonce'],)).fetchone()
        require(record is not None and record[0] == canonical(challenge) and record[1] == 0, 'action-not-outstanding')
        require(challenge['created_at'] <= now <= challenge['expires_at'], 'action-expired')
        indexes = indexes_for(challenge['facts'])
        require(presentation['disclose'] == indexes, 'presentation-disclosure')
        attributes = presentation['attributes']
        require(type(attributes) is list and len(attributes) == len(indexes) and
                all(type(v) is str and len(v) <= 128 for v in attributes), 'presentation-attributes')
        require(attributes[:3] == [PROFILE,SOURCE,POLICY_HASH], 'presentation-policy')
        require(all(v.isascii() and v.isdecimal() and str(int(v)) == v for v in attributes[3:5]), 'presentation-time')
        start, end = map(int, attributes[3:5])
        require(start > 0 and start % 3600 == 0 and end == start + 86400 and start <= now < end,
                'credential-expired-or-invalid')
        require(all(v == '1' for v in attributes[5:]), 'presentation-fact-false')
        self.crypto.call('verify', public_key=self.issuer, proof=presentation['proof'],
            attributes=attributes, disclose=indexes, context=canonical(challenge).hex())
        # Cryptographic work occurs before this atomic single-use transition.
        changed = self.db.execute('UPDATE actions SET used=1 WHERE nonce=? AND used=0 AND body=?',
            (challenge['nonce'], canonical(challenge))).rowcount
        require(changed == 1, 'action-replay')
        return {'profile': PROFILE, 'laboratory': True, 'verified': False,
                'cryptographic_proof_valid': True, 'source': SOURCE,
                'facts': challenge['facts'], 'observation_window_start': start, 'expires_at': end,
                'hardware_verified': False, 'source_honesty_required': True}


def production_readiness():
    # No boolean option bypasses these. Each needs a real implementation and
    # authoritative acceptance evidence before a production issuer is exposed.
    return {'ready': False, 'blockers': [
        'measured-issuer-image-and-bound-hardware-acceptance',
        'attestation-gated-api-and-issuer-key-provisioning',
        'rollback-resistant-account-registry-and-revocation',
        'hidden-index-revocation-and-atomic-account-replacement',
        'protected-desktop-secret-storage-and-browser-flow',
        'live-provider-and-public-challenge-acceptance',
        'public-zkid-same-secret-binding-and-alias-uniqueness',
    ]}
