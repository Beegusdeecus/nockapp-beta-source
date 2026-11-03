"""Pinned RFC9474 private-pipe primitive; no HTTP listener or payment authority.

Pending purchase records include PRIVATE blinding randomness. Their persistence
belongs in encrypted client storage, never public bundles or purchase requests.
Only `blinded_pack` is suitable for the paid issuance endpoint.
"""
import base64
import hashlib
from pathlib import Path
import secrets
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from policy import canonical, require, strict_json, Rejected

PROFILE = 'nockapp-ticket-rsabssa-sha384-pss-randomized-v1'
DOMAIN = b'nockapp-prepaid-ticket-v1\0'
MAX_PACK = 32


def _encode(data):
    return base64.b64encode(data).decode('ascii')


def _decode(value, maximum):
    require(type(value) is str and len(value) <= 4*((maximum+2)//3), 'ticket-encoding')
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        raise Rejected('ticket-encoding') from None
    require(len(raw) <= maximum and _encode(raw) == value, 'ticket-encoding')
    return raw


class TicketNative:
    """The installer supplies an independently pinned executable digest."""
    def __init__(self, binary, expected_sha256):
        self.binary = Path(binary)
        require(type(expected_sha256) is str and len(expected_sha256) == 64
                and all(c in '0123456789abcdef' for c in expected_sha256), 'ticket-worker-pin')
        self.sha256 = expected_sha256
        self._check_pin()

    def _check_pin(self):
        require(hashlib.sha256(self.binary.read_bytes()).hexdigest() == self.sha256, 'ticket-worker-changed')

    def _call(self, op, **body):
        self._check_pin()
        data = canonical({'profile': PROFILE, 'op': op, **body})
        require(len(data) <= 65536, 'ticket-request-size')
        try:
            p = subprocess.run([str(self.binary)], input=data, capture_output=True,
                timeout=15, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                    'GOMAXPROCS': '2', 'GOMEMLIMIT': '64MiB'})
            require(p.returncode == 0 and not p.stderr and len(p.stdout) <= 32768, 'ticket-native-rejected')
            result = strict_json(p.stdout, max_bytes=32768)
            require(type(result) is dict and result.get('ok') is True
                    and result.get('profile') == PROFILE, 'ticket-native-result')
            return result
        except Rejected:
            raise
        except Exception:
            raise Rejected('ticket-native-unavailable') from None


class TicketProtocol:
    """One operator-wide pinned public profile, never negotiated per buyer.

    parameter_hash must commit to the reviewed public price/limits/expiry/refund
    manifest, chain, contracts and SPKI. An arbitrary server-supplied digest is
    not sufficient. Configuration/purchase verification is a separate layer.
    """
    def __init__(self, native, public_key_der, parameter_hash):
        require(isinstance(native, TicketNative), 'ticket-native')
        require(type(public_key_der) is bytes and len(public_key_der) <= 1024, 'ticket-public-key')
        require(type(parameter_hash) is bytes and len(parameter_hash) == 32, 'ticket-parameters')
        try:
            key = serialization.load_der_public_key(public_key_der)
            require(isinstance(key, rsa.RSAPublicKey) and key.key_size == 3072
                    and key.public_numbers().e == 65537
                    and key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == public_key_der,
                    'ticket-public-key')
        except Rejected:
            raise
        except Exception:
            raise Rejected('ticket-public-key') from None
        self.native, self.key = native, _encode(public_key_der)
        self.parameters = parameter_hash

    def _prepared(self, value):
        raw = _decode(value, 32+len(DOMAIN)+64)
        require(len(raw) == 32+len(DOMAIN)+64
                and raw[32:32+len(DOMAIN)] == DOMAIN
                and raw[32+len(DOMAIN):32+len(DOMAIN)+32] == self.parameters, 'ticket-parameters')
        return raw

    def prepare(self):
        result = self.native._call('blind', public_key=self.key,
            parameters=_encode(self.parameters), serial=_encode(secrets.token_bytes(32)))
        require(set(result) == {'ok', 'profile', 'request'}, 'ticket-native-result')
        pending = {'profile': PROFILE, 'parameters': self.parameters.hex(), 'request': result['request']}
        self._pending(pending)
        return pending

    def _pending(self, pending):
        require(type(pending) is dict and set(pending) == {'profile', 'parameters', 'request'}
                and pending['profile'] == PROFILE and pending['parameters'] == self.parameters.hex(), 'ticket-pending')
        r = pending['request']
        require(type(r) is dict and set(r) == {'prepared', 'blinded', 'recovery'}, 'ticket-pending')
        self._prepared(r['prepared'])
        require(len(_decode(r['blinded'], 384)) == 384
                and 465 <= len(_decode(r['recovery'], 16417)) <= 16417, 'ticket-pending')
        return r

    def blinded_pack(self, pending):
        require(type(pending) is list and 1 <= len(pending) <= MAX_PACK, 'ticket-pack-size')
        pack = [self._pending(p)['blinded'] for p in pending]
        require(len(set(pack)) == len(pack), 'ticket-duplicate-request')
        return {'profile': PROFILE, 'parameters': self.parameters.hex(), 'blinded': pack}

    def finalize(self, pending, blind_signature):
        r = self._pending(pending)
        require(len(_decode(blind_signature, 384)) == 384, 'ticket-signature')
        result = self.native._call('finalize', public_key=self.key, **r, signature=blind_signature)
        require(set(result) == {'ok', 'profile', 'signature'}, 'ticket-native-result')
        token = {'profile': PROFILE, 'parameters': self.parameters.hex(),
                 'prepared': r['prepared'], 'signature': result['signature']}
        self.verify(token)
        return token

    def verify(self, token):
        require(type(token) is dict and set(token) == {'profile', 'parameters', 'prepared', 'signature'}
                and token['profile'] == PROFILE and token['parameters'] == self.parameters.hex(), 'ticket-token')
        prepared = self._prepared(token['prepared'])
        require(len(_decode(token['signature'], 384)) == 384, 'ticket-signature')
        result = self.native._call('verify', public_key=self.key,
                                  prepared=token['prepared'], signature=token['signature'])
        require(set(result) == {'ok', 'profile'}, 'ticket-native-result')
        # Ignore the randomized Prepare prefix: the serial determines one-use
        # identity within the shared parameters, even if a purchaser repeats it.
        return hashlib.sha256(b'nockapp-ticket-nullifier-v1\0' + self.parameters + prepared[-32:]).hexdigest()
