"""Optional authenticated LOCAL memoization, never imported server verdicts.

A separate Secret Service key authenticates results previously checked by this
installation. Its exact attributes derive from the installer-owned cache path,
never a cache file. Cache bytes alone cannot select a key or mint a verdict.
No wallet/holder key is opened. Missing/locked keyring means recompute, without
prompts or plaintext-key fallback. Same-user malicious code/keyring compromise
is outside this optimization's boundary (it can also change the verifier).
"""
import hashlib
import hmac
from pathlib import Path
import secrets

from bundle_disk_cache import DiskPublicCache, LazyCheckpointStore
from policy import canonical, hex_string, require, strict_json
from wallet import SecretService, KeyStoreRejected

PROFILE = 'nockapp-local-verified-result-cache-v1'
PREFIX = b'NOCKAPP-LOCAL-CACHE-INTEGRITY-v1:'
DOMAIN = b'NOCKAPP/LOCAL/VERIFIED-RESULT/v1\0'
MAX_VALUE = 65536


class CacheSecretService(SecretService):
    @staticmethod
    def attributes(key_id):
        hex_string(key_id, 32)
        return ['application', 'org.nockapp.ZKID.LocalVerificationCache',
                'cache-key-id', key_id, 'format', '1']

    def store(self, key_id, value):
        self.ready()
        status, output, error = self._run([
            '/usr/bin/secret-tool', 'store', '--label=NockApp local verification cache integrity',
            *self.attributes(key_id)], value, limit=1024)
        require(not status and not output and not error, 'cache-key-unavailable')


class CacheIntegrityKey:
    """Dedicated optional key. Creation only after a verified result, under lock.

    No item enumeration, owner credential lookup, deletion, rotation or retry.
    A failed attempt disables persistence for this instance. Memory reuse needs
    no further keyring requests. Lost keys merely invalidate old cache entries.
    """
    def __init__(self, directory):
        self.key_id = hashlib.sha256(canonical({'profile': PROFILE,
            'directory': str(Path(directory))})).hexdigest()[:32]
        self._value = None
        self.disabled = False

    @staticmethod
    def _decode(encoded):
        require(type(encoded) is bytes and encoded.startswith(PREFIX), 'cache-key-unavailable')
        text = encoded[len(PREFIX):].removesuffix(b'\n').decode('ascii')
        hex_string(text, 64)
        return bytes.fromhex(text)

    def key(self, create=False):
        if self.disabled: return None
        if self._value is not None: return self._value
        try:
            service = CacheSecretService()
            try: value = self._decode(service.lookup(self.key_id))
            except KeyStoreRejected as error:
                if str(error) != 'holder-key-missing': raise
                if not create: return None
                value = secrets.token_bytes(32)
                service.store(self.key_id, PREFIX + value.hex().encode('ascii'))
                require(hmac.compare_digest(value, self._decode(service.lookup(self.key_id))),
                        'cache-key-unavailable')
            self._value = value
            return value
        except Exception:
            self.disabled = True
            return None


def validate_value(value):
    require(type(value) is dict and set(value) == {'checked', 'dependencies'}
        and type(value['checked']) is dict and value['checked'].get('authorship_checked') is True
        and type(value['dependencies']) is list and len(value['dependencies']) <= 32
        and all(type(row) is dict for row in value['dependencies'])
        and len(canonical(value)) <= MAX_VALUE, 'verified-cache-value')
    return value


class DiskVerifiedResultCache(DiskPublicCache):
    object_limit = MAX_VALUE + 512

    def __init__(self, directory, key_provider, **limits):
        self.key_provider = key_provider
        super().__init__(directory, **limits)

    def _validate_bytes(self, digest, data):
        require(type(data) is bytes and 0 < len(data) <= self.object_limit, 'verified-cache-envelope')
        envelope = strict_json(data, max_bytes=self.object_limit)
        require(type(envelope) is dict and set(envelope) == {'profile', 'key', 'value', 'mac'}
            and envelope['profile'] == PROFILE and envelope['key'] == digest
            and canonical(envelope) == data, 'verified-cache-envelope')
        hex_string(envelope['mac'], 64)
        value = validate_value(envelope['value'])
        key = self.key_provider.key(False)
        require(type(key) is bytes and len(key) == 32 and hmac.compare_digest(envelope['mac'],
            hmac.new(key, DOMAIN + canonical({'key': digest, 'value': value}), hashlib.sha256).hexdigest()),
            'verified-cache-authentication')
        return value

    def get_result(self, digest):
        raw = super().get(digest)
        return None if raw is None else strict_json(raw, max_bytes=self.object_limit)['value']

    def put_result(self, digest, value):
        self._digest(digest)
        value = validate_value(value)
        # Serializes first-time Secret Service creation across helper processes.
        # No cache bytes/key identifier can supply or replace this secret.
        with self._lock():
            key = self.key_provider.key(True)
            if type(key) is not bytes or len(key) != 32: return False
            mac = hmac.new(key, DOMAIN + canonical({'key': digest, 'value': value}), hashlib.sha256).hexdigest()
            data = canonical({'profile': PROFILE, 'key': digest, 'value': value, 'mac': mac})
        return super().put(digest, data)


class LazyVerifiedResultCache(LazyCheckpointStore):
    """Dedicated bounded cache; absent get/clear creates no key or app state."""
    def __init__(self, directory, *, key_provider=None, max_bytes=8*1024*1024, max_entries=256):
        require(type(max_bytes) is int and 0 < max_bytes <= 32*1024*1024
            and type(max_entries) is int and 0 < max_entries <= 1024, 'verified-cache-limit')
        super().__init__(directory)
        self.key_provider = key_provider if key_provider is not None else CacheIntegrityKey(self.root)
        self.max_bytes, self.max_entries = max_bytes, max_entries

    def _make_cache(self):
        return DiskVerifiedResultCache(self.root, self.key_provider,
            max_bytes=self.max_bytes, max_entries=self.max_entries)

    def get(self, key):
        DiskPublicCache._digest(key)
        try:
            cache = self._open(False)
            if cache is None: return None
            value = cache.get_result(key)
            self.fault = cache.fault
            return value
        except Exception:
            self.fault = 'cache-unavailable'
            return None

    def put(self, key, value):
        DiskPublicCache._digest(key)
        validate_value(value)
        try:
            cache = self._open(True)
            if cache is None: return False
            result = cache.put_result(key, value)
            self.fault = cache.fault
            return result
        except Exception:
            self.fault = 'cache-unavailable'
            return False
