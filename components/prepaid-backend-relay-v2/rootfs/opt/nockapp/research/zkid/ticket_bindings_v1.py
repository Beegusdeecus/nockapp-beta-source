"""Exact one-use binding backed by a separate conditional-write authority.

A local database may be a rebuildable projection ONLY. It cannot establish that
a ticket is unspent. No signer/broadcaster or refund/reset operation exists here.
Production needs the private S3 journal's conditional-write/delete-denial policy
and recovery controls verified separately; versioning alone is insufficient.
"""
import base64
import hashlib
import re

from policy import canonical, require, strict_json, Rejected
from ticket_native_v1 import TicketProtocol

BINDING_PROFILE = 'nockapp-ticket-exact-binding-v1'


def _hash(value):
    require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value), 'ticket-binding-hash')
    return value


class ConditionalS3Records:
    """Bounded write-once records for an installer-owned private namespace.

    Deployment MUST deny overwrites lacking If-None-Match:* and all deletions
    (including delete markers), lifecycle expiration and namespace replacement.
    A restored local DB never replaces this authority. Losing/rolling back this
    authority requires stopping this ticket version, not starting an empty one.
    """
    def __init__(self, client, bucket, prefix, max_record):
        require(type(bucket) is str and re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket), 'ticket-journal-bucket')
        require(type(prefix) is str and re.fullmatch(r'ticket-(?:bindings-v1/[0-9a-f]{64}/|purchases-v1/[0-9a-f]{64}/(?:decisions|results)/)',prefix),'ticket-journal-prefix')
        require(type(max_record) is int and 0<max_record<=32768,'ticket-journal-size')
        self.client, self.bucket, self.prefix = client, bucket, prefix
        self.max_record = max_record

    def _key(self, nullifier):
        return self.prefix + _hash(nullifier) + '.json'

    def read(self, nullifier):
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=self._key(nullifier))
        except Exception as error:
            code = getattr(error, 'response', {}).get('Error', {}).get('Code')
            if code == 'NoSuchKey': return None
            raise Rejected('ticket-journal-unavailable') from None
        body = response.get('Body')
        try:
            require(type(response.get('ContentLength')) is int and 0 < response['ContentLength'] <= self.max_record,
                    'ticket-journal-size')
            data = body.read(self.max_record+1)
            require(type(data) is bytes and len(data) == response['ContentLength'], 'ticket-journal-size')
            return data
        except Rejected:
            raise
        except Exception:
            raise Rejected('ticket-journal-unavailable') from None
        finally:
            if body is not None:
                try: body.close()
                except Exception: pass

    def create(self, nullifier, data):
        require(type(data) is bytes and 0 < len(data) <= self.max_record, 'ticket-journal-size')
        try:
            self.client.put_object(Bucket=self.bucket, Key=self._key(nullifier), Body=data,
                ContentType='application/json', IfNoneMatch='*',
                ChecksumSHA256=base64.b64encode(hashlib.sha256(data).digest()).decode('ascii'),
                ServerSideEncryption='AES256')
        except Exception:
            # A lost response can mean the write succeeded. Never infer unspent
            # from the exception or allocate a different operation in this call.
            pass
        observed = self.read(nullifier)
        require(observed is not None, 'ticket-binding-uncertain')
        return observed


class S3BindingJournal(ConditionalS3Records):
    """Compatibility-preserving exact ticket/hash namespace, maximum 2 KiB."""
    def __init__(self,client,bucket,prefix):
        require(type(prefix) is str and re.fullmatch(r'ticket-bindings-v1/[0-9a-f]{64}/',prefix),'ticket-journal-prefix')
        super().__init__(client,bucket,prefix,2048)


class TicketBindings:
    """Authenticate first, then atomically create/read the permanent binding.

    journal.create(nullifier, bytes) must provide write-if-absent semantics and
    return the authoritative winning bytes. Adapters cannot implement it using
    a read followed by an unconditional write. No local fallback is supported.
    """
    def __init__(self, protocol, journal):
        require(isinstance(protocol, TicketProtocol), 'ticket-binding-protocol')
        self.protocol, self.journal = protocol, journal

    def bind(self, token, bundle_hash):
        bundle_hash = _hash(bundle_hash)
        nullifier = self.protocol.verify(token)
        operation = hashlib.sha256(b'nockapp-ticket-operation-v1\0' +
            self.protocol.parameters + bytes.fromhex(nullifier)).hexdigest()
        proposed = {'profile': BINDING_PROFILE, 'parameters': self.protocol.parameters.hex(),
            'nullifier': nullifier, 'bundle_hash': bundle_hash, 'operation': operation}
        encoded = canonical(proposed)
        observed = self.journal.create(nullifier, encoded)
        require(type(observed) is bytes and len(observed) <= 2048, 'ticket-binding-record')
        record = strict_json(observed, max_bytes=2048)
        require(canonical(record) == observed and record == proposed, 'ticket-already-bound')
        return record
