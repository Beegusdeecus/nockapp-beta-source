"""Actual pipe-worker tests with ephemeral lab keys; no payment/live claim."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from policy import Rejected, canonical, strict_json
from ticket_native_v1 import TicketNative, TicketProtocol

WORKER = Path(__file__).resolve().parent/'local/ticket-tools/nockapp-ticket-worker-v1'


class Tickets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = TicketNative(WORKER, hashlib.sha256(WORKER.read_bytes()).hexdigest())
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.private = key.private_bytes(serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        cls.public = key.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.params = hashlib.sha256(b'LAB ONLY manifest: no real payment parameters').digest()

    def protocol(self, params=None):
        return TicketProtocol(self.native, self.public, params or self.params)

    def sign(self, blinded):
        return self.native._call('blind-sign', private_key=base64.b64encode(self.private).decode(), blinded=blinded)['signature']

    def test_recovered_private_state_produces_same_unlinkable_public_token(self):
        p = self.protocol()
        pending = [p.prepare(), p.prepare()]
        public = p.blinded_pack(pending)
        self.assertEqual(set(public), {'profile', 'parameters', 'blinded'})
        self.assertNotEqual(public['blinded'][0], public['blinded'][1])
        replies = [self.sign(b) for b in public['blinded']]
        restored = strict_json(canonical({'tickets': pending}), max_bytes=65536)['tickets']
        fresh = self.protocol()
        token = fresh.finalize(restored[0], replies[0])
        self.assertEqual(token, fresh.finalize(restored[0], replies[0]))
        self.assertEqual(len(p.verify(token)), 64)
        other = fresh.finalize(restored[1], replies[1])
        self.assertNotEqual(p.verify(token), p.verify(other))
        self.assertEqual(set(token), {'profile', 'parameters', 'prepared', 'signature'})
        self.assertNotIn(public['blinded'][0], json.dumps(token))
        self.assertNotIn(restored[0]['request']['recovery'], json.dumps(token))
        with self.assertRaises(Rejected): fresh.finalize(restored[1], replies[0])

    def test_shared_parameters_and_exact_bytes_enforced(self):
        p = self.protocol(); pending = p.prepare()
        token = p.finalize(pending, self.sign(pending['request']['blinded']))
        other = self.protocol(hashlib.sha256(b'other manifest').digest())
        with self.assertRaises(Rejected): other.verify(token)
        altered = dict(token, parameters=other.parameters.hex())
        with self.assertRaises(Rejected): other.verify(altered)
        for field in ('wallet', 'twitter', 'account_id', 'zkid', 'purchase_id', 'blinded'):
            with self.assertRaises(Rejected): p.verify(dict(token, **{field:'tag'}))
        damaged = dict(token)
        raw = bytearray(base64.b64decode(damaged['prepared'])); raw[-1] ^= 1
        damaged['prepared'] = base64.b64encode(raw).decode()
        with self.assertRaises(Rejected): p.verify(damaged)
        with self.assertRaises(Rejected): p.blinded_pack([pending, pending])
        with self.assertRaises(Rejected): p.blinded_pack([])
        with self.assertRaises(Rejected): p.blinded_pack([pending]*33)

    def test_no_unpinned_binary_or_weak_key(self):
        with self.assertRaises(Rejected): TicketNative(WORKER, '0'*64)
        with tempfile.TemporaryDirectory() as d:
            copy = Path(d)/'worker'; copy.write_bytes(WORKER.read_bytes()); copy.chmod(0o700)
            n = TicketNative(copy, hashlib.sha256(copy.read_bytes()).hexdigest())
            with copy.open('ab') as f: f.write(b'changed')
            with self.assertRaises(Rejected): TicketProtocol(n,self.public,self.params).prepare()
        weak = rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key()
        der = weak.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(Rejected): TicketProtocol(self.native,der,self.params)


if __name__ == '__main__': unittest.main()
