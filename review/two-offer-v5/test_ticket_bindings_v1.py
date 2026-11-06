"""Real crypto + simulated atomic S3; not evidence of deployed AWS controls."""
from concurrent.futures import ThreadPoolExecutor
import io
import threading
import unittest

from policy import Rejected
from test_ticket_native_v1 import Tickets
from ticket_bindings_v1 import S3BindingJournal, TicketBindings


class ServiceError(Exception):
    def __init__(self, code): self.response = {'Error': {'Code': code}}


class AtomicS3Fixture:
    def __init__(self):
        self.records, self.lock, self.mode, self.puts = {}, threading.Lock(), None, []

    def put_object(self, **args):
        with self.lock:
            self.puts.append(args)
            if self.mode == 'before': raise TimeoutError()
            if args['Key'] in self.records: raise ServiceError('PreconditionFailed')
            if args['IfNoneMatch'] != '*': raise AssertionError('unsafe write')
            self.records[args['Key']] = args['Body']
            if self.mode == 'after': raise TimeoutError()
            return {}

    def get_object(self, **args):
        with self.lock:
            if self.mode == 'read': raise TimeoutError()
            if args['Key'] not in self.records: raise ServiceError('NoSuchKey')
            body = self.records[args['Key']]
            return {'Body': io.BytesIO(body), 'ContentLength': len(body)}


class Bindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Tickets.setUpClass()
        cls.crypto = Tickets()

    def setUp(self):
        self.protocol = self.crypto.protocol()
        self.s3 = AtomicS3Fixture()
        self.journal = S3BindingJournal(self.s3, 'lab-private-journal',
            'ticket-bindings-v1/'+self.protocol.parameters.hex()+'/')
        self.bindings = TicketBindings(self.protocol, self.journal)
        pending = self.protocol.prepare()
        self.token = self.protocol.finalize(pending, self.crypto.sign(pending['request']['blinded']))

    def test_restore_cannot_make_old_binding_unspent(self):
        first = self.bindings.bind(self.token, 'ab'*32)
        # Discard all service-local state and reconstruct from the same durable
        # authority, as after restoring a DB from before the redemption.
        restored = TicketBindings(self.crypto.protocol(), self.journal)
        self.assertEqual(restored.bind(self.token, 'ab'*32), first)
        with self.assertRaises(Rejected): restored.bind(self.token, 'cd'*32)
        self.assertEqual(len(self.s3.records), 1)
        self.assertEqual(set(first), {'profile','parameters','nullifier','bundle_hash','operation'})
        for args in self.s3.puts:
            self.assertEqual(args['IfNoneMatch'], '*')
            self.assertEqual(args['ServerSideEncryption'], 'AES256')

    def test_concurrent_different_bundles_have_one_permanent_winner(self):
        hashes = ['%02x'%i*32 for i in range(1,9)]
        def bind(h):
            try: return self.bindings.bind(self.token,h)
            except Rejected: return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(bind,hashes))
        winners = [r for r in results if r is not None]
        self.assertEqual(len(winners),1)
        self.assertEqual(len(self.s3.records),1)
        self.assertEqual(self.bindings.bind(self.token,winners[0]['bundle_hash']),winners[0])

    def test_lost_write_reply_recovers_without_new_binding(self):
        self.s3.mode = 'after'
        first = self.bindings.bind(self.token,'11'*32)
        self.s3.mode = None
        self.assertEqual(self.bindings.bind(self.token,'11'*32),first)
        with self.assertRaises(Rejected): self.bindings.bind(self.token,'22'*32)

    def test_unknown_authority_never_uses_a_local_unspent_assumption(self):
        self.s3.mode = 'before'
        with self.assertRaises(Rejected): self.bindings.bind(self.token,'11'*32)
        self.assertFalse(self.s3.records)
        self.s3.mode = 'read'
        with self.assertRaises(Rejected): self.bindings.bind(self.token,'11'*32)
        # The write DID happen, even though neither write nor read result was
        # observable by the caller. Later recovery must retain that first hash.
        self.s3.mode = None
        with self.assertRaises(Rejected): self.bindings.bind(self.token,'22'*32)
        self.assertEqual(self.bindings.bind(self.token,'11'*32)['bundle_hash'],'11'*32)

    def test_bad_ticket_cannot_allocate_a_binding(self):
        token = dict(self.token, signature='AA==')
        with self.assertRaises(Rejected): self.bindings.bind(token,'11'*32)
        self.assertFalse(self.s3.puts)
        with self.assertRaises(Rejected): self.bindings.bind(self.token,'not-a-hash')
        self.assertFalse(self.s3.puts)


if __name__ == '__main__': unittest.main()
