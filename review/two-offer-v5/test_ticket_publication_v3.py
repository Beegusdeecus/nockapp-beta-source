"""Actual authored bytes/EVM/managed journal; synthetic storage and finality."""
import copy,unittest
from unittest.mock import patch
from base_protocol import sha
from public_bundle_v5 import encode
from policy import Rejected,canonical
from ticket_publication_v3 import IndexFirstPublicationWorker
from ticket_service_v3 import request,validate_request,PublicationApplicationV3
import test_ticket_publication_v2 as fixture
import base64


class IndexFirstTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixture.PublicationTests.setUpClass()
    def setUp(self):
        self.f=fixture.PublicationTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.origin.restore=self.f.origin.put
        self.worker=self.make(self.f.queue)
    def make(self,queue):
        return IndexFirstPublicationWorker(self.f.offer,queue,self.f.index,self.f.content,
            self.f.author,resolve_original=self.f.reader.resolve_original)
    def post(self):
        with patch.object(self.f.content,'upload',return_value=None):h,value=self.f.post()
        return h,encode(value)
    def finalize(self,h,raw):
        result=self.worker.submit(self.f.tokens[0],h,raw)
        for _ in range(3):
            if result['state']=='indexed':return result
            result=self.worker.submit(self.f.tokens[0],h,raw)
        self.fail('synthetic finality did not index')

    def test_storage_is_after_final_index_and_restore_changes_no_ticket_nonce_or_number(self):
        h,raw=self.post()
        with self.assertRaisesRegex(Rejected,'index-not-finalized'):self.worker.store(h,raw)
        self.assertEqual(self.f.origin.puts,0)
        result=self.finalize(h,raw);self.assertEqual(self.f.origin.puts,0)
        job=self.f.queue.lookup(self.f.offer.protocol.verify(self.f.tokens[0]),h)
        nonce=self.f.rpc.call('eth_getTransactionCount',self.f.signer.address,'latest')
        stored=self.worker.store(h,raw);self.assertTrue(stored['readback_checked'])
        self.f.origin.objects[h]=b'corrupt fixture';self.f.content.clear()
        self.worker.store(h,raw)
        self.assertEqual(self.f.origin.objects[h],raw)
        self.assertEqual(self.f.index.record_for_hash(h)['post_number'],result['post_number'])
        self.assertEqual(self.f.rpc.call('eth_getTransactionCount',self.f.signer.address,'latest'),nonce)
        self.assertEqual(self.f.queue.lookup(self.f.offer.protocol.verify(self.f.tokens[0]),h),job)

    def test_admission_crash_recovers_same_approved_hash_without_public_files(self):
        h,raw=self.post()
        with patch.object(self.worker,'_resume',side_effect=OSError('synthetic-after-admission')):
            with self.assertRaises(OSError):self.worker.submit(self.f.tokens[0],h,raw)
        restarted=self.make(self.f.make_queue())
        for _ in range(3):restarted.recover_pending(4)
        record=self.f.index.record_for_hash(h);self.assertIsNotNone(record)
        self.assertEqual(self.f.origin.puts,0)
        self.assertEqual(self.f.rpc.call('eth_getTransactionCount',self.f.signer.address,'latest'),'0x1')

    def test_invalid_authorship_is_neither_admitted_nor_served_after_direct_garbage_index(self):
        h,raw=self.post()
        import json
        value=json.loads(raw);value['unsigned']['core']['post']['body']='forged'
        forged=canonical(value);bad=sha(forged)
        with self.assertRaises(Rejected):self.worker.submit(self.f.tokens[0],bad,forged)
        from permissionless_index import submission_data
        self.f.f.rpc.tx(self.f.f.accounts[2],submission_data(bad),self.f.contract)
        with self.assertRaises(Rejected):self.worker.store(bad,forged)
        self.assertEqual(self.f.origin.puts,0)

    def test_store_rpc_has_no_ticket_or_charge_authority_and_never_admits_unindexed_bytes(self):
        h,raw=self.post();body={'bundle_hash':h,'bundle_base64':base64.b64encode(raw).decode()}
        message=request(self.f.offer.hash,'store',body)
        app=PublicationApplicationV3(self.worker)
        self.assertEqual(app.dispatch(message)['status'],'rejected')
        with self.assertRaises(Rejected):validate_request({**message,'body':{**body,'ticket':self.f.tokens[0]}},self.f.offer.hash,'publication')
        with self.assertRaises(Rejected):validate_request({**message,'profile':'nockapp-prepaid-service-rpc-v2'},self.f.offer.hash,'publication')
        self.finalize(h,raw)
        self.assertEqual(app.dispatch(message)['status'],'ok')
