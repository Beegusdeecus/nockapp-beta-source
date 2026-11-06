"""Real TLS/conditional signed writes with synthetic S3 responses and budgets."""
import unittest
from policy import Rejected
from public_bundle_v5 import MAX_BYTES
from test_public_s3_v5 import OriginTests
from test_public_s3 import stored,HOST
from test_provider_tls import server,response


class RepairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):OriginTests.setUpClass()
    def setUp(self):self.f=OriginTests();self.f.setUp()
    def test_corrupt_version_repaired_conditionally_and_exact_concurrent_readback_resolves(self):
        etag='"'+'ab'*16+'"'
        for status in (200,412):
            with server([stored(b'corrupt',self.f.until,etag=etag),response(b'',status),
                    stored(self.f.data,self.f.until)],hostname=HOST)as(ctx,dial,seen):
                result=self.f.origin(ctx,dial,write=True).restore(self.f.digest,self.f.data)
            self.assertTrue(result['readback_checked']);self.assertEqual(len(seen),3)
            self.assertIn(('If-Match: '+etag).encode(),seen[1])
            self.assertNotIn(b'If-None-Match:',seen[1]);self.assertIn(b'if-match',seen[1])
            self.assertEqual(sum(req.startswith(b'PUT ')for req in seen),1)

    def test_inaccessible_object_allows_only_conditional_create_and_never_claims_success_without_readback(self):
        with server([response(b'',403),response(b'',412),response(b'',403)],hostname=HOST)as(ctx,dial,seen):
            with self.assertRaises(Rejected):self.f.origin(ctx,dial,write=True).restore(self.f.digest,self.f.data)
        self.assertEqual(len(seen),3);self.assertIn(b'If-None-Match: *',seen[1]);self.assertNotIn(b'If-Match:',seen[1])

    def test_probe_distinguishes_absence_integrity_and_unavailable_without_credentials(self):
        for raw,state in ((response(b'',404),'missing'),(response(b'',403),'inaccessible'),
                (response(b'',503),'unavailable'),(stored(b'corrupt',self.f.until),'corrupt'),
                (stored(self.f.data,self.f.until),'present')):
            with server([raw],hostname=HOST)as(ctx,dial,seen):
                self.assertEqual(self.f.origin(ctx,dial).probe(self.f.digest,MAX_BYTES),{'state':state})
            self.assertNotIn(b'Authorization:',seen[0])
