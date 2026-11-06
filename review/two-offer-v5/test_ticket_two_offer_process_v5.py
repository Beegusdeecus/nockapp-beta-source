"""Versioned launcher admission; synthetic metadata, no private packet/cloud IO."""
import copy,io,threading,unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from policy import canonical,digest,Rejected
from batch_checkout_v2.offer import PROFILE,manifest_hash
from ticket_offer_overlay_v1 import PROFILE as OVERLAY
import ticket_renewing_process_v3 as process
import ticket_renewing_process_v2 as original
import test_ticket_renewing_process_v2 as fixtures

class ProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixtures.AdmissionTests.setUpClass()
    @classmethod
    def tearDownClass(cls):fixtures.AdmissionTests.tearDownClass()
    def setUp(self):
        self.f=fixtures.AdmissionTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        base=copy.deepcopy(self.f.value);manifest=copy.deepcopy(base['backend']['offer'])
        manifest['terms'].update(profile=PROFILE,payment_receipt_version=2,packs_per_payment=25)
        manifest.update(purchase_contract='0x'+'12'*20,purchase_runtime_keccak='0x'+'ab'*32)
        overlay={'profile':OVERLAY,'base_backend_sha256':base['backend_sha256'],
            'offer':manifest,'offer_sha256':manifest_hash(manifest)}
        self.value={'profile':process.PROFILE_OFFERS,'base':base,'base_sha256':digest(base),
            'offer_overlay':overlay,'offer_overlay_sha256':digest(overlay)}
    def test_frozen_check_keeps_original_backend_sealed_record_resources_and_broker(self):
        saved=canonical(self.value['base']);path=self.f.f.root/'two-offers.json';path.write_bytes(canonical(self.value));path.chmod(0o600)
        out=io.StringIO()
        with patch.object(original,'assemble_sealed',side_effect=AssertionError('no private recovery')),\
                patch.object(process.legacy,'resources_build',side_effect=AssertionError('no credentials')),\
                patch('socket.create_connection',side_effect=AssertionError('no network')),redirect_stdout(out):
            self.assertEqual(process.main(['check','--deployment',str(path),'--sha256',digest(self.value)]),0)
        self.assertIn('"private_packet_read":false',out.getvalue());self.assertIn(process.PROFILE_OFFERS,out.getvalue())
        self.assertEqual(canonical(self.value['base']),saved)
    def test_old_profiles_unknown_authorities_and_changed_base_cannot_adopt_overlay(self):
        with self.assertRaises(Rejected):original.preflight(self.value,digest(self.value))
        for mutate in(lambda v:v.update(base_sha256='11'*32),
            lambda v:v['offer_overlay']['offer']['terms'].update(pack_price_wei='1'),
            lambda v:v['base'].update(profile=process.PROFILE_STORAGE),
            lambda v:v.update(allow_any_offer=True)):
            bad=copy.deepcopy(self.value);mutate(bad)
            with self.assertRaises(Rejected):process.preflight(bad,digest(bad))
    def test_worker_handoff_uses_exact_original_configuration_and_explicit_pinned_overlay(self):
        base=copy.deepcopy(self.value['base']);notifier=fixtures.Notification();stop=threading.Event()
        with patch.object(process.legacy,'harden_process'),patch.object(original,'serve',return_value={'phase':'stopped','drained':True})as runner:
            result=process.serve(self.value,digest(self.value),stop,notifier)
        runner.assert_called_once_with(base,digest(base),stop,notifier,offer_overlay={
            'plan':self.value['offer_overlay'],'sha256':self.value['offer_overlay_sha256']})
        self.assertEqual(result['profile'],process.PROFILE_OFFERS)
        self.assertTrue(result['original_sealed_packet_unchanged'])
if __name__=='__main__':unittest.main()
