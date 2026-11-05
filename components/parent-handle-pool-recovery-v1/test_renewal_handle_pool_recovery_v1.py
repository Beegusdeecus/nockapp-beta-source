"""Real native crypto and EVM cold boots; only synthetic identities/state/source."""
import copy
import secrets
import unittest
from unittest.mock import patch

from authorship import AuthorshipNative
from base_finality import LeasedIssuer
from count_pipeline import CountNative
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from domain_state import LIMIT
from policy import Rejected,canonical
import public_renewal_service_v1 as service
from renewal_native_v3 import RenewalNative,public_view
import test_domain_pipeline as domain
import test_public_renewal_service_v1 as integration
from test_zkid import NOW


class PoolCryptoTests(unittest.TestCase):
    def setUp(self):
        self.f=domain.DomainPipelineTests();self.f.setUp()

    def test_appending_inactive_names_keeps_keys_accumulator_and_old_credential(self):
        _,_,held,_=self.f.stage();core=self.f.issuer
        core._next=len(core._handles)  # Synthetic prior boots burned the pool.
        before=copy.deepcopy({k:v for k,v in core.__dict__.items() if k not in ('_lock','native')})
        before_issuer=copy.deepcopy(core._issuer)
        service.extend_inactive_boot_pool(core,4)
        self.assertEqual(core._handles[:16],before['_handles']);self.assertEqual(core._next,16)
        self.assertEqual(len(set(core._handles)),20)
        restored=copy.deepcopy(core._issuer);restored['revocation_registry']['elements']=before_issuer['revocation_registry']['elements']
        self.assertEqual(restored,before_issuer)
        self.assertEqual(core.public,before['public']);self.assertEqual(core._accounts,before['_accounts'])
        self.assertEqual(core._pending,before['_pending'])
        self.assertEqual(core._issuer['revocation_registry']['elements'],core._handles)
        fresh=core._handles[16]
        with self.assertRaises(Rejected):core.native.call('witness',issuer=core._issuer,handle=fresh)
        v,c,p=self.f.proof(held);self.assertTrue(v.verify(p,c,NOW+5)['cryptographic_proof_valid'])
        self.f.stage(account='555555555555')  # The unchanged native accepts a new name.
        v,c,p=self.f.proof(held);self.assertTrue(v.verify(p,c,NOW+5)['cryptographic_proof_valid'])

    def test_collision_or_limit_cannot_reuse_old_names_or_partially_mutate(self):
        core=self.f.issuer;core._next=len(core._handles);before=copy.deepcopy(core._issuer);names=list(core._handles)
        with patch.object(service,'MAX_PRIVATE_HANDLES',len(names)+1):
            with self.assertRaisesRegex(Rejected,'issuer-handle-pool-limit'):service.extend_inactive_boot_pool(core,2)
        self.assertEqual(core._issuer,before);self.assertEqual(core._handles,names)
        with patch.object(service.secrets,'token_hex',return_value=names[0]):
            with self.assertRaisesRegex(Rejected,'issuer-handle-generation'):service.extend_inactive_boot_pool(core,2)
        self.assertEqual(core._issuer,before);self.assertEqual(core._handles,names)

    def test_state_size_cap_remains_fail_closed_without_pruning_pending_delivery(self):
        self.f.stage(commit=False);core=self.f.issuer
        pending=next(iter(core._pending.values()))
        pending['response']['synthetic_fixture_padding']='x'*LIMIT
        before=copy.deepcopy(core._pending)
        state=object.__new__(service.RecoveringRenewalIssuer)
        state.namespace=core.definition_hash;state._cipher=AESGCM(secrets.token_bytes(32))
        state.count_native=CountNative();state.renewal_native=RenewalNative()
        with self.assertRaisesRegex(Rejected,'^issuer-state-capacity$'):state._seal(core,1)
        self.assertEqual(core._pending,before)


class ColdBootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):integration.PublicRenewalTests.setUpClass()

    def test_more_boot_reservations_than_original_pool_then_real_issuance(self):
        f=integration.PublicRenewalTests();f.setUp();self.addCleanup(f.doCleanups)
        live=f.make();_,first=live.state.load()
        original=copy.deepcopy(first._issuer);accounts=copy.deepcopy(first._accounts)
        names=list(first._handles);initial_count=len(names);start=first._next
        original_failure=False
        for _ in range(4):
            _,core=live.state.load()
            if core._next+3>len(core._handles):
                finite=copy.copy(live.state);finite.ready=False;finite.boot_receipt=None
                with self.assertRaisesRegex(Rejected,'^registry-capacity$'):LeasedIssuer.begin_boot(finite,3)
                original_failure=True
            live=f.make()
        self.assertTrue(original_failure)
        _,restored=live.state.load()
        self.assertGreater(restored._next,initial_count)
        self.assertEqual(restored._next,start+12)
        self.assertEqual(restored._handles[:initial_count],names)
        self.assertEqual(restored._accounts,accounts)
        self.assertEqual(restored._issuer['signing_key'],original['signing_key'])
        self.assertEqual(restored._issuer['revocation_registry']['value'],original['revocation_registry']['value'])
        remote=f.remote(live);f.provider.resolve.return_value='555555555555'
        public=public_view(f.native,remote.call('registry',{}))['public']
        secret=AuthorshipNative().call('generate')['secret']
        pending=f.native.call('prepare',public=public,secret=secret)
        begun=remote.call('begin',{'request':pending['request'],'desktop_nonce':secrets.token_hex(32),
            'username':'synthetic_new','approve_public_profile_lookup':True})
        issued=remote.call('check-post',{'session':begun['session'],'tweet_id':'3141592653589793','approve_source_check':True})
        received=f.native.call('receive',pending=pending['pending'],bundle=issued['bundle'],public=public,attributes=issued['attributes'])
        remote.call('commit',{'session':begun['session'],'ack':received['ack']})
        self.assertTrue(remote.call('activation-status',{'session':begun['session']})['active'])
        _,after=live.state.load()
        for account,handle in accounts.items():self.assertEqual(after._accounts[account],handle)
        self.assertEqual(after._issuer['signing_key'],original['signing_key'])


if __name__=='__main__':unittest.main()
