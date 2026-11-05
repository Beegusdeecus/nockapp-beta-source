"""Configured native signup/proof flow; real crypto, TLS and fixed local EVM.

Twitter/AWS attestation, public storage and keyring are labelled fixtures.
No installed owner state, real AWS or real wallet action is used.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import time
import unittest
import uuid
from unittest.mock import patch

from base_protocol import keccak
from policy import Rejected,canonical
from public_bundle_v5 import encode
from public_installation import BINARIES,PROFILE_DIRECT,factory,source_files,source_path,validate
from public_renewal_installation_v1 import PROFILE,PublicRenewalApplication
from test_base_enrollment import MemorySecretService
from test_public_reader_v5 import MemoryPublicOrigin
import test_public_renewal_service_v1 as serving
import renewal_transport_v3 as transport

ROOT=Path(__file__).resolve().parent


class InstallationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):serving.PublicRenewalTests.setUpClass()
    def setUp(self):
        self.case=serving.PublicRenewalTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.f=self.case.f;self.service=self.case.make();self.remote=self.case.remote(self.service)
        self.f.raw.call('evm_setNextBlockTimestamp',int(time.time()));self.f.raw.call('evm_mine')
        self.service.application.clock=self.now
        self.keyring=MemorySecretService();patcher=patch('wallet.WalletSecretService',return_value=self.keyring)
        patcher.start();self.addCleanup(patcher.stop)
        browser={'kind':'chrome','origin':'chrome-extension://'+'a'*32+'/'}
        installation={'profile':PROFILE_DIRECT,'browser':browser,'data_directory':str(Path(self.f.temp.name)/'client'),
            'chain':{'chain_id':84532,'application':self.f.proposal['application'],'contract':self.f.index,
                'runtime_keccak':keccak(bytes.fromhex(self.f.raw.call('eth_getCode',self.f.index,'latest')[2:])),
                'rpc_endpoint':'https://sepolia.base.org'},'issuer':{'definition_hash':self.f.f.namespace},
            'storage':{'region':'ap-southeast-2','bucket':'synthetic-renewal-public','account_id':'419720240831'},
            'binary_sha256':{n:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for n,p in BINARIES.items()},
            'files_sha256':{n:hashlib.sha256(source_path(ROOT,n).read_bytes()).hexdigest() for n in source_files(ROOT)},'legacy_wallets':[]}
        self.config={'profile':PROFILE,'browser':browser,'installation':installation,'registry_deployment_block':0,
            'renewal_approval':{'profile':transport.APPROVAL,'identity':copy.deepcopy(self.case.expected),
                'code_identity':'ab'*32,'state_authority_sha256':'cd'*32,'pcrs':{str(i):'ef'*48 for i in range(3)},
                'endpoint':{'profile':transport.ENDPOINT,'host':'issuer.example.com','port':443}}}
        self.origin=MemoryPublicOrigin()
    def now(self):return int(self.f.raw.call('eth_getBlockByNumber','latest',False)['timestamp'],16)
    def app(self,config=None):
        with patch('public_installation.BaseRPC',return_value=self.f.rpc),\
             patch('public_renewal_installation_v1.RenewalRemote',return_value=self.remote):
            app=factory(config or self.config,ROOT)
        app.desktop.clock=self.now;app.desktop.content.origin=self.origin
        return app
    def enroll(self,app):
        app.dispatch('public-initialize-identity',{'approve_private_key_setup':True})
        begin=app.dispatch('public-source-begin',{'username':'synthetic_user','approve_source_check':True})
        self.assertEqual(begin['state'],'waiting-for-source-post')
        result=app.dispatch('public-source-check-post',{'tweet_id':'3141592653589793','approve_source_check':True})
        self.assertTrue(result['credential_saved']);return result
    def prepare(self,app,*,followers=False,address=False):
        post={'kind':'thread','id':str(uuid.uuid4()),'created_at':self.now(),'title':'Private renewal beta',
            'body':'Exact public text with independently selected badges','references':[]}
        result=app.dispatch('public-prepare',{'post':post,'selection':{'address':address,'followers_threshold':10000 if followers else None},
            'thread':None,'references':None,'approve_publication':True})
        return post,result

    def test_expired_hidden_proof_stops_before_upload_or_ticket_submission(self):
        app=self.app();self.enroll(app);post,_=self.prepare(app,followers=True)
        app.dispatch('public-attach-followers',{'post_id':post['id'],'approve_follower_disclosure':True})
        app.dispatch('public-finish',{'post_id':post['id'],'approve_publication':True})
        self.f.raw.call('evm_setNextBlockTimestamp',self.now()+61);self.f.raw.call('evm_mine')
        with self.assertRaisesRegex(Rejected,'follower-publication-window-too-short'):
            app.desktop.publish(post['id'],True)
        self.assertEqual(self.origin.puts,0)
        self.assertIsNone(app.desktop.outbox()['entries'][0]['last_attempt'])

    def test_explicit_expired_badge_recovery_keeps_bytes_and_only_one_submission(self):
        from permissionless_index import submission_data
        app=self.app();self.enroll(app);post,_=self.prepare(app,followers=True)
        app.dispatch('public-attach-followers',{'post_id':post['id'],'approve_follower_disclosure':True})
        saved=app.dispatch('public-finish',{'post_id':post['id'],'approve_publication':True})
        original=app.dispatch('public-export-submission',{'post_id':post['id'],'approve_public_export':True})
        self.f.raw.call('evm_setNextBlockTimestamp',self.now()+61);self.f.raw.call('evm_mine')
        self.assertEqual(app.desktop.outbox()['entries'][0]['follower_window'],'expired')
        calls=[]
        def submit(h):
            calls.append(h);receipt=self.f.raw.tx(self.f.deployer,submission_data(h),self.f.index)
            return {'transaction_hash':receipt['transactionHash']}
        app.desktop.relay=type('ExactFixturePayer',(),{'submit':staticmethod(submit)})()
        with patch.object(app.desktop,'_prepare_author',side_effect=AssertionError('no new author intent')),\
             patch.object(app.enrollment.remote,'call',side_effect=AssertionError('no source or witness lookup')):
            result=app.desktop.publish(post['id'],True,approve_optional_badge_failure=True)
            again=app.desktop.publish(post['id'],True,approve_optional_badge_failure=True)
        self.assertEqual(calls,[saved['bundle_hash']])
        self.assertEqual(result['bundle_hash'],saved['bundle_hash'])
        self.assertEqual(again['last_known'],result['last_known'])
        self.assertEqual(app.dispatch('public-export-submission',{'post_id':post['id'],'approve_public_export':True}),original)
        number=int(result['last_known']['post_number'])
        row=app.dispatch('public-numbers',{'numbers':[number]})['posts'][0]
        self.assertTrue(row['proofs_verified']);self.assertIsNone(row['display']['followers'])
        self.assertEqual(row['post']['body'],post['body'])

    def test_expired_badge_override_cannot_sign_an_unfinished_post_or_bypass_fresh_guard(self):
        app=self.app();self.enroll(app);post,_=self.prepare(app,followers=True)
        with patch.object(app.desktop,'_save',side_effect=AssertionError('must reject before signing')):
            with self.assertRaisesRegex(Rejected,'follower-recovery-not-applicable'):
                app.desktop.publish(post['id'],True,approve_optional_badge_failure=True)
        app.dispatch('public-attach-followers',{'post_id':post['id'],'approve_follower_disclosure':True})
        app.dispatch('public-finish',{'post_id':post['id'],'approve_publication':True})
        with self.assertRaisesRegex(Rejected,'follower-recovery-not-applicable'):
            app.desktop.publish(post['id'],True,approve_optional_badge_failure=True)
        self.assertEqual(self.origin.puts,0)

    def test_factory_and_local_record_status_need_no_network_or_keyring(self):
        with patch('socket.getaddrinfo',side_effect=AssertionError('no network')),\
             patch('wallet.WalletSecretService',side_effect=AssertionError('no keyring')):
            app=factory(self.config,ROOT)
            self.assertIsInstance(app,PublicRenewalApplication)
            caps=app.dispatch('public-capabilities',{})
            self.assertEqual(caps['verifier_release'],10);self.assertEqual(caps['publication_mode'],'direct')
            self.assertTrue(caps['source_enrollment_configured']);self.assertTrue(caps['follower_proof_configured'])
            self.assertEqual(app.dispatch('public-source-status',{}),{'profile':'nockapp-public-source-status-v1',
                'credential_record_present':False,'renewal_pending':False})
            self.assertEqual(app.dispatch('public-identity-options',{})['sources'],[])

    def test_exact_config_binds_service_native_deployment_and_original_issuer(self):
        for field,value in [('application','0x'+'12'*32),('contract','0x'+'12'*20),
            ('renewal_native_sha256','12'*32),('definition_hash','12'*32)]:
            bad=copy.deepcopy(self.config);bad['renewal_approval']['identity'][field]=value
            with self.subTest(field=field),self.assertRaises(Rejected):validate(bad)
        for extra in ({'aws_credentials':{}},{'source_count':123},{'registry_deployment_block':True}):
            with self.assertRaises(Rejected):validate(dict(self.config,**extra))
        bad=copy.deepcopy(self.config);bad['installation']['files_sha256']['renewal_transport_v3.py']='12'*32
        with self.assertRaises(Rejected):self.app(bad)

    def test_enrollment_and_all_four_badge_combinations_are_independently_verified(self):
        app=self.app();result=self.enroll(app);author=app.desktop.author.wallet.read('credential.sealed')
        self.assertFalse(any(word in canonical(result).decode() for word in ('issued_at','renew_by','secret','account_id','followers')))
        for followers,address in ((False,False),(True,False),(False,True),(True,True)):
            post,_=self.prepare(app,followers=followers,address=address)
            if followers:app.dispatch('public-attach-followers',{'post_id':post['id'],'approve_follower_disclosure':True})
            if address:
                q=app.dispatch('public-wallet-request',{'post_id':post['id'],'address':self.f.deployer,'approve_address_disclosure':True})
                sig=self.f.raw.call('eth_signTypedData_v4',q['address'],json.dumps(q['typed_data']))
                saved=app.dispatch('public-wallet-result',{'post_id':post['id'],'request_sha256':q['request_sha256'],'signature':sig})
            else:saved=app.dispatch('public-finish',{'post_id':post['id'],'approve_publication':True})
            exported=app.dispatch('public-export-submission',{'post_id':post['id'],'approve_public_export':True})
            raw=base64.b64decode(exported['bundle_base64']);self.origin.put(exported['bundle_hash'],raw)
            ready=app.dispatch('public-direct-ready',{'post_id':post['id'],'approve_publication':True,'approve_public_payer':True})
            receipt=self.f.raw.tx(self.f.deployer,ready['calldata'],self.f.index);self.assertEqual(receipt['status'],'0x1')
            row=app.dispatch('public-check',{'post_id':post['id']});number=int(row['last_known']['post_number'])
            with patch('wallet.WalletSecretService',side_effect=AssertionError('public reader uses no secret')):
                read=app.dispatch('public-numbers',{'numbers':[number]})['posts'][0]
            self.assertTrue(read['proofs_verified']);self.assertEqual(read['display']['address'],self.f.deployer if address else None)
            self.assertEqual(read['display']['followers'] is not None,followers)
            if followers:
                self.assertEqual(read['display']['followers']['threshold'],10000)
                self.assertEqual(read['display']['followers']['credential_profile'],'nockapp-renewal-count-v3')
                self.assertNotIn('issued_at',raw.decode());self.assertNotIn('renew_by',raw.decode())
            self.assertEqual(saved['bundle_hash'],exported['bundle_hash'])
        self.assertEqual(app.desktop.author.wallet.read('credential.sealed'),author)

    def test_lost_begin_reply_resumes_same_private_request_without_second_profile_lookup(self):
        app=self.app();app.dispatch('public-initialize-identity',{'approve_private_key_setup':True})
        call=self.remote.call
        def lost(op,body):
            reply=call(op,body)
            if op=='begin':raise OSError('synthetic reply lost')
            return reply
        with patch.object(self.remote,'call',side_effect=lost),self.assertRaises(OSError):
            app.dispatch('public-source-begin',{'username':'synthetic_user','approve_source_check':True})
        before=app.enrollment.desktop.wallet.read('pending.sealed')
        with patch.object(self.remote,'call',side_effect=OSError('synthetic lookup unavailable')),self.assertRaises(OSError):
            app.enrollment.recover()
        self.assertEqual(app.enrollment.desktop.wallet.read('pending.sealed'),before)
        reopened=self.app();r=reopened.dispatch('public-source-recover',{'approve_source_check':True})
        self.assertEqual(r['state'],'waiting-for-source-post');self.case.provider.resolve.assert_called_once()
        self.assertEqual(reopened.dispatch('public-source-cancel',{'approve_cancel':True})['state'],'cancelled')
        self.assertIsNone(reopened.enrollment.desktop.wallet.read('pending.sealed',missing=True))

    def test_expired_lost_begin_reply_recovers_for_cancel_without_another_profile_lookup(self):
        app=self.app();app.dispatch('public-initialize-identity',{'approve_private_key_setup':True})
        author=app.desktop.author.wallet.read('credential.sealed')
        before=self.service.state.load()[1];accounts=copy.deepcopy(before._accounts)
        original_key=copy.deepcopy(before._issuer['signing_key']);call=self.remote.call
        def lost(op,body):
            reply=call(op,body)
            if op=='begin':raise OSError('synthetic reply lost')
            return reply
        with patch.object(self.remote,'call',side_effect=lost),self.assertRaises(OSError):
            app.dispatch('public-source-begin',{'username':'synthetic_user','approve_source_check':True})
        self.f.raw.call('evm_setNextBlockTimestamp',self.now()+601);self.f.raw.call('evm_mine')
        reopened=self.app()
        recovered=reopened.dispatch('public-source-recover',{'approve_source_check':True})
        self.assertEqual(recovered['state'],'expired')
        self.case.provider.resolve.assert_called_once();self.case.provider.check.assert_not_called()
        self.assertEqual(reopened.dispatch('public-source-cancel',{'approve_cancel':True})['state'],'cancelled')
        self.assertIsNone(reopened.enrollment.desktop.wallet.read('pending.sealed',missing=True))
        self.assertEqual(reopened.desktop.author.wallet.read('credential.sealed'),author)
        after=self.service.state.load()[1]
        self.assertEqual(after._accounts,accounts);self.assertEqual(after._issuer['signing_key'],original_key)

    def test_absent_remote_begin_does_not_discard_uncertain_local_request_or_query_source(self):
        app=self.app();app.dispatch('public-initialize-identity',{'approve_private_key_setup':True})
        call=self.remote.call
        def unavailable(op,body):
            if op=='begin':raise OSError('synthetic unavailable before delivery')
            return call(op,body)
        with patch.object(self.remote,'call',side_effect=unavailable),self.assertRaises(OSError):
            app.dispatch('public-source-begin',{'username':'synthetic_user','approve_source_check':True})
        before=app.enrollment.desktop.wallet.read('pending.sealed')
        self.assertEqual(app.dispatch('public-source-recover',{'approve_source_check':True})['state'],'begin-recovery-required')
        self.assertEqual(app.dispatch('public-source-cancel',{'approve_cancel':True})['state'],'begin-recovery-required')
        self.assertEqual(app.enrollment.desktop.wallet.read('pending.sealed'),before)
        self.case.provider.resolve.assert_not_called();self.case.provider.check.assert_not_called()

    def test_substituted_lookup_session_cannot_rebind_the_saved_request(self):
        app=self.app();app.dispatch('public-initialize-identity',{'approve_private_key_setup':True})
        call=self.remote.call
        def altered(op,body):
            reply=call(op,body)
            if op=='begin':raise OSError('synthetic reply lost')
            if op=='lookup-begin':reply['session']['desktop_nonce']='56'*32
            return reply
        with patch.object(self.remote,'call',side_effect=altered),self.assertRaises(OSError):
            app.dispatch('public-source-begin',{'username':'synthetic_user','approve_source_check':True})
        before=app.enrollment.desktop.wallet.read('pending.sealed')
        with patch.object(self.remote,'call',side_effect=altered),self.assertRaises(Rejected):
            app.dispatch('public-source-recover',{'approve_source_check':True})
        self.assertEqual(app.enrollment.desktop.wallet.read('pending.sealed'),before)
        self.case.provider.resolve.assert_called_once()

    def test_expired_challenge_rejected_before_paid_post_or_profile_check(self):
        app=self.app();app.dispatch('public-initialize-identity',{'approve_private_key_setup':True})
        app.dispatch('public-source-begin',{'username':'synthetic_user','approve_source_check':True})
        self.f.raw.call('evm_setNextBlockTimestamp',self.now()+601);self.f.raw.call('evm_mine')
        with self.assertRaises(Rejected):
            app.dispatch('public-source-check-post',{'tweet_id':'3141592653589793','approve_source_check':True})
        self.case.provider.check.assert_not_called();self.case.provider.resolve.assert_called_once()

    def test_unconsented_extra_private_fields_and_wrong_author_cannot_attach(self):
        app=self.app()
        with patch.object(self.remote,'call',side_effect=AssertionError('no source call')):
            for op,body in [('public-source-begin',{'username':'synthetic_user','approve_source_check':False}),
                ('public-source-check-post',{'tweet_id':'1','approve_source_check':True,'followers':99999}),
                ('public-source-recover',{}),('public-source-cancel',{'approve_cancel':False})]:
                with self.assertRaises(Rejected):app.dispatch(op,body)
        self.enroll(app);other_config=copy.deepcopy(self.config);other_config['installation']['data_directory']=str(Path(self.f.temp.name)/'other')
        other=self.app(other_config);other.dispatch('public-initialize-identity',{'approve_private_key_setup':True})
        source=app.enrollment.desktop;other.enrollment.desktop=source;other.desktop.author.legacy_sources=(source,)
        post,_=self.prepare(other,followers=True)
        with self.assertRaises(Rejected):other.dispatch('public-attach-followers',{'post_id':post['id'],'approve_follower_disclosure':True})
        self.assertIsNone(other.desktop.author.public_material()['unsigned']['evidence']['followers'])

    def test_finality_change_during_proof_does_not_save_follower_evidence(self):
        app=self.app();self.enroll(app);post,_=self.prepare(app,followers=True)
        before=app.desktop.author.wallet.read('post.sealed')
        with patch.object(app.desktop.index,'finish',side_effect=Rejected('synthetic reorg')),self.assertRaises(Rejected):
            app.dispatch('public-attach-followers',{'post_id':post['id'],'approve_follower_disclosure':True})
        self.assertEqual(app.desktop.author.wallet.read('post.sealed'),before)


if __name__=='__main__':unittest.main()
