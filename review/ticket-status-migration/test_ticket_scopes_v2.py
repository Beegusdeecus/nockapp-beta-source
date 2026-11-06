"""Cross-scope reservation/capacity checks; no owner records or real purchases."""
import copy
from types import SimpleNamespace
import unittest
from policy import Rejected
import test_ticket_publication_v2 as cases
from batch_checkout_v2.offer import BatchOffer,PROFILE,manifest_hash
from batch_checkout_v2.scopes import TicketScopes
from ticket_wallet_v1 import TicketWallet


class ScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cases.PublicationTests.setUpClass()
    def setUp(self):
        self.f=cases.PublicationTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.old=self.f.f.client
        manifest=copy.deepcopy(self.old.offer.manifest)
        manifest['terms'].update(profile=PROFILE,payment_receipt_version=2,packs_per_payment=25)
        offer=BatchOffer(manifest,manifest_hash(manifest),self.f.f.crypto.native)
        self.new=TicketWallet(self.old.wallet.directory.with_name('tickets-new-scope'),offer);self.new.initialize()
        self.signing=self.f.f.crypto
        self.seed(self.new,2)
        def remote(wallet):return SimpleNamespace(approved={'service':'publication','offer_sha256':wallet.offer.hash},submit=lambda *_:None)
        self.rows=[(self.old,remote(self.old)),(self.new,remote(self.new))]
        self.scopes=TicketScopes(self.rows[-1],self.rows[:-1])

    def seed(self,wallet,count):
        # Synthetic issuance only, intentionally independent of payment tests.
        r=wallet._load()
        import base64
        for _ in range(count):
            p=wallet.offer.protocol.prepare()
            sig=wallet.offer.protocol.native._call('blind-sign',private_key=base64.b64encode(self.signing.private).decode(),blinded=p['request']['blinded'])['signature']
            r['tickets'].append({'token':wallet.offer.protocol.finalize(p,sig),'bundle_hash':None})
        wallet._save(r)

    def test_existing_assignments_choose_original_offer_and_endpoint_after_restart(self):
        h='0x'+'12'*32;old_before=copy.deepcopy(self.old._load())
        wallet,remote=self.scopes.select(h,self.f.f.now)
        self.assertIs(wallet,self.old);self.assertEqual(self.scopes.status(),{'available':3,'reserved':1})
        restarted=TicketScopes(self.rows[-1],self.rows[:-1])
        self.assertIs(restarted.select(h,self.f.f.now)[0],self.old)
        self.assertEqual(self.new.status()['reserved'],0)
        self.assertEqual(self.old._load()['tickets'][1],old_before['tickets'][1])
        self.scopes.select('0x'+'13'*32,self.f.f.now)
        self.assertIs(self.scopes.select('0x'+'14'*32,self.f.f.now)[0],self.new)

    def test_foreign_pending_purchase_blocks_new_admission_without_mutation(self):
        p=self.old.prepare_purchase(self.f.f.now,True)
        self.old.arm_payment(p['pack_hash'],self.f.f.accounts[1],0,True)
        before=copy.deepcopy(self.old._load())
        with self.assertRaisesRegex(Rejected,'legacy-purchase-unresolved'):
            with self.scopes.purchase_guard(50):self.fail('must not admit')
        self.assertEqual(self.old._load(),before);self.assertIsNone(self.new._load()['pending'])

    def test_uninitialized_new_scope_reports_retained_legacy_state_consistently(self):
        from batch_checkout_v2.installation import BatchApplication
        fresh=TicketWallet(self.new.wallet.directory.with_name('never-initialized'),self.new.offer)
        remote=SimpleNamespace(approved={'service':'publication','offer_sha256':fresh.offer.hash},submit=lambda *_:None)
        scopes=TicketScopes((fresh,remote),self.rows[:1]);before=self.old.wallet.read('credential.sealed')
        selected=SimpleNamespace(tickets=fresh,payment=None,dispatch=lambda *_:{'initialized':False,
            'available':0,'reserved':0,'purchase_pending':False,'can_purchase':True})
        app=BatchApplication(SimpleNamespace(clock=lambda:self.f.f.now),scopes,{fresh.offer.hash:selected},fresh.offer.hash)
        result=app.dispatch('public-ticket-status',{})
        self.assertTrue(result['initialized']);self.assertEqual(result['profile'],'nockapp-protected-ticket-wallet-v1')
        self.assertEqual(result['available']+result['reserved'],2)
        self.assertEqual(self.old.wallet.read('credential.sealed'),before)
        self.assertIsNone(fresh.wallet.metadata())
        pending=self.old.prepare_purchase(self.f.f.now,True)
        self.assertTrue(app.dispatch('public-ticket-status',{})['purchase_pending'])
        self.assertEqual(self.old._load()['pending']['pack_hash'],pending['pack_hash'])
        self.old.arm_payment(pending['pack_hash'],self.f.f.accounts[1],0,True)
        self.assertFalse(app.dispatch('public-ticket-status',{})['can_purchase'])

    def test_completely_fresh_scope_status_stays_uninitialized_and_empty(self):
        fresh=TicketWallet(self.new.wallet.directory.with_name('empty-status'),self.new.offer)
        remote=SimpleNamespace(approved={'service':'publication','offer_sha256':fresh.offer.hash},submit=lambda *_:None)
        self.assertEqual(TicketScopes((fresh,remote),[]).status(include_initialization=True),
            {'available':0,'reserved':0,'initialized':False,'purchase_pending':False})

    def test_status_reuses_terminal_proof_after_deadline_without_erasing_intent(self):
        p=self.old.prepare_purchase(self.f.f.now,True)
        self.old.arm_payment(p['pack_hash'],self.f.f.accounts[1],0,True)
        before=self.old.wallet.read('credential.sealed');self.scopes.rpc=self.f.f.rpc
        self.assertFalse(self.scopes.status(include_initialization=True,now=self.f.f.now)['legacy_purchase_clear'])
        self.f.f.rpc.call('evm_setNextBlockTimestamp',self.old.offer.terms['purchase_before']);self.f.f.rpc.call('evm_mine')
        self.assertTrue(self.scopes.status(include_initialization=True,now=self.old.offer.terms['purchase_before'])['legacy_purchase_clear'])
        self.assertEqual(self.old.wallet.read('credential.sealed'),before)

    def test_cumulative_capacity_includes_assigned_history_in_every_scope(self):
        self.seed(self.old,12)
        for i in range(14):self.old.reserve('0x'+format(i+1,'064x'),self.f.f.now)
        self.assertEqual(self.old.status()['reserved'],14)
        with self.assertRaisesRegex(Rejected,'wallet-full'):
            with self.scopes.purchase_guard(50):self.fail('16+50 exceeds64')
        self.assertEqual(self.scopes.status(),{'available':2,'reserved':14})

    def test_conflicting_bindings_or_endpoint_scope_fail_closed(self):
        h='0x'+'23'*32;self.old.reserve(h,self.f.f.now);self.new.reserve(h,self.f.f.now)
        before=[copy.deepcopy(w._load())for w,_ in self.rows]
        with self.assertRaisesRegex(Rejected,'binding-conflict'):self.scopes.select(h,self.f.f.now)
        self.assertEqual([w._load()for w,_ in self.rows],before)
        bad=SimpleNamespace(approved={'service':'publication','offer_sha256':self.old.offer.hash},submit=lambda *_:None)
        with self.assertRaisesRegex(Rejected,'endpoint'):TicketScopes((self.new,bad),self.rows[:-1])

    def test_finalized_unpaid_expiry_allows_new_scope_without_erasing_old_intent(self):
        p=self.old.prepare_purchase(self.f.f.now,True)
        self.old.arm_payment(p['pack_hash'],self.f.f.accounts[1],0,True)
        before=self.old.wallet.read('credential.sealed')
        self.scopes.rpc=self.f.f.rpc
        with self.assertRaisesRegex(Rejected,'still-executable'):
            with self.scopes.purchase_guard(50):self.fail('old request can still charge')
        self.f.f.rpc.call('evm_setNextBlockTimestamp',self.old.offer.terms['purchase_before'])
        self.f.f.rpc.call('evm_mine')
        with self.scopes.purchase_guard(50):pass
        self.assertEqual(self.old.wallet.read('credential.sealed'),before)
