"""Concrete versioned factory; synthetic directories/keys, no owner installation."""
import copy,hashlib,unittest
from pathlib import Path
from policy import canonical,Rejected
import test_public_installation as fixture
from public_installation import validate,factory
from batch_checkout_v2.installation import PROFILE,TICKET_FIELDS,BatchApplication
from batch_checkout_v2.offer import PROFILE as OFFER,manifest_hash
from ticket_refund_vault_v1 import SCOPE
from ticket_routed_transport_v1 import REFUND


class InstallationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixture.PublicInstallationTests.setUpClass()
    def setUp(self):
        self.f=fixture.PublicInstallationTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        cfg=copy.deepcopy(self.f.config);self.old=self.f.f.f.client
        old_offer=copy.deepcopy(cfg['offer']);old_hash=cfg['offer_sha256']
        new=copy.deepcopy(old_offer);new['terms'].update(profile=OFFER,payment_receipt_version=2,packs_per_payment=25)
        new_hash=manifest_hash(new)
        def row(offer,h,name):
            policy={'profile':SCOPE,'parameters':h,'chain_id':84532,'vault':self.f.f.f.accounts[8],
                'runtime_sha256':'ab'*32,'authority':self.f.f.f.accounts[6],
                'pack_price_wei':offer['terms']['pack_price_wei'],'max_refunds':4,
                'principal_budget_wei':str(4*int(offer['terms']['pack_price_wei'])),'gas':100000}
            pin=hashlib.sha256(canonical(policy)).hexdigest()
            endpoints={k:{'profile':'nockapp-prepaid-service-endpoint-v2','host':name+'-'+service+'.example.test',
                'port':443,'service':service,'offer_sha256':h}for k,service in
                (('payment_endpoint','payment'),('publication_endpoint','publication'))}
            refund={'profile':REFUND,'host':name+'-refund.example.test','connect_host':'route.example.test',
                'port':443,'service':'refund','offer_sha256':h,'policy_sha256':pin}
            return {'offer':offer,'offer_sha256':h,**endpoints,'refund_endpoint':refund,
                'refund_vault':policy,'refund_vault_sha256':pin}
        cfg.update(row(new,new_hash,'new'));cfg.update(profile=PROFILE,checkout_scope=new_hash,
            legacy_ticket_scopes=[{**row(old_offer,old_hash,'old'),'directory':str(self.old.wallet.directory)}])
        self.config=cfg

    def test_concrete_factory_retains_old_inventory_without_retagging_or_initializing_new_keys(self):
        before=self.old.wallet.read('credential.sealed');app=factory(self.config,fixture.ROOT)
        self.assertIsInstance(app,BatchApplication)
        status=app.dispatch('public-ticket-status',{})
        self.assertEqual(status['available'],2);self.assertEqual(status['reserved'],0)
        self.assertIsNone(app.tickets.wallet.metadata())
        self.assertEqual(self.old.wallet.read('credential.sealed'),before)
        self.assertEqual(app.dispatch('public-ticket-offer',{})['parameters'],self.config['offer_sha256'])
        h='0x'+'12'*32
        self.assertEqual(app.scopes.select(h,self.f.f.f.now)[0].offer.hash,self.old.offer.hash)
        with self.assertRaisesRegex(Rejected,'use-fifty'):
            app.dispatch('public-ticket-prepare',{'approve_purchase':True})

    def test_pinned_legacy_checkout_does_not_switch_after_a_status_request(self):
        cfg=copy.deepcopy(self.config);cfg['checkout_scope']=self.old.offer.hash
        app=factory(cfg,fixture.ROOT)
        self.assertEqual(app.dispatch('public-ticket-offer',{})['parameters'],self.old.offer.hash)
        app.dispatch('public-ticket-status',{})
        self.assertEqual(app.dispatch('public-ticket-offer',{})['parameters'],self.old.offer.hash)

    def test_earlier_batch_is_visible_but_recovery_cannot_rearm_or_change_scope(self):
        from ticket_bulk_purchase_v1 import BulkPurchase
        app=factory(self.config,fixture.ROOT)
        bulk=BulkPurchase(self.old,self.f.f.f.rpc,None)
        saved=bulk.prepare(self.f.f.f.now,True)
        bulk.arm(saved['batch_id'],self.f.f.f.accounts[1],True)
        before=self.old.wallet.read('pending.sealed')
        rows=app.dispatch('public-ticket-earlier-status',{})['purchases']
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['parameters'],self.old.offer.hash)
        self.assertEqual(rows[0]['purchase']['batch_id'],saved['batch_id'])
        self.assertNotIn('dispatch_authorized',rows[0]['purchase'])
        snapshot=app.dispatch('public-ticket-page',{})
        self.assertTrue(app.dispatch('public-capabilities',{})['ticket_page_snapshot'])
        self.assertEqual(snapshot['earlier']['purchases'],rows)
        self.assertEqual(snapshot['inventory']['available'],2)
        self.assertFalse(snapshot['inventory']['can_purchase'])
        self.assertEqual(snapshot['offer']['parameters'],self.config['offer_sha256'])
        body={'parameters':self.old.offer.hash,'operation':'public-ticket-bulk-status','body':{}}
        self.assertEqual(app.dispatch('public-ticket-earlier-recovery',body),rows[0]['purchase'])
        for op in ('public-ticket-bulk-arm','public-ticket-bulk-prepare','public-ticket-payment','public-ticket-earlier-recovery'):
            with self.assertRaisesRegex(Rejected,'recovery-only'):
                app.dispatch('public-ticket-earlier-recovery',{**body,'operation':op})
        with self.assertRaisesRegex(Rejected,'recovery-only'):
            app.dispatch('public-ticket-earlier-recovery',{**body,'parameters':self.config['offer_sha256']})
        with self.assertRaises(Rejected):
            app.dispatch('public-ticket-earlier-recovery',{**body,'body':{'private_key':'synthetic-forbidden'}})
        self.assertEqual(self.old.wallet.read('pending.sealed'),before)
        self.assertIsNone(app.tickets.wallet.metadata())

    def test_missing_legacy_or_invalid_endpoint_context_is_not_silently_replaced(self):
        bad=copy.deepcopy(self.config);bad['legacy_ticket_scopes'][0]['directory']+='/missing'
        with self.assertRaisesRegex(Rejected,'legacy-missing'):factory(bad,fixture.ROOT)
        self.assertFalse(Path(self.config['data_directory']).exists())
        for mutate in (lambda c:c.update(checkout_scope='01'*32),
            lambda c:c['legacy_ticket_scopes'][0]['publication_endpoint'].update(offer_sha256=c['offer_sha256'])):
            bad=copy.deepcopy(self.config);mutate(bad)
            with self.assertRaises(Rejected):validate(bad)
