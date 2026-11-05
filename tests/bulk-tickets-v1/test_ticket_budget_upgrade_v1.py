"""Real local crypto/EVM; managed journal and OP fee observations are fixtures."""
from dataclasses import asdict,replace
import copy,hashlib,json,unittest
from unittest.mock import patch
from policy import canonical,digest,Rejected
from ticket_budget_upgrade_v1 import PROFILE,validate,resume
import test_ticket_publication_v2 as fixtures

class UpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixtures.PublicationTests.setUpClass()
    def setUp(self):
        self.f=fixtures.PublicationTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        q=self.f.queue;self.serial=0
        self.backend={'role':'publication','offer':self.f.offer.manifest,'key_bindings':{'publication':self.f.signer.address},
            'transaction':{'limits':asdict(q.limits),'fee_policy':q.fees.policy,'runtime_sha256':json.loads(q.context)['code_hashes'][self.f.contract]}}
        limits=asdict(replace(q.limits,max_submissions=200,execution_budget=2*10**17))
        fees={**q.fees.policy,'total_budget':2*10**17,'funded_budget':2*10**17}
        changed={**json.loads(q.context),'limits':limits,'fee_policy':fees}
        self.plan={'profile':PROFILE,'previous_backend_sha256':digest(self.backend),'limits':limits,'fee_policy':fees,
            'purchase_ticket_count':50,'incoming_payment_wei':str(25*int(self.f.offer.terms['pack_price_wei'])),
            'old_context_sha256':hashlib.sha256(q.context.encode()).hexdigest(),'new_context_sha256':hashlib.sha256(canonical(changed)).hexdigest()}
    def upgrade(self,plan=None):
        self.serial+=1;f=self.f;plan=plan or self.plan
        return resume(f.rpc,f.signer,f.queue.path.with_name('upgraded-'+str(self.serial)+'.sqlite'),self.backend,plan,digest(plan),anchor=f.anchor)
    def snapshot(self,q):
        with q._db()as db:return {table:[{k:r[k]for k in r.keys()if k not in ('mac','context')}for r in db.execute('SELECT * FROM '+table)]for table in ('meta','submissions','fees','ticket_jobs')}
    def pending(self):
        h,_=self.f.post();original=self.f.rpc.call
        def outage(method,*args):
            if method=='eth_sendRawTransaction':raise OSError('synthetic lost broadcast')
            return original(method,*args)
        with patch.object(self.f.rpc,'call',side_effect=outage):self.f.worker.submit(self.f.tokens[0],h)
        return h
    def test_all_ticket_bindings_raw_transactions_nonce_and_cumulative_charges_survive(self):
        h=self.pending();before=self.snapshot(self.f.queue);revision=self.f.anchor.read()[0]
        with patch.object(self.f.signer,'sign',side_effect=AssertionError('migration must not sign')):
            q=self.upgrade()
        self.assertEqual(self.snapshot(q),before);self.assertEqual(q.limits.max_submissions,200)
        self.assertEqual(self.f.anchor.read()[0],revision+1)
        self.assertEqual(self.snapshot(self.upgrade()),before);self.assertEqual(self.f.anchor.read()[0],revision+1)
        self.assertEqual(q.lookup(self.f.offer.protocol.verify(self.f.tokens[0]),h)['bundle_hash'],h)
    def test_wrong_context_decrease_or_per_transaction_raise_cannot_write(self):
        before=copy.deepcopy(self.f.sdk.records)
        for field,value in [('max_gas',self.plan['limits']['max_gas']+1),('max_submissions',1)]:
            plan=copy.deepcopy(self.plan);plan['limits'][field]=value
            with self.assertRaises(Rejected):validate(plan,digest(plan),self.backend)
        plan=copy.deepcopy(self.plan);plan['new_context_sha256']='f'*64
        with self.assertRaises(Rejected):self.upgrade(plan)
        self.assertEqual(self.f.sdk.records,before)
    def test_lost_managed_commit_reply_resumes_new_context_without_reset_or_second_migration(self):
        self.pending();before=self.snapshot(self.f.queue);revision=self.f.anchor.read()[0];write=self.f.anchor.compare_exchange
        def lost(*args):write(*args);raise TimeoutError('synthetic lost migration reply')
        with patch.object(self.f.anchor,'compare_exchange',side_effect=lost):
            with self.assertRaises(TimeoutError):self.upgrade()
        self.assertEqual(self.f.anchor.read()[0],revision+1)
        self.assertEqual(self.snapshot(self.upgrade()),before);self.assertEqual(self.f.anchor.read()[0],revision+1)
