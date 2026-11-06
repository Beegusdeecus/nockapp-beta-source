"""Real local refunds/signatures/AEAD/CAS; synthetic keys, storage and OP fees."""
import copy,hashlib,json,subprocess,unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
from base_evm import TOOLS,encode
from base_protocol import keccak
from policy import canonical,digest,Rejected
from batch_checkout_v2.offer import BatchOffer,PROFILE as OFFER,terms_hash,manifest_hash
from batch_checkout_v2.payment import FinalizedBatchPayment
from ticket_offer_overlay_v1 import PROFILE as OVERLAY
from ticket_refund_scope_upgrade_v2 import contexts,resume
from ticket_refund_payout_v1 import RefundWorker
from ticket_refund_service_v1 import RefundApplication
from ticket_scope_apps_v1 import ScopedRefundApplication
from ticket_refund_v1 import refund_data
from ticket_issuance_v1 import PaidTicketIssuer
from ticket_bindings_v1 import ConditionalS3Records
from test_ticket_backend_boot_v1 import BootBase,RoutedS3,private
import test_ticket_refund_payout_v1 as fixtures

class RefundScopeTests(BootBase,unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RefundTests.setUpClass();z=Path(__file__).parent
        request={'language':'Solidity','sources':{'Batch.sol':{'content':(z/'batch_checkout_v2/PrepaidTicketPacksBatchV2.sol').read_text()}},
            'settings':{'optimizer':{'enabled':True,'runs':200},'evmVersion':'prague','outputSelection':{'*':{'*':['evm.bytecode.object']}}}}
        v=json.loads(subprocess.run([str(TOOLS/'solc-0.8.30'),'--standard-json'],input=json.dumps(request).encode(),capture_output=True,check=True).stdout)
        cls.creation=v['contracts']['Batch.sol']['PrepaidTicketPacksBatchV2']['evm']['bytecode']['object']
    def setUp(self):
        self.f=fixtures.RefundTests();self.f.setUp();self.addCleanup(self.f.doCleanups);f=self.f
        terms=copy.deepcopy(f.offer.terms);terms.update(profile=OFFER,payment_receipt_version=2,packs_per_payment=25)
        receipt=f.f.rpc.tx(f.f.accounts[0],'0x'+self.creation+encode('f(bytes32,address,uint256,uint64)',
            terms_hash(terms),terms['payment_recipient'],terms['pack_price_wei'],terms['purchase_before'])[10:])
        purchase=receipt['contractAddress'];manifest={'terms':terms,'purchase_contract':purchase,
            'purchase_runtime_keccak':keccak(bytes.fromhex(f.f.rpc.call('eth_getCode',purchase,'latest')[2:]))}
        self.offer=BatchOffer(manifest,manifest_hash(manifest),f.f.crypto.native)
        self.payments=FinalizedBatchPayment(f.rpc,self.offer)
        price=int(terms['pack_price_wei']);data='0x'+f.compiled['evm']['bytecode']['object']+encode(
            'f(bytes32,address,address,uint256,uint256)','0x'+self.offer.hash,purchase,f.signer.address,price,f.count)[10:]
        receipt=f.f.rpc.tx(f.f.accounts[0],data);vault=receipt['contractAddress'];self.vault_block=int(receipt['blockNumber'],16)
        runtime=bytes.fromhex(f.f.rpc.call('eth_getCode',vault,'latest')[2:])
        self.vault={**f.scope,'parameters':self.offer.hash,'vault':vault,'runtime_sha256':hashlib.sha256(runtime).hexdigest()}
        deposit=f.f.rpc.call('eth_sendTransaction',{'from':f.f.accounts[0],'to':vault,'value':hex(price*f.count),'gas':hex(500000)})
        self.assertEqual(f.f.receipt(deposit)['status'],'0x1')
        self.cfg=self.config('refund',f.offer,{'publication':f.f.accounts[7],'refund':f.signer.address},
            {'purchase_bucket':f.f.decisions.bucket,'ledger_bucket':'private-refund-snapshots'},
            {'limits':asdict(f.limits),'fee_policy':f.fees,'runtime_sha256':f.scope['runtime_sha256']})
        self.cfg.update(refund_vault=f.scope,refund_vault_sha256=f.scope_hash)
        self.plan={'profile':OVERLAY,'base_backend_sha256':digest(self.cfg),'offer':manifest,'offer_sha256':self.offer.hash,
            'refund_vault':self.vault,'refund_vault_sha256':digest(self.vault),'transition':{
                'profile':'nockapp-ticket-refund-context-upgrade-v2','old_context_sha256':'00'*32,'new_context_sha256':'00'*32}}
        old,new=contexts(self.cfg,self.plan)
        self.plan['transition'].update(old_context_sha256=hashlib.sha256(old.encode()).hexdigest(),new_context_sha256=hashlib.sha256(new.encode()).hexdigest())
        self.paths=0
    def upgrade(self,plan=None):
        self.paths+=1;f=self.f;p=plan or self.plan
        return resume(f.rpc,f.signer,Path(f.f.temp.name)/('scoped-'+str(self.paths)+'.sqlite'),self.cfg,digest(self.cfg),p,digest(p),native=f.f.crypto.native,anchor=f.anchor)
    def snapshot(self,q):
        with q._db()as db:
            return {table:[{k:r[k]for k in r.keys()if k not in('mac','context')}for r in db.execute('SELECT *FROM '+table)]
                for table in('meta','refund_jobs','submissions','fees')}
    def authorize_new(self):
        f=self.f;p=[self.offer.protocol.prepare()for _ in range(2)];pack=self.offer.protocol.blinded_pack(p);h=self.offer.pack_hash(pack)
        tx=self.offer.transaction([h]+['0x'+format(i,'064x')for i in range(1,25)])
        receipt=f.f.receipt(f.f.rpc.call('eth_sendTransaction',{'from':f.f.accounts[1],**tx,'gas':hex(2000000)}))
        self.assertEqual(receipt['status'],'0x1');request={'pack':pack,'transaction_hash':receipt['transactionHash']}
        signature=f.f.rpc.call('eth_signTypedData_v4',f.f.accounts[1],json.dumps(refund_data(self.offer,h,request['transaction_hash'])))
        prefix='ticket-purchases-v1/'+self.offer.hash+'/'
        decisions=ConditionalS3Records(f.f.s3,f.f.decisions.bucket,prefix+'decisions/',2048)
        results=ConditionalS3Records(f.f.s3,f.f.results.bucket,prefix+'results/',32768)
        issuer=PaidTicketIssuer(self.offer,self.payments,decisions,results,f.f.crypto.private)
        issuer.reserve_unissued_refund(**request,signature=signature)
        return h,signature,decisions
    def test_migration_preserves_signed_transaction_and_all_counters_then_refunds_both_domains(self):
        f=self.f;f.authorize();original=f.rpc.call
        def lost(method,*args):
            if method=='eth_sendRawTransaction':original(method,*args);raise TimeoutError('synthetic lost reply')
            return original(method,*args)
        with patch.object(f.rpc,'call',side_effect=lost):first=f.worker.refund(f.pack_hash,f.signature)
        before=self.snapshot(f.queue);revision=f.anchor.read()[0]
        with patch.object(f.signer,'sign',side_effect=AssertionError('migration must never sign')):q=self.upgrade()
        self.assertEqual(self.snapshot(q),before);self.assertEqual(f.anchor.read()[0],revision+1)
        self.assertEqual(q.limits,f.queue.limits);self.assertEqual(q.fees.policy,f.queue.fees.policy)
        old=RefundWorker(f.offer,f.payments,f.f.decisions,q.view(f.offer.hash))
        with patch.object(f.signer,'sign',side_effect=AssertionError('must recover original transaction')):
            paid=old.refund(f.pack_hash,f.signature)
        self.assertTrue(paid['payout_confirmed']);self.assertEqual(paid['transaction_hash'],first['transaction_hash'])
        h,signature,decisions=self.authorize_new();new=RefundWorker(self.offer,self.payments,decisions,q.view(self.offer.hash))
        app=ScopedRefundApplication(RefundApplication(old),RefundApplication(new))
        second=new.refund(h,signature)
        if not second['payout_confirmed']:
            f.f.receipt(second['transaction_hash']);second=new.refund(h,signature)
        self.assertTrue(second['payout_confirmed']);self.assertEqual(second['parameters'],self.offer.hash)
        self.assertEqual(f.rpc.call('eth_getTransactionCount',f.signer.address,'latest'),'0x2')
        with self.assertRaises(Rejected):q.view(self.offer.hash).job(f.pack_hash)
        self.assertIs(app.queue,q)
    def test_lost_head_commit_reply_reopens_new_context_without_second_migration(self):
        f=self.f;f.authorize();f.queue.admit(f.pack_hash,f.worker._authorized(f.pack_hash,f.signature))
        before=self.snapshot(f.queue);revision=f.anchor.read()[0];commit=f.anchor.compare_exchange
        def lost(*args):commit(*args);raise TimeoutError('synthetic committed reply lost')
        with patch.object(f.anchor,'compare_exchange',side_effect=lost):
            with self.assertRaises(TimeoutError):self.upgrade()
        self.assertEqual(f.anchor.read()[0],revision+1)
        q=self.upgrade();self.assertEqual(self.snapshot(q),before);self.assertEqual(f.anchor.read()[0],revision+1)
        self.assertEqual(self.snapshot(self.upgrade()),before)
    def test_bad_context_or_changed_budget_rejects_without_writing_head(self):
        before=copy.deepcopy(self.f.sdk.records)
        for mutate in(lambda p:p['transition'].update(new_context_sha256='ff'*32),
            lambda p:p['refund_vault'].update(max_refunds=self.vault['max_refunds']+1)):
            plan=copy.deepcopy(self.plan);mutate(plan);plan['refund_vault_sha256']=digest(plan['refund_vault'])
            with self.assertRaises(Rejected):self.upgrade(plan)
        self.assertEqual(self.f.sdk.records,before)
    def test_unfinalized_new_vault_cannot_migrate_existing_authority(self):
        f=self.f;before=copy.deepcopy(f.sdk.records)
        anchor=f.f.rpc.call('eth_getBlockByNumber',hex(self.vault_block-1),False);original=f.rpc.call
        def lag(method,*args):
            if method=='eth_getBlockByNumber'and args[0]=='finalized':return anchor
            return original(method,*args)
        with patch.object(f.rpc,'call',side_effect=lag):
            with self.assertRaises(Rejected):self.upgrade()
        self.assertEqual(f.sdk.records,before)
    def test_new_offer_cannot_get_a_separate_refund_allowance_or_unknown_domain(self):
        q=self.upgrade();f=self.f
        # Durable fixture jobs exercise one shared original count bound without
        # spending funds. The real worker checks decisions/signatures first.
        f.authorize();payload=f.worker._authorized(f.pack_hash,f.signature)
        for i in range(f.count):
            p=copy.deepcopy(payload);h='0x'+format(i+1,'064x');p['decision']['payment']['pack_hash']=h
            if i%2:p['decision']['payment']['parameters']=self.offer.hash
            q.admit(h,p)
        h='0x'+'ff'*32;p=copy.deepcopy(payload);p['decision']['payment'].update(pack_hash=h,parameters=self.offer.hash)
        with self.assertRaisesRegex(Rejected,'capacity'):q.admit(h,p)
        p['decision']['payment']['parameters']='11'*32
        with self.assertRaisesRegex(Rejected,'domain'):q.admit(h,p)
    def test_original_private_packet_and_new_versioned_TLS_server_serve_both_policies(self):
        f=self.f;body=self.body(self.cfg,private(f.key.key));saved=canonical(body)
        scratch=Path(f.f.temp.name)/'boot-scoped-refund';scratch.mkdir(mode=0o700)
        sdk=RoutedS3({f.f.decisions.bucket:f.f.s3,'private-refund-snapshots':f.sdk})
        with patch('ticket_backend_boot_v1.harden_process'):
            app,context,server=self.boot(self.cfg,body,ticket_native=f.f.crypto.native,rpc=f.rpc,s3=sdk,
                scratch_directory=scratch,offer_overlay={'plan':self.plan,'sha256':digest(self.plan)})
        self.assertEqual(canonical(body),saved);self.assertIs(type(app),ScopedRefundApplication)
        self.assertEqual(server['profile'],'nockapp-ticket-role-server-scopes-v2')
        remote=self.serve(app,context,server,refund=True)
        old=remote.call('policy',{});self.assertEqual(old['policy'],f.scope)
        from ticket_refund_rpc_v1 import RefundRemote
        new=RefundRemote({**remote.approved,'offer_sha256':self.offer.hash,'policy_sha256':digest(self.vault)},
            remote._context,dial=remote._dial)
        self.assertEqual(new.call('policy',{})['policy'],self.vault)
if __name__=='__main__':unittest.main()
