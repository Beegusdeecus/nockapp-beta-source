"""Two public offer domains; real local crypto/TLS/EVM, synthetic storage/keys."""
import base64,copy,socket,threading,unittest
from unittest.mock import patch
from dataclasses import replace
from policy import Rejected,digest
from ticket_scope_apps_v1 import ScopedPublicationApplication
from ticket_offer_overlay_v1 import pair
from batch_checkout_v2.offer import BatchOffer,PROFILE,manifest_hash
from ticket_service_v3 import PublicationApplicationV3,request
from ticket_publication_v3 import IndexFirstPublicationWorker
from ticket_server_v1 import RoleServer,ServerLimits
from ticket_transport_v3 import PublicationRemoteV3,ENDPOINT
from test_ticket_transport_v2 import contexts,HOST
import test_ticket_publication_v3 as fixture

class ScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixture.IndexFirstTests.setUpClass()
    def setUp(self):
        self.f=fixture.IndexFirstTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        f=self.f.f;manifest=copy.deepcopy(f.offer.manifest)
        manifest['terms'].update(profile=PROFILE,payment_receipt_version=2,packs_per_payment=25)
        manifest.update(purchase_contract=f.f.accounts[8],purchase_runtime_keccak='0x'+'ab'*32)
        self.offer=BatchOffer(manifest,manifest_hash(manifest),f.f.crypto.native)
        self.base=PublicationApplicationV3(self.f.worker)
        self.added=self.application(f.queue);self.app=ScopedPublicationApplication(self.base,self.added)
        pending=self.offer.protocol.prepare()
        self.token=self.offer.protocol.finalize(pending,f.f.crypto.sign(pending['request']['blinded']))
    def application(self,queue):
        w=self.f.worker
        return PublicationApplicationV3(IndexFirstPublicationWorker(self.offer,queue,w.index,w.content,w.native,
            resolve_original=w.resolve_original))
    def message(self,offer,token,h,raw):
        return request(offer.hash,'submit',{'ticket':token,'bundle_hash':h,'bundle_base64':base64.b64encode(raw).decode()})
    def submit(self,offer,token):
        h,raw=self.f.post();message=self.message(offer,token,h,raw)
        result=self.app.dispatch(message);self.assertEqual(result['status'],'ok')
        return h,raw,message,result
    def test_both_domains_share_exact_journal_context_nonce_and_cumulative_capacity(self):
        f=self.f.f;context=f.queue.context;limits=f.queue.limits;fees=copy.deepcopy(f.queue.fees.policy)
        old=self.submit(f.offer,f.tokens[0]);new=self.submit(self.offer,self.token)
        for item in(old,new):
            reply=self.app.dispatch(item[2]);self.assertEqual(reply['status'],'ok')
            self.assertEqual(reply['offer_sha256'],item[2]['offer_sha256'])
            self.assertEqual(reply['result']['parameters'],item[2]['offer_sha256'])
        self.assertEqual(f.queue.context,context);self.assertEqual(f.queue.limits,limits);self.assertEqual(f.queue.fees.policy,fees)
        self.assertEqual(f.rpc.call('eth_getTransactionCount',f.signer.address,'latest'),'0x2')
        with f.queue._db()as db:
            rows=db.execute('SELECT parameters,bundle_hash FROM ticket_jobs').fetchall()
            self.assertEqual({(r['parameters'],r['bundle_hash'])for r in rows},{(f.offer.hash,old[0]),(self.offer.hash,new[0])})
    def test_unknown_scope_and_retagged_token_cannot_admit_or_spend(self):
        h,raw=self.f.post();good=self.message(self.offer,self.token,h,raw)
        for changed in({**good,'offer_sha256':'ff'*32},{**good,'offer_sha256':self.base.offer.hash}):
            with self.assertRaises(Rejected):self.app.dispatch(changed)
        with self.f.f.queue._db()as db:self.assertEqual(db.execute('SELECT count(*)FROM ticket_jobs').fetchone()[0],0)
        self.assertEqual(self.f.f.rpc.call('eth_getTransactionCount',self.f.f.signer.address,'latest'),'0x0')
    def test_background_restart_keeps_job_scope_and_recovers_original_operation(self):
        h,raw=self.f.post();message=self.message(self.offer,self.token,h,raw)
        with patch.object(self.added.worker,'_resume',side_effect=OSError('synthetic-lost-after-admission')):
            self.assertEqual(self.app.dispatch(message)['status'],'rejected')
        # Rebuild the same authenticated queue from its managed fixture journal.
        q=self.f.f.make_queue();w=self.f.worker
        base=PublicationApplicationV3(IndexFirstPublicationWorker(w.offer,q,w.index,w.content,w.native,resolve_original=w.resolve_original))
        restored=ScopedPublicationApplication(base,self.application(q))
        results=restored.recover_pending(4);self.assertEqual(len(results),1)
        self.assertEqual(results[0]['parameters'],self.offer.hash)
        restored.recover_pending(4);self.assertIsNotNone(w.index.record_for_hash(h))
        self.assertEqual(self.f.f.rpc.call('eth_getTransactionCount',self.f.f.signer.address,'latest'),'0x1')
    def test_second_queue_changed_price_or_mutated_offer_is_rejected(self):
        with self.assertRaisesRegex(Rejected,'authority'):
            ScopedPublicationApplication(self.base,self.application(self.f.f.make_queue()))
        changed=copy.deepcopy(self.offer.manifest);changed['terms']['pack_price_wei']=str(int(changed['terms']['pack_price_wei'])+1)
        with self.assertRaisesRegex(Rejected,'changed-authority'):pair(self.base.offer.manifest,changed)
        self.offer.manifest['purchase_contract']=self.f.f.f.accounts[9]
        h,raw=self.f.post()
        with self.assertRaises(Rejected):self.app.dispatch(request(self.base.offer.hash,'store',{
            'bundle_hash':h,'bundle_base64':base64.b64encode(raw).decode()}))
    def test_shared_capacity_is_not_a_new_allowance_per_offer(self):
        # Lower the synthetic queue cap before creating either job. This tests
        # the shared accounting behavior; no live/runtime limit is changed.
        self.f.f.queue.limits=replace(self.f.f.queue.limits,max_submissions=1)
        self.submit(self.base.offer,self.f.f.tokens[0])
        h,raw=self.f.post();result=self.app.dispatch(self.message(self.offer,self.token,h,raw))
        self.assertEqual(result['status'],'rejected')
        self.assertEqual(self.f.f.rpc.call('eth_getTransactionCount',self.f.f.signer.address,'latest'),'0x1')
    def test_real_TLS_dispatch_preserves_each_offer_and_one_server_recovery_authority(self):
        serverctx,clientctx=contexts();listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(4)
        server=RoleServer(self.app,serverctx,listener,ServerLimits(2,8,16,1,4,2))
        stop=threading.Event();ready=threading.Event();thread=threading.Thread(target=server.run,args=(stop,lambda _:ready.set()))
        thread.start();self.assertTrue(ready.wait(3))
        try:
            for offer,token in((self.base.offer,self.f.f.tokens[0]),(self.offer,self.token)):
                remote=PublicationRemoteV3({'profile':ENDPOINT,'host':HOST,'connect_host':'route.example.test',
                    'port':443,'service':'publication','offer_sha256':offer.hash},clientctx,
                    dial=lambda:socket.create_connection(listener.getsockname(),timeout=3))
                h,raw=self.f.post();reply=remote.submit_bundle(token,h,raw);self.assertEqual(reply['parameters'],offer.hash)
        finally:stop.set();thread.join(timeout=5);listener.close()
        self.assertFalse(thread.is_alive());self.assertEqual(server.role,'publication')
    def test_old_server_config_cannot_silently_enable_second_offer(self):
        from dataclasses import asdict
        serverctx,_=contexts();listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(2);self.addCleanup(listener.close)
        config={'profile':'nockapp-ticket-role-server-v1','service':'publication','offer_sha256':self.base.offer.hash,
            'limits':asdict(ServerLimits(2,8,16,1,4,2))}
        with self.assertRaises(Rejected):RoleServer.from_config(self.app,serverctx,listener,config,digest(config))
        config.update(profile='nockapp-ticket-role-server-scopes-v2',scope_sha256=self.app.scope_sha256)
        self.assertIs(RoleServer.from_config(self.app,serverctx,listener,config,digest(config)).application,self.app)
        config['scope_sha256']='11'*32
        with self.assertRaises(Rejected):RoleServer.from_config(self.app,serverctx,listener,config,digest(config))
if __name__=='__main__':unittest.main()
