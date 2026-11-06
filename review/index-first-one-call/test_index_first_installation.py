"""Complete configured native/TLS/EVM path; keyring/storage/finality fixtures."""
import copy,shutil,socket,ssl,threading,unittest,uuid
from pathlib import Path
from unittest.mock import patch
from base_protocol import sha
from public_installation import factory
from public_bundle_v5 import encode
from public_desktop_v6 import IndexFirstDesktop
from batch_checkout_v2.installation import PROFILE_INDEX
from ticket_transport_v3 import ENDPOINT,PublicationRemoteV3
from ticket_service_v3 import validate_request,PublicationApplicationV3
from ticket_transport_v2 import serve_connection
from ticket_publication_v3 import IndexFirstPublicationWorker
from test_ticket_transport_v2 import contexts
import test_batch_installation_v2 as fixture


class InstalledPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixture.InstallationTests.setUpClass()
    def setUp(self):
        self.seed=fixture.InstallationTests();self.seed.setUp();self.addCleanup(self.seed.doCleanups)
        self.case=self.seed.f;self.runtime=self.case.f;self.raw=self.runtime.f
        cfg=copy.deepcopy(self.seed.config);old=cfg['legacy_ticket_scopes'][0]
        cfg.update({k:v for k,v in old.items()if k!='directory'})
        cfg.update(profile=PROFILE_INDEX,legacy_ticket_scopes=[],checkout_scope=cfg['offer_sha256'])
        endpoint=cfg['publication_endpoint'];endpoint.update(profile=ENDPOINT,connect_host=endpoint['host'])
        self.serverctx,clientctx=contexts(endpoint['host'])
        cfg['operator_ca_pem']=ssl.DER_cert_to_PEM_cert(clientctx.get_ca_certs(binary_form=True)[0])
        data=Path(cfg['data_directory']);data.mkdir(mode=0o700)
        shutil.copytree(self.raw.client.wallet.directory,data/'tickets-v2')
        with patch('public_installation.BaseRPC',return_value=self.runtime.rpc):self.app=factory(cfg,fixture.fixture.ROOT)
        self.app.desktop.clock=lambda:int(self.raw.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16)
        self.runtime.origin.restore=self.runtime.origin.put
        def probe(h,limit):
            value=self.runtime.origin.objects.get(h)
            return {'state':'missing'if value is None else 'present'if sha(value)==h else 'corrupt'}
        self.runtime.origin.probe=probe
        self.app.desktop.content.origin.reader=self.runtime.origin
        self.worker=IndexFirstPublicationWorker(self.runtime.offer,self.runtime.queue,self.runtime.index,
            self.runtime.content,self.runtime.author,resolve_original=self.runtime.reader.resolve_original)
        backend=PublicationApplicationV3(self.worker);self.threads=[]
        def dial():
            left,right=socket.socketpair()
            thread=threading.Thread(target=serve_connection,args=(right,backend,self.serverctx),kwargs={'validator':validate_request})
            thread.start();self.threads.append(thread);return left
        self.app.scopes.primary[1]._dial=dial
        self.addCleanup(lambda:[thread.join(timeout=5)for thread in self.threads])

    def test_native_paid_ticket_path_indexes_before_public_delivery_and_recovers_without_another_spend(self):
        app=self.app;self.assertIsInstance(app.desktop,IndexFirstDesktop)
        self.assertEqual(app.dispatch('public-ticket-status',{})['available'],2)
        app.dispatch('public-initialize-identity',{'approve_private_key_setup':True})
        p={'kind':'thread','id':str(uuid.uuid4()),'created_at':int(app.desktop.clock()),
            'title':'Index first','body':'Exact bytes, one ticket, one number','references':[]}
        app.dispatch('public-prepare',{'post':p,'selection':{'address':False,'followers_threshold':None},
            'thread':None,'references':None,'approve_publication':True})
        app.dispatch('public-finish',{'post_id':p['id'],'approve_publication':True})
        self.assertEqual(self.runtime.origin.puts,0)
        result=app.dispatch('public-publish',{'post_id':p['id'],'approve_publication':True})
        for _ in range(3):
            if result['last_known']['state']=='finalized':break
            self.raw.rpc.call('evm_increaseTime',400);self.raw.rpc.call('evm_mine')
            result=app.dispatch('public-check',{'post_id':p['id']})
        self.assertEqual(result['last_known']['state'],'finalized')
        raw=encode(app.desktop._outbox()['entries'][0]['bundle']);h=sha(raw)
        self.assertEqual(self.runtime.origin.objects[h],raw)
        number=result['last_known']['post_number'];nonce=self.raw.rpc.call('eth_getTransactionCount',self.runtime.signer.address,'latest')
        self.raw.rpc.call('evm_increaseTime',400);self.raw.rpc.call('evm_mine')
        del self.runtime.origin.objects[h]
        app.dispatch('public-check',{'post_id':p['id']})
        self.assertEqual(self.runtime.origin.objects[h],raw)
        self.assertEqual(self.runtime.index.record_for_hash(h)['post_number'],number)
        self.assertEqual(self.raw.rpc.call('eth_getTransactionCount',self.runtime.signer.address,'latest'),nonce)
        self.assertEqual(app.dispatch('public-ticket-status',{})['available'],1)
        self.assertEqual(app.dispatch('public-ticket-status',{})['reserved'],1)
