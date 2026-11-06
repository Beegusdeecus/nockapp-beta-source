"""Pinned overlay boot with real local payments/signatures; synthetic keys/S3."""
import copy,json,subprocess,unittest
from pathlib import Path
from unittest.mock import patch
from base_evm import TOOLS,encode
from base_protocol import keccak
from policy import canonical,digest,Rejected
from ticket_offer_overlay_v1 import PROFILE,validate
from batch_checkout_v2.offer import BatchOffer,PROFILE as BATCH,terms_hash,manifest_hash
from ticket_service_v2 import request
from ticket_scope_apps_v1 import ScopedPaymentApplication
from test_ticket_backend_boot_v1 import BootBase,RoutedS3,pin
import test_ticket_publication_v2 as fixture

class OverlayTests(BootBase,unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.PublicationTests.setUpClass();z=Path(__file__).parent
        request={'language':'Solidity','sources':{'Batch.sol':{'content':(z/'batch_checkout_v2/PrepaidTicketPacksBatchV2.sol').read_text()}},
            'settings':{'optimizer':{'enabled':True,'runs':200},'evmVersion':'prague','outputSelection':{'*':{'*':['evm.bytecode.object']}}}}
        compiled=json.loads(subprocess.run([str(TOOLS/'solc-0.8.30'),'--standard-json'],input=json.dumps(request).encode(),capture_output=True,check=True).stdout)
        cls.creation=compiled['contracts']['Batch.sol']['PrepaidTicketPacksBatchV2']['evm']['bytecode']['object']
    def setUp(self):
        self.f=fixture.PublicationTests();self.f.setUp();self.addCleanup(self.f.doCleanups);f=self.f.f
        t=copy.deepcopy(self.f.offer.terms);t.update(profile=BATCH,payment_receipt_version=2,packs_per_payment=25)
        receipt=f.rpc.tx(f.accounts[0],'0x'+self.creation+encode('f(bytes32,address,uint256,uint64)',terms_hash(t),t['payment_recipient'],t['pack_price_wei'],t['purchase_before'])[10:])
        manifest={'terms':t,'purchase_contract':receipt['contractAddress'],'purchase_runtime_keccak':keccak(bytes.fromhex(f.rpc.call('eth_getCode',receipt['contractAddress'],'latest')[2:]))}
        self.offer=BatchOffer(manifest,manifest_hash(manifest),f.crypto.native)
        self.cfg=self.config('payment',self.f.offer,{'publication':self.f.signer.address,'refund':f.accounts[6]},
            {'purchase_bucket':f.decisions.bucket})
        self.body_value=self.body(self.cfg,f.crypto.private)
        self.plan={'profile':PROFILE,'base_backend_sha256':pin(self.cfg),'offer':manifest,'offer_sha256':self.offer.hash}
        self.sdk=RoutedS3({f.decisions.bucket:f.s3})
    def arguments(self):return {'ticket_native':self.f.f.crypto.native,'rpc':self.f.f.rpc,'s3':self.sdk,
        'offer_overlay':{'plan':self.plan,'sha256':digest(self.plan)}}
    def test_same_old_packet_boots_both_domains_without_key_or_record_rebinding(self):
        cfg=canonical(self.cfg);body=canonical(self.body_value);before=copy.deepcopy(self.f.f.s3.records)
        with patch('ticket_backend_boot_v1.harden_process'):app,_,server=self.boot(self.cfg,self.body_value,**self.arguments())
        self.assertIs(type(app),ScopedPaymentApplication);self.assertEqual(server['offer_sha256'],self.f.offer.hash)
        self.assertEqual(canonical(self.cfg),cfg);self.assertEqual(canonical(self.body_value),body)
        old_request,_=self.f.f.paid()
        old=app.dispatch(request(self.f.offer.hash,'payment','issue',old_request));self.assertEqual(old['status'],'ok')
        pending=[self.offer.protocol.prepare()for _ in range(2)];pack=self.offer.protocol.blinded_pack(pending)
        packs=[self.offer.pack_hash(pack)]+['0x'+format(i,'064x')for i in range(1,25)]
        tx=self.offer.transaction(packs)
        transaction=self.f.f.rpc.call('eth_sendTransaction',{'from':self.f.f.accounts[1],**tx,'gas':hex(2000000)})
        receipt=self.f.f.receipt(transaction);self.assertEqual(receipt['status'],'0x1')
        message=request(self.offer.hash,'payment','issue',{'pack':pack,'transaction_hash':receipt['transactionHash']})
        response=app.dispatch(message);self.assertEqual(response['status'],'ok');self.assertEqual(response['result']['parameters'],self.offer.hash)
        for prepared,signature in zip(pending,response['result']['signatures']):self.offer.protocol.verify(self.offer.protocol.finalize(prepared,signature))
        puts=len(self.f.f.s3.puts);self.assertEqual(app.dispatch(message),response);self.assertEqual(len(self.f.f.s3.puts),puts+1)
        # The immutable decision may be reasserted, never a fresh signature/result.
        for key,value in before.items():self.assertEqual(self.f.f.s3.records[key],value)
        extra=[args['Key']for _,args in self.sdk.calls if args.get('Key','').startswith('ticket-purchases-v1/'+self.offer.hash+'/')]
        self.assertTrue(extra);self.assertTrue(all('/decisions/'in n or'/results/'in n for n in extra))
    def test_wrong_overlay_pin_or_changed_authority_rejected_before_private_input(self):
        for mode in('wrong-pin','wrong-base','changed-price'):
            plan=copy.deepcopy(self.plan)
            if mode=='wrong-base':plan['base_backend_sha256']='11'*32
            if mode=='changed-price':
                plan['offer']['terms']['pack_price_wei']=str(int(plan['offer']['terms']['pack_price_wei'])+1)
                plan['offer_sha256']=manifest_hash(plan['offer'])
            args=self.arguments();args['offer_overlay']={'plan':plan,'sha256':'ff'*32 if mode=='wrong-pin'else digest(plan)}
            with patch('ticket_backend_boot_v1.read_private',side_effect=AssertionError('private pipe must remain unread')):
                with self.assertRaises(Rejected):self.boot(self.cfg,self.body_value,**args)
        self.assertEqual(self.sdk.calls,[])
    def test_overlay_cannot_add_unbounded_domains_or_modify_original_backend(self):
        for change in({'offers':[self.plan['offer']]},{'allow_any_offer':True},{'role':'publication'}):
            changed={**self.plan,**change}
            with self.assertRaises(Rejected):validate(changed,digest(changed),self.cfg,pin(self.cfg))
        cfg=copy.deepcopy(self.cfg);cfg['key_bindings']['publication']=self.f.f.accounts[4]
        with self.assertRaises(Rejected):validate(self.plan,digest(self.plan),cfg,pin(cfg))
if __name__=='__main__':unittest.main()
