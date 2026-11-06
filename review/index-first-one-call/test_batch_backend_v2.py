"""Versioned backend admission/issuance using only synthetic key pipes and EVM."""
import copy,tempfile
from pathlib import Path
from unittest.mock import patch
from policy import Rejected
from test_batch_checkout_v2 import BatchFixture
from test_ticket_backend_boot_v1 import BootBase,RoutedS3,pin
import test_ticket_native_v1 as crypto
from test_ticket_bindings_v1 import AtomicS3Fixture
from test_base_enrollment import MemorySecretService
from ticket_backend_boot_v1 import validate,PROFILE,PROFILE_BATCH
from ticket_offer_v1 import configured_offer,configured_payments
from ticket_service_v2 import request
from ticket_wallet_v1 import TicketWallet


class BackendTests(BootBase,BatchFixture):
    def config_payment(self):
        cfg=self.config('payment',self.offer,{'publication':self.accounts[5],'refund':self.accounts[6]},
            {'purchase_bucket':'synthetic-batch-purchases'})
        cfg['profile']=PROFILE_BATCH
        return cfg

    def test_explicit_boot_version_and_pins_reject_silent_scope_reinterpretation(self):
        cfg=self.config_payment();self.assertEqual(validate(cfg,pin(cfg)),cfg)
        with self.assertRaises(Rejected):validate({**cfg,'profile':PROFILE},pin({**cfg,'profile':PROFILE}))
        changed={**cfg,'offer_sha256':'01'*32}
        with self.assertRaises(Rejected):validate(changed,pin(changed))
        self.assertEqual(configured_offer(self.manifest,self.offer.hash,self.native).hash,self.offer.hash)
        self.assertEqual(configured_payments(self.rpc,self.offer).verify_batch.__self__.offer.hash,self.offer.hash)

    def test_recovered_synthetic_payment_key_issues_only_after_real_batch_payment(self):
        cfg=self.config_payment();private=self.body(cfg,crypto.Tickets.private)
        records=AtomicS3Fixture();s3=RoutedS3({'synthetic-batch-purchases':records})
        with patch('ticket_backend_boot_v1.harden_process'):
            app,context,server=self.boot(cfg,private,ticket_native=self.native,rpc=self.rpc,s3=s3)
        self.assertEqual(server['offer_sha256'],self.offer.hash)
        with tempfile.TemporaryDirectory(prefix='batch-backend-wallet-') as d,\
                patch('wallet.WalletSecretService',return_value=MemorySecretService()):
            wallet=TicketWallet(Path(d)/'tickets',self.offer);wallet.initialize()
            pending=wallet.prepare_purchase(self.now,True)
            pack=wallet._load()['pending']['pack'];self.packs[0]=pending['pack_hash']
            before=copy.deepcopy(wallet._load())
            denied=app.dispatch(request(self.offer.hash,'payment','issue',{'pack':pack,'transaction_hash':'0x'+'ab'*32}))
            self.assertEqual(denied['status'],'rejected');self.assertEqual(wallet._load(),before)
            tx=self.pay();wallet.record_payment(pending['pack_hash'],tx)
            body=wallet.issuance_request();message=request(self.offer.hash,'payment','issue',body)
            issued=app.dispatch(message);self.assertEqual(issued['status'],'ok')
            self.assertEqual(wallet.receive(issued['result'])['available'],2)
            self.assertEqual(app.dispatch(message)['result'],issued['result'])
            self.assertTrue(all(self.offer.hash in call[1]['Key']for call in s3.calls if 'Key'in call[1]))
