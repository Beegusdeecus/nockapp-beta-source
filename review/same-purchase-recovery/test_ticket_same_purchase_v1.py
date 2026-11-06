"""Exact deployed wallet bytecode, synthetic EOA/keys and local EVM only."""
import copy,json,unittest
from pathlib import Path
from types import SimpleNamespace
from policy import Rejected,digest
from base_evm import encode
from base_protocol import keccak
from ticket_bulk_purchase_v1 import BulkPurchase
from ticket_same_purchase_v1 import IMPLEMENTATION,IMPLEMENTATION_HASH,MODE,calldata,review,arm,validate
from test_ticket_purchase_v1 import PurchaseTests as Fixture

class SamePurchaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Fixture.setUpClass();cls.runtime=(Path(__file__).parent/'test_inputs/metamask-stateless7702-v1.3.0-runtime.hex').read_text().strip()
        assert keccak(bytes.fromhex(cls.runtime[2:]))==IMPLEMENTATION_HASH
    def setUp(self):
        self.f=Fixture();self.f.setUp();self.addCleanup(self.f.doCleanups);f=self.f
        self.payer=f.accounts[1];f.rpc.call('anvil_setCode',IMPLEMENTATION,self.runtime)
        f.rpc.call('anvil_setCode',self.payer,'0xef0100'+IMPLEMENTATION[2:])
        f.rpc.call('anvil_setNextBlockBaseFeePerGas','0x0');f.rpc.call('evm_mine')
        self.gas_price=1000000
        self.rpc=SimpleNamespace(call=lambda method,*args:hex(self.gas_price)if method=='eth_gasPrice'else f.rpc.call(method,*args))
        self.bulk=BulkPurchase(f.client,self.rpc,f.issuer)
        self.saved=self.bulk.prepare(f.now,True);self.bulk.arm(self.saved['batch_id'],self.payer,True)
        self.before=copy.deepcopy(self.bulk._read())
    def quote(self):return review(self.bulk,'100000000000000',self.f.now)
    def submit(self,transaction):return self.f.receipt(self.f.rpc.call('eth_sendTransaction',transaction))
    def delayed(self):
        # Isolated impersonation models the already-approved old execution path.
        manager='0x'+self.f.rpc.call('eth_call',{'to':IMPLEMENTATION,'data':encode('delegationManager()')},'latest')[-40:]
        self.f.rpc.call('anvil_impersonateAccount',manager);self.f.rpc.call('anvil_setBalance',manager,hex(10**22))
        data=calldata(self.before,self.f.client.offer);execution='0x'+data[10+64+64+64:]
        return self.submit({'from':manager,'to':self.payer,'data':encode('executeFromExecutor(bytes32,bytes)','0x'+MODE,execution),'gas':hex(2000000)})
    def principal(self):return int(self.f.rpc.call('eth_getBalance',self.f.terms['payment_recipient'],'latest'),16)
    def test_resume_then_delayed_original_cannot_charge_twice_and_imports_original_tickets(self):
        q=self.quote();a=arm(self.bulk,q,True,self.f.now);self.assertTrue(a['dispatch_authorized'])
        for key in self.before:self.assertEqual(self.bulk._read()[key],self.before[key])
        before=self.principal();r=self.submit(q['transaction']);self.assertEqual(r['status'],'0x1')
        self.assertEqual(self.delayed()['status'],'0x0')
        self.assertEqual(self.principal()-before,int(self.saved['total_price_wei']))
        for _ in range(25):result=self.bulk.recover(self.saved['batch_id'],True)
        self.assertEqual(result['imported_tickets'],50);self.assertEqual(result['phase'],'complete')
        self.assertEqual(self.f.client.status()['available'],50)
    def test_delayed_original_then_resume_reverts_without_second_principal_payment(self):
        q=self.quote();arm(self.bulk,q,True,self.f.now);before=self.principal()
        self.assertEqual(self.delayed()['status'],'0x1')
        self.assertEqual(self.submit(q['transaction'])['status'],'0x0')
        self.assertEqual(self.principal()-before,int(self.saved['total_price_wei']))
        self.assertEqual(self.bulk.recover(self.saved['batch_id'],True)['imported_tickets'],2)
    def test_partial_batch_reverts_entire_resume_and_native_refuses_to_authorize(self):
        call=self.saved['calls'][13]
        self.submit({'from':self.f.accounts[2],'to':call['to'],'data':call['data'],'value':call['value'],'gas':hex(100000)})
        before=self.principal();journal=self.f.client.wallet.read('pending.sealed')
        with self.assertRaises(Rejected):self.quote()
        self.assertEqual(self.f.client.wallet.read('pending.sealed'),journal)
        tx={'from':self.payer,'to':self.payer,'value':hex(int(self.saved['total_price_wei'])),'data':calldata(self.before,self.f.client.offer),'gas':hex(2000000)}
        self.assertEqual(self.submit(tx)['status'],'0x0');self.assertEqual(self.principal(),before)
        first=self.before['items'][0]['pack_hash'];self.assertEqual(self.f.rpc.call('eth_call',{'to':call['to'],'data':encode('paid(bytes32)',first)},'latest'),'0x'+'0'*64)
    def test_altered_mode_nonce_code_and_consumed_review_never_overwrite_journal(self):
        q=self.quote();journal=self.f.client.wallet.read('pending.sealed')
        bad=copy.deepcopy(q);bad['transaction']['data']=bad['transaction']['data'][:12]+'01'+bad['transaction']['data'][14:];bad['quote_sha256']=digest({k:v for k,v in bad.items()if k!='quote_sha256'})
        with self.assertRaises(Rejected):arm(self.bulk,bad,True,self.f.now)
        self.assertEqual(self.f.client.wallet.read('pending.sealed'),journal)
        self.f.rpc.call('anvil_setCode',self.payer,'0x')
        with self.assertRaises(Rejected):arm(self.bulk,q,True,self.f.now)
        self.assertEqual(self.f.client.wallet.read('pending.sealed'),journal)
        self.f.rpc.call('anvil_setCode',self.payer,'0xef0100'+IMPLEMENTATION[2:])
        self.f.rpc.call('anvil_setNonce',self.payer,hex(int(q['transaction']['nonce'],16)+1))
        with self.assertRaises(Rejected):arm(self.bulk,q,True,self.f.now)
        self.assertEqual(self.f.client.wallet.read('pending.sealed'),journal)
    def test_fresh_explicit_review_preserves_same_nonce_and_cumulative_execution_reservation(self):
        q=self.quote();arm(self.bulk,q,True,self.f.now);journal=self.f.client.wallet.read('pending.sealed')
        with self.assertRaises(Rejected):arm(self.bulk,q,True,self.f.now)
        self.assertEqual(self.f.client.wallet.read('pending.sealed'),journal)
        self.gas_price*=2;q2=review(self.bulk,'100000000000000',self.f.now+1);arm(self.bulk,q2,True,self.f.now+1)
        self.assertEqual(q2['transaction']['nonce'],q['transaction']['nonce'])
        fence=self.bulk._read()['resume_payment'];self.assertEqual(len(fence['attempts']),2)
        validate(fence['quote'],self.bulk._read(),self.f.client.offer)
        self.assertEqual(self.f.client.status()['available'],0)

    def test_recovery_execution_reservations_are_bounded_even_when_nonce_is_same(self):
        self.gas_price=500000000
        q=review(self.bulk,'1000000000000000',self.f.now);arm(self.bulk,q,True,self.f.now)
        before=self.f.client.wallet.read('pending.sealed')
        self.assertGreater(int(q['execution_fee_wei']),500000000000000)
        with self.assertRaisesRegex(Rejected,'execution-budget'):
            review(self.bulk,'1000000000000000',self.f.now+1)
        self.assertEqual(self.f.client.wallet.read('pending.sealed'),before)
        self.assertEqual(self.f.client.status()['available'],0)
