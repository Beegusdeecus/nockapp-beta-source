"""Synthetic encrypted wallet and actual local-EVM atomic payment; no owner data."""
import json,subprocess,unittest
from unittest.mock import patch
from base_evm import TOOLS,encode
from policy import Rejected,canonical
from ticket_bulk_purchase_v1 import BulkPurchase
from test_ticket_purchase_v1 import PurchaseTests

class BulkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        PurchaseTests.setUpClass()
        source='''pragma solidity 0.8.30;
interface Packs {function buy(bytes32 h) external payable;}
contract Fixture {function pay(address target,bytes32[25] calldata ids,uint256 each) external payable {
require(msg.sender==address(this) && msg.value==25*each);for(uint i=0;i<25;i++)Packs(target).buy{value:each}(ids[i]);}}'''
        request={'language':'Solidity','sources':{'Fixture.sol':{'content':source}},'settings':{'outputSelection':{'*':{'*':['evm.deployedBytecode.object']}}}}
        result=subprocess.run([str(TOOLS/'solc-0.8.30'),'--standard-json'],input=json.dumps(request).encode(),capture_output=True,check=True)
        cls.runtime=json.loads(result.stdout)['contracts']['Fixture.sol']['Fixture']['evm']['deployedBytecode']['object']
    def setUp(self):
        self.f=PurchaseTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.bulk=BulkPurchase(self.f.client,self.f.rpc,self.f.issuer)
    def pay_batch(self,b,payer=None):
        payer=payer or self.f.accounts[1]
        # Synthetic account code emulates one atomic self-call; not EIP-7702 acceptance.
        self.f.rpc.call('anvil_setCode',payer,'0x'+self.runtime)
        ids='['+','.join('0x'+call['data'][-64:] for call in b['calls'])+']'
        data=encode('pay(address,bytes32[25],uint256)',self.f.contract,ids,self.f.terms['pack_price_wei'])
        tx=self.f.rpc.call('eth_sendTransaction',{'from':payer,'to':payer,'data':data,'value':hex(int(b['total_price_wei'])),'gas':hex(4000000)})
        receipt=self.f.receipt(tx);self.assertEqual(receipt['status'],'0x1');return tx
    def test_fifty_tickets_one_payment_preserves_old_assignments_and_crash_recovery(self):
        for _ in range(3):
            request,_=self.f.paid();self.f.client.receive(self.f.issuer.issue(**request))
        for number in range(6):self.f.client.reserve('0x'+format(number+1,'064x'),self.f.now)
        before=self.f.client._load()['tickets']
        b=self.bulk.prepare(self.f.now,True);self.assertEqual(b['ticket_count'],50)
        self.assertLess(len(canonical(self.bulk._read())),131072)
        self.assertNotIn('requests',json.dumps(b));self.assertEqual(self.bulk.prepare(self.f.now,True),b)
        armed=self.bulk.arm(b['batch_id'],self.f.accounts[1],True);self.assertTrue(armed['dispatch_authorized'])
        with self.assertRaises(Rejected):self.bulk.arm(b['batch_id'],self.f.accounts[1],True)
        with self.assertRaises(Rejected):self.f.client.prepare_purchase(self.f.now,True)
        tx=self.pay_batch(b)
        original_write=self.bulk._write;crashed=False
        def crash(value):
            nonlocal crashed
            if value['imported']==1 and not crashed:crashed=True;raise RuntimeError('synthetic-lost-cursor-write')
            original_write(value)
        with patch.object(self.bulk,'_write',side_effect=crash):
            with self.assertRaises(RuntimeError):self.bulk.recover(b['batch_id'],True)
        self.assertEqual(self.f.client.status()['available'],2)
        for _ in range(25):result=self.bulk.recover(b['batch_id'],True)
        self.assertEqual(result['phase'],'complete');self.assertEqual(result['imported_tickets'],50);self.assertEqual(result['transaction_hash'],tx)
        self.assertEqual(self.f.client.status()['available'],50);self.assertEqual(self.f.client.status()['reserved'],6)
        self.assertEqual(self.f.client._load()['tickets'][:6],before)
        self.assertEqual(self.bulk.recover(b['batch_id'],True),result)
        self.assertFalse(self.f.client.status()['purchase_pending'])
    def test_partial_payment_cannot_authorize_a_bulk_import(self):
        b=self.bulk.prepare(self.f.now,True);self.bulk.arm(b['batch_id'],self.f.accounts[1],True)
        self.f.send({'to':b['calls'][0]['to'],'data':b['calls'][0]['data'],'value':b['calls'][0]['value']})
        with self.assertRaisesRegex(Rejected,'not-atomic'):self.bulk.recover(b['batch_id'],True)
        self.assertEqual(self.f.client.status()['available'],0);self.assertEqual(self.bulk.status()['phase'],'armed')
        before=self.f.client.wallet.read('pending.sealed')
        with self.assertRaises(Rejected):self.bulk.record_payment(b['batch_id'],'0x'+'11'*32,True)
        self.assertEqual(self.f.client.wallet.read('pending.sealed'),before)

    def test_public_transaction_hash_requires_full_original_receipt_and_preserves_import_cursor(self):
        b=self.bulk.prepare(self.f.now,True);self.bulk.arm(b['batch_id'],self.f.accounts[1],True)
        tx=self.pay_batch(b);before=self.f.client.wallet.read('pending.sealed')
        for batch,transaction,approve in ((b['batch_id'],'0x'+'11'*32,True),('ab'*32,tx,True),(b['batch_id'],tx,False)):
            with self.assertRaises(Rejected):self.bulk.record_payment(batch,transaction,approve)
            self.assertEqual(self.f.client.wallet.read('pending.sealed'),before)
        saved=self.bulk.record_payment(b['batch_id'],tx,True)
        self.assertEqual(saved['transaction_hash'],tx);self.assertEqual(saved['phase'],'importing')
        self.assertEqual(self.f.client.status()['available'],0)
        self.bulk.recover(b['batch_id'],True)
        self.assertEqual(self.bulk.record_payment(b['batch_id'],tx,True)['imported_tickets'],2)
        self.assertEqual(self.f.client.status()['available'],2)

    def test_legacy_plain_and_bounded_compressed_journals_preserve_exact_blind_inputs(self):
        import base64,zlib
        from wallet import MAX_PLAIN
        b=self.bulk.prepare(self.f.now,True);original=self.bulk._read();raw=canonical(original)
        self.assertEqual(self.bulk.status()['batch_id'],b['batch_id'])
        envelope={'profile':self.bulk.profile,'phase':original['phase'],'encoding':'zlib-canonical-json-v1',
            'payload':base64.b64encode(zlib.compress(raw)).decode()}
        self.f.client.wallet.save('pending',envelope)
        self.assertEqual(self.bulk._read(),original)
        if len(raw)<=MAX_PLAIN:
            self.f.client.wallet.save('pending',original)
            self.assertEqual(self.bulk._read(),original)
        for packed in (zlib.compress(b' '* (self.bulk.max_plain+1)),zlib.compress(raw)+b'extra'):
            self.f.client.wallet.save('pending',{**envelope,'payload':base64.b64encode(packed).decode()})
            with self.assertRaises(Rejected):self.bulk._read()
    def test_wrong_payer_cannot_import_and_no_second_wallet_dispatch(self):
        b=self.bulk.prepare(self.f.now,True);self.bulk.arm(b['batch_id'],self.f.accounts[1],True)
        self.pay_batch(b,payer=self.f.accounts[2])
        with self.assertRaises(Rejected):self.bulk.recover(b['batch_id'],True)
        self.assertEqual(self.f.client.status()['available'],0)
        with self.assertRaises(Rejected):self.bulk.arm(b['batch_id'],self.f.accounts[1],True)
    def test_existing_purchase_and_unapproved_bulk_are_preserved(self):
        with self.assertRaises(Rejected):self.bulk.prepare(self.f.now,False)
        old=self.f.client.prepare_purchase(self.f.now,True)
        with self.assertRaises(Rejected):self.bulk.prepare(self.f.now,True)
        self.assertEqual(self.f.client.purchase_state()['purchase'],old)
    def test_refund_preparation_pauses_automatic_import_and_keeps_existing_refund_path(self):
        b=self.bulk.prepare(self.f.now,True);self.bulk.arm(b['batch_id'],self.f.accounts[1],True);tx=self.pay_batch(b)
        paused=self.bulk.recover(b['batch_id'],True,prepare_refund=True)
        self.assertEqual(paused['phase'],'paused');self.assertEqual(self.f.client.status()['available'],0)
        self.assertEqual(self.f.client.purchase_state()['purchase']['payment_tx'],tx)
        with self.assertRaisesRegex(Rejected,'paused'):self.bulk.recover(b['batch_id'],True)
        resumed=self.bulk.recover(b['batch_id'],True,resume=True)
        self.assertEqual(resumed['imported_tickets'],2);self.assertEqual(resumed['phase'],'importing')

    def test_explicitly_include_unarmed_pack_preserves_exact_inputs_and_imports_fifty(self):
        old=self.f.client.prepare_purchase(self.f.now,True);before=self.f.client._load()['pending']
        b=self.bulk.prepare(self.f.now,True,include_prepared_pack=True)
        self.assertEqual(self.bulk._read()['items'][0],before)
        self.assertEqual(self.f.client._load()['pending'],before)
        self.assertEqual(b['calls'][0]['data'],old['transaction']['data'])
        self.assertEqual(self.bulk.prepare(self.f.now,True,include_prepared_pack=True),b)
        with self.assertRaisesRegex(Rejected,'bulk-purchase-pending'):
            self.f.client.arm_payment(old['pack_hash'],self.f.accounts[1],0,True)
        self.bulk.arm(b['batch_id'],self.f.accounts[1],True)
        self.assertIsNone(self.f.client._load()['pending']);self.assertEqual(self.bulk._read()['items'][0],before)
        self.pay_batch(b)
        for _ in range(25):result=self.bulk.recover(b['batch_id'],True)
        self.assertEqual(result['phase'],'complete');self.assertEqual(self.f.client.status()['available'],50)

    def test_include_rejects_armed_attempt_without_changing_it(self):
        p=self.f.client.prepare_purchase(self.f.now,True);self.f.client.arm_payment(p['pack_hash'],self.f.accounts[1],0,True)
        before=self.f.client._load()
        with self.assertRaises(Rejected):self.bulk.prepare(self.f.now,True,include_prepared_pack=True)
        self.assertEqual(self.f.client._load(),before);self.assertIsNone(self.bulk._read())

    def test_include_rejects_recorded_payment_without_changing_it(self):
        self.f.paid();before=self.f.client._load()
        with self.assertRaises(Rejected):self.bulk.prepare(self.f.now,True,include_prepared_pack=True)
        self.assertEqual(self.f.client._load(),before);self.assertIsNone(self.bulk._read())

    def test_unrecorded_existing_chain_payment_stops_inclusion_without_writes(self):
        p=self.f.client.prepare_purchase(self.f.now,True);before=self.f.client._load()
        self.f.send(p['transaction'])
        with self.assertRaises(Rejected):self.bulk.prepare(self.f.now,True,include_prepared_pack=True)
        self.assertEqual(self.f.client._load(),before);self.assertIsNone(self.bulk._read())

    def test_crash_after_batch_arm_before_single_slot_release_recovers_same_fifty(self):
        self.f.client.prepare_purchase(self.f.now,True);before=self.f.client._load()['pending']
        b=self.bulk.prepare(self.f.now,True,include_prepared_pack=True)
        with patch.object(self.f.client,'_save',side_effect=RuntimeError('synthetic-before-slot-release')):
            with self.assertRaises(RuntimeError):self.bulk.arm(b['batch_id'],self.f.accounts[1],True)
        self.assertEqual(self.bulk.status()['phase'],'armed');self.assertEqual(self.f.client._load()['pending'],before)
        with self.assertRaises(Rejected):self.bulk.arm(b['batch_id'],self.f.accounts[1],True)
        self.pay_batch(b)
        for _ in range(25):result=self.bulk.recover(b['batch_id'],True)
        self.assertEqual(result['phase'],'complete');self.assertEqual(self.f.client.status()['available'],50)
