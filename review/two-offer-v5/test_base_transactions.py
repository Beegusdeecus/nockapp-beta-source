"""Actual local EIP-1559 signatures, EVM mining and durable lost-reply recovery.

Funding/finality are explicit Anvil fixtures, never live Base evidence.
"""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from base_protocol import ReceiptKey, ordinary_publication_data, keccak
from base_transactions import Limits, ProtectedSigner, TransactionQueue, rlp
from policy import Rejected
import test_base_discussions as discussions


class TransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):discussions.OrdinaryDiscussionTests.setUpClass()

    def setUp(self):
        self.fixture=discussions.OrdinaryDiscussionTests();self.fixture.setUp();self.rpc=self.fixture.rpc
        self.work=tempfile.TemporaryDirectory(prefix='nockapp-transaction-');self.path=Path(self.work.name)/'queue.sqlite'
        self.key=ReceiptKey(self.rpc);self.signer=ProtectedSigner(self.rpc,self.key)
        self.rpc.call('anvil_setBalance',self.key.address,hex(10**20))
        self.selector=keccak(b'publishOrdinary(bytes32,bytes32,bytes)')[:10]
        self.contracts={self.fixture.contract:[self.selector]}
        self.limits=Limits(500000,3000000000,1000000,10**17,100)
        self.queue=self.make(initial_nonce=0)
        self.submission=secrets.token_hex(32);self.post=self.fixture.post
        self.data=ordinary_publication_data(self.post,self.submission)

    def tearDown(self):self.work.cleanup();self.fixture.tearDown()

    def make(self,**kwargs):
        return TransactionQueue(self.rpc,self.signer,self.path,self.contracts,self.limits,laboratory=True,**kwargs)

    def submit(self):return self.queue.submit(self.submission,self.fixture.contract,self.data,300000)

    def test_real_signature_mines_without_node_managed_signing_and_reloads_same_submission(self):
        original=self.rpc.call
        with patch.object(self.rpc,'call',wraps=original) as calls:
            first=self.submit();second=self.queue.poll(self.submission)
        self.assertEqual(first['state'],'pending');self.assertEqual(second['state'],'finalized')
        self.assertFalse(any(c.args[0] in ('eth_sendTransaction','eth_sign','personal_sign') for c in calls.call_args_list))
        tx=self.rpc.call('eth_getTransactionByHash',second['transaction_hash'])
        self.assertEqual(tx['from'].lower(),self.key.address.lower());self.assertEqual(tx['type'],'0x2')
        self.assertEqual(int(tx['chainId'],16),31337);self.assertEqual(tx['input'],self.data)
        rebuilt=self.make();self.assertEqual(rebuilt.submit(self.submission,self.fixture.contract,self.data,300000),second)
        self.assertEqual(int(self.rpc.call('eth_getTransactionCount',self.key.address,'latest'),16),1)

    def test_lost_broadcast_reply_recovers_mined_hash_without_second_send_or_nonce(self):
        original=self.rpc.call;sent=[]
        def lost(method,*args):
            result=original(method,*args)
            if method=='eth_sendRawTransaction':sent.append(args[0]);raise OSError('synthetic lost reply')
            return result
        with patch.object(self.rpc,'call',side_effect=lost):first=self.submit()
        self.assertEqual(first['state'],'recoverable');self.assertEqual(len(sent),1)
        with patch.object(self.rpc,'call',wraps=original) as calls:second=self.make().poll(self.submission)
        self.assertEqual(second['state'],'finalized');self.assertEqual(second['transaction_hash'],first['transaction_hash'])
        self.assertFalse(any(c.args[0]=='eth_sendRawTransaction' for c in calls.call_args_list))

    def test_crash_before_transmission_leaves_durable_exact_bytes_for_rebroadcast(self):
        original=self.rpc.call;attempt=[]
        def failed(method,*args):
            if method=='eth_sendRawTransaction':attempt.append(args[0]);raise OSError('synthetic pre-send outage')
            return original(method,*args)
        with patch.object(self.rpc,'call',side_effect=failed):self.assertEqual(self.submit()['state'],'recoverable')
        with patch.object(self.rpc,'call',wraps=original) as calls:result=self.make().poll(self.submission)
        self.assertEqual(result['state'],'pending')
        actual=[c.args[1] for c in calls.call_args_list if c.args[0]=='eth_sendRawTransaction']
        self.assertEqual(actual,attempt);self.assertEqual(self.queue.poll(self.submission)['state'],'finalized')

    def test_simultaneous_same_submission_uses_single_nonce_and_signature(self):
        other=self.make()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda q:q.submit(self.submission,self.fixture.contract,self.data,300000),[self.queue,other]))
        self.assertEqual(len({r['transaction_hash'] for r in results}),1)
        self.assertEqual(int(self.rpc.call('eth_getTransactionCount',self.key.address,'latest'),16),1)

    def test_post_edit_cannot_reuse_submission(self):
        self.submit()
        changed=ordinary_publication_data(dict(self.post,body='altered'),self.submission)
        with self.assertRaises(Rejected):self.queue.submit(self.submission,self.fixture.contract,changed,300000)

    def test_wrong_target_selector_gas_or_chain_rejected_before_signing(self):
        for target,data,gas in [(self.fixture.registry,self.data,300000),
            (self.fixture.contract,'0xdeadbeef',300000),(self.fixture.contract,self.data,500001)]:
            with self.assertRaises(Rejected):self.queue.submit(self.submission,target,data,gas)
        with self.assertRaises(Rejected):TransactionQueue(self.rpc,self.signer,self.path,self.contracts,self.limits)
        self.assertEqual(int(self.rpc.call('eth_getTransactionCount',self.key.address,'latest'),16),0)

    def test_missing_journal_never_recreates_or_resets_nonce(self):
        self.path.unlink()
        with self.assertRaises(Rejected):self.make()
        self.assertFalse(self.path.exists())

    def test_fee_and_submission_limits_persist_across_restart(self):
        self.submit()
        altered=Limits(500000,3000000000,1000000,10**18,1000)
        with self.assertRaises(Rejected):TransactionQueue(self.rpc,self.signer,self.path,self.contracts,altered,laboratory=True)
        with self.queue._db() as db:
            self.assertEqual(db.execute('SELECT sum(reserve) FROM submissions').fetchone()[0],300000*3000000000)
        limited=Path(self.work.name)/'limited.sqlite'
        queue=TransactionQueue(self.rpc,self.signer,limited,self.contracts,
            Limits(500000,3000000000,1000000,100000,1),initial_nonce=1,laboratory=True)
        with self.assertRaises(Rejected):queue.submit(secrets.token_hex(32),self.fixture.contract,self.data,300000)

    def test_unexpected_nonce_consumption_never_retries_intent_at_another_nonce(self):
        original=self.rpc.call
        def failed(method,*args):
            if method=='eth_sendRawTransaction':raise OSError('synthetic outage')
            return original(method,*args)
        with patch.object(self.rpc,'call',side_effect=failed):self.submit()
        # Explicit local corruption/fault fixture: another signer user spends the
        # dedicated key's nonce. Queue must stop instead of guessing a new nonce.
        self.rpc.call('anvil_setNonce',self.key.address,'0x1')
        with patch.object(self.rpc,'call',wraps=original) as calls:result=self.make().poll(self.submission)
        self.assertEqual(result['state'],'nonce-conflict')
        self.assertFalse(any(c.args[0]=='eth_sendRawTransaction' for c in calls.call_args_list))

    def test_pending_is_not_finalized_and_orphaned_receipt_is_recovered(self):
        snap=self.rpc.call('evm_snapshot');first=self.submit();original=self.rpc.call
        head=original('eth_getBlockByNumber','0x0',False)
        def delayed(method,*args):
            if method=='eth_getBlockByNumber' and args[0]=='finalized':return head
            return original(method,*args)
        with patch.object(self.rpc,'call',side_effect=delayed):self.assertEqual(self.queue.poll(self.submission)['state'],'confirmed')
        self.rpc.call('evm_revert',snap)
        self.assertEqual(self.make().poll(self.submission)['transaction_hash'],first['transaction_hash'])
        self.assertEqual(self.queue.poll(self.submission)['state'],'finalized')

    def test_finalized_transaction_disappearance_fails_closed(self):
        snap=self.rpc.call('evm_snapshot');self.submit();self.assertEqual(self.queue.poll(self.submission)['state'],'finalized')
        self.rpc.call('evm_revert',snap)
        with self.assertRaises(Rejected):self.make().poll(self.submission)

    def test_known_pending_transaction_is_not_rebroadcast(self):
        self.rpc.call('evm_setAutomine',False);self.submit();original=self.rpc.call
        with patch.object(self.rpc,'call',wraps=original) as calls:self.assertEqual(self.make().poll(self.submission)['state'],'pending')
        self.assertFalse(any(c.args[0]=='eth_sendRawTransaction' for c in calls.call_args_list))
        self.rpc.call('evm_mine');self.assertEqual(self.queue.poll(self.submission)['state'],'finalized')

    def test_wrapped_transaction_key_recovers_same_signer_and_rejects_context_tamper(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from base_keys import wrap_transaction_key,recover_transaction_key,TRANSACTION_PROFILE
        from base_state import Replicas
        class FixtureKMS:
            def __init__(self):self.cipher=AESGCM(secrets.token_bytes(32))
            def wrap(self,data,aad):
                nonce=secrets.token_bytes(12);return nonce+self.cipher.encrypt(nonce,data,aad)
            def unwrap(self,data,aad):return self.cipher.decrypt(data[:12],data[12:],aad)
        kms=FixtureKMS();replicas=Replicas([Path(self.work.name)/'a',Path(self.work.name)/'b'])
        context={'profile':TRANSACTION_PROFILE,'role':'sponsor','chain_id':31337,
            'contract':self.fixture.contract,'address':self.key.address}
        digest=wrap_transaction_key(kms,replicas,context,self.key.key,self.rpc)
        recovered=recover_transaction_key(kms,replicas,digest,context,self.rpc)
        self.assertEqual(recovered.address,self.signer.address)
        queue=TransactionQueue(self.rpc,recovered,self.path,self.contracts,self.limits,laboratory=True)
        self.assertEqual(queue.submit(self.submission,self.fixture.contract,self.data,300000)['state'],'pending')
        for altered in (dict(context,chain_id=84532),dict(context,role='issuer-updater'),
            dict(context,contract=self.fixture.registry),dict(context,address=self.fixture.accounts[0])):
            with self.assertRaises(Exception):recover_transaction_key(kms,replicas,digest,altered,self.rpc)

    def test_existing_transaction_api_uses_queue_and_refuses_unlocked_or_wrong_sender(self):
        from base_transactions import SignedRPC
        adapter=SignedRPC(self.rpc,self.queue)
        receipt=adapter.tx(self.key.address,self.data,self.fixture.contract,300000)
        self.assertEqual(receipt['status'],'0x1')
        self.assertEqual(adapter.tx(self.key.address,self.data,self.fixture.contract,300000),receipt)
        with self.assertRaises(Rejected):adapter.call('eth_sendTransaction',{})
        with self.assertRaises(Rejected):adapter.tx(self.fixture.accounts[0],self.data,self.fixture.contract,300000)

    def test_journal_mutations_cannot_change_intent_nonce_cost_or_terminal_status(self):
        from contextlib import closing
        import sqlite3
        self.submit();self.queue.poll(self.submission)
        with closing(sqlite3.connect(self.path)) as db:
            for column,value in [('intent','{}'),('nonce',55),('reserve',1),('raw','0x02'),('state','recoverable')]:
                original=db.execute('SELECT '+column+' FROM submissions').fetchone()[0]
                db.execute('UPDATE submissions SET '+column+'=?',(value,));db.commit()
                with self.assertRaisesRegex(Rejected,'transaction-journal-authentication'):self.make()
                db.execute('UPDATE submissions SET '+column+'=?',(original,));db.commit()
            db.execute('UPDATE meta SET next_nonce=99');db.commit()
            with self.assertRaisesRegex(Rejected,'transaction-journal-authentication'):self.make()


class EncodingTests(unittest.TestCase):
    def test_eip_rlp_reference_encodings_and_integer_bounds(self):
        self.assertEqual(rlp(b'dog').hex(),'83646f67')
        self.assertEqual(rlp([b'cat',b'dog']).hex(),'c88363617483646f67')
        self.assertEqual(rlp(0),b'\x80');self.assertEqual(rlp(15),b'\x0f')
        self.assertEqual(rlp(1024).hex(),'820400')
        for value in (-1,2**256,True):
            with self.assertRaises(Rejected):rlp(value)
