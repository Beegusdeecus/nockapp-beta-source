"""Actual EVM/signatures/encryption, explicit synthetic managed DynamoDB CAS.

No AWS IAM/effective permission/physical-storage availability claim is made.
"""
import copy
import secrets
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from base_managed_storage import DynamoObjects,DynamoJournalAnchor,CHUNK
from base_transactions import TransactionQueue
from policy import Rejected
import test_base_transactions as transaction_fixture


class ConditionalFailure(Exception):
    response={'Error':{'Code':'ConditionalCheckFailedException'}}


class DynamoFixture:
    def __init__(self):self.rows={};self.lock=threading.Lock();self.lost_reply=False;self.fail_before=False;self.calls=[]

    def get_item(self,**request):
        self.calls.append(('get',copy.deepcopy(request)))
        assert request['ConsistentRead'] is True
        with self.lock:
            item=self.rows.get(request['Key']['id']['S'])
            return {'Item':copy.deepcopy(item)} if item is not None else {}

    def put_item(self,**request):
        self.calls.append(('put',copy.deepcopy(request)))
        if self.fail_before:raise OSError('synthetic managed outage')
        with self.lock:
            item=request['Item'];key=item['id']['S'];old=self.rows.get(key)
            if request['ConditionExpression']=='attribute_not_exists(#id)':
                if old is not None:raise ConditionalFailure()
            else:
                assert request['ConditionExpression']=='attribute_exists(#id) AND #revision = :expected'
                if old is None or old['revision']!=request['ExpressionAttributeValues'][':expected']:
                    raise ConditionalFailure()
            self.rows[key]=copy.deepcopy(item)
        if self.lost_reply:raise OSError('synthetic lost managed reply')
        return {}


class ObjectTests(unittest.TestCase):
    def setUp(self):
        self.sdk=DynamoFixture();self.objects=DynamoObjects(self.sdk,'synthetic-table','ab'*32)
        self.anchor=DynamoJournalAnchor(self.objects,'0x'+'cd'*20)

    def test_immutable_bytes_and_chunked_manifest_reconstruct_exact_ciphertext(self):
        data=secrets.token_bytes(CHUNK*2+37)
        self.assertEqual(self.anchor.compare_exchange(None,data),0)
        self.assertEqual(self.anchor.read(),(0,data))
        self.assertTrue(all(c[1].get('ConditionExpression') is not None for c in self.sdk.calls if c[0]=='put'))
        with self.assertRaisesRegex(Rejected,'base-journal-conflict'):self.anchor.compare_exchange(None,b'x'*50)
        self.assertEqual(self.anchor.read(),(0,data))

    def test_lost_object_and_head_replies_resolve_authoritative_state_without_reset(self):
        self.sdk.lost_reply=True
        self.assertEqual(self.anchor.compare_exchange(None,b'a'*100),0)
        self.assertEqual(self.anchor.read(),(0,b'a'*100))
        self.assertEqual(self.anchor.compare_exchange(0,b'b'*100),1)
        self.assertEqual(self.anchor.read(),(1,b'b'*100))

    def test_missing_or_changed_ciphertext_is_not_replaced_by_its_hash(self):
        self.anchor.compare_exchange(None,b'a'*100)
        key=next(k for k in self.sdk.rows if ':object:' in k)
        self.sdk.rows[key]['data']['B']=b'tampered'
        with self.assertRaisesRegex(Rejected,'base-storage-digest'):self.anchor.read()
        del self.sdk.rows[key]
        with self.assertRaisesRegex(Rejected,'base-storage-missing'):self.anchor.read()

    def test_unavailable_write_leaves_old_head_in_place(self):
        self.anchor.compare_exchange(None,b'a'*100);self.sdk.fail_before=True
        with self.assertRaises(Rejected):self.anchor.compare_exchange(0,b'b'*100)
        self.assertEqual(self.anchor.read(),(0,b'a'*100))


class ManagedQueueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):transaction_fixture.TransactionTests.setUpClass()

    def setUp(self):
        f=transaction_fixture.TransactionTests();f.setUp();self.fixture=f;self.addCleanup(f.tearDown)
        self.sdk=DynamoFixture();self.objects=DynamoObjects(self.sdk,'synthetic-table','ab'*32)
        self.anchor=DynamoJournalAnchor(self.objects,f.signer.address)
        self.serial=0;self.queue=self.make(initial_nonce=0)

    def make(self,**kwargs):
        self.serial+=1;f=self.fixture
        return TransactionQueue(f.rpc,f.signer,f.path.with_name('managed-'+str(self.serial)+'.sqlite'),
            f.contracts,f.limits,anchor=self.anchor,laboratory=True,**kwargs)

    def submit(self):
        f=self.fixture;return self.queue.submit(f.submission,f.fixture.contract,f.data,300000)

    def test_restart_on_empty_enclave_disk_recovers_managed_state_same_nonce_and_keys(self):
        f=self.fixture;first=self.submit()
        self.queue.path.unlink()
        restored=self.make();result=restored.poll(f.submission)
        self.assertEqual(result['state'],'finalized');self.assertEqual(result['transaction_hash'],first['transaction_hash'])
        self.assertEqual(result['nonce'],0)
        # The public calldata is encrypted in the managed object/chunk store.
        data=bytes.fromhex(f.data[2:])
        self.assertFalse(any(data in value.get('data',{}).get('B',b'') for value in self.sdk.rows.values()))

    def test_untrusted_local_file_replay_cannot_roll_back_managed_nonce_history(self):
        stale=self.queue.path.read_bytes();self.submit();self.queue.path.write_bytes(stale)
        result=self.queue.poll(self.fixture.submission)
        self.assertEqual(result['state'],'finalized')
        self.assertEqual(int(self.fixture.rpc.call('eth_getTransactionCount',self.fixture.key.address,'latest'),16),1)

    def test_failed_managed_commit_never_broadcasts_new_signed_bytes(self):
        f=self.fixture;original=f.rpc.call;self.sdk.fail_before=True
        with patch.object(f.rpc,'call',wraps=original) as calls:
            with self.assertRaises(Rejected):self.submit()
        self.assertFalse(any(c.args[0]=='eth_sendRawTransaction' for c in calls.call_args_list))
        self.sdk.fail_before=False;self.assertEqual(self.submit()['nonce'],0)

    def test_lost_managed_commit_reply_recovers_same_authorization(self):
        self.sdk.lost_reply=True;self.assertEqual(self.submit()['state'],'pending')
        self.sdk.lost_reply=False;restored=self.make()
        self.assertEqual(restored.poll(self.fixture.submission)['state'],'finalized')

    def test_missing_managed_head_never_falls_back_to_local_journal_or_reinitializes(self):
        self.submit();key=self.objects.key(self.anchor.suffix)['id']['S'];del self.sdk.rows[key]
        with self.assertRaisesRegex(Rejected,'transaction-journal-missing'):self.queue.poll(self.fixture.submission)
        with self.assertRaisesRegex(Rejected,'transaction-journal-missing'):self.make()

    def test_existing_managed_journal_cannot_be_reinitialized(self):
        before=copy.deepcopy(self.sdk.rows)
        with self.assertRaisesRegex(Rejected,'transaction-journal-create'):self.make(initial_nonce=0)
        self.assertEqual(self.sdk.rows,before)

    def test_replayed_managed_revision_is_rejected_within_running_workload(self):
        key=self.objects.key(self.anchor.suffix)['id']['S'];old=copy.deepcopy(self.sdk.rows[key])
        self.submit();self.sdk.rows[key]=old
        with self.assertRaisesRegex(Rejected,'transaction-journal-rollback'):self.queue.poll(self.fixture.submission)

    def test_competing_workloads_only_broadcast_the_winner_of_managed_cas(self):
        f=self.fixture;other=self.make();barrier=threading.Barrier(2)
        original=self.anchor.compare_exchange
        def race(expected,envelope):
            if expected==0:barrier.wait(timeout=4)
            return original(expected,envelope)
        def submit(pair):
            queue,submission=pair
            try:return queue.submit(submission,f.fixture.contract,f.data,300000)['state']
            except Rejected as error:return str(error)
        with patch.object(self.anchor,'compare_exchange',side_effect=race),ThreadPoolExecutor(max_workers=2) as pool:
            states=list(pool.map(submit,[(self.queue,f.submission),(other,secrets.token_hex(32))]))
        self.assertEqual(sorted(states),['base-journal-conflict','pending'])
        self.assertEqual(int(f.rpc.call('eth_getTransactionCount',f.key.address,'latest'),16),1)
