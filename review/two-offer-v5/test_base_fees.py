"""Real signing/EVM/journal recovery with explicit OP fee RPC fixtures.

The local EVM does NOT charge the injected L1/operator fee observations. Live
Base probes and funded spending acceptance remain separate required evidence.
"""
import copy
import hashlib
import json
import secrets
import unittest
from types import SimpleNamespace
import uuid
from unittest.mock import patch

from base_rpc import BaseRPC
from base_evm import encode
from base_fees import BaseFees,ORACLE,L1_BLOCK
from base_protocol import ordinary_publication_data
from base_transactions import TransactionQueue
from policy import Rejected
import test_base_transactions as tx_cases


class FeeRPC:
    check_identity=BaseRPC.check_identity
    def __init__(self,rpc):
        self.rpc=rpc;self.l1=1000;self.actual_l1=900;self.scalar=2;self.constant=100;self.missing_l1=False
        self.stale=False;self.bad_code=False;self.reorg=False
        self.implementations={ORACLE:'0x'+'11'*20,L1_BLOCK:'0x'+'22'*20}
        self.codes={a:bytes([0x60,i+1]) for i,a in enumerate([ORACLE,L1_BLOCK,*self.implementations.values()])}
        self.calls=[];self.extra={}

    def approved(self):
        result={'max_l1_fee':100000,'max_operator_fee':2000000,'max_total_fee':3*10**15,
            'total_budget':10**17,'funded_budget':10**17,'max_head_age':60}
        for address,prefix in ((ORACLE,'oracle'),(L1_BLOCK,'l1_block')):
            impl=self.implementations[address]
            result.update({prefix+'_proxy_sha256':hashlib.sha256(self.codes[address]).hexdigest(),
                prefix+'_implementation':impl,prefix+'_implementation_sha256':hashlib.sha256(self.codes[impl]).hexdigest()})
        return result

    def call(self,method,*args):
        self.calls.append((method,args))
        if method=='eth_getCode' and args[0] in self.codes:
            return '0x'+(b'bad-code' if self.bad_code else self.codes[args[0]]).hex()
        if method=='eth_call' and args[0]['to'] in (ORACLE,L1_BLOCK):
            address=args[0]['to'];data=args[0]['data']
            if data==encode('implementation()'):n=int(self.implementations[address],16)
            elif data==encode('isJovian()'):n=1
            elif data.startswith(encode('getL1FeeUpperBound(uint256)',0)[:10]):n=self.l1
            elif data.startswith(encode('getOperatorFee(uint256)',0)[:10]):n=int(data[-64:],16)*self.scalar+self.constant
            else:raise AssertionError('unexpected oracle call')
            return '0x'+n.to_bytes(32,'big').hex()
        value=self.rpc.call(method,*args)
        if method=='eth_getTransactionReceipt' and value is not None:
            value=copy.deepcopy(value)
            if not self.missing_l1:
                value['l1Fee']=hex(self.actual_l1)
                additional=self.actual_l1+int(value['gasUsed'],16)*self.scalar+self.constant
                self.extra[value['transactionHash']]=(value['from'].lower(),max(additional,self.extra.get(value['transactionHash'],('',0))[1]))
        if method=='eth_getBalance':
            # Explicit OP fee fixture: Anvil charges execution only. Deduct the
            # injected additional charges from its balance oracle consistently.
            value=hex(int(value,16)-sum(cost for sender,cost in self.extra.values() if sender==args[0].lower()))
        if method=='eth_getBlockByNumber' and value is not None:
            value=copy.deepcopy(value)
            if self.stale and args[0]=='latest':value['timestamp']='0x0'
            if self.reorg and args[0] not in ('latest','finalized'):value['hash']='0x'+'ab'*32
        return value


class TotalFeeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):tx_cases.TransactionTests.setUpClass()

    def setUp(self):
        self.f=tx_cases.TransactionTests();self.f.setUp();self.addCleanup(self.f.tearDown)
        clock=patch('base_fees.time',SimpleNamespace(time=lambda:int(self.f.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16)))
        clock.start();self.addCleanup(clock.stop)
        self.f.rpc.call('anvil_setBalance',self.f.key.address,hex(10**17))
        self.rpc=FeeRPC(self.f.rpc);self.policy=self.rpc.approved();self.path=self.f.path.with_name('total-fee.sqlite')
        self.queue=self.make(initial_nonce=0)

    def make(self,**kwargs):
        return TransactionQueue(self.rpc,self.f.signer,self.path,self.f.contracts,self.f.limits,
            laboratory=True,fee_policy=self.policy,**kwargs)

    def submit(self):return self.queue.submit(self.f.submission,self.f.fixture.contract,self.f.data,300000)

    def other(self):
        identifier=secrets.token_hex(32);post=dict(self.f.post,id=str(uuid.uuid4()))
        return self.queue.submit(identifier,self.f.fixture.contract,ordinary_publication_data(post,identifier),300000)

    def test_exact_unsigned_size_all_fee_reservation_and_actual_receipt_survive_restart(self):
        sent=self.submit();final=self.queue.poll(self.f.submission)
        self.assertEqual(final['state'],'finalized');self.assertFalse(final['fee_policy_overrun'])
        self.assertEqual(final['total_fee_reserved_wei'],300000*self.f.limits.max_fee_per_gas+2100000)
        with self.queue._db() as db:
            fee=db.execute('SELECT * FROM fees').fetchone();q=json.loads(fee['quote']);a=json.loads(fee['actual'])
            intent=json.loads(db.execute('SELECT intent FROM submissions').fetchone()[0])
            unsigned=self.queue._unsigned(0,intent);self.assertEqual(unsigned[0],2);self.assertEqual(q['unsigned_bytes'],len(unsigned))
            self.assertEqual(a['total_wei'],a['execution_wei']+a['l1_wei']+a['operator_wei']);self.assertEqual(a['l1_wei'],900)
        self.assertEqual(self.make().poll(self.f.submission),final)
        self.assertEqual(sent['transaction_hash'],final['transaction_hash'])

    def test_extra_fee_or_code_or_stale_head_rejects_before_signature_or_nonce(self):
        implementations=copy.deepcopy(self.rpc.implementations)
        for change in ('l1','code','stale','operator','implementation','reorg'):
            self.rpc.implementations=copy.deepcopy(implementations)
            if change=='implementation':self.rpc.implementations[ORACLE]='0x'+'33'*20
            self.rpc.reorg=change=='reorg'
            self.rpc.l1=100001 if change=='l1' else 1000;self.rpc.bad_code=change=='code';self.rpc.stale=change=='stale'
            self.rpc.scalar=100 if change=='operator' else 2
            with patch.object(self.f.signer,'sign',side_effect=AssertionError('must not sign')):
                with self.assertRaises(Rejected):self.submit()
        self.assertEqual(int(self.f.rpc.call('eth_getTransactionCount',self.f.key.address,'latest'),16),0)
        with self.queue._db() as db:self.assertEqual(db.execute('SELECT count(*) FROM fees').fetchone()[0],0)

    def test_unpriced_previous_submission_blocks_another_nonce_until_receipt_accounted(self):
        self.submit()
        with self.assertRaisesRegex(Rejected,'transaction-fee-recovery-pending'):self.other()
        self.queue.poll(self.f.submission);self.assertEqual(self.other()['nonce'],1)

    def test_missing_l1_fee_is_not_zero_and_never_refunds_or_resigns(self):
        self.submit();self.rpc.missing_l1=True
        with self.assertRaisesRegex(Rejected,'transaction-fee-response'):self.queue.poll(self.f.submission)
        with self.assertRaisesRegex(Rejected,'transaction-fee-recovery-pending'):self.other()
        self.rpc.missing_l1=False;self.assertEqual(self.make().poll(self.f.submission)['state'],'finalized')

    def test_actual_data_fee_overrun_is_retained_and_stops_new_signatures_after_restart(self):
        self.submit();self.rpc.actual_l1=100001
        observed=self.queue.poll(self.f.submission);self.assertTrue(observed['fee_policy_overrun'])
        self.queue=self.make()
        with patch.object(self.f.signer,'sign',side_effect=AssertionError('must not sign')):
            with self.assertRaisesRegex(Rejected,'transaction-total-fee-overrun'):self.other()
        self.rpc.actual_l1=1;self.assertTrue(self.queue.poll(self.f.submission)['fee_policy_overrun'])

    def test_committed_reservation_requotes_before_rebroadcast_without_new_id_or_signature(self):
        with patch.object(self.queue,'poll',side_effect=OSError('fixture crash after durable commit')):
            with self.assertRaises(OSError):self.submit()
        self.queue=self.make();self.rpc.l1=100001;self.rpc.calls=[]
        held=self.queue.poll(self.f.submission);self.assertEqual(held['state'],'recoverable')
        self.assertFalse(any(m=='eth_sendRawTransaction' for m,_ in self.rpc.calls))
        self.rpc.l1=1000;sent=self.queue.poll(self.f.submission);self.assertEqual(sent['nonce'],0)
        self.assertEqual(sent['transaction_hash'],held['transaction_hash'])
        self.assertEqual(self.queue.poll(self.f.submission)['state'],'finalized')

    def test_lifetime_total_reservation_exhaustion_is_durable_and_precedes_new_signature(self):
        self.path=self.path.with_name('one-transaction.sqlite')
        reserved=300000*self.f.limits.max_fee_per_gas+2100000
        self.policy.update(max_total_fee=reserved,total_budget=reserved,funded_budget=reserved)
        self.f.rpc.call('anvil_setBalance',self.f.key.address,hex(reserved))
        self.queue=self.make(initial_nonce=0);self.submit();self.queue.poll(self.f.submission);self.queue=self.make()
        with patch.object(self.f.signer,'sign',side_effect=AssertionError('must not sign')):
            with self.assertRaisesRegex(Rejected,'transaction-total-fee-budget'):self.other()
        with self.queue._db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM fees').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT next_nonce FROM meta').fetchone()[0],1)

    def test_excess_wallet_funding_blocks_signature_and_nonce_allocation(self):
        self.f.rpc.call('anvil_setBalance',self.f.key.address,hex(self.policy['funded_budget']+1))
        with patch.object(self.f.signer,'sign',side_effect=AssertionError('must not sign')):
            with self.assertRaisesRegex(Rejected,'transaction-funded-cap'):self.submit()
        with self.queue._db() as db:self.assertEqual(db.execute('SELECT next_nonce FROM meta').fetchone()[0],0)

    def test_refill_cannot_ignore_previous_observed_fees_across_restart(self):
        self.submit();self.queue.poll(self.f.submission);self.queue=self.make()
        # Balance alone fits the cap, but balance PLUS already paid fees does not.
        self.f.rpc.call('anvil_setBalance',self.f.key.address,hex(self.policy['funded_budget']))
        with patch.object(self.f.signer,'sign',side_effect=AssertionError('must not sign')):
            with self.assertRaisesRegex(Rejected,'transaction-funded-cap'):self.other()
        self.assertEqual(self.queue.poll(self.f.submission)['state'],'finalized')

    def test_insufficient_funds_or_changed_balance_anchor_holds_preflight(self):
        with self.queue._db() as db:self.assertEqual(db.execute('SELECT count(*) FROM fees').fetchone()[0],0)
        self.f.rpc.call('anvil_setBalance',self.f.key.address,'0x1')
        with self.assertRaisesRegex(Rejected,'transaction-funded-balance'):self.queue.preflight(300000)
        self.f.rpc.call('anvil_setBalance',self.f.key.address,hex(self.policy['funded_budget']))
        self.rpc.reorg=True
        with self.assertRaisesRegex(Rejected,'transaction-funded-reorg'):self.queue.preflight(300000)

    def test_committed_raw_bytes_are_not_rebroadcast_after_excess_funding(self):
        with patch.object(self.queue,'poll',side_effect=OSError('fixture crash after commit')):
            with self.assertRaises(OSError):self.submit()
        self.f.rpc.call('anvil_setBalance',self.f.key.address,hex(self.policy['funded_budget']+1))
        self.rpc.calls=[];result=self.make().poll(self.f.submission)
        self.assertEqual(result['state'],'recoverable')
        self.assertFalse(any(method=='eth_sendRawTransaction' for method,_ in self.rpc.calls))
        with self.queue._db() as db:self.assertEqual(db.execute('SELECT next_nonce FROM meta').fetchone()[0],1)

    def test_policy_changes_cannot_silently_reset_existing_budget_or_journal(self):
        self.submit();self.policy['total_budget']+=1
        with self.assertRaisesRegex(Rejected,'transaction-journal-context'):self.make()
        self.policy['total_budget']-=1
        with self.queue._db() as db:
            fee=dict(db.execute('SELECT * FROM fees').fetchone());fee['quote']='{}'
            db.execute('UPDATE fees SET quote=?',(fee['quote'],))
        with self.assertRaisesRegex(Rejected,'transaction-journal-authentication'):self.make()
