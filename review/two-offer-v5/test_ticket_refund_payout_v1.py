"""Real local vault transfers/signatures/managed journal; OP fees/S3/finality fixtures."""
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from base_evm import encode
from base_protocol import ReceiptKey,keccak
from base_transactions import Limits,ProtectedSigner
from policy import canonical,Rejected
from ticket_bindings_v1 import ConditionalS3Records
from ticket_journal_v2 import ImmutableS3JournalAnchor
from ticket_offer_v1 import TicketOffer,OFFER_V2,manifest_hash
from ticket_payment_v1 import FinalizedTicketPayment
from ticket_refund_v1 import refund_data
from ticket_refund_payout_v1 import build,SCOPE,PROFILE,SELECTOR,RefundQueue,RefundWorker,namespace,calldata
from ticket_wallet_v1 import TicketWallet
from test_ticket_publication_v2 import SnapshotS3Fixture,FinalityFeeRPC
import test_ticket_purchase_v1 as cases


class RefundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cases.PurchaseTests.setUpClass();cls.compiled=build()

    def setUp(self):
        self.f=f=cases.PurchaseTests();f.setUp();self.addCleanup(f.doCleanups)
        terms=copy.deepcopy(f.terms);terms.update(profile=OFFER_V2,redemption_ledger='nockapp-ticket-publication-ledger-v2')
        purchase=f.deploy(terms)
        manifest={'terms':terms,'purchase_contract':purchase,'purchase_runtime_keccak':keccak(bytes.fromhex(f.rpc.call('eth_getCode',purchase,'latest')[2:]))}
        f.offer=self.offer=TicketOffer(manifest,manifest_hash(manifest),f.crypto.native)
        f.client=TicketWallet(Path(f.temp.name)/'refund-buyer-v2',self.offer);f.client.initialize()
        f.decisions=ConditionalS3Records(f.s3,'private-refund-lab','ticket-purchases-v1/'+self.offer.hash+'/decisions/',2048)
        f.results=ConditionalS3Records(f.s3,'private-refund-lab','ticket-purchases-v1/'+self.offer.hash+'/results/',32768)
        self.rpc=FinalityFeeRPC(f.rpc);self.fees=self.rpc.approved()
        clock=patch('base_fees.time',SimpleNamespace(time=lambda:int(f.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16)))
        clock.start();self.addCleanup(clock.stop)
        f.payment=self.payments=FinalizedTicketPayment(self.rpc,self.offer);f.issuer=f.service()
        self.request,self.receipt=f.paid();self.pack_hash=self.offer.pack_hash(self.request['pack'])
        self.signature=f.refund_signature(self.request)
        self.key=ReceiptKey(self.rpc);self.signer=ProtectedSigner(self.rpc,self.key)
        # Leave headroom under the unchanged funded cap: conservative fee
        # exposure survives orphaning even though the chain restores balance.
        f.rpc.call('anvil_setBalance',self.key.address,hex(5*10**16))
        self.count=8;price=int(terms['pack_price_wei'])
        data='0x'+self.compiled['evm']['bytecode']['object']+encode('f(bytes32,address,address,uint256,uint256)',
            '0x'+self.offer.hash,purchase,self.signer.address,price,self.count)[10:]
        r=f.rpc.tx(f.accounts[0],data);self.assertEqual(r['status'],'0x1');self.vault=r['contractAddress']
        self.runtime=bytes.fromhex(f.rpc.call('eth_getCode',self.vault,'latest')[2:])
        self.scope={'profile':SCOPE,'parameters':self.offer.hash,'chain_id':84532,'vault':self.vault,
            'runtime_sha256':hashlib.sha256(self.runtime).hexdigest(),'authority':self.signer.address.lower(),
            'pack_price_wei':terms['pack_price_wei'],'max_refunds':self.count,'principal_budget_wei':str(price*self.count),'gas':200000}
        self.scope_hash=hashlib.sha256(canonical(self.scope)).hexdigest()
        funding=f.rpc.call('eth_sendTransaction',{'from':f.accounts[0],'to':self.vault,'value':hex(price*self.count),'gas':hex(500000)})
        self.assertEqual(f.receipt(funding)['status'],'0x1')
        self.limits=Limits(200000,3000000000,1000000,10**17,100)
        self.sdk=SnapshotS3Fixture();self.anchor=ImmutableS3JournalAnchor(self.sdk,'private-refund-snapshots',namespace(self.signer.address),account_id='419720240831')
        self.paths=0;self.queue=self.make_queue(initial_nonce=0);self.worker=self.make_worker(self.queue)

    def make_queue(self,**kwargs):
        self.paths+=1
        return RefundQueue(self.rpc,self.signer,Path(self.f.temp.name)/('refund-queue-'+str(self.paths)+'.sqlite'),
            self.offer,self.scope,self.limits,expected_hash=self.scope_hash,anchor=self.anchor,fee_policy=self.fees,**kwargs)

    def make_worker(self,queue):return RefundWorker(self.offer,self.payments,self.f.decisions,queue)

    def authorize(self):return self.f.issuer.reserve_unissued_refund(**self.request,signature=self.signature)

    def finish(self):
        first=self.worker.refund(self.pack_hash,self.signature)
        if first['payout_confirmed']:return first
        self.f.receipt(first['transaction_hash'])
        return self.worker.refund(self.pack_hash,self.signature)

    def test_actual_refund_pays_original_payer_once_and_preserves_issuance_fence(self):
        self.authorize();payer=self.f.accounts[1]
        before=int(self.f.rpc.call('eth_getBalance',payer,'latest'),16)
        with patch.object(self.rpc,'call',wraps=self.rpc.call) as calls:result=self.finish()
        self.assertTrue(result['payout_confirmed']);self.assertEqual(result['state'],'refunded')
        self.assertEqual(result['payer'],payer);self.assertEqual(result['amount_wei'],self.offer.terms['pack_price_wei'])
        self.assertEqual(int(self.f.rpc.call('eth_getBalance',payer,'latest'),16)-before,int(result['amount_wei']))
        self.assertEqual(self.worker.refund(self.pack_hash,self.signature),result)
        self.assertEqual(int(self.f.rpc.call('eth_getTransactionCount',self.signer.address,'latest'),16),1)
        tx=self.f.rpc.call('eth_getTransactionByHash',result['transaction_hash'])
        self.assertEqual(tx['value'],'0x0');self.assertEqual(tx['to'],self.vault);self.assertTrue(tx['input'].startswith(SELECTOR))
        self.assertFalse(any(c.args[0] in ('eth_sendTransaction','eth_sign','personal_sign') for c in calls.call_args_list))
        with self.assertRaises(Rejected):self.f.issuer.issue(**self.request)

    def test_no_decision_issue_winner_or_wrong_payer_signature_cannot_spend(self):
        with self.assertRaises(Rejected):self.worker.refund(self.pack_hash,self.signature)
        self.f.issuer.issue(**self.request)
        with self.assertRaises(Rejected):self.worker.refund(self.pack_hash,self.signature)
        self.assertIsNone(self.queue.job(self.pack_hash))
        self.assertEqual(int(self.f.rpc.call('eth_getTransactionCount',self.signer.address,'latest'),16),0)

    def test_wrong_payer_consent_and_arbitrary_queue_calls_are_rejected(self):
        self.authorize();wrong=self.f.refund_signature(self.request,self.f.accounts[2])
        with self.assertRaises(Rejected):self.worker.refund(self.pack_hash,wrong)
        with self.assertRaises(Rejected):self.queue.submit('11'*32,self.f.accounts[2],'0x',21000)
        self.assertIsNone(self.queue.job(self.pack_hash))

    def test_lost_broadcast_reply_recovers_same_raw_transaction_after_restart(self):
        self.authorize();original=self.rpc.call;sent=[]
        def lost(method,*args):
            if method=='eth_sendRawTransaction':
                sent.append(args[0]);original(method,*args);raise TimeoutError('fixture lost broadcast reply')
            return original(method,*args)
        with patch.object(self.rpc,'call',side_effect=lost):first=self.worker.refund(self.pack_hash,self.signature)
        self.assertFalse(first['payout_confirmed']);self.assertEqual(len(sent),1)
        self.f.receipt(first['transaction_hash'])
        fresh=self.make_worker(self.make_queue())
        with patch.object(self.signer,'sign',side_effect=AssertionError('no second signature')):
            result=fresh.refund(self.pack_hash,self.signature)
        self.assertTrue(result['payout_confirmed']);self.assertEqual(result['transaction_hash'],first['transaction_hash'])
        self.assertEqual(int(self.f.rpc.call('eth_getTransactionCount',self.signer.address,'latest'),16),1)

    def test_accepted_unsigned_job_recovers_without_user_or_original_process(self):
        self.authorize()
        with patch.object(self.signer,'sign',side_effect=OSError('fixture signer unavailable')):
            with self.assertRaises(OSError):self.worker.refund(self.pack_hash,self.signature)
        self.assertIsNotNone(self.queue.job(self.pack_hash))
        fresh=self.make_worker(self.make_queue());first=fresh.recover_pending()[0]
        self.f.receipt(first['transaction_hash']);result=fresh.recover_pending()[0]
        self.assertTrue(result['payout_confirmed'])

    def test_failed_snapshot_write_cannot_broadcast_or_lose_refund_job(self):
        self.authorize();payload=self.worker._authorized(self.pack_hash,self.signature);self.queue.admit(self.pack_hash,payload)
        original=self.anchor.compare_exchange
        def broken(expected,envelope):raise OSError('fixture journal unavailable')
        with patch.object(self.anchor,'compare_exchange',side_effect=broken),patch.object(self.rpc,'call',wraps=self.rpc.call) as calls:
            with self.assertRaises(OSError):self.worker.refund(self.pack_hash,self.signature)
        self.assertFalse(any(c.args[0]=='eth_sendRawTransaction' for c in calls.call_args_list))
        self.assertIsNotNone(self.make_queue().job(self.pack_hash))
        self.assertIs(self.anchor.compare_exchange.__func__,original.__func__)

    def test_duplicate_callers_share_one_payout_nonce_and_onchain_pack_guard(self):
        self.authorize();other=self.make_worker(self.make_queue())
        def attempt(worker):
            try:return worker.refund(self.pack_hash,self.signature)
            except Rejected:return None # Losing snapshot CAS must recover, never sign a new operation.
        with ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(attempt,[self.worker,other]))
        result=self.finish();self.assertTrue(result['payout_confirmed'])
        payload=self.queue.job(self.pack_hash)
        # Even the authorized key cannot pay this pack again through a new nonce.
        self.f.rpc.call('anvil_impersonateAccount',self.signer.address)
        h=self.f.rpc.call('eth_sendTransaction',{'from':self.signer.address,'to':self.vault,'data':calldata(payload),'gas':hex(200000)})
        self.assertEqual(self.f.receipt(h)['status'],'0x0')

    def test_orphaned_unfinalized_payout_reuses_identical_saved_bytes(self):
        self.authorize();snapshot=self.f.rpc.call('evm_snapshot')
        original=self.rpc.call;final=self.f.rpc.call('eth_getBlockByNumber','latest',False)
        def lag(method,*args):
            if method=='eth_getBlockByNumber' and args[0]=='finalized':return final
            return original(method,*args)
        with patch.object(self.rpc,'call',side_effect=lag):
            first=self.worker.refund(self.pack_hash,self.signature);self.f.receipt(first['transaction_hash'])
            self.assertEqual(self.worker.refund(self.pack_hash,self.signature)['state'],'confirmed')
        self.assertTrue(self.f.rpc.call('evm_revert',snapshot))
        with self.queue._db() as db:saved=db.execute('SELECT raw FROM submissions').fetchone()[0]
        with patch.object(self.signer,'sign',side_effect=AssertionError('do not resign')),patch.object(self.rpc,'call',wraps=self.rpc.call) as calls:
            behind=self.worker.refund(self.pack_hash,self.signature)
            self.assertEqual(behind['state'],'recoverable');self.assertFalse(behind['payout_confirmed'])
            # The conservative funding oracle refuses a head older than an
            # observed receipt. Model the replacement chain catching up first.
            self.assertFalse(any(c.args[0]=='eth_sendRawTransaction' for c in calls.call_args_list))
            self.f.rpc.call('evm_mine')
            again=self.worker.refund(self.pack_hash,self.signature)
            self.assertEqual([c.args[1] for c in calls.call_args_list if c.args[0]=='eth_sendRawTransaction'],[saved])
        self.assertEqual(first['transaction_hash'],again['transaction_hash']);self.f.receipt(again['transaction_hash'])
        self.assertTrue(self.worker.refund(self.pack_hash,self.signature)['payout_confirmed'])

    def test_finalized_payout_disappearance_halts_without_new_signature(self):
        self.authorize();snapshot=self.f.rpc.call('evm_snapshot');self.finish()
        self.assertTrue(self.f.rpc.call('evm_revert',snapshot))
        with patch.object(self.signer,'sign',side_effect=AssertionError('halt')):
            with self.assertRaises(Rejected):self.worker.refund(self.pack_hash,self.signature)

    def test_vault_rejects_other_authority_wrong_payer_and_overfunding(self):
        self.authorize();payload=self.worker._authorized(self.pack_hash,self.signature)
        tx=self.f.rpc.tx(self.f.accounts[2],calldata(payload),self.vault,200000)
        self.assertEqual(tx['status'],'0x0')
        self.f.rpc.call('anvil_impersonateAccount',self.signer.address)
        bad={**payload,'payer':self.f.accounts[2]}
        h=self.f.rpc.call('eth_sendTransaction',{'from':self.signer.address,'to':self.vault,'data':calldata(bad),'gas':hex(200000)})
        self.assertEqual(self.f.receipt(h)['status'],'0x0')
        h=self.f.rpc.call('eth_sendTransaction',{'from':self.f.accounts[0],'to':self.vault,'value':'0x1','gas':hex(100000)})
        self.assertEqual(self.f.receipt(h)['status'],'0x0')
        names={entry.get('name') for entry in self.compiled['abi']}
        self.assertFalse(names & {'upgradeTo','pause','withdraw','setAuthority','setRecipient','transferOwnership'})

    def test_restored_old_local_database_cannot_repeat_a_completed_refund(self):
        old=self.queue.path.read_bytes();self.authorize();result=self.finish()
        self.queue.path.write_bytes(old)
        fresh=self.make_worker(self.make_queue())
        with patch.object(self.signer,'sign',side_effect=AssertionError('authoritative journal must survive local rollback')):
            self.assertEqual(fresh.refund(self.pack_hash,self.signature),result)
        self.assertEqual(int(self.f.rpc.call('eth_getTransactionCount',self.signer.address,'latest'),16),1)

    def test_vault_or_gas_underfunding_preserves_unsigned_job_for_unattended_recovery(self):
        self.authorize();self.f.rpc.call('anvil_setBalance',self.vault,'0x0')
        with patch.object(self.signer,'sign',side_effect=AssertionError('do not sign without principal funding')):
            with self.assertRaises(ValueError):self.worker.refund(self.pack_hash,self.signature)
        self.assertIsNotNone(self.queue.job(self.pack_hash))
        self.f.rpc.call('anvil_setBalance',self.vault,hex(int(self.scope['principal_budget_wei'])))
        self.f.rpc.call('anvil_setBalance',self.signer.address,'0x0')
        with patch.object(self.signer,'sign',side_effect=AssertionError('do not sign without gas funding')):
            with self.assertRaises(Rejected):self.worker.refund(self.pack_hash,self.signature)
        self.f.rpc.call('anvil_setBalance',self.signer.address,hex(5*10**16))
        fresh=self.make_worker(self.make_queue());first=fresh.recover_pending()[0]
        self.f.receipt(first['transaction_hash']);self.assertTrue(fresh.recover_pending()[0]['payout_confirmed'])

    def test_changed_original_payment_or_vault_code_cannot_admit_a_refund(self):
        self.authorize();original=self.rpc.call
        for failure in ('payment-anchor','vault-code'):
            def changed(method,*args):
                value=original(method,*args)
                if failure=='payment-anchor' and method=='eth_getBlockByNumber' and args[0]==self.receipt['blockNumber']:
                    value=copy.deepcopy(value);value['hash']='0x'+'ab'*32
                if failure=='vault-code' and method=='eth_getCode' and args[0]==self.vault:value='0x00'
                return value
            with patch.object(self.rpc,'call',side_effect=changed),patch.object(self.signer,'sign',side_effect=AssertionError('do not sign')):
                with self.assertRaises(Rejected):self.worker.refund(self.pack_hash,self.signature)
            self.assertIsNone(self.queue.job(self.pack_hash))

    def test_finalized_failed_payout_keeps_pack_bound_and_never_allocates_another_nonce(self):
        self.authorize();original=self.signer.sign
        def undergas(chain,nonce,to,data,gas,max_fee,tip):return original(chain,nonce,to,data,50000,max_fee,tip)
        with patch.object(self.signer,'sign',side_effect=undergas):first=self.worker.refund(self.pack_hash,self.signature)
        self.assertEqual(self.f.receipt(first['transaction_hash'])['status'],'0x0')
        with patch.object(self.signer,'sign',side_effect=AssertionError('failed refund cannot auto-resign')):
            failed=self.worker.refund(self.pack_hash,self.signature);again=self.worker.refund(self.pack_hash,self.signature)
        self.assertEqual(failed['state'],'failed');self.assertFalse(failed['payout_confirmed']);self.assertEqual(again,failed)
        self.assertEqual(int(self.f.rpc.call('eth_getTransactionCount',self.signer.address,'latest'),16),1)

    def test_compiler_template_is_repeatable_and_recovery_bound_is_enforced(self):
        self.assertEqual(build(),self.compiled)
        with self.assertRaises(Rejected):self.worker.recover_pending(0)
        with self.assertRaises(Rejected):self.worker.recover_pending(9)

    def test_consensus_principal_cap_remains_even_with_forced_extra_funding(self):
        # Deliberately synthetic payer claims sent directly by the privileged
        # authority: the vault is NOT a payment oracle. Production worker would
        # reject these without real payment/refund decisions. Here we isolate
        # its immutable spend/count boundary, including forced extra funding.
        payer=self.f.accounts[1];self.f.rpc.call('anvil_impersonateAccount',self.signer.address)
        for i in range(self.count+1):
            pack='0x'+hashlib.sha256(('refund-cap-fixture-'+str(i)).encode()).hexdigest()
            payment='0x'+'12'*32
            signature=self.f.rpc.call('eth_signTypedData_v4',payer,json.dumps(refund_data(self.offer,pack,payment)))
            data=encode('refund(bytes32,bytes32,address,bytes)',pack,payment,payer,signature)
            h=self.f.rpc.call('eth_sendTransaction',{'from':self.signer.address,'to':self.vault,'data':data,'gas':hex(200000)})
            self.assertEqual(self.f.receipt(h)['status'],'0x1' if i<self.count else '0x0')
            if i==self.count-1:self.f.rpc.call('anvil_setBalance',self.vault,hex(int(self.scope['principal_budget_wei'])))
        total=self.f.rpc.call('eth_call',{'to':self.vault,'data':encode('totalRefunded()')},'latest')
        self.assertEqual(int(total,16),int(self.scope['principal_budget_wei']))
