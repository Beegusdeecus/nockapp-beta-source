"""Actual local EVM/native/encrypted files; finality/keyring/S3 are fixtures."""
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from base_evm import local_chain,encode
from base_protocol import keccak
from policy import Rejected,canonical
from test_base_discussions import immediate_finality
from test_base_enrollment import MemorySecretService
import test_ticket_native_v1 as crypto_cases
from test_ticket_bindings_v1 import AtomicS3Fixture
from ticket_bindings_v1 import ConditionalS3Records,S3BindingJournal,TicketBindings
from ticket_issuance_v1 import PaidTicketIssuer
from ticket_offer_v1 import TicketOffer,manifest_hash,terms_hash,OFFER,REFUNDS
from ticket_payment_v1 import FinalizedTicketPayment
from ticket_purchase_contract import build
from ticket_wallet_v1 import TicketWallet
from ticket_refund_v1 import refund_data
from ticket_payment_recovery_v2 import find_payment,failed_payment_proof,check_closed_payments


class PurchaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        crypto_cases.Tickets.setUpClass();cls.crypto=crypto_cases.Tickets();cls.compiled=build()

    def setUp(self):
        self.chain=local_chain(chain_id=84532);self.rpc=self.chain.__enter__();self.addCleanup(self.chain.__exit__,None,None,None)
        self.finality=immediate_finality(self.rpc);self.finality.start();self.addCleanup(self.finality.stop)
        self.accounts=self.rpc.call('eth_accounts');self.now=int(self.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16)
        self.terms={'profile':OFFER,'chain_id':84532,'application':'0x'+'ab'*32,
            'index_contract':self.accounts[4],'index_runtime_keccak':'0x'+'cd'*32,
            'ticket_spki':base64.b64encode(self.crypto.public).decode(),'pack_size':2,
            'pack_price_wei':'10000','payment_recipient':self.accounts[3],
            'purchase_before':self.now+1000,'redeem_before':self.now+10000,
            'max_bundle_bytes':65536,'max_gas':200000,'max_total_fee_wei':'10000000','refund_policy':REFUNDS}
        self.contract=self.deploy(self.terms)
        manifest={'terms':self.terms,'purchase_contract':self.contract,
            'purchase_runtime_keccak':keccak(bytes.fromhex(self.rpc.call('eth_getCode',self.contract,'latest')[2:]))}
        self.offer=TicketOffer(manifest,manifest_hash(manifest),self.crypto.native)
        self.payment=FinalizedTicketPayment(self.rpc,self.offer)
        self.s3=AtomicS3Fixture()
        self.decisions=ConditionalS3Records(self.s3,'private-lab-journal','ticket-purchases-v1/'+self.offer.hash+'/decisions/',2048)
        self.results=ConditionalS3Records(self.s3,'private-lab-journal','ticket-purchases-v1/'+self.offer.hash+'/results/',32768)
        self.issuer=self.service()
        self.temp=tempfile.TemporaryDirectory(prefix='ticket-purchase-');self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name)/'tickets'
        self.keyring=MemorySecretService();p=patch('wallet.WalletSecretService',return_value=self.keyring);p.start();self.addCleanup(p.stop)
        self.client=TicketWallet(self.directory,self.offer);self.client.initialize()

    def service(self):return PaidTicketIssuer(self.offer,self.payment,self.decisions,self.results,self.crypto.private)

    def deploy(self,terms):
        creation=self.compiled['evm']['bytecode']['object']
        data='0x'+creation+encode('f(bytes32,address,uint256,uint64)',terms_hash(terms),terms['payment_recipient'],
            terms['pack_price_wei'],terms['purchase_before'])[10:]
        r=self.rpc.tx(self.accounts[0],data);self.assertEqual(r['status'],'0x1');return r['contractAddress']

    def send(self,transaction):
        tx=self.rpc.call('eth_sendTransaction',{'from':self.accounts[1],'to':transaction['to'],
            'data':transaction['data'],'value':transaction['value'],'gas':hex(500000)})
        return self.receipt(tx)

    def receipt(self,transaction_hash):
        # Anvil may return the hash before its automined receipt is observable
        # under concurrent browser/installer load. Poll ONLY that same hash;
        # absence never authorizes a second send or relaxes status assertions.
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            receipt=self.rpc.call('eth_getTransactionReceipt',transaction_hash)
            if receipt is not None:return receipt
            time.sleep(.01)
        self.fail('local transaction receipt unavailable before fixture deadline')

    def paid(self):
        request=self.client.prepare_purchase(self.now,True)
        receipt=self.send(request['transaction']);self.assertEqual(receipt['status'],'0x1')
        self.client.record_payment(request['pack_hash'],receipt['transactionHash'])
        return self.client.issuance_request(),receipt

    def refund_signature(self,request,account=None):
        data=refund_data(self.offer,self.offer.pack_hash(request['pack']),request['transaction_hash'])
        return self.rpc.call('eth_signTypedData_v4',account or self.accounts[1],json.dumps(data))

    def test_armed_payment_recovers_exact_rpc_transaction_and_issues_once(self):
        request=self.client.prepare_purchase(self.now,True)
        nonce=int(self.rpc.call('eth_getTransactionCount',self.accounts[1],'pending'),16)
        armed=self.client.arm_payment(request['pack_hash'],self.accounts[1],nonce,True)
        self.assertEqual(armed['state'],'send-uncertain')
        receipt=self.send(armed['transaction'])
        fresh=TicketWallet(self.directory,self.offer)
        before=(self.directory/'credential.sealed').read_bytes()
        with self.assertRaises(Rejected):fresh.record_payment(request['pack_hash'],receipt['transactionHash'])
        tx=self.rpc.call('eth_getTransactionByHash',receipt['transactionHash'])
        for field,value in [('from',self.accounts[2]),('nonce',hex(nonce+1)),('chainId','0x1'),
                ('to',self.accounts[2]),('input','0x'),('value','0x1')]:
            changed=copy.deepcopy(tx);changed[field]=value
            with self.assertRaises(Rejected):fresh.recover_payment(changed)
            self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        self.assertEqual(fresh.recover_payment(tx)['state'],'recorded')
        self.assertEqual(fresh.recover_payment(tx)['payment_tx'],receipt['transactionHash'])
        reply=self.issuer.issue(**fresh.issuance_request())
        self.assertEqual(fresh.receive(reply)['available'],2)
        self.assertEqual(fresh.receive(reply)['available'],2)

    def test_lost_arming_reply_never_authorizes_another_send(self):
        request=self.client.prepare_purchase(self.now,True)
        original=self.client._save
        def save(r):original(r);raise OSError('fixture lost durable arming reply')
        with patch.object(self.client,'_save',side_effect=save):
            with self.assertRaises(OSError):self.client.arm_payment(request['pack_hash'],self.accounts[1],0,True)
        fresh=TicketWallet(self.directory,self.offer)
        self.assertEqual(fresh.payment_intent()['state'],'send-uncertain')
        for payer,nonce in [(self.accounts[1],0),(self.accounts[1],1),(self.accounts[2],0)]:
            with self.assertRaises(Rejected):fresh.arm_payment(request['pack_hash'],payer,nonce,True)
        self.assertEqual(fresh.prepare_purchase(self.now,True)['pack_hash'],request['pack_hash'])
        with self.assertRaises(Rejected):fresh.issuance_request()

    def test_concurrent_payment_arming_has_only_one_admission(self):
        request=self.client.prepare_purchase(self.now,True)
        original=copy.deepcopy(self.client.wallet.load('credential'))
        self.assertNotIn('payment_intent',original['pending'])
        with self.assertRaises(Rejected):self.client.arm_payment(request['pack_hash'],self.accounts[1],0,False)
        self.assertEqual(self.client.wallet.load('credential'),original)
        def arm(nonce):
            try:
                return TicketWallet(self.directory,self.offer).arm_payment(request['pack_hash'],self.accounts[1],nonce,True)
            except Rejected:return None
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(arm,[0,1]))
        self.assertEqual(sum(v is not None for v in results),1)
        self.assertEqual(self.client.payment_intent()['payment_intent'],next(v for v in results if v)['payment_intent'])

    def search_intent(self):
        request=self.client.prepare_purchase(self.now,True)
        block=self.rpc.call('eth_getBlockByNumber','latest',False)
        nonce=int(self.rpc.call('eth_getTransactionCount',self.accounts[1],'pending'),16)
        return self.client.arm_payment(request['pack_hash'],self.accounts[1],nonce,True,
            anchor={'number':block['number'],'hash':block['hash']})

    def test_lost_wallet_hash_is_found_by_finalized_nonce_then_issued(self):
        view=self.search_intent()
        self.assertEqual(find_payment(self.rpc,view)['state'],'not-finalized')
        for _ in range(4):self.rpc.tx(self.accounts[2],'0x',self.accounts[3],21000)
        receipt=self.send(view['transaction'])
        for _ in range(4):self.rpc.tx(self.accounts[2],'0x',self.accounts[3],21000)
        restarted=TicketWallet(self.directory,self.offer)
        with patch.object(self.rpc,'call',wraps=self.rpc.call) as calls:
            found=find_payment(self.rpc,restarted.payment_intent())
            self.assertLessEqual(calls.call_count,20)
        self.assertEqual(found['state'],'transaction-found');self.assertEqual(found['receipt_status'],'0x1')
        self.assertEqual(found['transaction']['hash'],receipt['transactionHash'])
        restarted.recover_payment(found['transaction'])
        self.assertEqual(restarted.receive(self.issuer.issue(**restarted.issuance_request()))['available'],2)

    def test_pending_send_is_uncertain_until_mined_and_never_rearmed(self):
        view=self.search_intent();self.rpc.call('evm_setAutomine',False)
        tx=view['transaction'];h=self.rpc.call('eth_sendTransaction',{'from':self.accounts[1],
            'to':tx['to'],'data':tx['data'],'value':tx['value'],'gas':hex(500000)})
        self.assertIsNone(self.rpc.call('eth_getTransactionReceipt',h))
        before=(self.directory/'credential.sealed').read_bytes()
        self.assertEqual(find_payment(self.rpc,view)['state'],'not-finalized')
        self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        with self.assertRaises(Rejected):self.client.arm_payment(view['pack_hash'],self.accounts[1],1,True)
        self.rpc.call('evm_mine')
        self.assertEqual(find_payment(self.rpc,view)['transaction']['hash'],h)

    def test_nonce_used_for_another_transaction_does_not_reset_or_record_payment(self):
        view=self.search_intent();self.rpc.tx(self.accounts[1],'0x',self.accounts[2],21000)
        before=(self.directory/'credential.sealed').read_bytes()
        self.assertEqual(find_payment(self.rpc,view)['state'],'nonce-consumed-by-other-transaction')
        self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        with self.assertRaises(Rejected):self.client.issuance_request()
        with self.assertRaises(Rejected):self.client.arm_payment(view['pack_hash'],self.accounts[1],1,True)

    def test_failed_exact_transaction_is_found_but_never_confirms_payment(self):
        view=self.search_intent();tx=view['transaction']
        h=self.rpc.call('eth_sendTransaction',{'from':self.accounts[1],'to':tx['to'],
            'data':tx['data'],'value':tx['value'],'gas':hex(30000)})
        self.assertEqual(self.receipt(h)['status'],'0x0')
        found=find_payment(self.rpc,view)
        self.assertEqual(found['receipt_status'],'0x0')
        self.client.recover_payment(found['transaction'])
        with self.assertRaises(Rejected):self.issuer.issue(**self.client.issuance_request())
        self.assertEqual(self.client.status()['available'],0)

    def test_search_rejects_legacy_unanchored_intent_and_changed_anchor(self):
        q=self.client.prepare_purchase(self.now,True)
        old=self.client.arm_payment(q['pack_hash'],self.accounts[1],0,True)
        with patch.object(self.rpc,'call',side_effect=AssertionError('no guessed history scan')):
            with self.assertRaises(Rejected):find_payment(self.rpc,old)
        # Separate public-view fixture; no conversion of the saved v1 intent.
        block=self.rpc.call('eth_getBlockByNumber','latest',False)
        changed=copy.deepcopy(old);changed['payment_intent'].update(
            profile='nockapp-ticket-wallet-payment-intent-v2',anchor={'number':block['number'],'hash':'0x'+'11'*32})
        before=(self.directory/'credential.sealed').read_bytes()
        with self.assertRaises(Rejected):find_payment(self.rpc,changed)
        self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        self.assertEqual(self.client.payment_intent(),old)

    def test_nonce_search_work_is_logarithmic_over_large_history(self):
        view=self.search_intent();paid=self.send(view['transaction'])
        actual=self.rpc.call('eth_getTransactionByHash',paid['transactionHash'])
        high=2**52-1;target=high//2+1;endhash='0x'+'22'*32;targethash='0x'+'33'*32
        tx={**actual,'blockNumber':hex(target),'blockHash':targethash,'transactionIndex':'0x0'}
        receipt={**paid,'blockNumber':hex(target),'blockHash':targethash,'transactionIndex':'0x0'}
        start=view['payment_intent']['anchor'];seen=[];ticks=[0.];times=[]
        def pause(delay):ticks[0]+=delay
        def call(method,*args):
            seen.append((method,args));times.append(ticks[0])
            if method=='eth_chainId':return '0x14a34'
            if method=='eth_getTransactionCount':return hex(int(int(args[1],16)>=target))
            if method=='eth_getTransactionReceipt':return receipt
            self.assertEqual(method,'eth_getBlockByNumber')
            if args[0]=='finalized' or args[0]==hex(high):return {'number':hex(high),'hash':endhash}
            if args[0]==start['number']:return start
            self.assertEqual(args[0],hex(target))
            return {'number':hex(target),'hash':targethash,'transactions':[tx if args[1] else tx['hash']]}
        with patch.object(self.rpc,'call',side_effect=call):
            found=find_payment(self.rpc,view,clock=lambda:ticks[0],pause=pause)
        self.assertEqual(found['transaction'],tx)
        self.assertLessEqual(len(seen),64)
        self.assertTrue(all(b-a>=0.129999 for a,b in zip(times,times[1:])))
        self.assertLess(ticks[0],9)

    def test_search_timeout_preserves_the_uncertain_payment(self):
        view=self.search_intent();before=(self.directory/'credential.sealed').read_bytes();ticks=[0.]
        call=self.rpc.call
        def slow(method,*args):
            ticks[0]+=26
            return call(method,*args)
        with patch.object(self.rpc,'call',side_effect=slow):
            with self.assertRaises(Rejected):find_payment(self.rpc,view,clock=lambda:ticks[0])
        self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        self.assertEqual(self.client.payment_intent(),view)

    def test_inconsistent_receipt_anchor_or_block_budget_never_records_payment(self):
        view=self.search_intent();self.send(view['transaction'])
        before=(self.directory/'credential.sealed').read_bytes();original=self.rpc.call
        for mode in ('receipt','anchor','budget','unresolved'):
            start_reads=[0]
            def changed(method,*args):
                result=original(method,*args)
                if method=='eth_getTransactionReceipt' and mode=='receipt':
                    result['blockHash']='0x'+'11'*32
                if method=='eth_getBlockByNumber' and args[0]==view['payment_intent']['anchor']['number']:
                    start_reads[0]+=1
                    if mode=='anchor' and start_reads[0]>1:result['hash']='0x'+'11'*32
                if method=='eth_getBlockByNumber' and args[1] is True:
                    if mode=='budget':result['transactions']=[result['transactions'][0]]*2049
                    if mode=='unresolved':result['transactions'][0]['from']=self.accounts[2]
                return result
            with self.subTest(mode=mode),patch.object(self.rpc,'call',side_effect=changed):
                if mode=='unresolved':
                    self.assertEqual(find_payment(self.rpc,view,pause=lambda _:None)['state'],'nonce-consumed-unresolved')
                else:
                    with self.assertRaises(Rejected):find_payment(self.rpc,view,pause=lambda _:None)
            self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
            self.assertEqual(self.client.payment_intent(),view)

    def fail_purchase(self,view):
        tx=view['transaction']
        h=self.rpc.call('eth_sendTransaction',{'from':self.accounts[1],'to':tx['to'],
            'data':tx['data'],'value':tx['value'],'gas':hex(30000)})
        self.assertEqual(self.receipt(h)['status'],'0x0')
        return h

    def test_finalized_failure_closes_only_after_immutable_purchase_deadline(self):
        view=self.search_intent();pending=copy.deepcopy(self.client.wallet.load('credential')['pending'])
        failed=self.fail_purchase(view)
        before=(self.directory/'credential.sealed').read_bytes()
        with self.assertRaisesRegex(Rejected,'relay-window-open'):
            failed_payment_proof(self.rpc,self.offer,view,pause=lambda _:None)
        self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        self.rpc.call('evm_setNextBlockTimestamp',self.terms['purchase_before'])
        self.rpc.call('evm_mine')
        proof=failed_payment_proof(self.rpc,self.offer,view,pause=lambda _:None)
        self.assertEqual(proof['transaction_hash'],failed);self.assertEqual(proof['outcome'],'failed')
        self.assertEqual(self.client._close_payment(view,proof)['state'],'attempt-closed')
        saved=self.client.wallet.load('credential')['pending']
        for key in ('pack_hash','pack','requests'):self.assertEqual(saved[key],pending[key])
        self.assertIsNone(saved['payment_tx']);self.assertNotIn('payment_intent',saved)
        self.assertEqual(saved['closed_payments'],[proof])
        before=(self.directory/'credential.sealed').read_bytes()
        with self.assertRaises(Rejected):self.client.record_payment(view['pack_hash'],failed)
        self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        with self.assertRaises(Rejected):self.client.arm_payment(view['pack_hash'],self.accounts[1],0,True,
            anchor=proof['checked_through'])
        block=self.rpc.call('eth_getBlockByNumber','latest',False)
        check_closed_payments(self.rpc,self.client.closed_payments(),block)
        next_view=self.client.arm_payment(view['pack_hash'],self.accounts[1],1,True,
            anchor={'number':block['number'],'hash':block['hash']})
        # Closing cannot resurrect a delayed relayer payment: the fixed
        # contract now rejects all further purchases under these terms.
        self.assertEqual(self.send(next_view['transaction'])['status'],'0x0')
        self.assertEqual(self.client.status()['available'],0)

    def test_uncertain_or_successful_payment_cannot_be_closed(self):
        view=self.search_intent();before=(self.directory/'credential.sealed').read_bytes()
        with self.assertRaises(Rejected):failed_payment_proof(self.rpc,self.offer,view,pause=lambda _:None)
        self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        self.send(view['transaction'])
        with self.assertRaises(Rejected):failed_payment_proof(self.rpc,self.offer,view,pause=lambda _:None)
        self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        self.assertFalse(self.client.closed_payments())

    def test_consumed_nonce_cancellation_and_lost_closing_reply_recover_without_resending(self):
        view=self.search_intent();self.rpc.tx(self.accounts[1],'0x',self.accounts[1],21000)
        with self.assertRaisesRegex(Rejected,'relay-window-open'):
            failed_payment_proof(self.rpc,self.offer,view,pause=lambda _:None)
        self.rpc.call('evm_setNextBlockTimestamp',self.terms['purchase_before'])
        self.rpc.call('evm_mine')
        proof=failed_payment_proof(self.rpc,self.offer,view,pause=lambda _:None)
        self.assertEqual(proof['outcome'],'other-transaction')
        original=self.client._save
        def save(r):original(r);raise OSError('fixture lost close reply after fsync')
        with patch.object(self.client,'_save',side_effect=save):
            with self.assertRaises(OSError):self.client._close_payment(view,proof)
        fresh=TicketWallet(self.directory,self.offer)
        self.assertEqual(fresh._close_payment(view,proof)['state'],'attempt-closed')
        self.assertEqual(fresh.closed_payments(),[proof])
        with patch.object(self.crypto.native,'_call',side_effect=AssertionError('do not replace blinded pack')):
            self.assertEqual(fresh.prepare_purchase(self.now,True)['pack_hash'],view['pack_hash'])
        self.assertEqual(fresh.status()['available'],0)

    def test_failed_original_attempt_cannot_close_after_pack_was_paid_elsewhere(self):
        view=self.search_intent();failed=self.fail_purchase(view)
        failed_block=self.rpc.call('eth_getTransactionReceipt',failed)['blockNumber']
        paid=self.send(view['transaction']);self.assertEqual(paid['status'],'0x1')
        before=(self.directory/'credential.sealed').read_bytes()
        with self.assertRaises(Rejected):failed_payment_proof(self.rpc,self.offer,view,pause=lambda _:None)
        original=self.rpc.call
        def lagging_finality(method,*args):
            if method=='eth_getBlockByNumber' and args[0]=='finalized':
                return original(method,failed_block,*args[1:])
            return original(method,*args)
        # Final state is still unpaid, but a newer canonical payment exists.
        with patch.object(self.rpc,'call',side_effect=lagging_finality):
            with self.assertRaises(Rejected):failed_payment_proof(self.rpc,self.offer,view,pause=lambda _:None)
        self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        self.assertFalse(self.client.closed_payments())

    def test_mined_failure_does_not_close_before_finality(self):
        view=self.search_intent();self.fail_purchase(view)
        before=(self.directory/'credential.sealed').read_bytes();original=self.rpc.call
        def lagging_finality(method,*args):
            if method=='eth_getBlockByNumber' and args[0]=='finalized':
                return original(method,view['payment_intent']['anchor']['number'],*args[1:])
            return original(method,*args)
        with patch.object(self.rpc,'call',side_effect=lagging_finality):
            with self.assertRaises(Rejected):failed_payment_proof(self.rpc,self.offer,view,pause=lambda _:None)
        self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        self.assertEqual(self.client.payment_intent(),view)

    def test_full_paid_pack_then_anonymous_redemption_and_restart(self):
        request,receipt=self.paid()
        pending=self.client.wallet.load('credential')['pending']
        ciphertext=(self.directory/'credential.sealed').read_bytes()
        for p in pending['requests']:
            self.assertNotIn(p['request']['recovery'].encode(),ciphertext)
        self.assertEqual(set(request),{'pack','transaction_hash'})
        self.assertEqual(set(request['pack']),{'profile','parameters','blinded'})
        reply=self.issuer.issue(**request)
        self.assertEqual(self.client.receive(reply)['available'],2)
        self.assertEqual(self.client.receive(reply)['available'],2)
        restarted=TicketWallet(self.directory,self.offer)
        token=restarted.reserve('0x'+'11'*32,self.now)
        self.assertEqual(token,restarted.reserve('0x'+'11'*32,self.terms['redeem_before']+1))
        self.assertNotIn(receipt['transactionHash'],canonical(token).decode())
        self.assertNotIn(pending['pack_hash'],canonical(token).decode())
        self.assertNotIn(self.accounts[1][2:],canonical(token).decode())
        journal=S3BindingJournal(self.s3,'private-lab-journal','ticket-bindings-v1/'+self.offer.hash+'/')
        authority=TicketBindings(self.offer.protocol,journal)
        binding=authority.bind(token,'11'*32)
        self.assertEqual(authority.bind(token,'11'*32),binding)
        with self.assertRaises(Rejected):authority.bind(token,'22'*32)
        second=restarted.reserve('0x'+'22'*32,self.now)
        self.assertNotEqual(self.offer.protocol.verify(token),self.offer.protocol.verify(second))
        with self.assertRaises(Rejected):restarted.reserve('0x'+'33'*32,self.now)

    def test_pending_saved_before_prompt_and_reused_after_lost_local_reply(self):
        original=self.client._save
        def save(r):original(r);raise OSError('fixture loss after durable write')
        with patch.object(self.client,'_save',side_effect=save):
            with self.assertRaises(OSError):self.client.prepare_purchase(self.now,True)
        saved=self.client.wallet.load('credential')['pending']
        fresh=TicketWallet(self.directory,self.offer)
        with patch.object(self.crypto.native,'_call',side_effect=AssertionError('retry must not reblind')):
            request=fresh.prepare_purchase(self.now,True)
        self.assertEqual(request['pack_hash'],saved['pack_hash'])
        self.assertEqual(fresh.wallet.load('credential')['pending'],saved)

    def test_invalid_member_keeps_whole_pending_pack_then_lost_import_reply_recovers(self):
        request,_=self.paid();reply=self.issuer.issue(**request)
        bad=copy.deepcopy(reply);bad['signatures'][1]='AA=='
        before=(self.directory/'credential.sealed').read_bytes()
        with self.assertRaises(Rejected):self.client.receive(bad)
        self.assertEqual((self.directory/'credential.sealed').read_bytes(),before)
        original=self.client._save
        def save(r):original(r);raise OSError('fixture lost import reply')
        with patch.object(self.client,'_save',side_effect=save):
            with self.assertRaises(OSError):self.client.receive(reply)
        fresh=TicketWallet(self.directory,self.offer)
        self.assertEqual(fresh.receive(reply)['available'],2)
        self.assertIsNone(fresh.wallet.load('credential')['pending'])

    def test_lost_local_reservation_reply_never_reassigns_ticket(self):
        request,_=self.paid();self.client.receive(self.issuer.issue(**request))
        original=self.client._save
        def save(r):original(r);raise OSError('fixture lost reserve reply')
        with patch.object(self.client,'_save',side_effect=save):
            with self.assertRaises(OSError):self.client.reserve('0x'+'11'*32,self.now)
        fresh=TicketWallet(self.directory,self.offer)
        token=fresh.reserve('0x'+'11'*32,self.now)
        other=fresh.reserve('0x'+'22'*32,self.now)
        self.assertNotEqual(token,other)
        self.assertEqual(fresh.reserve('0x'+'11'*32,self.now),token)

    def test_missing_record_never_initializes_empty_balance(self):
        self.client.wallet.delete('credential')
        keys=copy.deepcopy(self.keyring.values)
        with self.assertRaises(Rejected):TicketWallet(self.directory,self.offer).initialize()
        self.assertEqual(self.keyring.values,keys)

    def test_unavailable_keyring_does_not_overwrite_records(self):
        before={p.name:p.read_bytes() for p in self.directory.iterdir() if p.name in ('public.json','credential.sealed')}
        with patch('wallet.WalletSecretService',side_effect=Rejected('fixture-keyring-unavailable')):
            with self.assertRaises(Rejected):TicketWallet(self.directory,self.offer).initialize()
        self.assertEqual({p.name:p.read_bytes() for p in self.directory.iterdir() if p.name in before},before)

    def test_payment_must_be_canonical_finalized_and_for_exact_pack(self):
        before=self.rpc.call('eth_getBlockByNumber','latest',False)
        request,_=self.paid();original=self.rpc.call
        def lag(method,*args):
            if method=='eth_getBlockByNumber' and args[0]=='finalized':return before
            return original(method,*args)
        with patch.object(self.rpc,'call',side_effect=lag):
            with self.assertRaises(Rejected):self.issuer.issue(**request)
        self.assertFalse(self.s3.records)
        other=[self.offer.protocol.prepare(),self.offer.protocol.prepare()]
        wrong=self.offer.protocol.blinded_pack(other)
        with self.assertRaises(Rejected):self.issuer.issue(wrong,request['transaction_hash'])
        self.assertFalse(self.s3.records)
        self.assertEqual(len(self.issuer.issue(**request)['signatures']),2)

    def test_issue_refund_race_has_one_permanent_decision(self):
        request,_=self.paid()
        signature=self.refund_signature(request)
        def attempt(mode):
            try:
                fn=self.issuer.issue if mode=='issue' else self.issuer.reserve_unissued_refund
                return mode,fn(**request,**({'signature':signature} if mode=='refund' else {}))
            except Rejected:return mode,None
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(attempt,['issue','refund']))
        winners=[(mode,result) for mode,result in results if result is not None]
        self.assertEqual(len(winners),1)
        mode,result=winners[0]
        if mode=='issue':
            with self.assertRaises(Rejected):self.service().reserve_unissued_refund(**request,signature=signature)
            self.assertEqual(self.service().issue(**request),result)
        else:
            with self.assertRaises(Rejected):self.service().issue(**request)
            self.assertIsNone(self.results.read(result['payment']['pack_hash'][2:]))
            self.assertEqual(self.service().reserve_unissued_refund(**request,signature=signature),result)

    def test_lost_result_write_reply_recovers_saved_signatures_without_resigning(self):
        request,_=self.paid();original=self.results.create
        def lost(key,data):original(key,data);raise TimeoutError('fixture lost result readback')
        with patch.object(self.results,'create',side_effect=lost):
            with self.assertRaises(TimeoutError):self.issuer.issue(**request)
        with self.assertRaises(Rejected):self.issuer.reserve_unissued_refund(**request,signature=self.refund_signature(request))
        with patch.object(self.crypto.native,'_call',side_effect=AssertionError('saved results need no signing')):
            reply=self.service().issue(**request)
        self.assertEqual(self.client.receive(reply)['available'],2)

    def test_unissued_refund_decision_survives_restart_and_forbids_issuance(self):
        request,_=self.paid()
        signature=self.refund_signature(request)
        decision=self.issuer.reserve_unissued_refund(**request,signature=signature)
        self.assertEqual(self.service().reserve_unissued_refund(**request,signature=signature),decision)
        with self.assertRaises(Rejected):self.service().issue(**request)
        self.assertIsNone(self.results.read(decision['payment']['pack_hash'][2:]))
        self.assertNotIn('payer',canonical(decision).decode())

    def test_payment_reorg_after_saved_results_stops_reply_without_resetting_decision(self):
        snapshot=self.rpc.call('evm_snapshot')
        request,_=self.paid();original=self.results.create
        def reorg(key,data):
            saved=original(key,data)
            self.assertTrue(self.rpc.call('evm_revert',snapshot))
            return saved
        with patch.object(self.results,'create',side_effect=reorg):
            with self.assertRaises(Rejected):self.issuer.issue(**request)
        self.assertEqual(len(self.s3.records),2) # Decision and signatures remain immutable.
        before=copy.deepcopy(self.s3.records)
        with self.assertRaises(Rejected):self.service().reserve_unissued_refund(**request,signature=self.refund_signature(request))
        with self.assertRaises(Rejected):self.service().issue(**request)
        self.assertEqual(self.s3.records,before)

    def test_copied_purchase_cannot_cancel_without_original_payer_signature(self):
        request,_=self.paid()
        with self.assertRaises(Rejected):self.issuer.reserve_unissued_refund(**request,signature=self.refund_signature(request,self.accounts[2]))
        self.assertFalse(self.s3.records)
        self.assertEqual(len(self.issuer.issue(**request)['signatures']),2)

    def test_same_pack_cannot_be_paid_twice_or_after_exact_deadline(self):
        request=self.client.prepare_purchase(self.now,True)
        self.assertEqual(self.send(request['transaction'])['status'],'0x1')
        before=self.rpc.call('eth_getBalance',self.accounts[3],'latest')
        self.assertEqual(self.send(request['transaction'])['status'],'0x0')
        self.assertEqual(self.rpc.call('eth_getBalance',self.accounts[3],'latest'),before)
        tx=dict(request['transaction'],data=encode('buy(bytes32)','0x'+'77'*32))
        self.rpc.call('evm_setNextBlockTimestamp',self.terms['purchase_before'])
        self.assertEqual(self.send(tx)['status'],'0x0')

    def test_fixed_contract_has_no_admin_or_index_authority(self):
        funcs={a['name']:a for a in self.compiled['abi'] if a['type']=='function'}
        self.assertEqual(set(funcs),{'PURCHASE_VERSION','termsHash','recipient','packPrice','purchaseBefore','paid','buy'})
        self.assertEqual({n for n,v in funcs.items() if v['stateMutability'] not in ('view','pure')},{'buy'})
        for signature,args in [('setPrice(uint256)',(1,)),('pause()',()),('upgradeTo(address)',(self.accounts[2],))]:
            self.assertEqual(self.rpc.tx(self.accounts[0],encode(signature,*args),self.contract)['status'],'0x0')

    def test_manifest_drift_and_different_pin_fail_closed(self):
        changed=copy.deepcopy(self.offer.manifest);changed['terms']['pack_price_wei']='10001'
        with self.assertRaises(Rejected):TicketOffer(changed,self.offer.hash,self.crypto.native)
        self.offer.terms['pack_price_wei']='10001'
        with self.assertRaises(Rejected):self.client.prepare_purchase(self.now,True)


if __name__=='__main__':unittest.main()
