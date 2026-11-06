"""Actual signatures/native proofs/EVM/SQLite; S3, OP fees and finality fixtures."""
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

from authorship import AuthorshipNative
from authorship_v5 import core,points,prove
from base_protocol import ReceiptKey,keccak,sha
from base_transactions import ProtectedSigner,Limits
from permissionless_contracts import build as build_index
from permissionless_index import PublicIndexReader,submission_data
from policy import Rejected,canonical
from public_bundle_v5 import unsigned,build,encode,blob
from public_content_v5 import PublicContent
from public_reader_v6 import HistoricalPublicReader
from test_base_fees import FeeRPC
import test_ticket_purchase_v1 as purchase_cases
from test_ticket_bindings_v1 import AtomicS3Fixture
from test_public_reader_v5 import MemoryPublicOrigin
from ticket_offer_v1 import TicketOffer,OFFER_V2,manifest_hash
from ticket_payment_v1 import FinalizedTicketPayment
from ticket_bindings_v1 import ConditionalS3Records
from ticket_journal_v2 import ImmutableS3JournalAnchor
from ticket_publication_queue_v2 import TicketPublicationQueue,PROFILE
from ticket_publication_v2 import TicketPublicationWorker
from ticket_wallet_v1 import TicketWallet
from ticket_publisher_v2 import TicketPublisher
from base_evm import encode as abi


class SnapshotS3Fixture(AtomicS3Fixture):
    def list_objects_v2(self,**args):
        with self.lock:
            if self.mode=='read':raise TimeoutError()
            assert args['MaxKeys']==1 and args['ExpectedBucketOwner']=='419720240831'
            keys=sorted(k for k in self.records if k.startswith(args['Prefix']))
            return {'Contents':[{'Key':k,'Size':len(self.records[k])} for k in keys[:1]],
                'KeyCount':min(1,len(keys)),'IsTruncated':len(keys)>1}


class FinalityFeeRPC(FeeRPC):
    def call(self,method,*args):
        # Match the fixture's explicit latest-as-finalized block oracle also
        # for eth_getCode; Anvil's native finalized tag otherwise lags it.
        if method=='eth_getCode' and args[1]=='finalized':
            args=(args[0],self.rpc.call('eth_getBlockByNumber','latest',False)['number'])
        return super().call(method,*args)


class PublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        purchase_cases.PurchaseTests.setUpClass()
        cls.index_compiled=build_index();cls.author=AuthorshipNative()

    def setUp(self):
        f=self.f=purchase_cases.PurchaseTests();f.setUp();self.addCleanup(f.doCleanups)
        code=self.index_compiled['contracts/PublicCommitmentIndex.sol']['PublicCommitmentIndex']['evm']['bytecode']['object']
        r=f.rpc.tx(f.accounts[0],'0x'+code+abi('f(bytes32)',f.terms['application'])[10:])
        self.assertEqual(r['status'],'0x1');self.contract=r['contractAddress']
        runtime=bytes.fromhex(f.rpc.call('eth_getCode',self.contract,'latest')[2:])
        terms=copy.deepcopy(f.terms);terms.update(profile=OFFER_V2,redemption_ledger=PROFILE,index_contract=self.contract,
            index_runtime_keccak=keccak(runtime),max_total_fee_wei=str(3*10**15))
        purchase=f.deploy(terms)
        manifest={'terms':terms,'purchase_contract':purchase,
            'purchase_runtime_keccak':keccak(bytes.fromhex(f.rpc.call('eth_getCode',purchase,'latest')[2:]))}
        f.offer=self.offer=TicketOffer(manifest,manifest_hash(manifest),f.crypto.native)
        f.payment=FinalizedTicketPayment(f.rpc,self.offer)
        f.decisions=ConditionalS3Records(f.s3,'lab-private-journal','ticket-purchases-v1/'+self.offer.hash+'/decisions/',2048)
        f.results=ConditionalS3Records(f.s3,'lab-private-journal','ticket-purchases-v1/'+self.offer.hash+'/results/',32768)
        f.issuer=f.service();f.client=TicketWallet(f.directory.with_name('tickets-v2'),self.offer);f.client.initialize()
        request,_=f.paid();f.client.receive(f.issuer.issue(**request))
        self.tokens=[v['token'] for v in f.client.wallet.load('credential')['tickets']]
        self.rpc=FinalityFeeRPC(f.rpc);self.policy=self.rpc.approved()
        now=SimpleNamespace(time=lambda:int(f.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16))
        for module in ('base_fees','ticket_publication_queue_v2'):
            p=patch(module+'.time',now);p.start();self.addCleanup(p.stop)
        self.key=ReceiptKey(self.rpc);self.signer=ProtectedSigner(self.rpc,self.key)
        f.rpc.call('anvil_setBalance',self.key.address,hex(10**17))
        self.limits=Limits(200000,3000000000,1000000,10**17,100)
        self.sdk=SnapshotS3Fixture()
        # Global per gas-wallet/chain journal, NOT a new nonce ledger per offer.
        namespace=hashlib.sha256(('84532:'+self.signer.address+':'+PROFILE).encode()).hexdigest()
        self.anchor=ImmutableS3JournalAnchor(self.sdk,'lab-private-snapshots',namespace,account_id='419720240831')
        self.paths=0;self.queue=self.make_queue(initial_nonce=0)
        self.index=PublicIndexReader(self.rpc,self.contract,terms['application'],runtime_hash=terms['index_runtime_keccak'])
        self.origin=MemoryPublicOrigin();self.content=PublicContent(self.origin)
        self.reader=HistoricalPublicReader(self.index,self.content,self.author,issuer_authority='ab'*32)
        self.worker=self.make_worker(self.queue)
        self.secret=self.author.call('generate')['secret']

    def make_queue(self,**kw):
        self.paths+=1
        runtime=bytes.fromhex(self.f.rpc.call('eth_getCode',self.contract,'latest')[2:])
        return TicketPublicationQueue(self.rpc,self.signer,Path(self.f.temp.name)/('queue-'+str(self.paths)+'.sqlite'),
            self.contract,self.offer.terms['application'],self.limits,code_hashes={self.contract:hashlib.sha256(runtime).hexdigest()},
            anchor=self.anchor,fee_policy=self.policy,**kw)

    def make_worker(self,queue):
        return TicketPublicationWorker(self.offer,queue,self.index,self.content,self.author,resolve_original=self.reader.resolve_original)

    def post(self,*,bad_badges=False,parent=None):
        now=int(self.f.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16)
        post={'kind':'thread' if parent is None else 'comment','id':str(uuid.uuid4()),'created_at':now,
            'title':'Ticket publication' if parent is None else None,'body':'Exact privately authored public bytes','references':[]}
        context={'protocol':5,'chain_id':84532,'application':self.offer.terms['application'],
            'contract':self.contract,'submission_id':hashlib.sha256(uuid.uuid4().bytes).hexdigest()}
        c=core(post,context,thread=parent,address_disclosure=bad_badges,followers_threshold=123 if bad_badges else None)
        evidence={'wallet':blob(b'bad optional wallet','wallet'),'followers':blob(b'bad optional followers','followers')} if bad_badges else {}
        u=unsigned(c,points(self.author,self.secret,c),**evidence);v=build(u,prove(self.author,self.secret,u))
        self.content.upload(v);return sha(encode(v)),v

    def finish(self,token,h):
        self.worker.submit(token,h)
        return self.worker.submit(token,h)

    def test_actual_paid_ticket_indexes_exact_bytes_and_reader_omits_only_bad_badges(self):
        h,_=self.post(bad_badges=True)
        token=self.f.client.reserve(h,self.f.now)
        result=self.finish(token,h);self.assertEqual(result['state'],'indexed');self.assertTrue(result['ticket_used'])
        tx=self.rpc.call('eth_getTransactionByHash',result['transaction_hash'])
        self.assertEqual(tx['input'],submission_data(h));self.assertEqual(tx['from'].lower(),self.signer.address.lower())
        page=self.reader.read_numbers([int(result['post_number'])],int(self.f.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16))
        self.assertTrue(page['posts'][0]['proofs_verified'])
        self.assertEqual(page['posts'][0]['display'],{'address':None,'followers':None,'history':None})

    def test_exact_raw_nonce_and_ticket_are_authoritative_before_lost_broadcast_reply(self):
        h,_=self.post();sent=[];original=self.rpc.call
        def lost(method,*args):
            if method=='eth_sendRawTransaction':
                revision,envelope=self.anchor.read()
                raw=self.signer.open_journal(envelope,self.queue._anchor_aad(revision))
                db=sqlite3.connect(':memory:');db.deserialize(raw)
                row=db.execute('SELECT raw,nonce FROM submissions').fetchone()
                self.assertEqual(row,(args[0],0));self.assertEqual(db.execute('SELECT bundle_hash FROM ticket_jobs').fetchone()[0],h);db.close()
                sent.append(args[0]);original(method,*args);raise OSError('fixture lost send reply')
            return original(method,*args)
        with patch.object(self.rpc,'call',side_effect=lost):first=self.worker.submit(self.tokens[0],h)
        self.assertEqual(first['state'],'recoverable');self.assertEqual(len(sent),1)
        stale=self.queue.path.read_bytes();self.queue.path.unlink()
        restored=self.make_queue();other=self.make_worker(restored)
        self.origin.fail=True;self.content.clear()
        with patch.object(self.author,'call',side_effect=AssertionError('no fresh proofs during recovery')):
            result=other.submit(self.tokens[0],h)
        self.assertEqual(result['state'],'indexed');self.assertEqual(result['transaction_hash'],first['transaction_hash'])
        restored.path.write_bytes(stale)
        self.assertEqual(other.submit(self.tokens[0],h)['post_number'],result['post_number'])
        different='0x'+'ff'*32
        with self.assertRaises(Rejected):other.submit(self.tokens[0],different)
        self.assertEqual(int(self.rpc.call('eth_getTransactionCount',self.signer.address,'latest'),16),1)

    def test_same_hash_other_ticket_is_not_consumed_and_can_publish_another_post(self):
        h,_=self.post();first=self.finish(self.tokens[0],h)
        duplicate=self.worker.submit(self.tokens[1],h)
        self.assertFalse(duplicate['ticket_used']);self.assertEqual(duplicate['post_number'],first['post_number'])
        other,_=self.post();second=self.finish(self.tokens[1],other)
        self.assertTrue(second['ticket_used']);self.assertNotEqual(second['post_number'],first['post_number'])
        self.assertEqual(int(self.rpc.call('eth_getTransactionCount',self.signer.address,'latest'),16),2)

    def test_direct_indexing_before_service_does_not_consume_a_ticket(self):
        h,_=self.post();self.f.rpc.tx(self.f.accounts[2],submission_data(h),self.contract)
        result=self.worker.submit(self.tokens[0],h)
        self.assertEqual(result['state'],'indexed');self.assertFalse(result['ticket_used']);self.assertIsNone(result['transaction_hash'])
        other,_=self.post();self.assertTrue(self.finish(self.tokens[0],other)['ticket_used'])

    def test_failed_snapshot_commit_never_broadcasts_or_consumes_from_local_db(self):
        h,_=self.post();original=self.rpc.call
        self.sdk.mode='before'
        with patch.object(self.rpc,'call',wraps=original) as calls:
            with self.assertRaises(Rejected):self.worker.submit(self.tokens[0],h)
        self.assertFalse(any(c.args[0]=='eth_sendRawTransaction' for c in calls.call_args_list))
        self.sdk.mode=None
        self.assertEqual(self.finish(self.tokens[0],h)['state'],'indexed')

    def test_same_ticket_concurrent_hashes_have_one_atomic_winner(self):
        h,_=self.post();other,_=self.post();q2=self.make_queue()
        nullifier=self.offer.protocol.verify(self.tokens[0]);barrier=threading.Barrier(2)
        original=self.anchor.compare_exchange
        def race(expected,envelope):
            if expected==0:barrier.wait(timeout=10)
            return original(expected,envelope)
        def admit(pair):
            queue,value=pair
            try:return queue.admit(nullifier,self.offer.hash,value,gas=200000,fee_ceiling=3*10**15,redeem_before=self.offer.terms['redeem_before'])
            except Rejected:return None
        with patch.object(self.anchor,'compare_exchange',side_effect=race),ThreadPoolExecutor(max_workers=2) as pool:
            rows=list(pool.map(admit,[(self.queue,h),(q2,other)]))
        winners=[r for r in rows if r is not None];self.assertEqual(len(winners),1)
        self.assertEqual(self.finish(self.tokens[0],winners[0]['bundle_hash'])['state'],'indexed')
        loser=other if winners[0]['bundle_hash']==h else h
        with self.assertRaises(Rejected):self.worker.submit(self.tokens[0],loser)

    def test_bad_author_or_missing_origin_is_rejected_before_ticket_binding(self):
        h,v=self.post();v['unsigned']['core']['post']['body']='tampered'
        bad=sha(canonical(v));self.origin.put(bad,canonical(v))
        with self.assertRaises(Rejected):self.worker.submit(self.tokens[0],bad)
        self.assertIsNone(self.queue.lookup(self.offer.protocol.verify(self.tokens[0]),bad))
        _,forged=self.post();forged['authorship']['response']='01'+'00'*31
        forged_hash=sha(encode(forged));self.origin.put(forged_hash,encode(forged))
        with self.assertRaises(Rejected):self.worker.submit(self.tokens[0],forged_hash)
        self.assertIsNone(self.queue.lookup(self.offer.protocol.verify(self.tokens[0]),forged_hash))
        self.origin.fail=True;self.content.clear()
        with self.assertRaises(Rejected):self.worker.submit(self.tokens[0],h)
        self.assertIsNone(self.queue.lookup(self.offer.protocol.verify(self.tokens[0]),h))

    def test_unattended_recovery_finishes_saved_operation_without_owner_or_new_signature(self):
        h,_=self.post();first=self.worker.submit(self.tokens[0],h)
        with patch.object(self.signer,'sign',side_effect=AssertionError('do not resign')):
            recovered=self.worker.recover_pending()
        self.assertEqual(len(recovered),1);self.assertEqual(recovered[0]['state'],'indexed')
        self.assertEqual(recovered[0]['transaction_hash'],first['transaction_hash'])

    def test_new_expired_ticket_rejected_but_previously_admitted_unsigned_job_recovers(self):
        h,_=self.post();nullifier=self.offer.protocol.verify(self.tokens[0])
        self.queue.admit(nullifier,self.offer.hash,h,gas=200000,fee_ceiling=3*10**15,redeem_before=self.offer.terms['redeem_before'])
        self.f.rpc.call('evm_setNextBlockTimestamp',self.offer.terms['redeem_before']);self.f.rpc.call('evm_mine')
        other,_=self.post()
        with self.assertRaisesRegex(Rejected,'ticket-redemptions-closed'):self.worker.submit(self.tokens[1],other)
        self.assertIsNone(self.queue.lookup(self.offer.protocol.verify(self.tokens[1]),other))
        self.assertEqual(self.finish(self.tokens[0],h)['state'],'indexed')

    def test_orphaned_unfinalized_transaction_reuses_identical_saved_bytes(self):
        h,_=self.post();snapshot=self.f.rpc.call('evm_snapshot')
        sent=[];original=self.rpc.call
        def track(method,*args):
            if method=='eth_sendRawTransaction':sent.append(args[0])
            return original(method,*args)
        with patch.object(self.rpc,'call',side_effect=track):
            self.worker.submit(self.tokens[0],h)
            self.assertTrue(self.f.rpc.call('evm_revert',snapshot))
            with patch.object(self.signer,'sign',side_effect=AssertionError('orphan retry must not resign')):
                self.worker.submit(self.tokens[0],h)
                result=self.worker.submit(self.tokens[0],h)
        self.assertEqual(result['state'],'indexed');self.assertEqual(len(sent),2);self.assertEqual(sent[0],sent[1])

    def test_finalized_disappearance_halts_without_new_nonce_or_ticket_reuse(self):
        h,_=self.post();snapshot=self.f.rpc.call('evm_snapshot');self.finish(self.tokens[0],h)
        self.assertTrue(self.f.rpc.call('evm_revert',snapshot))
        with patch.object(self.signer,'sign',side_effect=AssertionError('finality violation must not sign')):
            with self.assertRaises(Rejected):self.make_worker(self.make_queue()).submit(self.tokens[0],h)
        self.assertIsNotNone(self.queue.lookup(self.offer.protocol.verify(self.tokens[0]),h))

    def test_finalized_failure_remains_bound_and_does_not_retry_another_nonce(self):
        h,_=self.post();original=self.signer.sign
        # Explicit fault injection: a genuinely signed, intrinsically valid but
        # too-small execution allowance produces an actual EVM failure receipt.
        def undergas(chain,nonce,to,data,gas,max_fee,tip):return original(chain,nonce,to,data,50000,max_fee,tip)
        with patch.object(self.signer,'sign',side_effect=undergas):first=self.worker.submit(self.tokens[0],h)
        with patch.object(self.signer,'sign',side_effect=AssertionError('failure must not allocate a new nonce')):
            failed=self.worker.submit(self.tokens[0],h)
            again=self.worker.submit(self.tokens[0],h)
        self.assertEqual(failed['state'],'failed');self.assertTrue(failed['ticket_used'])
        self.assertEqual(failed['transaction_hash'],first['transaction_hash']);self.assertEqual(again,failed)
        with self.assertRaises(Rejected):self.worker.submit(self.tokens[0],'0x'+'88'*32)
        self.assertEqual(int(self.rpc.call('eth_getTransactionCount',self.signer.address,'latest'),16),1)

    def test_external_nonce_consumption_stops_instead_of_signing_replacement(self):
        h,_=self.post();self.f.rpc.call('evm_setAutomine',False)
        first=self.worker.submit(self.tokens[0],h)
        self.f.rpc.call('anvil_setNonce',self.signer.address,1)
        with patch.object(self.signer,'sign',side_effect=AssertionError('nonce conflict must not resign')):
            stopped=self.worker.submit(self.tokens[0],h)
        self.assertEqual(stopped['state'],'nonce-conflict');self.assertEqual(stopped['transaction_hash'],first['transaction_hash'])
        self.assertTrue(stopped['ticket_used'])

    def test_raw_snapshot_write_failure_cannot_broadcast_tentative_signature(self):
        h,_=self.post();original=self.anchor.compare_exchange;rpc=self.rpc.call;failed=[]
        def fail_raw(expected,envelope):
            next_revision=0 if expected is None else expected+1
            raw=self.signer.open_journal(envelope,self.queue._anchor_aad(next_revision))
            db=sqlite3.connect(':memory:');db.deserialize(raw)
            count=db.execute('SELECT count(*) FROM submissions').fetchone()[0];db.close()
            if count and not failed:
                failed.append(True);self.sdk.mode='before'
                try:return original(expected,envelope)
                finally:self.sdk.mode=None
            return original(expected,envelope)
        with patch.object(self.anchor,'compare_exchange',side_effect=fail_raw),patch.object(self.rpc,'call',wraps=rpc) as calls:
            with self.assertRaises(Rejected):self.worker.submit(self.tokens[0],h)
        self.assertTrue(failed);self.assertFalse(any(c.args[0]=='eth_sendRawTransaction' for c in calls.call_args_list))
        self.assertIsNotNone(self.queue.lookup(self.offer.protocol.verify(self.tokens[0]),h))
        self.assertEqual(self.finish(self.tokens[0],h)['state'],'indexed')

    def test_whole_fee_cap_rejects_before_consuming_a_ticket(self):
        h,_=self.post();n=self.offer.protocol.verify(self.tokens[0])
        with self.assertRaisesRegex(Rejected,'ticket-queue-offer-fee-cap'):
            self.queue.admit(n,self.offer.hash,h,gas=200000,fee_ceiling=1,redeem_before=self.offer.terms['redeem_before'])
        self.assertIsNone(self.queue.lookup(n,h))

    def test_invalid_thread_root_cannot_obtain_paid_sponsorship(self):
        parent={'protocol':5,'chain_id':84532,'contract':self.contract,'number':'999','bundle_hash':'0x'+'77'*32}
        h,_=self.post(parent=parent)
        with self.assertRaises(Rejected):self.worker.submit(self.tokens[0],h)
        self.assertIsNone(self.queue.lookup(self.offer.protocol.verify(self.tokens[0]),h))

    def test_client_timeout_keeps_reservation_and_recovers_same_operation(self):
        h,_=self.post()
        def lost(token,value):self.worker.submit(token,value);raise TimeoutError('fixture lost worker reply')
        client=TicketPublisher(self.f.client,lost,clock=lambda:self.f.now)
        with self.assertRaises(TimeoutError):client.publish(h,True)
        self.assertEqual(self.f.client.status()['available'],1)
        retry=TicketPublisher(self.f.client,self.worker.submit,clock=lambda:self.f.now)
        self.assertEqual(retry.publish(h,True)['state'],'indexed')
        self.assertEqual(self.f.client.status()['available'],1)
        self.assertEqual(int(self.rpc.call('eth_getTransactionCount',self.signer.address,'latest'),16),1)

    def test_other_clients_duplicate_is_not_charged_and_its_ticket_is_usable(self):
        h,_=self.post();self.finish(self.tokens[0],h)
        self.f.client=TicketWallet(self.f.directory.with_name('another-client'),self.offer);self.f.client.initialize()
        request,_=self.f.paid();self.f.client.receive(self.f.issuer.issue(**request))
        client=TicketPublisher(self.f.client,self.worker.submit,clock=lambda:self.f.now)
        self.assertFalse(client.publish(h,True)['ticket_used'])
        self.assertEqual(self.f.client.status()['available'],2)
        other,_=self.post();self.assertTrue(client.publish(other,True)['ticket_used'])
        self.assertEqual(self.f.client.status()['available'],1)

    def test_malformed_or_uncorrelated_reply_does_not_release_a_reserved_ticket(self):
        h,_=self.post()
        client=TicketPublisher(self.f.client,lambda token,value:{'ticket_used':False},clock=lambda:self.f.now)
        with self.assertRaises(Rejected):client.publish(h,True)
        self.assertEqual(self.f.client.status()['available'],1)
        with self.assertRaises(Rejected):client.publish(h,False)


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.sdk=SnapshotS3Fixture();self.anchor=ImmutableS3JournalAnchor(self.sdk,'lab-private-snapshots','ab'*32,account_id='419720240831')

    def test_cold_tip_discovery_and_lost_put_reply_preserve_all_immutable_slots(self):
        self.assertEqual(self.anchor.read(),(None,None))
        for n in range(20):
            self.sdk.mode='after'
            self.assertEqual(self.anchor.compare_exchange(None if n==0 else n-1,bytes([n])*100),n)
        cold=ImmutableS3JournalAnchor(self.sdk,'lab-private-snapshots','ab'*32,account_id='419720240831')
        self.assertEqual(cold.read(),(19,bytes([19])*100))
        self.assertEqual(len(self.sdk.records),20)
        for put in self.sdk.puts:self.assertEqual(put['IfNoneMatch'],'*')

    def test_stale_or_failed_writes_cannot_replace_tip(self):
        self.anchor.compare_exchange(None,b'a'*100)
        self.anchor.compare_exchange(0,b'b'*100)
        with self.assertRaises(Rejected):self.anchor.compare_exchange(0,b'c'*100)
        self.sdk.mode='before'
        with self.assertRaises(Rejected):self.anchor.compare_exchange(1,b'c'*100)
        self.assertEqual(self.anchor.read(),(1,b'b'*100))

    def test_two_independent_writers_cannot_commit_different_bytes_at_same_revision(self):
        self.anchor.compare_exchange(None,b'a'*100)
        other=ImmutableS3JournalAnchor(self.sdk,'lab-private-snapshots','ab'*32,account_id='419720240831')
        original=self.sdk.put_object;barrier=threading.Barrier(2)
        def race(**args):
            if args['Key'].endswith('0000000000000001.sealed'):barrier.wait(timeout=5)
            return original(**args)
        def write(pair):
            a,data=pair
            try:return a.compare_exchange(0,data)
            except Rejected:return None
        with patch.object(self.sdk,'put_object',side_effect=race),ThreadPoolExecutor(max_workers=2) as pool:
            result=list(pool.map(write,[(self.anchor,b'b'*100),(other,b'c'*100)]))
        self.assertEqual(result.count(1),1);self.assertEqual(len(self.sdk.records),2)

    def test_missing_known_authority_and_unavailable_reads_fail_closed(self):
        self.anchor.compare_exchange(None,b'a'*100)
        self.sdk.mode='read'
        with self.assertRaises(Rejected):self.anchor.read()
        self.sdk.mode=None;self.sdk.records.clear()
        with self.assertRaises(Rejected):self.anchor.read()


if __name__=='__main__':unittest.main()
