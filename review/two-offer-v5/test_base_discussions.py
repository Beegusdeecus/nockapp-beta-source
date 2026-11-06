"""Actual local EVM publications/readers. No live Base or browser claim."""
import copy
import secrets
import unittest
from unittest.mock import patch

from base_client import SharedReader
from base_evm import compile_contracts, encode, local_chain
from base_protocol import ordinary_publication_data, read, sha
from policy import Rejected
from test_domain_posts import post
from test_base_integration import BaseFixture


def immediate_finality(rpc):
    """Explicit software finality oracle for Anvil; never used by live clients."""
    original=rpc.call
    def call(method,*args):
        if method=='eth_getBlockByNumber' and args[0]=='finalized':
            return original(method,'latest',*args[1:])
        return original(method,*args)
    return patch.object(rpc,'call',side_effect=call)


class OrdinaryDiscussionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.compiled=compile_contracts()

    def setUp(self):
        self.chain=local_chain();self.rpc=self.chain.__enter__()
        self.accounts=self.rpc.call('eth_accounts');self.app='0x'+'ab'*32
        self.registry=self.deploy('IssuerState','f(address,address,bytes32)',
            self.accounts[0],self.accounts[1],'0x'+'cd'*32)
        self.contract=self.deploy('PostAcceptance','f(address,bytes32,address,address)',
            self.registry,self.app,self.accounts[0],self.accounts[2])
        self.reader=SharedReader(self.rpc,self.contract,None,self.app,page_blocks=2)
        self.post=dict(post(),claims=[]);self.submission=secrets.token_hex(32)
        self.finality=immediate_finality(self.rpc);self.finality.start()

    def tearDown(self):
        self.finality.stop();self.chain.__exit__(None,None,None)

    def deploy(self,name,constructor,*args):
        code=self.compiled['contracts/'+name+'.sol'][name]['evm']['bytecode']['object']
        receipt=self.rpc.tx(self.accounts[0],'0x'+code+encode(constructor,*args)[10:])
        self.assertEqual(receipt['status'],'0x1');return receipt['contractAddress']

    def publish(self,p=None,submission=None,sender=None):
        return self.rpc.tx(sender or self.accounts[3],ordinary_publication_data(p or self.post,
            submission or self.submission),self.contract)

    def now(self):return int(self.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16)

    def test_no_credential_or_initialized_issuer_required_and_independent_reader_agrees(self):
        self.assertEqual(int(read(self.rpc,self.registry,'initialized()'),16),0)
        receipt=self.publish();self.assertEqual(receipt['status'],'0x1')
        first=self.reader.read(self.now())
        second=SharedReader(self.rpc,self.contract,None,self.app).read(self.now())
        self.assertEqual(first,second);self.assertEqual(first[0]['post'],self.post)
        self.assertEqual(first[0]['post_number'],'1');self.assertEqual(first[0]['facts'],[])
        self.assertEqual(first[0]['credential_status'],'not-requested')
        self.assertEqual(first[0]['state'],'finalized');self.assertIsNone(first[0]['public_id'])

    def test_two_independent_senders_share_numbering_and_exact_references(self):
        self.assertEqual(self.publish()['status'],'0x1')
        comment=dict(self.post,kind='comment',id='87654321-1234-4123-8123-123456789abc',
            thread_id=self.post['id'],title=None,body='reply >>1')
        self.assertEqual(self.publish(comment,secrets.token_hex(32),self.accounts[4])['status'],'0x1')
        results=self.reader.read(self.now());self.assertEqual([r['post_number'] for r in results],['1','2'])
        self.assertEqual(results[1]['post']['body'],'reply >>1')
        self.assertEqual(results[1]['post']['thread_id'],results[0]['post']['id'])

    def test_duplicate_submission_and_uuid_do_not_allocate_extra_numbers(self):
        self.assertEqual(self.publish()['status'],'0x1')
        self.assertEqual(self.publish()['status'],'0x0')
        self.assertEqual(self.publish(dict(self.post,body='changed'),secrets.token_hex(32))['status'],'0x0')
        self.assertEqual(int(read(self.rpc,self.contract,'nextPostNumber()'),16),2)

    def test_pause_blocks_ordinary_publication(self):
        self.rpc.tx(self.accounts[0],encode('setPaused(bool)','true'),self.contract)
        self.assertEqual(self.publish()['status'],'0x0')

    def test_ordinary_adapter_refuses_demo_claims_and_zero_submission(self):
        with self.assertRaises(Rejected):ordinary_publication_data(dict(self.post,claims=[['x-account',None]]),self.submission)
        with self.assertRaises(Rejected):ordinary_publication_data(self.post,'00'*32)

    def test_bad_item_does_not_hide_good_post_and_never_gets_a_credential_badge(self):
        malformed=b'not a canonical post'
        self.rpc.tx(self.accounts[3],encode('publishOrdinary(bytes32,bytes32,bytes)',
            '0x'+secrets.token_hex(32),sha(b'bad'),'0x'+malformed.hex()),self.contract)
        self.assertEqual(self.publish()['status'],'0x1')
        results=self.reader.read(self.now())
        self.assertEqual([r['state'] for r in results],['unavailable','finalized'])
        self.assertFalse(results[0]['valid_when_published']);self.assertEqual(results[1]['post'],self.post)

    def test_temporarily_missing_receipt_is_retried_without_rescanning_history(self):
        receipt=self.publish();original=self.rpc.call;queries=[]
        def outage(method,*args):
            if method=='eth_getTransactionReceipt' and args[0]==receipt['transactionHash']:return None
            if method=='eth_getLogs':queries.append(args[0])
            return original(method,*args)
        with patch.object(self.rpc,'call',side_effect=outage):
            first=self.reader.read(self.now());self.assertEqual(first[0]['state'],'unavailable')
        with patch.object(self.rpc,'call',wraps=original) as calls:
            second=self.reader.read(self.now());self.assertEqual(second[0]['state'],'finalized')
            self.assertFalse(any(c.args[0]=='eth_getLogs' for c in calls.call_args_list))
        self.assertTrue(queries);self.assertTrue(all(int(q['toBlock'],16)-int(q['fromBlock'],16)<2 for q in queries))

    def test_failed_range_query_never_advances_cursor_or_loses_posts(self):
        self.publish();original=self.rpc.call
        def fail(method,*args):
            if method=='eth_getLogs':raise OSError('synthetic provider outage')
            return original(method,*args)
        with patch.object(self.rpc,'call',side_effect=fail):
            with self.assertRaises(OSError):self.reader.read(self.now())
        self.assertIsNone(self.reader.checkpoint);self.assertEqual(self.reader._logs,{})
        self.assertEqual(self.reader.read(self.now())[0]['state'],'finalized')

    def test_cache_returns_copies_and_avoids_rechecking_unchanged_publications(self):
        self.publish();first=self.reader.read(self.now());first[0]['post']['body']='tampered in UI'
        original=self.rpc.call
        with patch.object(self.rpc,'call',wraps=original) as calls:
            second=self.reader.read(self.now())
        self.assertEqual(second[0]['post']['body'],self.post['body'])
        self.assertFalse(any(c.args[0] in ('eth_getLogs','eth_getTransactionReceipt','eth_call') for c in calls.call_args_list))

    def test_finalized_checkpoint_change_stops_display_instead_of_false_confirmation(self):
        snap=self.rpc.call('evm_snapshot');self.publish();self.reader.read(self.now())
        self.assertTrue(self.rpc.call('evm_revert',snap));self.rpc.call('evm_mine')
        with self.assertRaises(Rejected):self.reader.read(self.now())

    def test_explicit_local_demo_reorg_rebuilds_and_discards_orphaned_number(self):
        reader=SharedReader(self.rpc,self.contract,None,self.app,demo_finality=True)
        snap=self.rpc.call('evm_snapshot');self.publish();self.assertEqual(len(reader.read(self.now())),1)
        self.rpc.call('evm_revert',snap);self.rpc.call('evm_mine')
        self.assertEqual(reader.read(self.now()),[])

    def test_catchup_advances_in_bounded_pages_without_claiming_complete_history(self):
        self.publish();reader=SharedReader(self.rpc,self.contract,None,self.app,page_blocks=1,max_pages=1)
        prior=-1;seen=[]
        for _ in range(16):
            seen=reader.read(self.now());height=int(reader.checkpoint['number'],16)
            self.assertGreater(height,prior);self.assertLessEqual(height,prior+1);prior=height
            if reader.sync_complete:break
            self.assertEqual(seen,[])
        self.assertTrue(reader.sync_complete);self.assertEqual(seen[0]['post'],self.post)


class MixedDiscussionTests(BaseFixture):
    def test_ordinary_and_credential_posts_share_numbers_and_native_verification_is_cached(self):
        from domain_pipeline import Native
        finality=immediate_finality(self.rpc);finality.start();self.addCleanup(finality.stop)
        ordinary=dict(self.post,claims=[])
        receipt=self.rpc.tx(self.relayer,ordinary_publication_data(ordinary,secrets.token_hex(32)),self.contract)
        self.assertEqual(receipt['status'],'0x1')
        self.post=dict(self.post,id='87654321-1234-4123-8123-123456789abc')
        self.assertEqual(self.publish(self.package())['status'],'0x1')
        reader=SharedReader(self.rpc,self.contract,self.backend,self.app)
        now=max(self.now,int(self.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16))
        with patch('base_client.Native',wraps=Native) as native:
            results=reader.read(now);self.assertEqual([r['post_number'] for r in results],['1','2'])
            self.assertEqual(native.call_count,1)
        with patch('base_client.Native',side_effect=AssertionError('must use verified cache')):
            self.assertEqual(reader.read(now),results)
            self.assertEqual(reader.read(now+86400)[1]['credential_status'],'expired')
        self.enroll(account='77777777')
        with patch('base_client.Native',side_effect=AssertionError('immutable proof remains cached')):
            results=reader.read(now)
            self.assertEqual(results[1]['credential_status'],'unknown-after-registry-update')
            self.assertTrue(results[1]['valid_when_published'])
