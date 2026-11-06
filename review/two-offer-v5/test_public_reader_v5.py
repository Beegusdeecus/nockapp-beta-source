"""Actual immutable EVM index + native proofs, synthetic public CAS and finality."""
import copy
import secrets
import unittest
import uuid
from unittest.mock import patch
from authorship import AuthorshipNative
from authorship_v5 import core,points,prove
from base_protocol import sha,keccak
from historical_authorship_v5 import prove as history_prove
from permissionless_index import PublicIndexReader,submission_data
from policy import canonical,Rejected
from public_bundle_v5 import unsigned,build,encode,blob,MAX_BYTES
from public_content_v5 import PublicContent
from public_reader_v5 import PublicDiscussionReader
import test_permissionless_index as index_cases


class MemoryPublicOrigin:
    """Only synthetic PUBLIC bytes; neither persistence nor AWS evidence."""
    def __init__(self):self.objects={};self.reads=0;self.puts=0;self.fail=False
    def put(self,h,raw):self.puts+=1;self.objects[h]=raw
    def get(self,h,limit):
        self.reads+=1
        if self.fail:raise OSError('synthetic unavailable origin')
        raw=self.objects[h]
        if len(raw)>limit:raise ValueError('bounded synthetic read')
        return raw


class PublicReaderV5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):index_cases.PermissionlessIndexTests.setUpClass();cls.native=AuthorshipNative()
    def setUp(self):
        self.f=index_cases.PermissionlessIndexTests('test_existing_reader_checks_runtime_inclusion_and_finality_without_claiming_proof_validity')
        self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.now=int(self.f.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16)
        self.secret=self.native.call('generate')['secret'];self.origin=MemoryPublicOrigin();self.content=PublicContent(self.origin)
        pin=keccak(bytes.fromhex(self.f.rpc.call('eth_getCode',self.f.index,'latest')[2:]))
        self.index=PublicIndexReader(self.f.rpc,self.f.index,self.f.app,runtime_hash=pin)
        self.reader=PublicDiscussionReader(self.index,self.content,self.native)
    def make(self,*,parent=None,address=False,evidence=None,secret=None,ident=None,threshold=None):
        c=core({'kind':'thread' if parent is None else 'comment','id':ident or str(uuid.uuid4()),'created_at':self.now,
            'title':'Synthetic public thread' if parent is None else None,'body':'Public exact text','references':[]},
            {'protocol':5,'chain_id':84532,'application':self.f.app,'contract':self.f.index,'submission_id':secrets.token_hex(32)},
            thread=parent,address_disclosure=address,followers_threshold=threshold)
        key=secret or self.secret;u=unsigned(c,points(self.native,key,c),wallet=evidence)
        return build(u,prove(self.native,key,u))
    def commit(self,raw):
        h=sha(raw);self.origin.objects[h]=raw
        receipt=self.f.rpc.tx(self.f.accounts[2],submission_data(h),self.f.index);self.assertEqual(receipt['status'],'0x1')
        return {'protocol':5,'chain_id':84532,'contract':self.f.index,'number':str(int(receipt['logs'][0]['topics'][2],16)),'bundle_hash':h}
    def read(self,numbers):
        now=int(self.f.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16)
        return self.reader.read_numbers(numbers,max(now,self.now))
    def test_plain_and_missing_follower_evidence_do_not_fetch_issuer_state(self):
        from unittest.mock import Mock
        views=Mock();self.reader.issuer_views=views
        self.commit(encode(self.make()));self.commit(encode(self.make(threshold=0)))
        rows=self.read([1,2])['posts']
        self.assertTrue(all(r['proofs_verified'] and r['state']=='finalized' for r in rows))
        self.assertTrue(all(r['display']['followers'] is None for r in rows))
        views.at.assert_not_called();views.current.assert_not_called()

    def test_parallel_public_inclusion_matches_serial_and_rejects_inclusion_failure(self):
        for _ in range(4):self.commit(encode(self.make()))
        serial=self.read([1,2,3,4]);self.f.rpc.public_read_batching=True
        self.f.rpc.read_many=lambda calls:[self.f.rpc.call(method,*params) for method,params in calls]
        parallel=self.read([1,2,3,4]);self.assertEqual(serial,parallel)
        original=self.index._record
        def changed(n,final):
            if n==3:raise Rejected('synthetic-inclusion-conflict')
            return original(n,final)
        with patch.object(self.index,'_record',side_effect=changed),self.assertRaises(Rejected):self.read([1,2,3,4])

    def test_direct_indexed_garbage_bad_author_and_missing_content_keep_canonical_numbers(self):
        self.commit(b'not JSON');bad=self.make();bad['authorship']['response']='11'*32;self.commit(canonical(bad))
        missing=self.commit(encode(self.make()));del self.origin.objects[missing['bundle_hash']]
        good=self.make();self.commit(encode(good))
        page=self.read([1,2,3,4,5]);self.assertEqual([r['post_number'] for r in page['posts']],['1','2','3','4','5'])
        self.assertEqual([r['state'] for r in page['posts']],['invalid','invalid','content-unavailable','finalized','unassigned'])
        self.assertEqual([r['proofs_verified'] for r in page['posts']],[False,False,False,True,False])
        self.assertFalse(page['whole_log_complete']);self.assertEqual(page['next_number'],'5')
    def test_bad_badge_is_silently_absent_and_cached_bytes_are_reverified(self):
        ref=self.commit(encode(self.make(address=True,evidence=blob(b'bad wallet evidence','wallet'))))
        page=self.read([1]);row=page['posts'][0];self.assertEqual(row['state'],'finalized');self.assertIsNone(row['display']['address'])
        before=self.origin.reads
        with patch.object(self.native,'call',return_value={'accepted':False}):
            row=self.read([1])['posts'][0];self.assertEqual(row['state'],'invalid');self.assertFalse(row['proofs_verified'])
        self.assertEqual(self.origin.reads,before)
    def test_hash_bound_thread_root_and_unverified_relationship_never_relabel_records(self):
        parent=self.commit(encode(self.make()));self.commit(encode(self.make(parent=parent)))
        wrong=copy.deepcopy(parent);wrong['number']='2';self.commit(encode(self.make(parent=wrong)))
        page=self.read([2,3]);self.assertEqual([r['state'] for r in page['posts']],['finalized','finalized'])
        self.assertEqual([r['relationship_state'] for r in page['posts']],['valid','unverified'])
        self.assertEqual(page['posts'][1]['thread'],wrong)
        self.origin.fail=True;self.content.clear()
        self.assertEqual(self.read([2])['posts'][0]['state'],'content-unavailable')
    def test_history_uses_independently_resolved_original_and_copy_cannot_claim_authorship(self):
        old=self.make();raw=encode(old);ref=self.commit(raw)
        at=self.index.records([1])[0]['indexed_at'];new=self.make();u=new['unsigned']
        u['evidence']['history']=history_prove(self.native,self.secret,u['core'],u['author'],[ref],lambda r:(raw,at))
        self.commit(encode(build(u,prove(self.native,self.secret,u))))
        copy_u=self.make()['unsigned'];copy_u['evidence']['history']=u['evidence']['history']
        self.commit(encode(build(copy_u,prove(self.native,self.secret,copy_u))))
        page=self.read([2,3]);self.assertEqual(page['posts'][0]['display']['history'],[ref])
        self.assertIsNone(page['posts'][1]['display']['history']);self.assertEqual(page['posts'][1]['state'],'finalized')
    def test_other_author_same_uuid_and_copying_bytes_cannot_squat_or_change_authorship(self):
        good=self.make();ident=good['unsigned']['core']['post']['id'];other=self.native.call('generate')['secret']
        self.commit(encode(self.make(secret=other,ident=ident)));ref=self.commit(encode(good))
        page=self.read([1,2]);a,b=page['posts'];self.assertNotEqual(a['logical_key'],b['logical_key'])
        self.f.rpc.tx(self.f.accounts[3],submission_data(ref['bundle_hash']),self.f.index)
        self.assertEqual(self.read([2])['posts'][0]['bundle_hash'],b['bundle_hash'])
        self.assertEqual(self.read([2])['next_number'],'3')
    def test_snapshot_change_during_content_fetch_rejects_whole_page(self):
        self.commit(encode(self.make()));actual=self.f.rpc.call;get=self.origin.get;changed=False
        def fetch(h,limit):
            nonlocal changed
            value=get(h,limit);changed=True;return value
        def rpc(method,*args):
            result=actual(method,*args)
            if changed and method=='eth_getBlockByNumber':result=dict(result,hash='0x'+'98'*32)
            return result
        with patch.object(self.origin,'get',side_effect=fetch),patch.object(self.f.rpc,'call',side_effect=rpc):
            with self.assertRaises(Rejected):self.read([1])
    def test_unavailable_author_verifier_and_requested_page_bounds_never_fabricate_validity(self):
        self.commit(encode(self.make()));self.reader.native=None
        row=self.read([1])['posts'][0]
        self.assertEqual(row['state'],'verification-unavailable');self.assertFalse(row['proofs_verified'])
        for numbers in [[],[1,1],list(range(1,10)),[True],[2**53]]:
            with self.subTest(numbers=numbers),self.assertRaises(Rejected):self.read(numbers)
    def test_one_origin_upload_readback_mirror_fallback_and_bounded_integrity_cache(self):
        v=self.make();receipt=self.content.upload(v);self.assertTrue(receipt['readback_checked']);self.assertEqual(self.origin.puts,1)
        h=receipt['bundle_hash'];raw=encode(v);self.assertEqual(self.content.fetch(h),raw)
        self.content.clear();mirror=MemoryPublicOrigin();mirror.objects[h]=raw;self.origin.objects[h]=b'wrong bytes'
        store=PublicContent(self.origin,mirrors=[mirror],cache_bytes=MAX_BYTES,cache_entries=1)
        self.assertEqual(store.fetch(h),raw)
        other=b'synthetic garbage';self.origin.objects[sha(other)]=other;store.fetch(sha(other))
        self.assertEqual(len(store.cache),1);self.assertLessEqual(store.bytes,MAX_BYTES)
        self.origin.fail=True;mirror.fail=True;store.clear()
        with self.assertRaises(Rejected):store.fetch(h)

if __name__=='__main__':unittest.main()
