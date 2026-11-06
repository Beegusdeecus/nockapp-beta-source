"""Synthetic replica/failure-domain fixtures. No real independent storage claim."""
import copy
import unittest
import uuid

from base_protocol import sha
from policy import Rejected
from public_bundle import build,encode,decode,MAX_BYTES
from public_storage import PublicBundleCache,ReplicatedPublicStore,RETENTION_SECONDS
from test_domain_posts import post


class ReplicaFixture:
    def __init__(self,name,domain,clock):
        self.name,self.failure_domain,self.clock=name,domain,clock
        self.rows={};self.available=True;self.corrupt=False;self.short_retention=False;self.puts=0
    def put(self,digest,data,*,retain_until,repair):
        self.puts+=1
        if not self.available:raise OSError('synthetic storage unavailable')
        if sha(data)!=digest:raise ValueError('synthetic digest mismatch')
        if digest in self.rows and self.rows[digest]!=data and not repair:raise ValueError('synthetic immutable conflict')
        self.rows[digest]=data
        return {'replica':self.name,'failure_domain':self.failure_domain,'digest':digest,'bytes':len(data),
            'stored_at':self.clock(),'retain_until':self.clock()+1 if self.short_retention else retain_until,'version':str(self.puts)}
    def get(self,digest,limit):
        if not self.available or digest not in self.rows:raise OSError('synthetic missing object')
        data=b'corrupt fixture' if self.corrupt else self.rows[digest]
        if len(data)>limit:raise ValueError('synthetic too large')
        return data


def ordinary(contract='0x'+'cd'*20):
    p=dict(post(),claims=[],id=str(uuid.uuid4()))
    context={'application':'0x'+'ab'*32,'chain_id':31337,'contract':contract,'submission_id':uuid.uuid4().hex+uuid.uuid4().hex}
    return build(p,{'credential_kind':0,'facts':[],'threshold':None},context)


class PublicStorageTests(unittest.TestCase):
    def setUp(self):
        self.clock=lambda:1793011200
        self.a=ReplicaFixture('replica-one','fixture-region-one',self.clock)
        self.b=ReplicaFixture('replica-two','fixture-region-two',self.clock)
        self.store=ReplicatedPublicStore([self.a,self.b],clock=self.clock)
        self.bundle=ordinary();self.data=encode(self.bundle);self.digest=sha(self.data)

    def test_two_acks_and_readbacks_precede_satisfied_replication(self):
        result=self.store.upload(self.bundle)
        self.assertEqual(len(result['acknowledgments']),2)
        self.assertFalse(result['permanent_availability_proven'])
        self.assertEqual(result['retention_seconds'],RETENTION_SECONDS)
        self.assertEqual(self.a.rows[self.digest],self.b.rows[self.digest])

    def test_one_failed_or_short_retention_replica_prevents_acceptance(self):
        for mode in ('down','short-retention','corrupt-readback'):
            self.b.available=mode!='down';self.b.short_retention=mode=='short-retention';self.b.corrupt=mode=='corrupt-readback'
            with self.assertRaisesRegex(Rejected,'public-replication-unavailable'):self.store.upload(self.bundle)

    def test_corrupted_first_replica_falls_back_and_repairs_from_independent_copy(self):
        self.store.upload(self.bundle);self.store.cache.clear();self.a.rows[self.digest]=b'wrong bytes'
        found=self.store.fetch(self.digest)
        self.assertEqual(found['source'],self.b.name);self.assertEqual(found['data'],self.data)
        self.assertTrue(self.store.repair(self.digest)['replication_satisfied'])
        self.assertEqual(self.a.rows[self.digest],self.data)

    def test_all_replicas_lost_means_unavailable_and_cannot_reconstruct_from_hash(self):
        self.store.upload(self.bundle);self.a.rows.clear();self.b.rows.clear();self.store.cache.clear()
        result=self.store.fetch(self.digest)
        self.assertEqual(result['state'],'content-unavailable');self.assertIsNone(result['data'])
        with self.assertRaisesRegex(Rejected,'public-repair-source-unavailable'):self.store.repair(self.digest)
        # An independently retained backup restores the original exact bytes.
        self.b.rows[self.digest]=self.data
        self.assertEqual(self.store.fetch(self.digest)['data'],self.data)

    def test_cache_is_bounded_and_clearing_does_not_delete_shared_objects(self):
        cache=PublicBundleCache(max_bytes=2048,max_entries=1)
        store=ReplicatedPublicStore([self.a,self.b],cache=cache,clock=self.clock)
        store.upload(self.bundle);other=ordinary();other_hash=sha(encode(other));store.upload(other)
        self.assertIsNone(cache.get(self.digest));self.assertIsNotNone(cache.get(other_hash))
        self.assertLessEqual(cache.bytes,2048);cache.clear()
        self.assertEqual(len(self.a.rows),2);self.assertEqual(len(self.b.rows),2)
        self.assertEqual(store.fetch(self.digest)['data'],self.data)

    def test_duplicate_failure_domains_and_corrupted_bundles_fail_closed(self):
        self.b.failure_domain=self.a.failure_domain
        with self.assertRaisesRegex(Rejected,'public-replica-independence'):ReplicatedPublicStore([self.a,self.b])
        for changed in [self.data+b' ',b'{}',b'x'*(MAX_BYTES+1)]:
            with self.assertRaises((Rejected,ValueError)):decode(changed,self.digest)
        bad=copy.deepcopy(self.bundle);bad['private_issuer']={'secret':'synthetic'}
        with self.assertRaises(Rejected):encode(bad)
        bad=copy.deepcopy(self.bundle);bad['encoding']='gzip'
        with self.assertRaises(Rejected):encode(bad)


if __name__=='__main__':unittest.main()
