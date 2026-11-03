"""Replicated PUBLIC bundle storage, integrity-only cache and repair policy.

An acknowledgment/readback is an operational assurance at that time, never a
cryptographic guarantee of permanent availability. No private issuer data API,
delete API, onchain acceptance or proof-verification claim is provided here.
"""
from collections import OrderedDict
import copy
import re
import time

from base_protocol import sha
from policy import hex_string,require
from public_bundle import MAX_BYTES,encode,decode

RETENTION_SECONDS=90*86400
MAX_CACHE_BYTES=32*1024*1024


class PublicBundleCache:
    def __init__(self,max_bytes=MAX_CACHE_BYTES,max_entries=1024):
        require(type(max_bytes) is int and 0<max_bytes<=MAX_CACHE_BYTES and type(max_entries) is int
            and 0<max_entries<=4096,'public-cache-limit')
        self.max_bytes,self.max_entries=max_bytes,max_entries;self.bytes=0;self._items=OrderedDict()

    def get(self,digest):
        value=self._items.get(digest)
        if value is not None:self._items.move_to_end(digest)
        return value

    def put(self,digest,data):
        decode(data,digest)
        if len(data)>self.max_bytes:return False
        if digest in self._items:self.bytes-=len(self._items.pop(digest))
        while self._items and (self.bytes+len(data)>self.max_bytes or len(self._items)>=self.max_entries):
            _,removed=self._items.popitem(last=False);self.bytes-=len(removed)
        self._items[digest]=data;self.bytes+=len(data);return True

    def clear(self):
        count=len(self._items);self._items.clear();self.bytes=0;return count


class ReplicatedPublicStore:
    """Installer-owned replica objects; locations never establish bundle truth.

Replica adapters must bound IO and supply immutable CAS put/get. Real failure
domains/retention must be independently provisioned and audited at deployment.
"""
    def __init__(self,replicas,*,cache=None,clock=None,retention_seconds=RETENTION_SECONDS):
        require(type(replicas) is list and 2<=len(replicas)<=4,'public-replica-count')
        require(type(retention_seconds) is int and RETENTION_SECONDS<=retention_seconds<=365*86400,'public-retention')
        for replica in replicas:
            require(type(replica.name) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{2,63}',replica.name)
                and type(replica.failure_domain) is str and 3<=len(replica.failure_domain)<=128,'public-replica-identity')
        require(len({r.name for r in replicas})==len(replicas)
            and len({r.failure_domain for r in replicas})==len(replicas),'public-replica-independence')
        self.replicas=list(replicas);self.cache=cache if cache is not None else PublicBundleCache()
        self.clock=clock or (lambda:int(time.time()));self.retention_seconds=retention_seconds

    def _ack(self,replica,ack,digest,data,started):
        require(type(ack) is dict and set(ack)=={'replica','failure_domain','digest','bytes','stored_at','retain_until','version'}
            and ack['replica']==replica.name and ack['failure_domain']==replica.failure_domain and ack['digest']==digest
            and type(ack['bytes']) is int and ack['bytes']==len(data) and type(ack['stored_at']) is int
            and started<=ack['stored_at']<=self.clock()+5 and type(ack['retain_until']) is int
            and ack['retain_until']>=started+self.retention_seconds and type(ack['version']) is str
            and 0<len(ack['version'])<=256,'public-replica-ack')
        retrieved=replica.get(digest,MAX_BYTES)
        require(type(retrieved) is bytes and retrieved==data,'public-replica-readback')
        decode(retrieved,digest);return copy.deepcopy(ack)

    def upload(self,bundle):
        data=encode(bundle);digest=sha(data);started=self.clock();acks=[];failed=[]
        for replica in self.replicas:
            try:
                ack=replica.put(digest,data,retain_until=started+self.retention_seconds,repair=False)
                acks.append(self._ack(replica,ack,digest,data,started))
            except Exception:failed.append(replica.name)
        require(len(acks)>=2,'public-replication-unavailable')
        self.cache.put(digest,data)
        return {'digest':digest,'bytes':len(data),'acknowledgments':acks,'unavailable_replicas':failed,
            'retention_seconds':self.retention_seconds,'permanent_availability_proven':False}

    def fetch(self,digest,*,use_cache=True):
        require(type(digest) is str and digest.startswith('0x'),'public-content-digest');hex_string(digest[2:],64)
        if use_cache:
            data=self.cache.get(digest)
            if data is not None:
                decode(data,digest);return {'state':'available','data':data,'source':'cache','failed_replicas':[]}
        failed=[]
        for replica in self.replicas:
            try:
                data=replica.get(digest,MAX_BYTES);decode(data,digest)
                self.cache.put(digest,data)
                return {'state':'available','data':data,'source':replica.name,'failed_replicas':failed}
            except Exception:failed.append(replica.name)
        return {'state':'content-unavailable','data':None,'source':None,'failed_replicas':failed}

    def repair(self,digest):
        available=self.fetch(digest)
        require(available['state']=='available','public-repair-source-unavailable')
        data=available['data'];started=self.clock();repaired=[];failed=[]
        for replica in self.replicas:
            try:
                ack=replica.put(digest,data,retain_until=started+self.retention_seconds,repair=True)
                self._ack(replica,ack,digest,data,started);repaired.append(replica.name)
            except Exception:failed.append(replica.name)
        return {'digest':digest,'healthy_replicas':repaired,'unavailable_replicas':failed,
            'replication_satisfied':len(repaired)>=2,'permanent_availability_proven':False}
