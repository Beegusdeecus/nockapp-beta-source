"""Bounded local positive verification results; never a remote verdict cache.

Caller pins exact verifier/worker/authority versions. Every use checks the exact
content hash and canonical record again; historical dependencies retain their
own canonical record fingerprints. Only this installation's verified results enter.
Optional disk entries must carry this installation's separate integrity MAC.
No remote verdict import, global database scan or expiry-based badge removal.
"""
from collections import OrderedDict
import copy
from policy import canonical,digest,hex_string,require


class VerifiedPublicCache:
    def __init__(self,version,*,max_bytes=8*1024*1024,max_entries=256,disk_cache=None):
        hex_string(version,64);require(any(bytes.fromhex(version)),'proof-cache-version')
        require(type(max_bytes) is int and 0<max_bytes<=32*1024*1024
            and type(max_entries) is int and 0<max_entries<=1024,'proof-cache-limit')
        self.version=version;self.max_bytes=max_bytes;self.max_entries=max_entries;self.bytes=0;self._items=OrderedDict()
        if disk_cache is not None:
            from public_verified_cache import LazyVerifiedResultCache
            require(isinstance(disk_cache,LazyVerifiedResultCache),'proof-cache-store')
        self.disk_cache=disk_cache

    def _key(self,scope,record):return digest({'verifier':self.version,'scope':scope,'record':record})

    def get(self,scope,record,check_dependency):
        key=self._key(scope,record);entry=self._items.get(key)
        if entry is None and self.disk_cache is not None:
            try:
                value=self.disk_cache.get('0x'+key)
                if value is not None:
                    self._remember(key,value);entry=self._items.get(key)
            except Exception:pass
        if entry is None:return None
        value,size=entry
        try:
            if not all(check_dependency(r) for r in value['dependencies']):return None
        except Exception:return None
        self._items.move_to_end(key);return copy.deepcopy(value['checked'])

    def put(self,scope,record,checked,dependencies):
        require(type(checked) is dict and checked.get('authorship_checked') is True
            and type(dependencies) is list and len(dependencies)<=32,'proof-cache-result')
        value=copy.deepcopy({'checked':checked,'dependencies':dependencies});size=len(canonical(value))
        if size>65536 or size>self.max_bytes:return False
        key=self._key(scope,record)
        self._remember(key,value)
        if self.disk_cache is not None:
            try:self.disk_cache.put('0x'+key,value)
            except Exception:pass
        return True

    def _remember(self,key,value):
        size=len(canonical(value))
        if size>65536 or size>self.max_bytes:return False
        if key in self._items:self.bytes-=self._items.pop(key)[1]
        while self._items and (self.bytes+size>self.max_bytes or len(self._items)>=self.max_entries):
            _,(_,old_size)=self._items.popitem(last=False);self.bytes-=old_size
        self._items[key]=(value,size);self.bytes+=size;return True

    def clear(self):
        if self.disk_cache is not None:
            try:self.disk_cache.clear()
            except Exception:pass
        count=len(self._items);self._items.clear();self.bytes=0;return count
