"""Bounded persistent PUBLIC protocol5 CAS bytes; no stored validity verdict.

Correctly hashed indexed garbage may be cached. Schema, chain, context,
authorship and independent optional badges are checked by the reader each time
it has no process-local verified result. This never stores private holder data.
"""
import hashlib
from bundle_disk_cache import DiskPublicCache,LazyCheckpointStore
from policy import require
from public_bundle_v5 import MAX_BYTES

class DiskContentCacheV5(DiskPublicCache):
    object_limit=MAX_BYTES
    @staticmethod
    def _validate_bytes(digest,data):
        require(type(data) is bytes and 0<len(data)<=MAX_BYTES
            and '0x'+hashlib.sha256(data).hexdigest()==digest,'v5-disk-content-integrity')
        return data

class LazyContentCacheV5(LazyCheckpointStore):
    """Missing cache creates no files until an integrity-checked public put."""
    def __init__(self,directory,*,max_bytes=8*1024*1024,max_entries=256):
        require(type(max_bytes) is int and 0<max_bytes<=32*1024*1024
            and type(max_entries) is int and 0<max_entries<=1024,'v5-disk-content-limit')
        super().__init__(directory);self.max_bytes=max_bytes;self.max_entries=max_entries
    def _make_cache(self):
        return DiskContentCacheV5(self.root,max_bytes=self.max_bytes,max_entries=self.max_entries)
    def get(self,digest):
        DiskPublicCache._digest(digest);cache=self._open(False)
        if cache is None:return None
        value=cache.get(digest);self.fault=cache.fault;return value
    def put(self,digest,data):
        DiskPublicCache._digest(digest);DiskContentCacheV5._validate_bytes(digest,data)
        cache=self._open(True)
        if cache is None:return False
        try:return cache.put(digest,data)
        finally:self.fault=cache.fault
