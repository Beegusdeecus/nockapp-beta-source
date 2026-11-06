"""Bounded public CAS bytes from one origin, with optional public mirrors.

Integrity alone permits caching, including indexed garbage. Schema/proof truth
belongs to the independent reader. Adapters must bound their network reads and
timeouts too. This module does not provision AWS versioning or backups.
"""
from collections import OrderedDict
from base_protocol import sha
from permissionless_index import digest
from policy import require
from public_bundle_v5 import MAX_BYTES,encode


class PublicContent:
    def __init__(self,origin,*,mirrors=(),cache_bytes=8*1024*1024,cache_entries=256,disk_cache=None):
        require(type(mirrors) in (list,tuple) and len(mirrors)<=3,'v5-content-mirrors')
        require(type(cache_bytes) is int and 0<cache_bytes<=32*1024*1024
            and type(cache_entries) is int and 0<cache_entries<=1024,'v5-cache-limit')
        self.origin=origin;self.sources=[origin,*mirrors];self.cache=OrderedDict()
        self.max_bytes=cache_bytes;self.max_entries=cache_entries;self.bytes=0
        require(disk_cache is None or all(callable(getattr(disk_cache,n,None)) for n in ('get','put','clear')),'v5-disk-content-cache')
        self.disk_cache=disk_cache

    def _check(self,h,raw):
        digest(h);require(type(raw) is bytes and 0<len(raw)<=MAX_BYTES and sha(raw)==h,'v5-content-integrity')
        return raw

    def _remember(self,h,raw,*,persist=True):
        self._check(h,raw)
        if persist and self.disk_cache is not None:
            try:self.disk_cache.put(h,raw)
            except Exception:pass # Optional cache never changes origin readback truth.
        if len(raw)>self.max_bytes:return
        if h in self.cache:self.bytes-=len(self.cache.pop(h))
        while self.cache and (self.bytes+len(raw)>self.max_bytes or len(self.cache)>=self.max_entries):
            _,removed=self.cache.popitem(last=False);self.bytes-=len(removed)
        self.cache[h]=raw;self.bytes+=len(raw)

    def fetch(self,h):
        digest(h)
        if h in self.cache:
            self.cache.move_to_end(h);return self._check(h,self.cache[h])
        if self.disk_cache is not None:
            try:
                raw=self.disk_cache.get(h)
                if raw is not None:
                    raw=self._check(h,raw);self._remember(h,raw,persist=False);return raw
            except Exception:pass
        for source in self.sources:
            try:
                raw=self._check(h,source.get(h,MAX_BYTES));self._remember(h,raw);return raw
            except Exception:pass
        require(False,'v5-content-unavailable')

    def upload(self,bundle):
        raw=encode(bundle);h=sha(raw)
        # No approval receipt or replica quorum. The caller independently checks
        # proofs before sponsorship; any payer can index other bytes directly.
        self.origin.put(h,raw)
        require(self._check(h,self.origin.get(h,MAX_BYTES))==raw,'v5-content-readback')
        self._remember(h,raw)
        return {'bundle_hash':h,'bytes':len(raw),'readback_checked':True,'permanent_availability_proven':False}

    def restore(self,bundle):
        """Only finalized-index admission may call this conditional repair path."""
        raw=encode(bundle);h=sha(raw)
        require(callable(getattr(self.origin,'restore',None)),'v5-origin-restore-unavailable')
        self.origin.restore(h,raw)
        require(self._check(h,self.origin.get(h,MAX_BYTES))==raw,'v5-content-readback')
        self._remember(h,raw)
        return {'bundle_hash':h,'bytes':len(raw),'readback_checked':True,'permanent_availability_proven':False}

    def clear(self):
        n=len(self.cache);self.cache.clear();self.bytes=0
        if self.disk_cache is not None:
            try:self.disk_cache.clear()
            except Exception:pass
        return n
