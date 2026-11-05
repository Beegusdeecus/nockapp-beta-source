"""Bounded public-content archives, never proof verdicts or private state.

The caller exports explicitly selected canonical public records only. Imports
admit exact hashes into the separate public byte cache, never chain checkpoints,
verification results, drafts or wallets. Readers must still verify public chain
inclusion/context/authorship/badges. Keeping the archive file is necessary:
imported cache entries remain bounded and evictable.
"""
import base64
import copy
import re

from base_protocol import sha
from permissionless_index import digest
from policy import canonical,require,strict_json
from public_bundle_v5 import MAX_BYTES
from public_content_cache_v5 import LazyContentCacheV5

PROFILE='nockapp-public-content-archive-v5'
MAX_OBJECTS=4
MAX_ARCHIVE_BYTES=384*1024


def scope(value):
    require(type(value) is dict and set(value)=={'protocol','chain_id','application','contract'}
        and type(value['protocol']) is int and value['protocol']==5
        and type(value['chain_id']) is int and value['chain_id']==84532,'public-archive-scope')
    digest(value['application'])
    require(type(value['contract']) is str and re.fullmatch(r'0x[0-9a-f]{40}',value['contract'])
        and value['contract']!='0x'+'00'*20,'public-archive-scope')
    return copy.deepcopy(value)


def encode(expected_scope,objects):
    expected_scope=scope(expected_scope)
    require(type(objects) is dict and 1<=len(objects)<=MAX_OBJECTS,'public-archive-objects')
    rows=[]
    for h,raw in sorted(objects.items()):
        digest(h);require(type(raw) is bytes and 0<len(raw)<=MAX_BYTES and sha(raw)==h,'public-archive-integrity')
        rows.append({'bundle_hash':h,'bundle_base64':base64.b64encode(raw).decode('ascii')})
    data=canonical({'profile':PROFILE,'scope':expected_scope,'objects':rows})
    require(len(data)<=MAX_ARCHIVE_BYTES,'public-archive-size');return data


class ArchiveOrigin:
    """Read-only bounded public mirror. No network, paths, writes or verdict API."""
    def __init__(self,raw,expected_scope):
        expected_scope=scope(expected_scope)
        require(type(raw) is bytes and 0<len(raw)<=MAX_ARCHIVE_BYTES,'public-archive-size')
        value=strict_json(raw,max_bytes=MAX_ARCHIVE_BYTES)
        require(type(value) is dict and set(value)=={'profile','scope','objects'} and value['profile']==PROFILE
            and scope(value['scope'])==expected_scope and canonical(value)==raw,'public-archive-schema')
        rows=value['objects'];require(type(rows) is list and 1<=len(rows)<=MAX_OBJECTS,'public-archive-objects')
        objects={};previous=''
        for row in rows:
            require(type(row) is dict and set(row)=={'bundle_hash','bundle_base64'},'public-archive-object')
            h=digest(row['bundle_hash']);require(h>previous,'public-archive-order');previous=h
            encoded=row['bundle_base64']
            require(type(encoded) is str and 0<len(encoded)<=4*((MAX_BYTES+2)//3),'public-archive-object-size')
            try:data=base64.b64decode(encoded,validate=True)
            except Exception:require(False,'public-archive-encoding')
            require(0<len(data)<=MAX_BYTES and base64.b64encode(data).decode('ascii')==encoded and sha(data)==h,
                'public-archive-integrity');objects[h]=data
        self.scope=expected_scope;self._objects=objects;self.sha256=sha(raw)

    def get(self,h,limit):
        digest(h);require(type(limit) is int and 0<limit<=MAX_BYTES,'public-archive-read-limit')
        require(h in self._objects and len(self._objects[h])<=limit,'public-archive-unavailable')
        return self._objects[h]

    def restore_cache(self,cache):
        require(type(cache) is LazyContentCacheV5,'public-archive-cache')
        # Constructor admits the ENTIRE archive before this first write. Cache
        # failures/evictions may retain only a subset; report final readback,
        # never claim an atomic restore or delete/repair unrelated cache data.
        for h,data in self._objects.items():
            try:cache.put(h,data)
            except Exception:pass
        present=[]
        for h,data in self._objects.items():
            try:
                if cache.get(h)==data:present.append(h)
            except Exception:pass
        return {'profile':PROFILE,'scope':copy.deepcopy(self.scope),'archive_sha256':self.sha256,
            'objects':len(self._objects),'restored':len(present),'complete':len(present)==len(self._objects),
            'present_hashes':present,'proofs_or_chain_verified':False,'cache_entries_evictable':True}
