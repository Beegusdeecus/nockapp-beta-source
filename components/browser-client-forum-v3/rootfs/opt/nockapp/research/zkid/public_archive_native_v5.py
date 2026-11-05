"""Public-only archive operations under the existing 128KiB native frame limit.

One <=64KiB object per message. The UI assembles/admits a bounded file before
individual imports. No caller filesystem path, outbox, identity, keyring, wallet,
service credential, cloud write, proof verdict or chain checkpoint is accepted.
"""
import base64
import copy

from base_protocol import sha
from permissionless_index import digest
from policy import canonical,require
from public_bundle_v5 import MAX_BYTES
from public_content_archive_v5 import ArchiveOrigin,MAX_OBJECTS,MAX_ARCHIVE_BYTES,scope
from public_content_cache_v5 import LazyContentCacheV5

OBJECT='nockapp-public-archive-object-v5'
STATUS='nockapp-public-archive-cache-status-v5'
CAPABILITIES='nockapp-public-archive-capabilities-v5'
OPERATIONS={'public-archive-capabilities','public-archive-export-object','public-archive-import-object','public-archive-cache-status'}


def dispatch(desktop,operation,body):
    require(operation in OPERATIONS and type(body) is dict,'public-archive-operation')
    expected=scope(desktop.scope)
    if operation=='public-archive-capabilities':
        require(not body,'public-archive-schema')
        return {'profile':CAPABILITIES,'scope':expected,'max_objects':MAX_OBJECTS,'max_object_bytes':MAX_BYTES,
            'max_archive_bytes':MAX_ARCHIVE_BYTES,'native_objects_per_message':1,
            'cache_import_configured':type(desktop.content.disk_cache) is LazyContentCacheV5,'chain_RPC_still_required':True}
    if operation=='public-archive-export-object':
        require(set(body)=={'number','bundle_hash','approve_public_export'} and body['approve_public_export'] is True
            and type(body['number']) is int and 0<body['number']<2**53,'public-archive-export-consent')
        h=digest(body['bundle_hash']);index=desktop.index;final=index.anchor()
        record=index._record(body['number'],final)
        require(record['bundle_hash']==h,'public-archive-record-changed')
        data=desktop.content.fetch(h)
        require(type(data) is bytes and 0<len(data)<=MAX_BYTES and sha(data)==h,'public-archive-integrity')
        index.finish(final)
        return {'profile':OBJECT,'scope':expected,'post_number':str(body['number']),'bundle_hash':h,
            'bundle_base64':base64.b64encode(data).decode('ascii'),'canonical_indexed':True,'proofs_verified':False}
    cache=desktop.content.disk_cache
    require(type(cache) is LazyContentCacheV5,'public-archive-cache-unavailable')
    if operation=='public-archive-import-object':
        require(set(body)=={'archive','approve_public_import'} and body['approve_public_import'] is True
            and type(body['archive']) is dict and type(body['archive'].get('objects')) is list
            and len(body['archive']['objects'])==1,'public-archive-import-consent')
        return ArchiveOrigin(canonical(body['archive']),expected).restore_cache(cache)
    require(set(body)=={'bundle_hashes'} and type(body['bundle_hashes']) is list
        and 1<=len(body['bundle_hashes'])<=MAX_OBJECTS,'public-archive-status')
    hashes=body['bundle_hashes'];require(hashes==sorted(set(hashes)),'public-archive-status')
    for h in hashes:digest(h)
    present=[]
    for h in hashes:
        try:
            raw=cache.get(h)
            if type(raw) is bytes and 0<len(raw)<=MAX_BYTES and sha(raw)==h:present.append(h)
        except Exception:pass
    return {'profile':STATUS,'scope':copy.deepcopy(expected),'bundle_hashes':list(hashes),'present_hashes':present,
        'complete':present==hashes,'proofs_or_chain_verified':False,'cache_entries_evictable':True}
