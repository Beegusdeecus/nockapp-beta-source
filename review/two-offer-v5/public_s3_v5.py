"""One bounded public v5 S3 origin, distinct from legacy v3 replica semantics.

Public reads use no AWS SDK or credentials and check only exact byte integrity,
including indexed junk. Proof validity belongs to independent readers. Writes
require supplied temporary credentials and an explicit pre-I/O resource budget.
No policy provisioning, delete, repair, metadata renewal or automatic retry.
"""
import base64
import hashlib
import re

from base_protocol import sha
from policy import require,Rejected
from public_bundle_v5 import MAX_BYTES,decode
from public_s3 import S3PublicReplica
from public_storage_budget import DynamoStorageBudget,limits
from policy import digest as policy_digest


class OriginStorageBudget(DynamoStorageBudget):
    """Separate explicitly provisioned one-origin/64KiB resource-budget scope."""
    max_object_bytes=MAX_BYTES


def budget_scope(region,bucket,account_id,policy,retention_seconds):
    from public_s3_endpoints import s3_host
    host=s3_host(region,bucket);limits(policy)
    require(type(account_id) is str and re.fullmatch(r'[0-9]{12}',account_id),'public-origin-account')
    require(type(retention_seconds) is int and 90*86400<=retention_seconds<=365*86400,'public-origin-retention')
    return policy_digest({'profile':'nockapp-public-origin-budget-v5','host':host,'account_id':account_id,
        'max_object_bytes':MAX_BYTES,'namespace':'/v5/sha256/','limits':policy,'retention_seconds':retention_seconds})


class S3PublicOrigin(S3PublicReplica):
    max_bytes=MAX_BYTES

    def __init__(self,region,bucket,account_id,context,*,credentials=None,budget=None,
            retention_seconds=90*86400,dial=None,clock=None):
        require(type(account_id) is str and re.fullmatch(r'[0-9]{12}',account_id),'public-origin-account')
        require(type(retention_seconds) is int and 90*86400<=retention_seconds<=365*86400,'public-origin-retention')
        if credentials is not None:
            require(isinstance(budget,OriginStorageBudget) and budget.retention_seconds==retention_seconds,
                'public-origin-budget-required')
            require(budget.context==budget_scope(region,bucket,account_id,budget.limits,retention_seconds),'public-origin-budget-scope')
        self.account_id,self.retention_seconds=account_id,retention_seconds
        super().__init__('public-origin',region,bucket,context,credentials=credentials,budget=budget,dial=dial,clock=clock)

    @staticmethod
    def _path(digest):
        require(type(digest) is str and re.fullmatch(r'0x[0-9a-f]{64}',digest),'public-content-digest')
        return '/v5/sha256/'+digest[2:]+'.json'

    def _request(self,method,digest,*,data=b'',headers=None,limit=MAX_BYTES):
        fields=dict(headers or {});fields['x-amz-expected-bucket-owner']=self.account_id
        return super()._request(method,digest,data=data,headers=fields,limit=limit)

    def get(self,digest,max_bytes):
        status,_,data=self._request('GET',digest,limit=max_bytes)
        require(status==200,'public-origin-content-unavailable')
        require(0<len(data)<=max_bytes and sha(data)==digest,'public-origin-content-integrity')
        return data # Intentionally no JSON/proof decoding here.

    def probe(self,digest,max_bytes):
        """An origin observation, not a cached copy or proof-validity verdict."""
        try:status,_,data=self._request('GET',digest,limit=max_bytes)
        except Exception:return {'state':'unavailable'}
        if status==404:return {'state':'missing'}
        if status==403:return {'state':'inaccessible'}
        if status!=200:return {'state':'unavailable'} # In particular,403 is not absence.
        return {'state':'present'if 0<len(data)<=max_bytes and sha(data)==digest else 'corrupt'}

    def _acknowledgement(self,digest,data,headers):
        version=self._version(headers)
        until=headers.get('x-amz-meta-retain-until','')
        require(type(until) is str and re.fullmatch(r'[0-9]{1,12}',until)
            and self.clock()<int(until),'public-origin-retention')
        return {'bundle_hash':digest,'bytes':len(data),'version':version,
            'retain_until':int(until),'readback_checked':True,'permanent_availability_proven':False}

    def put(self,digest,data):
        return self._put(digest,data,repair=False)

    def restore(self,digest,data):
        """Caller must already verify finalized inclusion of these exact bytes."""
        return self._put(digest,data,repair=True)

    def _put(self,digest,data,*,repair):
        require(self._source is not None or self._credentials is not None,'public-s3-read-only')
        decode(data,digest) # Canonical v5 shape; application checks native authorship.
        status,headers,current=self._request('GET',digest)
        condition={'If-None-Match':'*'}
        if status==200:
            if current==data:return self._acknowledgement(digest,data,headers)
            require(repair and sha(current)!=digest,'public-origin-content-conflict')
            self._version(headers) # Retain the corrupt prior version; no delete.
            etag=headers.get('etag')
            require(type(etag) is str and re.fullmatch(r'"[0-9a-f]{32}(?:-[1-9][0-9]{0,5})?"',etag),'public-origin-repair-etag')
            condition={'If-Match':etag}
        # Anonymous missing-key GET may return403 without ListBucket. A
        # conditional PUT cannot overwrite an inaccessible existing object.
        #403 does not establish absence. If-None-Match can still attempt one
        # initial delivery without overwriting an inaccessible existing object.
        require(status in (200,403,404),'public-origin-preflight')
        until=self.clock()+self.retention_seconds
        fields={'Content-Type':'application/json','Cache-Control':'public, max-age=31536000, immutable',
            **condition,'x-amz-meta-retain-until':str(until),
            'x-amz-checksum-sha256':base64.b64encode(hashlib.sha256(data).digest()).decode('ascii')}
        try:self._request('PUT',digest,data=data,headers=fields)
        except Rejected as error:
            if str(error) in ('public-s3-read-only','aws-credentials-expired','public-storage-budget-exhausted',
                'public-storage-budget-state','public-storage-budget-unavailable','registry-unavailable'):raise
        # Resolve successful, existing-object and lost-reply outcomes by ONE
        # exact anonymous readback. Never issue another PUT after uncertainty.
        status,headers,current=self._request('GET',digest)
        require(status==200 and current==data,'public-origin-write-unresolved')
        return self._acknowledgement(digest,data,headers)
