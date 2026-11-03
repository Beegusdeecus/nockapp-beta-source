"""Append-only encrypted snapshot authority, independent of the local database.

Revision slots are immutable S3 objects; If-None-Match:* elects one winner.
There is no mutable head to restore to an old database backup. Pinned private
namespace, enforced conditional writes and denial of deletion/lifecycle/version
rollback remain deployment requirements, not properties proved by this adapter.
"""
import base64
import hashlib
import re
import threading

from policy import require,Rejected

MAX_BYTES=16*1024*1024
MAX_REVISION=2**53-1


class ImmutableS3JournalAnchor:
    production_antirollback=False # Actual IAM/bucket/restore acceptance is pending.

    def __init__(self,client,bucket,namespace,*,account_id):
        require(type(bucket) is str and re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',bucket),'ticket-authority-bucket')
        require(type(namespace) is str and re.fullmatch(r'[0-9a-f]{64}',namespace),'ticket-authority-namespace')
        require(type(account_id) is str and re.fullmatch(r'[0-9]{12}',account_id),'ticket-authority-account')
        self.client,self.bucket=client,bucket
        self.account_id=account_id
        self.prefix='ticket-publication-ledger-v2/'+namespace+'/'
        self._hint=None;self._lock=threading.RLock()

    def _key(self,revision):
        require(type(revision) is int and 0<=revision<=MAX_REVISION,'ticket-authority-revision')
        return self.prefix+str(revision).zfill(16)+'.sealed'

    def _probe(self,revision):
        # Exact-key prefix + one result allows prefix-restricted ListBucket IAM.
        # HEAD's missing-key status depends on broader ListBucket permissions;
        # an authorization error must never be mistaken for an unused slot.
        key=self._key(revision)
        try:result=self.client.list_objects_v2(Bucket=self.bucket,Prefix=key,MaxKeys=1,ExpectedBucketOwner=self.account_id)
        except Exception:raise Rejected('ticket-authority-unavailable') from None
        require(type(result) is dict and type(result.get('Contents',[])) is list,'ticket-authority-list')
        items=result.get('Contents',[])
        require(len(items)<=1 and result.get('KeyCount')==len(items)
            and result.get('IsTruncated') is False,'ticket-authority-list')
        if not items:return None
        item=items[0]
        require(type(item) is dict and item.get('Key')==key and type(item.get('Size')) is int
            and 28<item['Size']<=MAX_BYTES,'ticket-authority-size')
        return item

    def _get(self,revision):
        try:response=self.client.get_object(Bucket=self.bucket,Key=self._key(revision),ExpectedBucketOwner=self.account_id)
        except Exception:raise Rejected('ticket-authority-unavailable') from None
        body=response.get('Body')
        try:
            require(type(response.get('ContentLength')) is int and 28<response['ContentLength']<=MAX_BYTES,'ticket-authority-size')
            raw=body.read(MAX_BYTES+1)
            require(type(raw) is bytes and len(raw)==response['ContentLength'],'ticket-authority-size')
            return raw
        except Rejected:raise
        except Exception:raise Rejected('ticket-authority-unavailable') from None
        finally:
            if body is not None:
                try:body.close()
                except Exception:pass

    def read(self):
        with self._lock:
            low=0 if self._hint is None else self._hint
            if self._probe(low) is None:
                require(self._hint is None,'ticket-authority-missing')
                return None,None
            # Cold start is logarithmic in revision count; warm reads normally
            # make one absence probe. There is no mutable/disk head hint.
            step=1;high=low+step
            while high<=MAX_REVISION and self._probe(high) is not None:
                low=high;step*=2;high=low+step
            high=min(high,MAX_REVISION+1)
            while low+1<high:
                middle=(low+high)//2
                if self._probe(middle) is None:high=middle
                else:low=middle
            data=self._get(low);self._hint=low
            return low,data

    def compare_exchange(self,expected,envelope):
        require(expected is None or type(expected) is int and 0<=expected<MAX_REVISION,'ticket-authority-revision')
        require(type(envelope) is bytes and 28<len(envelope)<=MAX_BYTES,'ticket-authority-size')
        with self._lock:
            actual,_=self.read()
            require(actual==expected,'ticket-authority-conflict')
            revision=0 if expected is None else expected+1
            try:
                self.client.put_object(Bucket=self.bucket,Key=self._key(revision),Body=envelope,
                    ContentType='application/octet-stream',IfNoneMatch='*',ServerSideEncryption='AES256',
                    ExpectedBucketOwner=self.account_id,
                    ChecksumSHA256=base64.b64encode(hashlib.sha256(envelope).digest()).decode('ascii'))
            except Exception:pass # Could be a successful write with a lost reply.
            require(self._get(revision)==envelope,'ticket-authority-conflict')
            self._hint=revision
            return revision
