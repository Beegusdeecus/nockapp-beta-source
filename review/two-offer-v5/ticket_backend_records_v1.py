"""Internal S3 capability filter for one role; not a substitute for AWS IAM.

The launcher supplies an authenticated SDK client with explicit bounded transport
and renewable credentials. No SDK session/credential discovery is performed here.
"""
import base64
import hashlib
import re
from policy import require,Rejected

MAX_SNAPSHOT=16*1024*1024

class MissingRecord(Rejected):
    response={'Error':{'Code':'NoSuchKey'}}
    def __init__(self):super().__init__('ticket-backend-record-missing')

class RoleRecords:
    def __init__(self,client,account,scopes):
        require(type(account) is str and re.fullmatch('[0-9]{12}',account),'ticket-backend-record-account')
        require(type(scopes) is dict and scopes,'ticket-backend-record-scope')
        self._client,self.account,self._scopes=client,account,dict(scopes)
        for (bucket,prefix),(kind,write) in self._scopes.items():
            require(type(bucket) is str and re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',bucket)
                and type(prefix) is str and type(write) is bool and kind in ('decisions','results','snapshot'),'ticket-backend-record-scope')
            pattern=(r'ticket-publication-ledger-v2/[0-9a-f]{64}/' if kind=='snapshot' else
                r'ticket-purchases-v1/[0-9a-f]{64}/'+kind+'/')
            require(re.fullmatch(pattern,prefix),'ticket-backend-record-scope')

    def _scope(self,args,key,write=False):
        require(type(args) is dict and args.get('ExpectedBucketOwner',self.account)==self.account,'ticket-backend-record-owner')
        bucket=args.get('Bucket');name=args.get(key)
        require(type(bucket) is str and type(name) is str,'ticket-backend-record-key')
        for (allowed,prefix),(kind,can_write) in self._scopes.items():
            if bucket!=allowed or not name.startswith(prefix):continue
            suffix=name[len(prefix):]
            valid=(re.fullmatch(r'[0-9]{16}\.sealed',suffix) and int(suffix[:16])<2**53) if kind=='snapshot' else re.fullmatch(r'[0-9a-f]{64}\.json',suffix)
            require(valid and (not write or can_write),'ticket-backend-record-key')
            return kind,MAX_SNAPSHOT if kind=='snapshot' else 2048 if kind=='decisions' else 32768
        raise Rejected('ticket-backend-record-scope')

    def list_objects_v2(self,**args):
        require(set(args)<= {'Bucket','Prefix','MaxKeys','ExpectedBucketOwner'} and args.get('MaxKeys')==1
            and type(args.get('MaxKeys')) is int,'ticket-backend-record-list')
        self._scope(args,'Prefix')
        value=self._client.list_objects_v2(**{**args,'ExpectedBucketOwner':self.account})
        require(type(value) is dict and type(value.get('Contents',[])) is list and len(value.get('Contents',[]))<=1
            and value.get('KeyCount')==len(value.get('Contents',[])) and value.get('IsTruncated') is False,'ticket-backend-record-list')
        for item in value.get('Contents',[]):
            require(type(item) is dict and item.get('Key')==args['Prefix'],'ticket-backend-record-list')
        return value

    def get_object(self,**args):
        require(set(args)<= {'Bucket','Key','ExpectedBucketOwner'},'ticket-backend-record-read')
        kind,maximum=self._scope(args,'Key')
        if kind!='snapshot':
            # Exact-key list distinguishes absence under prefix-limited IAM.
            # An authorization or transport failure is never an absent record.
            found=self.list_objects_v2(Bucket=args['Bucket'],Prefix=args['Key'],MaxKeys=1)
            if found['KeyCount']==0:raise MissingRecord()
        value=self._client.get_object(**{**args,'ExpectedBucketOwner':self.account})
        if not (type(value) is dict and type(value.get('ContentLength')) is int and 0<value['ContentLength']<=maximum):
            if type(value) is dict and value.get('Body') is not None:value['Body'].close()
            raise Rejected('ticket-backend-record-size')
        return value

    def put_object(self,**args):
        require(set(args)<= {'Bucket','Key','Body','ContentType','IfNoneMatch','ServerSideEncryption','ChecksumSHA256','ExpectedBucketOwner'},'ticket-backend-record-write')
        kind,maximum=self._scope(args,'Key',True);body=args.get('Body')
        require(type(body) is bytes and 0<len(body)<=maximum and (kind!='snapshot' or len(body)>28)
            and args.get('IfNoneMatch')=='*' and args.get('ServerSideEncryption')=='AES256'
            and args.get('ContentType')==('application/octet-stream' if kind=='snapshot' else 'application/json')
            and args.get('ChecksumSHA256')==base64.b64encode(hashlib.sha256(body).digest()).decode(),'ticket-backend-record-write')
        return self._client.put_object(**{**args,'ExpectedBucketOwner':self.account})
