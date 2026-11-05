"""Bounded public CAS transport to installer-pinned, versioned S3 buckets.

No AWS credential discovery, SDK sessions, arbitrary URLs, redirects or delete
API. Retention metadata is an operational promise, not S3 Object Lock. Bucket
versioning, lifecycle, anonymous reads and independent regions need deployment
checks; this adapter cannot establish their continued availability.
"""
import base64
import copy
import hashlib
import http.client
import re
import socket
import ssl
import threading
import time

from aws_transport import _silence_sdk
from policy import Rejected,require
from provisioning import validate_value
from public_bundle import MAX_BYTES,decode
from public_s3_endpoints import s3_host
from setup_aws_sdk import activate
from workload_sessions import WorkloadCredentials


class S3PublicReplica:
    max_bytes=MAX_BYTES
    def __init__(self,name,region,bucket,context,*,credentials=None,dial=None,clock=None,budget=None):
        require(type(name) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{2,63}',name),'public-replica-identity')
        try:host=s3_host(region,bucket)
        except ValueError as error:raise Rejected(str(error)) from None
        require(isinstance(context,ssl.SSLContext) and context.check_hostname
            and context.verify_mode==ssl.CERT_REQUIRED
            and context.minimum_version>=ssl.TLSVersion.TLSv1_2,'public-s3-tls')
        self.budget=budget
        self.name=name;self.failure_domain='aws-region:'+region
        self.region=region;self.host=host
        self._context=context;self.clock=clock or (lambda:int(time.time()))
        self._dial=dial or (lambda:socket.create_connection((self.host,443),timeout=10))
        self._source=credentials if isinstance(credentials,WorkloadCredentials) else None
        self._credentials=(None if credentials is None or self._source else
            copy.deepcopy(validate_value('managed-writer-credentials',credentials)))
        # Public readers do not load the SDK or acquire any credentials.
        if credentials is not None:
            activate()
            from botocore.auth import S3SigV4Auth
            from botocore.awsrequest import AWSRequest
            from botocore.credentials import Credentials
            _silence_sdk()
            self._Auth,self._Request,self._Credentials=S3SigV4Auth,AWSRequest,Credentials

    @staticmethod
    def _path(digest):
        require(type(digest) is str and re.fullmatch(r'0x[0-9a-f]{64}',digest),'public-content-digest')
        return '/v3/sha256/'+digest[2:]+'.json'

    def _request(self,method,digest,*,data=b'',headers=None,limit=MAX_BYTES):
        path=self._path(digest);raw=secure=connection=timer=None
        require(method in ('GET','PUT') and type(limit) is int and 0<limit<=self.max_bytes,'public-s3-request')
        require(type(data) is bytes and len(data)<=self.max_bytes,'public-s3-request-size')
        fields=dict(headers or {})
        if method=='PUT':
            require(self._source is not None or self._credentials is not None,'public-s3-read-only')
            creds=self._source.get() if self._source else self._credentials
            require(creds['expires_at']>int(time.time())+5,'aws-credentials-expired')
            signing=self._Credentials(creds['access_key_id'],creds['secret_access_key'],creds['session_token'])
            request=self._Request(method=method,url='https://'+self.host+path,data=data,headers=fields)
            self._Auth(signing,'s3',self.region).add_auth(request)
            fields=dict(request.headers.items())
        fields.update({'Accept-Encoding':'identity','Connection':'close'})
        if self.budget is not None:self.budget.reserve(method,len(data),limit)
        try:
            raw=self._dial();raw.settimeout(10)
            def expire():
                try:(secure or raw).shutdown(socket.SHUT_RDWR)
                except OSError:pass
            timer=threading.Timer(15,expire);timer.daemon=True;timer.start()
            secure=self._context.wrap_socket(raw,server_hostname=self.host)
            connection=http.client.HTTPConnection(self.host,timeout=10);connection.sock=secure
            connection.set_debuglevel(0)
            connection.request(method,path,body=data if method=='PUT' else None,headers=fields)
            response=connection.getresponse();pairs=response.getheaders()
            require(sum(len(k)+len(v)+4 for k,v in pairs)<=16384,'public-s3-headers')
            lowered=[k.lower() for k,_ in pairs]
            require(len(set(lowered))==len(lowered),'public-s3-ambiguous')
            result={k.lower():v for k,v in pairs}
            require(response.status in (200,403,404,409,412),'public-s3-status')
            require(result.get('content-encoding','identity').lower()=='identity','public-s3-encoding')
            if 'transfer-encoding' in result:
                # Real S3 uses chunked XML for missing/denied objects. Error
                # bodies carry no application evidence: close without reading
                # them. Keep successful objects length-bounded and reject
                # conflicting framing, compression and other transfer codings.
                require(result['transfer-encoding'].lower()=='chunked'
                    and 'content-length' not in result and response.status in (403,404,409,412),
                    'public-s3-encoding')
                return response.status,result,b''
            length=result.get('content-length','')
            require(re.fullmatch(r'[0-9]{1,8}',length) and int(length)<=limit,'public-s3-response-size')
            body=response.read(limit+1)
            require(len(body)==int(length),'public-s3-response-size')
            if response.status==200 and method=='GET':
                require(result.get('content-type','').split(';')[0].lower()=='application/json','public-s3-content-type')
            return response.status,result,body
        except Rejected:raise
        except Exception:raise Rejected('public-s3-unavailable') from None
        finally:
            if timer:timer.cancel()
            if connection:connection.close()
            elif secure:secure.close()
            elif raw:raw.close()

    @staticmethod
    def _version(headers):
        version=headers.get('x-amz-version-id','')
        require(type(version) is str and re.fullmatch(r'[A-Za-z0-9+/=_.-]{1,256}',version)
            and version!='null','public-s3-versioning-required')
        return version

    def get(self,digest,max_bytes):
        status,_,data=self._request('GET',digest,limit=max_bytes)
        require(status==200,'public-s3-content-unavailable');decode(data,digest)
        return data

    def _ack(self,digest,data,headers,retain_until):
        require(headers.get('x-amz-meta-retain-until','').isdigit()
            and len(headers['x-amz-meta-retain-until'])<=12
            and int(headers['x-amz-meta-retain-until'])>=retain_until,'public-s3-retention')
        return {'replica':self.name,'failure_domain':self.failure_domain,'digest':digest,'bytes':len(data),
            'stored_at':self.clock(),'retain_until':int(headers['x-amz-meta-retain-until']),
            'version':self._version(headers)}

    def put(self,digest,data,*,retain_until,repair):
        decode(data,digest)
        require(type(repair) is bool and type(retain_until) is int
            and self.clock()<retain_until<=self.clock()+365*86400,'public-s3-retention')
        if self.budget is not None:
            require(retain_until<=self.clock()+self.budget.retention_seconds,'public-storage-budget-retention')
        # At most two PUTs. Ambiguous replies are resolved by GET, never blind
        # repeated writes. Readback is anonymous, matching independent readers.
        condition={'If-None-Match':'*'}
        for attempt in range(2):
            fields={'Content-Type':'application/json','Cache-Control':'no-store',
                'x-amz-meta-retain-until':str(retain_until),
                'x-amz-checksum-sha256':base64.b64encode(hashlib.sha256(data).digest()).decode(),**condition}
            status=None
            try:status,_,_=self._request('PUT',digest,data=data,headers=fields)
            except Rejected as error:
                # Configuration/expiry failures are not ambiguous writes.
                if str(error) in ('public-s3-read-only','aws-credentials-expired','public-storage-budget-exhausted',
                    'public-storage-budget-state','public-storage-budget-unavailable','registry-unavailable'):raise
            found,headers,current=self._request('GET',digest)
            require(found==200,'public-s3-write-unresolved')
            self._version(headers)
            if current==data:
                try:return self._ack(digest,data,headers,retain_until)
                except Rejected:
                    require(status==412 and attempt==0,'public-s3-retention-unresolved')
            else:
                require(repair and status==412 and attempt==0,'public-s3-content-conflict')
            # ETag is a concurrency precondition, never the content commitment.
            etag=headers.get('etag','')
            require(re.fullmatch(r'"[A-Za-z0-9-]{1,128}"',etag),'public-s3-precondition')
            condition={'If-Match':etag}
        raise Rejected('public-s3-write-unresolved')
