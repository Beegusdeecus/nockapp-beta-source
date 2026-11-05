"""Narrow signed regional S3 transport for private ticket records/snapshots.

The caller MUST retain RoleRecords' exact role/key filter and deployed IAM.
This transport limits API/buckets/key shape; it does not grant permissions or
prove no-delete/lifecycle/rollback controls. No SDK session, ambient credentials,
redirect, retry, multipart/copy/delete/version-selection or payload logging.
"""
import base64
from http.client import HTTPConnection
import hashlib
import io
import re
import socket
import threading
import time
from urllib.parse import quote,urlencode
import xml.etree.ElementTree as ET

from aws_transport import _silence_sdk
from policy import require,Rejected
from setup_aws_sdk import activate
from ticket_aws_credentials_v1 import check_tls,tls_context
from ticket_credential_broker_v1 import CredentialSession
from workload_sessions import WorkloadCredentials

MAX_SNAPSHOT=16*1024*1024
XML='http://s3.amazonaws.com/doc/2006-03-01/'

class S3Failure(Rejected):
    def __init__(self,code):
        self.response={'Error':{'Code':code}};super().__init__('ticket-private-s3-rejected')

class PrivateS3Transport:
    def __init__(self,region,account_id,buckets,source,*,context=None,dial=None):
        require(type(region) is str and re.fullmatch('[a-z]{2}-[a-z]+-[1-9]',region)
            and type(account_id) is str and re.fullmatch('[0-9]{12}',account_id),'ticket-private-s3-endpoint')
        require(type(buckets) in (list,tuple) and 1<=len(buckets)<=2 and len(set(buckets))==len(buckets),'ticket-private-s3-buckets')
        for bucket in buckets:
            require(type(bucket) is str and re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',bucket),'ticket-private-s3-buckets')
        require(isinstance(source,WorkloadCredentials) and type(source._session) is CredentialSession
            and source._session.config['role_arn']=='arn:aws:iam::'+account_id+':role/nockapp-ticket-'+source._session.config['role'],
            'ticket-private-s3-source')
        self.region,self.account_id,self.buckets,self.source=region,account_id,tuple(buckets),source
        self.host='s3.'+region+'.amazonaws.com';self.context=context if context is not None else tls_context();check_tls(self.context)
        self._dial=dial or (lambda:socket.create_connection((self.host,443),timeout=5))
        activate()
        from botocore.auth import S3SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.credentials import Credentials
        _silence_sdk();self._auth,self._request,self._credentials=S3SigV4Auth,AWSRequest,Credentials

    def _key(self,args,name):
        require(args.get('Bucket') in self.buckets and args.get('ExpectedBucketOwner')==self.account_id,'ticket-private-s3-owner')
        key=args.get(name);require(type(key) is str,'ticket-private-s3-key')
        if re.fullmatch(r'ticket-purchases-v1/[0-9a-f]{64}/decisions/[0-9a-f]{64}\.json',key):return key,2048,'application/json'
        if re.fullmatch(r'ticket-purchases-v1/[0-9a-f]{64}/results/[0-9a-f]{64}\.json',key):return key,32768,'application/json'
        match=re.fullmatch(r'ticket-publication-ledger-v2/[0-9a-f]{64}/([0-9]{16})\.sealed',key)
        require(match is not None and int(match[1])<2**53,'ticket-private-s3-key')
        return key,MAX_SNAPSHOT,'application/octet-stream'

    @staticmethod
    def _version(headers):
        value=headers.get('x-amz-version-id')
        require(type(value) is str and re.fullmatch(r'[A-Za-z0-9+/=_.-]{1,256}',value) and value!='null','ticket-private-s3-versioning')
        return value

    def _call(self,bucket,method,key,*,body=b'',headers=None,query=None,limit):
        check_tls(self.context)
        raw=secure=connection=timer=None
        path='/'+quote(bucket,safe='')+'/'+quote(key,safe='/')
        if query:path+='?'+urlencode(sorted(query.items()),quote_via=quote)
        fields={'x-amz-expected-bucket-owner':self.account_id,**dict(headers or {})}
        credentials=self.source.get();require(credentials['expires_at']>int(time.time())+5,'aws-credentials-expired')
        signing=self._credentials(credentials['access_key_id'],credentials['secret_access_key'],credentials['session_token'])
        request=self._request(method=method,url='https://'+self.host+path,data=body,headers=fields)
        self._auth(signing,'s3',self.region).add_auth(request)
        fields={**dict(request.headers.items()),'Accept-Encoding':'identity','Connection':'close'}
        try:
            raw=self._dial();raw.settimeout(5)
            def close():
                try:(secure or raw).shutdown(socket.SHUT_RDWR)
                except OSError:pass
            timer=threading.Timer(15,close);timer.daemon=True;timer.start()
            secure=self.context.wrap_socket(raw,server_hostname=self.host)
            connection=HTTPConnection(self.host,timeout=5);connection.sock=secure;connection.set_debuglevel(0)
            connection.request(method,path,body=body,headers=fields);response=connection.getresponse();pairs=response.getheaders()
            require(sum(len(k)+len(v)+4 for k,v in pairs)<=16384
                and len({k.lower() for k,_ in pairs})==len(pairs),'ticket-private-s3-headers')
            if response.status!=200:limit=min(limit,65536)
            result={k.lower():v for k,v in pairs};length=result.get('content-length');transfer=result.get('transfer-encoding','').lower()
            require(not(length is not None and transfer) and transfer in ('','chunked')
                and result.get('content-encoding','identity').lower()=='identity'
                and (length is None and transfer=='chunked' or type(length) is str and re.fullmatch('[0-9]{1,9}',length) and int(length)<=limit),
                'ticket-private-s3-size')
            data=response.read(limit+1)
            require(len(data)<=limit and (length is None or len(data)==int(length)),'ticket-private-s3-size')
            if response.status!=200:
                code={403:'AccessDenied',409:'ConditionalRequestConflict',412:'PreconditionFailed'}.get(response.status,'S3Unavailable')
                # Missing buckets/list errors are NEVER unused record slots.
                if response.status==404 and method=='GET' and key:
                    try:
                        xml=data.decode('utf-8');require('<!' not in xml,'ticket-private-s3-response')
                        error=ET.fromstring(xml)
                        tags=[v for v in error if v.tag in ('Code','{'+XML+'}Code')]
                        if error.tag in ('Error','{'+XML+'}Error') and len(tags)==1 and len(tags[0])==0 and tags[0].text=='NoSuchKey':code='NoSuchKey'
                    except (UnicodeDecodeError,ET.ParseError):pass
                raise S3Failure(code)
            return result,data
        except Rejected:raise
        except Exception:raise Rejected('ticket-private-s3-unavailable') from None
        finally:
            if timer:timer.cancel()
            if connection:connection.close()
            elif secure:secure.close()
            elif raw:raw.close()

    def get_object(self,**args):
        require(set(args)=={'Bucket','Key','ExpectedBucketOwner'},'ticket-private-s3-read')
        key,maximum,kind=self._key(args,'Key')
        headers,data=self._call(args['Bucket'],'GET',key,headers={'x-amz-checksum-mode':'ENABLED'},limit=maximum)
        require(0<len(data)<=maximum and headers.get('content-type','').split(';')[0].lower()==kind
            and headers.get('x-amz-checksum-sha256')==base64.b64encode(hashlib.sha256(data).digest()).decode(),'ticket-private-s3-integrity')
        version=self._version(headers)
        return {'Body':io.BytesIO(data),'ContentLength':len(data),'VersionId':version}

    def put_object(self,**args):
        require(set(args)=={'Bucket','Key','Body','ContentType','IfNoneMatch','ServerSideEncryption','ChecksumSHA256','ExpectedBucketOwner'},'ticket-private-s3-write')
        key,maximum,kind=self._key(args,'Key');body=args['Body']
        require(type(body) is bytes and 0<len(body)<=maximum and (kind!='application/octet-stream' or len(body)>28)
            and args['ContentType']==kind and args['IfNoneMatch']=='*' and args['ServerSideEncryption']=='AES256'
            and args['ChecksumSHA256']==base64.b64encode(hashlib.sha256(body).digest()).decode(),'ticket-private-s3-write')
        headers,data=self._call(args['Bucket'],'PUT',key,body=body,limit=65536,headers={'Content-Type':kind,'If-None-Match':'*',
            'x-amz-server-side-encryption':'AES256','x-amz-checksum-sha256':args['ChecksumSHA256']})
        require(not data and headers.get('x-amz-checksum-sha256')==args['ChecksumSHA256']
            and headers.get('x-amz-server-side-encryption')=='AES256','ticket-private-s3-write-ack')
        return {'VersionId':self._version(headers)}

    def list_objects_v2(self,**args):
        require(set(args)=={'Bucket','Prefix','MaxKeys','ExpectedBucketOwner'} and args['MaxKeys']==1 and type(args['MaxKeys']) is int,'ticket-private-s3-list')
        key,maximum,_=self._key(args,'Prefix')
        headers,data=self._call(args['Bucket'],'GET','',query={'list-type':'2','max-keys':'1','prefix':key},limit=65536)
        try:xml=data.decode('utf-8')
        except UnicodeDecodeError:raise Rejected('ticket-private-s3-list') from None
        require(headers.get('content-type','').split(';')[0].lower() in ('application/xml','text/xml') and '<!' not in xml,'ticket-private-s3-list')
        try:root=ET.fromstring(xml)
        except ET.ParseError:raise Rejected('ticket-private-s3-list') from None
        require(root.tag=='{'+XML+'}ListBucketResult' and not root.attrib,'ticket-private-s3-list')
        allowed={'Name','Prefix','KeyCount','MaxKeys','IsTruncated','Contents'};fields={};rows=[]
        for child in root:
            require(child.tag.startswith('{'+XML+'}') and not child.attrib,'ticket-private-s3-list');name=child.tag.split('}',1)[1]
            require(name in allowed,'ticket-private-s3-list')
            if name=='Contents':rows.append(child)
            else:
                require(name not in fields and len(child)==0,'ticket-private-s3-list');fields[name]=child.text or ''
        require(set(fields)==allowed-{'Contents'} and fields['Name']==args['Bucket'] and fields['Prefix']==key
            and fields['MaxKeys']=='1' and fields['IsTruncated']=='false' and fields['KeyCount'] in ('0','1')
            and len(rows)==int(fields['KeyCount']),'ticket-private-s3-list')
        result=[]
        for row in rows:
            values={}
            for child in row:
                require(child.tag.startswith('{'+XML+'}') and not child.attrib,'ticket-private-s3-list');name=child.tag.split('}',1)[1]
                require(name in {'Key','LastModified','ETag','Size','StorageClass','ChecksumAlgorithm','ChecksumType'}
                    and (name not in values or name=='ChecksumAlgorithm') and len(child)==0,'ticket-private-s3-list');values[name]=child.text or ''
            require({'Key','Size'}<=set(values) and values['Key']==key and re.fullmatch('[1-9][0-9]{0,8}',values['Size'])
                and int(values['Size'])<=maximum,'ticket-private-s3-list')
            result.append({'Key':key,'Size':int(values['Size'])})
        return {'Contents':result,'KeyCount':len(result),'IsTruncated':False}
