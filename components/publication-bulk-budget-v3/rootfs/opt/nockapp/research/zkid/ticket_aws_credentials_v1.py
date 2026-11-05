"""Explicit IMDSv2 -> fixed STS roles, for a host credential broker only.

No ambient SDK credential/config chain, IMDSv1, redirects, retries, arbitrary
role API, IAM changes or payload diagnostics. Existing enclave identities stay
unchanged. Host broker/OS/IAM isolation remains a separate deployment requirement.
"""
import copy
from datetime import datetime
from http.client import HTTPConnection
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlencode,quote
import xml.etree.ElementTree as ET

from aws_transport import _silence_sdk
from policy import canonical,require,Rejected,strict_json
from provisioning import validate_value
from setup_aws_sdk import activate
from workload_sessions import WorkloadSession,WorkloadCredentials

PROFILE='nockapp-ticket-aws-broker-v1'
ROLES=('payment','publication','refund')
METADATA='169.254.169.254'
XML='https://sts.amazonaws.com/doc/2011-06-15/'
CA_BUNDLE='/etc/ssl/certs/ca-certificates.crt'

def tls_context():
    # Avoid environment-controlled CA or TLS key-log file discovery.
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=CA_BUNDLE);return context

def check_tls(context):
    require(isinstance(context,ssl.SSLContext) and context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED
        and context.minimum_version>=ssl.TLSVersion.TLSv1_2 and context.keylog_filename is None,'ticket-aws-tls')

def validate(config):
    require(type(config) is dict and set(config)=={'profile','region','account_id','instance_id','instance_role_arn',
        'instance_profile_arn','broker_uid','group_gid','socket_path','roles'} and config['profile']==PROFILE,'ticket-aws-config')
    require(type(config['account_id']) is str and re.fullmatch('[0-9]{12}',config['account_id'])
        and type(config['region']) is str and re.fullmatch('[a-z]{2}-[a-z]+-[1-9]',config['region'])
        and type(config['instance_id']) is str and re.fullmatch('i-[0-9a-f]{17}',config['instance_id']),'ticket-aws-config')
    prefix='arn:aws:iam::'+config['account_id']+':'
    for key,kind in [('instance_role_arn','role'),('instance_profile_arn','instance-profile')]:
        require(type(config[key]) is str and re.fullmatch(re.escape(prefix+kind+'/')+r'[A-Za-z0-9_+=,.@/-]{1,128}',config[key]),'ticket-aws-parent')
    require(type(config['broker_uid']) is int and 0<=config['broker_uid']<2**31
        and type(config['group_gid']) is int and 100<=config['group_gid']<2**31,'ticket-aws-users')
    path=config['socket_path']
    require(type(path) is str and len(path.encode())<=100 and re.fullmatch(r'/[A-Za-z0-9_./-]+\.sock',path)
        and '..' not in path.split('/') and not any(v.startswith('.env') for v in path.split('/')),'ticket-aws-socket')
    require(type(config['roles']) is dict and set(config['roles'])==set(ROLES),'ticket-aws-roles')
    uids=[]
    for purpose,r in config['roles'].items():
        require(type(r) is dict and set(r)=={'uid','role_arn','duration_seconds'} and type(r['uid']) is int and 100<=r['uid']<2**31
            and r['role_arn']==prefix+'role/nockapp-ticket-'+purpose and r['role_arn']!=config['instance_role_arn']
            and type(r['duration_seconds']) is int and 900<=r['duration_seconds']<=3600,'ticket-aws-role')
        uids.append(r['uid'])
    require(len(set([config['broker_uid'],*uids]))==4,'ticket-aws-users')
    return copy.deepcopy(config)

def temporary():return Rejected('workload-session-unavailable')

def expiry(text):
    require(type(text) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z',text),'ticket-aws-response')
    try:return int(datetime.fromisoformat(text.replace('Z','+00:00')).timestamp())
    except (ValueError,OverflowError):raise Rejected('ticket-aws-response') from None

def http(host,method,path,headers,body=b'',*,dial,context=None,limit=65536):
    raw=secure=connection=timer=None
    try:
        if context is not None:check_tls(context)
        raw=dial();raw.settimeout(5)
        def close():
            try:(secure or raw).shutdown(socket.SHUT_RDWR)
            except OSError:pass
        timer=threading.Timer(12,close);timer.daemon=True;timer.start()
        if context is not None:secure=context.wrap_socket(raw,server_hostname=host)
        connection=HTTPConnection(host,timeout=5);connection.sock=secure or raw;connection.set_debuglevel(0)
        connection.request(method,path,body=body,headers={**headers,'Accept-Encoding':'identity','Connection':'close'})
        response=connection.getresponse()
        for name in ('Content-Length','Transfer-Encoding','Content-Type','Content-Encoding'):
            require(sum(k.lower()==name.lower() for k,_ in response.getheaders())<=1,'ticket-aws-http')
        length=response.getheader('Content-Length');transfer=response.getheader('Transfer-Encoding','').lower()
        require(not(length and transfer) and transfer in ('','chunked')
            and response.getheader('Content-Encoding','identity').lower()=='identity'
            and (length is None or re.fullmatch('[0-9]{1,9}',length) and int(length)<=limit),'ticket-aws-http')
        data=response.read(limit+1)
        require(len(data)<=limit and (length is None or len(data)==int(length)),'ticket-aws-size')
        if response.status==429 or 500<=response.status<600:raise temporary()
        require(response.status==200,'ticket-aws-authorization')
        return data,response.getheader('Content-Type','').split(';')[0].lower()
    except Rejected:raise
    except Exception:raise temporary() from None
    finally:
        if timer:timer.cancel()
        if connection:connection.close()
        elif secure:secure.close()
        elif raw:raw.close()

class MetadataSession(WorkloadSession):
    """Implements only the existing create_session refresh interface, no X509."""
    def __init__(self,config,*,dial=None):
        self.config=validate(config);self._dial=dial or (lambda:socket.create_connection((METADATA,80),timeout=5))
        self._last_expiry=0
    def create_session(self):
        token,_=http(METADATA,'PUT','/latest/api/token',{'X-aws-ec2-metadata-token-ttl-seconds':'900'},dial=self._dial,limit=4096)
        require(re.fullmatch(rb'[A-Za-z0-9+/=_-]{1,4096}',token),'ticket-aws-metadata-token')
        headers={'X-aws-ec2-metadata-token':token.decode('ascii')}
        def get(path,maximum=65536):return http(METADATA,'GET','/latest/meta-data/'+path,headers,dial=self._dial,limit=maximum)[0]
        require(get('instance-id',64).decode('ascii')==self.config['instance_id'],'ticket-aws-wrong-instance')
        info=strict_json(get('iam/info'),max_bytes=65536)
        require(type(info) is dict and set(info)=={'Code','LastUpdated','InstanceProfileArn','InstanceProfileId'}
            and info['Code']=='Success' and info['InstanceProfileArn']==self.config['instance_profile_arn']
            and type(info['InstanceProfileId']) is str and re.fullmatch('AIPA[A-Z0-9]{12,124}',info['InstanceProfileId']),'ticket-aws-instance-profile')
        require(expiry(info['LastUpdated'])<=int(time.time())+5,'ticket-aws-response')
        role=self.config['instance_role_arn'].split('/')[-1]
        value=strict_json(get('iam/security-credentials/'+quote(role,safe='')),max_bytes=65536)
        require(type(value) is dict and set(value)=={'Code','LastUpdated','Type','AccessKeyId','SecretAccessKey','Token','Expiration'}
            and value['Code']=='Success' and value['Type']=='AWS-HMAC' and expiry(value['LastUpdated'])<=int(time.time())+5,'ticket-aws-metadata-response')
        end=expiry(value['Expiration']);now=int(time.time())
        result=validate_value('managed-writer-credentials',{'access_key_id':value['AccessKeyId'],'secret_access_key':value['SecretAccessKey'],
            'session_token':value['Token'],'expires_at':end})
        # Near-expiry unchanged metadata is transient, not a fresh credential.
        if end<=self._last_expiry or end<=now+600:raise temporary()
        self._last_expiry=end;return copy.deepcopy(result)

def xml_children(node,names,required=None):
    result={}
    require(not node.attrib,'ticket-aws-response')
    for child in node:
        require(child.tag.startswith('{'+XML+'}'),'ticket-aws-response');name=child.tag.split('}',1)[1]
        require(name in names and name not in result and not child.attrib,'ticket-aws-response');result[name]=child
    require(set(required if required is not None else names)<=set(result),'ticket-aws-response');return result

def text(node):
    require(len(node)==0 and not node.attrib and type(node.text) is str,'ticket-aws-response');return node.text

class STSRoleSession(WorkloadSession):
    """Fixed configured role, not an arbitrary AssumeRole RPC."""
    def __init__(self,config,role,parent,context,*,dial=None):
        self.config=validate(config);require(role in ROLES and isinstance(parent,WorkloadCredentials),'ticket-aws-role')
        check_tls(context)
        self.role,self.parent,self.context=role,parent,context;self.host='sts.'+self.config['region']+'.amazonaws.com'
        self._dial=dial or (lambda:socket.create_connection((self.host,443),timeout=5))
        activate()
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.credentials import Credentials
        _silence_sdk();self._auth,self._request,self._credentials=SigV4Auth,AWSRequest,Credentials
    def create_session(self):
        check_tls(self.context)
        r=self.config['roles'][self.role];name='nockapp-ticket-'+self.role
        body=urlencode({'Action':'AssumeRole','Version':'2011-06-15','RoleArn':r['role_arn'],
            'RoleSessionName':name,'SourceIdentity':name,'DurationSeconds':r['duration_seconds']}).encode('ascii')
        try:value=self.parent.get()
        except Rejected as error:
            # A parent cache with no usable value can still be retryable. Keep
            # that distinction across the nested role cache; a transient IMDS
            # refresh must not permanently poison every child role.
            if error.args==('workload-credentials-unavailable',) and not self.parent._fatal:
                raise temporary() from None
            raise
        require(value['expires_at']>int(time.time())+5,'ticket-aws-parent-expired')
        credentials=self._credentials(value['access_key_id'],value['secret_access_key'],value['session_token'])
        request=self._request(method='POST',url='https://'+self.host+'/',data=body,headers={'Content-Type':'application/x-www-form-urlencoded; charset=utf-8'})
        self._auth(credentials,'sts',self.config['region']).add_auth(request)
        raw,content=http(self.host,'POST','/',dict(request.headers.items()),body,dial=self._dial,context=self.context)
        try:xml=raw.decode('utf-8')
        except UnicodeDecodeError:raise Rejected('ticket-aws-response') from None
        require(content in ('text/xml','application/xml') and '<!' not in xml,'ticket-aws-response')
        try:root=ET.fromstring(xml)
        except ET.ParseError:raise Rejected('ticket-aws-response') from None
        require(root.tag=='{'+XML+'}AssumeRoleResponse','ticket-aws-response')
        parts=xml_children(root,{'AssumeRoleResult','ResponseMetadata'});result=xml_children(parts['AssumeRoleResult'],
            {'Credentials','AssumedRoleUser','PackedPolicySize','SourceIdentity',
             'SessionTokenSize','SessionTokenUtilization'},{'Credentials','AssumedRoleUser','SourceIdentity'})
        require(text(result['SourceIdentity'])==name,'ticket-aws-wrong-role')
        if 'PackedPolicySize' in result:require(re.fullmatch('[0-9]{1,3}',text(result['PackedPolicySize'])) and int(text(result['PackedPolicySize']))<=100,'ticket-aws-response')
        # Documented optional accounting fields, observed in real STS replies.
        # They never select an identity, change expiry or allocate a buffer.
        # Keep the same bounded response and strict XML/credential admission.
        for field,maximum in (('SessionTokenSize',65536),('SessionTokenUtilization',100)):
            if field in result:
                value=text(result[field])
                require(re.fullmatch('0|[1-9][0-9]{0,5}',value) and int(value)<=maximum,'ticket-aws-response')
        user=xml_children(result['AssumedRoleUser'],{'Arn','AssumedRoleId'})
        require(text(user['Arn'])=='arn:aws:sts::'+self.config['account_id']+':assumed-role/'+name+'/'+name
            and re.fullmatch('[A-Z0-9]{16,128}:'+re.escape(name),text(user['AssumedRoleId'])),'ticket-aws-wrong-role')
        fields=xml_children(result['Credentials'],{'AccessKeyId','SecretAccessKey','SessionToken','Expiration'})
        end=expiry(text(fields['Expiration']));now=int(time.time())
        require(now+600<end<=now+r['duration_seconds']+5,'ticket-aws-session-expiry')
        return copy.deepcopy(validate_value('managed-writer-credentials',{'access_key_id':text(fields['AccessKeyId']),
            'secret_access_key':text(fields['SecretAccessKey']),'session_token':text(fields['SessionToken']),'expires_at':end}))
