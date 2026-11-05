"""Versioned CA-only extension to the host's UID-bound credential broker.

Original three-role broker/configuration remain unchanged. A trusted broker UID
serves a separate socket and assumes one fixed new CA role. CA process receives
only its own temporary sessions. Real IAM/UID/metadata/mount enforcement remains
required; Python classes/source restrictions do not establish isolation.
"""
import copy
from pathlib import Path
import re
import threading
import time

from aws_transport import _silence_sdk
from policy import require
from setup_aws_sdk import activate
from ticket_aws_credentials_v1 import validate as base_validate,MetadataSession,STSRoleSession,check_tls,tls_context
from ticket_credential_broker_v1 import CredentialBroker,CredentialSession,FreshRoleCredentials,CLIENT,digest
from ticket_backend_boot_v1 import harden_process
from workload_sessions import WorkloadCredentials

PROFILE='nockapp-ticket-ca-broker-extension-v1'
ROLE='tls-ca'

def validate(value,expected):
    require(type(value) is dict and set(value)=={'profile','base','base_sha256','ca_uid','ca_role_arn',
        'ca_socket_path','duration_seconds'} and value['profile']==PROFILE and digest(value)==expected,
        'tls-ca-broker-extension')
    base=base_validate(value['base']);require(digest(base)==value['base_sha256'],'tls-ca-broker-base')
    require(base['account_id']=='419720240831' and base['region']=='ap-southeast-2'
        and base['broker_uid']>=100,'tls-ca-broker-account-region-user')
    uid=value['ca_uid'];used=[base['broker_uid'],*(r['uid'] for r in base['roles'].values())]
    require(type(uid) is int and 100<=uid<2**31 and uid not in used
        and value['ca_role_arn']=='arn:aws:iam::'+base['account_id']+':role/nockapp-ticket-tls-ca'
        and value['ca_role_arn']!=base['instance_role_arn']
        and type(value['duration_seconds']) is int and value['duration_seconds']==900,'tls-ca-broker-role')
    path=value['ca_socket_path']
    require(type(path) is str and len(path.encode())<=100 and re.fullmatch(r'/[A-Za-z0-9_./-]+\.sock',path)
        and '..' not in path.split('/') and not any(v.startswith('.env') for v in path.split('/'))
        and Path(path).parent!=Path(base['socket_path']).parent,'tls-ca-broker-socket')
    transport=copy.deepcopy(base);transport['socket_path']=path
    transport['roles'][ROLE]={'uid':uid,'role_arn':value['ca_role_arn'],'duration_seconds':900}
    return copy.deepcopy(value),transport

class CaRoleSession(STSRoleSession):
    """Reuse the reviewed fixed-session STS wire operation, with CA-only scope."""
    def __init__(self,value,expected,parent,context,*,dial=None):
        extension,self.config=validate(value,expected)
        require(isinstance(parent,WorkloadCredentials) and type(parent._session) is MetadataSession
            and digest(parent._session.config)==extension['base_sha256'],'tls-ca-broker-parent')
        check_tls(context);self.role=ROLE;self.parent=parent;self.context=context
        self.host='sts.'+self.config['region']+'.amazonaws.com'
        if dial is None:
            import socket
            dial=lambda:socket.create_connection((self.host,443),timeout=5)
        self._dial=dial
        activate()
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.credentials import Credentials
        _silence_sdk();self._auth,self._request,self._credentials=SigV4Auth,AWSRequest,Credentials

class CaCredentialBroker(CredentialBroker):
    """Only the CA UID is admitted on this socket; original roles are absent."""
    def __init__(self,value,expected,source):
        _,self.config=validate(value,expected);self.scope=digest(self.config)
        require(type(source) is FreshRoleCredentials and type(source.session) is CaRoleSession
            and source.role==ROLE and source.scope==self.scope,'tls-ca-broker-source')
        self.sources={ROLE:source};uid=self.config['roles'][ROLE]['uid'];self._uids={uid:ROLE}
        self._slots={ROLE:threading.BoundedSemaphore(1)};self._admission={uid:[4.,time.monotonic()]}
        self._lock=threading.RLock();self._streams=set();self._threads=set();self._stopping=False;self._started=False

class CaCredentialSession(CredentialSession):
    def __init__(self,value,expected,*,dial=None):
        extension,config=validate(value,expected)
        self.config={'profile':CLIENT,'scope':digest(config),'role':ROLE,'role_arn':extension['ca_role_arn'],
            'duration_seconds':900,'socket_path':extension['ca_socket_path'],
            'broker_uid':config['broker_uid'],'group_gid':config['group_gid']}
        self._pin=digest(self.config);self._dial=dial

def build(value,expected,*,context=None,metadata_dial=None,sts_dial=None):
    harden_process();extension,_=validate(value,expected)
    parent=WorkloadCredentials(MetadataSession(extension['base'],dial=metadata_dial))
    if context is None:context=tls_context()
    source=FreshRoleCredentials(CaRoleSession(extension,expected,parent,context,dial=sts_dial))
    return CaCredentialBroker(extension,expected,source)

def credentials(value,expected,*,dial=None):
    return WorkloadCredentials(CaCredentialSession(value,expected,dial=dial))

def metadata_policy(value,expected,nft_sha256):
    """Compile the four-service IMDS deny set from the exact CA/broker binding.

    Public proposal only. The separate v2 table leaves any v1 table untouched.
    Kernel enforcement and service-manager dependencies still need live proof.
    """
    import ticket_metadata_firewall_v1 as firewall
    extension,_=validate(value,expected);base=extension['base']
    result={'profile':firewall.PROFILE_CA,'broker_sha256':extension['base_sha256'],
        'broker_uid':base['broker_uid'],'service_uids':{r:item['uid'] for r,item in base['roles'].items()},
        'nft_sha256':nft_sha256,'ca_uid':extension['ca_uid'],'ca_broker_sha256':expected}
    return firewall.validate(result,digest(result))
