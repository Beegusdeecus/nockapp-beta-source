"""Role-bound renewable AWS resources and decrypt-only sealed boot recovery.

No initializer, key creation, permission provisioning or ambient identity source.
Host keys are separate from original Nitro issuer keys; deployed IAM/OS/KMS
separation is still required. No plaintext key file or generic decrypt RPC.
"""
from dataclasses import dataclass
import hashlib
import os
import re
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from aws_transport import AwsJsonClient
from base_rpc import BaseRPC
from policy import canonical,require,strict_json,Rejected
from public_s3_v5 import S3PublicOrigin,OriginStorageBudget
from ticket_aws_credentials_v1 import validate as broker_validate,tls_context,check_tls
from ticket_backend_boot_v1 import validate as backend_validate,harden_process,assemble,PRIVATE
from ticket_credential_broker_v1 import credentials,CredentialSession
from ticket_native_v1 import _decode
from ticket_private_s3_v1 import PrivateS3Transport
from workload_sessions import WorkloadCredentials

PROFILE='nockapp-ticket-resource-plan-v1'
SEALED='nockapp-ticket-sealed-boot-v1'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):require(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) and int(v,16)>0,'ticket-resource-pin')

class HostAwsClient(AwsJsonClient):
    """Host SDK operations require our exact broker-backed service identity."""
    def __init__(self,service,region,source,context,*,role,account,dial=None):
        require(isinstance(source,WorkloadCredentials) and type(source._session) is CredentialSession
            and source._session.config['role']==role
            and source._session.config['role_arn']=='arn:aws:iam::'+account+':role/nockapp-ticket-'+role,'ticket-resource-identity')
        require(service=='kms' or service=='dynamodb' and role=='publication','ticket-resource-service')
        check_tls(context);super().__init__(service,region,source,context,dial)
    def _call(self,operation,parameters):
        check_tls(self._context)
        require(operation in ({'Decrypt'} if self.service=='kms' else {'TransactGetItems','TransactWriteItems'}),'ticket-resource-operation')
        return super()._call(operation,parameters)

class RecoveryKey:
    def __init__(self,client,key_arn,role,backend_sha256):
        require(type(client) is HostAwsClient and client.service=='kms','ticket-recovery-client')
        self.client,self.key_arn,self.role,self.backend_sha256=client,key_arn,role,backend_sha256
        self.context={'application':'nockapp-ticket-backend-v1','role':role,'backend-sha256':backend_sha256}
    def decrypt(self,wrapped):
        require(type(wrapped) is bytes and 0<len(wrapped)<=6144,'ticket-recovery-envelope')
        result=self.client.decrypt(KeyId=self.key_arn,CiphertextBlob=wrapped,EncryptionAlgorithm='SYMMETRIC_DEFAULT',EncryptionContext=self.context)
        require(type(result) is dict and set(result)<={'KeyId','EncryptionAlgorithm','Plaintext','KeyMaterialId','ResponseMetadata'}
            and result.get('KeyId')==self.key_arn and result.get('EncryptionAlgorithm')=='SYMMETRIC_DEFAULT'
            and type(result.get('Plaintext')) is bytes and len(result['Plaintext'])==32 and any(result['Plaintext']),'ticket-recovery-key')
        # Current symmetric KMS Decrypt responses also identify the public
        # material version. It neither replaces the exact key/context checks
        # nor the sealed packet's authenticated encryption.
        if 'KeyMaterialId' in result:
            require(type(result['KeyMaterialId']) is str
                and re.fullmatch('[a-f0-9]{64}',result['KeyMaterialId']),'ticket-recovery-key-material')
        return result['Plaintext']

class RuntimeOriginBudget(OriginStorageBudget):
    def initialize(self):raise Rejected('ticket-resource-budget-initialization-forbidden')

@dataclass(frozen=True)
class Resources:
    role:str
    backend_sha256:str
    plan_sha256:str
    sealed_boot_sha256:str
    rpc:object
    s3:PrivateS3Transport
    recovery:RecoveryKey
    origin:object

def build(backend,backend_pin,broker,broker_pin,plan,plan_pin,*,contexts=None,dials=None):
    cfg=backend_validate(backend,backend_pin);b=broker_validate(broker)
    require(sha(canonical(b))==broker_pin and type(plan) is dict
        and set(plan)=={'profile','backend_sha256','broker_sha256','rpc','kms_key_arn','sealed_boot_sha256'}
        and plan['profile']==PROFILE and plan['backend_sha256']==backend_pin and plan['broker_sha256']==broker_pin
        and sha(canonical(plan))==plan_pin,'ticket-resource-plan')
    digest(plan_pin);digest(plan['sealed_boot_sha256']);role=cfg['role'];r=cfg['records']
    require(b['account_id']==r['account_id'] and b['region']==r['region'] and os.getuid()==b['roles'][role]['uid'],'ticket-resource-user')
    prefix='arn:aws:kms:'+r['region']+':'+r['account_id']+':key/'
    require(type(plan['kms_key_arn']) is str and re.fullmatch(re.escape(prefix)+r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',plan['kms_key_arn']),'ticket-resource-kms')
    rpc=plan['rpc'];require(type(rpc) is dict and set(rpc)=={'endpoint','rate','burst','timeout'},'ticket-resource-rpc')
    contexts=dict(contexts or {});dials=dict(dials or {})
    require(set(contexts)<={'base_rpc','s3','kms','dynamodb','public_s3'} and set(dials)<={'base_rpc','s3','kms','dynamodb','public_s3','broker'},'ticket-resource-transport')
    def context(name):
        value=contexts.get(name)
        if value is None:value=tls_context()
        check_tls(value);return value
    # BaseRPC validates endpoint and budgets without acquiring credentials/I/O.
    base=BaseRPC(rpc['endpoint'],rate=rpc['rate'],burst=rpc['burst'],timeout=rpc['timeout'],context=context('base_rpc'),dial=dials.get('base_rpc'))
    source=credentials(b,role,dial=dials.get('broker'))
    require(source._session.config['scope']==broker_pin,'ticket-resource-identity')
    buckets=[r[k] for k in ('purchase_bucket','ledger_bucket') if k in r]
    s3=PrivateS3Transport(r['region'],r['account_id'],tuple(dict.fromkeys(buckets)),source,context=context('s3'),dial=dials.get('s3'))
    kms=HostAwsClient('kms',r['region'],source,context('kms'),role=role,account=r['account_id'],dial=dials.get('kms'))
    recovery=RecoveryKey(kms,plan['kms_key_arn'],role,backend_pin);origin=None
    if role=='publication':
        o=cfg['origin'];client=HostAwsClient('dynamodb',r['region'],source,context('dynamodb'),role=role,account=r['account_id'],dial=dials.get('dynamodb'))
        budget=RuntimeOriginBudget(client,o['budget_table_arn'].split(':table/',1)[1],o['budget_namespace'],o['budget_scope'],o['budget_limits'],o['retention_seconds'])
        origin=S3PublicOrigin(o['region'],o['bucket'],o['account_id'],context('public_s3'),credentials=source,budget=budget,
            retention_seconds=o['retention_seconds'],dial=dials.get('public_s3'))
    return Resources(role,backend_pin,plan_pin,plan['sealed_boot_sha256'],base,s3,recovery,origin)

def open_sealed(resources,envelope):
    harden_process()
    require(type(resources) is Resources and type(envelope) is bytes and 0<len(envelope)<=100000
        and sha(envelope)==resources.sealed_boot_sha256,'ticket-recovery-envelope')
    try:
        value=strict_json(envelope,max_bytes=100000)
        require(type(value) is dict and set(value)=={'profile','role','backend_sha256','kms_key_arn','wrapped_key','nonce','ciphertext'}
            and value['profile']==SEALED and canonical(value)==envelope and value['role']==resources.role
            and value['backend_sha256']==resources.backend_sha256 and value['kms_key_arn']==resources.recovery.key_arn,'ticket-recovery-scope')
        wrapped=_decode(value['wrapped_key'],6144);nonce=_decode(value['nonce'],12);ciphertext=_decode(value['ciphertext'],65552)
        require(len(wrapped)>0 and len(nonce)==12 and 16<len(ciphertext)<=65552,'ticket-recovery-envelope')
        aad=canonical({'profile':SEALED,'role':resources.role,'backend_sha256':resources.backend_sha256,
            'kms_key_arn':resources.recovery.key_arn,'wrapped_key_sha256':sha(wrapped)})
        data=AESGCM(resources.recovery.decrypt(wrapped)).decrypt(nonce,ciphertext,aad)
        body=strict_json(data,max_bytes=65536)
        require(canonical(body)==data and type(body) is dict and body.get('profile')==PRIVATE
            and body.get('role')==resources.role and body.get('config_sha256')==resources.backend_sha256,'ticket-recovery-body')
        return body
    except Exception:raise Rejected('ticket-recovery-unavailable') from None

def assemble_sealed(backend,backend_pin,resources,envelope,*,ticket_native,scratch_directory=None,author_native=None):
    # Public scope is checked before KMS or any plaintext recovery.
    cfg=backend_validate(backend,backend_pin)
    require(type(resources) is Resources and resources.backend_sha256==backend_pin and resources.role==cfg['role'],'ticket-resource-plan')
    body=open_sealed(resources,envelope);read,write=os.pipe();errors=[]
    def deliver():
        try:
            raw=canonical(body)
            with os.fdopen(write,'wb') as out:out.write(raw)
        except Exception:errors.append(True)
    writer=threading.Thread(target=deliver,daemon=True);writer.start()
    try:
        result=assemble(cfg,backend_pin,read,ticket_native=ticket_native,rpc=resources.rpc,s3=resources.s3,
            scratch_directory=scratch_directory,origin=resources.origin,author_native=author_native)
    finally:os.close(read);writer.join(timeout=10)
    require(not writer.is_alive() and not errors,'ticket-recovery-pipe');return result
