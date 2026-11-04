"""Measured leaf renewal using existing keys/root and conditional CA revisions.

No identity/root creation or generic signer. A valid old leaf obtains one AWS
session before renewal; that snapshot authorizes CA IO without recursively
asking the renewing credential cache for credentials. No enclosing AWS write
is retried. Root replacement is not implemented; boot recovery separately uses its
attestation-gated bootstrap role when no service certificate is still valid.
"""
import base64
import copy
import hashlib
import threading
import time

from cryptography import x509
from aws_transport import AwsJsonClient,AwsFailure
from base_key_vault import RecipientKeyVault
from base_managed_storage import DynamoObjects
from domain_transport import _decode
from renewable_issuer import relay
from policy import canonical, require,Rejected
from workload_bootstrap import WorkloadIdentity
from workload_ca import WorkloadCA,scope
from workload_identity_ceremony import IdentityCeremony,PURPOSES,public_key_hash
from workload_sessions import WorkloadSession,WorkloadCredentials

RENEW_BEFORE = 86400
RENEW_BACKOFF = 30


def temporary_renewal_failure(error):
    if isinstance(error,AwsFailure):
        return error.response['Error']['Code'] in {'ThrottlingException','ProvisionedThroughputExceededException','InternalServerError',
            'ServiceUnavailable','RequestLimitExceeded','DependencyTimeoutException','KMSInternalException'}
    return isinstance(error,Rejected) and error.args==('aws-unavailable',)


class RenewalObjects(DynamoObjects):
    """Preserve authenticated error categories for conservative renewal backoff."""
    def _get(self,suffix):
        value=self.client.get_item(TableName=self.table,Key=self.key(suffix),ConsistentRead=True)
        require(type(value) is dict, 'base-storage-response')
        return value.get('Item')


class RenewalVault(RecipientKeyVault):
    """Recovery-only vault; retain only safe transport error categories."""
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self._unwrap_lock=threading.RLock();self._aws_error=None
    def _key(self,*args,**kwargs):
        try:return super()._key(*args,**kwargs)
        except Rejected as error:
            if isinstance(error,AwsFailure) or error.args==('aws-unavailable',):self._aws_error=error
            raise
    def unwrap(self,*args,**kwargs):
        with self._unwrap_lock:
            self._aws_error=None
            try:return super().unwrap(*args,**kwargs)
            except Exception:
                if self._aws_error is not None:raise self._aws_error from None
                raise
            finally:self._aws_error=None
    def wrap(self,*args,**kwargs):
        raise Rejected('workload-renewal-creation-forbidden')


class RotatingSession(WorkloadSession):
    """Internal session interface; private key remains in WorkloadIdentity."""
    def __init__(self, session, identity, root, root_sha256, context, renew, dial=None):
        require(isinstance(session, WorkloadSession) and isinstance(identity, WorkloadIdentity), 'workload-renewal-source')
        self._current=session;self._identity=identity;self._root=root;self._root_sha256=root_sha256
        self._context=context;self._renew=renew;self._dial=dial;self._rotation_lock=threading.RLock()
        self._renew_retry_at=0
    @property
    def certificate_der(self):return self._current._der
    @property
    def config(self):return copy.deepcopy(self._current.config)
    def create_session(self):
        with self._rotation_lock:
            # Never ask the credential cache for credentials from inside its
            # refresh. This authenticated snapshot also avoids CA bootstrap loops.
            value=self._current.create_session()
            old=self._current._cert
            if old.not_valid_after_utc.timestamp()-time.time()>RENEW_BEFORE:return value
            if time.monotonic()<self._renew_retry_at:return value
            try:
                der=self._renew(value)
            except Exception as error:
                if not temporary_renewal_failure(error):raise
                # Keep only the newly authenticated, still-valid AWS session.
                # No certificate is adopted and no write is retried here.
                self._renew_retry_at=time.monotonic()+RENEW_BACKOFF
                return value
            require(type(der) is bytes and 0<len(der)<=8192, 'workload-renewal-certificate')
            new=x509.load_der_x509_certificate(der)
            require(new.not_valid_after_utc>old.not_valid_after_utc
                    and new.not_valid_after_utc.timestamp()>time.time()+3600, 'workload-renewal-lifetime')
            cfg=self.config;cfg['certificate_sha256']=hashlib.sha256(der).hexdigest()
            replacement=self._identity.session(cfg,der,self._root,self._root_sha256,self._context,self._dial)
            self._current=replacement;self._renew_retry_at=0
            # The fresh AWS session already authenticated above remains valid.
            # The next AWS-session refresh uses the new leaf.
            return value


class RecoveredIdentities(IdentityCeremony):
    """Read durable selections, but offer only keys already recovered at boot."""
    def __init__(self,*args,recovered,**kwargs):
        super().__init__(*args,**kwargs)
        require(set(recovered)==set(PURPOSES), 'workload-renewal-identities')
        self._recovered=dict(recovered)
    def recover(self,purpose):
        require(purpose in PURPOSES, 'workload-renewal-purpose')
        selected=self.head(purpose);require(selected is not None, 'workload-renewal-selection-missing')
        identity=self._recovered[purpose]
        require(isinstance(identity,WorkloadIdentity) and identity.scope==selected['context']
                and identity.key_arn==selected['key_arn'] and identity.code_identity==self.code
                and base64.b64encode(identity._wrapped).decode()==selected['wrapped_seed']
                and public_key_hash(identity)==selected['public_key_sha256'], 'workload-renewal-selection-changed')
        return identity
    def create(self,purpose):
        raise ValueError('workload-renewal-creation-forbidden')


def renew_leaf(ca,purpose,current_der):
    require(isinstance(ca,WorkloadCA), 'workload-renewal-ca')
    head=ca.certificate(purpose)
    if _decode(head['certificate_der'],8192)==current_der:
        head=ca.issue(purpose,expected_revision=head['revision'])
    return _decode(head['certificate_der'],8192)


def protected_ca(kms,objects,identities,config,code,authority,nsm):
    issuer=config['issuer'];namespace=issuer['authority']['namespace'];key=issuer['kms_key_arn']
    selected=RecoveredIdentities(nsm,kms,objects,key,authority,code,recovered=identities)
    vault=RenewalVault(kms,nsm,key,namespace,authority,code,[canonical(scope(namespace,authority,key))])
    ca=WorkloadCA(nsm,vault,objects,selected)
    require(ca.public()['root_sha256']==config['root_sha256'], 'workload-renewal-root-changed')
    return ca


def sources(sessions,identities,config,code,authority,nsm,context):
    """Assemble only after original recovery and certificate/root validation."""
    require(set(sessions)==set(identities)==set(PURPOSES), 'workload-renewal-sources')
    issuer=config['issuer'];cfg=issuer['authority'];region=cfg['region'];namespace=cfg['namespace'];key=issuer['kms_key_arn']
    root=_decode(config['root_certificate'],8192);wrapped={}
    def renewal(purpose,fresh):
        # A budget/verifier role cannot sign certificates. Obtain an issuer
        # snapshot directly from its rotating session, outside any source cache.
        # Lock order is budget/verifier -> issuer; issuer never takes their locks.
        if purpose!='issuer':fresh=wrapped['issuer'].create_session()
        kms=AwsJsonClient('kms',region,fresh,context,relay('kms'))
        objects=RenewalObjects(AwsJsonClient('dynamodb',region,fresh,context,relay('dynamodb')),
                              cfg['table_arn'].split(':table/',1)[1],namespace)
        ca=protected_ca(kms,objects,identities,config,code,authority,nsm)
        return renew_leaf(ca,purpose,wrapped[purpose].certificate_der)
    for purpose in PURPOSES:
        wrapped[purpose]=RotatingSession(sessions[purpose],identities[purpose],root,config['root_sha256'],context,
            lambda fresh,p=purpose:renewal(p,fresh),relay('rolesanywhere'))
    return {purpose:WorkloadCredentials(wrapped[purpose]) for purpose in PURPOSES}
