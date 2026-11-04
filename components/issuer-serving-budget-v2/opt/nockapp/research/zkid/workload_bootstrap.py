"""Recipient-only workload seed recovery, attested CSR and pinned CA admission.

Internal measured component; no listener, disk private keys, ambient credentials,
new IAM resources, automatic seed replacement or generic signing interface.
"""
import base64
import copy
import hashlib
import hmac
import re
import secrets
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.x509.oid import NameOID
from domain_transport import _decode
from domain_trust import validate_approval as validate_issuer_approval
from policy import Rejected,canonical,digest,hex_string,require
from provisioning import RecipientProvisioner
from trust import verify_aws_document,validate_pcrs
from workload_sessions import WorkloadSession,UUID

PROFILE='nockapp-zkid-workload-bootstrap-v1'
APPROVAL='nockapp-zkid-workload-bootstrap-approval-v1'
ORDER=int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',16)
PURPOSES=('issuer','budget','verifier','public-reader')


def validate_key_arn(value):
    require(type(value) is str and re.fullmatch(r'arn:aws:kms:[a-z]{2}-[a-z]+-[1-9]:[0-9]{12}:key/'+UUID,value),
            'workload-bootstrap-key')
    return value


def context(namespace,authority,purpose):
    for value in (namespace,authority):
        hex_string(value,64);require(any(bytes.fromhex(value)),'workload-bootstrap-context')
    require(type(purpose) is str and purpose in PURPOSES,'workload-bootstrap-context')
    return {'application':'nockapp-zkid-v1','kind':'workload-identity-seed','issuer':namespace,
            'state-authority':authority,'purpose':purpose}


def _derive(seed,scope):
    require(type(seed) is bytes and len(seed)==32 and any(seed),'workload-seed')
    for counter in range(256):
        value=int.from_bytes(hmac.digest(seed,canonical({'profile':PROFILE,'context':scope,'counter':counter}),'sha256'),'big')
        # Exact rejection sampling: reducing P-256 scalars modulo n adds bias.
        if 0<value<ORDER:return ec.derive_private_key(value,ec.SECP256R1())
    raise Rejected('workload-seed')


def _subject(scope):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'nockapp-zkid-'+scope['purpose']),
                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,scope['issuer'])])


class WorkloadIdentity:
    def __init__(self,key,wrapped,scope,key_arn,code_identity,nsm):
        self._key=key;self._wrapped=wrapped;self.scope=copy.deepcopy(scope)
        self.key_arn=key_arn;self.code_identity=code_identity;self._nsm=nsm

    def offer(self,nonce):
        hex_string(nonce,64)
        csr=(x509.CertificateSigningRequestBuilder().subject_name(_subject(self.scope))
             .sign(self._key,hashes.SHA256()).public_bytes(serialization.Encoding.DER))
        public=self._key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint)
        bind={'profile':PROFILE,'nonce':nonce,'context':self.scope,'key_arn':self.key_arn,
              'code_identity':self.code_identity,'wrapped_seed_sha256':hashlib.sha256(self._wrapped).hexdigest(),
              'csr_sha256':hashlib.sha256(csr).hexdigest()}
        document=self._nsm.attest(bytes.fromhex(nonce),public,bytes.fromhex(digest(bind)))
        require(type(document) is bytes and 0<len(document)<=32768,'workload-bootstrap-document')
        return {'profile':PROFILE,'nonce':nonce,'context':copy.deepcopy(self.scope),'key_arn':self.key_arn,
                'code_identity':self.code_identity,'wrapped_seed':base64.b64encode(self._wrapped).decode('ascii'),
                'csr':base64.b64encode(csr).decode('ascii'),'document':base64.b64encode(document).decode('ascii')}

    def session(self,config,certificate_der,root_der,approved_root_sha256,tls_context,dial=None):
        try:
            hex_string(approved_root_sha256,64)
            require(type(root_der) is bytes and 0<len(root_der)<=8192
                    and hashlib.sha256(root_der).hexdigest()==approved_root_sha256,'workload-root')
            require(type(certificate_der) is bytes and 0<len(certificate_der)<=8192,'workload-certificate')
            root=x509.load_der_x509_certificate(root_der);leaf=x509.load_der_x509_certificate(certificate_der)
            require(root.public_bytes(serialization.Encoding.DER)==root_der and root.subject==root.issuer
                    and root.version==x509.Version.v3 and root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                    and root.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
                    and isinstance(root.public_key(),ec.EllipticCurvePublicKey)
                    and isinstance(root.public_key().curve,ec.SECP256R1),'workload-root')
            for cert in (root,leaf):
                require(cert.signature_hash_algorithm.name in ('sha256','sha384','sha512')
                        and cert.not_valid_before_utc.timestamp()<=time.time()<cert.not_valid_after_utc.timestamp(),
                        'workload-certificate')
                require(not any(ext.critical and not isinstance(ext.value,(x509.BasicConstraints,x509.KeyUsage))
                                for ext in cert.extensions),'workload-certificate')
            root.verify_directly_issued_by(root);leaf.verify_directly_issued_by(root)
            require(root.not_valid_before_utc<=leaf.not_valid_before_utc and leaf.not_valid_after_utc<=root.not_valid_after_utc
                    and leaf.subject==_subject(self.scope) and config['namespace']==self.scope['issuer']
                    and config['purpose']==self.scope['purpose'] and config['account']==self.key_arn.split(':')[4]
                    and config['region']==self.key_arn.split(':')[3],'workload-certificate')
            return WorkloadSession(config,certificate_der,self._key,tls_context,dial)
        except Exception:raise Rejected('workload-identity-unavailable') from None


class IdentityBootstrap:
    def __init__(self,kms,nsm,key_arn,namespace,authority,purpose,code_identity):
        validate_key_arn(key_arn)
        self.scope=context(namespace,authority,purpose);hex_string(code_identity,64)
        require(any(bytes.fromhex(code_identity)),'workload-bootstrap-code')
        self._recipient=RecipientProvisioner(kms,nsm,key_arn,namespace,authority)
        self._kms=kms;self._nsm=nsm;self.key_arn=key_arn;self.code_identity=code_identity
        self._creation_lock=threading.Lock();self._creation_attempted=False

    def _obtain(self,operation,wrapped=None):
        try:
            if operation=='Decrypt':require(type(wrapped) is bytes and 0<len(wrapped)<=6144,'workload-wrapped-seed')
            recipient=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            public=recipient.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
            bind={'profile':PROFILE,'operation':operation,'context':self.scope,'key_arn':self.key_arn,
                  'code_identity':self.code_identity,'wrapped_seed_sha256':hashlib.sha256(wrapped).hexdigest() if wrapped else None}
            document=self._nsm.attest(secrets.token_bytes(32),public,bytes.fromhex(digest(bind)))
            require(type(document) is bytes and 0<len(document)<=32768,'workload-bootstrap-document')
            request={'KeyId':self.key_arn,'EncryptionContext':copy.deepcopy(self.scope),
                     'Recipient':{'KeyEncryptionAlgorithm':'RSAES_OAEP_SHA_256','AttestationDocument':document}}
            if operation=='GenerateDataKey':
                response=self._kms.generate_data_key(**request,KeySpec='AES_256')
                allowed={'KeyId','CiphertextBlob','CiphertextForRecipient','Plaintext','ResponseMetadata'}
                wrapped=response.get('CiphertextBlob')
            else:
                response=self._kms.decrypt(**request,CiphertextBlob=wrapped,EncryptionAlgorithm='SYMMETRIC_DEFAULT')
                allowed={'KeyId','EncryptionAlgorithm','CiphertextForRecipient','Plaintext','ResponseMetadata'}
                require(response.get('EncryptionAlgorithm')=='SYMMETRIC_DEFAULT','workload-bootstrap-response')
            require(type(response) is dict and set(response)<=allowed and response.get('KeyId')==self.key_arn
                    and response.get('Plaintext') in (None,b'') and type(wrapped) is bytes and 0<len(wrapped)<=6144,
                    'workload-bootstrap-response')
            seed=self._recipient._decrypt_cms(recipient,response.get('CiphertextForRecipient'))
            key=_derive(seed,self.scope)
            return WorkloadIdentity(key,wrapped,self.scope,self.key_arn,self.code_identity,self._nsm)
        except Exception:raise Rejected('workload-bootstrap-unavailable') from None

    def create(self):
        """Explicit initial ceremony ONLY. Never called as recovery fallback."""
        with self._creation_lock:
            require(not self._creation_attempted,'workload-bootstrap-already-attempted')
            self._creation_attempted=True  # Before KMS, including uncertain failure.
            return self._obtain('GenerateDataKey')

    def recover(self,wrapped):return self._obtain('Decrypt',wrapped)


def verify_offer(offer,nonce,approved):
    """Independent operator checks before CA issuance; always genuine AWS trust."""
    try:
        require(type(approved) is dict and set(approved)=={'profile','namespace','authority','purpose','key_arn','code_identity','pcrs'}
                and approved['profile']==APPROVAL,'workload-bootstrap-approval')
        scope=context(approved['namespace'],approved['authority'],approved['purpose'])
        validate_key_arn(approved['key_arn'])
        validate_issuer_approval({'mode':'production','definition_hash':approved['namespace'],
            'state_authority_sha256':approved['authority'],'code_identity':approved['code_identity'],'pcrs':approved['pcrs']})
        hex_string(nonce,64)
        require(type(offer) is dict and set(offer)=={'profile','nonce','context','key_arn','code_identity','wrapped_seed','csr','document'}
                and offer['profile']==PROFILE and offer['nonce']==nonce and offer['context']==scope
                and offer['key_arn']==approved['key_arn'] and offer['code_identity']==approved['code_identity'],'workload-bootstrap-offer')
        csr_bytes=_decode(offer['csr'],8192);wrapped=_decode(offer['wrapped_seed'],6144)
        csr=x509.load_der_x509_csr(csr_bytes)
        require(csr.public_bytes(serialization.Encoding.DER)==csr_bytes and csr.is_signature_valid
                and csr.signature_hash_algorithm.name=='sha256' and csr.subject==_subject(scope)
                and len(csr.extensions)==0 and isinstance(csr.public_key(),ec.EllipticCurvePublicKey)
                and isinstance(csr.public_key().curve,ec.SECP256R1),'workload-bootstrap-csr')
        bind={'profile':PROFILE,'nonce':nonce,'context':scope,'key_arn':offer['key_arn'],'code_identity':offer['code_identity'],
              'wrapped_seed_sha256':hashlib.sha256(wrapped).hexdigest(),'csr_sha256':hashlib.sha256(csr_bytes).hexdigest()}
        now=int(time.time()*1000);payload=verify_aws_document(_decode(offer['document'],32768),now)
        require(payload.get('nonce')==bytes.fromhex(nonce)
                and payload.get('public_key')==csr.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint)
                and payload.get('user_data')==bytes.fromhex(digest(bind)) and type(payload.get('timestamp')) is int
                and now-120000<=payload['timestamp']<=now+5000,'workload-bootstrap-quote')
        validate_pcrs(payload['pcrs'],approved['pcrs'])
        return csr_bytes,wrapped
    except Exception:raise Rejected('workload-bootstrap-offer-rejected') from None
