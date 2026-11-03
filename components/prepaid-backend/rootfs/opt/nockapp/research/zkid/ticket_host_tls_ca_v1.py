"""Fixed-three-key host TLS CA using a separate asymmetric AWS KMS key.

No CA private key import/export/recovery, generic signing RPC, original enclave
CA use, permission changes, ambient AWS provider, automatic retries or disk IO.
Public root selection, runtime IAM/UID separation and service renewal integration
are independent gates. The explicitly supplied credential source must renew.
"""
import base64
import copy
import ctypes
from datetime import datetime,timezone
import hashlib
import re
import resource
import socket
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from aws_transport import _silence_sdk
from policy import canonical,digest,require,strict_json,Rejected
from setup_aws_sdk import activate
from ticket_aws_credentials_v1 import check_tls,http
from workload_sessions import WorkloadCredentials

PROFILE='nockapp-host-tls-ca-policy-v1'
ROOT='nockapp-host-tls-ca-root-v1'
ROLES=('payment','publication','refund')
ACCOUNT='419720240831'
REGION='ap-southeast-2'
ORIGINAL_KMS='arn:aws:kms:'+REGION+':'+ACCOUNT+':key/f5bc0a85-c760-4c79-b2a1-fc70e83d9d82'
ORIGINAL_CA='51034b0fbe78ab88659ace315c10462876ef4a6f98c32365bcbdd662c115d91d'
ALGORITHM='ECDSA_SHA_256'
# RFC5758 ecdsa-with-SHA256 AlgorithmIdentifier; absent parameters.
ALGORITHM_DER=bytes.fromhex('300a06082a8648ce3d040302')

def sha(raw):return hashlib.sha256(raw).hexdigest()
def b64(raw):return base64.b64encode(raw).decode('ascii')
def un64(value,limit):
    require(type(value) is str and 0<len(value)<=4*((limit+2)//3),'host-ca-public-encoding')
    raw=base64.b64decode(value,validate=True)
    require(0<len(raw)<=limit and b64(raw)==value,'host-ca-public-encoding')
    return raw
def spki(key):return key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
def dt(stamp):return datetime.fromtimestamp(stamp,timezone.utc)
def harden():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));libc=ctypes.CDLL(None,use_errno=True)
    require(libc.prctl(4,0,0,0,0)==0 and libc.prctl(38,1,0,0,0)==0,'host-ca-process')

def leaf_values(hostname):
    return [(x509.BasicConstraints(False,None),True),
        (x509.KeyUsage(True,False,False,False,False,False,False,None,None),True),
        (x509.SubjectAlternativeName([x509.DNSName(hostname)]),False),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)]

def leaf_extensions(builder,hostname):
    for value,critical in leaf_values(hostname):builder=builder.add_extension(value,critical)
    return builder

def checked_policy(value,expected):
    require(type(value) is dict and set(value)=={'profile','kms_key_arn','ca_spki_der','ca_spki_sha256',
        'root_not_before','root_not_after','leaf_seconds','renew_before_seconds','services'}
        and value['profile']==PROFILE and len(canonical(value))<=32768 and digest(value)==expected,'host-ca-policy')
    prefix='arn:aws:kms:'+REGION+':'+ACCOUNT+':key/'
    require(type(value['kms_key_arn']) is str and re.fullmatch(re.escape(prefix)+
        r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['kms_key_arn'])
        and value['kms_key_arn']!=ORIGINAL_KMS,'host-ca-kms-scope')
    for field in ('root_not_before','root_not_after','leaf_seconds','renew_before_seconds'):
        require(type(value[field]) is int,'host-ca-times')
    require(0<=value['root_not_before']<value['root_not_after']<2**40
        and 86400<=value['root_not_after']-value['root_not_before']<=366*86400
        and 3600<=value['leaf_seconds']<=7*86400
        and 300<=value['renew_before_seconds']<=value['leaf_seconds']//2,'host-ca-times')
    raw=un64(value['ca_spki_der'],256);key=serialization.load_der_public_key(raw)
    require(isinstance(key,ec.EllipticCurvePublicKey) and isinstance(key.curve,ec.SECP256R1)
        and spki(key)==raw and sha(raw)==value['ca_spki_sha256'],'host-ca-public-key')
    require(type(value['services']) is dict and set(value['services'])==set(ROLES),'host-ca-role-set')
    csrs={}
    for role in ROLES:
        item=value['services'][role]
        require(type(item) is dict and set(item)=={'hostname','key_sha256','csr_der'},'host-ca-service')
        hostname=item['hostname']
        require(type(hostname) is str and len(hostname)<=253 and re.fullmatch(
            r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}',hostname),'host-ca-hostname')
        raw=un64(item['csr_der'],8192);csr=x509.load_der_x509_csr(raw);public=csr.public_key()
        require(csr.public_bytes(serialization.Encoding.DER)==raw and csr.is_signature_valid
            and csr.signature_hash_algorithm.name=='sha256'
            and csr.subject==x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)])
            and isinstance(public,ec.EllipticCurvePublicKey) and isinstance(public.curve,ec.SECP256R1)
            and sha(spki(public))==item['key_sha256'],'host-ca-csr')
        # Compare criticality and exact public DER without generating another key.
        actual=[(e.oid,e.critical,e.value.public_bytes()) for e in csr.extensions]
        wanted=[(e.oid,critical,e.public_bytes()) for e,critical in leaf_values(hostname)]
        require(actual==wanted,'host-ca-csr-extensions');csrs[role]=csr
    pins=[value['services'][r]['key_sha256'] for r in ROLES]
    require(len(set(pins))==3 and value['ca_spki_sha256'] not in pins,'host-ca-key-reuse')
    return copy.deepcopy(value),key,csrs

class KmsSigner:
    """Explicit fixed-key SigV4 transport. Only GetPublicKey and digest Sign.

    Python method restrictions are not an IAM boundary. Exact deployed role,
    key policy, credentials and OS isolation still require live verification.
    """
    def __init__(self,key_arn,source,context,*,dial=None):
        require(isinstance(source,WorkloadCredentials),'host-ca-credential-source')
        check_tls(context);harden()
        self.key_arn=key_arn;self._source=source;self._context=context
        self.host='kms.'+REGION+'.amazonaws.com'
        self._dial=dial or (lambda:socket.create_connection((self.host,443),timeout=5))
    def __repr__(self):return '<Host TLS KMS signer; credentials omitted>'
    def __reduce_ex__(self,_):raise TypeError('host-ca-serialization-forbidden')
    def _call(self,operation,parameters):
        try:
            require(operation in ('GetPublicKey','Sign'),'host-ca-operation')
            check_tls(self._context);value=self._source.get()
            require(value['expires_at']>int(time.time())+5,'host-ca-credentials')
            activate()
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
            from botocore.credentials import Credentials
            _silence_sdk()
            body=canonical(parameters)
            request=AWSRequest(method='POST',url='https://'+self.host+'/',data=body,headers={
                'Content-Type':'application/x-amz-json-1.1','X-Amz-Target':'TrentService.'+operation})
            SigV4Auth(Credentials(value['access_key_id'],value['secret_access_key'],value['session_token']),
                'kms',REGION).add_auth(request)
            raw,content=http(self.host,'POST','/',dict(request.headers.items()),body,
                context=self._context,dial=self._dial,limit=16384)
            require(content=='application/x-amz-json-1.1','host-ca-response')
            return strict_json(raw,max_bytes=16384)
        except Exception:raise Rejected('host-ca-kms-unavailable') from None
    def public(self):
        value=self._call('GetPublicKey',{'KeyId':self.key_arn})
        require(type(value) is dict and set(value)<={'KeyId','PublicKey','KeyUsage','KeySpec',
            'CustomerMasterKeySpec','SigningAlgorithms','KeyOrigin'} and value.get('KeyId')==self.key_arn
            and value.get('KeySpec')=='ECC_NIST_P256' and value.get('KeyUsage')=='SIGN_VERIFY'
            and value.get('SigningAlgorithms')==[ALGORITHM]
            and value.get('CustomerMasterKeySpec','ECC_NIST_P256')=='ECC_NIST_P256'
            # Actual authenticated KMS replies also carry this public metadata.
            # Accept only the native KMS origin used by this fixed CA key.
            and value.get('KeyOrigin','AWS_KMS')=='AWS_KMS','host-ca-kms-key')
        return un64(value.get('PublicKey'),256)
    def sign_digest(self,data):
        require(type(data) is bytes and len(data)==32,'host-ca-digest')
        value=self._call('Sign',{'KeyId':self.key_arn,'Message':b64(data),
            'MessageType':'DIGEST','SigningAlgorithm':ALGORITHM})
        require(type(value) is dict and {'KeyId','Signature','SigningAlgorithm'}<=set(value)<=
            {'KeyId','Signature','SigningAlgorithm','KeyOrigin'}
            and value['KeyId']==self.key_arn and value['SigningAlgorithm']==ALGORITHM
            # Actual KMS Sign replies now include this public metadata too.
            and value.get('KeyOrigin','AWS_KMS')=='AWS_KMS','host-ca-kms-signature')
        return un64(value['Signature'],80)

def der(tag,body):
    # Only the public outer Certificate envelope is assembled here. cryptography
    # builds TBSCertificate and parses/verifies the result independently.
    require(type(body) is bytes and len(body)<16384,'host-ca-der-size')
    size=len(body)
    length=bytes([size]) if size<128 else (lambda raw:bytes([128|len(raw)])+raw)(size.to_bytes((size.bit_length()+7)//8,'big'))
    return bytes([tag])+length+body

def signed(builder,signer,public):
    # The throwaway EC key selects standard ECDSA/SHA256 DER encoding only.
    # Its signature is discarded; every returned certificate is KMS-signed.
    draft=builder.sign(ec.generate_private_key(ec.SECP256R1()),hashes.SHA256())
    tbs=draft.tbs_certificate_bytes;signature=signer.sign_digest(hashlib.sha256(tbs).digest())
    public.verify(signature,tbs,ec.ECDSA(hashes.SHA256()))
    encoded=der(0x30,tbs+ALGORITHM_DER+der(0x03,b'\x00'+signature))
    cert=x509.load_der_x509_certificate(encoded)
    require(cert.public_bytes(serialization.Encoding.DER)==encoded and cert.tbs_certificate_bytes==tbs
        and cert.signature_algorithm_oid.dotted_string=='1.2.840.10045.4.3.2','host-ca-certificate-der')
    return cert

def root_builder(policy,pin,key):
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'NockApp host TLS '+pin[:24])])
    serial=int.from_bytes(hashlib.sha256(('root:'+pin).encode()).digest()[:19],'big') or 1
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key).serial_number(serial)
        .not_valid_before(dt(policy['root_not_before'])).not_valid_after(dt(policy['root_not_after']))
        .add_extension(x509.BasicConstraints(True,0),True)
        .add_extension(x509.KeyUsage(False,False,False,False,False,True,False,None,None),True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key),False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key),False))

class HostCA:
    def __init__(self,policy,expected,signer,*,root_record=None,root_pin=None):
        harden();self._policy,self._public,self._csrs=checked_policy(policy,expected)
        require(type(signer) is KmsSigner and signer.key_arn==self._policy['kms_key_arn'],'host-ca-signer')
        self._signer=signer;self._pin=expected;self._lock=threading.RLock();self._root_attempted=False
        self._last=0;self._root=None;self._record=None
        self._time()
        if root_record is not None:
            require(type(root_record) is dict and set(root_record)=={'profile','policy_sha256','certificate_der'}
                and root_record['profile']==ROOT and root_record['policy_sha256']==expected
                and digest(root_record)==root_pin,'host-ca-root-record')
            raw=un64(root_record['certificate_der'],8192);require(sha(raw)!=ORIGINAL_CA,'host-ca-original-root')
            root=x509.load_der_x509_certificate(raw)
            template=root_builder(self._policy,expected,self._public).sign(ec.generate_private_key(ec.SECP256R1()),hashes.SHA256())
            require(root.public_bytes(serialization.Encoding.DER)==raw
                and root.tbs_certificate_bytes==template.tbs_certificate_bytes,'host-ca-root-template')
            root.verify_directly_issued_by(root)
            self._root=root;self._record=copy.deepcopy(root_record);self._root_attempted=True
        else:require(root_pin is None,'host-ca-root-record')
    def __repr__(self):return '<Fixed three-key host TLS CA; credentials omitted>'
    def __reduce_ex__(self,_):raise TypeError('host-ca-serialization-forbidden')
    def _time(self):
        now=int(time.time())
        require(now>=self._last-5 and self._policy['root_not_before']<=now<self._policy['root_not_after']-60,'host-ca-clock-or-root-expiry')
        self._last=max(now,self._last);return now
    def create_root(self):
        with self._lock:
            require(not self._root_attempted,'host-ca-root-already-attempted');self._root_attempted=True
            try:
                self._time();require(self._signer.public()==un64(self._policy['ca_spki_der'],256),'host-ca-kms-public-pin')
                root=signed(root_builder(self._policy,self._pin,self._public),self._signer,self._public)
                root.verify_directly_issued_by(root)
                self._root=root;self._record={'profile':ROOT,'policy_sha256':self._pin,
                    'certificate_der':b64(root.public_bytes(serialization.Encoding.DER))}
                return copy.deepcopy(self._record)
            except Exception:raise Rejected('host-ca-root-unavailable') from None
    def issue(self,role):
        with self._lock:
            require(role in ROLES and self._root is not None,'host-ca-not-ready')
            try:
                now=self._time();end=min(now+self._policy['leaf_seconds'],self._policy['root_not_after'])
                require(end-now>self._policy['renew_before_seconds']+60,'host-ca-root-expiring')
                csr=self._csrs[role];hostname=self._policy['services'][role]['hostname']
                builder=(x509.CertificateBuilder().subject_name(csr.subject).issuer_name(self._root.subject)
                    .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(dt(max(now-60,self._policy['root_not_before']))).not_valid_after(dt(end)))
                builder=leaf_extensions(builder,hostname)
                cert=signed(builder,self._signer,self._public);cert.verify_directly_issued_by(self._root)
                return cert.public_bytes(serialization.Encoding.DER)
            except Exception:raise Rejected('host-ca-renewal-unavailable') from None
