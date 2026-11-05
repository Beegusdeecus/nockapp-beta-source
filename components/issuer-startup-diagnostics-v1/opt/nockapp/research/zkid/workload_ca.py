"""Protected fixed-purpose workload CA; no credential-issuer or generic signing.

Root private DER is wrapped by an attested Recipient vault before immutable
selection. Only certificates for the three durably selected service keys may be
signed. Leaf renewal is explicit CAS with an expected revision, never a reset.
"""
import base64
import copy
from datetime import datetime,timezone
import hashlib
import secrets
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from base_key_vault import RecipientKeyVault
from base_managed_storage import DynamoObjects
from domain_authority import _number
from domain_transport import _decode
from issuer_supervisor import validate_device
from policy import Rejected,canonical,digest,hex_string,require,strict_json
from workload_bootstrap import verify_offer,APPROVAL
from trust import verify_aws_document
from workload_certificates import subject,parse_root,parse_leaf,current,ROOT_SECONDS,LEAF_SECONDS,CA_NAME
from workload_identity_ceremony import IdentityCeremony,PURPOSES

SCOPE='nockapp-workload-ca-scope-v1'
ROOT='nockapp-workload-ca-selection-v1'
MATERIAL='nockapp-workload-ca-material-v1'
CERT='nockapp-workload-certificate-v1'
MAX_REVISION=2**53-1


def scope(namespace,authority,key_arn):
    for value in (namespace,authority):hex_string(value,64);require(any(bytes.fromhex(value)),'workload-ca-scope')
    from workload_bootstrap import validate_key_arn
    validate_key_arn(key_arn)
    return {'profile':SCOPE,'namespace':namespace,'authority':authority,'key_arn':key_arn,
        'certificate_policy':{'root_seconds':ROOT_SECONDS,'leaf_seconds':LEAF_SECONDS,'ca_name':CA_NAME}}


def ca_suffix(value):return 'workload-ca:'+digest(value)


def certificate_suffix(value,purpose):
    require(purpose in PURPOSES,'workload-ca-purpose')
    return 'workload-certificate:'+digest(value)+':'+purpose


def _der(cert):return cert.public_bytes(serialization.Encoding.DER)


def _extensions(builder,public,issuer,ca):
    return (builder.add_extension(x509.BasicConstraints(ca=ca,path_length=0 if ca else None),critical=True)
        .add_extension(x509.KeyUsage(not ca,False,False,False,False,ca,ca,None,None),critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer),critical=False))


class WorkloadCA:
    def __init__(self,nsm,vault,objects,identities):
        require(isinstance(vault,RecipientKeyVault) and isinstance(objects,DynamoObjects) and isinstance(identities,IdentityCeremony)
            and identities.objects is objects and identities.nsm is nsm and vault.nsm is nsm
            and vault.namespace==objects.namespace and vault.authority==identities.authority
            and vault.key_arn==identities.key_arn and vault.code==identities.code,'workload-ca-authority')
        self.scope=scope(objects.namespace,vault.authority,vault.key_arn);self.aad=canonical(self.scope)
        require(self.aad in vault.allowed,'workload-ca-authority');validate_device(nsm)
        self.nsm,self.vault,self.objects,self.identities=nsm,vault,objects,identities
        self.suffix=ca_suffix(self.scope);self._creation_attempted=False
        # Compare workload offers to a freshly verified quote of this same
        # device. Final KMS/image and operator approvals remain independent.
        nonce=secrets.token_bytes(32);public=b'\x02'+secrets.token_bytes(32)
        data=bytes.fromhex(digest({'profile':SCOPE,'scope':self.scope,'code_identity':vault.code}))
        at=int(time.time()*1000);payload=verify_aws_document(nsm.attest(nonce,public,data),at)
        require(payload.get('nonce')==nonce and payload.get('public_key')==public and payload.get('user_data')==data
            and type(payload.get('timestamp')) is int and at-120000<=payload['timestamp']<=at+5000
            and all(type(payload.get('pcrs',{}).get(i)) is bytes and len(payload['pcrs'][i])==48
                and any(payload['pcrs'][i]) for i in range(3)),'workload-ca-device')
        self.approved_pcrs={str(i):payload['pcrs'][i].hex() for i in range(3)}

    def _head(self):
        item=self.objects._get(self.suffix)
        if item is None:return None
        require(type(item) is dict and set(item)=={'id','data'} and item['id']==self.objects.key(self.suffix)['id']
            and type(item['data']) is dict and set(item['data'])=={'B'},'workload-ca-head')
        raw=item['data']['B'];require(type(raw) is bytes and 0<len(raw)<=16384,'workload-ca-head')
        value=strict_json(raw,max_bytes=16384);require(canonical(value)==raw,'workload-ca-head')
        require(type(value) is dict and set(value)=={'profile','scope','root_certificate','root_sha256','wrapped_private_key'}
            and value['profile']==ROOT and value['scope']==self.scope,'workload-ca-head')
        der=_decode(value['root_certificate'],8192);parse_root(der,self.scope['namespace'])
        require(hashlib.sha256(der).hexdigest()==value['root_sha256'],'workload-ca-head')
        _decode(value['wrapped_private_key'],16384);return value

    def public(self):
        value=self._head();require(value is not None,'workload-ca-missing')
        root=parse_root(_decode(value['root_certificate'],8192),self.scope['namespace'])
        return {'profile':ROOT,'scope':copy.deepcopy(self.scope),'root_certificate':value['root_certificate'],
            'root_sha256':value['root_sha256'],'not_before':int(root.not_valid_before_utc.timestamp()),
            'not_after':int(root.not_valid_after_utc.timestamp()),'credential_issuer_loaded':False}

    def _recover(self,value):
        der=_decode(value['root_certificate'],8192);root=parse_root(der,self.scope['namespace']);current(root)
        raw=self.vault.unwrap(_decode(value['wrapped_private_key'],16384),self.aad);private=strict_json(raw)
        require(canonical(private)==raw and type(private) is dict and set(private)=={'profile','scope','root_sha256','private_der'}
            and private['profile']==MATERIAL and private['scope']==self.scope and private['root_sha256']==value['root_sha256'],
            'workload-ca-material')
        key_der=bytes.fromhex(private['private_der']);key=serialization.load_der_private_key(key_der,password=None)
        require(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256R1)
            and key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())==key_der
            and key.public_key()==root.public_key(),'workload-ca-material')
        return key,root

    def recover(self):
        value=self._head();require(value is not None,'workload-ca-missing');self._recover(value)
        return self.public()

    def create(self):
        value=self._head()
        if value is not None:return self.recover()
        require(not self._creation_attempted,'workload-ca-already-attempted');self._creation_attempted=True
        now=int(time.time());key=ec.generate_private_key(ec.SECP256R1());name=subject(self.scope['namespace'])
        builder=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.fromtimestamp(now-300,timezone.utc))
            .not_valid_after(datetime.fromtimestamp(now+ROOT_SECONDS,timezone.utc)))
        root=_extensions(builder,key.public_key(),key.public_key(),True).sign(key,hashes.SHA256());der=_der(root)
        private={'profile':MATERIAL,'scope':self.scope,'root_sha256':hashlib.sha256(der).hexdigest(),
            'private_der':key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()).hex()}
        value={'profile':ROOT,'scope':self.scope,'root_certificate':base64.b64encode(der).decode(),
            'root_sha256':private['root_sha256'],'wrapped_private_key':base64.b64encode(self.vault.wrap(canonical(private),self.aad)).decode()}
        self._recover(value)
        try:self.objects.client.put_item(TableName=self.objects.table,Item={**self.objects.key(self.suffix),'data':{'B':canonical(value)}},
            ConditionExpression='attribute_not_exists(#id)',ExpressionAttributeNames={'#id':'id'})
        except Exception:
            observed=self._head();require(observed is not None,'workload-ca-commit-unavailable');return self.recover()
        require(self._head()==value,'workload-ca-commit-conflict');return self.recover()

    def _certificate(self,purpose):
        suffix=certificate_suffix(self.scope,purpose);item=self.objects._get(suffix)
        if item is None:return None
        require(type(item) is dict and set(item)=={'id','revision','data'} and item['id']==self.objects.key(suffix)['id']
            and type(item['data']) is dict and set(item['data'])=={'B'},'workload-ca-certificate-head')
        raw=item['data']['B'];require(type(raw) is bytes and 0<len(raw)<=16384,'workload-ca-certificate-head')
        value=strict_json(raw,max_bytes=16384)
        require(canonical(value)==raw and type(value) is dict and set(value)=={'profile','scope','purpose','revision',
            'root_sha256','identity_selection_sha256','certificate_der','certificate_sha256'} and value['profile']==CERT
            and value['scope']==self.scope and value['purpose']==purpose and type(value['revision']) is int
            and 1<=value['revision']<=MAX_REVISION and _number(item['revision'])==value['revision'],
            'workload-ca-certificate-head')
        selected=self.identities.head(purpose);require(selected is not None and digest(selected)==value['identity_selection_sha256'],
            'workload-ca-certificate-identity')
        root=self.public();require(value['root_sha256']==root['root_sha256'],'workload-ca-certificate-root')
        der=_decode(value['certificate_der'],8192)
        require(hashlib.sha256(der).hexdigest()==value['certificate_sha256'],'workload-ca-certificate-head')
        parse_leaf(der,parse_root(_decode(root['root_certificate'],8192),self.scope['namespace']),
            self.scope['namespace'],purpose,selected['public_key_sha256'])
        return value

    def certificate(self,purpose):
        value=self._certificate(purpose);require(value is not None,'workload-ca-certificate-missing')
        root=parse_root(_decode(self.public()['root_certificate'],8192),self.scope['namespace']);current(root)
        selected=self.identities.head(purpose)
        current(parse_leaf(_decode(value['certificate_der'],8192),root,self.scope['namespace'],purpose,selected['public_key_sha256']))
        return copy.deepcopy(value)

    def enrollment(self):
        root=self.public();current(parse_root(_decode(root['root_certificate'],8192),self.scope['namespace']))
        return {'profile':'nockapp-workload-enrollment-v1','scope':copy.deepcopy(self.scope),
            'root_certificate':root['root_certificate'],'root_sha256':root['root_sha256'],
            'identities':{purpose:{'selection':self.identities.head(purpose),'certificate':self.certificate(purpose)}
                for purpose in PURPOSES}}

    def issue(self,purpose,expected_revision=None):
        require(purpose in PURPOSES,'workload-ca-purpose')
        require(expected_revision is None or type(expected_revision) is int and 1<=expected_revision<MAX_REVISION,
            'workload-ca-certificate-revision')
        previous=self._certificate(purpose)
        if expected_revision is None:
            if previous is not None:return self.certificate(purpose)
            revision=1
        else:
            require(previous is not None,'workload-ca-certificate-missing')
            if previous['revision']==expected_revision+1:return self.certificate(purpose)
            require(previous['revision']==expected_revision,'workload-ca-certificate-revision-conflict')
            revision=expected_revision+1
        root_record=self._head();require(root_record is not None,'workload-ca-missing')
        key,root=self._recover(root_record)
        nonce=secrets.token_hex(32);offer=self.identities.offer(purpose,nonce)
        csr_bytes,_=verify_offer(offer,nonce,{'profile':APPROVAL,'namespace':self.scope['namespace'],
            'authority':self.scope['authority'],'purpose':purpose,'key_arn':self.scope['key_arn'],
            'code_identity':self.identities.code,'pcrs':self.approved_pcrs})
        csr=x509.load_der_x509_csr(csr_bytes);selected=self.identities.head(purpose)
        now=int(time.time());end=min(now+LEAF_SECONDS,int(root.not_valid_after_utc.timestamp()))
        require(end>now+3600,'workload-ca-expiring')
        builder=(x509.CertificateBuilder().subject_name(csr.subject).issuer_name(root.subject).public_key(csr.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.fromtimestamp(max(now-300,int(root.not_valid_before_utc.timestamp())),timezone.utc))
            .not_valid_after(datetime.fromtimestamp(end,timezone.utc)))
        der=_der(_extensions(builder,csr.public_key(),root.public_key(),False).sign(key,hashes.SHA256()))
        parse_leaf(der,root,self.scope['namespace'],purpose,selected['public_key_sha256'])
        value={'profile':CERT,'scope':self.scope,'purpose':purpose,'revision':revision,'root_sha256':root_record['root_sha256'],
            'identity_selection_sha256':digest(selected),'certificate_der':base64.b64encode(der).decode(),
            'certificate_sha256':hashlib.sha256(der).hexdigest()}
        arguments={'TableName':self.objects.table,'Item':{**self.objects.key(certificate_suffix(self.scope,purpose)),
            'revision':{'N':str(revision)},'data':{'B':canonical(value)}}}
        if previous is None:arguments.update(ConditionExpression='attribute_not_exists(#id)',ExpressionAttributeNames={'#id':'id'})
        else:arguments.update(ConditionExpression='#revision = :old AND #data = :data',
            ExpressionAttributeNames={'#revision':'revision','#data':'data'},
            ExpressionAttributeValues={':old':{'N':str(expected_revision)},':data':{'B':canonical(previous)}})
        try:self.objects.client.put_item(**arguments)
        except Exception as error:
            observed=self._certificate(purpose)
            if observed is None or observed['revision']!=revision:
                # Preserve authenticated denial/throttle/protocol categories
                # after readback proves that the new revision is not present.
                if isinstance(error,Rejected):raise error
                require(False,'workload-ca-certificate-commit-unavailable')
            return self.certificate(purpose)
        require(self._certificate(purpose)==value,'workload-ca-certificate-commit-conflict')
        return self.certificate(purpose)
