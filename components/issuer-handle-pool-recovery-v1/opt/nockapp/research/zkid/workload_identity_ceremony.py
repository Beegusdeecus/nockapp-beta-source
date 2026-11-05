"""Explicit immutable workload-key selection, separate from credential issuance.

Only selected encrypted seeds/public key digests may leave this component.
Normal service recovery never imports its create path. The managed authority
must deny untrusted overwrite/deletion; privileged administrators remain trusted.
"""
import base64
import copy
import hashlib

from cryptography.hazmat.primitives import serialization
from base_managed_storage import DynamoObjects
from domain_transport import _decode
from issuer_supervisor import validate_device
from policy import canonical,digest,hex_string,require,strict_json
from workload_bootstrap import IdentityBootstrap,context,validate_key_arn

PROFILE='nockapp-workload-identity-selection-v1'
PURPOSES=('issuer','budget','verifier')


def selection_key(namespace,authority,key_arn,purpose):
    require(purpose in PURPOSES,'identity-ceremony-purpose');validate_key_arn(key_arn)
    selected=context(namespace,authority,purpose)
    return 'workload-identity:'+digest({'context':selected,'key_arn':key_arn})


def public_key_hash(identity):
    # A private identity remains entirely inside the measured process. Its CSR
    # and attestation are emitted later only after recovering the selected head.
    raw=identity._key.public_key().public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(raw).hexdigest()


class IdentityCeremony:
    def __init__(self,nsm,kms,objects,key_arn,authority,code):
        require(isinstance(objects,DynamoObjects),'identity-ceremony-authority')
        validate_key_arn(key_arn);hex_string(authority,64);hex_string(code,64)
        require(any(bytes.fromhex(authority)) and any(bytes.fromhex(code)),'identity-ceremony-authority')
        validate_device(nsm)  # Genuine non-debug NSM before any managed IO.
        self.nsm,self.kms,self.objects=nsm,kms,objects
        self.key_arn,self.authority,self.code=key_arn,authority,code
        self.bootstraps={purpose:IdentityBootstrap(kms,nsm,key_arn,objects.namespace,authority,purpose,code)
            for purpose in PURPOSES}

    def _suffix(self,purpose):return selection_key(self.objects.namespace,self.authority,self.key_arn,purpose)

    def _validate(self,value,purpose):
        require(type(value) is dict and set(value)=={'profile','context','key_arn','wrapped_seed','public_key_sha256'}
            and value['profile']==PROFILE and value['context']==context(self.objects.namespace,self.authority,purpose)
            and value['key_arn']==self.key_arn,'identity-ceremony-head')
        _decode(value['wrapped_seed'],6144);hex_string(value['public_key_sha256'],64)
        require(any(bytes.fromhex(value['public_key_sha256'])),'identity-ceremony-head')
        return copy.deepcopy(value)

    def head(self,purpose):
        suffix=self._suffix(purpose);item=self.objects._get(suffix)
        if item is None:return None
        require(type(item) is dict and set(item)=={'id','data'}
            and item['id']==self.objects.key(suffix)['id'] and type(item['data']) is dict
            and set(item['data'])=={'B'},'identity-ceremony-head')
        raw=item['data']['B'];require(type(raw) is bytes and 0<len(raw)<=16384,'identity-ceremony-head')
        value=strict_json(raw,max_bytes=16384);require(canonical(value)==raw,'identity-ceremony-head')
        return self._validate(value,purpose)

    def _recover(self,purpose,value):
        selected=self._validate(value,purpose)
        identity=self.bootstraps[purpose].recover(_decode(selected['wrapped_seed'],6144))
        require(public_key_hash(identity)==selected['public_key_sha256'],'identity-ceremony-key-mismatch')
        return identity

    def recover(self,purpose):
        selected=self.head(purpose);require(selected is not None,'identity-ceremony-missing')
        return self._recover(purpose,selected)

    def create(self,purpose):
        """Explicit creation; only the durable winner can ever be offered.

        Unselected KMS ciphertext is an orphan, never an admitted identity.
        Each per-purpose bootstrap latches before KMS creation, even on failure.
        Restart may retry an unselected ceremony; selected heads always recover.
        """
        selected=self.head(purpose)
        if selected is not None:return self._recover(purpose,selected)
        identity=self.bootstraps[purpose].create()
        candidate=self._validate({'profile':PROFILE,'context':identity.scope,'key_arn':self.key_arn,
            'wrapped_seed':base64.b64encode(identity._wrapped).decode(),
            'public_key_sha256':public_key_hash(identity)},purpose)
        self._recover(purpose,candidate)  # Actual decrypt/readback BEFORE selection.
        suffix=self._suffix(purpose)
        try:
            self.objects.client.put_item(TableName=self.objects.table,
                Item={**self.objects.key(suffix),'data':{'B':canonical(candidate)}},
                ConditionExpression='attribute_not_exists(#id)',ExpressionAttributeNames={'#id':'id'})
        except Exception:
            selected=self.head(purpose);require(selected is not None,'identity-ceremony-commit-unavailable')
            return self._recover(purpose,selected)
        selected=self.head(purpose);require(selected==candidate,'identity-ceremony-commit-conflict')
        return self._recover(purpose,selected)

    def offer(self,purpose,nonce):
        hex_string(nonce,64)
        return self.recover(purpose).offer(nonce)
