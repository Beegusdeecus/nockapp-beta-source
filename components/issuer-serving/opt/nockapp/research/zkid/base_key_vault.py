"""Recipient-only KMS envelope encryption for fixed Base service key objects.

Wrap is an explicit initial ceremony. Runtime recovery only calls unwrap; neither
operation accepts plaintext KMS responses or logs plaintext/private key material.
The parent can relay KMS TLS but cannot open an attested recipient envelope.
"""
import base64
import copy
import hashlib
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from domain_transport import _decode
from policy import Rejected,canonical,digest,hex_string,require,strict_json
from provisioning import RecipientProvisioner
from workload_bootstrap import validate_key_arn

PROFILE='nockapp-base-recipient-key-vault-v1'


class RecipientKeyVault:
    def __init__(self,kms,nsm,key_arn,namespace,authority,code,allowed_contexts):
        validate_key_arn(key_arn)
        for value in (namespace,authority,code):
            hex_string(value,64);require(any(bytes.fromhex(value)),'base-vault-context')
        require(type(allowed_contexts) is list and 0<len(allowed_contexts)<=4
            and all(type(value) is bytes and 0<len(value)<=4096 for value in allowed_contexts)
            and len(set(allowed_contexts))==len(allowed_contexts),'base-vault-context')
        for value in allowed_contexts:require(canonical(strict_json(value))==value,'base-vault-context')
        self.kms,self.nsm,self.key_arn=kms,nsm,key_arn
        self.namespace,self.authority,self.code=namespace,authority,code
        self.allowed=frozenset(allowed_contexts)
        self.recipient=RecipientProvisioner(kms,nsm,key_arn,namespace,authority)

    def _context(self,aad):
        require(type(aad) is bytes and aad in self.allowed,'base-vault-context')
        return {'application':'nockapp-zkid-v1','kind':'base-service-key','issuer':self.namespace,
            'state-authority':self.authority,'object-context-sha256':hashlib.sha256(aad).hexdigest()}

    def _key(self,aad,wrapped=None):
        context=self._context(aad);operation='GenerateDataKey' if wrapped is None else 'Decrypt'
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        public=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        bind={'profile':PROFILE,'operation':operation,'context':context,'code_identity':self.code,
            'wrapped_sha256':hashlib.sha256(wrapped).hexdigest() if wrapped is not None else None}
        document=self.nsm.attest(secrets.token_bytes(32),public,bytes.fromhex(digest(bind)))
        require(type(document) is bytes and 0<len(document)<=32768,'base-vault-attestation')
        parameters={'KeyId':self.key_arn,'EncryptionContext':copy.deepcopy(context),
            'Recipient':{'KeyEncryptionAlgorithm':'RSAES_OAEP_SHA_256','AttestationDocument':document}}
        if wrapped is None:
            response=self.kms.generate_data_key(**parameters,KeySpec='AES_256')
            allowed={'KeyId','CiphertextBlob','CiphertextForRecipient','Plaintext','ResponseMetadata'}
            require(type(response) is dict,'base-vault-response');wrapped=response.get('CiphertextBlob')
        else:
            require(type(wrapped) is bytes and 0<len(wrapped)<=6144,'base-vault-wrapped')
            response=self.kms.decrypt(**parameters,CiphertextBlob=wrapped,EncryptionAlgorithm='SYMMETRIC_DEFAULT')
            allowed={'KeyId','EncryptionAlgorithm','CiphertextForRecipient','Plaintext','ResponseMetadata'}
            require(type(response) is dict and response.get('EncryptionAlgorithm')=='SYMMETRIC_DEFAULT','base-vault-response')
        require(set(response)<=allowed and response.get('KeyId')==self.key_arn
            and response.get('Plaintext') in (None,b'') and type(wrapped) is bytes and 0<len(wrapped)<=6144,
            'base-vault-response')
        plaintext=self.recipient._decrypt_cms(key,response.get('CiphertextForRecipient'))
        require(type(plaintext) is bytes and len(plaintext)==32 and any(plaintext),'base-vault-key')
        return plaintext,wrapped

    def wrap(self,data,aad):
        try:
            require(type(data) is bytes and 0<len(data)<=4096,'base-vault-size')
            key,wrapped=self._key(aad);nonce=secrets.token_bytes(12)
            ciphertext=AESGCM(key).encrypt(nonce,data,aad)
            return canonical({'profile':PROFILE,'wrapped_key':base64.b64encode(wrapped).decode(),
                'nonce':base64.b64encode(nonce).decode(),'ciphertext':base64.b64encode(ciphertext).decode()})
        except Exception:raise Rejected('base-vault-unavailable') from None

    def unwrap(self,envelope,aad):
        try:
            require(type(envelope) is bytes and len(envelope)<=16384,'base-vault-size')
            value=strict_json(envelope)
            require(set(value)=={'profile','wrapped_key','nonce','ciphertext'} and value['profile']==PROFILE
                and canonical(value)==envelope,'base-vault-envelope')
            key,_=self._key(aad,_decode(value['wrapped_key'],6144))
            nonce=_decode(value['nonce'],12);require(len(nonce)==12,'base-vault-envelope')
            data=AESGCM(key).decrypt(nonce,_decode(value['ciphertext'],4112),aad)
            require(0<len(data)<=4096,'base-vault-size')
            return data
        except Exception:raise Rejected('base-vault-unavailable') from None
