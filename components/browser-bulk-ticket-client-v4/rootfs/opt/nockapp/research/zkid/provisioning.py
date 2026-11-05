"""KMS Recipient provisioning inside the measured enclave, never plaintext KMS.

The supervisor owns an authenticated, fixed-endpoint KMS client and Nsm adapter.
This is not a public RPC, a credential discovery mechanism or resource creator.
No ambient environment/profile credentials are read by this module.
"""
import hashlib
import os
from pathlib import Path
import re
import secrets
import subprocess
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from credential import private_child
from policy import POLICY_HASH, Rejected, canonical, hex_string, require, strict_json

PROFILE = 'nockapp-zkid-kms-recipient-secrets-v1'
KINDS = {'twitterapi-key','blind-issuer-key','managed-writer-credentials'}
OPENSSL = Path('/usr/bin/openssl')


def encryption_context(kind, namespace, authority, *, role=None, purpose=None):
    require(type(kind) is str and kind in KINDS,'provision-kind')
    hex_string(namespace,64);hex_string(authority,64)
    require(any(bytes.fromhex(namespace)) and any(bytes.fromhex(authority)),'provision-context')
    context={'application':'nockapp-zkid-v1','kind':kind,'issuer':namespace,'state-authority':authority}
    if role is not None or purpose is not None:
        require(kind == 'managed-writer-credentials' and purpose in ('issuer','budget')
                and type(role) is str and re.fullmatch(r'arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+',role),
                'provision-context')
        context.update({'role':role,'purpose':purpose})
    return context


def validate_value(kind,value):
    if kind == 'twitterapi-key':
        require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]{16,256}',value),'provision-value')
    elif kind == 'blind-issuer-key':
        # This key seals the native issuer signing state; it is not a holder secret.
        hex_string(value,64);require(any(bytes.fromhex(value)),'provision-value')
        return bytes.fromhex(value)
    elif kind == 'managed-writer-credentials':
        require(type(value) is dict and set(value) == {'access_key_id','secret_access_key','session_token','expires_at'},
                'provision-value')
        require(type(value['access_key_id']) is str and re.fullmatch(r'ASIA[A-Z0-9]{16}',value['access_key_id'])
                and type(value['secret_access_key']) is str and re.fullmatch(r'[A-Za-z0-9/+=]{40}',value['secret_access_key'])
                and type(value['session_token']) is str and re.fullmatch(r'[A-Za-z0-9/+=]{16,4096}',value['session_token'])
                and type(value['expires_at']) is int
                and int(time.time())+60 <= value['expires_at'] <= int(time.time())+43200,'provision-value')
    else:raise Rejected('provision-kind')
    return value


class RecipientProvisioner:
    """Internal boot component. Positive actual KMS/IAM acceptance remains a gate.

    The KMS client MUST be constructed by measured code with explicit parent
    decrypt-only credentials, approved endpoint/CA, no retries and no logging.
    Writer credentials are separately encrypted and never returned to the parent.
    """
    def __init__(self,client,nsm,key_arn,namespace,authority,*,openssl=OPENSSL):
        require(type(key_arn) is str and re.fullmatch(
            r'arn:aws:kms:[a-z]{2}-[a-z]+-[1-9]:[0-9]{12}:key/[a-f0-9-]{36}',key_arn),'provision-key')
        encryption_context('blind-issuer-key',namespace,authority)
        self._client = client;self._nsm = nsm;self.key_arn = key_arn
        self.namespace = namespace;self.authority = authority
        self._openssl = Path(openssl);self._openssl_sha = hashlib.sha256(self._openssl.read_bytes()).digest()

    def _decrypt_cms(self,recipient,encrypted):
        """OpenSSL's CMS parser handles KMS BER/DER without a new ASN.1 parser.

        Only authenticated KMS responses enter here. The RSA key is fresh per
        call and never written to a disk file, argv, evidence or exception text.
        """
        require(type(encrypted) is bytes and 0 < len(encrypted) <= 6144,'provision-response')
        fd = os.memfd_create('zkid-kms-recipient',os.MFD_CLOEXEC)
        try:
            require(hashlib.sha256(self._openssl.read_bytes()).digest() == self._openssl_sha,'provision-runtime')
            os.write(fd,recipient.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
            result = subprocess.run([str(self._openssl),'cms','-decrypt','-binary','-inform','DER',
                '-inkey',f'/proc/self/fd/{fd}'],input=encrypted,capture_output=True,pass_fds=(fd,),
                timeout=5,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'},
                preexec_fn=private_child)
            require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 4096,
                    'provision-response')
            return result.stdout
        finally:os.close(fd)

    def decrypt(self,kind,ciphertext, *, role=None, purpose=None):
        try:
            context = encryption_context(kind,self.namespace,self.authority,role=role,purpose=purpose)
            require(type(ciphertext) is bytes and 0 < len(ciphertext) <= 6144,'provision-ciphertext')
            recipient = rsa.generate_private_key(public_exponent=65537,key_size=2048)
            public = recipient.public_key().public_bytes(serialization.Encoding.DER,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo)
            require(len(public) == 294,'provision-recipient')
            nonce = secrets.token_bytes(32)
            bind = {'profile':PROFILE,'policy':POLICY_HASH,'context':context,'key_arn':self.key_arn,
                    'ciphertext_sha256':hashlib.sha256(ciphertext).hexdigest()}
            document = self._nsm.attest(nonce,public,hashlib.sha256(canonical(bind)).digest())
            require(type(document) is bytes and 0 < len(document) <= 32768,'provision-document')
            response = self._client.decrypt(KeyId=self.key_arn,CiphertextBlob=ciphertext,
                EncryptionAlgorithm='SYMMETRIC_DEFAULT',EncryptionContext=context,
                Recipient={'KeyEncryptionAlgorithm':'RSAES_OAEP_SHA_256','AttestationDocument':document})
            require(type(response) is dict and set(response) <= {'KeyId','EncryptionAlgorithm','CiphertextForRecipient',
                                                               'Plaintext','ResponseMetadata'}
                    and response.get('KeyId') == self.key_arn
                    and response.get('EncryptionAlgorithm') == 'SYMMETRIC_DEFAULT'
                    and response.get('Plaintext') in (None,b'')
                    and type(response.get('CiphertextForRecipient')) is bytes,'provision-response')
            plaintext = self._decrypt_cms(recipient,response['CiphertextForRecipient'])
            # GenerateDataKey returns raw AES bytes, not the older wrapped JSON
            # fixture format. BOTH formats still require attested Recipient CMS.
            if kind == 'blind-issuer-key' and len(plaintext) == 32:
                require(any(plaintext),'provision-value');return plaintext
            secret = strict_json(plaintext)
            require(set(secret) == {'profile','context','value'} and secret['profile'] == PROFILE
                    and secret['context'] == context,'provision-context')
            return validate_value(kind,secret['value'])
        except Exception:
            # No plaintext fallback, retries or diagnostics, including CMS errors.
            raise Rejected('provisioning-unavailable') from None

    def generate_state_key(self):
        """Internal initial ceremony only. Never returns a plaintext KMS response.

        Raw key stays in the enclave controller; only its KMS-wrapped copy may
        be delivered to the provisioner for persistent production boot recovery.
        """
        try:
            context=encryption_context('blind-issuer-key',self.namespace,self.authority)
            recipient=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            public=recipient.public_key().public_bytes(serialization.Encoding.DER,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)
            bind={'profile':PROFILE,'operation':'GenerateDataKey','key_arn':self.key_arn,'context':context,
                  'key_spec':'AES_256','policy':POLICY_HASH}
            document=self._nsm.attest(secrets.token_bytes(32),public,hashlib.sha256(canonical(bind)).digest())
            require(type(document) is bytes and 0<len(document)<=32768,'provision-document')
            response=self._client.generate_data_key(KeyId=self.key_arn,KeySpec='AES_256',EncryptionContext=context,
                Recipient={'KeyEncryptionAlgorithm':'RSAES_OAEP_SHA_256','AttestationDocument':document})
            require(type(response) is dict and set(response)<={'KeyId','CiphertextBlob','CiphertextForRecipient',
                                                              'Plaintext','ResponseMetadata'}
                    and response.get('KeyId')==self.key_arn and response.get('Plaintext') in (None,b''),
                    'provision-response')
            wrapped=response.get('CiphertextBlob')
            require(type(wrapped) is bytes and 0<len(wrapped)<=6144,'provision-response')
            key=self._decrypt_cms(recipient,response.get('CiphertextForRecipient'))
            require(len(key)==32 and any(key),'provision-value')
            return key,wrapped
        except Exception:raise Rejected('provisioning-unavailable') from None
