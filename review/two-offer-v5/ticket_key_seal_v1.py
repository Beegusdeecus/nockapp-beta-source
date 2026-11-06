"""Internal one-shot envelope preparation for NEW host service keys only.

No CLI, key generation, ambient AWS identity, disk output, initialization,
permission changes or retries. A reviewed launcher must supply a private pipe
and an explicit setup KMS client. Existing Nitro issuer material is out of scope.
Python/OpenSSL do not guarantee erasure of every in-memory key copy.
"""
import base64
import os
import re

from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aws_transport import AwsJsonClient
from base_protocol import ReceiptKey
from policy import canonical,require,Rejected
from ticket_backend_boot_v1 import (validate,PRIVATE,private_key,der_public,
    read_private,harden_process,tls_context)
from ticket_backend_resources_v1 import SEALED,sha
from ticket_native_v1 import _decode
from ticket_aws_credentials_v1 import check_tls


def public_scope(backend,expected,key_arn,client):
    cfg=validate(backend,expected)
    prefix='arn:aws:kms:'+cfg['records']['region']+':'+cfg['records']['account_id']+':key/'
    require(type(key_arn) is str and re.fullmatch(re.escape(prefix)+
        r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',key_arn),'ticket-seal-kms-scope')
    # The runtime's decrypt-only subclass is intentionally ineligible here.
    # Explicit client possession is not proof of an appropriately narrow IAM
    # policy or of an AWS identity: those require reviewed setup/live evidence.
    require(type(client) is AwsJsonClient and client.service=='kms'
        and client.region==cfg['records']['region']
        and client.host=='kms.'+cfg['records']['region']+'.amazonaws.com','ticket-seal-setup-client')
    check_tls(client._context)
    return cfg


def checked_body(cfg,expected,body):
    require(type(body) is dict and set(body)=={'profile','role','config_sha256',
        'service_key_der','tls_private_key_der','tls_certificate_der'}
        and body['profile']==PRIVATE and body['role']==cfg['role']
        and body['config_sha256']==expected,'ticket-seal-body-scope')
    _,key=private_key(body['service_key_der'])
    # Enforce the same actual service authority as boot, without journal, RPC,
    # credential acquisition or application initialization.
    if cfg['role']=='payment':
        require(isinstance(key,rsa.RSAPrivateKey) and key.key_size==3072
            and key.public_key().public_numbers().e==65537
            and der_public(key.public_key())==_decode(cfg['offer']['terms']['ticket_spki'],1024),
            'ticket-seal-service-key')
    else:
        require(isinstance(key,ec.EllipticCurvePrivateKey)
            and isinstance(key.curve,ec.SECP256K1)
            and ReceiptKey(None,key).address==cfg['key_bindings'][cfg['role']],
            'ticket-seal-service-key')
    tls_context(cfg,body) # Existing SAN/SPKI/chain/usage/time and sealed-memfd checks.
    data=canonical(body)
    require(0<len(data)<=65536,'ticket-seal-body-size')
    return data


def seal(backend,expected,key_arn,descriptor,*,client):
    """Return encrypted bytes only; KMS is called once, after local admission.

    Any failure is terminal for this invocation. No operation here imports an
    existing encrypted packet or changes a live role, key, service or journal.
    Save returned ciphertext durably and review its digest before installation.
    """
    cfg=public_scope(backend,expected,key_arn,client) # Before private input or AWS.
    harden_process()
    try:
        data=checked_body(cfg,expected,read_private(descriptor))
        context={'application':'nockapp-ticket-backend-v1','role':cfg['role'],
            'backend-sha256':expected}
        check_tls(client._context)
        result=client.generate_data_key(KeyId=key_arn,KeySpec='AES_256',EncryptionContext=context)
        require(type(result) is dict and set(result)<={'KeyId','Plaintext','CiphertextBlob',
            'KeyMaterialId','ResponseMetadata'} and result.get('KeyId')==key_arn,
            'ticket-seal-kms-response')
        key=result.get('Plaintext');wrapped=result.get('CiphertextBlob')
        require(type(key) is bytes and len(key)==32 and any(key)
            and type(wrapped) is bytes and 0<len(wrapped)<=6144,'ticket-seal-kms-response')
        nonce=os.urandom(12)
        aad=canonical({'profile':SEALED,'role':cfg['role'],'backend_sha256':expected,
            'kms_key_arn':key_arn,'wrapped_key_sha256':sha(wrapped)})
        encode=lambda raw:base64.b64encode(raw).decode('ascii')
        return canonical({'profile':SEALED,'role':cfg['role'],'backend_sha256':expected,
            'kms_key_arn':key_arn,'wrapped_key':encode(wrapped),'nonce':encode(nonce),
            'ciphertext':encode(AESGCM(key).encrypt(nonce,data,aad))})
    except Exception:
        # Never propagate plaintext, provider replies or upstream exception text.
        raise Rejected('ticket-seal-unavailable') from None
