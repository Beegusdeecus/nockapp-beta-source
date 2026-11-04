"""Durable WRAPPED service recovery objects; no plaintext key files or fallback.

KMS adapter must enforce attestation/permissions in deployment. The local tests
inject a labelled software KMS fixture; this module claims no hardware trust.
"""
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from base_protocol import ReceiptKey, read
from policy import canonical, require, strict_json

PROFILE='nockapp-base-wrapped-service-keys-v1'
TRANSACTION_PROFILE='nockapp-base-wrapped-transaction-key-v1'


def transaction_context(context):
    from base_transactions import hex_data
    require(type(context) is dict and set(context)=={'profile','role','chain_id','contract','address'}
        and context['profile']==TRANSACTION_PROFILE and context['role'] in ('issuer-updater','sponsor')
        and type(context['chain_id']) is int and context['chain_id'] in (31337,84532),'transaction-key-context')
    hex_data(context['contract'],20);hex_data(context['address'],20)
    return canonical(context)


def wrap_transaction_key(kms,replicas,context,key,rpc):
    aad=transaction_context(context)
    require(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256K1),
        'transaction-key')
    require(ReceiptKey(rpc,key).address.lower()==context['address'].lower(),'transaction-key-mismatch')
    data=canonical({'profile':TRANSACTION_PROFILE,'private_der':key.private_bytes(
        serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).hex()})
    wrapped=kms.wrap(data,aad)
    require(type(wrapped) is bytes and len(wrapped)>28,'wrapped-key')
    return replicas.put(wrapped)


def recover_transaction_key(kms,replicas,digest,context,rpc):
    from base_transactions import ProtectedSigner
    aad=transaction_context(context)
    require(int(rpc.call('eth_chainId'),16)==context['chain_id'],'transaction-key-chain')
    value=strict_json(kms.unwrap(replicas.get(digest),aad))
    require(set(value)=={'profile','private_der'} and value['profile']==TRANSACTION_PROFILE,'transaction-key-record')
    key=serialization.load_der_private_key(bytes.fromhex(value['private_der']),password=None)
    require(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256K1),
        'transaction-key')
    recovered=ReceiptKey(rpc,key)
    require(recovered.address.lower()==context['address'].lower(),'transaction-key-mismatch')
    if context['role']=='issuer-updater':
        require('0x'+read(rpc,context['contract'],'updater()')[-40:].lower()==recovered.address.lower(),
            'transaction-key-updater')
    return ProtectedSigner(rpc,recovered)


def wrap_service_keys(kms,replicas,context,state_key,receipt_key):
    require(type(state_key) is bytes and len(state_key)==32,'state-key')
    require(type(context) is dict and set(context)=={'profile','definition','application'}
            and context['profile']==PROFILE,'key-context')
    data=canonical({'profile':PROFILE,'state_key':state_key.hex(),
        'receipt_private_der':receipt_key.private_bytes(serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).hex()})
    wrapped=kms.wrap(data,canonical(context))
    require(type(wrapped) is bytes and len(wrapped)>28,'wrapped-key')
    # This public digest must be in the approved recovery manifest. It supplies
    # neither the key nor the ciphertext's availability by itself.
    return replicas.put(wrapped)


def recover_service_keys(kms,replicas,digest,context,rpc,contract):
    require(type(context) is dict and set(context)=={'profile','definition','application'}
            and context['profile']==PROFILE,'key-context')
    require(read(rpc,contract,'application()').lower()==context['application'].lower(),'key-context')
    issuer='0x'+read(rpc,contract,'issuer()')[-40:]
    require(read(rpc,issuer,'definition()')=='0x'+context['definition'],'key-context')
    data=kms.unwrap(replicas.get(digest),canonical(context))
    value=strict_json(data)
    require(set(value)=={'profile','state_key','receipt_private_der'} and value['profile']==PROFILE,'key-record')
    key=serialization.load_der_private_key(bytes.fromhex(value['receipt_private_der']),password=None)
    require(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256K1),'receipt-key')
    recovered=ReceiptKey(rpc,key)
    require(recovered.address.lower()=='0x'+read(rpc,contract,'signer()')[-40:].lower(),'receipt-key-mismatch')
    state_key=bytes.fromhex(value['state_key']);require(len(state_key)==32,'state-key')
    return state_key,recovered
