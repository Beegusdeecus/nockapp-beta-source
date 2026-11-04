"""Strictly separated insecure local assertions and real AWS Nitro verification."""
import datetime
import io
import time
import cbor2
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from .common import ROOT, b64, unb64, canonical, digest, require, core_run

AWS_ROOT = ROOT/'tests/fixtures/aws-nitro-root.pem'
AWS_ROOT_DER_SHA256 = '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b'
# Fingerprint is checked against the downloaded official certificate during setup.

def public_der(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

class LocalTestProvider:
    """This authority is controlled by the local host. It offers no hardware trust."""
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())

    @property
    def public_key(self):
        return b64(public_der(self.key.public_key()))

    def attest(self, challenge, bind):
        payload = {'provider': 'local-test-v1', 'insecure': True, 'challenge': challenge,
                   'binding': bind, 'timestamp_ms': int(time.time()*1000)}
        return {'provider': 'local-test-v1', 'payload': payload,
                'signature': b64(self.key.sign(canonical(payload), ec.ECDSA(hashes.SHA256())))}

class NitroProvider:
    def attest(self, challenge, bind):
        doc = core_run('nsm', {'nonce': list(bytes.fromhex(challenge)),
            'public_key': bind['notary_key']['data'],
            'user_data': list(bytes.fromhex(digest(canonical(bind))))})
        return {'provider': 'aws-nitro-v1', 'document': b64(bytes(doc['document']))}


def cbor_load(data):
    # Only the exact signed bytes are verified. Reject trailing CBOR objects.
    stream = io.BytesIO(data)
    value = cbor2.CBORDecoder(stream).decode()
    require(stream.read(1) == b'', 'trailing CBOR data')
    return value


def verify_aws_document(document, now_ms):
    """Cryptographic layer; archived fixture tests may explicitly supply historical time.

    Fresh service verification always calls this with the verifier's current time.
    This function alone does NOT authorize PCRs, binding or challenge.
    """
    require(0 < len(document) <= 32768, 'Nitro document size')
    cose = cbor_load(document)
    if isinstance(cose, cbor2.CBORTag):
        require(cose.tag == 18, 'wrong COSE tag')
        cose = cose.value
    require(isinstance(cose, (list, tuple)) and len(cose) == 4, 'invalid COSE Sign1')
    protected, unprotected, payload_bytes, signature = cose
    require(isinstance(protected, bytes) and cbor_load(protected) == {1: -35}, 'ES384 required')
    require(unprotected == {}, 'unprotected headers forbidden')
    require(isinstance(payload_bytes, bytes) and isinstance(signature, bytes) and len(signature) == 96, 'invalid COSE fields')
    payload = cbor_load(payload_bytes)
    required = {'module_id', 'digest', 'timestamp', 'pcrs', 'certificate', 'cabundle'}
    require(isinstance(payload, dict) and required <= payload.keys(), 'missing Nitro fields')
    require(set(payload) <= required | {'public_key', 'user_data', 'nonce'}, 'unknown Nitro field')
    require(all(payload[k] is not None for k in required), 'null mandatory Nitro field')
    require(isinstance(payload['module_id'], str) and payload['module_id'], 'module id')
    require(payload['digest'] == 'SHA384', 'Nitro digest')
    require(type(payload['timestamp']) is int and payload['timestamp'] > 0, 'Nitro timestamp')
    require(isinstance(payload['pcrs'], dict) and 1 <= len(payload['pcrs']) <= 32, 'Nitro PCR map')
    for index, value in payload['pcrs'].items():
        require(type(index) is int and 0 <= index < 32 and isinstance(value, bytes) and len(value) in (32,48,64), 'Nitro PCR field')
    for name, limit in [('nonce',512),('user_data',512),('public_key',1024)]:
        if payload.get(name) is not None:
            require(isinstance(payload[name],bytes) and len(payload[name]) <= limit, 'Nitro optional field')
    require(isinstance(payload['certificate'],bytes) and 0 < len(payload['certificate']) <= 4096, 'Nitro leaf size')
    require(isinstance(payload['cabundle'],list) and 1 <= len(payload['cabundle']) <= 16, 'Nitro chain size')
    require(all(isinstance(c,bytes) and 0 < len(c) <= 1024 for c in payload['cabundle']), 'Nitro CA size')
    root = x509.load_pem_x509_certificate(AWS_ROOT.read_bytes())
    require(root.fingerprint(hashes.SHA256()).hex() == AWS_ROOT_DER_SHA256, 'AWS trust anchor mismatch')
    leaf = x509.load_der_x509_certificate(payload['certificate'])
    chain = [x509.load_der_x509_certificate(c) for c in payload['cabundle']]
    moment = datetime.datetime.fromtimestamp(now_ms/1000, datetime.timezone.utc)
    for cert in [root, leaf] + chain:
        require(cert.not_valid_before_utc <= moment <= cert.not_valid_after_utc, 'expired attestation certificate')
    require(not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'attestation leaf is CA')
    require(leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature, 'attestation leaf usage')
    store = crypto.X509Store()
    store.add_cert(crypto.X509.from_cryptography(root))
    store.set_time(moment)
    # AWS archived chains omit AKI; OpenSSL strict profile rejects genuine chains.
    # Normal PKIX validation still enforces signatures, paths and critical extensions.
    for cert in [root] + chain:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        require(bc.critical and bc.value.ca, "invalid attestation CA constraints")
        require(cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign, "invalid attestation CA usage")
    # Bundle certificates are untrusted intermediates, never trust anchors.
    untrusted = [crypto.X509.from_cryptography(c) for c in chain if c.fingerprint(hashes.SHA256()) != root.fingerprint(hashes.SHA256())]
    crypto.X509StoreContext(store, crypto.X509.from_cryptography(leaf), untrusted).verify_certificate()
    key = leaf.public_key()
    require(isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP384R1), 'Nitro signing curve')
    sig = encode_dss_signature(int.from_bytes(signature[:48],'big'), int.from_bytes(signature[48:],'big'))
    key.verify(sig, cbor2.dumps(['Signature1', protected, b'', payload_bytes]), ec.ECDSA(hashes.SHA384()))
    return payload


def verify_attestation(attestation, bind, challenge, trust, now_ms=None):
    require(isinstance(challenge,str) and len(challenge)==64 and len(bytes.fromhex(challenge))==32, 'challenge format')
    now_ms = int(time.time()*1000) if now_ms is None else now_ms
    mode = trust['mode']
    require(mode in ('local-test', 'production'), 'unknown verification mode')
    if mode == 'production':
        require(attestation.get('provider') == 'aws-nitro-v1', 'production requires AWS hardware attestation')
        require(set(attestation)=={'provider','document'}, 'unexpected AWS envelope field')
        p = verify_aws_document(unb64(attestation['document']), now_ms)
        require(p.get('nonce') == bytes.fromhex(challenge), 'wrong Nitro challenge')
        require(p.get('public_key') == bytes(bind['notary_key']['data']), 'wrong Nitro signing key')
        require(p.get('user_data') == bytes.fromhex(digest(canonical(bind))), 'wrong Nitro binding')
        validate_pcrs(p['pcrs'], trust.get('pcrs', {}))
        timestamp = p['timestamp']
    else:
        require(attestation.get('provider') == 'local-test-v1', 'local-test provider required')
        require(set(attestation)=={'provider','payload','signature'}, 'unexpected test envelope field')
        p = attestation['payload']
        require(set(p)=={'provider','insecure','challenge','binding','timestamp_ms'}, 'unexpected test payload field')
        require(p['provider']=='local-test-v1' and p['insecure'] is True, 'invalid test marker')
        key = serialization.load_der_public_key(unb64(trust['test_authority']))
        require(isinstance(key,ec.EllipticCurvePublicKey) and isinstance(key.curve,ec.SECP256R1), 'test authority curve')
        key.verify(unb64(attestation['signature']),canonical(p),ec.ECDSA(hashes.SHA256()))
        require(p['challenge']==challenge, 'wrong test challenge')
        require(p['binding']==bind, 'wrong test binding')
        timestamp = p['timestamp_ms']
    require(type(timestamp) is int and now_ms-120000 <= timestamp <= now_ms+5000, 'stale or future attestation')
    require(bind['code_identity']==trust['code_identity'], 'unauthorized code identity')
    return {'provider': attestation['provider'], 'hardware_verified': mode=='production'}


def validate_pcrs(actual, expected_pcrs):
    require(set(expected_pcrs) >= {'0','1','2'}, 'PCR0/1/2 must be independently configured')
    for index, expected in expected_pcrs.items():
        require(index in {str(i) for i in range(32)}, 'invalid PCR index')
        expected_bytes = bytes.fromhex(expected)
        require(len(expected_bytes)==48 and any(expected_bytes), 'invalid or debug PCR expectation')
        require(actual.get(int(index)) == expected_bytes, 'Nitro measurement mismatch')


def inspect_attestation(attestation, bind, challenge, trust):
    """Historical cryptographic inspection, NEVER fresh hardware acceptance.

    The candidate time only selects historical certificate validation. It is
    trusted only AFTER normal signature/PCR/nonce/key/binding verification.
    There is no caller-selected clock and future documents are rejected.
    """
    if trust['mode'] == 'production':
        require(set(attestation) == {'provider', 'document'} and attestation['provider'] == 'aws-nitro-v1',
                'production archive requires AWS attestation')
        document = unb64(attestation['document'])
        require(0 < len(document) <= 32768, 'Nitro archive size')
        cose = cbor_load(document)
        if isinstance(cose, cbor2.CBORTag):
            require(cose.tag == 18, 'wrong archive COSE tag')
            cose = cose.value
        require(isinstance(cose, (list, tuple)) and len(cose) == 4 and isinstance(cose[2], bytes), 'archive COSE fields')
        payload = cbor_load(cose[2])
        require(isinstance(payload, dict), 'archive payload')
        moment = payload.get('timestamp')
    else:
        require(trust['mode'] == 'local-test' and attestation.get('provider') == 'local-test-v1', 'explicit archive test mode')
        moment = attestation['payload']['timestamp_ms']
    require(type(moment) is int and 0 < moment <= int(time.time()*1000) + 5000, 'future archive attestation')
    checked = verify_attestation(attestation, bind, challenge, trust, now_ms=moment)
    return {'provider': checked['provider'], 'hardware_signature_verified': checked['hardware_verified'],
            'hardware_verified': False, 'attestation_time_ms': moment, 'archival_only': True, 'fresh': False}
