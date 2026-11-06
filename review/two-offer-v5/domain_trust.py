"""Composite issuer enrollment. Only fresh AWS documents can authorize a channel.

Installer approvals are independent inputs, never fields supplied by a browser
or learned from the server. Old CL and TLSNotary enrollment cannot be reused.
"""
import hashlib
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from domain_pipeline import PROFILE, definition_hash
from policy import SOURCE, POLICY_HASH, Rejected, canonical, hex_string, require
from trust import verify_aws_document, validate_pcrs, pinned_channel_context

ENROLLMENT = 'nockapp-zkid-composite-aws-enrollment-v1'
SCHEME = 'credx-bbs-domain-0.2.1'
HOSTNAME = 'zkid-issuer.local'
APPROVAL_FIELDS = {'mode','definition_hash','code_identity','state_authority_sha256','pcrs'}


def certificate_key(certificate):
    require(type(certificate) is bytes and 0 < len(certificate) <= 8192,'channel-certificate')
    try:
        cert = x509.load_der_x509_certificate(certificate)
        require(cert.public_bytes(serialization.Encoding.DER) == certificate,'channel-certificate')
        key = cert.public_key()
        require(isinstance(key,ec.EllipticCurvePublicKey) and isinstance(key.curve,ec.SECP256R1),
                'channel-certificate')
        # The pinned native NSM adapter accepts exactly 33 bytes. The full
        # certificate is separately bound in user_data; no ambiguity with the
        # historical secp256k1 notary key/profile is permitted.
        return key.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint)
    except Exception:
        raise Rejected('channel-certificate') from None


def validate_approval(approved):
    require(type(approved) is dict and set(approved) == APPROVAL_FIELDS
            and approved['mode'] == 'production','production-trust-required')
    for field in ('definition_hash','code_identity','state_authority_sha256'):
        hex_string(approved[field],64)
        require(any(bytes.fromhex(approved[field])),'issuer-not-approved')
    pcrs = approved['pcrs']
    require(type(pcrs) is dict,'issuer-pcr-approval')
    # Validate expectations even before receiving a document, including zero PCRs.
    try:
        validate_pcrs({int(k):bytes.fromhex(v) for k,v in pcrs.items()},pcrs)
    except Exception:
        raise Rejected('issuer-pcr-approval') from None


def binding(view, certificate, code_identity, state_authority_sha256):
    require(type(view) is dict and set(view) == {'definition_hash','public','sequence'}
            and type(view['public']) is dict and type(view['sequence']) is int
            and view['sequence'] >= 0,'issuer-registry')
    require(definition_hash(view['public']) == view['definition_hash'],'issuer-definition')
    for value in (view['definition_hash'],code_identity,state_authority_sha256):
        hex_string(value,64)
        require(any(bytes.fromhex(value)),'issuer-not-approved')
    certificate_key(certificate)
    return {'profile':ENROLLMENT,'credential_profile':PROFILE,'credential_scheme':SCHEME,
            'source':SOURCE,'policy':POLICY_HASH,'definition_hash':view['definition_hash'],
            'registry_sha256':hashlib.sha256(canonical(view)).hexdigest(),
            'code_identity':code_identity,'state_authority_sha256':state_authority_sha256,
            'channel_certificate_sha256':hashlib.sha256(certificate).hexdigest()}


def enroll_production(document, nonce, view, certificate, approved):
    """No injectable verifier, local-test mode, historical clock or PCR fallback."""
    try:
        validate_approval(approved)
        hex_string(nonce,64)
        expected = binding(view,certificate,approved['code_identity'],approved['state_authority_sha256'])
        require(expected['definition_hash'] == approved['definition_hash'],'issuer-not-approved')
        now_ms = int(time.time()*1000)
        require(type(document) is bytes and 0 < len(document) <= 32768,'issuer-document')
        payload = verify_aws_document(document,now_ms)
        require(payload.get('nonce') == bytes.fromhex(nonce),'issuer-quote-nonce')
        require(payload.get('public_key') == certificate_key(certificate),'issuer-quote-key')
        require(payload.get('user_data') == hashlib.sha256(canonical(expected)).digest(),'issuer-quote-binding')
        require(type(payload.get('timestamp')) is int
                and now_ms-120000 <= payload['timestamp'] <= now_ms+5000,'issuer-quote-stale')
        validate_pcrs(payload['pcrs'],approved['pcrs'])
        return expected
    except Rejected:
        raise
    except Exception:
        raise Rejected('issuer-attestation-rejected') from None
