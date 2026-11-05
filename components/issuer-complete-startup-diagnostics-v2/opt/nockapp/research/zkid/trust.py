"""Fresh production issuer enrollment, reusing the pinned neutral AWS verifier.

This validates an attested binding, NOT provider honesty or a credential's proof.
No local-test provider is accepted by enroll_production. New measurements and
issuer keys must be approved independently; historical TLSNotary PCRs do not
authorize this new application.
"""
import hashlib
from pathlib import Path
import ssl
import sys
import time

from policy import PROFILE, POLICY_HASH, SOURCE, Rejected, canonical, hex_string, require

VENDOR=Path(__file__).resolve().parents[3]/'TLSNotaryVendor'
sys.path.insert(0,str(VENDOR))
from vendor_service.attestation import verify_aws_document, validate_pcrs

ENROLLMENT='nockapp-zkid-issuer-enrollment-anoncreds-v1'


def binding(issuer_definition,revocation_definition,channel_certificate,code_identity):
    hex_string(issuer_definition,64);hex_string(revocation_definition,64);hex_string(code_identity,64)
    require(type(channel_certificate) is bytes and 0<len(channel_certificate)<=8192,'channel-certificate')
    return {'profile':ENROLLMENT,'credential_profile':PROFILE,'source':SOURCE,'policy':POLICY_HASH,
            'credential_scheme':'anoncreds-cl-0.2.3',
            'issuer_definition_sha256':issuer_definition,'revocation_definition_sha256':revocation_definition,
            'code_identity':code_identity,
            'channel_certificate_sha256':hashlib.sha256(channel_certificate).hexdigest()}


def enroll_production(document,nonce,expected_binding,approved):
    """approved is installer-owned configuration; never read it from evidence."""
    try:
        require(type(approved) is dict and set(approved)=={'mode','issuer_definition_sha256',
                'revocation_definition_sha256','code_identity','pcrs'}
                and approved['mode']=='production','production-trust-required')
        for field in ('issuer_definition_sha256','revocation_definition_sha256','code_identity'):
            hex_string(approved[field],64)
        hex_string(nonce,64)
        require(type(expected_binding) is dict and expected_binding.get('profile')==ENROLLMENT
                and expected_binding.get('credential_profile')==PROFILE
                and expected_binding.get('source')==SOURCE and expected_binding.get('policy')==POLICY_HASH
                and expected_binding.get('credential_scheme')=='anoncreds-cl-0.2.3',
                'issuer-binding-profile')
        require(expected_binding['issuer_definition_sha256']==approved['issuer_definition_sha256']
                and expected_binding['revocation_definition_sha256']==approved['revocation_definition_sha256']
                and expected_binding['code_identity']==approved['code_identity'],'issuer-not-approved')
        now_ms=int(time.time()*1000)
        payload=verify_aws_document(document,now_ms)
        require(payload.get('nonce')==bytes.fromhex(nonce),'issuer-quote-nonce')
        # Full CL definitions exceed NSM's public_key size limit. Bind their
        # independently approved SHA-256 digests, not caller-provided new keys.
        expected_keys=bytes.fromhex(approved['issuer_definition_sha256']+approved['revocation_definition_sha256'])
        require(payload.get('public_key')==expected_keys,'issuer-quote-key')
        require(payload.get('user_data')==hashlib.sha256(canonical(expected_binding)).digest(),'issuer-quote-binding')
        require(type(payload['timestamp']) is int and now_ms-120000<=payload['timestamp']<=now_ms+5000,
                'issuer-quote-stale')
        validate_pcrs(payload['pcrs'],approved['pcrs'])
        return {'profile':ENROLLMENT,'hardware_verified':True,
                'issuer_definition_sha256':approved['issuer_definition_sha256'],
                'policy':POLICY_HASH,'source_honesty_required':True}
    except Rejected:
        raise
    except Exception:
        raise Rejected('issuer-attestation-rejected') from None


def pinned_channel_context(certificate):
    require(type(certificate) is bytes and 0<len(certificate)<=8192,'channel-certificate')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
    context.check_hostname=True
    try:context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(certificate))
    except Exception:raise Rejected('channel-certificate') from None
    return context
