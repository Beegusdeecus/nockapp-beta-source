"""Public-only direct-root P256 workload certificate profile and validity checks."""
import hashlib
import time
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from policy import hex_string,require
from workload_identity_ceremony import PURPOSES

CA_NAME='nockapp-workload-ca'
ROOT_SECONDS=365*86400
LEAF_SECONDS=30*86400


def subject(namespace,purpose=None):
    hex_string(namespace,64)
    require(any(bytes.fromhex(namespace)) and (purpose is None or purpose in PURPOSES),'workload-cert-subject')
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,CA_NAME if purpose is None else 'nockapp-zkid-'+purpose),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,namespace)])


def key_hash(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _parse(raw,namespace,purpose):
    require(type(raw) is bytes and 0<len(raw)<=8192,'workload-cert-bytes')
    cert=x509.load_der_x509_certificate(raw)
    require(cert.public_bytes(serialization.Encoding.DER)==raw and cert.version==x509.Version.v3
        and cert.signature_hash_algorithm.name=='sha256' and isinstance(cert.public_key(),ec.EllipticCurvePublicKey)
        and isinstance(cert.public_key().curve,ec.SECP256R1) and cert.subject==subject(namespace,purpose),
        'workload-cert-profile')
    require({type(ext.value) for ext in cert.extensions}=={x509.BasicConstraints,x509.KeyUsage,
        x509.SubjectKeyIdentifier,x509.AuthorityKeyIdentifier} and
        all(ext.critical==isinstance(ext.value,(x509.BasicConstraints,x509.KeyUsage)) for ext in cert.extensions),
        'workload-cert-extensions')
    require(cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value==
        x509.SubjectKeyIdentifier.from_public_key(cert.public_key()),'workload-cert-extensions')
    require(cert.not_valid_before_utc<cert.not_valid_after_utc,'workload-cert-dates')
    return cert


def _usage(cert,ca):
    value=cert.extensions.get_extension_for_class(x509.KeyUsage).value
    # encipherOnly/decipherOnly are undefined when keyAgreement is false.
    return (value.digital_signature==(not ca) and not value.content_commitment and not value.key_encipherment
        and not value.data_encipherment and not value.key_agreement and value.key_cert_sign==ca and value.crl_sign==ca)


def parse_root(raw,namespace):
    cert=_parse(raw,namespace,None)
    require(cert.issuer==cert.subject and cert.extensions.get_extension_for_class(x509.BasicConstraints).value==
        x509.BasicConstraints(ca=True,path_length=0) and _usage(cert,True),'workload-cert-root')
    require(cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value==
        x509.AuthorityKeyIdentifier.from_issuer_public_key(cert.public_key()),'workload-cert-root')
    require((cert.not_valid_after_utc-cert.not_valid_before_utc).total_seconds()<=ROOT_SECONDS+300,'workload-cert-dates')
    cert.verify_directly_issued_by(cert);return cert


def parse_leaf(raw,root,namespace,purpose,public_key_sha256):
    require(purpose in PURPOSES,'workload-cert-purpose');hex_string(public_key_sha256,64)
    cert=_parse(raw,namespace,purpose)
    require(cert.issuer==root.subject and cert.extensions.get_extension_for_class(x509.BasicConstraints).value==
        x509.BasicConstraints(ca=False,path_length=None) and _usage(cert,False),'workload-cert-leaf')
    require(cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value==
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root.public_key()) and
        root.not_valid_before_utc<=cert.not_valid_before_utc<cert.not_valid_after_utc<=root.not_valid_after_utc
        and key_hash(cert.public_key())==public_key_sha256,'workload-cert-leaf')
    require((cert.not_valid_after_utc-cert.not_valid_before_utc).total_seconds()<=LEAF_SECONDS+300,'workload-cert-dates')
    cert.verify_directly_issued_by(root);return cert


def current(cert):
    require(cert.not_valid_before_utc.timestamp()<=time.time()<cert.not_valid_after_utc.timestamp(),
        'workload-cert-expired')
