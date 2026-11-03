"""Admit current public leaf records at boot without changing identity/root.

Normal boot reads three public certificate heads. Expired-leaf recovery also
needs read access to the existing encrypted CA/identity selections and CAS
write access restricted to the same three public certificate heads.
Without a recovery callback this path is read-only. A measured boot recovery
callback can renew expired selected leaves from the existing protected CA;
missing records never trigger initialization or fallback.
"""
import base64
import copy
import hashlib
import time

from cryptography import x509
from base_managed_storage import DynamoObjects
from domain_authority import _number
from domain_transport import _decode
from policy import canonical,digest,require,strict_json
from workload_bootstrap import WorkloadIdentity
from workload_ca import CERT,scope,certificate_suffix
from workload_identity_ceremony import PROFILE as SELECTION,public_key_hash
from workload_certificates import parse_root,parse_leaf,current as valid_now


def certificate_record(objects,identity,settings,fallback_der,root_sha256):
    require(isinstance(objects,DynamoObjects) and isinstance(identity,WorkloadIdentity)
            and objects.namespace==identity.scope['issuer'], 'workload-restart-source')
    purpose=identity.scope['purpose']
    selected={'profile':SELECTION,'context':identity.scope,'key_arn':identity.key_arn,
              'wrapped_seed':base64.b64encode(identity._wrapped).decode(),
              'public_key_sha256':public_key_hash(identity)}
    expected=scope(identity.scope['issuer'],identity.scope['state-authority'],identity.key_arn)
    suffix=certificate_suffix(expected,purpose)
    item=objects._get(suffix)
    require(type(item) is dict and set(item)=={'id','revision','data'}
            and item['id']==objects.key(suffix)['id'] and type(item['data']) is dict
            and set(item['data'])=={'B'}, 'workload-restart-head')
    raw=item['data']['B']
    require(type(raw) is bytes and 0<len(raw)<=16384, 'workload-restart-head')
    row=strict_json(raw,max_bytes=16384)
    require(canonical(row)==raw and set(row)=={'profile','scope','purpose','revision','root_sha256',
            'identity_selection_sha256','certificate_der','certificate_sha256'}
            and row['profile']==CERT and row['scope']==expected and row['purpose']==purpose
            and type(row['revision']) is int and 1<=row['revision']<2**53
            and _number(item['revision'])==row['revision'] and row['root_sha256']==root_sha256
            and row['identity_selection_sha256']==digest(selected), 'workload-restart-binding')
    der=_decode(row['certificate_der'],8192)
    require(hashlib.sha256(der).hexdigest()==row['certificate_sha256']
            and type(fallback_der) is bytes
            and hashlib.sha256(fallback_der).hexdigest()==settings['certificate_sha256'], 'workload-restart-pin')
    previous=x509.load_der_x509_certificate(fallback_der);current=x509.load_der_x509_certificate(der)
    require(previous.public_key()==identity._key.public_key()
            and current.not_valid_after_utc>=previous.not_valid_after_utc
            and current.not_valid_before_utc>=previous.not_valid_before_utc, 'workload-restart-rollback')
    return row


def session(objects,identity,settings,fallback_der,root,root_sha256,context,dial=None,*,recover=None):
    row=certificate_record(objects,identity,settings,fallback_der,root_sha256)
    der=_decode(row['certificate_der'],8192);leaf=x509.load_der_x509_certificate(der)
    if leaf.not_valid_after_utc.timestamp()<=time.time() and recover is not None:
        # An expired leaf cannot log in to AWS. Authenticate its historical
        # root/key binding before allowing the private boot recovery path.
        require(hashlib.sha256(root).hexdigest()==root_sha256, 'workload-restart-root')
        ca=parse_root(root,identity.scope['issuer']);valid_now(ca)
        parse_leaf(der,ca,identity.scope['issuer'],identity.scope['purpose'],public_key_hash(identity))
        old_revision=row['revision'];old_end=leaf.not_valid_after_utc
        recover(identity.scope['purpose'],old_revision)
        row=certificate_record(objects,identity,settings,fallback_der,root_sha256)
        der=_decode(row['certificate_der'],8192)
        require(row['revision']>old_revision and x509.load_der_x509_certificate(der).not_valid_after_utc>old_end,
                'workload-restart-renewal-unconfirmed')
    cfg=copy.deepcopy(settings);cfg['certificate_sha256']=row['certificate_sha256']
    # The table cannot supply authority: original pinned root and recovered key
    # independently check signatures, subject, key possession and current dates.
    return identity.session(cfg,der,root,root_sha256,context,dial)
