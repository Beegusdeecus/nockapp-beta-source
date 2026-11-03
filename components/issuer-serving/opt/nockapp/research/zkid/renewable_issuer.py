"""Measured fixed-purpose issuer recovery with enclave-held renewable identities.

No initialization/migration, ambient credentials, caller-selected authority,
plaintext writer handoff, key generation, generic signer or public bootstrap.
"""
import copy
import ctypes
import hashlib
import os
from pathlib import Path
import resource
import socket
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from aws_transport import AwsJsonClient
from boot_attestation import serve_boot
from domain_authority import DynamoIssuerStore,DynamoBudget
from domain_issuer import IssuerApplication
from domain_pipeline import Native
from domain_state import PersistentDomainIssuer
from domain_transport import _decode,serve_connection
from enclave_nsm import Nsm
from issuer_supervisor import (APP,CA,PARENT_CID,RUNTIME_MANIFEST,REQUIRED as LEGACY_REQUIRED,
    CONFIG as LEGACY_CONFIG,validate_config as validate_issuer,validate_device,tls_context,relay as legacy_relay,
    listener,verify_runtime,_path)
from policy import ProviderClient,digest,hex_string,require,strict_json
from provisioning import RecipientProvisioner,validate_value
from workload_bootstrap import IdentityBootstrap
from workload_sessions import WorkloadCredentials,validate_config as validate_workload,PROFILE as WORKLOAD
from service_admission import ServiceAdmission

PROFILE='nockapp-zkid-renewable-issuer-v1'
CONFIG=APP+'/renewable-issuer-config.json'
REQUIRED=(LEGACY_REQUIRED-{LEGACY_CONFIG})|{CONFIG,APP+'/renewable_issuer.py',APP+'/renewable_issuer_entrypoint.py',APP+'/service_admission.py'}
ROLESANYWHERE_PORT=9445


def _workload_config(config,purpose,fingerprint):
    cfg=config['issuer']['authority'];account=config['issuer']['kms_key_arn'].split(':')[4]
    public=config['workloads'][purpose]
    return {'profile':WORKLOAD,'region':cfg['region'],'account':account,'purpose':purpose,'namespace':cfg['namespace'],
        'role_arn':cfg['roles'][purpose],'certificate_sha256':fingerprint,**public}


def validate_config(config):
    require(type(config) is dict and set(config)=={'profile','issuer','root_certificate','root_sha256','workloads'}
            and config['profile']==PROFILE,'renewable-issuer-config')
    return validate_identity_settings(config,('issuer','budget'))


def validate_identity_settings(config,purposes):
    """Shared public trust validation; each measured service fixes purposes."""
    authority=validate_issuer(config['issuer']);hex_string(config['root_sha256'],64)
    root_der=_decode(config['root_certificate'],8192)
    require(hashlib.sha256(root_der).hexdigest()==config['root_sha256'],'renewable-root')
    root=x509.load_der_x509_certificate(root_der)
    require(root.public_bytes(serialization.Encoding.DER)==root_der
            and root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,'renewable-root')
    require(type(config['workloads']) is dict and set(config['workloads'])==set(purposes),'renewable-workloads')
    for purpose,value in config['workloads'].items():
        require(type(value) is dict and set(value)=={'trust_anchor_arn','profile_arn','duration_seconds'},'renewable-workload')
        validate_workload(_workload_config(config,purpose,config['root_sha256']))
    return authority


def _envelope(envelope):
    require(type(envelope) is dict and set(envelope)=={'profile','parent_credentials','encrypted_secrets','identities'}
            and envelope['profile']==PROFILE,'renewable-bootstrap')
    parent=copy.deepcopy(validate_value('managed-writer-credentials',envelope['parent_credentials']))
    require(type(envelope['encrypted_secrets']) is dict
            and set(envelope['encrypted_secrets'])=={'blind-issuer-key','twitterapi-key'}
            and type(envelope['identities']) is dict and set(envelope['identities'])=={'issuer','budget'},'renewable-bootstrap')
    encrypted={k:_decode(v,6144) for k,v in envelope['encrypted_secrets'].items()};identities={}
    for purpose,record in envelope['identities'].items():
        require(type(record) is dict and set(record)=={'wrapped_seed','certificate_der'},'renewable-identity')
        identities[purpose]={'wrapped_seed':_decode(record['wrapped_seed'],6144),'certificate_der':_decode(record['certificate_der'],8192)}
    return parent,encrypted,identities


def relay(service):
    if service!='rolesanywhere':return legacy_relay(service)
    def dial():
        raw=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
        try:raw.settimeout(10);raw.connect((PARENT_CID,ROLESANYWHERE_PORT));return raw
        except Exception:raw.close();raise
    return dial


class RenewableIssuer:
    def __init__(self,config,code_identity,authority,ca,native,nsm,envelope):
        config=copy.deepcopy(config)
        require(validate_config(config)==authority,'renewable-authority');hex_string(code_identity,64)
        require(any(bytes.fromhex(code_identity)),'renewable-code')
        validate_device(nsm)  # Before ANY secret recovery or workload session.
        parent,encrypted,records=_envelope(envelope)
        cfg=config['issuer']['authority'];namespace=cfg['namespace'];region=cfg['region'];key=config['issuer']['kms_key_arn']
        kms=AwsJsonClient('kms',region,parent,tls_context(ca),relay('kms'))
        sources={};root=_decode(config['root_certificate'],8192)
        for purpose,record in records.items():
            # Recovery only. No create(), table initialize(), budget initialize()
            # or unused-policy upgrade exists anywhere in this assembly.
            identity=IdentityBootstrap(kms,nsm,key,namespace,authority,purpose,code_identity).recover(record['wrapped_seed'])
            public=_workload_config(config,purpose,hashlib.sha256(record['certificate_der']).hexdigest())
            session=identity.session(public,record['certificate_der'],root,config['root_sha256'],tls_context(ca),relay('rolesanywhere'))
            sources[purpose]=WorkloadCredentials(session)
        provision=RecipientProvisioner(kms,nsm,key,namespace,authority)
        state_key=provision.decrypt('blind-issuer-key',encrypted['blind-issuer-key'])
        issuer_client=AwsJsonClient('dynamodb',region,sources['issuer'],tls_context(ca),relay('dynamodb'))
        budget_client=AwsJsonClient('dynamodb',region,sources['budget'],tls_context(ca),relay('dynamodb'))
        table=cfg['table_arn'].split(':table/',1)[1];store=DynamoIssuerStore(issuer_client,table,namespace)
        state=PersistentDomainIssuer(store,state_key,namespace,native);_,core=state.load()
        view=store.public_view()
        require(view['definition_hash']==core.definition_hash and view['sequence']==core.sequence
                and view['public']==core.public,'issuer-public-state')
        budget=DynamoBudget(budget_client,table,namespace);budget.public_summary()
        api_key=provision.decrypt('twitterapi-key',encrypted['twitterapi-key'])
        self._application=IssuerApplication(state,ProviderClient(api_key,tls_context(ca),relay('provider'),budget=budget),lambda:int(time.time()))
        self._sources=sources;self._code_identity=code_identity;self._authority=authority
        self._admission=ServiceAdmission()

    def handle(self,stream):
        try:
            if not self._admission.admit():return
            # No static writer-session deadline. Each source refreshes separately
            # and fails closed before admission; the RPC is never retried here.
            for source in self._sources.values():source.get()
            serve_connection(stream,self._application,self._code_identity,self._authority)
        finally:stream.close()


def load_runtime(root=Path('/')):
    root=Path(root);manifest=verify_runtime(root,REQUIRED)
    config=strict_json(_path(root,CONFIG).read_bytes());authority=validate_config(config)
    return config,digest(manifest),authority


def main():
    try:
        os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        require(ctypes.CDLL(None).prctl(4,0,0,0,0)==0,'renewable-private-process')
        config,code,authority=load_runtime();nsm=Nsm();validate_device(nsm)
        instance=None;deadline=time.monotonic()+60
        with listener('bootstrap') as boot:
            while instance is None and time.monotonic()<deadline:
                try:raw,peer=boot.accept()
                except socket.timeout:continue
                if peer[0]!=PARENT_CID:raw.close();continue
                instance=serve_boot(raw,nsm,code,authority,config['issuer']['authority']['namespace'],
                    lambda envelope:RenewableIssuer(config,code,authority,Path('/')/CA,Native(),nsm,envelope))
        require(instance is not None,'renewable-bootstrap-unavailable')
        with listener('issuer') as service:
            while True:
                try:raw,peer=service.accept()
                except socket.timeout:continue
                if peer[0]!=PARENT_CID:raw.close();continue
                instance.handle(raw)
    except Exception:return 1  # No secret diagnostics or restart/reinitialization.


if __name__=='__main__':raise SystemExit(main())
