"""Measured issuer assembly. No local state, test device or plaintext fallback.

Only encrypted KMS secrets and decrypt-only parent credentials arrive at boot.
All authority/endpoint/code choices come from the measured immutable image.
The public service can reach only IssuerApplication through the bound channel.
"""
import base64
import copy
import ctypes
import hashlib
import os
from pathlib import Path, PurePosixPath
import resource
import re
import secrets
import socket
import ssl
import time

from aws_transport import AwsJsonClient
from domain_authority import DynamoIssuerStore,DynamoBudget,authority_identity
from domain_issuer import IssuerApplication
from domain_pipeline import Native
from domain_state import PersistentDomainIssuer
from domain_transport import serve_connection
from boot_attestation import serve_boot
from enclave_nsm import Nsm
from policy import ProviderClient,Rejected,canonical,digest,hex_string,require,strict_json
from provisioning import RecipientProvisioner,validate_value
from trust import verify_aws_document

PROFILE='nockapp-zkid-measured-issuer-boot-v1'
MANIFEST='nockapp-zkid-complete-runtime-manifest-v1'
APP='opt/nockapp/research/zkid'
CONFIG=APP+'/issuer-config.json'
CA=APP+'/runtime-ca.pem'
RUNTIME_MANIFEST=APP+'/runtime-manifest.json'
PARENT_CID=3
PORTS={'issuer':9440,'kms':9441,'dynamodb':9442,'provider':9443,'bootstrap':9444}
REQUIRED={CONFIG,CA,APP+'/issuer_supervisor.py',APP+'/issuer_entrypoint.py',
          APP+'/policy.py',APP+'/domain_issuer.py',APP+'/domain_pipeline.py',APP+'/domain_state.py',
          APP+'/domain_authority.py',APP+'/aws_transport.py',APP+'/provisioning.py',APP+'/enclave_nsm.py',
          APP+'/domain_transport.py',APP+'/domain_trust.py',APP+'/trust.py',APP+'/credential.py',
          APP+'/boot_attestation.py',APP+'/workload_sessions.py',APP+'/workload_bootstrap.py',
          APP+'/budget.py',APP+'/setup_aws_sdk.py',APP+'/aws-sdk.lock.json',
          APP+'/domain-crypto/target/debug/nockapp-zkid-domain-research',
          APP+'/enclave-nsm/target/release/nockapp-zkid-enclave-nsm'}


def _path(root,relative):
    require(type(relative) is str,'runtime-path')
    name=PurePosixPath(relative)
    require(type(relative) is str and name.parts and not name.is_absolute() and '..' not in name.parts
            and str(name)==relative and not any(p.startswith('.env') for p in name.parts),'runtime-path')
    path=root/relative
    # Runtime packages use regular files. No mutable symlink may redirect a pin.
    require(not any(p.is_symlink() for p in [path,*path.parents]),'runtime-path')
    return path


def validate_config(config):
    require(type(config) is dict and set(config)=={'profile','authority','kms_key_arn'}
            and config['profile']==PROFILE,'issuer-boot-config')
    authority=authority_identity(config['authority']);arn=config['kms_key_arn']
    require(type(arn) is str and re.fullmatch(
        r'arn:aws:kms:[a-z]{2}-[a-z]+-[1-9]:[0-9]{12}:key/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',arn)
        and arn.split(':')[3:5]==config['authority']['table_arn'].split(':')[3:5],'issuer-boot-config')
    return authority


def verify_runtime(root,required):
    """Image-owned manifest, not evidence received from the parent/client."""
    root=Path(root)
    manifest=strict_json(_path(root,RUNTIME_MANIFEST).read_bytes(),max_bytes=1048576)
    require(set(manifest)=={'profile','files'} and manifest['profile']==MANIFEST
            and type(manifest['files']) is dict and required<=set(manifest['files'])
            and len(manifest['files'])<=2048,'runtime-manifest')
    for relative,record in manifest['files'].items():
        require(type(record) is dict and set(record)=={'sha256','bytes','mode'},'runtime-manifest')
        hex_string(record['sha256'],64)
        require(type(record['bytes']) is int and record['bytes']>=0 and type(record['mode']) is int
                and 0<=record['mode']<=0o777,'runtime-manifest')
        path=_path(root,relative);info=path.stat()
        require(path.is_file() and info.st_size==record['bytes'] and info.st_mode&0o777==record['mode']
                and hashlib.sha256(path.read_bytes()).hexdigest()==record['sha256'],'runtime-file-changed')
    return manifest


def load_runtime(root=Path('/')):
    root=Path(root);manifest=verify_runtime(root,REQUIRED)
    config=strict_json(_path(root,CONFIG).read_bytes())
    authority=validate_config(config)
    return config,digest(manifest),authority


def relay(service):
    """No caller-selected URL, address, parent CID or network fallback."""
    require(service in ('kms','dynamodb','provider'),'issuer-relay')
    def dial():
        stream=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
        try:
            stream.settimeout(10);stream.connect((PARENT_CID,PORTS[service]));return stream
        except Exception:
            stream.close();raise Rejected('issuer-relay-unavailable') from None
    return dial


def tls_context(ca):
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(ca))
    return context


def validate_device(nsm):
    """Genuine fresh NSM and non-debug PCR0/1/2 before any provisioning."""
    nonce=secrets.token_bytes(32);key=b'\x02'+secrets.token_bytes(32)
    data=hashlib.sha256(PROFILE.encode()).digest()
    document=nsm.attest(nonce,key,data)
    now=int(time.time()*1000);payload=verify_aws_document(document,now)
    require(payload.get('nonce')==nonce and payload.get('public_key')==key and payload.get('user_data')==data
            and type(payload.get('timestamp')) is int and now-120000<=payload['timestamp']<=now+5000,
            'issuer-device')
    require(all(type(payload['pcrs'].get(i)) is bytes and len(payload['pcrs'][i])==48
                and any(payload['pcrs'][i]) for i in range(3)),'issuer-debug-device')


def _ciphertexts(envelope):
    require(type(envelope) is dict and set(envelope)=={'profile','parent_credentials','encrypted_secrets'}
            and envelope['profile']==PROFILE,'issuer-bootstrap')
    parent=copy.deepcopy(validate_value('managed-writer-credentials',envelope['parent_credentials']))
    encrypted=envelope['encrypted_secrets']
    require(type(encrypted) is dict and set(encrypted)=={'twitterapi-key','blind-issuer-key','issuer-writer','budget-writer'},
            'issuer-bootstrap')
    result={}
    for name,value in encrypted.items():
        require(type(value) is str and 0<len(value)<=8192,'issuer-bootstrap')
        try:blob=base64.b64decode(value,validate=True)
        except Exception:raise Rejected('issuer-bootstrap') from None
        require(0<len(blob)<=6144 and base64.b64encode(blob).decode()==value,'issuer-bootstrap')
        result[name]=blob
    return parent,result


class IssuerSupervisor:
    """Resume an existing provisioned issuer. Missing state never creates keys.

    No fixture/provider injection arguments and no unmeasured endpoint config.
    Tests patch dependencies externally; this class has no simulated boot mode.
    """
    def __init__(self,config,code_identity,authority,ca,native,nsm,envelope):
        config=copy.deepcopy(config)
        require(validate_config(config)==authority,'issuer-authority')
        hex_string(code_identity,64);require(any(bytes.fromhex(code_identity)),'issuer-code-identity')
        validate_device(nsm)
        parent,encrypted=_ciphertexts(envelope)
        cfg=config['authority'];namespace=cfg['namespace'];region=cfg['region']
        kms=AwsJsonClient('kms',region,parent,tls_context(ca),relay('kms'))
        provision=RecipientProvisioner(kms,nsm,config['kms_key_arn'],namespace,authority)
        state_key=provision.decrypt('blind-issuer-key',encrypted['blind-issuer-key'])
        issuer_credentials=provision.decrypt('managed-writer-credentials',encrypted['issuer-writer'],
                                               role=cfg['roles']['issuer'],purpose='issuer')
        budget_credentials=provision.decrypt('managed-writer-credentials',encrypted['budget-writer'],
                                               role=cfg['roles']['budget'],purpose='budget')
        issuer_client=AwsJsonClient('dynamodb',region,issuer_credentials,tls_context(ca),relay('dynamodb'))
        budget_client=AwsJsonClient('dynamodb',region,budget_credentials,tls_context(ca),relay('dynamodb'))
        table=cfg['table_arn'].split(':table/',1)[1]
        store=DynamoIssuerStore(issuer_client,table,namespace)
        state=PersistentDomainIssuer(store,state_key,namespace,native)
        state.upgrade_unused_beta_policy()  # Exact prior unused policy only; same signer/counter.
        _,core=state.load()  # No initialize/regenerate fallback on any error.
        view=store.public_view()
        require(view['definition_hash']==core.definition_hash and view['sequence']==core.sequence
                and view['public']==core.public,'issuer-public-state')
        budget=DynamoBudget(budget_client,table,namespace);budget.public_summary()
        api_key=provision.decrypt('twitterapi-key',encrypted['twitterapi-key'])
        provider=ProviderClient(api_key,tls_context(ca),relay('provider'),budget=budget)
        self._application=IssuerApplication(state,provider,lambda:int(time.time()))
        self._code_identity=code_identity;self._authority=authority
        self._deadline=min(issuer_credentials['expires_at'],budget_credentials['expires_at'])-5

    def handle(self,stream):
        if int(time.time())>=self._deadline:
            stream.close();return
        # All application operations, source TLS and private signer calls remain
        # within this measured assembly. No action-proof/public-ID RPC exists.
        serve_connection(stream,self._application,self._code_identity,self._authority)


def listener(kind):
    require(kind in ('bootstrap','issuer'),'issuer-listener')
    stream=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
    stream.bind((socket.VMADDR_CID_ANY,PORTS[kind]));stream.listen(2);stream.settimeout(5)
    return stream


def main():
    # No secrets/configuration in argv/environment; no status dump to stdout.
    try:
        os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        require(ctypes.CDLL(None).prctl(4,0,0,0,0)==0,'issuer-private-process')
        config,identity,authority=load_runtime()
        nsm=Nsm();validate_device(nsm)
        # Bootstrap is distinct from public issuer RPC and carries NO plaintext
        # provider/state/writer secret, only parent decrypt-only credentials.
        supervisor=None;boot_deadline=time.monotonic()+60
        def construct(envelope):
            return IssuerSupervisor(config,identity,authority,Path('/')/CA,Native(),nsm,envelope)
        with listener('bootstrap') as bootstrap:
            while supervisor is None and time.monotonic()<boot_deadline:
                try:stream,peer=bootstrap.accept()
                except socket.timeout:continue
                if peer[0]!=PARENT_CID:stream.close();continue
                supervisor=serve_boot(stream,nsm,identity,authority,config['authority']['namespace'],construct)
        require(supervisor is not None,'issuer-bootstrap-unavailable')
        # Serial admission is intentional: no unbounded worker/thread queue or
        # shared mutable SDK/native connection. CAS still guards other replicas.
        with listener('issuer') as service:
            while int(time.time())<supervisor._deadline:
                try:stream,peer=service.accept()
                except socket.timeout:continue
                if peer[0]!=PARENT_CID:stream.close();continue
                supervisor.handle(stream)
        return 0
    except Exception:
        return 1  # Fail closed without printing secret-bearing diagnostics.


if __name__=='__main__':raise SystemExit(main())
