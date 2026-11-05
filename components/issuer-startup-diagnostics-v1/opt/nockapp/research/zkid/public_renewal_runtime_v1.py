"""Image-owned recovery supervisor for the permissionless beta's renewal issuer.

Recovers the original state key/CA/selected identities and one protected updater.
No creation, migration, receipt key, post sponsor, arbitrary endpoint or ambient
credential lookup. The bootstrap channel transports ciphertext/temporary parent
credentials privately; it cannot select service keys, contracts or authority.
"""
import copy
import ctypes
import hashlib
import os
from pathlib import Path
import resource
import secrets
import socket
import time

from aws_transport import AwsJsonClient
from base_fees import policy as fee_policy
from base_key_vault import RecipientKeyVault
from base_keys import TRANSACTION_PROFILE,transaction_context,recover_transaction_key
from base_managed_storage import DynamoObjects,DynamoJournalAnchor
from base_rpc import BaseRPC
from base_transactions import Limits,TransactionQueue,hex_data
from boot_attestation import serve_boot
from count_pipeline import CountNative
from deferred_provider import DeferredProvider
from domain_authority import DynamoBudget
from domain_pipeline import Native
from domain_transport import _decode
from enclave_nsm import Nsm
from issuer_supervisor import (APP,CA,PARENT_CID,REQUIRED as LEGACY_REQUIRED,CONFIG as LEGACY_CONFIG,
    listener,tls_context,validate_device,verify_runtime,_path)
from policy import canonical,digest,hex_string,require,strict_json
from provisioning import RecipientProvisioner,validate_value
from public_renewal_service_v1 import PublicRenewalService
from public_updater_keys_v1 import (SCOPE as SELECTED_SCOPE,UpdaterCeremony,public_selection)
from renewable_issuer import validate_identity_settings,_workload_config,relay as common_relay
from renewal_native_v3 import RenewalNative
from renewal_policy_v3 import RenewalProvider
from renewal_transport_v3 import identity,check_chain,UPDATER_SELECTORS
from workload_bootstrap import IdentityBootstrap
from workload_renewal import protected_ca,sources as renewing_sources
from workload_restart import session as restart_session

PROFILE='nockapp-public-renewal-measured-runtime-v1'
PROFILE_SELECTED='nockapp-public-renewal-measured-runtime-v2'
PROFILE_BUDGET='nockapp-public-renewal-measured-runtime-v3'
CONFIG=APP+'/public-renewal-runtime-config.json'
SCRATCH_ROOT=Path('/run')
BASE_RPC_PORT=9450
PURPOSES=('issuer','budget','verifier')
BINARIES={'domain_native_sha256':'domain-crypto/target/debug/nockapp-zkid-domain-research',
    'count_native_sha256':'local/count-native/debug/nockapp-zkid-count-v2',
    'renewal_native_sha256':'local/renewal-native/debug/nockapp-renewal-count-v3'}
MODULES={'public_renewal_runtime_v1.py','public_renewal_runtime_entrypoint_v1.py','public_renewal_service_v1.py',
    'renewal_transport_v3.py','renewal_service_v3.py','renewal_state_v3.py','renewal_policy_v3.py',
    'renewal_native_v3.py','fixed_issuer_code_v1.py','bounded_issuer_store_v1.py','public_issuer_views.py',
    'permissionless_index.py','base_fees.py','base_key_vault.py','base_keys.py','public_updater_keys_v1.py',
    'base_managed_storage.py','base_protocol.py','base_rpc.py','base_transactions.py','base_evm.py',
    'base_state.py','base_finality.py','count_pipeline.py','count_policy.py','count_state.py',
    'deferred_provider.py','renewable_issuer.py','service_admission.py','workload_renewal.py',
    'workload_restart.py','workload_ca.py','workload_identity_ceremony.py','workload_certificates.py',
    'base_budget_upgrade_v1.py'}
REQUIRED=(LEGACY_REQUIRED-{LEGACY_CONFIG})|{CONFIG,APP+'/local/base-tools/cast'}|\
    {APP+'/'+name for name in MODULES}|{APP+'/'+name for name in BINARIES.values()}


def updater_context(config):
    expected=config['service']
    if config['profile'] in (PROFILE_SELECTED,PROFILE_BUDGET):
        from issuer_supervisor import validate_config as validate_issuer
        return {'profile':SELECTED_SCOPE,'chain_id':84532,'definition':expected['definition_hash'],
            'application':expected['application'],'authority':validate_issuer(config['issuer'])}
    return {'profile':TRANSACTION_PROFILE,'role':'issuer-updater','chain_id':84532,
        'contract':expected['registry'],'address':expected['updater']}


def validate_config(config):
    require(type(config) is dict and config.get('profile') in (PROFILE,PROFILE_SELECTED,PROFILE_BUDGET),'public-renewal-config')
    selected=config['profile'] in (PROFILE_SELECTED,PROFILE_BUDGET)
    upgraded=config['profile']==PROFILE_BUDGET
    require(set(config)=={'profile','issuer','root_certificate','root_sha256','workloads',
        'service','rpc_endpoint','reservation_batch','limits','fee_policy'}|
        ({'updater_selection'} if selected else {'updater_object'})|
        ({'budget_upgrade','budget_upgrade_sha256'} if upgraded else set()),'public-renewal-config')
    authority=validate_identity_settings(config,PURPOSES);expected=identity(config['service'])
    require(expected['definition_hash']==config['issuer']['authority']['namespace']
        and config['rpc_endpoint']=='https://sepolia.base.org','public-renewal-context')
    require(type(config['reservation_batch']) is int and 1<=config['reservation_batch']<=1024,'public-renewal-batch')
    limits=config['limits']
    require(type(limits) is dict and set(limits)==set(Limits.__dataclass_fields__),'public-renewal-limits')
    Limits(**limits).validate();fee_policy(config['fee_policy'])
    if upgraded:
        from base_budget_upgrade_v1 import contexts
        require(digest(config['budget_upgrade'])==config['budget_upgrade_sha256'],'budget-upgrade-review-pin')
        contexts(84532,expected['updater'],{expected['registry']:UPDATER_SELECTORS},
            Limits(**limits),config['fee_policy'],{expected['registry']:expected['runtime_code'][expected['registry']]},
            config['budget_upgrade'],False)
    if selected:
        selection=public_selection(config['updater_selection'],updater_context(config))
        require(selection['proposal']['updater']==expected['updater']
            and any(bytes.fromhex(selection['selection_sha256'])),'public-renewal-selected-updater')
    else:
        transaction_context(updater_context(config));obj=hex_data(config['updater_object'],32)
        require(any(obj) and config['updater_object']=='0x'+obj.hex(),'public-renewal-key-object')
    return authority


def bootstrap(envelope,profile=PROFILE):
    require(profile in (PROFILE,PROFILE_SELECTED,PROFILE_BUDGET),'public-renewal-bootstrap')
    require(type(envelope) is dict and set(envelope)=={'profile','parent_credentials','identities','encrypted_secrets'}
        and envelope['profile']==profile,'public-renewal-bootstrap')
    parent=copy.deepcopy(validate_value('managed-writer-credentials',envelope['parent_credentials']))
    require(type(envelope['identities']) is dict and set(envelope['identities'])==set(PURPOSES),'public-renewal-identities')
    records={}
    for purpose,record in envelope['identities'].items():
        require(type(record) is dict and set(record)=={'wrapped_seed','certificate_der'},'public-renewal-identities')
        records[purpose]={'wrapped_seed':_decode(record['wrapped_seed'],6144),
            'certificate_der':_decode(record['certificate_der'],8192)}
    encrypted=envelope['encrypted_secrets']
    require(type(encrypted) is dict and set(encrypted)=={'blind-issuer-key','twitterapi-key'},'public-renewal-secrets')
    return parent,records,{kind:_decode(value,6144) for kind,value in encrypted.items()}


def relay(service):
    if service!='base_rpc':return common_relay(service)
    def dial():
        raw=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
        try:raw.settimeout(10);raw.connect((PARENT_CID,BASE_RPC_PORT));return raw
        except Exception:raw.close();raise
    return dial


class DeferredRenewalProvider(DeferredProvider,RenewalProvider):pass


class RecoveryContext:
    """Private measured recovery only; no provider, journal or issuer mutation.

    Shared by the serving image and the separately measured preservation image.
    The caller owns the image configuration; no request selects these bindings.
    """
    def __init__(self,config,code,authority,ca,native,nsm,envelope):
        config=copy.deepcopy(config)
        require(validate_config(config)==authority,'public-renewal-authority')
        hex_string(code,64);require(any(bytes.fromhex(code)),'public-renewal-code')
        expected=config['service'];count_native=CountNative();renewal_native=RenewalNative()
        require(native.sha256.hex()==expected['domain_native_sha256']
            and count_native.sha256.hex()==expected['count_native_sha256']
            and renewal_native.sha256==expected['renewal_native_sha256'],'public-renewal-native')
        validate_device(nsm)  # Before ANY credential or protected AWS recovery.
        parent,records,encrypted=bootstrap(envelope,config['profile'])
        context=tls_context(ca);rpc=BaseRPC(config['rpc_endpoint'],dial=relay('base_rpc'),context=context)
        check_chain(expected,rpc)
        cfg=config['issuer']['authority'];region=cfg['region'];namespace=cfg['namespace']
        key=config['issuer']['kms_key_arn'];table=cfg['table_arn'].split(':table/',1)[1]
        boot_kms=AwsJsonClient('kms',region,parent,context,relay('kms'))
        boot_objects=DynamoObjects(AwsJsonClient('dynamodb',region,parent,context,relay('dynamodb')),table,namespace)
        identities={purpose:IdentityBootstrap(boot_kms,nsm,key,namespace,authority,purpose,code).recover(record['wrapped_seed'])
            for purpose,record in records.items()}
        root=_decode(config['root_certificate'],8192);boot_ca=None
        def recover_leaf(purpose,revision):
            nonlocal boot_ca
            if boot_ca is None:boot_ca=protected_ca(boot_kms,boot_objects,identities,config,code,authority,nsm)
            boot_ca.issue(purpose,expected_revision=revision)  # Same selected CA and keys only.
        sessions={}
        for purpose,record in records.items():
            public=_workload_config(config,purpose,hashlib.sha256(record['certificate_der']).hexdigest())
            sessions[purpose]=restart_session(boot_objects,identities[purpose],public,record['certificate_der'],
                root,config['root_sha256'],context,relay('rolesanywhere'),recover=recover_leaf)
        sources=renewing_sources(sessions,identities,config,code,authority,nsm,context)
        issuer_kms=AwsJsonClient('kms',region,sources['issuer'],context,relay('kms'))
        objects=DynamoObjects(AwsJsonClient('dynamodb',region,sources['issuer'],context,relay('dynamodb')),table,namespace)
        provision=RecipientProvisioner(issuer_kms,nsm,key,namespace,authority)
        state_key=provision.decrypt('blind-issuer-key',encrypted['blind-issuer-key'])
        key_aad=updater_context(config)
        vault=RecipientKeyVault(issuer_kms,nsm,key,namespace,authority,code,[canonical(key_aad)])
        if config['profile'] in (PROFILE_SELECTED,PROFILE_BUDGET):
            selected=UpdaterCeremony(nsm,vault,objects.client,table,key_aad,rpc).recover(
                config['updater_selection']['selection_sha256'])
            require(selected.public==config['updater_selection'],'public-renewal-selected-updater')
            updater=selected.signer()
        else:updater=recover_transaction_key(vault,objects,config['updater_object'],key_aad,rpc)
        self.config=config;self.context=context;self.rpc=rpc;self.sources=sources
        self.objects=objects;self.provision=provision;self.encrypted=encrypted
        self.state_key=state_key;self.updater=updater
        self.count_native=count_native;self.renewal_native=renewal_native


class PublicRenewalRuntime:
    def __init__(self,config,code,authority,ca,native,nsm,envelope):
        recovered=RecoveryContext(config,code,authority,ca,native,nsm,envelope)
        config=recovered.config;expected=config['service'];objects=recovered.objects;rpc=recovered.rpc
        sources=recovered.sources;context=recovered.context;cfg=config['issuer']['authority']
        region=cfg['region'];namespace=cfg['namespace'];table=objects.table;updater=recovered.updater
        budget=DynamoBudget(AwsJsonClient('dynamodb',region,sources['budget'],context,relay('dynamodb')),table,namespace)
        budget.public_summary()  # Existing budget only; no initialize/reset.
        def provider():
            api_key=recovered.provision.decrypt('twitterapi-key',recovered.encrypted['twitterapi-key'])
            return RenewalProvider(api_key,context,relay('provider'),budget=budget)
        scratch=SCRATCH_ROOT/('nockapp-public-renewal-'+secrets.token_hex(16));scratch.mkdir(mode=0o700)
        contracts={expected['registry']:UPDATER_SELECTORS}
        codes={expected['registry']:expected['runtime_code'][expected['registry']]}
        anchor=DynamoJournalAnchor(objects,updater.address)
        if config['profile']==PROFILE_BUDGET:
            from base_budget_upgrade_v1 import resume
            queue=resume(rpc,updater,scratch/'updater.sqlite',contracts,Limits(**config['limits']),
                code_hashes=codes,anchor=anchor,fees=config['fee_policy'],
                upgrade=config['budget_upgrade'],upgrade_sha256=config['budget_upgrade_sha256'])
        else:
            queue=TransactionQueue(rpc,updater,scratch/'updater.sqlite',contracts,
                Limits(**config['limits']),code_hashes=codes,anchor=anchor,fee_policy=config['fee_policy'])
        self.service=PublicRenewalService(expected,native,recovered.count_native,recovered.renewal_native,
            recovered.state_key,objects,rpc,queue,
            DeferredRenewalProvider(provider),batch=config['reservation_batch'])
        self._sources=sources;self._code=code;self._authority=authority

    def handle(self,raw):self.service.handle(raw,self._code,self._authority)


def load_runtime(root=Path('/')):
    root=Path(root);manifest=verify_runtime(root,REQUIRED)
    config=strict_json(_path(root,CONFIG).read_bytes());authority=validate_config(config)
    for name,relative in BINARIES.items():
        require(manifest['files'][APP+'/'+relative]['sha256']==config['service'][name],'public-renewal-native')
    return config,digest(manifest),authority


def main():
    try:
        os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        require(ctypes.CDLL(None).prctl(4,0,0,0,0)==0,'public-renewal-private-process')
        config,code,authority=load_runtime();nsm=Nsm();validate_device(nsm)
        instance=None;deadline=time.monotonic()+60
        with listener('bootstrap') as boot:
            while instance is None and time.monotonic()<deadline:
                try:raw,peer=boot.accept()
                except socket.timeout:continue
                if peer[0]!=PARENT_CID:raw.close();continue
                instance=serve_boot(raw,nsm,code,authority,config['service']['definition_hash'],
                    lambda envelope:PublicRenewalRuntime(config,code,authority,Path('/')/CA,Native(),nsm,envelope))
        require(instance is not None,'public-renewal-bootstrap-unavailable')
        with listener('issuer') as service:
            while True:
                try:raw,peer=service.accept()
                except socket.timeout:continue
                if peer[0]!=PARENT_CID:raw.close();continue
                instance.handle(raw)
    except Exception:return 1


if __name__=='__main__':raise SystemExit(main())
