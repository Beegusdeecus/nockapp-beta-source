"""Explicit six-process ticket deployment proposal with renewable service TLS.

Public inputs only. Old plans remain unchanged. No host/cloud installation,
credential acquisition, key creation or readiness claim. Runtime copies are
separate from the immutable verified release; installer admission remains a gate.
"""
import argparse
import copy
import hashlib
from pathlib import Path

from policy import canonical,require,strict_json
import ticket_service_plan_v1 as old
import ticket_tls_ca_credentials_v1 as ca_broker
import ticket_metadata_firewall_v1 as firewall
import ticket_ca_supervised_v1 as ca_service
import ticket_renewing_process_v2 as worker
import ticket_host_tls_ca_v1 as authority
from ticket_capsule_v1 import safe,verify,APP
from ticket_process_v1 import read_file

PROFILE='nockapp-ticket-service-plan-with-ca-v2'
ROLES=(*old.ROLES,'ca-broker','tls-ca')
RUNTIME='/var/lib/nockapp-ticket-backend/runtime'
PUBLIC='/var/lib/nockapp-ticket-backend/public-certificates'
STRATEGY='verified-release-with-separate-per-service-runtime-copies-v1'
pin=old.pin


def projection(value):
    result=copy.deepcopy(value);result['profile']=old.PROFILE;result.pop('runtime_root_strategy')
    result['deployments']={r:result['deployments'][r] for r in old.ROLES}
    result['limits']={r:result['limits'][r] for r in old.ROLES}
    for role in old.ROLES[1:]:
        d=result['deployments'][role];d['profile']='nockapp-ticket-process-v1';d.pop('certificate_delivery')
    return result


def validate(value,expected,manifest):
    require(type(value) is dict and set(value)=={'profile','purpose','release_manifest_sha256','deployments',
        'limits','ticket_memory_budget_mib','ticket_cpu_budget_percent','nft_sha256','runtime_root_strategy'}
        and value['profile']==PROFILE and pin(value)==expected and value['runtime_root_strategy']==STRATEGY
        and type(value['deployments']) is dict and set(value['deployments'])==set(ROLES)
        and type(value['limits']) is dict and set(value['limits'])==set(ROLES),'ticket-ca-plan-config')
    ds=value['deployments'];extension=ds['ca-broker'].get('ca_broker')
    extension,_=ca_broker.validate(extension,pin(extension));base=extension['base']
    require(base==ds['broker']['broker'] and extension['ca_socket_path']==ca_service.CA_SOCKET,
        'ticket-ca-plan-broker')
    metadata=ca_broker.metadata_policy(extension,pin(extension),value['nft_sha256'])
    common={'profile','kind','ca_broker','ca_broker_sha256','metadata_policy','metadata_policy_sha256'}
    extra={'policy','policy_sha256','root_record','root_record_sha256','certificates_directory','interval_seconds'}
    for role,kind in [('ca-broker','broker'),('tls-ca','renewer')]:
        d=ds[role]
        require(type(d) is dict and set(d)==common|(extra if kind=='renewer' else set())
            and d['profile']==ca_service.PROFILE and d['kind']==kind and d['ca_broker']==extension
            and d['ca_broker_sha256']==pin(extension) and d['metadata_policy']==metadata
            and d['metadata_policy_sha256']==pin(metadata),'ticket-ca-plan-service')
    d=ds['tls-ca'];policy=d['policy'];authority.checked_policy(policy,d['policy_sha256'])
    require(d['certificates_directory']==ca_service.PUBLIC_DIR and type(d['interval_seconds']) is int
        and 30<=d['interval_seconds']<=300,'ticket-ca-plan-directory-interval')
    # Constructor verifies the pinned public root's exact signed template; this
    # source has no get()/KMS call until an actual signer operation is requested.
    signer=authority.KmsSigner(policy['kms_key_arn'],ca_broker.credentials(extension,pin(extension)),ca_broker.tls_context())
    authority.HostCA(policy,d['policy_sha256'],signer,root_record=d['root_record'],root_pin=d['root_record_sha256'])
    root_sha=authority.sha(authority.un64(d['root_record']['certificate_der'],8192))
    for role in old.ROLES[1:]:
        v=ds[role]
        require(type(v) is dict and set(v)==worker.FIELDS and v['profile']==worker.PROFILE,
            'ticket-ca-plan-worker-profile')
        delivery=v['certificate_delivery']
        require(delivery=={'profile':worker.DELIVERY,'directory':ca_service.PUBLIC_DIR,'ca_broker':extension,
            'ca_broker_sha256':pin(extension),'metadata_policy':metadata,'metadata_policy_sha256':pin(metadata)},
            'ticket-ca-plan-delivery')
        tls=v['backend']['tls'];service=policy['services'][role]
        require(tls['root_sha256']==root_sha and tls['hostname']==service['hostname']
            and tls['key_sha256']==service['key_sha256'],'ticket-ca-plan-leaf-binding')
    core=projection(value);old.validate(core,pin(core),manifest)
    # Admission requires these executable bytes, not merely similarly named routes.
    for module in ('ticket_ca_supervised_v1.py','ticket_renewing_process_v2.py',
                   'ticket_backend_tls_boot_v2.py','ticket_server_v2.py'):
        require(manifest['files'].get('rootfs/'+APP+'/'+module,{}).get('sha256')==
            hashlib.sha256(Path(__file__).with_name(module).read_bytes()).hexdigest(),'ticket-ca-plan-runtime-source')
    seal={ds[r]['resources']['kms_key_arn'] for r in old.ROLES[1:]}
    require(len(seal)==1 and policy['kms_key_arn'] not in seal and authority.ORIGINAL_KMS not in seal,
        'ticket-ca-plan-key-separation')
    private=[ds['payment']['backend']['records']['purchase_bucket'],
        ds['publication']['backend']['records']['ledger_bucket'],ds['refund']['backend']['records']['ledger_bucket']]
    require(len(set(private))==3,'ticket-ca-plan-journal-separation')
    memory=128;cpu=10;tasks=16
    for limits in value['limits'].values():
        require(type(limits) is dict and set(limits)=={'memory_mib','cpu_percent','tasks','files'},'ticket-ca-plan-limits')
        for key,low,high in [('memory_mib',128,4096),('cpu_percent',1,400),('tasks',16,256),('files',64,4096)]:
            require(type(limits[key]) is int and low<=limits[key]<=high,'ticket-ca-plan-limits')
        memory+=limits['memory_mib'];cpu+=limits['cpu_percent'];tasks+=limits['tasks']
    require(memory<=value['ticket_memory_budget_mib'] and cpu<=value['ticket_cpu_budget_percent'],'ticket-ca-plan-total-budget')
    return copy.deepcopy(value),metadata,tasks


def units(value,expected,manifest,helper_sha):
    value,fw,tasks=validate(value,expected,manifest);old.digest(helper_sha)
    configs='/etc/nockapp-ticket-backend/plans/'+expected
    base=value['deployments']['broker']['broker']
    rendered={old.META:firewall.service(fw,pin(fw),helper_sha).replace('[Service]\n','[Service]\nSlice='+old.SLICE+'\n',1)}
    rendered[old.SLICE]=f'''[Unit]
Description=NockApp ticket backend resource budget

[Slice]
MemoryAccounting=yes
CPUAccounting=yes
TasksAccounting=yes
MemoryMax={value['ticket_memory_budget_mib']}M
CPUQuota={value['ticket_cpu_budget_percent']}%
TasksMax={tasks}
'''
    for role in ROLES:
        d=value['deployments'][role];limits=value['limits'][role]
        uid=base['broker_uid'] if role in ('broker','ca-broker') else (extension_uid(value,'tls-ca') if role=='tls-ca' else base['roles'][role]['uid'])
        wants=['network-online.target'];details=[]
        if role in ('broker','ca-broker'):
            runtime='nockapp-ticket-credentials' if role=='broker' else 'nockapp-ticket-ca-credentials'
            details+=['RuntimeDirectory='+runtime,'RuntimeDirectoryMode=0750','RuntimeDirectoryPreserve=yes','ReadWritePaths=+/run/'+runtime]
        elif role=='tls-ca':
            wants+=[old.name('ca-broker')]
            details+=['BindReadOnlyPaths=/run/nockapp-ticket-ca-credentials',
                'BindPaths='+PUBLIC+':'+ca_service.PUBLIC_DIR,'ReadWritePaths=+'+ca_service.PUBLIC_DIR]
        else:
            wants+=[old.name('broker'),old.name('tls-ca')]
            details+=['BindReadOnlyPaths=/run/nockapp-ticket-credentials',
                'BindReadOnlyPaths=/var/lib/nockapp-ticket-backend/sealed/'+role+'.json:/sealed.json',
                'BindReadOnlyPaths='+PUBLIC+':'+ca_service.PUBLIC_DIR]
            if role!='payment':
                runtime='nockapp-ticket-'+role
                details+=['RuntimeDirectory='+runtime,'RuntimeDirectoryMode=0700','RuntimeDirectoryPreserve=no',
                    'BindPaths=/run/'+runtime+':/scratch','ReadWritePaths=+/scratch']
        route='systemd' if role=='broker' else ('ca-systemd run' if role in ('ca-broker','tls-ca') else 'role-tls-systemd run')
        command='/usr/bin/'+manifest['python']+' -I -B -S /bootstrap.py '+route+' --deployment /deployment.json --sha256 '+pin(d)
        detail='\n'.join(details)+'\n'
        rendered[old.name(role)]=f'''[Unit]
Description=NockApp ticket {role} service
Requires={old.META}
BindsTo={old.META}
Wants={' '.join(wants)}
After={old.META} {' '.join(wants)}
StartLimitIntervalSec=0

[Service]
Type=notify
NotifyAccess=main
User={uid}
Group={base['group_gid']}
SupplementaryGroups=
Slice={old.SLICE}
RootDirectory={RUNTIME}/{expected}/{role}/rootfs
MountAPIVFS=yes
WorkingDirectory=/
BindReadOnlyPaths={configs}/{role}.json:/deployment.json
BindReadOnlyPaths=/etc/resolv.conf
{detail}ExecStart={command}
Restart=on-failure
RestartSec=30s
TimeoutStartSec=180s
TimeoutStopSec=75s
KillMode=control-group
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateUsers=no
PrivateNetwork=no
PrivateTmp=no
TemporaryFileSystem=/run:rw,nosuid,nodev,noexec /var:rw,nosuid,nodev,noexec /tmp:rw,mode=1777,nosuid,nodev,noexec
ReadWritePaths=+/tmp
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
LimitCORE=0
LimitNOFILE={limits['files']}
MemoryMax={limits['memory_mib']}M
CPUQuota={limits['cpu_percent']}%
TasksMax={limits['tasks']}
Environment=PATH=/usr/bin:/bin LC_ALL=C
UnsetEnvironment=HOME AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY SSLKEYLOGFILE SSL_CERT_FILE SSL_CERT_DIR PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH OPENSSL_CONF OPENSSL_MODULES
StandardInput=null
StandardOutput=journal
StandardError=journal
'''
    required=' '.join([old.META,old.SLICE,*[old.name(r) for r in ROLES]])
    rendered['nockapp-ticket-backend.target']=f'''[Unit]
Description=NockApp ticket backend (inspect each service readiness separately)
Wants={required}

[Install]
WantedBy=multi-user.target
'''
    return rendered,fw


def extension_uid(value,role):
    extension=value['deployments']['ca-broker']['ca_broker']
    return extension['base']['broker_uid'] if role=='broker' else extension['ca_uid']


def proposal(value,expected,manifest):
    validate(value,expected,manifest)
    helper=Path(__file__).with_name('ticket_metadata_firewall_v1.py');raw=helper.read_bytes();helper_sha=hashlib.sha256(raw).hexdigest()
    rendered,fw=units(value,expected,manifest,helper_sha)
    contents={**{'units/'+n:t.encode() for n,t in rendered.items()},'metadata/policy.json':canonical(fw),
        'metadata/policy.nft':firewall.program(fw,pin(fw)),'host/'+helper_sha+'.py':raw,
        **{'config/'+r+'.json':canonical(v) for r,v in value['deployments'].items()},'plan.json':canonical(value)}
    return contents,{'profile':PROFILE,'plan_sha256':expected,'release_manifest_sha256':value['release_manifest_sha256'],
        'files':{n:hashlib.sha256(b).hexdigest() for n,b in contents.items()},'helper_sha256':helper_sha,
        'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'firewall_policy_sha256':pin(fw),
        'runtime_root_strategy':STRATEGY,'synthetic_only':value['purpose']=='synthetic-review',
        'production_ready':False,'installed':False,'enabled':False,'started':False,
        'credentials_included':False,'sealed_packets_included':False,'kernel_enforcement_proven':False}


def prepare(package,release_pin,value,expected,output):
    manifest=verify(safe(package),release_pin)
    require(value.get('release_manifest_sha256')==release_pin,'ticket-ca-plan-release')
    contents,result=proposal(value,expected,manifest);output=safe(output)
    require(not output.exists(),'ticket-ca-plan-output-exists');output.mkdir(mode=0o700)
    for name,body in sorted({**contents,'review.json':canonical(result)}.items()):
        p=output/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with p.open('xb') as out:out.write(body)
        p.chmod(0o600)
    return result


def verify_review(root,expected,package,release_pin):
    root=safe(root);raw=read_file(str(root/'review.json'),1048576,expected=expected)
    review=strict_json(raw,max_bytes=1048576);require(canonical(review)==raw,'ticket-ca-plan-review')
    raw=read_file(str(root/'plan.json'),1048576,expected=review['plan_sha256']);value=strict_json(raw,max_bytes=1048576)
    require(canonical(value)==raw and value['release_manifest_sha256']==release_pin,'ticket-ca-plan-review')
    contents,reconstructed=proposal(value,review['plan_sha256'],verify(safe(package),release_pin))
    require(review==reconstructed,'ticket-ca-plan-review')
    files=set();dirs=set()
    for p in root.rglob('*'):
        safe(p)
        if p.is_dir():dirs.add(str(p.relative_to(root)))
        else:require(p.is_file(),'ticket-ca-plan-review');files.add(str(p.relative_to(root)))
    require(files==set(contents)|{'review.json'} and dirs=={'config','host','metadata','units'},'ticket-ca-plan-inventory')
    for name,body in contents.items():require(read_file(str(root/name),1048576,expected=review['files'][name])==body,'ticket-ca-plan-review')
    return {'proposal_integrity_checked':True,'synthetic_only':review['synthetic_only'],'production_ready':False,'installed':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('package','release-sha256','plan','plan-sha256','output'):parser.add_argument('--'+name,required=True)
    a=parser.parse_args()
    try:
        raw=read_file(a.plan,1048576,expected=a.plan_sha256);value=strict_json(raw,max_bytes=1048576)
        require(canonical(value)==raw,'ticket-ca-plan-canonical')
        result=prepare(a.package,a.release_sha256,value,a.plan_sha256,safe(a.output));print(canonical({'ok':True,**result}).decode())
    except Exception:
        print(canonical({'ok':False,'error':'ticket-renewing-plan-unavailable'}).decode());raise SystemExit(1)
