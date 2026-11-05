"""Public, pinned backend unit/configuration proposal; no host/cloud installation.

Validate all four deployments and cross-role resources before writing a NEW
review directory. Sealed packets, credentials, private keys and owner state are
never opened. Actual user allocation/IAM/firewall/installation remain gates.
"""
import argparse
import copy
import hashlib
import ipaddress
import re
from pathlib import Path

from base_rpc import BaseRPC
from policy import canonical,require,strict_json
from ticket_aws_credentials_v1 import validate as broker_validate,tls_context
from ticket_backend_boot_v1 import validate as backend_validate
from ticket_backend_resources_v1 import PROFILE as RESOURCE
from ticket_capsule_v1 import verify,safe,APP,NATIVES,BROKER
import ticket_metadata_firewall_v1 as firewall

PROFILE='nockapp-ticket-service-plan-v1'
ROLES=('broker','payment','publication','refund')
PREFIX='/opt/nockapp-ticket-backend'
META='nockapp-ticket-metadata.service'
SLICE='nockapp-ticket-backend.slice'

def pin(v):return hashlib.sha256(canonical(v)).hexdigest()
def digest(v):require(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) and int(v,16)>0,'ticket-plan-pin')
def name(role,suffix='service'):return 'nockapp-ticket-'+role+'.'+suffix

def deployment(value,role,manifest):
    common={'profile','kind','broker','broker_sha256'}
    extra={'backend','backend_sha256','resources','resources_sha256','ticket_native','author_native','sealed_boot','scratch','listen'}
    require(type(value) is dict and set(value)==(common if role=='broker' else common|extra)
        and value['profile']=='nockapp-ticket-process-v1' and value['kind']==('broker' if role=='broker' else 'role'),'ticket-plan-deployment')
    b=broker_validate(value['broker']);require(pin(b)==value['broker_sha256'] and b['broker_uid']>=100
        and b['socket_path']==BROKER,'ticket-plan-broker')
    if role=='broker':return b,None
    c=backend_validate(value['backend'],value['backend_sha256']);r=value['resources'];records=c['records']
    require(c['role']==role and records['account_id']==b['account_id'] and records['region']==b['region'],'ticket-plan-role')
    require(type(r) is dict and set(r)=={'profile','backend_sha256','broker_sha256','rpc','kms_key_arn','sealed_boot_sha256'}
        and r['profile']==RESOURCE and r['backend_sha256']==value['backend_sha256']
        and r['broker_sha256']==value['broker_sha256'] and pin(r)==value['resources_sha256'],'ticket-plan-resource')
    digest(r['sealed_boot_sha256'])
    prefix='arn:aws:kms:'+b['region']+':'+b['account_id']+':key/'
    require(type(r['kms_key_arn']) is str and re.fullmatch(re.escape(prefix)+r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',r['kms_key_arn']),'ticket-plan-kms')
    rpc=r['rpc'];require(type(rpc) is dict and set(rpc)=={'endpoint','rate','burst','timeout'},'ticket-plan-rpc')
    BaseRPC(rpc['endpoint'],rate=rpc['rate'],burst=rpc['burst'],timeout=rpc['timeout'],context=tls_context())
    require(value['ticket_native']=='/'+APP+'/'+NATIVES['ticket']
        and c['ticket_native_sha256']==manifest['files']['rootfs/'+APP+'/'+NATIVES['ticket']]['sha256']
        and value['sealed_boot']=='/sealed.json' and value['scratch']==(None if role=='payment' else '/scratch'),'ticket-plan-paths')
    require(value['author_native']==('/'+APP+'/'+NATIVES['author'] if role=='publication' else None),'ticket-plan-paths')
    if role=='publication':
        require(c['author_native_sha256']==manifest['files']['rootfs/'+APP+'/'+NATIVES['author']]['sha256']
            and c['origin']['region']==b['region'],'ticket-plan-author-origin')
    address=value['listen'];require(type(address) is dict and set(address)=={'ip','port'} and type(address['ip']) is str
        and type(address['port']) is int and 1024<=address['port']<=65535,'ticket-plan-listen')
    ip=ipaddress.ip_address(address['ip'])
    require(str(ip)==address['ip'] and '%' not in address['ip'] and not ip.is_multicast
        and not (ip.version==6 and ip.ipv4_mapped is not None),'ticket-plan-listen')
    return b,c

def validate(value,expected,manifest):
    digest(expected);require(type(value) is dict and set(value)=={'profile','purpose','release_manifest_sha256','deployments',
        'limits','ticket_memory_budget_mib','ticket_cpu_budget_percent','nft_sha256'}
        and value['profile']==PROFILE and value['purpose'] in ('synthetic-review','administrator-review')
        and pin(value)==expected,'ticket-plan-config')
    digest(value['release_manifest_sha256']);digest(value['nft_sha256'])
    supervised=Path(__file__).resolve().with_name('ticket_supervised_v2.py')
    require(manifest['files'].get('rootfs/'+APP+'/ticket_supervised_v2.py',{}).get('sha256')
        ==hashlib.sha256(supervised.read_bytes()).hexdigest(),'ticket-plan-owned-socket-runtime')
    require(type(value['deployments']) is dict and set(value['deployments'])==set(ROLES)
        and type(value['limits']) is dict and set(value['limits'])==set(ROLES),'ticket-plan-config')
    brokers={};backends={}
    for role in ROLES:brokers[role],backends[role]=deployment(value['deployments'][role],role,manifest)
    b=brokers['broker'];require(all(pin(v)==pin(b) for v in brokers.values()),'ticket-plan-split-broker')
    configs=[backends[r] for r in ROLES[1:]];payment,publication,refund=configs
    require(len({c['offer_sha256'] for c in configs})==1
        and all(c['key_bindings']==payment['key_bindings'] for c in configs)
        and len({c['tls']['root_sha256'] for c in configs})==1,'ticket-plan-split-offer-keys-root')
    purchase=payment['records']['purchase_bucket']
    require(refund['records']['purchase_bucket']==purchase,'ticket-plan-purchase-bucket')
    private={purchase,publication['records']['ledger_bucket'],refund['records']['ledger_bucket']}
    require(purchase not in (publication['records']['ledger_bucket'],refund['records']['ledger_bucket'])
        and publication['origin']['bucket'] not in private,'ticket-plan-public-private-buckets')
    # Separate TLS keys and packets prevent accidental cross-service staging.
    require(len({c['tls']['key_sha256'] for c in configs})==3
        and len({value['deployments'][r]['resources']['sealed_boot_sha256'] for r in ROLES[1:]})==3,'ticket-plan-key-packet-reuse')
    # Same port can collide across wildcard/IPv4/IPv6 bindings. Keep it unique.
    require(len({value['deployments'][r]['listen']['port'] for r in ROLES[1:]})==3,'ticket-plan-listen-collision')
    memory=128;cpu=10;tasks=16
    for role,limits in value['limits'].items():
        require(type(limits) is dict and set(limits)=={'memory_mib','cpu_percent','tasks','files'},'ticket-plan-limits')
        for key,low,high in [('memory_mib',128,4096),('cpu_percent',1,400),('tasks',16,256),('files',64,4096)]:
            require(type(limits[key]) is int and low<=limits[key]<=high,'ticket-plan-limits')
        memory+=limits['memory_mib'];cpu+=limits['cpu_percent'];tasks+=limits['tasks']
    require(type(value['ticket_memory_budget_mib']) is int and memory<=value['ticket_memory_budget_mib']<=32768
        and type(value['ticket_cpu_budget_percent']) is int and cpu<=value['ticket_cpu_budget_percent']<=1600,'ticket-plan-total-budget')
    fw={'profile':firewall.PROFILE,'broker_sha256':pin(b),'broker_uid':b['broker_uid'],
        'service_uids':{r:b['roles'][r]['uid'] for r in ROLES[1:]},'nft_sha256':value['nft_sha256']}
    firewall.validate(fw,pin(fw))
    return copy.deepcopy(value),fw,tasks

def units(value,expected,manifest,helper_sha256):
    value,fw,tasks=validate(value,expected,manifest);digest(helper_sha256)
    release=PREFIX+'/releases/'+value['release_manifest_sha256']
    config='/etc/nockapp-ticket-backend/plans/'+expected
    result={META:firewall.service(fw,pin(fw),helper_sha256).replace('[Service]\n','[Service]\nSlice='+SLICE+'\n',1)}
    result[SLICE]=f'''[Unit]
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
        v=value['deployments'][role];b=v['broker'];limits=value['limits'][role]
        uid=b['broker_uid'] if role=='broker' else b['roles'][role]['uid']
        runtime='nockapp-ticket-credentials' if role=='broker' else 'nockapp-ticket-'+role
        requires=META
        after=requires+' network-online.target'+(' '+name('broker') if role!='broker' else '')
        wants='network-online.target'+(' '+name('broker') if role!='broker' else '')
        details=''
        if role=='broker':details=f'RuntimeDirectory={runtime}\nRuntimeDirectoryMode=0750\nRuntimeDirectoryPreserve=yes\nReadWritePaths=+/run/{runtime}\n'
        elif role!='payment':details=f'RuntimeDirectory={runtime}\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=no\nBindPaths=/run/{runtime}:/scratch\nReadWritePaths=+/scratch\n'
        if role!='broker':
            details+='BindReadOnlyPaths=/run/nockapp-ticket-credentials\n'
            details+='BindReadOnlyPaths=/var/lib/nockapp-ticket-backend/sealed/'+role+'.json:/sealed.json\n'
        command='/usr/bin/'+manifest['python']+' -I -B -S /bootstrap.py systemd --deployment /deployment.json --sha256 '+pin(v)
        result[name(role)]=f'''[Unit]
Description=NockApp ticket {role} service
Requires={requires}
BindsTo={META}
Wants={wants}
After={after}
StartLimitIntervalSec=0

[Service]
Type=notify
NotifyAccess=main
User={uid}
Group={b['group_gid']}
Slice={SLICE}
RootDirectory={release}/rootfs
MountAPIVFS=yes
WorkingDirectory=/
BindReadOnlyPaths={config}/{role}.json:/deployment.json
BindReadOnlyPaths=/etc/resolv.conf
{details}ExecStart={command}
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
    required=' '.join([META,SLICE,*[name(r) for r in ROLES]])
    result['nockapp-ticket-backend.target']=f'''[Unit]
Description=NockApp ticket backend (inspect each service readiness separately)
Wants={required}

[Install]
WantedBy=multi-user.target
'''
    return result,fw

def proposal(value,expected,manifest):
    # Development inputs may be group writable; proposals copy fixed bytes to
    # private files. Actual root-owned installation is a separate audited gate.
    validate(value,expected,manifest)
    helper=safe(Path(__file__).resolve().with_name('ticket_metadata_firewall_v1.py'))
    require(helper.is_file() and helper.stat().st_size<=65536,'ticket-plan-helper')
    helper_raw=helper.read_bytes();helper_sha=hashlib.sha256(helper_raw).hexdigest()
    rendered,fw=units(value,expected,manifest,helper_sha)
    contents={**{'units/'+n:t.encode() for n,t in rendered.items()},'metadata/policy.json':canonical(fw),
        'metadata/policy.nft':firewall.program(fw,pin(fw)),'host/'+helper_sha+'.py':helper_raw,
        **{'config/'+r+'.json':canonical(v) for r,v in value['deployments'].items()},'plan.json':canonical(value)}
    return contents,{'profile':PROFILE,'plan_sha256':expected,'release_manifest_sha256':value['release_manifest_sha256'],
        'files':{n:hashlib.sha256(raw).hexdigest() for n,raw in contents.items()},
        'firewall_policy_sha256':pin(fw),'helper_sha256':helper_sha,
        'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'synthetic_only':value['purpose']=='synthetic-review',
        'production_ready':False,'installed':False,'enabled':False,'started':False,
        'credentials_included':False,'sealed_packets_included':False,'users_created':False,
        'host_identity_and_capacity_verified':False,'kernel_enforcement_proven':False}

def prepare(package,release_pin,value,expected,output):
    package=safe(package);manifest=verify(package,release_pin)
    require(type(value) is dict and value.get('release_manifest_sha256')==release_pin,'ticket-plan-release')
    contents,result=proposal(value,expected,manifest)
    output=safe(output);require(not output.exists(),'ticket-plan-output-exists')
    output.mkdir(mode=0o700)
    for relative,body in sorted(contents.items()):
        p=output/relative;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with p.open('xb') as out:out.write(body)
        p.chmod(0o600)
    with (output/'review.json').open('xb') as out:out.write(canonical(result))
    (output/'review.json').chmod(0o600);return result

def verify_review(root,expected,package,release_pin):
    """Local review integrity, not authorization, installation or host acceptance."""
    from ticket_process_v1 import read_file
    root=safe(root);digest(expected)
    raw=read_file(str(root/'review.json'),1048576,expected=expected);review=strict_json(raw,max_bytes=1048576)
    require(type(review) is dict and canonical(review)==raw and review.get('release_manifest_sha256')==release_pin,'ticket-plan-review')
    plan_raw=read_file(str(root/'plan.json'),1048576,expected=review['plan_sha256'])
    value=strict_json(plan_raw,max_bytes=1048576);require(canonical(value)==plan_raw,'ticket-plan-review')
    manifest=verify(safe(package),release_pin);require(value['release_manifest_sha256']==release_pin,'ticket-plan-release')
    contents,reconstructed=proposal(value,review['plan_sha256'],manifest)
    require(canonical(review)==canonical(reconstructed),'ticket-plan-review')
    files=set();directories=set()
    for p in root.rglob('*'):
        safe(p)
        if p.is_dir():directories.add(str(p.relative_to(root)))
        else:require(p.is_file(),'ticket-plan-review');files.add(str(p.relative_to(root)))
    require(files==set(contents)|{'review.json'} and directories=={'config','host','metadata','units'},'ticket-plan-review-inventory')
    for n,body in contents.items():
        require(read_file(str(root/n),1048576,expected=review['files'][n])==body,'ticket-plan-review-file')
    return {'proposal_integrity_checked':True,'synthetic_only':review['synthetic_only'],'production_ready':False,
        'installed':False,'host_identity_and_capacity_verified':False,'kernel_enforcement_proven':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--package',required=True)
    parser.add_argument('--release-sha256',required=True);parser.add_argument('--plan',required=True)
    parser.add_argument('--plan-sha256',required=True);parser.add_argument('--output',required=True);a=parser.parse_args()
    try:
        from ticket_process_v1 import read_file
        raw=read_file(a.plan,1048576,expected=a.plan_sha256);value=strict_json(raw,max_bytes=1048576)
        require(canonical(value)==raw,'ticket-plan-canonical')
        result=prepare(a.package,a.release_sha256,value,a.plan_sha256,a.output)
        print(canonical({'ok':True,**result}).decode(),flush=True)
    except Exception:
        print(canonical({'ok':False,'error':'ticket-service-plan-unavailable'}).decode(),flush=True);raise SystemExit(1)
