"""Standalone narrow host guard: verify or create ONLY the ticket IMDS table.

Root ensure is for a reviewed host installation, never invoked during local
fixture checks. No delete/flush/replace/repair, credentials, metadata request,
shell, ambient configuration, arbitrary table or caller-provided nft program.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
from types import SimpleNamespace

PROFILE='nockapp-ticket-metadata-firewall-v1'
PROFILE_CA='nockapp-ticket-metadata-firewall-with-ca-v2'
TABLE='nockapp_ticket_metadata_v1'
TABLE_CA='nockapp_ticket_metadata_v2'
CHAIN='deny_metadata'
NFT='/usr/sbin/nft'
ROLES=('payment','publication','refund')
ADDRESSES=(('ip','169.254.169.254'),('ip6','fd00:ec2::254'))

def require(value):
    if not value:raise ValueError('ticket-firewall-rejected')
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(value):require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) and int(value,16)>0)

def safe(value):
    p=Path(value);require(p.is_absolute() and '..' not in p.parts
        and not any(n.startswith('.env') for n in p.parts) and not any(n.is_symlink() for n in (p,*p.parents)))
    return p
def read(value,limit,*,root_owned=False):
    p=safe(value);fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno());require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=limit
            and not info.st_mode&0o022 and (not root_owned or info.st_uid==0))
        data=source.read(limit+1);require(len(data)==info.st_size and len(data)<=limit);return data
def decode(raw):
    require(type(raw) is bytes and 0<len(raw)<=65536)
    def unique(pairs):
        result={}
        for key,value in pairs:require(key not in result);result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False))

def validate(value,pin):
    digest(pin);require(type(value) is dict)
    ca=value.get('profile')==PROFILE_CA
    require(set(value)=={'profile','broker_sha256','broker_uid','service_uids','nft_sha256'}
        |({'ca_uid','ca_broker_sha256'} if ca else set())
        and value['profile'] in (PROFILE,PROFILE_CA) and sha(canonical(value))==pin)
    digest(value['broker_sha256']);digest(value['nft_sha256'])
    require(type(value['service_uids']) is dict and set(value['service_uids'])==set(ROLES))
    uids=[value['broker_uid'],*[value['service_uids'][role] for role in ROLES]]
    if ca:
        digest(value['ca_broker_sha256']);uids.append(value['ca_uid'])
    require(all(type(uid) is int and 100<=uid<2**31 for uid in uids) and len(set(uids))==len(uids))
    return copy.deepcopy(value)

def table_name(value):return TABLE_CA if value['profile']==PROFILE_CA else TABLE

def blocked_uids(value):
    return [value['service_uids'][role] for role in ROLES]+([value['ca_uid']] if value['profile']==PROFILE_CA else [])

def program(value,pin):
    value=validate(value,pin)
    table=table_name(value)
    lines=['create table inet '+table,
        'add chain inet '+table+' '+CHAIN+' { type filter hook output priority 300; policy accept; }']
    for uid in blocked_uids(value):
        for family,address in ADDRESSES:
            lines.append('add rule inet '+table+' '+CHAIN+' meta skuid '+str(uid)+' '+family+' daddr '+address+' reject with icmpx type admin-prohibited')
    result=('\n'.join(lines)+'\n').encode();require(len(result)<=4096);return result

def objects(value,pin):
    value=validate(value,pin)
    table=table_name(value)
    result=[{'table':{'family':'inet','name':table}},
        {'chain':{'family':'inet','table':table,'name':CHAIN,'type':'filter','hook':'output','prio':300,'policy':'accept'}}]
    for uid in blocked_uids(value):
        for family,address in ADDRESSES:
            expr=[{'match':{'op':'==','left':{'meta':{'key':'skuid'}},'right':uid}},
                {'match':{'op':'==','left':{'payload':{'protocol':family,'field':'daddr'}},'right':address}},
                {'reject':{'type':'icmpx','expr':'admin-prohibited'}}]
            result.append({'rule':{'family':'inet','table':table,'chain':CHAIN,'expr':expr}})
    return result

def service(value,pin,helper_sha256):
    """Reviewable root guard unit, not installation or policy enforcement proof."""
    validate(value,pin);digest(helper_sha256)
    ca_before=' nockapp-ticket-tls-ca.service nockapp-ticket-ca-broker.service' if value['profile']==PROFILE_CA else ''
    return f'''[Unit]
Description=NockApp ticket metadata firewall guard
Before=nockapp-ticket-broker.service nockapp-ticket-payment.service nockapp-ticket-publication.service nockapp-ticket-refund.service{ca_before}
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
ExecStart=/usr/bin/python3 -I -B -S /opt/nockapp-ticket-backend/host/{helper_sha256}.py ensure --policy /etc/nockapp-ticket-backend/metadata/{pin}.json --sha256 {pin}
Restart=on-failure
RestartSec=30s
TimeoutStartSec=90s
TimeoutStopSec=15s
KillMode=control-group
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
PrivateUsers=no
PrivateNetwork=no
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictNamespaces=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
LimitCORE=0
LimitNOFILE=64
MemoryMax=128M
TasksMax=16
CPUQuota=10%
StandardInput=null
StandardOutput=journal
StandardError=journal
'''

def nft_objects(raw):
    value=decode(raw);require(type(value) is dict and set(value)=={'nftables'}
        and type(value['nftables']) is list and len(value['nftables'])<=1025)
    result=[];meta=False
    for item in value['nftables']:
        require(type(item) is dict and len(item)==1)
        if 'metainfo' in item:
            v=item['metainfo'];require(not meta and not result and type(v) is dict
                and set(v)=={'version','release_name','json_schema_version'} and type(v['version']) is str
                and 0<len(v['version'])<=64 and type(v['release_name']) is str and len(v['release_name'])<=128
                and type(v['json_schema_version']) is int and v['json_schema_version']==1)
            meta=True;continue
        result.append(item)
    return result

def table_present(raw,*,table=TABLE):
    require(table in (TABLE,TABLE_CA))
    found=False;seen=set()
    for item in nft_objects(raw):
        require(set(item)=={'table'} and type(item['table']) is dict)
        value=item['table'];require({'family','name'}<=set(value) and set(value)<={'family','name','handle','flags','comment'}
            and type(value['family']) is str and value['family'] in ('ip','ip6','inet','arp','bridge','netdev')
            and type(value['name']) is str and 0<len(value['name'])<=255)
        identity=(value['family'],value['name']);require(identity not in seen);seen.add(identity)
        if identity==('inet',table):found=True
    return found

def verify_table(raw,value,pin):
    normalized=[]
    for item in nft_objects(raw):
        kind=next(iter(item));require(kind in ('table','chain','rule') and type(item[kind]) is dict)
        v=copy.deepcopy(item[kind])
        if 'handle' in v:require(type(v['handle']) is int and v['handle']>0);v.pop('handle')
        if kind=='table' and 'flags' in v:require(v['flags']==[]);v.pop('flags')
        # nft --numeric emits the documented ICMPX admin-prohibited code 3.
        # Normalize only that exact verdict; retain every match and field.
        if kind=='rule' and type(v.get('expr')) is list:
            for expr in v['expr']:
                if type(expr) is dict and set(expr)=={'reject'}:
                    reject=expr['reject']
                    if (type(reject) is dict and set(reject)=={'type','expr'}
                        and reject['type']=='icmpx' and type(reject['expr']) is int
                        and reject['expr']==3):reject['expr']='admin-prohibited'
        normalized.append({kind:v})
    # Canonical bytes also distinguish bool from int, flags and bypass rules.
    require(canonical(normalized)==canonical(objects(value,pin)));return True

def execute(args,body=b''):
    """Bound stdout/stderr while running, with no inherited ambient environment."""
    require(type(args) is list and args[0]==NFT and type(body) is bytes and len(body)<=4096)
    p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},close_fds=True)
    streams={p.stdout:bytearray(),p.stderr:bytearray()}
    try:
        if body:p.stdin.write(body)
        p.stdin.close();end=time.monotonic()+10
        with selectors.DefaultSelector() as selected:
            for stream in streams:selected.register(stream,selectors.EVENT_READ)
            while selected.get_map():
                remaining=end-time.monotonic();require(remaining>0)
                for key,_ in selected.select(min(remaining,.2)):
                    chunk=os.read(key.fileobj.fileno(),4096)
                    if not chunk:selected.unregister(key.fileobj);continue
                    streams[key.fileobj].extend(chunk)
                    require(len(streams[key.fileobj])<=(65536 if key.fileobj is p.stdout else 16384))
        code=p.wait(timeout=max(.1,end-time.monotonic()))
        return SimpleNamespace(returncode=code,stdout=bytes(streams[p.stdout]),stderr=bytes(streams[p.stderr]))
    finally:
        if p.poll() is None:p.kill();p.wait(timeout=5)
        for stream in (p.stdin,p.stdout,p.stderr):stream.close()

def operate(value,pin,*,ensure=False,run=execute):
    value=validate(value,pin);require(type(ensure) is bool and os.geteuid()==0)
    table=table_name(value)
    def call(args,body=b''):
        require(sha(read(NFT,4194304,root_owned=True))==value['nft_sha256'])
        return run([NFT,*args],body)
    def inventory():
        reply=call(['--json','--numeric','--numeric-priority','list','tables'])
        require(reply.returncode==0 and not reply.stderr);return table_present(reply.stdout,table=table)
    def verify():
        reply=call(['--json','--numeric','--numeric-priority','list','table','inet',table])
        require(reply.returncode==0 and not reply.stderr);verify_table(reply.stdout,value,pin)
    present=inventory();attempted=False;uncertain=False
    if present:verify()
    else:
        require(ensure)
        body=program(value,pin);checked=call(['--check','--file','-'],body)
        require(checked.returncode==0 and not checked.stderr)
        attempted=True
        try:
            reply=call(['--file','-'],body)
            uncertain=reply.returncode!=0 or bool(reply.stderr)
        except Exception:uncertain=True
        # Never retry a write. Exact readback resolves even a lost reply.
        require(inventory());verify()
    return {'ok':True,'profile':value['profile'],'policy_sha256':pin,'verified':True,
        'write_attempted':attempted,'uncertain_write_reply':uncertain,'resolved_by_readback':True,
        'table':table,'credentials_read':False,'other_tables_changed':False}

def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self,_):raise ValueError('ticket-firewall-arguments')
    try:
        parser=Parser(description=__doc__);parser.add_argument('action',choices=('plan','verify','ensure'))
        parser.add_argument('--policy',required=True);parser.add_argument('--sha256',required=True);args=parser.parse_args(argv)
        raw=read(args.policy,65536,root_owned=args.action!='plan');require(sha(raw)==args.sha256)
        value=decode(raw);require(canonical(value)==raw);validate(value,args.sha256)
        if args.action=='plan':result={'ok':True,'profile':value['profile'],'policy_sha256':args.sha256,
            'program_sha256':sha(program(value,args.sha256)),'verified':False,'write_attempted':False}
        else:result=operate(value,args.sha256,ensure=args.action=='ensure')
        print(canonical(result).decode(),flush=True);return 0
    except Exception:
        print(canonical({'ok':False,'profile':PROFILE,'error':'ticket-firewall-unavailable'}).decode(),flush=True);return 1

if __name__=='__main__':raise SystemExit(main())
