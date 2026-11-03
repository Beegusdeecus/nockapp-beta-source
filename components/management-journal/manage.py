"""Stdlib release verification/staging and offline frozen-runtime checks.

This does not install system services, read sealed keys, or launch production
network services. Local user namespaces do not prove cross-user broker isolation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

PROFILE='nockapp-ticket-backend-capsule-v1'
APP='opt/nockapp/research/zkid'
NATIVES={'ticket':'local/ticket-tools/nockapp-ticket-worker-v1',
    'author':'local/authorship-native/debug/nockapp-authorship-v4','abi':'local/base-tools/cast'}
BROKER='/run/nockapp-ticket-credentials/credentials.sock'

def require(value):
    if not value:raise ValueError('ticket-capsule-rejected')

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()

def safe(value):
    path=Path(value)
    require(path.is_absolute() and str(path)==str(value) and '..' not in path.parts
        and not any(p.startswith('.env') for p in path.parts)
        and not any(p.is_symlink() for p in (path,*path.parents)))
    return path

def relative(value):
    require(type(value) is str and value and not value.startswith('/') and all(
        p and p not in ('.','..') and not p.startswith('.env') for p in value.split('/')))
    return value

def data(path,limit=2097152):
    path=safe(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=limit and not info.st_mode&0o022)
        raw=stream.read(limit+1);require(len(raw)==info.st_size and len(raw)<=limit);return raw

def digest(path):
    path=safe(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and info.st_size<=134217728 and not info.st_mode&0o022)
        # Host installer also runs on Amazon Linux's Python3.9. Keep the
        # standalone manager independent of Python3.11's file_digest helper.
        result=hashlib.sha256()
        for block in iter(lambda:stream.read(1048576),b''):result.update(block)
        return result.hexdigest()

def decode(raw):
    def unique(pairs):
        value={}
        for k,v in pairs:require(k not in value);value[k]=v
        return value
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False))
    require(canonical(value)==raw);return value

def verify(root,expected):
    root=safe(root);require(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected))
    raw=data(root/'manifest.json');require(sha(raw)==expected);m=decode(raw)
    require(type(m) is dict and set(m)=={'profile','python','files','directories','bwrap_sha256',
        'private_secrets_included','independent_source_rebuild'} and m['profile']==PROFILE
        and m['private_secrets_included'] is False and m['independent_source_rebuild'] is False
        and type(m['python']) is str and re.fullmatch(r'python3\.[0-9]{1,2}',m['python'])
        and type(m['files']) is dict and 0<len(m['files'])<=3000
        and type(m['directories']) is list and m['directories']==sorted(set(m['directories']))
        and len(m['directories'])<=1500 and re.fullmatch('[0-9a-f]{64}',m['bwrap_sha256']))
    files=set();directories=set();total=0
    for path in root.rglob('*'):
        safe(path);name=str(path.relative_to(root));info=path.stat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
        if stat.S_ISDIR(info.st_mode):
            require(stat.S_IMODE(info.st_mode)==0o755);directories.add(name)
        else:files.add(name)
    require(files==set(m['files'])|{'manifest.json'} and directories==set(m['directories']))
    for name in m['directories']:relative(name)
    for name,record in m['files'].items():
        relative(name);require(type(record) is dict and set(record)=={'sha256','bytes','mode'}
            and type(record['mode']) is int and record['mode'] in (0o644,0o755)
            and type(record['bytes']) is int and 0<=record['bytes']<=134217728
            and type(record['sha256']) is str and re.fullmatch('[0-9a-f]{64}',record['sha256']))
        path=root/name;info=path.stat();total+=info.st_size
        require(stat.S_IMODE(info.st_mode)==record['mode'] and info.st_size==record['bytes']
            and digest(path)==record['sha256'])
    require(total<=536870912)
    required={'manage.py','build-inputs.json','rootfs/bootstrap.py','rootfs/deployment.json','rootfs/sealed.json',
        'rootfs/usr/bin/'+m['python'],'rootfs/'+APP+'/ticket_process_v1.py',
        'rootfs/etc/ssl/certs/ca-certificates.crt'}|{'rootfs/'+APP+'/'+v for v in NATIVES.values()}
    require(required<=files);return m

def stage(root,expected,destination):
    """Copy an exact public release to a NEW private destination; no registration."""
    root=safe(root);m=verify(root,expected);destination=safe(destination);parent=destination.parent
    info=parent.stat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid()
        and not info.st_mode&0o077 and not destination.exists())
    destination.mkdir(mode=0o700) # Exclusive reservation, never replace existing data.
    try:
        for name in m['directories']:
            (destination/name).mkdir(mode=0o755);(destination/name).chmod(0o755)
        for name,entry in m['files'].items():
            target=destination/name
            with (root/name).open('rb') as incoming,target.open('xb') as out:shutil.copyfileobj(incoming,out,1048576)
            target.chmod(entry['mode'])
        with (destination/'manifest.json').open('xb') as out:out.write(data(root/'manifest.json'))
        (destination/'manifest.json').chmod(0o644);verify(destination,expected)
    except Exception:
        shutil.rmtree(destination);raise
    return {'profile':PROFILE,'staged':True,'package':str(destination),'manifest_sha256':expected,
        'services_installed':False,'keys_initialized':False}

def deployment(path,expected):
    raw=data(path,1048576);require(sha(raw)==expected);v=decode(raw)
    require(type(v) is dict and v.get('profile')=='nockapp-ticket-process-v1'
        and v.get('kind') in ('role','broker') and type(v.get('broker')) is dict
        and v['broker'].get('socket_path')==BROKER)
    if v['kind']=='role':
        require(type(v.get('backend')) is dict and v['backend'].get('role') in ('payment','publication','refund')
            and v.get('ticket_native')=='/'+APP+'/'+NATIVES['ticket'] and v.get('sealed_boot')=='/sealed.json')
        require(v.get('author_native')==('/'+APP+'/'+NATIVES['author'] if v['backend']['role']=='publication' else None)
            and v.get('scratch')==('/scratch' if v['backend']['role']!='payment' else None))
    return v

def command(root,expected,*,config=None,config_sha256=None,scratch=None):
    root=safe(root);m=verify(root,expected)
    require(digest(Path('/usr/bin/bwrap'))==m['bwrap_sha256'])
    require((config is None)==(config_sha256 is None))
    args=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
        '--setenv','PATH','/usr/bin:/bin','--setenv','LC_ALL','C',
        '--ro-bind',str(root/'rootfs'),'/', '--dev','/dev','--proc','/proc','--tmpfs','/tmp']
    if config is None:require(scratch is None);tail=['selfcheck']
    else:
        config=safe(config);v=deployment(config,config_sha256)
        needs_scratch=v['kind']=='role' and v['backend']['role']!='payment'
        require(needs_scratch==(scratch is not None))
        if needs_scratch:
            scratch=safe(scratch);info=scratch.stat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700)
            args+=['--ro-bind',str(scratch),'/scratch']
        args+=['--ro-bind',str(config),'/deployment.json']
        tail=['check','--deployment','/deployment.json','--sha256',config_sha256]
    args+=['/usr/bin/'+m['python'],'-I','-B','-S','/bootstrap.py',*tail]
    return args,{'PATH':'/usr/bin:/bin','LC_ALL':'C'}

def check(root,expected,**kwargs):
    args,env=command(root,expected,**kwargs)
    p=subprocess.run(args,capture_output=True,env=env,timeout=60)
    require(p.returncode==0 and not p.stderr and 0<len(p.stdout)<=4096)
    value=json.loads(p.stdout);require(type(value) is dict and value.get('ok') is True)
    return value

def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self,_):raise ValueError('ticket-capsule-arguments')
    try:
        parser=Parser(description=__doc__);parser.add_argument('action',choices=('verify','stage','selfcheck','check'))
        parser.add_argument('--manifest-sha256',required=True);parser.add_argument('--destination')
        parser.add_argument('--deployment');parser.add_argument('--deployment-sha256');parser.add_argument('--scratch')
        a=parser.parse_args(argv);root=Path(__file__).resolve().parent
        if a.action=='verify':
            require(all(v is None for v in (a.destination,a.deployment,a.deployment_sha256,a.scratch)))
            verify(root,a.manifest_sha256);value={'integrity_checked':True,'authenticity_requires_independent_checksum':True}
        elif a.action=='stage':
            require(a.destination is not None and all(v is None for v in (a.deployment,a.deployment_sha256,a.scratch)))
            value=stage(root,a.manifest_sha256,a.destination)
        else:
            require(a.destination is None and (a.action=='check')==(a.deployment is not None)
                and (a.deployment is None)==(a.deployment_sha256 is None))
            value=check(root,a.manifest_sha256,config=a.deployment,config_sha256=a.deployment_sha256,scratch=a.scratch)
        print(canonical({'ok':True,**value}).decode(),flush=True);return 0
    except Exception:
        print(canonical({'ok':False,'error':'ticket-capsule-unavailable'}).decode(),flush=True);return 1

if __name__=='__main__':raise SystemExit(main())
