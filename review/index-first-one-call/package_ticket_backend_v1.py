"""Freeze public backend runtime from pinned inputs; no owner state or cloud IO.

No issuer/Vendor collection, private folders, keys, configured deployment or
release trust approval. Repeated archive equality is not a source rebuild.
"""
import argparse
import ast
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import sysconfig
import tarfile

from ticket_capsule_v1 import PROFILE,APP,NATIVES,verify,canonical,digest,safe,relative
from policy import require
from setup_aws_sdk import prepare,SDK

ROOT=Path(__file__).resolve().parent
BASE='artifacts/ticket-six-process-source-admission-20261103T022822282782+1000.json'
BASE_SHA='604d2e8c6d24fa4c9f9d895ad0e4bea8a8268099201eee2961215ec9dd61d3d3'
EXCLUDE={'__pycache__','test','tests','idlelib','ensurepip','pip','turtledemo','site-packages','dist-packages','tkinter'}

def sha(raw):return hashlib.sha256(raw).hexdigest()
def input_digest(path):
    # Development inputs may be group writable; release copies never are.
    path=safe(path);require(path.is_file(),'ticket-freeze-input');return sha(path.read_bytes())

def closure():
    from source_module_closure import module_closure
    seen=module_closure(ROOT,['ticket_process_v1.py','ticket_supervised_v2.py','ticket_capsule_probe_v1.py','ticket_plan_admission_v1.py',
        'ticket_ca_supervised_v1.py','ticket_renewing_process_v2.py','ticket_renewing_process_v3.py','ticket_plan_admission_v2.py'])
    require(all(not Path(name).name.startswith('test_') and name!='trust.py'for name in seen),'ticket-freeze-unrelated-source')
    return sorted(seen)


def tree(root):
    for folder,dirs,names in os.walk(root):
        dirs[:]=sorted(n for n in dirs if n not in EXCLUDE and not n.startswith('.env'))
        for name in sorted(names):
            if not name.startswith('.env') and not name.endswith('.pyc'):yield Path(folder)/name

def runtime_sources():
    require(input_digest(ROOT/BASE)==BASE_SHA,'ticket-freeze-evidence')
    base=json.loads((ROOT/BASE).read_bytes());require(base['ok'] is True,'ticket-freeze-evidence')
    sources={}
    for name in closure():
        observed=input_digest(ROOT/name)
        require(base['sources'].get(name)==observed,'ticket-freeze-source-pin')
        sources[name]=observed
    return base,sources

def files():
    base,sources=runtime_sources();modules=sorted(sources);result={};executables=set()
    def add(source,target,*,executable=False):
        relative(target);require(target not in result,'ticket-freeze-duplicate')
        if not isinstance(source,bytes):source=safe(source);require(source.is_file(),'ticket-freeze-input')
        result[target]=source
        if executable:executables.add(target)
    for name in modules:
        add(ROOT/name,'rootfs/'+APP+'/'+name)
    add(ROOT/'aws-sdk.lock.json','rootfs/'+APP+'/aws-sdk.lock.json')
    sdk=prepare(fetch=False)
    require({str((SDK/n).relative_to(ROOT)):h for n,h in sdk.items()}==base['sdk_files'],'ticket-freeze-sdk-pin')
    for name in sdk:add(SDK/name,'rootfs/'+APP+'/local/aws-sdk/'+name)
    for package in json.loads((ROOT/'aws-sdk.lock.json').read_bytes())['packages']:
        name='local/aws-sdk-wheels/'+package['filename'];add(ROOT/name,'rootfs/'+APP+'/'+name)
    natives={}
    for name,p in NATIVES.items():
        expected=base['binaries'][name];require(input_digest(ROOT/p)==expected,'ticket-freeze-native-pin')
        natives[name]=expected;add(ROOT/p,'rootfs/'+APP+'/'+p,executable=True)
    version='python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor)
    python=Path(sys.executable).resolve();add(python,'rootfs/usr/bin/'+version,executable=True)
    stdlib=Path(sysconfig.get_path('stdlib'))
    for source in tree(stdlib):
        if source.suffix not in ('.py','.so') or source.name.startswith(('_test','_tkinter','xx','readline')) or source.name in ('sitecustomize.py','usercustomize.py'):continue
        resolved=source.resolve();require(resolved.is_relative_to(stdlib.parent),'ticket-freeze-stdlib-alias')
        add(resolved,'rootfs/usr/lib/'+version+'/'+str(source.relative_to(stdlib)))
    site=Path(sysconfig.get_path('purelib'));target='rootfs/usr/lib/'+version+'/site-packages/'
    for name in ('cryptography','cffi','pycparser'):
        for source in tree(site/name):add(source,target+str(source.relative_to(site)))
    for pattern in ('_cffi_backend*.so','typing_extensions.py'):
        for source in site.glob(pattern):add(source,target+source.name)
    # Reject arbitrary ldd failure for the static ticket worker.
    check=subprocess.run(['/usr/bin/readelf','-l',str(ROOT/NATIVES['ticket'])],capture_output=True,text=True,timeout=10,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    require(check.returncode==0 and 'INTERP' not in check.stdout and 'DYNAMIC' not in check.stdout,'ticket-freeze-static')
    dynamic={python,ROOT/NATIVES['abi'],ROOT/NATIVES['author']}
    dynamic.update(p for p in result.values() if isinstance(p,Path) and p.suffix=='.so')
    libraries=set()
    for binary in sorted(dynamic):
        checked=subprocess.run(['/usr/bin/ldd',str(binary)],capture_output=True,text=True,timeout=10,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        require(checked.returncode==0 and 'not found' not in checked.stdout,'ticket-freeze-library')
        libraries.update(Path(p) for p in re.findall(r'(/[^\s()]+)',checked.stdout) if Path(p).is_file())
    for library in sorted(libraries):
        target='rootfs/'+str(library).lstrip('/')
        if target not in result:add(library.resolve(),target,executable=True)
    ca=Path('/etc/ssl/certs/ca-certificates.crt')
    require(input_digest(ca)==base['aws_ca_bundle_sha256'],'ticket-freeze-ca')
    add(ca,'rootfs/etc/ssl/certs/ca-certificates.crt');add(ca,'rootfs/usr/lib/ssl/cert.pem')
    add(Path('/etc/resolv.conf').resolve(),'rootfs/etc/resolv.conf')
    add(b'127.0.0.1 localhost\n::1 localhost\n','rootfs/etc/hosts');add(b'hosts: files dns\n','rootfs/etc/nsswitch.conf')
    for name in ('deployment.json','sealed.json'):add(b'','rootfs/'+name)
    bootstrap=("import sys\nsys.path[:0]="+repr(['/'+APP,'/usr/lib/'+version+'/site-packages'])+"\n"
        "if sys.argv[1:] == ['selfcheck']:\n"
        " from ticket_capsule_probe_v1 import run\n import json\n"
        " print(json.dumps(run("+repr(modules)+","+repr('/'+APP+'/'+NATIVES['ticket'])+","+repr(natives['ticket'])+","+repr('/'+APP+'/'+NATIVES['author'])+"),sort_keys=True))\n"
        "elif len(sys.argv)>1 and sys.argv[1]=='systemd':\n sys.argv.pop(1)\n from ticket_supervised_v2 import main\n raise SystemExit(main())\n"
        "elif len(sys.argv)>1 and sys.argv[1]=='review':\n sys.argv.pop(1)\n from ticket_plan_admission_v1 import main\n raise SystemExit(main())\n"
        "elif len(sys.argv)>1 and sys.argv[1]=='review-with-ca':\n sys.argv.pop(1)\n from ticket_plan_admission_v2 import main\n raise SystemExit(main())\n"
        "elif len(sys.argv)>1 and sys.argv[1]=='ca-systemd':\n sys.argv.pop(1)\n from ticket_ca_supervised_v1 import main\n raise SystemExit(main())\n"
        "elif len(sys.argv)>1 and sys.argv[1]=='role-tls-systemd':\n sys.argv.pop(1)\n from ticket_renewing_process_v2 import main\n raise SystemExit(main())\n"
        "else:\n from ticket_process_v1 import main\n raise SystemExit(main())\n")
    add(bootstrap.encode(),'rootfs/bootstrap.py');add(ROOT/'ticket_capsule_v1.py','manage.py')
    add(canonical({'profile':PROFILE,'packager_sha256':input_digest(Path(__file__).resolve()),
        'manager_sha256':input_digest(ROOT/'ticket_capsule_v1.py'),'runtime_sources':sources,'native_sha256':natives,
        'baseline_receipt':BASE,'baseline_sha256':BASE_SHA,'private_secrets_included':False,
        'independent_source_rebuild':False,'vendor_files_included':False}),'build-inputs.json')
    return result,executables,version

def archive(root,out):
    with gzip.GzipFile(filename='',fileobj=out,mode='wb',mtime=0,compresslevel=6) as compressed:
        with tarfile.open(fileobj=compressed,mode='w|',format=tarfile.PAX_FORMAT) as stream:
            for path in [root,*sorted(root.rglob('*'))]:
                require(not path.is_symlink(),'ticket-freeze-symlink')
                name='nockapp-ticket-backend'+('/'+str(path.relative_to(root)) if path!=root else '')
                info=stream.gettarinfo(str(path),arcname=name);info.uid=info.gid=info.mtime=0;info.uname=info.gname='';info.pax_headers={}
                if path.is_file():
                    with path.open('rb') as source:stream.addfile(info,source)
                else:stream.addfile(info)

class HashSink:
    def __init__(self):self.hash=hashlib.sha256()
    def write(self,data):self.hash.update(data);return len(data)
    def flush(self):pass

def build(output):
    output=safe(output);require(not output.exists(),'ticket-freeze-output')
    incoming,executables,version=files();output.mkdir(mode=0o700)
    reviewed=json.loads(incoming['build-inputs.json'])
    copy_pins={'rootfs/'+APP+'/'+n:h for n,h in reviewed['runtime_sources'].items()}
    copy_pins.update({'rootfs/'+APP+'/'+NATIVES[n]:h for n,h in reviewed['native_sha256'].items()})
    copy_pins['manage.py']=reviewed['manager_sha256']
    root=output/'nockapp-ticket-backend';root.mkdir(mode=0o700);records={};source_pins={}
    for name,source in sorted(incoming.items()):
        raw=source if isinstance(source,bytes) else source.read_bytes()
        require(name not in copy_pins or sha(raw)==copy_pins[name],'ticket-freeze-copy-pin')
        if not isinstance(source,bytes):source_pins[str(source)]=sha(raw)
        path=root/name;path.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        with path.open('xb') as out:out.write(raw)
        mode=0o755 if name in executables else 0o644;path.chmod(mode)
        records[name]={'sha256':sha(raw),'bytes':len(raw),'mode':mode}
    for name in ('tmp','run','run/nockapp-ticket-credentials','run/nockapp-ticket-ca-credentials',
                 'public-certificates','home','scratch','dev','proc','sys','var','review','package'):
        (root/'rootfs'/name).mkdir(mode=0o755,parents=True,exist_ok=True)
    for path in root.rglob('*'):
        if path.is_dir():path.chmod(0o755)
    directories=sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_dir())
    manifest={'profile':PROFILE,'python':version,'files':records,'directories':directories,
        'bwrap_sha256':input_digest(Path('/usr/bin/bwrap')),'private_secrets_included':False,'independent_source_rebuild':False}
    (root/'manifest.json').write_bytes(canonical(manifest));(root/'manifest.json').chmod(0o644)
    expected=digest(root/'manifest.json');verify(root,expected)
    for name,h in source_pins.items():require(input_digest(Path(name))==h,'ticket-freeze-input-changed')
    target=output/'nockapp-ticket-backend.tar.gz'
    with target.open('xb') as out:archive(root,out)
    target.chmod(0o644)
    repeated=HashSink();archive(root,repeated);require(digest(target)==repeated.hash.hexdigest(),'ticket-freeze-repeat')
    value={'profile':PROFILE,'package':str(root),'archive':str(target),'manifest_sha256':expected,
        'archive_sha256':digest(target),'archive_bytes':target.stat().st_size,'files':len(records),
        'repeat_archive_matches':True,'private_secrets_included':False,'vendor_files_included':False,
        'independent_source_rebuild':False,'production_ready':False,'services_installed':False}
    (output/'build.json').write_bytes(canonical(value));print(json.dumps(value),flush=True);return value

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True,type=Path)
    build(parser.parse_args().output)
