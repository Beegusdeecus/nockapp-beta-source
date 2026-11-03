"""Verify pinned public wheels; extract only the KMS/DynamoDB SDK dependencies.

No pip install, ambient AWS configuration, credentials or service call occurs.
The complete original wheels remain intact in the goal's local source cache.
"""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import urllib.request
import zipfile

from policy import require

ROOT = Path(__file__).resolve().parent
SDK = ROOT/'local/aws-sdk'


def prepare(fetch=False):
    lock = json.loads((ROOT/'aws-sdk.lock.json').read_bytes())
    require(not SDK.is_symlink() and not (ROOT/'local').is_symlink(),'aws-sdk-path')
    files = {}
    for package in lock['packages']:
        path = ROOT/'local/aws-sdk-wheels'/package['filename']
        require(not path.is_symlink() and not path.parent.is_symlink(),'aws-sdk-path')
        if not path.exists():
            require(fetch is True,'aws-sdk-wheel-missing')
            with urllib.request.urlopen(package['url'],timeout=30) as stream:data = stream.read(package['bytes']+1)
            require(len(data) == package['bytes'] and hashlib.sha256(data).hexdigest() == package['sha256'],
                    'aws-sdk-wheel')
            path.parent.mkdir(parents=True,exist_ok=True)
            with path.open('xb') as stream:stream.write(data)
        data = path.read_bytes()
        require(len(data) == package['bytes'] and hashlib.sha256(data).hexdigest() == package['sha256'],
                'aws-sdk-wheel')
        with zipfile.ZipFile(io.BytesIO(data)) as wheel:
            members = wheel.infolist()
            require(len(members) < 10000 and sum(m.file_size for m in members) < 150000000,'aws-sdk-wheel-size')
            for member in members:
                name = PurePosixPath(member.filename)
                require(not name.is_absolute() and '..' not in name.parts and name.parts
                        and not stat.S_ISLNK(member.external_attr >> 16),'aws-sdk-wheel-path')
                if member.is_dir():continue
                require(not any(p == '.env' or p.startswith('.env.') for p in name.parts)
                        and name.suffix != '.pth','aws-sdk-wheel-type')
                if name.parts[:2] == ('botocore','data') and len(name.parts) > 3:
                    if name.parts[2] not in lock['services']:continue
                relative = Path(*name.parts)
                require(relative not in files,'aws-sdk-duplicate')
                files[relative] = wheel.read(member)
    for relative,data in files.items():
        path = SDK/relative
        require(not any(p.is_symlink() for p in [path,*path.parents]),'aws-sdk-path')
        if path.exists():require(path.read_bytes() == data,'aws-sdk-changed')
        else:
            path.parent.mkdir(parents=True,exist_ok=True)
            with path.open('xb') as stream:stream.write(data)
    for path in SDK.rglob('*'):
        require(not path.is_symlink() and (not path.is_file() or path.relative_to(SDK) in files),'aws-sdk-extra')
    return {str(path):hashlib.sha256(data).hexdigest() for path,data in files.items()}


def activate():
    manifest = prepare()
    for name,module in list(sys.modules.items()):
        if name.split('.')[0] in {'botocore','dateutil','jmespath','urllib3','six'}:
            path = getattr(module,'__file__',None)
            if name == 'six.moves' and path is None:
                # six creates this virtual module from its verified six.py.
                require(type(module).__module__ == 'six'
                        and Path(sys.modules['six'].__file__).is_relative_to(SDK),'aws-sdk-unapproved-import')
                continue
            require(path is not None and Path(path).is_relative_to(SDK),'aws-sdk-unapproved-import')
    if str(SDK) not in sys.path:sys.path.insert(0,str(SDK))
    return manifest


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--fetch',action='store_true')
    args = parser.parse_args()
    print(json.dumps({'verified_files':len(prepare(args.fetch))}))
