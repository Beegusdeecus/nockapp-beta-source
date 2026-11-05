"""Pinned minimal NSM adapter. Public inputs only; no simulated device fallback."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import urllib.request

from policy import Rejected, canonical, require, strict_json

ROOT = Path(__file__).resolve().parent
BINARY = ROOT/'enclave-nsm/target/release/nockapp-zkid-enclave-nsm'


def prepare(fetch=False):
    lock = json.loads((ROOT/'nsm-source.lock.json').read_bytes())
    archive = ROOT/'local'/('nsm-source-'+lock['commit']+'.tar.gz')
    target = ROOT/'local'/('nsm-source-'+lock['commit'])
    require(not archive.is_symlink() and not target.is_symlink() and not (ROOT/'local').is_symlink(),
            'nsm-source-path')
    if not archive.exists():
        require(fetch is True,'nsm-source-archive-missing')
        with urllib.request.urlopen(lock['archive_url'],timeout=30) as stream:
            data = stream.read(lock['archive_bytes']+1)
        require(len(data) == lock['archive_bytes'] and hashlib.sha256(data).hexdigest() == lock['archive_sha256'],
                'nsm-source-archive')
        archive.parent.mkdir(parents=True,exist_ok=True)
        with archive.open('xb') as stream:stream.write(data)
    data = archive.read_bytes()
    require(len(data) == lock['archive_bytes'] and hashlib.sha256(data).hexdigest() == lock['archive_sha256'],
            'nsm-source-archive')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as source:
        members = source.getmembers()
        require(len(members) <= 1024 and sum(m.size for m in members) <= 2000000,'nsm-source-size')
        for member in members:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts and name.parts
                    and name.parts[0] == 'aws-nitro-enclaves-nsm-api-'+lock['commit'],'nsm-source-path')
            if member.isdir():continue
            require(member.isfile() and len(name.parts) > 1,'nsm-source-type')
            if any(p == '.env' or p.startswith('.env.') for p in name.parts):continue
            relative = Path(*name.parts[1:]);require(relative not in files,'nsm-source-duplicate')
            files[relative] = source.extractfile(member).read()
    for relative,content in files.items():
        out = target/relative
        require(not any(p.is_symlink() for p in [out,*out.parents]),'nsm-source-path')
        if out.exists():require(out.read_bytes() == content,'nsm-source-changed')
        else:
            out.parent.mkdir(parents=True,exist_ok=True)
            with out.open('xb') as stream:stream.write(content)
    for out in target.rglob('*'):
        require(not out.is_symlink() and (not out.is_file() or out.relative_to(target) in files),'nsm-source-extra')
    return {str(p):hashlib.sha256(content).hexdigest() for p,content in files.items()}


class Nsm:
    def __init__(self,binary=BINARY):
        self.binary = Path(binary)
        self.sha256 = hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def attest(self,nonce,public_key,user_data):
        require(type(nonce) is bytes and len(nonce) == 32 and type(user_data) is bytes and len(user_data) == 32
                and type(public_key) is bytes and len(public_key) in (33,294),'nsm-binding')
        try:
            require(hashlib.sha256(self.binary.read_bytes()).hexdigest() == self.sha256,'nsm-binary-changed')
            result = subprocess.run([str(self.binary)],input=canonical({'nonce':list(nonce),'public_key':list(public_key),
                'user_data':list(user_data)}),capture_output=True,timeout=5,
                env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 131072,'nsm-unavailable')
            value = strict_json(result.stdout)
            require(set(value) == {'document'} and type(value['document']) is list
                    and 0 < len(value['document']) <= 32768
                    and all(type(v) is int and 0 <= v <= 255 for v in value['document']),'nsm-document')
            return bytes(value['document'])
        except Rejected:raise
        except Exception:raise Rejected('nsm-unavailable') from None


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch-source',action='store_true')
    args = parser.parse_args()
    print(json.dumps({'source_files_verified':len(prepare(args.fetch_source))}))
