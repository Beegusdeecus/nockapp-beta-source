"""Pinned, synthetic-only composite proof experiment; no installed backend change."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import secrets
import subprocess
import tarfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
TOOLS = Path('/home/beegus/TLSNotaryVendor/with-tools.sh')


def source_files(data, manifest):
    if len(data) != manifest['archive_bytes'] or hashlib.sha256(data).hexdigest() != manifest['archive_sha256']:
        raise ValueError('source archive mismatch')
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        if len(members) > 2048 or sum(m.size for m in members) > 10_000_000:
            raise ValueError('source archive too large')
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or not name.parts:
                raise ValueError('unsafe archive path')
            if name.parts[0] != 'anoncreds-v2-rs-' + manifest['commit']:
                raise ValueError('unexpected archive prefix')
            if member.isdir():
                continue
            if not member.isfile() or len(name.parts) < 2:
                raise ValueError('nonregular archive member')
            # Environment files are never extracted or opened.
            if any(part == '.env' or part.startswith('.env.') for part in name.parts):
                continue
            relative = Path(*name.parts[1:])
            if relative in result:
                raise ValueError('duplicate archive member')
            result[relative] = archive.extractfile(member).read()
    return result


def prepare(fetch=False):
    manifest = json.loads((ROOT/'domain-source.lock.json').read_bytes())
    target = ROOT/'local'/('credx-source-' + manifest['commit'])
    archive = ROOT/'local'/('credx-source-' + manifest['commit'] + '.tar.gz')
    if archive.is_symlink() or target.is_symlink() or (ROOT/'local').is_symlink():
        raise ValueError('source path is a symlink')
    if not archive.exists():
        if not fetch:
            raise ValueError('pinned source archive missing; run --fetch-source')
        with urllib.request.urlopen(manifest['archive_url'], timeout=30) as stream:
            data = stream.read(manifest['archive_bytes'] + 1)
        files = source_files(data, manifest)
        archive.parent.mkdir(parents=True, exist_ok=True)
        with archive.open('xb') as stream:
            stream.write(data)
    else:
        files = source_files(archive.read_bytes(), manifest)
    for relative, data in files.items():
        out = target/relative
        for parent in [out, *out.parents]:
            if parent == ROOT:
                break
            if parent.is_symlink():
                raise ValueError('source member is a symlink')
        if out.exists():
            if out.read_bytes() != data:
                raise ValueError('refusing changed upstream source')
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open('xb') as stream:
                stream.write(data)
    # No added Rust/config/build files are allowed to change compilation.
    allowed = set(files) | {Path('inspection-provenance.json')}
    for file in target.rglob('*'):
        if file.is_symlink():
            raise ValueError('unexpected source symlink')
        if file.is_file() and file.relative_to(target) not in allowed:
            raise ValueError('unexpected source file')
    return {str(p): hashlib.sha256(data).hexdigest() for p, data in files.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch-source', action='store_true')
    parser.add_argument('--fetch-dependencies', action='store_true')
    args = parser.parse_args()
    started = time.monotonic()
    tag = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '-' + secrets.token_hex(3)
    receipt = {'profile': 'nockapp-zkid-domain-feasibility-run-v1', 'run': tag,
               'production_ready': False, 'hardware_verified': False,
               'live_provider_called': False, 'live_keyring_used': False,
               'historical_synthetic_only': True, 'durable_replay_enforced': False,
               'deployed_registry_antirollback': False, 'provider_policy_evaluated': False,
               'selected_backend_changed': False, 'passed': False}
    inputs = [ROOT/'domain-source.lock.json', ROOT/'domain_candidate.py',
              ROOT/'domain-crypto/Cargo.toml', ROOT/'domain-crypto/Cargo.lock',
              *sorted((ROOT/'domain-crypto/src').rglob('*.rs'))]
    try:
        receipt['upstream_source_sha256'] = prepare(args.fetch_source)
        receipt['source_sha256'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
        base = ['bash', str(TOOLS), 'cargo']
        manifest = ['--manifest-path', str(ROOT/'domain-crypto/Cargo.toml')]
        if args.fetch_dependencies:
            fetched = subprocess.run(base + ['fetch', '--locked'] + manifest, capture_output=True, timeout=120)
            if fetched.returncode:
                raise ValueError('locked dependency fetch failed')
        built = subprocess.run(base + ['build', '--locked', '--offline', '--jobs', '2'] + manifest,
                               capture_output=True, timeout=300)
        if built.returncode:
            raise ValueError('offline candidate build failed')
        binary = ROOT/'domain-crypto/target/debug/nockapp-zkid-domain-research'
        receipt['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        public_directory = ROOT/'artifacts'/('domain-public-' + tag)
        tested = subprocess.run([str(binary), '--export-public-fixture', str(public_directory)], capture_output=True, timeout=60)
        receipt['process_success'] = tested.returncode == 0
        # Never save panic/debug output or ephemeral holder material.
        if tested.returncode or tested.stderr or len(tested.stdout) > 65536:
            raise ValueError('candidate experiment failed')
        result = json.loads(tested.stdout)
        if result.get('profile') != 'nockapp-zkid-domain-feasibility-v1':
            raise ValueError('wrong candidate result profile')
        checks = result['checks']
        if len(checks) < 63 or not all(v is True for v in checks.values()):
            raise ValueError('incomplete candidate checks')
        receipt['checks'] = checks
        public_names = {'verifier-trust.json', 'public-proof.json'}
        if {p.name for p in public_directory.iterdir()} != public_names:
            raise ValueError('unexpected public evidence member')
        receipt['public_evidence'] = {str((public_directory/name).relative_to(ROOT)):
            hashlib.sha256((public_directory/name).read_bytes()).hexdigest() for name in sorted(public_names)}
        public_trust = json.loads((public_directory/'verifier-trust.json').read_bytes())
        public_proof_bytes = (public_directory/'public-proof.json').read_bytes()
        if set(public_trust['issuer']) != {'id','schema','verifying_key','revocation_verifying_key',
                                          'verifiable_encryption_key','revocation_registry'}:
            raise ValueError('unexpected exported issuer projection')
        if set(json.loads(public_proof_bytes)) != {'proof','claimed_id'}:
            raise ValueError('unexpected exported proof projection')
        if any(token in public_proof_bytes for token in [b'synthetic-pool-incumbent', b'synthetic-session-1']):
            raise ValueError('hidden fixture handle or binding exported')
        receipt['public_only_projection_checked'] = True
        independent = subprocess.run([str(binary), '--verify-app-candidate', str(public_directory/'verifier-trust.json')],
            input=(public_directory/'public-proof.json').read_bytes(), capture_output=True, timeout=10,
            env={'PATH':'/usr/bin:/bin','RAYON_NUM_THREADS':'2'})
        if independent.returncode or independent.stderr or json.loads(independent.stdout) != {'accepted':True,'laboratory_only':True}:
            raise ValueError('exported public proof failed independent verification')
        receipt['exported_evidence_independently_verified'] = True
        unchanged = all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest() == h for p,h in receipt['source_sha256'].items())
        unchanged = unchanged and prepare() == receipt['upstream_source_sha256']
        receipt['sources_unchanged'] = unchanged
        receipt['passed'] = unchanged
    except (ValueError, OSError, subprocess.SubprocessError):
        receipt['error'] = 'candidate-preparation-build-or-check-failed'
    receipt['seconds'] = round(time.monotonic() - started, 3)
    path = ROOT/'artifacts'/('domain-candidate-' + tag + '.json')
    path.parent.mkdir(exist_ok=True)
    with path.open('x') as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'passed': receipt['passed'], 'checks': len(receipt.get('checks', {})), 'receipt': str(path)}))
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
