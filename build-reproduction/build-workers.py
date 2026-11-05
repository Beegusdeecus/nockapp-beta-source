"""Build one pinned public Rust worker in an empty, network-isolated workspace.

This never installs a worker, invokes an owner helper, signs data or starts an
enclave. The recorded host compiler/linker environment is required for hashes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ORIGINAL=Path('/home/beegus/nockapp/research/zkid')
CARGO=Path('/home/beegus/TLSNotaryVendor/.tools/cargo')
RUST=Path('/home/beegus/TLSNotaryVendor/.tools/rustup/toolchains/nightly-2026-04-03-x86_64-unknown-linux-gnu')
SOURCE='native-source/reproduced-runtime-v1/'
LEGACY='native-source/legacy-count-v2/'
PLANS={
    'author':('authorship-crypto','local/authorship-native','debug/nockapp-authorship-v4','dc66398792965a5a7d458b548a3751f7f574bd4559da45529d2d66ac93dd44dd',False),
    'renewal':('renewal-crypto','local/renewal-native','debug/nockapp-renewal-count-v3','26d2f23accdc646648de676dc0f22d70dacf59e15d7bf91396a349b3e8fd59da',False),
    'count':('count-crypto','local/count-native','debug/nockapp-zkid-count-v2','0d0ef1072d39bdcbb589b9dd2eef03554dfcf71571e99a41f916742a33a6461f',False),
    'domain':('domain-crypto','domain-crypto/target','debug/nockapp-zkid-domain-research','7caf9649a8dd665ddeed096407d20e5406cf5b9a56d75fa3d6fa08b84abc5d09',False),
    'nsm':('enclave-nsm','enclave-nsm/target','release/nockapp-zkid-enclave-nsm','68abaa2f68f09f4a9cc03d3593d913f6ffb90274759ea07e090756c50767fdc1',True)}

def require(value, message):
    if not value:raise ValueError(message)
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def safe(path):
    path=path.absolute()
    require('..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)), 'Symlink or parent traversal in build input.')
    return path

def main(args):
    release=safe(args.release_root);toolchain=safe(args.toolchain);registry=safe(args.cargo_registry);work=safe(args.workspace)
    require(not work.exists(),'Use a new empty workspace; no existing files will be replaced.')
    manifest=json.loads((release/'PUBLIC-SOURCE-MANIFEST.json').read_bytes())['files']
    def public(name):
        require(name in manifest and '..' not in Path(name).parts and not Path(name).is_absolute()
                and not any(p.startswith('.env') or p=='.git' for p in Path(name).parts), 'Unexpected source member.')
        path=safe(release/name);pin=manifest[name]
        require(sha(path)==pin['sha256'] and path.stat().st_size==pin['bytes'],'Public source checksum mismatch.')
        return path
    environment=json.loads(public('build-reproduction/build-environment.json').read_bytes())
    for name,pin in environment['rust_toolchain_sha256'].items():
        require(sha(toolchain/'bin'/name)==pin,'Rust compiler differs from the pinned build environment.')
    for name,pin in environment['linker_runtime']['file_sha256'].items():
        require(sha(Path(name))==pin['sha256'],'Use the recorded GCC/glibc build environment from the README.')
    selected={n.removeprefix(SOURCE):public(n)for n in manifest if n.startswith(SOURCE)}
    require(selected and all(Path(n).suffix in ('.rs','.toml','.lock','.md') or Path(n).name in ('Cargo.lock','LICENSE','NOTICE','README') for n in selected), 'Unexpected build source set.')
    if args.worker=='count':
        selected={n:p for n,p in selected.items()if not n.startswith('count-crypto/')}
        legacy={n.removeprefix(LEGACY):public(n)for n in manifest if n.startswith(LEGACY)}
        require(len(legacy)==5,'The original five-file count source snapshot is required.')
        selected.update(legacy)
    crate,target_relative,binary_relative,expected,release_profile=PLANS[args.worker]
    require(crate+'/Cargo.toml' in selected and crate+'/Cargo.lock' in selected,'Incomplete crate source.')
    mounts=[]
    for kind in ('src','cache','index'):
        paths=list((registry/kind).glob('index.crates.io-*'))
        require(len(paths)==1 and paths[0].is_dir(),'Provide the public crates.io registry cache used by the locked offline build.')
        mounts.append((safe(paths[0]),CARGO/'registry'/kind/paths[0].name))
    work.mkdir(mode=0o700);source=work/'source';source.mkdir()
    for name,path in selected.items():
        target=source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
    target=work/'target';target.mkdir();(source/target_relative).mkdir(parents=True,exist_ok=True)
    cargo=work/'cargo-home';cargo.mkdir();(cargo/'registry').mkdir()
    command=['/usr/bin/bwrap','--unshare-all','--new-session','--die-with-parent','--clearenv',
        '--ro-bind','/usr','/usr','--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64',
        '--ro-bind','/etc/alternatives','/etc/alternatives','--ro-bind','/etc/ld.so.cache','/etc/ld.so.cache',
        '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--ro-bind',str(source),str(ORIGINAL),
        '--bind',str(target),str(ORIGINAL/target_relative),'--bind',str(cargo),str(CARGO),
        '--ro-bind',str(toolchain),str(RUST)]
    for outside,inside in mounts:command+=['--ro-bind',str(outside),str(inside)]
    command+=['--setenv','HOME','/home/beegus','--setenv','CARGO_HOME',str(CARGO),
        '--setenv','RUSTC',str(RUST/'bin/rustc'),'--setenv','RUSTDOC',str(RUST/'bin/rustdoc'),
        '--setenv','PATH',str(RUST/'bin')+':/usr/bin:/bin','--setenv','LC_ALL','C','--chdir',str(ORIGINAL),
        '--',str(RUST/'bin/cargo'),'build','--locked','--offline','--jobs','2',
        '--manifest-path',str(ORIGINAL/crate/'Cargo.toml'),'--target-dir',str(ORIGINAL/target_relative)]
    if release_profile:command.append('--release')
    with (work/'build.stdout').open('xb')as stdout,(work/'build.stderr').open('xb')as stderr:
        done=subprocess.run(command,stdout=stdout,stderr=stderr,timeout=1200)
    actual=sha(target/binary_relative)if done.returncode==0 else None
    result={'profile':'nockapp-public-worker-build-v1','worker':args.worker,'exit_code':done.returncode,
        'expected_sha256':expected,'rebuilt_sha256':actual,'byte_identical':actual==expected,
        'source_files':len(selected),'source_read_only':True,'network_enabled':False,
        'owner_home_or_credentials_mounted':False,'original_targets_changed':False,
        'installed_or_started':False,'independent_machine_build_claimed':False}
    (work/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    return 0 if result['byte_identical'] else 1

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-root',type=Path,required=True)
    parser.add_argument('--toolchain',type=Path,required=True)
    parser.add_argument('--cargo-registry',type=Path,required=True)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--worker',choices=tuple(PLANS),required=True)
    try:raise SystemExit(main(parser.parse_args()))
    except (ValueError,OSError,subprocess.SubprocessError)as error:
        print(str(error)if type(error)is ValueError else 'Build could not finish. Keep its workspace for diagnosis.');raise SystemExit(1)
