"""Reproduce the deployed index's complete bytecode without chain writes.

Run beside compiler-input.json and deployment.json with the pinned solc binary.
The original flat Solidity filename is part of its metadata commitment.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

COMPILER = 'f3e987dc6ecebd4bd350c48edcbc320b46cf9e3109bd3fc3d88f1acaf4c428f7'
INPUT = '9b3a5efb527fdd7b71cabf302d19a3b3752e54c9e18959ef2889ee856f621e69'
RUNTIME = 'aab5bba00c8eda446db0b13e5e28b6902a41982673b1c7289e144325b82916f6'
INITCODE = '8260fb15797de0c49d1b3692e956ccea1a4b76c768192240082d9793e71af78c'
APPLICATION = 'c97375890bd5909e2ebc8a323704adcbd98946fd7525f4e0ac3a8fcf51f96874'

def digest(raw): return hashlib.sha256(raw).hexdigest()

def verify(compiler, directory):
    assert compiler.is_file() and not compiler.is_symlink()
    assert digest(compiler.read_bytes()) == COMPILER, 'wrong-compiler'
    raw = (directory/'compiler-input.json').read_bytes()
    assert digest(raw) == INPUT, 'wrong-compiler-input'
    data = json.loads(raw)
    assert set(data['sources']) == {'PublicCommitmentIndex.sol'}
    done = subprocess.run([str(compiler.resolve()),'--standard-json'],input=raw,capture_output=True,timeout=30,check=True)
    output = json.loads(done.stdout)
    assert not [e for e in output.get('errors',[]) if e['severity']=='error']
    contract = output['contracts']['PublicCommitmentIndex.sol']['PublicCommitmentIndex']
    deployed = contract['evm']['deployedBytecode']
    runtime = bytearray.fromhex(deployed['object'])
    refs = deployed['immutableReferences']
    assert len(refs) == 1
    references = next(iter(refs.values())); assert len(references) == 1
    for ref in references:
        assert ref['length'] == 32 and runtime[ref['start']:ref['start']+32] == bytes(32)
        runtime[ref['start']:ref['start']+32] = bytes.fromhex(APPLICATION)
    initcode = bytes.fromhex(contract['evm']['bytecode']['object']+APPLICATION)
    assert len(runtime) == 1010 and digest(runtime) == RUNTIME, 'runtime-mismatch'
    assert digest(initcode) == INITCODE, 'creation-bytecode-mismatch'
    mutating = [f['name'] for f in contract['abi'] if f['type']=='function' and f['stateMutability'] not in ('view','pure')]
    assert mutating == ['submit']
    return {'profile':'nockapp-deployed-index-build-reproduction-v1','ok':True,
        'compiler_sha256':COMPILER,'input_sha256':INPUT,'runtime_bytes':len(runtime),
        'runtime_sha256':RUNTIME,'creation_bytecode_with_constructor_sha256':INITCODE,
        'full_runtime_including_metadata_reproduced':True,'network_or_signing_operation':False}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--solc',required=True,type=Path)
    parser.add_argument('--directory',type=Path,default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    print(json.dumps(verify(args.solc,args.directory)))
