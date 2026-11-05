"""Pinned, dependency-free protocol5 contracts; excludes all legacy governors."""
import hashlib
import json
import subprocess
from pathlib import Path
from base_evm import TOOLS
from policy import require
ROOT=Path(__file__).resolve().parent
NAMES=('PublicCommitmentIndex','FixedIssuerState')
SETTINGS={'optimizer':{'enabled':True,'runs':200},'evmVersion':'prague',
    'outputSelection':{'*':{'*':['abi','storageLayout','evm.bytecode.object','evm.deployedBytecode.object','evm.deployedBytecode.immutableReferences']}}}


def build():
    sources={'contracts/'+n+'.sol':{'content':(ROOT/'base/contracts'/(n+'.sol')).read_text()} for n in NAMES}
    request={'language':'Solidity','sources':sources,'settings':SETTINGS}
    done=subprocess.run([str(TOOLS/'solc-0.8.30'),'--standard-json'],input=json.dumps(request).encode(),
        capture_output=True,timeout=30,check=True)
    result=json.loads(done.stdout)
    require(not any(e['severity']=='error' for e in result.get('errors',[])),'permissionless-contract-build')
    require(set(result['contracts'])==set(sources) and all(set(result['contracts']['contracts/'+n+'.sol'])=={n} for n in NAMES),
        'permissionless-contract-build')
    return result['contracts']


def provenance(compiled):
    return {'compiler':'solc-0.8.30','compiler_sha256':hashlib.sha256((TOOLS/'solc-0.8.30').read_bytes()).hexdigest(),
        'settings':SETTINGS,'sources_sha256':{'contracts/'+n+'.sol':hashlib.sha256((ROOT/'base/contracts'/(n+'.sol')).read_bytes()).hexdigest() for n in NAMES},
        'contracts':{n:{'abi':compiled['contracts/'+n+'.sol'][n]['abi'],
            'creation_sha256':hashlib.sha256(bytes.fromhex(compiled['contracts/'+n+'.sol'][n]['evm']['bytecode']['object'])).hexdigest(),
            'runtime_template_sha256':hashlib.sha256(bytes.fromhex(compiled['contracts/'+n+'.sol'][n]['evm']['deployedBytecode']['object'])).hexdigest(),
            'immutable_references':compiled['contracts/'+n+'.sol'][n]['evm']['deployedBytecode']['immutableReferences']} for n in NAMES},
        'imports_or_libraries':[],'deployed_to_base':False}
