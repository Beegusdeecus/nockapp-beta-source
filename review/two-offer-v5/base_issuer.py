"""Private administrative revocation; public updates contain no account key."""
import hashlib
import json
from pathlib import Path
import subprocess

from credential import private_child
from domain_pipeline import definition_hash
from domain_state import public_view
from policy import canonical, require

ROOT=Path(__file__).resolve().parent
BINARY=ROOT/'local/base-native/debug/nockapp-zkid-domain-research'


class IssuerAdministration:
    """In-enclave capability, NOT a public RPC route.

    The service exposing this capability must authenticate a separately approved
    private issuer administrator. Post receipt clients never receive it.
    """
    def __init__(self,state):
        self.state=state
        self.binary_sha256=hashlib.sha256(BINARY.read_bytes()).digest()

    def revoke(self,account):
        if hasattr(self.state,'poll_boot'):
            require(self.state.ready and self.state.poll_boot()['state']=='ready','issuer-not-ready')
        revision,core=self.state.load()
        require(account in core._accounts,'account-not-active')
        handle=core._accounts[account]
        require(hashlib.sha256(BINARY.read_bytes()).digest()==self.binary_sha256,'revocation-binary-changed')
        result=subprocess.run([str(BINARY)],input=canonical({'issuer':core._issuer,'handle':handle}),
            capture_output=True,timeout=15,env={'PATH':'/usr/bin:/bin','RAYON_NUM_THREADS':'2'},preexec_fn=private_child)
        require(result.returncode==0 and not result.stderr and len(result.stdout)<=262144,'revocation-rejected')
        value=json.loads(result.stdout)
        require(definition_hash(value['public'])==core.definition_hash,'issuer-definition')
        core._issuer=value['issuer'];core.public=value['public'];core.sequence+=1
        del core._accounts[account]
        self.state.backend.compare_exchange(revision,self.state._seal(core,revision+1),public_view(core))
        return {'registry_sequence':core.sequence,'revoked':True,'laboratory_only':True}
