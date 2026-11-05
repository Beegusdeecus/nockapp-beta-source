"""Count enrollment via the one attested service; holder keys/proofs stay local.

The raw-count wallet is explicitly separate from the existing v1 wallet. An
encrypted ACK survives transport loss and finalized activation is checked using
independent canonical registry state and a local native activation proof.
"""
from pathlib import Path

from base_enrollment import BaseEnrollment
from count_desktop import CountDesktop
from count_pipeline import CountNative,PROFILE
from count_policy import CountSession
from count_service import validate_count_approval
from count_state import count_view
from count_transport import CountRemote
from domain_pipeline import definition_hash
from policy import require


class CountEnrollment(BaseEnrollment):
    session_type=CountSession
    credential_profile=PROFILE

    def __init__(self,directory,base,approved,native=None):
        approved=validate_count_approval(approved)
        native=native if native is not None else CountNative()
        require(native.sha256.hex()==approved['native_sha256']==base.identity['count_native_sha256'],'count-native-identity')
        path=Path(directory);legacy=Path(base.wallet_directory)
        require(path.is_absolute() and legacy.is_absolute() and not path.is_relative_to(legacy)
            and not legacy.is_relative_to(path),'count-wallet-separate')
        self._base=base;self._approved={'definition_hash':None}
        self._count=CountRemote(base.remote,approved,native)
        self.desktop=CountDesktop(directory,base.identity['definition_hash'],native)

    def _check_definition(self,value):
        # Authenticated local v2 records bind the original pinned authority and
        # native version. The derived schema definition is learned initially
        # only through CountRemote's independent same-key projection check.
        value=self.desktop._check(value)
        public=value['public_definition'] if 'public_definition' in value else value['issuance_context']['public_definition']
        require(value['definition_hash']==definition_hash(public),'count-wallet-definition')
        self._approved['definition_hash']=value['definition_hash']

    def _view(self):
        view=self._count.public_view()
        if self._approved['definition_hash'] is not None:
            require(view['definition_hash']==self._approved['definition_hash'],'count-wallet-definition')
        self._approved['definition_hash']=view['definition_hash'];return view

    def _remote(self,operation,body):return self._count.call(operation,body)

    def _activation(self,session):
        value=self._remote('activation-status',{'session':session})
        if value.get('state')=='pending-or-uncommitted':return value
        require(set(value)=={'state','active','finalized_block','issuer_definition','authority_definition'}
            and value['authority_definition']==self._base.identity['definition_hash'],'count-activation-authority')
        return {k:v for k,v in value.items() if k!='authority_definition'}

    def _final_view(self,registry,tag):return count_view(self.desktop.native,registry.public_at(tag))
