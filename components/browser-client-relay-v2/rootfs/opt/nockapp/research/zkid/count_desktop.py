"""Versioned local raw-count credential wallet. No v1 credential reinterpretation."""
from pathlib import Path

from count_pipeline import CountNative,CountPending,PROFILE
from count_policy import CountSession,POLICY_HASH,SCHEME
from domain_desktop import DomainDesktop
from policy import hex_string,require

DESKTOP='nockapp-zkid-protected-count-desktop-v2'


class CountDesktop(DomainDesktop):
    desktop_profile=DESKTOP
    credential_profile=PROFILE
    policy_hash=POLICY_HASH
    session_type=CountSession
    pending_type=CountPending
    request_scheme=SCHEME

    def __init__(self,directory,authority_definition,native=None):
        hex_string(authority_definition,64);require(any(bytes.fromhex(authority_definition)),'count-authority')
        path=Path(directory)
        require(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents))
            and not any(p.startswith('.env') for p in path.parts),'count-wallet-directory')
        self.authority_definition=authority_definition
        super().__init__(directory,native if native is not None else CountNative())

    def _binding(self):return {'authority_definition':self.authority_definition}

    def _activation_challenge(self,view,now):
        return {**super()._activation_challenge(view,now),'threshold':None}
