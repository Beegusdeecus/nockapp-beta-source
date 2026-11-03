"""Holder count-v2 client over the pinned attested Base channel.

Count policy/native pins are supplied independently by the installer. The client
derives the count schema from the original issuer public keys, never an issuer
object. Witness requests contain the existing private opaque handle only.
"""
import copy

from count_service import OPERATIONS,POST_OPERATIONS,validate_count_approval
from count_state import count_view
from policy import hex_string,require


class CountRemote:
    def __init__(self,remote,approved,native):
        self.remote=remote;self.approved=copy.deepcopy(validate_count_approval(approved));self.native=native
        require(native.sha256.hex()==self.approved['native_sha256'],'count-native-identity')
        self._checked=False

    def _ready(self):
        if not self._checked:
            result=self.remote.call('count-parameters',{})
            require(result==self.approved,'count-service-identity');self._checked=True

    def call(self,operation,body):
        require(operation in OPERATIONS|POST_OPERATIONS and operation!='parameters','count-operation')
        self._ready();return self.remote.call('count-'+operation,copy.deepcopy(body))

    def public_view(self):
        self._ready();legacy=self.remote.public_view()
        expected=count_view(self.native,legacy);actual=self.remote.call('count-registry',{})
        require(actual==expected,'count-registry-state-changed');return actual

    def refresh_witness(self,handle,view):
        hex_string(handle,64);self._ready()
        result=self.remote.call('count-witness',{'handle':handle})
        require(type(result) is dict and set(result)=={'witness','public','sequence','definition_hash'}
            and result['public']==view['public'] and result['sequence']==view['sequence']
            and result['definition_hash']==view['definition_hash'],'registry-state-changed')
        return result
