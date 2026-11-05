"""Existing desktop enrollment over the single Base service, finalized activation.

The encrypted receipt survives finality delays and transport loss. No issuer
object, source session, credential or activation proof crosses into the browser.
"""
import time

from domain_bridge import DomainBridge
from domain_desktop import DomainDesktop
from policy import hex_string,require


class BaseEnrollment(DomainBridge):
    def __init__(self,directory,base):
        self._base=base
        self._approved={'definition_hash':base.identity['definition_hash']}
        self.desktop=DomainDesktop(directory)
        require(self.desktop.native.sha256.hex()==base.identity['native_sha256'],'base-native-identity')

    def _remote(self,operation,body):return self._base.remote.call(operation,body)

    def _activation(self,session):return self._remote('activation-status',{'session':session})

    def _final_view(self,registry,tag):return registry.public_at(tag)

    def _finish(self,value,status):
        if status['state']=='issued':
            if value['credential'] is None:
                issued=self._remote('recover-delivery',{'session':value['session']})
                self.desktop.receive(issued,value['public_definition']);value=self._pending()
            ack=self.desktop.recover_ack()
            self._remote('commit',{'session':value['session'],'ack':ack})
        elif status['state']!='committed':return self._display(value,status['state'])
        require(value['credential'] is not None,'registration-recovery-required')
        activation=self._activation(value['session'])
        require(type(activation) is dict and type(activation.get('active')) is bool,'base-activation')
        if activation.get('state')=='pending-or-uncommitted':
            require(set(activation)=={'state','active'} and activation['active'] is False,'base-activation')
            return self._display(value,'activation-pending-finality')
        require(set(activation)=={'state','active','finalized_block','issuer_definition'}
            and activation['issuer_definition']==self._approved['definition_hash']
            and activation['state']==('active' if activation['active'] else 'replaced-or-revoked'), 'base-activation')
        anchor=activation['finalized_block']
        require(type(anchor) is str and anchor.startswith('0x'),'base-activation');hex_string(anchor[2:],64)
        rpc,registry=self._base._chain()
        block=rpc.call('eth_getBlockByHash',anchor,False);final=rpc.call('eth_getBlockByNumber','finalized',False)
        require(block is not None and final is not None and block['hash']==anchor
            and int(block['number'],16)<=int(final['number'],16),'base-activation-finality')
        canonical=rpc.call('eth_getBlockByNumber',block['number'],False)
        require(canonical is not None and canonical['hash']==anchor,'base-activation-orphaned')
        if not activation['active']:return self._display(value,'activation-replaced-or-revoked')
        # A current witness must also match a registry already finalized in the
        # independent chain view. Waiting does not extend source/proof expiry.
        view=self._view();final_view=self._final_view(registry,final['number'])
        if view!=final_view:return self._display(value,'activation-pending-finality')
        witness=self._witness(view,pending=True)
        self.desktop.promote(view,witness,int(time.time()))
        return self._display(None,'credential-saved')
