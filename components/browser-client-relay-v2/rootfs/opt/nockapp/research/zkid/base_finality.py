"""Lease-aware local issuer lifecycle without weakening source/proof freshness.

Wait for a finalized burned allocation batch at boot, BEFORE opening ten-minute
source sessions. Within a boot, state/activation is tentative until finalized.
No signed handle from a prior boot is ever allocated again, even after reorg.
"""
import copy
import json
import secrets

from domain_pipeline import LabDomainIssuer, attributes
from domain_state import PersistentDomainIssuer, snapshot, restore, public_view, LIMIT
from policy import Rejected, canonical, require

PROFILE='nockapp-base-leased-private-state-v1'


class RPCFinality:
    """Requires an authenticated trustworthy RPC or locally verified chain.

    This is not a light client. Deployment must configure that trust explicitly.
    No fallback to latest, safe or a numeric confirmation count.
    """
    def __init__(self,rpc):
        self.rpc=rpc;self.checkpoint=None

    def finalized(self):
        block=self.rpc.call('eth_getBlockByNumber','finalized',False)
        require(block is not None,'finality-unavailable')
        if self.checkpoint is not None:
            prior=self.rpc.call('eth_getBlockByNumber',self.checkpoint['number'],False)
            require(prior is not None and prior['hash']==self.checkpoint['hash'],'finality-violation')
            require(int(block['number'],16)>=int(self.checkpoint['number'],16),'finality-rollback')
        self.checkpoint={'number':block['number'],'hash':block['hash']}
        return block

    def includes(self,receipt):
        block=self.finalized()
        canonical=self.rpc.call('eth_getBlockByNumber',receipt['blockNumber'],False)
        require(canonical is not None and canonical['hash']==receipt['blockHash'],'transaction-orphaned')
        return int(block['number'],16)>=int(receipt['blockNumber'],16)


class LeasedCore(LabDomainIssuer):
    def _stage(self,session,values):
        # Same source evaluator, blind signing, dated attributes and receipt
        # proof as the original path. Only index allocation is different.
        with self._lock:
            pending=self._pending_session(session)
            require(not pending['issued'] and 'handle' not in pending,'issuance-replay')
            lease=self._base_lease
            require(lease is not None and lease['cursor']<lease['end'],'reserved-batch-exhausted')
            pending['handle']=self._handles[lease['cursor']];lease['cursor']+=1
            pending['base_sequence']=self.sequence
            self._persist()  # Tentative journal; entire batch already burned at finality.
            attrs=attributes(values,session.binding)
            result=self.native.call('stage',issuer=self._issuer,request=pending['request'],
                                    handle=pending['handle'],attributes=attrs)
            pending['issued']=True;pending['attributes']=attrs
            pending['response']={'bundle':result['bundle'],'attributes':copy.deepcopy(attrs)}
            self._persist()
            return copy.deepcopy(pending['response'])


class LeasedIssuer(PersistentDomainIssuer):
    def __init__(self,backend,key,namespace,native,finality):
        super().__init__(backend,key,namespace,native)
        self.finality=finality;self.boot_receipt=None;self.ready=False

    def _aad(self,revision,**kwargs):
        return canonical({'profile':PROFILE,'namespace':self.namespace,'revision':revision})

    def _seal(self,core,revision):
        body=canonical({'profile':PROFILE,'core':snapshot(core),'lease':getattr(core,'_base_lease',None)})
        require(len(body)<=LIMIT,'registry-capacity')
        nonce=secrets.token_bytes(12)
        return nonce+self._cipher.encrypt(nonce,body,self._aad(revision))

    def _open(self,revision,envelope):
        require(type(revision) is int and type(envelope) is bytes and 28<len(envelope)<=LIMIT+28,'registry-missing')
        try:
            data=json.loads(self._cipher.decrypt(envelope[:12],envelope[12:],self._aad(revision)))
            require(set(data)=={'profile','core','lease'} and data['profile']==PROFILE,'registry-profile')
            core=restore(data['core'],self.native);core.__class__=LeasedCore
            core._base_lease=data['lease']
            require(core.definition_hash==self.namespace,'issuer-definition')
            return core
        except Rejected:raise
        except Exception:raise Rejected('registry-authentication') from None

    def load(self):
        revision,envelope=self.backend.read()
        core=self._open(revision,envelope)
        lease=core._base_lease
        if lease is not None:
            require(set(lease)=={'epoch','start','end','cursor'} and lease['epoch']==self.backend.lease
                    and 0<=lease['start']<=lease['cursor']<=lease['end']==core._next<=len(core._handles),'issuer-lease')
        return revision,core

    def begin_boot(self,batch_size):
        require(not self.ready and self.boot_receipt is None,'boot-already-started')
        require(type(batch_size) is int and batch_size>0,'batch-size')
        revision,core=self.load()
        start=core._next;end=start+batch_size
        require(end<=len(core._handles),'registry-capacity')
        core._next=end  # Burn the ENTIRE batch in the finalized snapshot.
        core._base_lease={'epoch':self.backend.lease+1,'start':start,'end':end,'cursor':start}
        # Recover committed accounts/keys. Previous boot's signed but uncommitted
        # sessions are explicitly retired; neither their handles nor batch reuse.
        for pending in core._pending.values():
            if not pending['acknowledged']:
                pending['aborted']=True;pending.pop('response',None)
        self.backend.begin_lease(revision,self._seal(core,revision+1),public_view(core))
        self.boot_receipt=self.backend.last_receipt
        return {'state':'boot-pending-finality','epoch':core._base_lease['epoch']}

    def poll_boot(self):
        require(self.boot_receipt is not None,'boot-not-started')
        self.backend.head()  # Reject superseded lease and orphaned journal.
        self.ready=self.finality.includes(self.boot_receipt)
        return {'state':'ready' if self.ready else 'boot-pending-finality'}

    def operate(self,method,*args,**kwargs):
        require(self.ready and self.poll_boot()['state']=='ready','issuer-not-ready')
        result=super().operate(method,*args,**kwargs)
        if method=='commit':
            return {**result,'activation_pending_finality':True,'verified':False}
        return result

    def finalized_status(self,session):
        block=self.finality.finalized()
        revision,envelope=self.backend.read(block['number'])
        core=self._open(revision,envelope)
        pending=core._pending.get(session.binding)
        if pending is None or not pending['acknowledged']:
            return {'state':'pending-or-uncommitted','active':False}
        active=core._accounts.get(session.account_id)==pending['handle']
        return {'state':'active' if active else 'replaced-or-revoked','active':active,
                'finalized_block':block['hash'],'issuer_definition':core.definition_hash}
