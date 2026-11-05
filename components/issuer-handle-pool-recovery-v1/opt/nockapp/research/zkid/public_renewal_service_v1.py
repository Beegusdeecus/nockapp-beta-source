"""Recovery-only renewal serving assembly for the permissionless-log beta.

Called inside an image-owned supervisor after original KMS/identity recovery.
No cloud factory, initialize, key generation, receipt, governor or post sponsor.
All dependencies below are private supervisor inputs, never request fields.
Image construction and real AWS/source acceptance remain deployment gates.
"""
import copy
import json
import secrets
import time

from base_finality import RPCFinality
from base_managed_storage import DynamoObjects,DynamoJournalAnchor
from base_protocol import read
from bounded_issuer_store_v1 import BoundedIssuerStore
from base_transactions import TransactionQueue,SignedRPC
from domain_state import public_view
from policy import Rejected,require
from renewal_policy_v3 import RenewalProvider
from renewal_service_v3 import RenewalApplication
from renewal_state_v3 import RenewalLeasedIssuer
from renewal_transport_v3 import identity,check_chain,serve_connection,UPDATER_SELECTORS
from service_admission import ServiceAdmission

MAX_PRIVATE_HANDLES=1000  # Existing native setup's maximum.


def extend_inactive_boot_pool(core,batch):
    """Append fresh inactive names; never recycle a signed/burned reservation.

    The native accumulator's public value and active set stay byte-identical.
    Only its ordered 'ever known' names and the matching private pool grow.
    The existing native stage operation activates one leased name later. This
    metadata extension creates no credential/witness and changes no issuer key.
    The enclosing beginLease commits extension and the burn in one fenced CAS.
    """
    require(type(batch) is int and 1<=batch<=1024,'renewal-boot-batch')
    handles=core._handles;start=core._next
    require(type(handles) is list and type(start) is int and 0<=start<=len(handles)
        and len(handles)<=MAX_PRIVATE_HANDLES and all(type(h) is str and len(h)==64 for h in handles)
        and len(set(handles))==len(handles),'issuer-handle-pool-state')
    end=start+batch
    if end<=len(handles):return
    require(end<=MAX_PRIVATE_HANDLES,'issuer-handle-pool-limit')
    registry=core._issuer.get('revocation_registry')
    require(type(registry) is dict and set(registry)=={'value','elements','active'}
        and registry['elements']==handles and type(registry['active']) is list
        and all(type(h) is str and len(h)==64 for h in registry['active'])
        and len(set(registry['active']))==len(registry['active'])
        and set(registry['active'])<=set(handles),'issuer-handle-pool-state')
    names=list(handles);known=set(handles)
    while len(names)<end:
        for attempt in range(8):
            value=secrets.token_hex(32)
            if value not in known:break
        else:raise Rejected('issuer-handle-generation')
        known.add(value);names.append(value)
    issuer=copy.deepcopy(core._issuer)
    issuer['revocation_registry']['elements']=list(names)
    # No active insertion or accumulator arithmetic occurs here. Old public
    # snapshots, account generations, receipts and every old name are retained.
    core._issuer=issuer;core._handles=names


class RecoveringRenewalIssuer(RenewalLeasedIssuer):
    def __init__(self,backend,key,namespace,native,finality,count_native,renewal_native,queue,batch):
        require(type(batch) is int and 1<=batch<=1024,'renewal-boot-batch')
        super().__init__(backend,key,namespace,native,finality,count_native,renewal_native)
        self.queue,self.batch=queue,batch

    def _seal(self,core,revision):
        try:return super()._seal(core,revision)
        except Rejected as error:
            if error.args==('registry-capacity',):raise Rejected('issuer-state-capacity') from None
            raise

    def begin_boot(self,batch_size):
        # Same lease protocol as the finite-pool research reference, with an
        # append-only production pool extension before its one atomic write.
        require(not self.ready and self.boot_receipt is None,'boot-already-started')
        require(type(batch_size) is int and batch_size>0,'batch-size')
        revision,core=self.load();start=core._next
        extend_inactive_boot_pool(core,batch_size);end=start+batch_size
        require(end<=len(core._handles),'issuer-boot-pool-exhausted')
        core._next=end
        core._base_lease={'epoch':self.backend.lease+1,'start':start,'end':end,'cursor':start}
        for pending in core._pending.values():
            if not pending['acknowledged']:
                pending['aborted']=True;pending.pop('response',None)
        self.backend.begin_lease(revision,self._seal(core,revision+1),public_view(core))
        self.boot_receipt=self.backend.last_receipt
        return {'state':'boot-pending-finality','epoch':core._base_lease['epoch']}

    def poll_boot(self):
        if self.boot_receipt is None:
            results=[self.queue.poll(row) for row in self.queue.outstanding()]
            if any(row['state'] not in ('finalized','failed') for row in results) or self.queue.outstanding():
                return {'state':'boot-recovery-pending'}
            # Drain first, then reload the actual onchain epoch/head: an older
            # saved transaction may have advanced it while recovery was pending.
            self.backend.lease=int(read(self.backend.rpc,self.backend.contract,'bootEpoch()'),16)
            self.begin_boot(self.batch)
        return super().poll_boot()


class PublicRenewalApplication(RenewalApplication):
    def __init__(self,state,provider,expected):
        super().__init__(state,provider,lambda:int(time.time()));self.identity=identity(expected)

    def operate(self,op,body):
        if op not in ('parameters','registry'):
            require(self.protected.poll_boot()['state']=='ready','issuer-not-ready')
        return super().operate(op,body)


class PublicRenewalService:
    def __init__(self,expected,native,count_native,renewal_native,state_key,objects,rpc,queue,provider,*,batch):
        expected=identity(expected);namespace=expected['definition_hash'];registry=expected['registry']
        require(native.sha256.hex()==expected['domain_native_sha256']
            and count_native.sha256.hex()==expected['count_native_sha256']
            and renewal_native.sha256==expected['renewal_native_sha256'],'renewal-service-native')
        require(type(state_key) is bytes and len(state_key)==32 and type(objects) is DynamoObjects
            and objects.namespace==namespace,'renewal-service-state')
        require(isinstance(provider,RenewalProvider) and provider.budget_enforced is True,'renewal-service-provider')
        require(type(queue) is TransactionQueue and queue.rpc is rpc and queue.chain==84532
            and queue.signer.address==expected['updater'] and queue.fees is not None and not queue.creations
            and queue.contracts=={registry:UPDATER_SELECTORS}
            and json.loads(queue.context)['code_hashes']=={registry:expected['runtime_code'][registry]},'renewal-service-queue')
        anchor=queue._anchor
        require(type(anchor) is DynamoJournalAnchor and anchor.objects.client is objects.client
            and anchor.objects.table==objects.table and anchor.objects.namespace==namespace
            and anchor.suffix=='journal:'+expected['updater'][2:],'renewal-service-anchor')
        check_chain(expected,rpc)  # Before any lease write or source request.
        backend=BoundedIssuerStore(SignedRPC(rpc,queue),expected,objects)
        state=RecoveringRenewalIssuer(backend,state_key,namespace,native,RPCFinality(rpc),count_native,renewal_native,queue,batch)
        _,core=state.load();view=backend.public_view()
        require(view=={'definition_hash':core.definition_hash,'sequence':core.sequence,'public':core.public},'renewal-service-state-view')
        self.state=state;self.application=PublicRenewalApplication(state,provider,expected);self.admission=ServiceAdmission()
        state.poll_boot()

    def handle(self,raw,code,authority):
        try:
            if not self.admission.admit():return
            self.state.poll_boot()
            serve_connection(raw,self.application,code,authority)
        except Exception:pass
        finally:raw.close()
