"""Recovery-only renewal serving assembly for the permissionless-log beta.

Called inside an image-owned supervisor after original KMS/identity recovery.
No cloud factory, initialize, key generation, receipt, governor or post sponsor.
All dependencies below are private supervisor inputs, never request fields.
Image construction and real AWS/source acceptance remain deployment gates.
"""
import json
import time

from base_finality import RPCFinality
from base_managed_storage import DynamoObjects,DynamoJournalAnchor
from base_protocol import read
from bounded_issuer_store_v1 import BoundedIssuerStore
from base_transactions import TransactionQueue,SignedRPC
from policy import require
from renewal_policy_v3 import RenewalProvider
from renewal_service_v3 import RenewalApplication
from renewal_state_v3 import RenewalLeasedIssuer
from renewal_transport_v3 import identity,check_chain,serve_connection,UPDATER_SELECTORS
from service_admission import ServiceAdmission


class RecoveringRenewalIssuer(RenewalLeasedIssuer):
    def __init__(self,backend,key,namespace,native,finality,count_native,renewal_native,queue,batch):
        require(type(batch) is int and 1<=batch<=1024,'renewal-boot-batch')
        super().__init__(backend,key,namespace,native,finality,count_native,renewal_native)
        self.queue,self.batch=queue,batch

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
