"""Finite two-offer RPC routing; one TLS role and one cumulative gas authority.

The original offer remains the TLS/boot identity. The explicit second offer is
selected only by its installer-pinned hash. Never normalize versions, retag
tickets/jobs, instantiate another journal, or send a publication-history list.
"""
import hmac
from types import MappingProxyType
from policy import digest,require
from ticket_offer_overlay_v1 import pair
from ticket_service_v2 import PaymentApplication,validate_request as validate_v2
from ticket_service_v3 import PublicationApplicationV3
from ticket_refund_service_v1 import RefundApplication

class _Scopes:
    def __init__(self,base,added):
        require(base.service==added.service,'ticket-scope-role')
        base.offer.check();added.offer.check();pair(base.offer.manifest,added.offer.manifest)
        require(base.offer.hash!=added.offer.hash,'ticket-scope-duplicate')
        self.offer=base.offer;self.service=base.service
        self.applications=MappingProxyType({base.offer.hash:base,added.offer.hash:added})
        self._scope_pin=digest(self._pins())
    def _pins(self):
        return {h:({'offer':a.offer.manifest,'vault':a.worker.queue.vault}if self.service=='refund'else a.offer.manifest)
            for h,a in self.applications.items()}
    @property
    def scope_sha256(self):return self._scope_pin
    def check(self):
        require(self.offer.hash in self.applications and len(self.applications)==2
            and digest(self._pins())==self._scope_pin,'ticket-scope-changed')
        for h,app in self.applications.items():
            app.offer.check();require(app.offer.hash==h and app.service==self.service,'ticket-scope-changed')
    def validate(self,message,base_hash,service):
        self.check()
        require(base_hash==self.offer.hash and service==self.service
            and type(message)is dict and type(message.get('offer_sha256'))is str
            and message['offer_sha256']in self.applications,'ticket-scope-envelope')
        app=self.applications[message['offer_sha256']]
        if self.service in('publication','refund'):app.validate(message,app.offer.hash,service)
        else:validate_v2(message,app.offer.hash,service)
        return message
    def dispatch(self,message):
        self.validate(message,self.offer.hash,self.service)
        return self.applications[message['offer_sha256']].dispatch(message)

class ScopedPaymentApplication(_Scopes):
    def __init__(self,base,added):
        require(type(base)is PaymentApplication and type(added)is PaymentApplication,'ticket-scope-payment-app')
        # Same recovered authority, independently pinned receipt/record domains.
        require(base.issuer.payments.rpc is added.issuer.payments.rpc
            and hmac.compare_digest(base.issuer._key,added.issuer._key),'ticket-scope-payment-authority')
        for name in('decisions','results'):
            old=getattr(base.issuer,name);new=getattr(added.issuer,name)
            suffix='decisions/'if name=='decisions'else'results/'
            require(old.client is new.client and old.bucket==new.bucket
                and old.prefix=='ticket-purchases-v1/'+base.offer.hash+'/'+suffix
                and new.prefix=='ticket-purchases-v1/'+added.offer.hash+'/'+suffix
                and old.max_record==new.max_record,'ticket-scope-payment-records')
        super().__init__(base,added)

class ScopedPublicationApplication(_Scopes):
    def __init__(self,base,added):
        require(type(base)is PublicationApplicationV3 and type(added)is PublicationApplicationV3,
            'ticket-scope-publication-app')
        a,b=base.worker,added.worker
        require(a.queue is b.queue and a.index is b.index and a.content is b.content
            and a.native is b.native and a.resolve_original is b.resolve_original,
            'ticket-scope-publication-authority')
        super().__init__(base,added);self.worker=self;self.queue=a.queue
    def recover_pending(self,limit=4):
        self.check();results=[]
        for job in self.queue.pending_jobs(limit):
            # Every existing job keeps its exact original parameters and bytes.
            require(job['parameters']in self.applications,'ticket-scope-recovery-context')
            worker=self.applications[job['parameters']].worker
            try:results.append(worker._resume(job,job['nullifier']))
            except Exception:results.append({'operation':job['operation'],'state':'recovery-unavailable'})
        return results

class ScopedRefundApplication(_Scopes):
    def __init__(self,base,added):
        from ticket_refund_scopes_v2 import RefundQueueView
        require(type(base)is RefundApplication and type(added)is RefundApplication,'ticket-scope-refund-app')
        a,b=base.worker.queue,added.worker.queue
        require(type(a)is RefundQueueView and type(b)is RefundQueueView and a.parent is b.parent
            and a.parameters==base.offer.hash and b.parameters==added.offer.hash,'ticket-scope-refund-authority')
        super().__init__(base,added);self.worker=self;self.queue=a.parent
    def recover_pending(self,limit=4):
        self.check();results=[]
        for pack in self.queue.pending_jobs(limit):
            payload=self.queue.job(pack);parameters=payload['decision']['payment']['parameters']
            require(parameters in self.applications,'ticket-scope-recovery-context')
            try:results.append(self.applications[parameters].worker._resume(pack,payload))
            except Exception:results.append({'pack_hash':pack,'state':'recovery-unavailable','payout_confirmed':False})
        return results
