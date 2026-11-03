"""Refund-only backend application, separate from blind-issuance keys."""
import copy
import hashlib
from policy import canonical
from ticket_refund_rpc_v1 import validate
from ticket_refund_payout_v1 import RefundWorker,PROFILE

class RefundApplication:
    service='refund'
    def __init__(self,worker):
        if not isinstance(worker,RefundWorker):raise ValueError('refund-worker')
        self.worker,self.offer=worker,worker.offer
        self.policy_hash=hashlib.sha256(canonical(worker.queue.vault)).hexdigest()

    def validate(self,message,offer_hash,service):
        if service!='refund':raise ValueError('refund-service')
        validate(message,offer_hash,self.policy_hash)

    def dispatch(self,message):
        self.validate(message,self.offer.hash,self.service)
        reply={k:message[k] for k in ('profile','offer_sha256','policy_sha256','service','request_id')}
        try:
            op=message['operation'];b=message['body']
            if op=='policy':result={'policy':copy.deepcopy(self.worker.queue.vault),'sha256':self.policy_hash}
            elif op=='submit':result=self.worker.refund(b['pack_hash'],b['signature'])
            else:
                payload=self.worker.queue.job(b['pack_hash'])
                result=(self.worker._resume(b['pack_hash'],payload) if payload is not None else
                    {'profile':PROFILE,'parameters':self.offer.hash,'pack_hash':b['pack_hash'],'state':'not-enqueued','payout_confirmed':False})
            return {**reply,'status':'ok','result':result}
        except Exception:return {**reply,'status':'rejected','error':'operation-unavailable'}
