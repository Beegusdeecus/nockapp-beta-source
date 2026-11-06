"""Index-first sponsorship and finalized-only content admission.

Queue admission is the durable approval fence. Background recovery can finish
that SAME admitted hash/transaction without public content or another ticket.
Storage requests cannot admit jobs, assign tickets, sign or broadcast anything.
"""
from policy import require
from ticket_publication_v2 import TicketPublicationWorker


class IndexFirstPublicationWorker(TicketPublicationWorker):
    def _resume(self,job,nullifier):
        h=job['bundle_hash'];status=self.queue.recover_bound(h)
        indexed=self.index.record_for_hash(h)
        if job['indexed_number'] is not None:
            require(indexed is not None and indexed['post_number']==job['indexed_number']
                and indexed['block_hash']==job['indexed_block_hash'],'ticket-index-finality-violation')
        if indexed is not None:
            self.queue.observe_indexed(h,indexed)
            return self._reply(job,nullifier,'indexed',status,indexed['post_number'])
        require(job['nullifier'] is not None,'ticket-index-finality-violation')
        if status is None:
            self.queue.preflight(job['gas']);status=self.queue.submit_bound(h)
        return self._reply(job,nullifier,status['state'],status,None)

    def submit(self,token,bundle_hash,raw):
        self.offer.check();self._validate_bytes(raw,bundle_hash)
        nullifier=self.offer.protocol.verify(token)
        prior=self.queue.lookup(nullifier,bundle_hash)
        if prior is not None:return self._resume(prior,nullifier)
        indexed=self.index.record_for_hash(bundle_hash)
        if indexed is None:self.queue.preflight(self.offer.terms['max_gas'])
        t=self.offer.terms
        job=self.queue.admit(nullifier,self.offer.hash,bundle_hash,gas=t['max_gas'],
            fee_ceiling=int(t['max_total_fee_wei']),redeem_before=t['redeem_before'],indexed=indexed)
        return self._resume(job,nullifier)

    def store(self,bundle_hash,raw):
        self.offer.check()
        indexed=self.index.record_for_hash(bundle_hash)
        require(indexed is not None,'ticket-content-index-not-finalized')
        value=self._validate_bytes(raw,bundle_hash)
        require(value['unsigned']['core']['post']['created_at']<=indexed['indexed_at'],'ticket-content-post-after-index')
        stored=self.content.restore(value)
        require(stored['bundle_hash']==indexed['bundle_hash']
            and stored['readback_checked'] is True,'ticket-worker-storage')
        # Re-read the finalized commitment after I/O; storage is not new indexing.
        require(self.index.record_for_hash(bundle_hash)==indexed,'ticket-content-index-changed')
        return stored
