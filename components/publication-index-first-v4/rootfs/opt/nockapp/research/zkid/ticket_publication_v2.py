"""Spend-only publication worker; no ticket/credential signing or index admin.

Mandatory authored bytes are verified before new sponsorship. Optional badges
are reader decisions and cannot block otherwise valid authored text. A response
is payment/queue status, never a public proof-validity verdict.
"""
from authorship import AuthorshipNative
from authorship_v5 import verify as verify_author
from public_bundle_v5 import decode
from public_content_v5 import PublicContent
from permissionless_index import PublicIndexReader,digest
from policy import require
from ticket_offer_v1 import TicketOffer,OFFER_V2
from ticket_publication_queue_v2 import TicketPublicationQueue,PROFILE


class TicketPublicationWorker:
    def __init__(self,offer,queue,index,content,native,*,resolve_original=None):
        require(isinstance(offer,TicketOffer) and isinstance(queue,TicketPublicationQueue)
            and isinstance(index,PublicIndexReader) and isinstance(content,PublicContent)
            and isinstance(native,AuthorshipNative),'ticket-worker-configuration')
        t=offer.terms
        from batch_checkout_v2.offer import BatchOffer
        require((t['profile']==OFFER_V2 or isinstance(offer,BatchOffer))
            and t.get('redemption_ledger')==PROFILE,'ticket-worker-ledger-version')
        require(queue.rpc is index.rpc and queue.chain==index.chain_id==84532
            and queue.index_contract==index.contract==t['index_contract']
            and queue.application==index.application==t['application']
            and index.runtime_hash==t['index_runtime_keccak'],'ticket-worker-context')
        self.offer,self.queue,self.index,self.content,self.native=offer,queue,index,content,native
        self.resolve_original=resolve_original

    def _validate_bytes(self,raw,bundle_hash):
        value=decode(raw,bundle_hash);u=value['unsigned'];c=u['core']
        x=c['context'];t=self.offer.terms
        require(x['protocol']==5 and x['chain_id']==84532 and x['application']==t['application']
            and x['contract']==t['index_contract'] and verify_author(self.native,u,value['authorship']),'ticket-worker-author')
        head=self.queue.rpc.call('eth_getBlockByNumber','latest',False)
        require(c['post']['created_at']<=int(head['timestamp'],16),'ticket-worker-future-post')
        if c['thread'] is not None:
            require(self.resolve_original is not None,'ticket-worker-root-unavailable')
            original,when=self.resolve_original(c['thread']);root=decode(original,c['thread']['bundle_hash']);r=root['unsigned']
            require(r['core']['post']['kind']=='thread' and r['core']['post']['created_at']<=when<=int(head['timestamp'],16)
                and all(r['core']['context'][k]==x[k] for k in ('protocol','chain_id','application','contract'))
                and verify_author(self.native,r,root['authorship']),'ticket-worker-root')
        return value

    def _validate_and_store(self,bundle_hash):
        value=self._validate_bytes(self.content.fetch(bundle_hash),bundle_hash)
        stored=self.content.upload(value)
        require(stored['bundle_hash']==bundle_hash and stored['readback_checked'] is True,'ticket-worker-storage')

    def store(self,token,bundle_hash,raw):
        """Authenticated ingress: public storage only, NEVER index or sign gas."""
        self.offer.check();digest(bundle_hash)
        nullifier=self.offer.protocol.verify(token)
        prior=self.queue.lookup(nullifier,bundle_hash)
        if prior is None:
            # No new public ingress under an expired/unfunded offer. This does
            # not bind a ticket or allocate a nonce; all I/O is budgeted below.
            self.queue.preflight(self.offer.terms['max_gas'])
            self.queue.check_admission_time(self.offer.terms['redeem_before'])
        value=self._validate_bytes(raw,bundle_hash)
        stored=self.content.upload(value)
        require(stored['bundle_hash']==bundle_hash and stored['readback_checked'] is True,'ticket-worker-storage')
        return stored

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
            self._validate_and_store(h)
            self.queue.preflight(job['gas'])
            status=self.queue.submit_bound(h)
        return self._reply(job,nullifier,status['state'],status,None)

    def _reply(self,job,nullifier,state,status,number):
        return {'profile':PROFILE,'parameters':self.offer.hash,'bundle_hash':job['bundle_hash'],
            'operation':job['operation'],'ticket_used':job['nullifier']==nullifier,
            'state':state,'post_number':number,
            'transaction_hash':None if status is None else status['transaction_hash']}

    def submit(self,token,bundle_hash):
        self.offer.check();digest(bundle_hash)
        nullifier=self.offer.protocol.verify(token)
        prior=self.queue.lookup(nullifier,bundle_hash)
        if prior is not None:return self._resume(prior,nullifier)
        indexed=self.index.record_for_hash(bundle_hash)
        if indexed is None:
            self._validate_and_store(bundle_hash)
            self.queue.preflight(self.offer.terms['max_gas'])
        t=self.offer.terms
        job=self.queue.admit(nullifier,self.offer.hash,bundle_hash,gas=t['max_gas'],
            fee_ceiling=int(t['max_total_fee_wei']),redeem_before=t['redeem_before'],indexed=indexed)
        return self._resume(job,nullifier)

    def recover_pending(self,limit=4):
        """Bounded unattended recovery of already accepted work only."""
        result=[]
        for job in self.queue.pending_jobs(limit):
            try:result.append(self._resume(job,job['nullifier']))
            except Exception:
                result.append({'operation':job['operation'],'state':'recovery-unavailable'})
        return result
