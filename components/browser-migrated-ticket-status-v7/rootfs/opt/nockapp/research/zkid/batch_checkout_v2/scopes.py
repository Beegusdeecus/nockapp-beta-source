"""Local scope routing preserves old tickets, assignments and uncertain buys.

Never sends a history list or reusable buyer identifier. Each operation goes to
one installer-pinned service using its original offer and existing reservation.
"""
from contextlib import contextmanager,ExitStack
from policy import require
from ticket_wallet_v1 import TicketWallet,MAX_TICKETS
from ticket_bulk_purchase_v1 import active
from ticket_publisher_v2 import TicketPublisher
from ticket_public_client_v2 import TicketPublicRelay
from ticket_offer_v1 import hex_value


class TicketScopes:
    def __init__(self,primary,legacy,*,rpc=None):
        require(type(legacy) in (list,tuple) and len(legacy)<=4,'ticket-scopes')
        self.rows=[*legacy,primary];self.primary=primary;self.rpc=rpc
        require(all(type(row) is tuple and len(row)==2 and isinstance(row[0],TicketWallet)
            and callable(getattr(row[1],'submit',None))for row in self.rows),'ticket-scopes')
        hashes=[w.offer.hash for w,_ in self.rows];paths=[w.wallet.directory for w,_ in self.rows]
        require(len(set(hashes))==len(hashes) and len(set(paths))==len(paths),'ticket-scopes-duplicate')
        expected={k:primary[0].offer.terms[k]for k in ('chain_id','application','index_contract','index_runtime_keccak')}
        for wallet,_ in self.rows:
            wallet.offer.check()
            require(all(wallet.offer.terms[k]==v for k,v in expected.items()),'ticket-scopes-context')
        for wallet,remote in self.rows:
            approved=getattr(remote,'approved',None)
            require(type(approved) is dict and approved.get('service')=='publication'
                and approved.get('offer_sha256')==wallet.offer.hash,'ticket-scopes-endpoint')
        require(all(not a.is_relative_to(b) and not b.is_relative_to(a)
            for i,a in enumerate(paths) for b in paths[i+1:]),'ticket-scopes-overlap')

    @contextmanager
    def locked(self,*,legacy_only=False):
        rows=self.rows[:-1]if legacy_only else self.rows
        with ExitStack() as stack:
            for wallet,_ in sorted(rows,key=lambda row:str(row[0].wallet.directory)):
                stack.enter_context(wallet.wallet.controller_lock())
            yield

    @staticmethod
    def _record(wallet):
        if wallet.wallet.metadata() is None:
            require(wallet.wallet.read('credential.sealed',missing=True) is None
                and wallet.wallet.read('pending.sealed',missing=True) is None,'ticket-scopes-incomplete')
            return None
        return wallet._load()

    def status(self,*,include_initialization=False,now=None):
        with self.locked():
            records=[(w,self._record(w))for w,_ in self.rows]
            result={'available':sum(sum(t['bundle_hash'] is None for t in r['tickets'])for _,r in records if r),
                'reserved':sum(sum(t['bundle_hash'] is not None for t in r['tickets'])for _,r in records if r)}
            if include_initialization:
                initialized=any(r is not None for _,r in records)
                result.update(initialized=initialized,purchase_pending=any(
                    r is not None and(r['pending']is not None or active(w))for w,r in records))
                if initialized:result['profile']='nockapp-protected-ticket-wallet-v1'
                if now is not None:
                    require(type(now)is int,'ticket-scopes-clock')
                    result['legacy_purchase_clear']=all(self._legacy_clear(w,r,now)
                        for w,r in records if w is not self.primary[0])
            return result

    def _legacy_clear(self,wallet,record,now):
        if record is None:return True
        bulk=active(wallet);pending=record['pending']
        if not bulk and(pending is None or set(pending)=={'pack_hash','pack','requests','payment_tx'}and pending['payment_tx']is None):return True
        # Status is read-only and conservative. Before expiry no chain query can
        # prove terminal nonpayment; afterward reuse the actual admission proof.
        if now<wallet.offer.terms['purchase_before']:return False
        try:
            if bulk:
                from ticket_bulk_purchase_v1 import BulkPurchase
                from .offer import BatchOffer
                from .purchase import BatchPurchase
                controller=BatchPurchase if isinstance(wallet.offer,BatchOffer)else BulkPurchase
                value=controller(wallet,self.rpc,None)._read()
                self._terminal(wallet,[p['pack_hash']for p in value['items']],value['anchor'])
            else:self._terminal(wallet,[pending['pack_hash']],pending.get('payment_intent',{}).get('anchor'))
            return True
        except Exception:return False

    @contextmanager
    def purchase_guard(self,count):
        require(type(count) is int and count in (2,50),'ticket-scopes-count')
        # The primary controller acquires its own lock inside this context.
        # Foreign controllers are held throughout admission, so they cannot
        # arm an old request or consume capacity while a new batch is prepared.
        with self.locked(legacy_only=True):
            total=0
            for wallet,remote in self.rows:
                r=self._record(wallet)
                if r is None:continue
                total+=len(r['tickets'])
                if wallet is self.primary[0]:continue
                if active(wallet):
                    from ticket_bulk_purchase_v1 import BulkPurchase
                    from .offer import BatchOffer
                    from .purchase import BatchPurchase
                    controller=BatchPurchase if isinstance(wallet.offer,BatchOffer)else BulkPurchase
                    b=controller(wallet,self.rpc,remote)._read()
                    self._terminal(wallet,[p['pack_hash']for p in b['items']],b['anchor'])
                    # Keep the complete old journal and its inputs untouched.
                    # Finalized unpaid expiry means it can never issue tickets.
                    continue
                p=r['pending']
                if p is not None:
                    unarmed=set(p)=={'pack_hash','pack','requests','payment_tx'}and p['payment_tx'] is None
                    if unarmed:total+=wallet.offer.terms['pack_size']
                    else:self._terminal(wallet,[p['pack_hash']],p.get('payment_intent',{}).get('anchor'))
            require(total+count<=MAX_TICKETS,'ticket-wallet-full')
            yield

    def _terminal(self,wallet,packs,anchor):
        from ticket_offer_v1 import configured_payments
        from .terminal import unpaid_after_deadline
        require(self.rpc is not None,'ticket-legacy-purchase-unresolved')
        verifier=type(configured_payments(self.rpc,wallet.offer))
        if anchor is None:
            final=verifier(self.rpc,wallet.offer).preflight()
            anchor={k:final[k]for k in ('number','hash')}
        unpaid_after_deadline(self.rpc,wallet.offer,packs,anchor,payment_type=verifier)

    def select(self,bundle_hash,now):
        hex_value(bundle_hash,32)
        with self.locked():
            rows=[(w,remote,self._record(w))for w,remote in self.rows]
            matching=[(w,remote)for w,remote,r in rows if r is not None
                and any(t['bundle_hash']==bundle_hash for t in r['tickets'])]
            require(len(matching)<=1,'ticket-scopes-binding-conflict')
            if matching:return matching[0]
            eligible=[(w,remote)for w,remote,r in rows if r is not None
                and now<w.offer.terms['redeem_before'] and any(t['bundle_hash'] is None for t in r['tickets'])]
            require(eligible,'ticket-wallet-empty')
            wallet,remote=eligible[0];wallet._reserve_locked(bundle_hash,now)
            return wallet,remote


class ScopedRelay:
    def __init__(self,scopes,index,clock):self.scopes,self.index,self.clock=scopes,index,clock
    def submit(self,bundle_hash):
        wallet,remote=self.scopes.select(bundle_hash,int(self.clock()))
        return TicketPublicRelay(TicketPublisher(wallet,remote.submit,clock=self.clock),self.index).submit(bundle_hash)


class ScopedOrigin:
    def __init__(self,reader,scopes,clock):self.reader,self.scopes,self.clock=reader,scopes,clock
    def get(self,h,limit):return self.reader.get(h,limit)
    def put(self,h,raw):
        from public_bundle_v5 import decode
        decode(raw,h);wallet,remote=self.scopes.select(h,int(self.clock()))
        token=wallet.reserve(h,int(self.clock()))
        result=remote.store(token,h,raw)
        require(type(result) is dict and set(result)=={'bundle_hash','bytes','readback_checked','permanent_availability_proven'}
            and result['bundle_hash']==h and result['bytes']==len(raw)
            and result['readback_checked'] is True and result['permanent_availability_proven'] is False,'ticket-origin-response')
        return result
