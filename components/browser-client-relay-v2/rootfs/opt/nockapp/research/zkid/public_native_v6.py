"""Installed public operations, with private ticket recovery kept off-browser."""
import hashlib
import copy
from contextlib import ExitStack
from public_native_v5 import PublicApplicationV5
from policy import require,digest,Rejected
from ticket_payment_v1 import FinalizedTicketPayment,_quantity
from ticket_offer_v1 import hex_value
from ticket_payment_recovery_v2 import find_payment,budgeted_rpc,check_closed_payments,require_unpaid,failed_payment_proof
from ticket_payment_recovery_v3 import find_finalized_payment,verified_payment
from ticket_refund_v1 import refund_data


class PublicApplicationV6(PublicApplicationV5):
    def __init__(self,desktop,tickets,payment):
        super().__init__(desktop);self.tickets=tickets;self.payment=payment

    def _identity_sources(self):
        from count_desktop import CountDesktop
        from domain_desktop import DomainDesktop
        from renewal_desktop_v3 import RenewalDesktop
        rows=[];author=self.desktop.author
        for source in (*author.previous_authors,*author.legacy_sources):
            # Renewal records have their own same-holder recovery coordinator;
            # never offer their different schema as a legacy domain adoption.
            if isinstance(source,RenewalDesktop):continue
            kind=('author-v4' if source in author.previous_authors else
                'count-v2' if isinstance(source,CountDesktop) else 'domain-v1' if isinstance(source,DomainDesktop) else None)
            require(kind is not None,'v6-identity-source')
            source_id=digest({'kind':kind,'directory':str(source.wallet.directory),
                'binding':getattr(source,'binding',None),'metadata':source.wallet.metadata(),
                'record_sha256':hashlib.sha256(source.wallet.read('credential.sealed',missing=True) or b'').hexdigest(),
                'issuer':author.binding['issuer_definition']})
            rows.append((source_id,kind,source))
        return rows

    def _ticket_status(self):
        w=self.tickets.wallet
        if w.metadata() is None:
            require(w.read('credential.sealed',missing=True) is None,'ticket-wallet-incomplete')
            state={'available':0,'reserved':0,'purchase_pending':False,'initialized':False}
        else:state={**self.tickets.status(),'initialized':True}
        now=int(self.desktop.clock());t=self.tickets.offer.terms
        return {**state,'can_purchase':now<t['purchase_before'],'can_redeem':now<t['redeem_before'],
            'pack_size':t['pack_size'],'pack_price_wei':t['pack_price_wei'],
            'purchase_before':t['purchase_before'],'redeem_before':t['redeem_before'],
            'refund_policy':t['refund_policy'],'prepaid_custody':True}

    def dispatch(self,operation,body):
        require(type(operation) is str and type(body) is dict,'v6-native-schema')
        if operation=='public-wallet-request':
            require(set(body)=={'post_id','address','approve_address_disclosure'} and body['approve_address_disclosure'] is True,
                'consent-required')
            return self.desktop.request_address(body['post_id'],body['address'],True,public_binding=True)
        if operation=='public-wallet-result':
            require(set(body)=={'post_id','request_sha256','signature'},'v6-native-schema')
            return self.desktop.accept_address(body['post_id'],body['request_sha256'],body['signature'],finish=True)
        if operation=='public-wallet-finish':
            require(set(body)=={'post_id','request_sha256','approve_save'} and body['approve_save'] is True,'consent-required')
            return self.desktop.finish_wallet(body['post_id'],body['request_sha256'])
        if operation=='public-wallet-recover':
            require(set(body)=={'post_id','approve_save'} and body['approve_save'] is True,'consent-required')
            return self.desktop.finish_wallet(body['post_id'])
        if operation=='public-wallet-reset':
            require(set(body)=={'post_id','request_sha256','approve_fresh_request'} and body['approve_fresh_request'] is True,'consent-required')
            return self.desktop.reset_unfinished_address(body['post_id'],body['request_sha256'],True)
        if operation=='public-page':
            require(set(body)=={'after','limit'},'v6-native-schema')
            return self.desktop.reader.read_page(body['after'],body['limit'],int(self.desktop.clock()))
        if operation=='public-capabilities':
            result=super().dispatch(operation,body)
            return {**result,'verifier_release':6,'anonymous_ticket_packs':True,
                'source_enrollment_configured':False,'historical_issuer_views':self.desktop.reader.issuer_views is not None}
        if operation=='public-identity-options':
            require(not body,'v6-native-schema');author=self.desktop.author
            return {'identity_record_present':author.wallet.read('credential.sealed',missing=True) is not None,
                'sources':[{'source_id':ident,'kind':kind,
                    'identity_record_present':source.wallet.read('credential.sealed',missing=True) is not None,
                    'pending_recovery':source.wallet.read('pending.sealed',missing=True) is not None}
                    for ident,kind,source in self._identity_sources()]}
        if operation=='public-initialize-identity':
            require(set(body)=={'approve_private_key_setup'} and body['approve_private_key_setup'] is True,'consent-required')
            # Choosing one existing authority is a distinct explicit decision.
            # The older desktop convenience method auto-selects a sole source.
            author=self.desktop.author
            with author.transaction(),ExitStack() as locks:
                sources=sorted((*author.previous_authors,*author.legacy_sources),key=lambda s:str(s.wallet.directory))
                for source in sources:locks.enter_context(source.transaction())
                if author.wallet.read('credential.sealed',missing=True) is None:
                    for source in sources:
                        require(source.wallet.metadata() is None and all(source.wallet.read(n,missing=True) is None
                            for n in ('credential.sealed','pending.sealed','post.sealed')),'v6-identity-reuse-or-recovery-required')
                return author.initialize(int(self.desktop.clock()),True)
        if operation=='public-adopt-identity':
            require(set(body)=={'source_id','approve_key_reuse'} and body['approve_key_reuse'] is True,'consent-required')
            rows=[row for row in self._identity_sources() if row[0]==body['source_id']]
            require(len(rows)==1,'v6-identity-source');_,kind,source=rows[0];author=self.desktop.author
            # Match the approved encrypted record again under the same lock
            # order used by adoption; a concurrently replaced record is a new
            # decision, even if it uses the same storage/keyring metadata.
            with author.transaction(),source.transaction():
                require(any(ident==body['source_id'] and old is source for ident,_,old in self._identity_sources()),
                    'v6-identity-source-changed')
                return (author.adopt_author if kind=='author-v4' else author.adopt)(source,int(self.desktop.clock()),True)
        if operation=='public-ticket-status':
            require(not body,'v6-native-schema');return self._ticket_status()
        if operation=='public-ticket-offer':
            require(not body,'v6-native-schema');self.tickets.offer.check()
            return {'manifest':copy.deepcopy(self.tickets.offer.manifest),'parameters':self.tickets.offer.hash}
        if operation=='public-ticket-pending':
            require(not body,'v6-native-schema')
            if self.tickets.wallet.metadata() is None:
                require(self.tickets.wallet.read('credential.sealed',missing=True) is None,'ticket-wallet-incomplete')
                return {'profile':'nockapp-public-ticket-purchase-state-v1','purchase':None,
                    'payment_intent':None,'closed_attempts':0,'attempt_limit':8}
            return self.tickets.purchase_state()
        if operation=='public-ticket-arm':
            require(set(body)=={'pack_hash','payer','nonce','approve_payment'} and body['approve_payment'] is True,
                'consent-required')
            hex_value(body['pack_hash'],32);hex_value(body['payer'],20)
            require(type(body['nonce']) is int and 0<=body['nonce']<2**64,'ticket-payment-nonce')
            offer=self.tickets.offer;rpc=budgeted_rpc(self.desktop.index.rpc)
            final=FinalizedTicketPayment(rpc,offer).preflight()
            check_closed_payments(rpc,self.tickets.closed_payments(),final)
            require_unpaid(rpc,offer,body['pack_hash'],final['number'])
            require_unpaid(rpc,offer,body['pack_hash'],'latest')
            require(int(self.desktop.clock())<offer.terms['purchase_before']
                and _quantity(final['timestamp'])<offer.terms['purchase_before'],'ticket-purchases-closed')
            require(_quantity(rpc.call('eth_getTransactionCount',body['payer'],'pending'))==body['nonce'],
                'ticket-payment-nonce-changed')
            require(_quantity(rpc.call('eth_getTransactionCount',body['payer'],final['number']))<=body['nonce'],
                'ticket-payment-nonce-changed')
            current=rpc.call('eth_getBlockByNumber',final['number'],False)
            require(type(current) is dict and current.get('hash')==final['hash'],'ticket-payment-finality-changed')
            return self.tickets.arm_payment(body['pack_hash'],body['payer'],body['nonce'],True,
                anchor={'number':final['number'],'hash':final['hash']})
        if operation=='public-ticket-intent':
            require(not body,'v6-native-schema');return self.tickets.payment_intent()
        if operation=='public-ticket-close-attempt':
            require(set(body)=={'pack_hash','payment_intent_sha256','approve_close_attempt'}
                and body['approve_close_attempt'] is True,'consent-required')
            hex_value(body['pack_hash'],32)
            previous=self.tickets.closed_payments()
            matches=[proof for proof in previous if proof['pack_hash']==body['pack_hash']
                and digest(proof['intent'])==body['payment_intent_sha256']]
            require(len(matches)<=1,'ticket-closed-payment-duplicate')
            if matches:return self.tickets._closed_result(matches[0])
            view=self.tickets.payment_intent()
            require(view['pack_hash']==body['pack_hash']
                and digest(view['payment_intent'])==body['payment_intent_sha256'],'ticket-payment-intent-changed')
            proof=failed_payment_proof(self.desktop.index.rpc,self.tickets.offer,view,previous)
            return self.tickets._close_payment(view,proof)
        if operation=='public-ticket-find':
            require(not body,'v6-native-schema')
            view=self.tickets.payment_intent()
            paid=find_finalized_payment(self.desktop.index.rpc,self.tickets.offer,view)
            if paid['state']=='payment-found':
                saved=self.tickets.recover_verified_payment(view,paid['payment'],paid['payer'])
                return {**saved,'search_state':'transaction-found','receipt_status':'0x1',
                    'checked_through':paid['checked_through']}
            found=find_payment(self.desktop.index.rpc,view)
            if found['state']=='transaction-found':
                saved=self.tickets.recover_payment(found['transaction'])
                return {**saved,'search_state':found['state'],'receipt_status':found['receipt_status'],
                    'checked_through':found['checked_through']}
            require(self.tickets.payment_intent()==view,'ticket-payment-intent-changed')
            return {**view,'search_state':found['state'],
                'checked_through':found['checked_through']}
        if operation=='public-ticket-prepare':
            require(set(body)=={'approve_purchase'} and body['approve_purchase'] is True,'consent-required')
            self.tickets.initialize()
            return self.tickets.prepare_purchase(int(self.desktop.clock()),True)
        if operation=='public-ticket-payment':
            require(set(body)=={'pack_hash','transaction_hash'},'v6-native-schema')
            pending=self.tickets.wallet.load('credential')['pending']
            if pending is not None and 'payment_intent' in pending:
                hex_value(body['transaction_hash'],32)
                require(pending['pack_hash']==body['pack_hash'],'ticket-purchase-conflict')
                tx=self.desktop.index.rpc.call('eth_getTransactionByHash',body['transaction_hash'])
                require(type(tx) is dict and tx.get('hash')==body['transaction_hash'],'ticket-payment-unavailable')
                try:return self.tickets.recover_payment(tx)
                except Rejected as error:
                    if error.args!=('ticket-payment-intent-mismatch',):raise
                view=self.tickets.payment_intent()
                payment,payer=verified_payment(self.desktop.index.rpc,self.tickets.offer,view,body['transaction_hash'])
                return self.tickets.recover_verified_payment(view,payment,payer)
            return self.tickets.record_payment(body['pack_hash'],body['transaction_hash'])
        if operation=='public-ticket-recover':
            require(not body,'v6-native-schema')
            if self.tickets.wallet.load('credential')['pending'] is None:return self._ticket_status()
            request=self.tickets.issuance_request()
            return self.tickets.receive(self.payment.issue(**request))
        if operation in ('public-ticket-refund-request','public-ticket-refund-result'):
            require(set(body)==(set() if operation.endswith('request') else {'request_sha256','signature'}),'v6-native-schema')
            request=self.tickets.issuance_request();offer=self.tickets.offer
            verified=FinalizedTicketPayment(self.desktop.index.rpc,offer).verify(**request)
            data=refund_data(offer,verified['pack_hash'],request['transaction_hash']);h=digest(data)
            if operation.endswith('request'):
                payer=FinalizedTicketPayment(self.desktop.index.rpc,offer).canonical_payer(verified)
                return {'address':payer,'typed_data':data,'request_sha256':h}
            require(body['request_sha256']==h,'ticket-refund-request-changed')
            decision=self.payment.call('refund',{**request,'signature':body['signature']})
            require(decision.get('mode')=='refund' and decision.get('payment')==verified,'ticket-refund-response')
            # This is a cancellation fence, not evidence that a payout mined.
            return {'state':'cancellation-recorded','payout_confirmed':False}
        return super().dispatch(operation,body)
