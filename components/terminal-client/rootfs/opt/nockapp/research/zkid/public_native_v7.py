"""Client-verified refund recovery; service claims cannot confirm a payout."""
import copy
from policy import digest,require
from public_native_v6 import PublicApplicationV6
from ticket_offer_v1 import hex_value
from ticket_payment_v1 import FinalizedTicketPayment
from ticket_refund_v1 import refund_data,authorize_refund
from ticket_refund_vault_v1 import scope,RefundVaultReader

class PublicApplicationV7(PublicApplicationV6):
    def __init__(self,desktop,tickets,payment,refund,policy,policy_sha256):
        super().__init__(desktop,tickets,payment)
        self.refund,self.refund_policy=refund,scope(policy,tickets.offer,policy_sha256)
        self.refund_policy_sha256=policy_sha256
        self.refund_reader=RefundVaultReader(desktop.index.rpc,tickets.offer,policy,policy_sha256)

    def _refund_progress(self,pack_hash):
        return {'profile':'nockapp-public-refund-progress-v1','parameters':self.tickets.offer.hash,
            'pack_hash':pack_hash,'state':'not-confirmed','payout_confirmed':False}

    def _refund_check(self,pack_hash,*,resume=False):
        record=self.tickets.refund_record(pack_hash);p=record['pending'];saved=p['refund_intent']
        require(saved['policy_sha256']==self.refund_policy_sha256,'ticket-refund-policy-changed')
        payments=FinalizedTicketPayment(self.desktop.index.rpc,self.tickets.offer)
        verified=payments.verify(p['pack'],p['payment_tx'])
        authorize_refund(self.tickets.offer,payments,verified,saved['signature'])
        tx=self.desktop.index.rpc.call('eth_getTransactionByHash',p['payment_tx'])
        require(type(tx) is dict,'ticket-refund-payment')
        def public_payout():
            result=self.refund_reader.payout(pack_hash,p['payment_tx'],tx['from'])
            if result is not None:return self.tickets.complete_refund(self.refund_policy,result)
            require(not record['archived'],'ticket-refund-archive-finality-violation')
            return None
        found=public_payout()
        if found is not None:return found # Recovery works with both services offline.
        if resume:
            # Original saved signature, never a browser replacement or a new
            # wallet prompt. The paid issue/refund fence precedes payout work.
            request={'pack':copy.deepcopy(p['pack']),'transaction_hash':p['payment_tx'],'signature':saved['signature']}
            decision=self.payment.call('refund',request)
            require(decision.get('mode')=='refund' and decision.get('payment')==verified,'ticket-refund-response')
            policy=self.refund.call('policy',{})
            require(policy=={'policy':self.refund_policy,'sha256':self.refund_policy_sha256},'ticket-refund-policy-changed')
            reply=self.refund.call('submit',{'pack_hash':pack_hash,'signature':saved['signature']})
            require(reply.get('parameters')==self.tickets.offer.hash and reply.get('pack_hash')==pack_hash,'ticket-refund-response')
            # Even an authenticated server's payout_confirmed:true is a hint.
            found=public_payout()
            if found is not None:return found
        return self._refund_progress(pack_hash)

    def dispatch(self,operation,body):
        require(type(operation) is str and type(body) is dict,'v7-native-schema')
        if operation=='public-capabilities':
            return {**super().dispatch(operation,body),'verifier_release':7,'refund_payout_configured':True}
        if operation=='public-ticket-refund-state':
            require(not body,'v7-native-schema');w=self.tickets.wallet
            if w.metadata() is None:
                require(w.read('credential.sealed',missing=True) is None,'ticket-wallet-incomplete')
                state={'pending':None,'completed':[],'archive_limit':8}
            else:state=self.tickets.refund_state()
            return {'profile':'nockapp-public-refund-state-v1','policy':copy.deepcopy(self.refund_policy),
                'policy_sha256':self.refund_policy_sha256,**state}
        if operation in ('public-ticket-refund-recover','public-ticket-refund-status'):
            require(set(body)=={'pack_hash'},'v7-native-schema');hex_value(body['pack_hash'],32)
            return self._refund_check(body['pack_hash'],resume=operation.endswith('recover'))
        if operation=='public-ticket-refund-request':
            require(not body,'v7-native-schema');self.tickets.ensure_refund_capacity(self.refund_policy)
        if operation=='public-ticket-refund-result':
            require(set(body)=={'request_sha256','signature'},'v7-native-schema')
            request=self.tickets.issuance_request();payments=FinalizedTicketPayment(self.desktop.index.rpc,self.tickets.offer)
            verified=payments.verify(**request);data=refund_data(self.tickets.offer,verified['pack_hash'],request['transaction_hash'])
            require(body['request_sha256']==digest(data),'ticket-refund-request-changed')
            authorize_refund(self.tickets.offer,payments,verified,body['signature'])
            self.tickets.save_refund(self.refund_policy,body['request_sha256'],body['signature'])
            return self._refund_check(verified['pack_hash'],resume=True)
        return super().dispatch(operation,body)
