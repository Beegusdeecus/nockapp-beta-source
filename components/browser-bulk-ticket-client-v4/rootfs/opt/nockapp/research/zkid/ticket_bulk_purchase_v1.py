"""One atomic wallet payment for existing shared packs; no server changes.

All blind inputs are encrypted before dispatch. An armed batch never grants a
second dispatch. Chain evidence, not a wallet reply, authorizes each import.
"""
import copy,hashlib
from base_evm import encode
from policy import canonical,require
from ticket_offer_v1 import hex_value
from ticket_payment_v1 import EVENT,FinalizedTicketPayment
from ticket_payment_recovery_v2 import budgeted_rpc,check_anchor,require_unpaid
from ticket_payment_recovery_v3 import find_finalized_payment
from ticket_payment_progress_v1 import progress
from ticket_wallet_v1 import MAX_TICKETS,PAYMENT_INTENT_V2,payment_anchor
from wallet import MAX_PLAIN

PROFILE='nockapp-ticket-bulk-purchase-v1'
PHASES=('prepared','armed','importing','paused','complete')

def active(tickets):
    if tickets.wallet.read('pending.sealed',missing=True) is None:return False
    value=tickets.wallet.load('pending')
    require(type(value) is dict and value.get('profile')==PROFILE and value.get('phase') in PHASES,'ticket-bulk-record')
    return value['phase']!='complete'

class BulkPurchase:
    def __init__(self,tickets,rpc,payment):self.tickets,self.rpc,self.payment=tickets,rpc,payment

    def _read(self):
        t=self.tickets
        if t.wallet.read('pending.sealed',missing=True) is None:return None
        b=t.wallet.load('pending')
        require(type(b) is dict and set(b)=={'profile','parameters','worker_sha256','batch_id','phase','items','imported','refunded','payer','anchor','transaction_hash'}
            and b['profile']==PROFILE and b['parameters']==t.offer.hash and b['worker_sha256']==t.offer.protocol.native.sha256
            and b['phase'] in PHASES and type(b['items']) is list and len(b['items'])==25
            and t.offer.terms['pack_size']==2 and type(b['imported']) is int and 0<=b['imported']<=25,'ticket-bulk-record')
        ids=[]
        for item in b['items']:t._validate_pending(item);ids.append(item['pack_hash'])
        require(len(set(ids))==25 and b['batch_id']==hashlib.sha256(canonical({'parameters':t.offer.hash,'packs':ids})).hexdigest(),'ticket-bulk-record')
        require(type(b['refunded']) is list and len(set(b['refunded']))==len(b['refunded'])
            and all(h in ids[:b['imported']]for h in b['refunded']),'ticket-bulk-record')
        require((b['phase']=='complete')==(b['imported']==25),'ticket-bulk-record')
        if b['phase']=='prepared':require(b['payer'] is b['anchor'] is b['transaction_hash'] is None and b['imported']==0,'ticket-bulk-record')
        else:hex_value(b['payer'],20);payment_anchor(b['anchor'])
        if b['transaction_hash'] is not None:hex_value(b['transaction_hash'],32)
        if b['imported']:require(b['transaction_hash'] is not None,'ticket-bulk-record')
        return b

    def _write(self,b):
        require(len(canonical(b))<=MAX_PLAIN,'ticket-bulk-capacity')
        self.tickets.wallet.save('pending',b);require(self._read()==b,'ticket-bulk-readback')

    def _public(self,b):
        if b is None:return {'profile':PROFILE,'phase':'none'}
        offer=self.tickets.offer
        return {'profile':PROFILE,'phase':b['phase'],'batch_id':b['batch_id'],'ticket_count':50,'pack_count':25,
            'imported_tickets':(b['imported']-len(b['refunded']))*2,'settled_tickets':b['imported']*2,'refunded_tickets':len(b['refunded'])*2,
            'payer':b['payer'],'transaction_hash':b['transaction_hash'],
            'total_price_wei':str(25*int(offer.terms['pack_price_wei'])),
            'calls':[{'to':offer.manifest['purchase_contract'],'value':hex(int(offer.terms['pack_price_wei'])),
                'data':encode('buy(bytes32)',item['pack_hash'])}for item in b['items']]}

    def status(self):
        if self.tickets.wallet.metadata() is None:return self._public(None)
        with self.tickets.wallet.controller_lock():return self._public(self._read())

    def prepare(self,now,approve_purchase):
        require(approve_purchase is True,'consent-required');t=self.tickets
        t.initialize()
        with t.wallet.controller_lock():
            previous=self._read()
            if previous is not None:return self._public(previous)
            r=t._load();require(r['pending'] is None,'ticket-existing-purchase')
            require(t.offer.terms['pack_size']==2 and type(now) is int and 0<=now<t.offer.terms['purchase_before'],'ticket-bulk-offer')
            require(len(r['tickets'])+50<=MAX_TICKETS,'ticket-wallet-full')
            items=[]
            for _ in range(25):
                requests=[t.offer.protocol.prepare()for _ in range(2)];pack=t.offer.protocol.blinded_pack(requests)
                items.append({'pack_hash':t.offer.pack_hash(pack),'pack':pack,'requests':requests,'payment_tx':None})
            b={'profile':PROFILE,'parameters':t.offer.hash,'worker_sha256':t.offer.protocol.native.sha256,
                'batch_id':hashlib.sha256(canonical({'parameters':t.offer.hash,'packs':[p['pack_hash']for p in items]})).hexdigest(),
                'phase':'prepared','items':items,'imported':0,'refunded':[],'payer':None,'anchor':None,'transaction_hash':None}
            self._write(b);return self._public(b)

    def arm(self,batch_id,payer,approve_payment):
        require(approve_payment is True,'consent-required');hex_value(payer,20);t=self.tickets
        with t.wallet.controller_lock():
            b=self._read();require(b is not None and b['batch_id']==batch_id and b['phase']=='prepared','ticket-bulk-dispatch-already-armed')
            require(t._load()['pending'] is None,'ticket-existing-purchase')
            rpc=budgeted_rpc(self.rpc,max_calls=96);final=FinalizedTicketPayment(rpc,t.offer).preflight()
            require(int(final['timestamp'],16)<t.offer.terms['purchase_before'],'ticket-purchases-closed')
            for item in b['items']:
                require_unpaid(rpc,t.offer,item['pack_hash'],final['number'])
                require_unpaid(rpc,t.offer,item['pack_hash'],'latest')
            anchor=payment_anchor({'number':final['number'],'hash':final['hash']});check_anchor(rpc,anchor)
            b.update(phase='armed',payer=payer,anchor=anchor);self._write(b)
            return {**self._public(b),'dispatch_authorized':True}

    def payment_progress(self,batch_id):
        with self.tickets.wallet.controller_lock():
            b=self._read();require(b is not None and b['batch_id']==batch_id,'ticket-bulk-missing')
            p=progress(self.rpc,self.tickets.offer,b['items'][0]['pack_hash'])
            return {**p,'batch_id':batch_id}

    def _verify_atomic_receipt(self,b,tx):
        offer=self.tickets.offer;payments=FinalizedTicketPayment(self.rpc,offer)
        payment,payer=payments._verified(b['items'][0]['pack_hash'],tx)
        require(payer==b['payer'] and int(payment['block_number'],16)>int(b['anchor']['number'],16),'ticket-bulk-payment-payer')
        receipt=self.rpc.call('eth_getTransactionReceipt',tx);expected={p['pack_hash']for p in b['items']};seen=set()
        for log in receipt['logs']:
            topics=log.get('topics')
            if log.get('address','').lower()!=offer.manifest['purchase_contract'] or type(topics) is not list or not topics or topics[0]!=EVENT:continue
            topics=log['topics']
            if len(topics)!=3 or topics[1] not in expected:continue
            require(topics[1] not in seen and topics[2]=='0x'+'0'*24+payer[2:]
                and log.get('data')=='0x'+int(offer.terms['pack_price_wei']).to_bytes(32,'big').hex()
                and log.get('transactionHash')==tx and log.get('blockHash')==payment['block_hash']
                and log.get('blockNumber')==payment['block_number'] and not log.get('removed',False),'ticket-bulk-payment-event')
            seen.add(topics[1])
        require(seen==expected,'ticket-bulk-payment-not-atomic')
        payments.finish(payment);check_anchor(self.rpc,b['anchor'])

    def recover(self,batch_id,approve_import,*,resume=False,prepare_refund=False):
        require(approve_import is True,'consent-required');t=self.tickets
        with t.wallet.controller_lock():
            b=self._read();require(b is not None and b['batch_id']==batch_id and b['phase']!='prepared','ticket-bulk-not-sent')
            if b['phase']=='complete':return self._public(b)
            require(b['phase']!='paused' or resume or prepare_refund,'ticket-bulk-paused')
            if b['transaction_hash'] is None:
                view={'pack_hash':b['items'][0]['pack_hash'],'payment_intent':{'profile':PAYMENT_INTENT_V2,
                    'payer':b['payer'],'nonce':0,'anchor':b['anchor']}}
                found=find_finalized_payment(self.rpc,t.offer,view)
                if found['state']!='payment-found':return self._public(b)
                tx=found['payment']['transaction_hash'];self._verify_atomic_receipt(b,tx)
                b.update(transaction_hash=tx,phase='importing');self._write(b)
            else:self._verify_atomic_receipt(b,b['transaction_hash'])
            p=copy.deepcopy(b['items'][b['imported']]);p['payment_tx']=b['transaction_hash'];r=t._load()
            refunds=t._refund_archive()['entries']
            refunded=any(v['pending']['pack_hash']==p['pack_hash'] and v['pending']['payment_tx']==p['payment_tx']for v in refunds)
            if refunded:
                require(r['pending'] is None,'ticket-existing-purchase');b['refunded'].append(p['pack_hash'])
            elif r['pending'] is None and r['last_import']==p['pack_hash']:
                pass # Previous import committed; only the bulk cursor reply was lost.
            else:
                if prepare_refund:
                    require(r['pending'] is None or r['pending']==p,'ticket-existing-purchase')
                    b['phase']='paused';self._write(b)
                    if r['pending'] is None:r['pending']=p;t._save(r)
                    return self._public(b)
                require(r['pending'] is None or r['pending']==p,'ticket-existing-purchase')
                if r['pending'] is None:r['pending']=p;t._save(r)
                reply=self.payment.issue(pack=p['pack'],transaction_hash=p['payment_tx'])
                t._receive_locked(reply)
            b['imported']+=1
            b['phase']='complete' if b['imported']==25 else 'paused' if prepare_refund else 'importing'
            self._write(b);return self._public(b)
