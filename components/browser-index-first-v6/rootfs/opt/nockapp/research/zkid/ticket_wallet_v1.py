"""Encrypted, account-free client ticket wallet; no authorship/source secrets.

One pending purchase and bounded ticket inventory, atomic readback before any
payment/redemption projection escapes. No automatic reset of a bound ticket.
"""
import copy
from pathlib import Path
from base_evm import encode
from policy import canonical,require
from ticket_offer_v1 import TicketOffer,hex_value
from ticket_issuance_v1 import REPLY
from wallet import Wallet,MAX_PLAIN
import hashlib
import re

PROFILE='nockapp-protected-ticket-wallet-v1'
MAX_TICKETS=64
PAYMENT_INTENT='nockapp-ticket-wallet-payment-intent-v1'
PAYMENT_INTENT_V2='nockapp-ticket-wallet-payment-intent-v2'
CLOSED_PAYMENT='nockapp-ticket-wallet-closed-payment-v1'
MAX_CLOSED_PAYMENTS=8
REFUND_INTENT='nockapp-ticket-wallet-refund-intent-v1'
REFUND_ARCHIVE='nockapp-ticket-wallet-refund-archive-v1'
MAX_REFUNDS=8


def _nonce(value):
    require(type(value) is int and 0<=value<2**64,'ticket-payment-nonce')
    return value


def payment_anchor(value):
    require(type(value) is dict and set(value)=={'number','hash'},'ticket-payment-anchor')
    number=value['number']
    require(type(number) is str and number.startswith('0x') and 1<=len(number[2:])<=14,
        'ticket-payment-anchor')
    try:height=int(number,16)
    except ValueError:require(False,'ticket-payment-anchor')
    require(hex(height)==number and height<2**53,'ticket-payment-anchor')
    hex_value(value['hash'],32)
    return value


def payment_transaction(view,transaction):
    """Exact saved purchase match; this alone is never payment confirmation."""
    require(type(transaction) is dict,'ticket-payment-transaction')
    intent=view['payment_intent'];tx=view['transaction']
    transaction_hash=hex_value(transaction.get('hash'),32)
    require(transaction.get('from')==intent['payer']
        and transaction.get('nonce')==hex(intent['nonce'])
        and transaction.get('chainId')==hex(tx['chain_id'])
        and transaction.get('to')==tx['to'] and transaction.get('input')==tx['data']
        and transaction.get('value')==tx['value'],'ticket-payment-intent-mismatch')
    return transaction_hash


def validate_payment_intent(intent):
    require(type(intent) is dict and (
        set(intent)=={'profile','payer','nonce'} and intent['profile']==PAYMENT_INTENT or
        set(intent)=={'profile','payer','nonce','anchor'} and intent['profile']==PAYMENT_INTENT_V2),
        'ticket-payment-intent')
    hex_value(intent['payer'],20);_nonce(intent['nonce'])
    if intent['profile']==PAYMENT_INTENT_V2:payment_anchor(intent['anchor'])


def closed_payment(value):
    require(type(value) is dict and set(value)=={'profile','parameters','pack_hash','intent',
        'transaction_hash','transaction_block','checked_through','outcome'}
        and value['profile']==CLOSED_PAYMENT and value['outcome'] in ('failed','other-transaction')
        and type(value['parameters']) is str,'ticket-closed-payment')
    hex_value('0x'+value['parameters'],32);hex_value(value['pack_hash'],32)
    validate_payment_intent(value['intent'])
    require(value['intent']['profile']==PAYMENT_INTENT_V2,'ticket-payment-search-anchor-required')
    hex_value(value['transaction_hash'],32)
    payment_anchor(value['transaction_block']);payment_anchor(value['checked_through'])
    require(int(value['intent']['anchor']['number'],16)<int(value['transaction_block']['number'],16)
        <=int(value['checked_through']['number'],16),'ticket-closed-payment-order')
    return value


class TicketWallet:
    def __init__(self,directory,offer):
        require(isinstance(offer,TicketOffer),'ticket-wallet-offer')
        directory=Path(directory)
        require(directory.is_absolute() and '..' not in directory.parts
            and not any(p.is_symlink() for p in (directory,*directory.parents))
            and not any(p.startswith('.env') for p in directory.parts),'ticket-wallet-directory')
        self.wallet,self.offer=Wallet(directory),offer

    def _load(self):
        self.offer.check()
        r=self.wallet.load('credential')
        require(type(r) is dict and set(r)=={'profile','parameters','worker_sha256','pending','tickets','last_import'}
            and r['profile']==PROFILE and r['parameters']==self.offer.hash
            and r['worker_sha256']==self.offer.protocol.native.sha256
            and type(r['tickets']) is list and len(r['tickets'])<=MAX_TICKETS,'ticket-wallet-profile')
        seen=set()
        for item in r['tickets']:
            require(type(item) is dict and set(item)=={'token','bundle_hash'},'ticket-wallet-record')
            token=item['token']
            require(type(token) is dict and token.get('parameters')==self.offer.hash,'ticket-wallet-record')
            identity=canonical(token)
            require(identity not in seen,'ticket-wallet-duplicate');seen.add(identity)
            if item['bundle_hash'] is not None:hex_value(item['bundle_hash'],32)
        if r['last_import'] is not None:hex_value(r['last_import'],32)
        if r['pending'] is not None:self._validate_pending(r['pending'])
        return r

    def _validate_pending(self,p):
        base={'pack_hash','pack','requests','payment_tx'}
        require(type(p) is dict and base<=set(p)<=base|{'payment_intent','closed_payments','refund_intent'}
            and type(p['requests']) is list and len(p['requests'])==self.offer.terms['pack_size']
            and self.offer.pack_hash(p['pack'])==p['pack_hash']
            and self.offer.protocol.blinded_pack(p['requests'])==p['pack'],'ticket-wallet-pending')
        if p['payment_tx'] is not None:hex_value(p['payment_tx'],32)
        if 'refund_intent' in p:
            v=p['refund_intent']
            require(type(v) is dict and set(v)=={'profile','policy_sha256','request_sha256','signature'}
                and v['profile']==REFUND_INTENT and p['payment_tx'] is not None
                and type(v['policy_sha256']) is str and re.fullmatch('[0-9a-f]{64}',v['policy_sha256'])
                and type(v['request_sha256']) is str and re.fullmatch('[0-9a-f]{64}',v['request_sha256'])
                and type(v['signature']) is str and re.fullmatch('0x[0-9a-f]{130}',v['signature']), 'ticket-refund-intent')
        if 'payment_intent' in p:
            intent=p['payment_intent']
            validate_payment_intent(intent)
        if 'closed_payments' in p:
            closed=p['closed_payments']
            require(type(closed) is list and 1<=len(closed)<=MAX_CLOSED_PAYMENTS,'ticket-closed-payment-limit')
            seen=set()
            for item in closed:
                closed_payment(item)
                require(item['parameters']==self.offer.hash and item['pack_hash']==p['pack_hash'],
                    'ticket-closed-payment-scope')
                pair=(item['intent']['payer'],item['intent']['nonce'])
                require(pair not in seen,'ticket-closed-payment-duplicate');seen.add(pair)

    def _save(self,r):
        self.wallet.save('credential',r)
        require(self._load()==r,'ticket-wallet-readback')

    def _refund_archive(self):
        if self.wallet.read('post.sealed',missing=True) is None:return {'profile':REFUND_ARCHIVE,'entries':[]}
        archive=self.wallet.load('post')
        require(type(archive) is dict and set(archive)=={'profile','entries'} and archive['profile']==REFUND_ARCHIVE
            and type(archive['entries']) is list and len(archive['entries'])<=MAX_REFUNDS,'ticket-refund-archive')
        seen=set()
        for row in archive['entries']:
            require(type(row) is dict and set(row)=={'pending','policy','payout'},'ticket-refund-archive')
            self._validate_pending(row['pending']);p=row['pending'];h=p['pack_hash']
            require(h not in seen and 'refund_intent' in p,'ticket-refund-archive');seen.add(h)
            from ticket_refund_vault_v1 import scope,validate_payout
            scope(row['policy'],self.offer,p['refund_intent']['policy_sha256'])
            validate_payout(row['payout'],self.offer,row['policy'])
            require(row['payout']['pack_hash']==h and row['payout']['payment_transaction']==p['payment_tx'],'ticket-refund-archive')
        return archive

    def _refund_capacity(self,p,policy):
        archive=self._refund_archive()
        if any(v['pending']['pack_hash']==p['pack_hash'] for v in archive['entries']):return
        require(len(archive['entries'])<MAX_REFUNDS,'ticket-refund-archive-full')
        # Reserve the full encrypted archive slot BEFORE cancellation. Never
        # drop old recovery bytes when an archive/record bound is reached.
        pending=copy.deepcopy(p);pending['refund_intent']={'profile':REFUND_INTENT,
            'policy_sha256':hashlib.sha256(canonical(policy)).hexdigest(),'request_sha256':'f'*64,'signature':'0x'+'f'*130}
        payout={'profile':'nockapp-ticket-refund-payout-v1','parameters':self.offer.hash,'pack_hash':p['pack_hash'],
            'state':'refunded','payout_confirmed':True,'payer':'0x'+'f'*40,'amount_wei':self.offer.terms['pack_price_wei'],
            'payment_transaction':p['payment_tx'],'vault':policy['vault'],'transaction_hash':'0x'+'f'*64,
            'block_number':'0x'+'f'*64,'block_hash':'0x'+'f'*64}
        test={**archive,'entries':[*archive['entries'],{'pending':pending,'policy':policy,'payout':payout}]}
        require(len(canonical(test))<=MAX_PLAIN,'ticket-refund-archive-full')

    def ensure_refund_capacity(self,policy):
        with self.wallet.controller_lock():
            p=self._load()['pending'];require(p is not None and p['payment_tx'] is not None,'ticket-payment-missing')
            self._refund_capacity(p,policy)

    def save_refund(self,policy,request_sha256,signature):
        """Trusted native coordinator has checked original payer signature."""
        with self.wallet.controller_lock():
            r=self._load();p=r['pending'];require(p is not None and p['payment_tx'] is not None,'ticket-payment-missing')
            self._refund_capacity(p,policy)
            v={'profile':REFUND_INTENT,'policy_sha256':hashlib.sha256(canonical(policy)).hexdigest(),
                'request_sha256':request_sha256,'signature':signature.lower()}
            if 'refund_intent' in p:
                require(all(p['refund_intent'][k]==v[k] for k in ('profile','policy_sha256','request_sha256')),'ticket-refund-conflict')
            else:p['refund_intent']=v;self._validate_pending(p);self._save(r)

    def refund_record(self,pack_hash):
        hex_value(pack_hash,32)
        with self.wallet.controller_lock():
            r=self._load();p=r['pending']
            if p is not None and p['pack_hash']==pack_hash and 'refund_intent' in p:return {'pending':copy.deepcopy(p),'archived':False}
            rows=[v for v in self._refund_archive()['entries'] if v['pending']['pack_hash']==pack_hash]
            require(len(rows)==1,'ticket-refund-not-requested')
            return {**copy.deepcopy(rows[0]),'archived':True}

    def refund_state(self):
        with self.wallet.controller_lock():
            r=self._load();p=r['pending'];archive=self._refund_archive()
            return {'pending':None if p is None or 'refund_intent' not in p else {'pack_hash':p['pack_hash'],
                'request_sha256':p['refund_intent']['request_sha256']},
                'completed':[{'pack_hash':v['payout']['pack_hash'],'transaction_hash':v['payout']['transaction_hash'],
                    'amount_wei':v['payout']['amount_wei'],'verification_current':False} for v in archive['entries']],
                'archive_limit':MAX_REFUNDS}

    def complete_refund(self,policy,payout):
        from ticket_refund_vault_v1 import validate_payout
        validate_payout(payout,self.offer,policy)
        with self.wallet.controller_lock():
            r=self._load();p=r['pending'];archive=self._refund_archive()
            rows=[v for v in archive['entries'] if v['payout']['pack_hash']==payout['pack_hash']]
            if rows:
                require(len(rows)==1 and rows[0]['payout']==payout and rows[0]['policy']==policy,'ticket-refund-archive-conflict')
                if p is None or p['pack_hash']!=payout['pack_hash']:return copy.deepcopy(payout)
                require(rows[0]['pending']==p,'ticket-refund-archive-conflict')
            else:
                require(p is not None and p['pack_hash']==payout['pack_hash'] and p['payment_tx']==payout['payment_transaction']
                    and p.get('refund_intent',{}).get('policy_sha256')==hashlib.sha256(canonical(policy)).hexdigest(),'ticket-refund-conflict')
                self._refund_capacity(p,policy)
                archive['entries'].append({'pending':copy.deepcopy(p),'policy':copy.deepcopy(policy),'payout':copy.deepcopy(payout)})
                self.wallet.save('post',archive)
                require(self._refund_archive()==archive,'ticket-refund-archive-readback')
            # Archive is durably encrypted before clearing the pending slot.
            r['pending']=None;self._save(r);return copy.deepcopy(payout)

    def initialize(self):
        with self.wallet.controller_lock():
            existing_metadata=self.wallet.metadata()
            existing_record=self.wallet.read('credential.sealed',missing=True)
            require(existing_metadata is None or existing_record is not None,'ticket-wallet-incomplete')
            self.wallet.initialize()
            if self.wallet.read('credential.sealed',missing=True) is None:
                # Never treat other pending records as a new ticket wallet.
                require(all(self.wallet.read(n,missing=True) is None for n in ('pending.sealed','post.sealed')),'ticket-wallet-not-empty')
                self._save({'profile':PROFILE,'parameters':self.offer.hash,'worker_sha256':self.offer.protocol.native.sha256,
                    'pending':None,'tickets':[],'last_import':None})
            return self._status(self._load())

    def _status(self,r):
        from ticket_bulk_purchase_v1 import active
        return {'profile':PROFILE,'available':sum(v['bundle_hash'] is None for v in r['tickets']),
            'reserved':sum(v['bundle_hash'] is not None for v in r['tickets']), 'purchase_pending':r['pending'] is not None or active(self)}

    def status(self):
        with self.wallet.controller_lock():return self._status(self._load())

    def _purchase(self,r):
        p=r['pending'];require(p is not None,'ticket-purchase-missing')
        return {'profile':PROFILE,'pack_hash':p['pack_hash'], 'payment_tx':p['payment_tx'],
            'transaction':{'chain_id':84532,'to':self.offer.manifest['purchase_contract'],
                'value':hex(int(self.offer.terms['pack_price_wei'])),'data':encode('buy(bytes32)',p['pack_hash'])}}

    def prepare_purchase(self,now,approve_purchase):
        from ticket_bulk_purchase_v1 import active
        require(approve_purchase is True,'consent-required')
        with self.wallet.controller_lock():
            r=self._load()
            require(not active(self),'ticket-bulk-purchase-pending')
            if r['pending'] is not None:return self._purchase(r) # Never create another pack for a retry.
            require(type(now) is int and 0<=now<self.offer.terms['purchase_before'],'ticket-purchases-closed')
            require(len(r['tickets'])+self.offer.terms['pack_size']<=MAX_TICKETS,'ticket-wallet-full')
            requests=[self.offer.protocol.prepare() for _ in range(self.offer.terms['pack_size'])]
            pack=self.offer.protocol.blinded_pack(requests)
            r['pending']={'pack_hash':self.offer.pack_hash(pack),'pack':pack,'requests':requests,'payment_tx':None}
            self._save(r) # Encrypt+fsync+read back BEFORE wallet transaction request.
            return self._purchase(r)

    def record_payment(self,pack_hash,transaction_hash):
        hex_value(pack_hash,32);hex_value(transaction_hash,32)
        with self.wallet.controller_lock():
            r=self._load();p=r['pending']
            require(p is not None and p['pack_hash']==pack_hash
                and p['payment_tx'] in (None,transaction_hash),'ticket-purchase-conflict')
            # Once a send is armed, a bare browser-supplied hash cannot replace
            # recovery against the saved payer, nonce and exact transaction.
            require(('payment_intent' not in p and 'closed_payments' not in p)
                or p['payment_tx']==transaction_hash,
                'ticket-payment-intent-required')
            p['payment_tx']=transaction_hash;self._save(r)
            return self._purchase(r)

    def arm_payment(self,pack_hash,payer,nonce,approve_payment,*,anchor=None):
        """One-shot dispatch admission, durable BEFORE calling the wallet.

        Lost replies remain uncertain, even if the wallet was never reached.
        No automatic re-arm, nonce replacement or cancellation is provided.
        Legacy pending packs acquire this versioned field only by consent.
        """
        require(approve_payment is True,'consent-required')
        hex_value(pack_hash,32);hex_value(payer,20);_nonce(nonce)
        if anchor is not None:payment_anchor(anchor)
        with self.wallet.controller_lock():
            from ticket_bulk_purchase_v1 import active
            require(not active(self),'ticket-bulk-purchase-pending')
            r=self._load();p=r['pending']
            require(p is not None and p['pack_hash']==pack_hash and p['payment_tx'] is None
                and 'payment_intent' not in p,'ticket-payment-already-armed')
            closed=p.get('closed_payments',[])
            require(len(closed)<MAX_CLOSED_PAYMENTS,'ticket-closed-payment-limit')
            for old in closed:
                require(anchor is not None and int(anchor['number'],16)>=int(old['checked_through']['number'],16)
                    and (payer!=old['intent']['payer'] or nonce>old['intent']['nonce']),
                    'ticket-payment-closed-nonce')
            p['payment_intent']={'profile':PAYMENT_INTENT,'payer':payer,'nonce':nonce}
            if anchor is not None:
                p['payment_intent'].update(profile=PAYMENT_INTENT_V2,anchor=copy.deepcopy(anchor))
            self._save(r)
            return self._payment_intent(r)

    def _payment_intent(self,r):
        p=r['pending']
        require(p is not None and 'payment_intent' in p,'ticket-payment-intent-missing')
        result=self._purchase(r)
        result['payment_intent']=copy.deepcopy(p['payment_intent'])
        # Reading this projection never grants another wallet-send admission.
        result['state']='recorded' if p['payment_tx'] is not None else 'send-uncertain'
        return result

    def payment_intent(self):
        with self.wallet.controller_lock():return self._payment_intent(self._load())

    def purchase_state(self):
        """Read-only public projection; never prepare another pack on recovery."""
        with self.wallet.controller_lock():
            r=self._load();p=r['pending']
            return {'profile':'nockapp-public-ticket-purchase-state-v1',
                'purchase':self._purchase(r) if p is not None else None,
                'payment_intent':copy.deepcopy(p.get('payment_intent')) if p is not None else None,
                'closed_attempts':len(p.get('closed_payments',[])) if p is not None else 0,
                'attempt_limit':MAX_CLOSED_PAYMENTS}

    def closed_payments(self):
        """Installer coordinator only; never ticket redemption metadata."""
        with self.wallet.controller_lock():
            p=self._load()['pending']
            return copy.deepcopy(p.get('closed_payments',[])) if p is not None else []

    @staticmethod
    def _closed_result(proof):
        return {'state':'attempt-closed','parameters':proof['parameters'],'pack_hash':proof['pack_hash'],
            'closed_attempt':copy.deepcopy(proof)}

    def _close_payment(self,view,proof):
        """Trusted coordinator after canonical RPC checks, no browser proof API.

        Saves terminal evidence before removing dispatch authority. Lost replies
        recover the saved decision; no new pack, nonce or send is authorized.
        """
        closed_payment(proof)
        with self.wallet.controller_lock():
            r=self._load();p=r['pending']
            require(p is not None,'ticket-purchase-missing')
            closed=p.get('closed_payments',[])
            if proof in closed:return self._closed_result(proof)
            require(self._payment_intent(r)==view and proof['parameters']==self.offer.hash
                and proof['pack_hash']==p['pack_hash'] and proof['intent']==p['payment_intent'],
                'ticket-payment-intent-changed')
            require(len(closed)<MAX_CLOSED_PAYMENTS,'ticket-closed-payment-limit')
            p['closed_payments']=[*closed,copy.deepcopy(proof)]
            del p['payment_intent'];p['payment_tx']=None
            self._save(r)
            return self._closed_result(proof)

    def recover_payment(self,transaction):
        """Installer-owned RPC result, NOT a trusted browser transaction object.

        Matching a transaction records its hash; issuance separately requires
        its successful finalized receipt. Pending/failed transactions are never
        evidence of payment. RPC trust is the same as FinalizedTicketPayment.
        """
        require(type(transaction) is dict,'ticket-payment-transaction')
        with self.wallet.controller_lock():
            r=self._load();view=self._payment_intent(r)
            transaction_hash=payment_transaction(view,transaction)
            require(r['pending']['payment_tx'] in (None,transaction_hash),'ticket-purchase-conflict')
            r['pending']['payment_tx']=transaction_hash;self._save(r)
            return self._payment_intent(r)

    def recover_verified_payment(self,view,payment,payer):
        """Native coordinator only, after canonical contract-event validation.

        Never accepts a proof supplied by the browser. Compare the entire saved
        projection under the lock so a concurrent intent change fails closed.
        """
        hex_value(payer,20)
        require(type(payment) is dict and set(payment)=={'parameters','pack_hash','transaction_hash',
            'block_number','block_hash'},'ticket-payment-transaction')
        transaction_hash=hex_value(payment['transaction_hash'],32)
        with self.wallet.controller_lock():
            r=self._load();current=self._payment_intent(r)
            require(current==view and payment['parameters']==self.offer.hash
                and payment['pack_hash']==r['pending']['pack_hash']
                and payer==current['payment_intent']['payer'],'ticket-payment-intent-changed')
            intent=current['payment_intent']
            require(intent['profile']==PAYMENT_INTENT_V2,'ticket-payment-search-anchor-required')
            anchor=payment_anchor({'number':payment['block_number'],'hash':payment['block_hash']})
            require(int(anchor['number'],16)>int(intent['anchor']['number'],16),'ticket-payment-before-intent')
            require(r['pending']['payment_tx'] in (None,transaction_hash),'ticket-purchase-conflict')
            r['pending']['payment_tx']=transaction_hash;self._save(r)
            return self._payment_intent(r)

    def issuance_request(self):
        with self.wallet.controller_lock():
            p=self._load()['pending']
            require(p is not None and p['payment_tx'] is not None,'ticket-payment-missing')
            return {'pack':copy.deepcopy(p['pack']),'transaction_hash':p['payment_tx']}

    def receive(self,reply):
        with self.wallet.controller_lock():return self._receive_locked(reply)

    def _receive_locked(self,reply):
        require(type(reply) is dict and set(reply)=={'profile','parameters','pack_hash','signatures'}
            and reply['profile']==REPLY and reply['parameters']==self.offer.hash,'ticket-issuance-reply')
        r=self._load();p=r['pending']
        if p is None:
            require(r['last_import']==reply['pack_hash'],'ticket-purchase-missing')
            return self._status(r) # Lost local completion reply cannot import twice.
        require(p['pack_hash']==reply['pack_hash'] and p['payment_tx'] is not None
            and type(reply['signatures']) is list and len(reply['signatures'])==len(p['requests']),'ticket-issuance-reply')
        tokens=[self.offer.protocol.finalize(request,sig) for request,sig in zip(p['requests'],reply['signatures'])]
        # Import the whole pack atomically. Any invalid member preserves all
        # pending recovery material and the complete previous inventory.
        r['tickets'].extend({'token':token,'bundle_hash':None} for token in tokens)
        r['last_import']=p['pack_hash'];r['pending']=None
        self._save(r)
        return self._status(r)

    def reserve(self,bundle_hash,now):
        hex_value(bundle_hash,32)
        with self.wallet.controller_lock():
            return self._reserve_locked(bundle_hash,now)

    def _reserve_locked(self,bundle_hash,now):
        """Internal registry path; caller holds this wallet's controller lock."""
        hex_value(bundle_hash,32);r=self._load()
        matching=[v for v in r['tickets'] if v['bundle_hash']==bundle_hash]
        require(len(matching)<=1,'ticket-wallet-duplicate-binding')
        if matching:return copy.deepcopy(matching[0]['token']) # Exact retry, including after expiry.
        require(type(now) is int and 0<=now<self.offer.terms['redeem_before'],'ticket-redemptions-closed')
        available=next((v for v in r['tickets'] if v['bundle_hash'] is None),None)
        require(available is not None,'ticket-wallet-empty')
        self.offer.protocol.verify(available['token'])
        available['bundle_hash']=bundle_hash;self._save(r)
        return copy.deepcopy(available['token']) # Never payment tx, pack ID, wallet key or authorship secret.

    def _release_unconsumed(self,token,bundle_hash):
        """Installer-owned coordinator only, after correlated definitive status.

        Never expose this transition as a browser-supplied response/boolean.
        Exceptions, timeouts and absent replies cannot authorize it.
        """
        hex_value(bundle_hash,32)
        with self.wallet.controller_lock():
            r=self._load();matching=[v for v in r['tickets'] if v['token']==token]
            require(len(matching)==1,'ticket-wallet-reservation-missing')
            item=matching[0]
            require(item['bundle_hash'] in (None,bundle_hash),'ticket-wallet-reservation-changed')
            if item['bundle_hash'] is not None:
                item['bundle_hash']=None;self._save(r)
            return self._status(r)
