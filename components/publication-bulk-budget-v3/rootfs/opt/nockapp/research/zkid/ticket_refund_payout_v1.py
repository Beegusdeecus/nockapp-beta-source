"""Fixed-price custodial refunds through a separate immutable vault and key.

Canonical payment and a durable refund decision precede authorization. The
managed queue persists jobs and exact signed zero-value vault calls before
broadcast. No arbitrary recipient/amount, direct ETH signing or index authority.
This is source code, not a deployed refund service or an attestation claim.
"""
from contextlib import contextmanager
import copy
import hashlib
import hmac
import json
from pathlib import Path
import re
import subprocess

from base_evm import TOOLS,encode
from base_transactions import TransactionQueue
from permissionless_contracts import SETTINGS
from policy import canonical,require,strict_json
from ticket_bindings_v1 import ConditionalS3Records
from ticket_journal_v2 import ImmutableS3JournalAnchor
from ticket_offer_v1 import TicketOffer,hex_value
from ticket_payment_v1 import FinalizedTicketPayment,_quantity
from ticket_refund_v1 import authorize_refund

from ticket_refund_vault_v1 import PROFILE,SCOPE,SELECTOR,scope,RefundVaultReader

def build():
    source=Path(__file__).resolve().parent/'base/contracts/PrepaidRefundVault.sol'
    request={'language':'Solidity','sources':{'contracts/PrepaidRefundVault.sol':{'content':source.read_text()}},'settings':SETTINGS}
    result=subprocess.run([str(TOOLS/'solc-0.8.30'),'--standard-json'],input=json.dumps(request).encode(),
        capture_output=True,timeout=30,check=True)
    value=json.loads(result.stdout)
    require(not any(e['severity']=='error' for e in value.get('errors',[])),'refund-vault-build')
    return value['contracts']['contracts/PrepaidRefundVault.sol']['PrepaidRefundVault']


def namespace(authority):
    hex_value(authority.lower(),20)
    return hashlib.sha256(canonical({'profile':PROFILE,'chain':84532,'authority':authority.lower()})).hexdigest()


def decision(value,offer,pack_hash):
    require(type(value) is dict and set(value)=={'profile','mode','payment'}
        and value['profile']=='nockapp-ticket-purchase-decision-v1' and value['mode']=='refund', 'refund-decision-required')
    p=value['payment']
    require(type(p) is dict and set(p)=={'parameters','pack_hash','transaction_hash','block_number','block_hash'}
        and p['parameters']==offer.hash and p['pack_hash']==pack_hash,'refund-decision-scope')
    hex_value(pack_hash,32);hex_value(p['transaction_hash'],32);hex_value(p['block_hash'],32);_quantity(p['block_number'])
    return value


def calldata(payload):
    p=payload['decision']['payment']
    return encode('refund(bytes32,bytes32,address,bytes)',p['pack_hash'],p['transaction_hash'],payload['payer'],payload['signature'])


class RefundQueue(TransactionQueue):
    """One managed nonce ledger per refund key/chain, never per buyer/offer."""
    def __init__(self,rpc,signer,path,offer,vault,limits,*,expected_hash,anchor,fee_policy,initial_nonce=None):
        self.offer=offer;self.vault=scope(vault,offer,expected_hash)
        require(isinstance(anchor,ImmutableS3JournalAnchor) and fee_policy is not None
            and anchor.prefix=='ticket-publication-ledger-v2/'+namespace(signer.address)+'/'
            and signer.address.lower()==vault['authority'] and vault['gas']<=limits.max_gas,'refund-queue-configuration')
        super().__init__(rpc,signer,path,{vault['vault']:[SELECTOR]},limits,initial_nonce=initial_nonce,
            code_hashes={vault['vault']:vault['runtime_sha256']},anchor=anchor,fee_policy=fee_policy,
            application_binding={'profile':PROFILE,'vault':self.vault})

    def operation(self,pack_hash):
        hex_value(pack_hash,32)
        return hashlib.sha256(canonical({'profile':PROFILE,'parameters':self.offer.hash,'pack_hash':pack_hash})).hexdigest()

    @contextmanager
    def _db(self):
        with super()._db() as db:
            if self._creating:db.execute('CREATE TABLE refund_jobs (pack_hash TEXT PRIMARY KEY, operation TEXT UNIQUE NOT NULL, payload TEXT NOT NULL, mac TEXT NOT NULL)')
            yield db

    def _meta(self,db):
        meta=super()._meta(db);rows=list(db.execute('SELECT * FROM refund_jobs'))
        require(len(rows)<=min(self.vault['max_refunds'],self.limits.max_submissions),'refund-queue-capacity')
        jobs={}
        for row in rows:
            public={k:row[k] for k in row.keys() if k!='mac'}
            require(hmac.compare_digest(row['mac'],self._mac('refund-job-v1',public))
                and row['operation']==self.operation(row['pack_hash']),'refund-queue-authentication')
            payload=strict_json(row['payload'].encode(),max_bytes=4096)
            require(canonical(payload).decode()==row['payload'] and set(payload)=={'decision','payer','signature'},'refund-queue-payload')
            decision(payload['decision'],self.offer,row['pack_hash']);hex_value(payload['payer'],20)
            require(type(payload['signature']) is str and re.fullmatch('0x[0-9a-f]{130}',payload['signature']), 'refund-queue-signature')
            jobs[row['operation']]=(payload,row)
        for tx in db.execute('SELECT * FROM submissions'):
            require(tx['id'] in jobs,'refund-queue-orphan-transaction');payload,row=jobs[tx['id']]
            require(tx['operation_hash']==hashlib.sha256(row['payload'].encode()).hexdigest()
                and json.loads(tx['intent'])=={'to':self.vault['vault'],'data':calldata(payload),'gas':self.vault['gas']},
                'refund-queue-transaction-binding')
        return meta

    def job(self,pack_hash):
        hex_value(pack_hash,32)
        with self._db() as db:
            self._meta(db);row=db.execute('SELECT payload FROM refund_jobs WHERE pack_hash=?',(pack_hash,)).fetchone()
            return None if row is None else json.loads(row['payload'])

    def admit(self,pack_hash,payload):
        # Installer-owned worker has verified canonical payment, payer consent
        # and the immutable refund decision; no direct browser evidence API.
        payload=copy.deepcopy(payload)
        require(type(payload) is dict and set(payload)=={'decision','payer','signature'},'refund-queue-payload')
        decision(payload['decision'],self.offer,pack_hash);hex_value(payload['payer'],20)
        require(type(payload['signature']) is str and re.fullmatch('0x[0-9a-f]{130}',payload['signature']), 'refund-queue-signature')
        with self._db() as db:
            self._meta(db);old=db.execute('SELECT payload FROM refund_jobs WHERE pack_hash=?',(pack_hash,)).fetchone()
            if old is not None:
                saved=json.loads(old['payload'])
                require(saved['decision']==payload['decision'] and saved['payer']==payload['payer'],'refund-job-conflict')
                return saved # Retain the first signature and exact eventual bytes.
            count=db.execute('SELECT count(*) FROM refund_jobs').fetchone()[0]
            require(count<min(self.vault['max_refunds'],self.limits.max_submissions),'refund-queue-capacity')
            reserve=self.vault['gas']*self.limits.max_fee_per_gas+self.fees.policy['max_l1_fee']+self.fees.policy['max_operator_fee']
            require(reserve<=self.fees.policy['max_total_fee'] and (count+1)*reserve<=self.fees.policy['total_budget']
                and (count+1)*self.vault['gas']*self.limits.max_fee_per_gas<=self.limits.execution_budget
                and not self._fee_usage(db)[1],'refund-queue-fee-budget')
            record={'pack_hash':pack_hash,'operation':self.operation(pack_hash),'payload':canonical(payload).decode()}
            db.execute('INSERT INTO refund_jobs VALUES (?,?,?,?)',(*record.values(),self._mac('refund-job-v1',record)))
            return copy.deepcopy(payload)

    def submit(self,*args,**kwargs):require(False,'refund-queue-use-bound-operation')

    def submit_bound(self,pack_hash):
        payload=self.job(pack_hash);require(payload is not None,'refund-job-missing')
        operation_hash=hashlib.sha256(canonical(payload)).hexdigest()
        return super().submit(self.operation(pack_hash),self.vault['vault'],calldata(payload),self.vault['gas'],operation_hash=operation_hash)

    def recover_bound(self,pack_hash):
        payload=self.job(pack_hash);require(payload is not None,'refund-job-missing')
        return super().recover(self.operation(pack_hash),hashlib.sha256(canonical(payload)).hexdigest())

    def pending_jobs(self,limit=4):
        require(type(limit) is int and 1<=limit<=8,'refund-recovery-limit')
        with self._db() as db:
            self._meta(db)
            return [row[0] for row in db.execute("SELECT j.pack_hash FROM refund_jobs j LEFT JOIN submissions s ON s.id=j.operation WHERE s.id IS NULL OR s.state NOT IN ('finalized','failed') ORDER BY j.operation LIMIT ?",(limit,))]


class RefundWorker:
    def __init__(self,offer,payments,decisions,queue):
        require(isinstance(offer,TicketOffer) and isinstance(payments,FinalizedTicketPayment)
            and isinstance(decisions,ConditionalS3Records) and isinstance(queue,RefundQueue)
            and payments.rpc is queue.rpc and payments.offer.hash==queue.offer.hash==offer.hash,'refund-worker-configuration')
        self.offer,self.payments,self.decisions,self.queue=offer,payments,decisions,queue
        self.reader=RefundVaultReader(queue.rpc,offer,queue.vault,hashlib.sha256(canonical(queue.vault)).hexdigest())

    def _authorized(self,pack_hash,signature):
        raw=self.decisions.read(pack_hash[2:]);require(raw is not None,'refund-decision-required')
        d=strict_json(raw,max_bytes=2048);require(canonical(d)==raw,'refund-decision-encoding');decision(d,self.offer,pack_hash)
        p=self.payments.verify_hash(pack_hash,d['payment']['transaction_hash'])
        require(p==d['payment'],'refund-payment-changed')
        payer=authorize_refund(self.offer,self.payments,p,signature)
        return {'decision':d,'payer':payer,'signature':signature.lower()}

    def _resume(self,pack_hash,payload):
        require(self._authorized(pack_hash,payload['signature'])==payload,'refund-job-changed')
        p=payload['decision']['payment']
        paid=self.reader.payout(pack_hash,p['transaction_hash'],payload['payer'])
        status=self.queue.recover_bound(pack_hash)
        if paid is not None:return paid
        require(status is None or status['state']!='finalized','refund-payout-finality-violation')
        if status is None:
            self.reader.check() # Pin the vault again before new signing.
            status=self.queue.submit_bound(pack_hash)
        if status['state']=='finalized':
            paid=self.reader.payout(pack_hash,p['transaction_hash'],payload['payer'])
            require(paid is not None,'refund-payout-finality-violation');return paid
        return {'profile':PROFILE,'parameters':self.offer.hash,'pack_hash':pack_hash,
            'state':status['state'],'payout_confirmed':False,'transaction_hash':status['transaction_hash']}

    def refund(self,pack_hash,signature):
        hex_value(pack_hash,32);payload=self._authorized(pack_hash,signature)
        self.reader.check();saved=self.queue.admit(pack_hash,payload)
        return self._resume(pack_hash,saved)

    def recover_pending(self,limit=4):
        results=[]
        for pack_hash in self.queue.pending_jobs(limit):
            try:results.append(self._resume(pack_hash,self.queue.job(pack_hash)))
            except Exception:results.append({'profile':PROFILE,'pack_hash':pack_hash,'state':'recovery-unavailable','payout_confirmed':False})
        return results
