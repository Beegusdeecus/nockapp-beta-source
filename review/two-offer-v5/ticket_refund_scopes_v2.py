"""Two immutable refund vaults under ONE original nonce/gas/refund-count cap.

Explicit trusted configuration only. Opening the new context does not migrate,
reset or initialize existing state. The separate pinned migration handles the
old authenticated head. Per-offer views share this exact queue object.
"""
from types import MappingProxyType
import copy,hashlib,hmac,json,re
from base_transactions import TransactionQueue
from policy import canonical,require,strict_json
from ticket_refund_payout_v1 import RefundQueue,PROFILE,SELECTOR,namespace,decision,calldata
from ticket_refund_vault_v1 import scope
from ticket_offer_overlay_v1 import pair
from ticket_offer_v1 import hex_value
from ticket_journal_v2 import ImmutableS3JournalAnchor

BINDING='nockapp-ticket-refund-offer-set-v2'

class ScopedRefundQueue(RefundQueue):
    def __init__(self,rpc,signer,path,old_offer,old_vault,new_offer,new_vault,limits,*,
            old_pin,new_pin,anchor,fee_policy,initial_nonce=None):
        self._configure(signer,old_offer,old_vault,new_offer,new_vault,limits,
            old_pin=old_pin,new_pin=new_pin,anchor=anchor,fee_policy=fee_policy)
        contracts={v['vault']:[SELECTOR]for v in self.vaults.values()}
        codes={v['vault']:v['runtime_sha256']for v in self.vaults.values()}
        TransactionQueue.__init__(self,rpc,signer,path,contracts,limits,initial_nonce=initial_nonce,
            code_hashes=codes,anchor=anchor,fee_policy=fee_policy,
            application_binding={'profile':BINDING,'root_parameters':old_offer.hash,'vaults':self.vaults_public(),
                'global_max_refunds':self.vault['max_refunds']})
    def _configure(self,signer,old_offer,old_vault,new_offer,new_vault,limits,*,old_pin,new_pin,anchor,fee_policy):
        pair(old_offer.manifest,new_offer.manifest)
        old=scope(old_vault,old_offer,old_pin);new=scope(new_vault,new_offer,new_pin)
        require(old['vault']!=new['vault']and all(old[k]==new[k]for k in
            ('authority','chain_id','pack_price_wei','max_refunds','principal_budget_wei','gas')),'refund-scopes-authority')
        require(isinstance(anchor,ImmutableS3JournalAnchor)and fee_policy is not None
            and anchor.prefix=='ticket-publication-ledger-v2/'+namespace(signer.address)+'/'
            and signer.address.lower()==old['authority']and old['gas']<=limits.max_gas,'refund-scopes-queue')
        self.offer,self.vault=old_offer,old
        self.offers=MappingProxyType({old_offer.hash:old_offer,new_offer.hash:new_offer})
        self.vaults=MappingProxyType({old_offer.hash:old,new_offer.hash:new})
        self._scope_pin=hashlib.sha256(canonical(self.vaults_public())).hexdigest()
    def vaults_public(self):return {h:copy.deepcopy(v)for h,v in self.vaults.items()}
    def check(self):
        require(hashlib.sha256(canonical(self.vaults_public())).hexdigest()==self._scope_pin,'refund-scopes-changed')
        for h,offer in self.offers.items():
            offer.check();require(offer.hash==h and self.vaults[h]['parameters']==h,'refund-scopes-changed')
    @staticmethod
    def operation_for(parameters,pack_hash):
        hex_value('0x'+parameters,32);hex_value(pack_hash,32)
        return hashlib.sha256(canonical({'profile':PROFILE,'parameters':parameters,'pack_hash':pack_hash})).hexdigest()
    def operation(self,pack_hash):return self.operation_for(self.offer.hash,pack_hash)
    def _payload(self,payload,pack_hash):
        self.check()
        require(type(payload)is dict and set(payload)=={'decision','payer','signature'}
            and type(payload['decision'])is dict and type(payload['decision'].get('payment'))is dict,
            'refund-scopes-payload')
        parameters=payload['decision']['payment'].get('parameters')
        require(type(parameters)is str and parameters in self.offers,'refund-scopes-domain')
        decision(payload['decision'],self.offers[parameters],pack_hash);hex_value(payload['payer'],20)
        require(type(payload['signature'])is str and re.fullmatch('0x[0-9a-f]{130}',payload['signature']),
            'refund-scopes-signature')
        return parameters,self.vaults[parameters]
    def _meta(self,db):
        self.check();meta=TransactionQueue._meta(self,db);rows=list(db.execute('SELECT * FROM refund_jobs'))
        # SAME original global cap: an extra offer never creates new capacity.
        require(len(rows)<=min(self.vault['max_refunds'],self.limits.max_submissions),'refund-queue-capacity')
        jobs={}
        for row in rows:
            record={k:row[k]for k in row.keys()if k!='mac'}
            require(hmac.compare_digest(row['mac'],self._mac('refund-job-v1',record)),'refund-queue-authentication')
            payload=strict_json(row['payload'].encode(),max_bytes=4096)
            parameters,vault=self._payload(payload,row['pack_hash'])
            require(canonical(payload).decode()==row['payload']
                and row['operation']==self.operation_for(parameters,row['pack_hash']),'refund-queue-authentication')
            jobs[row['operation']]=(payload,row,vault)
        for tx in db.execute('SELECT * FROM submissions'):
            require(tx['id']in jobs,'refund-queue-orphan-transaction');payload,row,vault=jobs[tx['id']]
            require(tx['operation_hash']==hashlib.sha256(row['payload'].encode()).hexdigest()
                and json.loads(tx['intent'])=={'to':vault['vault'],'data':calldata(payload),'gas':vault['gas']},
                'refund-queue-transaction-binding')
        return meta
    def job(self,pack_hash):
        hex_value(pack_hash,32)
        with self._db()as db:
            self._meta(db);row=db.execute('SELECT payload FROM refund_jobs WHERE pack_hash=?',(pack_hash,)).fetchone()
            return None if row is None else json.loads(row['payload'])
    def admit(self,pack_hash,payload):
        payload=copy.deepcopy(payload);parameters,vault=self._payload(payload,pack_hash)
        with self._db()as db:
            self._meta(db);old=db.execute('SELECT payload FROM refund_jobs WHERE pack_hash=?',(pack_hash,)).fetchone()
            if old is not None:
                saved=json.loads(old['payload']);require(saved['decision']==payload['decision']
                    and saved['payer']==payload['payer'],'refund-job-conflict');return saved
            count=db.execute('SELECT count(*)FROM refund_jobs').fetchone()[0]
            require(count<min(self.vault['max_refunds'],self.limits.max_submissions),'refund-queue-capacity')
            reserve=vault['gas']*self.limits.max_fee_per_gas+self.fees.policy['max_l1_fee']+self.fees.policy['max_operator_fee']
            require(reserve<=self.fees.policy['max_total_fee']and(count+1)*reserve<=self.fees.policy['total_budget']
                and(count+1)*vault['gas']*self.limits.max_fee_per_gas<=self.limits.execution_budget
                and not self._fee_usage(db)[1],'refund-queue-fee-budget')
            record={'pack_hash':pack_hash,'operation':self.operation_for(parameters,pack_hash),'payload':canonical(payload).decode()}
            db.execute('INSERT INTO refund_jobs VALUES (?,?,?,?)',(*record.values(),self._mac('refund-job-v1',record)))
            return payload
    def submit_bound(self,pack_hash):
        payload=self.job(pack_hash);require(payload is not None,'refund-job-missing')
        parameters,vault=self._payload(payload,pack_hash)
        return TransactionQueue.submit(self,self.operation_for(parameters,pack_hash),vault['vault'],calldata(payload),vault['gas'],
            operation_hash=hashlib.sha256(canonical(payload)).hexdigest())
    def recover_bound(self,pack_hash):
        payload=self.job(pack_hash);require(payload is not None,'refund-job-missing')
        parameters,_=self._payload(payload,pack_hash)
        return TransactionQueue.recover(self,self.operation_for(parameters,pack_hash),hashlib.sha256(canonical(payload)).hexdigest())
    def pending_jobs(self,limit=4):
        require(type(limit)is int and 1<=limit<=8,'refund-recovery-limit')
        with self._db()as db:
            self._meta(db)
            return [r[0]for r in db.execute("SELECT j.pack_hash FROM refund_jobs j LEFT JOIN submissions s ON s.id=j.operation WHERE s.id IS NULL OR s.state NOT IN ('finalized','failed') ORDER BY j.operation LIMIT ?",(limit,))]
    def view(self,parameters):return RefundQueueView(self,parameters)

class RefundQueueView(RefundQueue):
    """Worker interface only. Never constructs a journal, signer or counter."""
    def __init__(self,parent,parameters):
        require(type(parent)is ScopedRefundQueue and parameters in parent.offers,'refund-scopes-view')
        parent.check();self.parent,self.parameters=parent,parameters
        self.offer,self.vault,self.rpc=parent.offers[parameters],parent.vaults[parameters],parent.rpc
    def _check_payload(self,payload,pack_hash):
        if payload is not None:require(self.parent._payload(payload,pack_hash)[0]==self.parameters,'refund-scopes-view-domain')
        return payload
    def job(self,pack_hash):return self._check_payload(self.parent.job(pack_hash),pack_hash)
    def admit(self,pack_hash,payload):
        self._check_payload(payload,pack_hash);return self.parent.admit(pack_hash,payload)
    def submit_bound(self,pack_hash):self.job(pack_hash);return self.parent.submit_bound(pack_hash)
    def recover_bound(self,pack_hash):self.job(pack_hash);return self.parent.recover_bound(pack_hash)
    def pending_jobs(self,limit=4):
        return [h for h in self.parent.pending_jobs(limit)if self.parent.job(h)['decision']['payment']['parameters']==self.parameters]
    def submit(self,*_,**__):require(False,'refund-queue-use-bound-operation')
