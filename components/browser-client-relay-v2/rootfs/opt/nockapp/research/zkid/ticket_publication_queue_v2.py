"""Atomic ticket/bundle admission in the SAME managed gas/nonce authority.

This is a new ledger profile, not a reinterpretation of standalone v1 S3
bindings. The parent SQLite file is disposable; every operation restores the
authenticated managed snapshot and commits it by CAS before broadcasting.
"""
from contextlib import contextmanager
import hashlib
import hmac
import json
import time

from base_fees import quantity
from base_protocol import keccak
from base_transactions import TransactionQueue
from permissionless_index import digest
from policy import canonical,require
from ticket_journal_v2 import ImmutableS3JournalAnchor

PROFILE='nockapp-ticket-publication-ledger-v2'


def operation_id(contract,application,bundle_hash):
    digest(application);digest(bundle_hash)
    return hashlib.sha256(canonical({'profile':PROFILE,'chain':84532,'application':application,
        'contract':contract,'bundle_hash':bundle_hash})).hexdigest()


class TicketPublicationQueue(TransactionQueue):
    def __init__(self,rpc,signer,path,contract,application,limits,*,code_hashes,anchor,fee_policy,initial_nonce=None):
        digest(application);require(isinstance(anchor,ImmutableS3JournalAnchor) and fee_policy is not None,'ticket-queue-managed-state-required')
        self.index_contract=contract;self.application=application
        self.submit_selector=keccak(b'submit(bytes32)')[:10]
        super().__init__(rpc,signer,path,{contract:[self.submit_selector]},limits,
            initial_nonce=initial_nonce,code_hashes=code_hashes,anchor=anchor,fee_policy=fee_policy,
            application_binding={'profile':PROFILE,'application':application,'index_contract':contract})

    @contextmanager
    def _db(self):
        with super()._db() as db:
            if self._creating:
                db.execute('CREATE TABLE ticket_jobs (bundle_hash TEXT PRIMARY KEY, operation TEXT UNIQUE NOT NULL, nullifier TEXT UNIQUE, parameters TEXT, admitted_at INTEGER NOT NULL, gas INTEGER NOT NULL, reserve INTEGER NOT NULL, indexed_number TEXT, indexed_block_hash TEXT, mac TEXT NOT NULL)')
            yield db

    def operation(self,bundle_hash):
        return operation_id(self.index_contract,self.application,bundle_hash)

    def _meta(self,db):
        meta=super()._meta(db)
        jobs=list(db.execute('SELECT * FROM ticket_jobs'))
        require(len(jobs)<=self.limits.max_submissions,'ticket-queue-capacity')
        by_operation={}
        for row in jobs:
            record={k:row[k] for k in row.keys() if k!='mac'}
            require(hmac.compare_digest(row['mac'],self._mac('ticket-job-v2',record))
                and row['operation']==self.operation(row['bundle_hash']),'ticket-queue-authentication')
            if row['nullifier'] is None:
                require(row['parameters'] is None and row['gas']==row['reserve']==0
                    and row['indexed_number'] is not None,'ticket-queue-free-record')
            else:
                digest('0x'+row['nullifier']);digest('0x'+row['parameters'])
                require(21000<=row['gas']<=self.limits.max_gas and row['reserve']>0,'ticket-queue-record')
            if row['indexed_number'] is not None:
                require(type(row['indexed_number']) is str and row['indexed_number'].isdigit()
                    and str(int(row['indexed_number']))==row['indexed_number']
                    and 0<int(row['indexed_number'])<2**53,'ticket-queue-canonical-record')
                digest(row['indexed_block_hash'])
            else:require(row['indexed_block_hash'] is None,'ticket-queue-canonical-record')
            by_operation[row['operation']]=row
        for row in db.execute('SELECT * FROM submissions'):
            job=by_operation.get(row['id']);require(job is not None and job['nullifier'] is not None,'ticket-queue-orphan-transaction')
            require(row['operation_hash']==job['bundle_hash'][2:]
                and json.loads(row['intent'])=={'to':self.index_contract,'data':self.submit_selector+job['bundle_hash'][2:],'gas':job['gas']},
                'ticket-queue-transaction-binding')
        return meta

    def _lookup(self,db,nullifier,bundle_hash):
        digest('0x'+nullifier);digest(bundle_hash)
        own=db.execute('SELECT * FROM ticket_jobs WHERE nullifier=?',(nullifier,)).fetchone()
        require(own is None or own['bundle_hash']==bundle_hash,'ticket-already-bound')
        row=own or db.execute('SELECT * FROM ticket_jobs WHERE bundle_hash=?',(bundle_hash,)).fetchone()
        return None if row is None else {k:row[k] for k in row.keys() if k!='mac'}

    def lookup(self,nullifier,bundle_hash):
        with self._db() as db:
            self._meta(db);return self._lookup(db,nullifier,bundle_hash)

    def check_admission_time(self,redeem_before):
        require(type(redeem_before) is int,'ticket-queue-admission')
        head=self.rpc.call('eth_getBlockByNumber','latest',False)
        require(type(head) is dict,'ticket-queue-head')
        stamp=quantity(head['timestamp']);digest(head['hash'])
        require(int(time.time())-self.fees.policy['max_head_age']<=stamp<=int(time.time())+5,'ticket-queue-head-stale')
        require(stamp<redeem_before,'ticket-redemptions-closed')
        return head

    def admit(self,nullifier,parameters,bundle_hash,*,gas,fee_ceiling,redeem_before,indexed=None):
        digest('0x'+parameters);digest(bundle_hash)
        require(type(gas) is int and 21000<=gas<=self.limits.max_gas and type(fee_ceiling) is int
            and fee_ceiling>0 and type(redeem_before) is int,'ticket-queue-admission')
        with self._db() as db:
            self._meta(db);prior=self._lookup(db,nullifier,bundle_hash)
            if prior is not None:return prior
            require(db.execute('SELECT count(*) FROM ticket_jobs').fetchone()[0]<self.limits.max_submissions,'ticket-queue-capacity')
            head=self.rpc.call('eth_getBlockByNumber','latest',False)
            require(type(head) is dict,'ticket-queue-head')
            stamp=quantity(head['timestamp']);digest(head['hash'])
            require(int(time.time())-self.fees.policy['max_head_age']<=stamp<=int(time.time())+5,'ticket-queue-head-stale')
            if indexed is not None:
                require(type(indexed) is dict and indexed['bundle_hash']==bundle_hash,'ticket-queue-free-record')
                record={'bundle_hash':bundle_hash,'operation':self.operation(bundle_hash),'nullifier':None,'parameters':None,
                    'admitted_at':stamp,'gas':0,'reserve':0,'indexed_number':indexed['post_number'],'indexed_block_hash':indexed['block_hash']}
            else:
                require(stamp<redeem_before,'ticket-redemptions-closed')
                self._fee_capacity(db,gas)
                reserve=gas*self.limits.max_fee_per_gas+self.fees.policy['max_l1_fee']+self.fees.policy['max_operator_fee']
                require(reserve<=fee_ceiling,'ticket-queue-offer-fee-cap')
                waiting=db.execute('SELECT coalesce(sum(j.reserve),0) FROM ticket_jobs j LEFT JOIN submissions s ON s.id=j.operation WHERE j.nullifier IS NOT NULL AND s.id IS NULL AND j.indexed_number IS NULL').fetchone()[0]
                spent,_=self._fee_usage(db)
                require(reserve+waiting<=self.fees.policy['total_budget']-spent,'ticket-queue-pending-budget')
                record={'bundle_hash':bundle_hash,'operation':self.operation(bundle_hash),'nullifier':nullifier,'parameters':parameters,
                    'admitted_at':stamp,'gas':gas,'reserve':reserve,'indexed_number':None,'indexed_block_hash':None}
            current=self.rpc.call('eth_getBlockByNumber',head['number'],False)
            require(type(current) is dict and current['hash']==head['hash'],'ticket-queue-head-reorg')
            db.execute('INSERT INTO ticket_jobs VALUES (?,?,?,?,?,?,?,?,?,?)',
                (*record.values(),self._mac('ticket-job-v2',record)))
            return record

    def observe_indexed(self,bundle_hash,indexed):
        require(indexed['bundle_hash']==bundle_hash,'ticket-queue-indexed-record')
        with self._db() as db:
            self._meta(db);row=db.execute('SELECT * FROM ticket_jobs WHERE bundle_hash=?',(bundle_hash,)).fetchone()
            require(row is not None,'ticket-queue-unknown')
            if row['indexed_number'] is not None:
                require(row['indexed_number']==indexed['post_number'] and row['indexed_block_hash']==indexed['block_hash'],'ticket-index-finality-violation')
                return
            updated={k:row[k] for k in row.keys() if k!='mac'}
            updated.update(indexed_number=indexed['post_number'],indexed_block_hash=indexed['block_hash'])
            db.execute('UPDATE ticket_jobs SET indexed_number=?,indexed_block_hash=?,mac=? WHERE bundle_hash=?',
                (updated['indexed_number'],updated['indexed_block_hash'],self._mac('ticket-job-v2',updated),bundle_hash))

    def submit(self,*args,**kwargs):
        require(False,'ticket-queue-use-bound-operation')

    def submit_bound(self,bundle_hash):
        operation=self.operation(bundle_hash)
        with self._db() as db:
            self._meta(db);row=db.execute('SELECT * FROM ticket_jobs WHERE bundle_hash=?',(bundle_hash,)).fetchone()
            require(row is not None and row['nullifier'] is not None,'ticket-queue-no-charge-authority')
            gas=row['gas']
        return super().submit(operation,self.index_contract,self.submit_selector+bundle_hash[2:],gas,operation_hash=bundle_hash[2:])

    def recover_bound(self,bundle_hash):
        return super().recover(self.operation(bundle_hash),bundle_hash[2:])

    def pending_jobs(self,limit=4):
        require(type(limit) is int and 1<=limit<=8,'ticket-queue-recovery-limit')
        with self._db() as db:
            self._meta(db)
            rows=db.execute("SELECT j.* FROM ticket_jobs j LEFT JOIN submissions s ON s.id=j.operation WHERE j.nullifier IS NOT NULL AND j.indexed_number IS NULL AND (s.id IS NULL OR s.state NOT IN ('finalized','failed')) ORDER BY j.admitted_at,j.operation LIMIT ?",(limit,)).fetchall()
            return [{k:r[k] for k in r.keys() if k!='mac'} for r in rows]
