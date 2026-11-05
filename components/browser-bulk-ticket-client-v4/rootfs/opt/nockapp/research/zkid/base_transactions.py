"""Protected EIP-1559 signing and a durable, serialized submission journal.

Keys are supplied by the protected recovery layer and never enter this journal.
SQLite stores only public signed transactions. No unlocked-account calls,
fee-bump replacements, automatic nonce skipping or silent journal recreation.
A deployment must put the journal in durable storage with rollback protection.
Execution fee caps do NOT cap Base's separate L1-data/operator charges.
"""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import os
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import stat
import time
import threading
import secrets
import zlib

from base_protocol import ReceiptKey, keccak
from policy import canonical, require
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_JOURNAL=16*1024*1024


def rlp(value):
    """Canonical EIP-1559 wire encoding, not a cryptographic implementation."""
    if type(value) is int:
        require(0<=value<2**256,'transaction-integer')
        value=value.to_bytes((value.bit_length()+7)//8,'big')
    if type(value) is list:
        data=b''.join(rlp(v) for v in value);prefix=0xc0
    else:
        require(type(value) is bytes,'transaction-rlp')
        if len(value)==1 and value[0]<0x80:return value
        data=value;prefix=0x80
    if len(data)<56:return bytes([prefix+len(data)])+data
    size=len(data).to_bytes((len(data).bit_length()+7)//8,'big')
    return bytes([prefix+55+len(size)])+size+data


def hex_data(value,size=None):
    require(type(value) is str and value.startswith('0x') and len(value)%2==0,'transaction-hex')
    try:data=bytes.fromhex(value[2:])
    except ValueError:raise ValueError('transaction-hex') from None
    require(value.lower()=='0x'+data.hex() and (size is None or len(data)==size),'transaction-hex')
    return data


@dataclass(frozen=True)
class Limits:
    max_gas: int
    max_fee_per_gas: int
    priority_fee: int
    execution_budget: int
    max_submissions: int

    def validate(self):
        require(all(type(v) is int and 0<v<2**63 for v in asdict(self).values())
            and self.priority_fee<=self.max_fee_per_gas,'transaction-limits')


class ProtectedSigner:
    """OpenSSL secp256k1 via the existing signing adapter; no key generation.

    Must be constructed inside the measured service using a recovered transaction
    key distinct from its credential/receipt keys. This class is no attestation.
    """
    def __init__(self,rpc,key):
        require(isinstance(key,ReceiptKey) and key.rpc is rpc,'transaction-key')
        self._key=key;self.address=key.address
        self._journal_key=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,
            info=b'nockapp/base/transaction-journal-authentication/v1').derive(
                key.key.private_numbers().private_value.to_bytes(32,'big'))
        self._journal_cipher=AESGCM(HKDF(algorithm=hashes.SHA256(),length=32,salt=None,
            info=b'nockapp/base/transaction-journal-encryption/v1').derive(
                key.key.private_numbers().private_value.to_bytes(32,'big')))

    def authenticate(self,data):return hmac.digest(self._journal_key,data,'sha256').hex()

    def seal_journal(self,data,aad):
        nonce=secrets.token_bytes(12)
        return nonce+self._journal_cipher.encrypt(nonce,zlib.compress(data),aad)

    def open_journal(self,data,aad):
        require(type(data) is bytes and 28<len(data)<=MAX_JOURNAL,'transaction-journal-envelope')
        compressed=self._journal_cipher.decrypt(data[:12],data[12:],aad)
        decoder=zlib.decompressobj();raw=decoder.decompress(compressed,MAX_JOURNAL+1)
        require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
            and 0<len(raw)<=MAX_JOURNAL,'transaction-journal-envelope')
        return raw

    def sign(self,chain,nonce,to,data,gas,max_fee,tip):
        unsigned=[chain,nonce,tip,max_fee,gas,hex_data(to,0 if to=='0x' else 20),0,hex_data(data),[]]
        digest=keccak(b'\x02'+rlp(unsigned));signature=self._key.sign(digest)
        return b'\x02'+rlp(unsigned+[signature['v']-27,int(signature['r'],16),int(signature['s'],16)])


class TransactionQueue:
    def __init__(self,rpc,signer,path,contracts,limits,*,initial_nonce=None,laboratory=False,code_hashes=None,anchor=None,fee_policy=None,creations=None,application_binding=None):
        limits.validate()
        # Private deployment tooling may authorize exact public initcode hashes
        # under fixed submission IDs. Runtime callers omit this capability.
        approved_creations={}
        if creations is not None:
            require(type(creations) is dict and 1<=len(creations)<=32,'transaction-creations')
            for identifier,digest in creations.items():
                hex_data('0x'+identifier,32);hex_data('0x'+digest,32)
                require(identifier==identifier.lower() and digest==digest.lower()
                    and any(bytes.fromhex(identifier)),'transaction-creations')
                approved_creations[identifier]=digest
            require(laboratory or anchor is not None and fee_policy is not None,'transaction-creation-protection')
        require(type(contracts) is dict and (bool(contracts) or bool(approved_creations)),'transaction-contracts')
        normalized={}
        for address,selectors in contracts.items():
            hex_data(address,20)
            require(type(selectors) is list and bool(selectors),'transaction-selectors')
            for selector in selectors:hex_data(selector,4)
            normalized[address.lower()]=sorted(set(s.lower() for s in selectors))
        require(len(normalized)==len(contracts),'transaction-contracts')
        chain=int(rpc.call('eth_chainId'),16)
        require(chain==(31337 if laboratory else 84532),'transaction-chain')
        if not laboratory:
            require(type(code_hashes) is dict and set(code_hashes)==set(normalized),'transaction-contract-code')
            for digest in code_hashes.values():hex_data('0x'+digest,32)
            if code_hashes:rpc.check_identity(code_hashes)
        else:require(code_hashes is None,'transaction-laboratory-config')
        self.rpc,self.signer,self.contracts,self.limits,self.chain=rpc,signer,normalized,limits,chain
        self.creations=approved_creations
        self.fees=None
        if fee_policy is not None:
            from base_fees import BaseFees
            self.fees=BaseFees(rpc,fee_policy,chain_id=chain)
        self._anchor=anchor;self._anchor_revision=None;self._journal_lock=threading.RLock()
        self.context=canonical({'profile':'nockapp-base-transaction-journal-v4' if self.creations else ('nockapp-base-transaction-journal-v3' if self.fees else 'nockapp-base-transaction-journal-v2'),'chain':chain,
            'signer':signer.address.lower(),'contracts':normalized,'code_hashes':code_hashes,
            'limits':asdict(limits),**({'fee_policy':self.fees.policy} if self.fees else {}),
            **({'creations':self.creations} if self.creations else {}),
            **({'application_binding':application_binding} if application_binding is not None else {})}).decode()
        self.path=Path(path)
        require(self.path.is_absolute() and not any(p.is_symlink() for p in (self.path,*self.path.parents)),
            'transaction-journal-path')
        self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        info=self.path.parent.stat()
        require(info.st_uid==os.getuid() and not info.st_mode&0o077,'transaction-journal-directory')
        exists=self.path.exists()
        if anchor is not None:
            # Managed state is authoritative. Each boot uses a fresh private
            # scratch file; a stale parent filesystem is never a fallback.
            require(not exists,'transaction-journal-scratch-exists')
            revision,envelope=anchor.read()
            if initial_nonce is None:
                require(revision is not None,'transaction-journal-missing')
                self._restore_anchor(revision,envelope);exists=True
            else:require(revision is None and envelope is None,'transaction-journal-create')
        if initial_nonce is None:require(exists,'transaction-journal-missing')
        else:
            require(type(initial_nonce) is int and 0<=initial_nonce<2**63 and not exists,'transaction-journal-create')
        if exists:
            info=self.path.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077,
                'transaction-journal-file')
        else:
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        self._creating=initial_nonce is not None
        with self._db() as db:
            if initial_nonce is not None:
                latest=int(rpc.call('eth_getTransactionCount',signer.address,'latest'),16)
                pending=int(rpc.call('eth_getTransactionCount',signer.address,'pending'),16)
                require(latest==pending==initial_nonce,'transaction-initial-nonce')
                db.execute('CREATE TABLE meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), context TEXT NOT NULL, first_nonce INTEGER NOT NULL, next_nonce INTEGER NOT NULL, mac TEXT NOT NULL)')
                db.execute('CREATE TABLE submissions (id TEXT PRIMARY KEY, intent TEXT NOT NULL, nonce INTEGER UNIQUE NOT NULL, raw TEXT NOT NULL, hash TEXT UNIQUE NOT NULL, reserve INTEGER NOT NULL, state TEXT NOT NULL, block_number TEXT, block_hash TEXT, operation_hash TEXT, mac TEXT NOT NULL)')
                if self.fees:db.execute('CREATE TABLE fees (id TEXT PRIMARY KEY, quote TEXT NOT NULL, actual TEXT, mac TEXT NOT NULL)')
                meta={'context':self.context,'first_nonce':initial_nonce,'next_nonce':initial_nonce}
                db.execute('INSERT INTO meta VALUES (1,?,?,?,?)',(*meta.values(),self._mac('meta',meta)))
            else:self._meta(db)
        self._creating=False
        if initial_nonce is None:self.revalidate_finalized()
        if not exists:
            fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)

    @contextmanager
    def _db(self):
        with self._journal_lock:
            revision=None
            if self._anchor is not None:
                revision,envelope=self._anchor.read()
                if revision is None:require(self._creating and envelope is None,'transaction-journal-missing')
                else:self._restore_anchor(revision,envelope)
            db=sqlite3.connect(self.path,timeout=20,isolation_level=None)
            db.row_factory=sqlite3.Row
            try:
                db.execute('PRAGMA synchronous=FULL')
                if self._anchor is not None:db.execute('PRAGMA journal_mode=MEMORY')
                db.execute('BEGIN IMMEDIATE')
                yield db
                changed=db.total_changes>0
                db.execute('COMMIT');db.close()
                if self._anchor is not None and changed:
                    raw=self.path.read_bytes();require(0<len(raw)<=MAX_JOURNAL,'transaction-journal-size')
                    next_revision=0 if revision is None else revision+1
                    envelope=self.signer.seal_journal(raw,self._anchor_aad(next_revision))
                    actual=self._anchor.compare_exchange(revision,envelope)
                    require(actual==next_revision,'transaction-journal-revision')
                    self._anchor_revision=actual
            except Exception:
                try:
                    if db.in_transaction:db.execute('ROLLBACK')
                except sqlite3.ProgrammingError:pass
                raise
            finally:db.close()

    def _anchor_aad(self,revision):
        require(type(revision) is int and 0<=revision<2**53,'transaction-journal-revision')
        return canonical({'profile':'nockapp-base-managed-journal-v1','context':self.context,'revision':revision})

    def _restore_anchor(self,revision,envelope):
        require(self._anchor_revision is None or revision>=self._anchor_revision,'transaction-journal-rollback')
        raw=self.signer.open_journal(envelope,self._anchor_aad(revision))
        fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        self._anchor_revision=revision

    def _meta(self,db):
        row=db.execute('SELECT * FROM meta WHERE singleton=1').fetchone()
        require(row is not None and row['context']==self.context,'transaction-journal-context')
        require(hmac.compare_digest(row['mac'],self._mac('meta',{
            k:row[k] for k in ('context','first_nonce','next_nonce')})),'transaction-journal-authentication')
        for record in db.execute('SELECT * FROM submissions'):
            require(hmac.compare_digest(record['mac'],self._mac('submission',{
                k:record[k] for k in record.keys() if k!='mac'})),'transaction-journal-authentication')
        rows=db.execute('SELECT count(*),min(nonce),max(nonce) FROM submissions').fetchone()
        require(rows[0]==row['next_nonce']-row['first_nonce'] and (rows[0]==0 or
            (rows[1]==row['first_nonce'] and rows[2]==row['next_nonce']-1)),'transaction-journal-gap')
        if self.fees:
            charges=list(db.execute('SELECT * FROM fees'))
            require(len(charges)==rows[0] and {r['id'] for r in charges}=={r[0] for r in db.execute('SELECT id FROM submissions')},'transaction-fee-journal-gap')
            for charge in charges:
                require(hmac.compare_digest(charge['mac'],self._mac('fee',{k:charge[k] for k in charge.keys() if k!='mac'})),
                    'transaction-journal-authentication')
        return row

    def _unsigned(self,nonce,intent):
        return b'\x02'+rlp([self.chain,nonce,self.limits.priority_fee,self.limits.max_fee_per_gas,intent['gas'],
            hex_data(intent['to'],0 if intent['to']=='0x' else 20),0,hex_data(intent['data']),[]])

    def _fee_usage(self,db):
        total=0;overrun=False
        for row in db.execute('SELECT * FROM fees'):
            quote=json.loads(row['quote']);reserve=quote['total_reserved_wei'];actual=json.loads(row['actual']) if row['actual'] else None
            total+=max(reserve,actual['total_wei'] if actual else 0)
            overrun=overrun or bool(actual and (actual['total_wei']>reserve or actual['l1_wei']>self.fees.policy['max_l1_fee']
                or actual['operator_wei']>self.fees.policy['max_operator_fee']))
        return total,overrun

    def _funding_check(self,db,reserve):
        """Conservative funded envelope, never an automatic refill operation.

        External transfers can still fund already-broadcast bytes. This detects
        excess funding before further service signing/dialing; it cannot revoke
        those bytes or impose a consensus cap on arbitrary incoming transfers.
        """
        from base_fees import quantity
        self._identity();block=self.rpc.call('eth_getBlockByNumber','latest',False)
        require(type(block) is dict,'transaction-funded-state')
        hex_data(block.get('hash'),32)
        height=quantity(block['number']);observed=0
        for row in db.execute('SELECT s.block_number,f.actual FROM submissions s JOIN fees f ON s.id=f.id'):
            if row['actual'] is not None:
                observed+=json.loads(row['actual'])['total_wei']
                if row['block_number'] is not None:require(height>=quantity(row['block_number']),'transaction-funded-stale')
        balance=quantity(self.rpc.call('eth_getBalance',self.signer.address,block['number']))
        same=self.rpc.call('eth_getBlockByNumber',block['number'],False)
        require(type(same) is dict and same.get('hash')==block.get('hash'),'transaction-funded-reorg')
        require(balance+observed<=self.fees.policy['funded_budget'],'transaction-funded-cap')
        require(balance>=reserve,'transaction-funded-balance')

    def _fee_capacity(self,db,gas):
        spent,overrun=self._fee_usage(db)
        require(not overrun,'transaction-total-fee-overrun')
        # Do not accumulate a queue of unpriced transactions. A canonical
        # inclusion with checked fee data is needed before another signature.
        require(db.execute("SELECT count(*) FROM submissions s JOIN fees f ON s.id=f.id WHERE f.actual IS NULL OR s.state NOT IN ('confirmed','finalized','failed')").fetchone()[0]==0,
            'transaction-fee-recovery-pending')
        reserve=gas*self.limits.max_fee_per_gas+self.fees.policy['max_l1_fee']+self.fees.policy['max_operator_fee']
        require(reserve<=self.fees.policy['max_total_fee'],'transaction-total-fee-cap')
        require(reserve<=self.fees.policy['total_budget']-spent,'transaction-total-fee-budget')
        self._funding_check(db,reserve)
        return reserve

    def preflight(self,gas):
        require(type(gas) is int and 21000<=gas<=self.limits.max_gas,'transaction-gas')
        if self.fees:
            # A previous author need not remain online to trigger receipt/fee
            # recovery. Bound this work to the one unpriced saved transaction;
            # poll may reuse its exact raw bytes, never a new nonce/signature.
            with self._db() as db:
                self._meta(db)
                pending=db.execute("SELECT s.id FROM submissions s JOIN fees f ON s.id=f.id WHERE f.actual IS NULL OR s.state NOT IN ('confirmed','finalized','failed') ORDER BY s.nonce LIMIT 1").fetchone()
            if pending is not None:self.poll(pending[0])
            with self._db() as db:self._meta(db);self._fee_capacity(db,gas)

    def _fee_admit(self,db,nonce,intent):
        self._fee_capacity(db,intent['gas'])
        return self.fees.quote(self._unsigned(nonce,intent),intent['gas'],intent['gas']*self.limits.max_fee_per_gas)

    def _fee_observe(self,db,row,receipt,block):
        intent=json.loads(row['intent']);actual=self.fees.actual(receipt,block,intent['gas'],self.limits.max_fee_per_gas)
        old=db.execute('SELECT * FROM fees WHERE id=?',(row['id'],)).fetchone()
        previous=json.loads(old['actual']) if old['actual'] else None
        # Keep the conservative largest observed charge across a reorg; never
        # refund uncertain spend. This is an exposure ledger, not a billing API.
        if previous:
            actual={k:max(actual[k],previous[k]) for k in actual}
            actual['total_wei']=actual['execution_wei']+actual['l1_wei']+actual['operator_wei']
        updated={'id':old['id'],'quote':old['quote'],'actual':canonical(actual).decode()}
        db.execute('UPDATE fees SET actual=?,mac=? WHERE id=?',
            (updated['actual'],self._mac('fee',updated),row['id']))

    def _mac(self,kind,record):
        return self.signer.authenticate(canonical({'profile':'nockapp-base-journal-record-v1',
            'context':self.context,'kind':kind,'record':record}))

    def _identity(self):
        require(int(self.rpc.call('eth_chainId'),16)==self.chain,'transaction-chain')

    def recover(self,submission,operation_hash):
        """Recover only the exact already-authorized application request.

        This binding permits recovery after a proof/receipt deadline expires;
        it never authorizes signing new bytes after expiry. The measured
        application computes the hash; it is not a client-selected shortcut.
        """
        hex_data('0x'+operation_hash,32)
        with self._db() as db:
            self._meta(db)
            row=db.execute('SELECT * FROM submissions WHERE id=?',(submission,)).fetchone()
            if row is None:return None
            require(row['operation_hash']==operation_hash,'transaction-submission-conflict')
        return self.poll(submission)

    def outstanding(self,limit=32):
        """Bounded recovery work list; no mutation or new nonce allocation."""
        require(type(limit) is int and 1<=limit<=32,'transaction-recovery-limit')
        with self._db() as db:
            self._meta(db)
            return [row[0] for row in db.execute(
                "SELECT id FROM submissions WHERE state NOT IN ('finalized','failed') ORDER BY nonce LIMIT ?",(limit,))]

    def revalidate_finalized(self):
        """Anchor a restarted queue to its latest persisted finalized receipt."""
        with self._db() as db:
            self._meta(db)
            row=db.execute("SELECT id FROM submissions WHERE state IN ('finalized','failed') ORDER BY nonce DESC LIMIT 1").fetchone()
        if row is not None:self.poll(row[0])

    def submit(self,submission,to,data,gas,*,operation_hash=None):
        require(type(submission) is str and len(hex_data('0x'+submission,32))==32
            and any(bytes.fromhex(submission)),'transaction-submission')
        require(type(to) is str,'transaction-target')
        to=to.lower();blob=hex_data(data)
        if to=='0x':
            require(0<len(blob)<=32768 and self.creations.get(submission)==hashlib.sha256(blob).hexdigest(),
                'transaction-creation')
        else:
            hex_data(to,20)
            require(len(blob)<=32768 and to in self.contracts and data[:10].lower() in self.contracts[to],
                'transaction-target')
        require(type(gas) is int and 21000<=gas<=self.limits.max_gas,'transaction-gas')
        if operation_hash is not None:hex_data('0x'+operation_hash,32)
        intent=canonical({'to':to,'data':data.lower(),'gas':gas}).decode()
        with self._db() as db:
            meta=self._meta(db)
            row=db.execute('SELECT * FROM submissions WHERE id=?',(submission,)).fetchone()
            if row is not None:
                previous=json.loads(row['intent'])
                require(row['operation_hash']==operation_hash and (row['intent']==intent or
                    operation_hash is not None and previous['to']==to and previous['gas']==gas),
                    'transaction-submission-conflict')
            else:
                self._identity()
                latest=int(self.rpc.call('eth_getTransactionCount',self.signer.address,'latest'),16)
                pending=int(self.rpc.call('eth_getTransactionCount',self.signer.address,'pending'),16)
                require(meta['first_nonce']<=latest<=pending<=meta['next_nonce'],'transaction-nonce-conflict')
                require(db.execute('SELECT count(*) FROM submissions').fetchone()[0]<self.limits.max_submissions,
                    'transaction-count-budget')
                reserve=gas*self.limits.max_fee_per_gas
                spent=db.execute('SELECT coalesce(sum(reserve),0) FROM submissions').fetchone()[0]
                require(reserve<=self.limits.execution_budget-spent,'transaction-execution-budget')
                block=self.rpc.call('eth_getBlockByNumber','latest',False)
                require(block is not None and int(block['baseFeePerGas'],16)+self.limits.priority_fee<=
                    self.limits.max_fee_per_gas,'transaction-fee-cap')
                estimate=int(self.rpc.call('eth_estimateGas',{'from':self.signer.address,
                    **({'to':to} if to!='0x' else {}),'data':data,'value':'0x0','gas':hex(gas)}),16)
                require(21000<=estimate<=gas,'transaction-gas-estimate')
                fee_quote=self._fee_admit(db,meta['next_nonce'],json.loads(intent)) if self.fees else None
                raw=self.signer.sign(self.chain,meta['next_nonce'],to,data,gas,
                    self.limits.max_fee_per_gas,self.limits.priority_fee)
                require(type(raw) is bytes and len(raw)<=33000,'transaction-signature')
                digest=keccak(raw)
                record=dict(zip(('id','intent','nonce','raw','hash','reserve','state','block_number','block_hash','operation_hash'),
                    (submission,intent,meta['next_nonce'],'0x'+raw.hex(),digest,reserve,'recoverable',None,None,operation_hash)))
                db.execute('INSERT INTO submissions VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                    (*record.values(),self._mac('submission',record)))
                if fee_quote is not None:
                    charge={'id':submission,'quote':canonical(fee_quote).decode(),'actual':None}
                    db.execute('INSERT INTO fees VALUES (?,?,?,?)',(*charge.values(),self._mac('fee',charge)))
                updated={'context':self.context,'first_nonce':meta['first_nonce'],'next_nonce':meta['next_nonce']+1}
                db.execute('UPDATE meta SET next_nonce=?,mac=? WHERE singleton=1',
                    (updated['next_nonce'],self._mac('meta',updated)))
        # Durable COMMIT precedes the first network transmission. A crash here
        # leaves exactly the same signed bytes available for later recovery.
        return self.poll(submission)

    def poll(self,submission):
        with self._db() as db:
            self._meta(db);self._identity()
            row=db.execute('SELECT * FROM submissions WHERE id=?',(submission,)).fetchone()
            require(row is not None,'transaction-unknown')
            require(keccak(hex_data(row['raw']))==row['hash'],'transaction-journal-tamper')
            receipt=self.rpc.call('eth_getTransactionReceipt',row['hash'])
            state='recoverable';number=None;block_hash=None
            if receipt is not None:
                require(receipt['transactionHash']==row['hash'] and receipt['status'] in ('0x0','0x1'),
                    'transaction-receipt')
                block=self.rpc.call('eth_getBlockByNumber',receipt['blockNumber'],False)
                if block is not None and block['hash']==receipt['blockHash']:
                    if self.fees:self._fee_observe(db,row,receipt,block)
                    number,block_hash=receipt['blockNumber'],receipt['blockHash']
                    final=self.rpc.call('eth_getBlockByNumber','finalized',False)
                    require(final is not None,'transaction-finality-unavailable')
                    state=('finalized' if receipt['status']=='0x1' else 'failed') if int(final['number'],16)>=int(number,16) else 'confirmed'
            if row['state'] in ('finalized','failed'):
                require(state==row['state'] and row['block_number']==number and row['block_hash']==block_hash,
                    'transaction-finality-violation')
            if state=='recoverable':
                latest=int(self.rpc.call('eth_getTransactionCount',self.signer.address,'latest'),16)
                pending=int(self.rpc.call('eth_getTransactionCount',self.signer.address,'pending'),16)
                if latest>row['nonce']:
                    # Another mined transaction used this nonce, or RPC lost a
                    # receipt. Never resubmit this intent under a fresh nonce.
                    state='nonce-conflict'
                else:
                    known=self.rpc.call('eth_getTransactionByHash',row['hash'])
                    if known is not None:state='pending'
                    elif pending<=row['nonce']:
                        try:
                            if self.fees:
                                require(not self._fee_usage(db)[1],'transaction-total-fee-overrun')
                                saved=json.loads(row['intent'])
                                allowed=json.loads(db.execute('SELECT quote FROM fees WHERE id=?',(row['id'],)).fetchone()[0])['total_reserved_wei']
                                self._funding_check(db,allowed)
                                self.fees.quote(self._unsigned(row['nonce'],saved),saved['gas'],row['reserve'])
                            returned=self.rpc.call('eth_sendRawTransaction',row['raw'])
                            require(returned==row['hash'],'transaction-returned-hash')
                            state='pending'
                        except Exception:
                            state='recoverable'  # Lost reply: inspect chain before another transmission.
                    else:state='nonce-conflict'
            updated={k:row[k] for k in row.keys() if k!='mac'}
            updated.update(state=state,block_number=number,block_hash=block_hash)
            if any(updated[k]!=row[k] for k in updated):
                db.execute('UPDATE submissions SET state=?,block_number=?,block_hash=?,mac=? WHERE id=?',
                    (state,number,block_hash,self._mac('submission',updated),submission))
            return {'submission_id':submission,'transaction_hash':row['hash'],'nonce':row['nonce'],
                'state':state,'block_number':number,'block_hash':block_hash,
                'execution_fee_reserved_wei':row['reserve'],
                **({'total_fee_reserved_wei':json.loads(db.execute('SELECT quote FROM fees WHERE id=?',(submission,)).fetchone()[0])['total_reserved_wei'],
                    'fee_policy_overrun':self._fee_usage(db)[1]} if self.fees else {})}


class SignedRPC:
    """Connect existing issuer CAS transactions to the protected durable queue.

    tx() returns a canonical inclusion receipt, never a finality promise. The
    leased issuer's explicit finalized activation/boot gates remain necessary.
    A timeout preserves the queued transaction for inspection/recovery.
    """
    def __init__(self,rpc,queue,*,timeout=20):
        require(queue.rpc is rpc and type(timeout) is int and 0<timeout<=30,'signed-rpc-config')
        self.rpc,self.queue,self.timeout=rpc,queue,timeout

    def call(self,method,*params):
        require(method not in ('eth_sendTransaction','eth_sign','personal_sign','eth_sendRawTransaction'),
            'signed-rpc-method')
        return self.rpc.call(method,*params)

    def keccak(self,data):return keccak(data)

    def tx(self,sender,data,to=None,gas=None):
        require(sender.lower()==self.queue.signer.address.lower() and to is not None,'signed-rpc-sender')
        if gas is None:gas=self.queue.limits.max_gas
        # CAS arguments commit the expected revision/lease and next ciphertext.
        # The exact same operation after a timeout recovers its existing hash.
        import hashlib
        submission=hashlib.sha256(canonical({'profile':'nockapp-base-service-transaction-v1',
            'chain':self.queue.chain,'to':to.lower(),'data':data.lower(),'gas':gas})).hexdigest()
        state=self.queue.submit(submission,to,data,gas)
        deadline=time.monotonic()+self.timeout
        while True:
            if state['state'] in ('confirmed','finalized','failed'):
                receipt=self.rpc.call('eth_getTransactionReceipt',state['transaction_hash'])
                require(receipt is not None and receipt['blockHash']==state['block_hash'],'transaction-receipt')
                return receipt
            require(state['state']!='nonce-conflict','transaction-nonce-conflict')
            if time.monotonic()>=deadline:raise TimeoutError('transaction-recovery-required')
            time.sleep(.25)
            state=self.queue.poll(submission)
