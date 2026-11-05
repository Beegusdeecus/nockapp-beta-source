"""Ubuntu helper shared discussions: durable public outbox and independent reads.

No ordinary-post keyring/credential dependency. Credential proofs stay local;
only selected exact-post public proofs go over the attested service channel.
Installer owns endpoints/contracts/paths. Local forum history is never imported.
"""
import copy
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import time

from base_client import SharedReader
from base_protocol import challenge as expected_challenge,inspect_publication
from base_rpc import BaseRPC
from base_state import ChainIssuerStore
from base_transport import BaseRemote,validate_approval
from domain_pipeline import Native
from policy import Rejected,canonical,hex_string,require
from post_scope import payload,facts,uuid

PROFILE='nockapp-base-desktop-v1'
STATES={'prepared','challenge-saved','proof-saved','submitted'}
TX_STATES={'pending','confirmed','finalized','failed','recoverable'}


def validate_chain(value,approved):
    require(type(value) is dict and set(value)=={'rpc_endpoint','runtime_code','deployment_block'}
        and value['rpc_endpoint']=='https://sepolia.base.org' and type(value['runtime_code']) is dict
        and set(value['runtime_code'])=={approved['identity']['contract'],approved['identity']['registry']}
        and type(value['deployment_block']) is int and 0<=value['deployment_block']<2**53,'base-desktop-chain')
    for digest in value['runtime_code'].values():hex_string(digest,64)
    return value


class BaseDesktop:
    record_names=frozenset(('outbox.json','history-cache.json'))
    def __init__(self,directory,approved,chain,wallet_directory):
        self.approved=copy.deepcopy(validate_approval(approved));self.chain=copy.deepcopy(validate_chain(chain,approved))
        self.identity=copy.deepcopy(approved['identity']);self.remote=BaseRemote(approved)
        self.root=Path(directory);self.wallet_directory=wallet_directory
        require(self.root.is_absolute() and not any(p.is_symlink() for p in (self.root,*self.root.parents))
            and not any(p.startswith('.env') for p in self.root.parts),'base-desktop-directory')
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        info=self.root.stat();require(info.st_uid==os.getuid() and not info.st_mode&0o077,'base-desktop-directory')
        self._rpc=None;self._registry=None;self._reader=None

    @contextmanager
    def lock(self):
        fd=os.open(self.root/'controller.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd);require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
                and not info.st_mode&0o077 and info.st_nlink==1,'base-desktop-lock')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Rejected('base-desktop-busy') from None
            yield
        finally:os.close(fd)

    def _read(self,name,*,missing=False):
        require(name in self.record_names,'base-desktop-record')
        try:fd=os.open(self.root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        except FileNotFoundError:
            if missing:return None
            raise
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
                and not info.st_mode&0o077 and info.st_nlink==1 and 0<info.st_size<=4*1048576,'base-desktop-record')
            data=stream.read(4*1048576+1)
        # The shared outbox contains public post/proof data, never a credential.
        def pairs(items):
            result={}
            for key,item in items:
                require(key not in result,'base-desktop-record');result[key]=item
            return result
        def constant(_):raise Rejected('base-desktop-record')
        value=json.loads(data,object_pairs_hook=pairs,parse_constant=constant)
        require(type(value) is dict and canonical(value)==data,'base-desktop-record')
        return value

    def _write(self,name,value):
        require(name in self.record_names,'base-desktop-record')
        data=canonical(value);require(len(data)<=4*1048576,'base-desktop-storage-limit')
        if (self.root/name).exists() or (self.root/name).is_symlink():self._read(name)
        stage=self.root/('.write-'+secrets.token_hex(16))
        try:
            fd=os.open(stage,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            os.replace(stage,self.root/name)
            fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:
            if stage.exists():stage.unlink()

    def _outbox(self):
        value=self._read('outbox.json',missing=True)
        if value is None:return {'profile':PROFILE,'identity':self.identity,'entries':[]}
        require(set(value)=={'profile','identity','entries'} and value['profile']==PROFILE
            and value['identity']==self.identity and type(value['entries']) is list and len(value['entries'])<=100,'base-desktop-outbox')
        seen=set()
        for row in value['entries']:
            require(type(row) is dict and set(row)=={'post','facts','submission_id','phase','challenge','proof','status'}
                and row['phase'] in STATES,'base-desktop-outbox')
            payload(row['post']);require(row['post']['id'] not in seen,'base-desktop-outbox');seen.add(row['post']['id'])
            hex_string(row['submission_id'],64)
            require(any(bytes.fromhex(row['submission_id'])) and row['post']['claims']==[],'base-desktop-outbox')
            require(type(row['facts']) is list and (row['facts']==[] or facts(row['facts'])==row['facts']),'base-desktop-outbox')
            require(row['status'] is None or type(row['status']) is dict and row['status'].get('state') in TX_STATES,'base-desktop-outbox')
            if not row['facts']:
                require(row['challenge'] is None and row['proof'] is None
                    and row['phase'] in ('prepared','submitted'),'base-desktop-outbox')
            elif row['phase']=='prepared':
                require(row['challenge'] is None and row['proof'] is None,'base-desktop-outbox')
            else:
                c=row['challenge'];require(type(c) is dict,'base-desktop-outbox')
                require(c==expected_challenge(row['post'],row['facts'],self.identity['application'],self.identity['chain_id'],
                    self.identity['contract'],c['registry_sequence'],c['created_at'],row['submission_id']),'base-desktop-outbox')
                require((row['phase']=='challenge-saved' and row['proof'] is None)
                    or (row['phase'] in ('proof-saved','submitted') and type(row['proof']) is dict),'base-desktop-outbox')
        return value

    def _chain(self):
        if self._rpc is None:
            rpc=BaseRPC(self.chain['rpc_endpoint']);rpc.check_identity(self.chain['runtime_code'])
            expected=self.identity
            registry=ChainIssuerStore(rpc,expected['registry'],None,None,expected['definition_hash'])
            self._rpc,self._registry=rpc,registry
        return self._rpc,self._registry

    def capabilities(self):
        return {'configured':True,'identity':copy.deepcopy(self.identity),'experimental':True}

    def _projection(self,row):
        return {'post':copy.deepcopy(row['post']),'facts':copy.deepcopy(row['facts']),
            'submission_id':row['submission_id'],'phase':row['phase'],
            'status':copy.deepcopy(row['status']) if row['status'] is not None else {'state':'recoverable'},'experimental':True}

    def outbox(self,after=0,limit=8):
        require(type(after) is int and 0<=after<=100 and type(limit) is int and 1<=limit<=8,'base-outbox-page')
        with self.lock():
            rows=self._outbox()['entries'];page=[]
            for row in rows[after:after+limit]:
                projection=self._projection(row)
                if len(canonical(page+[projection]))>110000:break
                page.append(projection)
            return {'entries':page,'next_after':after+len(page),'more':after+len(page)<len(rows),'experimental':True}

    def _verify_status(self,row,remote):
        require(type(remote) is dict and remote.get('submission_id')==row['submission_id'],'base-submission-status')
        tx=remote.get('transaction_hash');require(type(tx) is str and tx.startswith('0x'),'base-submission-status');hex_string(tx[2:],64)
        rpc,registry=self._chain();receipt=rpc.call('eth_getTransactionReceipt',tx)
        result={'state':'pending','transaction_hash':tx,'post_number':None,'checked_at':int(time.time())}
        if receipt is None:return result
        require(receipt['transactionHash']==tx and receipt.get('to','').lower()==self.identity['contract'],'base-submission-receipt')
        block=rpc.call('eth_getBlockByNumber',receipt['blockNumber'],False)
        if block is None or block['hash']!=receipt['blockHash']:
            return {**result,'state':'recoverable'}
        final=rpc.call('eth_getBlockByNumber','finalized',False);require(final is not None,'base-finality-unavailable')
        if int(final['number'],16)<int(receipt['blockNumber'],16):return {**result,'state':'confirmed'}
        require(receipt['status'] in ('0x0','0x1'),'base-submission-receipt')
        if receipt['status']=='0x0':return {**result,'state':'failed'}
        logs=[log for log in receipt['logs'] if log['address'].lower()==self.identity['contract']
            and len(log['topics'])==3 and log['topics'][1]=='0x'+row['submission_id']]
        require(len(logs)==1,'base-submission-publication')
        native=Native() if row['facts'] else None
        checked=inspect_publication(rpc,self.identity['contract'],logs[0],registry,native,self.identity['application'],
            int(time.time()),int(final['number'],16))
        require(checked['post']==row['post'] and checked['facts']==row['facts'],'base-submission-content')
        return {**result,'state':'finalized','post_number':checked['post_number']}

    def _proof(self,row):
        from domain_desktop import DomainDesktop
        desktop=DomainDesktop(self.wallet_directory)
        require(desktop.native.sha256.hex()==self.identity['native_sha256'],'base-native-identity')
        view=self.remote.public_view()
        c=self.remote.call('post-challenge',{'post':row['post'],'facts':row['facts'],'submission_id':row['submission_id']})
        expected=expected_challenge(row['post'],row['facts'],self.identity['application'],self.identity['chain_id'],
            self.identity['contract'],view['sequence'],c['created_at'],row['submission_id'])
        now=int(time.time());require(c==expected and now-5<=c['created_at']<=now+5 and now<c['expires_at'],'base-post-challenge')
        row['challenge']=c;row['phase']='challenge-saved'
        return desktop,view

    def _run(self,box,row):
        try:
            if row['facts'] and row['proof'] is None:
                desktop,view=self._proof(row);self._write('outbox.json',box)
                witness=self.remote.refresh_witness(desktop.witness_handle(),view)
                proof=desktop.present(view,witness,row['challenge'],int(time.time()))
                require(proof.get('claimed_id') is None,'base-identity-disclosure')
                row['proof']=proof;row['phase']='proof-saved';self._write('outbox.json',box)
            body={key:copy.deepcopy(row[key]) for key in ('post','facts','submission_id','challenge','proof')}
            body['approve_publication']=True
            # Exact saved request only. Server checks its durable originating
            # request binding before recovery, including after proof expiry.
            remote=self.remote.call('post-submit',body)
            row['phase']='submitted';row['status']=self._verify_status(row,remote)
        except Exception:
            row['status']={'state':'recoverable','checked_at':int(time.time())}
        self._write('outbox.json',box)
        return self._projection(row)

    def publish(self,post,selected,approve_publication):
        require(approve_publication is True,'consent-required');payload(post)
        require(type(selected) is list and (selected==[] or facts(selected)==selected),'post-facts')
        require(post['claims']==[],'base-demo-claims')
        with self.lock():
            box=self._outbox();row=next((r for r in box['entries'] if r['post']['id']==post['id']),None)
            if row is None:
                require(len(box['entries'])<100,'base-desktop-storage-limit')
                row={'post':copy.deepcopy(post),'facts':copy.deepcopy(selected),'submission_id':secrets.token_hex(32),
                    'phase':'prepared','challenge':None,'proof':None,'status':None}
                box['entries'].append(row);self._write('outbox.json',box)
            require(row['post']==post and row['facts']==selected,'base-post-identity-conflict')
            return self._run(box,row)

    def recover(self,post_id):
        uuid(post_id)
        with self.lock():
            box=self._outbox();row=next((r for r in box['entries'] if r['post']['id']==post_id),None)
            require(row is not None,'base-post-unknown')
            return self._run(box,row)

    def _canonical_recovery_status(self,row):
        """Legacy migration: observe existing acceptance, never submit again."""
        from base_protocol import keccak
        rpc,_=self._chain();final=rpc.call('eth_getBlockByNumber','finalized',False)
        require(final is not None,'base-finality-unavailable')
        logs=rpc.call('eth_getLogs',{'address':self.identity['contract'],
            'fromBlock':hex(self.chain['deployment_block']),'toBlock':final['number'],
            'topics':[[keccak(b'Published(bytes32,bytes32,bytes32,uint256,bytes,bytes,bytes)'),
                keccak(b'OrdinaryPublished(bytes32,bytes32,bytes32,uint256,bytes)')],'0x'+row['submission_id']]})
        require(type(logs) is list and len(logs)<=1,'base-submission-publication')
        tx=logs[0]['transactionHash'] if logs else (row['status'] or {}).get('transaction_hash')
        status=self._verify_status(row,{'submission_id':row['submission_id'],'transaction_hash':tx}) if tx is not None else None
        anchored=rpc.call('eth_getBlockByNumber',final['number'],False)
        require(anchored is not None and anchored['hash']==final['hash'],'base-history-reorg')
        return status

    def recover_read_only(self,post_id):
        uuid(post_id)
        with self.lock():
            box=self._outbox();row=next((r for r in box['entries'] if r['post']['id']==post_id),None)
            require(row is not None,'base-post-unknown')
            previous=row['status'] or {}
            try:status=self._canonical_recovery_status(row)
            except Exception:status=None
            if status is None:
                status={'state':'recoverable','checked_at':int(time.time())}
                if 'transaction_hash' in previous:status.update(transaction_hash=previous['transaction_hash'],post_number=None)
            row['status']=status
            if status['state']=='finalized':row['phase']='submitted'
            self._write('outbox.json',box)
            return self._projection(row)

    def history(self):
        with self.lock():
            rpc,registry=self._chain()
            if self._reader is None:
                reader=SharedReader(rpc,self.identity['contract'],registry,self.identity['application'],
                    start_block=self.chain['deployment_block'])
                saved=self._read('history-cache.json',missing=True)
                if saved is not None:
                    require(set(saved)=={'profile','identity','checkpoint','logs'} and saved['profile']==PROFILE
                        and saved['identity']==self.identity and type(saved['logs']) is list,'base-history-cache')
                    checkpoint=saved['checkpoint']
                    require(type(checkpoint) is dict and set(checkpoint)=={'number','hash'}
                        and type(checkpoint['number']) is str and checkpoint['number'].startswith('0x')
                        and self.chain['deployment_block']<=int(checkpoint['number'],16)<2**53,'base-history-cache')
                    require(type(checkpoint['hash']) is str and checkpoint['hash'].startswith('0x'),'base-history-cache')
                    hex_string(checkpoint['hash'][2:],64)
                    for log in saved['logs']:
                        require(type(log) is dict and log.get('address','').lower()==self.identity['contract']
                            and self.chain['deployment_block']<=int(log['blockNumber'],16)<=int(checkpoint['number'],16),
                            'base-history-cache')
                    reader.checkpoint=checkpoint
                    reader._logs={reader._key(log):log for log in saved['logs']}
                    require(len(reader._logs)==len(saved['logs']),'base-history-cache')
                self._reader=reader
            rows=self._reader.read(int(time.time()))
            self._write('history-cache.json',{'profile':PROFILE,'identity':self.identity,
                'checkpoint':self._reader.checkpoint,'logs':list(self._reader._logs.values())})
            # A native message remains bounded; caller pages the public view.
            return rows,self._reader.sync_complete,self._reader.checkpoint

    def discussion(self,after,limit):
        require(type(after) is int and 0<=after<2**53 and type(limit) is int and 1<=limit<=20,'base-history-page')
        rows,complete,checkpoint=self.history();available=[r for r in rows if r['state']=='finalized' and int(r['post_number'])>after]
        page=[]
        for row in available[:limit]:
            if len(canonical(page+[row]))>110000:break
            page.append(row)
        return {'identity':copy.deepcopy(self.identity),'posts':page,
            'unavailable':[r for r in rows if r['state']=='unavailable'][:20],
            'next_after':int(page[-1]['post_number']) if page else after,'more':len(available)>len(page),
            'sync_complete':complete,'checkpoint':checkpoint,'experimental':True}
