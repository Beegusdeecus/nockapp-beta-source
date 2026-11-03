"""Chain-serialized encrypted issuer snapshots and independent public registry.

Local reference backend uses unlocked Anvil accounts ONLY. Production needs a
measured transaction-signing adapter, finalized-chain policy and replica admin
separation. Chain hashes detect rollback/substitution; replicas supply bytes.
"""
import hashlib
import os
from pathlib import Path
import secrets
import stat

from base_evm import encode
from base_protocol import read, sha, words, dynamic_fields
from policy import canonical, require, strict_json, Rejected


class Replicas:
    """Immutable content-addressed files; require two durable copies pre-commit.

    Only ciphertext/public registry objects enter this store. It never receives
    a plaintext issuer key/account map. File paths in this demo model distinct
    storage operators, not distinct physical failure domains.
    """
    def __init__(self,roots):
        self.roots=[Path(p) for p in roots]
        require(len(self.roots)>=2 and len(set(self.roots))==len(self.roots),'replica-config')
        for root in self.roots:
            require(root.is_absolute() and not any(p.is_symlink() for p in (root,*root.parents)), 'replica-path')
            root.mkdir(parents=True,exist_ok=True,mode=0o700)

    def put(self,data):
        digest=sha(data)
        for root in self.roots:
            target=root/digest[2:]
            stage=root/('.stage-'+secrets.token_hex(16))
            fd=os.open(stage,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                with os.fdopen(fd,'wb') as stream:
                    stream.write(data);stream.flush();os.fsync(stream.fileno())
                try:os.link(stage,target)
                except FileExistsError:
                    require(self._read(target,digest)==data,'replica-conflict')
            finally:stage.unlink()
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        return digest

    @staticmethod
    def _read(path,digest):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),'replica-file')
            data=stream.read(262145+28)
        require(sha(data)==digest,'replica-digest')
        return data

    def get(self,digest):
        require(type(digest) is str and len(digest)==66 and digest.startswith('0x'),'replica-digest')
        require(all(c in '0123456789abcdef' for c in digest[2:]),'replica-digest')
        for root in self.roots:
            try:return self._read(root/digest[2:],digest)
            except (OSError,ValueError,Rejected):pass
        raise ValueError('all-replicas-unavailable-or-corrupt')


class ChainIssuerStore:
    production_antirollback=False

    def __init__(self,rpc,contract,updater,replicas,definition):
        self.rpc,self.contract,self.updater,self.replicas,self.definition=rpc,contract,updater,replicas,definition
        self.confirmed=None
        require(read(rpc,contract,'definition()')=='0x'+definition,'issuer-definition')
        self.lease=int(read(rpc,contract,'bootEpoch()'),16)

    def _call(self,signature,block='latest'):
        return self.rpc.call('eth_call',{'to':self.contract,'data':encode(signature)},block)

    def head(self,block='latest'):
        if self.updater is not None:
            require(int(read(self.rpc,self.contract,'bootEpoch()'),16)==self.lease,'issuer-lease-superseded')
        if self.confirmed is not None:
            prior=self.rpc.call('eth_getBlockByNumber',self.confirmed['number'],False)
            require(prior is not None and prior['hash']==self.confirmed['hash'],'issuer-finality-violation')
        # One eth_call returns all head fields at a single block, rather than
        # mixing independent latest reads across a concurrently mined update.
        return self._decode_head(self.rpc.call('eth_call',{
            'to':self.contract,'data':encode('head()')},block))

    @staticmethod
    def _decode_head(data):
        w=words(data);require(len(w)==5,'registry-head')
        return {'revision':int.from_bytes(w[0],'big'),'ciphertext':'0x'+w[1].hex(),
                'registry':'0x'+w[2].hex(),'sequence':int.from_bytes(w[3],'big'),
                'initialized':bool(int.from_bytes(w[4],'big'))}

    def read(self,block='latest'):
        head=self.head(block)
        if not head['initialized']:return None,None
        data=self.replicas.get(head['ciphertext'])
        require(self.head(block)==head,'registry-state-changed')
        return head['revision']-1,data

    def public_at(self,block='latest',before=None):
        logs=self.rpc.call('eth_getLogs',{'address':self.contract,'fromBlock':'0x0','toBlock':block,
            'topics':[self.rpc.keccak(b'Updated(uint256,bytes32,bytes32,uint256,bytes)')]})
        if before is not None:
            logs=[log for log in logs if (int(log['blockNumber'],16),int(log['logIndex'],16)) <
                  (int(before['blockNumber'],16),int(before['logIndex'],16))]
        require(bool(logs),'registry-missing')
        log=logs[-1]
        public=dynamic_fields(log['data'],(3,))[0]
        value=strict_json(public)
        require(canonical(value)==public and value['definition_hash']==self.definition
                and value['sequence']==int.from_bytes(words(log['data'])[2],'big'),'registry-public')
        require(sha(public)=='0x'+words(log['data'])[1].hex(),'registry-hash')
        if before is None:
            require(sha(public)==self.head(block)['registry'],'registry-state-changed')
        return value

    def public_view(self):
        return self.public_at()

    def compare_exchange(self,expected,envelope,public):
        return self._exchange(expected,envelope,public,False)

    def begin_lease(self,expected,envelope,public):
        return self._exchange(expected,envelope,public,True)

    def _exchange(self,expected,envelope,public,new_lease):
        require(type(envelope) is bytes and 28<len(envelope)<=262144+28,'registry-envelope')
        require(set(public)=={'definition_hash','public','sequence'}
                and public['definition_hash']==self.definition,'registry-public')
        head=self.head()
        revision=head['revision']-1 if head['initialized'] else None
        require(expected==revision,'registry-conflict')
        # An orphan blob after failed CAS is harmless. A committed hash whose
        # bytes were never durably written is NOT harmless: write replicas first.
        digest=self.replicas.put(envelope)
        args=[head['revision'],head['ciphertext'],digest,public['sequence'],'0x'+canonical(public).hex()]
        if new_lease:
            data=encode('beginLease(uint256,uint256,bytes32,bytes32,uint256,bytes)',self.lease,*args)
        elif self.lease:
            data=encode('updateLeased(uint256,uint256,bytes32,bytes32,uint256,bytes)',self.lease,*args)
        else:data=encode('update(uint256,bytes32,bytes32,uint256,bytes)',*args)
        receipt=self.rpc.tx(self.updater,data,self.contract)
        require(receipt['status']=='0x1','registry-conflict')
        if new_lease:self.lease+=1
        self.last_receipt=receipt
        # Laboratory immediate-finality oracle. A deployment MUST wait for the
        # authenticated finalized head here BEFORE acknowledging persistence.
        self.confirmed={'number':receipt['blockNumber'],'hash':receipt['blockHash']}
        return 0 if expected is None else expected+1
