"""Independent local holder profiles and a chain-only shared discussion reader.

Fixture keys are injected in private pipes. An installed desktop must use its
existing persistent keyring; this module does not access or migrate that wallet.
"""
import copy
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base_protocol import PROTOCOL, inspect_publication, keccak, sha
from domain_pipeline import Native, definition_hash
from policy import POLICY_HASH, canonical, require, strict_json


class LocalHolder:
    def __init__(self,directory,key):
        self.root=Path(directory)
        require(self.root.is_absolute() and not any(p.is_symlink() for p in (self.root,*self.root.parents)),
                'holder-profile')
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        require(type(key) is bytes and len(key)==32,'holder-key')
        self.cipher=AESGCM(key)
        self.aad=(PROTOCOL+'/local-credential').encode()

    def save(self,credential):
        nonce=secrets.token_bytes(12)
        data=nonce+self.cipher.encrypt(nonce,canonical(credential),self.aad)
        stage=self.root/('.credential-'+secrets.token_hex(12))
        fd=os.open(stage,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(stage,self.root/'credential.enc')
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)

    def load(self):
        fd=os.open(self.root/'credential.enc',os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:data=stream.read(262145)
        require(28<len(data)<=262144,'holder-credential-size')
        return strict_json(self.cipher.decrypt(data[:12],data[12:],self.aad))

    def refresh(self,remote,view):
        """Explicit private witness maintenance, separate from making a post.

        Existing issuer API learns its already-known handle and refresh timing.
        It receives no post, challenge or proof. Prefetch on registry changes and
        use cover traffic/anonymous transport for stronger timing protection.
        """
        credential=self.load()
        require(definition_hash(credential['issuer'])==view['definition_hash'],'issuer-definition')
        handle=credential['credential']['claims'][0]['Revocation']['value']
        result=remote.refresh_witness(handle,view)
        require(type(result) is dict and set(result)=={'witness','public','sequence','definition_hash'}
            and result['public']==view['public'] and result['sequence']==view['sequence']
            and result['definition_hash']==view['definition_hash'],'registry-state-changed')
        refreshed=Native().call('refresh',credential=credential,public=result['public'],witness=result['witness'])
        self.save(refreshed['credential'])

    def present(self,view,challenge):
        credential=self.load()
        require(definition_hash(credential['issuer'])==view['definition_hash'],'issuer-definition')
        require(credential['issuer']['revocation_registry']==view['public']['revocation_registry'],
                'witness-refresh-required')
        return Native().call('present',credential=credential,trust={
            'issuer':view['public'],'policy':POLICY_HASH,'challenge':challenge,
            'current_sequence':view['sequence'],'now':challenge['created_at']})


def prove_in_process(directory,key,view,challenge):
    from credential import private_child
    request=canonical({'directory':str(directory),'key':key.hex(),'view':view,'challenge':challenge})
    result=subprocess.run([sys.executable,'-B',str(Path(__file__).resolve()),'--holder'],
                          input=request,capture_output=True,timeout=20,preexec_fn=private_child)
    require(result.returncode==0 and not result.stderr and len(result.stdout)<=262144,'holder-worker')
    return strict_json(result.stdout)


class SharedReader:
    def __init__(self,rpc,contract,registry,app,*,demo_finality=False,start_block=0,page_blocks=1000,max_pages=4,count_native=None):
        require(type(start_block) is int and start_block>=0 and type(page_blocks) is int
                and 0<page_blocks<=10000 and type(max_pages) is int and 0<max_pages<=16,'history-config')
        self.rpc,self.contract,self.registry,self.app=rpc,contract,registry,app
        self.demo_finality=demo_finality
        self.count_native=count_native
        self.checkpoint=None;self.start_block=start_block;self.page_blocks=page_blocks;self.max_pages=max_pages
        self.sync_complete=False;self.sync_target=None
        self._logs={};self._verified={};self._chain=None

    @staticmethod
    def _key(log):
        return log['blockHash'],log['transactionHash'],log['logIndex']

    def read(self,now):
        chain=int(self.rpc.call('eth_chainId'),16)
        require(self._chain in (None,chain),'history-chain-changed')
        self._chain=chain
        if self.demo_finality:
            require(chain==31337,'local-finality-only')
        tag='latest' if self.demo_finality else 'finalized'
        finalized=self.rpc.call('eth_getBlockByNumber',tag,False)
        require(finalized is not None,'finality-unavailable')
        if self.checkpoint is not None:
            prior=self.rpc.call('eth_getBlockByNumber',self.checkpoint['number'],False)
            consistent=prior is not None and prior['hash']==self.checkpoint['hash']
            if not self.demo_finality:require(consistent,'finality-violation')
            elif not consistent:
                self.checkpoint=None;self._logs.clear();self._verified.clear()
        tip=int(finalized['number'],16)
        require(self.checkpoint is None or tip>=int(self.checkpoint['number'],16),'finality-regression')
        start=max(self.start_block,0 if self.checkpoint is None else int(self.checkpoint['number'],16)+1)
        end=min(tip,start+self.page_blocks*self.max_pages-1)
        target=finalized if end==tip else self.rpc.call('eth_getBlockByNumber',hex(end),False)
        require(target is not None,'history-unavailable')
        topics=[keccak(b'Published(bytes32,bytes32,bytes32,uint256,bytes,bytes,bytes)'),
                keccak(b'OrdinaryPublished(bytes32,bytes32,bytes32,uint256,bytes)')]
        added={}
        for first in range(start,end+1,self.page_blocks):
            last=min(first+self.page_blocks-1,end)
            logs=self.rpc.call('eth_getLogs',{'address':self.contract,'fromBlock':hex(first),'toBlock':hex(last),
                'topics':[topics]})
            require(type(logs) is list,'history-response')
            for log in logs:
                require(first<=int(log['blockNumber'],16)<=last and not log.get('removed',False),'history-range')
                key=self._key(log)
                require(key not in added or added[key]==log,'history-conflict')
                added[key]=copy.deepcopy(log)
        # Commit no cursor or cache changes if the range changed while scanning.
        anchor=self.rpc.call('eth_getBlockByNumber',target['number'],False)
        require(anchor is not None and anchor['hash']==target['hash'],'history-reorg')
        self._logs.update(added)
        self.checkpoint={'number':target['number'],'hash':target['hash']}
        self.sync_complete=end==tip;self.sync_target={'number':finalized['number'],'hash':finalized['hash']}
        current=None;results=[]
        for key,log in sorted(self._logs.items(),key=lambda pair:(int(pair[1]['blockNumber'],16),
                int(pair[1]['transactionIndex'],16),int(pair[1]['logIndex'],16))):
            try:
                if key not in self._verified:
                    native=Native() if log.get('topics',[None])[0]==topics[0] else None
                    self._verified[key]=inspect_publication(self.rpc,self.contract,log,self.registry,native,self.app,now,end,
                        count_native=self.count_native)
                result=copy.deepcopy(self._verified[key])
                require(type(now) is int and now>=result['accepted_at'],'publication-clock')
                if result['facts']:
                    if current is None:current=sha(canonical(self.registry.public_view()))
                    result['credential_status']=('expired' if now>=result['credential_expiry'] else
                        'valid-at-current-registry' if current==result['publication_registry_hash'] else
                        'unknown-after-registry-update')
                result.update(submission_id=log['topics'][1][2:],state='finalized')
                results.append(result)
            except Exception:
                # An invalid proof or temporarily missing receipt is isolated.
                # Failed verification is never cached; next refresh retries it.
                results.append({'submission_id':log['topics'][1][2:] if len(log.get('topics',[]))>1 else None,
                    'state':'unavailable','valid_when_published':False,'credential_status':'unavailable'})
        anchor=self.rpc.call('eth_getBlockByNumber',target['number'],False)
        require(anchor is not None and anchor['hash']==target['hash'],'history-reorg')
        return results


def main():
    require(sys.argv[1:]==['--holder'],'holder-operation')
    request=strict_json(sys.stdin.buffer.read(262145))
    holder=LocalHolder(Path(request['directory']),bytes.fromhex(request['key']))
    proof=holder.present(request['view'],request['challenge'])
    sys.stdout.buffer.write(canonical(proof))


if __name__=='__main__':
    try:main()
    except Exception:sys.exit(1)
