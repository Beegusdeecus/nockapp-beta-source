"""Bounded public-only historical views of the fixed issuer-state contract.

No secret DB or ciphertext fetch. Exact-block logs and revision-guided binary
search replace unbounded event-history downloads. Same-block ordering is checked
against the canonical index event, including updates after that event.
"""
from collections import OrderedDict
import copy
from base_evm import encode
from base_protocol import keccak,words,dynamic_fields,sha
from domain_pipeline import definition_hash
from permissionless_index import digest
from policy import canonical,require,strict_json

EVENT=keccak(b'Updated(uint256,bytes32,bytes32,uint256,bytes)')


class PublicIssuerViews:
    def __init__(self,rpc,contract,runtime_hash,updater,definition,deployment_block,*,index_contract):
        for v in (runtime_hash,'0x'+definition):digest(v)
        for v in (contract,updater,index_contract):
            require(type(v) is str and len(v)==42 and v==v.lower() and v.startswith('0x')
                and int(v,16)>0,'public-issuer-address')
        require(type(deployment_block) is int and 0<=deployment_block<2**53,'public-issuer-deployment')
        self.rpc,self.contract,self.runtime_hash,self.updater,self.definition=rpc,contract,runtime_hash,updater,definition
        self.deployment=deployment_block;self.cache=OrderedDict()
        self.index_contract=index_contract

    def _call(self,signature,block):
        return self.rpc.call('eth_call',{'to':self.contract,'data':encode(signature)},hex(block))

    def _head(self,block):
        fields=words(self._call('head()',block));require(len(fields)==5,'public-issuer-head')
        revision,_,registry,sequence,initialized=fields
        require(int.from_bytes(initialized,'big')==1,'public-issuer-uninitialized')
        r=int.from_bytes(revision,'big');s=int.from_bytes(sequence,'big')
        require(0<r<2**53 and 0<=s<2**53,'public-issuer-head')
        return r,'0x'+registry.hex(),s

    def _pins(self,block):
        require(self.rpc.call('eth_chainId')=='0x14a34','public-issuer-chain')
        code=self.rpc.call('eth_getCode',self.contract,hex(block))
        require(type(code) is str and code.startswith('0x') and len(code)<=131074
            and keccak(bytes.fromhex(code[2:]))==self.runtime_hash,'public-issuer-code')
        require(self._call('definition()',block)=='0x'+self.definition
            and int(self._call('updater()',block),16)==int(self.updater,16)
            and self.rpc.call('eth_getCode',self.updater,hex(block))=='0x','public-issuer-fixed-authority')

    def _event(self,log):
        require(type(log) is dict and log.get('address','').lower()==self.contract
            and type(log.get('topics')) is list and len(log['topics'])==2 and log['topics'][0]==EVENT
            and not log.get('removed',False),'public-issuer-event')
        block=self.rpc.call('eth_getBlockByNumber',log['blockNumber'],False)
        receipt=self.rpc.call('eth_getTransactionReceipt',log['transactionHash'])
        require(type(block) is dict and block['hash']==log['blockHash'] and type(receipt) is dict
            and receipt['status']=='0x1' and receipt['blockHash']==block['hash']
            and receipt['transactionHash']==log['transactionHash'] and receipt['blockNumber']==log['blockNumber']
            and receipt['to'].lower()==self.contract and receipt['from'].lower()==self.updater
            and log in receipt['logs'],'public-issuer-inclusion')
        data=log['data'];fields=words(data)
        raw=dynamic_fields(data,(3,))[0]
        require(0<len(raw)<=16384,'public-issuer-size')
        value=strict_json(raw,max_bytes=16384)
        require(set(value)=={'public','definition_hash','sequence'} and canonical(value)==raw and value.get('definition_hash')==self.definition
            and definition_hash(value['public'])==self.definition
            and type(value.get('sequence')) is int and value['sequence']==int.from_bytes(fields[2],'big')
            and sha(raw)=='0x'+fields[1].hex(),'public-issuer-public-view')
        return int(log['topics'][1],16),sha(raw),value

    def _logs(self,block,revision=None):
        topics=[EVENT]
        if revision is not None:topics.append('0x'+revision.to_bytes(32,'big').hex())
        result=self.rpc.call('eth_getLogs',{'address':self.contract,'fromBlock':hex(block),'toBlock':hex(block),'topics':topics})
        require(type(result) is list and len(result)<=64,'public-issuer-log-limit')
        return result

    def _view(self,block):
        r,h,s=self._head(block)
        key=(h,s)
        if key in self.cache:self.cache.move_to_end(key);return copy.deepcopy(self.cache[key])
        low=self.deployment;high=block
        # Find the first block whose end-state reaches this exact revision.
        for _ in range(53):
            if low>=high:break
            middle=(low+high)//2
            data=self._call('head()',middle)
            if data=='0x':
                # A genesis-bounded lookup can cross blocks before deployment.
                # Empty output is zero history only if no contract existed;
                # a deployed contract with a malformed head must still reject.
                require(self.rpc.call('eth_getCode',self.contract,hex(middle))=='0x','public-issuer-head')
                revision=0
            else:
                fields=words(data);require(len(fields)==5,'public-issuer-head')
                revision=int.from_bytes(fields[0],'big')
            if revision>=r:high=middle
            else:low=middle+1
        require(low==high,'public-issuer-search-limit')
        logs=self._logs(low,r);require(len(logs)==1,'public-issuer-event-missing')
        revision,digest_,value=self._event(logs[0])
        require(revision==r and digest_==h and value['sequence']==s,'public-issuer-head-binding')
        self.cache[key]=copy.deepcopy(value)
        while len(self.cache)>128:self.cache.popitem(last=False)
        return value

    def at(self,record):
        block=record['block_number'];require(type(block) is int and self.deployment<=block<2**53,'public-issuer-time')
        self._pins(block)
        canonical_block=self.rpc.call('eth_getBlockByNumber',hex(block),False)
        require(canonical_block['hash']==record['block_hash'],'public-issuer-anchor')
        receipt=self.rpc.call('eth_getTransactionReceipt',record['transaction_hash'])
        require(type(receipt) is dict and receipt['blockHash']==record['block_hash'] and receipt['status']=='0x1'
            and receipt['transactionHash']==record['transaction_hash'] and int(receipt['blockNumber'],16)==block,
            'public-issuer-index-receipt')
        index_topic=keccak(b'Indexed(bytes32,uint64,uint64)')
        indices=[log for log in receipt['logs'] if log.get('address','').lower()==self.index_contract
            and log.get('topics',[None])[:2]==[index_topic,record['bundle_hash']]]
        require(len(indices)==1,'public-issuer-index-event')
        require(indices[0]['blockHash']==record['block_hash'] and indices[0]['transactionHash']==record['transaction_hash']
            and int(indices[0]['blockNumber'],16)==block and not indices[0].get('removed',False),'public-issuer-index-event')
        before=int(indices[0]['logIndex'],16)
        logs=[log for log in self._logs(block) if int(log['logIndex'],16)<before]
        if logs:
            _,_,value=self._event(max(logs,key=lambda v:int(v['logIndex'],16)))
        else:
            require(block>self.deployment,'public-issuer-uninitialized');value=self._view(block-1)
        current=self.rpc.call('eth_getBlockByNumber',hex(block),False)
        require(current['hash']==record['block_hash'],'public-issuer-anchor-changed')
        return copy.deepcopy(value)

    def current(self,final):
        block=int(final['number'],16);self._pins(block);value=self._view(block)
        require(self.rpc.call('eth_getBlockByNumber',final['number'],False)['hash']==final['hash'],'public-issuer-anchor-changed')
        return copy.deepcopy(value)
