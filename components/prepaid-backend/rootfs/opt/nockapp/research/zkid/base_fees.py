"""Pinned Base fee quotes and receipt accounting; not a future inclusion cap.

A type-2 transaction caps execution gas only. L1/operator quotes can change
before inclusion. Reservations and a stop on overruns bound admission, not an
unconditional burn maximum. Funding/exposure controls remain separately required.
"""
import copy
import hashlib
import time

from base_evm import encode
from policy import hex_string,require

ORACLE='0x420000000000000000000000000000000000000f'
L1_BLOCK='0x4200000000000000000000000000000000000015'
ZERO='0x'+'00'*20
FIELDS={'max_l1_fee','max_operator_fee','max_total_fee','total_budget','funded_budget','max_head_age',
    'oracle_proxy_sha256','oracle_implementation','oracle_implementation_sha256',
    'l1_block_proxy_sha256','l1_block_implementation','l1_block_implementation_sha256'}


def policy(value):
    require(type(value) is dict and set(value)==FIELDS,'transaction-total-fee-policy')
    for k in ('max_l1_fee','max_operator_fee','max_total_fee','total_budget','funded_budget'):
        require(type(value[k]) is int and 0<=value[k]<2**63,'transaction-total-fee-policy')
    require(0<value['max_total_fee']<=value['funded_budget']<=value['total_budget'] and type(value['max_head_age']) is int
        and 1<=value['max_head_age']<=60,'transaction-total-fee-policy')
    for k in ('oracle_proxy_sha256','oracle_implementation_sha256','l1_block_proxy_sha256','l1_block_implementation_sha256'):
        hex_string(value[k],64);require(any(bytes.fromhex(value[k])),'transaction-total-fee-policy')
    addresses=[ORACLE,L1_BLOCK]
    for k in ('oracle_implementation','l1_block_implementation'):
        a=value[k];require(type(a) is str and a.startswith('0x') and a==a.lower(),'transaction-total-fee-policy')
        hex_string(a[2:],40);require(a!=ZERO,'transaction-total-fee-policy');addresses.append(a)
    require(len(set(addresses))==4,'transaction-total-fee-policy')
    return copy.deepcopy(value)


def quantity(value):
    require(type(value) is str and value.startswith('0x') and 2<len(value)<=66
        and all(c in '0123456789abcdef' for c in value[2:]) and (value=='0x0' or value[2]!='0'),'transaction-fee-response')
    return int(value,16)


class BaseFees:
    def __init__(self,rpc,approved,*,chain_id=84532):
        require(chain_id in (84532,31337),'transaction-fee-chain')
        self.rpc,self.policy,self.chain=rpc,policy(approved),chain_id

    def _uint(self,address,signature,*args,tag):
        raw=self.rpc.call('eth_call',{'to':address,'from':ZERO,'data':encode(signature,*args)},tag)
        require(type(raw) is str and raw.startswith('0x'),'transaction-fee-response');hex_string(raw[2:],64)
        return int(raw,16)

    def _pins(self,block):
        require(quantity(self.rpc.call('eth_chainId'))==self.chain,'transaction-fee-chain')
        tag=block['number'];quantity(tag);hex_string(block['hash'][2:],64)
        for address,prefix in ((ORACLE,'oracle'),(L1_BLOCK,'l1_block')):
            for target,key in ((address,prefix+'_proxy_sha256'),(self.policy[prefix+'_implementation'],prefix+'_implementation_sha256')):
                raw=self.rpc.call('eth_getCode',target,tag)
                require(type(raw) is str and raw.startswith('0x') and len(raw)<=131074,'transaction-fee-code')
                hex_string(raw[2:],len(raw)-2)
                require(len(raw)>2 and hashlib.sha256(bytes.fromhex(raw[2:])).hexdigest()==self.policy[key],'transaction-fee-code')
            implementation=self._uint(address,'implementation()',tag=tag)
            require(implementation==int(self.policy[prefix+'_implementation'],16),'transaction-fee-implementation')
        require(self._uint(ORACLE,'isJovian()',tag=tag)==1,'transaction-fee-fork')

    def _finish(self,block):
        same=self.rpc.call('eth_getBlockByNumber',block['number'],False)
        require(type(same) is dict and same.get('hash')==block['hash'],'transaction-fee-reorg')

    def quote(self,unsigned,gas,execution_cap):
        require(type(unsigned) is bytes and 0<len(unsigned)<=33000 and type(gas) is int and gas>=21000
            and type(execution_cap) is int and execution_cap>0,'transaction-fee-request')
        block=self.rpc.call('eth_getBlockByNumber','latest',False)
        require(type(block) is dict,'transaction-fee-head')
        stamp=quantity(block['timestamp']);now=int(time.time())
        require(now-self.policy['max_head_age']<=stamp<=now+5,'transaction-fee-head-stale')
        self._pins(block);tag=block['number']
        l1=self._uint(ORACLE,'getL1FeeUpperBound(uint256)',len(unsigned),tag=tag)
        operator=self._uint(ORACLE,'getOperatorFee(uint256)',gas,tag=tag)
        self._finish(block)
        require(l1<=self.policy['max_l1_fee'] and operator<=self.policy['max_operator_fee'],'transaction-extra-fee-cap')
        reserve=execution_cap+self.policy['max_l1_fee']+self.policy['max_operator_fee']
        require(reserve<=self.policy['max_total_fee'],'transaction-total-fee-cap')
        return {'block_number':tag,'block_hash':block['hash'],'unsigned_bytes':len(unsigned),
            'l1_quote_wei':l1,'operator_quote_wei':operator,'total_reserved_wei':reserve}

    def actual(self,receipt,block,gas_limit,max_fee):
        require(receipt.get('blockHash')==block.get('hash') and receipt.get('blockNumber')==block.get('number'),
            'transaction-fee-receipt')
        used=quantity(receipt.get('gasUsed'));price=quantity(receipt.get('effectiveGasPrice'))
        require(21000<=used<=gas_limit and price<=max_fee,'transaction-fee-receipt')
        # Require the separate data fee; absence is NOT zero. The pinned oracle
        # at the receipt's historical block supplies its actual operator formula.
        l1=quantity(receipt.get('l1Fee'));self._pins(block)
        operator=self._uint(ORACLE,'getOperatorFee(uint256)',used,tag=block['number']);self._finish(block)
        execution=used*price;total=execution+l1+operator
        return {'execution_wei':execution,'l1_wei':l1,'operator_wei':operator,'total_wei':total}
