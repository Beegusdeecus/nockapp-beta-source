"""Public pinned refund policy and canonical payout verification; no signing key."""
import copy
import hashlib
import re
from base_evm import encode
from base_protocol import keccak
from policy import canonical,require
from ticket_offer_v1 import TicketOffer,hex_value,wei,configured_manifest_hash
from ticket_payment_v1 import _quantity

PROFILE='nockapp-ticket-refund-payout-v1'
SCOPE='nockapp-public-refund-vault-v1'
SELECTOR=keccak(b'refund(bytes32,bytes32,address,bytes)')[:10]
EVENT=keccak(b'Refunded(bytes32,address,bytes32,uint256)')

def validate_payout(value,offer,vault):
    require(type(value) is dict and set(value)=={'profile','parameters','pack_hash','state','payout_confirmed','payer',
        'amount_wei','payment_transaction','vault','transaction_hash','block_number','block_hash'}
        and value['profile']==PROFILE and value['parameters']==offer.hash and value['state']=='refunded'
        and value['payout_confirmed'] is True and value['vault']==vault['vault']
        and value['amount_wei']==offer.terms['pack_price_wei'],'refund-payout-shape')
    for key in ('pack_hash','payment_transaction','transaction_hash','block_hash'):hex_value(value[key],32)
    hex_value(value['payer'],20);_quantity(value['block_number'])
    return value


def scope(value,offer,expected_hash):
    require(isinstance(offer,TicketOffer),'refund-vault-offer');offer.check()
    return scope_manifest(value,offer.manifest,offer.hash,expected_hash)

def scope_manifest(value,manifest,offer_hash,expected_hash):
    require(configured_manifest_hash(manifest)==offer_hash and type(value) is dict and set(value)=={
        'profile','parameters','chain_id','vault','runtime_sha256','authority','pack_price_wei','max_refunds','principal_budget_wei','gas'},
        'refund-vault-scope')
    require(type(expected_hash) is str and re.fullmatch('[0-9a-f]{64}',expected_hash)
        and hashlib.sha256(canonical(value)).hexdigest()==expected_hash,'refund-vault-pin')
    require(value['profile']==SCOPE and value['parameters']==offer_hash and value['chain_id']==84532
        and type(value['chain_id']) is int and value['pack_price_wei']==manifest['terms']['pack_price_wei'], 'refund-vault-scope')
    require(type(value['runtime_sha256']) is str,'refund-vault-pin')
    hex_value(value['vault'],20);hex_value(value['authority'],20);hex_value('0x'+value['runtime_sha256'],32)
    require(type(value['max_refunds']) is int and 1<=value['max_refunds']<=4096
        and type(value['gas']) is int and 21000<=value['gas']<=200000
        and wei(value['principal_budget_wei'])==wei(value['pack_price_wei'])*value['max_refunds'], 'refund-vault-limits')
    return copy.deepcopy(value)


class RefundVaultReader:
    """Public canonical payout evidence; configured RPC/finality, not light client."""
    def __init__(self,rpc,offer,vault,expected_hash):self.rpc,self.offer,self.vault=rpc,offer,scope(vault,offer,expected_hash)

    def _call(self,signature,*args,tag):
        return self.rpc.call('eth_call',{'to':self.vault['vault'],'data':encode(signature,*args)},tag)

    def check(self):
        require(self.rpc.call('eth_chainId')=='0x14a34','refund-chain')
        final=self.rpc.call('eth_getBlockByNumber','finalized',False)
        require(type(final) is dict,'refund-finality');_quantity(final['number']);hex_value(final['hash'],32)
        raw=self.rpc.call('eth_getCode',self.vault['vault'],final['number'])
        require(type(raw) is str and re.fullmatch('0x(?:[0-9a-f]{2}){1,16384}',raw)
            and hashlib.sha256(bytes.fromhex(raw[2:])).hexdigest()==self.vault['runtime_sha256'],'refund-vault-code')
        fields={'REFUND_VERSION()':1,'parameters()':int(self.offer.hash,16),'purchaseContract()':int(self.offer.manifest['purchase_contract'],16),
            'authority()':int(self.vault['authority'],16),'packPrice()':int(self.vault['pack_price_wei']),
            'maxRefunds()':self.vault['max_refunds'],'principalBudget()':int(self.vault['principal_budget_wei'])}
        for signature,expected in fields.items():
            require(self._call(signature,tag=final['number'])=='0x'+expected.to_bytes(32,'big').hex(),'refund-vault-terms')
        self.finish(final);return final

    def finish(self,anchor):
        current=self.rpc.call('eth_getBlockByNumber',anchor['number'],False)
        require(type(current) is dict and current.get('number')==anchor['number'] and current.get('hash')==anchor['hash'],'refund-finality-changed')

    def payout(self,pack_hash,payment_hash,payer):
        hex_value(pack_hash,32);hex_value(payment_hash,32);hex_value(payer,20);final=self.check()
        raw=self._call('refunds(bytes32)',pack_hash,tag=final['number'])
        require(type(raw) is str and re.fullmatch('0x[0-9a-f]{192}',raw),'refund-vault-record')
        words=[int(raw[i:i+64],16) for i in (2,66,130)]
        if not words[2]:
            require(words==[0,0,0],'refund-vault-record');self.finish(final);return None
        require(words[0]==int(payer,16) and words[1]==int(payment_hash,16) and 0<words[2]<=_quantity(final['number']), 'refund-vault-record')
        number=hex(words[2]);block=self.rpc.call('eth_getBlockByNumber',number,False)
        require(type(block) is dict and block.get('number')==number,'refund-payout-block');hex_value(block['hash'],32)
        logs=self.rpc.call('eth_getLogs',{'address':self.vault['vault'],'fromBlock':number,'toBlock':number,'topics':[EVENT,pack_hash]})
        require(type(logs) is list and len(logs)==1,'refund-payout-event');log=logs[0]
        require(log.get('address')==self.vault['vault'] and log.get('topics')==[EVENT,pack_hash,'0x'+'0'*24+payer[2:],payment_hash]
            and log.get('data')=='0x'+int(self.vault['pack_price_wei']).to_bytes(32,'big').hex()
            and log.get('blockNumber')==number and log.get('blockHash')==block['hash'] and log.get('removed') is False, 'refund-payout-event')
        transaction_hash=hex_value(log.get('transactionHash'),32)
        receipt=self.rpc.call('eth_getTransactionReceipt',transaction_hash)
        tx=self.rpc.call('eth_getTransactionByHash',transaction_hash)
        require(type(receipt) is dict and type(tx) is dict and receipt.get('status')=='0x1'
            and receipt.get('transactionHash')==tx.get('hash')==transaction_hash
            and receipt.get('blockNumber')==tx.get('blockNumber')==number
            and receipt.get('blockHash')==tx.get('blockHash')==block['hash']
            and receipt.get('to')==tx.get('to')==self.vault['vault'] and tx.get('from')==self.vault['authority']
            and tx.get('value')=='0x0' and transaction_hash in block.get('transactions',[])
            and type(receipt.get('logs')) is list and len(receipt['logs'])<=128 and log in receipt['logs'],'refund-payout-inclusion')
        self.finish({'number':number,'hash':block['hash']});self.finish(final)
        return {'profile':PROFILE,'parameters':self.offer.hash,'pack_hash':pack_hash,'state':'refunded','payout_confirmed':True,
            'payer':payer,'amount_wei':self.vault['pack_price_wei'],'payment_transaction':payment_hash,
            'vault':self.vault['vault'],'transaction_hash':transaction_hash,'block_number':number,'block_hash':block['hash']}

