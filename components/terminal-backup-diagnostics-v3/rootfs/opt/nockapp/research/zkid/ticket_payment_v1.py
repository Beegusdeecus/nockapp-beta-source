"""Read-only finalized payment checks against the pinned receipt contract.

Uses the configured RPC's canonical/finalized views, not a consensus light
client. Neither a user-supplied receipt nor a remote 'paid' flag is accepted.
"""
from base_evm import encode
from base_protocol import keccak
from policy import require
from ticket_offer_v1 import TicketOffer, hex_value, terms_hash

EVENT=keccak(b'PackPaid(bytes32,address,uint256)')


def _quantity(value):
    require(type(value) is str and value.startswith('0x') and 1<=len(value[2:])<=64,'ticket-payment-quantity')
    try:number=int(value,16)
    except ValueError:require(False,'ticket-payment-quantity')
    require(hex(number)==value,'ticket-payment-quantity')
    return number


class FinalizedTicketPayment:
    def __init__(self,rpc,offer):
        require(isinstance(offer,TicketOffer),'ticket-payment-offer')
        self.rpc,self.offer=rpc,offer

    def _call(self,signature,*args,tag):
        return self.rpc.call('eth_call',{'to':self.offer.manifest['purchase_contract'],'data':encode(signature,*args)},tag)

    def preflight(self):
        """Check pinned immutable contract before any buyer wallet prompt."""
        offer=self.offer;t=offer.terms;contract=offer.manifest['purchase_contract']
        offer.check()
        require(_quantity(self.rpc.call('eth_chainId'))==t['chain_id'],'ticket-payment-chain')
        final=self.rpc.call('eth_getBlockByNumber','finalized',False)
        require(type(final) is dict,'ticket-payment-finality')
        _quantity(final['number']);hex_value(final['hash'],32)
        code=self.rpc.call('eth_getCode',contract,final['number'])
        require(type(code) is str and code.startswith('0x') and len(code)<=32770,'ticket-payment-code')
        try:runtime=bytes.fromhex(code[2:])
        except ValueError:require(False,'ticket-payment-code')
        require(keccak(runtime)==offer.manifest['purchase_runtime_keccak'],'ticket-payment-code')
        require(int(self._call('PURCHASE_VERSION()',tag=final['number']),16)==1
            and self._call('termsHash()',tag=final['number'])==terms_hash(t)
            and int(self._call('recipient()',tag=final['number']),16)==int(t['payment_recipient'],16)
            and int(self._call('packPrice()',tag=final['number']),16)==int(t['pack_price_wei'])
            and int(self._call('purchaseBefore()',tag=final['number']),16)==t['purchase_before'],'ticket-payment-contract')
        current=self.rpc.call('eth_getBlockByNumber',final['number'],False)
        require(type(current) is dict and current.get('hash')==final['hash'],'ticket-payment-finality-changed')
        return final

    def verify(self,pack,transaction_hash):
        return self.verify_hash(self.offer.pack_hash(pack),transaction_hash)

    def verify_hash(self,pack_hash,transaction_hash):
        """Check an already-committed pack hash without exporting blind inputs."""
        return self._verified(pack_hash,transaction_hash)[0]

    def canonical_payer(self,payment):
        """Reverify the exact payment; a relayer's outer sender is not its payer.

        The fixed non-proxy purchase runtime emits msg.sender only after the
        exact price is paid. This also covers a delegated EOA executing buy().
        Keep the persisted five-field payment/decision encoding unchanged.
        """
        verified,payer=self._verified(payment['pack_hash'],payment['transaction_hash'])
        require(verified==payment,'ticket-payment-changed')
        return payer

    def _verified(self,pack_hash,transaction_hash):
        hex_value(pack_hash,32)
        hex_value(transaction_hash,32)
        offer=self.offer;t=offer.terms;contract=offer.manifest['purchase_contract']
        final=self.preflight();final_height=_quantity(final['number'])
        # ABI words have leading zeros; do not parse them as RPC quantities.
        require(int(self._call('paid(bytes32)',pack_hash,tag=final['number']),16)==1,'ticket-payment-not-paid')
        receipt=self.rpc.call('eth_getTransactionReceipt',transaction_hash)
        tx=self.rpc.call('eth_getTransactionByHash',transaction_hash)
        require(type(receipt) is dict and type(tx) is dict,'ticket-payment-unavailable')
        require(receipt.get('status')=='0x1' and receipt.get('transactionHash')==transaction_hash
            and tx.get('hash')==transaction_hash
            and _quantity(tx.get('chainId'))==t['chain_id'],'ticket-payment-transaction')
        height=_quantity(receipt['blockNumber']);block_hash=hex_value(receipt['blockHash'],32)
        require(height<=final_height and tx.get('blockNumber')==receipt['blockNumber']
            and tx.get('blockHash')==block_hash,'ticket-payment-unfinalized')
        block=self.rpc.call('eth_getBlockByNumber',receipt['blockNumber'],False)
        require(type(block) is dict and block.get('hash')==block_hash and block.get('number')==receipt['blockNumber']
            and transaction_hash in block.get('transactions',[])
            and _quantity(block['timestamp'])<t['purchase_before'],'ticket-payment-inclusion')
        logs=receipt.get('logs');require(type(logs) is list and len(logs)<=128,'ticket-payment-logs')
        matching=[v for v in logs if type(v) is dict and v.get('address','').lower()==contract
            and type(v.get('topics')) is list and v['topics'][0:2]==[EVENT,pack_hash]]
        require(len(matching)==1,'ticket-payment-event')
        log=matching[0]
        topics=log['topics']
        require(len(topics)==3 and type(topics[2]) is str and len(topics[2])==66
            and topics[2].startswith('0x'+'0'*24),'ticket-payment-event')
        payer=hex_value('0x'+topics[2][26:],20)
        require(log.get('topics')==[EVENT,pack_hash,'0x'+'0'*24+payer[2:]]
            and log.get('data')=='0x'+int(t['pack_price_wei']).to_bytes(32,'big').hex()
            and log.get('transactionHash')==transaction_hash and log.get('blockHash')==block_hash
            and log.get('blockNumber')==receipt['blockNumber'] and not log.get('removed',False),'ticket-payment-event')
        result={'parameters':offer.hash,'pack_hash':pack_hash,'transaction_hash':transaction_hash,
            'block_number':receipt['blockNumber'],'block_hash':block_hash}
        self.finish(result)
        current=self.rpc.call('eth_getBlockByNumber',final['number'],False)
        require(type(current) is dict and current.get('hash')==final['hash'],'ticket-payment-finality-changed')
        return result,payer

    def finish(self,payment):
        current=self.rpc.call('eth_getBlockByNumber',payment['block_number'],False)
        require(type(current) is dict and current.get('hash')==payment['block_hash'],'ticket-payment-finality-changed')
