"""Unconfigured v2 receipt verifier; no broadcast, key export or policy writes."""
from base_protocol import keccak
from policy import require
from ticket_payment_v1 import FinalizedTicketPayment,EVENT,_quantity
from ticket_offer_v1 import hex_value
from .offer import BatchOffer,PACKS,VERSION,terms_hash

class FinalizedBatchPayment(FinalizedTicketPayment):
    def __init__(self,rpc,offer):
        require(isinstance(offer,BatchOffer),'batch-explicit-offer-required')
        super().__init__(rpc,offer)
    def preflight(self):
        offer=self.offer;offer.check();t=offer.terms
        require(_quantity(self.rpc.call('eth_chainId'))==84532,'batch-payment-chain')
        final=self.rpc.call('eth_getBlockByNumber','finalized',False)
        require(type(final) is dict,'batch-payment-finality');_quantity(final['number']);hex_value(final['hash'],32)
        code=self.rpc.call('eth_getCode',offer.manifest['purchase_contract'],final['number'])
        require(type(code) is str and code.startswith('0x') and len(code)<=32770,'batch-payment-code')
        try:runtime=bytes.fromhex(code[2:])
        except ValueError:require(False,'batch-payment-code')
        require(keccak(runtime)==offer.manifest['purchase_runtime_keccak'],'batch-payment-code')
        require(int(self._call('PURCHASE_VERSION()',tag=final['number']),16)==VERSION
            and int(self._call('BATCH_PACKS()',tag=final['number']),16)==PACKS
            and self._call('termsHash()',tag=final['number'])==terms_hash(t)
            and int(self._call('recipient()',tag=final['number']),16)==int(t['payment_recipient'],16)
            and int(self._call('packPrice()',tag=final['number']),16)==int(t['pack_price_wei'])
            and int(self._call('purchaseBefore()',tag=final['number']),16)==t['purchase_before'],'batch-payment-contract')
        self.finish({'block_number':final['number'],'block_hash':final['hash']})
        return final
    def verify_batch(self,packs,transaction_hash,payer):
        self.offer.transaction(packs);hex_value(payer,20)
        payment,observed=self._verified(packs[0],transaction_hash)
        require(payer==observed,'batch-payment-payer')
        receipt=self.rpc.call('eth_getTransactionReceipt',transaction_hash)
        require(type(receipt) is dict and receipt.get('status')=='0x1'
            and receipt.get('transactionHash')==transaction_hash
            and receipt.get('blockNumber')==payment['block_number']
            and receipt.get('blockHash')==payment['block_hash']
            and type(receipt.get('logs')) is list and len(receipt['logs'])<=128,'batch-payment-receipt')
        expected=set(packs);seen=set()
        for log in receipt['logs']:
            require(type(log) is dict,'batch-payment-log')
            topics=log.get('topics')
            if log.get('address','').lower()!=self.offer.manifest['purchase_contract'] or type(topics) is not list or topics[:1]!=[EVENT]:continue
            if len(topics)<2 or topics[1] not in expected:continue
            require(topics[1] not in seen and topics==[EVENT,topics[1],'0x'+'0'*24+payer[2:]]
                and log.get('data')=='0x'+int(self.offer.terms['pack_price_wei']).to_bytes(32,'big').hex()
                and log.get('transactionHash')==transaction_hash and log.get('blockHash')==payment['block_hash']
                and log.get('blockNumber')==payment['block_number'] and not log.get('removed',False),'batch-payment-event')
            seen.add(topics[1])
        require(seen==expected,'batch-payment-incomplete')
        self.finish(payment)
        return {'parameters':self.offer.hash,'transaction_hash':transaction_hash,'payer':payer,
            'pack_hashes':list(packs),'block_number':payment['block_number'],'block_hash':payment['block_hash']}
