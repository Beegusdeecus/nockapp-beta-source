"""Public commitment-log transport. Never treats indexing as proof validation.

The configured RPC is a trust dependency, not a light client. Production pins
the deployed runtime hash. No signer, issuer, receipt or private key is needed
to construct a submission or independently resolve a finalized commitment.
"""
import threading
from base_evm import encode
from base_protocol import keccak, sha, words
from policy import canonical, hex_string, require

EVENT = b'Indexed(bytes32,uint64,uint64)'
ZERO = '0x' + '00' * 32


def digest(value):
    require(type(value) is str and value.startswith('0x'), 'index-hash')
    hex_string(value[2:], 64)
    require(value == value.lower() and value != ZERO, 'index-hash')
    return value


def submission_data(bundle_hash):
    """Public bytes only; any replacement relayer may pay for this call."""
    return encode('submit(bytes32)', digest(bundle_hash))


class PublicIndexReader:
    def __init__(self, rpc, contract, application, *, chain_id=84532,
                 runtime_hash=None, laboratory=False, checkpoint_store=None):
        require(type(contract) is str and contract.startswith('0x'), 'index-contract')
        hex_string(contract[2:], 40)
        require(contract == contract.lower() and int(contract, 16) != 0, 'index-contract')
        digest(application)
        require(chain_id == 84532 or laboratory is True and chain_id == 31337, 'index-chain')
        require(laboratory is True or runtime_hash is not None, 'index-code-pin-required')
        if runtime_hash is not None: digest(runtime_hash)
        self.rpc, self.contract, self.application = rpc, contract, application
        self.chain_id, self.runtime_hash = chain_id, runtime_hash
        self.checkpoints = checkpoint_store
        self.scope = sha(canonical({'profile': 'nockapp-public-index-v1', 'chain_id': chain_id,
            'contract': contract, 'application': application, 'runtime_hash': runtime_hash}))
        self.checkpoint = checkpoint_store.get_checkpoint(self.scope) if checkpoint_store is not None else None
        self._checkpoint_lock = threading.RLock()
        self._selectors = {}
        self._event_topic = None
        self._code_cache = None

    def _call(self, signature, *args, tag):
        # Only three fixed PUBLIC no-argument selectors. Never memoize generic
        # encoder inputs, signing data or caller-provided argument collections.
        if not args and signature in ('INDEX_VERSION()','application()','nextPostNumber()'):
            data=self._selectors.get(signature)
            if data is None:
                data=encode(signature);self._selectors[signature]=data
        else:data=encode(signature,*args)
        return self.rpc.call('eth_call', {'to': self.contract, 'data': data}, tag)

    def _checkpoint_snapshots(self):
        # Called under the local lock. Shared hints remain untrusted until the
        # caller checks them against its own canonical chain observations.
        result=[]
        if self.checkpoint is not None:result.append(dict(self.checkpoint))
        if self.checkpoints is not None:
            shared=self.checkpoints.get_checkpoint(self.scope)
            if shared is not None and shared not in result:result.append(dict(shared))
        return result

    def _check_checkpoint(self,checkpoint):
        prior=self.rpc.call('eth_getBlockByNumber',checkpoint['number'],False)
        require(prior is not None and prior['hash']==checkpoint['hash'],'index-finality-violation')

    @staticmethod
    def _newer_checkpoint(a,b):
        if a is None:return dict(b)
        x,y=int(a['number'],16),int(b['number'],16)
        if x==y:require(a['hash']==b['hash'],'index-finality-violation')
        return dict(b if y>x else a)

    def anchor(self):
        # Recovery and public requests may share this reader. Compare this RPC
        # observation against its starting checkpoint, not a newer observation
        # installed by another thread after the finalized-block request began.
        with self._checkpoint_lock:
            checkpoints = self._checkpoint_snapshots()
        require(int(self.rpc.call('eth_chainId'), 16) == self.chain_id, 'index-chain')
        final = self.rpc.call('eth_getBlockByNumber', 'finalized', False)
        require(final is not None, 'index-finality-unavailable')
        for checkpoint in checkpoints:
            self._check_checkpoint(checkpoint)
            require(int(final['number'],16)>=int(checkpoint['number'],16),'index-finality-violation')
        if self.runtime_hash is not None:
            code = self.rpc.call('eth_getCode', self.contract, final['number'])
            raw=bytes.fromhex(code.removeprefix('0x'))
            cached=self._code_cache
            observed=cached[1] if cached is not None and cached[0]==raw else keccak(raw)
            require(observed == self.runtime_hash, 'index-code-pin')
            self._code_cache=(raw,observed)
        require(int(self._call('INDEX_VERSION()', tag=final['number']), 16) == 1
            and self._call('application()', tag=final['number']) == self.application, 'index-application')
        return final

    def finish(self, final):
        with self._checkpoint_lock:
            current = self.rpc.call('eth_getBlockByNumber', final['number'], False)
            require(current is not None and current['hash'] == final['hash'], 'index-finalized-reorg')
            candidate={'number':final['number'],'hash':final['hash']}
            for checkpoint in self._checkpoint_snapshots():
                self._check_checkpoint(checkpoint)
                candidate=self._newer_checkpoint(candidate,checkpoint)
            if self.checkpoints is not None:
                advance=getattr(self.checkpoints,'advance_checkpoint',None)
                if advance is not None:
                    shared=advance(self.scope,dict(candidate))
                    if shared is not None:
                        self._check_checkpoint(shared)
                        require(int(shared['number'],16)>=int(candidate['number'],16),'index-checkpoint-store-regression')
                        candidate=self._newer_checkpoint(candidate,shared)
                elif candidate!=self.checkpoint:
                    # Compatibility with older optional stores; the shared
                    # atomic update guarantee applies to advance_checkpoint.
                    self.checkpoints.put_checkpoint(self.scope,dict(candidate))
            self.checkpoint=candidate

    def _record(self, number, final):
        require(type(number) is int and 0 < number < 2**53, 'index-number')
        bundle_hash = self._call('bundleHashes(uint64)', number, tag=final['number'])
        digest(bundle_hash)
        record = words(self._call('records(bytes32)', bundle_hash, tag=final['number']))
        require(len(record) == 3, 'index-record')
        actual, height, when = [int.from_bytes(w, 'big') for w in record]
        require(actual == number and 0 < height <= int(final['number'], 16), 'index-record')
        topic=self._event_topic
        if topic is None:topic=keccak(EVENT);self._event_topic=topic
        logs = self.rpc.call('eth_getLogs', {'address': self.contract, 'fromBlock': hex(height),
            'toBlock': hex(height), 'topics': [topic, bundle_hash, '0x' + number.to_bytes(32, 'big').hex()]})
        require(type(logs) is list and len(logs) == 1, 'index-event-missing')
        log = logs[0]
        require(log['address'].lower() == self.contract and not log.get('removed', False)
            and log['topics'] == [topic, bundle_hash, '0x' + number.to_bytes(32, 'big').hex()]
            and log['data'] == '0x' + when.to_bytes(32, 'big').hex()
            and int(log['blockNumber'], 16) == height, 'index-event')
        block = self.rpc.call('eth_getBlockByNumber', hex(height), False)
        receipt = self.rpc.call('eth_getTransactionReceipt', log['transactionHash'])
        require(block is not None and log['blockHash'] == block['hash']
            and int(block['timestamp'], 16) == when and receipt is not None
            and receipt['status'] == '0x1' and receipt['blockHash'] == block['hash']
            and int(receipt['blockNumber'], 16) == height
            and receipt['transactionHash'] == log['transactionHash']
            and log in receipt['logs'], 'index-inclusion')
        # A smart wallet/relayer may CALL the log internally. The authenticated
        # event emitter above is the index; the outer transaction recipient
        # need not be. No payer or outer sender establishes post authorship.
        return {'post_number': str(number), 'bundle_hash': bundle_hash, 'indexed_at': when,
            'block_number': height, 'block_hash': block['hash'], 'transaction_hash': log['transactionHash'],
            'canonical_indexed': True, 'proofs_verified': False}

    def records(self, numbers):
        require(type(numbers) is list and 1 <= len(numbers) <= 8
            and all(type(n) is int and 0 < n < 2**53 for n in numbers)
            and len(set(numbers)) == len(numbers), 'index-page-limit')
        final = self.anchor()
        rows = [self._record(number, final) for number in numbers]
        self.finish(final)
        return rows

    def number_for_hash(self, bundle_hash):
        row=self.record_for_hash(bundle_hash)
        return None if row is None else int(row['post_number'])

    def record_for_hash(self, bundle_hash):
        """Return one fully checked record, avoiding a second inclusion fetch."""
        digest(bundle_hash)
        final = self.anchor()
        record = words(self._call('records(bytes32)', bundle_hash, tag=final['number']))
        require(len(record) == 3, 'index-record')
        number = int.from_bytes(record[0], 'big')
        require(0 <= number < 2**53, 'index-record')
        row=None
        if number:
            row=self._record(number, final)
            require(row['bundle_hash'] == bundle_hash, 'index-record')
        else: require(not any(any(w) for w in record), 'index-record')
        self.finish(final)
        return row
