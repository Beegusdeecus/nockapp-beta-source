"""Real local EVM tests of ownerless index/fixed issuer authority. No Base write."""
import hashlib
import unittest
from base_evm import local_chain,encode
from permissionless_contracts import build as compile_contracts
from base_protocol import read,words
from policy import canonical
from permissionless_index import PublicIndexReader,submission_data
from test_base_discussions import immediate_finality
from base_protocol import keccak

class PermissionlessIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.compiled=compile_contracts()
    def setUp(self):
        self.chain=local_chain(chain_id=84532);self.rpc=self.chain.__enter__();self.addCleanup(self.chain.__exit__,None,None,None)
        self.finality=immediate_finality(self.rpc);self.finality.start();self.addCleanup(self.finality.stop)
        self.accounts=self.rpc.call('eth_accounts');self.app='0x'+'ab'*32
        self.index=self.deploy('PublicCommitmentIndex','f(bytes32)',self.app)
    def deploy(self,name,constructor,*args):
        code=self.compiled['contracts/'+name+'.sol'][name]['evm']['bytecode']['object']
        receipt=self.rpc.tx(self.accounts[0],'0x'+code+encode(constructor,*args)[10:]);self.assertEqual(receipt['status'],'0x1');return receipt['contractAddress']
    def call(self,contract,signature,*args):return read(self.rpc,contract,signature,*args)
    def tx(self,sender,contract,signature,*args):return self.rpc.tx(sender,encode(signature,*args),contract)
    def commit(self,sender,value):return self.tx(sender,self.index,'submit(bytes32)',value)
    def test_arbitrary_independent_senders_can_index_hashes_without_a_receipt_or_original_relayer(self):
        for n,sender in enumerate(self.accounts[1:4],1):
            h='0x'+hashlib.sha256(('synthetic record '+str(n)).encode()).hexdigest();receipt=self.commit(sender,h)
            self.assertEqual(receipt['status'],'0x1');self.assertEqual(int.from_bytes(words(self.call(self.index,'records(bytes32)',h))[0],'big'),n)
            record=words(self.call(self.index,'records(bytes32)',h));self.assertEqual(self.call(self.index,'bundleHashes(uint64)',n),h)
            self.assertEqual(int.from_bytes(record[1],'big'),int(receipt['blockNumber'],16));self.assertEqual(len(receipt['logs']),1)
        self.assertEqual(int(self.call(self.index,'nextPostNumber()'),16),4);self.assertEqual(self.call(self.index,'application()'),self.app)
    def test_exact_hash_copying_and_lost_reply_retries_keep_one_original_number(self):
        h='0x'+'12'*32;first=self.commit(self.accounts[1],h);before=self.call(self.index,'records(bytes32)',h)
        for sender in (self.accounts[2],self.accounts[3],self.accounts[1]):
            receipt=self.commit(sender,h);self.assertEqual(receipt['status'],'0x1');self.assertEqual(receipt['logs'],[])
            self.assertEqual(self.call(self.index,'records(bytes32)',h),before)
        self.assertEqual(int(self.call(self.index,'nextPostNumber()'),16),2)
        self.assertEqual(int.from_bytes(words(self.call(self.index,'records(bytes32)',h))[0],'big'),1);self.assertNotEqual(first['transactionHash'],receipt['transactionHash'])
    def test_garbage_and_claimed_uuid_metadata_cannot_squat_an_authentic_bundle_identifier(self):
        # The log deliberately accepts garbage hashes. Separate client verification
        # must reject their contents. The contract never interprets these UUIDs.
        uuid='11111111-1111-4111-8111-111111111111'
        garbage='0x'+hashlib.sha256(canonical({'id':uuid,'author':'unverified claim'})).hexdigest()
        authored='0x'+hashlib.sha256(canonical({'id':uuid,'synthetic_authorized_bytes':'different complete bytes'})).hexdigest()
        self.assertEqual(self.commit(self.accounts[1],garbage)['status'],'0x1')
        self.assertEqual(self.commit(self.accounts[2],authored)['status'],'0x1')
        self.assertEqual(int.from_bytes(words(self.call(self.index,'records(bytes32)',authored))[0],'big'),2)
        self.assertEqual(int.from_bytes(words(self.call(self.index,'records(bytes32)',garbage))[0],'big'),1)
    def test_index_abi_has_no_administrator_or_validation_mutator_and_direct_calls_cannot_pause_or_rewrite(self):
        contract=self.compiled['contracts/PublicCommitmentIndex.sol']['PublicCommitmentIndex']
        functions={a['name']:a for a in contract['abi'] if a['type']=='function'}
        self.assertEqual(set(functions),{'INDEX_VERSION','application','nextPostNumber','records','bundleHashes','submit'})
        self.assertEqual({name for name,a in functions.items() if a['stateMutability'] not in ('view','pure')},{'submit'})
        h='0x'+'23'*32;self.commit(self.accounts[1],h);before=self.call(self.index,'records(bytes32)',h)
        for sender in self.accounts[:2]:
            for signature,args in [('setPaused(bool)',('true',)),('setSigner(address)',(sender,)),('setOwner(address)',(sender,)),
                ('deleteRecord(uint256)',(1,)),('upgradeTo(address)',(sender,)),('setCommitment(uint256,bytes32)',(1,'0x'+'34'*32))]:
                self.assertEqual(self.tx(sender,self.index,signature,*args)['status'],'0x0')
        self.assertEqual(self.call(self.index,'records(bytes32)',h),before)
        self.assertEqual(self.commit(self.accounts[3],'0x'+'34'*32)['status'],'0x1')
    def test_zero_hash_rejects_without_allocating_number_and_unknown_number_stays_empty(self):
        self.assertEqual(self.commit(self.accounts[1],'0x'+'00'*32)['status'],'0x0')
        self.assertEqual(int(self.call(self.index,'nextPostNumber()'),16),1)
        self.assertEqual(self.call(self.index,'bundleHashes(uint64)',999),'0x'+'00'*32)
    def test_fixed_issuer_authority_has_no_replacement_or_admin_route(self):
        state=self.deploy('FixedIssuerState','f(address,bytes32)',self.accounts[1],'0x'+'56'*32)
        abi=self.compiled['contracts/FixedIssuerState.sol']['FixedIssuerState']['abi']
        self.assertEqual({a['name'] for a in abi if a['type']=='function' and a['stateMutability'] not in ('view','pure')},{'update','beginLease','updateLeased'})
        for sender in self.accounts[:3]:
            self.assertEqual(self.tx(sender,state,'setUpdater(address)',self.accounts[2])['status'],'0x0')
        self.assertEqual(self.call(state,'updater()')[-40:],self.accounts[1][2:])
    def test_fixed_issuer_cas_boot_lease_and_sequence_rules_fence_stale_writers(self):
        writer=self.accounts[1];state=self.deploy('FixedIssuerState','f(address,bytes32)',writer,'0x'+'56'*32)
        zero='0x'+'00'*32;one='0x'+'12'*32;two='0x'+'23'*32;three='0x'+'34'*32
        registry='0x'+canonical({'synthetic_registry':'initial protected account map'}).hex()
        changed='0x'+canonical({'synthetic_registry':'one permitted revision'}).hex()
        sig='beginLease(uint256,uint256,bytes32,bytes32,uint256,bytes)'
        self.assertEqual(self.tx(self.accounts[2],state,sig,0,0,zero,one,7,registry)['status'],'0x0')
        self.assertEqual(self.tx(writer,state,sig,0,0,zero,one,7,registry)['status'],'0x1')
        self.assertEqual(int(self.call(state,'bootEpoch()'),16),1)
        # Reusing boot epoch/revision or bypassing the lease fails.
        self.assertEqual(self.tx(writer,state,sig,0,0,zero,two,7,registry)['status'],'0x0')
        self.assertEqual(self.tx(writer,state,'update(uint256,bytes32,bytes32,uint256,bytes)',1,one,two,7,registry)['status'],'0x0')
        leased='updateLeased(uint256,uint256,bytes32,bytes32,uint256,bytes)'
        self.assertEqual(self.tx(writer,state,leased,1,1,one,two,7,registry)['status'],'0x1')
        self.assertEqual(self.tx(writer,state,leased,1,2,two,three,9,changed)['status'],'0x0')
        self.assertEqual(self.tx(writer,state,leased,1,2,two,three,8,changed)['status'],'0x1')
        # A new boot invalidates prior leases without replacing the fixed key.
        self.assertEqual(self.tx(writer,state,sig,1,3,three,'0x'+'45'*32,8,changed)['status'],'0x1')
        self.assertEqual(self.tx(writer,state,leased,1,4,'0x'+'45'*32,'0x'+'67'*32,8,changed)['status'],'0x0')
        self.assertEqual(int(self.call(state,'revision()'),16),4)

    def test_existing_reader_checks_runtime_inclusion_and_finality_without_claiming_proof_validity(self):
        h='0x'+'89'*32;receipt=self.rpc.tx(self.accounts[3],submission_data(h),self.index)
        self.assertEqual(receipt['status'],'0x1')
        pin=keccak(bytes.fromhex(self.rpc.call('eth_getCode',self.index,'latest')[2:]))
        reader=PublicIndexReader(self.rpc,self.index,self.app,runtime_hash=pin)
        self.assertEqual(reader.number_for_hash(h),1);row=reader.records([1])[0]
        self.assertTrue(row['canonical_indexed']);self.assertFalse(row['proofs_verified']);self.assertEqual(row['bundle_hash'],h)
        bad=PublicIndexReader(self.rpc,self.index,self.app,runtime_hash='0x'+'12'*32)
        with self.assertRaises(Exception):bad.records([1])

    def test_reader_accepts_actual_nested_call_through_wallet_contract(self):
        # Copy calldata, CALL the fixed index with value0, discard its return,
        # STOP. This is real local EVM forwarding, not a mocked receipt target.
        runtime=bytes.fromhex('365f5f375f5f365f5f73'+self.index[2:]+'5af15000')
        init='0x'+bytes.fromhex('60'+format(len(runtime),'02x')+'600c60003960'+format(len(runtime),'02x')+'6000f3').hex()+runtime.hex()
        wallet=self.rpc.tx(self.accounts[2],init)['contractAddress']
        h='0x'+'91'*32;receipt=self.rpc.tx(self.accounts[3],submission_data(h),wallet)
        self.assertEqual(receipt['status'],'0x1');self.assertEqual(receipt['to'],wallet)
        self.assertEqual(receipt['logs'][0]['address'],self.index)
        pin=keccak(bytes.fromhex(self.rpc.call('eth_getCode',self.index,'latest')[2:]))
        reader=PublicIndexReader(self.rpc,self.index,self.app,runtime_hash=pin)
        record=reader.record_for_hash(h)
        self.assertEqual(record['transaction_hash'],receipt['transactionHash'])
        self.assertEqual(record['post_number'],'1');self.assertFalse(record['proofs_verified'])
        from unittest.mock import patch
        original=self.rpc.call
        for field,value in [('status','0x0'),('blockHash','0x'+'00'*32),('logs',[])]:
            def corrupted(method,*args):
                result=original(method,*args)
                return {**result,field:value} if method=='eth_getTransactionReceipt' else result
            with patch.object(self.rpc,'call',side_effect=corrupted):
                with self.assertRaises(Exception):reader.record_for_hash(h)

if __name__=='__main__':unittest.main()
