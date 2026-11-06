"""Single-service enrollment with real encrypted desktop/native/EVM/TLS.

AWS, source responses, keyring and finality timing are explicit fixtures.
"""
import copy
import unittest
from unittest.mock import Mock,patch

import base_desktop
from base_client import SharedReader
from base_enrollment import BaseEnrollment
from base_protocol import ReceiptKey,keccak
from base_service import BaseApplication
from base_state import ChainIssuerStore
from base_transactions import TransactionQueue,ProtectedSigner,Limits
from policy import Rejected,canonical,evaluate
import test_base_finality as finality
import test_base_service as service
from test_zkid import fixture


class MemorySecretService:
    """Only keys created by this fixture; no real Secret Service access."""
    def __init__(self):self.values={}
    def ready(self):pass
    def store(self,key,value):self.values[key]=value
    def lookup(self,key):return self.values[key]
    def clear(self,key):del self.values[key]


class EnrollmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):finality.FinalityTests.setUpClass()

    def setUp(self):
        f=self.f=finality.FinalityTests('test_commit_within_source_window_waits_twenty_minutes_for_activation')
        f.setUp();self.addCleanup(f.doCleanups);self.addCleanup(f.tearDown);f.ready()
        self.secrets=MemorySecretService()
        keyring=patch('wallet.WalletSecretService',return_value=self.secrets);keyring.start();self.addCleanup(keyring.stop)
        f.tx_key=ReceiptKey(f.rpc);f.rpc.call('anvil_setBalance',f.tx_key.address,hex(10**20))
        selectors=[keccak(b'publishOrdinary(bytes32,bytes32,bytes)')[:10],
            keccak(b'publish((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint256,uint256,uint256,uint256),bytes,bytes,bytes,uint8,bytes32,bytes32)')[:10]]
        queue=TransactionQueue(f.rpc,ProtectedSigner(f.rpc,f.tx_key),f.root/'queue.sqlite',
            {f.contract:selectors},Limits(600000,3000000000,1000000,10**17,100),initial_nonce=0,laboratory=True)
        f.provider=Mock(budget_enforced=True);f.provider.resolve.return_value='88888888'
        def source(session,tweet,now):
            post,user=fixture(session,tweet_id=tweet)
            return evaluate(session,tweet,canonical(post),canonical(user),now)
        f.provider.check.side_effect=source
        f.app_service=BaseApplication(f.state,f.provider,f.verifier,queue,
            SharedReader(f.rpc,f.contract,f.backend,f.app),lambda:f.now)

    def channel(self):return service.BaseServiceTests.channel(self.f)

    def bridge(self,client):
        f=self.f
        chain={'rpc_endpoint':'https://sepolia.base.org','runtime_code':{f.contract:'12'*32,f.registry_address:'34'*32},'deployment_block':0}
        with patch.object(base_desktop,'BaseRemote',return_value=client):
            base=base_desktop.BaseDesktop(f.root/'public',client.approved,chain,str(f.root/'wallet'))
        base._rpc=f.delayed;base._registry=ChainIssuerStore(f.delayed,f.registry_address,None,None,f.definition)
        return BaseEnrollment(str(f.root/'wallet'),base)

    def test_saved_receipt_waits_for_finality_then_recovers_after_source_deadline(self):
        f=self.f
        with self.channel() as (client,requests),patch('time.time',side_effect=lambda:f.now):
            bridge=self.bridge(client);bridge.begin('synthetic_user',True)
            waiting=bridge.check_post('3141592653589793',True)
            self.assertEqual(waiting['state'],'activation-pending-finality');self.assertFalse(waiting['credential_saved'])
            wallet=bridge.desktop.wallet;sealed=wallet.read('pending.sealed');metadata=wallet.read('public.json')
            self.assertIsNone(wallet.read('credential.sealed',missing=True));self.assertEqual(len(self.secrets.values),1)
            f.now+=1200;f.rpc.call('evm_setNextBlockTimestamp',f.now);f.rpc.call('evm_mine');f.delayed.advance()
            recovered=self.bridge(client).recover()
            self.assertEqual(recovered['state'],'credential-saved');self.assertTrue(recovered['credential_saved'])
            self.assertIsNone(wallet.read('pending.sealed',missing=True));self.assertIsNotNone(wallet.read('credential.sealed'))
            self.assertEqual(wallet.read('public.json'),metadata);self.assertEqual(len(self.secrets.values),1)
            self.assertNotIn(b'credential',sealed)
            self.assertEqual(sum(m['operation']=='commit' for m in requests),1)
            self.assertEqual(sum(m['operation']=='check-post' for m in requests),1)
            witness=[m['body'] for m in requests if m['operation']=='witness']
            self.assertEqual(len(witness),1);self.assertEqual(set(witness[0]),{'handle'})
            self.assertFalse(any(m['operation']=='present' for m in requests))

    def test_active_hint_at_unfinalized_block_cannot_promote_or_erase_receipt(self):
        f=self.f
        with self.channel() as (client,_),patch('time.time',side_effect=lambda:f.now):
            bridge=self.bridge(client);bridge.begin('synthetic_user',True)
            def premature(_):return {'state':'active','active':True,
                'finalized_block':f.rpc.call('eth_getBlockByNumber','latest',False)['hash'],'issuer_definition':f.definition}
            with patch.object(f.state,'finalized_status',side_effect=premature):
                with self.assertRaisesRegex(Rejected,'base-activation-finality'):bridge.check_post('3141592653589793',True)
            self.assertIsNotNone(bridge.desktop.wallet.read('pending.sealed'))
            self.assertIsNone(bridge.desktop.wallet.read('credential.sealed',missing=True))
            value=copy.deepcopy(bridge.desktop.wallet.load('pending'))
            self.assertIsNotNone(value['ack']);self.assertIsNotNone(value['credential'])
            self.assertEqual(self.bridge(client).recover()['state'],'activation-pending-finality')


if __name__=='__main__':unittest.main()
