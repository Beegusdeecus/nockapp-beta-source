"""Actual EVM/native proofs with a controlled delayed-finality oracle.

This controls the meaning of RPC 'finalized' in the fixture, not proof validity,
contract execution, source windows, encryption or chain reorganization.
"""
import secrets
import unittest
from unittest.mock import patch

from base_evm import encode
from base_finality import LeasedIssuer, RPCFinality
from base_client import SharedReader
from base_protocol import ReceiptVerifier, challenge
from base_state import ChainIssuerStore, Replicas
from domain_pipeline import Native, PendingHolder
from policy import Rejected, canonical
from test_base_integration import BaseFixture
from test_zkid import NOW, fixture


class DelayedRPC:
    def __init__(self,rpc):
        self.rpc=rpc;self.number=int(rpc.call('eth_blockNumber'),16)

    def call(self,method,*params):
        if method=='eth_getBlockByNumber' and params[0]=='finalized':
            return self.rpc.call(method,hex(self.number),*params[1:])
        return self.rpc.call(method,*params)

    def __getattr__(self,name):return getattr(self.rpc,name)

    def advance(self):
        self.number=int(self.rpc.call('eth_blockNumber'),16)


class FinalityTests(BaseFixture):
    def setUp(self):
        super().setUp()
        # Separate fresh laboratory identity store; no existing identity migration.
        self.registry_address=self.deploy('IssuerState','f(address,address,bytes32)',
                                          self.admin,self.updater,'0x'+self.definition)
        self.contract=self.deploy('PostAcceptance','f(address,bytes32,address,address)',
                                  self.registry_address,self.app,self.admin,self.signing.address)
        self.replicas=Replicas([self.root/'leased-a',self.root/'leased-b'])
        self.backend=ChainIssuerStore(self.rpc,self.registry_address,self.updater,self.replicas,self.definition)
        self.delayed=DelayedRPC(self.rpc);self.finality=RPCFinality(self.delayed)
        self.state=LeasedIssuer(self.backend,self.wrap_key,self.definition,Native(),self.finality)
        self.state.initialize(self.core);self.delayed.advance()
        self.state.begin_boot(6)
        self.verifier=ReceiptVerifier(self.rpc,self.contract,self.backend,Native(),self.signing,self.app,lambda:self.now)

    def ready(self):
        self.rpc.call('evm_setNextBlockTimestamp',NOW+1204);self.rpc.call('evm_mine')
        self.now=NOW+1204;self.delayed.advance()
        self.assertEqual(self.state.poll_boot()['state'],'ready')

    def issue(self,account='42424242',commit=True):
        _,core=self.state.load();pending=PendingHolder.create(Native(),core.public)
        session=self.state.operate('begin',pending.request,pending.desktop_nonce,account,'synthetic_user',self.now)
        tweet,user=fixture(session)
        issued=self.state.operate('stage_fixture',session,'3141592653589793',canonical(tweet),canonical(user),self.now+2)
        _,core=self.state.load();held,ack=pending.receive(issued,core.public,session)
        if commit:
            result=self.state.operate('commit',session,ack,self.now+3)
            self.assertTrue(result['activation_pending_finality'])
        return held,session,ack

    def restart(self,batch=6):
        self.backend=ChainIssuerStore(self.rpc,self.registry_address,self.updater,self.replicas,self.definition)
        self.finality=RPCFinality(self.delayed)
        self.state=LeasedIssuer(self.backend,self.wrap_key,self.definition,Native(),self.finality)
        self.state.begin_boot(batch)
        self.verifier=ReceiptVerifier(self.rpc,self.contract,self.backend,Native(),self.signing,self.app,lambda:self.now)

    def test_source_session_starts_only_after_finalized_boot_and_keeps_original_window(self):
        self.assertEqual(self.state.poll_boot()['state'],'boot-pending-finality')
        _,core=self.state.load();pending=PendingHolder.create(Native(),core.public)
        with self.assertRaises(Rejected):self.state.operate('begin',pending.request,pending.desktop_nonce,
                                                         '42424242','synthetic_user',NOW+4)
        self.ready()
        _,session,ack=self.issue(commit=False)
        # Finality waiting does not lengthen the actual source/receipt window.
        with self.assertRaises(Rejected):self.state.operate('commit',session,ack,self.now+601)

    def test_commit_within_source_window_waits_twenty_minutes_for_activation(self):
        self.ready();held,session,ack=self.issue()
        self.assertFalse(self.state.finalized_status(session)['active'])
        self.now+=1200;self.rpc.call('evm_setNextBlockTimestamp',self.now);self.rpc.call('evm_mine')
        self.delayed.advance()
        self.assertTrue(self.state.finalized_status(session)['active'])
        # No replayed commit and no new source acceptance after expiry.
        with self.assertRaises(Rejected):self.state.operate('commit',session,ack,self.now)
        self.held=held
        package=self.package();self.assertEqual(self.publish(package)['status'],'0x1')

    def test_orphaned_signed_delivery_never_reuses_handle_on_restart(self):
        self.ready()
        snapshot=self.rpc.call('evm_snapshot')
        orphan,session,ack=self.issue(commit=False)
        orphan_handle=orphan.private['credential']['claims'][0]['Revocation']['value']
        self.assertTrue(self.rpc.call('evm_revert',snapshot))
        with self.assertRaises(Rejected):self.state.load()
        self.restart()
        self.assertEqual(self.state.poll_boot()['state'],'boot-pending-finality')
        self.delayed.advance();self.assertEqual(self.state.poll_boot()['state'],'ready')
        fresh,session2,ack2=self.issue()
        fresh_handle=fresh.private['credential']['claims'][0]['Revocation']['value']
        self.assertNotEqual(orphan_handle,fresh_handle)
        with self.assertRaises(Rejected):self.prepare(held=orphan)
        self.held=fresh;self.assertEqual(self.publish(self.package())['status'],'0x1')

    def test_superseded_process_and_unleased_write_cannot_update_issuer(self):
        self.ready();old=self.state;old_backend=self.backend
        self.restart()
        with self.assertRaises(Rejected):old.poll_boot()
        with self.assertRaises(Rejected):old_backend.read()
        head=self.backend.head();view=self.backend.public_view()
        data=encode('update(uint256,bytes32,bytes32,uint256,bytes)',head['revision'],head['ciphertext'],
                    '0x'+'cc'*32,head['sequence'],'0x'+canonical(view).hex())
        self.assertEqual(self.rpc.tx(self.updater,data,self.registry_address)['status'],'0x0')

    def test_lost_commit_reply_recovers_final_status_without_reissuing(self):
        self.ready();held,session,ack=self.issue(commit=False)
        original=self.rpc.tx
        def lost(*args,**kwargs):
            result=original(*args,**kwargs)
            raise ValueError('synthetic-lost-reply')
        with patch.object(self.rpc,'tx',side_effect=lost):
            with self.assertRaises(ValueError):self.state.operate('commit',session,ack,self.now+3)
        self.assertFalse(self.state.finalized_status(session)['active'])
        self.delayed.advance();self.assertTrue(self.state.finalized_status(session)['active'])
        before=self.backend.head()
        with self.assertRaises(Rejected):self.state.operate('commit',session,ack,self.now+3)
        self.assertEqual(self.backend.head(),before)

    def test_active_identity_and_issuer_keys_survive_new_finalized_boot(self):
        self.ready();held,session,ack=self.issue();self.delayed.advance()
        _,before=self.state.load();self.assertTrue(self.state.finalized_status(session)['active'])
        self.restart();self.delayed.advance();self.state.poll_boot()
        _,after=self.state.load()
        self.assertEqual(before._issuer,after._issuer);self.assertEqual(before._accounts,after._accounts)
        self.assertEqual(after._next,12);self.assertTrue(self.state.finalized_status(session)['active'])
        self.held=held;self.assertEqual(self.publish(self.package())['status'],'0x1')

    def test_finalized_oracle_rollback_rejected_without_latest_fallback(self):
        self.ready();self.finality.finalized()
        self.delayed.number-=1
        with self.assertRaises(Rejected):self.state.poll_boot()

    def test_shared_reader_displays_no_final_badge_until_post_and_registry_finalize(self):
        self.ready();held,session,ack=self.issue();self.held=held
        self.assertEqual(self.publish(self.package())['status'],'0x1')
        reader=SharedReader(self.delayed,self.contract,self.backend,self.app)
        now=int(self.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16)
        self.assertEqual(reader.read(now),[])
        self.delayed.advance()
        self.assertTrue(reader.read(now)[0]['valid_when_published'])


if __name__=='__main__':unittest.main()
