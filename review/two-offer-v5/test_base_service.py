"""Connected native proofs + signed local EVM + one service + actual remote TLS.

Source data, positive AWS attestation and immediate finality are explicit
fixtures. This does not establish deployed enclave/two-machine acceptance.
"""
from contextlib import contextmanager,nullcontext
import copy
import hashlib
import secrets
import socket
import threading
import time
from unittest.mock import Mock,patch

import base_transport as transport
from base_client import LocalHolder,SharedReader,prove_in_process
from base_protocol import ReceiptKey,keccak
from base_service import BaseApplication,RPC
from base_transactions import Limits,ProtectedSigner,TransactionQueue
from policy import Rejected,canonical
from test_base_discussions import immediate_finality
from test_base_integration import BaseFixture
from test_domain_transport import payload


class BaseServiceTests(BaseFixture):
    def setUp(self):
        super().setUp()
        self.finality=immediate_finality(self.rpc);self.finality.start();self.addCleanup(self.finality.stop)
        self.tx_key=ReceiptKey(self.rpc);self.rpc.call('anvil_setBalance',self.tx_key.address,hex(10**20))
        selectors=[keccak(b'publishOrdinary(bytes32,bytes32,bytes)')[:10],
            keccak(b'publish((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint256,uint256,uint256,uint256),bytes,bytes,bytes,uint8,bytes32,bytes32)')[:10]]
        self.queue_args=(self.rpc,ProtectedSigner(self.rpc,self.tx_key),self.root/'tx'/'journal.sqlite',
            {self.contract:selectors},Limits(600000,3000000000,1000000,10**17,100))
        self.queue=TransactionQueue(*self.queue_args,initial_nonce=0,laboratory=True)
        self.provider=Mock(budget_enforced=True)
        self.app_service=self.make_app()
        self.submission=secrets.token_hex(32)
        self.ordinary=dict(self.post,claims=[])

    def make_app(self):
        return BaseApplication(self.state,self.provider,self.verifier,self.queue,
            SharedReader(self.rpc,self.contract,self.backend,self.app),lambda:self.now)

    def message(self,operation,body):
        return {'profile':RPC,'id':secrets.token_hex(16),'operation':operation,'body':body}

    def ordinary_body(self):
        return {'post':self.ordinary,'facts':[],'submission_id':self.submission,'challenge':None,
            'proof':None,'approve_publication':True}

    @contextmanager
    def channel(self,application=None,*,bad_quote=False,approved_changes=None,through_gateway=False):
        current=application or self.app_service;approved={'profile':transport.APPROVAL,
            'identity':copy.deepcopy(current.identity),'code_identity':'ab'*32,'state_authority_sha256':'cd'*32,
            'pcrs':{str(i):'ef'*48 for i in range(3)},
            'endpoint':{'profile':transport.ENDPOINT,'host':'beta.example.com','port':443}}
        if approved_changes:approved.update(approved_changes)
        captures={};threads=[];requests=[]
        listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        listener.bind(('127.0.0.1',0));listener.listen(4)
        original=current.dispatch
        def dispatch(message):requests.append(copy.deepcopy(message));return original(message)
        def quote(nonce,bind,cert):
            captures.clear();captures.update(payload(nonce,bind,cert))
            if bad_quote:captures['nonce']=b'wrong'
            return b'explicit-synthetic-AWS-quote'
        def dial(*args,**kwargs):
            left=socket.create_connection(listener.getsockname(),timeout=2)
            right,_=listener.accept()
            worker=threading.Thread(target=transport.serve_connection,
                args=(right,current,'ab'*32,'cd'*32));threads.append(worker);worker.start();return left
        host=None;route_patch=nullcontext();connect=dial
        if through_gateway:
            from public_gateway import PublicGateway
            host=PublicGateway(16,port=0);address=host.start()
            route_patch=patch.object(host,'_dial',side_effect=lambda profile:dial())
            connect=lambda *a,**kw:socket.create_connection(address,timeout=2)
        with route_patch,patch.object(transport,'CHAIN_ID',31337),patch.object(transport,'connect_endpoint',side_effect=connect),\
             patch.object(transport,'_aws_document',side_effect=quote),\
             patch.object(transport,'verify_aws_document',return_value=captures),\
             patch.object(current,'dispatch',side_effect=dispatch):
            client=transport.BaseRemote(approved)
            try:yield client,requests
            finally:
                if host is not None:host.close()
                for thread in threads:thread.join(timeout=3);self.assertFalse(thread.is_alive())
                listener.close()

    def test_ordinary_publication_needs_no_credential_and_remote_reader_retrieves_it(self):
        issuer_before=self.state.load()[1]._issuer
        with self.channel() as (client,requests):
            result=client.call('post-submit',self.ordinary_body());self.assertEqual(result['state'],'pending')
            status=client.call('post-status',{'submission_id':self.submission})
            self.assertEqual(status['state'],'finalized')
            self.now=max(self.now,int(self.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16))
            discussion=client.call('discussion',{'after':0,'limit':20})
            self.assertEqual(discussion['posts'][0]['post'],self.ordinary)
            self.assertEqual(discussion['posts'][0]['post_number'],'1')
            self.assertEqual(discussion['posts'][0]['facts'],[])
        self.assertEqual(self.provider.mock_calls,[])
        self.assertEqual(self.state.load()[1]._issuer,issuer_before)
        self.assertFalse(any(message['operation'] in ('begin','witness','commit') for message in requests))

    def test_remote_witness_refresh_and_separate_holder_process_proof_publish(self):
        # Another account advances the accumulator after this holder's issuance.
        self.enroll(account='77777777')
        holder_key=secrets.token_bytes(32);holder=LocalHolder(self.root/'holder',holder_key)
        holder.save(self.held.private);before=holder.load();draft=b'unpublished draft >>99'
        (holder.root/'draft').write_bytes(draft)
        with self.channel() as (client,requests):
            view=client.public_view();holder.refresh(client,view)
            self.assertNotEqual(before['issuer']['revocation_registry'],holder.load()['issuer']['revocation_registry'])
            c=client.call('post-challenge',{'post':self.post,'facts':self.selected,'submission_id':self.submission})
            proof=prove_in_process(holder.root,holder_key,view,c)
            body={'post':self.post,'facts':self.selected,'submission_id':self.submission,
                'challenge':c,'proof':proof,'approve_publication':True}
            self.assertEqual(client.call('post-submit',body)['state'],'pending')
            self.assertEqual(client.call('post-status',{'submission_id':self.submission})['state'],'finalized')
            self.now=max(self.now,int(self.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16))
            results=client.call('discussion',{'after':0,'limit':20})['posts']
            self.assertTrue(results[0]['valid_when_published']);self.assertEqual(results[0]['facts'],self.selected)
        witness=[m['body'] for m in requests if m['operation']=='witness']
        self.assertEqual(len(witness),1);self.assertEqual(set(witness[0]),{'handle'})
        self.assertNotIn(b'credential',canonical(witness));self.assertNotIn(b'proof',canonical(witness))
        self.assertEqual((holder.root/'draft').read_bytes(),draft)

    def test_same_credential_request_recovers_after_expiry_and_service_restart(self):
        c,proof=self.prepare()
        body={'post':self.post,'facts':self.selected,'submission_id':c['nonce'],
            'challenge':c,'proof':proof,'approve_publication':True}
        original=self.rpc.call
        def lost(method,*args):
            result=original(method,*args)
            if method=='eth_sendRawTransaction':raise OSError('synthetic lost reply')
            return result
        with self.channel() as (client,_),patch.object(self.rpc,'call',side_effect=lost):
            result=client.call('post-submit',body);self.assertEqual(result['state'],'recoverable')
        # Proof's original 60-second authorization expires before recovery.
        self.now+=120;self.queue=TransactionQueue(*self.queue_args,laboratory=True)
        restarted=self.make_app()
        with self.channel(restarted) as (client,_),patch.object(self.verifier,'approve',side_effect=AssertionError('never sign recovery')):
            recovered=client.call('post-submit',body);self.assertEqual(recovered['state'],'finalized')
            self.assertEqual(recovered['transaction_hash'],result['transaction_hash'])
            changed=copy.deepcopy(body);changed['post']['body']='edited after authorization'
            with self.assertRaisesRegex(Rejected,'transaction-submission-conflict'):client.call('post-submit',changed)
        self.assertEqual(int(self.rpc.call('eth_getTransactionCount',self.tx_key.address,'latest'),16),1)

    def test_bad_quote_or_wrong_contract_never_receives_private_request(self):
        for bad,changes in [(True,None),(False,{'identity':dict(self.app_service.identity,contract=self.registry_address)})]:
            with self.channel(bad_quote=bad,approved_changes=changes) as (client,requests):
                with self.assertRaises(Rejected):client.call('post-submit',self.ordinary_body())
                self.assertEqual(requests,[])
        self.assertEqual(int(self.rpc.call('eth_getTransactionCount',self.tx_key.address,'latest'),16),0)

    def test_public_api_never_exposes_signer_keys_issuer_administration_or_caller_targets(self):
        for op,body in [('revoke',{'account':'42424242'}),('sign',{'digest':'00'*32}),
            ('post-submit',dict(self.ordinary_body(),to=self.registry_address)),
            ('post-submit',dict(self.ordinary_body(),approve_publication=False))]:
            result=self.app_service.dispatch(self.message(op,body));self.assertEqual(result['status'],'rejected')
        self.assertEqual(int(self.rpc.call('eth_getTransactionCount',self.tx_key.address,'latest'),16),0)

    def test_revoked_credential_cannot_refresh_or_publish_but_ordinary_post_still_works(self):
        from base_issuer import IssuerAdministration
        IssuerAdministration(self.state).revoke('42424242')
        holder=LocalHolder(self.root/'revoked',secrets.token_bytes(32));holder.save(self.held.private)
        original=(holder.root/'credential.enc').read_bytes()
        with self.channel() as (client,_):
            with self.assertRaises(Rejected):holder.refresh(client,client.public_view())
            self.assertEqual(client.call('post-submit',self.ordinary_body())['state'],'pending')
        self.assertEqual((holder.root/'credential.enc').read_bytes(),original)

    def test_witness_root_mismatch_does_not_replace_saved_credential(self):
        holder=LocalHolder(self.root/'root-mismatch',secrets.token_bytes(32));holder.save(self.held.private)
        before=(holder.root/'credential.enc').read_bytes();view=self.backend.public_view()
        remote=Mock();remote.refresh_witness.return_value={'public':{},'witness':{},'sequence':view['sequence'],
            'definition_hash':view['definition_hash']}
        with self.assertRaisesRegex(Rejected,'registry-state-changed'):holder.refresh(remote,view)
        self.assertEqual((holder.root/'credential.enc').read_bytes(),before)

    def test_managed_service_recovers_after_loss_of_its_entire_local_journal(self):
        from base_managed_storage import DynamoObjects,DynamoJournalAnchor
        from test_base_managed_storage import DynamoFixture
        sdk=DynamoFixture();anchor=DynamoJournalAnchor(DynamoObjects(sdk,'synthetic-table',self.definition),self.tx_key.address)
        args=list(self.queue_args);args[2]=self.root/'managed-a'/'queue.sqlite'
        self.queue=TransactionQueue(*args,initial_nonce=0,laboratory=True,anchor=anchor)
        service=self.make_app();before=self.state.load()[1]._issuer
        c,proof=self.prepare()
        body={'post':self.post,'facts':self.selected,'submission_id':c['nonce'],
            'challenge':c,'proof':proof,'approve_publication':True}
        with self.channel(service) as (client,_):first=client.call('post-submit',body)
        self.queue.path.unlink();args[2]=self.root/'managed-b'/'queue.sqlite'
        args[1]=ProtectedSigner(self.rpc,self.tx_key)
        self.queue=TransactionQueue(*args,laboratory=True,anchor=anchor)
        self.state=self.make_state();service=self.make_app();self.now+=120
        with self.channel(service) as (client,_):
            result=client.call('post-submit',body)
            self.assertEqual(result['state'],'finalized');self.assertEqual(result['transaction_hash'],first['transaction_hash'])
            page=client.call('discussion',{'after':0,'limit':20})
            self.assertTrue(page['posts'][0]['valid_when_published'])
        self.assertEqual(self.state.load()[1]._issuer,before)

    def test_issuer_boot_wait_does_not_prevent_ordinary_posts_and_is_polled_again(self):
        self.state.poll_boot=Mock(side_effect=[{'state':'boot-pending-finality'},{'state':'ready'}])
        request={'post':self.post,'facts':self.selected,'submission_id':self.submission}
        with self.channel() as (client,_):
            with self.assertRaisesRegex(Rejected,'issuer-not-ready'):client.call('post-challenge',request)
            self.assertEqual(client.call('post-submit',self.ordinary_body())['state'],'pending')
            self.assertEqual(client.call('post-challenge',request)['nonce'],self.submission)
        self.assertEqual(self.state.poll_boot.call_count,2)

    def test_single_cid_public_gateway_routes_new_attested_base_service(self):
        with self.channel(through_gateway=True) as (client,requests):
            self.assertEqual(client.call('parameters',{}),self.app_service.identity)
            self.assertEqual(client.call('post-submit',self.ordinary_body())['state'],'pending')
            self.assertEqual(client.call('post-status',{'submission_id':self.submission})['state'],'finalized')
        self.assertEqual([m['operation'] for m in requests],['parameters','post-submit','post-status'])
