"""Real native ZK + actual local EVM. Source/KMS/attestation are synthetic.

No owner's accounts, wallet, drafts, keyring, services or cloud state are read.
"""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
import tempfile
import threading
import unittest
from unittest.mock import patch

from base_evm import local_chain, compile_contracts, encode
from base_protocol import (ReceiptKey, ReceiptVerifier, challenge, read, sha, AUTH_TYPE, auth_tuple,
                           authorization_digest, publication_data, inspect_publication)
from base_state import ChainIssuerStore, Replicas
from base_client import LocalHolder, prove_in_process, SharedReader
from base_issuer import IssuerAdministration
from base_keys import wrap_service_keys, recover_service_keys, PROFILE as KEY_PROFILE
from domain_pipeline import Native, LabDomainIssuer, PendingHolder
from domain_state import PersistentDomainIssuer
from policy import Rejected, canonical
from test_domain_posts import post
from test_zkid import NOW, fixture


class FixtureWitnessClient:
    """Synthetic source/lab-only adapter; remote acceptance uses real TLS tests."""
    def __init__(self,state):self.state=state

    def refresh_witness(self,handle,view):
        _,core=self.state.load()
        result=core.native.call('witness',issuer=core._issuer,handle=handle)
        return {**result,'sequence':core.sequence,'definition_hash':core.definition_hash}


class BaseFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled=compile_contracts()

    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix='zkid-base-')
        self.root=Path(self.work.name)
        self.chain=local_chain(self.root/'chain.json');self.rpc=self.chain.__enter__()
        self.accounts=self.rpc.call('eth_accounts');self.admin,self.updater,self.relayer=self.accounts[:3]
        self.native=Native();self.core=LabDomainIssuer(self.native,NOW,24)
        self.definition=self.core.definition_hash;self.app='0x'+'ab'*32
        self.signing=ReceiptKey(self.rpc)
        self.registry_address=self.deploy('IssuerState','f(address,address,bytes32)',
                                          self.admin,self.updater,'0x'+self.definition)
        self.contract=self.deploy('PostAcceptance','f(address,bytes32,address,address)',
                                  self.registry_address,self.app,self.admin,self.signing.address)
        self.replicas=Replicas([self.root/'replica-a',self.root/'replica-b'])
        self.backend=ChainIssuerStore(self.rpc,self.registry_address,self.updater,self.replicas,self.definition)
        # Models a stable KMS-unwrapped state key in the enclave, injected anew
        # into reconstructed service instances. No plaintext key file is written.
        self.wrap_key=secrets.token_bytes(32)
        self.state=self.make_state()
        self.state.initialize(self.core)
        self.after_initialization()
        self.held=self.enroll()
        self.now=getattr(self,'source_now',NOW)+4
        self.rpc.call('evm_setNextBlockTimestamp',self.now);self.rpc.call('evm_mine')
        self.verifier=ReceiptVerifier(self.rpc,self.contract,self.backend,Native(),self.signing,self.app,lambda:self.now)
        self.post=post();self.selected=['account-controlled','followers-at-least-10000']

    def make_state(self):
        return PersistentDomainIssuer(self.backend,self.wrap_key,self.definition,Native())

    def after_initialization(self):pass

    def tearDown(self):
        self.chain.__exit__(None,None,None);self.work.cleanup()

    def deploy(self,name,constructor,*args):
        code=self.compiled['contracts/'+name+'.sol'][name]['evm']['bytecode']['object']
        encoded=encode(constructor,*args)[10:]
        receipt=self.rpc.tx(self.admin,'0x'+code+encoded)
        self.assertEqual(receipt['status'],'0x1')
        return receipt['contractAddress']

    def enroll(self,account='42424242',followers=10000,commit=True):
        now=getattr(self,'source_now',NOW)
        _,core=self.state.load();holder=PendingHolder.create(Native(),core.public)
        session=self.state.operate('begin',holder.request,holder.desktop_nonce,account,'synthetic_user',now)
        tweet,user=fixture(session,followers=followers)
        issued=self.state.operate('stage_fixture',session,'3141592653589793',canonical(tweet),canonical(user),now+2)
        _,core=self.state.load();held,ack=holder.receive(issued,core.public,session)
        if commit:
            self.state.operate('commit',session,ack,now+3)
            return held
        return held,session,ack

    def prepare(self,held=None,p=None,selected=None,c=None):
        held=held or self.held;p=p or self.post;selected=selected or self.selected
        view=self.backend.public_view()
        c=c or challenge(p,selected,self.app,31337,self.contract,view['sequence'],self.now)
        _,core=self.state.load();proof=held.present(core,c)
        return c,proof

    def package(self,**kwargs):
        c,proof=self.prepare(**kwargs)
        return self.verifier.approve(kwargs.get('p',self.post),kwargs.get('selected',self.selected),c,proof)

    def publish(self,package,sender=None):
        return self.rpc.tx(sender or self.relayer,publication_data(package),self.contract)

    def inspect(self,log):
        now=max(self.now,int(self.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16))
        return inspect_publication(self.rpc,self.contract,log,self.backend,Native(),self.app,now,
                                   int(self.rpc.call('eth_blockNumber'),16))


class BaseTests(BaseFixture):
    def test_native_proof_receipt_and_independent_user_retrieves_entire_discussion(self):
        a=self.package();r=self.publish(a);self.assertEqual(r['status'],'0x1')
        self.assertEqual(self.inspect(r['logs'][0])['credential_status'],'valid-at-current-registry')
        # User B has another independent credential and publishes a comment.
        b=self.enroll(account='77777777')
        self.post=dict(post(),kind='comment',id='87654321-1234-4123-8123-123456789abc',
                       thread_id=self.post['id'],title=None,body='Independent user reply >>1')
        r2=self.publish(self.package(held=b),self.accounts[3]);self.assertEqual(r2['status'],'0x1')
        # Stateless reader C, author and verifier no longer involved. No replicas
        # needed for post retrieval; registry public bytes are also onchain.
        fresh=ChainIssuerStore(self.rpc,self.registry_address,None,None,self.definition)
        logs=self.rpc.call('eth_getLogs',{'address':self.contract,'fromBlock':'0x0','toBlock':'latest'})
        now=max(self.now,int(self.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16))
        results=[inspect_publication(self.rpc,self.contract,l,fresh,Native(),self.app,now,
                                    int(self.rpc.call('eth_blockNumber'),16)) for l in logs]
        self.assertEqual([x['post']['kind'] for x in results],['thread','comment'])
        self.assertTrue(all(x['valid_when_published'] for x in results))
        self.assertTrue(all(x['public_id'] is None for x in results))
        self.assertEqual(results[0]['credential_status'],'unknown-after-registry-update')

    def test_invalid_native_proof_never_gets_signed(self):
        c,p=self.prepare();p['proof']['challenge']='00'*32
        with self.assertRaises(Rejected):self.verifier.approve(self.post,self.selected,c,p)

    def test_edited_post_facts_scope_version_chain_contract_submission_rejected(self):
        c,p=self.prepare()
        for change in ({'body':'Edited'},{'id':'87654321-1234-4123-8123-123456789abc'}):
            with self.assertRaises(Rejected):self.verifier.approve(dict(self.post,**change),self.selected,c,p)
        with self.assertRaises(Rejected):self.verifier.approve(self.post,['account-controlled'],c,p)
        for field,value in [('nonce','cd'*32),('identity',True),('scope','ef'*32),('profile','v2')]:
            with self.assertRaises(Rejected):self.verifier.approve(self.post,self.selected,dict(c,**{field:value}),p)
        from base_protocol import scope_context
        for app,chain,contract in [('0x'+'cd'*32,31337,self.contract),(self.app,84532,self.contract),
                                   (self.app,31337,self.registry_address)]:
            altered=dict(c,scope=scope_context(self.post,self.selected,app,chain,contract,c['nonce']))
            with self.assertRaises(Rejected):self.verifier.approve(self.post,self.selected,altered,p)

    def test_signed_content_edits_and_proof_edits_revert_onchain(self):
        package=self.package()
        for key in ('post','facts','proof_envelope'):
            bad=copy.deepcopy(package);bad[key]+=b' '
            self.assertEqual(self.publish(bad)['status'],'0x0')
        self.assertEqual(self.publish(package)['status'],'0x1')

    def test_eip712_digest_matches_contract_and_cross_domain_signature_fails(self):
        package=self.package();a=package['authorization']
        digest=authorization_digest(a,self.app,self.definition,31337,self.contract)
        self.assertEqual(digest,read(self.rpc,self.contract,'authorizationHash('+AUTH_TYPE+')',auth_tuple(a)))
        for app,chain,contract in [('0x'+'cd'*32,31337,self.contract),(self.app,84532,self.contract),
                                   (self.app,31337,self.registry_address)]:
            bad=copy.deepcopy(package)
            bad['signature']=self.signing.sign(authorization_digest(a,app,self.definition,chain,contract))
            self.assertEqual(self.publish(bad)['status'],'0x0')

    def test_copied_concurrent_submission_exactly_one_and_front_runner_cannot_edit(self):
        package=self.package()
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses=list(pool.map(lambda sender:self.publish(package,sender)['status'],self.accounts[2:4]))
        self.assertEqual(sorted(statuses),['0x0','0x1'])
        self.assertEqual(self.publish(package)['status'],'0x0')
        self.assertEqual(len(self.rpc.call('eth_getLogs',{'address':self.contract,'fromBlock':'0x0','toBlock':'latest'})),1)

    def test_same_person_can_post_repeatedly_without_stable_public_holder_identifier(self):
        first=self.package();self.assertEqual(self.publish(first)['status'],'0x1')
        self.post=dict(self.post,id='87654321-1234-4123-8123-123456789abc',body='A second post')
        second=self.package();self.assertEqual(self.publish(second)['status'],'0x1')
        self.assertNotEqual(first['authorization']['submissionId'],second['authorization']['submissionId'])
        for package in (first,second):
            public=json.loads(package['proof_envelope'])
            self.assertIsNone(public['proof']['claimed_id'])
            self.assertEqual(set(public['proof']['proof']['proofs']),{'credential','active'})
            self.assertNotIn(b'42424242',package['proof_envelope'])

    def test_reauthorizing_exact_same_post_bytes_cannot_duplicate_discussion_item(self):
        self.assertEqual(self.publish(self.package())['status'],'0x1')
        self.assertEqual(self.publish(self.package())['status'],'0x0')
        self.post=dict(self.post,body='Changed content with same UUID')
        self.assertEqual(self.publish(self.package())['status'],'0x0')

    def test_actual_evm_restart_restores_issuer_and_post_history(self):
        package=self.package();r=self.publish(package);self.assertEqual(r['status'],'0x1')
        before=self.backend.head()
        self.chain.__exit__(None,None,None)
        self.chain=local_chain(self.root/'chain.json');self.rpc=self.chain.__enter__()
        self.backend=ChainIssuerStore(self.rpc,self.registry_address,self.updater,self.replicas,self.definition)
        self.state=PersistentDomainIssuer(self.backend,self.wrap_key,self.definition,Native())
        self.assertEqual(self.backend.head(),before);self.state.load()
        self.assertTrue(self.inspect(r['logs'][0])['valid_when_published'])
        self.assertEqual(self.publish(package)['status'],'0x0')

    def test_failed_replacement_preserves_incumbent_and_success_revokes_it(self):
        pending,session,ack=self.enroll(commit=False)
        bad=copy.deepcopy(ack);bad['proofs']={}
        with self.assertRaises(Rejected):self.state.operate('commit',session,bad,NOW+3)
        old=self.package();accepted=self.publish(old);self.assertEqual(accepted['status'],'0x1')
        self.state.operate('commit',session,ack,NOW+3)
        with self.assertRaises(Rejected):self.prepare()
        self.post=dict(self.post,id='87654321-1234-4123-8123-123456789abc')
        self.assertEqual(self.publish(self.package(held=pending))['status'],'0x1')
        old_status=self.inspect(accepted['logs'][0])
        self.assertTrue(old_status['valid_when_published'])
        self.assertEqual(old_status['credential_status'],'unknown-after-registry-update')

    def test_stale_registry_receipt_reverts_and_old_native_proof_cannot_be_resigned(self):
        package=self.package();c,p=self.prepare()
        self.enroll(account='77777777')
        self.assertEqual(self.publish(package)['status'],'0x0')
        with self.assertRaises(Rejected):self.verifier.approve(self.post,self.selected,c,p)

    def test_registry_race_during_native_verification_rejects(self):
        c,p=self.prepare();original=self.verifier.native.call
        def race(*args,**kwargs):
            result=original(*args,**kwargs);self.enroll(account='77777777');return result
        with patch.object(self.verifier.native,'call',side_effect=race):
            with self.assertRaises(Rejected):self.verifier.approve(self.post,self.selected,c,p)

    def test_expiry_preserves_historical_acceptance(self):
        package=self.package();r=self.publish(package);self.assertEqual(r['status'],'0x1')
        self.now=package['authorization']['credentialExpiry']
        self.assertEqual(self.inspect(r['logs'][0])['credential_status'],'expired')
        self.rpc.call('evm_setNextBlockTimestamp',self.now);self.rpc.call('evm_mine')
        self.assertEqual(self.publish(package)['status'],'0x0')

    def test_deadline_and_signer_epoch_and_pause(self):
        package=self.package()
        self.rpc.tx(self.admin,encode('setPaused(bool)','true'),self.contract)
        self.assertEqual(self.publish(package)['status'],'0x0')
        self.rpc.tx(self.admin,encode('setPaused(bool)','false'),self.contract)
        self.rpc.tx(self.admin,encode('setSigner(address)',self.signing.address),self.contract)
        self.assertEqual(self.publish(package)['status'],'0x0')
        package=self.package()
        self.rpc.call('evm_setNextBlockTimestamp',self.now+60);self.rpc.call('evm_mine')
        self.assertEqual(self.publish(package)['status'],'0x0')

    def test_permissions_no_post_authority_over_issuer_state(self):
        head=self.backend.head()
        data=encode('update(uint256,bytes32,bytes32,uint256,bytes)',head['revision'],head['ciphertext'],
                    '0x'+'cc'*32,head['sequence'],'0x'+canonical(self.backend.public_view()).hex())
        self.assertEqual(self.rpc.tx(self.relayer,data,self.registry_address)['status'],'0x0')
        self.assertEqual(self.rpc.tx(self.relayer,encode('setSigner(address)',self.accounts[4]),self.contract)['status'],'0x0')
        self.assertEqual(self.rpc.tx(self.relayer,encode('setUpdater(address)',self.accounts[4]),self.registry_address)['status'],'0x0')

    def test_encrypted_state_restarts_identity_and_history_without_action_database(self):
        package=self.package();receipt=self.publish(package);self.assertEqual(receipt['status'],'0x1')
        revision,old=self.state.load();definition=old.definition_hash
        backend=ChainIssuerStore(self.rpc,self.registry_address,self.updater,
            Replicas([self.root/'replica-a',self.root/'replica-b']),self.definition)
        restarted=PersistentDomainIssuer(backend,self.wrap_key,self.definition,Native())
        revision2,new=restarted.load();self.assertEqual((revision,definition),(revision2,new.definition_hash))
        self.assertEqual(old._accounts,new._accounts);self.assertEqual(old._issuer,new._issuer)
        verifier=ReceiptVerifier(self.rpc,self.contract,backend,Native(),ReceiptKey(self.rpc,self.signing.key),self.app,lambda:self.now)
        c=challenge(self.post,self.selected,self.app,31337,self.contract,new.sequence,self.now)
        proof=self.held.present(new,c)
        self.assertIsNotNone(verifier.approve(self.post,self.selected,c,proof))
        self.assertEqual(self.publish(package)['status'],'0x0')
        self.assertTrue(self.inspect(receipt['logs'][0])['valid_when_published'])
        with self.assertRaises(Rejected):PersistentDomainIssuer(backend,secrets.token_bytes(32),self.definition,Native()).load()
        with self.assertRaises(Rejected):restarted.initialize(self.core)

    def test_ciphertext_replica_loss_tamper_rollback_and_missing_key_fail_closed(self):
        head=self.backend.head();paths=[p/head['ciphertext'][2:] for p in self.replicas.roots]
        original=paths[0].read_bytes();paths[0].write_bytes(b'old-or-corrupt')
        self.state.load()  # Other replica still holds exact committed ciphertext.
        paths[1].unlink()
        with self.assertRaises(ValueError):self.state.load()
        paths[0].write_bytes(original)
        self.state.load()
        rev,envelope=self.backend.read()
        with self.assertRaises(Rejected):self.backend.compare_exchange(rev-1,envelope,self.backend.public_view())
        self.assertNotIn(b'42424242',original)

    def test_parallel_issuer_updates_serialize_and_never_publish_losing_state(self):
        revision,envelope=self.backend.read();view=self.backend.public_view()
        # Different authenticated snapshots, same base revision, same registry.
        a=self.state._seal(self.state.load()[1],revision+1)
        b=self.state._seal(self.state.load()[1],revision+1)
        barrier=threading.Barrier(2);original=self.replicas.put
        def wait(data):
            result=original(data);barrier.wait(timeout=10);return result
        def run(data):
            try:self.backend.compare_exchange(revision,data,view);return True
            except Rejected:return False
        with patch.object(self.replicas,'put',side_effect=wait):
            with ThreadPoolExecutor(max_workers=2) as pool:self.assertEqual(sum(pool.map(run,[a,b])),1)
        self.state.load()

    def test_reorg_orphaned_publication_is_removed_and_can_be_resubmitted(self):
        package=self.package();snapshot=self.rpc.call('evm_snapshot')
        receipt=self.publish(package);log=receipt['logs'][0]
        self.assertTrue(self.inspect(log)['valid_when_published'])
        self.assertTrue(self.rpc.call('evm_revert',snapshot))
        with self.assertRaises(Rejected):self.inspect(log)
        self.assertEqual(self.rpc.call('eth_getLogs',{'address':self.contract,'fromBlock':'0x0','toBlock':'latest'}),[])
        self.assertEqual(self.publish(package)['status'],'0x1')

    def test_unfinalized_missing_and_forged_content_never_displays_acceptance(self):
        receipt=self.publish(self.package());log=receipt['logs'][0]
        with self.assertRaises(Rejected):inspect_publication(self.rpc,self.contract,log,self.backend,Native(),
            self.app,self.now,int(log['blockNumber'],16)-1)
        for bad in (dict(log,data='0x00'),dict(log,transactionHash='0x'+'ff'*32),dict(log,removed=True)):
            with self.assertRaises(Rejected):self.inspect(bad)

    def test_standalone_revocation_persists_and_prevents_fresh_use(self):
        package=self.package();r=self.publish(package);self.assertEqual(r['status'],'0x1')
        IssuerAdministration(self.state).revoke('42424242')
        with self.assertRaises(Rejected):self.prepare()
        self.assertEqual(self.inspect(r['logs'][0])['credential_status'],'unknown-after-registry-update')
        restarted=PersistentDomainIssuer(self.backend,self.wrap_key,self.definition,Native())
        self.assertNotIn('42424242',restarted.load()[1]._accounts)
        # Re-enrollment still requires the original source/receipt path, not a reset.
        self.held=self.enroll();self.post=dict(self.post,id='87654321-1234-4123-8123-123456789abc')
        self.assertEqual(self.publish(self.package())['status'],'0x1')

    def test_two_encrypted_local_profiles_prove_in_independent_processes_and_drafts_survive(self):
        alice=self.held;bob=self.enroll(account='77777777')
        self.rpc.call('evm_mine')
        profiles=[]
        for name,held in [('alice',alice),('bob',bob)]:
            key=secrets.token_bytes(32);holder=LocalHolder(self.root/name,key)
            holder.save(held.private);holder.refresh(FixtureWitnessClient(self.state),self.backend.public_view())
            draft=b'{"body":"Unpublished local draft","selectedFacts":[]}'
            (holder.root/'drafts.json').write_bytes(draft)
            profiles.append((holder,key,draft))
        for i,(holder,key,draft) in enumerate(profiles):
            if i:self.post=dict(self.post,kind='comment',title=None,thread_id=self.post['id'],
                                id='87654321-1234-4123-8123-123456789abc',body='Reply >>1')
            view=self.backend.public_view();c=challenge(self.post,self.selected,self.app,31337,self.contract,view['sequence'],self.now)
            # No issuer/witness call occurs in the holder subprocess per post.
            proof=prove_in_process(holder.root,key,view,c)
            package=self.verifier.approve(self.post,self.selected,c,proof)
            self.assertEqual(self.publish(package)['status'],'0x1')
            self.assertEqual((holder.root/'drafts.json').read_bytes(),draft)
            self.assertNotIn(b'claims',(holder.root/'credential.enc').read_bytes())
            # Encrypted credential and secret recover after client reconstruction.
            reopened=LocalHolder(holder.root,key);self.assertEqual(reopened.load(),holder.load())
            with self.assertRaises(Exception):LocalHolder(holder.root,secrets.token_bytes(32)).load()
        reader=SharedReader(self.rpc,self.contract,self.backend,self.app,demo_finality=True)
        now=max(self.now,int(self.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16))
        self.assertEqual(len(reader.read(now)),2)
        for holder,key,draft in profiles:self.assertEqual((holder.root/'drafts.json').read_bytes(),draft)

    def test_issuer_finality_violation_latches_until_operator_recovery(self):
        snapshot=self.rpc.call('evm_snapshot')
        self.enroll(account='77777777')
        self.assertTrue(self.rpc.call('evm_revert',snapshot))
        with self.assertRaises(Rejected):self.state.load()
        with self.assertRaises(Rejected):self.state.initialize(self.core)

    def test_publication_bound_rejects_without_truncation_or_nonce_consumption(self):
        self.post=dict(self.post,body='😀'*3000)
        with self.assertRaises(Rejected):self.package()
        self.assertEqual(self.rpc.call('eth_getLogs',{'address':self.contract,'fromBlock':'0x0','toBlock':'latest'}),[])

    def test_signer_clock_rollback_or_expiry_rejects(self):
        c,p=self.prepare()
        for now in (c['created_at']-1,c['expires_at']):
            self.now=now
            with self.assertRaises(Rejected):self.verifier.approve(self.post,self.selected,c,p)

    def test_credential_expiry_checked_even_with_unconsumed_unexpired_receipt(self):
        initial=self.package();expiry=initial['authorization']['credentialExpiry']
        self.now=expiry-30
        package=self.package()
        self.rpc.call('evm_setNextBlockTimestamp',expiry);self.rpc.call('evm_mine')
        self.assertGreater(package['authorization']['deadline'],expiry)
        self.assertEqual(self.publish(package)['status'],'0x0')
        self.assertEqual(int(read(self.rpc,self.contract,'accepted(bytes32)',package['authorization']['submissionId']),16),0)

    def test_two_replacements_for_same_account_commit_only_one(self):
        first,s1,a1=self.enroll(commit=False)
        second,s2,a2=self.enroll(commit=False)
        def commit(session,ack):
            try:self.state.operate('commit',session,ack,NOW+3);return True
            except Rejected:return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda pair:commit(*pair),[(s1,a1),(s2,a2)]))
        self.assertEqual(sum(results),1)
        with self.assertRaises(Rejected):self.prepare()
        winner=first if results[0] else second
        loser=second if results[0] else first
        self.assertEqual(self.publish(self.package(held=winner))['status'],'0x1')
        with self.assertRaises(Rejected):self.prepare(held=loser)

    def test_exact_old_ciphertext_cannot_replace_current_committed_state(self):
        old=self.backend.read()[1]
        self.enroll(account='77777777')
        head=self.backend.head()
        for root in self.replicas.roots:(root/head['ciphertext'][2:]).write_bytes(old)
        with self.assertRaises(ValueError):self.state.load()

    def test_wrapped_keys_recover_same_issuer_and_receipt_identity_without_plaintext_key_files(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        class FixtureKMS:
            def __init__(self):self.cipher=AESGCM(secrets.token_bytes(32))
            def wrap(self,data,context):
                nonce=secrets.token_bytes(12);return nonce+self.cipher.encrypt(nonce,data,context)
            def unwrap(self,data,context):return self.cipher.decrypt(data[:12],data[12:],context)
        kms=FixtureKMS()
        replicas=Replicas([self.root/'wrapped-a',self.root/'wrapped-b'])
        context={'profile':KEY_PROFILE,'definition':self.definition,'application':self.app}
        digest=wrap_service_keys(kms,replicas,context,self.wrap_key,self.signing.key)
        recovered_key,recovered_signer=recover_service_keys(kms,replicas,digest,context,self.rpc,self.contract)
        reopened=PersistentDomainIssuer(self.backend,recovered_key,self.definition,Native())
        self.assertEqual(reopened.load()[1]._issuer,self.state.load()[1]._issuer)
        self.assertEqual(recovered_signer.address,self.signing.address)
        self.signing=recovered_signer
        self.verifier=ReceiptVerifier(self.rpc,self.contract,self.backend,Native(),recovered_signer,self.app,lambda:self.now)
        self.assertEqual(self.publish(self.package())['status'],'0x1')
        for root in replicas.roots:
            for path in root.iterdir():
                self.assertNotIn(self.wrap_key.hex().encode(),path.read_bytes())
        with self.assertRaises(Exception):recover_service_keys(kms,replicas,digest,dict(context,definition='00'*32),self.rpc,self.contract)
        with self.assertRaises(Exception):recover_service_keys(FixtureKMS(),replicas,digest,context,self.rpc,self.contract)

    def test_trusted_signer_forgery_is_detected_by_independent_native_reader(self):
        package=self.package()
        envelope=json.loads(package['proof_envelope'])
        envelope['proof']['proof']['challenge']='00'*32
        package['proof_envelope']=canonical(envelope)
        package['authorization']['proofHash']=sha(package['proof_envelope'])
        # Deliberately model a compromised approved signer. The contract trusts
        # it; independent native proof checking must still refuse the badge.
        package['signature']=self.signing.sign(authorization_digest(package['authorization'],
            self.app,self.definition,31337,self.contract))
        receipt=self.publish(package);self.assertEqual(receipt['status'],'0x1')
        with self.assertRaises(Rejected):self.inspect(receipt['logs'][0])


if __name__=='__main__':unittest.main()
