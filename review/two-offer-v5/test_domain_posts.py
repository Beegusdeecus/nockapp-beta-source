"""Actual native post proofs; SDK transactions/source/account are synthetic.

The managed fixture is NOT AWS/IAM acceptance. No wallet/keyring/cloud access.
"""
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from domain_authority import DynamoIssuerStore,role_policies
from domain_post_authority import DynamoPostActions
from domain_pipeline import Native,LabDomainIssuer,PendingHolder
from domain_state import PersistentDomainIssuer
from domain_posts import PostVerifier,PostProofArchive,observation
from policy import Rejected,canonical,digest
from post_scope import scope,payload
from test_domain_authority import TransactionSDK
from test_zkid import NOW,fixture


def post():
    return {'kind':'thread','id':'12345678-1234-4123-8123-123456789abc','created_at':NOW*1000,
            'thread_id':None,'title':'Synthetic post','body':'Explicitly chosen facts. 😀 Café\nsecond line',
            'references':[['https://x.com/i/status/3141592653589793','3141592653589793']],
            'claims':[['followers-10k',None]]}


class PostFixture(unittest.TestCase):
    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix='zkid-posts-');self.root=Path(self.work.name)
        self.sdk=TransactionSDK();self.native=Native();self.core=LabDomainIssuer(self.native,NOW,12)
        self.namespace=self.core.definition_hash;self.writer=DynamoIssuerStore(self.sdk,'synthetic',self.namespace)
        self.state=PersistentDomainIssuer(self.writer,secrets.token_bytes(32),self.namespace,self.native)
        self.state.initialize(self.core);self.actions=DynamoPostActions(self.sdk,'synthetic',self.namespace)
        self.archive=PostProofArchive(self.root/'archive');self.now=NOW+4
        self.verifier=PostVerifier(self.actions,Native(),self.namespace,'ab'*32,self.archive,lambda:self.now)
        self.held=self.enroll();self.post=post();self.facts=['account-controlled','followers-at-least-10000']

    def tearDown(self):self.work.cleanup()

    def enroll(self,followers=10000):
        _,core=self.state.load();holder=PendingHolder.create(Native(),core.public)
        session=self.state.operate('begin',holder.request,holder.desktop_nonce,'42424242','synthetic_user',NOW)
        t,u=fixture(session,followers=followers)
        issued=self.state.operate('stage_fixture',session,'3141592653589793',canonical(t),canonical(u),NOW+2)
        _,core=self.state.load();held,ack=holder.receive(issued,core.public,session)
        self.state.operate('commit',session,ack,NOW+3);return held

    def prepared(self,facts=None):
        selected=facts or self.facts;challenge=self.verifier.challenge(self.post,selected)
        _,core=self.state.load();proof=self.held.present(core,challenge)
        return challenge,proof

    def accept(self):
        c,p=self.prepared();r=self.verifier.accept(self.post,self.facts,c['nonce'],p);return c,p,r

class PostTests(PostFixture):
    def test_actual_joint_selective_proof_consumed_and_archived_without_identity(self):
        c,p,r=self.accept();self.assertIsNone(p['claimed_id']);self.assertTrue(r['fresh']);self.assertFalse(r['verified'])
        self.assertTrue(self.actions.action_record(c['nonce'])[1]);receipt=self.actions.acceptance(c['nonce'])
        self.assertEqual(receipt['proof_sha256'],digest(p));self.assertEqual(observation(p),(receipt['observed_at'],receipt['expires_at']))
        with self.assertRaises(Rejected):self.verifier.accept(self.post,self.facts,c['nonce'],p)
        action=self.sdk.rows[('synthetic',self.namespace+':action:'+c['nonce'])]
        metadata=action['body']['B']+action['receipt']['B']
        self.assertNotIn(b'claimed_id',metadata);self.assertNotIn(b'public_input',metadata)

    def test_archival_check_after_challenge_expiry_is_not_fresh_authorization(self):
        c,p,_=self.accept();self.now+=120
        reopened=PostVerifier(DynamoPostActions(self.sdk,'synthetic',self.namespace),Native(),self.namespace,'ab'*32,
                              PostProofArchive(self.root/'archive'),lambda:self.now)
        r=reopened.inspect(self.post,self.facts,c['nonce']);self.assertTrue(r['archival_only']);self.assertFalse(r['fresh'])
        self.assertFalse(r['verified']);self.assertNotIn('public_id',r)
        with self.assertRaises(Rejected):reopened.accept(self.post,self.facts,c['nonce'],p)

    def test_post_edits_copied_reference_fact_selection_and_audience_rejected(self):
        c,_,_=self.accept()
        for field,value in [('id','87654321-1234-4123-8123-123456789abc'),('title','Changed'),('body','Changed'),
                            ('created_at',NOW*1000+1),('references',[]),('claims',[])]:
            with self.subTest(field=field),self.assertRaises(Rejected):
                self.verifier.inspect(dict(self.post,**{field:value}),self.facts,c['nonce'])
        with self.assertRaises(Rejected):self.verifier.inspect(self.post,['account-controlled'],c['nonce'])
        other=PostVerifier(self.actions,Native(),self.namespace,'cd'*32,self.archive,lambda:self.now)
        with self.assertRaises(Rejected):other.inspect(self.post,self.facts,c['nonce'])

    def test_false_follower_claim_rejects_but_single_control_fact_succeeds(self):
        self.held=self.enroll(followers=9999);c,p=self.prepared()
        with self.assertRaises(Rejected):self.verifier.accept(self.post,self.facts,c['nonce'],p)
        self.assertIsNone(self.actions.acceptance(c['nonce']))
        c,p=self.prepared(['account-controlled'])
        self.verifier.accept(self.post,['account-controlled'],c['nonce'],p)

    def test_bad_proof_does_not_burn_nonce_or_write_archive(self):
        c,p=self.prepared();p['claimed_id']='not-a-point'
        with self.assertRaises(Rejected):self.verifier.accept(self.post,self.facts,c['nonce'],p)
        self.assertFalse(self.actions.action_record(c['nonce'])[1]);self.assertEqual(list(self.archive.root.iterdir()),[])

    def test_archive_write_failure_never_consumes(self):
        c,p=self.prepared()
        with patch.object(self.archive,'save',side_effect=OSError('synthetic')):
            with self.assertRaises(OSError):self.verifier.accept(self.post,self.facts,c['nonce'],p)
        self.assertFalse(self.actions.action_record(c['nonce'])[1])

    def test_managed_commit_succeeds_lost_reply_recovers_only_archival_status(self):
        c,p=self.prepared();original=self.actions.consume_post
        def lost(*args):original(*args);raise Rejected('synthetic-lost-reply')
        with patch.object(self.actions,'consume_post',side_effect=lost):
            with self.assertRaises(Rejected):self.verifier.accept(self.post,self.facts,c['nonce'],p)
        self.assertTrue(self.verifier.inspect(self.post,self.facts,c['nonce'])['archival_only'])
        with self.assertRaises(Rejected):self.verifier.accept(self.post,self.facts,c['nonce'],p)

    def test_archive_tamper_missing_and_symlink_rejected(self):
        c,p,_=self.accept();path=self.archive._path(c['nonce']);original=path.read_bytes()
        path.write_bytes(original.replace(b'claimed_id',b'changed_id'))
        with self.assertRaises(Rejected):self.verifier.inspect(self.post,self.facts,c['nonce'])
        path.unlink()
        with self.assertRaises(FileNotFoundError):self.verifier.inspect(self.post,self.facts,c['nonce'])
        outside=self.root/'not-an-archive';outside.write_bytes(original);path.symlink_to(outside)
        with self.assertRaises(OSError):self.verifier.inspect(self.post,self.facts,c['nonce'])

    def test_source_expiry_and_clock_rollback_reject_archival_check(self):
        c,_,_=self.accept();receipt=self.actions.acceptance(c['nonce'])
        for now in (receipt['expires_at'],receipt['accepted_at']-1):
            self.now=now
            with self.assertRaises(Rejected):self.verifier.inspect(self.post,self.facts,c['nonce'])

    def test_replacement_invalidates_old_archival_proof_and_new_holder_works(self):
        c,_,_=self.accept();self.held=self.enroll()
        with self.assertRaises(Rejected):self.verifier.inspect(self.post,self.facts,c['nonce'])
        self.accept()

    def test_atomic_root_condition_rejects_revocation_during_acceptance(self):
        c,p=self.prepared();original=self.actions.consume_post
        def revoke(*args):self.enroll();return original(*args)
        with patch.object(self.actions,'consume_post',side_effect=revoke):
            with self.assertRaises(Rejected):self.verifier.accept(self.post,self.facts,c['nonce'],p)
        self.assertFalse(self.actions.action_record(c['nonce'])[1]);self.assertIsNone(self.actions.acceptance(c['nonce']))

    def test_revocation_during_archival_crypto_recheck_rejects(self):
        c,_,_=self.accept();native=self.verifier.native;original=native.call
        def revoked(op,**body):result=original(op,**body);self.enroll();return result
        with patch.object(native,'call',side_effect=revoked):
            with self.assertRaises(Rejected):self.verifier.inspect(self.post,self.facts,c['nonce'])

    def test_concurrent_acceptance_consumes_exactly_once(self):
        c,p=self.prepared()
        def run():
            v=PostVerifier(DynamoPostActions(self.sdk,'synthetic',self.namespace),Native(),self.namespace,'ab'*32,
                           PostProofArchive(self.root/'archive'),lambda:self.now)
            try:v.accept(self.post,self.facts,c['nonce'],p);return True
            except Rejected:return False
        with ThreadPoolExecutor(max_workers=2) as pool:self.assertEqual(sum(pool.map(lambda _:run(),range(2))),1)

    def test_no_receiptless_consume_and_no_private_issuer_methods(self):
        c,_=self.prepared()
        with self.assertRaises(Rejected):self.actions.consume_action(c)
        self.assertFalse(hasattr(self.actions,'read'));self.assertFalse(hasattr(self.actions,'compare_exchange'))

    def test_delayed_archive_reaches_deadline_without_consuming(self):
        c,p=self.prepared();original=self.archive.save
        def delayed(*args):original(*args);self.now=c['expires_at']
        with patch.object(self.archive,'save',side_effect=delayed):
            with self.assertRaises(Rejected):self.verifier.accept(self.post,self.facts,c['nonce'],p)
        self.assertFalse(self.actions.action_record(c['nonce'])[1])

    def test_javascript_utf8_scope_payload_matches_unicode_and_comments(self):
        values=[self.post,dict(self.post,kind='comment',title=None,thread_id=self.post['id']),
                dict(self.post,kind='comment',title=None,thread_id='legacy-thread-a'),
                dict(self.post,body='\u0085not trimmed by JavaScript\u0085')]
        for p in values:
            source="const p=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(["+json.dumps('NOCKAPP/ZKID/POST-SCOPE/v1')+",...['kind','id','created_at','thread_id','title','body','references','claims'].map(k=>p[k])]));"
            actual=subprocess.run(['/usr/bin/node','-e',source],input=canonical(p),capture_output=True,check=True).stdout
            self.assertEqual(payload(p),actual)

    def test_strict_post_schema_rejects_private_extras_and_malformed_identity(self):
        for changed in [dict(self.post,eligibility=True),dict(self.post,id='wrong'),dict(self.post,created_at=True),
                        dict(self.post,body=' padded '),dict(self.post,body='\ufeffpadded'),dict(self.post,body='😀'*3001),
                        dict(self.post,body='\ud800'),dict(self.post,claims=[['unknown',None]])]:
            with self.assertRaises(Rejected):scope(changed,'ab'*32)

    def test_metadata_tamper_and_unconsumed_receipt_never_authorizes_inspection(self):
        c,p=self.prepared();self.archive.save(c['nonce'],p)
        with self.assertRaises(Rejected):self.verifier.inspect(self.post,self.facts,c['nonce'])
        self.verifier.accept(self.post,self.facts,c['nonce'],p)
        row=self.sdk.rows[('synthetic',self.namespace+':action:'+c['nonce'])]
        receipt=json.loads(row['receipt']['B']);receipt['proof_sha256']='ab'*32;row['receipt']['B']=canonical(receipt)
        with self.assertRaises(Rejected):self.verifier.inspect(self.post,self.facts,c['nonce'])
