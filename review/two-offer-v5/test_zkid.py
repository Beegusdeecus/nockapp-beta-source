"""Synthetic-only adversarial acceptance. Never touches real accounts/keyrings."""
import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tempfile
import time
import unittest

from credential import Crypto, LabIssuer, LabVerifier, Pending, production_readiness
from policy import PROFILE, POLICY_HASH, Rejected, Session, canonical, evaluate, strict_json

NOW = 1793011200


def fixture(session, *, followers=10000, tweet_id='3141592653589793'):
    author = {'type':'user', 'id':session.account_id, 'userName':session.username,
              'followers':followers, 'protected':False, 'unavailable':False}
    post = {'type':'tweet', 'id':tweet_id, 'text':session.post_text, 'author':author,
            'createdAt':datetime.fromtimestamp(session.created_at + 1,timezone.utc).strftime('%a %b %d %H:%M:%S %z %Y'),
            'isReply':False, 'retweeted_tweet':None, 'quoted_tweet':None}
    return {'status':'success','code':0,'tweets':[post]}, {'status':'success','data':copy.deepcopy(author)}


class ZkidTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto = Crypto()
        cls.issuer = LabIssuer(cls.crypto)
        cls.pending = Pending.create(cls.crypto)
        cls.session = cls.issuer.begin(cls.pending.commitment, '424242424242', 'synthetic_user', NOW, desktop_nonce=cls.pending.nonce)
        t,u = fixture(cls.session)
        cls.attributes, cls.signature = cls.issuer.issue_fixture(cls.session, '3141592653589793',canonical(t),canonical(u),NOW+2)
        cls.credential = cls.pending.accept(cls.crypto,cls.issuer.public_key,cls.attributes,cls.signature)

    def setup_presentation(self, facts=None):
        verifier = LabVerifier(self.crypto,self.issuer.public_key)
        challenge = verifier.challenge('ab'*32, facts or ['account-controlled'], NOW+3)
        presentation = self.credential.present(self.crypto,challenge)
        return verifier,challenge,presentation

    def assert_policy_rejects(self, change, *, target='tweet', now=NOW+2):
        tweet,user = fixture(self.session)
        change(tweet if target == 'tweet' else user)
        with self.assertRaises(Rejected):
            evaluate(self.session,'3141592653589793',canonical(tweet),canonical(user),now)

    def test_01_actual_blind_signature_and_local_proof(self):
        v,c,p = self.setup_presentation(['account-controlled','followers-at-least-10000'])
        result = v.verify(p,c,NOW+4)
        self.assertTrue(result['cryptographic_proof_valid'])
        self.assertFalse(result['verified'])
        self.assertFalse(result['hardware_verified'])
        self.assertEqual(result['facts'],['account-controlled','followers-at-least-10000'])

    def test_02_copied_credential_without_secret_cannot_prove(self):
        v,c,_ = self.setup_presentation()
        bad = copy.copy(self.credential)
        bad.secret = secrets.token_hex(32)
        with self.assertRaises(Rejected):
            v.verify(bad.present(self.crypto,c),c,NOW+4)

    def test_03_wrong_blinding_cannot_prove(self):
        v,c,_ = self.setup_presentation()
        bad = copy.copy(self.credential)
        bad.blinding = '00'*32
        with self.assertRaises(Rejected):
            v.verify(bad.present(self.crypto,c),c,NOW+4)

    def test_04_altered_signed_predicate_rejected(self):
        bad = copy.deepcopy(self.credential)
        bad.attributes[5] = '0'
        with self.assertRaises(Rejected):
            self.pending.accept(self.crypto,bad.issuer_key,bad.attributes,bad.signature)

    def test_05_presentations_randomized(self):
        v,c,p = self.setup_presentation()
        second = self.credential.present(self.crypto,c)
        self.assertNotEqual(p['proof'],second['proof'])
        v.verify(second,c,NOW+4)

    def test_06_public_projection_hides_secret_identity_signature_count(self):
        _,_,p = self.setup_presentation()
        rendered = canonical(p)
        for value in [self.pending.secret,self.pending.blinding,self.pending.commitment,
                      self.pending.local_zkid,self.signature,self.session.account_id,self.session.username,'10000']:
            self.assertNotIn(('"'+value+'"').encode(),rendered)
        self.assertNotIn(6,p['disclose'])
        self.assertNotIn('secret',repr(self.credential))
        self.assertNotIn('secret',repr(self.pending))

    def test_07_threshold_boundary_is_at_least(self):
        for count, expected in [(0,'0'),(9999,'0'),(10000,'1'),(10001,'1')]:
            t,u=fixture(self.session,followers=count)
            self.assertEqual(evaluate(self.session,'3141592653589793',canonical(t),canonical(u),NOW+2)[6],expected)

    def test_08_wrong_post_author(self):
        self.assert_policy_rejects(lambda t:t['tweets'][0]['author'].update(id='111'))

    def test_09_other_account_metrics(self):
        self.assert_policy_rejects(lambda u:u['data'].update(id='111'),target='user')

    def test_10_wrong_post(self):
        self.assert_policy_rejects(lambda t:t['tweets'][0].update(id='111'))

    def test_11_wrong_challenge(self):
        self.assert_policy_rejects(lambda t:t['tweets'][0].update(text='NockApp account verification: '+'0'*64))

    def test_12_old_post(self):
        self.assert_policy_rejects(lambda t:t['tweets'][0].update(createdAt='Mon Oct 26 00:00:00 +0000 2020'))

    def test_13_future_post(self):
        self.assert_policy_rejects(lambda t:t['tweets'][0].update(createdAt='Mon Oct 26 00:00:00 +0000 2030'))

    def test_14_expired_session(self):
        self.assert_policy_rejects(lambda t:None,now=NOW+601)

    def test_15_reposted_or_quoted_challenge(self):
        for field in ['retweeted_tweet','quoted_tweet']:
            self.assert_policy_rejects(lambda t:t['tweets'][0].update({field:{'text':self.session.post_text}}))

    def test_16_http200_error_is_not_success(self):
        self.assert_policy_rejects(lambda u:u.update(status='error'),target='user')

    def test_17_suspended_or_protected_user(self):
        for field in ['unavailable','protected']:
            self.assert_policy_rejects(lambda u:u['data'].update({field:True}),target='user')

    def test_18_malformed_count(self):
        for value in [True,-1,'10000',10000.0,None,2**53]:
            self.assert_policy_rejects(lambda u:u['data'].update(followers=value),target='user')

    def test_19_duplicate_json_key(self):
        with self.assertRaises(Rejected):
            strict_json(b'{"status":"error","status":"success"}')

    def test_20_json_size_depth_nonfinite(self):
        for data in [b' '*131073,b'{"x":NaN}',b'{"x":'+b'['*30+b'0'+b']'*30+b'}']:
            with self.assertRaises(Rejected): strict_json(data)

    def test_21_challenge_binds_blinded_request(self):
        changed=replace(self.session,commitment='0'*288)
        self.assertNotEqual(self.session.post_text,changed.post_text)
        t,u=fixture(self.session)
        with self.assertRaises(Rejected):
            evaluate(changed,'3141592653589793',canonical(t),canonical(u),NOW+2)

    def test_22_challenge_binds_issuer_and_account(self):
        for fields in [{'issuer_key':'0'*192},{'account_id':'111'},{'nonce':'0'*64}]:
            self.assertNotEqual(self.session.post_text,replace(self.session,**fields).post_text)

    def test_23_issuance_single_use(self):
        t,u=fixture(self.session)
        with self.assertRaisesRegex(Rejected,'issuance-replay'):
            self.issuer.issue_fixture(self.session,'3141592653589793',canonical(t),canonical(u),NOW+2)

    def test_24_only_one_active_credential_per_account_in_lab(self):
        p=Pending.create(self.crypto)
        s=self.issuer.begin(p.commitment,self.session.account_id,self.session.username,NOW+3,desktop_nonce=p.nonce)
        t,u=fixture(s)
        with self.assertRaisesRegex(Rejected,'account-already-active'):
            self.issuer.issue_fixture(s,'3141592653589793',canonical(t),canonical(u),NOW+5)

    def test_25_issuance_cannot_substitute_registered_session(self):
        s=replace(self.session,nonce='0'*64)
        t,u=fixture(s)
        with self.assertRaisesRegex(Rejected,'issuance-replay'):
            self.issuer.issue_fixture(s,'3141592653589793',canonical(t),canonical(u),NOW+2)

    def test_26_failed_check_does_not_consume_session(self):
        p=Pending.create(self.crypto)
        s=self.issuer.begin(p.commitment,'777777','synthetic_user',NOW,desktop_nonce=p.nonce)
        t,u=fixture(s)
        bad=copy.deepcopy(u);bad['data']['id']='111'
        with self.assertRaises(Rejected):
            self.issuer.issue_fixture(s,'3141592653589793',canonical(t),canonical(bad),NOW+2)
        a,sig=self.issuer.issue_fixture(s,'3141592653589793',canonical(t),canonical(u),NOW+2)
        p.accept(self.crypto,self.issuer.public_key,a,sig)

    def test_27_unauthorized_issuer(self):
        v,c,p=self.setup_presentation()
        p['issuer_key']=self.crypto.call('keygen')['public_key']
        with self.assertRaisesRegex(Rejected,'issuer-not-approved'):v.verify(p,c,NOW+4)

    def test_28_wrong_scope_nonce_or_facts(self):
        v,c,p=self.setup_presentation()
        for field,value in [('scope','bc'*32),('nonce','00'*32),('facts',['followers-at-least-10000'])]:
            changed={**c,field:value}
            with self.assertRaises(Rejected):v.verify(p,changed,NOW+4)
        v.verify(p,c,NOW+4)

    def test_29_proof_cannot_move_to_fresh_challenge(self):
        v,c,p=self.setup_presentation()
        fresh=v.challenge(c['scope'],c['facts'],NOW+3)
        with self.assertRaisesRegex(Rejected,'crypto-rejected'):v.verify(p,fresh,NOW+4)

    def test_30_action_replay(self):
        v,c,p=self.setup_presentation();v.verify(p,c,NOW+4)
        with self.assertRaises(Rejected):v.verify(p,c,NOW+4)

    def test_31_action_expiry(self):
        v,c,p=self.setup_presentation()
        with self.assertRaisesRegex(Rejected,'action-expired'):v.verify(p,c,NOW+64)

    def test_32_credential_expiry(self):
        v=LabVerifier(self.crypto,self.issuer.public_key)
        now=int(self.attributes[4])
        c=v.challenge('ab'*32,['account-controlled'],now)
        with self.assertRaisesRegex(Rejected,'credential-expired'):v.verify(self.credential.present(self.crypto,c),c,now)

    def test_33_epoch_key_revocation(self):
        v,c,p=self.setup_presentation()
        v.revoked=frozenset([self.issuer.public_key])
        with self.assertRaisesRegex(Rejected,'issuer-revoked'):v.verify(p,c,NOW+4)

    def test_34_corrupted_proof_and_invalid_lengths(self):
        v,c,p=self.setup_presentation()
        original=p['proof']
        for proof in [original[:-2],original+'00','00'+original[2:],'ff'*4000]:
            p['proof']=proof
            with self.assertRaises(Rejected):v.verify(p,c,NOW+4)

    def test_35_proof_policy_and_disclosure_tampering(self):
        v,c,p=self.setup_presentation()
        bad=copy.deepcopy(p);bad['attributes'][2]='0'*64
        with self.assertRaises(Rejected):v.verify(bad,c,NOW+4)
        bad=copy.deepcopy(p);bad['disclose']=[0,1,2,3,4,6]
        with self.assertRaises(Rejected):v.verify(bad,c,NOW+4)

    def test_36_false_threshold_not_disclosable_as_true(self):
        issuer=LabIssuer(self.crypto);pending=Pending.create(self.crypto)
        session=issuer.begin(pending.commitment,'999999','synthetic_user',NOW,desktop_nonce=pending.nonce)
        t,u=fixture(session,followers=9999)
        a,s=issuer.issue_fixture(session,'3141592653589793',canonical(t),canonical(u),NOW+2)
        cred=pending.accept(self.crypto,issuer.public_key,a,s)
        v=LabVerifier(self.crypto,issuer.public_key)
        c=v.challenge('ab'*32,['followers-at-least-10000'],NOW+3)
        with self.assertRaisesRegex(Rejected,'fact-unavailable'):cred.present(self.crypto,c)
        # Forging the locally saved bit still cannot forge the issuer signature.
        cred.attributes[6]='1'
        with self.assertRaises(Rejected):v.verify(cred.present(self.crypto,c),c,NOW+4)

    def test_37_persistent_action_replay_after_restart(self):
        with tempfile.TemporaryDirectory(prefix='nockapp-zkid-synthetic-') as td:
            path=Path(td)/'actions.sqlite'
            v=LabVerifier(self.crypto,self.issuer.public_key,str(path))
            c=v.challenge('ab'*32,['account-controlled'],NOW+3)
            p=self.credential.present(self.crypto,c);v.verify(p,c,NOW+4);v.db.close()
            again=LabVerifier(self.crypto,self.issuer.public_key,str(path))
            with self.assertRaises(Rejected):again.verify(p,c,NOW+4)
            again.db.close()

    def test_38_malformed_primitive_does_not_dump_inputs(self):
        binary=self.crypto._binary
        sentinel='SYNTHETIC-PRIVATE-MARKER'
        for data in [canonical({'op':'prepare','secret':sentinel}),b'{',b'x'*32769,
                     canonical({'op':'keygen','unexpected':sentinel})]:
            r=subprocess.run([str(binary)],input=data,capture_output=True,timeout=5)
            self.assertNotEqual(r.returncode,0)
            self.assertEqual(r.stderr,b'')
            self.assertEqual(json.loads(r.stdout),{'error':'crypto-rejected'})
            self.assertNotIn(sentinel.encode(),r.stdout)

    def test_39_production_is_unavailable(self):
        result=production_readiness()
        self.assertFalse(result['ready'])
        self.assertGreaterEqual(len(result['blockers']),5)

    def test_40_refresh_after_expiry_and_replay_policy(self):
        now=int(self.attributes[4])
        pending=Pending.create(self.crypto,secret=self.pending.secret)
        session=self.issuer.begin(pending.commitment,self.session.account_id,self.session.username,now,desktop_nonce=pending.nonce)
        t,u=fixture(session)
        a,s=self.issuer.issue_fixture(session,'3141592653589793',canonical(t),canonical(u),now+2)
        fresh=pending.accept(self.crypto,self.issuer.public_key,a,s)
        self.assertEqual(pending.local_zkid,self.pending.local_zkid)
        self.assertGreater(int(fresh.attributes[4]),int(self.attributes[4]))


if __name__ == '__main__':
    unittest.main()
