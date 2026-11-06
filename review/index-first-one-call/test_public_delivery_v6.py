"""Real authored outbox/index; synthetic origin probes and delivery failures."""
import unittest
from unittest.mock import patch
from base_protocol import sha
from public_bundle_v5 import encode
from permissionless_index import submission_data
from public_desktop_v6 import IndexFirstDesktop
import test_public_desktop_v5 as fixture


class DeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixture.PublicDesktopV5Tests.setUpClass()
    def setUp(self):
        self.f=fixture.PublicDesktopV5Tests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.probes=[];self.sent=0;self.fail_restore=False;self.lose_reply=False
        def probe(h,limit):
            self.probes.append(h)
            if self.f.origin.fail:return {'state':'unavailable'}
            raw=self.f.origin.objects.get(h)
            return {'state':'missing'if raw is None else 'present'if sha(raw)==h else 'corrupt'}
        def restore(h,raw):
            self.assertIsNotNone(self.f.index.record_for_hash(h))
            if self.fail_restore:raise OSError('synthetic-origin-write-outage')
            self.f.origin.put(h,raw)
        def submit(h,raw):
            self.sent+=1
            saved=self.desktop()._outbox()['entries'][-1]
            self.assertEqual(encode(saved['bundle']),raw)
            self.assertIsNotNone(saved['last_attempt'])
            self.assertNotIn(h,self.f.origin.objects)
            receipt=self.f.f.rpc.tx(self.f.f.accounts[3],submission_data(h),self.f.f.index)
            if self.lose_reply:raise OSError('synthetic-lost-relay-reply')
            return {'transaction_hash':receipt['transactionHash']}
        from types import SimpleNamespace
        self.relay=SimpleNamespace(submit_bundle=submit)
        self.f.origin.probe=probe;self.f.origin.restore=restore
    def desktop(self):
        return IndexFirstDesktop(self.f.root/'outbox',self.f.author,self.f.index,self.f.content,
            self.f.reader,relay=self.relay,clock=self.f.now)
    def post(self):
        post=self.f.post();self.desktop().prepare(post,{'address':False,'followers_threshold':None},True)
        return post
    def advance(self):self.f.f.rpc.call('evm_increaseTime',400);self.f.f.rpc.call('evm_mine')

    def test_first_public_upload_is_after_final_index_and_exact_bytes_survive_restart(self):
        p=self.post();result=self.desktop().publish(p['id'],True)
        self.assertEqual(result['last_known']['state'],'finalized');self.assertEqual(self.sent,1)
        raw=encode(self.desktop()._outbox()['entries'][0]['bundle']);h=sha(raw)
        self.assertEqual(self.f.origin.objects[h],raw)
        self.advance();del self.f.origin.objects[h]
        self.desktop().check(p['id'])
        self.assertEqual(self.f.origin.objects[h],raw);self.assertEqual(self.sent,1)

    def test_lost_reply_and_origin_outage_keep_newer_draft_and_use_backoff_without_private_keys(self):
        p=self.post();self.lose_reply=True
        with self.assertRaises(OSError):self.desktop().publish(p['id'],True)
        self.post();draft=self.f.author.wallet.read('post.sealed')
        self.f.origin.fail=True
        with patch('wallet.WalletSecretService',side_effect=AssertionError('recovery cannot unlock keys')):
            first=self.desktop().check(p['id'])
            self.assertEqual(first['last_known']['state'],'content-unavailable')
            count=len(self.probes);again=self.desktop().check(p['id'])
            self.assertFalse(again['verification_current']);self.assertEqual(len(self.probes),count)
            self.advance();self.f.origin.fail=False
            result=self.desktop().check(p['id'])
            self.assertEqual(result['last_known']['state'],'finalized')
        self.assertEqual(self.f.author.wallet.read('post.sealed'),draft);self.assertEqual(self.sent,1)

    def test_signed_but_unsent_bundle_is_never_automatically_uploaded(self):
        p=self.post();self.desktop().finish(p['id'])
        r=self.desktop()._outbox()['entries'][0];h=sha(encode(r['bundle']))
        self.f.f.rpc.tx(self.f.f.accounts[2],submission_data(h),self.f.f.index)
        self.desktop().reconcile();self.desktop().check(p['id'])
        self.assertEqual(self.f.origin.puts,0);self.assertNotIn(h,self.f.origin.objects)

    def test_queue_covers_older_unfinished_and_only_latest_five_completed_with_bounded_work(self):
        first=self.post();self.fail_restore=True
        result=self.desktop().publish(first['id'],True)
        self.assertEqual(result['last_known']['state'],'content-unavailable')
        self.fail_restore=False
        for _ in range(7):self.desktop().publish(self.post()['id'],True)
        box=self.desktop()._outbox();wanted=[box['entries'][0],*box['entries'][-5:]]
        for r in wanted:self.f.origin.objects.pop(sha(encode(r['bundle'])),None)
        self.advance();before=self.sent
        checked=[]
        for _ in range(3):checked.extend(self.desktop().reconcile(4))
        self.assertEqual({v['core']['post']['id']for v in checked},{r['core']['post']['id']for r in wanted})
        self.assertTrue(all(sha(encode(r['bundle']))in self.f.origin.objects for r in wanted))
        self.assertEqual(self.sent,before)
