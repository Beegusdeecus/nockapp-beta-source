"""Issuer application, real source TLS and cancellation; synthetic data only."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
import tempfile
import threading
import unittest

from budget import ApiBudget
from domain_issuer import IssuerApplication,RPC
from domain_pipeline import Native,LabDomainIssuer,PendingHolder
from domain_state import TrustedDomainStore,PersistentDomainIssuer,PersistentDomainVerifier
from policy import ProviderClient,Session,Rejected,canonical,evaluate
from test_provider_tls import server,response
from test_zkid import NOW,fixture


class SyntheticProvider:
    budget_enforced=True
    def __init__(self):self.calls=[]
    def resolve(self,username):self.calls.append('resolve');return '42424242'
    def check(self,session,tweet_id,now):
        self.calls.extend(['post','user']);t,u=fixture(session,tweet_id=tweet_id)
        return evaluate(session,tweet_id,canonical(t),canonical(u),now)


class IssuerTests(unittest.TestCase):
    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix='zkid-issuer-synthetic-')
        self.root=Path(self.work.name);self.native=Native();self.initial=LabDomainIssuer(self.native,NOW,20)
        self.backend=TrustedDomainStore(self.root)
        self.state_key=secrets.token_bytes(32)
        self.state=PersistentDomainIssuer(self.backend,self.state_key,self.initial.definition_hash,self.native)
        self.state.initialize(self.initial);self.provider=SyntheticProvider();self.now=NOW
        self.app=IssuerApplication(self.state,self.provider,lambda:self.now)

    def tearDown(self):self.backend.db.close();self.work.cleanup()

    def call(self,op,**body):
        return self.app.dispatch({'id':secrets.token_hex(16),'profile':RPC,'operation':op,'body':body})

    def begin(self):
        holder=PendingHolder.create(self.native,self.initial.public)
        result=self.call('begin',request=holder.request,desktop_nonce=holder.desktop_nonce,username='synthetic_user',
                         approve_public_profile_lookup=True)
        self.assertEqual(result['status'],'ok')
        return holder,Session(**result['result']['session'])

    def issue(self):
        h,s=self.begin();self.now=NOW+2
        result=self.call('check-post',session=s.__dict__,tweet_id='3141592653589793',approve_source_check=True)
        self.assertEqual(result['status'],'ok')
        held,ack=h.receive(result['result'],self.backend.public_view()['public'],s)
        return h,s,held,ack,result['result']

    def test_application_source_to_receipt_and_proof(self):
        _,s,held,ack,_=self.issue()
        self.assertEqual(self.call('commit',session=s.__dict__,ack=ack)['status'],'ok')
        v=PersistentDomainVerifier(self.backend,Native(),self.initial.definition_hash)
        c=v.challenge('ab'*32,['account-controlled','followers-at-least-10000'],NOW+4,identity=True)
        _,core=self.state.load();proof=held.present(core,c)
        self.assertTrue(v.verify(proof,c,NOW+5)['public_id']==held.local_zkid)
        self.assertEqual(self.provider.calls,['resolve','post','user'])

    def test_repeated_check_recovers_without_source_requests(self):
        _,s,_,_,issued=self.issue();before=list(self.provider.calls)
        result=self.call('check-post',session=s.__dict__,tweet_id='3141592653589793',approve_source_check=True)
        self.assertTrue(result['result']==issued);self.assertEqual(self.provider.calls,before)

    def test_invalid_blind_request_costs_no_lookup(self):
        h=PendingHolder.create(self.native,self.initial.public)
        other=PendingHolder.create(self.native,self.initial.public)
        request=copy.deepcopy(h.request)
        # Keep valid lengths/encodings but splice a different hidden message's
        # commitment into this request. Actual possession verification must fail.
        request['blind_signature_context']['commitment']=other.request['blind_signature_context']['commitment']
        result=self.call('begin',request=request,desktop_nonce=h.desktop_nonce,username='synthetic_user',approve_public_profile_lookup=True)
        self.assertEqual(result['status'],'rejected');self.assertEqual(self.provider.calls,[])

    def test_no_consent_costs_no_lookup(self):
        h=PendingHolder.create(self.native,self.initial.public)
        result=self.call('begin',request=h.request,desktop_nonce=h.desktop_nonce,username='synthetic_user',approve_public_profile_lookup=False)
        self.assertEqual(result['code'],'consent-required');self.assertEqual(self.provider.calls,[])

    def test_client_cannot_supply_eligibility_or_a_public_id(self):
        for op,body in [('verify',{'public_id':'forged'}),('stage',{'followers':1}),('provider-get',{'url':'https://example.com'})]:
            self.assertEqual(self.call(op,**body)['status'],'rejected')
        self.assertEqual(self.provider.calls,[])

    def test_abort_after_receipt_is_durable_and_blocks_commit(self):
        _,s,_,ack,_=self.issue();nonce=secrets.token_hex(32)
        result=self.call('abort',session=s.__dict__,nonce=nonce)
        self.assertEqual(result['result']['state'],'aborted')
        self.assertEqual(self.call('commit',session=s.__dict__,ack=ack)['status'],'rejected')
        self.assertEqual(self.call('recover-delivery',session=s.__dict__)['status'],'rejected')
        self.assertEqual(self.call('status',session=s.__dict__,nonce='ab'*32)['result']['state'],'aborted')
        before=list(self.provider.calls)
        self.assertEqual(self.call('check-post',session=s.__dict__,tweet_id='3141592653589793',approve_source_check=True)['status'],'rejected')
        self.assertEqual(self.provider.calls,before)

    def test_lost_begin_reply_recovers_exact_session_without_paid_profile_retry(self):
        holder,session=self.begin();revision=self.backend.read()[0]
        self.app=IssuerApplication(PersistentDomainIssuer(self.backend,self.state_key,self.initial.definition_hash,self.native),
                                   self.provider,lambda:self.now)
        again=self.call('begin',request=holder.request,desktop_nonce=holder.desktop_nonce,username='synthetic_user',
                        approve_public_profile_lookup=True)
        self.assertEqual(again['status'],'ok');self.assertEqual(again['result']['session'],session.__dict__)
        self.assertEqual(self.provider.calls,['resolve']);self.assertEqual(self.backend.read()[0],revision)

    def test_aborted_begin_cannot_be_silently_restarted_with_same_request(self):
        holder,session=self.begin();self.call('abort',session=session.__dict__,nonce='12'*32)
        again=self.call('begin',request=holder.request,desktop_nonce=holder.desktop_nonce,username='synthetic_user',
                        approve_public_profile_lookup=True)
        self.assertEqual(again['status'],'rejected');self.assertEqual(self.provider.calls,['resolve'])

    def test_expired_begin_requires_explicit_new_request_not_paid_retry(self):
        holder,_=self.begin();self.now=NOW+601
        again=self.call('begin',request=holder.request,desktop_nonce=holder.desktop_nonce,username='synthetic_user',
                        approve_public_profile_lookup=True)
        self.assertEqual(again['status'],'rejected');self.assertEqual(self.provider.calls,['resolve'])

    def test_same_begin_with_raced_stable_account_is_rejected(self):
        holder,_=self.begin()
        with self.assertRaisesRegex(Rejected,'source-account-mismatch'):
            self.state.operate('begin',holder.request,holder.desktop_nonce,'51515151','synthetic_user',NOW)
        self.assertEqual(len(self.state.load()[1]._pending),1)

    def test_new_nonce_still_generates_explicit_fresh_replacement_session(self):
        holder,session=self.begin()
        result=self.call('begin',request=holder.request,desktop_nonce='12'*32,username='synthetic_user',
                         approve_public_profile_lookup=True)
        self.assertEqual(result['status'],'ok');self.assertNotEqual(result['result']['session'],session.__dict__)
        self.assertEqual(self.provider.calls,['resolve','resolve'])

    def test_abort_committed_registration_is_rejected(self):
        _,s,_,ack,_=self.issue();self.call('commit',session=s.__dict__,ack=ack)
        self.assertEqual(self.call('abort',session=s.__dict__,nonce='ab'*32)['code'],'registration-already-committed')
        self.assertEqual(self.call('status',session=s.__dict__,nonce='ab'*32)['result']['state'],'committed')

    def test_expired_registration_can_be_irreversibly_aborted(self):
        _,s=self.begin();self.now=NOW+601
        self.assertEqual(self.call('status',session=s.__dict__,nonce='ab'*32)['result']['state'],'expired')
        self.assertEqual(self.call('abort',session=s.__dict__,nonce='cd'*32)['result']['state'],'aborted')

    def test_duplicate_fields_and_raw_error_text_not_reflected(self):
        raw=b'{"id":"'+b'a'*32+b'","id":"'+b'b'*32+b'","profile":"'+RPC.encode()+b'","operation":"registry","body":{}}'
        self.assertEqual(json.loads(self.app.dispatch_bytes(raw))['status'],'rejected')
        self.provider.resolve=lambda _:(_ for _ in ()).throw(RuntimeError('SYNTHETIC-PRIVATE-DIAGNOSTIC'))
        h=PendingHolder.create(self.native,self.initial.public)
        result=self.call('begin',request=h.request,desktop_nonce=h.desktop_nonce,username='synthetic_user',approve_public_profile_lookup=True)
        self.assertTrue(b'SYNTHETIC-PRIVATE-DIAGNOSTIC' not in canonical(result))
        self.provider.resolve=lambda _:(_ for _ in ()).throw(Rejected({'private':'SYNTHETIC-PRIVATE-DIAGNOSTIC'}))
        result=self.call('begin',request=h.request,desktop_nonce=h.desktop_nonce,username='synthetic_user',approve_public_profile_lookup=True)
        self.assertEqual(result['code'],'issuer-operation-failed')
        self.assertTrue(b'SYNTHETIC-PRIVATE-DIAGNOSTIC' not in canonical(result))

    def test_actual_tls_provider_resolve_and_stage_with_budget(self):
        budget=ApiBudget(self.root/'synthetic-budget');self.addCleanup(budget.db.close)
        ready=threading.Event();shared={}
        author={'type':'user','id':'42424242','userName':'synthetic_user','followers':10000,'protected':False,'unavailable':False}
        def responses():
            yield response(canonical({'status':'success','data':author}))
            if not ready.wait(3):return
            t,u=fixture(shared['session'])
            yield response(canonical(t));yield response(canonical(u))
        with server(responses()) as (context,dial,seen):
            self.app.provider=ProviderClient('synthetic-research-key',context,dial,budget=budget)
            h,s=self.begin();shared['session']=s;ready.set();self.now=NOW+2
            issued=self.call('check-post',session=s.__dict__,tweet_id='3141592653589793',approve_source_check=True)
            self.assertEqual(issued['status'],'ok')
            _,ack=h.receive(issued['result'],self.backend.public_view()['public'],s)
            self.assertEqual(self.call('commit',session=s.__dict__,ack=ack)['status'],'ok')
            self.assertEqual(len(seen),3)
        self.assertEqual(budget.public_summary()['reserved_request_count'],3)

    def test_abort_replacement_preserves_incumbent(self):
        _,s,old,ack,_=self.issue();self.call('commit',session=s.__dict__,ack=ack)
        _,new_s,new,new_ack,_=self.issue()
        self.assertEqual(self.call('abort',session=new_s.__dict__,nonce='ab'*32)['result']['state'],'aborted')
        v=PersistentDomainVerifier(self.backend,Native(),self.initial.definition_hash)
        c=v.challenge('ab'*32,['account-controlled'],NOW+4,identity=True)
        _,core=self.state.load();self.assertTrue(v.verify(old.present(core,c),c,NOW+5)['public_id_bound'])
        with self.assertRaises(Rejected):new.present(core,v.challenge('cd'*32,['account-controlled'],NOW+4,identity=True))

    def test_concurrent_abort_and_commit_have_one_winner(self):
        _,s,_,ack,_=self.issue();barrier=threading.Barrier(2)
        def run(op):
            backend=TrustedDomainStore(self.root)
            state=PersistentDomainIssuer(backend,self.state_key,self.initial.definition_hash,self.native)
            original=backend.compare_exchange
            def exchange(*args):barrier.wait(timeout=10);return original(*args)
            backend.compare_exchange=exchange
            try:
                if op=='commit':state.operate(op,s,ack,NOW+5)
                else:state.operate(op,s,'ab'*32,NOW+5)
                return op
            except Rejected:return None
            finally:backend.db.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(run,op) for op in ['abort','commit']]
            winners=[v for v in (f.result(timeout=15) for f in futures) if v]
        self.assertEqual(len(winners),1)
        result=self.call('status',session=s.__dict__,nonce='cd'*32)['result']['state']
        self.assertEqual(result,'committed' if winners[0]=='commit' else 'aborted')

    def test_provider_budget_is_required(self):
        provider=SyntheticProvider();provider.budget_enforced=False
        with self.assertRaisesRegex(Rejected,'provider-budget-required'):IssuerApplication(self.state,provider,lambda:NOW)

    def test_failed_reserved_signature_is_not_queried_again(self):
        h,s=self.begin();self.now=NOW+2
        from unittest.mock import patch
        original=self.native.call
        def fail(op,**body):
            if op=='stage':raise Rejected('domain-native-rejected')
            return original(op,**body)
        with patch.object(self.native,'call',side_effect=fail):
            self.assertEqual(self.call('check-post',session=s.__dict__,tweet_id='3141592653589793',approve_source_check=True)['status'],'rejected')
        before=list(self.provider.calls)
        self.assertEqual(self.call('status',session=s.__dict__,nonce='ab'*32)['result']['state'],'failed')
        self.assertEqual(self.call('check-post',session=s.__dict__,tweet_id='3141592653589793',approve_source_check=True)['status'],'rejected')
        self.assertEqual(self.provider.calls,before)
