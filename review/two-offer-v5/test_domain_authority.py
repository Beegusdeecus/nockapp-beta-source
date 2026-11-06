"""Managed transaction protocol/native proofs; in-memory SDK is NOT AWS/IAM.

The fake evaluates conditions against a locked before-image and publishes only
after all conditions pass. TLS/SDK serialization is exercised separately below.
No table/resource, subscription or real account is used.
"""
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import re
import secrets
import threading
import unittest
from unittest.mock import patch

from aws_transport import AwsFailure,AwsJsonClient
from domain_authority import DynamoIssuerStore,DynamoActionStore,DynamoBudget,role_policies,authority_identity
from domain_pipeline import Native,LabDomainIssuer,PendingHolder,definition_hash
from domain_state import PersistentDomainIssuer,PersistentDomainVerifier
from policy import Rejected,canonical
from test_aws_transport import credentials,REGION,check_signature
from test_provider_tls import server,response
from test_zkid import NOW,fixture


class TransactionSDK:
    def __init__(self):
        self.rows={};self.calls=[];self.lock=threading.RLock();self.after_commit=None

    @staticmethod
    def key(arguments):return (arguments['TableName'],(arguments.get('Key') or arguments['Item'])['id']['S'])

    def condition(self,arguments,rows):
        row=rows.get(self.key(arguments),{});names=arguments.get('ExpressionAttributeNames',{})
        values=arguments.get('ExpressionAttributeValues',{})
        def get(token):return values[token] if token.startswith(':') else row.get(names[token])
        for clause in arguments.get('ConditionExpression','').split(' AND '):
            if not clause:continue
            match=re.fullmatch(r'attribute_(not_exists|exists)\((#[a-z]+)\)',clause)
            if match:
                exists=names[match[2]] in row
                if exists != (match[1]=='exists'):return False
            else:
                match=re.fullmatch(r'(#[a-z]+) (=|<=) (:[a-z]+)',clause)
                if not match:raise AssertionError('unrecognized fixture condition')
                left,right=get(match[1]),get(match[3])
                if left is None:return False
                if match[2]=='=' and left != right:return False
                if match[2]=='<=' and int(left['N'])>int(right['N']):return False
        return True

    def apply(self,op,args,rows):
        key=self.key(args)
        if op=='Put':rows[key]=copy.deepcopy(args['Item'])
        elif op=='Update':
            names=args['ExpressionAttributeNames'];values=args['ExpressionAttributeValues']
            match=re.fullmatch(r'SET (#[a-z]+) = (:[a-z]+|#[a-z]+ \+ :[a-z]+)',args['UpdateExpression'])
            if not match:raise AssertionError('unrecognized fixture update')
            value=match[2]
            if value.startswith(':'):rows[key][names[match[1]]]=copy.deepcopy(values[value])
            else:
                left,right=value.split(' + ')
                rows[key][names[match[1]]]={'N':str(int(rows[key][names[left]]['N'])+int(values[right]['N']))}

    def get_item(self,**args):
        with self.lock:
            self.calls.append(('get',copy.deepcopy(args)))
            row=self.rows.get(self.key(args));return {'Item':copy.deepcopy(row)} if row is not None else {}

    def transact_get_items(self,**args):
        with self.lock:
            self.calls.append(('transact-get',copy.deepcopy(args)))
            return {'Responses':[{'Item':copy.deepcopy(self.rows[self.key(item['Get'])])}
                if self.key(item['Get']) in self.rows else {} for item in args['TransactItems']]}

    def transact_write_items(self,**args):
        with self.lock:
            self.calls.append(('transact-write',copy.deepcopy(args)))
            items=args['TransactItems'];keys=[self.key(next(iter(item.values()))) for item in items]
            assert len(keys)==len(set(keys))
            reasons=[{'Code':'None' if self.condition(next(iter(item.values())),self.rows) else 'ConditionalCheckFailed'}
                     for item in items]
            if any(r['Code']!='None' for r in reasons):
                raise AwsFailure('TransactionCanceledException',[r['Code'] for r in reasons])
            staged=copy.deepcopy(self.rows)
            for item in items:
                op,body=next(iter(item.items()));self.apply(op,body,staged)
            self.rows=staged
            if self.after_commit:self.after_commit()
            return {}

    def put_item(self,**args):
        with self.lock:
            self.calls.append(('put',copy.deepcopy(args)))
            if not self.condition(args,self.rows):raise AwsFailure('ConditionalCheckFailedException')
            self.apply('Put',args,self.rows);return {}


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.sdk=TransactionSDK();public={'issuer':'synthetic','revocation_registry':'synthetic'}
        self.namespace=definition_hash(public);self.view={'definition_hash':self.namespace,'public':public,'sequence':1}
        self.issuer=DynamoIssuerStore(self.sdk,'synthetic-table',self.namespace)
        self.actions=DynamoActionStore(self.sdk,'synthetic-table',self.namespace)
        self.budget=DynamoBudget(self.sdk,'synthetic-table',self.namespace)

    def initialize(self):self.issuer.compare_exchange(None,b'x'*64,self.view)

    def challenge(self):
        from domain_pipeline import PROFILE
        return {'profile':PROFILE,'nonce':secrets.token_hex(32),'scope':'ab'*32,'facts':['account-controlled'],
                'identity':True,'registry_sequence':1,'created_at':NOW,'expires_at':NOW+60}

    def test_01_atomic_private_public_publication_and_consistent_reads(self):
        self.assertEqual(self.issuer.read(),(None,None));self.initialize()
        self.assertEqual(self.issuer.read(),(0,b'x'*64));self.assertEqual(self.actions.public_view(),self.view)
        self.assertEqual([name for name,_ in self.sdk.calls],['transact-get','transact-write','transact-get','get'])
        self.assertTrue(self.sdk.calls[-1][1]['ConsistentRead'])

    def test_02_stale_public_half_prevents_any_private_write(self):
        self.initialize();before=copy.deepcopy(self.sdk.rows)
        public_key=('synthetic-table',self.namespace+':public')
        self.sdk.rows[public_key]['revision']={'N':'1'}
        with self.assertRaisesRegex(Rejected,'registry-conflict'):self.issuer.compare_exchange(0,b'y'*64,self.view)
        self.assertEqual(self.sdk.rows[('synthetic-table',self.namespace+':issuer')],before[('synthetic-table',self.namespace+':issuer')])

    def test_03_racing_cas_has_one_winner(self):
        self.initialize()
        def publish(n):
            try:self.issuer.compare_exchange(0,bytes([n])*64,self.view);return True
            except Rejected:return False
        with ThreadPoolExecutor(max_workers=2) as pool:self.assertEqual(sum(pool.map(publish,[1,2])),1)
        self.assertEqual(self.issuer.read()[0],1)

    def test_04_partial_missing_or_revision_mismatch_never_reinitializes(self):
        self.initialize();public_key=('synthetic-table',self.namespace+':public')
        self.sdk.rows[public_key]['revision']={'N':'1'}
        with self.assertRaises(Rejected):self.issuer.read()
        del self.sdk.rows[public_key]
        with self.assertRaises(Rejected):self.issuer.read()
        with self.assertRaises(Rejected):self.issuer.compare_exchange(None,b'y'*64,self.view)

    def test_05_duplicate_or_changed_action_body_never_consumes(self):
        self.initialize();c=self.challenge();self.actions.register_action(c)
        with self.assertRaises(Rejected):self.actions.register_action(c)
        changed={**c,'scope':'cd'*32}
        with self.assertRaises(Rejected):self.actions.consume_action(changed)
        self.assertFalse(self.actions.action_record(c['nonce'])[1])
        self.actions.consume_action(c);self.assertTrue(self.actions.action_record(c['nonce'])[1])

    def test_06_concurrent_action_consumption_accepts_once(self):
        self.initialize();c=self.challenge();self.actions.register_action(c)
        def consume(_):
            try:self.actions.consume_action(c);return True
            except Rejected:return False
        with ThreadPoolExecutor(max_workers=2) as pool:self.assertEqual(sum(pool.map(consume,range(2))),1)

    def test_07_revocation_race_preserves_unconsumed_action(self):
        self.initialize();c=self.challenge();self.actions.register_action(c)
        self.issuer.compare_exchange(0,b'y'*64,{**self.view,'sequence':2})
        with self.assertRaises(Rejected):self.actions.consume_action(c)
        self.assertFalse(self.actions.action_record(c['nonce'])[1])

    def test_08_budget_cap_race_and_unique_burn(self):
        self.budget.initialize()
        for _ in range(299):self.budget.reserve(secrets.token_hex(16),'one-public-post')
        def reserve(_):
            try:self.budget.reserve(secrets.token_hex(16),'one-user-profile');return True
            except Rejected:return False
        with ThreadPoolExecutor(max_workers=2) as pool:self.assertEqual(sum(pool.map(reserve,range(2))),1)
        self.assertEqual(self.budget.public_summary()['conservative_reserved_usd'],'3.00')
        self.assertEqual(len([key for _,key in self.sdk.rows if ':charge:' in key]),300)

    def test_09_budget_missing_duplicate_and_reinitialize_fail_closed(self):
        with self.assertRaises(Rejected):self.budget.reserve('ab'*16,'one-public-post')
        self.assertEqual(self.sdk.rows,{})
        self.budget.initialize();self.budget.reserve('ab'*16,'one-public-post')
        with self.assertRaises(Rejected):self.budget.reserve('ab'*16,'one-public-post')
        with self.assertRaises(Rejected):self.budget.initialize()
        self.assertEqual(self.budget.public_summary()['reserved_request_count'],1)

    def test_10_uncertain_budget_write_is_burned_once_without_retry(self):
        self.budget.initialize();before=len(self.sdk.calls)
        self.sdk.after_commit=lambda:(_ for _ in ()).throw(TimeoutError('SYNTHETIC-PRIVATE'))
        with self.assertRaisesRegex(Rejected,'^registry-unavailable$'):self.budget.reserve('ab'*16,'one-public-post')
        self.assertEqual(len(self.sdk.calls),before+1)
        self.assertEqual(self.budget.public_summary()['reserved_request_count'],1)

    def test_11_uncertain_issuer_commit_persists_without_retry(self):
        self.initialize();before=len(self.sdk.calls)
        self.sdk.after_commit=lambda:(_ for _ in ()).throw(TimeoutError('SYNTHETIC-PRIVATE'))
        with self.assertRaisesRegex(Rejected,'^registry-unavailable$'):self.issuer.compare_exchange(0,b'y'*64,self.view)
        self.assertEqual(len(self.sdk.calls),before+1);self.assertEqual(self.issuer.read(),(1,b'y'*64))

    def test_12_role_fragments_and_interfaces_separate_private_state(self):
        policies=role_policies('arn:aws:dynamodb:ap-southeast-2:123456789012:table/synthetic-table',self.namespace)
        self.assertFalse(hasattr(self.actions,'read'));self.assertFalse(hasattr(self.actions,'compare_exchange'))
        self.assertFalse(hasattr(self.issuer,'consume_action'))
        self.assertNotIn(':issuer',json.dumps(policies['verifier']));self.assertNotIn(':public',json.dumps(policies['budget']))
        self.assertNotIn('DeleteItem',json.dumps(policies));self.assertNotIn('Scan',json.dumps(policies))
        for statement in policies['verifier']['Statement']:
            self.assertEqual(statement['Condition']['Null'],{'dynamodb:LeadingKeys':'false'})
        initializer=json.dumps(policies['budget_initializer']);self.assertIn('PutItem',initializer)
        runtime=json.dumps(policies['budget']);self.assertNotIn('Initialize',runtime)

    def test_13_real_tls_sdk_atomic_write_and_snapshot_read_shapes(self):
        self.initialize();state=self.sdk.rows[('synthetic-table',self.namespace+':issuer')]
        public=self.sdk.rows[('synthetic-table',self.namespace+':public')]
        def wire(item):return {key:{kind:base64.b64encode(value).decode() if kind=='B' else value
                                   for kind,value in attribute.items()} for key,attribute in item.items()}
        reply={'Responses':[{'Item':wire(state)},{'Item':wire(public)}]}
        with server([response(),response(canonical(reply))],hostname='dynamodb.'+REGION+'.amazonaws.com') as (ctx,dial,seen):
            store=DynamoIssuerStore(AwsJsonClient('dynamodb',REGION,credentials(),ctx,dial),'synthetic-table',self.namespace)
            store.compare_exchange(None,b'x'*64,self.view)
            self.assertEqual(store.read(),(0,b'x'*64))
        write=json.loads(seen[0].split(b'\r\n\r\n',1)[1]);read=json.loads(seen[1].split(b'\r\n\r\n',1)[1])
        self.assertEqual(len(write['TransactItems']),2);self.assertEqual(len(read['TransactItems']),2)
        self.assertTrue(all('Put' in item for item in write['TransactItems']))
        for raw in seen:check_signature(self,raw,'dynamodb')

    def test_14_native_restart_replacement_separate_verifier_and_no_id_in_action_rows(self):
        native=Native();core=LabDomainIssuer(native,NOW,12);namespace=core.definition_hash
        store=DynamoIssuerStore(self.sdk,'synthetic-table',namespace);key=secrets.token_bytes(32)
        state=PersistentDomainIssuer(store,key,namespace,native);state.initialize(core)
        actions=DynamoActionStore(self.sdk,'synthetic-table',namespace)
        verifier=PersistentDomainVerifier(actions,native,namespace)
        def enroll():
            _,loaded=state.load();holder=PendingHolder.create(native,loaded.public)
            session=state.operate('begin',holder.request,holder.desktop_nonce,'424242424242','synthetic_user',NOW)
            post,user=fixture(session)
            issued=state.operate('stage_fixture',session,'3141592653589793',canonical(post),canonical(user),NOW+2)
            held,ack=holder.receive(issued,loaded.public,session)
            state.operate('commit',session,ack,NOW+3);return held
        first=enroll()
        # Reopen using only protected key + managed snapshot, never regenerate.
        state=PersistentDomainIssuer(DynamoIssuerStore(self.sdk,'synthetic-table',namespace),key,namespace,native)
        second=enroll();self.assertNotEqual(first.local_zkid,second.local_zkid)
        challenge=verifier.challenge('ab'*32,['account-controlled'],NOW+4,identity=True)
        _,loaded=state.load();proof=second.present(loaded,challenge)
        self.assertEqual(verifier.verify(proof,challenge,NOW+5)['public_id'],second.local_zkid)
        with self.assertRaises(Rejected):verifier.verify(proof,challenge,NOW+5)
        with self.assertRaises(Rejected):first.present(loaded,challenge)
        for (table,item_id),row in self.sdk.rows.items():
            if ':action:' in item_id:
                self.assertNotIn(canonical(second.local_zkid),row['body']['B'])
                self.assertEqual(set(row),{'id','body','used'})

    def test_15_expiry_during_remote_consumption_cannot_authorize(self):
        self.initialize();c=self.challenge();self.actions.register_action(c)
        class NativeVerifier:
            def call(self,*args,**kwargs):return {'accepted':True}
        verifier=PersistentDomainVerifier(self.actions,NativeVerifier(),self.namespace)
        with patch('domain_state.time.monotonic',side_effect=[0,1,61]):
            with self.assertRaisesRegex(Rejected,'^action-expired$'):
                verifier.verify({'claimed_id':'synthetic'},c,NOW+1)
        self.assertTrue(self.actions.action_record(c['nonce'])[1])  # Burned, not accepted.

    def test_16_malformed_public_or_action_projection_is_not_trusted(self):
        self.initialize();c=self.challenge();self.actions.register_action(c)
        action_key=('synthetic-table',self.namespace+':action:'+c['nonce'])
        self.sdk.rows[action_key]['public_id']={'S':'forged'}
        with self.assertRaises(Rejected):self.actions.action_record(c['nonce'])
        public_key=('synthetic-table',self.namespace+':public')
        self.sdk.rows[public_key]['view']={'B':canonical({**self.view,'sequence':True})}
        with self.assertRaises(Rejected):self.actions.public_view()

    def test_17_authority_identity_binds_single_region_table_and_separate_roles(self):
        config={'region':REGION,'table_arn':'arn:aws:dynamodb:'+REGION+':123456789012:table/synthetic-table',
                'namespace':self.namespace,'roles':{role:'arn:aws:iam::123456789012:role/synthetic-'+role
                    for role in ('issuer','verifier','budget','public_reader')}}
        original=authority_identity(config)
        changed=copy.deepcopy(config);changed['table_arn']+='-other'
        self.assertNotEqual(authority_identity(changed),original)
        changed=copy.deepcopy(config);changed['roles']['issuer']+='-other'
        self.assertNotEqual(authority_identity(changed),original)
        for changed in ({**config,'region':'us-east-1'},
                        {**config,'roles':{**config['roles'],'budget':config['roles']['issuer']}}):
            with self.assertRaises(Rejected):authority_identity(changed)


if __name__=='__main__':unittest.main()
