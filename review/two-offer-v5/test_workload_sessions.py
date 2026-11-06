"""Real TLS/ECDSA/SigV4; synthetic certificates and AWS sessions only."""
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
import hashlib
import ssl
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from aws_transport import AwsJsonClient
from policy import Rejected,canonical
from test_provider_tls import server,response
from workload_sessions import PROFILE,ALGORITHM,WorkloadSession,WorkloadCredentials,validate_config

REGION='ap-southeast-2';HOST='rolesanywhere.'+REGION+'.amazonaws.com'


def identity(purpose='issuer'):
    key=ec.generate_private_key(ec.SECP256R1());now=datetime.now(timezone.utc)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'nockapp-zkid-'+purpose),
                   x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,'ab'*32)])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(123456789)
        .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,None,None),critical=True)
        .sign(key,hashes.SHA256()))
    der=cert.public_bytes(serialization.Encoding.DER)
    cfg={'profile':PROFILE,'region':REGION,'account':'123456789012','purpose':purpose,'namespace':'ab'*32,
         'certificate_sha256':hashlib.sha256(der).hexdigest(),'duration_seconds':3600,
         'trust_anchor_arn':'arn:aws:rolesanywhere:'+REGION+':123456789012:trust-anchor/'+'11111111-1111-1111-1111-111111111111',
         'profile_arn':'arn:aws:rolesanywhere:'+REGION+':123456789012:profile/'+'22222222-2222-2222-2222-222222222222',
         'role_arn':'arn:aws:iam::123456789012:role/nockapp-zkid-'+purpose}
    return cfg,der,key


def issued(cfg,*,now=None,generation='A'):
    now=int(time.time()) if now is None else now
    return {'subjectArn':'arn:aws:rolesanywhere:'+REGION+':123456789012:subject/33333333-3333-3333-3333-333333333333',
        'credentialSet':[{'assumedRoleUser':{'arn':'arn:aws:sts::123456789012:assumed-role/nockapp-zkid-'+cfg['purpose']+'/123456789',
            'assumedRoleId':'AROA'+'A'*16+':123456789'},'packedPolicySize':0,'roleArn':cfg['role_arn'],
            'sourceIdentity':'CN=nockapp-zkid-'+cfg['purpose'],'credentials':{'accessKeyId':'ASIA'+generation*16,
            'secretAccessKey':generation*40,'sessionToken':generation*32,
            'expiration':datetime.fromtimestamp(now+3600,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}}]}


def wire_signature(test,wire,cfg,key):
    head,body=wire.split(b'\r\n\r\n',1);lines=head.decode().split('\r\n')
    test.assertEqual(lines[0],'POST /sessions HTTP/1.1')
    headers={k.lower():v.strip() for k,v in (line.split(':',1) for line in lines[1:])}
    algorithm,auth=headers['authorization'].split(' ',1)
    params=dict(pair.split('=',1) for pair in auth.split(', '));names=params['SignedHeaders'].split(';')
    test.assertEqual(algorithm,ALGORITHM);test.assertEqual(names,['content-type','host','x-amz-date','x-amz-x509'])
    certificate=x509.load_der_x509_certificate(base64.b64decode(headers['x-amz-x509']))
    test.assertEqual(certificate.public_key(),key.public_key());test.assertEqual(headers['host'],HOST)
    canonical_request='\n'.join(['POST','/sessions','',''.join(n+':'+headers[n]+'\n' for n in names),params['SignedHeaders'],hashlib.sha256(body).hexdigest()])
    scope=headers['x-amz-date'][:8]+'/'+REGION+'/rolesanywhere/aws4_request'
    test.assertEqual(params['Credential'],'123456789/'+scope)
    text='\n'.join([algorithm,headers['x-amz-date'],scope,hashlib.sha256(canonical_request.encode()).hexdigest()])
    certificate.public_key().verify(bytes.fromhex(params['Signature']),text.encode(),ec.ECDSA(hashes.SHA256()))
    import json
    test.assertEqual(json.loads(body),{'durationSeconds':3600,'profileArn':cfg['profile_arn'],
        'roleArn':cfg['role_arn'],'trustAnchorArn':cfg['trust_anchor_arn']})


class WorkloadTests(unittest.TestCase):
    def session(self):
        cfg,der,key=identity();context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2
        return WorkloadSession(cfg,der,key,context),cfg

    def test_real_tls_and_independent_certificate_request_signature(self):
        cfg,der,key=identity()
        with server([response(canonical(issued(cfg)),status=201)],hostname=HOST) as (context,dial,seen):
            result=WorkloadSession(cfg,der,key,context,dial).create_session()
        self.assertEqual(result['access_key_id'],'ASIA'+'A'*16);self.assertEqual(len(seen),1)
        wire_signature(self,seen[0],cfg,key)

    def test_bad_config_identity_or_tls_cannot_dial(self):
        cfg,der,key=identity();context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2
        for change in [{'role_arn':'arn:aws:iam::123456789012:role/Administrator'},
                       {'purpose':'initial-parent'},{'duration_seconds':True},{'duration_seconds':43200},
                       {'endpoint':'https://evil.invalid'},{'namespace':'00'*32},
                       {'profile_arn':cfg['profile_arn'].replace(REGION,'us-east-1')}]:
            with self.assertRaises(Rejected):validate_config({**cfg,**change})
        with self.assertRaises(Rejected):WorkloadSession(cfg,der,ec.generate_private_key(ec.SECP256R1()),context)
        with self.assertRaises(Rejected):WorkloadSession({**cfg,'namespace':'cd'*32},der,key,context)
        context.check_hostname=False
        with self.assertRaises(Rejected):WorkloadSession(cfg,der,key,context)

    def test_wrong_https_identity_never_receives_authorization(self):
        cfg,der,key=identity()
        for options in [{'hostname':'wrong.invalid'},{'hostname':HOST,'untrusted':True}]:
            with server([response()],**options) as (context,dial,seen):
                with self.assertRaises(Rejected):WorkloadSession(cfg,der,key,context,dial).create_session()
            self.assertEqual(seen,[])

    def test_only_one_matching_role_session_and_bounded_expiry_accepted(self):
        session,cfg=self.session()
        mutators=[lambda v:v['credentialSet'].append(copy.deepcopy(v['credentialSet'][0])),
            lambda v:v['credentialSet'][0].update(roleArn=cfg['role_arn'].replace('issuer','budget')),
            lambda v:v['credentialSet'][0].update(sourceIdentity='nockapp-zkid-verifier'),
            lambda v:v['credentialSet'][0]['assumedRoleUser'].update(arn='arn:aws:sts::999999999999:assumed-role/nockapp-zkid-issuer/123'),
            lambda v:v['credentialSet'][0]['credentials'].update(accessKeyId='AKIA'+'A'*16),
            lambda v:v['credentialSet'][0]['credentials'].update(expiration=datetime.fromtimestamp(time.time()+200,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')),
            lambda v:v.update(private='SYNTHETIC-PRIVATE')]
        for mutate in mutators:
            value=issued(cfg);mutate(value)
            with self.assertRaises(Rejected):session._parse(canonical(value),int(time.time()))
        with self.assertRaises(Rejected):session._parse(b'{"credentialSet":[],"credentialSet":[]}',int(time.time()))

    def test_aws_short_common_name_prefix_is_exact_for_each_service(self):
        # AWS documents CN= for our <62-character certificate common names.
        # The installed live failure exposed the old unprefixed fixture error.
        for purpose in ('issuer','budget','verifier'):
            cfg,der,key=identity(purpose)
            context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2
            session=WorkloadSession(cfg,der,key,context)
            good=issued(cfg);now=int(time.time())
            self.assertEqual(session._parse(canonical(good),now)['access_key_id'],'ASIA'+'A'*16)
            for wrong in ('nockapp-zkid-'+purpose,'ID=0123','CN=nockapp-zkid-'+purpose+'-other',
                          'CN=CN=nockapp-zkid-'+purpose,'CN=nockapp-zkid-public-reader'):
                bad=copy.deepcopy(good);bad['credentialSet'][0]['sourceIdentity']=wrong
                with self.assertRaises(Rejected):session._parse(canonical(bad),now)

    def test_status_failures_never_redirect_retry_or_print_response(self):
        cfg,der,key=identity()
        for status,code in [(301,'workload-authorization-rejected'),(403,'workload-authorization-rejected'),
                            (429,'workload-session-unavailable'),(503,'workload-session-unavailable')]:
            with server([response(b'SYNTHETIC-PRIVATE',status=status)],hostname=HOST) as (context,dial,seen):
                with self.assertRaisesRegex(Rejected,'^'+code+'$'):WorkloadSession(cfg,der,key,context,dial).create_session()
            self.assertEqual(len(seen),1)

    def test_expired_leaf_stops_before_any_network_request(self):
        session,_=self.session()
        with patch.object(session,'_dial') as dial,patch('workload_sessions.time.time',return_value=session._cert.not_valid_after_utc.timestamp()+1):
            with self.assertRaisesRegex(Rejected,'workload-identity-expired'):session.create_session()
            dial.assert_not_called()

    def test_ambiguous_http_responses_and_duplicate_json_never_release_sessions(self):
        cfg,der,key=identity();good=canonical(issued(cfg))
        variants=[response(good,status=201,headers=[('Content-Type','application/json'),('Content-Length',str(len(good))),('Content-Length',str(len(good)))]),
            response(good,status=201,headers=[('Content-Type','application/json'),('Content-Encoding','gzip')]),
            response(good,status=201,headers=[('Content-Type','text/html')]),
            response(good,status=201,headers=[('Content-Type','application/json'),('Content-Length','65537')]),
            response(b'{"credentialSet":[],"credentialSet":[]}',status=201)]
        for wire in variants:
            with server([wire],hostname=HOST) as (context,dial,seen):
                with self.assertRaises(Rejected):WorkloadSession(cfg,der,key,context,dial).create_session()
            self.assertEqual(len(seen),1)

    def test_initial_outage_is_bounded_and_recovers_without_an_existing_session(self):
        session,cfg=self.session();provider=WorkloadCredentials(session);clock=[int(time.time()),100.0]
        value=session._parse(canonical(issued(cfg)),clock[0])
        with patch('workload_sessions.time.time',side_effect=lambda:clock[0]),patch('workload_sessions.time.monotonic',side_effect=lambda:clock[1]),\
             patch.object(session,'create_session',side_effect=[Rejected('workload-session-unavailable'),value]) as refresh:
            for _ in range(8):
                with self.assertRaises(Rejected):provider.get()
            self.assertEqual(refresh.call_count,1)
            clock[0]+=30;clock[1]+=30;self.assertEqual(provider.get(),value)
            self.assertEqual(refresh.call_count,2)

    def test_monotonic_deadline_prevents_reuse_even_if_wall_clock_stops(self):
        session,cfg=self.session();provider=WorkloadCredentials(session);mono=[100.0]
        value=session._parse(canonical(issued(cfg)),int(time.time()))
        with patch('workload_sessions.time.monotonic',side_effect=lambda:mono[0]),\
             patch.object(session,'create_session',side_effect=[value,Rejected('workload-session-unavailable')]):
            provider.get();mono[0]+=3601
            with self.assertRaises(Rejected):provider.get()

    def test_invalid_operations_never_mint_sessions_or_dial_aws(self):
        session,_=self.session();provider=WorkloadCredentials(session);context=ssl.create_default_context()
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        with patch.object(session,'create_session') as refresh,patch('aws_transport.socket.create_connection') as dial:
            client=AwsJsonClient('dynamodb',REGION,provider,context)
            with self.assertRaises(Rejected):client._call('DeleteTable',{'TableName':'synthetic'})
            with self.assertRaises(Rejected):client.put_item(Unexpected='synthetic')
            refresh.assert_not_called();dial.assert_not_called()

    def test_aws_write_rejection_never_resubmits_or_refreshes_as_a_retry(self):
        cfg,der,key=identity()
        with server([response(canonical(issued(cfg)),status=201)],hostname=HOST) as (context,dial,seen_sessions),\
             server([response(canonical({'__type':'ExpiredTokenException'}),status=400)],hostname='dynamodb.'+REGION+'.amazonaws.com') as (aws_context,aws_dial,seen_aws):
            client=AwsJsonClient('dynamodb',REGION,WorkloadCredentials(WorkloadSession(cfg,der,key,context,dial)),aws_context,aws_dial)
            with self.assertRaises(Rejected):client.put_item(TableName='synthetic',Item={'id':{'S':'synthetic'}})
        self.assertEqual(len(seen_sessions),1);self.assertEqual(len(seen_aws),1)

    def test_single_refresh_then_snapshot_copy_is_safe_across_threads(self):
        session,cfg=self.session();provider=WorkloadCredentials(session)
        value=session._parse(canonical(issued(cfg)),int(time.time()))
        with patch.object(session,'create_session',return_value=value) as refresh:
            with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(lambda _:provider.get(),range(16)))
            refresh.assert_called_once();results[0]['session_token']='changed'
            self.assertNotEqual(provider.get()['session_token'],'changed')

    def test_transient_refresh_backoff_preserves_valid_session_and_never_uses_expired_one(self):
        session,cfg=self.session();provider=WorkloadCredentials(session);clock=[int(time.time()),100.0]
        first=session._parse(canonical(issued(cfg,now=clock[0])),clock[0])
        with patch('workload_sessions.time.time',side_effect=lambda:clock[0]),patch('workload_sessions.time.monotonic',side_effect=lambda:clock[1]),\
             patch.object(session,'create_session',side_effect=[first,Rejected('workload-session-unavailable'),Rejected('workload-session-unavailable')]) as refresh:
            self.assertEqual(provider.get(),first);clock[0]+=3301;clock[1]+=3301
            self.assertEqual(provider.get(),first)
            for _ in range(10):self.assertEqual(provider.get(),first)
            self.assertEqual(refresh.call_count,2)
            clock[0]+=300;clock[1]+=300
            with self.assertRaises(Rejected):provider.get()
            self.assertEqual(refresh.call_count,3)
            with self.assertRaises(Rejected):provider.get()
            self.assertEqual(refresh.call_count,3)

    def test_authorization_failure_latches_and_utc_rollback_cannot_extend_session(self):
        session,cfg=self.session();provider=WorkloadCredentials(session);clock=[int(time.time()),100.0]
        value=session._parse(canonical(issued(cfg)),clock[0])
        with patch('workload_sessions.time.time',side_effect=lambda:clock[0]),patch('workload_sessions.time.monotonic',side_effect=lambda:clock[1]),\
             patch.object(session,'create_session',side_effect=[value,Rejected('workload-authorization-rejected')]) as refresh:
            provider.get();clock[0]-=10
            with self.assertRaises(Rejected):provider.get()
            clock[0]+=3311;clock[1]+=3301
            with self.assertRaises(Rejected):provider.get()
            clock[0]+=31;clock[1]+=31
            with self.assertRaises(Rejected):provider.get()
            self.assertEqual(refresh.call_count,2)

    def test_actual_aws_client_uses_new_session_for_next_request_without_retrying_write(self):
        cfg,der,key=identity();clock=[int(time.time()),100.0]
        def session_response(_):return response(canonical(issued(cfg,now=clock[0],generation='A' if clock[1]==100 else 'B')),status=201)
        with server([session_response,session_response],hostname=HOST) as (context,dial,seen_sessions),\
             server([response(),response()],hostname='dynamodb.'+REGION+'.amazonaws.com') as (aws_context,aws_dial,seen_aws),\
             patch('workload_sessions.time.time',side_effect=lambda:clock[0]),patch('workload_sessions.time.monotonic',side_effect=lambda:clock[1]):
            provider=WorkloadCredentials(WorkloadSession(cfg,der,key,context,dial))
            client=AwsJsonClient('dynamodb',REGION,provider,aws_context,aws_dial)
            client.get_item(TableName='synthetic',Key={'id':{'S':'synthetic'}})
            clock[0]+=3301;clock[1]+=3301
            client.get_item(TableName='synthetic',Key={'id':{'S':'synthetic'}})
        self.assertEqual(len(seen_sessions),2);self.assertEqual(len(seen_aws),2)
        self.assertIn(('ASIA'+'A'*16).encode(),seen_aws[0]);self.assertIn(('ASIA'+'B'*16).encode(),seen_aws[1])
        self.assertIn(('x-amz-security-token: '+'B'*32).lower().encode(),seen_aws[1].lower())
