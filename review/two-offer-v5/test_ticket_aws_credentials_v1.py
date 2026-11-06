"""Real HTTP/TLS/SigV4 with synthetic IMDS/STS responses, never real metadata."""
from contextlib import contextmanager
from datetime import datetime,timezone
import hashlib
import hmac
import os
import socket
import ssl
import threading
import tempfile
from pathlib import Path
import time
from types import SimpleNamespace
from urllib.parse import parse_qs
import unittest
from unittest.mock import patch
from policy import canonical,Rejected
from provisioning import validate_value
from test_provider_tls import server,response
from ticket_aws_credentials_v1 import PROFILE,METADATA,MetadataSession,STSRoleSession,validate,tls_context
from workload_sessions import WorkloadCredentials

REGION='ap-southeast-2';ACCOUNT='123456789012';HOST='sts.'+REGION+'.amazonaws.com'
def cfg(path='/run/nockapp-ticket-credentials/credentials.sock'):
    uid=os.getuid()
    return {'profile':PROFILE,'region':REGION,'account_id':ACCOUNT,'instance_id':'i-'+'12'*8+'1',
        'instance_role_arn':'arn:aws:iam::'+ACCOUNT+':role/nockapp-ticket-host',
        'instance_profile_arn':'arn:aws:iam::'+ACCOUNT+':instance-profile/nockapp-ticket-host',
        'broker_uid':uid+1000,'group_gid':os.getgid(),'socket_path':path,
        'roles':{r:{'uid':uid+n,'role_arn':'arn:aws:iam::'+ACCOUNT+':role/nockapp-ticket-'+r,'duration_seconds':900}
            for n,r in enumerate(('payment','publication','refund'))}}
def creds(generation='A',*,now=None,duration=900):
    now=int(time.time()) if now is None else now
    return {'access_key_id':'ASIA'+generation*16,'secret_access_key':generation*40,'session_token':generation*32,'expires_at':now+duration}
def iso(stamp):return datetime.fromtimestamp(stamp,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
def metadata(config,*,generation='A',now=None):
    now=int(time.time()) if now is None else now;c=creds(generation,now=now,duration=3600)
    return [response(b'SYNTHETIC-TOKEN',headers=[('Content-Length','15')]),response(config['instance_id'].encode()),
        response(canonical({'Code':'Success','LastUpdated':iso(now-60),'InstanceProfileArn':config['instance_profile_arn'],'InstanceProfileId':'AIPA'+'A'*17})),
        response(canonical({'Code':'Success','LastUpdated':iso(now-60),'Type':'AWS-HMAC','AccessKeyId':c['access_key_id'],
            'SecretAccessKey':c['secret_access_key'],'Token':c['session_token'],'Expiration':iso(c['expires_at'])}))]

@contextmanager
def plain(responses):
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(4);listener.settimeout(2);address=listener.getsockname();seen=[]
    def run():
        for item in responses:
            try:
                raw,_=listener.accept()
                with raw:
                    raw.settimeout(2);data=bytearray()
                    while b'\r\n\r\n' not in data and len(data)<=8192:
                        chunk=raw.recv(1024)
                        if not chunk:break
                        data.extend(chunk)
                    seen.append(bytes(data));raw.sendall(item)
            except OSError:pass
    thread=threading.Thread(target=run);thread.start()
    try:yield lambda:socket.create_connection(address,timeout=1),seen
    finally:
        listener.close();thread.join(timeout=3)
        if thread.is_alive():raise RuntimeError('synthetic metadata fixture did not stop')

def sts_xml(config,role='payment',generation='A',*,now=None):
    name='nockapp-ticket-'+role;c=creds(generation,now=now,duration=config['roles'][role]['duration_seconds'])
    return ('<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>'
        '<AssumedRoleUser><Arn>arn:aws:sts::'+ACCOUNT+':assumed-role/'+name+'/'+name+'</Arn><AssumedRoleId>'+'AROA'+'A'*16+':'+name+'</AssumedRoleId></AssumedRoleUser>'
        '<Credentials><AccessKeyId>'+c['access_key_id']+'</AccessKeyId><SecretAccessKey>'+c['secret_access_key']+'</SecretAccessKey>'
        '<SessionToken>'+c['session_token']+'</SessionToken><Expiration>'+iso(c['expires_at'])+'</Expiration></Credentials>'
        '<SourceIdentity>'+name+'</SourceIdentity><PackedPolicySize>0</PackedPolicySize></AssumeRoleResult>'
        '<ResponseMetadata><RequestId>synthetic-request</RequestId></ResponseMetadata></AssumeRoleResponse>').encode()
def xml_response(raw,status=200):return response(raw,status=status,headers=[('Content-Type','text/xml'),('Content-Length',str(len(raw)))])

def signature(test,wire,parent,role='payment'):
    header,body=wire.split(b'\r\n\r\n',1);lines=header.decode().split('\r\n')
    test.assertEqual(lines[0],'POST / HTTP/1.1');headers={k.lower():v.strip() for k,v in (line.split(':',1) for line in lines[1:])}
    algorithm,fields=headers['authorization'].split(' ',1);params=dict(p.split('=',1) for p in fields.split(', '));names=params['SignedHeaders'].split(';')
    test.assertEqual(algorithm,'AWS4-HMAC-SHA256');test.assertEqual(headers['host'],HOST)
    test.assertEqual(headers['x-amz-security-token'],parent['session_token'])
    scope=headers['x-amz-date'][:8]+'/'+REGION+'/sts/aws4_request'
    test.assertEqual(params['Credential'],parent['access_key_id']+'/'+scope)
    request='POST\n/\n\n'+''.join(n+':'+headers[n]+'\n' for n in names)+'\n'+params['SignedHeaders']+'\n'+hashlib.sha256(body).hexdigest()
    text='AWS4-HMAC-SHA256\n'+headers['x-amz-date']+'\n'+scope+'\n'+hashlib.sha256(request.encode()).hexdigest()
    key=('AWS4'+parent['secret_access_key']).encode()
    for part in [headers['x-amz-date'][:8],REGION,'sts','aws4_request']:key=hmac.digest(key,part.encode(),'sha256')
    test.assertEqual(params['Signature'],hmac.digest(key,text.encode(),'sha256').hex())
    test.assertEqual(parse_qs(body.decode()),{'Action':['AssumeRole'],'Version':['2011-06-15'],
        'RoleArn':['arn:aws:iam::'+ACCOUNT+':role/nockapp-ticket-'+role],'RoleSessionName':['nockapp-ticket-'+role],
        'SourceIdentity':['nockapp-ticket-'+role],'DurationSeconds':['900']})

class AWSRoleSourceTests(unittest.TestCase):
    def test_imdsv2_checks_instance_profile_and_only_the_fixed_role_path(self):
        config=cfg()
        with plain(metadata(config)) as (dial,seen):result=MetadataSession(config,dial=dial).create_session()
        validate_value('managed-writer-credentials',result);self.assertEqual(result['access_key_id'],'ASIA'+'A'*16)
        self.assertEqual(len(seen),4);self.assertIn(b'PUT /latest/api/token HTTP/1.1',seen[0]);self.assertIn(b'900',seen[0])
        for request in seen:
            self.assertIn(b'Host: '+METADATA.encode(),request);self.assertNotIn(b'Authorization:',request)
        for request in seen[1:]:self.assertIn(b'X-aws-ec2-metadata-token: SYNTHETIC-TOKEN',request)
        self.assertIn(b'/iam/security-credentials/nockapp-ticket-host HTTP/1.1',seen[-1])

    def test_imds_token_refusal_wrong_instance_or_profile_stops_without_fallback(self):
        config=cfg()
        cases=[([response(b'no token',status=401)],1),
            ([metadata(config)[0],response(b'i-'+'ab'.encode()*8+b'1')],2),
            ([*metadata(config)[:2],response(canonical({'Code':'Success','LastUpdated':iso(int(time.time())-60),
                'InstanceProfileArn':config['instance_profile_arn']+'-wrong','InstanceProfileId':'AIPA'+'A'*17}))],3)]
        for replies,count in cases:
            with plain(replies) as (dial,seen),self.assertRaises(Rejected):MetadataSession(config,dial=dial).create_session()
            self.assertEqual(len(seen),count)

    def test_sts_real_tls_signature_exact_role_identity_and_bounded_expiry(self):
        config=cfg();parent=WorkloadCredentials(MetadataSession(config));p=creds('P',duration=3600)
        with server([xml_response(sts_xml(config))],hostname=HOST) as (context,dial,seen),patch.object(parent,'get',return_value=p):
            result=STSRoleSession(config,'payment',parent,context,dial=dial).create_session()
        self.assertEqual(result['access_key_id'],'ASIA'+'A'*16);self.assertEqual(len(seen),1);signature(self,seen[0],p)

    def test_documented_optional_token_metadata_keeps_real_tls_signature_and_identity_binding(self):
        config=cfg();parent=WorkloadCredentials(MetadataSession(config));p=creds('P',duration=3600)
        raw=sts_xml(config)
        for metadata in (b'<SessionTokenSize>32</SessionTokenSize>',
                         b'<SessionTokenUtilization>1</SessionTokenUtilization>',
                         b'<SessionTokenSize>32</SessionTokenSize><SessionTokenUtilization>1</SessionTokenUtilization>'):
            modern=raw.replace(b'</AssumeRoleResult>',metadata+b'</AssumeRoleResult>')
            modern=modern.replace(b'<PackedPolicySize>0</PackedPolicySize>',b'')
            with self.subTest(metadata=metadata),server([xml_response(modern)],hostname=HOST) as (context,dial,seen),patch.object(parent,'get',return_value=p):
                result=STSRoleSession(config,'payment',parent,context,dial=dial).create_session()
            self.assertEqual(result['access_key_id'],'ASIA'+'A'*16)
            self.assertEqual(len(seen),1);signature(self,seen[0],p)

    def test_new_accounting_fields_reject_malformed_duplicate_namespaced_or_nested_values(self):
        config=cfg();parent=WorkloadCredentials(MetadataSession(config));p=creds('P',duration=3600)
        raw=sts_xml(config)
        bad=[b'<SessionTokenSize>-1</SessionTokenSize>',b'<SessionTokenSize>65537</SessionTokenSize>',
             b'<SessionTokenSize>1.0</SessionTokenSize>',b'<SessionTokenUtilization>101</SessionTokenUtilization>',
             b'<SessionTokenUtilization> 1</SessionTokenUtilization>',b'<SessionTokenSize><Size>32</Size></SessionTokenSize>',
             b'<SessionTokenSize arbitrary="true">32</SessionTokenSize>',
             b'<SessionTokenSize xmlns="https://foreign.example/">32</SessionTokenSize>',
             b'<SessionTokenSize>32</SessionTokenSize><SessionTokenSize>32</SessionTokenSize>',
             b'<UnknownSessionAuthority>32</UnknownSessionAuthority>']
        for metadata in bad:
            modern=raw.replace(b'</AssumeRoleResult>',metadata+b'</AssumeRoleResult>')
            with self.subTest(metadata=metadata),server([xml_response(modern)],hostname=HOST) as (context,dial,seen),patch.object(parent,'get',return_value=p),self.assertRaises(Rejected):
                STSRoleSession(config,'payment',parent,context,dial=dial).create_session()
            self.assertEqual(len(seen),1)
        modern=raw.replace(b'</AssumeRoleResult>',b'<SessionTokenSize>32</SessionTokenSize></AssumeRoleResult>')
        modern=modern.replace(b'<SourceIdentity>nockapp-ticket-payment',b'<SourceIdentity>foreign')
        with server([xml_response(modern)],hostname=HOST) as (context,dial,_),patch.object(parent,'get',return_value=p),self.assertRaises(Rejected):
            STSRoleSession(config,'payment',parent,context,dial=dial).create_session()

    def test_sts_rejects_other_role_source_identity_duplicate_xml_and_dtd(self):
        config=cfg();parent=WorkloadCredentials(MetadataSession(config));raw=sts_xml(config)
        bad=[sts_xml(config,'refund'),raw.replace(b'<SourceIdentity>nockapp-ticket-payment',b'<SourceIdentity>foreign-identity'),
            raw.replace(b'<PackedPolicySize>0</PackedPolicySize>',b'<PackedPolicySize>0</PackedPolicySize><PackedPolicySize>0</PackedPolicySize>'),
            b'<!DOCTYPE x [<!ENTITY y "z">]>'+raw,
            sts_xml(config,now=int(time.time())-500)]
        for body in bad:
            with server([xml_response(body)],hostname=HOST) as (context,dial,seen),patch.object(parent,'get',return_value=creds('P',duration=3600)):
                with self.assertRaises(Rejected):STSRoleSession(config,'payment',parent,context,dial=dial).create_session()
            self.assertEqual(len(seen),1)

    def test_sts_denial_and_untrusted_tls_never_retry_or_return_provider_text(self):
        config=cfg();parent=WorkloadCredentials(MetadataSession(config))
        for untrusted,status in [(False,403),(True,200)]:
            with server([xml_response(b'<private-marker/>',status)],hostname=HOST,untrusted=untrusted) as (context,dial,seen),\
                patch.object(parent,'get',return_value=creds('P',duration=3600)):
                with self.assertRaises(Rejected) as error:STSRoleSession(config,'refund',parent,context,dial=dial).create_session()
            self.assertNotIn('private-marker',str(error.exception));self.assertEqual(len(seen),0 if untrusted else 1)

    def test_utf16_dtd_cannot_bypass_xml_guard(self):
        config=cfg();parent=WorkloadCredentials(MetadataSession(config))
        xml=sts_xml(config).decode().replace('<SessionToken>'+'A'*32,'<SessionToken>&token;')
        raw=('<?xml version="1.0" encoding="utf-16"?><!DOCTYPE AssumeRoleResponse [<!ENTITY token "'+'A'*32+'">]>'+xml).encode('utf-16')
        with server([xml_response(raw)],hostname=HOST) as (context,dial,seen),patch.object(parent,'get',return_value=creds('P',duration=3600)):
            with self.assertRaises(Rejected):STSRoleSession(config,'payment',parent,context,dial=dial).create_session()
        self.assertEqual(len(seen),1)

    def test_existing_refresh_cache_rotates_real_sts_responses_without_human_credentials(self):
        config=cfg();parent=WorkloadCredentials(MetadataSession(config));now=int(time.time());clock=SimpleNamespace(now=now,mono=100.)
        fake=SimpleNamespace(time=lambda:clock.now,monotonic=lambda:clock.mono)
        replies=[xml_response(sts_xml(config,now=now)),xml_response(sts_xml(config,generation='B',now=now+650))]
        with server(replies,hostname=HOST) as (context,dial,seen),patch.object(parent,'get',return_value=creds('P',duration=3600)),\
            patch('ticket_aws_credentials_v1.time',fake),patch('workload_sessions.time',fake),patch('provisioning.time',fake):
            cache=WorkloadCredentials(STSRoleSession(config,'payment',parent,context,dial=dial))
            self.assertEqual(cache.get()['access_key_id'],'ASIA'+'A'*16)
            self.assertEqual(cache.get()['access_key_id'],'ASIA'+'A'*16)
            clock.now+=650;clock.mono+=650
            self.assertEqual(cache.get()['access_key_id'],'ASIA'+'B'*16)
            clock.now-=100
            with self.assertRaises(Rejected):cache.get()
        self.assertEqual(len(seen),2)

    def test_configuration_cannot_alias_users_or_roles_and_construction_does_no_io(self):
        config=cfg()
        for change in [lambda v:v['roles']['refund'].update(uid=v['roles']['payment']['uid']),
            lambda v:v.update(broker_uid=v['roles']['payment']['uid']),
            lambda v:v['roles']['payment'].update(role_arn='arn:aws:iam::'+ACCOUNT+':role/Administrator'),
            lambda v:v['roles']['publication'].update(duration_seconds=7200),lambda v:v.update(socket_path='/tmp/.env/foo.sock')]:
            import copy
            bad=copy.deepcopy(config);change(bad)
            with self.assertRaises(Rejected):validate(bad)
        context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2
        with patch('socket.create_connection',side_effect=AssertionError('no implicit metadata or AWS request')):
            STSRoleSession(config,'payment',WorkloadCredentials(MetadataSession(config)),context)

    def test_explicit_tls_context_avoids_ambient_default_helper_and_logs(self):
        with patch('ssl.create_default_context',side_effect=AssertionError('no ambient CA/keylog helper')):
            context=tls_context()
        self.assertIsNone(context.keylog_filename);self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)

    def test_keylogging_or_late_weakened_tls_rejects_before_parent_credentials(self):
        config=cfg();parent=WorkloadCredentials(MetadataSession(config));context=tls_context()
        session=STSRoleSession(config,'payment',parent,context)
        with tempfile.TemporaryDirectory(prefix='synthetic-unused-keylog-') as directory:
            context.keylog_filename=str(Path(directory)/'unused.log')
            with patch.object(parent,'get',side_effect=AssertionError('no credentials for logging TLS')):
                with self.assertRaises(Rejected):session.create_session()
                with self.assertRaises(Rejected):STSRoleSession(config,'payment',parent,context)
            context.keylog_filename=None
        context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
        with patch.object(parent,'get',side_effect=AssertionError('no credentials for unauthenticated TLS')):
            with self.assertRaises(Rejected):session.create_session()
