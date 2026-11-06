"""Real TLS and independently checked signatures; synthetic S3, not live AWS."""
import hashlib
import hmac
import ssl
import threading
import time
import unittest
from unittest.mock import patch

from base_protocol import sha
from policy import Rejected
from public_bundle import encode,decode,MAX_BYTES
from public_s3 import S3PublicReplica
from public_storage import ReplicatedPublicStore,RETENTION_SECONDS
from test_aws_transport import credentials
from test_provider_tls import server,response
from test_public_storage import ordinary

REGION='ap-southeast-2'
BUCKET='nockapp-synthetic-fixture'
HOST=BUCKET+'.s3.'+REGION+'.amazonaws.com'


def stored(data,until,version='fixture-v1',etag='"fixture-etag"'):
    return response(data,headers=[('Content-Type','application/json'),('Content-Length',str(len(data))),
        ('x-amz-meta-retain-until',str(until)),('x-amz-version-id',version),('ETag',etag)])


class PublicS3Tests(unittest.TestCase):
    def setUp(self):
        self.data=encode(ordinary());self.digest=sha(self.data);self.until=int(time.time())+RETENTION_SECONDS

    def replica(self,ctx,dial,**kw):
        return S3PublicReplica('replica-one',REGION,BUCKET,ctx,dial=dial,**kw)

    def check_signature(self,raw):
        header,body=raw.split(b'\r\n\r\n',1);lines=header.decode().split('\r\n')
        self.assertEqual(lines[0],'PUT /v3/sha256/'+self.digest[2:]+'.json HTTP/1.1')
        fields={k.lower():v.strip() for k,v in (s.split(':',1) for s in lines[1:])}
        algorithm,auth=fields['authorization'].split(' ',1)
        params=dict(p.split('=',1) for p in auth.split(', '));signed=params['SignedHeaders'].split(';')
        self.assertEqual(algorithm,'AWS4-HMAC-SHA256')
        for field in ('host','x-amz-security-token','x-amz-meta-retain-until','x-amz-checksum-sha256'):
            self.assertIn(field,signed)
        payload=hashlib.sha256(body).hexdigest();self.assertEqual(fields['x-amz-content-sha256'],payload)
        canonical='PUT\n/v3/sha256/'+self.digest[2:]+'.json\n\n'
        canonical+=''.join(k+':'+fields[k]+'\n' for k in signed)+'\n'+params['SignedHeaders']+'\n'+payload
        date=fields['x-amz-date'][:8];scope=date+'/'+REGION+'/s3/aws4_request'
        self.assertEqual(params['Credential'],credentials()['access_key_id']+'/'+scope)
        message=algorithm+'\n'+fields['x-amz-date']+'\n'+scope+'\n'+hashlib.sha256(canonical.encode()).hexdigest()
        key=('AWS4'+credentials()['secret_access_key']).encode()
        for value in (date,REGION,'s3','aws4_request'):key=hmac.new(key,value.encode(),hashlib.sha256).digest()
        self.assertEqual(params['Signature'],hmac.new(key,message.encode(),hashlib.sha256).hexdigest())
        self.assertEqual(fields['host'],HOST);self.assertEqual(body,self.data)
        return fields

    def test_signed_conditional_upload_and_anonymous_exact_readback(self):
        with server([response(b''),stored(self.data,self.until)],hostname=HOST) as (ctx,dial,seen):
            ack=self.replica(ctx,dial,credentials=credentials()).put(self.digest,self.data,retain_until=self.until,repair=False)
        self.assertEqual(ack['version'],'fixture-v1');self.assertEqual(ack['bytes'],len(self.data))
        self.assertEqual(self.check_signature(seen[0])['if-none-match'],'*')
        self.assertNotIn(b'Authorization:',seen[1]);self.assertNotIn(b'x-amz-security-token:',seen[1])

    def test_existing_retention_renewal_is_conditional_new_version(self):
        replies=[response(b'',412),stored(self.data,self.until-1),response(b''),stored(self.data,self.until,'fixture-v2')]
        with server(replies,hostname=HOST) as (ctx,dial,seen):
            ack=self.replica(ctx,dial,credentials=credentials()).put(self.digest,self.data,retain_until=self.until,repair=False)
        self.assertEqual(ack['version'],'fixture-v2')
        self.assertEqual(self.check_signature(seen[2])['if-match'],'"fixture-etag"')

    def test_lost_reply_recovers_existing_exact_bytes_without_another_put(self):
        with server([b'',stored(self.data,self.until)],hostname=HOST) as (ctx,dial,seen):
            ack=self.replica(ctx,dial,credentials=credentials()).put(self.digest,self.data,retain_until=self.until,repair=False)
        self.assertEqual(ack['digest'],self.digest);self.assertEqual(len(seen),2)

    def test_corruption_requires_explicit_repair_and_verified_input(self):
        for repair in (False,True):
            replies=[response(b'',412),stored(b'corrupted',self.until)]
            if repair:replies.extend([response(b''),stored(self.data,self.until,'repaired-v2')])
            with server(replies,hostname=HOST) as (ctx,dial,seen):
                replica=self.replica(ctx,dial,credentials=credentials())
                if repair:
                    self.assertEqual(replica.put(self.digest,self.data,retain_until=self.until,repair=True)['version'],'repaired-v2')
                    self.assertIn(b'If-Match: "fixture-etag"',seen[2])
                else:
                    with self.assertRaisesRegex(Rejected,'public-s3-content-conflict'):
                        replica.put(self.digest,self.data,retain_until=self.until,repair=False)
        with self.assertRaises(Rejected):
            replica.put(self.digest,b'corrupt input',retain_until=self.until,repair=True)

    def test_read_only_no_sdk_credentials_or_ambient_proxy(self):
        with patch.dict('os.environ',{'HTTPS_PROXY':'http://wrong.invalid','AWS_PROFILE':'do-not-open'}):
            with server([stored(self.data,self.until)],hostname=HOST) as (ctx,dial,seen):
                with patch('public_s3.activate',side_effect=AssertionError('SDK loaded by reader')):
                    replica=self.replica(ctx,dial);self.assertEqual(replica.get(self.digest,MAX_BYTES),self.data)
                    with self.assertRaisesRegex(Rejected,'public-s3-read-only'):
                        replica.put(self.digest,self.data,retain_until=self.until,repair=False)
        self.assertEqual(len(seen),1);self.assertNotIn(b'Authorization:',seen[0])

    def test_oversize_ambiguous_encoding_and_redirect_rejected(self):
        headers=[[('Content-Length',str(MAX_BYTES+1))],[('Content-Length','2'),('Content-Length','2')],
            [('Content-Length','2'),('Transfer-Encoding','chunked')],
            [('Content-Length','2'),('Content-Encoding','gzip')],[('Content-Length','2'),('Content-Type','text/html')]]
        replies=[response(headers=h) for h in headers]
        replies.extend([response(b'',302,headers=[('Content-Length','0'),('Location','https://wrong.invalid')]),
            stored(b'{}',self.until)])
        for reply in replies:
            with server([reply],hostname=HOST) as (ctx,dial,seen):
                with self.assertRaises(Rejected):self.replica(ctx,dial).get(self.digest,MAX_BYTES)
            self.assertEqual(len(seen),1)

    def test_tls_name_and_ca_checked_before_authorization(self):
        for options in ({'hostname':'wrong.invalid'},{'hostname':HOST,'untrusted':True}):
            with server([response()],**options) as (ctx,dial,seen):
                with self.assertRaises(Rejected):
                    self.replica(ctx,dial,credentials=credentials())._request('PUT',self.digest,data=self.data)
            self.assertEqual(seen,[])

    def test_unversioned_and_short_retention_readbacks_cannot_ack(self):
        for version,until in [('null',self.until),('fixture-v1',self.until-1)]:
            with server([response(b''),stored(self.data,until,version)],hostname=HOST) as (ctx,dial,_):
                with self.assertRaises(Rejected):
                    self.replica(ctx,dial,credentials=credentials()).put(self.digest,self.data,retain_until=self.until,repair=False)

    def test_two_real_tls_fixture_regions_gate_upload(self):
        second_host=BUCKET+'.s3.eu-west-1.amazonaws.com'
        # Direct PUT+GET per destination, plus the store's independent readback.
        replies=[response(b''),stored(self.data,self.until+10),stored(self.data,self.until+10)]
        with server(replies,hostname=HOST) as (ctx,a,_):
            with server(replies,hostname=second_host) as (ctx2,b,_):
                left=self.replica(ctx,a,credentials=credentials())
                right=S3PublicReplica('replica-two','eu-west-1',BUCKET,ctx2,credentials=credentials(),dial=b)
                result=ReplicatedPublicStore([left,right]).upload(decode(self.data))
        self.assertEqual(len(result['acknowledgments']),2)
        # Identical region cannot be advertised as an independent failure domain.
        with self.assertRaisesRegex(Rejected,'public-replica-independence'):
            ReplicatedPublicStore([left,S3PublicReplica('replica-two',REGION,'another-fixture',ctx)])

    def test_corrupted_tls_replica_falls_back_without_author_connection(self):
        with server([stored(b'corrupt bytes',self.until)],hostname=HOST) as (ctx,a,_):
            with server([stored(self.data,self.until)],hostname=BUCKET+'.s3.eu-west-1.amazonaws.com') as (ctx2,b,_):
                left=self.replica(ctx,a)
                right=S3PublicReplica('replica-two','eu-west-1',BUCKET,ctx2,dial=b)
                found=ReplicatedPublicStore([left,right]).fetch(self.digest)
        self.assertEqual(found['source'],'replica-two');self.assertEqual(found['failed_replicas'],['replica-one'])
        self.assertEqual(found['data'],self.data)

    def test_signed_upload_tls_passes_opaque_parent_relay(self):
        from test_issuer_relays import proxied
        with server([response(b''),stored(self.data,self.until)],hostname=HOST) as (ctx,dial,seen):
            with proxied(dial) as routed:
                ack=self.replica(ctx,routed,credentials=credentials()).put(self.digest,self.data,
                    retain_until=self.until,repair=False)
        self.assertEqual(ack['digest'],self.digest);self.check_signature(seen[0])

    def test_absolute_deadline_interrupts_response_wait(self):
        original=threading.Timer
        def slow(_):time.sleep(.15);return stored(self.data,self.until)
        with server([slow],hostname=HOST) as (ctx,dial,_):
            with patch('public_s3.threading.Timer',side_effect=lambda _,callback:original(.05,callback)):
                with self.assertRaises(Rejected):self.replica(ctx,dial).get(self.digest,MAX_BYTES)

    def test_untrusted_endpoint_digest_bounds_and_credentials_never_dial(self):
        ctx=ssl.create_default_context();ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        for bucket in ('127.0.0.1','a.b','evil/path','bad--x-s3'):
            with self.assertRaises(Rejected):S3PublicReplica('replica-one',REGION,bucket,ctx)
        with self.assertRaises(Rejected):S3PublicReplica('replica-one','wrong.invalid',BUCKET,ctx)
        replica=self.replica(ctx,lambda:(_ for _ in ()).throw(AssertionError('dialed')))
        for digest,limit in [('../private',MAX_BYTES),(self.digest,MAX_BYTES+1),(self.digest,True)]:
            with self.assertRaises(Rejected):replica.get(digest,limit)


if __name__=='__main__':unittest.main()
