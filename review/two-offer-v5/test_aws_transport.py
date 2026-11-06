"""Real TLS + independently checked SigV4, fixed synthetic credentials only."""
import base64
import hashlib
import hmac
import json
import io
import logging
import os
import ssl
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from aws_transport import AwsJsonClient, AwsFailure
from policy import Rejected, canonical, strict_json
from test_provider_tls import server,response

REGION = 'ap-southeast-2'


def credentials():
    return {'access_key_id':'ASIA'+'A'*16,'secret_access_key':'b'*40,
            'session_token':'c'*32,'expires_at':int(time.time())+3600}


def check_signature(test,raw,service):
    header,body = raw.split(b'\r\n\r\n',1)
    lines=header.decode().split('\r\n');test.assertEqual(lines[0],'POST / HTTP/1.1')
    fields={key.lower():value.strip() for key,value in (line.split(':',1) for line in lines[1:])}
    auth=fields['authorization'];algorithm,parameters=auth.split(' ',1)
    params=dict(p.split('=',1) for p in parameters.split(', '))
    signed=params['SignedHeaders'].split(';')
    test.assertEqual(algorithm,'AWS4-HMAC-SHA256')
    test.assertIn('x-amz-security-token',signed);test.assertIn('x-amz-target',signed)
    test.assertEqual(fields['x-amz-security-token'],credentials()['session_token'])
    canonical_headers=''.join(name+':'+fields[name]+'\n' for name in signed)
    canonical_request='POST\n/\n\n'+canonical_headers+'\n'+params['SignedHeaders']+'\n'+hashlib.sha256(body).hexdigest()
    date=fields['x-amz-date'][:8];scope=date+'/'+REGION+'/'+service+'/aws4_request'
    test.assertEqual(params['Credential'],credentials()['access_key_id']+'/'+scope)
    to_sign=algorithm+'\n'+fields['x-amz-date']+'\n'+scope+'\n'+hashlib.sha256(canonical_request.encode()).hexdigest()
    key=('AWS4'+credentials()['secret_access_key']).encode()
    for value in (date,REGION,service,'aws4_request'):key=hmac.new(key,value.encode(),hashlib.sha256).digest()
    test.assertEqual(params['Signature'],hmac.new(key,to_sign.encode(),hashlib.sha256).hexdigest())
    return fields,json.loads(body)


class AwsTransportTests(unittest.TestCase):
    def test_transient_service_codes_preserved_without_repeating_request_or_diagnostics(self):
        for service,code in (('dynamodb','InternalServerError'),('dynamodb','ServiceUnavailable'),
                             ('kms','DependencyTimeoutException'),('kms','KMSInternalException')):
            payload={'__type':code,'message':'SYNTHETIC-PRIVATE-DIAGNOSTIC'}
            with server([response(canonical(payload),500)],hostname=service+'.'+REGION+'.amazonaws.com') as (ctx,dial,seen):
                with self.assertRaises(AwsFailure) as caught:
                    client=AwsJsonClient(service,REGION,credentials(),ctx,dial)
                    if service=='kms':client.decrypt(CiphertextBlob=b'synthetic')
                    else:client.get_item(TableName='synthetic',Key={'id':{'S':'synthetic'}})
            self.assertEqual(len(seen),1)
            self.assertEqual(caught.exception.response,{'Error':{'Code':code}})
            self.assertNotIn('PRIVATE',str(caught.exception))

    def test_01_real_tls_and_independent_sigv4_request_check(self):
        for service in ('kms','dynamodb'):
            host=service+'.'+REGION+'.amazonaws.com'
            with server([response()],hostname=host) as (ctx,dial,seen):
                client=AwsJsonClient(service,REGION,credentials(),ctx,dial)
                if service=='kms':client.decrypt(KeyId='synthetic',CiphertextBlob=b'public synthetic ciphertext')
                else:client.get_item(TableName='synthetic',Key={'id':{'S':'synthetic'}},ConsistentRead=True)
            self.assertEqual(len(seen),1);headers,body=check_signature(self,seen[0],service)
            self.assertEqual(headers['host'],host)
            self.assertEqual(headers['x-amz-target'],'TrentService.Decrypt' if service=='kms' else 'DynamoDB_20120810.GetItem')
            if service=='kms':self.assertEqual(base64.b64decode(body['CiphertextBlob']),b'public synthetic ciphertext')
            else:self.assertIs(body['ConsistentRead'],True)

    def test_02_sdk_binary_response_decoding(self):
        payload={'KeyId':'synthetic','EncryptionAlgorithm':'SYMMETRIC_DEFAULT',
                 'CiphertextForRecipient':base64.b64encode(b'public synthetic CMS').decode()}
        with server([response(canonical(payload))],hostname='kms.'+REGION+'.amazonaws.com') as (ctx,dial,_):
            result=AwsJsonClient('kms',REGION,credentials(),ctx,dial).decrypt(CiphertextBlob=b'synthetic')
        self.assertEqual(result['CiphertextForRecipient'],b'public synthetic CMS')

    def test_03_encrypted_state_response_exceeds_provider_limit_safely(self):
        data=b'x'*262172
        payload={'Item':{'id':{'S':'synthetic'},'envelope':{'B':base64.b64encode(data).decode()}}}
        self.assertGreater(len(canonical(payload)),131072)
        with self.assertRaises(Rejected):strict_json(canonical(payload))
        with server([response(canonical(payload))],hostname='dynamodb.'+REGION+'.amazonaws.com') as (ctx,dial,_):
            result=AwsJsonClient('dynamodb',REGION,credentials(),ctx,dial).get_item(TableName='synthetic',Key={'id':{'S':'synthetic'}})
        self.assertEqual(result['Item']['envelope']['B'],data)

    def test_04_wrong_hostname_and_untrusted_ca_receive_no_authorization(self):
        for options in ({'hostname':'wrong.invalid'},{'hostname':'kms.'+REGION+'.amazonaws.com','untrusted':True}):
            with server([response()],**options) as (ctx,dial,seen):
                with self.assertRaisesRegex(Rejected,'^aws-unavailable$'):
                    AwsJsonClient('kms',REGION,credentials(),ctx,dial).decrypt(CiphertextBlob=b'synthetic')
            self.assertEqual(seen,[])

    def test_05_redirect_not_followed(self):
        with server([response(status=302,headers=[('Location','https://wrong.invalid'),('Content-Length','0')])],
                    hostname='kms.'+REGION+'.amazonaws.com') as (ctx,dial,seen):
            with self.assertRaises(Rejected):AwsJsonClient('kms',REGION,credentials(),ctx,dial).decrypt(CiphertextBlob=b'synthetic')
        self.assertEqual(len(seen),1)

    def test_06_ambiguous_oversized_encoded_and_duplicate_json_rejected(self):
        responses=[response(headers=[('Content-Type','application/json'),('Content-Length','2'),('Content-Length','2')]),
                   response(headers=[('Content-Type','application/json'),('Content-Length','1048577')]),
                   response(headers=[('Content-Type','application/json'),('Content-Encoding','gzip'),('Content-Length','2')]),
                   response(b'{"Item":{},"Item":{}}')]
        for reply in responses:
            with server([reply],hostname='kms.'+REGION+'.amazonaws.com') as (ctx,dial,_):
                with self.assertRaises(Rejected):AwsJsonClient('kms',REGION,credentials(),ctx,dial).decrypt(CiphertextBlob=b'synthetic')

    def test_07_conditional_error_preserves_only_safe_codes(self):
        payload={'__type':'com.amazonaws.dynamodb.v20120810#TransactionCanceledException',
                 'message':'SYNTHETIC-PRIVATE-DIAGNOSTIC','CancellationReasons':[
                     {'Code':'ConditionalCheckFailed','Message':'PRIVATE'},{'Code':'None'}]}
        with server([response(canonical(payload),400)],hostname='dynamodb.'+REGION+'.amazonaws.com') as (ctx,dial,_):
            with self.assertRaises(AwsFailure) as caught:
                AwsJsonClient('dynamodb',REGION,credentials(),ctx,dial).transact_write_items(TransactItems=[
                    {'Put':{'TableName':'synthetic','Item':{'id':{'S':'synthetic'}}}}])
        self.assertEqual(caught.exception.response,{'Error':{'Code':'TransactionCanceledException'},
            'CancellationReasons':[{'Code':'ConditionalCheckFailed'},{'Code':'None'}]})
        self.assertNotIn('PRIVATE',str(caught.exception))

    def test_08_no_retry_after_uncertain_transport_failure(self):
        ctx=ssl.create_default_context();ctx.minimum_version=ssl.TLSVersion.TLSv1_2;calls=[]
        def dial():calls.append(True);raise TimeoutError('SYNTHETIC-PRIVATE-DIAGNOSTIC')
        with self.assertRaisesRegex(Rejected,'^aws-unavailable$'):
            AwsJsonClient('kms',REGION,credentials(),ctx,dial).decrypt(CiphertextBlob=b'synthetic')
        self.assertEqual(len(calls),1)

    def test_09_invalid_expired_credentials_and_operations_never_dial(self):
        ctx=ssl.create_default_context();ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        dial=lambda:(_ for _ in ()).throw(AssertionError('dialed'))
        for mutation in ({'expires_at':0},{'access_key_id':'AKIA'+'A'*16},{'secret_access_key':'bad\r\nheader'}):
            with self.assertRaises(Rejected):AwsJsonClient('kms',REGION,{**credentials(),**mutation},ctx,dial)
        client=AwsJsonClient('kms',REGION,credentials(),ctx,dial)
        with self.assertRaises(Rejected):client.get_item(TableName='synthetic',Key={'id':{'S':'synthetic'}})
        client._credential_data['expires_at']=0
        with self.assertRaisesRegex(Rejected,'aws-credentials-expired'):client.decrypt(CiphertextBlob=b'synthetic')

    def test_10_no_ambient_aws_credentials_config_proxy_or_session(self):
        with patch.dict(os.environ,{'AWS_ACCESS_KEY_ID':'DO-NOT-USE','AWS_SECRET_ACCESS_KEY':'DO-NOT-USE',
             'AWS_PROFILE':'DO-NOT-OPEN','AWS_CONFIG_FILE':'/do-not-open','HTTPS_PROXY':'http://wrong.invalid',
             'AWS_SHARED_CREDENTIALS_FILE':'/do-not-open'}):
            with server([response()],hostname='kms.'+REGION+'.amazonaws.com') as (ctx,dial,seen):
                AwsJsonClient('kms',REGION,credentials(),ctx,dial).decrypt(CiphertextBlob=b'synthetic')
        check_signature(self,seen[0],'kms');self.assertNotIn(b'DO-NOT-USE',seen[0])

    def test_11_insecure_tls_and_arbitrary_services_hosts_rejected(self):
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        with self.assertRaises(Rejected):AwsJsonClient('kms',REGION,credentials(),ctx)
        for service,region in [('sts',REGION),('https://wrong.invalid',REGION),('kms','wrong.invalid')]:
            with self.assertRaises(Rejected):AwsJsonClient(service,region,credentials(),ssl.create_default_context())

    def test_12_recipient_provisioning_through_real_tls_and_sdk_codec(self):
        from provisioning import RecipientProvisioner,PROFILE
        from test_provisioning import FakeNsm,encrypt_cms,ARN,NAMESPACE,AUTHORITY
        nsm=FakeNsm()
        def kms(raw):
            headers,body=check_signature(self,raw,'kms')
            self.assertEqual(body['Recipient']['KeyEncryptionAlgorithm'],'RSAES_OAEP_SHA_256')
            self.assertEqual(base64.b64decode(body['Recipient']['AttestationDocument']),b'synthetic-NSM-document')
            plaintext=canonical({'profile':PROFILE,'context':body['EncryptionContext'],
                                 'value':'SYNTHETIC-TWITTERAPI-KEY-NOT-A-CREDENTIAL'})
            cms=encrypt_cms(nsm.calls[-1][1],plaintext)
            return response(canonical({'KeyId':ARN,'EncryptionAlgorithm':'SYMMETRIC_DEFAULT',
                                       'CiphertextForRecipient':base64.b64encode(cms).decode()}))
        with server([kms],hostname='kms.'+REGION+'.amazonaws.com') as (ctx,dial,seen):
            client=AwsJsonClient('kms',REGION,credentials(),ctx,dial)
            provisioner=RecipientProvisioner(client,nsm,ARN,NAMESPACE,AUTHORITY)
            self.assertEqual(provisioner.decrypt('twitterapi-key',b'synthetic KMS ciphertext'),
                             'SYNTHETIC-TWITTERAPI-KEY-NOT-A-CREDENTIAL')
        self.assertEqual(len(seen),1)

    def test_13_sdk_debug_cannot_log_session_tokens_or_response_bodies(self):
        output=io.StringIO();handler=logging.StreamHandler(output)
        loggers=[logging.getLogger(name) for name in ('botocore.auth','botocore.parsers','botocore.credentials')]
        before=[(logger.level,list(logger.handlers),logger.propagate) for logger in loggers]
        try:
            for logger in loggers:
                logger.setLevel(logging.DEBUG);logger.handlers=[handler];logger.propagate=False
            payload={'KeyId':'SYNTHETIC-PRIVATE-MARKER','CiphertextForRecipient':base64.b64encode(b'synthetic').decode()}
            with patch('http.client.HTTPConnection.debuglevel',1),redirect_stdout(output):
                with server([response(canonical(payload))],hostname='kms.'+REGION+'.amazonaws.com') as (ctx,dial,_):
                    AwsJsonClient('kms',REGION,credentials(),ctx,dial).decrypt(CiphertextBlob=b'synthetic')
            self.assertEqual(output.getvalue(),'')
        finally:
            for logger,(level,handlers,propagate) in zip(loggers,before):
                logger.setLevel(level);logger.handlers=handlers;logger.propagate=propagate

    def test_14_initial_data_key_recipient_uses_actual_sdk_tls_codec(self):
        from provisioning import encryption_context
        from test_provisioning import ARN,NAMESPACE,AUTHORITY
        payload={'KeyId':ARN,'CiphertextBlob':base64.b64encode(b'public wrapped key').decode(),
                 'CiphertextForRecipient':base64.b64encode(b'public encrypted recipient CMS').decode()}
        with server([response(canonical(payload))],hostname='kms.'+REGION+'.amazonaws.com') as (ctx,dial,seen):
            client=AwsJsonClient('kms',REGION,credentials(),ctx,dial)
            result=client.generate_data_key(KeyId=ARN,KeySpec='AES_256',
                EncryptionContext=encryption_context('blind-issuer-key',NAMESPACE,AUTHORITY),
                Recipient={'KeyEncryptionAlgorithm':'RSAES_OAEP_SHA_256','AttestationDocument':b'synthetic'})
        fields,body=check_signature(self,seen[0],'kms')
        self.assertEqual(fields['x-amz-target'],'TrentService.GenerateDataKey')
        self.assertEqual(body['KeySpec'],'AES_256');self.assertNotIn('NumberOfBytes',body)
        self.assertEqual(result['CiphertextBlob'],b'public wrapped key')
        self.assertEqual(result['CiphertextForRecipient'],b'public encrypted recipient CMS')


if __name__=='__main__':unittest.main()
