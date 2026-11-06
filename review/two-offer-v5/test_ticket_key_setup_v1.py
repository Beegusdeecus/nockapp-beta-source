"""Three real synthetic service/TLS keys; AWS responses and setup IAM are fixtures."""
import base64
import copy
from datetime import datetime,timedelta,timezone
import fcntl
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock,patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from aws_transport import AwsJsonClient
from base_protocol import ReceiptKey
from policy import canonical,Rejected
from public_s3_v5 import budget_scope
from public_storage_budget import RESOURCES
from ticket_aws_credentials_v1 import tls_context
from test_aws_transport import credentials
import test_ticket_backend_boot_v1 as boots
import ticket_key_setup_v1 as setup

def b64(data):return base64.b64encode(data).decode()
def pin(value):return setup.storage.sha(canonical(value))

class KeySetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):boots.BackendBootTests.setUpClass()
    def setUp(self):
        f=boots.BackendBootTests();f.setUp();self.addCleanup(f.doCleanups)
        self.temp=tempfile.TemporaryDirectory(prefix='ticket-key-setup-fixture-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.output=self.root/'sealed'
        refund=copy.deepcopy(f.cfg);publication_key=ec.generate_private_key(ec.SECP256K1())
        bindings={**f.keys,'publication':ReceiptKey(None,publication_key).address}
        payment=f.config('payment',f.f.offer,bindings,{'purchase_bucket':'private-refund-lab'})
        publication=copy.deepcopy(payment);publication.update(role='publication',records={
            'account_id':boots.ACCOUNT,'region':'ap-southeast-2','ledger_bucket':'private-publication-ledger'},
            transaction=copy.deepcopy(refund['transaction']),author_native_sha256='ab'*32)
        limits={r:10**9 for r in RESOURCES};limits['retained_byte_seconds']=10**12;retention=90*86400
        publication['origin']={'region':'ap-southeast-2','account_id':boots.ACCOUNT,'bucket':'public-setup-fixture',
            'retention_seconds':retention,'budget_limits':limits,'budget_scope':budget_scope('ap-southeast-2',
            'public-setup-fixture',boots.ACCOUNT,limits,retention),'budget_table_arn':
            'arn:aws:dynamodb:ap-southeast-2:'+boots.ACCOUNT+':table/synthetic-table','budget_namespace':'ab'*32}
        self.configs={'payment':payment,'publication':publication,'refund':refund}
        now=datetime.now(timezone.utc);rootkey=ec.generate_private_key(ec.SECP256R1())
        ca=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic setup CA')])
        root=(x509.CertificateBuilder().subject_name(ca).issuer_name(ca).public_key(rootkey.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=2))
            .not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(True,0),True)
            .add_extension(x509.KeyUsage(True,False,False,False,False,True,True,None,None),True).sign(rootkey,hashes.SHA256()))
        rootder=root.public_bytes(serialization.Encoding.DER);self.bodies={}
        keys={'payment':f.f.f.crypto.private,'publication':boots.private(publication_key),'refund':boots.private(f.f.key.key)}
        for role,cfg in self.configs.items():
            leafkey=ec.generate_private_key(ec.SECP256R1());hostname=role+'.example.test'
            cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)]))
                .issuer_name(ca).public_key(leafkey.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1))
                .add_extension(x509.BasicConstraints(False,None),True)
                .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,None,None),True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]),False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(rootkey,hashes.SHA256()))
            cfg['key_bindings']=copy.deepcopy(bindings);cfg['tls']={'hostname':hostname,
                'root_certificate_der':b64(rootder),'root_sha256':setup.storage.sha(rootder),
                'key_sha256':setup.storage.sha(boots.der_public(leafkey.public_key()))}
            self.bodies[role]={'profile':boots.PRIVATE,'role':role,'config_sha256':pin(cfg),
                'service_key_der':b64(keys[role]),'tls_private_key_der':b64(boots.private(leafkey)),
                'tls_certificate_der':b64(cert.public_bytes(serialization.Encoding.DER))}
        self.key_arn='arn:aws:kms:ap-southeast-2:'+boots.ACCOUNT+':key/12345678-1234-1234-1234-123456789abc'
        self.plan={'profile':setup.PROFILE,'purpose':'new-host-service-keys','roles':{role:{'backend':cfg,
            'backend_sha256':pin(cfg),'kms_key_arn':self.key_arn} for role,cfg in self.configs.items()}}
        self.client=AwsJsonClient('kms','ap-southeast-2',credentials(),tls_context());self.data={}
        def generate(**args):
            role=args['EncryptionContext']['role'];key=os.urandom(32);wrapped=b'SYNTHETIC-WRAPPED-'+role.encode()
            self.data[wrapped]=key;return {'KeyId':self.key_arn,'Plaintext':key,'CiphertextBlob':wrapped}
        self.generate=Mock(side_effect=generate);self.client.generate_data_key=self.generate
        self.clients={r:self.client for r in setup.ROLES};self.descriptors={}
    def pipes(self,bodies=None):
        for role,body in (bodies or self.bodies).items():
            read,write=socket.socketpair();self.addCleanup(read.close);self.addCleanup(write.close)
            write.sendall(canonical(body));write.shutdown(socket.SHUT_WR);self.descriptors[role]=read.fileno()
        return self.descriptors
    def prepare(self):return setup.prepare(self.plan,pin(self.plan),self.descriptors,clients=self.clients,output=self.output)
    def decrypt(self,role):
        raw=(self.output/(role+'.json')).read_bytes();value=json.loads(raw);wrapped=base64.b64decode(value['wrapped_key'])
        aad=canonical({'profile':value['profile'],'role':role,'backend_sha256':value['backend_sha256'],
            'kms_key_arn':value['kms_key_arn'],'wrapped_key_sha256':setup.storage.sha(wrapped)})
        return json.loads(AESGCM(self.data[wrapped]).decrypt(base64.b64decode(value['nonce']),base64.b64decode(value['ciphertext']),aad))

    def test_three_real_role_keys_are_validated_sealed_and_durably_stored(self):
        self.pipes();reads=[];original=setup.seal.read_private
        def read(fd):reads.append(fd);return original(fd)
        generate=self.generate.side_effect
        def guarded(**args):self.assertGreaterEqual(len(reads),3);return generate(**args)
        self.generate.side_effect=guarded
        with patch.object(setup.seal,'read_private',side_effect=read):result=self.prepare()
        self.assertTrue(result['ok']);self.assertFalse(result['outcome_unknown']);self.assertTrue(result['journal_updated'])
        self.assertEqual(result['kms_attempts'],list(setup.ROLES));self.assertEqual(self.generate.call_count,3)
        for role in setup.ROLES:self.assertEqual(self.decrypt(role),self.bodies[role])
        stage=Path(result['stage']);self.assertEqual(json.loads((stage/'status.json').read_bytes()),result)
        for file in stage.iterdir():
            if file.is_file():
                for body in self.bodies.values():self.assertNotIn(body['service_key_der'].encode(),file.read_bytes())
        self.assertEqual({p.name for p in self.output.iterdir()},{r+'.json' for r in setup.ROLES})

    def test_bad_final_private_role_stops_before_any_kms_call(self):
        bodies=copy.deepcopy(self.bodies);bodies['refund']['service_key_der']=bodies['publication']['service_key_der'];self.pipes(bodies)
        result=self.prepare();self.assertFalse(result['ok']);self.generate.assert_not_called()
        self.assertFalse(self.output.exists());self.assertFalse(result['outcome_unknown'])
        self.assertEqual(result['validated_roles'],['payment','publication'])

    def test_existing_output_rejects_before_private_read_and_kms(self):
        self.pipes();self.output.mkdir();marker=self.output/'keep';marker.write_bytes(b'EXISTING')
        with patch.object(setup.seal,'read_private',side_effect=AssertionError('no keys read')),self.assertRaises(Rejected):self.prepare()
        self.generate.assert_not_called();self.assertEqual(marker.read_bytes(),b'EXISTING')

    def test_wrong_public_pin_or_cross_role_scope_rejects_before_staging(self):
        self.pipes()
        with self.assertRaises(Rejected):setup.prepare(self.plan,'12'*32,self.descriptors,clients=self.clients,output=self.output)
        self.plan['roles']['refund']['kms_key_arn']=self.key_arn.replace(boots.ACCOUNT,'999999999999')
        with self.assertRaises(Rejected):self.prepare()
        self.assertEqual(list(self.root.iterdir()),[]);self.generate.assert_not_called()

    def test_duplicate_fd_or_nonpipe_input_rejects_before_writes(self):
        original=self.pipes().copy();self.descriptors['refund']=self.descriptors['payment']
        with self.assertRaises(Rejected):self.prepare()
        self.descriptors=original;fd=os.memfd_create('synthetic-not-a-private-pipe');self.addCleanup(os.close,fd)
        self.descriptors['refund']=fd
        with self.assertRaises(Rejected):self.prepare()
        self.assertEqual(list(self.root.iterdir()),[]);self.generate.assert_not_called()

    def test_split_tls_or_offer_configuration_rejects_before_private_read(self):
        self.pipes();value=self.plan['roles']['publication'];value['backend']['tls']=copy.deepcopy(self.configs['payment']['tls'])
        value['backend_sha256']=pin(value['backend'])
        with patch.object(setup.seal,'read_private',side_effect=AssertionError('no keys read')),self.assertRaises(Rejected):self.prepare()
        self.generate.assert_not_called();self.assertEqual(list(self.root.iterdir()),[])

    def test_coordinator_lock_conflict_never_consumes_private_input(self):
        self.pipes();path=self.root/'.nockapp-ticket-setup-sealed.lock'
        fd=os.open(path,os.O_RDWR|os.O_CREAT,0o600);self.addCleanup(os.close,fd);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with patch.object(setup.seal,'read_private',side_effect=AssertionError('no keys read')),self.assertRaises(BlockingIOError):self.prepare()
        self.generate.assert_not_called();self.assertFalse(self.output.exists())

    def test_second_kms_failure_retains_first_encrypted_packet_without_retry(self):
        self.pipes();generate=self.generate.side_effect
        def fail(**args):
            if args['EncryptionContext']['role']=='publication':raise TimeoutError('SYNTHETIC-SECRET-FAILURE')
            return generate(**args)
        self.generate.side_effect=fail;result=self.prepare()
        self.assertFalse(result['ok']);self.assertTrue(result['kms_outcome_unknown']);self.assertTrue(result['outcome_unknown'])
        self.assertEqual(self.generate.call_count,2);self.assertFalse(self.output.exists())
        self.assertTrue((Path(result['stage'])/'payment.json').is_file());self.assertEqual(set(result['sealed_sha256']),{'payment'})
        self.assertNotIn('SYNTHETIC',json.dumps(result))

    def test_lost_storage_commit_reply_retains_all_ciphertexts_and_unknown_result(self):
        self.pipes();commit=setup.storage.commit;observed=[]
        def check_intent(*args):
            journals=list(self.root.glob('.nockapp-ticket-key-setup-*/status.json'));self.assertEqual(len(journals),1)
            journal=json.loads(journals[0].read_bytes());self.assertEqual(journal['phase'],'storage-intent')
            self.assertTrue(journal['outcome_unknown']);observed.append(True)
            commit(*args);raise TimeoutError('SYNTHETIC-LOST-COMMIT')
        with patch.object(setup.storage,'commit',side_effect=check_intent):result=self.prepare()
        self.assertFalse(result['ok']);self.assertTrue(result['outcome_unknown']);self.assertEqual(self.generate.call_count,3)
        self.assertEqual(observed,[True])
        for role in setup.ROLES:
            self.assertTrue((Path(result['stage'])/(role+'.json')).is_file());self.assertEqual(self.decrypt(role),self.bodies[role])

    def test_uncertain_success_journal_never_reports_success_or_retries(self):
        self.pipes();write=setup.storage.write_new
        def fail(fd,name,data):
            if name.startswith('status-'):
                value=json.loads(data)
                if value.get('profile')==setup.PROFILE and value.get('ok'):raise OSError('SYNTHETIC-JOURNAL-FAILURE')
            return write(fd,name,data)
        with patch.object(setup.storage,'write_new',side_effect=fail):result=self.prepare()
        self.assertFalse(result['ok']);self.assertTrue(result['outcome_unknown']);self.assertEqual(self.generate.call_count,3)
        self.assertTrue(self.output.is_dir());self.assertTrue(result['journal_updated'])

if __name__=='__main__':unittest.main()
