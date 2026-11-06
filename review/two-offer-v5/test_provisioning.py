"""Local RSA/CMS and NSM rejection, not real KMS or Nitro acceptance."""
import datetime
import hashlib
import os
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from enclave_nsm import BINARY, Nsm, prepare
from policy import Rejected, canonical
from provisioning import PROFILE, KINDS, RecipientProvisioner, encryption_context, validate_value

ARN = 'arn:aws:kms:ap-southeast-2:123456789012:key/12345678-1234-1234-1234-123456789abc'
NAMESPACE = 'ab'*32
AUTHORITY = 'cd'*32


def encrypt_cms(public,plaintext):
    """Fixture emits real OAEP-SHA256/AES256-CBC CMS for the captured NSM key."""
    key = serialization.load_der_public_key(public)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic KMS Recipient')])
    now = datetime.datetime.now(datetime.timezone.utc)
    # The certificate is fixture metadata only; KMS receives just the public key.
    signing = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key)
        .serial_number(1).not_valid_before(now-datetime.timedelta(minutes=1))
        .not_valid_after(now+datetime.timedelta(minutes=5)).sign(signing,hashes.SHA256()))
    fd = os.memfd_create('synthetic-kms-recipient-cert',os.MFD_CLOEXEC)
    try:
        os.write(fd,cert.public_bytes(serialization.Encoding.PEM))
        result = subprocess.run(['/usr/bin/openssl','cms','-encrypt','-binary','-aes-256-cbc','-outform','DER',
            '-recip',f'/proc/self/fd/{fd}','-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256',
            '-keyopt','rsa_mgf1_md:sha256'],input=plaintext,capture_output=True,timeout=5,pass_fds=(fd,),
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
        assert result.returncode == 0 and not result.stderr
        return result.stdout
    finally:os.close(fd)


class FakeNsm:
    def __init__(self):self.calls=[]
    def attest(self,nonce,public,user_data):
        self.calls.append((nonce,public,user_data));return b'synthetic-NSM-document'


class FakeKms:
    def __init__(self,nsm):self.nsm=nsm;self.calls=[];self.mutate=lambda p:p;self.mutate_response=lambda r:r
    def decrypt(self,**arguments):
        self.calls.append(arguments)
        value = 'SYNTHETIC-TWITTERAPI-KEY-NOT-A-CREDENTIAL'
        if arguments['EncryptionContext']['kind'] == 'blind-issuer-key':value = 'ef'*32
        secret = self.mutate({'profile':PROFILE,'context':arguments['EncryptionContext'],'value':value})
        encrypted = encrypt_cms(self.nsm.calls[-1][1],canonical(secret))
        return self.mutate_response({'KeyId':arguments['KeyId'],'EncryptionAlgorithm':'SYMMETRIC_DEFAULT',
                                    'CiphertextForRecipient':encrypted})


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.nsm = FakeNsm();self.kms = FakeKms(self.nsm)
        self.provisioner = RecipientProvisioner(self.kms,self.nsm,ARN,NAMESPACE,AUTHORITY)

    def test_01_real_oaep_cms_only_enclave_recipient_can_decrypt(self):
        self.assertEqual(self.provisioner.decrypt('twitterapi-key',b'synthetic-KMS-ciphertext'),
                         'SYNTHETIC-TWITTERAPI-KEY-NOT-A-CREDENTIAL')
        self.assertEqual(self.provisioner.decrypt('blind-issuer-key',b'synthetic-state-key'),bytes.fromhex('ef'*32))
        self.assertNotEqual(self.nsm.calls[0][1],self.nsm.calls[1][1])
        self.assertNotEqual(self.nsm.calls[0][0],self.nsm.calls[1][0])

    def test_02_exact_recipient_context_and_binding(self):
        self.provisioner.decrypt('twitterapi-key',b'synthetic')
        request = self.kms.calls[0]
        self.assertEqual(set(request),{'KeyId','CiphertextBlob','EncryptionAlgorithm','EncryptionContext','Recipient'})
        self.assertEqual(request['Recipient'],{'KeyEncryptionAlgorithm':'RSAES_OAEP_SHA_256',
                                             'AttestationDocument':b'synthetic-NSM-document'})
        self.assertEqual(request['EncryptionContext'],encryption_context('twitterapi-key',NAMESPACE,AUTHORITY))
        self.assertEqual(len(self.nsm.calls[0][1]),294)
        self.assertEqual(len(self.nsm.calls[0][2]),32)
        self.assertEqual(len(self.nsm.calls[0][0]),32)

    def test_03_plaintext_response_always_rejected_without_cms_decryption(self):
        for value in (b'private', 'private'):
            self.kms.mutate_response=lambda r:{**r,'Plaintext':value}
            with patch.object(self.provisioner,'_decrypt_cms') as cms:
                with self.assertRaisesRegex(Rejected,'^provisioning-unavailable$'):
                    self.provisioner.decrypt('twitterapi-key',b'synthetic')
                cms.assert_not_called()

    def test_04_wrong_key_algorithm_missing_recipient_and_unknown_fields_rejected(self):
        for mutation in (lambda r:{**r,'KeyId':ARN+'wrong'},lambda r:{**r,'EncryptionAlgorithm':'RSAES_OAEP_SHA_1'},
                         lambda r:{k:v for k,v in r.items() if k != 'CiphertextForRecipient'},
                         lambda r:{**r,'private':'SYNTHETIC-PRIVATE-MARKER'}):
            self.kms.mutate_response=mutation
            with self.assertRaisesRegex(Rejected,'^provisioning-unavailable$'):
                self.provisioner.decrypt('twitterapi-key',b'synthetic')

    def test_05_wrong_secret_namespace_authority_kind_profile_and_value_rejected(self):
        for mutation in (lambda p:{**p,'profile':'wrong'},lambda p:{**p,'context':{}},
                         lambda p:{**p,'context':{**p['context'],'issuer':'11'*32}},
                         lambda p:{**p,'context':{**p['context'],'state-authority':'11'*32}},
                         lambda p:{**p,'context':{**p['context'],'kind':'blind-issuer-key'}},
                         lambda p:{**p,'value':'header\r\ninjection'},lambda p:{**p,'extra':'wrong'}):
            self.kms.mutate=mutation
            with self.assertRaisesRegex(Rejected,'^provisioning-unavailable$'):
                self.provisioner.decrypt('twitterapi-key',b'synthetic')

    def test_06_wrong_recipient_cms_and_cms_corruption_rejected(self):
        other = rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_bytes(
            serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        for content in (b'malformed CMS',encrypt_cms(other,b'synthetic')):
            self.kms.mutate_response=lambda r:{**r,'CiphertextForRecipient':content}
            with self.assertRaisesRegex(Rejected,'^provisioning-unavailable$'):
                self.provisioner.decrypt('twitterapi-key',b'synthetic')

    def test_07_no_retry_after_kms_uncertainty(self):
        def fail(**kwargs):raise RuntimeError('SYNTHETIC-PRIVATE-DIAGNOSTIC')
        with patch.object(self.kms,'decrypt',side_effect=fail) as call:
            with self.assertRaisesRegex(Rejected,'^provisioning-unavailable$'):
                self.provisioner.decrypt('twitterapi-key',b'synthetic')
            self.assertEqual(call.call_count,1)

    def test_08_bad_kind_ciphertext_and_nsm_failure_do_not_call_kms(self):
        for kind,content in [('unknown',b'synthetic'),('twitterapi-key',b''),('twitterapi-key',b'x'*6145)]:
            with self.assertRaises(Rejected):self.provisioner.decrypt(kind,content)
        self.assertEqual(self.kms.calls,[])
        with patch.object(self.nsm,'attest',side_effect=Rejected('nsm-unavailable')):
            with self.assertRaises(Rejected):self.provisioner.decrypt('twitterapi-key',b'synthetic')
        self.assertEqual(self.kms.calls,[])

    def test_09_nsm_source_matches_pinned_archive(self):
        self.assertGreater(len(prepare()),10)

    def test_10_real_nsm_executable_rejects_bad_inputs_quietly(self):
        good = {'nonce':[1]*32,'public_key':[2]*294,'user_data':[3]*32}
        for data in (b'{}',b'x'*8193,canonical({**good,'private':'extra'}),
                     canonical({**good,'public_key':[1]*295}),canonical({**good,'nonce':[1]*31})):
            result = subprocess.run([str(BINARY)],input=data,capture_output=True,timeout=3,
                                    env={'PATH':'/usr/bin:/bin','RUST_LOG':'trace'})
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'')

    def test_11_real_missing_nsm_never_simulates(self):
        if Path('/dev/nsm').exists():self.skipTest('local missing-device check requires no NSM')
        nsm = Nsm()
        with self.assertRaisesRegex(Rejected,'^nsm-unavailable$'):nsm.attest(b'1'*32,b'2'*294,b'3'*32)

    def test_12_nsm_cannot_accept_private_or_arbitrary_size_fields(self):
        nsm = Nsm()
        for nonce,public,data in [(b'1'*31,b'2'*294,b'3'*32),(b'1'*32,b'2'*1024,b'3'*32),
                                  (b'1'*32,b'2'*33,b'3'*31)]:
            with self.assertRaises(Rejected):nsm.attest(nonce,public,data)

    def test_13_managed_writer_requires_short_lived_explicit_credentials(self):
        value = {'access_key_id':'ASIA'+'A'*16,'secret_access_key':'b'*40,
                 'session_token':'c'*32,'expires_at':int(time.time())+3600}
        self.assertEqual(validate_value('managed-writer-credentials',value),value)
        for field,bad in [('access_key_id','AKIA'+'A'*16),('secret_access_key','bad\nvalue'),
                          ('session_token','bad\nvalue'),('expires_at',int(time.time())-1),
                          ('expires_at',int(time.time())+86400)]:
            with self.assertRaises(Rejected):validate_value('managed-writer-credentials',{**value,field:bad})
        with self.assertRaises(Rejected):validate_value('managed-writer-credentials',{**value,'profile':'ambient'})

    def test_14_current_kms_policy_pins_context_and_writer_secret(self):
        from kms_policy import recipient_fragment
        role='arn:aws:iam::123456789012:role/synthetic-parent-decrypt-only'
        policy=recipient_fragment(role,'11'*48,'22'*48,NAMESPACE,AUTHORITY)
        allow=policy['Statement'][-1]
        fields=allow['Condition']['StringEquals']
        self.assertEqual(fields['kms:EncryptionContext:kind'],sorted(KINDS))
        self.assertEqual(fields['kms:EncryptionContext:issuer'],NAMESPACE)
        self.assertEqual(fields['kms:EncryptionContext:state-authority'],AUTHORITY)
        denies=policy['Statement'][:-1]
        self.assertEqual(len(denies),6)
        self.assertTrue(all(s['Effect']=='Deny' and s['Action']=='kms:Decrypt' for s in denies))
        denied_fields={key for statement in denies for condition in statement['Condition'].values() for key in condition}
        self.assertTrue(set(fields)<=denied_fields)
        self.assertTrue({'kms:RecipientAttestation:PCR0','kms:RecipientAttestation:PCR8'}<=denied_fields)

    def test_15_current_kms_policy_rejects_zero_missing_and_unapproved_context(self):
        from kms_policy import recipient_fragment
        for namespace,authority in [('00'*32,AUTHORITY),(NAMESPACE,'00'*32),('',AUTHORITY)]:
            with self.assertRaises(Rejected):
                recipient_fragment('arn:aws:iam::123456789012:role/synthetic','11'*48,'22'*48,namespace,authority)

    def test_16_no_private_material_in_child_arguments_or_disk_paths(self):
        # Exercise actual CMS decrypt and inspect its invocation without logging
        # the captured private pipe data or the recipient memfd contents.
        real_run = subprocess.run
        calls=[]
        def capture(argv,**kwargs):
            calls.append((argv,kwargs.get('pass_fds'),kwargs.get('preexec_fn')))
            return real_run(argv,**kwargs)
        with patch('provisioning.subprocess.run',side_effect=capture):
            self.provisioner.decrypt('twitterapi-key',b'synthetic')
        decrypt=[call for call in calls if '-decrypt' in call[0]]
        self.assertEqual(len(decrypt),1)
        argv,fds,guard=decrypt[0]
        self.assertEqual(argv[-1],'/proc/self/fd/'+str(fds[0]));self.assertIsNotNone(guard)
        self.assertFalse(any('PRIVATE KEY' in argument or 'SYNTHETIC' in argument for argument in argv))


if __name__ == '__main__':unittest.main()
