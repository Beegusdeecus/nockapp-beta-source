"""Real X509/ECDSA/TLS/SigV4; KMS and credential authority are synthetic.

Synthetic KMS private key stays in fixture memory. Production accepts public
KMS SPKI only. No key, credential or raw HTTP transcript is persisted.
"""
import base64
import copy
import hashlib
import json
import pickle
import socket
import ssl
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,utils
from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID
from policy import canonical,digest,Rejected
from test_provider_tls import server,response
from test_ticket_aws_credentials_v1 import creds
from workload_sessions import WorkloadSession,WorkloadCredentials
import test_ticket_new_keys_v1 as generated
import ticket_host_tls_ca_v1 as ca


class SyntheticSession(WorkloadSession):
    def __init__(self):self.calls=0
    def create_session(self):
        self.calls+=1;return creds('AB'[min(self.calls-1,1)],duration=900*self.calls)


class HostCaTests(unittest.TestCase):
    def setUp(self):
        self.fresh=generated.generate();self.addCleanup(self.fresh.close)
        self.key=ec.generate_private_key(ec.SECP256R1());self.now=int(time.time())
        raw=ca.spki(self.key.public_key())
        self.policy={'profile':ca.PROFILE,
            'kms_key_arn':'arn:aws:kms:'+ca.REGION+':'+ca.ACCOUNT+':key/12345678-1234-1234-1234-123456789abc',
            'ca_spki_der':ca.b64(raw),'ca_spki_sha256':ca.sha(raw),'root_not_before':self.now-120,
            'root_not_after':self.now+90*86400,'leaf_seconds':86400,'renew_before_seconds':3600,
            'services':self.fresh.public()['tls']}
        self.source=WorkloadCredentials(SyntheticSession());self.calls=[]

    def reply(self,operation,args):
        self.calls.append((operation,copy.deepcopy(args)))
        if operation=='GetPublicKey':
            return {'KeyId':self.policy['kms_key_arn'],'PublicKey':ca.b64(ca.spki(self.key.public_key())),
                'KeyUsage':'SIGN_VERIFY','KeySpec':'ECC_NIST_P256','SigningAlgorithms':[ca.ALGORITHM]}
        self.assertEqual(operation,'Sign');self.assertEqual(args['KeyId'],self.policy['kms_key_arn'])
        self.assertEqual(args['MessageType'],'DIGEST');self.assertEqual(args['SigningAlgorithm'],ca.ALGORITHM)
        data=base64.b64decode(args['Message']);self.assertEqual(len(data),32)
        signature=self.key.sign(data,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return {'KeyId':self.policy['kms_key_arn'],'SigningAlgorithm':ca.ALGORITHM,'Signature':ca.b64(signature)}

    def authority(self,*,root=None):
        signer=ca.KmsSigner(self.policy['kms_key_arn'],self.source,ca_context())
        mocked=patch.object(signer,'_call',side_effect=self.reply);mocked.start();self.addCleanup(mocked.stop)
        authority=ca.HostCA(self.policy,digest(self.policy),signer,root_record=root,
            root_pin=digest(root) if root is not None else None)
        if root is None:root=authority.create_root()
        return authority,root

    def test_kms_signed_root_and_three_fixed_role_leaves_are_valid_and_do_not_reuse_ca_key(self):
        authority,record=self.authority();root=x509.load_der_x509_certificate(ca.un64(record['certificate_der'],8192))
        root.verify_directly_issued_by(root)
        self.assertEqual(ca.spki(root.public_key()),ca.spki(self.key.public_key()))
        self.assertEqual(root.extensions.get_extension_for_class(x509.BasicConstraints).value,x509.BasicConstraints(True,0))
        for role in ca.ROLES:
            leaf=x509.load_der_x509_certificate(authority.issue(role));leaf.verify_directly_issued_by(root)
            self.assertEqual(ca.sha(ca.spki(leaf.public_key())),self.policy['services'][role]['key_sha256'])
            self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertLessEqual(leaf.not_valid_after_utc.timestamp(),self.policy['root_not_after'])
        self.assertEqual([v[0] for v in self.calls],['GetPublicKey','Sign','Sign','Sign','Sign'])
        with self.assertRaises(TypeError):pickle.dumps(authority)

    def test_restart_uses_pinned_public_root_and_renews_same_fixed_tls_keys_without_ca_private_import(self):
        authority,record=self.authority();old=x509.load_der_x509_certificate(authority.issue('payment'))
        self.calls.clear();restarted,_=self.authority(root=record)
        with patch.object(ca.time,'time',return_value=self.now+2*86400):
            renewed=x509.load_der_x509_certificate(restarted.issue('payment'))
        self.assertEqual([v[0] for v in self.calls],['Sign'])
        self.assertGreater(renewed.not_valid_after_utc,old.not_valid_after_utc)
        self.assertNotEqual(renewed.serial_number,old.serial_number)
        self.assertEqual(ca.spki(renewed.public_key()),ca.spki(old.public_key()))
        renewed.verify_directly_issued_by(x509.load_der_x509_certificate(ca.un64(record['certificate_der'],8192)))
        with self.assertRaises(Rejected):restarted.create_root()

    def test_modified_policy_or_public_root_is_rejected_without_kms(self):
        _,root=self.authority();self.calls.clear();signer=ca.KmsSigner(self.policy['kms_key_arn'],self.source,ca_context())
        with self.assertRaises(Rejected):ca.HostCA(self.policy,'00'*32,signer)
        root['certificate_der']=root['certificate_der'][:-4]+'AAAA'
        with self.assertRaises(Exception):ca.HostCA(self.policy,digest(self.policy),signer,root_record=root,root_pin='00'*32)
        self.assertEqual(self.calls,[])

    def test_original_key_foreign_key_bad_time_extra_role_and_duplicate_tls_keys_are_rejected(self):
        variants=[]
        for key in (ca.ORIGINAL_KMS,self.policy['kms_key_arn'].replace(ca.ACCOUNT,'123456789012')):
            value=copy.deepcopy(self.policy);value['kms_key_arn']=key;variants.append(value)
        value=copy.deepcopy(self.policy);value['root_not_after']=self.now+400*86400;variants.append(value)
        value=copy.deepcopy(self.policy);value['services']['issuer']=value['services']['payment'];variants.append(value)
        value=copy.deepcopy(self.policy);value['services']['refund']=value['services']['payment'];variants.append(value)
        for value in variants:
            with self.assertRaises(Rejected):ca.checked_policy(value,digest(value))
        self.assertEqual(self.calls,[])

    def test_changed_or_invalid_csr_and_server_identity_are_rejected_before_calls(self):
        value=copy.deepcopy(self.policy);item=value['services']['payment']
        raw=bytearray(base64.b64decode(item['csr_der']));raw[-1]^=1;item['csr_der']=ca.b64(raw)
        with self.assertRaises(Rejected):ca.checked_policy(value,digest(value))
        value=copy.deepcopy(self.policy);value['services']['payment']['hostname']='attacker.example.test'
        with self.assertRaises(Rejected):ca.checked_policy(value,digest(value))
        self.assertEqual(self.calls,[])

    def test_validly_signed_overprivileged_csr_extensions_cannot_change_fixed_leaf_scope(self):
        hostname=self.policy['services']['payment']['hostname']
        variants=[]
        for index,replacement in [(0,(x509.BasicConstraints(True,0),True)),
            (1,(x509.KeyUsage(True,False,False,False,False,True,False,None,None),True)),
            (2,(x509.SubjectAlternativeName([x509.DNSName(hostname),x509.DNSName('other.example.test')]),False)),
            (3,(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),False))]:
            values=ca.leaf_values(hostname);values[index]=replacement;variants.append(values)
        for values in variants:
            csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)]))
            for value,critical in values:csr=csr.add_extension(value,critical)
            csr=csr.sign(self.fresh._tls['payment'],hashes.SHA256()) # Fixture-only generated key.
            policy=copy.deepcopy(self.policy);policy['services']['payment']['csr_der']=ca.b64(csr.public_bytes(serialization.Encoding.DER))
            with self.assertRaisesRegex(Rejected,'csr-extensions'):ca.checked_policy(policy,digest(policy))
        self.assertEqual(self.calls,[])

    def test_kms_public_key_metadata_rejects_wrong_usage_algorithm_or_resource(self):
        signer=ca.KmsSigner(self.policy['kms_key_arn'],self.source,ca_context())
        correct=self.reply('GetPublicKey',{})
        for field,value in [('KeyId',ca.ORIGINAL_KMS),('KeyUsage','ENCRYPT_DECRYPT'),
                            ('KeySpec','ECC_SECG_P256K1'),('SigningAlgorithms',['ECDSA_SHA_384']),
                            ('CustomerMasterKeySpec','RSA_2048'),('KeyOrigin','EXTERNAL'),
                            ('KeyOrigin','AWS_CLOUDHSM'),('KeyOrigin',None),('KeyOrigin',[]),
                            ('KeyOrigin',{'origin':'AWS_KMS'}),('UnknownMetadata','AWS_KMS')]:
            altered=copy.deepcopy(correct);altered[field]=value
            with patch.object(signer,'_call',return_value=altered),self.assertRaises(Rejected):signer.public()

    def test_actual_kms_public_key_origin_metadata_preserves_key_and_algorithm_checks(self):
        signer=ca.KmsSigner(self.policy['kms_key_arn'],self.source,ca_context())
        correct=self.reply('GetPublicKey',{})
        correct.update(KeyOrigin='AWS_KMS',CustomerMasterKeySpec='ECC_NIST_P256')
        with patch.object(signer,'_call',return_value=correct):
            self.assertEqual(signer.public(),ca.spki(self.key.public_key()))
        for field,value in [('KeyId',ca.ORIGINAL_KMS),('KeyUsage','KEY_AGREEMENT'),
                            ('SigningAlgorithms',['ECDSA_SHA_256','ECDSA_SHA_384'])]:
            altered=copy.deepcopy(correct);altered[field]=value
            with patch.object(signer,'_call',return_value=altered),self.assertRaises(Rejected):signer.public()

    def test_untrusted_tls_peer_cannot_supply_kms_key_or_signature(self):
        with server([response(b'{}')],hostname='kms.'+ca.REGION+'.amazonaws.com',untrusted=True) as (context,dial,seen):
            signer=ca.KmsSigner(self.policy['kms_key_arn'],self.source,context,dial=dial)
            with self.assertRaisesRegex(Rejected,'^host-ca-kms-unavailable$'):signer.public()
            self.assertEqual(seen,[])

    def test_signature_origin_metadata_preserves_fixed_key_algorithm_and_signature(self):
        signer=ca.KmsSigner(self.policy['kms_key_arn'],self.source,ca_context())
        data=b'\x12'*32
        correct=self.reply('Sign',{'KeyId':self.policy['kms_key_arn'],'Message':ca.b64(data),
            'MessageType':'DIGEST','SigningAlgorithm':ca.ALGORITHM})
        correct['KeyOrigin']='AWS_KMS'
        with patch.object(signer,'_call',return_value=correct):
            self.key.public_key().verify(signer.sign_digest(data),data,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        for field,value in [('KeyOrigin','EXTERNAL'),('KeyOrigin','AWS_CLOUDHSM'),('KeyOrigin',None),
                            ('KeyOrigin',[]),('UnknownMetadata','AWS_KMS'),('KeyId',ca.ORIGINAL_KMS),
                            ('SigningAlgorithm','ECDSA_SHA_384')]:
            altered=copy.deepcopy(correct);altered[field]=value
            with patch.object(signer,'_call',return_value=altered),self.assertRaises(Rejected):signer.sign_digest(data)

    def test_unknown_role_no_root_root_expiry_and_clock_rollback_never_sign(self):
        authority,_=self.authority();self.calls.clear()
        with self.assertRaises(Rejected):authority.issue('issuer')
        with patch.object(ca.time,'time',return_value=self.now-1000),self.assertRaises(Rejected):authority.issue('payment')
        with patch.object(ca.time,'time',return_value=self.policy['root_not_after']-120),self.assertRaises(Rejected):authority.issue('refund')
        self.assertEqual(self.calls,[])

    def test_wrong_kms_public_key_is_rejected_before_root_signing_and_no_retry(self):
        signer=ca.KmsSigner(self.policy['kms_key_arn'],self.source,ca_context())
        authority=ca.HostCA(self.policy,digest(self.policy),signer)
        with (patch.object(signer,'public',return_value=ca.spki(ec.generate_private_key(ec.SECP256R1()).public_key())) as get,
              patch.object(signer,'sign_digest') as sign):
            with self.assertRaises(Rejected):authority.create_root()
            with self.assertRaises(Rejected):authority.create_root()
        self.assertEqual(get.call_count,1);sign.assert_not_called()

    def test_wrong_signing_key_response_is_never_accepted_as_certificate(self):
        authority,_=self.authority();wrong=ec.generate_private_key(ec.SECP256R1())
        with patch.object(authority._signer,'sign_digest',side_effect=lambda d:wrong.sign(d,ec.ECDSA(utils.Prehashed(hashes.SHA256())))) as sign:
            with self.assertRaises(Rejected):authority.issue('refund')
        self.assertEqual(sign.call_count,1)

    def test_kms_failure_has_fixed_diagnostic_and_root_attempt_is_not_repeated(self):
        signer=ca.KmsSigner(self.policy['kms_key_arn'],self.source,ca_context())
        authority=ca.HostCA(self.policy,digest(self.policy),signer)
        with patch.object(signer,'_call',side_effect=RuntimeError('SYNTHETIC-RESPONSE-DETAIL')) as call:
            with self.assertRaisesRegex(Rejected,'^host-ca-root-unavailable$'):authority.create_root()
            with self.assertRaises(Rejected):authority.create_root()
        self.assertEqual(call.call_count,1)

    def test_actual_sigv4_tls_kms_exchange_uses_renewable_explicit_source_and_fixed_key(self):
        count=[0]
        def answer(raw):
            header,_,body=raw.partition(b'\r\n\r\n');count[0]+=1
            self.assertIn(b'Credential=ASIA'+(b'A' if count[0]==1 else b'B')*16+b'/',header)
            target=next(line.split(b':',1)[1].strip() for line in header.split(b'\r\n') if line.lower().startswith(b'x-amz-target:'))
            if count[0]==1:self.source._deadline=0 # Force next signed call to refresh via existing provider.
            result=self.reply(target.decode().split('.')[1],json.loads(body))
            result['KeyOrigin']='AWS_KMS' # Exact extra field observed in real GetPublicKey/Sign replies.
            return response(canonical(result),headers=[('Content-Type','application/x-amz-json-1.1')])
        with server([answer]*4,hostname='kms.'+ca.REGION+'.amazonaws.com') as (context,dial,seen):
            signer=ca.KmsSigner(self.policy['kms_key_arn'],self.source,context,dial=dial)
            authority=ca.HostCA(self.policy,digest(self.policy),signer);record=authority.create_root()
            authority.issue('payment');authority.issue('refund')
            self.assertEqual(len(seen),4)
        self.assertEqual(self.source._session.calls,2)
        self.assertEqual(record['profile'],ca.ROOT)


def ca_context():
    from ticket_aws_credentials_v1 import tls_context
    return tls_context()


class HostTlsRenewalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):generated.GeneratedSetupTests.setUpClass()
    def setUp(self):
        from ticket_host_tls_renewal_v1 import RenewingContext
        self.Context=RenewingContext
        self.fixture=generated.GeneratedSetupTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.ca_fixture=HostCaTests();self.ca_fixture.setUp();self.addCleanup(self.ca_fixture.doCleanups)
        self.ca_fixture.policy['services']=self.fixture.fresh.public()['tls']
        self.authority,self.root=self.ca_fixture.authority()
        self.root_der=ca.un64(self.root['certificate_der'],8192)
        self.certificates={role:self.authority.issue(role) for role in ca.ROLES}
        self.plan=self.fixture.f.plan
        for value in self.plan['roles'].values():
            value['backend']['tls'].update(root_certificate_der=ca.b64(self.root_der),root_sha256=ca.sha(self.root_der))
            value['backend_sha256']=digest(value['backend'])
        self.bodies={r:json.loads(b) for r,b in self.fixture.fresh._checked_bodies(
            self.plan,digest(self.plan),self.certificates).items()}
        self.cfg=self.plan['roles']['payment']['backend'];self.pin=digest(self.cfg)

    def renewed(self,role='payment',offset=120):
        with patch.object(ca.time,'time',return_value=self.ca_fixture.now+offset):return self.authority.issue(role)

    def test_kms_ca_leaves_pass_existing_setup_private_key_and_public_iam_review(self):
        import ticket_setup_iam_review_v1 as iam
        self.assertTrue(self.fixture.fresh.admit_review(self.plan,digest(self.plan),self.certificates))
        public=self.fixture.fresh.public()
        review={'profile':iam.REVIEW,'session_id':'12'*16,'request_sha256':digest(generated.request()),
            'public_keys_sha256':digest(public),'plan':self.plan,'plan_sha256':digest(self.plan),
            'certificates':{r:ca.b64(c) for r,c in self.certificates.items()},'approval':iam.APPROVAL}
        result=iam.proposal(review,digest(review),public,digest(public),expires_at=int(time.time())+1200)
        self.assertFalse(result['aws_changes_executed']);self.assertFalse(result['can_deploy'])

    def test_context_replacement_preserves_service_private_key_and_rejects_old_leaf_rollback(self):
        original=copy.deepcopy(self.bodies['payment']);context=self.Context(self.cfg,self.pin,original)
        before=context.current();leaf=self.renewed(offset=30)
        status=context.install(leaf);self.assertTrue(status['changed']);self.assertIsNot(context.current(),before)
        self.assertFalse(context.install(leaf)['changed'])
        with self.assertRaises(Rejected):context.install(self.certificates['payment'])
        self.assertEqual(self.bodies['payment'],original)
        self.assertEqual(context._body['service_key_der'],original['service_key_der'])
        self.assertEqual(context._body['tls_private_key_der'],original['tls_private_key_der'])
        with self.assertRaises(TypeError):pickle.dumps(context)

    def test_new_current_leaf_recovers_an_expired_boot_certificate_without_resealing_keys(self):
        future=self.ca_fixture.now+2*86400;leaf=self.renewed(offset=2*86400)
        with patch.object(ca.time,'time',return_value=future):
            with self.assertRaises(Rejected):self.Context(self.cfg,self.pin,self.bodies['payment'])
            context=self.Context(self.cfg,self.pin,self.bodies['payment'],certificate_der=leaf)
            self.assertIsInstance(context.current(),ssl.SSLContext)
        self.assertEqual(context._body['service_key_der'],self.bodies['payment']['service_key_der'])

    def test_wrong_role_or_corrupted_leaf_keeps_last_valid_context_then_expiry_fails_closed(self):
        context=self.Context(self.cfg,self.pin,self.bodies['payment']);original=context.current()
        for certificate in (self.certificates['refund'],b'not-a-certificate'):
            with self.assertRaisesRegex(Rejected,'^host-tls-renewal-unavailable$'):context.install(certificate)
            self.assertIs(context.current(),original)
        with patch.object(ca.time,'time',return_value=context._expiry),self.assertRaises(Rejected):context.current()

    def test_kms_renewal_failure_preserves_incumbent_context_without_retry(self):
        context=self.Context(self.cfg,self.pin,self.bodies['payment']);original=context.current()
        with patch.object(self.authority._signer,'_call',side_effect=TimeoutError('SYNTHETIC-PRIVATE-DETAIL')) as call:
            with self.assertRaisesRegex(Rejected,'^host-ca-renewal-unavailable$'):self.authority.issue('payment')
        self.assertEqual(call.call_count,1);self.assertIs(context.current(),original)

    def handshake(self,context):
        left,right=socket.socketpair();errors=[]
        def serve():
            try:
                with context.wrap_socket(left,server_side=True) as secure:
                    secure.settimeout(3);self.assertEqual(secure.recv(4),b'ping');secure.sendall(b'pong')
            except Exception:errors.append(True)
        worker=threading.Thread(target=serve);worker.start()
        try:
            client=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);client.minimum_version=ssl.TLSVersion.TLSv1_3
            client.load_verify_locations(cadata=x509.load_der_x509_certificate(self.root_der).public_bytes(serialization.Encoding.PEM).decode())
            with client.wrap_socket(right,server_hostname=self.cfg['tls']['hostname']) as secure:
                secure.settimeout(3);certificate=secure.getpeercert(binary_form=True)
                secure.sendall(b'ping');self.assertEqual(secure.recv(4),b'pong')
        finally:
            left.close();right.close();worker.join(timeout=5)
        self.assertFalse(worker.is_alive());self.assertEqual(errors,[]);return certificate

    def test_actual_tls_handshakes_use_new_leaf_with_same_root_and_service_key_after_swap(self):
        context=self.Context(self.cfg,self.pin,self.bodies['payment'])
        old=self.handshake(context.current());leaf=self.renewed(offset=30);context.install(leaf)
        new=self.handshake(context.current());self.assertEqual(new,leaf);self.assertNotEqual(old,new)
        self.assertEqual(ca.spki(x509.load_der_x509_certificate(old).public_key()),
            ca.spki(x509.load_der_x509_certificate(new).public_key()))


if __name__=='__main__':unittest.main()
