"""Fresh generated keys and full synthetic setup; no production CA or AWS."""
import base64
import copy
from datetime import datetime,timedelta,timezone
import json
import pickle
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.x509.oid import NameOID
from policy import canonical,Rejected
from ticket_offer_v1 import manifest_hash
import ticket_new_keys_v1 as keys
import test_ticket_key_setup_v1 as setups

def pin(value):return keys.setup.storage.sha(canonical(value))
def request():return {'profile':keys.REQUEST,'hostnames':{r:r+'.example.test' for r in keys.ROLES}}
def generate():value=request();return keys.generate(value,pin(value))

class NewKeysTests(unittest.TestCase):
    def test_public_key_algorithms_csr_signatures_and_scope_are_exact(self):
        fresh=generate();self.addCleanup(fresh.close);public=fresh.public()
        self.assertEqual(set(public),{'profile','ticket_spki','key_bindings','tls'})
        key=serialization.load_der_public_key(base64.b64decode(public['ticket_spki']))
        self.assertIsInstance(key,rsa.RSAPublicKey);self.assertEqual(key.key_size,3072);self.assertEqual(key.public_numbers().e,65537)
        self.assertEqual(len(set(public['key_bindings'].values())),2)
        for role,value in public['tls'].items():
            csr=x509.load_der_x509_csr(base64.b64decode(value['csr_der']));self.assertTrue(csr.is_signature_valid)
            self.assertIsInstance(csr.public_key().curve,ec.SECP256R1)
            self.assertEqual(list(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),[x509.DNSName(role+'.example.test')])
            self.assertFalse(csr.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertEqual(keys.setup.storage.sha(keys.der_public(csr.public_key())),value['key_sha256'])
        self.assertEqual(len({v['key_sha256'] for v in public['tls'].values()}),3)

    def test_separate_generations_do_not_reuse_service_or_tls_keys(self):
        a=generate();b=generate();self.addCleanup(a.close);self.addCleanup(b.close)
        x,y=a.public(),b.public();self.assertNotEqual(x['ticket_spki'],y['ticket_spki'])
        for r in ('publication','refund'):self.assertNotEqual(x['key_bindings'][r],y['key_bindings'][r])
        for r in keys.ROLES:self.assertNotEqual(x['tls'][r]['key_sha256'],y['tls'][r]['key_sha256'])

    def test_invalid_public_request_rejects_before_generating_any_key(self):
        for change in [lambda v:v.update(owner_key='SYNTHETIC-REJECT'),lambda v:v['hostnames'].update(payment='*.example.test'),
            lambda v:v['hostnames'].pop('refund'),lambda v:v['hostnames'].update(payment='https://example.test'),
            lambda v:v['hostnames'].update(payment='example.test\n')]:
            value=request();change(value)
            with patch.object(keys.rsa,'generate_private_key',side_effect=AssertionError('no key generation')),self.assertRaises(Rejected):keys.generate(value,pin(value))
        with patch.object(keys,'harden_process',side_effect=AssertionError('no generation')),self.assertRaises(Rejected):keys.generate(request(),'12'*32)

    def test_private_container_cannot_be_pickled_and_public_copy_cannot_mutate_it(self):
        fresh=generate();self.addCleanup(fresh.close);original=fresh.public();view=fresh.public()
        view['ticket_spki']='modified';view['tls']['payment']['key_sha256']='12'*32
        self.assertEqual(fresh.public(),original)
        for operation in (pickle.dumps,copy.copy,copy.deepcopy):
            with self.assertRaisesRegex(TypeError,'ticket-new-keys-serialization-forbidden'):operation(fresh)
        self.assertNotIn(original['ticket_spki'],repr(fresh))

    def test_closing_keeps_public_evidence_but_disables_private_preparation(self):
        fresh=generate();public=fresh.public();fresh.close();fresh.close()
        self.assertEqual(fresh.public(),public)
        with self.assertRaisesRegex(Rejected,'ticket-new-keys-not-ready'):fresh.prepare({},'12'*32,{},clients={},output='/not-used')

    def test_process_hardening_precedes_generation(self):
        with patch.object(keys,'harden_process',side_effect=Rejected('synthetic-hardening-failure')),\
            patch.object(keys.rsa,'generate_private_key') as rsa_generate,patch.object(keys.ec,'generate_private_key') as ec_generate:
            value=request()
            with self.assertRaises(Rejected):keys.generate(value,pin(value))
        rsa_generate.assert_not_called();ec_generate.assert_not_called()


class GeneratedSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):setups.KeySetupTests.setUpClass()
    def setUp(self):
        self.f=setups.KeySetupTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.fresh=generate();self.addCleanup(self.fresh.close);public=self.fresh.public()
        now=datetime.now(timezone.utc);rootkey=ec.generate_private_key(ec.SECP256R1())
        ca=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic generated-key CA')])
        root=(x509.CertificateBuilder().subject_name(ca).issuer_name(ca).public_key(rootkey.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=2))
            .not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(True,0),True)
            .add_extension(x509.KeyUsage(True,False,False,False,False,True,True,None,None),True).sign(rootkey,hashes.SHA256()))
        rootder=root.public_bytes(serialization.Encoding.DER);self.certificates={}
        for role,item in self.f.plan['roles'].items():
            cfg=item['backend'];cfg['offer']['terms']['ticket_spki']=public['ticket_spki']
            cfg['offer_sha256']=manifest_hash(cfg['offer']);cfg['key_bindings']=copy.deepcopy(public['key_bindings'])
            csr=x509.load_der_x509_csr(base64.b64decode(public['tls'][role]['csr_der']))
            builder=(x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca).public_key(csr.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)))
            for extension in csr.extensions:builder=builder.add_extension(extension.value,extension.critical)
            self.certificates[role]=builder.sign(rootkey,hashes.SHA256()).public_bytes(serialization.Encoding.DER)
            cfg['tls']={k:public['tls'][role][k] for k in ('hostname','key_sha256')}
            cfg['tls'].update(root_certificate_der=keys.b64(rootder),root_sha256=keys.setup.storage.sha(rootder))
            if role=='refund':
                cfg['refund_vault'].update(parameters=cfg['offer_sha256'],authority=public['key_bindings']['refund'])
                cfg['refund_vault_sha256']=pin(cfg['refund_vault'])
            item['backend_sha256']=pin(cfg)
        # Only public fixture config is rebound. This does not deploy contracts
        # with the new authorities or prove matching live onchain state.
    def prepare(self):return self.fresh.prepare(self.f.plan,pin(self.f.plan),self.certificates,clients=self.f.clients,output=self.f.output)

    def test_new_keys_flow_through_sealing_storage_and_exact_recovery(self):
        result=self.prepare();self.assertTrue(result['ok']);self.assertEqual(self.f.generate.call_count,3)
        public=self.fresh.public()
        for role in keys.ROLES:
            body=self.f.decrypt(role);private=serialization.load_der_private_key(base64.b64decode(body['service_key_der']),None)
            self.assertEqual(body['role'],role);self.assertEqual(body['config_sha256'],self.f.plan['roles'][role]['backend_sha256'])
            if role=='payment':self.assertEqual(keys.b64(keys.der_public(private.public_key())),public['ticket_spki'])
            else:
                self.assertIsInstance(private.curve,ec.SECP256K1)
                self.assertEqual(keys.ReceiptKey(None,private).address,public['key_bindings'][role])
            self.assertEqual(body['tls_certificate_der'],keys.b64(self.certificates[role]))
        with self.assertRaisesRegex(Rejected,'ticket-new-keys-not-ready'):self.prepare()
        self.assertEqual(self.f.generate.call_count,3)

    def test_unrelated_reviewed_key_bindings_are_not_silently_rewritten(self):
        value=self.f.plan['roles']['payment'];value['backend']['key_bindings']['publication']='0x'+'12'*20
        value['backend_sha256']=pin(value['backend'])
        with self.assertRaisesRegex(Rejected,'^ticket-new-keys-prepare-unavailable$'):self.prepare()
        self.f.generate.assert_not_called();self.assertEqual(list(self.f.root.iterdir()),[])

    def test_wrong_role_certificate_rejects_before_any_aws_or_disk_output(self):
        self.certificates['refund']=self.certificates['publication']
        with self.assertRaisesRegex(Rejected,'^ticket-new-keys-prepare-unavailable$'):self.prepare()
        self.f.generate.assert_not_called();self.assertEqual(list(self.f.root.iterdir()),[])

    def test_failed_attempt_is_not_automatically_repeated_with_same_key_container(self):
        self.f.generate.side_effect=TimeoutError('SYNTHETIC-KMS-FAILURE');result=self.prepare()
        self.assertFalse(result['ok']);self.assertTrue(result['outcome_unknown']);self.assertEqual(self.f.generate.call_count,1)
        with self.assertRaisesRegex(Rejected,'ticket-new-keys-not-ready'):self.prepare()
        self.assertEqual(self.f.generate.call_count,1);self.assertTrue(keys.canonical(self.fresh.public()))

if __name__=='__main__':unittest.main()
