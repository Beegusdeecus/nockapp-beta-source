"""Real boot TLS with simulated NSM/AWS verification, no hardware claim."""
import hashlib
import socket
import threading
import time
import unittest
from unittest.mock import patch

import boot_attestation as boot
from policy import Rejected,canonical
from test_provisioning import FakeNsm


class BootAttestationTests(unittest.TestCase):
    def run_boot(self,*,inspect=False,mutate=None,handler_error=None):
        nsm=FakeNsm();client,server=socket.socketpair();received=[];result=[]
        self.failure_frames=[];original_send=boot.send
        def send(stream,value,*args):
            if type(value) is dict and value.get('status')=='unavailable':self.failure_frames.append(value)
            return original_send(stream,value,*args)
        approved={'mode':'production','definition_hash':'11'*32,'code_identity':'22'*32,
                  'state_authority_sha256':'33'*32,'pcrs':{str(i):'ef'*48 for i in range(3)}}
        def verify(document,now):
            nonce,key,data=nsm.calls[-1]
            payload={'nonce':nonce,'public_key':key,'user_data':data,'timestamp':now,
                     'pcrs':{i:bytes.fromhex('ef'*48) for i in range(3)}}
            if mutate:mutate(payload)
            return payload
        def handler(envelope):
            received.append(envelope)
            if handler_error is not None:raise handler_error
            return 'synthetic ready instance'
        def serve():result.append(boot.serve_boot(server,nsm,'22'*32,'33'*32,'11'*32,handler))
        with patch.object(boot,'verify_aws_document',side_effect=verify),patch.object(boot,'send',side_effect=send):
            thread=threading.Thread(target=serve);thread.start()
            try:
                if mutate or handler_error is not None:
                    with self.assertRaises(Rejected):boot.provision_boot(client,{'synthetic':'boot data'},approved)
                    response=None
                else:response=(boot.inspect_boot(client,approved) if inspect else
                               boot.provision_boot(client,{'synthetic':'boot data'},approved))
            finally:client.close();thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
        return received,result,response

    def test_01_inspection_is_fresh_boot_evidence_not_loaded_issuer(self):
        received,result,response=self.run_boot(inspect=True)
        self.assertEqual(received,[]);self.assertEqual(result,[None])
        self.assertFalse(response['issuer_loaded']);self.assertFalse(response['verified'])
        self.assertEqual(response['profile'],boot.PROFILE)

    def test_02_bootstrap_requires_bound_tls_before_handler(self):
        received,result,response=self.run_boot()
        self.assertEqual(received,[{'synthetic':'boot data'}]);self.assertEqual(result,['synthetic ready instance'])
        self.assertEqual(response,{'profile':boot.PROFILE,'status':'ready','verified':False})

    def test_03_wrong_freshness_key_nonce_and_binding_never_deliver_bootstrap(self):
        for mutation in (lambda p:p.update(nonce=b'wrong'),lambda p:p.update(public_key=b'wrong'),
                         lambda p:p.update(user_data=b'wrong'),lambda p:p.update(timestamp=1)):
            received,result,_=self.run_boot(mutate=mutation)
            self.assertEqual(received,[]);self.assertEqual(result,[None])
            self.assertEqual(self.failure_frames,[])

    def test_06_handler_failure_reports_only_fixed_code_and_never_success(self):
        from cryptography.exceptions import InvalidTag
        from aws_transport import AwsFailure
        for error,code in ((Rejected('transaction-journal-context'),'transaction-journal-context'),
                (RuntimeError('SYNTHETIC-PRIVATE-NEVER-PRINT'),'startup-unavailable'),
                (InvalidTag('SYNTHETIC-PRIVATE-NEVER-PRINT'),'startup-authentication-rejected'),
                (AwsFailure('AccessDeniedException'),'aws-access-denied')):
            with self.subTest(code=code):
                received,result,reply=self.run_boot(handler_error=error)
                self.assertEqual(len(received),1);self.assertEqual(result,[None]);self.assertIsNone(reply)
                self.assertEqual(self.failure_frames,[{'profile':boot.PROFILE,'status':'unavailable','verified':False,'code':code}])
                self.assertNotIn('SYNTHETIC-PRIVATE',canonical(self.failure_frames).decode())

    def test_07_nested_and_unknown_errors_never_export_raw_context_or_request_data(self):
        from aws_transport import AwsFailure
        inner=AwsFailure('AccessDeniedException');inner.response['Error']['Message']='SYNTHETIC-PRIVATE'
        outer=Rejected('registry-unavailable');outer.__context__=inner
        self.assertEqual(boot.initialization_failure_code(outer),'aws-access-denied')
        unknown=Rejected(['SYNTHETIC-PRIVATE']);unknown.__context__=unknown
        self.assertEqual(boot.initialization_failure_code(unknown),'startup-unavailable')
        for code in boot.INIT_FAILURE_CODES:
            self.assertLessEqual(len(canonical({'profile':boot.PROFILE,'status':'unavailable','verified':False,'code':code})),256)

    def test_04_fabricated_quote_cannot_be_a_boot_assertion(self):
        client,server=socket.socketpair();nsm=FakeNsm()
        thread=threading.Thread(target=boot.serve_boot,args=(server,nsm,'22'*32,'33'*32,'11'*32,lambda _:True))
        thread.start()
        approved={'mode':'production','definition_hash':'11'*32,'code_identity':'22'*32,
                  'state_authority_sha256':'33'*32,'pcrs':{str(i):'ef'*48 for i in range(3)}}
        try:
            with self.assertRaises(Rejected):boot.inspect_boot(client,approved)
        finally:client.close();thread.join(timeout=3)
        self.assertFalse(thread.is_alive())

    def test_05_boot_quote_cannot_enroll_a_loaded_credential_issuer(self):
        import domain_trust
        from domain_pipeline import definition_hash
        from domain_transport import channel_identity
        _,cert=channel_identity();public={'issuer':'synthetic','revocation_registry':'synthetic'}
        namespace=definition_hash(public);view={'definition_hash':namespace,'public':public,'sequence':1}
        approved={'mode':'production','definition_hash':namespace,'code_identity':'22'*32,
                  'state_authority_sha256':'33'*32,'pcrs':{str(i):'ef'*48 for i in range(3)}}
        boot_binding=boot.binding(cert,'22'*32,'33'*32,namespace)
        payload={'nonce':bytes.fromhex('44'*32),'public_key':domain_trust.certificate_key(cert),
                 'user_data':hashlib.sha256(canonical(boot_binding)).digest(),'timestamp':int(time.time()*1000),
                 'pcrs':{i:bytes.fromhex('ef'*48) for i in range(3)}}
        with patch.object(domain_trust,'verify_aws_document',return_value=payload):
            with self.assertRaisesRegex(Rejected,'issuer-quote-binding'):
                domain_trust.enroll_production(b'synthetic','44'*32,view,cert,approved)


if __name__=='__main__':unittest.main()
