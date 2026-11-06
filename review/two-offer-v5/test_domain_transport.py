"""Real TLS, simulated NSM payloads. Never new-image hardware acceptance.

Only the AWS cryptographic boundary is mocked for positive protocol tests.
Unmocked fake/archived quote rejection is tested separately. No credentials,
provider, desktop keyring, listener or cloud resource is used.
"""
import base64
import copy
import hashlib
import socket
import struct
import threading
import time
import unittest
from unittest.mock import patch

import domain_trust as trust
import domain_transport as transport
from domain_issuer import IssuerApplication, RPC
from domain_pipeline import definition_hash
from policy import Rejected, canonical
from trust import VENDOR


def fixture():
    # Transport treats public crypto material as opaque; native validation is
    # independently exercised by the real composite proof/lifecycle suite.
    public = {'issuer':'synthetic-public-definition','revocation_registry':'synthetic-root'}
    view = {'definition_hash':definition_hash(public),'public':public,'sequence':1}
    approved = {'mode':'production','definition_hash':view['definition_hash'],
                'code_identity':'ab'*32,'state_authority_sha256':'cd'*32,
                'pcrs':{str(i):'ef'*48 for i in range(3)}}
    return view,approved


def payload(nonce, bind, certificate):
    return {'nonce':bytes.fromhex(nonce),'public_key':trust.certificate_key(certificate),
            'user_data':hashlib.sha256(canonical(bind)).digest(),
            'timestamp':int(time.time()*1000),'pcrs':{i:bytes.fromhex('ef'*48) for i in range(3)}}


class Application(IssuerApplication):
    def __init__(self, view):
        class Backend:
            def public_view(self):return copy.deepcopy(view)
        class State:
            backend = Backend()
        class Provider:
            budget_enforced = True
        super().__init__(State(),Provider(),lambda:0)
        self.messages = []

    def dispatch_bytes(self, data):
        self.messages.append(data)
        return super().dispatch_bytes(data)


class DomainTransportTests(unittest.TestCase):
    def test_01_composite_binding_pins_registry_and_keeps_definition_stable(self):
        view,approved = fixture();_,cert = transport.channel_identity()
        bind = trust.binding(view,cert,approved['code_identity'],approved['state_authority_sha256'])
        changed = copy.deepcopy(view);changed['sequence'] += 1
        changed['public']['revocation_registry'] = 'another-root'
        other = trust.binding(changed,cert,approved['code_identity'],approved['state_authority_sha256'])
        self.assertEqual(other['definition_hash'],bind['definition_hash'])
        self.assertNotEqual(other['registry_sha256'],bind['registry_sha256'])
        self.assertNotEqual(bind['credential_scheme'],'anoncreds-cl-0.2.3')
        self.assertEqual(len(trust.certificate_key(cert)),33)

    def test_02_enrollment_checks_all_bound_fields(self):
        view,approved = fixture();_,cert = transport.channel_identity();nonce = '12'*32
        bind = trust.binding(view,cert,approved['code_identity'],approved['state_authority_sha256'])
        good = payload(nonce,bind,cert)
        with patch.object(trust,'verify_aws_document',return_value=good) as verify:
            self.assertEqual(trust.enroll_production(b'synthetic',nonce,view,cert,approved),bind)
            self.assertLess(abs(verify.call_args.args[1]-int(time.time()*1000)),1000)
        for field,value in [('nonce',b'wrong'),('public_key',b'wrong'),('user_data',b'wrong'),
                            ('timestamp',int(time.time()*1000)-121000),
                            ('timestamp',int(time.time()*1000)+6000),('timestamp',True),
                            ('pcrs',{i:b'\0'*48 for i in range(3)})]:
            with self.subTest(field=field,value=value):
                with patch.object(trust,'verify_aws_document',return_value={**good,field:value}):
                    with self.assertRaises(Rejected):
                        trust.enroll_production(b'synthetic',nonce,view,cert,approved)

    def test_03_independent_approval_not_server_selected(self):
        view,approved = fixture();_,cert = transport.channel_identity();nonce = '12'*32
        bind = trust.binding(view,cert,approved['code_identity'],approved['state_authority_sha256'])
        for field,value in [('mode','local-test'),('definition_hash','00'*32),
                            ('definition_hash','11'*32),('code_identity','11'*32),
                            ('state_authority_sha256','11'*32),('pcrs',{}),
                            ('pcrs',{str(i):'00'*48 for i in range(3)})]:
            with self.subTest(field=field,value=value):
                with patch.object(trust,'verify_aws_document',return_value=payload(nonce,bind,cert)):
                    with self.assertRaises(Rejected):
                        trust.enroll_production(b'synthetic',nonce,view,cert,{**approved,field:value})
        for mutation in ('definition','registry','sequence','certificate'):
            changed = copy.deepcopy(view);certificate = cert
            if mutation == 'definition':changed['public']['issuer'] = 'substituted'
            if mutation == 'registry':changed['public']['revocation_registry'] = 'substituted'
            if mutation == 'sequence':changed['sequence'] += 1
            if mutation == 'certificate':_,certificate = transport.channel_identity()
            with patch.object(trust,'verify_aws_document',return_value=payload(nonce,bind,cert)):
                with self.assertRaises(Rejected):
                    trust.enroll_production(b'synthetic',nonce,changed,certificate,approved)

    def test_04_fabricated_and_archived_quotes_never_enroll(self):
        view,approved = fixture();_,cert = transport.channel_identity()
        docs = [b'fake',*( (VENDOR/'tests/fixtures'/name).read_bytes() for name in
                         ('beta-valid-attestation-doc-bytes.cbor','beta-debug-mode-attestation-doc-bytes.cbor'))]
        for document in docs:
            with self.assertRaises(Rejected):
                trust.enroll_production(document,'12'*32,view,cert,approved)

    def exchange(self, *, mutate_payload=None, application=None):
        view,approved = fixture();app = application or Application(view)
        client,server = socket.socketpair()
        captured = {}
        def nsm(nonce,bind,cert):
            captured['payload'] = payload(nonce,bind,cert)
            if mutate_payload:mutate_payload(captured['payload'])
            return b'synthetic-NSM-document'
        def verify(document,now):
            self.assertEqual(document,b'synthetic-NSM-document')
            return captured['payload']
        with patch.object(transport,'_aws_document',side_effect=nsm),patch.object(trust,'verify_aws_document',side_effect=verify):
            thread = threading.Thread(target=transport.serve_connection,
                args=(server,app,approved['code_identity'],approved['state_authority_sha256']))
            thread.start()
            try:
                if mutate_payload:
                    with self.assertRaises(Rejected):transport.request(client,'registry',{},approved)
                    result = None
                else:result = transport.request(client,'registry',{},approved)
            finally:
                client.close();thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
        return app,result

    def test_05_real_tls_operation_after_simulated_aws_validation(self):
        app,result = self.exchange()
        self.assertEqual(result['status'],'ok')
        self.assertEqual(result['result'],fixture()[0]);self.assertFalse(result['verified'])
        self.assertEqual(len(app.messages),1)

    def test_06_bad_attestation_sends_no_application_payload(self):
        for field in ('nonce','public_key','user_data'):
            app,_ = self.exchange(mutate_payload=lambda p:p.update({field:b'wrong'}))
            self.assertEqual(app.messages,[])

    def test_07_invalid_approval_sends_no_hello_or_private_body(self):
        client,server = socket.socketpair();_,approved = fixture()
        try:
            with self.assertRaises(Rejected):
                transport.request(client,'begin',{'private':'SYNTHETIC-MARKER'},{**approved,'mode':'local-test'})
            self.assertEqual(server.recv(1),b'')
        finally:client.close();server.close()

    def test_08_certificate_substitution_fails_tls_before_private_body(self):
        view,approved = fixture();context,cert = transport.channel_identity();_,other = transport.channel_identity()
        client,server = socket.socketpair();observed = [];captured = {}
        def run():
            try:
                hello = transport.receive(server,256,time.monotonic()+3)
                bind = trust.binding(view,other,approved['code_identity'],approved['state_authority_sha256'])
                captured.update(payload(hello['nonce'],bind,other))
                transport.send(server,{'profile':trust.ENROLLMENT,'registry':view,
                    'certificate':base64.b64encode(other).decode(),'document':base64.b64encode(b'synthetic').decode()},
                    transport.ENVELOPE_LIMIT,time.monotonic()+3)
                with context.wrap_socket(server,server_side=True) as secure:observed.append(secure.recv(1))
            except OSError:pass
            finally:server.close()
        with patch.object(trust,'verify_aws_document',return_value=captured):
            thread = threading.Thread(target=run);thread.start()
            try:
                with self.assertRaises(Rejected):transport.request(client,'begin',{'private':'SYNTHETIC'},approved)
            finally:client.close();thread.join(timeout=3)
        self.assertFalse(thread.is_alive());self.assertEqual(observed,[])

    def test_09_encrypted_confirmation_required_before_dispatch(self):
        view,approved = fixture();app = Application(view);client,server = socket.socketpair()
        with patch.object(transport,'_aws_document',return_value=b'synthetic'):
            thread = threading.Thread(target=transport.serve_connection,
                args=(server,app,approved['code_identity'],approved['state_authority_sha256']))
            thread.start()
            try:
                deadline = time.monotonic()+3
                transport.send(client,{'profile':trust.ENROLLMENT,'nonce':'12'*32},256,deadline)
                envelope = transport.receive(client,transport.ENVELOPE_LIMIT,deadline)
                cert = base64.b64decode(envelope['certificate'])
                with trust.pinned_channel_context(cert).wrap_socket(client,server_hostname=trust.HOSTNAME) as secure:
                    transport.send(secure,{'enrollment_sha256':'00'*32,'request':
                        {'id':'12'*16,'profile':RPC,'operation':'registry','body':{}}},65536,deadline)
                    try:self.assertEqual(secure.recv(1),b'')
                    except OSError:pass  # TLS teardown may reset an invalid peer.
            finally:client.close();thread.join(timeout=3)
        self.assertFalse(thread.is_alive());self.assertEqual(app.messages,[])

    def test_10_framing_bounds_duplicates_truncation_and_deadline(self):
        for data in (struct.pack('!I',0),struct.pack('!I',257),
                     struct.pack('!I',13)+b'{"a":1,"a":2}',struct.pack('!I',9)+b'{}'):
            client,server = socket.socketpair()
            try:
                server.sendall(data);server.shutdown(socket.SHUT_WR)
                with self.assertRaises(Rejected):transport.receive(client,256,time.monotonic()+1)
            finally:client.close();server.close()
        client,server = socket.socketpair()
        try:
            with self.assertRaises(Rejected):transport.receive(client,256,time.monotonic()-1)
        finally:client.close();server.close()

    def test_11_nsm_uses_pinned_native_interface(self):
        view,approved = fixture();_,cert = transport.channel_identity()
        bind = trust.binding(view,cert,approved['code_identity'],approved['state_authority_sha256'])
        with patch.object(transport.Nsm,'attest',return_value=b'\x01\x02\x03') as native:
            self.assertEqual(transport._aws_document('12'*32,bind,cert),b'\x01\x02\x03')
        nonce,key,data = native.call_args.args
        self.assertEqual(nonce,bytes.fromhex('12'*32));self.assertEqual(len(key),33)
        self.assertEqual(data,hashlib.sha256(canonical(bind)).digest())

    def test_12_wrong_response_correlation_rejected(self):
        from policy import strict_json
        class WrongID(Application):
            def dispatch_bytes(self,data):
                result = strict_json(super().dispatch_bytes(data));result['id'] = '00'*16
                return canonical(result)
        view,_ = fixture()
        with self.assertRaises(Rejected):self.exchange(application=WrongID(view))

    def test_13_native_issuance_receipt_and_separate_proof_over_bound_channel(self):
        from domain_pipeline import Native, PendingHolder
        from domain_state import PersistentDomainVerifier, PersistentDomainIssuer, TrustedDomainStore
        from policy import Session
        from test_domain_issuer import IssuerTests
        from test_zkid import NOW
        case = IssuerTests('test_application_source_to_receipt_and_proof')
        case.setUp();self.addCleanup(case.tearDown)
        approved = fixture()[1];approved['definition_hash'] = case.initial.definition_hash
        seen = []
        def call(op,**body):
            captured = {};client,server = socket.socketpair()
            def nsm(nonce,bind,cert):
                captured.update(payload(nonce,bind,cert));return b'synthetic'
            def serve():
                # SQLite laboratory connections belong to their owning thread.
                backend = TrustedDomainStore(case.root)
                try:
                    state = PersistentDomainIssuer(backend,case.state_key,case.initial.definition_hash,case.native)
                    app = IssuerApplication(state,case.provider,lambda:case.now)
                    transport.serve_connection(server,app,approved['code_identity'],approved['state_authority_sha256'])
                finally:backend.db.close()
            with patch.object(transport,'_aws_document',side_effect=nsm),patch.object(trust,'verify_aws_document',return_value=captured):
                thread = threading.Thread(target=serve)
                thread.start()
                try:result = transport.request(client,op,body,approved)
                finally:client.close();thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
            seen.append(canonical(body));self.assertEqual(result['status'],'ok')
            return result['result']
        registry = call('registry')
        holder = PendingHolder.create(case.native,registry['public'])
        begun = call('begin',request=holder.request,desktop_nonce=holder.desktop_nonce,
                     username='synthetic_user',approve_public_profile_lookup=True)
        session = Session(**begun['session']);case.now = NOW+2
        issued = call('check-post',session=session.__dict__,tweet_id='3141592653589793',approve_source_check=True)
        self.assertEqual(call('recover-delivery',session=session.__dict__),issued)
        held,ack = holder.receive(issued,registry['public'],session)
        call('commit',session=session.__dict__,ack=ack)
        self.assertEqual(call('status',session=session.__dict__,nonce='12'*32)['state'],'committed')
        verifier = PersistentDomainVerifier(case.backend,Native(),case.initial.definition_hash)
        challenge = verifier.challenge('ab'*32,['account-controlled'],NOW+4,identity=True)
        _,core = case.state.load();proof = held.present(core,challenge)
        self.assertEqual(verifier.verify(proof,challenge,NOW+5)['public_id'],held.local_zkid)
        self.assertTrue(all(canonical(held.local_zkid) not in message for message in seen))
        self.assertEqual(case.provider.calls,['resolve','post','user'])

    def test_14_tls_12_client_never_reaches_application(self):
        import ssl
        view,approved = fixture();app = Application(view);client,server = socket.socketpair()
        with patch.object(transport,'_aws_document',return_value=b'synthetic'):
            thread = threading.Thread(target=transport.serve_connection,
                args=(server,app,approved['code_identity'],approved['state_authority_sha256']))
            thread.start()
            try:
                deadline = time.monotonic()+3
                transport.send(client,{'profile':trust.ENROLLMENT,'nonce':'12'*32},256,deadline)
                envelope = transport.receive(client,transport.ENVELOPE_LIMIT,deadline)
                context = trust.pinned_channel_context(base64.b64decode(envelope['certificate']))
                context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
                with self.assertRaises(ssl.SSLError):context.wrap_socket(client,server_hostname=trust.HOSTNAME)
            finally:client.close();thread.join(timeout=3)
        self.assertFalse(thread.is_alive());self.assertEqual(app.messages,[])


if __name__ == '__main__':unittest.main()
