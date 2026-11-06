"""Actual filesystem/TCP/TLS/native application; synthetic KMS/AWS/EVM authority.

Same-UID fixture directories do not establish root/CA/service UID isolation.
No real cloud, owner state, funds or private material is persisted by delivery.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from policy import canonical,digest,Rejected
from ticket_host_tls_delivery_v1 import PublicCertificates,CertificatePoller
from ticket_backend_tls_boot_v2 import assemble_recovered
import ticket_backend_tls_boot_v2 as boot_v2
from ticket_backend_resources_v1 import Resources
from ticket_host_tls_renewal_v1 import RenewingContext
from ticket_server_v2 import RenewingRoleServer
from ticket_transport_v2 import send,receive
from ticket_service_v2 import request
import test_ticket_host_tls_ca_v1 as fixtures
import test_ticket_backend_boot_v1 as boots


class PublicDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.HostCaTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.ca,self.root=self.f.authority();self.cert=self.ca.issue('payment')
        self.temp=tempfile.TemporaryDirectory(prefix='public-tls-delivery-');self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name);self.directory=PublicCertificates(self.path,os.getuid())
        self.addCleanup(self.directory.close)

    def test_atomic_public_leaf_publication_and_replacement_preserve_unrelated_files(self):
        marker=self.path/'unrelated-public-note';marker.write_bytes(b'keep')
        self.directory.publish('payment',self.cert);self.assertEqual(self.directory.read('payment'),self.cert)
        with patch.object(fixtures.ca.time,'time',return_value=self.f.now+30):new=self.ca.issue('payment')
        self.directory.publish('payment',new);self.assertEqual(self.directory.read('payment'),new)
        self.assertEqual(marker.read_bytes(),b'keep')
        self.assertEqual((self.path/'payment.der').stat().st_mode&0o777,0o644)
        self.assertEqual({p.name for p in self.path.iterdir()},{'unrelated-public-note','payment.der'})

    def test_private_blob_root_and_oversize_input_are_rejected_before_any_file_write(self):
        self.directory.publish('payment',self.cert)
        root=fixtures.ca.un64(self.root['certificate_der'],8192)
        for data in (b'-----BEGIN PRIVATE KEY-----\nPUBLIC-TEST-MARKER\n',root,b'x'*8193):
            with self.assertRaises(Exception):self.directory.publish('payment',data)
            self.assertEqual(self.directory.read('payment'),self.cert)
        self.assertEqual({p.name for p in self.path.iterdir()},{'payment.der'})

    def test_symlink_hardlink_fifo_writable_and_oversize_sources_are_rejected(self):
        target=self.path/'public-certificate';target.write_bytes(self.cert);target.chmod(0o644)
        named=self.path/'payment.der';named.symlink_to(target)
        with self.assertRaises(Exception):self.directory.read('payment')
        named.unlink();os.link(target,named)
        with self.assertRaises(Rejected):self.directory.read('payment')
        named.unlink();os.mkfifo(named,0o644)
        with self.assertRaises(Rejected):self.directory.read('payment')
        named.unlink();named.write_bytes(self.cert);named.chmod(0o666)
        with self.assertRaises(Rejected):self.directory.read('payment')
        named.chmod(0o644);named.write_bytes(b'x'*8193)
        with self.assertRaises(Rejected):self.directory.read('payment')
        self.assertEqual(target.read_bytes(),self.cert)

    def test_rebound_or_writable_directory_is_rejected_and_never_followed(self):
        self.directory.publish('payment',self.cert);self.path.chmod(0o777)
        with self.assertRaises(Rejected):self.directory.read('payment')
        self.path.chmod(0o700)
        moved=self.path/'old';moved.mkdir(mode=0o700)
        # Use a sibling fixture path to rebind the originally admitted directory.
        with tempfile.TemporaryDirectory(prefix='public-tls-rebind-') as outer:
            source=Path(outer)/'source';source.mkdir(mode=0o700)
            directory=PublicCertificates(source,os.getuid())
            try:
                directory.publish('payment',self.cert);source.rename(Path(outer)/'saved');source.mkdir(mode=0o700)
                with self.assertRaises(Rejected):directory.read('payment')
                self.assertEqual(list(source.iterdir()),[])
            finally:directory.close()

    def test_temp_name_collision_never_unlinks_existing_file_or_overwrites_certificate(self):
        self.directory.publish('payment',self.cert)
        other=self.path/('.payment-'+'ab'*16+'.tmp');other.write_bytes(b'unrelated')
        with patch('ticket_host_tls_delivery_v1.secrets.token_hex',return_value='ab'*16),self.assertRaises(FileExistsError):
            self.directory.publish('payment',self.cert)
        self.assertEqual(other.read_bytes(),b'unrelated');self.assertEqual(self.directory.read('payment'),self.cert)

    def test_file_fsync_failure_preserves_old_leaf_and_removes_own_temp(self):
        self.directory.publish('payment',self.cert)
        with patch('ticket_host_tls_delivery_v1.os.fsync',side_effect=OSError('public fixture fsync failure')),self.assertRaises(OSError):
            self.directory.publish('payment',self.cert)
        self.assertEqual(self.directory.read('payment'),self.cert)
        self.assertEqual({p.name for p in self.path.iterdir()},{'payment.der'})


class RenewingServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixtures.HostTlsRenewalTests.setUpClass()
    def setUp(self):
        self.f=fixtures.HostTlsRenewalTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.boot=boots.BackendBootTests();self.boot.setUp();self.addCleanup(self.boot.doCleanups)
        self.temp=tempfile.TemporaryDirectory(prefix='service-tls-public-');self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name);self.directory=PublicCertificates(self.path,os.getuid());self.addCleanup(self.directory.close)
        self.directory.publish('payment',self.f.certificates['payment'])
        self.args={'ticket_native':self.boot.f.offer.protocol.native,'rpc':self.boot.f.rpc,'s3':self.boot.sdk}
    def assemble(self):return assemble_recovered(self.f.cfg,self.f.pin,self.f.bodies['payment'],self.directory,**self.args)
    def launch(self):
        app,context,config,poller=self.assemble();raw=socket.socket();raw.bind(('127.0.0.1',0));raw.listen(4)
        self.addCleanup(raw.close);self.address=raw.getsockname()
        server=RenewingRoleServer.from_config(app,context,raw,config,digest(config),poller=poller)
        stop=threading.Event();ready=threading.Event();result=[]
        thread=threading.Thread(target=lambda:result.append(server.run(stop,lambda _:ready.set())))
        thread.start()
        def close():stop.set();thread.join(timeout=5);self.assertFalse(thread.is_alive())
        self.addCleanup(close);self.assertTrue(ready.wait(3))
        return server,context,stop,thread,result
    def call(self):
        client=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);client.minimum_version=ssl.TLSVersion.TLSv1_3
        client.load_verify_locations(cadata=x509.load_der_x509_certificate(self.f.root_der).public_bytes(serialization.Encoding.PEM).decode())
        with socket.create_connection(self.address,timeout=2) as raw:
            with client.wrap_socket(raw,server_hostname=self.f.cfg['tls']['hostname']) as secure:
                certificate=secure.getpeercert(binary_form=True);deadline=time.monotonic()+3
                send(secure,request(self.f.cfg['offer_sha256'],'payment','parameters',{}),65536,deadline)
                value=receive(secure,65536,deadline)
                self.assertEqual(value['status'],'ok');self.assertEqual(value['result'],self.f.cfg['offer'])
                return certificate

    def test_actual_server_switches_certificate_from_public_poller_without_process_or_key_restart(self):
        server,context,stop,thread,result=self.launch();old=self.call()
        new=self.f.renewed(offset=30);self.directory.publish('payment',new)
        deadline=time.monotonic()+4
        while context._fingerprint!=hashlib.sha256(new).hexdigest() and time.monotonic()<deadline:threading.Event().wait(.02)
        self.assertEqual(context._fingerprint,hashlib.sha256(new).hexdigest())
        self.assertEqual(self.call(),new);self.assertNotEqual(old,new);self.assertTrue(thread.is_alive())
        self.assertTrue(server.snapshot()['tls_usable'])
        stop.set();thread.join(timeout=4);self.assertTrue(result[0]['drained'])

    def test_bad_public_updates_preserve_incumbent_and_do_not_mutate_application_or_private_keys(self):
        server,context,stop,thread,result=self.launch();old=self.call()
        self.directory.publish('payment',self.f.certificates['refund'])
        before=context._body['service_key_der'];self.assertFalse(server._poller.refresh()['ok'])
        self.assertEqual(self.call(),old);self.assertEqual(context._body['service_key_der'],before)
        self.assertEqual(server.application.offer.hash,self.f.cfg['offer_sha256'])
        with self.assertRaises(Rejected):server.context=context.current()

    def test_expired_context_blocks_new_handshake_before_any_application_dispatch(self):
        server,context,stop,thread,result=self.launch()
        with patch.object(server.application,'dispatch',wraps=server.application.dispatch) as dispatch:
            with patch.object(fixtures.ca.time,'time',return_value=context._expiry):
                self.assertFalse(server.snapshot()['tls_usable'])
                with self.assertRaises(Exception):self.call()
            dispatch.assert_not_called()

    def test_startup_ignores_bad_update_if_embedded_leaf_valid_but_needs_fresh_leaf_if_expired(self):
        self.directory.publish('payment',self.f.certificates['refund'])
        _,context,_,_=self.assemble();self.assertIsInstance(context.current(),ssl.SSLContext)
        future=self.f.ca_fixture.now+2*86400;new=self.f.renewed(offset=2*86400)
        with patch.object(fixtures.ca.time,'time',return_value=future):
            with self.assertRaises(Rejected):self.assemble()
            self.directory.publish('payment',new)
            _,context,_,_=self.assemble();self.assertIsInstance(context.current(),ssl.SSLContext)
        self.assertEqual(context._body['service_key_der'],self.f.bodies['payment']['service_key_der'])

    def test_runtime_validator_keeps_all_three_authorities_and_rejects_private_key_substitution(self):
        import copy
        from ticket_backend_boot_v1 import private_key
        for role,item in self.f.plan['roles'].items():
            context=RenewingContext(item['backend'],item['backend_sha256'],self.f.bodies[role])
            self.assertIsInstance(context.current(),ssl.SSLContext)
            body=copy.deepcopy(self.f.bodies[role])
            if role=='payment':
                from test_ticket_backend_boot_v1 import private
                body['service_key_der']=fixtures.ca.b64(private(self.f.ca_fixture.fresh._service['payment']))
            else:body['service_key_der']=self.f.bodies['refund' if role=='publication' else 'publication']['service_key_der']
            with self.assertRaises(Rejected):RenewingContext(item['backend'],item['backend_sha256'],body)

    def test_real_sealed_packet_with_expired_leaf_recovers_once_using_new_public_certificate(self):
        import base64
        from types import SimpleNamespace
        from unittest.mock import Mock
        from dataclasses import replace
        generated=self.f.fixture;generated.certificates=self.f.certificates
        result=generated.prepare();self.assertTrue(result['ok'])
        envelope=(generated.f.output/'payment.json').read_bytes();packet=json.loads(envelope)
        decrypt=Mock(side_effect=lambda wrapped:generated.f.data[wrapped])
        recovery=SimpleNamespace(key_arn=packet['kms_key_arn'],decrypt=decrypt)
        resources=Resources('payment',self.f.pin,'ef'*32,hashlib.sha256(envelope).hexdigest(),
            self.args['rpc'],self.args['s3'],recovery,None)
        # Wrong role or altered sealed bytes cannot trigger even the fixture KMS.
        with self.assertRaises(Rejected):boot_v2.assemble_sealed(self.f.cfg,self.f.pin,replace(resources,role='refund'),
            envelope,self.directory,ticket_native=self.args['ticket_native'])
        with self.assertRaises(Rejected):boot_v2.assemble_sealed(self.f.cfg,self.f.pin,resources,
            envelope+b'x',self.directory,ticket_native=self.args['ticket_native'])
        decrypt.assert_not_called()
        new=self.f.renewed(offset=2*86400);self.directory.publish('payment',new)
        with patch.object(fixtures.ca.time,'time',return_value=self.f.ca_fixture.now+2*86400):
            app,context,config,poller=boot_v2.assemble_sealed(self.f.cfg,self.f.pin,resources,envelope,
                self.directory,ticket_native=self.args['ticket_native'])
            self.assertIsInstance(context.current(),ssl.SSLContext)
        self.assertEqual(decrypt.call_count,1)
        self.assertEqual(app.offer.hash,self.f.cfg['offer_sha256'])
        self.assertEqual(context._body['service_key_der'],self.f.bodies['payment']['service_key_der'])
        self.assertEqual((generated.f.output/'payment.json').read_bytes(),envelope)


if __name__=='__main__':unittest.main()
