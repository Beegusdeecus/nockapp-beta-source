"""New worker profile with actual TCP/TLS/native application and public updates.

AWS/sealed recovery and separate CA filesystem ownership are explicit fixtures.
The production ownership checks remain unchanged; no owner state or cloud use.
"""
import copy
import hashlib
import io
import os
from pathlib import Path
import socket
import threading
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from policy import canonical,digest,Rejected
from ticket_supervised_v1 import Notifier
from ticket_host_tls_delivery_v1 import PublicCertificates
from ticket_backend_tls_boot_v2 import assemble_recovered
import ticket_renewing_process_v2 as process
import test_ticket_process_v1 as original
import test_ticket_tls_service_v2 as tls


class Notification(Notifier):
    def __init__(self):self.states=[];self.ready=threading.Event()
    def send(self,state):
        self.states.append(state)
        if state=='ready':self.ready.set()


def configuration(base,directory):
    base=copy.deepcopy(base);base['profile']=process.PROFILE;base['listen']['port']=8443
    extension={'profile':process.ca.PROFILE,'base':base['broker'],'base_sha256':base['broker_sha256'],
        'ca_uid':os.getuid()+50,'ca_role_arn':'arn:aws:iam::419720240831:role/nockapp-ticket-tls-ca',
        'ca_socket_path':process.CA_SOCKET,'duration_seconds':900}
    metadata=process.ca.metadata_policy(extension,digest(extension),'ab'*32)
    base['certificate_delivery']={'profile':process.DELIVERY,'directory':str(directory),'ca_broker':extension,
        'ca_broker_sha256':digest(extension),'metadata_policy':metadata,'metadata_policy_sha256':digest(metadata)}
    return base


class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):original.ProcessTests.setUpClass()
    @classmethod
    def tearDownClass(cls):original.ProcessTests.tearDownClass()
    def setUp(self):
        self.f=original.ProcessTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.directory=self.f.root/'public';self.directory.mkdir(mode=0o755)
        self.value=configuration(self.f.value,self.directory)
        p=patch.object(process,'PUBLIC_DIR',str(self.directory));p.start();self.addCleanup(p.stop)
        # Same-UID test cannot allocate the real CA UID. Only the filesystem
        # constructor is injected; all config/UID/metadata and file checks run.
        p=patch.object(process,'PublicCertificates',side_effect=lambda path,owner:PublicCertificates(path,os.getuid()))
        p.start();self.addCleanup(p.stop)

    def test_public_check_preserves_original_backend_resources_and_needs_no_private_packet_or_network(self):
        path=self.f.root/'new-profile.json';path.write_bytes(canonical(self.value));path.chmod(0o600);out=io.StringIO()
        before=copy.deepcopy(self.f.value)
        with patch.object(process.legacy,'resources_build',side_effect=AssertionError('no credentials')),\
             patch.object(process,'assemble_sealed',side_effect=AssertionError('no keys')),\
             patch('socket.create_connection',side_effect=AssertionError('no network')),redirect_stdout(out):
            self.assertEqual(process.main(['check','--deployment',str(path),'--sha256',digest(self.value)]),0)
        self.assertIn('"phase":"checked"',out.getvalue());self.assertEqual(self.f.value,before)
        for name in ('backend','backend_sha256','resources','resources_sha256','broker','broker_sha256'):
            self.assertEqual(self.value[name],before[name])
        self.assertFalse(Path(self.value['sealed_boot']).exists())

    def test_new_and_old_profiles_cannot_be_interchanged_or_add_private_facts(self):
        with self.assertRaises(Rejected):process.preflight(self.f.value,digest(self.f.value))
        with self.assertRaises(Rejected):process.legacy.preflight(self.value,digest(self.value))
        for change in ({'kind':'broker'},{'secret_key':'forbidden'},{'profile':process.legacy.PROFILE},
            {'listen':{'ip':'127.0.0.1','port':443}}):
            value={**self.value,**change}
            with self.subTest(change=change),self.assertRaises(Rejected):process.preflight(value,digest(value))

    def test_wrong_directory_ca_metadata_broker_and_group_are_rejected_before_recovery(self):
        mutations=[lambda v:v['certificate_delivery'].update(directory='/home/owner'),
            lambda v:v['certificate_delivery']['metadata_policy'].update(ca_uid=os.getuid()),
            lambda v:v['certificate_delivery']['ca_broker'].update(ca_uid=os.getuid()),
            lambda v:v['certificate_delivery'].update(ca_broker_sha256='00'*32)]
        with patch.object(process.legacy,'resources_build') as resources,patch.object(process,'assemble_sealed') as recovery:
            for change in mutations:
                value=copy.deepcopy(self.value);change(value)
                with self.assertRaises((Rejected,ValueError)):process.preflight(value,digest(value))
            with patch.object(process.os,'getgid',return_value=os.getgid()+1),self.assertRaises(Rejected):
                process.preflight(self.value,digest(self.value))
        resources.assert_not_called();recovery.assert_not_called()


class LiveTLSFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):tls.RenewingServiceTests.setUpClass();original.ProcessTests.setUpClass()
    @classmethod
    def tearDownClass(cls):original.ProcessTests.tearDownClass()
    def setUp(self):
        self.f=tls.RenewingServiceTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.plan=original.ProcessTests();self.plan.setUp();self.addCleanup(self.plan.doCleanups)
        self.value=configuration(self.plan.value,self.f.path)
        self.value['backend']=self.f.f.cfg;self.value['backend_sha256']=digest(self.f.f.cfg)
        self.value['resources']['backend_sha256']=self.value['backend_sha256']
        self.value['resources_sha256']=digest(self.value['resources'])
        free=socket.socket();free.bind(('127.0.0.1',0));self.f.address=free.getsockname();free.close()
        self.value['listen']={'ip':'127.0.0.1','port':self.f.address[1]}
        self.sealed=b'opaque synthetic encrypted packet';path=Path(self.value['sealed_boot']);path.write_bytes(self.sealed);path.chmod(0o600)
        self.contexts=[];self.stop=threading.Event();self.notifier=Notification();self.results=[];self.failures=[]
        for target,kwargs in [('PUBLIC_DIR',{'new':str(self.f.path)}),('PublicCertificates',{'side_effect':lambda p,owner:PublicCertificates(p,os.getuid())})]:
            p=patch.object(process,target,**kwargs);p.start();self.addCleanup(p.stop)
    def assembled(self,cfg,pin,resource,envelope,directory,**kwargs):
        self.assertEqual(envelope,self.sealed)
        result=assemble_recovered(cfg,pin,self.f.f.bodies['payment'],directory,ticket_native=kwargs['ticket_native'],
            rpc=self.f.boot.f.rpc,s3=self.f.boot.sdk)
        self.contexts.append(result[1]);return result
    def worker(self):
        try:self.results.append(process.serve(self.value,digest(self.value),self.stop,self.notifier))
        except Exception as error:self.failures.append(type(error).__name__)

    def test_owned_worker_reloads_actual_tls_without_restart_or_spending_key_change(self):
        with patch.object(process.legacy,'resources_build',return_value=object()),patch.object(process,'assemble_sealed',side_effect=self.assembled):
            thread=threading.Thread(target=self.worker);thread.start()
            try:
                self.assertTrue(self.notifier.ready.wait(5),self.failures);old=self.f.call()
                key_hash=hashlib.sha256(self.contexts[0]._body['service_key_der'].encode()).hexdigest()
                renewed=self.f.f.renewed(offset=30);self.f.directory.publish('payment',renewed)
                deadline=time.monotonic()+4
                while self.contexts[0]._fingerprint!=hashlib.sha256(renewed).hexdigest() and time.monotonic()<deadline:
                    threading.Event().wait(.02)
                self.assertEqual(self.f.call(),renewed);self.assertNotEqual(old,renewed);self.assertTrue(thread.is_alive())
                self.assertEqual(hashlib.sha256(self.contexts[0]._body['service_key_der'].encode()).hexdigest(),key_hash)
            finally:self.stop.set();thread.join(timeout=5)
        self.assertFalse(thread.is_alive());self.assertEqual(self.failures,[]);self.assertEqual(self.notifier.states,['ready'])
        self.assertTrue(self.results[0]['drained']);self.assertFalse(self.results[0]['CA_credentials_used'])

    def test_recovery_failure_never_announces_ready_and_closes_owned_tcp_listener(self):
        with patch.object(process.legacy,'resources_build',return_value=object()),\
             patch.object(process,'assemble_sealed',side_effect=Rejected('synthetic recovery failure')),self.assertRaises(Rejected):
            process.serve(self.value,digest(self.value),self.stop,self.notifier)
        self.assertEqual(self.notifier.states,[])
        with socket.socket() as available:available.bind(self.f.address)


if __name__=='__main__':unittest.main()
