"""Executable admission/lifecycle with actual sockets, native crypto and local EVM.

AWS transport is supplied by existing fixture resources; this is not a configured
host, separate Unix users, systemd installation or production key provisioning.
"""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import selectors
import ssl
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from policy import canonical,Rejected
import ticket_process_v1 as process
from ticket_backend_resources_v1 import PROFILE as RESOURCE
from ticket_transport_v2 import TicketRemote,ENDPOINT
from test_ticket_aws_credentials_v1 import cfg as broker_config
import test_ticket_backend_boot_v1 as boots

Z=Path(__file__).resolve().parent

class ProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        boots.BackendBootTests.setUpClass()
        cls.fixture=boots.BackendBootTests();cls.fixture.setUp()
        try:
            f=cls.fixture
            cls.backend=f.config('payment',f.f.offer,f.keys,{'purchase_bucket':'private-refund-lab'})
            cls.packet=f.body(cls.backend,f.f.f.crypto.private)
        except Exception:cls.fixture.doCleanups();raise
    @classmethod
    def tearDownClass(cls):cls.fixture.doCleanups()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ticket-process-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.deployment=self.root/'deployment.json'
        native=self.root/'ticket-worker';native.write_bytes(self.fixture.f.offer.protocol.native.binary.read_bytes());native.chmod(0o500)
        b=broker_config(str(self.root/'broker.sock'));account=self.backend['records']['account_id']
        old=b['account_id'];b['account_id']=account
        for field in ('instance_role_arn','instance_profile_arn'):b[field]=b[field].replace(old,account)
        for role,v in b['roles'].items():v['role_arn']=v['role_arn'].replace(old,account)
        self.plan={'profile':RESOURCE,'backend_sha256':process.pin(self.backend),'broker_sha256':process.pin(b),
            'rpc':{'endpoint':'https://sepolia.base.org','rate':8,'burst':16,'timeout':5},
            'kms_key_arn':'arn:aws:kms:ap-southeast-2:'+account+':key/12345678-1234-1234-1234-123456789abc',
            'sealed_boot_sha256':process.sha(b'opaque synthetic encrypted packet')}
        self.value={'profile':process.PROFILE,'kind':'role','broker':b,'broker_sha256':process.pin(b),
            'backend':copy.deepcopy(self.backend),'backend_sha256':process.pin(self.backend),'resources':self.plan,
            'resources_sha256':process.pin(self.plan),'ticket_native':str(native),
            'author_native':None,'sealed_boot':str(self.root/'not-present.cms'),'scratch':None,
            'listen':{'ip':'127.0.0.1','port':443}}

    def write(self,value=None):
        value=self.value if value is None else value;self.deployment.write_bytes(canonical(value));self.deployment.chmod(0o600)
        return ['check','--deployment',str(self.deployment),'--sha256',process.pin(value)]

    def listener(self):
        s=socket.socket();s.bind(('127.0.0.1',0));s.listen(4);self.addCleanup(s.close)
        self.value['listen']={'ip':'127.0.0.1','port':s.getsockname()[1]};return s

    def test_check_is_public_only_no_sealed_packet_socket_or_provider(self):
        argv=self.write();out=io.StringIO()
        with patch('socket.create_connection',side_effect=AssertionError('no network')),\
            patch.object(process,'resources_build',side_effect=AssertionError('no resources')),\
            patch.object(process,'broker_build',side_effect=AssertionError('no provider')),\
            patch.object(process,'assemble_sealed',side_effect=AssertionError('no keys')),contextlib.redirect_stdout(out):
            self.assertEqual(process.main(argv),0)
        self.assertEqual(json.loads(out.getvalue())['phase'],'checked');self.assertFalse(Path(self.value['sealed_boot']).exists())

    def test_public_pin_schema_role_user_plan_rpc_and_native_fail_before_recovery(self):
        changes=[lambda v:v.update(secret_key='forbidden'),lambda v:v.update(kind='arbitrary-factory'),
            lambda v:v.update(author_native='/tmp/unapproved'),lambda v:v['broker']['roles']['payment'].update(uid=os.getuid()+55),
            lambda v:v['resources'].update(kms_key_arn=v['resources']['kms_key_arn'].replace('419720240831','999999999999')),
            lambda v:v['resources']['rpc'].update(endpoint='http://169.254.169.254/'),
            lambda v:v.update(ticket_native=str(self.root/'.env')),
            lambda v:v.update(sealed_boot=str(self.root/'.env.owner')),
            lambda v:v.update(listen={'ip':'::ffff:127.0.0.1','port':443})]
        for index,change in enumerate(changes):
            value=copy.deepcopy(self.value);change(value)
            value['broker_sha256']=process.pin(value['broker']);value['resources']['broker_sha256']=value['broker_sha256']
            value['resources_sha256']=process.pin(value['resources'])
            with self.subTest(case=index),self.assertRaises((Rejected,ValueError,OSError)):process.preflight(value,process.pin(value))
        with self.assertRaises(Rejected):process.preflight(self.value,'12'*32)

    def test_safe_file_reader_rejects_symlink_fifo_oversize_and_writable_files(self):
        target=self.root/'public.json';target.write_bytes(b'public');target.chmod(0o600)
        link=self.root/'link';link.symlink_to(target)
        folder=self.root/'folder';folder.symlink_to(self.root,target_is_directory=True)
        fifo=self.root/'fifo';os.mkfifo(fifo)
        for p in (link,folder/'public.json',fifo):
            with self.assertRaises((Rejected,OSError)):process.read_file(str(p),100)
        with self.assertRaises(Rejected):process.read_file(str(target),2)
        target.chmod(0o666)
        with self.assertRaises(Rejected):process.read_file(str(target),100)

    def test_native_bytes_or_executable_permissions_cannot_change_after_approval(self):
        path=Path(self.value['ticket_native']);path.chmod(0o600)
        with self.assertRaises(Rejected):process.preflight(self.value,process.pin(self.value))
        path.write_bytes(b'changed native executable');path.chmod(0o500)
        with self.assertRaisesRegex(Rejected,'file-pin'):process.preflight(self.value,process.pin(self.value))

    def test_scratch_never_initializes_or_reuses_an_old_journal(self):
        p=self.root/'scratch';p.mkdir(mode=0o700);process.scratch(str(p));self.assertEqual(list(p.iterdir()),[])
        (p/'journal.sqlite').symlink_to(self.root/'absent')
        with self.assertRaisesRegex(Rejected,'not-fresh'):process.scratch(str(p))
        (p/'journal.sqlite').unlink();p.chmod(0o750)
        with self.assertRaises(Rejected):process.scratch(str(p))

    def test_inherited_tcp_listener_exact_bind_and_nonlistening_guards(self):
        s=self.listener()
        with process.listener(self.value,os.dup(s.fileno())) as accepted:
            self.assertFalse(accepted.get_inheritable());self.assertEqual(accepted.getsockname(),s.getsockname())
        bad=copy.deepcopy(self.value);bad['listen']['port']+=1
        with self.assertRaises(Rejected):process.listener(bad,os.dup(s.fileno()))
        left,right=socket.socketpair()
        with left,right,self.assertRaises(Rejected):process.listener(self.value,os.dup(left.fileno()))

    def test_ipv6_socket_must_not_accept_unpinned_ipv4_connections(self):
        if not socket.has_ipv6:self.skipTest('IPv6 unavailable on fixture host')
        s=socket.socket(socket.AF_INET6);self.addCleanup(s.close)
        try:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0);s.bind(('::',0));s.listen(1)
        except OSError:self.skipTest('dual-stack unavailable on fixture host')
        self.value['listen']={'ip':'::','port':s.getsockname()[1]}
        with self.assertRaisesRegex(Rejected,'dual-stack'):process.listener(self.value,os.dup(s.fileno()))

    def broker_value(self):
        b=copy.deepcopy(self.value['broker']);b['broker_uid']=os.getuid()
        for n,r in enumerate(b['roles'].values()):r['uid']=os.getuid()+10+n
        return {'profile':process.PROFILE,'kind':'broker','broker':b,'broker_sha256':process.pin(b)}

    def broker_listener(self,value):
        self.root.chmod(0o750)
        s=socket.socket(socket.AF_UNIX);s.bind(value['broker']['socket_path']);s.listen(4)
        self.addCleanup(s.close);Path(value['broker']['socket_path']).chmod(0o660);return s

    def test_unix_listener_requires_exact_socket_parent_uid_gid_and_modes(self):
        value=self.broker_value();s=self.broker_listener(value);process.preflight(value,process.pin(value))
        with process.listener(value,os.dup(s.fileno())):pass
        Path(value['broker']['socket_path']).chmod(0o666)
        with self.assertRaises(Rejected):process.listener(value,os.dup(s.fileno()))
        Path(value['broker']['socket_path']).chmod(0o660);self.root.chmod(0o770)
        with self.assertRaises(Rejected):process.listener(value,os.dup(s.fileno()))

    def test_wrong_inherited_socket_or_changed_packet_precedes_resource_construction(self):
        s=self.listener();bad=copy.deepcopy(self.value);bad['listen']['port']+=1
        with patch.object(process,'resources_build',side_effect=AssertionError('no key provider')):
            with self.assertRaises(Rejected):process.run(bad,process.pin(bad),threading.Event(),descriptor=os.dup(s.fileno()))
            path=Path(self.value['sealed_boot']);path.write_bytes(b'wrong encrypted file');path.chmod(0o600)
            with self.assertRaises(Rejected):process.run(self.value,process.pin(self.value),threading.Event(),descriptor=os.dup(s.fileno()))

    def test_broker_real_inherited_listener_readiness_and_clean_stop_without_metadata(self):
        value=self.broker_value();s=self.broker_listener(value);stop=threading.Event();ready=[]
        def started(status):ready.append(status);stop.set()
        with patch('socket.create_connection',side_effect=AssertionError('no metadata/STS without request')):
            result=process.run(value,process.pin(value),stop,started,descriptor=os.dup(s.fileno()))
        self.assertEqual(ready[0]['phase'],'listening');self.assertTrue(result['drained'])

    def test_actual_role_tls_payment_from_existing_recovered_key_no_new_identity(self):
        s=self.listener();stop=threading.Event();ready=threading.Event();results=[];errors=[];f=self.fixture
        sealed=b'opaque synthetic encrypted packet';p=Path(self.value['sealed_boot']);p.write_bytes(sealed);p.chmod(0o600)
        def assembled(cfg,pin,resource,envelope,**kwargs):
            self.assertEqual(envelope,sealed);return f.boot(cfg,self.packet,ticket_native=kwargs['ticket_native'],rpc=f.f.rpc,s3=f.sdk)
        def serve():
            try:results.append(process.run(self.value,process.pin(self.value),stop,lambda _:ready.set(),descriptor=os.dup(s.fileno())))
            except Exception as exc:errors.append(exc)
        with patch.object(process,'resources_build',return_value=object()),patch.object(process,'assemble_sealed',side_effect=assembled):
            thread=threading.Thread(target=serve);thread.start()
            try:
                self.assertTrue(ready.wait(5),errors)
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.minimum_version=ssl.TLSVersion.TLSv1_3
                context.load_verify_locations(cadata=f.root.public_bytes(boots.serialization.Encoding.PEM).decode())
                endpoint={'profile':ENDPOINT,'host':boots.HOST,'port':s.getsockname()[1],'service':'payment','offer_sha256':f.f.offer.hash}
                remote=TicketRemote(endpoint,context,dial=lambda:socket.create_connection(s.getsockname(),timeout=2))
                self.assertEqual(remote.call('parameters',{}),f.f.offer.manifest)
            finally:stop.set();thread.join(timeout=5)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[]);self.assertEqual(results[0]['phase'],'stopped')

    def test_role_failure_or_incomplete_drain_cannot_be_success(self):
        s=self.listener();p=Path(self.value['sealed_boot']);p.write_bytes(b'opaque synthetic encrypted packet');p.chmod(0o600)
        for phase,drained in [('failed',True),('drain-incomplete',False)]:
            server={'profile':'synthetic'}
            with patch.object(process,'resources_build',return_value=object()),\
                patch.object(process,'assemble_sealed',return_value=(object(),object(),server)),\
                patch.object(process.RoleServer,'from_config') as factory:
                factory.return_value.run.return_value={'phase':phase,'drained':drained}
                with self.assertRaisesRegex(Rejected,'role-failed'):
                    process.run(self.value,process.pin(self.value),threading.Event(),descriptor=os.dup(s.fileno()))

    def test_cli_bad_configuration_is_sanitized_and_nonzero(self):
        argv=self.write();argv[-1]='12'*32;out=io.StringIO()
        with contextlib.redirect_stdout(out):self.assertEqual(process.main(argv),1)
        self.assertEqual(json.loads(out.getvalue()),{'ok':False,'profile':process.PROFILE,'error':'ticket-process-unavailable'})
        self.assertNotIn(str(self.deployment),out.getvalue())

    def test_real_executable_check_in_isolated_python_with_hostile_ambient_configuration(self):
        argv=self.write()
        code='import sys;sys.path.insert(0,sys.argv.pop(1));from ticket_process_v1 import main;raise SystemExit(main())'
        result=subprocess.run([sys.executable,'-I','-B','-c',code,str(Z),*argv],capture_output=True,timeout=20,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','AWS_PROFILE':'unapproved','AWS_ENDPOINT_URL':'http://169.254.169.254',
                'HTTPS_PROXY':'http://127.0.0.1:1','SSLKEYLOGFILE':str(self.root/'must-not-exist')})
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stderr,b'')
        self.assertEqual(json.loads(result.stdout)['phase'],'checked');self.assertFalse((self.root/'must-not-exist').exists())

    def test_real_broker_process_uses_fd3_and_handles_sigterm_with_clean_drain(self):
        value=self.broker_value();s=self.broker_listener(value);argv=self.write(value);argv[0]='serve'
        code=('import os,sys;sys.path.insert(0,sys.argv.pop(1));fd=int(sys.argv.pop(1));'
            'os.dup2(fd,3,inheritable=False);'
            'exec("if fd!=3:os.close(fd)");'
            'from ticket_process_v1 import main;raise SystemExit(main())')
        child=subprocess.Popen([sys.executable,'-I','-B','-c',code,str(Z),str(s.fileno()),*argv],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(s.fileno(),),env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout,selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=10),'broker readiness timeout')
            first=json.loads(child.stdout.readline());self.assertEqual(first['phase'],'listening')
            child.terminate();out,err=child.communicate(timeout=5)
            self.assertEqual(child.returncode,0,err);self.assertEqual(err,b'')
            self.assertEqual(json.loads(out)['phase'],'stopped');self.assertTrue(json.loads(out)['drained'])
        finally:
            if child.poll() is None:child.kill();child.communicate(timeout=5)

if __name__=='__main__':unittest.main()
