"""Real byte-stream/TLS tests; no cloud, provider or user credentials involved."""
from contextlib import contextmanager,redirect_stdout,redirect_stderr
import hashlib
import io
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import Mock,patch

from issuer_relays import RelayHost,relay_opaque,fixed_targets,PORTS,MAX_SESSIONS
from policy import HOST,ProviderClient,Rejected
from test_provider_tls import server,response
from test_aws_transport import credentials,REGION,check_signature


@contextmanager
def proxied(dial):
    workers=[];streams=[];errors=[];stop=threading.Event()
    def open_proxy():
        client,left=socket.socketpair();right=dial();streams.extend((client,left,right))
        def run():
            try:relay_opaque(left,right,stop,timeout=3)
            except OSError:pass
            except Exception as error:errors.append(type(error).__name__)
            finally:left.close();right.close()
        worker=threading.Thread(target=run);workers.append(worker);worker.start();return client
    try:yield open_proxy
    finally:
        stop.set()
        for worker in workers:worker.join(timeout=4)
        for stream in streams:stream.close()
        if any(w.is_alive() for w in workers) or errors:raise AssertionError('relay fixture cleanup')


class RelayTests(unittest.TestCase):
    def test_separate_verifier_has_only_fixed_enrollment_and_approved_shared_egress(self):
        host=RelayHost(16,REGION,workload_sessions=True,verifier_cid=17)
        for service,peer in [('provider',(17,0)),('issuer_enrollment',(16,0)),('kms',(3,0))]:
            stream=Mock();self.assertFalse(host.admit(stream,service,peer));stream.close.assert_called_once()
        with patch('issuer_relays.threading.Thread'):
            for service in ('kms','dynamodb','rolesanywhere','issuer_enrollment'):
                self.assertTrue(host.admit(Mock(),service,(17,0)))
            host.close()
        with patch('issuer_relays.socket.socket') as make:
            host.destination('issuer_enrollment');make.return_value.connect.assert_called_with((16,PORTS['issuer']))
            host.destination('verifier');make.return_value.connect.assert_called_with((17,9447))
            host.destination('verifier_bootstrap');make.return_value.connect.assert_called_with((17,9448))
        for kwargs in [{'verifier_cid':16,'workload_sessions':True},{'verifier_cid':17},{'verifier_cid':True,'workload_sessions':True}]:
            with self.assertRaises(ValueError):RelayHost(16,REGION,**kwargs)

    def test_workload_egress_is_opt_in_fixed_and_only_selected_enclave_can_use_it(self):
        from renewable_issuer import ROLESANYWHERE_PORT
        legacy=RelayHost(16,REGION);host=RelayHost(16,REGION,workload_sessions=True)
        self.assertNotIn('rolesanywhere',legacy.targets)
        self.assertEqual(host.ports['rolesanywhere'],ROLESANYWHERE_PORT)
        with self.assertRaises(ValueError):legacy.destination('rolesanywhere')
        with patch('issuer_relays.socket.create_connection') as dial:
            host.destination('rolesanywhere')
            dial.assert_called_once_with(('rolesanywhere.'+REGION+'.amazonaws.com',443),timeout=10)
        stream=Mock();self.assertFalse(host.admit(stream,'rolesanywhere',(17,0)));stream.close.assert_called_once()

    def test_actual_workload_session_tls_crosses_only_opaque_byte_relay(self):
        from test_workload_sessions import identity,issued,wire_signature,HOST
        from workload_sessions import WorkloadSession
        from policy import canonical
        cfg,der,key=identity()
        with server([response(canonical(issued(cfg)),status=201)],hostname=HOST) as (context,dial,seen),proxied(dial) as routed:
            result=WorkloadSession(cfg,der,key,context,routed).create_session()
        self.assertEqual(result['access_key_id'],'ASIA'+'A'*16)
        wire_signature(self,seen[0],cfg,key)

    def test_01_ports_match_measured_supervisor_and_targets_are_fixed(self):
        from issuer_supervisor import PORTS as MEASURED_PORTS
        self.assertEqual(PORTS,MEASURED_PORTS)
        self.assertEqual(fixed_targets(REGION),{'kms':('kms.'+REGION+'.amazonaws.com',443),
            'dynamodb':('dynamodb.'+REGION+'.amazonaws.com',443),'provider':('api.twitterapi.io',443)})
        for region in ['https://wrong.invalid','us-east-1/other','us-east-1\n','localhost']:
            with self.assertRaises(ValueError):fixed_targets(region)
        for cid in [0,1,2,3,2**32-1,True]:
            with self.assertRaises(ValueError):RelayHost(cid,REGION)

    def test_02_all_tcp_listeners_are_loopback_and_vsock_egress_is_fixed(self):
        host=RelayHost(16,REGION,issuer_port=0,bootstrap_port=0);made=[]
        def create(family,kind):
            stream=Mock();stream.family=family;made.append(stream);return stream
        with patch('issuer_relays.socket.socket',side_effect=create),patch('issuer_relays.threading.Thread'):
            host.start();host.close()
        self.assertEqual(len(made),5)
        for stream,service in zip(made,('kms','dynamodb','provider','issuer','bootstrap')):
            stream.bind.assert_called_once_with((socket.VMADDR_CID_ANY,PORTS[service])
                if service in host.targets else ('127.0.0.1',0))

    def test_03_wrong_enclave_or_non_loopback_peer_is_not_admitted(self):
        host=RelayHost(16,REGION)
        for service,peer in [('kms',(17,1234)),('provider',(3,1234)),('issuer',('192.0.2.1',1234))]:
            stream=Mock();self.assertFalse(host.admit(stream,service,peer));stream.close.assert_called_once()

    def test_04_busy_host_rejects_without_dialing_or_unbounded_workers(self):
        host=RelayHost(16,REGION)
        for _ in range(MAX_SESSIONS):self.assertTrue(host._slots.acquire(blocking=False))
        with patch.object(host,'destination') as destination:
            stream=Mock();self.assertFalse(host.admit(stream,'kms',(16,1234)))
            stream.close.assert_called_once();destination.assert_not_called()
        for _ in range(MAX_SESSIONS):host._slots.release()

    def test_05_large_stream_and_directional_eof_preserve_all_bytes(self):
        client,left=socket.socketpair();right,remote=socket.socketpair();errors=[]
        payload=b'public synthetic relay fixture'*40000
        def relay():
            try:relay_opaque(left,right,timeout=3)
            except Exception as error:errors.append(type(error).__name__)
        def endpoint():
            data=bytearray()
            while chunk:=remote.recv(32768):data.extend(chunk)
            remote.sendall(hashlib.sha256(data).digest()+b'ack');remote.shutdown(socket.SHUT_WR)
        relay_worker=threading.Thread(target=relay);endpoint_worker=threading.Thread(target=endpoint)
        relay_worker.start();endpoint_worker.start()
        try:
            client.settimeout(3);client.sendall(payload);client.shutdown(socket.SHUT_WR)
            result=bytearray()
            while chunk:=client.recv(1024):result.extend(chunk)
            self.assertEqual(bytes(result),hashlib.sha256(payload).digest()+b'ack')
        finally:
            for stream in (client,left,right,remote):stream.close()
            relay_worker.join(timeout=3);endpoint_worker.join(timeout=3)
        self.assertFalse(relay_worker.is_alive());self.assertFalse(endpoint_worker.is_alive());self.assertEqual(errors,[])

    def test_06_idle_deadline_is_total_and_bounded(self):
        left,peer_left=socket.socketpair();right,peer_right=socket.socketpair()
        started=time.monotonic()
        try:
            with self.assertRaises(TimeoutError):relay_opaque(left,right,timeout=0.05)
            self.assertLess(time.monotonic()-started,1)
        finally:
            for stream in (left,right,peer_left,peer_right):stream.close()

    def test_07_stop_cancels_an_idle_session_promptly(self):
        left,peer_left=socket.socketpair();right,peer_right=socket.socketpair();stop=threading.Event()
        worker=threading.Thread(target=relay_opaque,args=(left,right,stop));worker.start();stop.set();worker.join(timeout=1)
        for stream in (left,right,peer_left,peer_right):stream.close()
        self.assertFalse(worker.is_alive())

    def test_08_destination_never_takes_a_caller_url_or_falls_back_to_tcp(self):
        host=RelayHost(16,REGION)
        with patch('issuer_relays.socket.create_connection') as tcp:
            host.destination('provider');tcp.assert_called_once_with(('api.twitterapi.io',443),timeout=10)
        with patch('issuer_relays.socket.socket') as vsock:
            host.destination('bootstrap');vsock.assert_called_once_with(socket.AF_VSOCK,socket.SOCK_STREAM)
            vsock.return_value.connect.assert_called_once_with((16,9444))
        with patch('issuer_relays.socket.create_connection') as tcp:
            with self.assertRaises(ValueError):host.destination('https://wrong.invalid')
            tcp.assert_not_called()

    def test_09_partial_listener_failure_closes_every_owned_listener(self):
        host=RelayHost(16,REGION);made=[]
        def create(*args):
            stream=Mock();made.append(stream)
            if len(made)==3:stream.bind.side_effect=OSError('synthetic busy port')
            return stream
        with patch('issuer_relays.socket.socket',side_effect=create),patch('issuer_relays.threading.Thread'):
            with self.assertRaisesRegex(ValueError,'^relay-start-failed$'):host.start()
        for stream in made:stream.close.assert_called()

    def test_10_actual_provider_tls_remains_end_to_end_through_byte_relay(self):
        with server([response(b'{"synthetic":true}')]) as (context,dial,seen):
            with proxied(dial) as proxy:
                data=ProviderClient('SYNTHETIC-NOT-A-CREDENTIAL',context,proxy)._get('/twitter/tweets?tweet_ids=1')
                self.assertEqual(data,b'{"synthetic":true}')
        self.assertEqual(len(seen),1);self.assertIn(b'Host: '+HOST.encode(),seen[0])
        with server([response()],hostname='wrong.invalid') as (context,dial,seen):
            with proxied(dial) as proxy:
                with self.assertRaises(Rejected):ProviderClient('SYNTHETIC-NOT-A-CREDENTIAL',context,proxy)._get('/twitter/tweets?tweet_ids=1')
        self.assertEqual(seen,[])

    def test_11_actual_signed_aws_tls_passes_opaque_relay(self):
        from aws_transport import AwsJsonClient
        with server([response()],hostname='kms.'+REGION+'.amazonaws.com') as (context,dial,seen):
            with proxied(dial) as proxy:
                AwsJsonClient('kms',REGION,credentials(),context,proxy).decrypt(CiphertextBlob=b'public synthetic ciphertext')
        self.assertEqual(len(seen),1);check_signature(self,seen[0],'kms')

    def test_12_failed_dial_releases_slot_and_emits_no_private_diagnostics(self):
        host=RelayHost(16,REGION);host._slots.acquire();stream=Mock();output=io.StringIO()
        with patch.object(host,'destination',side_effect=TimeoutError('SYNTHETIC-PRIVATE-MARKER')):
            with redirect_stdout(output),redirect_stderr(output):host._handle(stream,'kms')
        self.assertEqual(output.getvalue(),'');stream.close.assert_called_once()
        acquired=[host._slots.acquire(blocking=False) for _ in range(MAX_SESSIONS)]
        self.assertTrue(all(acquired))
        for _ in acquired:host._slots.release()

    def test_13_parent_tool_runs_without_third_party_python_packages(self):
        script=Path(__file__).with_name('issuer_relays.py')
        result=subprocess.run([sys.executable,'-I','-B','-S',str(script),'--help'],capture_output=True,timeout=3)
        self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'')
        self.assertIn(b'--cid',result.stdout);self.assertNotIn(b'--url',result.stdout)


if __name__=='__main__':unittest.main()
