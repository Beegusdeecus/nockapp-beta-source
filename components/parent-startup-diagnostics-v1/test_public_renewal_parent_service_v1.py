"""Crash boundaries and publication gate; Nitro/AWS/source remain fixtures."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from policy import Rejected,canonical,digest
import public_renewal_parent_service_v1 as service
import test_public_renewal_parent_bootstrap_v1 as fixtures
from test_renewal_transport_v3 import fixture as approval_fixture

INSTANCE='i-07cdced76336a314e'
ENCLAVE=INSTANCE+'-encabcdef'
BOOT='11111111-2222-3333-4444-555555555555'


class InputTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.ParentBootstrapTests();f.setUp();self.addCleanup(f.doCleanups)
        self.f=f;self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.directory=Path(self.tmp.name)
        image=self.directory/'serving.eif';image.write_bytes(b'synthetic-only-image')
        self.patch=patch.object(service,'GUEST_EIF',str(image));self.patch.start();self.addCleanup(self.patch.stop)
        approved=approval_fixture();approved['identity']=f.config['service']
        for key in ('code_identity','state_authority_sha256','pcrs'):approved[key]=copy.deepcopy(f.approved[key])
        approved['endpoint']['port']=19449
        values={'config':f.config,'boot_approval':f.approved,'packet':f.packet,'plan':f.value,'service_approval':approved}
        paths={}
        for key,value in values.items():
            path=self.directory/(key+'.json');path.write_bytes(canonical(value));path.chmod(0o600);paths[key]=str(path)
        self.spec={'profile':service.PROFILE,'instance_id':INSTANCE,'eif':str(image),'eif_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),
            **paths,'plan_sha256':digest(f.value),'service_approval_sha256':digest(approved),'bind':'0.0.0.0',
            'port':19449,'readiness_seconds':3600}

    def test_actual_pinned_plan_admits_without_imds_or_host_tool(self):
        with patch.object(service.bootstrap,'credentials') as creds,patch.object(service,'host_request') as host:
            value=service.inputs(self.spec,digest(self.spec))
        self.assertEqual(value['config'],self.f.config);creds.assert_not_called();host.assert_not_called()

    def test_migration_changed_image_different_service_and_extra_authority_are_rejected(self):
        for change in ({'profile':'migration'},{'bind':'127.0.0.1'},{'port':22},{'readiness_seconds':3601},
                       {'bootstrap_argv':['preserve']},{'instance_id':'i-'+'1'*17}):
            spec={**self.spec,**change}
            with self.subTest(change=change),self.assertRaises(Rejected):service.inputs(spec,digest(spec))
        Path(self.spec['eif']).write_bytes(b'different image')
        with self.assertRaises(Rejected):service.inputs(self.spec,digest(self.spec))

    def test_same_authority_but_different_code_is_rejected(self):
        path=Path(self.spec['service_approval']);approved=service.bootstrap.read_record(path)
        approved['code_identity']='cd'*32;path.write_bytes(canonical(approved))
        self.spec['service_approval_sha256']=digest(approved)
        with self.assertRaises(Rejected):service.inputs(self.spec,digest(self.spec))


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.directory=Path(self.tmp.name);self.directory.chmod(0o700)
        self.pin='12'*32;self.ledger=service.Ledger(self.directory,self.pin);self.addCleanup(lambda:self.ledger.close())
        approved=approval_fixture();self.approved=approved
        self.spec={'instance_id':INSTANCE,'eif':service.GUEST_EIF,'plan_sha256':'34'*32,
            'readiness_seconds':3600,'bind':'0.0.0.0','port':19449}
        self.records={'service_approval':approved,'boot_approval':{},'packet':{},'plan':{},
            'config':{'issuer':{'authority':{'region':'ap-southeast-2'}}}}
        self.rows=[];self.calls=[];self.lost_launch=False;self.boot_failure=False;self.probe_failure=False
        self.host=Mock();self.host.start.return_value={'issuer':('127.0.0.1',12345),'bootstrap':('127.0.0.1',12346)}
        self.host.stop_event.is_set.return_value=False
        self.gateway=Mock();self.gateway.stop_event.is_set.return_value=False
        self.stop=Mock();self.stop.is_set.return_value=False;self.stop.wait.return_value=True
        def read_text(path,*a,**kw):
            if path==service.INSTANCE:return INSTANCE
            if path==service.BOOT_ID:return BOOT
            raise AssertionError('unexpected file')
        self.boot=Mock(side_effect=self.bootstrap);self.probe=Mock(side_effect=self.readiness)
        self.listener=Mock()
        for target,kwargs in [('inputs',{'return_value':self.records}),('host_request',{'side_effect':self.host_request}),
            ('RelayHost',{'return_value':self.host}),('PublicGateway',{'return_value':self.gateway}),
            ('readiness',{'new':self.probe}),('bootstrap_listener',{'new':self.listener}),('notify_ready',{} )]:
            p=patch.object(service,target,**kwargs);p.start();self.addCleanup(p.stop)
        for target,kwargs in [(service.bootstrap,{'execute':self.boot})]:
            p=patch.object(target,'execute',kwargs['execute']);p.start();self.addCleanup(p.stop)
        p=patch.object(Path,'read_text',read_text);p.start();self.addCleanup(p.stop)
        p=patch.object(service.socket,'create_connection');p.start();self.addCleanup(p.stop)

    def host_request(self,args):
        self.calls.append(args)
        if args==['describe-enclaves']:return copy.deepcopy(self.rows)
        if args[0]=='run-enclave':
            self.rows=[{'EnclaveID':ENCLAVE,'EnclaveName':args[8],'EnclaveCID':16,'State':'RUNNING','Flags':'NONE',
                'Measurements':{'PCR'+k:v for k,v in self.approved['pcrs'].items()}}]
            if self.lost_launch:raise TimeoutError('synthetic-lost-launch-reply')
            return {'EnclaveID':ENCLAVE}
        raise AssertionError('mutation outside fixed launch')

    def bootstrap(self,*args):
        self.listener.assert_called()
        self.assertTrue(self.ledger.value['bootstrap_attempted'])
        if self.boot_failure:raise TimeoutError('synthetic-lost-boot-reply')
        return {'state':'startup-acknowledged'}

    def readiness(self,*args):
        self.gateway.start.assert_not_called()
        if self.probe_failure:raise Rejected('synthetic-not-ready')
        return {'operational_lease_gate_passed':True}

    def run_service(self):return service.run(self.spec,self.pin,self.stop,self.ledger)

    def restart(self):
        self.ledger.close();self.ledger=service.Ledger(self.directory,self.pin)
        self.gateway.reset_mock();self.host.reset_mock()

    def test_restart_reattaches_recorded_service_without_boot_or_launch_and_keeps_it_running(self):
        self.assertTrue(self.run_service()['enclave_retained']);self.boot.assert_called_once();self.gateway.start.assert_called_once()
        self.assertEqual(self.gateway._routes,{service.RENEWAL:(16,9440)})
        self.restart();self.run_service();self.boot.assert_called_once()
        self.assertEqual(sum(c[0]=='run-enclave' for c in self.calls),1)
        self.assertEqual(len(self.rows),1);self.gateway.start.assert_called_once();self.gateway.close.assert_called_once()

    def test_lost_boot_reply_never_repeats_boot_and_recovery_needs_operational_gate(self):
        self.boot_failure=True
        with self.assertRaises(TimeoutError):self.run_service()
        self.gateway.start.assert_not_called();self.assertTrue(self.ledger.value['bootstrap_attempted'])
        self.restart();self.boot_failure=False;self.probe_failure=True
        with self.assertRaises(Rejected):self.run_service()
        self.gateway.start.assert_not_called();self.boot.assert_called_once()
        self.restart();self.probe_failure=False;self.run_service();self.boot.assert_called_once()

    def test_failure_stage_distinguishes_launch_bootstrap_and_readiness_without_retry(self):
        diagnostic={};self.lost_launch=True
        with self.assertRaises(TimeoutError):service.run(self.spec,self.pin,self.stop,self.ledger,diagnostic=diagnostic)
        self.assertEqual(diagnostic['stage'],'native-launch');self.boot.assert_not_called()
        self.restart();self.lost_launch=False;self.boot_failure=True
        with self.assertRaises(TimeoutError):service.run(self.spec,self.pin,self.stop,self.ledger,diagnostic=diagnostic)
        self.assertEqual(diagnostic['stage'],'bootstrap');self.boot.assert_called_once()
        self.assertTrue(self.ledger.value['bootstrap_attempted'])
        self.restart();self.boot_failure=False;self.probe_failure=True
        with self.assertRaises(Rejected):service.run(self.spec,self.pin,self.stop,self.ledger,diagnostic=diagnostic)
        self.assertEqual(diagnostic['stage'],'readiness');self.boot.assert_called_once()
        self.assertEqual(sum(c[0]=='run-enclave' for c in self.calls),1)

    def test_listener_failure_does_not_claim_or_repeat_a_private_delivery(self):
        self.listener.side_effect=Rejected('renewal-host-bootstrap-listener-unavailable')
        with self.assertRaises(Rejected):self.run_service()
        self.assertFalse(self.ledger.value['bootstrap_attempted'])
        self.boot.assert_not_called();self.gateway.start.assert_not_called()
        self.restart();self.listener.side_effect=None;self.run_service()
        self.boot.assert_called_once()
        self.assertEqual(sum(c[0]=='run-enclave' for c in self.calls),1)

    def test_lost_launch_reply_recovers_own_enclave_on_next_start_without_second_launch(self):
        self.lost_launch=True
        with self.assertRaises(TimeoutError):self.run_service()
        self.boot.assert_not_called();self.gateway.start.assert_not_called()
        self.restart();self.run_service();self.boot.assert_called_once()
        self.assertEqual(sum(c[0]=='run-enclave' for c in self.calls),1)

    def test_unknown_resource_wrong_pcr_and_debug_enclave_do_not_boot(self):
        self.rows=[{'EnclaveID':'unrecorded'}]
        with self.assertRaises(Rejected):self.run_service()
        self.boot.assert_not_called();self.assertIsNone(self.ledger.value)
        self.rows=[];self.run_service();self.restart();self.boot.reset_mock()
        original=copy.deepcopy(self.rows)
        for field,value in [('EnclaveID',INSTANCE+'-enc999'),('EnclaveName','other'),('Flags','DEBUG_MODE'),
            ('Measurements',{'PCR0':'00'*48})]:
            self.rows=copy.deepcopy(original);self.rows[0][field]=value
            with self.subTest(field=field),self.assertRaises(Rejected):self.run_service()
        self.boot.assert_not_called();self.gateway.start.assert_not_called()

    def test_acknowledged_enclave_crash_restarts_but_unknown_empty_launch_does_not(self):
        self.run_service();self.restart();self.rows=[]
        self.run_service();self.assertEqual(self.boot.call_count,2)
        self.assertEqual(sum(c[0]=='run-enclave' for c in self.calls),2)
        self.restart();self.rows=[]
        value=copy.deepcopy(self.ledger.value);value['enclave_id']=None
        value['bootstrap_attempted']=False;value['boot_acknowledged']=False;self.ledger.save(value)
        with self.assertRaises(Rejected):self.run_service()
        self.assertEqual(sum(c[0]=='run-enclave' for c in self.calls),2)

    def test_host_reboot_with_authoritative_empty_description_starts_new_boot(self):
        self.run_service();self.restart()
        value=copy.deepcopy(self.ledger.value);value['boot_id']='99999999-2222-3333-4444-555555555555';self.ledger.save(value)
        self.rows=[];self.run_service();self.assertEqual(self.boot.call_count,2)
        self.assertEqual(sum(c[0]=='run-enclave' for c in self.calls),2)

    def test_changed_spec_and_second_process_cannot_take_over_lifecycle_ledger(self):
        self.run_service()
        with self.assertRaises(BlockingIOError):service.Ledger(self.directory,self.pin)
        self.ledger.close()
        with self.assertRaises(Rejected):service.Ledger(self.directory,'56'*32)


class DiagnosticTests(unittest.TestCase):
    def test_known_reason_is_fixed_and_unknown_exception_text_never_escapes(self):
        report=service.failure_report(Rejected('renewal-host-readiness-timeout'),'readiness')
        self.assertEqual(report['failure_reason'],'renewal-host-readiness-timeout')
        self.assertEqual(report['failure_stage'],'readiness')
        self.assertFalse(report['automatic_bootstrap_retry'])
        secret='SYNTHETIC-PRIVATE-INPUT-NEVER-PRINT'
        for error in (Rejected(secret),RuntimeError(secret),OSError(secret),ValueError({'secret':secret})):
            result=service.failure_report(error,secret)
            self.assertNotIn(secret,canonical(result).decode())
            self.assertEqual(result['failure_reason'],'unclassified')
            self.assertEqual(result['failure_stage'],'unknown')

    def test_main_reports_configuration_stage_without_printing_file_error(self):
        import contextlib,io,json
        output=io.StringIO()
        with (patch.object(service.argparse.ArgumentParser,'parse_args',return_value=service.argparse.Namespace(
                spec='synthetic-config',spec_sha256='12'*32,state_directory='synthetic-directory')),
              patch.object(service.bootstrap,'read_record',side_effect=FileNotFoundError('SYNTHETIC-PRIVATE-PATH')),
              patch.object(service.ctypes,'CDLL') as libc,patch.object(service.resource,'setrlimit'),
              patch.object(service.signal,'signal'),contextlib.redirect_stdout(output)):
            libc.return_value.prctl.return_value=0
            self.assertEqual(service.main(),1)
        report=json.loads(output.getvalue())
        self.assertEqual(report['failure_stage'],'configuration')
        self.assertEqual(report['failure_class'],'FileNotFoundError')
        self.assertNotIn('SYNTHETIC-PRIVATE',output.getvalue())


class ReadinessTests(unittest.TestCase):
    def test_guest_listener_wait_sends_no_bytes_and_closes_refused_and_ready_connections(self):
        stop=Mock();stop.is_set.return_value=False;stop.wait.return_value=False
        refused=Mock();refused.connect.side_effect=ConnectionRefusedError()
        ready=Mock()
        with patch.object(service.socket,'socket',side_effect=[refused,ready]):
            service.bootstrap_listener(stop)
        for raw in (refused,ready):
            raw.connect.assert_called_once_with((16,9444));raw.close.assert_called_once()
            raw.send.assert_not_called();raw.sendall.assert_not_called()

    def test_guest_listener_wait_cancellation_and_deadline_do_not_start_bootstrap(self):
        stop=Mock();stop.is_set.return_value=True
        with patch.object(service.socket,'socket') as sock,self.assertRaises(Rejected):
            service.bootstrap_listener(stop)
        sock.assert_not_called()
        stop.is_set.return_value=False;stop.wait.return_value=False
        raw=Mock();raw.connect.side_effect=ConnectionRefusedError()
        with patch.object(service.socket,'socket',return_value=raw),\
             patch.object(service.time,'monotonic',side_effect=[0,31]),self.assertRaises(Rejected):
            service.bootstrap_listener(stop)
        raw.close.assert_called_once();raw.sendall.assert_not_called()

    def test_only_read_only_transient_results_wait_and_wrong_identity_never_admits(self):
        approved=approval_fixture();stop=Mock();stop.is_set.return_value=False;stop.wait.return_value=False
        proof={'operational_lease_gate_passed':True,'identity_sha256':digest(approved['identity'])}
        with patch.object(service.admission,'probe',side_effect=[Rejected('renewal-parent-await-operational-state'),proof]) as probe:
            service.readiness(approved,1234,3600,stop)
        self.assertEqual(probe.call_count,2);stop.wait.assert_called_once_with(2)
        for error in (Rejected('renewal-parent-probe-rejected'),Rejected('bad-quote')):
            with patch.object(service.admission,'probe',side_effect=error) as probe,self.assertRaises(Rejected):
                service.readiness(approved,1234,3600,stop)
            probe.assert_called_once()
        with patch.object(service.admission,'probe',return_value={**proof,'identity_sha256':'00'*32}),self.assertRaises(Rejected):
            service.readiness(approved,1234,3600,stop)


if __name__=='__main__':unittest.main()
