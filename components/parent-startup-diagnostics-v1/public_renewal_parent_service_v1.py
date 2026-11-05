"""Serving-only host lifecycle with durable ownership and guarded readiness.

No migration, key creation, sudo fallback, broad stop or bootstrap retry. A
parent restart reopens relays and authenticates its recorded enclave. Shutdown
leaves that enclave running; a deployment replaces it through the owned broker.
"""
import argparse
import copy
import ctypes
import fcntl
import hashlib
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import socket
import stat
import threading
import time

from issuer_relays import RelayHost
from nitro_host_tool import request as host_request,notify_ready,GUEST_EIF
from policy import Rejected,canonical,digest,hex_string,require
from public_gateway import PublicGateway,RENEWAL
import public_renewal_parent_bootstrap_v1 as bootstrap
import public_renewal_parent_probe_v1 as admission

PROFILE='nockapp-renewal-parent-service-v1'
STATE='nockapp-renewal-parent-lifecycle-v1'
BOOT_ID=Path('/proc/sys/kernel/random/boot_id')
INSTANCE=Path('/sys/devices/virtual/dmi/id/board_asset_tag')
RETRYABLE={('renewal-parent-probe-unavailable',),('renewal-parent-await-operational-state',)}
DIAGNOSTIC_STAGES=frozenset(('arguments','configuration','lifecycle-open','inputs','instance-binding',
    'describe-enclaves','ownership','relay-start','native-launch','bootstrap-listener','bootstrap',
    'readiness','gateway-start','notify-ready','supervision'))
DIAGNOSTIC_REASONS=frozenset(('renewal-host-spec','renewal-host-fixed-scope','renewal-host-image-path',
    'renewal-host-image-file','renewal-host-image-pin','renewal-host-plan','renewal-host-service-binding',
    'renewal-host-instance','renewal-host-boot-id','renewal-host-description','renewal-host-unrecorded-enclave',
    'renewal-host-recorded-resource-missing','renewal-host-loopback','renewal-host-cancelled',
    'renewal-host-launch','renewal-host-launch-readback','renewal-host-bootstrap-listener-unavailable',
    'renewal-host-bootstrap','renewal-host-operational-proof','renewal-host-readiness-timeout',
    'renewal-host-relay-exited','renewal-host-enclave-exited','renewal-host-state-binding',
    'renewal-host-state-path','renewal-host-state-mode','renewal-host-lock-mode',
    'renewal-parent-probe-unavailable','renewal-parent-await-operational-state'))


def failure_report(error,stage):
    """Fixed constants only: never serialize exception text or private inputs."""
    reason=error.args[0] if isinstance(error,Rejected) and len(error.args)==1 and type(error.args[0]) is str else None
    category=type(error).__name__
    return {'ok':False,'code':'renewal-host-stopped','automatic_bootstrap_retry':False,
        'failure_stage':stage if type(stage) is str and stage in DIAGNOSTIC_STAGES else 'unknown',
        'failure_reason':reason if reason in DIAGNOSTIC_REASONS else 'unclassified',
        'failure_class':category if category in ('Rejected','ValueError','OSError','TimeoutError',
            'FileNotFoundError','PermissionError','BlockingIOError','ConnectionError') else 'unclassified'}


def inputs(spec,pin):
    require(type(spec) is dict and set(spec)=={'profile','instance_id','eif','eif_sha256',
        'config','boot_approval','packet','plan','plan_sha256','service_approval','service_approval_sha256',
        'bind','port','readiness_seconds'} and spec['profile']==PROFILE and digest(spec)==pin,'renewal-host-spec')
    hex_string(pin,64);hex_string(spec['eif_sha256'],64)
    require(type(spec['instance_id']) is str and re.fullmatch('i-[0-9a-f]{17}',spec['instance_id'])
        and spec['eif']==GUEST_EIF and spec['bind']=='0.0.0.0' and spec['port']==19449
        and type(spec['port']) is int and type(spec['readiness_seconds']) is int
        and 60<=spec['readiness_seconds']<=3600,'renewal-host-fixed-scope')
    image=Path(spec['eif'])
    require(not any(p.is_symlink() for p in (image,*image.parents)),'renewal-host-image-path')
    with image.open('rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),'renewal-host-image-file')
        h=hashlib.file_digest(stream,'sha256').hexdigest()
    require(h==spec['eif_sha256'],'renewal-host-image-pin')
    config=bootstrap.read_record(spec['config']);approved=bootstrap.read_record(spec['boot_approval'])
    packet=bootstrap.read_record(spec['packet'],private=True);plan=bootstrap.read_record(spec['plan'])
    require(plan['phase']=='serving' and plan==bootstrap.plan(config,approved,digest(packet),plan['parent'],'serving')
        and digest(plan)==spec['plan_sha256'] and plan['parent']['instance']==spec['instance_id'],'renewal-host-plan')
    runtime,_=bootstrap.settings(config,'serving');bootstrap.validate_packet(packet,runtime)
    public=admission.transport.validate_approval(bootstrap.read_record(spec['service_approval']))
    require(digest(public)==spec['service_approval_sha256'] and public['identity']==config['service']
        and public['endpoint']['port']==spec['port']
        and all(public[k]==approved[k] for k in ('code_identity','state_authority_sha256','pcrs')),
        'renewal-host-service-binding')
    return {'config':config,'boot_approval':approved,'packet':packet,'plan':plan,'service_approval':public}


class Ledger:
    def __init__(self,directory,pin):
        self.directory=Path(directory);self.fd=None;hex_string(pin,64);self.pin=pin
        require(self.directory.is_absolute() and '..' not in self.directory.parts
            and not any(p.is_symlink() for p in (self.directory,*self.directory.parents)), 'renewal-host-state-path')
        info=self.directory.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077,'renewal-host-state-mode')
        fd=os.open(self.directory/'service.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077,'renewal-host-lock-mode')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.fd=fd
            self.path=self.directory/'service.json';self.value=None
            if self.path.exists() or self.path.is_symlink():
                value=bootstrap.read_record(self.path,private=True)
                require(type(value) is dict and set(value)=={'profile','spec_sha256','boot_id','launch_name',
                    'enclave_id','launch_attempted','bootstrap_attempted','boot_acknowledged','operational','phase'}
                    and value['profile']==STATE and value['spec_sha256']==pin
                    and type(value['boot_id']) is str and re.fullmatch('[0-9a-f-]{36}',value['boot_id'])
                    and type(value['launch_name']) is str and re.fullmatch('nockapp-serving-[0-9a-f]{24}',value['launch_name'])
                    and (value['enclave_id'] is None or type(value['enclave_id']) is str
                        and re.fullmatch('i-[0-9a-f]{17}-enc[0-9a-f]+',value['enclave_id']))
                    and all(type(value[k]) is bool for k in ('launch_attempted','bootstrap_attempted','boot_acknowledged','operational'))
                    and (not value['bootstrap_attempted'] or value['launch_attempted'])
                    and (not value['boot_acknowledged'] or value['bootstrap_attempted'])
                    and value['phase'] in ('launch-intent','launched','bootstrap-intent','boot-acknowledged',
                        'readiness','operational','retained'),'renewal-host-state-binding')
                self.value=value
        except Exception:
            os.close(fd);self.fd=None;raise

    def save(self,value):
        require(value['spec_sha256']==self.pin,'renewal-host-state-binding')
        temporary=self.directory/('state-'+secrets.token_hex(12)+'.tmp')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,self.path)
        fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.value=copy.deepcopy(value)

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


def owned(row,state,spec,approved):
    require(type(row) is dict and row.get('EnclaveName')==state['launch_name']
        and type(row.get('EnclaveID')) is str and re.fullmatch(re.escape(spec['instance_id'])+'-enc[0-9a-f]+',row['EnclaveID'])
        and (state['enclave_id'] is None or row['EnclaveID']==state['enclave_id'])
        and row.get('EnclaveCID')==16 and row.get('State')=='RUNNING' and row.get('Flags')=='NONE'
        and all(row.get('Measurements',{}).get('PCR'+k)==v for k,v in approved['pcrs'].items()),'renewal-host-enclave-binding')


def readiness(approved,port,seconds,stop):
    deadline=time.monotonic()+seconds
    while True:
        require(not stop.is_set(),'renewal-host-cancelled')
        try:
            result=admission.probe(approved,port)
            require(result.get('operational_lease_gate_passed') is True
                and result.get('identity_sha256')==digest(approved['identity']),'renewal-host-operational-proof')
            return result
        except Rejected as error:
            if error.args not in RETRYABLE:raise
            require(time.monotonic()<deadline and not stop.wait(2),'renewal-host-readiness-timeout')


def bootstrap_listener(stop):
    """Wait for the actual guest listener without sending private bytes.

    A ready loopback relay does not imply the freshly launched guest has loaded
    its runtime. Only connection readiness is retried; bootstrap remains once.
    """
    deadline=time.monotonic()+30
    while True:
        require(not stop.is_set(),'renewal-host-cancelled')
        raw=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
        try:
            raw.settimeout(1);raw.connect((16,9444));return
        except OSError:
            require(time.monotonic()<deadline and not stop.wait(.1),'renewal-host-bootstrap-listener-unavailable')
        finally:raw.close()


def run(spec,pin,stop,ledger,*,diagnostic=None):
    def mark(stage):
        if diagnostic is not None:diagnostic['stage']=stage
    mark('inputs')
    records=inputs(spec,pin)
    mark('instance-binding')
    require(INSTANCE.read_text().strip()==spec['instance_id'],'renewal-host-instance')
    boot_id=BOOT_ID.read_text().strip();require(re.fullmatch('[0-9a-f-]{36}',boot_id),'renewal-host-boot-id')
    approved=records['service_approval'];state=copy.deepcopy(ledger.value)
    mark('describe-enclaves');rows=host_request(['describe-enclaves'])
    require(type(rows) is list and len(rows)<=64 and all(type(r) is dict for r in rows),'renewal-host-description')
    mark('ownership');fresh=False
    if state is None or state['boot_id']!=boot_id or rows==[] and (
            state['enclave_id'] is not None or not state['launch_attempted']):
        require(rows==[],'renewal-host-unrecorded-enclave')
        state={'profile':STATE,'spec_sha256':pin,'boot_id':boot_id,'launch_name':'nockapp-serving-'+secrets.token_hex(12),
            'enclave_id':None,'launch_attempted':False,'bootstrap_attempted':False,'boot_acknowledged':False,
            'operational':False,'phase':'launch-intent'}
        ledger.save(state);fresh=True
    else:
        # An unacknowledged launch with no row remains uncertain. A known
        # former ID plus authoritative absence can restart through the broker,
        # which independently reconciles its own durable launch ledger.
        require(len(rows)==1,'renewal-host-recorded-resource-missing')
        owned(rows[0],state,spec,approved)
        state['enclave_id']=rows[0]['EnclaveID'];ledger.save(state)
    host=gateway=None
    try:
        mark('relay-start')
        host=RelayHost(16,records['config']['issuer']['authority']['region'],issuer_port=0,bootstrap_port=0,
            workload_sessions=True,base_rpc=True)
        addresses=host.start()
        require(all(addresses[k][0]=='127.0.0.1' for k in ('issuer','bootstrap')),'renewal-host-loopback')
        require(not stop.is_set(),'renewal-host-cancelled')
        if fresh:
            mark('native-launch')
            state['launch_attempted']=True;ledger.save(state)
            started=host_request(['run-enclave','--cpu-count','2','--memory','2048','--enclave-cid','16',
                '--enclave-name',state['launch_name'],'--eif-path',GUEST_EIF])
            require(type(started) is dict and type(started.get('EnclaveID')) is str,'renewal-host-launch')
            state['enclave_id']=started['EnclaveID'];state['phase']='launched';ledger.save(state)
            observed=host_request(['describe-enclaves'])
            require(type(observed) is list and len(observed)==1,'renewal-host-launch-readback')
            owned(observed[0],state,spec,approved)
        if not state['bootstrap_attempted']:
            mark('bootstrap-listener')
            bootstrap_listener(stop)
            require(not stop.is_set(),'renewal-host-cancelled')
            # Durable intent precedes the private delivery. Once uncertain,
            # only a fresh authenticated read-only probe can recover readiness.
            state['bootstrap_attempted']=True;state['phase']='bootstrap-intent';ledger.save(state)
            mark('bootstrap')
            with socket.create_connection(addresses['bootstrap'],timeout=10) as raw:
                result=bootstrap.execute(raw,records['config'],records['boot_approval'],records['packet'],
                    records['plan'],spec['plan_sha256'],{})
            require(result.get('state')=='startup-acknowledged','renewal-host-bootstrap')
            state['boot_acknowledged']=True;state['phase']='boot-acknowledged';ledger.save(state)
        state['operational']=False;state['phase']='readiness';ledger.save(state)
        mark('readiness')
        readiness(approved,addresses['issuer'][1],spec['readiness_seconds'],stop)
        require(not stop.is_set() and not host.stop_event.is_set(),'renewal-host-cancelled')
        mark('gateway-start')
        gateway=PublicGateway(16,bind=spec['bind'],port=spec['port'])
        gateway._routes={RENEWAL:(16,9440)}
        gateway.start();state['operational']=True;state['phase']='operational';ledger.save(state)
        mark('notify-ready')
        notify_ready('attested-renewal-operational')
        mark('supervision')
        while not stop.wait(15):
            require(not host.stop_event.is_set() and not gateway.stop_event.is_set(),'renewal-host-relay-exited')
            current=host_request(['describe-enclaves'])
            require(type(current) is list and len(current)==1,'renewal-host-enclave-exited')
            owned(current[0],state,spec,approved)
        return {'profile':PROFILE,'stopped':True,'enclave_retained':True,'bootstrap_retried':False}
    finally:
        # Keep the approved enclave running, including uncertain bootstrap. The
        # durable broker alone may perform an explicit owned replacement.
        try:
            if gateway is not None:gateway.close()
        finally:
            try:
                if host is not None:host.close()
            finally:
                state['phase']='retained';state['operational']=False;ledger.save(state)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('spec','spec-sha256','state-directory'):parser.add_argument('--'+key,required=True)
    args=parser.parse_args();ledger=None;stop=threading.Event();diagnostic={'stage':'arguments'}
    try:
        os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        require(ctypes.CDLL(None).prctl(4,0,0,0,0)==0,'renewal-host-private-process')
        for number in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(number,lambda *_:stop.set())
        diagnostic['stage']='configuration';spec=bootstrap.read_record(args.spec)
        diagnostic['stage']='lifecycle-open';ledger=Ledger(args.state_directory,args.spec_sha256)
        result=run(spec,args.spec_sha256,stop,ledger,diagnostic=diagnostic);print(canonical(result).decode());return 0
    except Exception as error:
        print(canonical(failure_report(error,diagnostic['stage'])).decode(),flush=True);return 1
    finally:
        if ledger is not None:ledger.close()


if __name__=='__main__':raise SystemExit(main())
