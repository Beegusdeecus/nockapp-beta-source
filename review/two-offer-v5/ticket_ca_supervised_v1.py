"""Executable CA-only broker and pinned-root certificate renewal service.

Public configuration only. No root creation, key import, CSR job endpoint,
ambient credential chain, IAM change, installer or application-state access.
The system manager must enforce the bound metadata guard and separate UIDs.
"""
import argparse
import copy
import os
import signal
import socket
import threading

from policy import canonical,digest,require,strict_json
from ticket_process_v1 import harden_process,read_file
from ticket_supervised_v1 import BrokerSocket,Notifier
import ticket_tls_ca_credentials_v1 as broker
from ticket_host_tls_ca_v1 import HostCA,KmsSigner,checked_policy
from ticket_host_tls_daemon_v1 import CertificateRenewer
from ticket_host_tls_delivery_v1 import PublicCertificates
from ticket_capsule_v1 import BROKER

PROFILE='nockapp-ticket-ca-supervised-v1'
PUBLIC_DIR='/public-certificates'
CA_SOCKET='/run/nockapp-ticket-ca-credentials/broker.sock'


def preflight(value,pin):
    fields={'profile','kind','ca_broker','ca_broker_sha256','metadata_policy','metadata_policy_sha256'}
    extra={'policy','policy_sha256','root_record','root_record_sha256','certificates_directory','interval_seconds'}
    require(type(value) is dict and value.get('kind') in ('broker','renewer')
        and value.get('profile')==PROFILE and digest(value)==pin
        and set(value)==fields|(extra if value['kind']=='renewer' else set()),'ticket-ca-service-config')
    extension,_=broker.validate(value['ca_broker'],value['ca_broker_sha256'])
    require(extension['base']['socket_path']==BROKER and extension['ca_socket_path']==CA_SOCKET,
        'ticket-ca-service-socket-scope')
    metadata=value['metadata_policy']
    require(type(metadata) is dict and digest(metadata)==value['metadata_policy_sha256']
        and metadata==broker.metadata_policy(extension,value['ca_broker_sha256'],metadata.get('nft_sha256')),
        'ticket-ca-service-metadata-binding')
    uid=extension['base']['broker_uid'] if value['kind']=='broker' else extension['ca_uid']
    require(os.getuid()==uid and os.getgid()==extension['base']['group_gid'],'ticket-ca-service-user')
    if value['kind']=='renewer':
        checked_policy(value['policy'],value['policy_sha256'])
        require(type(value['root_record']) is dict and digest(value['root_record'])==value['root_record_sha256']
            and value['root_record'].get('policy_sha256')==value['policy_sha256'],'ticket-ca-service-root-binding')
        require(type(value['interval_seconds']) is int and 30<=value['interval_seconds']<=300,'ticket-ca-service-interval')
        # Path traversal/symlink/ownership admission is completed by the held
        # directory descriptor in prepare(), before any credential acquisition.
        require(value['certificates_directory']==PUBLIC_DIR,'ticket-ca-service-public-directory')
    return copy.deepcopy(value)


class CaNotifier(Notifier):
    def send(self,state):
        messages={'ready':b'READY=1\nSTATUS=Ticket CA service ready',
            'stopping':b'STOPPING=1\nSTATUS=Ticket CA service stopping',
            'failed':b'STATUS=Ticket CA service unavailable'}
        require(state in messages,'ticket-ca-service-notification')
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as raw:
            raw.settimeout(1);require(raw.sendto(messages[state],self.address)==len(messages[state]),'ticket-ca-service-notification')


def prepare(value):
    """Admit the public root/directory before any source.get()/KMS Sign call."""
    extension=value['ca_broker'];directory=PublicCertificates(value['certificates_directory'],extension['ca_uid'])
    try:
        source=broker.credentials(extension,value['ca_broker_sha256'])
        signer=KmsSigner(value['policy']['kms_key_arn'],source,broker.tls_context())
        authority=HostCA(value['policy'],value['policy_sha256'],signer,
            root_record=value['root_record'],root_pin=value['root_record_sha256'])
        renewer=CertificateRenewer(authority,value['policy_sha256'],value['root_record_sha256'],directory,
            interval=value['interval_seconds'])
        return renewer,directory
    except BaseException:
        directory.close();raise


def serve(value,pin,stop,notifier,emit):
    harden_process();value=preflight(value,pin)
    require(type(stop) is threading.Event and isinstance(notifier,Notifier) and callable(emit)
        and not stop.is_set(),'ticket-ca-service-start')
    if value['kind']=='broker':
        extension,transport=broker.validate(value['ca_broker'],value['ca_broker_sha256'])
        with BrokerSocket(transport) as raw:
            result=broker.build(extension,value['ca_broker_sha256']).run(raw,stop,lambda _:notifier.send('ready'))
        require(result['drained'],'ticket-ca-service-undrained')
    else:
        renewer,directory=prepare(value);ready=False
        try:
            def cycle(status):
                nonlocal ready
                # IPC readiness is distinct from renewal readiness. Announce
                # renewal only after all three fixed leaves validate/publish.
                if status.get('ok') is True and not ready and not stop.is_set():
                    notifier.send('ready');ready=True
                emit(status)
            renewer.run(stop,cycle)
        finally:directory.close()
    return {'profile':PROFILE,'deployment_sha256':pin,'kind':value['kind'],'phase':'stopped',
        'root_replaced':False,'service_keys_created':False,'credentials_saved':False}


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self,_):raise ValueError('ticket-ca-service-arguments')
    notifier=None
    def emit(value):print(canonical(value).decode(),flush=True)
    try:
        harden_process()
        parser=Parser(description=__doc__);parser.add_argument('operation',choices=('check','run'))
        parser.add_argument('--deployment',required=True);parser.add_argument('--sha256',required=True);args=parser.parse_args(argv)
        raw=read_file(args.deployment,65536,expected=args.sha256);value=strict_json(raw,max_bytes=65536)
        require(canonical(value)==raw,'ticket-ca-service-canonical');value=preflight(value,args.sha256)
        require(os.environ.get('LISTEN_FDS') in (None,'0'),'ticket-ca-service-owned-socket')
        if args.operation=='check':
            if value['kind']=='renewer':
                _,directory=prepare(value);directory.close()
            emit({'ok':True,'profile':PROFILE,'kind':value['kind'],'deployment_sha256':args.sha256,
                'public_admission_only':True,'credentials_acquired':False,'root_created':False});return 0
        notifier=CaNotifier(os.environ.get('NOTIFY_SOCKET'));stop=threading.Event()
        def shutdown(*_):
            stop.set()
            try:notifier.send('stopping')
            except Exception:pass
        previous={number:signal.signal(number,shutdown) for number in (signal.SIGTERM,signal.SIGINT)}
        try:emit({'ok':True,**serve(value,args.sha256,stop,notifier,emit)})
        finally:
            for number,handler in previous.items():signal.signal(number,handler)
        return 0
    except Exception:
        if notifier is not None:
            try:notifier.send('failed')
            except Exception:pass
        emit({'ok':False,'profile':PROFILE,'code':'ticket-ca-service-unavailable'});return 1


if __name__=='__main__':raise SystemExit(main())
