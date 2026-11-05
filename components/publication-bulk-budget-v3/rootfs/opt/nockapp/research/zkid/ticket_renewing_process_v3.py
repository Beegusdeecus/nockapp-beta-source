"""Explicit publication-only profile for a pinned cumulative-cap migration.

Existing backend/sealed-key/journal authorities are unchanged. Legacy executable
profiles remain static; only this pinned profile adopts the renewing boot/server.
No CA credentials, initializer, private-key file, permission change or installer.
"""
import argparse
import copy
import os
import signal
import threading

from policy import canonical,digest,require,strict_json
import ticket_process_v1 as legacy
from ticket_supervised_v1 import Notifier
from ticket_supervised_v2 import TcpSocket
import ticket_tls_ca_credentials_v1 as ca
from ticket_ca_supervised_v1 import PUBLIC_DIR,CA_SOCKET
from ticket_host_tls_delivery_v1 import PublicCertificates
from ticket_backend_tls_boot_v2 import assemble_sealed
from ticket_server_v2 import RenewingRoleServer

PROFILE='nockapp-ticket-renewing-budget-process-v3'
DELIVERY='nockapp-ticket-role-certificate-delivery-v2'
FIELDS={'profile','kind','broker','broker_sha256','backend','backend_sha256','resources','resources_sha256',
    'ticket_native','author_native','sealed_boot','scratch','listen','certificate_delivery',
    'publication_budget_upgrade','publication_budget_upgrade_sha256'}


def preflight(value,pin):
    require(type(value) is dict and set(value)==FIELDS and digest(value)==pin
        and value['profile']==PROFILE and value['kind']=='role','ticket-renewing-process-config')
    from ticket_budget_upgrade_v1 import validate as validate_budget
    validate_budget(value['publication_budget_upgrade'],value['publication_budget_upgrade_sha256'],value['backend'])
    delivery=value['certificate_delivery']
    require(type(delivery) is dict and set(delivery)=={'profile','directory','ca_broker','ca_broker_sha256',
        'metadata_policy','metadata_policy_sha256'} and delivery['profile']==DELIVERY
        and delivery['directory']==PUBLIC_DIR,'ticket-renewing-process-delivery')
    extension,_=ca.validate(delivery['ca_broker'],delivery['ca_broker_sha256'])
    require(extension['base']==value['broker'] and digest(extension['base'])==value['broker_sha256']
        and extension['ca_socket_path']==CA_SOCKET,'ticket-renewing-process-broker-binding')
    metadata=delivery['metadata_policy']
    require(type(metadata) is dict and digest(metadata)==delivery['metadata_policy_sha256']
        and metadata==ca.metadata_policy(extension,delivery['ca_broker_sha256'],metadata.get('nft_sha256')),
        'ticket-renewing-process-metadata-binding')
    require(os.getgid()==value['broker']['group_gid'],'ticket-renewing-process-group')
    # Reuse unchanged public/base admission under its own explicit schema. Only
    # the new outer profile chooses renewing TLS; no old packet/config is altered.
    inner={k:copy.deepcopy(v) for k,v in value.items() if k not in ('certificate_delivery','publication_budget_upgrade','publication_budget_upgrade_sha256')}
    inner['profile']=legacy.PROFILE;legacy.preflight(inner,digest(inner))
    require(1024<=value['listen']['port']<=65535,'ticket-renewing-process-unprivileged-port')
    # Directory ownership is checked before key recovery. No leaf/private packet
    # or credential provider is needed for public installation admission.
    directory=PublicCertificates(PUBLIC_DIR,extension['ca_uid']);directory.close()
    return copy.deepcopy(value)


def serve(value,pin,stop,notifier):
    legacy.harden_process();cfg=preflight(value,pin)
    require(type(stop) is threading.Event and isinstance(notifier,Notifier) and not stop.is_set(),
        'ticket-renewing-process-start')
    directory=PublicCertificates(PUBLIC_DIR,cfg['certificate_delivery']['ca_broker']['ca_uid'])
    try:
        with TcpSocket(cfg) as raw:
            sealed=legacy.read_file(cfg['sealed_boot'],100000,expected=cfg['resources']['sealed_boot_sha256'])
            resources=legacy.resources_build(cfg['backend'],cfg['backend_sha256'],cfg['broker'],cfg['broker_sha256'],
                cfg['resources'],cfg['resources_sha256'])
            require(not stop.is_set(),'ticket-renewing-process-stopped')
            native=legacy.TicketNative(cfg['ticket_native'],cfg['backend']['ticket_native_sha256'])
            author=legacy.AuthorshipNative(cfg['author_native']) if cfg['author_native'] is not None else None
            app,context,server,poller=assemble_sealed(cfg['backend'],cfg['backend_sha256'],resources,sealed,directory,
                ticket_native=native,scratch_directory=cfg['scratch'],author_native=author,
                publication_budget_upgrade={'plan':cfg['publication_budget_upgrade'],'sha256':cfg['publication_budget_upgrade_sha256']})
            require(not stop.is_set(),'ticket-renewing-process-stopped')
            worker=RenewingRoleServer.from_config(app,context,raw,server,digest(server),poller=poller)
            def ready(_):
                require(not stop.is_set(),'ticket-renewing-process-stopped');notifier.send('ready')
            result=worker.run(stop,ready)
            require(result['phase']=='stopped' and result['drained'],'ticket-renewing-process-undrained')
        return {'profile':PROFILE,'deployment_sha256':pin,'phase':'stopped','drained':True,
            'renewing_tls_profile':True,'CA_credentials_used':False,'service_keys_created':False}
    finally:directory.close()


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self,_):raise ValueError('ticket-renewing-process-arguments')
    notifier=None
    def emit(value):print(canonical(value).decode(),flush=True)
    try:
        legacy.harden_process()
        parser=Parser(description=__doc__);parser.add_argument('operation',choices=('check','run'))
        parser.add_argument('--deployment',required=True);parser.add_argument('--sha256',required=True);args=parser.parse_args(argv)
        raw=legacy.read_file(args.deployment,1048576,expected=args.sha256)
        value=strict_json(raw,max_bytes=1048576);require(canonical(value)==raw,'ticket-renewing-process-canonical')
        value=preflight(value,args.sha256)
        require(os.environ.get('LISTEN_FDS') in (None,'0'),'ticket-renewing-process-owned-socket')
        if args.operation=='check':
            emit({'ok':True,'profile':PROFILE,'deployment_sha256':args.sha256,'phase':'checked',
                'private_packet_read':False,'credentials_acquired':False});return 0
        notifier=Notifier(os.environ.get('NOTIFY_SOCKET'));stop=threading.Event()
        def shutdown(*_):
            stop.set()
            try:notifier.send('stopping')
            except Exception:pass
        previous={number:signal.signal(number,shutdown) for number in (signal.SIGTERM,signal.SIGINT)}
        try:emit({'ok':True,**serve(value,args.sha256,stop,notifier)})
        finally:
            for number,handler in previous.items():signal.signal(number,handler)
        return 0
    except Exception:
        if notifier is not None:
            try:notifier.send('failed')
            except Exception:pass
        emit({'ok':False,'profile':PROFILE,'code':'ticket-renewing-process-unavailable'});return 1


if __name__=='__main__':raise SystemExit(main())
