"""System-manager readiness and broker-owned Unix socket lifecycle.

Each service creates its own sockets. SO_PEERCRED captures listen credentials;
metadata UID rules also require the socket creator to be the service user.
No keys, installer, permission changes, arbitrary endpoint or credential input.
"""
import argparse
import os
import signal
import socket
import threading

from policy import canonical,require,strict_json
from ticket_credential_broker_v1 import build as broker_build
from ticket_process_v1 import preflight,run as role_run,read_file,harden_process

PROFILE='nockapp-ticket-supervised-v2'

from ticket_supervised_v1 import BrokerSocket,Notifier

class TcpSocket:
    """Unprivileged pinned TCP bind; never accept a root-created activation fd."""
    def __init__(self,value):self.address=value['listen'];self.socket=None
    def __enter__(self):
        a=self.address
        require(os.getuid()>=100 and type(a['port']) is int and 1024<=a['port']<=65535,'ticket-supervised-unprivileged-port')
        ipv6=':' in a['ip'];self.socket=socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET,socket.SOCK_STREAM)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            if ipv6:self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            self.socket.bind((a['ip'],a['port']));self.socket.listen(32)
            require(os.fstat(self.socket.fileno()).st_uid==os.getuid(),'ticket-supervised-socket-owner')
            return self.socket
        except Exception:self.__exit__(None,None,None);raise
    def __exit__(self,*_):
        if self.socket is not None:self.socket.close();self.socket=None
        return False

def run_owned_role(cfg,pin,stop,ready):
    with TcpSocket(cfg) as raw:
        info=os.fstat(raw.fileno());descriptor=os.dup(raw.fileno())
        try:return role_run(cfg,pin,stop,ready,descriptor=descriptor)
        finally:
            # role_run owns its duplicate after listener admission. If admission
            # failed earlier, close it ourselves. Keep the original open while
            # checking identity, so a reused fd cannot accidentally be closed.
            try:
                current=os.fstat(descriptor)
                if (current.st_dev,current.st_ino)==(info.st_dev,info.st_ino):os.close(descriptor)
            except OSError:pass

def serve(value,pin,stop,notifier):
    harden_process();cfg=preflight(value,pin)
    require(type(stop) is threading.Event and isinstance(notifier,Notifier) and not stop.is_set(),'ticket-supervised-start')
    def ready(_):
        require(not stop.is_set(),'ticket-supervised-stopped');notifier.send('ready')
    if cfg['kind']=='broker':
        with BrokerSocket(cfg['broker']) as raw:
            result=broker_build(cfg['broker'],cfg['broker_sha256']).run(raw,stop,ready)
            require(result['drained'],'ticket-supervised-drain-incomplete')
    else:
        result=run_owned_role(cfg,pin,stop,ready)
        require(result['phase']=='stopped' and result['drained'],'ticket-supervised-role-failed')
    return {'profile':PROFILE,'deployment_sha256':pin,'kind':cfg['kind'],'phase':'stopped','drained':True}

def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self,_):raise ValueError('ticket-supervised-arguments')
    notifier=None
    def emit(value):print(canonical(value).decode(),flush=True)
    try:
        harden_process()
        parser=Parser(description=__doc__);parser.add_argument('--deployment',required=True);parser.add_argument('--sha256',required=True)
        args=parser.parse_args(argv);raw=read_file(args.deployment,1048576,expected=args.sha256)
        value=strict_json(raw,max_bytes=1048576);require(canonical(value)==raw,'ticket-supervised-config')
        cfg=preflight(value,args.sha256)
        # Only system-manager IPC coordinates come from the environment.
        notifier=Notifier(os.environ.get('NOTIFY_SOCKET'))
        require(os.environ.get('LISTEN_FDS') in (None,'0'),'ticket-supervised-socket-creator')
        stop=threading.Event()
        def shutdown(*_):
            stop.set()
            try:notifier.send('stopping')
            except Exception:pass
        previous={sig:signal.signal(sig,shutdown) for sig in (signal.SIGTERM,signal.SIGINT)}
        try:emit({'ok':True,**serve(cfg,args.sha256,stop,notifier)})
        finally:
            for sig,handler in previous.items():signal.signal(sig,handler)
        return 0
    except Exception:
        if notifier is not None:
            try:notifier.send('failed')
            except Exception:pass
        emit({'ok':False,'profile':PROFILE,'error':'ticket-supervised-unavailable'});return 1

if __name__=='__main__':raise SystemExit(main())
