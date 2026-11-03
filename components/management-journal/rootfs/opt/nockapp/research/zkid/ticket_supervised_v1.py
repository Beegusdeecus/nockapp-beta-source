"""System-manager readiness and broker-owned Unix socket lifecycle.

Public TCP sockets remain inherited. The broker creates and listens on its Unix
socket: SO_PEERCRED reports the credentials captured by listen(), not accept().
No keys, installer, permission changes, arbitrary endpoint or credential input.
"""
import argparse
import errno
import fcntl
import os
from pathlib import Path
import signal
import socket
import stat
import threading

from policy import canonical,require,strict_json
from ticket_credential_broker_v1 import build as broker_build
from ticket_process_v1 import preflight,run as role_run,read_file,open_path,harden_process

PROFILE='nockapp-ticket-supervised-v1'

class Notifier:
    def __init__(self,path):
        require(type(path) is str and 1<len(path.encode())<=100 and '\x00' not in path
            and (path.startswith('/') or path.startswith('@'))
            and not any(p.startswith('.env') or p=='..' for p in path.split('/')),'ticket-supervised-notifier')
        self.address='\x00'+path[1:] if path.startswith('@') else path
    def send(self,state):
        require(state in ('ready','stopping','failed'),'ticket-supervised-notification')
        message={'ready':b'READY=1\nSTATUS=Ticket service listening',
            'stopping':b'STOPPING=1\nSTATUS=Ticket service stopping',
            'failed':b'STATUS=Ticket service unavailable'}[state]
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as raw:
            raw.settimeout(1);require(raw.sendto(message,self.address)==len(message),'ticket-supervised-notification')

class BrokerSocket:
    """Stable parent and lock inode, new broker-owned socket per process boot."""
    def __init__(self,config):
        self.config=config;self.parent=None;self.lock=None;self.socket=None;self.identity=None
        self.path=Path(config['socket_path'])
    def __enter__(self):
        b=self.config
        require(os.getuid()==b['broker_uid'],'ticket-supervised-user')
        try:
            self.parent=open_path(str(self.path.parent),directory=True);info=os.fstat(self.parent)
            require(info.st_uid==b['broker_uid'] and info.st_gid==b['group_gid']
                and stat.S_IMODE(info.st_mode)==0o750,'ticket-supervised-directory')
            self.lock=os.open('broker.lock',os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self.parent)
            info=os.fstat(self.lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==b['broker_uid'] and info.st_gid==b['group_gid']
                and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and info.st_size==0,'ticket-supervised-lock')
            fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            try:old=os.stat(self.path.name,dir_fd=self.parent,follow_symlinks=False)
            except FileNotFoundError:old=None
            if old is not None:
                require(stat.S_ISSOCK(old.st_mode) and old.st_uid==b['broker_uid'] and old.st_gid==b['group_gid']
                    and stat.S_IMODE(old.st_mode)==0o660,'ticket-supervised-existing-socket')
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
                    probe.settimeout(.5)
                    try:probe.connect(str(self.path))
                    except OSError as exc:
                        require(exc.errno in (errno.ECONNREFUSED,errno.ENOENT),'ticket-supervised-existing-socket')
                    else:require(False,'ticket-supervised-live-socket')
                current=os.stat(self.path.name,dir_fd=self.parent,follow_symlinks=False)
                require((current.st_dev,current.st_ino)==(old.st_dev,old.st_ino),'ticket-supervised-socket-race')
                os.unlink(self.path.name,dir_fd=self.parent)
            self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.socket.bind(str(self.path));info=os.stat(self.path.name,dir_fd=self.parent,follow_symlinks=False)
            self.identity=(info.st_dev,info.st_ino)
            require(info.st_uid==b['broker_uid'] and info.st_gid==b['group_gid'],'ticket-supervised-socket-owner')
            os.chmod(self.path.name,0o660,dir_fd=self.parent,follow_symlinks=False)
            self.socket.listen(8);return self.socket
        except Exception:self.__exit__(None,None,None);raise
    def __exit__(self,*_):
        if self.socket is not None:self.socket.close();self.socket=None
        try:
            if self.parent is not None and self.identity is not None:
                try:info=os.stat(self.path.name,dir_fd=self.parent,follow_symlinks=False)
                except FileNotFoundError:pass
                else:
                    if (info.st_dev,info.st_ino)==self.identity and stat.S_ISSOCK(info.st_mode):os.unlink(self.path.name,dir_fd=self.parent)
        finally:
            if self.lock is not None:os.close(self.lock);self.lock=None
            if self.parent is not None:os.close(self.parent);self.parent=None
        return False

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
        result=role_run(cfg,pin,stop,ready)
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
        if cfg['kind']=='role':
            require(os.environ.get('LISTEN_PID')==str(os.getpid()) and os.environ.get('LISTEN_FDS')=='1','ticket-supervised-inherited-socket')
        else:
            require(os.environ.get('LISTEN_FDS') in (None,'0'),'ticket-supervised-broker-socket-creator')
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
