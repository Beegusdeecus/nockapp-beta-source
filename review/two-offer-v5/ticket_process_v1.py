"""Pinned executable role/broker entry point. No installer or key initializer.

The service manager supplies exactly one listening socket as fd 3. Arguments
contain only a public deployment path and its independently approved SHA256.
Check mode does not read sealed keys, open sockets or contact AWS/Base.
"""
import argparse
import copy
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import signal
import socket
import stat
import threading

from authorship import AuthorshipNative
from base_rpc import BaseRPC
from policy import canonical,require,strict_json
from ticket_aws_credentials_v1 import validate as broker_validate,tls_context
from ticket_backend_boot_v1 import validate as backend_validate,harden_process
from ticket_backend_resources_v1 import PROFILE as RESOURCE,build as resources_build,assemble_sealed
from ticket_credential_broker_v1 import build as broker_build
from ticket_native_v1 import TicketNative
from ticket_offer_v1 import configured_offer
from ticket_server_v1 import RoleServer

PROFILE='nockapp-ticket-process-v1'

def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(value):return sha(canonical(value))

def path_parts(value):
    require(type(value) is str and 1<len(value)<=4096 and value.startswith('/')
        and '\x00' not in value,'ticket-process-path')
    parts=value.split('/')[1:]
    require(all(p and p not in ('.','..') and not p.startswith('.env') for p in parts),'ticket-process-path')
    return parts

def open_path(value,*,directory=False):
    # Walk open directories, never follow a symlink (including parent races).
    parts=path_parts(value);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for n,part in enumerate(parts):
            flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
            if n<len(parts)-1 or directory:flags|=os.O_DIRECTORY
            new=os.open(part,flags,dir_fd=fd);os.close(fd);fd=new
        result=fd;fd=None;return result
    finally:
        if fd is not None:os.close(fd)

def read_file(value,limit,*,expected=None,executable=False):
    fd=open_path(value)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and not info.st_mode&0o022
            and 0<info.st_size<=limit and (not executable or info.st_mode&0o111),'ticket-process-file')
        with os.fdopen(fd,'rb') as stream:
            fd=None;raw=stream.read(limit+1)
        require(0<len(raw)<=limit and len(raw)==info.st_size,'ticket-process-file')
        if expected is not None:require(sha(raw)==expected,'ticket-process-file-pin')
        return raw
    finally:
        if fd is not None:os.close(fd)

def scratch(value):
    fd=open_path(value,directory=True)
    try:
        info=os.fstat(fd)
        require(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'ticket-process-scratch')
        try:os.stat('journal.sqlite',dir_fd=fd,follow_symlinks=False)
        except FileNotFoundError:return
        require(False,'ticket-process-scratch-not-fresh')
    finally:os.close(fd)

def preflight(value,expected):
    """All public admission, without encrypted-key/state/network operations."""
    require(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected)
        and type(value) is dict and pin(value)==expected,'ticket-process-pin')
    common={'profile','kind','broker','broker_sha256'}
    require(value.get('profile')==PROFILE and value.get('kind') in ('broker','role'),'ticket-process-config')
    fields=common|({'backend','backend_sha256','resources','resources_sha256','ticket_native','author_native','sealed_boot','scratch','listen'} if value['kind']=='role' else set())
    require(set(value)==fields,'ticket-process-config')
    b=broker_validate(value['broker']);require(pin(b)==value['broker_sha256'],'ticket-process-broker-pin')
    if value['kind']=='broker':
        require(os.getuid()==b['broker_uid'],'ticket-process-user')
    else:
        c=backend_validate(value['backend'],value['backend_sha256']);r=value['resources'];role=c['role'];records=c['records']
        require(b['account_id']==records['account_id'] and b['region']==records['region']
            and os.getuid()==b['roles'][role]['uid'],'ticket-process-user')
        require(type(r) is dict and set(r)=={'profile','backend_sha256','broker_sha256','rpc','kms_key_arn','sealed_boot_sha256'}
            and r['profile']==RESOURCE and r['backend_sha256']==value['backend_sha256']
            and r['broker_sha256']==value['broker_sha256'] and pin(r)==value['resources_sha256'],'ticket-process-resources')
        require(type(r['sealed_boot_sha256']) is str and re.fullmatch('[0-9a-f]{64}',r['sealed_boot_sha256'])
            and int(r['sealed_boot_sha256'],16)>0,'ticket-process-sealed-pin')
        prefix='arn:aws:kms:'+records['region']+':'+records['account_id']+':key/'
        require(type(r['kms_key_arn']) is str and re.fullmatch(re.escape(prefix)+r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',r['kms_key_arn']),'ticket-process-kms')
        rpc=r['rpc'];require(type(rpc) is dict and set(rpc)=={'endpoint','rate','burst','timeout'},'ticket-process-rpc')
        BaseRPC(rpc['endpoint'],rate=rpc['rate'],burst=rpc['burst'],timeout=rpc['timeout'],context=tls_context())
        read_file(value['ticket_native'],128*1024*1024,expected=c['ticket_native_sha256'],executable=True)
        configured_offer(c['offer'],c['offer_sha256'],TicketNative(value['ticket_native'],c['ticket_native_sha256'])).check()
        if role=='publication':
            read_file(value['author_native'],128*1024*1024,expected=c['author_native_sha256'],executable=True)
        else:require(value['author_native'] is None,'ticket-process-role-resources')
        path_parts(value['sealed_boot']) # Deliberately no stat/open in check mode.
        if role=='payment':require(value['scratch'] is None,'ticket-process-role-resources')
        else:scratch(value['scratch'])
        address=value['listen']
        require(type(address) is dict and set(address)=={'ip','port'} and type(address['ip']) is str
            and type(address['port']) is int and 1<=address['port']<=65535,'ticket-process-listen')
        ip=ipaddress.ip_address(address['ip'])
        require(str(ip)==address['ip'] and '%' not in address['ip'] and not ip.is_multicast
            and not (ip.version==6 and ip.ipv4_mapped is not None),'ticket-process-listen')
    return copy.deepcopy(value)

def listener(value,fd=3):
    """Take ownership of a supplied listening fd; never bind a network socket."""
    raw=socket.socket(fileno=fd)
    try:
        raw.set_inheritable(False)
        require(raw.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)==socket.SOCK_STREAM
            and raw.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1,'ticket-process-listener')
        if value['kind']=='broker':
            b=value['broker'];p=Path(b['socket_path'])
            require(raw.family==socket.AF_UNIX and raw.getsockname()==b['socket_path'],'ticket-process-listener')
            parent=open_path(str(p.parent),directory=True)
            try:
                info=os.stat(p.name,dir_fd=parent,follow_symlinks=False);directory=os.fstat(parent)
                require(stat.S_ISSOCK(info.st_mode) and info.st_uid==b['broker_uid'] and info.st_gid==b['group_gid']
                    and stat.S_IMODE(info.st_mode)==0o660 and directory.st_uid==b['broker_uid']
                    and directory.st_gid==b['group_gid'] and stat.S_IMODE(directory.st_mode)==0o750,'ticket-process-socket-permissions')
            finally:os.close(parent)
        else:
            address=value['listen'];ip=ipaddress.ip_address(address['ip'])
            require(raw.family==(socket.AF_INET6 if ip.version==6 else socket.AF_INET)
                and raw.getsockname()[:2]==(address['ip'],address['port'])
                and (raw.family!=socket.AF_INET6 or raw.getsockname()[2:]==(0,0)),'ticket-process-listener')
            if raw.family==socket.AF_INET6:require(raw.getsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY)==1,'ticket-process-dual-stack')
        return raw
    except Exception:raw.close();raise

def run(value,expected,stop,ready=None,*,descriptor=3):
    harden_process()
    require(type(stop) is threading.Event,'ticket-process-stop')
    cfg=preflight(value,expected);raw=listener(cfg,descriptor)
    def report(_):
        if ready is not None:ready({'profile':PROFILE,'deployment_sha256':expected,'kind':cfg['kind'],'phase':'listening'})
    try:
        require(not stop.is_set(),'ticket-process-stopped')
        if cfg['kind']=='broker':
            result=broker_build(cfg['broker'],cfg['broker_sha256']).run(raw,stop,report)
            require(result['drained'],'ticket-process-drain-incomplete')
        else:
            sealed=read_file(cfg['sealed_boot'],100000,expected=cfg['resources']['sealed_boot_sha256'])
            resources=resources_build(cfg['backend'],cfg['backend_sha256'],cfg['broker'],cfg['broker_sha256'],cfg['resources'],cfg['resources_sha256'])
            require(not stop.is_set(),'ticket-process-stopped')
            native=TicketNative(cfg['ticket_native'],cfg['backend']['ticket_native_sha256'])
            author=AuthorshipNative(cfg['author_native']) if cfg['author_native'] is not None else None
            app,context,server=assemble_sealed(cfg['backend'],cfg['backend_sha256'],resources,sealed,
                ticket_native=native,scratch_directory=cfg['scratch'],author_native=author)
            require(not stop.is_set(),'ticket-process-stopped')
            result=RoleServer.from_config(app,context,raw,server,pin(server)).run(stop,report)
            require(result['phase']=='stopped' and result['drained'],'ticket-process-role-failed')
        return {'profile':PROFILE,'deployment_sha256':expected,'kind':cfg['kind'],'phase':'stopped','drained':True}
    finally:raw.close()

def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self,message):raise ValueError('ticket-process-arguments')
    def emit(value):print(canonical(value).decode(),flush=True)
    try:
        harden_process() # Before configuration, SDK construction or key recovery.
        parser=Parser(description=__doc__)
        parser.add_argument('mode',choices=('check','serve'));parser.add_argument('--deployment',required=True)
        parser.add_argument('--sha256',required=True);args=parser.parse_args(argv)
        raw=read_file(args.deployment,1048576,expected=args.sha256)
        value=strict_json(raw,max_bytes=1048576);require(canonical(value)==raw,'ticket-process-canonical')
        if args.mode=='check':
            preflight(value,args.sha256)
            emit({'ok':True,'profile':PROFILE,'deployment_sha256':args.sha256,'kind':value['kind'],'phase':'checked'});return 0
        stop=threading.Event()
        def shutdown(*_):stop.set()
        old={sig:signal.signal(sig,shutdown) for sig in (signal.SIGTERM,signal.SIGINT)}
        try:emit({'ok':True,**run(value,args.sha256,stop,lambda status:emit({'ok':True,**status}))})
        finally:
            for sig,handler in old.items():signal.signal(sig,handler)
        return 0
    except Exception:
        # Exceptions can contain provider payloads, local paths and private keys.
        emit({'ok':False,'profile':PROFILE,'error':'ticket-process-unavailable'});return 1

if __name__=='__main__':raise SystemExit(main())
