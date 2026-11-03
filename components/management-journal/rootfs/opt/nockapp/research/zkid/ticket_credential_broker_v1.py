"""UID-bound local temporary credentials. No role ARN chosen over the wire.

Only the future host broker may reach IMDS. Service users must be denied direct
metadata access by independently tested OS policy; this code does not install it.
"""
import copy
import hashlib
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import threading
import time

from policy import canonical,require,Rejected
from ticket_backend_boot_v1 import harden_process
from provisioning import validate_value
from ticket_aws_credentials_v1 import validate,ROLES,temporary,STSRoleSession,MetadataSession,tls_context
from ticket_transport_v2 import receive,send
from workload_sessions import WorkloadSession,WorkloadCredentials

RPC='nockapp-ticket-credential-rpc-v1'
CLIENT='nockapp-ticket-credential-client-v1'
REQUEST_LIMIT=2048;RESPONSE_LIMIT=16384;DEADLINE=90
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()

def client_config(config,role):
    cfg=validate(config);require(role in ROLES,'ticket-credential-role');r=cfg['roles'][role]
    return {'profile':CLIENT,'scope':digest(cfg),'role':role,'role_arn':r['role_arn'],'duration_seconds':r['duration_seconds'],
        'socket_path':cfg['socket_path'],'broker_uid':cfg['broker_uid'],'group_gid':cfg['group_gid']}

class FreshRoleCredentials:
    """Broker cache returns enough lifetime for a NEW service credential cache."""
    def __init__(self,session):
        require(isinstance(session,STSRoleSession),'ticket-credential-source')
        self.session=session;self.role=session.role;self.scope=digest(session.config)
        self._lock=threading.RLock();self._cached=None;self._deadline=0;self._retry_at=0;self._last_utc=0;self._fatal=False
    def get(self):
        with self._lock:
            now=int(time.time());mono=time.monotonic()
            require(not self._fatal and now>=self._last_utc-5,'ticket-credential-clock');self._last_utc=max(self._last_utc,now)
            remaining=min(self._deadline-mono,self._cached['expires_at']-now) if self._cached else 0
            if remaining>700:return copy.deepcopy(self._cached)
            if mono>=self._retry_at:
                try:
                    value=self.session.create_session();after=int(time.time());end=time.monotonic()
                    validate_value('managed-writer-credentials',value)
                    require(after>=now-5 and value['expires_at']>after+600
                        and value['expires_at']<=after+self.session.config['roles'][self.role]['duration_seconds']+5
                        and (self._cached is None or value['expires_at']>self._cached['expires_at']),'ticket-credential-source')
                    self._cached=copy.deepcopy(value);self._deadline=end+value['expires_at']-after
                    self._retry_at=0
                    return copy.deepcopy(value)
                except Exception as error:
                    self._retry_at=time.monotonic()+30
                    if not isinstance(error,Rejected) or error.args!=('workload-session-unavailable',):
                        self._fatal=True;self._cached=None;raise Rejected('ticket-credential-source') from None
            now=int(time.time());mono=time.monotonic()
            if self._cached and min(self._deadline-mono,self._cached['expires_at']-now)>610:return copy.deepcopy(self._cached)
            raise temporary()

class CredentialBroker:
    def __init__(self,config,pin,sources):
        self.config=validate(config);self.scope=digest(self.config)
        require(self.scope==pin and type(sources) is dict and set(sources)==set(ROLES),'ticket-credential-config')
        for role,source in sources.items():
            require(type(source) is FreshRoleCredentials and source.role==role and source.scope==pin,'ticket-credential-source')
        self.sources=dict(sources);self._uids={r['uid']:role for role,r in self.config['roles'].items()}
        self._slots={role:threading.BoundedSemaphore(1) for role in ROLES}
        self._admission={uid:[4.,time.monotonic()] for uid in self._uids}
        self._lock=threading.RLock();self._streams=set();self._threads=set();self._stopping=False;self._started=False

    def serve(self,raw):
        role=None;slot=False
        try:
            require(raw.family==socket.AF_UNIX,'ticket-credential-peer')
            _,uid,_=struct.unpack('3i',raw.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));role=self._uids.get(uid)
            require(role is not None,'ticket-credential-peer')
            slot=self._slots[role].acquire(blocking=False);require(slot,'ticket-credential-busy')
            end=time.monotonic()+DEADLINE;raw.settimeout(5);message=receive(raw,REQUEST_LIMIT,min(end,time.monotonic()+5))
            require(type(message) is dict and set(message)=={'profile','scope','role','request_id'}
                and message['profile']==RPC and message['scope']==self.scope and message['role']==role
                and type(message['request_id']) is str and re.fullmatch('[0-9a-f]{32}',message['request_id']),'ticket-credential-message')
            header={k:message[k] for k in ('profile','scope','role','request_id')}
            try:
                credentials=self.sources[role].get()
                reply={**header,'status':'ok','role_arn':self.config['roles'][role]['role_arn'],'credentials':credentials}
            except Exception:reply={**header,'status':'unavailable'} # No private diagnostic.
            send(raw,reply,RESPONSE_LIMIT,end)
        except Exception:pass
        finally:
            raw.close()
            if slot:self._slots[role].release()
            with self._lock:self._streams.discard(raw);self._threads.discard(threading.current_thread())

    def _admit_uid(self,uid):
        with self._lock:
            role=self._uids.get(uid)
            if role is None:return False
            tokens,last=self._admission[uid];now=time.monotonic();require(now>=last,'ticket-credential-clock')
            tokens=min(4.,tokens+(now-last)*2.)
            own=sum(getattr(t,'credential_role',None)==role for t in self._threads)
            self._admission[uid]=[tokens,now]
            if tokens<1 or own>=1:return False
            self._admission[uid][0]-=1;return True

    def run(self,listener,stop,ready=None):
        require(not self._started and os.getuid()==self.config['broker_uid'] and type(stop) is threading.Event,'ticket-credential-process')
        require(type(listener) is socket.socket and listener.family==socket.AF_UNIX
            and listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1
            and listener.getsockname()==self.config['socket_path'],'ticket-credential-listener')
        harden_process()
        self._started=True;listener.settimeout(.2)
        if ready is not None:ready({'profile':RPC,'scope':self.scope,'phase':'listening'})
        try:
            while not stop.is_set():
                try:raw,_=listener.accept()
                except socket.timeout:continue
                _,uid,_=struct.unpack('3i',raw.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                role=self._uids.get(uid)
                with self._lock:
                    # At most one active request per service UID. No unbounded
                    # executor queue, and one service cannot occupy all slots.
                    if stop.is_set() or not self._admit_uid(uid):raw.close();continue
                    thread=threading.Thread(target=self.serve,args=(raw,),daemon=True);thread.credential_role=role
                    self._streams.add(raw);self._threads.add(thread)
                try:thread.start()
                except Exception:
                    with self._lock:self._streams.discard(raw);self._threads.discard(thread)
                    raw.close();raise
        finally:
            stop.set();listener.close()
            with self._lock:self._stopping=True;streams=list(self._streams);threads=list(self._threads)
            for stream in streams:
                try:stream.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            end=time.monotonic()+5
            for thread in threads:thread.join(max(0,end-time.monotonic()))
        with self._lock:return {'profile':RPC,'scope':self.scope,'drained':not self._threads}

class CredentialSession(WorkloadSession):
    """Existing refresh interface over a UID-authenticated Unix broker, no X509."""
    def __init__(self,config,*,dial=None):
        require(type(config) is dict and set(config)=={'profile','scope','role','role_arn','duration_seconds','socket_path','broker_uid','group_gid'}
            and config['profile']==CLIENT and config['role'] in ROLES
            and type(config['scope']) is str and re.fullmatch('[0-9a-f]{64}',config['scope'])
            and type(config['role_arn']) is str and re.fullmatch(r'arn:aws:iam::[0-9]{12}:role/nockapp-ticket-'+config['role'],config['role_arn'])
            and type(config['duration_seconds']) is int and 900<=config['duration_seconds']<=3600
            and type(config['broker_uid']) is int and 0<=config['broker_uid']<2**31
            and type(config['group_gid']) is int and 100<=config['group_gid']<2**31,'ticket-credential-client')
        path=config['socket_path'];require(type(path) is str and len(path.encode())<=100
            and re.fullmatch(r'/[A-Za-z0-9_./-]+\.sock',path) and '..' not in path.split('/')
            and not any(v.startswith('.env') for v in path.split('/')),'ticket-credential-client')
        self.config=copy.deepcopy(config);self._pin=digest(self.config);self._dial=dial

    def _connect(self):
        p=Path(self.config['socket_path']);require(not any(v.is_symlink() for v in (p,*p.parents)),'ticket-credential-socket')
        info=p.stat();parent=p.parent.stat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid==self.config['broker_uid'] and info.st_gid==self.config['group_gid']
            and stat.S_IMODE(info.st_mode)==0o660 and parent.st_uid==self.config['broker_uid']
            and parent.st_gid==self.config['group_gid'] and not parent.st_mode&0o027,'ticket-credential-socket')
        raw=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);raw.settimeout(5)
        try:raw.connect(str(p));return raw
        except Exception:raw.close();raise

    def create_session(self):
        raw=None
        try:
            require(digest(self.config)==self._pin,'ticket-credential-client-changed')
            raw=self._dial() if self._dial is not None else self._connect()
            require(raw.family==socket.AF_UNIX,'ticket-credential-peer')
            _,uid,_=struct.unpack('3i',raw.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(uid==self.config['broker_uid'],'ticket-credential-peer')
            message={'profile':RPC,'scope':self.config['scope'],'role':self.config['role'],'request_id':secrets.token_hex(16)}
            end=time.monotonic()+DEADLINE;send(raw,message,REQUEST_LIMIT,end);reply=receive(raw,RESPONSE_LIMIT,end)
            require(type(reply) is dict and all(reply.get(k)==v for k,v in message.items()),'ticket-credential-reply')
            if reply.get('status')=='unavailable':
                require(set(reply)==set(message)|{'status'},'ticket-credential-reply');raise temporary()
            require(set(reply)==set(message)|{'status','role_arn','credentials'} and reply['status']=='ok'
                and reply['role_arn']==self.config['role_arn'],'ticket-credential-reply')
            value=validate_value('managed-writer-credentials',reply['credentials']);now=int(time.time())
            require(now+600<value['expires_at']<=now+self.config['duration_seconds']+5,'ticket-credential-expiry')
            return copy.deepcopy(value)
        except Rejected:raise
        except Exception:raise temporary() from None
        finally:
            if raw is not None:raw.close()

def credentials(config,role,*,dial=None):
    return WorkloadCredentials(CredentialSession(client_config(config,role),dial=dial))

def build(config,pin,*,context=None,metadata_dial=None,sts_dial=None):
    """Host broker construction; no credentials acquired until an allowed request."""
    cfg=validate(config);require(digest(cfg)==pin,'ticket-credential-config')
    if context is None:context=tls_context()
    parent=WorkloadCredentials(MetadataSession(cfg,dial=metadata_dial))
    sources={role:FreshRoleCredentials(STSRoleSession(cfg,role,parent,context,dial=sts_dial)) for role in ROLES}
    return CredentialBroker(cfg,pin,sources)
