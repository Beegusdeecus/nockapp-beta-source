"""Untrusted parent byte relays. Standard library only; no TLS termination.

Run explicitly on the existing enclave parent. Egress targets and vsock ports
are fixed; ingress binds only IPv4 loopback for an SSH-forwarded desktop/helper.
Never reads config/credential files, parses payloads, logs bytes or retries.
"""
import argparse
import json
import re
import selectors
import signal
import socket
import threading
import time

PORTS={'issuer':9440,'kms':9441,'dynamodb':9442,'provider':9443,'bootstrap':9444}
CHUNK=32768
MAX_BUFFER=131072
MAX_SESSIONS=8


def public_s3_targets(rows):
    # Keep the parent CLI self-contained under python -I -S. Match the measured
    # public_s3_endpoints rules; TLS identity and content checks remain enclave-owned.
    if type(rows) is not list or not 2<=len(rows)<=4:raise ValueError('relay-public-s3')
    result={};names=set();regions=set()
    for i,row in enumerate(rows):
        if type(row) is not dict or set(row)!={'name','region','bucket'}:raise ValueError('relay-public-s3')
        name,region,bucket=(row[k] for k in ('name','region','bucket'))
        if (type(name) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9-]{2,63}',name)
            or type(region) is not str or not re.fullmatch(r'[a-z]{2}-[a-z]+-[1-9]',region)
            or type(bucket) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]',bucket)
            or bucket.startswith(('xn--','sthree-','amzn-s3-demo-'))
            or bucket.endswith(('-s3alias','--ol-s3','--x-s3','--table-s3'))
            or name in names or region in regions):raise ValueError('relay-public-s3')
        names.add(name);regions.add(region)
        result['public_s3_'+str(i)]=(bucket+'.s3.'+region+'.amazonaws.com',443)
    return result


def relay_opaque(left,right,stop=None,*,timeout=180,byte_limit=None):
    """Bounded buffers/deadline and directional EOF over raw sockets only."""
    sockets=(left,right);buffers=[bytearray(),bytearray()];eof=[False,False];closed=[False,False]
    if byte_limit is not None and (type(byte_limit) is not int or byte_limit<=0):raise ValueError('relay-byte-limit')
    received=[0,0]
    deadline=time.monotonic()+timeout
    for stream in sockets:stream.setblocking(False)
    with selectors.DefaultSelector() as selector:
        while stop is None or not stop.is_set():
            if time.monotonic()>=deadline:raise TimeoutError('relay-deadline')
            for i,stream in enumerate(sockets):
                if eof[1-i] and not buffers[i] and not closed[i]:
                    stream.shutdown(socket.SHUT_WR);closed[i]=True
            if all(eof) and not any(buffers):return
            for key in list(selector.get_map().values()):selector.unregister(key.fileobj)
            for i,stream in enumerate(sockets):
                events=selectors.EVENT_READ if not eof[i] and len(buffers[1-i])<MAX_BUFFER else 0
                if buffers[i]:events|=selectors.EVENT_WRITE
                if events:selector.register(stream,events,i)
            for key,mask in selector.select(min(0.25,max(0,deadline-time.monotonic()))):
                i=key.data;stream=key.fileobj
                if mask & selectors.EVENT_WRITE and buffers[i]:
                    try:
                        size=stream.send(buffers[i])
                        if size==0:raise ConnectionError('relay-closed')
                        del buffers[i][:size]
                    except BlockingIOError:pass
                if mask & selectors.EVENT_READ and not eof[i]:
                    try:data=stream.recv(min(CHUNK,MAX_BUFFER-len(buffers[1-i])))
                    except BlockingIOError:continue
                    if data:
                        received[i]+=len(data)
                        if byte_limit is not None and received[i]>byte_limit:raise ValueError('relay-byte-limit')
                        buffers[1-i].extend(data)
                    else:eof[i]=True


def fixed_targets(region,*,workload_sessions=False,base_rpc=False,public_s3=None):
    if type(region) is not str or not re.fullmatch(r'[a-z]{2}-[a-z]+-[1-9]',region):
        raise ValueError('relay-region')
    if type(workload_sessions) is not bool or type(base_rpc) is not bool:raise ValueError('relay-workload-sessions')
    targets={'kms':('kms.'+region+'.amazonaws.com',443),
            'dynamodb':('dynamodb.'+region+'.amazonaws.com',443),'provider':('api.twitterapi.io',443),
            **({'rolesanywhere':('rolesanywhere.'+region+'.amazonaws.com',443)} if workload_sessions else {}),
            **({'base_rpc':('sepolia.base.org',443)} if base_rpc else {})}
    if public_s3 is not None:
        if not base_rpc:raise ValueError('relay-public-s3-base-required')
        targets.update(public_s3_targets(public_s3))
    return targets


class RelayHost:
    def __init__(self,cid,region,*,issuer_port=19440,bootstrap_port=19444,workload_sessions=False,
                 verifier_cid=None,verifier_port=19447,verifier_bootstrap_port=19448,base_rpc=False,public_s3=None):
        if type(cid) is not int or not 4<=cid<2**32-1:raise ValueError('relay-cid')
        if any(type(p) is not int or not 0<=p<=65535 for p in (issuer_port,bootstrap_port,verifier_port,verifier_bootstrap_port)):
            raise ValueError('relay-loopback-port')
        if verifier_cid is not None and (type(verifier_cid) is not int or not 4<=verifier_cid<2**32-1
                                        or verifier_cid==cid or workload_sessions is not True):
            raise ValueError('relay-verifier-cid')
        self.verifier_cid=verifier_cid
        if base_rpc and verifier_cid is not None:raise ValueError('relay-single-base-enclave')
        self.cid=cid;self.targets=fixed_targets(region,workload_sessions=workload_sessions,base_rpc=base_rpc,public_s3=public_s3)
        self.ports={**PORTS,**({'rolesanywhere':9445} if workload_sessions else {}),**({'base_rpc':9450} if base_rpc else {})}
        if public_s3 is not None:self.ports.update({'public_s3_'+str(i):9451+i for i in range(len(public_s3))})
        self.ingress={'issuer':issuer_port,'bootstrap':bootstrap_port}
        if verifier_cid is not None:
            self.targets['issuer_enrollment']=None  # Fixed vsock destination below, never TCP/URL selection.
            self.ports.update(issuer_enrollment=9446,verifier=9447,verifier_bootstrap=9448)
            self.ingress.update(verifier=verifier_port,verifier_bootstrap=verifier_bootstrap_port)
        self.stop_event=threading.Event();self._slots=threading.BoundedSemaphore(MAX_SESSIONS)
        self._lock=threading.Lock();self._streams=set();self._workers=set();self._listeners=[];self._acceptors=[]

    def destination(self,service):
        if service=='issuer_enrollment' and self.verifier_cid is not None:
            stream=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
            try:stream.settimeout(10);stream.connect((self.cid,PORTS['issuer']));return stream
            except Exception:stream.close();raise
        if service in self.targets:return socket.create_connection(self.targets[service],timeout=10)
        if service not in self.ingress:raise ValueError('relay-service')
        stream=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
        try:
            target=self.verifier_cid if service in ('verifier','verifier_bootstrap') else self.cid
            stream.settimeout(10);stream.connect((target,self.ports[service]));return stream
        except Exception:stream.close();raise

    def _handle(self,left,service):
        right=None
        try:
            right=self.destination(service)
            with self._lock:self._streams.add(right)
            relay_opaque(left,right,self.stop_event)
        except (OSError,ValueError):pass
        finally:
            with self._lock:
                self._streams.discard(left)
                if right is not None:self._streams.discard(right)
                self._workers.discard(threading.current_thread())
            left.close()
            if right is not None:right.close()
            self._slots.release()

    def admit(self,left,service,peer):
        if service=='issuer_enrollment':expected={self.verifier_cid} if self.verifier_cid is not None else set()
        elif service in self.targets:
            expected={self.cid}
            if self.verifier_cid is not None and service in ('kms','dynamodb','rolesanywhere'):expected.add(self.verifier_cid)
        else:expected={'127.0.0.1'} if service in self.ingress else set()
        if peer[0] not in expected or self.stop_event.is_set() or not self._slots.acquire(blocking=False):
            left.close();return False
        worker=threading.Thread(target=self._handle,args=(left,service),daemon=True)
        with self._lock:self._streams.add(left);self._workers.add(worker)
        try:worker.start()
        except Exception:
            with self._lock:self._streams.discard(left);self._workers.discard(worker)
            self._slots.release();left.close();raise
        return True

    def _accept(self,listener,service):
        while not self.stop_event.is_set():
            try:left,peer=listener.accept()
            except socket.timeout:continue
            except OSError:return
            self.admit(left,service,peer)

    def start(self):
        if self._listeners:raise ValueError('relay-already-started')
        addresses={}
        try:
            for service in (*self.targets,*self.ingress):
                family=socket.AF_VSOCK if service in self.targets else socket.AF_INET
                listener=socket.socket(family,socket.SOCK_STREAM);self._listeners.append(listener)
                if family==socket.AF_INET:
                    listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                    listener.bind(('127.0.0.1',self.ingress[service]))
                else:listener.bind((socket.VMADDR_CID_ANY,self.ports[service]))
                listener.listen(4);listener.settimeout(0.5);addresses[service]=listener.getsockname()
                thread=threading.Thread(target=self._accept,args=(listener,service),daemon=True)
                self._acceptors.append(thread)
            for thread in self._acceptors:thread.start()
            return addresses
        except Exception:self.close();raise ValueError('relay-start-failed') from None

    def close(self):
        self.stop_event.set()
        for stream in self._listeners:stream.close()
        with self._lock:streams=list(self._streams);workers=list(self._workers)
        for stream in streams:
            try:stream.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        for worker in [*workers,*self._acceptors]:
            if worker.ident is not None and worker is not threading.current_thread():worker.join(timeout=11)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cid',required=True,type=int);parser.add_argument('--region',default='ap-southeast-2')
    parser.add_argument('--issuer-port',type=int,default=19440);parser.add_argument('--bootstrap-port',type=int,default=19444)
    parser.add_argument('--workload-sessions',action='store_true',help='Add only fixed regional Roles Anywhere TLS byte egress')
    parser.add_argument('--base-rpc',action='store_true',help='One-enclave Base service: fixed sepolia.base.org TLS byte egress')
    parser.add_argument('--public-s3',nargs=3,action='append',metavar=('NAME','REGION','BUCKET'),
        help='Image-approved public replica; repeat for 2..4 distinct AWS Regions, ordered as runtime config')
    parser.add_argument('--verifier-cid',type=int,help='Separate measured verifier; shares only KMS/DynamoDB/session egress')
    parser.add_argument('--verifier-port',type=int,default=19447);parser.add_argument('--verifier-bootstrap-port',type=int,default=19448)
    args=parser.parse_args();host=None
    try:
        host=RelayHost(args.cid,args.region,issuer_port=args.issuer_port,bootstrap_port=args.bootstrap_port,workload_sessions=args.workload_sessions,
            verifier_cid=args.verifier_cid,verifier_port=args.verifier_port,verifier_bootstrap_port=args.verifier_bootstrap_port,
            base_rpc=args.base_rpc,public_s3=None if args.public_s3 is None else
                [dict(zip(('name','region','bucket'),row)) for row in args.public_s3])
        for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,lambda *_:host.stop_event.set())
        print(json.dumps({'profile':'nockapp-zkid-parent-byte-relays-v1','addresses':host.start(),
                          'tls_terminated':False,'public_tcp_listener':False}),flush=True)
        while not host.stop_event.wait(0.5):pass
        return 0
    except Exception:return 1
    finally:
        if host is not None:host.close()


if __name__=='__main__':raise SystemExit(main())
