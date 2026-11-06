"""Bounded public greeting router; all application TLS stays enclave-to-helper.

Versioned public profile/nonce greetings select fixed ports in ONE enclave. No bootstrap,
TLS termination, private RPC parsing, credentials, files or caller destinations.
Loopback binding is the default; public deployment needs explicit reviewed bind.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import math
import secrets
import signal
import socket
import struct
import threading
import time

from issuer_relays import relay_opaque

ISSUER='nockapp-zkid-composite-aws-enrollment-v1'
VERIFIER='nockapp-zkid-post-aws-enrollment-v1'
BASE='nockapp-base-aws-enrollment-v1'
BUNDLE='nockapp-bundle-aws-enrollment-v3'
AUTHORED_BUNDLE='nockapp-bundle-aws-enrollment-v4'
RENEWAL='nockapp-renewal-aws-enrollment-v3'
HELLO_LIMIT=256
HELLO_SECONDS=5
STREAM_SECONDS=75
STREAM_BYTES=1048576
MAX_CONNECTIONS=16
MAX_PEER_CONNECTIONS=4
MAX_PEERS=1024
PEER_IDLE_SECONDS=300


def _pairs(items):
    result={}
    for key,value in items:
        if key in result:raise ValueError('gateway-hello')
        result[key]=value
    return result


def greeting(raw):
    deadline=time.monotonic()+HELLO_SECONDS
    def exact(count):
        data=bytearray()
        while len(data)<count:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ValueError('gateway-timeout')
            raw.settimeout(remaining);part=raw.recv(count-len(data))
            if not part:raise ValueError('gateway-closed')
            data.extend(part)
        return bytes(data)
    header=exact(4);length=struct.unpack('!I',header)[0]
    if not 0<length<=HELLO_LIMIT:raise ValueError('gateway-hello-size')
    body=exact(length);value=json.loads(body.decode('utf-8'),object_pairs_hook=_pairs)
    if (type(value) is not dict or set(value)!={'profile','nonce'} or type(value['profile']) is not str
            or value['profile'] not in (ISSUER,VERIFIER,BASE,BUNDLE,AUTHORED_BUNDLE,RENEWAL) or type(value['nonce']) is not str
            or len(value['nonce'])!=64 or any(c not in '0123456789abcdef' for c in value['nonce'])):
        raise ValueError('gateway-hello')
    return value['profile'],header+body


class Admission:
    """Atomic global/peer tokens and leases; IP keys are ephemeral RAM HMACs."""
    def __init__(self,*,clock=None):
        self._clock=clock or time.monotonic;self._lock=threading.Lock();self._salt=secrets.token_bytes(32)
        self._tokens=32.0;self._last=self._clock();self._peers={};self._leases={}

    def enter(self,address):
        try:
            ip=ipaddress.ip_address(address)
            if isinstance(ip,ipaddress.IPv6Address):ip=ip.ipv4_mapped or ipaddress.ip_network(str(ip)+'/64',strict=False).network_address
            key=hmac.digest(self._salt,ip.packed,'sha256')
        except ValueError:return None
        with self._lock:
            now=self._clock()
            if not math.isfinite(now) or now<self._last or len(self._leases)>=MAX_CONNECTIONS:return None
            self._tokens=min(32.0,self._tokens+(now-self._last)*8);self._last=now
            for old,value in list(self._peers.items()):
                if value['active']==0 and now-value['seen']>=PEER_IDLE_SECONDS:del self._peers[old]
            row=self._peers.get(key)
            if row is None:
                if len(self._peers)>=MAX_PEERS:return None
                row={'tokens':12.0,'seen':now,'active':0};self._peers[key]=row
            tokens=min(12.0,row['tokens']+(now-row['seen'])*2)
            row['tokens']=tokens;row['seen']=now
            if self._tokens<1 or tokens<1 or row['active']>=MAX_PEER_CONNECTIONS:return None
            self._tokens-=1;row['tokens']-=1;row['active']+=1
            lease=object();self._leases[lease]=key;return lease

    def leave(self,lease):
        with self._lock:
            key=self._leases.pop(lease,None)
            if key is not None:self._peers[key]['active']-=1

    def summary(self):
        with self._lock:return {'active':len(self._leases),'tracked_peers':len(self._peers)}


class PublicGateway:
    def __init__(self,enclave_cid,*,bind='127.0.0.1',port=19449):
        if (type(enclave_cid) is not int or not 4<=enclave_cid<2**32-1
                or type(port) is not int or not 0<=port<=65535):raise ValueError('gateway-config')
        address=ipaddress.ip_address(bind)
        self.family=socket.AF_INET if address.version==4 else socket.AF_INET6
        self.bind=str(address);self.port=port
        self._routes={ISSUER:(enclave_cid,9440),VERIFIER:(enclave_cid,9447),BASE:(enclave_cid,9440),
            BUNDLE:(enclave_cid,9440),AUTHORED_BUNDLE:(enclave_cid,9440),RENEWAL:(enclave_cid,9440)}
        self.admission=Admission();self.stop_event=threading.Event();self._lock=threading.Lock()
        self._streams=set();self._workers=set();self._listener=None;self._acceptor=None

    def _dial(self,profile):
        target=self._routes[profile];raw=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
        with self._lock:
            if self.stop_event.is_set():raw.close();raise ValueError('gateway-stopped')
            self._streams.add(raw)
        try:raw.settimeout(10);raw.connect(target);return raw
        except Exception:
            with self._lock:self._streams.discard(raw)
            raw.close();raise

    def _handle(self,left,lease):
        right=None
        try:
            profile,frame=greeting(left)
            if self.stop_event.is_set():return
            right=self._dial(profile)
            with self._lock:self._streams.add(right)
            right.sendall(frame)
            relay_opaque(left,right,self.stop_event,timeout=STREAM_SECONDS,byte_limit=STREAM_BYTES)
        except Exception:pass  # Never print private bytes, hello nonce, IP or diagnostics.
        finally:
            left.close()
            if right is not None:right.close()
            with self._lock:
                self._streams.discard(left)
                if right is not None:self._streams.discard(right)
                self._workers.discard(threading.current_thread())
            self.admission.leave(lease)

    def admit(self,raw,peer):
        lease=self.admission.enter(peer[0])
        if lease is None or self.stop_event.is_set():
            if lease is not None:self.admission.leave(lease)
            raw.close();return False
        worker=threading.Thread(target=self._handle,args=(raw,lease),daemon=True)
        with self._lock:self._streams.add(raw);self._workers.add(worker)
        try:worker.start()
        except Exception:
            with self._lock:self._streams.discard(raw);self._workers.discard(worker)
            self.admission.leave(lease);raw.close();raise
        return True

    def _accept(self):
        while not self.stop_event.is_set():
            try:raw,peer=self._listener.accept()
            except socket.timeout:continue
            except OSError:return
            try:self.admit(raw,peer)
            except Exception:raw.close()  # Thread-allocation failure already released its lease; keep accepting.

    def start(self):
        if self._listener is not None:raise ValueError('gateway-already-started')
        raw=socket.socket(self.family,socket.SOCK_STREAM);self._listener=raw
        try:
            raw.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            if self.family==socket.AF_INET6:raw.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            raw.bind((self.bind,self.port));raw.listen(MAX_CONNECTIONS);raw.settimeout(.25)
            self._acceptor=threading.Thread(target=self._accept,daemon=True);self._acceptor.start()
            return raw.getsockname()
        except Exception:raw.close();self._listener=None;raise

    def close(self):
        self.stop_event.set()
        if self._listener is not None:self._listener.close()
        with self._lock:streams=list(self._streams);workers=list(self._workers)
        for raw in streams:
            try:raw.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            raw.close()
        deadline=time.monotonic()+12
        for worker in [*workers,*([self._acceptor] if self._acceptor else [])]:
            if worker is not threading.current_thread():worker.join(timeout=max(0,deadline-time.monotonic()))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--cid',required=True,type=int)
    parser.add_argument('--bind',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=19449);args=parser.parse_args();gateway=None
    try:
        gateway=PublicGateway(args.cid,bind=args.bind,port=args.port)
        for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,lambda *_:gateway.stop_event.set())
        print(json.dumps({'profile':'nockapp-zkid-public-gateway-v2','address':gateway.start(),
            'enclave_cid':args.cid,'tls_terminated':False}),flush=True)
        while not gateway.stop_event.wait(.25):pass
        return 0
    except Exception:return 1
    finally:
        if gateway is not None:gateway.close()


if __name__=='__main__':raise SystemExit(main())
