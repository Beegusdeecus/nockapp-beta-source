"""Bounded lifecycle for ONE payment/publication/refund application.

The launcher supplies the listening socket and recovered TLS/application keys.
No key creation, credential discovery, queue reset, AWS permission changes or
payload/client/error logging. This module does not establish OS key isolation.
"""
from dataclasses import dataclass
import hashlib
import ipaddress
import re
import socket
import ssl
import threading
import time

from policy import canonical,require
from ticket_service_v2 import PaymentApplication,PublicationApplication,validate_request,MAX_REQUEST,MAX_RESPONSE
from ticket_refund_service_v1 import RefundApplication
from ticket_refund_rpc_v1 import MAX_REQUEST as REFUND_REQUEST,MAX_RESPONSE as REFUND_RESPONSE
from ticket_transport_v2 import receive,send,DEADLINE

PROFILE='nockapp-ticket-role-server-v1'
APPLICATIONS={'payment':PaymentApplication,'publication':PublicationApplication,'refund':RefundApplication}

@dataclass(frozen=True)
class ServerLimits:
    max_connections:int
    requests_per_second:int
    burst:int
    recovery_interval:int
    recovery_limit:int
    shutdown_seconds:int

    def validate(self):
        for name,low,high in [('max_connections',1,16),('requests_per_second',1,32),('burst',1,64),
            ('recovery_interval',1,300),('recovery_limit',1,8),('shutdown_seconds',1,60)]:
            value=getattr(self,name);require(type(value) is int and low<=value<=high,'ticket-server-limits')


class RoleServer:
    @classmethod
    def from_config(cls,application,context,listener,value,pin):
        require(type(value) is dict and set(value)=={'profile','service','offer_sha256','limits'}
            and value['profile']==PROFILE and value['service']==application.service
            and value['offer_sha256']==application.offer.hash and type(pin) is str
            and re.fullmatch('[0-9a-f]{64}',pin) and hashlib.sha256(canonical(value)).hexdigest()==pin,'ticket-server-config')
        require(type(value['limits']) is dict and set(value['limits'])==set(ServerLimits.__dataclass_fields__),'ticket-server-limits')
        return cls(application,context,listener,ServerLimits(**value['limits']))

    def __init__(self,application,context,listener,limits):
        require(type(limits) is ServerLimits,'ticket-server-limits');limits.validate()
        role=getattr(application,'service',None)
        require(role in APPLICATIONS and type(application) is APPLICATIONS[role],'ticket-server-role')
        require(isinstance(context,ssl.SSLContext) and context.minimum_version>=ssl.TLSVersion.TLSv1_3
            and context.verify_mode==ssl.CERT_NONE and context.num_tickets==0,'ticket-server-tls')
        require(type(listener) is socket.socket and listener.family in (socket.AF_INET,socket.AF_INET6)
            and listener.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)==socket.SOCK_STREAM
            and listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1,'ticket-server-listener')
        ipaddress.ip_address(listener.getsockname()[0])
        self.application,self.context,self.listener,self.limits=application,context,listener,limits
        self.role,self.offer_hash=role,application.offer.hash
        self._lock=threading.RLock();self._streams=set();self._threads=set();self._maintenance=None
        self._slots=threading.BoundedSemaphore(limits.max_connections)
        self._tokens=float(limits.burst);self._last=time.monotonic();self._started=False;self._stopping=False
        self._phase='created';self._accepted=0;self._dropped=0;self._recovery_runs=0;self._recovery_errors=0

    def snapshot(self):
        with self._lock:
            return {'profile':PROFILE,'service':self.role,'offer_sha256':self.offer_hash,'phase':self._phase,
                'accepted':self._accepted,'dropped':self._dropped,'active':len(self._threads),
                'recovery_runs':self._recovery_runs,'recovery_errors':self._recovery_errors,
                'drained':not self._threads and (self._maintenance is None or not self._maintenance.is_alive())}

    def _recover(self):
        if self.role=='payment':return
        # Only previously admitted durable operations; no public caller can
        # select new recovery destinations, gas intents or reset a journal.
        rows=self.application.worker.recover_pending(self.limits.recovery_limit)
        require(type(rows) is list and len(rows)<=self.limits.recovery_limit,'ticket-server-recovery')
        with self._lock:
            self._recovery_runs+=1
            self._recovery_errors+=sum(type(r) is dict and r.get('state')=='recovery-unavailable' for r in rows)

    def _maintain(self,stop):
        try:
            while not stop.wait(self.limits.recovery_interval):self._recover()
        except Exception:
            with self._lock:self._phase='failed';self._recovery_errors+=1
            stop.set() # An unexpected lifecycle error cannot become readiness.

    def _admit(self):
        now=time.monotonic()
        with self._lock:
            require(now>=self._last,'ticket-server-clock')
            self._tokens=min(self.limits.burst,self._tokens+(now-self._last)*self.limits.requests_per_second);self._last=now
            if self._stopping or self._tokens<1 or not self._slots.acquire(blocking=False):
                self._dropped+=1;return False
            self._tokens-=1;self._accepted+=1;return True

    def _serve(self,raw):
        secure=None;deadline=time.monotonic()+DEADLINE
        try:
            with self._lock:
                require(not self._stopping,'ticket-server-stopped')
                raw.settimeout(DEADLINE)
                secure=self.context.wrap_socket(raw,server_side=True,do_handshake_on_connect=False)
                self._streams.discard(raw);self._streams.add(secure)
            # Track the SSL stream BEFORE handshake, so stop can close even
            # peers that send nothing or stall during TLS negotiation.
            secure.do_handshake();require(secure.version()=='TLSv1.3','ticket-server-tls')
            require(self.application.service==self.role and type(self.application) is APPLICATIONS[self.role]
                and self.application.offer.hash==self.offer_hash,'ticket-server-role-changed')
            refund=self.role=='refund'
            message=receive(secure,REFUND_REQUEST if refund else MAX_REQUEST,deadline)
            if refund:self.application.validate(message,self.offer_hash,self.role)
            else:validate_request(message,self.offer_hash,self.role)
            send(secure,self.application.dispatch(message),REFUND_RESPONSE if refund else MAX_RESPONSE,deadline)
        except Exception:pass # Deliberately no client, request or error logging.
        finally:
            if secure is not None:secure.close()
            raw.close()
            with self._lock:
                self._streams.discard(raw);self._streams.discard(secure);self._threads.discard(threading.current_thread())
            self._slots.release()

    def run(self,stop,ready=None):
        require(type(stop) is threading.Event and (ready is None or callable(ready)),'ticket-server-stop')
        with self._lock:
            require(not self._started,'ticket-server-already-started');self._started=True;self._phase='starting'
        try:
            require(not stop.is_set(),'ticket-server-stopped')
            self.application.offer.check()
            self._recover() # Recovery failure cannot be hidden behind readiness.
            require(not stop.is_set(),'ticket-server-stopped')
            self._maintenance=threading.Thread(target=self._maintain,args=(stop,),daemon=True)
            self._maintenance.start()
            with self._lock:self._phase='listening'
            if ready is not None:ready(self.snapshot())
            self.listener.settimeout(.2)
            while not stop.is_set():
                try:raw,_=self.listener.accept()
                except socket.timeout:continue
                if stop.is_set():raw.close();break
                if not self._admit():raw.close();continue
                thread=threading.Thread(target=self._serve,args=(raw,),daemon=True)
                with self._lock:self._streams.add(raw);self._threads.add(thread)
                try:thread.start()
                except Exception:
                    with self._lock:self._streams.discard(raw);self._threads.discard(thread)
                    raw.close();self._slots.release();raise
        except Exception:
            with self._lock:self._phase='failed'
        finally:
            stop.set()
            with self._lock:
                self._stopping=True
                if self._phase!='failed':self._phase='stopping'
                streams=list(self._streams);threads=list(self._threads)
            self.listener.close()
            for stream in streams:
                try:stream.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            end=time.monotonic()+self.limits.shutdown_seconds
            for thread in [*threads,*([self._maintenance] if self._maintenance is not None else [])]:
                thread.join(timeout=max(0,end-time.monotonic()))
            with self._lock:
                if self._phase!='failed':self._phase='stopped' if self.snapshot()['drained'] else 'drain-incomplete'
        return self.snapshot()
