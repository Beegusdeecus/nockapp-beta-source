"""One bounded anonymous request per authenticated TLS1.3 connection.

Installer-owned endpoint/CA context; no browser URLs, redirects, cookies,
ambient credentials, client certificates, retries or payload/error logs.
This authenticates the payment operator; it is not enclave attestation.
"""
import base64
import copy
import hashlib
import ipaddress
import re
import socket
import ssl
import struct
import time

from policy import canonical,strict_json,require,Rejected
from ticket_service_v2 import RPC,MAX_REQUEST,MAX_RESPONSE,request,validate_request

ENDPOINT='nockapp-prepaid-service-endpoint-v2'
DEADLINE=30


def endpoint(value):
    require(type(value) is dict and set(value)=={'profile','host','port','service','offer_sha256'}
        and value['profile']==ENDPOINT and value['service'] in ('payment','publication')
        and type(value['offer_sha256']) is str and re.fullmatch(r'[0-9a-f]{64}',value['offer_sha256']), 'ticket-endpoint')
    host=value['host']
    require(type(host) is str and len(host)<=253 and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}',host)
        and type(value['port']) is int and 1<=value['port']<=65535,'ticket-endpoint')
    return value


def _timeout(stream,deadline):
    left=deadline-time.monotonic();require(left>0,'ticket-channel-timeout');stream.settimeout(left)


def _read(stream,n,deadline):
    data=bytearray()
    while len(data)<n:
        _timeout(stream,deadline);part=stream.recv(n-len(data))
        require(bool(part),'ticket-channel-closed');data.extend(part)
    return bytes(data)


def receive(stream,limit,deadline):
    size=struct.unpack('!I',_read(stream,4,deadline))[0]
    require(0<size<=limit,'ticket-channel-frame-size')
    raw=_read(stream,size,deadline);value=strict_json(raw,max_bytes=limit)
    require(canonical(value)==raw,'ticket-channel-canonical');return value


def send(stream,value,limit,deadline):
    raw=canonical(value);require(0<len(raw)<=limit,'ticket-channel-frame-size')
    _timeout(stream,deadline);stream.sendall(struct.pack('!I',len(raw))+raw)


def _connect(config,deadline):
    raw=None
    try:
        answers=socket.getaddrinfo(config['host'],config['port'],type=socket.SOCK_STREAM,proto=socket.IPPROTO_TCP)
        require(0<len(answers)<=16,'ticket-endpoint-address')
        for family,kind,protocol,_,address in answers:
            ip=ipaddress.ip_address(address[0])
            require(ip.is_global and not ip.is_multicast and family in (socket.AF_INET,socket.AF_INET6)
                and kind==socket.SOCK_STREAM and protocol==socket.IPPROTO_TCP and address[1]==config['port'],'ticket-endpoint-address')
        family,kind,protocol,_,address=answers[0]
        raw=socket.socket(family,kind,protocol);_timeout(raw,deadline);raw.connect(address);return raw
    except Exception:
        if raw is not None:raw.close()
        raise Rejected('ticket-endpoint-unavailable') from None


def serve_connection(raw,application,context,*,validator=validate_request,max_request=MAX_REQUEST,max_response=MAX_RESPONSE):
    """No listener or credentials setup here; supervisor selects ONE role app."""
    secure=None;deadline=time.monotonic()+DEADLINE
    try:
        require(isinstance(context,ssl.SSLContext) and context.minimum_version>=ssl.TLSVersion.TLSv1_3,'ticket-server-tls')
        require(context.verify_mode==ssl.CERT_NONE and context.num_tickets==0,'ticket-server-anonymous-clients')
        _timeout(raw,deadline);secure=context.wrap_socket(raw,server_side=True)
        require(secure.version()=='TLSv1.3','ticket-channel-version')
        message=receive(secure,max_request,deadline)
        validator(message,application.offer.hash,application.service)
        send(secure,application.dispatch(message),max_response,deadline)
    except Exception:pass
    finally:
        if secure is not None:secure.close()
        raw.close()


class TicketRemote:
    _endpoint=staticmethod(endpoint)
    _correlation=('profile','offer_sha256','service','request_id')
    _max_request=MAX_REQUEST
    _max_response=MAX_RESPONSE

    def _message(self,a,operation,body):return request(a['offer_sha256'],a['service'],operation,body)

    def __init__(self,approved,context,*,dial=None):
        self.approved=copy.deepcopy(self._endpoint(approved));self._context=context;self._dial=dial
        self._approved_sha256=hashlib.sha256(canonical(self.approved)).hexdigest()
        require(isinstance(context,ssl.SSLContext) and context.check_hostname
            and context.verify_mode==ssl.CERT_REQUIRED and context.minimum_version>=ssl.TLSVersion.TLSv1_3,'ticket-client-tls')
        context.options|=ssl.OP_NO_TICKET

    def call(self,operation,body):
        a=self._endpoint(self.approved)
        require(hashlib.sha256(canonical(a)).hexdigest()==self._approved_sha256,'ticket-endpoint-changed')
        message=self._message(a,operation,body)
        require(self._context.check_hostname and self._context.verify_mode==ssl.CERT_REQUIRED
            and self._context.minimum_version>=ssl.TLSVersion.TLSv1_3,'ticket-client-tls')
        require(len(canonical(message))<=self._max_request,'ticket-channel-frame-size')
        raw=secure=None;deadline=time.monotonic()+DEADLINE
        try:
            raw=self._dial() if self._dial is not None else _connect(a,deadline)
            _timeout(raw,deadline);secure=self._context.wrap_socket(raw,server_hostname=a['host'])
            require(secure.version()=='TLSv1.3','ticket-channel-version')
            send(secure,message,self._max_request,deadline);reply=receive(secure,self._max_response,deadline)
            expected={k:message[k] for k in self._correlation}
            require(type(reply) is dict and all(reply.get(k)==v for k,v in expected.items()),'ticket-channel-correlation')
            if reply.get('status')=='rejected':
                require(set(reply)==set(expected)|{'status','error'} and reply['error']=='operation-unavailable','ticket-channel-reply')
                raise Rejected('ticket-remote-unavailable')
            require(set(reply)==set(expected)|{'status','result'} and reply['status']=='ok'
                and type(reply['result']) is dict,'ticket-channel-reply')
            return reply['result']
        except Rejected:raise
        except Exception:raise Rejected('ticket-channel-unavailable') from None
        finally:
            if secure is not None:secure.close()
            if raw is not None:raw.close()

    def issue(self,pack,transaction_hash):return self.call('issue',{'pack':pack,'transaction_hash':transaction_hash})
    def parameters(self):
        from ticket_offer_v1 import manifest_hash
        result=self.call('parameters',{})
        require(manifest_hash(result)==self.approved['offer_sha256'],'ticket-manifest-pin')
        return result
    def submit(self,token,bundle_hash):return self.call('submit',{'ticket':token,'bundle_hash':bundle_hash})
    def store(self,token,bundle_hash,raw):
        require(type(raw) is bytes and 0<len(raw)<=65536,'ticket-channel-content')
        return self.call('store',{'ticket':token,'bundle_hash':bundle_hash,'bundle_base64':base64.b64encode(raw).decode('ascii')})
