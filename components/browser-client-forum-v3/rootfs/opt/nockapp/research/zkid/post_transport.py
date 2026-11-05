"""Independent application transport selected only by installer approval.

Private Unix sockets retain certificate/configuration pins and same-UID checks.
The distinct public profile requires fresh AWS attestation and bound TLS before
proof data. No caller endpoint/trust selection or automatic effectful retry.
"""
import copy
import hashlib
import os
from pathlib import Path
import secrets
import socket
import ssl
import stat
import struct
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from domain_post_rpc import PROFILE as RPC,MAX_REQUEST,validate_request
from policy import Rejected,canonical,digest,hex_string,require,strict_json

PROFILE='nockapp-zkid-post-private-tls-v1'
APPROVAL='nockapp-zkid-post-client-approval-v1'
BINDING='nockapp-zkid-post-service-binding-v1'
REMOTE_APPROVAL='nockapp-zkid-post-attested-client-v1'
HOSTNAME='zkid-post-verifier.local'
DEADLINE=60
LIMIT=MAX_REQUEST+2048


def validate_binding(value):
    require(type(value) is dict and set(value)=={'profile','definition_hash','audience','state_authority_sha256','native_sha256'}
            and value['profile']==BINDING,'post-service-binding')
    for name in ('definition_hash','audience','state_authority_sha256','native_sha256'):
        hex_string(value[name],64);require(any(bytes.fromhex(value[name])),'post-service-binding')
    return value


def socket_path(value):
    require(type(value) is str and 0<len(os.fsencode(value))<104,'post-socket')
    path=Path(value)
    require(path.is_absolute() and '..' not in path.parts and path.name=='verifier.sock'
            and not any(p.startswith('.env') for p in path.parts)
            and not any(p.is_symlink() for p in [path,*path.parents]),'post-socket')
    return path


def private_parent(path):
    info=path.parent.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077,'post-socket')


def certificate(value):
    require(type(value) is str and 0<len(value)<=16384,'post-certificate')
    cert=x509.load_pem_x509_certificate(value.encode('ascii'))
    require(cert.public_bytes(serialization.Encoding.PEM).decode('ascii')==value,'post-certificate')
    return cert.public_bytes(serialization.Encoding.DER)


def validate_approval(value):
    if type(value) is dict and value.get('profile')==REMOTE_APPROVAL:
        from post_remote_transport import validate_approval as validate_remote
        return validate_remote(value)
    require(type(value) is dict and set(value)=={'profile','binding','certificate_pem','socket_path','uid'}
            and value['profile']==APPROVAL and type(value['uid']) is int and value['uid']==os.getuid(),'post-client-approval')
    validate_binding(value['binding']);certificate(value['certificate_pem']);socket_path(value['socket_path'])
    return value


def peer_uid(stream):
    require(stream.family==socket.AF_UNIX,'post-peer')
    return struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]


def _timeout(stream,deadline):
    remaining=deadline-time.monotonic();require(remaining>0,'post-channel-timeout');stream.settimeout(remaining)


def _exact(stream,size,deadline):
    body=bytearray()
    while len(body)<size:
        _timeout(stream,deadline);part=stream.recv(size-len(body));require(part,'post-channel-closed');body.extend(part)
    return bytes(body)


def receive(stream,limit,deadline):
    size=struct.unpack('!I',_exact(stream,4,deadline))[0]
    require(0<size<=limit,'post-channel-size');return strict_json(_exact(stream,size,deadline),max_bytes=limit)


def send(stream,value,limit,deadline):
    body=canonical(value);require(0<len(body)<=limit,'post-channel-size')
    _timeout(stream,deadline);stream.sendall(struct.pack('!I',len(body))+body)


def server_context(cert_pem,key_pem):
    certificate(cert_pem);require(type(key_pem) is str and 0<len(key_pem)<=16384,'post-private-key')
    cert_fd=os.memfd_create('post-public-certificate',os.MFD_CLOEXEC)
    key_fd=os.memfd_create('post-private-tls-key',os.MFD_CLOEXEC)
    try:
        os.write(cert_fd,cert_pem.encode('ascii'));os.write(key_fd,key_pem.encode('ascii'))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3;context.options|=ssl.OP_NO_TICKET
        context.load_cert_chain(f'/proc/self/fd/{cert_fd}',f'/proc/self/fd/{key_fd}')
        return context
    finally:os.close(cert_fd);os.close(key_fd)


def serve_connection(raw,application,context,binding,*,expires_at):
    secure=None;deadline=time.monotonic()+DEADLINE
    try:
        validate_binding(binding);require(peer_uid(raw)==os.getuid(),'post-peer')
        require(int(time.time())<expires_at,'post-service-expired')
        _timeout(raw,deadline);secure=context.wrap_socket(raw,server_side=True)
        hello=receive(secure,512,deadline)
        require(type(hello) is dict and set(hello)=={'profile','nonce','binding_sha256'}
                and hello['profile']==PROFILE and hello['binding_sha256']==digest(binding),'post-channel-binding')
        hex_string(hello['nonce'],64)
        send(secure,hello,512,deadline)
        message=receive(secure,MAX_REQUEST,deadline)
        require(int(time.time())<expires_at,'post-service-expired')
        result=application.dispatch(message)
        send(secure,result,LIMIT,deadline)
    except Exception:pass
    finally:
        if secure is not None:secure.close()
        raw.close()


class PostClient:
    def __init__(self,approved):self.approved=copy.deepcopy(validate_approval(approved))

    def request(self,operation,body):
        if self.approved['profile']==REMOTE_APPROVAL:
            from post_remote_transport import request
            return request(operation,body,self.approved)
        raw=secure=None;deadline=time.monotonic()+DEADLINE
        try:
            approved=self.approved
            message={'profile':RPC,'id':secrets.token_hex(16),'operation':operation,'body':copy.deepcopy(body)}
            validate_request(message)  # Reject extras/private fields BEFORE dialing.
            path=socket_path(approved['socket_path']);private_parent(path);info=path.stat()
            require(stat.S_ISSOCK(info.st_mode) and info.st_uid==approved['uid'] and not info.st_mode&0o077,'post-socket')
            raw=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);_timeout(raw,deadline);raw.connect(str(path))
            require(peer_uid(raw)==approved['uid'],'post-peer')
            expected=certificate(approved['certificate_pem'])
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
            context.load_verify_locations(cadata=approved['certificate_pem'])
            _timeout(raw,deadline);secure=context.wrap_socket(raw,server_hostname=HOSTNAME)
            require(secure.version()=='TLSv1.3' and secure.getpeercert(binary_form=True)==expected,'post-certificate')
            hello={'profile':PROFILE,'nonce':secrets.token_hex(32),'binding_sha256':digest(approved['binding'])}
            send(secure,hello,512,deadline);require(receive(secure,512,deadline)==hello,'post-channel-binding')
            send(secure,message,MAX_REQUEST,deadline);reply=receive(secure,LIMIT,deadline)
            require(type(reply) is dict and reply.get('profile')==RPC and reply.get('id')==message['id']
                    and reply.get('laboratory') is True and reply.get('verified') is False,'post-channel-reply')
            expected_fields={'profile','id','status','laboratory','verified'}
            if reply.get('status')=='ok':
                require(set(reply)==expected_fields|{'result'} and type(reply['result']) is dict,'post-channel-reply')
            else:require(reply.get('status')=='rejected' and set(reply)==expected_fields|{'code'}
                         and type(reply['code']) is str,'post-channel-reply')
            return reply
        except Rejected:raise
        except Exception:raise Rejected('post-channel-unavailable') from None
        finally:
            if secure is not None:secure.close()
            if raw is not None:raw.close()
