"""One bounded issuer operation per fresh attestation + TLS 1.3 connection.

This module opens NO listener. A measured supervisor owns the application,
authority configuration and NSM. The parent may relay bytes only. Private
registration data is sent only after AWS enrollment and TLS key possession.
"""
import base64
import copy
import datetime
import hashlib
import ipaddress
import os
import re
import secrets
import socket
import ssl
import struct
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from domain_issuer import RPC, MAX_REQUEST
from domain_trust import (ENROLLMENT, HOSTNAME, binding, certificate_key,
                          enroll_production, validate_approval, pinned_channel_context)
from policy import Rejected, canonical, hex_string, require, strict_json
from enclave_nsm import Nsm

ENVELOPE_LIMIT = 131072
RESPONSE_LIMIT = 131072
DEADLINE = 30
ENDPOINT = 'nockapp-zkid-public-issuer-endpoint-v1'


def _public_address(value):
    try:address=ipaddress.ip_address(value)
    except ValueError:raise Rejected('issuer-endpoint-address') from None
    require(address.is_global and not any((address.is_multicast,address.is_loopback,
            address.is_link_local,address.is_unspecified,address.is_reserved))
            and '%' not in value,'issuer-endpoint-address')
    return address


def validate_endpoint(value,*,profile=ENDPOINT):
    """Installer-owned public address, never a browser URL or trust source."""
    require(type(value) is dict and set(value)=={'profile','host','port'}
            and value['profile']==profile and type(value['port']) is int
            and 1<=value['port']<=65535 and type(value['host']) is str,'issuer-endpoint')
    host=value['host']
    require(0<len(host)<=253 and host==host.lower() and host.isascii(),'issuer-endpoint')
    try:ipaddress.ip_address(host)
    except ValueError:
        require('.' in host and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part)
                for part in host.split('.')) and not host.replace('.','').isdigit(),'issuer-endpoint')
    else:_public_address(host)
    return value


def connect_endpoint(endpoint,*,profile=ENDPOINT):
    """Resolve once, reject private/mixed targets, dial once without proxy/retry.

    The address grants no application trust: fresh AWS enrollment and pinned TLS
    still precede private payloads in request(). DNS cannot select a local target.
    """
    endpoint=copy.deepcopy(validate_endpoint(endpoint,profile=profile));raw=None;deadline=time.monotonic()+10
    try:
        answers=socket.getaddrinfo(endpoint['host'],endpoint['port'],type=socket.SOCK_STREAM,
                                   proto=socket.IPPROTO_TCP,flags=socket.AI_NUMERICSERV)
        require(0<len(answers)<=16,'issuer-endpoint-address')
        for family,kind,protocol,_,address in answers:
            require(family in (socket.AF_INET,socket.AF_INET6) and kind==socket.SOCK_STREAM
                    and protocol==socket.IPPROTO_TCP and address[1]==endpoint['port']
                    and (family!=socket.AF_INET6 or address[2:]==(0,0)),'issuer-endpoint-address')
            parsed=_public_address(address[0])
            require(parsed.version==(4 if family==socket.AF_INET else 6),'issuer-endpoint-address')
        family,kind,protocol,_,address=answers[0]
        raw=socket.socket(family,kind,protocol);_timeout(raw,deadline);raw.connect(address)
        return raw
    except Exception:
        if raw is not None:raw.close()
        raise Rejected('issuer-endpoint-unavailable') from None


def _timeout(stream, deadline):
    remaining = deadline-time.monotonic()
    require(remaining > 0,'issuer-channel-timeout')
    stream.settimeout(remaining)


def _exact(stream, size, deadline):
    result = bytearray()
    while len(result) < size:
        _timeout(stream,deadline)
        part = stream.recv(size-len(result))
        require(bool(part),'issuer-channel-closed')
        result.extend(part)
    return bytes(result)


def receive(stream, limit, deadline):
    size = struct.unpack('!I',_exact(stream,4,deadline))[0]
    require(0 < size <= limit,'issuer-frame-size')
    return strict_json(_exact(stream,size,deadline))


def send(stream, value, limit, deadline):
    data = canonical(value)
    require(0 < len(data) <= limit,'issuer-frame-size')
    _timeout(stream,deadline)
    stream.sendall(struct.pack('!I',len(data))+data)


def _decode(value, limit):
    require(type(value) is str and 0 < len(value) <= 4*((limit+2)//3),'issuer-envelope')
    try:
        data = base64.b64decode(value,validate=True)
        require(0 < len(data) <= limit and base64.b64encode(data).decode('ascii') == value,'issuer-envelope')
        return data
    except Exception:
        raise Rejected('issuer-envelope') from None


def channel_identity(*,hostname=HOSTNAME):
    """Fresh TLS key lives only in enclave memory, including OpenSSL loading."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
        .not_valid_after(now+datetime.timedelta(minutes=5))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]),critical=False)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .sign(key,hashes.SHA256()))
    cert_fd = os.memfd_create('zkid-channel-cert',os.MFD_CLOEXEC)
    key_fd = os.memfd_create('zkid-channel-key',os.MFD_CLOEXEC)
    try:
        os.write(cert_fd,cert.public_bytes(serialization.Encoding.PEM))
        os.write(key_fd,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.options |= ssl.OP_NO_TICKET
        context.load_cert_chain(f'/proc/self/fd/{cert_fd}',f'/proc/self/fd/{key_fd}')
    finally:
        os.close(cert_fd);os.close(key_fd)
    return context,cert.public_bytes(serialization.Encoding.DER)


def _aws_document(nonce, bind, certificate):
    # Minimal pinned NSM helper shared with recipient provisioning, no simulator.
    document = Nsm().attest(bytes.fromhex(nonce),certificate_key(certificate),
                            hashlib.sha256(canonical(bind)).digest())
    require(0 < len(document) <= 32768,'issuer-document')
    return document


def serve_connection(raw, application, code_identity, state_authority_sha256):
    """Internal supervisor entry, never caller-selected keys/configuration.

    Secret provisioning and a managed authority remain deployment prerequisites.
    This handler deliberately does not convert local state into production trust.
    """
    secure = None
    deadline = time.monotonic()+DEADLINE
    try:
        hello = receive(raw,256,deadline)
        require(type(hello) is dict and set(hello) == {'profile','nonce'}
                and hello['profile'] == ENROLLMENT,'issuer-hello')
        hex_string(hello['nonce'],64)
        view = application.state.backend.public_view()
        context,certificate = channel_identity()
        bind = binding(view,certificate,code_identity,state_authority_sha256)
        document = _aws_document(hello['nonce'],bind,certificate)
        send(raw,{'profile':ENROLLMENT,'registry':view,
                  'certificate':base64.b64encode(certificate).decode('ascii'),
                  'document':base64.b64encode(document).decode('ascii')},ENVELOPE_LIMIT,deadline)
        _timeout(raw,deadline)
        secure = context.wrap_socket(raw,server_side=True)
        request = receive(secure,MAX_REQUEST+256,deadline)
        require(type(request) is dict and set(request) == {'enrollment_sha256','request'}
                and request['enrollment_sha256'] == hashlib.sha256(canonical(bind)).hexdigest(),
                'issuer-channel-binding')
        # Only the policy controller is reachable; the native signer is not RPC.
        response = application.dispatch_bytes(canonical(request['request']))
        send(secure,strict_json(response),RESPONSE_LIMIT,deadline)
    except Exception:
        # No private input, source data, keys or exception text reaches logs/wire.
        pass
    finally:
        if secure is not None:secure.close()
        raw.close()


def request(raw, operation, body, approved):
    """Helper-owned socket + installer trust. No automatic retry after uncertainty.

    A failed commit/abort must be resolved with a new authenticated status call.
    Result remains laboratory-only until the complete deployment gates pass.
    """
    secure = None
    deadline = time.monotonic()+DEADLINE
    try:
        approved = copy.deepcopy(approved)
        validate_approval(approved)
        message = {'id':secrets.token_hex(16),'profile':RPC,'operation':operation,'body':body}
        require(type(operation) is str and len(canonical(message)) <= MAX_REQUEST,'message-schema')
        nonce = secrets.token_hex(32)
        send(raw,{'profile':ENROLLMENT,'nonce':nonce},256,deadline)
        envelope = receive(raw,ENVELOPE_LIMIT,deadline)
        require(type(envelope) is dict and set(envelope) == {'profile','registry','certificate','document'}
                and envelope['profile'] == ENROLLMENT,'issuer-envelope')
        certificate = _decode(envelope['certificate'],8192)
        bind = enroll_production(_decode(envelope['document'],32768),nonce,envelope['registry'],certificate,approved)
        context = pinned_channel_context(certificate)
        _timeout(raw,deadline)
        secure = context.wrap_socket(raw,server_hostname=HOSTNAME)
        require(secure.version() == 'TLSv1.3' and secure.getpeercert(binary_form=True) == certificate,
                'issuer-channel-certificate')
        send(secure,{'enrollment_sha256':hashlib.sha256(canonical(bind)).hexdigest(),
                     'request':message},MAX_REQUEST+256,deadline)
        response = receive(secure,RESPONSE_LIMIT,deadline)
        require(type(response) is dict and response.get('id') == message['id']
                and response.get('profile') == RPC and response.get('laboratory') is True
                and response.get('verified') is False,'issuer-response')
        if response.get('status') == 'ok':
            require(set(response) == {'id','profile','status','result','laboratory','verified'}
                    and type(response['result']) is dict,'issuer-response')
        else:
            require(set(response) == {'id','profile','status','code','laboratory','verified'}
                    and response['status'] == 'rejected' and type(response['code']) is str,'issuer-response')
        return response
    except Rejected:
        raise
    except Exception:
        raise Rejected('issuer-channel-unavailable') from None
    finally:
        if secure is not None:secure.close()
        raw.close()
