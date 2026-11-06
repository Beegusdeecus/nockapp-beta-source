"""Fresh host-service keys, public CSRs, and one-shot sealed setup delivery.

Internal API only. No import/export of existing keys, CA key creation, issuer
key access, ambient credentials, deployment or funding. Generate -> review
public bindings/certificates/config -> prepare. Persist before deploying or
funding these authorities. Losing this process before persistence loses keys.
"""
import base64
import copy
import re
import socket
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from base_protocol import ReceiptKey
from policy import canonical,require,Rejected
from ticket_backend_boot_v1 import harden_process,validate,PRIVATE,der_public
import ticket_key_seal_v1 as sealing
import ticket_key_setup_v1 as setup

REQUEST='nockapp-ticket-new-keys-v1'
PUBLIC='nockapp-ticket-generated-public-keys-v1'
ROLES=setup.ROLES
def b64(data):return base64.b64encode(data).decode('ascii')
def private(key):return key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())

class _FreshKeys:
    def __init__(self,hostnames):
        self._lock=threading.Lock();self._attempted=False;self._closed=False
        self._service={'payment':rsa.generate_private_key(public_exponent=65537,key_size=3072),
            'publication':ec.generate_private_key(ec.SECP256K1()),'refund':ec.generate_private_key(ec.SECP256K1())}
        self._tls={r:ec.generate_private_key(ec.SECP256R1()) for r in ROLES}
        self._public={'profile':PUBLIC,'ticket_spki':b64(der_public(self._service['payment'].public_key())),
            'key_bindings':{r:ReceiptKey(None,self._service[r]).address for r in ('publication','refund')},'tls':{}}
        require(len(set(self._public['key_bindings'].values()))==2,'ticket-new-keys-collision')
        for role in ROLES:
            hostname=hostnames[role];key=self._tls[role]
            csr=(x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)]))
                .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
                .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,None,None),True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]),False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(key,hashes.SHA256()))
            self._public['tls'][role]={'hostname':hostname,'key_sha256':setup.storage.sha(der_public(key.public_key())),
                'csr_der':b64(csr.public_bytes(serialization.Encoding.DER))}
    def __repr__(self):return '<Fresh NockApp host-service keys; private material omitted>'
    def __reduce_ex__(self,_):raise TypeError('ticket-new-keys-serialization-forbidden')
    def public(self):
        with self._lock:return copy.deepcopy(self._public)
    def close(self):
        # Drop references, not a promise that Python/OpenSSL erased every copy.
        with self._lock:self._service.clear();self._tls.clear();self._closed=True
    def _checked_bodies(self,plan,expected,certificates):
        setup.validate_public(plan,expected)
        plan=copy.deepcopy(plan)
        require(type(plan) is dict and plan.get('profile')==setup.PROFILE
            and setup.storage.sha(canonical(plan))==expected and type(plan.get('roles')) is dict
            and set(plan['roles'])==set(ROLES) and type(certificates) is dict
            and set(certificates)==set(ROLES),'ticket-new-keys-plan')
        bodies={}
        for role in ROLES:
            value=plan['roles'][role];cfg=validate(value['backend'],value['backend_sha256'])
            info=self._public['tls'][role];cert=certificates[role]
            require(cfg['role']==role and cfg['key_bindings']==self._public['key_bindings']
                and cfg['offer']['terms']['ticket_spki']==self._public['ticket_spki']
                and cfg['tls']['hostname']==info['hostname'] and cfg['tls']['key_sha256']==info['key_sha256']
                and type(cert) is bytes and 0<len(cert)<=8192,'ticket-new-keys-binding')
            body={'profile':PRIVATE,'role':role,'config_sha256':value['backend_sha256'],
                'service_key_der':b64(private(self._service[role])),
                'tls_private_key_der':b64(private(self._tls[role])),'tls_certificate_der':b64(cert)}
            bodies[role]=sealing.checked_body(cfg,value['backend_sha256'],body)
        return bodies

    def admit_review(self,plan,expected,certificates):
        """Public review/chain/binding admission, no credentials, AWS or IO.

        Locally generated private keys are checked against the supplied public
        certificates in memory; no private bytes are returned to the caller.
        """
        with self._lock:
            require(not self._closed and not self._attempted,'ticket-new-keys-not-ready')
            try:self._checked_bodies(plan,expected,certificates);return True
            except Exception:raise Rejected('ticket-new-keys-review-unavailable') from None

    def prepare(self,plan,expected,certificates,*,clients,output):
        """One-shot handoff to the existing coordinator; no private file output.

        Certificates are public DER bytes signed outside this API by a separately
        protected CA. This API does not provide certificate issuance or renewal.
        Any attempted preparation consumes this object's one-shot capability;
        false/unknown results require review rather than another attempt.
        """
        with self._lock:
            require(not self._closed and not self._attempted,'ticket-new-keys-not-ready')
            try:
                self._attempted=True
                bodies=self._checked_bodies(plan,expected,certificates)
                sockets=[];writers=[];descriptors={}
                def deliver(stream,data):
                    try:
                        with stream:stream.sendall(data);stream.shutdown(socket.SHUT_WR)
                    except Exception:pass # Coordinator validates complete private input/EOF.
                try:
                    for role in ROLES:
                        read,write=socket.socketpair();sockets.extend((read,write));descriptors[role]=read.fileno()
                        writer=threading.Thread(target=deliver,args=(write,bodies[role]),daemon=True)
                        writer.start();writers.append(writer)
                    result=setup.prepare(plan,expected,descriptors,clients=clients,output=output)
                    return result
                finally:
                    for stream in sockets:stream.close()
                    for writer in writers:writer.join(timeout=10)
                    require(not any(w.is_alive() for w in writers),'ticket-new-keys-private-relay')
                    # Early public rejection can close readers before delivery;
                    # coordinator status is authoritative, no automatic retry.
            except Exception:
                raise Rejected('ticket-new-keys-prepare-unavailable') from None

def validate_request(request,expected):
    require(type(request) is dict and set(request)=={'profile','hostnames'} and request['profile']==REQUEST
        and type(request['hostnames']) is dict and set(request['hostnames'])==set(ROLES)
        and type(expected) is str and setup.storage.sha(canonical(request))==expected,'ticket-new-keys-request')
    names=request['hostnames'].copy()
    for name in names.values():
        require(type(name) is str and len(name)<=253
            and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}',name),'ticket-new-keys-hostname')
    return names

def generate(request,expected):
    names=validate_request(request,expected)
    harden_process() # Before any secret generation.
    try:return _FreshKeys(names)
    except Exception:raise Rejected('ticket-new-keys-unavailable') from None
