"""In-memory same-key certificate replacement for a trusted host launcher.

No CA credentials, signing, private files, sealed-packet rewrite, network or
automatic initialization. The original encrypted boot packet stays unchanged.
Installed certificate delivery and RoleServer polling are separate integration
gates. A consumer must call current() for each new handshake, not retain it.
"""
import copy
import threading
import time
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from policy import require,canonical,strict_json,Rejected
from ticket_backend_boot_v1 import validate,tls_context,harden_process,private_key,der_public,PRIVATE
from base_protocol import ReceiptKey
from ticket_native_v1 import _decode

def checked_body(config,expected,body):
    """Runtime-only key/leaf admission; no setup sealer or GDK import."""
    cfg=validate(config,expected)
    require(type(body) is dict and set(body)=={'profile','role','config_sha256',
        'service_key_der','tls_private_key_der','tls_certificate_der'} and body['profile']==PRIVATE
        and body['role']==cfg['role'] and body['config_sha256']==expected,'host-tls-private-body')
    _,key=private_key(body['service_key_der'])
    if cfg['role']=='payment':
        require(isinstance(key,rsa.RSAPrivateKey) and key.key_size==3072
            and key.public_key().public_numbers().e==65537
            and der_public(key.public_key())==_decode(cfg['offer']['terms']['ticket_spki'],1024),'host-tls-service-key')
    else:
        require(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256K1)
            and ReceiptKey(None,key).address==cfg['key_bindings'][cfg['role']],'host-tls-service-key')
    tls_context(cfg,body)
    data=canonical(body);require(0<len(data)<=65536,'host-tls-private-size');return data


class RenewingContext:
    def __init__(self,config,expected,private_body,*,certificate_der=None):
        harden_process();self._config=validate(config,expected);self._expected=expected
        require(type(private_body) is dict and set(private_body)=={'profile','role','config_sha256',
            'service_key_der','tls_private_key_der','tls_certificate_der'},'host-tls-private-body')
        self._body=copy.deepcopy(private_body);self._lock=threading.RLock()
        self._context=None;self._expiry=0;self._last=0;self._fingerprint=None
        if certificate_der is None:
            certificate_der=_decode(self._body['tls_certificate_der'],8192)
        self.install(certificate_der)
    def __repr__(self):return '<Renewing host TLS context; private material omitted>'
    def __reduce_ex__(self,_):raise TypeError('host-tls-serialization-forbidden')
    def install(self,certificate_der):
        with self._lock:
            try:
                require(type(certificate_der) is bytes and 0<len(certificate_der)<=8192,'host-tls-certificate')
                import base64,hashlib
                fingerprint=hashlib.sha256(certificate_der).hexdigest()
                candidate=copy.deepcopy(self._body);candidate['tls_certificate_der']=base64.b64encode(certificate_der).decode()
                # Same backend/service keys and full current leaf/root/SAN/SPKI
                # admission as boot, including sealed-memfd loading only.
                checked=strict_json(checked_body(self._config,self._expected,candidate),max_bytes=65536)
                leaf=x509.load_der_x509_certificate(certificate_der);expiry=int(leaf.not_valid_after_utc.timestamp())
                now=int(time.time());require(now>=self._last-5,'host-tls-clock')
                if self._fingerprint==fingerprint:
                    self._last=max(now,self._last)
                    return {'changed':False,'certificate_sha256':fingerprint,'expires_at':expiry}
                require(expiry>self._expiry,'host-tls-rollback')
                context=tls_context(self._config,checked)
                self._context=context;self._body=checked;self._expiry=expiry
                self._fingerprint=fingerprint;self._last=max(now,self._last)
                return {'changed':True,'certificate_sha256':fingerprint,'expires_at':expiry}
            except Exception:raise Rejected('host-tls-renewal-unavailable') from None
    def current(self):
        with self._lock:
            now=int(time.time())
            require(self._context is not None and now>=self._last-5 and now<self._expiry,'host-tls-certificate-unavailable')
            self._last=max(now,self._last);return self._context
