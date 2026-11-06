"""Real HTTPS through an untrusted relay socket, using public synthetic fixtures.

No API key/account/service is contacted. The fixture key only exists in memory.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
import socket
import ssl
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from credential import Crypto, LabIssuer, Pending
from policy import HOST, ProviderClient, Rejected, canonical
from test_zkid import NOW, fixture


@contextmanager
def server(responses, *, hostname=HOST, untrusted=False):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(seconds=5))
        .not_valid_after(now+timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]),critical=False)
        .sign(key,hashes.SHA256()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Test private key never reaches the filesystem, argv or test receipt.
    cert_fd, key_fd = os.memfd_create('synthetic-cert'), os.memfd_create('synthetic-key')
    try:
        os.write(cert_fd,cert.public_bytes(serialization.Encoding.PEM))
        os.write(key_fd,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        context.load_cert_chain('/proc/self/fd/'+str(cert_fd),'/proc/self/fd/'+str(key_fd))
    finally:
        os.close(cert_fd);os.close(key_fd)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    if not untrusted:
        client.load_verify_locations(cadata=cert.public_bytes(serialization.Encoding.PEM).decode())
    observed = []
    listener = socket.socket()
    listener.bind(('127.0.0.1',0));listener.listen(4);listener.settimeout(2)
    address=listener.getsockname()
    done=threading.Event()
    def run():
        for response in responses:
            try:
                raw,_=listener.accept()
                with context.wrap_socket(raw,server_side=True) as stream:
                    request=bytearray()
                    while b'\r\n\r\n' not in request and len(request)<8192:
                        data=stream.recv(1024)
                        if not data:break
                        request.extend(data)
                    # AWS transport fixtures also use this server for bounded
                    # POST bodies. Existing provider GET fixtures have no body.
                    header,_,body = bytes(request).partition(b'\r\n\r\n')
                    lengths = [line.split(b':',1)[1].strip() for line in header.split(b'\r\n')
                               if line.lower().startswith(b'content-length:')]
                    size = int(lengths[0]) if lengths else 0
                    if size > 1048576:raise ValueError('synthetic request too large')
                    while len(body) < size:
                        data = stream.recv(min(65536,size-len(body)))
                        if not data:break
                        request.extend(data);body += data
                    observed.append(bytes(request))
                    stream.sendall(response(bytes(request)) if callable(response) else response)
            except (OSError,ssl.SSLError):
                pass
        done.set()
    thread=threading.Thread(target=run,daemon=True);thread.start()
    try:
        yield client,lambda:socket.create_connection(address,timeout=1),observed
    finally:
        listener.close();thread.join(timeout=3)
        if thread.is_alive():raise RuntimeError('synthetic TLS fixture failed cleanup')


def response(data=b'{}',status=200,headers=None):
    hdr = headers or [('Content-Type','application/json'),('Content-Length',str(len(data)))]
    return ('HTTP/1.1 '+str(status)+' Result\r\n'+''.join(k+': '+v+'\r\n' for k,v in hdr)
            +'Connection: close\r\n\r\n').encode()+data


class ProviderTLSTests(unittest.TestCase):
    def test_41_real_tls_fetch_and_policy(self):
        crypto=Crypto();issuer=LabIssuer(crypto);pending=Pending.create(crypto)
        session=issuer.begin(pending.commitment,'42424242','synthetic_user',NOW,desktop_nonce=pending.nonce)
        t,u=fixture(session)
        synthetic_key='SYNTHETIC-API-KEY-NOT-A-CREDENTIAL'
        with server([response(canonical(t)),response(canonical(u))]) as (ctx,dial,seen):
            attributes=ProviderClient(synthetic_key,ctx,dial).check(session,'3141592653589793',NOW+2)
        self.assertEqual(attributes[-1],'1')
        self.assertEqual(len(seen),2)
        self.assertIn(b'GET /twitter/tweets?tweet_ids=3141592653589793 HTTP/1.1',seen[0])
        self.assertIn(b'GET /twitter/user/info?userName=synthetic_user HTTP/1.1',seen[1])
        self.assertTrue(all(b'Host: api.twitterapi.io\r\n' in r for r in seen))
        self.assertTrue(all(('X-API-Key: '+synthetic_key).encode() in r for r in seen))

    def test_42_wrong_tls_hostname(self):
        with server([response()],hostname='wrong.invalid') as (ctx,dial,seen):
            with self.assertRaisesRegex(Rejected,'provider-unavailable'):
                ProviderClient('synthetic-research-key',ctx,dial)._get('/twitter/tweets?tweet_ids=1')
        self.assertEqual(seen,[])

    def test_43_untrusted_tls_certificate(self):
        with server([response()],untrusted=True) as (ctx,dial,seen):
            with self.assertRaisesRegex(Rejected,'provider-unavailable'):
                ProviderClient('synthetic-research-key',ctx,dial)._get('/twitter/tweets?tweet_ids=1')
        self.assertEqual(seen,[])

    def test_44_redirect_not_followed_or_key_forwarded(self):
        with server([response(status=302,headers=[('Location','https://wrong.invalid'),('Content-Length','0')])]) as (ctx,dial,seen):
            with self.assertRaisesRegex(Rejected,'provider-http-error'):
                ProviderClient('synthetic-research-key',ctx,dial)._get('/twitter/tweets?tweet_ids=1')
        self.assertEqual(len(seen),1)

    def test_45_rate_limit_safe_error(self):
        with server([response(b'{"private":"synthetic-sensitive-marker"}',429)]) as (ctx,dial,seen):
            with self.assertRaisesRegex(Rejected,'^provider-rate-limit$'):
                ProviderClient('synthetic-research-key',ctx,dial)._get('/twitter/tweets?tweet_ids=1')

    def test_46_ambiguous_framing(self):
        for headers in [[('Content-Type','application/json'),('Content-Length','2'),('Transfer-Encoding','chunked')],
                        [('Content-Type','application/json'),('Content-Length','2'),('Content-Length','2')]]:
            with server([response(headers=headers)]) as (ctx,dial,seen):
                with self.assertRaises(Rejected):
                    ProviderClient('synthetic-research-key',ctx,dial)._get('/twitter/tweets?tweet_ids=1')

    def test_47_oversized_compressed_and_wrong_content_type(self):
        cases=[[('Content-Type','application/json'),('Content-Length','131073')],
               [('Content-Type','application/json'),('Content-Encoding','gzip'),('Content-Length','2')],
               [('Content-Type','text/html'),('Content-Length','2')]]
        for headers in cases:
            with server([response(headers=headers)]) as (ctx,dial,seen):
                with self.assertRaises(Rejected):
                    ProviderClient('synthetic-research-key',ctx,dial)._get('/twitter/tweets?tweet_ids=1')

    def test_48_no_insecure_tls_or_header_injection(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
        with self.assertRaises(Rejected):ProviderClient('synthetic-research-key',context)
        context=ssl.create_default_context()
        with self.assertRaises(Rejected):ProviderClient('synthetic\r\nInjected: bad',context)


if __name__=='__main__':
    unittest.main()
