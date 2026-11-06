"""Actual TLS1.3 + paid/native/EVM flow; CA/S3/OP fees/keyring are fixtures."""
from contextlib import contextmanager
from datetime import datetime,timedelta,timezone
import copy
import os
import socket
import ssl
import struct
import threading
import time
import unittest
from unittest.mock import Mock,patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID

from policy import canonical,Rejected
from public_bundle_v5 import encode
from public_content_v5 import PublicContent
from public_s3_v5 import S3PublicOrigin
from ticket_service_v2 import PaymentApplication,PublicationApplication,request,validate_request,MAX_REQUEST
from ticket_transport_v2 import TicketRemote,ENDPOINT,serve_connection,send,receive
from ticket_publisher_v2 import TicketPublisher
from ticket_public_client_v2 import TicketPublicOrigin,TicketPublicRelay
from test_provider_tls import server as http_server
from test_public_s3 import stored,REGION,BUCKET,HOST as S3HOST
import test_ticket_publication_v2 as cases

HOST='operator.nockapp.example'


def contexts(hostname=HOST,*,trusted=True):
    now=datetime.now(timezone.utc);rootkey=ec.generate_private_key(ec.SECP256R1());key=ec.generate_private_key(ec.SECP256R1())
    rootname=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic operator CA, not AWS attestation')])
    root=(x509.CertificateBuilder().subject_name(rootname).issuer_name(rootname).public_key(rootkey.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(seconds=10)).not_valid_after(now+timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(rootkey,hashes.SHA256()))
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)]))
        .issuer_name(rootname).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(seconds=10)).not_valid_after(now+timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]),critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(rootkey,hashes.SHA256()))
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server.minimum_version=ssl.TLSVersion.TLSv1_3;server.num_tickets=0
    certfd,keyfd=os.memfd_create('synthetic-service-cert'),os.memfd_create('synthetic-service-key')
    try:
        os.write(certfd,cert.public_bytes(serialization.Encoding.PEM)+root.public_bytes(serialization.Encoding.PEM))
        os.write(keyfd,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        server.load_cert_chain('/proc/self/fd/'+str(certfd),'/proc/self/fd/'+str(keyfd))
    finally:os.close(certfd);os.close(keyfd)
    client=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);client.minimum_version=ssl.TLSVersion.TLSv1_3
    if trusted:client.load_verify_locations(cadata=root.public_bytes(serialization.Encoding.PEM).decode())
    return server,client


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cases.PublicationTests.setUpClass()
    def setUp(self):
        self.f=cases.PublicationTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.pay=PaymentApplication(self.f.f.issuer);self.pub=PublicationApplication(self.f.worker)

    @contextmanager
    def channel(self,app,*,hostname=HOST,trusted=True,mutate=None,approved_hash=None):
        serverctx,clientctx=contexts(hostname,trusted=trusted)
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(4)
        threads=[];requests=[];original=app.dispatch
        def dispatch(value):
            requests.append(copy.deepcopy(value));reply=original(value)
            return mutate(reply) if mutate else reply
        def dial():
            left=socket.create_connection(listener.getsockname(),timeout=2);right,_=listener.accept()
            t=threading.Thread(target=serve_connection,args=(right,app,serverctx));threads.append(t);t.start();return left
        approved={'profile':ENDPOINT,'host':HOST,'port':443,'service':app.service,
            'offer_sha256':approved_hash or self.f.offer.hash}
        remote=TicketRemote(approved,clientctx,dial=dial)
        with patch.object(app,'dispatch',side_effect=dispatch):
            try:yield remote,requests
            finally:
                listener.close()
                for t in threads:t.join(timeout=5);self.assertFalse(t.is_alive())

    def test_paid_issuance_over_authenticated_tls_and_fresh_request_correlation(self):
        request,_=self.f.f.paid()
        with self.channel(self.pay) as (remote,requests):
            self.assertEqual(remote.parameters(),self.f.offer.manifest)
            result=remote.issue(**request)
            self.assertEqual(self.f.f.client.receive(result)['available'],4)
        self.assertEqual(len(requests),2);self.assertNotEqual(requests[0]['request_id'],requests[1]['request_id'])
        self.assertEqual(set(requests[1]['body']),{'pack','transaction_hash'})

    def test_real_tls_ingress_does_not_index_then_relay_publishes_and_reader_verifies(self):
        h,v=self.f.post();raw=encode(v)
        del self.f.origin.objects[h];self.f.content.clear()
        with self.channel(self.pub) as (remote,requests):
            with http_server([stored(raw,int(time.time())+90*86400)],hostname=S3HOST) as (ctx,dial,downloads):
                reader=S3PublicOrigin(REGION,BUCKET,'419720240831',ctx,dial=dial)
                origin=TicketPublicOrigin(reader,remote,self.f.f.client,clock=lambda:self.f.f.now)
                receipt=PublicContent(origin).upload(v)
                self.assertTrue(receipt['readback_checked'])
            self.assertIsNone(self.f.index.number_for_hash(h))
            self.assertIsNone(self.f.queue.lookup(self.f.offer.protocol.verify(self.f.tokens[0]),h))
            publisher=TicketPublisher(self.f.f.client,remote.submit,clock=lambda:self.f.f.now)
            relay=TicketPublicRelay(publisher,self.f.index)
            first=relay.submit(h);again=relay.submit(h)
            self.assertEqual(first,again)
        self.assertNotIn(b'Authorization:',downloads[0]);self.assertNotIn(b'x-amz-security-token:',downloads[0])
        self.assertEqual([v['operation'] for v in requests],['store','submit','submit'])
        self.assertFalse(self.f.secret.encode() in canonical({'requests':requests}))
        n=self.f.index.number_for_hash(h)
        page=self.f.reader.read_numbers([n],int(self.f.f.rpc.call('eth_getBlockByNumber','latest',False)['timestamp'],16))
        self.assertTrue(page['posts'][0]['proofs_verified'])

    def test_wrong_ca_hostname_or_offer_never_reaches_application(self):
        for options in ({'trusted':False},{'hostname':'wrong.operator.example'},{'approved_hash':'ff'*32}):
            with self.channel(self.pub,**options) as (remote,requests):
                with self.assertRaises(Rejected):remote.submit(self.f.tokens[0],'0x'+'11'*32)
            self.assertFalse(requests)

    def test_cross_role_and_extra_credential_fields_reject_before_dial(self):
        _,ctx=contexts();dial=Mock(side_effect=AssertionError('no network'))
        config={'profile':ENDPOINT,'host':HOST,'port':443,'service':'publication','offer_sha256':self.f.offer.hash}
        remote=TicketRemote(config,ctx,dial=dial)
        for op,body in [('issue',{'pack':{},'transaction_hash':'0x'+'11'*32}),
            ('submit',{'ticket':self.f.tokens[0],'bundle_hash':'0x'+'11'*32,'aws_credentials':{}}),
            ('submit',{'ticket':dict(self.f.tokens[0],private_key='never send'),'bundle_hash':'0x'+'11'*32}),
            ('sign',{'message':'anything'}),('store',{'ticket':self.f.tokens[0],'bundle_hash':'0x'+'11'*32,'bundle_base64':'x'*100000})]:
            with self.assertRaises(Rejected):remote.call(op,body)
        dial.assert_not_called()
        self.assertFalse(hasattr(self.pub,'issuer'));self.assertFalse(hasattr(self.pay,'worker'))

    def test_alternate_payer_relay_adapter_recovers_canonical_tx_and_releases_unused_ticket(self):
        h,_=self.f.post();receipt=self.f.f.rpc.tx(self.f.f.accounts[2],cases.submission_data(h),self.f.contract)
        with self.channel(self.pub) as (remote,_):
            publisher=TicketPublisher(self.f.f.client,remote.submit,clock=lambda:self.f.f.now)
            result=TicketPublicRelay(publisher,self.f.index).submit(h)
        self.assertEqual(result,{'transaction_hash':receipt['transactionHash']})
        self.assertEqual(self.f.f.client.status()['available'],2)
        self.assertEqual(int(self.f.rpc.call('eth_getTransactionCount',self.f.signer.address,'latest'),16),0)

    def test_wrong_response_nonce_or_payload_leaves_pending_ticket_reserved(self):
        h,_=self.f.post()
        def change(reply):reply['request_id']='00'*16;return reply
        with self.channel(self.pub,mutate=change) as (remote,_):
            client=TicketPublisher(self.f.f.client,remote.submit,clock=lambda:self.f.f.now)
            with self.assertRaisesRegex(Rejected,'ticket-channel-correlation'):client.publish(h,True)
        self.assertEqual(self.f.f.client.status()['available'],1)
        with self.channel(self.pub) as (remote,_):
            client=TicketPublisher(self.f.f.client,remote.submit,clock=lambda:self.f.f.now)
            self.assertEqual(client.publish(h,True)['state'],'indexed')
        self.assertEqual(self.f.f.client.status()['available'],1)

    def test_backend_exception_is_fixed_error_and_does_not_clear_local_reservation(self):
        h,_=self.f.post()
        with patch.object(self.pub,'_operate',side_effect=RuntimeError('SYNTHETIC PRIVATE EXCEPTION TEXT')):
            with self.channel(self.pub) as (remote,_):
                client=TicketPublisher(self.f.f.client,remote.submit,clock=lambda:self.f.f.now)
                with self.assertRaises(Rejected) as result:client.publish(h,True)
                self.assertEqual(str(result.exception),'ticket-remote-unavailable')
        self.assertEqual(self.f.f.client.status()['available'],1)

    def test_endpoint_or_tls_policy_drift_rejected_without_sending_tickets(self):
        _,ctx=contexts();dial=Mock(side_effect=AssertionError('no network'))
        config={'profile':ENDPOINT,'host':HOST,'port':443,'service':'publication','offer_sha256':self.f.offer.hash}
        remote=TicketRemote(config,ctx,dial=dial);remote.approved['host']='changed.example'
        with self.assertRaises(Rejected):remote.submit(self.f.tokens[0],'0x'+'11'*32)
        remote=TicketRemote(config,ctx,dial=dial);ctx.check_hostname=False
        with self.assertRaises(Rejected):remote.submit(self.f.tokens[0],'0x'+'11'*32)
        dial.assert_not_called()

    def test_refund_cancellation_through_payment_tls_is_original_payer_authorized(self):
        req,_=self.f.f.paid();sig=self.f.f.refund_signature(req)
        with self.channel(self.pay) as (remote,_):
            result=remote.call('refund',{**req,'signature':sig});self.assertEqual(result['mode'],'refund')
            with self.assertRaises(Rejected):remote.issue(**req)


class FramingTests(unittest.TestCase):
    def test_oversized_zero_duplicate_or_noncanonical_frame_rejected(self):
        for data in (struct.pack('!I',MAX_REQUEST+1),struct.pack('!I',0),
            struct.pack('!I',13)+b'{"x":1,"x":2}',struct.pack('!I',8)+b'{"x": 1}'):
            left,right=socket.socketpair()
            try:
                left.sendall(data)
                with self.assertRaises(Rejected):receive(right,MAX_REQUEST,time.monotonic()+1)
            finally:left.close();right.close()

    def test_private_or_unknown_fields_do_not_reach_operation(self):
        value={'private_key':'never accepted'}
        with self.assertRaises(Rejected):validate_request(value,'ab'*32,'publication')


if __name__=='__main__':unittest.main()
