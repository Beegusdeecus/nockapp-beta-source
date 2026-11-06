"""Actual TLS1.3/role server with synthetic storage, real signatures and EVM."""
import socket,threading,unittest
from unittest.mock import patch
from policy import Rejected
from ticket_server_v1 import RoleServer,ServerLimits
from ticket_transport_v3 import PublicationRemoteV3,ENDPOINT
from ticket_service_v3 import PublicationApplicationV3
from test_ticket_transport_v2 import contexts,HOST
import test_ticket_publication_v3 as fixture


class ChannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixture.IndexFirstTests.setUpClass()
    def setUp(self):
        self.f=fixture.IndexFirstTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        server,client=contexts();listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(4)
        self.addCleanup(listener.close)
        self.server=RoleServer(PublicationApplicationV3(self.f.worker),server,listener,ServerLimits(2,8,16,1,4,2))
        stop=threading.Event();ready=threading.Event();errors=[]
        def serve():
            try:self.server.run(stop,lambda _:ready.set())
            except Exception as e:errors.append(type(e).__name__)
        thread=threading.Thread(target=serve);thread.start()
        def cleanup():
            stop.set();thread.join(timeout=5);self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
        self.addCleanup(cleanup);self.assertTrue(ready.wait(3))
        approved={'profile':ENDPOINT,'host':HOST,'connect_host':'public-route.example.test','port':443,
            'service':'publication','offer_sha256':self.f.f.offer.hash}
        self.remote=PublicationRemoteV3(approved,client,dial=lambda:socket.create_connection(listener.getsockname(),timeout=2))

    def test_wire_requires_raw_bytes_for_admission_and_repair_never_needs_a_ticket(self):
        h,raw=self.f.post()
        with self.assertRaises(Rejected):self.remote.store(h,raw)
        result=self.remote.submit_bundle(self.f.f.tokens[0],h,raw)
        for _ in range(3):
            if result['state']=='indexed':break
            result=self.remote.submit_bundle(self.f.f.tokens[0],h,raw)
        self.assertEqual(result['state'],'indexed');self.assertEqual(self.f.f.origin.puts,0)
        stored=self.remote.store(h,raw);self.assertTrue(stored['readback_checked'])
        self.assertEqual(self.f.f.origin.objects[h],raw)
        with self.assertRaises(Rejected):self.remote.submit(self.f.f.tokens[1],h)

    def test_changed_scope_or_route_is_rejected_before_dial(self):
        self.remote.approved['connect_host']='changed.example.test'
        with patch.object(self.remote,'_dial',side_effect=AssertionError('no dial after changed pin')):
            with self.assertRaises(Rejected):self.remote.store('0x'+'ab'*32,b'{}')
