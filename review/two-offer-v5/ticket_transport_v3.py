"""Installer-pinned index-first publication channel; no new trust discovery."""
import base64,copy,time
from policy import require
from ticket_transport_v2 import TicketRemote,endpoint as old_endpoint,_connect,DEADLINE
from ticket_service_v3 import request

ENDPOINT='nockapp-index-first-publication-endpoint-v1'

def endpoint(value):
    require(type(value) is dict and set(value)=={'profile','host','connect_host','port','service','offer_sha256'}
        and value['profile']==ENDPOINT and value['service']=='publication','index-first-endpoint')
    base={k:v for k,v in value.items()if k!='connect_host'};base['profile']='nockapp-prepaid-service-endpoint-v2'
    old_endpoint(base);old_endpoint({**base,'host':value['connect_host']})
    return value

class PublicationRemoteV3(TicketRemote):
    _endpoint=staticmethod(endpoint)
    def __init__(self,approved,context,*,dial=None):
        super().__init__(approved,context,dial=self._route if dial is None else dial)
    def _route(self):
        value=self._endpoint(self.approved)
        return _connect({'host':value['connect_host'],'port':value['port']},time.monotonic()+DEADLINE)
    def _message(self,a,operation,body):return request(a['offer_sha256'],operation,body)
    @staticmethod
    def _raw(raw):
        require(type(raw) is bytes and 0<len(raw)<=65536,'index-first-content')
        return base64.b64encode(raw).decode('ascii')
    def submit_bundle(self,token,h,raw):
        return self.call('submit',{'ticket':token,'bundle_hash':h,'bundle_base64':self._raw(raw)})
    def store(self,h,raw):return self.call('store',{'bundle_hash':h,'bundle_base64':self._raw(raw)})
    def submit(self,*_):require(False,'index-first-exact-bytes-required')

class IndexedOrigin:
    def __init__(self,reader,remote):
        require(type(remote) is PublicationRemoteV3,'index-first-origin')
        self.reader,self.remote=reader,remote
    def get(self,h,limit):return self.reader.get(h,limit)
    def probe(self,h,limit):return self.reader.probe(h,limit)
    def put(self,h,raw):return self.remote.store(h,raw)
    def restore(self,h,raw):return self.remote.store(h,raw)

class IndexedRelay:
    def __init__(self,scopes,index,clock):self.scopes,self.index,self.clock=scopes,index,clock
    def submit_bundle(self,h,raw):
        from public_bundle_v5 import decode
        from ticket_publisher_v2 import TicketPublisher
        decode(raw,h);wallet,remote=self.scopes.select(h,int(self.clock()))
        require(type(remote) is PublicationRemoteV3,'index-first-scope-service')
        result=TicketPublisher(wallet,lambda token,bundle_hash:remote.submit_bundle(token,bundle_hash,raw),clock=self.clock).publish(h,True)
        if result['transaction_hash'] is not None:return {'transaction_hash':result['transaction_hash']}
        indexed=self.index.record_for_hash(h);require(indexed is not None,'index-first-canonical-unavailable')
        return {'transaction_hash':indexed['transaction_hash']}
