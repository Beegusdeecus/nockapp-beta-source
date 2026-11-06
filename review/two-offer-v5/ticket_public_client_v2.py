"""Desktop adapters: ordinary public reads, ticket-authenticated ingress/relay.

All objects/endpoints are installer-injected. No browser-supplied response can
release a ticket or supply an AWS credential. Uploading bytes alone never indexes.
"""
import time
from policy import require
from public_bundle_v5 import decode
from public_s3_v5 import S3PublicOrigin
from ticket_publisher_v2 import TicketPublisher
from ticket_transport_v2 import TicketRemote
from ticket_wallet_v1 import TicketWallet


class TicketPublicOrigin:
    def __init__(self,public_reader,remote,wallet,*,clock=None):
        require(isinstance(public_reader,S3PublicOrigin) and public_reader._source is None
            and public_reader._credentials is None and isinstance(remote,TicketRemote)
            and isinstance(wallet,TicketWallet) and remote.approved['service']=='publication'
            and remote.approved['offer_sha256']==wallet.offer.hash,'ticket-origin-configuration')
        self.reader,self.remote,self.wallet=public_reader,remote,wallet
        self.clock=clock or (lambda:int(time.time()))

    def get(self,digest,max_bytes):return self.reader.get(digest,max_bytes)

    def put(self,digest,data):
        decode(data,digest)
        token=self.wallet.reserve(digest,int(self.clock()))
        result=self.remote.store(token,digest,data)
        require(type(result) is dict and set(result)=={'bundle_hash','bytes','readback_checked','permanent_availability_proven'}
            and result['bundle_hash']==digest and result['bytes']==len(data)
            and result['readback_checked'] is True and result['permanent_availability_proven'] is False,'ticket-origin-response')
        return result


class TicketPublicRelay:
    def __init__(self,publisher,index):
        require(isinstance(publisher,TicketPublisher),'ticket-relay-configuration')
        require(index.contract==publisher.wallet.offer.terms['index_contract']
            and index.application==publisher.wallet.offer.terms['application'],'ticket-relay-context')
        self.publisher,self.index=publisher,index

    def submit(self,bundle_hash):
        # The desktop's publish consent and durable outbox precede this call.
        result=self.publisher.publish(bundle_hash,True)
        if result['transaction_hash'] is not None:return {'transaction_hash':result['transaction_hash']}
        # Another independent payer can finalize this exact hash before the
        # service consumes a ticket. Recover its genuine public transaction.
        indexed=self.index.record_for_hash(bundle_hash)
        require(indexed is not None,'ticket-relay-canonical-unavailable')
        return {'transaction_hash':indexed['transaction_hash']}
