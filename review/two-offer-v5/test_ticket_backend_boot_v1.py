"""Actual recovered keys/TLS/crypto/EVM; AWS resources are explicit fixtures."""
import base64
import copy
import ctypes
from dataclasses import asdict
from datetime import datetime,timedelta,timezone
import hashlib
import os
import resource
from pathlib import Path
import socket
import ssl
import threading
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from policy import canonical,Rejected
from ticket_backend_boot_v1 import PROFILE,PRIVATE,assemble,read_private,der_public
from ticket_backend_records_v1 import RoleRecords
from ticket_server_v1 import RoleServer,ServerLimits
from ticket_transport_v2 import TicketRemote,ENDPOINT
from ticket_refund_rpc_v1 import RefundRemote,ENDPOINT as REFUND_ENDPOINT
from ticket_service_v2 import PaymentApplication
from ticket_bindings_v1 import ConditionalS3Records
from public_s3_v5 import S3PublicOrigin,OriginStorageBudget,budget_scope
from public_storage_budget import RESOURCES
import test_ticket_refund_payout_v1 as refund
import test_ticket_publication_v2 as publication
from test_domain_authority import TransactionSDK
from test_aws_transport import credentials

HOST='tickets.example.test';ACCOUNT='419720240831'
def b64(raw):return base64.b64encode(raw).decode()
def private(key):return key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
def pin(value):return hashlib.sha256(canonical(value)).hexdigest()

def tls_identity(san=HOST,lifetime=timedelta(hours=1),eku=ExtendedKeyUsageOID.SERVER_AUTH):
    now=datetime.now(timezone.utc);rootkey=ec.generate_private_key(ec.SECP256R1());key=ec.generate_private_key(ec.SECP256R1())
    ca=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic backend root')])
    root=(x509.CertificateBuilder().subject_name(ca).issuer_name(ca).public_key(rootkey.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=2)).not_valid_after(now+timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
        .add_extension(x509.KeyUsage(True,False,False,False,False,True,True,None,None),True).sign(rootkey,hashes.SHA256()))
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,HOST)]))
        .issuer_name(ca).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+lifetime)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
        .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,None,None),True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]),False)
        .add_extension(x509.ExtendedKeyUsage([eku]),False).sign(rootkey,hashes.SHA256()))
    raw=root.public_bytes(serialization.Encoding.DER)
    return {'hostname':HOST,'root_certificate_der':b64(raw),'root_sha256':hashlib.sha256(raw).hexdigest(),
        'key_sha256':hashlib.sha256(der_public(key.public_key())).hexdigest()},key,cert,root

class RoutedS3:
    """In-memory resource routing, expected owner and bounded exact list model."""
    def __init__(self,clients):self.clients=clients;self.calls=[]
    def _client(self,op,args):
        assert args['ExpectedBucketOwner']==ACCOUNT
        self.calls.append((op,copy.copy(args)));return self.clients[args['Bucket']]
    def get_object(self,**args):return self._client('get',args).get_object(**args)
    def put_object(self,**args):return self._client('put',args).put_object(**args)
    def list_objects_v2(self,**args):
        client=self._client('list',args)
        if hasattr(client,'list_objects_v2'):return client.list_objects_v2(**args)
        with client.lock:
            if client.mode=='read':raise TimeoutError('synthetic denied/failed list')
            keys=sorted(k for k in client.records if k.startswith(args['Prefix']))
            return {'Contents':[{'Key':k,'Size':len(client.records[k])} for k in keys[:1]],'KeyCount':min(1,len(keys)),'IsTruncated':len(keys)>1}

class BootBase:
    def config(self,role,offer,key_bindings,records,transaction=None):
        tls,self.tlskey,self.cert,self.root=tls_identity()
        self.tls_public=tls
        return {'profile':PROFILE,'role':role,'offer':offer.manifest,'offer_sha256':offer.hash,
            'ticket_native_sha256':offer.protocol.native.sha256,'key_bindings':key_bindings,'records':{'account_id':ACCOUNT,'region':'ap-southeast-2',**records},
            'tls':tls,'server':asdict(ServerLimits(2,8,16,1,4,2)),**({'transaction':transaction} if transaction else {})}
    def body(self,cfg,service_key):
        return {'profile':PRIVATE,'role':cfg['role'],'config_sha256':pin(cfg),'service_key_der':b64(service_key),
            'tls_private_key_der':b64(private(self.tlskey)),'tls_certificate_der':b64(self.cert.public_bytes(serialization.Encoding.DER))}
    def boot(self,cfg,body,**kwargs):
        read,write=os.pipe()
        try:
            raw=canonical(body);self.assertLess(len(raw),8192);self.assertEqual(os.write(write,raw),len(raw));os.close(write);write=None
            return assemble(cfg,pin(cfg),read,**kwargs)
        finally:
            os.close(read)
            if write is not None:os.close(write)
    def scratch(self,base):
        p=Path(base)/('boot-'+str(self.counter));self.counter+=1;p.mkdir(mode=0o700);return p
    def serve(self,app,context,config,refund=False):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(4);address=listener.getsockname()
        server=RoleServer.from_config(app,context,listener,config,pin(config));stop=threading.Event();ready=threading.Event();result=[]
        thread=threading.Thread(target=lambda:result.append(server.run(stop,lambda _:ready.set())));thread.start()
        def cleanup():stop.set();thread.join(timeout=5);self.assertFalse(thread.is_alive())
        self.addCleanup(cleanup);self.assertTrue(ready.wait(3))
        client=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);client.minimum_version=ssl.TLSVersion.TLSv1_3
        client.load_verify_locations(cadata=self.root.public_bytes(serialization.Encoding.PEM).decode())
        endpoint={'profile':REFUND_ENDPOINT if refund else ENDPOINT,'host':HOST,'port':address[1],'service':app.service,'offer_sha256':app.offer.hash}
        if refund:endpoint['policy_sha256']=pin(app.worker.queue.vault)
        return (RefundRemote if refund else TicketRemote)(endpoint,client,dial=lambda:socket.create_connection(address,timeout=2))

class BackendBootTests(BootBase,unittest.TestCase):
    @classmethod
    def setUpClass(cls):refund.RefundTests.setUpClass()
    def setUp(self):
        self.f=refund.RefundTests();self.f.setUp();self.addCleanup(self.f.doCleanups);self.counter=0
        self.sdk=RoutedS3({'private-refund-lab':self.f.f.s3,'private-refund-snapshots':self.f.sdk})
        self.keys={'publication':self.f.f.accounts[7],'refund':self.f.signer.address}
        transaction={'limits':asdict(self.f.limits),'fee_policy':self.f.fees,'runtime_sha256':self.f.scope['runtime_sha256']}
        self.cfg=self.config('refund',self.f.offer,self.keys,{'purchase_bucket':'private-refund-lab','ledger_bucket':'private-refund-snapshots'},transaction)
        self.cfg.update(refund_vault=self.f.scope,refund_vault_sha256=self.f.scope_hash)
        self.packet=self.body(self.cfg,private(self.f.key.key))
    def arguments(self):
        return {'ticket_native':self.f.offer.protocol.native,'rpc':self.f.rpc,'s3':self.sdk,'scratch_directory':self.scratch(self.f.f.temp.name)}

    def test_existing_refund_key_and_managed_journal_restore_across_new_boots(self):
        self.f.authorize();app,ctx,server=self.boot(self.cfg,self.packet,**self.arguments());remote=self.serve(app,ctx,server,True)
        result=remote.call('submit',{'pack_hash':self.f.pack_hash,'signature':self.f.signature})
        if result.get('transaction_hash'):self.f.f.receipt(result['transaction_hash'])
        paid=remote.call('status',{'pack_hash':self.f.pack_hash});self.assertTrue(paid['payout_confirmed'])
        again,_,_=self.boot(self.cfg,self.packet,**self.arguments())
        same=again.worker.refund(self.f.pack_hash,self.f.signature);self.assertEqual(same,paid)
        with again.worker.queue._db() as db:self.assertEqual(db.execute('SELECT count(*) FROM submissions').fetchone()[0],1)
        self.assertEqual(again.worker.queue.signer.address,self.f.signer.address)

    def test_payment_boot_only_has_purchase_record_capabilities_and_imports_whole_pack(self):
        cfg=self.config('payment',self.f.offer,self.keys,{'purchase_bucket':'private-refund-lab'})
        packet=self.body(cfg,self.f.f.crypto.private)
        app,ctx,server=self.boot(cfg,packet,ticket_native=self.f.offer.protocol.native,rpc=self.f.rpc,s3=self.sdk)
        self.assertIsInstance(app,PaymentApplication);remote=self.serve(app,ctx,server)
        reply=remote.call('issue',self.f.request);self.f.f.client.receive(reply)
        self.assertEqual(self.f.f.client.status()['available'],self.f.offer.terms['pack_size'])
        self.assertTrue(all(args['Bucket']=='private-refund-lab' for _,args in self.sdk.calls))
        self.assertFalse(hasattr(app,'worker'))

    def test_bad_public_config_is_rejected_before_private_pipe_or_state_io(self):
        for change in [lambda v:v.update(role='payment'),lambda v:v.update(private_key='forbidden'),
            lambda v:v['key_bindings'].update(publication=v['key_bindings']['refund']),
            lambda v:v['server'].update(max_connections=True),lambda v:v['refund_vault'].update(authority=self.f.f.accounts[2])]:
            bad=copy.deepcopy(self.cfg);change(bad)
            with patch('ticket_backend_boot_v1.read_private',side_effect=AssertionError('must not read secrets')),self.assertRaises(Rejected):
                assemble(bad,pin(bad),-1,**self.arguments())
        self.assertEqual(self.sdk.calls,[])

    def test_wrong_role_key_tls_identity_and_extra_secrets_never_reach_journal(self):
        for change in [lambda b:b.update(role='payment'),lambda b:b.update(config_sha256='12'*32),
            lambda b:b.update(aws_secret_access_key='synthetic-forbidden'),lambda b:b.update(service_key_der=b['tls_private_key_der']),
            lambda b:b.update(tls_private_key_der=b['service_key_der']),lambda b:b.update(tls_certificate_der=self.cfg['tls']['root_certificate_der']),
            lambda b:b.update(service_key_der=b64(private(ec.generate_private_key(ec.SECP256K1()))))]:
            bad=copy.deepcopy(self.packet);change(bad)
            with self.assertRaisesRegex(Rejected,'ticket-backend-private-rejected'):self.boot(self.cfg,bad,**self.arguments())
        self.assertEqual(self.sdk.calls,[])

    def test_wrong_tls_hostname_usage_expiry_or_issuer_reject_before_journal_io(self):
        for options in [{'san':'other.example.test'},{'eku':ExtendedKeyUsageOID.CLIENT_AUTH},
            {'lifetime':timedelta(seconds=-10)},{'lifetime':timedelta(seconds=30)}]:
            tls,key,cert,_=tls_identity(**options);cfg=copy.deepcopy(self.cfg);cfg['tls']=tls
            packet={**self.packet,'config_sha256':pin(cfg),'tls_private_key_der':b64(private(key)),
                'tls_certificate_der':b64(cert.public_bytes(serialization.Encoding.DER))}
            with self.assertRaisesRegex(Rejected,'ticket-backend-private-rejected'):self.boot(cfg,packet,**self.arguments())
        other,_,_,_=tls_identity();cfg=copy.deepcopy(self.cfg)
        cfg['tls']['root_certificate_der']=other['root_certificate_der'];cfg['tls']['root_sha256']=other['root_sha256']
        with self.assertRaisesRegex(Rejected,'ticket-backend-private-rejected'):
            self.boot(cfg,{**self.packet,'config_sha256':pin(cfg)},**self.arguments())
        self.assertEqual(self.sdk.calls,[])

    def test_missing_managed_journal_is_not_initialized_or_replaced(self):
        self.f.sdk.records.clear();args=self.arguments()
        with self.assertRaisesRegex(Rejected,'transaction-journal-missing'):self.boot(self.cfg,self.packet,**args)
        self.assertFalse((args['scratch_directory']/'journal.sqlite').exists());self.assertFalse(any(op=='put' for op,_ in self.sdk.calls))

    def test_private_input_rejects_regular_files_and_noncanonical_bytes(self):
        path=Path(self.f.f.temp.name)/'synthetic-not-a-secret';path.write_bytes(b'{}')
        with path.open('rb') as stream,self.assertRaises(Rejected):read_private(stream.fileno())
        read,write=os.pipe()
        try:
            os.write(write,b'{ "x": 1 }');os.close(write);write=None
            with self.assertRaises(Rejected):read_private(read)
        finally:
            os.close(read)
            if write is not None:os.close(write)

    def test_process_hardening_precedes_private_key_input(self):
        import ticket_backend_boot_v1 as boot
        original=boot.read_private;checked=[]
        def guarded(fd):
            self.assertEqual(resource.getrlimit(resource.RLIMIT_CORE),(0,0))
            libc=ctypes.CDLL(None);self.assertEqual(libc.prctl(3,0,0,0,0),0)
            self.assertEqual(libc.prctl(39,0,0,0,0),1)
            checked.append(True);return original(fd)
        with patch.object(boot,'read_private',side_effect=guarded):self.boot(self.cfg,self.packet,**self.arguments())
        self.assertEqual(checked,[True])
        with patch.object(boot,'harden_process',side_effect=Rejected('ticket-backend-process')),\
            patch.object(boot,'read_private',side_effect=AssertionError('must not consume secret')):
            with self.assertRaisesRegex(Rejected,'ticket-backend-process'):self.boot(self.cfg,self.packet,**self.arguments())

    def test_role_records_deny_foreign_keys_owner_versions_and_unconditional_writes(self):
        prefix='ticket-purchases-v1/'+self.f.offer.hash+'/decisions/';key=prefix+'ab'*32+'.json'
        records=RoleRecords(self.sdk,ACCOUNT,{('private-refund-lab',prefix):('decisions',False)})
        for args in [{'Bucket':'foreign-bucket','Key':key},{'Bucket':'private-refund-lab','Key':key,'VersionId':'old'},
            {'Bucket':'private-refund-lab','Key':key,'ExpectedBucketOwner':'123456789012'},
            {'Bucket':'private-refund-lab','Key':prefix+'../other'}]:
            with self.assertRaises(Rejected):records.get_object(**args)
        with self.assertRaises(Rejected):records.list_objects_v2(Bucket='private-refund-lab',Prefix=prefix,MaxKeys=1000)
        with self.assertRaises(Rejected):records.put_object(Bucket='private-refund-lab',Key=key,Body=b'{}')
        writable=RoleRecords(self.sdk,ACCOUNT,{('private-refund-lab',prefix):('decisions',True)})
        good={'Bucket':'private-refund-lab','Key':key,'Body':b'{}','ContentType':'application/json','IfNoneMatch':'*',
            'ServerSideEncryption':'AES256','ChecksumSHA256':b64(hashlib.sha256(b'{}').digest())}
        for delta in [{'IfNoneMatch':None},{'ChecksumSHA256':'AA=='},{'ServerSideEncryption':'aws:kms'},{'ACL':'public-read'},{'Body':b'x'*2049}]:
            with self.assertRaises(Rejected):writable.put_object(**{**good,**delta})
        self.assertEqual(self.sdk.calls,[])

    def test_exact_key_absence_denial_and_lost_write_reply_remain_distinct(self):
        prefix='ticket-purchases-v1/'+self.f.offer.hash+'/results/'
        capability=RoleRecords(self.sdk,ACCOUNT,{('private-refund-lab',prefix):('results',True)})
        records=ConditionalS3Records(capability,'private-refund-lab',prefix,32768)
        self.assertIsNone(records.read('ab'*32))
        self.f.f.s3.mode='read'
        with self.assertRaises(Rejected):records.read('ab'*32)
        self.f.f.s3.mode='after';before=len(self.f.f.s3.puts)
        self.assertEqual(records.create('ab'*32,b'{}'),b'{}');self.assertEqual(len(self.f.f.s3.puts),before+1)

class PublicationBootTests(BootBase,unittest.TestCase):
    @classmethod
    def setUpClass(cls):publication.PublicationTests.setUpClass()
    def setUp(self):
        self.f=publication.PublicationTests();self.f.setUp();self.addCleanup(self.f.doCleanups);self.counter=0
        self.sdk=RoutedS3({'lab-private-snapshots':self.f.sdk})
        self.resources={k:10**9 for k in RESOURCES};self.resources['retained_byte_seconds']=10**12
        retention=90*86400;bucket='public-boot-fixture';region='ap-southeast-2'
        scope=budget_scope(region,bucket,ACCOUNT,self.resources,retention)
        budget=OriginStorageBudget(TransactionSDK(),'synthetic-table','ab'*32,scope,self.resources,retention)
        context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.origin=S3PublicOrigin(region,bucket,ACCOUNT,context,credentials=credentials(),budget=budget)
        # Public HTTP/storage is replaced by the explicit in-memory fixture;
        # production constructor and exact public/budget pins remain enforced.
        self.origin.get=self.f.origin.get;self.origin.put=self.f.origin.put
        keys={'publication':self.f.signer.address,'refund':self.f.f.accounts[7]}
        runtime=self.f.f.rpc.call('eth_getCode',self.f.contract,'latest')
        self.cfg=self.config('publication',self.f.offer,keys,{'ledger_bucket':'lab-private-snapshots'},
            {'limits':asdict(self.f.limits),'fee_policy':self.f.policy,'runtime_sha256':hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest()})
        self.cfg.update(author_native_sha256=self.f.author.sha256,origin={'region':region,'bucket':bucket,'account_id':ACCOUNT,
            'retention_seconds':retention,'budget_limits':self.resources,'budget_scope':scope,
            'budget_table_arn':'arn:aws:dynamodb:'+region+':'+ACCOUNT+':table/synthetic-table','budget_namespace':'ab'*32})
        self.packet=self.body(self.cfg,private(self.f.key.key))
    def arguments(self):return {'ticket_native':self.f.offer.protocol.native,'rpc':self.f.rpc,'s3':self.sdk,
        'scratch_directory':self.scratch(self.f.f.temp.name),'origin':self.origin,'author_native':self.f.author}
    def test_publication_boot_restores_same_gas_key_and_can_publish_over_actual_tls(self):
        app,ctx,server=self.boot(self.cfg,self.packet,**self.arguments());remote=self.serve(app,ctx,server)
        h,_=self.f.post();body={'ticket':self.f.tokens[0],'bundle_hash':h};first=remote.call('submit',body)
        if first['transaction_hash']:self.f.f.receipt(first['transaction_hash'])
        self.assertEqual(remote.call('submit',body)['state'],'indexed')
        restored,_,_=self.boot(self.cfg,self.packet,**self.arguments())
        self.assertEqual(restored.worker.submit(**{'token':body['ticket'],'bundle_hash':h})['state'],'indexed')
        self.assertEqual(restored.worker.queue.signer.address,self.f.signer.address)
        self.assertTrue(all(args['Bucket']=='lab-private-snapshots' for _,args in self.sdk.calls))
    def test_wrong_public_origin_or_author_pin_reject_before_private_input(self):
        for field in ('origin','author_native_sha256','budget_table_arn','budget_namespace'):
            bad=copy.deepcopy(self.cfg)
            if field=='origin':bad['origin']['bucket']='other-public-origin';bad['origin']['budget_scope']=budget_scope(
                bad['origin']['region'],bad['origin']['bucket'],ACCOUNT,self.resources,bad['origin']['retention_seconds'])
            elif field=='author_native_sha256':bad[field]='12'*32
            elif field=='budget_table_arn':bad['origin'][field]=bad['origin'][field].replace('synthetic-table','other-table')
            else:bad['origin'][field]='12'*32
            with patch('ticket_backend_boot_v1.read_private',side_effect=AssertionError('not admitted')),self.assertRaises(Rejected):
                assemble(bad,pin(bad),-1,**self.arguments())
        self.assertEqual(self.sdk.calls,[])
