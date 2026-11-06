"""Pinned role assembly from existing keys over a private pipe; no initializer.

Authenticated AWS/RPC/public-origin resources must be supplied by the launcher.
This is not an executable deployment, credential provider or OS isolation claim.
"""
import copy
import ctypes
import fcntl
import hashlib
import os
from pathlib import Path
import re
import resource
import select
import ssl
import stat
import time
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from authorship import AuthorshipNative
from base_fees import policy as fee_policy
from base_protocol import ReceiptKey
from base_transactions import Limits,ProtectedSigner
from permissionless_index import PublicIndexReader
from policy import canonical,require,strict_json,Rejected
from public_content_v5 import PublicContent
from public_reader_v5 import PublicDiscussionReader
from public_s3_v5 import S3PublicOrigin,budget_scope
from ticket_backend_records_v1 import RoleRecords
from ticket_bindings_v1 import ConditionalS3Records
from ticket_issuance_v1 import PaidTicketIssuer
from ticket_journal_v2 import ImmutableS3JournalAnchor
from ticket_native_v1 import TicketNative,_decode
from ticket_offer_v1 import TicketOffer,OFFER_V2,hex_value,manifest_hash,terms,configured_manifest_hash,configured_offer,configured_payments
from ticket_payment_v1 import FinalizedTicketPayment
from ticket_publication_queue_v2 import TicketPublicationQueue,PROFILE as LEDGER
from ticket_publication_v2 import TicketPublicationWorker
from ticket_refund_payout_v1 import RefundQueue,RefundWorker,namespace as refund_namespace
from ticket_refund_vault_v1 import scope_manifest
from ticket_refund_service_v1 import RefundApplication
from ticket_server_v1 import ServerLimits,PROFILE as SERVER
from ticket_service_v2 import PaymentApplication,PublicationApplication

PROFILE='nockapp-ticket-backend-boot-v1'
PROFILE_BATCH='nockapp-ticket-backend-boot-v2'
PRIVATE='nockapp-ticket-backend-private-boot-v1'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):require(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) and int(v,16)>0,'ticket-backend-pin')
def der_public(key):return key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)

def validate(value,pin):
    require(type(value) is dict and value.get('role') in ('payment','publication','refund'),'ticket-backend-role')
    role=value['role'];extra=({'transaction','origin','author_native_sha256'} if role=='publication' else {'transaction','refund_vault','refund_vault_sha256'} if role=='refund' else set())
    require(set(value)=={'profile','role','offer','offer_sha256','ticket_native_sha256','key_bindings','records','tls','server'}|extra
        and value['profile'] in (PROFILE,PROFILE_BATCH) and type(pin) is str and sha(canonical(value))==pin,'ticket-backend-config')
    digest(pin);digest(value['ticket_native_sha256'])
    manifest=value['offer']
    if value['profile']==PROFILE_BATCH:
        require(configured_manifest_hash(manifest)==value['offer_sha256']
            and manifest['terms']['profile']=='nockapp-public-prepaid-batch-offer-v3','ticket-backend-offer')
    else:
        require(manifest_hash(manifest)==value['offer_sha256'],'ticket-backend-offer')
        terms(manifest['terms']);require(manifest['terms']['profile']==OFFER_V2,'ticket-backend-offer')
    keys=value['key_bindings'];require(type(keys) is dict and set(keys)=={'publication','refund'},'ticket-backend-key-bindings')
    for key in keys.values():hex_value(key,20)
    require(keys['publication']!=keys['refund'],'ticket-backend-key-reuse')
    r=value['records'];fields={'account_id','region'}|({'purchase_bucket'} if role=='payment' else {'ledger_bucket'} if role=='publication' else {'purchase_bucket','ledger_bucket'})
    require(type(r) is dict and set(r)==fields and type(r['account_id']) is str and re.fullmatch('[0-9]{12}',r['account_id']),'ticket-backend-records')
    require(type(r['region']) is str and re.fullmatch(r'[a-z]{2}-[a-z]+-[1-9]',r['region']),'ticket-backend-records')
    for k in fields-{'account_id','region'}:
        require(type(r[k]) is str and re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',r[k]),'ticket-backend-records')
    tls=value['tls'];require(type(tls) is dict and set(tls)=={'hostname','root_certificate_der','root_sha256','key_sha256'},'ticket-backend-tls')
    require(type(tls['hostname']) is str and len(tls['hostname'])<=253 and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}',tls['hostname']),'ticket-backend-tls')
    digest(tls['key_sha256']);digest(tls['root_sha256']);root=_decode(tls['root_certificate_der'],8192)
    require(sha(root)==tls['root_sha256'],'ticket-backend-tls-root')
    cert=x509.load_der_x509_certificate(root)
    now=time.time()
    require(cert.public_bytes(serialization.Encoding.DER)==root and cert.version==x509.Version.v3
        and cert.signature_hash_algorithm.name in ('sha256','sha384','sha512')
        and isinstance(cert.public_key(),ec.EllipticCurvePublicKey) and isinstance(cert.public_key().curve,ec.SECP256R1)
        and cert.not_valid_before_utc.timestamp()<=now<now+60<cert.not_valid_after_utc.timestamp()
        and cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        and cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign,'ticket-backend-tls-root')
    cert.verify_directly_issued_by(cert)
    server=value['server'];require(type(server) is dict and set(server)==set(ServerLimits.__dataclass_fields__),'ticket-backend-server')
    ServerLimits(**server).validate()
    if role!='payment':
        t=value['transaction'];require(type(t) is dict and set(t)=={'limits','fee_policy','runtime_sha256'},'ticket-backend-transaction')
        require(type(t['limits']) is dict and set(t['limits'])==set(Limits.__dataclass_fields__),'ticket-backend-transaction')
        Limits(**t['limits']).validate();fee_policy(t['fee_policy']);digest(t['runtime_sha256'])
    if role=='refund':
        scope_manifest(value['refund_vault'],manifest,value['offer_sha256'],value['refund_vault_sha256'])
        require(value['refund_vault']['authority']==keys['refund'] and value['transaction']['runtime_sha256']==value['refund_vault']['runtime_sha256'],'ticket-backend-refund')
    if role=='publication':
        digest(value['author_native_sha256']);o=value['origin']
        require(type(o) is dict and set(o)=={'region','bucket','account_id','retention_seconds','budget_limits','budget_scope','budget_table_arn','budget_namespace'}
            and o['account_id']==r['account_id'] and o['bucket']!=r['ledger_bucket'],'ticket-backend-origin')
        digest(o['budget_namespace'])
        require(type(o['budget_table_arn']) is str and re.fullmatch(re.escape('arn:aws:dynamodb:'+r['region']+':'+r['account_id']+':table/')+r'[A-Za-z0-9_.-]{3,255}',o['budget_table_arn']),'ticket-backend-origin-budget')
        require(budget_scope(o['region'],o['bucket'],o['account_id'],o['budget_limits'],o['retention_seconds'])==o['budget_scope'],'ticket-backend-origin')
    return copy.deepcopy(value)

def read_private(fd):
    require(type(fd) is int and fd>=0 and (stat.S_ISFIFO(os.fstat(fd).st_mode) or stat.S_ISSOCK(os.fstat(fd).st_mode)),'ticket-backend-private-pipe')
    raw=bytearray();end=time.monotonic()+10
    while len(raw)<=65536:
        left=end-time.monotonic();require(left>0 and select.select([fd],[],[],left)[0],'ticket-backend-private-timeout')
        part=os.read(fd,min(8192,65537-len(raw)))
        if not part:break
        raw.extend(part)
    value=strict_json(bytes(raw),max_bytes=65536)
    require(canonical(value)==bytes(raw),'ticket-backend-private-encoding');return value

def private_key(value):
    raw=_decode(value,4096);key=serialization.load_der_private_key(raw,password=None)
    require(raw==key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),'ticket-backend-key-encoding')
    return raw,key

def harden_process():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    libc=ctypes.CDLL(None,use_errno=True)
    require(libc.prctl(4,0,0,0,0)==0 and libc.prctl(38,1,0,0,0)==0,'ticket-backend-process')

def tls_context(config,body):
    _,key=private_key(body['tls_private_key_der'])
    require(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256R1)
        and sha(der_public(key.public_key()))==config['tls']['key_sha256'],'ticket-backend-tls-key')
    leaf_raw=_decode(body['tls_certificate_der'],8192);cert=x509.load_der_x509_certificate(leaf_raw)
    root_raw=_decode(config['tls']['root_certificate_der'],8192);root=x509.load_der_x509_certificate(root_raw)
    require(cert.public_bytes(serialization.Encoding.DER)==leaf_raw and cert.version==x509.Version.v3
        and cert.public_key()==key.public_key() and cert.signature_hash_algorithm.name in ('sha256','sha384','sha512')
        and not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        and cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
        and list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)==[x509.DNSName(config['tls']['hostname'])]
        and list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)==[ExtendedKeyUsageOID.SERVER_AUTH],'ticket-backend-tls-leaf')
    cert.verify_directly_issued_by(root);now=time.time()
    require(root.not_valid_before_utc.timestamp()<=cert.not_valid_before_utc.timestamp()<=now
        and now+60<cert.not_valid_after_utc.timestamp()<=root.not_valid_after_utc.timestamp(),'ticket-backend-tls-lifetime')
    # Anonymous sealed memfd only: ssl has no in-memory private-key loader.
    payload=cert.public_bytes(serialization.Encoding.PEM)+root.public_bytes(serialization.Encoding.PEM)+key.private_bytes(
        serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    fd=os.memfd_create('nockapp-role-tls',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(fd,0o400);require(os.write(fd,payload)==len(payload),'ticket-backend-tls-memory')
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3
        context.num_tickets=0;context.load_cert_chain('/proc/self/fd/'+str(fd));return context
    finally:os.close(fd)

def assemble(value,pin,descriptor,*,ticket_native,rpc,s3,scratch_directory=None,origin=None,author_native=None,publication_budget_upgrade=None,publication_protocol=2,offer_overlay=None):
    """Internal launcher API. Supplied resources are never browser parameters."""
    cfg=validate(value,pin) # Public admission BEFORE consuming any secret.
    require(type(publication_protocol) is int and publication_protocol in (2,3)
        and (publication_protocol==2 or cfg['role']=='publication'),'ticket-publication-protocol')
    additional=None
    if offer_overlay is not None:
        from ticket_offer_overlay_v1 import validate as overlay_validate
        require(type(offer_overlay)is dict and set(offer_overlay)=={'plan','sha256'}
            and (cfg['role']!='publication'or publication_protocol==3),'ticket-overlay-assembly')
        plan=overlay_validate(offer_overlay['plan'],offer_overlay['sha256'],cfg,pin)
        additional=configured_offer(plan['offer'],plan['offer_sha256'],ticket_native)
    if publication_budget_upgrade is not None:
        from ticket_budget_upgrade_v1 import validate as validate_budget
        require(type(publication_budget_upgrade) is dict and set(publication_budget_upgrade)=={'plan','sha256'},'ticket-budget-envelope')
        validate_budget(publication_budget_upgrade['plan'],publication_budget_upgrade['sha256'],cfg)
    require(isinstance(ticket_native,TicketNative) and ticket_native.sha256==cfg['ticket_native_sha256'],'ticket-backend-native')
    offer=configured_offer(cfg['offer'],cfg['offer_sha256'],ticket_native);role=cfg['role'];r=cfg['records']
    if role=='publication':
        o=cfg['origin']
        require(isinstance(origin,S3PublicOrigin) and origin.region==o['region'] and origin.account_id==o['account_id']
            and origin.host==o['bucket']+'.s3.'+o['region']+'.amazonaws.com'
            and origin.retention_seconds==o['retention_seconds'] and origin.budget is not None
            and origin.budget.context==o['budget_scope'] and origin.budget.limits==o['budget_limits']
            and origin.budget.table==o['budget_table_arn'].split(':table/',1)[1] and origin.budget.namespace==o['budget_namespace']
            and (origin._source is not None or origin._credentials is not None),'ticket-backend-origin')
        require(isinstance(author_native,AuthorshipNative) and author_native.sha256==cfg['author_native_sha256'],'ticket-backend-author')
    else:require(origin is None and author_native is None,'ticket-backend-role-resources')
    if role!='payment':
        require(isinstance(scratch_directory,(str,Path)),'ticket-backend-scratch')
        path=Path(scratch_directory)
        require(path.is_absolute() and '..' not in path.parts and not any(p.startswith('.env') for p in path.parts)
            and not any(p.is_symlink() for p in (path,*path.parents)) and path.is_dir(),'ticket-backend-scratch')
        info=path.stat();require(info.st_uid==os.getuid() and not info.st_mode&0o077 and not (path/'journal.sqlite').exists(),'ticket-backend-scratch')
    else:require(scratch_directory is None,'ticket-backend-role-resources')
    harden_process() # Linux: disable dumps and privilege escalation BEFORE keys.
    body=read_private(descriptor)
    try:
        require(type(body) is dict and set(body)=={'profile','role','config_sha256','service_key_der','tls_private_key_der','tls_certificate_der'}
            and body['profile']==PRIVATE and body['role']==role and body['config_sha256']==pin,'ticket-backend-private-scope')
        raw,key=private_key(body['service_key_der']);context=tls_context(cfg,body)
        if role=='payment':
            require(isinstance(key,rsa.RSAPrivateKey) and der_public(key.public_key())==_decode(offer.terms['ticket_spki'],1024),'ticket-backend-payment-key')
        else:
            require(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256K1),'ticket-backend-gas-key')
            receipt=ReceiptKey(rpc,key);require(receipt.address==cfg['key_bindings'][role],'ticket-backend-gas-key')
    except Exception:raise Rejected('ticket-backend-private-rejected') from None
    scopes={};prefix='ticket-purchases-v1/'+offer.hash+'/'
    if role in ('payment','refund'):scopes[(r['purchase_bucket'],prefix+'decisions/')]=('decisions',role=='payment')
    if role=='payment':scopes[(r['purchase_bucket'],prefix+'results/')]=('results',True)
    else:
        ns=(hashlib.sha256(('84532:'+receipt.address+':'+LEDGER).encode()).hexdigest() if role=='publication' else refund_namespace(receipt.address))
        scopes[(r['ledger_bucket'],'ticket-publication-ledger-v2/'+ns+'/')]=('snapshot',True)
    if role in('payment','refund')and additional is not None:
        extra_prefix='ticket-purchases-v1/'+additional.hash+'/'
        scopes[(r['purchase_bucket'],extra_prefix+'decisions/')]=('decisions',role=='payment')
        if role=='payment':scopes[(r['purchase_bucket'],extra_prefix+'results/')]=('results',True)
    records=RoleRecords(s3,r['account_id'],scopes)
    if role=='payment':
        decisions=ConditionalS3Records(records,r['purchase_bucket'],prefix+'decisions/',2048)
        results=ConditionalS3Records(records,r['purchase_bucket'],prefix+'results/',32768)
        app=PaymentApplication(PaidTicketIssuer(offer,configured_payments(rpc,offer),decisions,results,raw))
    else:
        anchor=ImmutableS3JournalAnchor(records,r['ledger_bucket'],ns,account_id=r['account_id'])
        signer=ProtectedSigner(rpc,receipt);t=cfg['transaction'];limits=Limits(**t['limits'])
        if role=='refund':
            if additional is None:
                queue=RefundQueue(rpc,signer,path/'journal.sqlite',offer,cfg['refund_vault'],limits,
                    expected_hash=cfg['refund_vault_sha256'],anchor=anchor,fee_policy=t['fee_policy'])
            else:
                from ticket_refund_scope_upgrade_v2 import resume as refund_resume
                queue=refund_resume(rpc,signer,path/'journal.sqlite',cfg,pin,plan,offer_overlay['sha256'],
                    native=ticket_native,anchor=anchor)
            app=RefundApplication(RefundWorker(offer,configured_payments(rpc,offer),
                ConditionalS3Records(records,r['purchase_bucket'],prefix+'decisions/',2048),
                queue if additional is None else queue.view(offer.hash)))
        else:
            index=PublicIndexReader(rpc,offer.terms['index_contract'],offer.terms['application'],runtime_hash=offer.terms['index_runtime_keccak'])
            if publication_budget_upgrade is None:
                queue=TicketPublicationQueue(rpc,signer,path/'journal.sqlite',index.contract,index.application,limits,
                    code_hashes={index.contract:t['runtime_sha256']},anchor=anchor,fee_policy=t['fee_policy'])
            else:
                from ticket_budget_upgrade_v1 import resume
                queue=resume(rpc,signer,path/'journal.sqlite',cfg,publication_budget_upgrade['plan'],publication_budget_upgrade['sha256'],anchor=anchor)
            content=PublicContent(origin);reader=PublicDiscussionReader(index,content,author_native)
            if publication_protocol==3:
                from ticket_publication_v3 import IndexFirstPublicationWorker
                from ticket_service_v3 import PublicationApplicationV3
                app=PublicationApplicationV3(IndexFirstPublicationWorker(offer,queue,index,content,author_native,resolve_original=reader.resolve_original))
            else:app=PublicationApplication(TicketPublicationWorker(offer,queue,index,content,author_native,resolve_original=reader.resolve_original))
    if additional is not None:
        from ticket_scope_apps_v1 import ScopedPaymentApplication,ScopedPublicationApplication,ScopedRefundApplication
        if role=='payment':
            extra_prefix='ticket-purchases-v1/'+additional.hash+'/'
            extra=PaymentApplication(PaidTicketIssuer(additional,configured_payments(rpc,additional),
                ConditionalS3Records(records,r['purchase_bucket'],extra_prefix+'decisions/',2048),
                ConditionalS3Records(records,r['purchase_bucket'],extra_prefix+'results/',32768),raw))
            app=ScopedPaymentApplication(app,extra)
        elif role=='publication':
            w=app.worker
            extra=PublicationApplicationV3(IndexFirstPublicationWorker(additional,w.queue,w.index,w.content,
                w.native,resolve_original=w.resolve_original))
            app=ScopedPublicationApplication(app,extra)
        else:
            extra_prefix='ticket-purchases-v1/'+additional.hash+'/'
            extra=RefundApplication(RefundWorker(additional,configured_payments(rpc,additional),
                ConditionalS3Records(records,r['purchase_bucket'],extra_prefix+'decisions/',2048),
                queue.view(additional.hash)))
            app=ScopedRefundApplication(app,extra)
    server={'profile':SERVER,'service':role,'offer_sha256':offer.hash,'limits':cfg['server']}
    if additional is not None:
        from ticket_server_v1 import SCOPED_PROFILE
        server.update(profile=SCOPED_PROFILE,scope_sha256=app.scope_sha256)
    return app,context,server
