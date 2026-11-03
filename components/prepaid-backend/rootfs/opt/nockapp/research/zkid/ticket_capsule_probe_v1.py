"""Fixed synthetic release probe, never used for production initialization."""
import base64
import hashlib
import importlib
import os
import socket
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from authorship import AuthorshipNative
from aws_transport import AwsJsonClient
from base_protocol import keccak
from policy import require
from setup_aws_sdk import activate
from ticket_backend_boot_v1 import harden_process
from ticket_aws_credentials_v1 import tls_context
from ticket_native_v1 import TicketNative,TicketProtocol
from ticket_supervised_v2 import TcpSocket

def run(modules,ticket_path,ticket_sha256,author_path):
    harden_process()
    for name in modules:importlib.import_module(name.removesuffix('.py'))
    sdk=activate()
    fake={'access_key_id':'ASIA'+'A'*16,'secret_access_key':'A'*40,'session_token':'A'*32,'expires_at':int(time.time())+900}
    kms=AwsJsonClient('kms','ap-southeast-2',fake,tls_context())
    ddb=AwsJsonClient('dynamodb','ap-southeast-2',fake,tls_context())
    require('Decrypt' in kms._model.operation_names and 'TransactGetItems' in ddb._model.operation_names,'capsule-sdk-models')
    with socket.socket() as free:free.bind(('0.0.0.0',0));port=free.getsockname()[1]
    with TcpSocket({'listen':{'ip':'0.0.0.0','port':port}}) as listener:
        require(os.fstat(listener.fileno()).st_uid==os.getuid(),'capsule-service-socket-uid')
    require(keccak(b'')=='0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470','capsule-abi')
    native=AuthorshipNative(author_path);scope=[{'kind':'post','intent_sha256':'12'*32}]
    proof=native.call('prove',secret='01'+'00'*31,scopes=scope,context='34'*32)['proof']
    require(native.call('verify',proof=proof,scopes=scope,context='34'*32)=={'accepted':True}
        and native.call('verify',proof=proof,scopes=scope,context='35'*32)=={'accepted':False},'capsule-author')
    # Disposable synthetic key only, never written to a file or command line.
    key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    public=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    private=key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    ticket=TicketNative(ticket_path,ticket_sha256);parameters=hashlib.sha256(b'nockapp disposable capsule probe').digest()
    protocol=TicketProtocol(ticket,public,parameters);pending=protocol.prepare()
    signature=ticket._call('blind-sign',private_key=base64.b64encode(private).decode(),blinded=pending['request']['blinded'])['signature']
    token=protocol.finalize(pending,signature);require(len(protocol.verify(token))==64,'capsule-ticket')
    return {'ok':True,'profile':'nockapp-ticket-capsule-probe-v1','modules':len(modules),'sdk_files':len(sdk),
        'abi_keccak_checked':True,'author_binding_checked':True,'blind_ticket_checked':True,'sdk_models_loaded':True,
        'synthetic_only':True,'external_network_used':False,'tcp_socket_binding_checked':True,'production_ready':False}
