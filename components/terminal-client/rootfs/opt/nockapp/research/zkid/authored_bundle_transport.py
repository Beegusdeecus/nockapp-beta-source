"""Fresh pinned AWS attestation and TLS1.3 for the authored v4 service.

Independent installer approval fixes PCRs/code, issuer and publication/storage
policy. Public proof/content retrieval is independently checked by BundleReader.
Attestation receipts do not prove permanent storage availability.
"""
import base64
import copy
import hashlib
import secrets
import socket
import time

from base_transport import BaseRemote
from authored_bundle_service import RPC,MAX_REQUEST,MAX_RESPONSE,identity,validate_request
from count_policy import POLICY_HASH as COUNT_POLICY
from domain_transport import (channel_identity,connect_endpoint,validate_endpoint,_aws_document,
    _decode,_timeout,receive,send,ENVELOPE_LIMIT)
from domain_trust import certificate_key,validate_approval as issuer_approval
from policy import POLICY_HASH,Rejected,digest,hex_string,require
from trust import verify_aws_document,validate_pcrs,pinned_channel_context

ENROLLMENT='nockapp-bundle-aws-enrollment-v4'
APPROVAL='nockapp-bundle-service-approval-v4'
ENDPOINT='nockapp-bundle-service-endpoint-v4'
HOSTNAME='authored-bundle-service.nockapp.local'
CHAIN_ID=84532
DEADLINE=30


def validate_approval(value):
    require(type(value) is dict and set(value)=={'profile','identity','endpoint','code_identity',
        'state_authority_sha256','pcrs'} and value['profile']==APPROVAL,'bundle-approval')
    expected=identity(value['identity']);require(expected['chain_id']==CHAIN_ID,'bundle-chain-identity')
    validate_endpoint(value['endpoint'],profile=ENDPOINT)
    issuer_approval({'mode':'production','definition_hash':expected['definition_hash'],
        'code_identity':value['code_identity'],'state_authority_sha256':value['state_authority_sha256'],
        'pcrs':value['pcrs']})
    return value


def binding(expected,certificate,code,authority):
    identity(expected);certificate_key(certificate);hex_string(code,64);hex_string(authority,64)
    require(any(bytes.fromhex(code)) and any(bytes.fromhex(authority)),'bundle-service-binding')
    return {'profile':ENROLLMENT,'rpc':RPC,'identity':copy.deepcopy(expected),'policy':POLICY_HASH,
        'count_policy':COUNT_POLICY if expected['count_native_sha256'] is not None else None,
        'code_identity':code,'state_authority_sha256':authority,
        'certificate_sha256':hashlib.sha256(certificate).hexdigest()}


def enroll(document,nonce,certificate,approved):
    validate_approval(approved);hex_string(nonce,64)
    expected=binding(approved['identity'],certificate,approved['code_identity'],approved['state_authority_sha256'])
    require(type(document) is bytes and 0<len(document)<=32768,'bundle-document')
    now=int(time.time()*1000);payload=verify_aws_document(document,now)
    require(payload.get('nonce')==bytes.fromhex(nonce) and payload.get('public_key')==certificate_key(certificate)
        and payload.get('user_data')==bytes.fromhex(digest(expected)),'bundle-quote-binding')
    require(type(payload.get('timestamp')) is int and now-120000<=payload['timestamp']<=now+5000,'bundle-quote-stale')
    validate_pcrs(payload['pcrs'],approved['pcrs']);return expected


def serve_connection(raw,application,code,authority):
    secure=None;deadline=time.monotonic()+DEADLINE
    try:
        hello=receive(raw,256,deadline)
        require(type(hello) is dict and set(hello)=={'profile','nonce'}
            and hello['profile']==ENROLLMENT,'bundle-hello');hex_string(hello['nonce'],64)
        context,certificate=channel_identity(hostname=HOSTNAME)
        bind=binding(application.identity,certificate,code,authority)
        document=_aws_document(hello['nonce'],bind,certificate)
        send(raw,{'profile':ENROLLMENT,'certificate':base64.b64encode(certificate).decode(),
            'document':base64.b64encode(document).decode()},ENVELOPE_LIMIT,deadline)
        _timeout(raw,deadline);secure=context.wrap_socket(raw,server_side=True)
        message=receive(secure,MAX_REQUEST+256,deadline)
        require(type(message) is dict and set(message)=={'enrollment_sha256','request'}
            and message['enrollment_sha256']==digest(bind),'bundle-channel-confirmation')
        validate_request(message['request'])
        send(secure,application.dispatch(message['request']),MAX_RESPONSE,deadline)
    except Exception:pass
    finally:
        if secure is not None:secure.close()
        raw.close()


class AuthoredBundleRemote(BaseRemote):
    # Reuse only the public registry and handle-only witness projection methods.
    def __init__(self,approved,*,dial=None):
        self.approved=copy.deepcopy(validate_approval(approved));self._dial=dial

    def call(self,operation,body):
        raw=secure=None;deadline=time.monotonic()+DEADLINE
        try:
            approved=self.approved
            message={'profile':RPC,'id':secrets.token_hex(16),'operation':operation,'body':copy.deepcopy(body)}
            validate_request(message)
            raw=self._dial() if self._dial is not None else connect_endpoint(approved['endpoint'],profile=ENDPOINT)
            nonce=secrets.token_hex(32);send(raw,{'profile':ENROLLMENT,'nonce':nonce},256,deadline)
            envelope=receive(raw,ENVELOPE_LIMIT,deadline)
            require(type(envelope) is dict and set(envelope)=={'profile','certificate','document'}
                and envelope['profile']==ENROLLMENT,'bundle-envelope')
            certificate=_decode(envelope['certificate'],8192)
            bind=enroll(_decode(envelope['document'],32768),nonce,certificate,approved)
            context=pinned_channel_context(certificate);_timeout(raw,deadline)
            secure=context.wrap_socket(raw,server_hostname=HOSTNAME)
            require(secure.version()=='TLSv1.3' and secure.getpeercert(binary_form=True)==certificate,'bundle-channel-certificate')
            send(secure,{'enrollment_sha256':digest(bind),'request':message},MAX_REQUEST+256,deadline)
            response=receive(secure,MAX_RESPONSE,deadline)
            require(type(response) is dict and response.get('profile')==RPC and response.get('id')==message['id']
                and response.get('experimental') is True,'bundle-channel-reply')
            fields={'profile','id','status','experimental'}
            if response.get('status')=='ok':
                require(set(response)==fields|{'result'} and type(response['result']) is dict,'bundle-channel-reply')
                return response['result']
            require(response.get('status')=='rejected' and set(response)==fields|{'code'}
                and type(response['code']) is str and len(response['code'])<=80,'bundle-channel-reply')
            raise Rejected(response['code'])
        except Rejected:raise
        except Exception:raise Rejected('bundle-channel-unavailable') from None
        finally:
            if secure is not None:secure.close()
            if raw is not None:raw.close()


def probe_loopback(approved,port):
    """Parent-only read-only check; endpoint files cannot select a local target."""
    require(type(port) is int and 1<=port<=65535,'bundle-probe-port')
    # The public installer approval is still validated in full. Only this
    # explicit in-process probe uses a fixed loopback transport instead of DNS.
    remote=AuthoredBundleRemote(approved,dial=lambda:socket.create_connection(('127.0.0.1',port),timeout=5))
    value=remote.call('parameters',{})
    require(value==approved['identity'],'bundle-probe-identity')
    return {'attested_service':True,'tls_key_possession':True,'identity_sha256':digest(value)}
