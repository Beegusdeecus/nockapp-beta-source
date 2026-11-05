"""Independent verifier: fresh AWS attestation then bound TLS 1.3, one RPC.

Public addresses are installer inputs. No private socket/issuer fallback, TOFU,
caller trust, permanent certificate pin, automatic retry or plaintext proof data.
The measured service owns its application, NSM and separately scoped authority.
"""
import base64
import copy
import hashlib
import secrets
import time

from domain_post_rpc import PROFILE as RPC,MAX_REQUEST,validate_request
from domain_transport import (ENVELOPE_LIMIT,channel_identity,connect_endpoint,
                              validate_endpoint,_aws_document,_decode,_timeout,receive,send)
from domain_trust import certificate_key,validate_approval as validate_issuer_approval
from post_transport import REMOTE_APPROVAL,HOSTNAME,LIMIT,DEADLINE,validate_binding
from policy import POLICY_HASH,Rejected,canonical,digest,hex_string,require
from trust import verify_aws_document,validate_pcrs,pinned_channel_context

ENROLLMENT='nockapp-zkid-post-aws-enrollment-v1'
ENDPOINT='nockapp-zkid-public-verifier-endpoint-v1'


def validate_approval(value):
    require(type(value) is dict and set(value)=={'profile','binding','endpoint','code_identity','pcrs'}
            and value['profile']==REMOTE_APPROVAL,'post-remote-approval')
    bind=validate_binding(value['binding']);validate_endpoint(value['endpoint'],profile=ENDPOINT)
    validate_issuer_approval({'mode':'production','definition_hash':bind['definition_hash'],
        'state_authority_sha256':bind['state_authority_sha256'],
        'code_identity':value['code_identity'],'pcrs':value['pcrs']})
    return value


def binding(application_binding,certificate,code_identity):
    validate_binding(application_binding);certificate_key(certificate);hex_string(code_identity,64)
    require(any(bytes.fromhex(code_identity)),'post-remote-identity')
    return {'profile':ENROLLMENT,'rpc':RPC,'binding':copy.deepcopy(application_binding),
            'policy':POLICY_HASH,'code_identity':code_identity,'certificate_sha256':digest_bytes(certificate)}


def digest_bytes(value):return hashlib.sha256(value).hexdigest()


def enroll(document,nonce,certificate,approved):
    try:
        # Expectations come only from independent installation, never the peer.
        validate_approval(approved);hex_string(nonce,64)
        expected=binding(approved['binding'],certificate,approved['code_identity'])
        require(type(document) is bytes and 0<len(document)<=32768,'post-remote-document')
        now=int(time.time()*1000);payload=verify_aws_document(document,now)
        require(payload.get('nonce')==bytes.fromhex(nonce),'post-remote-nonce')
        require(payload.get('public_key')==certificate_key(certificate),'post-remote-key')
        require(payload.get('user_data')==bytes.fromhex(digest(expected)),'post-remote-binding')
        require(type(payload.get('timestamp')) is int and now-120000<=payload['timestamp']<=now+5000,
                'post-remote-stale')
        validate_pcrs(payload['pcrs'],approved['pcrs'])
        return expected
    except Rejected:raise
    except Exception:raise Rejected('post-remote-attestation-rejected') from None


def serve_connection(raw,application,application_binding,code_identity,*,expires_at):
    """Internal measured service entry. Does not open a public listener."""
    secure=None;deadline=time.monotonic()+DEADLINE
    try:
        validate_binding(application_binding)
        require(type(expires_at) is int and int(time.time())<expires_at,'post-service-expired')
        hello=receive(raw,256,deadline)
        require(type(hello) is dict and set(hello)=={'profile','nonce'}
                and hello['profile']==ENROLLMENT,'post-remote-hello');hex_string(hello['nonce'],64)
        context,certificate=channel_identity(hostname=HOSTNAME)
        bind=binding(application_binding,certificate,code_identity)
        document=_aws_document(hello['nonce'],bind,certificate)
        send(raw,{'profile':ENROLLMENT,'certificate':base64.b64encode(certificate).decode('ascii'),
                  'document':base64.b64encode(document).decode('ascii')},ENVELOPE_LIMIT,deadline)
        _timeout(raw,deadline);secure=context.wrap_socket(raw,server_side=True)
        message=receive(secure,MAX_REQUEST+256,deadline)
        require(type(message) is dict and set(message)=={'enrollment_sha256','request'}
                and message['enrollment_sha256']==digest(bind),'post-remote-confirmation')
        require(int(time.time())<expires_at,'post-service-expired')
        validate_request(message['request'])
        send(secure,application.dispatch(message['request']),LIMIT,deadline)
    except Exception:pass  # No private payload, key or diagnostic text on wire/logs.
    finally:
        if secure is not None:secure.close()
        raw.close()


def request(operation,body,approved):
    raw=secure=None;deadline=time.monotonic()+DEADLINE
    try:
        approved=copy.deepcopy(validate_approval(approved))
        message={'profile':RPC,'id':secrets.token_hex(16),'operation':operation,'body':copy.deepcopy(body)}
        validate_request(message)  # BEFORE resolving/dialing or sending a quote hello.
        raw=connect_endpoint(approved['endpoint'],profile=ENDPOINT)
        nonce=secrets.token_hex(32)
        send(raw,{'profile':ENROLLMENT,'nonce':nonce},256,deadline)
        envelope=receive(raw,ENVELOPE_LIMIT,deadline)
        require(type(envelope) is dict and set(envelope)=={'profile','certificate','document'}
                and envelope['profile']==ENROLLMENT,'post-remote-envelope')
        certificate=_decode(envelope['certificate'],8192)
        bind=enroll(_decode(envelope['document'],32768),nonce,certificate,approved)
        context=pinned_channel_context(certificate);_timeout(raw,deadline)
        secure=context.wrap_socket(raw,server_hostname=HOSTNAME)
        require(secure.version()=='TLSv1.3' and secure.getpeercert(binary_form=True)==certificate,'post-certificate')
        send(secure,{'enrollment_sha256':digest(bind),'request':message},MAX_REQUEST+256,deadline)
        reply=receive(secure,LIMIT,deadline)
        require(type(reply) is dict and reply.get('profile')==RPC and reply.get('id')==message['id']
                and reply.get('laboratory') is True and reply.get('verified') is False,'post-channel-reply')
        fields={'profile','id','status','laboratory','verified'}
        if reply.get('status')=='ok':require(set(reply)==fields|{'result'} and type(reply['result']) is dict,'post-channel-reply')
        else:require(reply.get('status')=='rejected' and set(reply)==fields|{'code'} and type(reply['code']) is str,'post-channel-reply')
        return reply
    except Rejected:raise
    except Exception:raise Rejected('post-channel-unavailable') from None
    finally:
        if secure is not None:secure.close()
        if raw is not None:raw.close()
