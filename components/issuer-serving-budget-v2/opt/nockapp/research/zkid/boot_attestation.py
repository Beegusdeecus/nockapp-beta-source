"""Fresh AWS-bound boot channel, distinct from credential-issuer enrollment.

The quote authorizes only a measured startup/secret-loading connection. It does
not assert a loaded signer, current registry, source observation or app identity.
"""
import base64
import hashlib
import secrets
import time

from domain_transport import channel_identity,send,receive,_decode,_timeout
from domain_trust import certificate_key,validate_approval,validate_pcrs,pinned_channel_context,HOSTNAME
from policy import POLICY_HASH,SOURCE,Rejected,canonical,hex_string,require
from trust import verify_aws_document

PROFILE='nockapp-zkid-issuer-boot-attestation-v1'


def binding(certificate,identity,authority,namespace):
    for value in (identity,authority,namespace):hex_string(value,64)
    return {'profile':PROFILE,'code_identity':identity,'state_authority_sha256':authority,
            'definition_hash':namespace,'policy':POLICY_HASH,'source':SOURCE,
            'certificate_sha256':hashlib.sha256(certificate).hexdigest()}


def negotiate(raw,approved):
    validate_approval(approved);nonce=secrets.token_hex(32);deadline=time.monotonic()+30
    send(raw,{'profile':PROFILE,'nonce':nonce},256,deadline)
    envelope=receive(raw,65536,deadline)
    require(type(envelope) is dict and set(envelope)=={'profile','certificate','document'}
            and envelope['profile']==PROFILE,'issuer-boot-envelope')
    cert=_decode(envelope['certificate'],8192)
    expected=binding(cert,approved['code_identity'],approved['state_authority_sha256'],approved['definition_hash'])
    now=int(time.time()*1000);payload=verify_aws_document(_decode(envelope['document'],32768),now)
    require(payload.get('nonce')==bytes.fromhex(nonce) and payload.get('public_key')==certificate_key(cert)
            and payload.get('user_data')==hashlib.sha256(canonical(expected)).digest()
            and type(payload.get('timestamp')) is int and now-120000<=payload['timestamp']<=now+5000,'issuer-boot-quote')
    validate_pcrs(payload['pcrs'],approved['pcrs'])
    return cert,expected


def inspect_boot(raw,approved):
    try:
        _,bind=negotiate(raw,approved)
        return {'profile':PROFILE,'binding':bind,'hardware_verified':True,'issuer_loaded':False,
                'verified':False,'production_ready':False}
    except Exception:raise Rejected('issuer-boot-rejected') from None
    finally:raw.close()


def provision_boot(raw,envelope,approved):
    secure=None
    try:
        cert,bind=negotiate(raw,approved);deadline=time.monotonic()+180
        _timeout(raw,deadline)
        secure=pinned_channel_context(cert).wrap_socket(raw,server_hostname=HOSTNAME)
        require(secure.version()=='TLSv1.3' and secure.getpeercert(binary_form=True)==cert,'issuer-boot-channel')
        send(secure,{'binding_sha256':hashlib.sha256(canonical(bind)).hexdigest(),'bootstrap':envelope},65536,deadline)
        result=receive(secure,256,deadline)
        require(result=={'profile':PROFILE,'status':'ready','verified':False},'issuer-boot-not-ready')
        return result
    except Exception:raise Rejected('issuer-boot-rejected') from None
    finally:
        if secure is not None:secure.close()
        raw.close()


def serve_boot(raw,nsm,identity,authority,namespace,handler):
    secure=None
    try:
        deadline=time.monotonic()+180;hello=receive(raw,256,deadline)
        require(type(hello) is dict and set(hello)=={'profile','nonce'} and hello['profile']==PROFILE,'issuer-boot-hello')
        hex_string(hello['nonce'],64);context,cert=channel_identity();bind=binding(cert,identity,authority,namespace)
        document=nsm.attest(bytes.fromhex(hello['nonce']),certificate_key(cert),hashlib.sha256(canonical(bind)).digest())
        send(raw,{'profile':PROFILE,'certificate':base64.b64encode(cert).decode(),
                  'document':base64.b64encode(document).decode()},65536,deadline)
        _timeout(raw,deadline);secure=context.wrap_socket(raw,server_side=True)
        request=receive(secure,65536,deadline)
        require(type(request) is dict and set(request)=={'binding_sha256','bootstrap'}
                and request['binding_sha256']==hashlib.sha256(canonical(bind)).hexdigest(),'issuer-boot-binding')
        result=handler(request['bootstrap'])
        send(secure,{'profile':PROFILE,'status':'ready','verified':False},256,deadline)
        return result
    except Exception:return None
    finally:
        if secure is not None:secure.close()
        raw.close()
