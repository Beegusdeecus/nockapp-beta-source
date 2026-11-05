"""Fresh attestation and TLS1.3 for the six-month issuer, independently pinned.

One request per connection; no retry, TOFU, legacy-profile fallback, publication
approval or caller-selected authority. The image supervisor owns the handler.
This channel alone is not evidence that an approved image is deployed.
"""
import base64
import copy
import hashlib
import secrets
import time

from base_evm import encode
from base_protocol import keccak
from base_transactions import hex_data
from domain_pipeline import definition_hash
from domain_transport import (channel_identity,connect_endpoint,validate_endpoint,
    _aws_document,_decode,_timeout,receive,send,ENVELOPE_LIMIT)
from domain_trust import certificate_key,validate_approval as issuer_approval
from fixed_issuer_code_v1 import sha256 as fixed_sha
from policy import Rejected,canonical,digest,hex_string,require
from renewal_policy_v3 import POLICY_HASH
from renewal_service_v3 import RPC,OPERATIONS
from trust import verify_aws_document,validate_pcrs,pinned_channel_context

IDENTITY='nockapp-renewal-service-identity-v3'
ENROLLMENT='nockapp-renewal-aws-enrollment-v3'
APPROVAL='nockapp-renewal-service-approval-v3'
ENDPOINT='nockapp-renewal-service-endpoint-v3'
HOSTNAME='renewal-issuer.nockapp.local'
MAX_REQUEST=65536
MAX_RESPONSE=131072
DEADLINE=60
UPDATER_SELECTORS=sorted(keccak(s)[:10] for s in (
    b'beginLease(uint256,uint256,bytes32,bytes32,uint256,bytes)',
    b'updateLeased(uint256,uint256,bytes32,bytes32,uint256,bytes)'))


def identity(value):
    fields={'profile','protocol','chain_id','registry','contract','application','definition_hash',
        'updater','runtime_code','domain_native_sha256','count_native_sha256','renewal_native_sha256','policy_sha256'}
    require(type(value) is dict and set(value)==fields and value['profile']==IDENTITY
        and value['protocol']==RPC and type(value['chain_id']) is int and value['chain_id']==84532
        and value['policy_sha256']==POLICY_HASH,'renewal-service-identity')
    for name in ('registry','contract','updater'):
        address=value[name];raw=hex_data(address,20)
        require(address=='0x'+raw.hex() and any(raw),'renewal-service-address')
    require(len({value[k] for k in ('registry','contract','updater')})==3,'renewal-service-address')
    app=hex_data(value['application'],32)
    require(value['application']=='0x'+app.hex() and any(app),'renewal-service-application')
    for name in ('definition_hash','domain_native_sha256','count_native_sha256','renewal_native_sha256'):
        hex_string(value[name],64);require(any(bytes.fromhex(value[name])),'renewal-service-pin')
    codes=value['runtime_code']
    require(type(codes) is dict and set(codes)=={value['registry'],value['contract']},'renewal-service-contracts')
    for pin in codes.values():hex_string(pin,64);require(any(bytes.fromhex(pin)),'renewal-service-pin')
    require(codes[value['registry']]==fixed_sha(value['updater'],value['definition_hash']),'renewal-service-fixed-code')
    return copy.deepcopy(value)


def check_chain(expected,rpc):
    expected=identity(expected)
    require(rpc.call('eth_chainId')=='0x14a34','renewal-service-chain')
    block=rpc.call('eth_getBlockByNumber','latest',False);tag=block['number']
    for address,pin in expected['runtime_code'].items():
        require(hashlib.sha256(hex_data(rpc.call('eth_getCode',address,tag))).hexdigest()==pin,'renewal-service-code')
    def read(address,signature):return rpc.call('eth_call',{'to':address,'data':encode(signature)},tag)
    registry=expected['registry'];index=expected['contract']
    require(read(registry,'definition()')=='0x'+expected['definition_hash']
        and hex_data(read(registry,'updater()'),32)==bytes(12)+hex_data(expected['updater'],20)
        and rpc.call('eth_getCode',expected['updater'],tag)=='0x'
        and read(index,'application()')==expected['application']
        and int(read(index,'INDEX_VERSION()'),16)==1,'renewal-service-chain-binding')
    require(rpc.call('eth_getBlockByNumber',tag,False)['hash']==block['hash'],'renewal-service-reorg')


def validate_approval(value):
    require(type(value) is dict and set(value)=={'profile','identity','endpoint','code_identity',
        'state_authority_sha256','pcrs'} and value['profile']==APPROVAL,'renewal-approval')
    expected=identity(value['identity']);validate_endpoint(value['endpoint'],profile=ENDPOINT)
    issuer_approval({'mode':'production','definition_hash':expected['definition_hash'],
        'code_identity':value['code_identity'],'state_authority_sha256':value['state_authority_sha256'],'pcrs':value['pcrs']})
    return copy.deepcopy(value)


def binding(expected,certificate,code,authority):
    expected=identity(expected);certificate_key(certificate)
    for pin in (code,authority):hex_string(pin,64);require(any(bytes.fromhex(pin)),'renewal-channel-pin')
    return {'profile':ENROLLMENT,'rpc':RPC,'identity':expected,'code_identity':code,
        'state_authority_sha256':authority,'certificate_sha256':hashlib.sha256(certificate).hexdigest()}


def enroll(document,nonce,certificate,approved):
    approved=validate_approval(approved);hex_string(nonce,64)
    expected=binding(approved['identity'],certificate,approved['code_identity'],approved['state_authority_sha256'])
    require(type(document) is bytes and 0<len(document)<=32768,'renewal-document')
    now=int(time.time()*1000)
    try:payload=verify_aws_document(document,now)
    except Exception:raise Rejected('renewal-attestation-rejected') from None
    require(payload.get('nonce')==bytes.fromhex(nonce) and payload.get('public_key')==certificate_key(certificate)
        and payload.get('user_data')==bytes.fromhex(digest(expected)),'renewal-quote-binding')
    require(type(payload.get('timestamp')) is int and now-120000<=payload['timestamp']<=now+5000,'renewal-quote-stale')
    validate_pcrs(payload['pcrs'],approved['pcrs']);return expected


def validate_request(message):
    require(type(message) is dict and set(message)=={'profile','id','operation','body'} and message['profile']==RPC
        and type(message['operation']) is str and message['operation'] in OPERATIONS
        and type(message['body']) is dict and len(canonical(message))<=MAX_REQUEST,'renewal-request')
    hex_string(message['id'],32)


def serve_connection(raw,application,code,authority):
    secure=None;deadline=time.monotonic()+DEADLINE
    try:
        hello=receive(raw,256,deadline)
        require(type(hello) is dict and set(hello)=={'profile','nonce'} and hello['profile']==ENROLLMENT,'renewal-hello')
        hex_string(hello['nonce'],64)
        context,certificate=channel_identity(hostname=HOSTNAME)
        bind=binding(application.identity,certificate,code,authority)
        document=_aws_document(hello['nonce'],bind,certificate)
        send(raw,{'profile':ENROLLMENT,'certificate':base64.b64encode(certificate).decode(),
            'document':base64.b64encode(document).decode()},ENVELOPE_LIMIT,deadline)
        _timeout(raw,deadline);secure=context.wrap_socket(raw,server_side=True)
        message=receive(secure,MAX_REQUEST+256,deadline)
        require(type(message) is dict and set(message)=={'enrollment_sha256','request'}
            and message['enrollment_sha256']==digest(bind),'renewal-channel-confirmation')
        validate_request(message['request'])
        send(secure,application.dispatch(message['request']),MAX_RESPONSE,deadline)
    except Exception:pass  # No private request/source/key diagnostics on wire/logs.
    finally:
        if secure is not None:secure.close()
        raw.close()


class RenewalRemote:
    def __init__(self,approved):self.approved=validate_approval(approved)

    def call(self,operation,body):
        raw=secure=None;deadline=time.monotonic()+DEADLINE
        try:
            approved=validate_approval(self.approved)
            message={'profile':RPC,'id':secrets.token_hex(16),'operation':operation,'body':copy.deepcopy(body)}
            validate_request(message)
            raw=connect_endpoint(approved['endpoint'],profile=ENDPOINT)
            nonce=secrets.token_hex(32);send(raw,{'profile':ENROLLMENT,'nonce':nonce},256,deadline)
            envelope=receive(raw,ENVELOPE_LIMIT,deadline)
            require(type(envelope) is dict and set(envelope)=={'profile','certificate','document'}
                and envelope['profile']==ENROLLMENT,'renewal-envelope')
            certificate=_decode(envelope['certificate'],8192)
            bind=enroll(_decode(envelope['document'],32768),nonce,certificate,approved)
            _timeout(raw,deadline)
            secure=pinned_channel_context(certificate).wrap_socket(raw,server_hostname=HOSTNAME)
            require(secure.version()=='TLSv1.3' and secure.getpeercert(binary_form=True)==certificate,'renewal-channel-certificate')
            send(secure,{'enrollment_sha256':digest(bind),'request':message},MAX_REQUEST+256,deadline)
            response=receive(secure,MAX_RESPONSE,deadline)
            require(type(response) is dict and response.get('profile')==RPC and response.get('id')==message['id'],
                'renewal-channel-reply')
            fields={'profile','id','status'}
            if response.get('status')=='ok':
                require(set(response)==fields|{'result'} and type(response['result']) is dict,'renewal-channel-reply')
                return response['result']
            require(response.get('status')=='rejected' and set(response)==fields|{'code'}
                and response['code']=='renewal-operation-unavailable','renewal-channel-reply')
            raise Rejected(response['code'])
        except Rejected:raise
        except Exception:raise Rejected('renewal-channel-unavailable') from None
        finally:
            if secure is not None:secure.close()
            if raw is not None:raw.close()

    def public_view(self):
        view=self.call('registry',{})
        require(type(view) is dict and set(view)=={'definition_hash','public','sequence'}
            and view['definition_hash']==self.approved['identity']['definition_hash']
            and type(view['sequence']) is int and 0<=view['sequence']<2**53
            and definition_hash(view['public'])==view['definition_hash'],'renewal-registry')
        return view
