"""One protocol4 application: authored publication + original protected issuer.

Retains original issuer and count routes; old protocol3 publication is rejected.
Hardware/channel/installed runtime admission remains separately required.
"""
import copy
import hashlib
import threading
from authorship import intent
from authored_count import trust as count_trust
from base_protocol import keccak,read
from bundle_acceptance import AUTH_TYPE,acceptance_data,creation_time
from bundle_service import BundleApplication,OPERATIONS,ERRORS as LEGACY_ERRORS,MAX_REQUEST,MAX_RESPONSE,identity as legacy_identity
from count_state import count_view
from domain_issuer import IssuerApplication
from policy import Rejected,canonical,hex_string,require
from public_bundle_v4 import PROFILE,MAX_BYTES,encode,kind
from service_admission import ServiceAdmission

RPC='nockapp-bundle-rpc-v4'
IDENTITY='nockapp-bundle-service-identity-v4'
ERRORS=LEGACY_ERRORS|frozenset({'authored-bundle-author-rejected','authored-bundle-wallet-rejected','authored-bundle-count-rejected',
    'authored-bundle-already-accepted','authored-bundle-duplicate-post','authored-bundle-proof-context',
    'authored-bundle-application','authored-bundle-schema','authored-bundle-address-off','authored-bundle-selection'})


def identity(value):
    require(type(value) is dict and value.get('profile')==IDENTITY and value.get('protocol')==4
        and value.get('bundle_profile')==PROFILE and 'author_native_sha256' in value,'authored-service-identity')
    hex_string(value['author_native_sha256'],64);require(any(bytes.fromhex(value['author_native_sha256'])),'authored-service-identity')
    shared=copy.deepcopy(value);shared.pop('author_native_sha256')
    shared.update(profile='nockapp-bundle-service-identity-v3',protocol=3,bundle_profile='nockapp-public-discussion-bundle-v3')
    legacy_identity(shared)  # Same address/storage/issuer field grammar, distinct protocol admission above.
    return value


def validate_request(message):
    require(type(message) is dict and set(message)=={'profile','id','operation','body'} and message['profile']==RPC
        and message['operation'] in OPERATIONS and type(message['body']) is dict and len(canonical(message))<=MAX_REQUEST,'message-schema')
    hex_string(message['id'],32);return message


class AuthoredBundleApplication(BundleApplication):
    def __init__(self,state,provider,verifier,queue,reader,clock,*,counts=None,upload_admission=None):
        IssuerApplication.__init__(self,state,provider,clock)
        self.verifier,self.queue,self.reader,self.counts=verifier,queue,reader,counts
        selector=keccak(('accept('+AUTH_TYPE+',uint8,bytes32,bytes32)').encode())[:10]
        require(set(queue.contracts)=={verifier.contract} and set(queue.contracts[verifier.contract])=={selector},'bundle-service-sponsor-scope')
        require(queue.rpc is verifier.rpc and reader.rpc is queue.rpc and reader.contract==verifier.contract
            and reader.app==verifier.app and reader.registry.contract==verifier.registry.contract
            and reader.registry.definition==verifier.registry.definition and reader.store is verifier.store
            and state.backend is verifier.registry and state.namespace==verifier.registry.definition,'bundle-service-components')
        require(verifier.key.address.lower()!=queue.signer.address.lower(),'bundle-service-key-separation')
        require(read(queue.rpc,verifier.contract,'application()').lower()==verifier.app
            and int(read(queue.rpc,verifier.contract,'PROTOCOL_VERSION()'),16)==4
            and reader.protocol_version==4 and '0x'+read(queue.rpc,verifier.contract,'issuer()')[-40:].lower()==verifier.registry.contract
            and read(queue.rpc,verifier.registry.contract,'definition()')=='0x'+state.namespace,'bundle-service-contract')
        require(reader.chain_id==queue.chain,'bundle-service-chain')
        require(counts is None or counts.protected_state is state and verifier.count_native is not None
            and counts.native.sha256==verifier.count_native.sha256,'bundle-service-counts')
        require(reader.author_native is not None and verifier.author_native is not None
            and reader.author_native.sha256==verifier.author_native.sha256,'bundle-service-verifiers')
        def pin(native):return None if native is None else native.sha256 if type(native.sha256) is str else native.sha256.hex()
        require(pin(reader.count_native)==pin(verifier.count_native),'bundle-service-verifiers')
        self.identity={'profile':IDENTITY,'protocol':4,'chain_id':queue.chain,'contract':verifier.contract,
            'registry':verifier.registry.contract,'application':verifier.app,'definition_hash':state.namespace,
            'native_sha256':pin(state.native),'count_native_sha256':pin(verifier.count_native),
            'author_native_sha256':pin(verifier.author_native),'bundle_profile':PROFILE,
            'storage':{'replicas':[{'name':r.name,'failure_domain':r.failure_domain} for r in verifier.store.replicas],
                'retention_seconds':verifier.store.retention_seconds,'max_bundle_bytes':MAX_BYTES,'permanent_availability_proven':False}}
        identity(self.identity);self._lock=threading.RLock()
        self.upload_admission=upload_admission if upload_admission is not None else ServiceAdmission(rate=.2,burst=4)

    def _context(self,submission):
        return {'protocol':4,**super()._context(submission)}

    def _challenge(self,body):
        self.fields(body,['post','selection','submission_id']);chosen=body['selection']
        require(type(chosen) is dict and set(chosen)=={'address','followers_threshold'},'authored-bundle-selection')
        context=self._context(body['submission_id'])
        i=intent(body['post'],context,disclose_address=chosen['address'],followers_threshold=chosen['followers_threshold'])
        require(chosen['followers_threshold'] is not None,'bundle-ordinary');self._ready()
        require(self.counts is not None and self.verifier.count_native is not None,'count-service-unavailable')
        view=self.state.backend.public_view();projected=count_view(self.verifier.count_native,view)
        created=creation_time(self.queue.rpc,self.clock());c=count_trust(i,projected,created)['legacy']['challenge']
        return {'challenge':c,'issuer_view':view,'selection':copy.deepcopy(chosen),'context':context}

    def _submit(self,body):
        self.fields(body,['bundle','approve_publication']);require(body['approve_publication'] is True,'consent-required')
        bundle=body['bundle'];encode(bundle)
        require(bundle['context']==self._context(bundle['context']['submission_id']),'authored-bundle-application')
        submission=bundle['context']['submission_id']
        scope={k:self.identity[k] for k in ('protocol','chain_id','contract','registry','application','definition_hash','bundle_profile')}
        operation_hash=hashlib.sha256(canonical({'profile':RPC,'operation':'post-submit','scope':scope,'body':body})).hexdigest()
        recovered=self.queue.recover(submission,operation_hash)
        if recovered is not None:return recovered
        self.queue.preflight(self.queue.limits.max_gas)
        if kind(bundle):self._ready()
        require(self.upload_admission.admit(),'bundle-upload-rate')
        package=self.verifier.approve(bundle)
        return self.queue.submit(submission,self.verifier.contract,acceptance_data(package),self.queue.limits.max_gas,operation_hash=operation_hash)

    def dispatch(self,message):
        ident='0'*32
        try:
            validate_request(message);ident=message['id'];result=self.operate(message['operation'],copy.deepcopy(message['body']))
            require(type(result) is dict and len(canonical(result))<=MAX_RESPONSE-256,'bundle-result-size')
            return {'profile':RPC,'id':ident,'status':'ok','result':result,'experimental':True}
        except Exception as error:
            code=error.args[0] if isinstance(error,Rejected) and error.args and error.args[0] in ERRORS else 'bundle-operation-unavailable'
            return {'profile':RPC,'id':ident,'status':'rejected','code':code,'experimental':True}
