"""Lean-only v3 publication and existing issuer routes in one enclave service.

No key initialization, private-state migration, listeners or legacy publication
routes. Bundle uploads precede acceptance signatures and sponsor transactions.
Runtime, attested client transport and release wiring are separate components.
"""
import copy
import hashlib
import re
import threading

from base_protocol import keccak,read
from base_service import ISSUER_OPERATIONS
from bundle_acceptance import AUTH_TYPE,acceptance_data,creation_time
from domain_issuer import IssuerApplication,ERRORS as ISSUER_ERRORS
from policy import Rejected,canonical,hex_string,require,strict_json
from public_bundle import PROFILE,MAX_BYTES,build,encode,validate_selection
from service_admission import ServiceAdmission

RPC='nockapp-bundle-rpc-v3'
IDENTITY='nockapp-bundle-service-identity-v3'
MAX_REQUEST=MAX_BYTES+4096
MAX_RESPONSE=131072
PUBLIC_OPERATIONS=frozenset({'parameters','post-challenge','post-submit','post-status','discussion','threads','thread'})
COUNT_OPERATIONS=frozenset('count-'+op for op in ISSUER_OPERATIONS|{'parameters'})
OPERATIONS=PUBLIC_OPERATIONS|ISSUER_OPERATIONS|COUNT_OPERATIONS
ERRORS=frozenset(ISSUER_ERRORS)|frozenset({'bundle-schema','bundle-context','bundle-post','bundle-thread',
    'bundle-selection','bundle-ordinary','bundle-evidence','bundle-public-proof','bundle-application',
    'bundle-proof-context','bundle-credential-rejected','bundle-thread-unavailable','bundle-size','bundle-page',
    'bundle-upload-rate','public-replication-unavailable','action-expired','issuer-not-ready',
    'transaction-submission-conflict','transaction-unknown','transaction-count-budget',
    'transaction-execution-budget','transaction-total-fee-budget','transaction-total-fee-cap','transaction-extra-fee-cap',
    'transaction-total-fee-overrun','transaction-funded-cap','transaction-funded-balance','transaction-funded-state',
    'transaction-funded-reorg','transaction-funded-stale','transaction-fee-recovery-pending','transaction-fee-cap','transaction-nonce-conflict','count-service-unavailable'})


def identity(value):
    require(type(value) is dict and set(value)=={'profile','protocol','chain_id','contract','registry','application',
        'definition_hash','native_sha256','count_native_sha256','bundle_profile','storage'}
        and value['profile']==IDENTITY and type(value['protocol']) is int and value['protocol']==3
        and type(value['chain_id']) is int and value['chain_id'] in (31337,84532)
        and value['bundle_profile']==PROFILE,'bundle-service-identity')
    for field,size in (('contract',40),('registry',40),('application',64)):
        text=value[field]
        require(type(text) is str and re.fullmatch('0x[0-9a-f]{'+str(size)+'}',text)
            and any(bytes.fromhex(text[2:])),'bundle-service-identity')
    for field in ('definition_hash','native_sha256','count_native_sha256'):
        text=value[field]
        if text is None and field!='definition_hash':continue
        hex_string(text,64);require(any(bytes.fromhex(text)),'bundle-service-identity')
    storage=value['storage']
    require(type(storage) is dict and set(storage)=={'replicas','retention_seconds','max_bundle_bytes',
        'permanent_availability_proven'} and type(storage['retention_seconds']) is int
        and 90*86400<=storage['retention_seconds']<=365*86400 and storage['max_bundle_bytes']==MAX_BYTES
        and type(storage['max_bundle_bytes']) is int and storage['permanent_availability_proven'] is False,
        'bundle-storage-identity')
    rows=storage['replicas'];require(type(rows) is list and 2<=len(rows)<=4,'bundle-storage-identity')
    for row in rows:
        require(type(row) is dict and set(row)=={'name','failure_domain'} and type(row['name']) is str
            and re.fullmatch(r'[a-z0-9][a-z0-9-]{2,63}',row['name']) and type(row['failure_domain']) is str
            and 3<=len(row['failure_domain'])<=128,'bundle-storage-identity')
    require(len({r['name'] for r in rows})==len(rows) and len({r['failure_domain'] for r in rows})==len(rows),
        'bundle-storage-identity')
    return value


def validate_request(message):
    require(type(message) is dict and set(message)=={'profile','id','operation','body'}
        and message['profile']==RPC and type(message['operation']) is str and message['operation'] in OPERATIONS
        and type(message['body']) is dict and len(canonical(message))<=MAX_REQUEST,'message-schema')
    hex_string(message['id'],32);return message


class BundleApplication(IssuerApplication):
    def __init__(self,state,provider,verifier,queue,reader,clock,*,counts=None,upload_admission=None):
        super().__init__(state,provider,clock)
        self.verifier,self.queue,self.reader,self.counts=verifier,queue,reader,counts
        selector=keccak(('accept('+AUTH_TYPE+',uint8,bytes32,bytes32)').encode())[:10]
        require(set(queue.contracts)=={verifier.contract}
            and set(queue.contracts[verifier.contract])=={selector},'bundle-service-sponsor-scope')
        require(queue.rpc is verifier.rpc and reader.rpc is queue.rpc
            and reader.contract==verifier.contract and reader.app==verifier.app
            and reader.registry.contract==verifier.registry.contract
            and reader.registry.definition==verifier.registry.definition
            and reader.store is verifier.store and state.backend is verifier.registry
            and state.namespace==verifier.registry.definition,'bundle-service-components')
        require(verifier.key.address.lower()!=queue.signer.address.lower(),'bundle-service-key-separation')
        require(read(queue.rpc,verifier.contract,'application()').lower()==verifier.app
            and int(read(queue.rpc,verifier.contract,'PROTOCOL_VERSION()'),16)==3
            and '0x'+read(queue.rpc,verifier.contract,'issuer()')[-40:].lower()==verifier.registry.contract
            and read(queue.rpc,verifier.registry.contract,'definition()')=='0x'+state.namespace,
            'bundle-service-contract')
        require(reader.chain_id==queue.chain,'bundle-service-chain')
        require(counts is None or counts.protected_state is state and verifier.count_native is not None
            and counts.native.sha256==verifier.count_native.sha256,'bundle-service-counts')
        def pin(native):return None if native is None else native.sha256.hex()
        require(pin(reader.native)==pin(verifier.native) and pin(reader.count_native)==pin(verifier.count_native),
            'bundle-service-verifiers')
        self.identity={'profile':IDENTITY,'protocol':3,'chain_id':queue.chain,'contract':verifier.contract,
            'registry':verifier.registry.contract,'application':verifier.app,'definition_hash':state.namespace,
            'native_sha256':pin(verifier.native),'count_native_sha256':pin(verifier.count_native),'bundle_profile':PROFILE,
            'storage':{'replicas':[{'name':r.name,'failure_domain':r.failure_domain} for r in verifier.store.replicas],
                'retention_seconds':verifier.store.retention_seconds,'max_bundle_bytes':MAX_BYTES,
                'permanent_availability_proven':False}}
        identity(self.identity)
        self._lock=threading.RLock()
        self.upload_admission=upload_admission if upload_admission is not None else ServiceAdmission(rate=.2,burst=4)

    def _ready(self):
        if hasattr(self.state,'poll_boot'):require(self.state.poll_boot()['state']=='ready','issuer-not-ready')

    def _context(self,submission):
        hex_string(submission,64);require(any(bytes.fromhex(submission)),'bundle-context')
        return {'application':self.verifier.app,'chain_id':self.queue.chain,'contract':self.verifier.contract,
            'submission_id':submission}

    def _challenge(self,body):
        self.fields(body,['post','selection','submission_id'])
        context=self._context(body['submission_id']);chosen=body['selection'];kind=validate_selection(chosen)
        # Validate public post/context before accessing the private issuer service.
        build(body['post'],{'credential_kind':0,'facts':[],'threshold':None},context)
        require(kind!=0,'bundle-ordinary');self._ready()
        require(kind!=2 or self.counts is not None,'count-service-unavailable')
        view=self.state.backend.public_view()
        created=creation_time(self.queue.rpc,self.clock())
        if kind==1:
            from base_protocol import challenge
            c=challenge(body['post'],chosen['facts'],context['application'],context['chain_id'],context['contract'],
                view['sequence'],created,context['submission_id'])
        else:
            from count_protocol import challenge
            c=challenge(body['post'],chosen['facts'],chosen['threshold'],context['application'],context['chain_id'],
                context['contract'],view['sequence'],created,context['submission_id'])
        return {'challenge':c,'issuer_view':view,'selection':copy.deepcopy(chosen),'context':context}

    def _submit(self,body):
        self.fields(body,['bundle','approve_publication']);require(body['approve_publication'] is True,'consent-required')
        bundle=body['bundle'];encode(bundle)
        require(bundle['context']==self._context(bundle['context']['submission_id']),'bundle-application')
        submission=bundle['context']['submission_id']
        scope={key:self.identity[key] for key in ('protocol','chain_id','contract','registry','application',
            'definition_hash','bundle_profile')}
        operation_hash=hashlib.sha256(canonical({'profile':RPC,'operation':'post-submit',
            'scope':scope,'body':body})).hexdigest()
        # Exact request recovery precedes proof deadlines, storage or source calls.
        # The queue resends only previously persisted signed bytes at their nonce.
        recovered=self.queue.recover(submission,operation_hash)
        if recovered is not None:return recovered
        self.queue.preflight(self.queue.limits.max_gas)  # before proof checks/replica costs
        if bundle['selection']['credential_kind']:self._ready()
        require(self.upload_admission.admit(),'bundle-upload-rate')
        package=self.verifier.approve(bundle)
        return self.queue.submit(submission,self.verifier.contract,acceptance_data(package),self.queue.limits.max_gas,
            operation_hash=operation_hash)

    def operate(self,op,body):
        require(op in OPERATIONS,'message-schema')
        with self._lock:
            if op=='parameters':self.fields(body,[]);return copy.deepcopy(self.identity)
            if op=='post-submit':return self._submit(body)
            if op=='post-challenge':return self._challenge(body)
            if op=='post-status':
                self.fields(body,['submission_id']);self._context(body['submission_id'])
                return self.queue.poll(body['submission_id'])
            if op=='discussion':
                self.fields(body,['numbers'])
                return {'identity':copy.deepcopy(self.identity),**self.reader.read_numbers(body['numbers'],self.clock())}
            if op=='threads':
                self.fields(body,['after','limit'])
                return {'identity':copy.deepcopy(self.identity),**self.reader.read_threads(body['after'],body['limit'],self.clock())}
            if op=='thread':
                self.fields(body,['thread_id','after','limit'])
                return {'identity':copy.deepcopy(self.identity),**self.reader.read_thread(body['thread_id'],body['after'],body['limit'],self.clock())}
            if op in COUNT_OPERATIONS:
                require(self.counts is not None,'count-service-unavailable')
                if op not in ('count-parameters','count-registry','count-status','count-activation-status'):self._ready()
                return self.counts.operate(op[6:],body)
            if op=='activation-status':
                self.fields(body,['session']);require(hasattr(self.state,'finalized_status'),'issuer-finality-required')
                return self.state.finalized_status(self.session(body['session']))
            if op not in ('registry','status','abort'):self._ready()
            return super().operate(op,body)

    def dispatch(self,message):
        ident='0'*32
        try:
            validate_request(message);ident=message['id']
            result=self.operate(message['operation'],copy.deepcopy(message['body']))
            require(type(result) is dict and len(canonical(result))<=MAX_RESPONSE-256,'bundle-result-size')
            return {'profile':RPC,'id':ident,'status':'ok','result':result,'experimental':True}
        except Exception as error:
            code=error.args[0] if isinstance(error,Rejected) and error.args and error.args[0] in ERRORS else 'bundle-operation-unavailable'
            return {'profile':RPC,'id':ident,'status':'rejected','code':code,'experimental':True}

    def dispatch_bytes(self,data):
        try:message=strict_json(data,max_bytes=MAX_REQUEST)
        except Exception:message=None
        return canonical(self.dispatch(message))
