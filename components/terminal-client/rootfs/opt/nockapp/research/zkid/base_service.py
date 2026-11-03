"""One bounded issuer + Base discussion application inside the measured service.

Issuer registration state and public post acceptance stay separate. Public
posting never invokes the issuer signer or changes account/replacement state.
This module does not create keys, initialize issuer state or open listeners.
"""
import copy
import hashlib
import threading

from base_protocol import (PROTOCOL,challenge,ordinary_publication_data,publication_data,read,keccak)
from domain_issuer import IssuerApplication
from policy import Rejected,canonical,hex_string,require,strict_json
from post_scope import payload,facts

RPC='nockapp-base-rpc-v1'
IDENTITY='nockapp-base-service-identity-v1'
MAX_REQUEST=65536
MAX_RESPONSE=131072
ISSUER_OPERATIONS=frozenset({'registry','begin','status','abort','check-post','discover-post',
    'recover-delivery','commit','witness','activation-status'})
BASE_OPERATIONS=frozenset({'parameters','post-challenge','post-submit','post-status','discussion'})
COUNT_OPERATIONS=frozenset('count-'+op for op in ('parameters','registry','begin','status','abort','check-post',
    'discover-post','recover-delivery','commit','witness','activation-status','post-challenge','post-submit'))
ERRORS=frozenset({'message-schema','consent-required','ordinary-post','post-facts','post-schema',
    'post-context','post-identity-disclosure','publication-size','issuer-not-ready','action-expired',
    'transaction-submission-conflict','transaction-unknown','transaction-count-budget',
    'transaction-execution-budget','transaction-fee-cap','transaction-nonce-conflict',
    'witness-refresh-required','registry-state-changed','domain-proof-rejected'})


def identity(value):
    require(type(value) is dict and set(value)=={'profile','protocol','chain_id','contract','registry',
        'application','definition_hash','native_sha256'} and value['profile']==IDENTITY
        and value['protocol']==PROTOCOL and type(value['chain_id']) is int
        and value['chain_id'] in (31337,84532),'base-service-identity')
    for key in ('contract','registry'):
        require(type(value[key]) is str and value[key].startswith('0x') and len(value[key])==42,
            'base-service-identity');hex_string(value[key][2:],40)
        require(any(bytes.fromhex(value[key][2:])),'base-service-identity')
    require(type(value['application']) is str and value['application'].startswith('0x'),'base-service-identity')
    for field in ('application','definition_hash','native_sha256'):
        text=value[field][2:] if field=='application' else value[field]
        hex_string(text,64);require(any(bytes.fromhex(text)),'base-service-identity')
    return value


def validate_request(message):
    require(type(message) is dict and set(message)=={'profile','id','operation','body'}
        and message['profile']==RPC and type(message['operation']) is str
        and message['operation'] in ISSUER_OPERATIONS|BASE_OPERATIONS|COUNT_OPERATIONS
        and type(message['body']) is dict and len(canonical(message))<=MAX_REQUEST,'message-schema')
    hex_string(message['id'],32)
    return message


class BaseApplication(IssuerApplication):
    def __init__(self,state,provider,verifier,queue,reader,clock,*,counts=None):
        super().__init__(state,provider,clock)
        self.verifier,self.queue,self.reader=verifier,queue,reader
        self.identity=identity({'profile':IDENTITY,'protocol':PROTOCOL,'chain_id':queue.chain,
            'contract':verifier.contract.lower(),'registry':verifier.registry.contract.lower(),
            'application':verifier.app.lower(),'definition_hash':verifier.registry.definition,
            'native_sha256':verifier.native.sha256.hex()})
        require(reader.contract.lower()==self.identity['contract'] and reader.app.lower()==self.identity['application']
            and state.namespace==self.identity['definition_hash'] and state.backend is verifier.registry,
            'base-service-components')
        require(read(queue.rpc,verifier.contract,'application()').lower()==verifier.app.lower()
            and '0x'+read(queue.rpc,verifier.contract,'issuer()')[-40:].lower()==self.identity['registry']
            and read(queue.rpc,self.identity['registry'],'definition()')=='0x'+state.namespace,
            'base-service-contract')
        selectors={keccak(b'publishOrdinary(bytes32,bytes32,bytes)')[:10],
            keccak(b'publish((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint256,uint256,uint256,uint256),bytes,bytes,bytes,uint8,bytes32,bytes32)')[:10]}
        require(set(queue.contracts)=={self.identity['contract']}
            and set(queue.contracts[self.identity['contract']])==selectors,'base-service-sponsor-scope')
        require(verifier.key.address.lower()!=queue.signer.address.lower(),'base-service-key-separation')
        self._lock=threading.RLock()
        require(counts is None or counts.protected_state is state,'base-service-components')
        self.counts=counts
        self.count_verifier=None
        if counts is not None:
            from count_receipts import CountReceiptVerifier
            self.count_verifier=CountReceiptVerifier(verifier,counts.native)
            require(reader.count_native is None or reader.count_native.sha256==counts.native.sha256,'base-service-components')
            reader.count_native=counts.native

    def _ready(self):
        if hasattr(self.state,'poll_boot'):
            require(self.state.poll_boot()['state']=='ready','issuer-not-ready')

    def _submit(self,body):
        self.fields(body,['post','facts','submission_id','challenge','proof','approve_publication'])
        require(body['approve_publication'] is True,'consent-required')
        post=body['post'];data=payload(post);require(len(data)<=8192,'publication-size')
        selected=body['facts'];require(type(selected) is list,'post-facts')
        submission=body['submission_id'];hex_string(submission,64)
        require(any(bytes.fromhex(submission)),'message-schema')
        if selected:
            require(selected==facts(selected) and type(body['challenge']) is dict and type(body['proof']) is dict,
                'post-facts')
            require(body['challenge'].get('nonce')==submission,'post-context')
        else:
            require(body['challenge'] is None and body['proof'] is None and post['claims']==[],'ordinary-post')
        # Commit the exact originating application request independently of the
        # randomized ECDSA receipt signature. Recovery never signs again.
        request_hash=hashlib.sha256(canonical({'profile':RPC,'identity':self.identity,'body':body})).hexdigest()
        recovered=self.queue.recover(submission,request_hash)
        if recovered is not None:return recovered
        if selected:
            self._ready()
            package=self.verifier.approve(post,selected,body['challenge'],body['proof'])
            call_data=publication_data(package)
        else:call_data=ordinary_publication_data(post,submission)
        return self.queue.submit(submission,self.identity['contract'],call_data,self.queue.limits.max_gas,
            operation_hash=request_hash)

    def operate(self,op,body):
        # Keep all state-sensitive operations within one bounded application
        # lock. No private issuer state enters the public proof verifier.
        with self._lock:
            if op=='count-post-submit':return self._count_submit(body)
            if op=='count-post-challenge':
                require(self.counts is not None,'count-service-unavailable');self._ready()
                self.fields(body,['post','facts','threshold','submission_id'])
                require(len(payload(body['post']))<=8192,'publication-size')
                from count_protocol import challenge as count_challenge
                view=self.state.backend.public_view()
                return count_challenge(body['post'],body['facts'],body['threshold'],self.verifier.app,self.queue.chain,
                    self.verifier.contract,view['sequence'],self.clock(),body['submission_id'])
            if op in COUNT_OPERATIONS:
                require(self.counts is not None,'count-service-unavailable')
                if op not in ('count-parameters','count-registry','count-status','count-activation-status'):self._ready()
                return self.counts.operate(op[6:],body)
            if op=='parameters':
                self.fields(body,[]);return copy.deepcopy(self.identity)
            if op=='post-submit':return self._submit(body)
            if op=='post-status':
                self.fields(body,['submission_id']);hex_string(body['submission_id'],64)
                return self.queue.poll(body['submission_id'])
            if op=='post-challenge':
                self.fields(body,['post','facts','submission_id']);self._ready()
                require(len(payload(body['post']))<=8192,'publication-size')
                selected=facts(body['facts']);require(selected==body['facts'],'post-facts')
                hex_string(body['submission_id'],64)
                view=self.state.backend.public_view()
                return challenge(body['post'],selected,self.verifier.app,self.queue.chain,self.verifier.contract,
                    view['sequence'],self.clock(),body['submission_id'])
            if op=='discussion':
                self.fields(body,['after','limit'])
                require(type(body['after']) is int and 0<=body['after']<=2**53-1
                    and type(body['limit']) is int and 1<=body['limit']<=20,'message-schema')
                results=self.reader.read(self.clock());available=[];unavailable=[]
                for item in results:
                    if item['state']=='unavailable':
                        if len(unavailable)<20:unavailable.append(item)
                    elif int(item['post_number'])>body['after']:available.append(item)
                page=[]
                for item in available[:body['limit']]:
                    if len(canonical(page+[item]))>MAX_RESPONSE-8192:break
                    page.append(item)
                require(not available or bool(page),'publication-size')
                return {'identity':copy.deepcopy(self.identity),'posts':page,'unavailable':unavailable,
                    'next_after':int(page[-1]['post_number']) if page else body['after'],
                    'more':len(available)>len(page),'sync_complete':self.reader.sync_complete,
                    'checkpoint':copy.deepcopy(self.reader.checkpoint),'sync_target':copy.deepcopy(self.reader.sync_target)}
            if op=='activation-status':
                self.fields(body,['session'])
                require(hasattr(self.state,'finalized_status'),'issuer-finality-required')
                return self.state.finalized_status(self.session(body['session']))
            require(op in ISSUER_OPERATIONS,'message-schema')
            if op not in ('registry','status','abort'):self._ready()
            return super().operate(op,body)

    def _count_submit(self,body):
        require(self.count_verifier is not None,'count-service-unavailable')
        self.fields(body,['post','facts','threshold','submission_id','challenge','proof','approve_publication'])
        require(body['approve_publication'] is True,'consent-required')
        post=body['post'];require(len(payload(post))<=8192 and post['claims']==[],'publication-size')
        from count_protocol import selection
        selection(body['facts'],body['threshold'])
        submission=body['submission_id'];hex_string(submission,64)
        require(any(bytes.fromhex(submission)) and type(body['challenge']) is dict and type(body['proof']) is dict
            and body['challenge'].get('nonce')==submission,'post-context')
        request_hash=hashlib.sha256(canonical({'profile':RPC,'operation':'count-post-submit',
            'identity':self.identity,'body':body})).hexdigest()
        recovered=self.queue.recover(submission,request_hash)
        if recovered is not None:return recovered
        self._ready()
        package=self.count_verifier.approve(post,body['facts'],body['threshold'],body['challenge'],body['proof'])
        return self.queue.submit(submission,self.identity['contract'],publication_data(package),self.queue.limits.max_gas,
            operation_hash=request_hash)

    def dispatch(self,message):
        ident='0'*32
        try:
            validate_request(message);ident=message['id']
            result=self.operate(message['operation'],copy.deepcopy(message['body']))
            require(type(result) is dict and len(canonical(result))<=MAX_RESPONSE-256,'base-result-size')
            return {'profile':RPC,'id':ident,'status':'ok','result':result,'experimental':True}
        except Exception as error:
            code=error.args[0] if isinstance(error,Rejected) and error.args and error.args[0] in ERRORS else 'base-operation-unavailable'
            return {'profile':RPC,'id':ident,'status':'rejected','code':code,'experimental':True}

    def dispatch_bytes(self,data):
        try:message=strict_json(data,max_bytes=MAX_REQUEST)
        except Exception:message=None
        return canonical(self.dispatch(message))
