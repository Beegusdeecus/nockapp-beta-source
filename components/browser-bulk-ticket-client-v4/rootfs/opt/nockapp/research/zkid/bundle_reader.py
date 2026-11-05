"""Selective v3 downloads from canonical chain records and untrusted replicas.

No server listing, author connection or verifier archive establishes acceptance.
Unavailable bytes keep their canonical numbers; commitments cannot restore text.
"""
from collections import OrderedDict
import copy
from base_evm import encode
from base_protocol import keccak,words,sha
from bundle_acceptance import check_evidence
from policy import Rejected,canonical,hex_string,require
from public_bundle import decode,commitments

EVENT= b'Accepted(bytes32,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint64,uint8)'
ZERO='0x'+'00'*32


class BundleReader:
    protocol_version=3
    accepted_kinds=(0,1,2)
    def __init__(self,rpc,contract,registry,app,store,native=None,count_native=None,*,chain_id=84532,laboratory=False,
                 runtime_code=None,checkpoint_store=None,proof_cache_entries=128):
        require(chain_id==84532 or laboratory is True and chain_id==31337,'bundle-reader-chain')
        require(laboratory is True or type(runtime_code) is dict and set(runtime_code)=={contract,registry.contract},
            'bundle-reader-code-pins')
        if runtime_code is not None:rpc.check_identity(runtime_code)
        self.rpc,self.contract,self.registry,self.app,self.store=rpc,contract,registry,app,store
        self.native,self.count_native,self.chain_id=native,count_native,chain_id
        require(type(proof_cache_entries) is int and 1<=proof_cache_entries<=4096,'bundle-proof-cache-limit')
        self._proof_cache=OrderedDict();self._proof_cache_entries=proof_cache_entries
        self._checkpoint_store=checkpoint_store
        self._scope=sha(canonical({'chain':chain_id,'contract':contract,'registry':registry.contract,
            'issuer_definition':registry.definition,'application':app,'protocol':self.protocol_version}))
        self.checkpoint=checkpoint_store.get_checkpoint(self._scope) if checkpoint_store is not None else None

    def _call(self,contract,signature,*args,tag):
        return self.rpc.call('eth_call',{'to':contract,'data':encode(signature,*args)},tag)

    def _finalized(self):
        require(int(self.rpc.call('eth_chainId'),16)==self.chain_id,'bundle-reader-chain')
        block=self.rpc.call('eth_getBlockByNumber','finalized',False);require(block is not None,'bundle-finality-unavailable')
        if self.checkpoint is not None:
            prior=self.rpc.call('eth_getBlockByNumber',self.checkpoint['number'],False)
            require(prior is not None and prior['hash']==self.checkpoint['hash']
                and int(block['number'],16)>=int(self.checkpoint['number'],16),'bundle-finality-violation')
        tag=block['number']
        require(int(self._call(self.contract,'PROTOCOL_VERSION()',tag=tag),16)==self.protocol_version
            and self._call(self.contract,'application()',tag=tag).lower()==self.app
            and '0x'+self._call(self.contract,'issuer()',tag=tag)[-40:].lower()==self.registry.contract,'bundle-reader-application')
        require(self._call(self.registry.contract,'definition()',tag=tag)=='0x'+self.registry.definition,'bundle-reader-issuer')
        return block

    def _finish(self,final):
        anchor=self.rpc.call('eth_getBlockByNumber',final['number'],False)
        require(anchor is not None and anchor['hash']==final['hash'],'bundle-history-reorg')
        self.checkpoint={'number':final['number'],'hash':final['hash']}
        if self._checkpoint_store is not None:self._checkpoint_store.put_checkpoint(self._scope,self.checkpoint)

    def _evidence(self,value,header):
        if not header['credential_kind']:
            return check_evidence(value,self.registry.definition,self.native,self.count_native,header['accepted_at'])
        def pin(native):return native.sha256.hex() if native is not None else None
        key=(header['bundle_hash'],self.registry.definition,pin(self.native),pin(self.count_native),header['accepted_at'])
        if key in self._proof_cache:
            self._proof_cache.move_to_end(key);return copy.deepcopy(self._proof_cache[key])
        checked=check_evidence(value,self.registry.definition,self.native,self.count_native,header['accepted_at'])
        self._proof_cache[key]=copy.deepcopy(checked)
        while len(self._proof_cache)>self._proof_cache_entries:self._proof_cache.popitem(last=False)
        return checked

    def _header(self,number,final):
        tag=final['number'];submission=self._call(self.contract,'submissionsByNumber(uint64)',number,tag=tag)
        require(submission!=ZERO,'bundle-index-gap');hex_string(submission[2:],64)
        record=words(self._call(self.contract,'records(bytes32)',submission,tag=tag));require(len(record)==5,'bundle-record')
        digest='0x'+record[0].hex();actual,block_number,accepted_at,kind=[int.from_bytes(w,'big') for w in record[1:]]
        require(actual==number and 0<block_number<=int(tag,16) and kind in self.accepted_kinds,'bundle-record')
        logs=self.rpc.call('eth_getLogs',{'address':self.contract,'fromBlock':hex(block_number),'toBlock':hex(block_number),
            'topics':[keccak(EVENT),submission]})
        require(type(logs) is list and len(logs)==1,'bundle-index-gap');log=logs[0]
        require(log['address'].lower()==self.contract and len(log['topics'])==4 and not log.get('removed',False)
            and log['topics'][0]==keccak(EVENT) and log['topics'][1]==submission,'bundle-event')
        event=words(log['data']);require(len(event)==8,'bundle-event')
        numbers=[int.from_bytes(w,'big') for w in event[2:]]
        sequence,event_number,event_time,observed,expiry,event_kind=numbers
        require('0x'+event[0].hex()==digest and event_number==number and event_time==accepted_at and event_kind==kind,'bundle-event')
        block=self.rpc.call('eth_getBlockByNumber',hex(block_number),False)
        receipt=self.rpc.call('eth_getTransactionReceipt',log['transactionHash'])
        require(block is not None and block['hash']==log['blockHash'] and int(block['timestamp'],16)==accepted_at
            and int(log['blockNumber'],16)==block_number and receipt is not None and receipt['status']=='0x1'
            and receipt['blockHash']==block['hash'] and receipt.get('to','').lower()==self.contract
            and log in receipt['logs'],'bundle-canonical-receipt')
        return {'submission_id':submission[2:],'post_id':log['topics'][2],'thread_id':log['topics'][3],
            'bundle_hash':digest,'registry_hash':'0x'+event[1].hex(),'registry_sequence':sequence,'post_number':str(number),
            'accepted_at':accepted_at,'observed_at':observed,'credential_expiry':expiry,'credential_kind':kind,
            'block_hash':block['hash'],'block_number':block_number,'transaction_hash':log['transactionHash']}

    def _content(self,header,now,current_hash):
        base={**header,'canonical_accepted':True,'post':None,'content_integrity_checked':False,
            'credential_evidence_checked':False,'valid_when_published':None}
        fetched=self.store.fetch(header['bundle_hash'])
        if fetched['state']=='content-unavailable':return {**base,'state':'content-unavailable','credential_status':'unavailable'}
        try:
            value=self._bound_content(fetched['data'],header)
            base.update(post=value['post'],selection=value['selection'],content_integrity_checked=True)
            checked=self._evidence(value,header)
            require(checked['registryHash']==header['registry_hash'] and checked['registrySequence']==header['registry_sequence']
                and checked['observedAt']==header['observed_at'] and checked['credentialExpiry']==header['credential_expiry'],
                'bundle-evidence-binding')
            kind=header['credential_kind']
            status=('not-requested' if not kind else 'expired' if now>=header['credential_expiry'] else
                'valid-at-current-registry' if current_hash==header['registry_hash'] else 'unknown-after-registry-update')
            return {**base,'state':'finalized','valid_when_published':True,'credential_evidence_checked':kind!=0,
                'credential_status':status,'disclosed_follower_count':checked['disclosed_count'],'public_id':None,
                'content_source':fetched['source'],'experimental':True}
        except Rejected as error:
            unavailable=error.args==('bundle-verifier-unavailable',)
            return {**base,'state':'evidence-unavailable' if unavailable else 'verification-failed',
                'valid_when_published':None if unavailable else False,'credential_status':'unavailable' if unavailable else 'invalid'}
        except Exception:return {**base,'state':'verification-failed','valid_when_published':False,'credential_status':'invalid'}

    def _bound_content(self,data,header):
        value=decode(data,header['bundle_hash']);bound=commitments(value)
        require(value['context']=={'application':self.app,'chain_id':self.chain_id,'contract':self.contract,
            'submission_id':header['submission_id']},'bundle-application')
        require(bound['postId']==header['post_id'] and bound['threadId']==header['thread_id']
            and bound['credentialKind']==header['credential_kind'],'bundle-content-binding')
        return value

    def export_public(self,number):
        require(type(number) is int and 0<number<2**53,'bundle-archive-number')
        final=self._finalized();header=self._header(number,final)
        fetched=self.store.fetch(header['bundle_hash'])
        require(fetched['state']=='available','bundle-archive-unavailable')
        self._bound_content(fetched['data'],header);self._finish(final)
        # Only exact public bytes; no saved verdict, witness, wallet or outbox.
        return header['bundle_hash'],fetched['data']

    def restore_public(self,number,data):
        require(type(number) is int and 0<number<2**53,'bundle-archive-number')
        final=self._finalized();header=self._header(number,final)
        self._bound_content(data,header);self._finish(final)
        # Archives are retrieval sources. A future read rechecks canonical
        # acceptance and native proof evidence before presenting any badge.
        cached=self.store.cache.put(header['bundle_hash'],data)
        return {'post_number':str(number),'bundle_hash':header['bundle_hash'],
            'cached':cached,'verification_required':True,'experimental':True}

    def read_numbers(self,numbers,now):
        require(type(numbers) is list and 0<len(numbers)<=8 and len(set(numbers))==len(numbers)
            and all(type(n) is int and 0<n<2**53 for n in numbers),'bundle-page')
        final=self._finalized();tag=final['number']
        last=int(self._call(self.contract,'nextPostNumber()',tag=tag),16)-1
        try:current=self._call(self.registry.contract,'registryHash()',tag=tag)
        except Exception:current=None
        results=[]
        for number in numbers:
            if number>last:results.append({'post_number':str(number),'state':'not-accepted','canonical_accepted':False});continue
            try:results.append(self._content(self._header(number,final),now,current))
            except Exception:results.append({'post_number':str(number),'state':'acceptance-unavailable','canonical_accepted':False})
        self._finish(final)
        return {'posts':results,'last_canonical_number':str(last),'checkpoint':self.checkpoint,
            'scope':'explicit-post-numbers','global_listing_complete':False,'experimental':True}

    def _row_evidence_checked(self,row):
        return row['credential_kind']==0 or row['credential_evidence_checked']

    def read_threads(self,after,limit,now):return self._listing(None,after,limit,now)

    def read_thread(self,thread_id,after,limit,now):
        require(type(thread_id) is str and thread_id.startswith('0x'),'bundle-thread-id')
        hex_string(thread_id[2:],64);require(any(bytes.fromhex(thread_id[2:])),'bundle-thread-id')
        return self._listing(thread_id,after,limit,now)

    def _listing(self,thread_id,after,limit,now):
        require(type(after) is int and 0<=after<2**53 and type(limit) is int and 1<=limit<=8,'bundle-page')
        final=self._finalized();tag=final['number']
        require(int(self._call(self.contract,'INDEX_VERSION()',tag=tag),16)==1,'bundle-index-version')
        if thread_id is None:
            count=int(self._call(self.contract,'threadCount()',tag=tag),16);accepted=None
            def number_at(ordinal):return int(self._call(self.contract,'threadNumbers(uint64)',ordinal,tag=tag),16)
        else:
            accepted=int(self._call(self.contract,'threads(bytes32)',thread_id,tag=tag),16)==1
            count=int(self._call(self.contract,'threadPostCount(bytes32)',thread_id,tag=tag),16)
            require(accepted and count>0 or not accepted and count==0,'bundle-index-gap')
            def number_at(ordinal):
                return int(self._call(self.contract,'threadPostNumbers(bytes32,uint64)',thread_id,ordinal,tag=tag),16)
        require(0<=after<=count<2**53,'bundle-index-cursor')
        last=int(self._call(self.contract,'nextPostNumber()',tag=tag),16)-1
        try:current=self._call(self.registry.contract,'registryHash()',tag=tag)
        except Exception:current=None
        end=min(count,after+limit);posts=[];gaps=[];previous=0
        if after:
            try:previous=number_at(after);require(0<previous<=last,'bundle-index-gap')
            except Exception:previous=None;gaps.append(after)
        for ordinal in range(after+1,end+1):
            try:
                number=number_at(ordinal)
                require(0<number<=last and (previous is None or number>previous),'bundle-index-gap')
                previous=number;header=self._header(number,final)
                require(header['thread_id']==thread_id if thread_id is not None else
                    header['post_id']==header['thread_id'],'bundle-index-membership')
                posts.append({'ordinal':ordinal,**self._content(header,now,current)})
            except Exception:
                gaps.append(ordinal)
                posts.append({'ordinal':ordinal,'state':'index-gap','canonical_accepted':False,'post':None})
        self._finish(final)
        complete=after==0 and end==count and not gaps
        return {'posts':posts,'scope':'thread' if thread_id is not None else 'thread-catalog','thread_id':thread_id,
            'thread_accepted':accepted,'canonical_total_count':str(count),'last_canonical_number':str(last),
            'after':after,'next_after':end,'more':end<count,'index_gaps':gaps,'page_complete':not gaps,
            'listing_complete':complete,'global_listing_complete':False,
            'page_content_complete':not gaps and all(p['content_integrity_checked'] for p in posts),
            'page_evidence_complete':not gaps and all(self._row_evidence_checked(p) for p in posts),
            'content_complete':complete and all(p['content_integrity_checked'] for p in posts),
            'checkpoint':copy.deepcopy(self.checkpoint),'experimental':True}
