"""Protocol4 durable public outbox + protected author + independent Base reader.

All endpoints/paths/pins are installer-owned. Browser projections contain no
credential/holder key. Exact complete bundles survive signing-state release.
"""
import copy
import os
from pathlib import Path
import secrets
import ssl
import time

from authorship import intent,validate_intent
from authorship_desktop import AuthorshipDesktop
from authored_bundle_reader import AuthoredBundleReader
from authored_bundle_transport import AuthoredBundleRemote,validate_approval
from authored_count import trust as count_trust
from base_protocol import read,sha
from bundle_desktop import BundleDesktop,validate_chain
from bundle_disk_cache import DiskPublicCache
from count_service import validate_count_approval
from count_state import count_view
from count_transport import CountRemote
from policy import Rejected,canonical,digest,hex_string,require
from public_bundle_v4 import build,encode,commitments,post_intent
from public_s3 import S3PublicReplica
from public_storage import ReplicatedPublicStore
from post_scope import payload,uuid
from wallet_authorship import post_data

PROFILE='nockapp-authored-bundle-desktop-v4'
PHASES={'prepared','authored','challenge-saved','wallet-needed','bundle-saved','submitted'}
ZERO='0x'+'00'*32


class AuthoredBundleDesktop(BundleDesktop):
    record_names=BundleDesktop.record_names|frozenset(('authorship-requests.json','authorship-responses.json'))

    def history_request(self,numbers,approve_request):
        from authored_history_desktop import AuthoredHistoryDesktop
        return AuthoredHistoryDesktop(self).request(numbers,approve_request)

    def history_prove(self,request,approve_linking):
        from authored_history_desktop import AuthoredHistoryDesktop
        return AuthoredHistoryDesktop(self).prove(request,approve_linking)

    def history_verify(self,response,request_sha256):
        from authored_history_desktop import AuthoredHistoryDesktop
        return AuthoredHistoryDesktop(self).verify(response,request_sha256)

    def history_requests(self,after,limit):
        from authored_history_desktop import AuthoredHistoryDesktop
        return AuthoredHistoryDesktop(self).requests(after,limit)
    def __init__(self,directory,approved,chain,author,*,count_desktop=None,count_approval=None,clock=time.time):
        self.approved=copy.deepcopy(validate_approval(approved));self.chain=copy.deepcopy(validate_chain(chain,approved))
        self.identity=copy.deepcopy(approved['identity']);self.remote=AuthoredBundleRemote(approved)
        require(isinstance(author,AuthorshipDesktop) and author.native.sha256==self.identity['author_native_sha256'],'author-native-identity')
        expected={k:self.identity[k] for k in ('protocol','chain_id','application','contract')}
        expected['issuer_definition']=self.identity['definition_hash'];require(author.binding==expected,'author-desktop-binding')
        self.author=author;self.count_desktop=count_desktop;self.count_approval=None;self.clock=clock
        self.root=Path(directory);self.wallet_directory=str(author.wallet.directory)
        require(self.root.is_absolute() and '..' not in self.root.parts and not any(p.is_symlink() for p in (self.root,*self.root.parents))
            and not any(p.startswith('.env') for p in self.root.parts),'bundle-desktop-directory')
        wallets=[author.wallet.directory]
        if count_desktop is not None:
            require(count_approval is not None and count_desktop in author.legacy_sources,'author-count-config')
            self.count_approval=copy.deepcopy(validate_count_approval(count_approval));wallets.append(count_desktop.wallet.directory)
            require(self.count_approval['native_sha256']==self.identity['count_native_sha256']==count_desktop.native.sha256.hex(),
                'count-native-identity')
        else:require(count_approval is None,'author-count-config')
        for p in wallets:require(not p.is_relative_to(self.root) and not self.root.is_relative_to(p),'bundle-desktop-directory')
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700);st=self.root.stat()
        require(st.st_uid==os.getuid() and not st.st_mode&0o077,'bundle-desktop-directory')
        storage=self.chain['storage'];self.cache=DiskPublicCache(self.root/'public-cache',max_bytes=storage['cache_bytes'],max_entries=storage['cache_entries'])
        context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.store=ReplicatedPublicStore([S3PublicReplica(r['name'],r['region'],r['bucket'],context) for r in storage['replicas']],
            cache=self.cache,retention_seconds=storage['retention_seconds'])
        self._rpc=None;self._registry=None;self._reader=None;self._native=None;self._count_native=None
        self.scope={k:self.identity[k] for k in ('protocol','chain_id','contract','registry','application','definition_hash','bundle_profile')}

    def initialize_identity(self,approve_private_key_setup):
        require(approve_private_key_setup is True,'consent-required')
        with self.lock():
            if self.author.wallet.read('credential.sealed',missing=True) is not None:return self.author.status()
            # Reuse the active count holder first so optional badges and author
            # proofs keep one key; preserve any separate legacy records.
            sources=list(self.author.legacy_sources)
            if self.count_desktop in sources:sources.remove(self.count_desktop);sources.insert(0,self.count_desktop)
            for source in sources:
                require(source.wallet.read('pending.sealed',missing=True) is None,'author-legacy-recovery-required')
                if source.wallet.read('credential.sealed',missing=True) is not None:
                    return self.author.adopt(source,int(self.clock()),True)
            return self.author.initialize(int(self.clock()),True)

    def capabilities(self):
        return {'configured':True,'identity':copy.deepcopy(self.identity),'count_enrollment_configured':self.count_desktop is not None,'experimental':True}

    def _context(self,submission):return {'protocol':4,**super()._context(submission)}

    def _intent(self,row):
        return intent(row['post'],self._context(row['submission_id']),disclose_address=row['selection']['address'],
            followers_threshold=row['selection']['followers_threshold'])

    def _reader_instance(self):
        if self._reader is None:
            rpc,registry=self._chain()
            if self.identity['count_native_sha256'] is not None and self._count_native is None:
                from count_pipeline import CountNative
                self._count_native=CountNative();require(self._count_native.sha256.hex()==self.identity['count_native_sha256'],'count-native-identity')
            self._reader=AuthoredBundleReader(rpc,self.identity['contract'],registry,self.identity['application'],self.store,
                author_native=self.author.native,count_native=self._count_native,chain_id=self.identity['chain_id'],
                runtime_code=self.chain['runtime_code'],checkpoint_store=self.cache)
        return self._reader

    def _outbox(self):
        box=self._read('outbox.json',missing=True)
        if box is None:return {'profile':PROFILE,'scope':copy.deepcopy(self.scope),'entries':[]}
        require(type(box) is dict and set(box)=={'profile','scope','entries'} and box['profile']==PROFILE and box['scope']==self.scope
            and type(box['entries']) is list and len(box['entries'])<=100,'authored-outbox')
        seen=set();submissions=set()
        for row in box['entries']:
            require(type(row) is dict and set(row)=={'post','selection','submission_id','phase','challenge_response','bundle','status','previous_attempts','wallet_request'}
                and row['phase'] in PHASES and type(row['previous_attempts']) is list and len(row['previous_attempts'])<=3,'authored-outbox')
            validate_intent(self._intent(row));hex_string(row['submission_id'],64)
            require(row['post']['id'] not in seen and row['submission_id'] not in submissions,'authored-outbox')
            seen.add(row['post']['id']);submissions.add(row['submission_id'])
            if row['bundle'] is not None:
                encode(row['bundle']);require(post_intent(row['bundle'])==self._intent(row),'authored-outbox')
            require((row['bundle'] is not None)==(row['phase'] in ('bundle-saved','submitted')),'authored-outbox')
            if row['wallet_request'] is not None:
                q=row['wallet_request']
                require(row['selection']['address'] is True and type(q) is dict
                    and set(q)=={'address','nonce','created_at','expires_at','request_sha256'}
                    and type(q['created_at']) is int and type(q['expires_at']) is int
                    and q['expires_at']-q['created_at']==60,'authored-outbox')
                from wallet_authorship import address
                address(q['address']);hex_string(q['nonce'],64);hex_string(q['request_sha256'],64)
            if row['challenge_response'] is not None:self._expected_challenge(row,row['challenge_response'],fresh=False)
            if row['status'] is not None:
                self._status_schema(row['status'])
        return box

    @staticmethod
    def _status_schema(status):
        allowed={'state','transaction_hash','post_number','checked_at','recovery_action','last_known',
            'authorship_checked','address_evidence_checked','credential_evidence_checked','content_state'}
        require(type(status) is dict and set(status)<=allowed and {'state','checked_at'}<=set(status)
            and status['state'] in ('pending','confirmed','finalized','failed','recoverable')
            and type(status['checked_at']) is int and 0<=status['checked_at']<2**53,'authored-outbox-status')
        for key in ('authorship_checked','address_evidence_checked','credential_evidence_checked'):
            if key in status:require(type(status[key]) is bool,'authored-outbox-status')
        if 'transaction_hash' in status:
            tx=status['transaction_hash'];require(type(tx) is str and tx.startswith('0x'),'authored-outbox-status');hex_string(tx[2:],64)
        if 'content_state' in status:require(status['content_state']=='locally-retained','authored-outbox-status')
        if status.get('post_number') is not None:
            n=status['post_number'];require(type(n) is str and n.isascii() and n.isdigit() and 0<int(n)<2**53,'authored-outbox-status')
        if 'last_known' in status:
            old=status['last_known'];require(type(old) is dict and set(old)<={'state','transaction_hash','post_number','checked_at'},'authored-outbox-status')
            AuthoredBundleDesktop._status_schema(old)
        if 'recovery_action' in status:require(status['recovery_action'] in
            ('refresh-independent-verification','sign-with-wallet','recover-same-submission','renew-expired-authorization','set-up-private-signing-identity'),
            'authored-outbox-status')

    def _expected_challenge(self,row,response,*,fresh=True):
        require(self.count_desktop is not None and type(response) is dict
            and set(response)=={'context','selection','issuer_view','challenge'} and response['context']==self._context(row['submission_id'])
            and response['selection']==row['selection'],'author-count-challenge')
        view=count_view(self.count_desktop.native,response['issuer_view']);c=response['challenge']
        t=count_trust(self._intent(row),view,c['created_at']);require(c==t['legacy']['challenge'],'author-count-challenge')
        if fresh:require(c['created_at']<=int(self.clock())<c['expires_at'],'action-expired')
        return view,c

    def _projection(self,row,*,fresh=False):
        status=copy.deepcopy(row['status']) if row['status'] is not None else {'state':'recoverable','checked_at':int(self.clock())}
        if not fresh:
            for k in ('authorship_checked','address_evidence_checked','credential_evidence_checked'):status[k]=False
            if status['state']=='finalized':
                status={'state':'recoverable','checked_at':int(self.clock()),'recovery_action':'refresh-independent-verification',
                    'last_known':{k:status[k] for k in ('state','transaction_hash','post_number','checked_at') if k in status}}
        for k in ('authorship_checked','address_evidence_checked','credential_evidence_checked'):status.setdefault(k,False)
        return {'post':copy.deepcopy(row['post']),'selection':copy.deepcopy(row['selection']),'submission_id':row['submission_id'],
            'phase':row['phase'],'status':status,'renewal_count':len(row['previous_attempts']),'experimental':True}

    def _release(self,row):
        if row['bundle'] is not None:
            self.author.release_saved_post(self,row['post']['id'],commitments(row['bundle'])['bundleHash'])

    def _prepare(self,box,row):
        if self.author.wallet.read('post.sealed',missing=True) is not None:
            active=self.author._post()['intent']['context']['submission_id']
            if active!=row['submission_id']:
                previous=next((p for p in row['previous_attempts'] if p['submission_id']==active),None)
                if previous is not None:
                    if previous['bundle'] is not None:self._release(previous)
                    else:self.author.retire_expired_post(self._reader_instance(),active,coordinator=self)
        self.author.prepare_post(self._intent(row),int(self.clock()),True)
        row['phase']='authored';self._write('outbox.json',box)
        if row['selection']['followers_threshold'] is not None:
            require(self.count_desktop is not None,'count-wallet-unavailable')
            if row['challenge_response'] is None:
                response=self.remote.call('post-challenge',{'post':row['post'],'selection':row['selection'],'submission_id':row['submission_id']})
                self._expected_challenge(row,response);row['challenge_response']=response;row['phase']='challenge-saved';self._write('outbox.json',box)
            view,c=self._expected_challenge(row,row['challenge_response'])
            current=self.author._post()['credential_evidence']
            if current is None:
                remote=CountRemote(self.remote,self.count_approval,self.count_desktop.native)
                witness=remote.refresh_witness(self.count_desktop.witness_handle(),view)
                self.author.attach_count(self.count_desktop,view,witness,int(self.clock()),canonical_view=row['challenge_response']['issuer_view'],challenge=c)
            else:require(current['issuer_view']==row['challenge_response']['issuer_view'] and current['challenge']==c,'author-count-challenge')
        if row['selection']['address'] and self.author._post()['address_signature'] is None:
            row['phase']='wallet-needed';row['status']={'state':'recoverable','checked_at':int(self.clock()),'recovery_action':'sign-with-wallet'}
            if row['wallet_request'] is not None and int(self.clock())>=self._expiry(row):
                row['status']['recovery_action']='renew-expired-authorization'
            self._write('outbox.json',box);return False
        row['bundle']=build(self.author.material());row['phase']='bundle-saved';self._write('outbox.json',box)
        self._release(row)  # Only after exact signed bytes are durably written and read back.
        return True

    def _accepted(self,row):
        reader=self._reader_instance();final=reader._finalized();submission='0x'+row['submission_id']
        number=int(reader._call(self.identity['contract'],'postNumbers(bytes32)',submission,tag=final['number']),16)
        if not number:reader._finish(final);return None
        header=reader._header(number,final);bound=commitments(row['bundle'])
        require(all(header[k]==bound[v] for k,v in [('bundle_hash','bundleHash'),('post_id','postId'),('thread_id','threadId'),
            ('credential_kind','credentialKind')]),'authored-canonical-conflict')
        checked=reader._evidence(row['bundle'],header)
        require(all(checked[k]==header[h] for k,h in [('registryHash','registry_hash'),('registrySequence','registry_sequence'),
            ('observedAt','observed_at'),('credentialExpiry','credential_expiry')]),'authored-canonical-evidence')
        reader._finish(final);self.cache.put(bound['bundleHash'],encode(row['bundle']))
        return {'state':'finalized','transaction_hash':header['transaction_hash'],'post_number':str(number),'checked_at':int(self.clock()),
            'authorship_checked':True,'address_evidence_checked':checked['address_checked'],
            'credential_evidence_checked':row['selection']['followers_threshold'] is not None,'content_state':'locally-retained'}

    def _remote_status(self,row,value):
        require(type(value) is dict and value.get('submission_id')==row['submission_id'],'base-submission-status')
        tx=value.get('transaction_hash');require(type(tx) is str and tx.startswith('0x'),'base-submission-status');hex_string(tx[2:],64)
        rpc,_=self._chain();receipt=rpc.call('eth_getTransactionReceipt',tx);now=int(self.clock())
        if receipt is None:return {'state':'pending','transaction_hash':tx,'post_number':None,'checked_at':now}
        require(receipt.get('to','').lower()==self.identity['contract'] and receipt['transactionHash']==tx,'base-submission-receipt')
        block=rpc.call('eth_getBlockByNumber',receipt['blockNumber'],False);final=rpc.call('eth_getBlockByNumber','finalized',False)
        require(block is not None and block['hash']==receipt['blockHash'] and final is not None,'base-submission-receipt')
        if int(final['number'],16)<int(receipt['blockNumber'],16):return {'state':'confirmed','transaction_hash':tx,'post_number':None,'checked_at':now}
        require(receipt['status'] in ('0x0','0x1'),'base-submission-receipt')
        if receipt['status']=='0x0':return {'state':'failed','transaction_hash':tx,'post_number':None,'checked_at':now}
        result=self._accepted(row);require(result is not None and result['transaction_hash']==tx,'authored-canonical-conflict');return result

    def _run(self,box,row):
        try:
            if row['bundle'] is None and not self._prepare(box,row):return self._projection(row,fresh=True)
            # Independent canonical recovery precedes remote service availability
            # and proof/wallet deadlines. No new signing material is generated.
            try:self._release(row)
            except Exception:pass  # Complete public bytes remain durable; keyring may be locked.
            accepted=self._accepted(row)
            if accepted is not None:row['status']=accepted;row['phase']='submitted'
            else:
                reply=self.remote.call('post-submit',{'bundle':copy.deepcopy(row['bundle']),'approve_publication':True})
                row['status']=self._remote_status(row,reply);row['phase']='submitted'
        except Exception as error:
            previous=row['status'];action='recover-same-submission'
            if row['bundle'] is None and row['phase']=='wallet-needed':action='sign-with-wallet'
            if row['challenge_response'] is not None and int(self.clock())>=row['challenge_response']['challenge']['expires_at']:action='renew-expired-authorization'
            if row['wallet_request'] is not None and int(self.clock())>=self._expiry(row):action='renew-expired-authorization'
            if isinstance(error,Rejected) and error.args and error.args[0] in ('author-identity-missing','author-key-adoption-required'):
                action='set-up-private-signing-identity'
            row['status']={'state':'recoverable','checked_at':int(self.clock()),'recovery_action':action}
            if previous is not None and previous.get('state') in ('finalized','failed'):
                row['status']['last_known']={k:previous[k] for k in ('state','transaction_hash','post_number','checked_at') if k in previous}
        self._write('outbox.json',box);return self._projection(row,fresh=True)

    def publish(self,post,selected,approve_publication):
        require(approve_publication is True,'consent-required')
        with self.lock():
            box=self._outbox();row=next((r for r in box['entries'] if r['post']['id']==post['id']),None)
            if row is None:
                require(type(selected) is dict and set(selected)=={'address','followers_threshold'},'authored-selection')
                probe={'post':post,'selection':selected,'submission_id':'01'*32};validate_intent(self._intent(probe))
                require(len(box['entries'])<100,'base-desktop-storage-limit')
                row={'post':copy.deepcopy(post),'selection':copy.deepcopy(selected),'submission_id':secrets.token_hex(32),
                    'phase':'prepared','challenge_response':None,'bundle':None,'status':None,'previous_attempts':[],'wallet_request':None}
                box['entries'].append(row);self._write('outbox.json',box)
            require(row['post']==post and row['selection']==selected,'base-post-identity-conflict')
            return self._run(box,row)

    def request_address(self,post_id,account,approve_address_disclosure):
        require(approve_address_disclosure is True,'consent-required');uuid(post_id)
        with self.lock():
            box=self._outbox();row=next((r for r in box['entries'] if r['post']['id']==post_id),None)
            require(row is not None and row['bundle'] is None and row['phase']=='wallet-needed','author-wallet-state')
            require(self.author._post()['intent']==self._intent(row),'author-wallet-state')
            if row['challenge_response'] is not None:self._expected_challenge(row,row['challenge_response'])
            request=self.author.request_address(account,int(self.clock()),True)
            q=self.author._post()['address_request'];row['wallet_request']={**q,'request_sha256':request['request_sha256']}
            self._write('outbox.json',box)
            return {**request,'authorization_expires_at':self._expiry(row)}

    def accept_address(self,post_id,submission_id,request_sha256,signature):
        uuid(post_id);hex_string(submission_id,64);hex_string(request_sha256,64)
        with self.lock():
            box=self._outbox();row=next((r for r in box['entries'] if r['post']['id']==post_id),None)
            require(row is not None and row['submission_id']==submission_id,'author-wallet-state')
            if row['bundle'] is None:
                p=self.author._post();q=p['address_request'];require(p['intent']==self._intent(row) and q is not None,'author-wallet-state')
                data=post_data(p['intent'],p['author_proof'],p['credential_evidence'],q['nonce'],q['created_at'],q['expires_at'])
                require(digest(data)==request_sha256,'author-wallet-response-mismatch')
                self.author.accept_address(signature,int(self.clock()))
            else:
                d=row['bundle']['address_disclosure'];require(d is not None and d['signature']==signature,'author-wallet-signature-conflict')
                data=post_data(post_intent(row['bundle']),row['bundle']['authorship'],row['bundle']['evidence'],d['nonce'],d['created_at'],d['expires_at'])
                require(digest(data)==request_sha256,'author-wallet-response-mismatch')
            return self._run(box,row)

    @staticmethod
    def _expiry(row):
        deadlines=[]
        if row['challenge_response'] is not None:deadlines.append(row['challenge_response']['challenge']['expires_at'])
        if row['wallet_request'] is not None:deadlines.append(row['wallet_request']['expires_at'])
        if row['bundle'] is not None:
            if row['bundle']['evidence'] is not None:deadlines.append(row['bundle']['evidence']['challenge']['expires_at'])
            if row['bundle']['address_disclosure'] is not None:deadlines.append(row['bundle']['address_disclosure']['expires_at'])
        require(deadlines,'authored-renewal-unavailable')
        return min(deadlines)

    def renew(self,post_id,expected_submission_id,approve_fresh_proof):
        require(approve_fresh_proof is True,'consent-required');uuid(post_id);hex_string(expected_submission_id,64)
        with self.lock():
            box=self._outbox();row=next((r for r in box['entries'] if r['post']['id']==post_id),None)
            require(row is not None,'base-post-unavailable')
            if row['submission_id']!=expected_submission_id:
                require(row['previous_attempts'] and row['previous_attempts'][-1]['submission_id']==expected_submission_id,'bundle-renewal-conflict')
                return self._run(box,row)
            require(len(row['previous_attempts'])<3,'bundle-renewal-limit')
            reader=self._reader_instance();final=reader._finalized();expiry=self._expiry(row)
            require(int(final['timestamp'],16)>=expiry,'bundle-renewal-wait-finality')
            require(int(reader._call(self.identity['contract'],'postNumbers(bytes32)','0x'+row['submission_id'],tag=final['number']),16)==0
                and reader._call(self.identity['contract'],'submissionsByPost(bytes32)',sha(post_id.encode()),tag=final['number'])==ZERO,
                'bundle-renewal-already-accepted')
            reader._finish(final)
            old={k:copy.deepcopy(v) for k,v in row.items() if k!='previous_attempts'}
            # Archive any fully completed protected signature before changing ID.
            if old['bundle'] is None and self.author.wallet.read('post.sealed',missing=True) is not None:
                p=self.author._post()
                if p['intent']==self._intent(row):
                    try:old['bundle']=build(self.author.material());old['phase']='bundle-saved'
                    except Rejected:pass
            row.update(submission_id=secrets.token_hex(32),phase='prepared',challenge_response=None,bundle=None,status=None,wallet_request=None,
                previous_attempts=[*row['previous_attempts'],old])
            self._write('outbox.json',box)  # Changed ID and exact old attempt durable BEFORE any new authorization.
            return self._run(box,row)

    def threads(self,after,limit):
        with self.lock():return {'identity':copy.deepcopy(self.identity),**self._reader_instance().read_threads(after,limit,int(self.clock()))}

    def thread(self,thread_id,after,limit):
        with self.lock():return {'identity':copy.deepcopy(self.identity),**self._reader_instance().read_thread(thread_id,after,limit,int(self.clock()))}

    def numbers(self,numbers):
        with self.lock():return {'identity':copy.deepcopy(self.identity),**self._reader_instance().read_numbers(numbers,int(self.clock()))}
