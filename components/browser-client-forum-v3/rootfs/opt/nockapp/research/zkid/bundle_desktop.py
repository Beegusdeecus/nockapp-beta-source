"""V3 holder-side public outbox, canonical reads and selective cache recovery.

No ordinary-post wallet/keyring dependency. Installer owns all locations/pins.
Public bundles, rather than credentials, are persisted in this separate outbox.
"""
import copy
import base64
import os
from pathlib import Path
import secrets
import re
import ssl
import time

from base_desktop import BaseDesktop,validate_chain as legacy_chain,TX_STATES
from bundle_disk_cache import DiskPublicCache
from bundle_reader import BundleReader
from bundle_transport import BundleRemote,validate_approval
from domain_pipeline import Native,definition_hash
from policy import Rejected,hex_string,require
from public_bundle import build,encode,commitments,validate_selection
from public_s3 import S3PublicReplica
from public_s3_endpoints import replicas as validate_replicas
from public_storage import ReplicatedPublicStore
from post_scope import payload,uuid

PROFILE='nockapp-bundle-desktop-v3'
PHASES={'prepared','challenge-saved','bundle-saved','submitted'}
ARCHIVE_PROFILE='nockapp-public-bundle-archive-v1'


def validate_chain(value,approved):
    require(type(value) is dict and set(value)=={'rpc_endpoint','runtime_code','deployment_block','storage'},'bundle-desktop-chain')
    legacy_chain({k:v for k,v in value.items() if k!='storage'},approved)
    storage=value['storage']
    require(type(storage) is dict and set(storage)=={'replicas','retention_seconds','cache_bytes','cache_entries'},'bundle-desktop-storage')
    validate_replicas(storage['replicas'])
    require(approved['identity']['storage']=={'replicas':[{'name':r['name'],'failure_domain':'aws-region:'+r['region']}
        for r in storage['replicas']],'retention_seconds':storage['retention_seconds'],
        'max_bundle_bytes':32768,'permanent_availability_proven':False},'bundle-desktop-storage')
    require(type(storage['cache_bytes']) is int and 0<storage['cache_bytes']<=32*1048576
        and type(storage['cache_entries']) is int and 0<storage['cache_entries']<=4096,'public-cache-limit')
    return value


class BundleDesktop(BaseDesktop):
    def __init__(self,directory,approved,chain,wallet_directory,*,count_directory=None,count_approval=None):
        self.approved=copy.deepcopy(validate_approval(approved));self.chain=copy.deepcopy(validate_chain(chain,approved))
        self.identity=copy.deepcopy(approved['identity']);self.remote=BundleRemote(approved)
        self.root=Path(directory);self.wallet_directory=str(wallet_directory)
        require(self.root.is_absolute() and '..' not in self.root.parts
            and not any(p.is_symlink() for p in (self.root,*self.root.parents))
            and not any(p.startswith('.env') for p in self.root.parts),'bundle-desktop-directory')
        wallets=[Path(wallet_directory)]
        if count_directory is not None:wallets.append(Path(count_directory))
        for path in wallets:
            require(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents))
                and not any(p.startswith('.env') for p in path.parts)
                and not path.is_relative_to(self.root) and not self.root.is_relative_to(path),'bundle-desktop-directory')
        self.count_directory=count_directory;self.count_approval=None
        require((count_directory is None)==(count_approval is None),'bundle-count-config')
        if count_approval is not None:
            from count_service import validate_count_approval
            self.count_approval=copy.deepcopy(validate_count_approval(count_approval))
            require(self.count_approval['native_sha256']==self.identity['count_native_sha256']
                and not wallets[0].is_relative_to(wallets[1]) and not wallets[1].is_relative_to(wallets[0]),'bundle-count-config')
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        info=self.root.stat();require(info.st_uid==os.getuid() and not info.st_mode&0o077,'bundle-desktop-directory')
        storage=self.chain['storage']
        self.cache=DiskPublicCache(self.root/'public-cache',max_bytes=storage['cache_bytes'],max_entries=storage['cache_entries'])
        context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2
        replicas=[S3PublicReplica(r['name'],r['region'],r['bucket'],context) for r in storage['replicas']]
        self.store=ReplicatedPublicStore(replicas,cache=self.cache,retention_seconds=storage['retention_seconds'])
        self._rpc=None;self._registry=None;self._reader=None;self._native=None;self._count_native=None
        self.scope={k:self.identity[k] for k in ('protocol','chain_id','contract','registry','application','definition_hash','bundle_profile')}

    def _verifiers(self):
        if self._native is None:
            self._native=Native();require(self._native.sha256.hex()==self.identity['native_sha256'],'base-native-identity')
        if self.identity['count_native_sha256'] is not None and self._count_native is None:
            from count_pipeline import CountNative
            self._count_native=CountNative()
            require(self._count_native.sha256.hex()==self.identity['count_native_sha256'],'count-native-identity')
        return self._native,self._count_native

    def capabilities(self):
        return {'configured':True,'identity':copy.deepcopy(self.identity),
            'count_enrollment_configured':self.count_approval is not None,'experimental':True}

    def _context(self,submission):
        return {'application':self.identity['application'],'chain_id':self.identity['chain_id'],
            'contract':self.identity['contract'],'submission_id':submission}

    def _expected_challenge(self,row,response):
        require(type(response) is dict and set(response)=={'context','selection','issuer_view','challenge'}
            and response['context']==self._context(row['submission_id']) and response['selection']==row['selection'],
            'bundle-desktop-challenge')
        view=response['issuer_view'];c=response['challenge'];chosen=row['selection']
        require(type(view) is dict and set(view)=={'public','definition_hash','sequence'}
            and view['definition_hash']==self.identity['definition_hash']==definition_hash(view['public']),
            'bundle-desktop-challenge')
        if chosen['credential_kind']==1:
            from base_protocol import challenge
            expected=challenge(row['post'],chosen['facts'],self.identity['application'],self.identity['chain_id'],
                self.identity['contract'],view['sequence'],c['created_at'],row['submission_id'])
        else:
            from count_protocol import challenge
            expected=challenge(row['post'],chosen['facts'],chosen['threshold'],self.identity['application'],self.identity['chain_id'],
                self.identity['contract'],view['sequence'],c['created_at'],row['submission_id'])
        require(c==expected,'bundle-desktop-challenge');return c

    def _outbox(self):
        value=self._read('outbox.json',missing=True)
        if value is None:return {'profile':PROFILE,'scope':self.scope,'entries':[]}
        require(set(value)=={'profile','scope','entries'} and value['profile']==PROFILE and value['scope']==self.scope
            and type(value['entries']) is list and len(value['entries'])<=100,'bundle-desktop-outbox')
        seen=set();submissions=set()
        fields={'post','selection','submission_id','phase','challenge_response','bundle','status'}
        for current in value['entries']:
            require(type(current) is dict and set(current) in (fields,fields|{'previous_attempts'}),'bundle-desktop-outbox')
            previous=current.get('previous_attempts',[])
            require(type(previous) is list and len(previous)<=3 and current['post']['id'] not in seen,'bundle-desktop-outbox')
            seen.add(current['post']['id'])
            for row in [*previous,{k:v for k,v in current.items() if k!='previous_attempts'}]:
                require(type(row) is dict and set(row)==fields and row['phase'] in PHASES
                    and row['post']==current['post'] and row['selection']==current['selection'],'bundle-desktop-outbox')
                payload(row['post']);kind=validate_selection(row['selection']);hex_string(row['submission_id'],64)
                require(row['post']['claims']==[] and row['submission_id'] not in submissions
                    and any(bytes.fromhex(row['submission_id'])),'bundle-desktop-outbox')
                submissions.add(row['submission_id'])
                if row['challenge_response'] is not None:
                    require(kind!=0,'bundle-desktop-outbox');self._expected_challenge(row,row['challenge_response'])
                if row['bundle'] is not None:
                    encode(row['bundle']);require(row['bundle']['context']==self._context(row['submission_id'])
                        and row['bundle']['post']==row['post'] and row['bundle']['selection']==row['selection'], 'bundle-desktop-outbox')
                    if kind:
                        evidence=row['bundle']['evidence'];response=row['challenge_response']
                        require(response is not None and evidence['issuer_view']==response['issuer_view']
                            and evidence['challenge']==response['challenge'],'bundle-desktop-outbox')
                require(row['status'] is None or type(row['status']) is dict and row['status'].get('state') in TX_STATES,
                    'bundle-desktop-outbox')
                if row['status'] is not None:self._saved_status(row['status'])
                require((row['phase']=='prepared' and row['bundle'] is None and row['challenge_response'] is None)
                    or (row['phase']=='challenge-saved' and row['bundle'] is None and row['challenge_response'] is not None)
                    or (row['phase'] in ('bundle-saved','submitted') and row['bundle'] is not None),'bundle-desktop-outbox')
        return value

    @staticmethod
    def _saved_status(value):
        fields={'state','transaction_hash','post_number','checked_at','content_state','credential_evidence_checked','evidence_state','last_known','recovery_action'}
        require(set(value)<=fields and {'state','checked_at'}<=set(value)
            and type(value['checked_at']) is int and 0<=value['checked_at']<2**53,'bundle-desktop-status')
        if 'transaction_hash' in value:
            require(type(value['transaction_hash']) is str and value['transaction_hash'].startswith('0x'),'bundle-desktop-status')
            hex_string(value['transaction_hash'][2:],64)
        if value.get('post_number') is not None:
            number=value['post_number']
            require(value['state']=='finalized' and type(number) is str and number.isascii() and number.isdigit()
                and 0<int(number)<2**53,'bundle-desktop-status')
        if 'credential_evidence_checked' in value:require(type(value['credential_evidence_checked']) is bool,'bundle-desktop-status')
        if 'content_state' in value:require(value['content_state']=='locally-retained','bundle-desktop-status')
        if 'evidence_state' in value:
            require(value['evidence_state'] in ('not-requested','checked-at-acceptance','verification-unavailable-or-failed'),
                'bundle-desktop-status')
        if 'recovery_action' in value:
            require(value['state']=='recoverable' and value['recovery_action'] in
                ('renew-expired-proof','check-credential-or-selection'),'bundle-desktop-status')
        if 'last_known' in value:
            old=value['last_known']
            require(type(old) is dict and set(old)=={'state','transaction_hash','post_number','checked_at'}
                and old['state'] in ('finalized','failed'),'bundle-desktop-status')
            BundleDesktop._saved_status(old)

    def _projection(self,row):
        return {'post':copy.deepcopy(row['post']),'selection':copy.deepcopy(row['selection']),
            'submission_id':row['submission_id'],'phase':row['phase'],
            'status':copy.deepcopy(row['status']) if row['status'] is not None else {'state':'recoverable'},'experimental':True,
            **({'renewal_count':len(row['previous_attempts'])} if row.get('previous_attempts') else {})}

    def _save_bundle(self,box,row):
        selected=row['selection'];kind=selected['credential_kind'];evidence=None
        if kind:
            native,count_native=self._verifiers()
            response=self.remote.call('post-challenge',{'post':row['post'],'selection':selected,'submission_id':row['submission_id']})
            c=self._expected_challenge(row,response);now=int(time.time())
            require(c['created_at']<=now+5 and now<c['expires_at'],'base-post-challenge')
            row['challenge_response']=response;row['phase']='challenge-saved';self._write('outbox.json',box)
            view=response['issuer_view']
            if kind==1:
                from domain_desktop import DomainDesktop
                holder=DomainDesktop(self.wallet_directory,native)
                witness=self.remote.refresh_witness(holder.witness_handle(),view)
            else:
                from count_desktop import CountDesktop
                from count_state import count_view
                from count_transport import CountRemote
                require(self.count_approval is not None,'count-wallet-unavailable')
                holder=CountDesktop(self.count_directory,self.identity['definition_hash'],count_native)
                remote=CountRemote(self.remote,self.count_approval,count_native);view=count_view(count_native,view)
                witness=remote.refresh_witness(holder.witness_handle(),view)
            try:proof=holder.present(view,witness,c,int(time.time()))
            except Exception:raise Rejected('bundle-local-proof-unavailable') from None
            require(proof.get('claimed_id') is None,'base-identity-disclosure')
            evidence={'issuer_view':response['issuer_view'],'challenge':c,'proof':proof}
        row['bundle']=build(row['post'],selected,self._context(row['submission_id']),evidence)
        row['phase']='bundle-saved';self._write('outbox.json',box)

    def _reader_instance(self):
        if self._reader is None:
            rpc,registry=self._chain();native,count_native=self._verifiers()
            self._reader=BundleReader(rpc,self.identity['contract'],registry,self.identity['application'],self.store,
                native,count_native,chain_id=self.identity['chain_id'],runtime_code=self.chain['runtime_code'],checkpoint_store=self.cache)
        return self._reader

    def _verify_status(self,row,remote):
        require(type(remote) is dict and remote.get('submission_id')==row['submission_id'],'base-submission-status')
        tx=remote.get('transaction_hash');require(type(tx) is str and tx.startswith('0x'),'base-submission-status');hex_string(tx[2:],64)
        rpc,registry=self._chain();receipt=rpc.call('eth_getTransactionReceipt',tx)
        result={'state':'pending','transaction_hash':tx,'post_number':None,'checked_at':int(time.time())}
        if receipt is None:
            return {**result,'state':'recoverable'} if remote.get('state') in ('recoverable','nonce-conflict','failed') else result
        require(receipt['transactionHash']==tx and receipt.get('to','').lower()==self.identity['contract'],'base-submission-receipt')
        block=rpc.call('eth_getBlockByNumber',receipt['blockNumber'],False)
        if block is None or block['hash']!=receipt['blockHash']:return {**result,'state':'recoverable'}
        final=rpc.call('eth_getBlockByNumber','finalized',False);require(final is not None,'base-finality-unavailable')
        if int(final['number'],16)<int(receipt['blockNumber'],16):return {**result,'state':'confirmed'}
        require(receipt['status'] in ('0x0','0x1'),'base-submission-receipt')
        if receipt['status']=='0x0':return {**result,'state':'failed'}
        reader=self._reader_instance();final=reader._finalized();submission='0x'+row['submission_id']
        number=int(reader._call(self.identity['contract'],'postNumbers(bytes32)',submission,tag=final['number']),16)
        require(0<number<2**53,'base-submission-publication');header=reader._header(number,final)
        bound=commitments(row['bundle'])
        require(header['submission_id']==row['submission_id'] and header['transaction_hash']==tx
            and header['bundle_hash']==bound['bundleHash'] and header['post_id']==bound['postId']
            and header['thread_id']==bound['threadId'] and header['credential_kind']==bound['credentialKind'], 'base-submission-content')
        evidence_state='not-requested';checked=False
        if row['selection']['credential_kind']:
            try:
                evidence=reader._evidence(row['bundle'],header)
                require(evidence['registryHash']==header['registry_hash'] and evidence['registrySequence']==header['registry_sequence']
                    and evidence['observedAt']==header['observed_at'] and evidence['credentialExpiry']==header['credential_expiry'],
                    'bundle-evidence-binding')
                evidence_state='checked-at-acceptance';checked=True
            except Exception:evidence_state='verification-unavailable-or-failed'
        reader._finish(final)
        self.cache.put(bound['bundleHash'],encode(row['bundle']))  # actual retained bytes, not reconstructed text
        return {**result,'state':'finalized','post_number':str(number),'content_state':'locally-retained',
            'credential_evidence_checked':checked,'evidence_state':evidence_state}

    def _run(self,box,row):
        try:
            if row['bundle'] is not None:
                # Recover canonical acceptance even when the original service
                # lost its reply or is now unavailable. Server listings/status
                # are not the authority for a saved post's number.
                try:
                    reader=self._reader_instance();final=reader._finalized()
                    number=int(reader._call(self.identity['contract'],'postNumbers(bytes32)',
                        '0x'+row['submission_id'],tag=final['number']),16)
                    if number:
                        header=reader._header(number,final)
                        row['status']=self._verify_status(row,{'submission_id':row['submission_id'],
                            'transaction_hash':header['transaction_hash'],'state':'finalized'})
                        row['phase']='submitted';self._write('outbox.json',box);return self._projection(row)
                except Exception:pass
            if row['bundle'] is None:self._save_bundle(box,row)
            remote=self.remote.call('post-submit',{'bundle':copy.deepcopy(row['bundle']),'approve_publication':True})
            row['phase']='submitted';row['status']=self._verify_status(row,remote)
        except Exception as error:
            previous=row['status'];row['status']={'state':'recoverable','checked_at':int(time.time())}
            response=row['challenge_response']
            if response is not None and int(time.time())>=response['challenge']['expires_at']:
                row['status']['recovery_action']='renew-expired-proof'
            elif isinstance(error,Rejected) and str(error) in ('bundle-local-proof-unavailable','count-wallet-unavailable'):
                row['status']['recovery_action']='check-credential-or-selection'
            if previous is not None:
                if previous.get('state') in ('finalized','failed'):
                    row['status']['last_known']={k:previous[k] for k in ('state','transaction_hash','post_number','checked_at')}
                elif 'last_known' in previous:row['status']['last_known']=copy.deepcopy(previous['last_known'])
        self._write('outbox.json',box);return self._projection(row)

    def _canonical_recovery_status(self,row):
        reader=self._reader_instance();final=reader._finalized()
        number=int(reader._call(self.identity['contract'],'postNumbers(bytes32)',
            '0x'+row['submission_id'],tag=final['number']),16)
        if number:
            require(row['bundle'] is not None,'bundle-legacy-content-unavailable')
            header=reader._header(number,final)
            result=self._verify_status(row,{'submission_id':row['submission_id'],'transaction_hash':header['transaction_hash']})
        else:
            tx=(row['status'] or {}).get('transaction_hash')
            result=self._verify_status(row,{'submission_id':row['submission_id'],'transaction_hash':tx}) if tx is not None else None
        reader._finish(final)
        return result

    def publish(self,post,selected,approve_publication):
        require(approve_publication is True,'consent-required');payload(post);validate_selection(selected)
        build(post,{'credential_kind':0,'facts':[],'threshold':None},self._context('ab'*32))
        with self.lock():
            box=self._outbox();row=next((r for r in box['entries'] if r['post']['id']==post['id']),None)
            if row is None:
                require(len(box['entries'])<100,'base-desktop-storage-limit')
                row={'post':copy.deepcopy(post),'selection':copy.deepcopy(selected),'submission_id':secrets.token_hex(32),
                    'phase':'prepared','challenge_response':None,'bundle':None,'status':None}
                box['entries'].append(row);self._write('outbox.json',box)
            require(row['post']==post and row['selection']==selected,'base-post-identity-conflict')
            return self._run(box,row)

    def renew(self,post_id,expected_submission_id,approve_fresh_proof):
        """Explicit new attempt only after finalized expiry rules out old acceptance.

        Contract v3 binds credential receipt deadline to the original challenge
        expiry. A finalized block at/after that deadline plus both negative
        lookups fences pending/lost-reply attempts. The pinned contract's UUID
        guard still prevents two canonical acceptances. RPC trust is unchanged.
        """
        require(approve_fresh_proof is True,'consent-required');uuid(post_id);hex_string(expected_submission_id,64)
        with self.lock():
            box=self._outbox();row=next((r for r in box['entries'] if r['post']['id']==post_id),None)
            require(row is not None,'base-post-unavailable')
            previous=row.get('previous_attempts',[])
            if row['submission_id']!=expected_submission_id:
                # Retry a lost renewal reply, not another new authorization.
                require(previous and previous[-1]['submission_id']==expected_submission_id,'bundle-renewal-conflict')
                return self._run(box,row)
            require(row['selection']['credential_kind']!=0 and row['challenge_response'] is not None,'bundle-renewal-unavailable')
            require(len(previous)<3,'bundle-renewal-limit')
            reader=self._reader_instance();final=reader._finalized()
            expiry=row['challenge_response']['challenge']['expires_at']
            require(int(final['timestamp'],16)>=expiry,'bundle-renewal-wait-finality')
            submission='0x'+row['submission_id']
            number=int(reader._call(self.identity['contract'],'postNumbers(bytes32)',submission,tag=final['number']),16)
            post=commitments(row['bundle'] if row['bundle'] is not None else
                build(row['post'],{'credential_kind':0,'facts':[],'threshold':None},self._context(row['submission_id'])))['postId']
            accepted=reader._call(self.identity['contract'],'submissionsByPost(bytes32)',post,tag=final['number'])
            require(number==0 and accepted=='0x'+'00'*32,'bundle-renewal-already-accepted')
            # Re-read the anchored block before persisting a changed attempt.
            reader._finish(final)
            old={k:copy.deepcopy(v) for k,v in row.items() if k!='previous_attempts'}
            row.update(submission_id=secrets.token_hex(32),phase='prepared',challenge_response=None,bundle=None,status=None,
                previous_attempts=[*previous,old])
            self._write('outbox.json',box)  # new ID + old exact bytes durable BEFORE any new call
            return self._run(box,row)

    def threads(self,after,limit):
        with self.lock():return {'identity':copy.deepcopy(self.identity),**self._reader_instance().read_threads(after,limit,int(time.time()))}

    def thread(self,thread_id,after,limit):
        with self.lock():return {'identity':copy.deepcopy(self.identity),**self._reader_instance().read_thread(thread_id,after,limit,int(time.time()))}

    def numbers(self,numbers):
        with self.lock():return {'identity':copy.deepcopy(self.identity),**self._reader_instance().read_numbers(numbers,int(time.time()))}

    def clear_cache(self):
        with self.lock():
            count=self.cache.clear();self._reader=None
            return {'cleared_bundles':count,'remote_records_deleted':False,'drafts_deleted':False,'experimental':True}

    def archive_scope(self):
        return {k:self.identity[k] for k in ('chain_id','contract','application')}

    def archive_export(self,number,consent):
        require(consent is True,'consent-required')
        with self.lock():
            digest,data=self._reader_instance().export_public(number)
            return {'profile':ARCHIVE_PROFILE,'scope':self.archive_scope(),
                'record':{'post_number':str(number),'bundle_hash':digest,
                    'bundle_base64':base64.b64encode(data).decode('ascii')},'experimental':True}

    def archive_import(self,scope,record,consent):
        require(consent is True,'consent-required')
        require(type(scope) is dict and scope==self.archive_scope(),'bundle-archive-scope')
        require(type(record) is dict and set(record)=={'post_number','bundle_hash','bundle_base64'}
            and type(record['post_number']) is str and re.fullmatch('[1-9][0-9]{0,15}',record['post_number'])
            and 0<int(record['post_number'])<2**53,'bundle-archive-record')
        encoded=record['bundle_base64']
        require(type(encoded) is str and 0<len(encoded)<=43692,'bundle-archive-size')
        try:data=base64.b64decode(encoded,validate=True)
        except (ValueError,TypeError):raise Rejected('bundle-archive-record') from None
        from base_protocol import sha
        require(len(data)<=32768 and base64.b64encode(data).decode('ascii')==encoded
            and record['bundle_hash']==sha(data),'bundle-archive-record')
        with self.lock():return self._reader_instance().restore_public(int(record['post_number']),data)

    def history(self):raise Rejected('bundle-selective-api-required')

    def discussion(self,after,limit):raise Rejected('bundle-selective-api-required')
