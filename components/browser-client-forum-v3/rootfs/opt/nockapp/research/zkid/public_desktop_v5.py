"""Durable protocol5 public outbox and permissionless publication coordinator.

Installer injects protected author, public chain/content/reader and optional
spend-only relay. Browser input never chooses endpoints, paths or authority.
Completed bundle retry/check/export requires no private wallet/keyring access.
"""
import copy
import os
from pathlib import Path
import secrets
import time
from authorship_desktop_v5 import AuthorshipDesktopV5
from authorship_v5 import core,validate_core
from base_desktop import BaseDesktop
from base_protocol import sha
from permissionless_index import digest as hash32,submission_data
from policy import require,timestamp,digest
from post_scope import uuid
from public_bundle_v5 import encode

PROFILE='nockapp-public-desktop-v5'
PHASES={'prepared','proofs-needed','wallet-needed','bundle-saved','submitted'}


class PublicDesktopV5(BaseDesktop):
    record_names=frozenset(('outbox.json',))

    def __init__(self,directory,author,index,content,reader,*,relay=None,clock=time.time):
        require(isinstance(author,AuthorshipDesktopV5) and reader.index is index and reader.content is content
            and reader.native is author.native,'v5-desktop-components')
        self.author=author;self.index=index;self.content=content;self.reader=reader;self.relay=relay;self.clock=clock
        self.scope={k:author.binding[k] for k in ('protocol','chain_id','application','contract')}
        require(self.scope=={'protocol':5,'chain_id':index.chain_id,'application':index.application,'contract':index.contract},'v5-desktop-context')
        self.root=Path(directory)
        require(self.root.is_absolute() and '..' not in self.root.parts
            and not any(p.is_symlink() for p in (self.root,*self.root.parents))
            and not any(p.startswith('.env') for p in self.root.parts),'v5-outbox-directory')
        for w in [author,*author.legacy_sources,*author.previous_authors]:
            p=w.wallet.directory
            require(not p.is_relative_to(self.root) and not self.root.is_relative_to(p),'v5-outbox-overlap')
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700);st=self.root.stat()
        require(st.st_uid==os.getuid() and not st.st_mode&0o077,'v5-outbox-directory')

    def _outbox(self):
        box=self._read('outbox.json',missing=True)
        if box is None:return {'profile':PROFILE,'scope':copy.deepcopy(self.scope),'entries':[]}
        require(type(box) is dict and set(box)=={'profile','scope','entries'} and box['profile']==PROFILE
            and box['scope']==self.scope and type(box['entries']) is list and len(box['entries'])<=40,'v5-outbox')
        seen=set()
        for r in box['entries']:
            require(type(r) is dict and set(r)=={'core','phase','bundle','status','last_attempt'}
                and r['phase'] in PHASES,'v5-outbox')
            c=validate_core(r['core']);ident=c['post']['id']
            require(ident not in seen and all(c['context'][k]==self.scope[k] for k in self.scope),'v5-outbox');seen.add(ident)
            require((r['bundle'] is not None)==(r['phase'] in ('bundle-saved','submitted')),'v5-outbox')
            if r['bundle'] is not None:
                encode(r['bundle']);require(r['bundle']['unsigned']['core']==c,'v5-outbox')
            s=r['status'];require(s is None or type(s) is dict and set(s)=={'state','post_number','checked_at'}
                and s['state'] in ('not-indexed','finalized','invalid','content-unavailable','verification-unavailable'),'v5-outbox-status')
            if s is not None:
                timestamp(s['checked_at']);n=s['post_number']
                require(n is None and s['state']=='not-indexed' or type(n) is str and n.isascii() and n.isdigit()
                    and 0<int(n)<2**53 and n==str(int(n)),'v5-outbox-status')
            a=r['last_attempt']
            if a is not None:
                require(type(a) is dict and set(a) in ({'requested_at'},{'requested_at','transaction_hash'}),'v5-outbox-attempt')
                timestamp(a['requested_at'])
                if 'transaction_hash' in a:hash32(a['transaction_hash'])
        return box

    def initialize_identity(self,approve_private_key_setup):
        require(approve_private_key_setup is True,'consent-required')
        with self.lock():
            if self.author.wallet.read('credential.sealed',missing=True) is not None:return self.author.status()
            for old in self.author.previous_authors:
                if old.wallet.read('credential.sealed',missing=True) is not None:
                    return self.author.adopt_author(old,int(self.clock()),True)
            for source in self.author.legacy_sources:
                require(source.wallet.read('pending.sealed',missing=True) is None,'author-legacy-recovery-required')
                if source.wallet.read('credential.sealed',missing=True) is not None:
                    return self.author.adopt(source,int(self.clock()),True)
            return self.author.initialize(int(self.clock()),True)

    def _row(self,box,post_id):
        uuid(post_id);r=next((r for r in box['entries'] if r['core']['post']['id']==post_id),None)
        require(r is not None,'v5-post-missing');return r

    def _projection(self,r,*,fresh=False):
        # Persistent status is last-known only; independent checks must be rerun.
        return {'core':copy.deepcopy(r['core']),'phase':r['phase'],
            'bundle_hash':None if r['bundle'] is None else sha(encode(r['bundle'])),
            'last_known':copy.deepcopy(r['status']),'verification_current':fresh,
            'last_attempt':copy.deepcopy(r['last_attempt'])}

    def _prepare_author(self,box,c):
        if self.author.wallet.read('post.sealed',missing=True) is not None:
            material=self.author.public_material()
            if material['unsigned']['core']!=c:
                old=self._row(box,material['unsigned']['core']['post']['id'])
                require(old['bundle'] is not None,'author-post-recovery-required')
                self.author.release_saved_post(self,old['core']['post']['id'],sha(encode(old['bundle'])))
        return self.author.prepare_post(c,int(self.clock()),True)

    def prepare(self,post,selection,approve_publication,*,thread=None,references=None):
        require(approve_publication is True and type(selection) is dict
            and set(selection)=={'address','followers_threshold'},'consent-required')
        with self.lock():
            box=self._outbox();uuid(post['id']);r=next((r for r in box['entries'] if r['core']['post']['id']==post['id']),None)
            context={**self.scope,'submission_id':secrets.token_hex(32) if r is None else r['core']['context']['submission_id']}
            c=core(post,context,thread=thread,references=references,address_disclosure=selection['address'],followers_threshold=selection['followers_threshold'])
            if r is None:
                require(len(box['entries'])<40,'v5-outbox-full')
                r={'core':c,'phase':'prepared','bundle':None,'status':None,'last_attempt':None}
                box['entries'].append(r);self._write('outbox.json',box)
            else:require(r['core']==c,'v5-intent-conflict')
            if r['bundle'] is None:
                self._prepare_author(box,c)
                r['phase']='proofs-needed' if selection['followers_threshold'] is not None else 'wallet-needed' if selection['address'] else 'prepared'
                self._write('outbox.json',box)
            return self._projection(r)

    def attach_count(self,post_id,desktop,canonical_view,witness):
        with self.lock():
            box=self._outbox();r=self._row(box,post_id);require(r['bundle'] is None,'v5-already-signed')
            self._prepare_author(box,r['core'])
            self.author.attach_count(desktop,canonical_view,witness,int(self.clock()))
            r['phase']='wallet-needed' if r['core']['selection']['address'] else 'prepared';self._write('outbox.json',box)
            return self._projection(r)

    def attach_history(self,post_id,records,resolve,approve_linking):
        with self.lock():
            box=self._outbox();r=self._row(box,post_id);require(r['bundle'] is None,'v5-already-signed')
            self._prepare_author(box,r['core'])
            self.author.attach_history(records,resolve,int(self.clock()),approve_linking)
            return self._projection(r)

    def attach_renewal(self,post_id,desktop,canonical_view,witness,*,before_save):
        require(callable(before_save),'renewal-finality-fence')
        with self.lock():
            box=self._outbox();r=self._row(box,post_id);require(r['bundle'] is None,'v5-already-signed')
            self._prepare_author(box,r['core'])
            # Exact native proof checks bind the credential to this author;
            # recheck the public anchor before final outbox acknowledgement.
            self.author.attach_renewal(desktop,canonical_view,witness,int(self.clock()),before_save=before_save)
            r['phase']='wallet-needed' if r['core']['selection']['address'] else 'prepared'
            self._write('outbox.json',box);return self._projection(r)

    def request_address(self,post_id,account,approve_address_disclosure,*,public_binding=False):
        with self.lock():
            box=self._outbox();r=self._row(box,post_id);require(r['bundle'] is None,'v5-already-signed')
            self._prepare_author(box,r['core'])
            reply=self.author.request_address(account,int(self.clock()),approve_address_disclosure)
            r['phase']='wallet-needed';self._write('outbox.json',box)
            if public_binding:
                from public_bundle_v5 import unblob
                from policy import strict_json
                u=self.author.public_material()['unsigned']
                require(u['core']==r['core'],'v6-wallet-core-changed')
                if u['evidence']['followers'] is not None:
                    require(strict_json(unblob(u['evidence']['followers'],'followers'),max_bytes=32768).get('profile')
                        =='nockapp-hidden-renewal-evidence-v3','v6-wallet-hidden-dates-required')
                return {**reply,'profile':'nockapp-public-wallet-request-v6','post_id':post_id,
                    'submission_id':r['core']['context']['submission_id'],
                    'binding':{'core':copy.deepcopy(u['core']),'author':copy.deepcopy(u['author']),
                        'followers':u['evidence']['followers'],'history':u['evidence']['history']},
                    'signature_saved':u['evidence']['wallet'] is not None}
            return {**reply,'post_id':post_id,'submission_id':r['core']['context']['submission_id']}

    def finish_wallet(self,post_id,request_sha256=None):
        """Persist the exact final public bundle, without upload, gas or relay."""
        from public_bundle_v5 import unblob
        from policy import strict_json
        import wallet_authorship_v5 as wallet
        with self.lock():
            box=self._outbox();r=self._row(box,post_id)
            if r['bundle'] is not None:u=r['bundle']['unsigned']
            else:
                material=self.author.public_material();u=material['unsigned']
                require(u['core']==r['core'],'v6-wallet-core-changed')
            raw=unblob(u['evidence']['wallet'],'wallet');require(raw is not None,'v6-wallet-signature-missing')
            v=strict_json(raw,max_bytes=4096)
            # Validate the saved authorization at its own issuance window. Later
            # index-time expiry is independently evaluated by public readers.
            wallet.verify(u,v['created_at'])
            require(request_sha256 is None or digest(wallet.typed_data(u,v['nonce'],v['created_at'],v['expires_at']))==request_sha256,
                'v6-wallet-request-changed')
            self._save(box,r);return self._projection(r)

    def accept_address(self,post_id,request_sha256,signature,*,finish=False):
        with self.lock():
            box=self._outbox();r=self._row(box,post_id)
            if finish and r['bundle'] is not None:
                from public_bundle_v5 import unblob
                from policy import strict_json
                import wallet_authorship_v5 as wallet
                u=r['bundle']['unsigned'];v=strict_json(unblob(u['evidence']['wallet'],'wallet'),max_bytes=4096)
                require(v['signature']==signature and digest(wallet.typed_data(u,v['nonce'],v['created_at'],v['expires_at']))==request_sha256,
                    'v6-wallet-reply-changed')
                wallet.verify(u,v['created_at']);return self._projection(r)
            require(r['bundle'] is None,'v5-already-signed')
            current=self.author.public_material();q=current['address_request']
            require(current['unsigned']['core']==r['core'] and q is not None and q['request_sha256']==request_sha256,'v5-wallet-reply-context')
            self.author.accept_address(signature,int(self.clock()))
            if finish:self._save(box,r)
            return self._projection(r)

    def reset_unfinished_address(self,post_id,request_sha256,approve_fresh_request):
        with self.lock():
            box=self._outbox();r=self._row(box,post_id);require(r['bundle'] is None,'v5-already-signed')
            material=self.author.public_material();require(material['unsigned']['core']==r['core'],'v5-wallet-reply-context')
            self.author.reset_unfinished_address(request_sha256,int(self.clock()),approve_fresh_request)
            return self._projection(r)

    def _save(self,box,r):
        if r['bundle'] is None:
            self._prepare_author(box,r['core'])
            r['bundle']=self.author.material(int(self.clock()));r['phase']='bundle-saved'
            self._write('outbox.json',box)
            # Release checks the exact independently read-back outbox, not just
            # an in-memory acknowledgment or successful write return.
            self.author.release_saved_post(self,r['core']['post']['id'],sha(encode(r['bundle'])))
        return r['bundle']

    def finish(self,post_id):
        with self.lock():
            box=self._outbox();r=self._row(box,post_id);self._save(box,r);return self._projection(r)

    def _canonical(self,r):
        require(r['bundle'] is not None,'v5-bundle-unsaved');raw=encode(r['bundle']);h=sha(raw)
        n=self.index.number_for_hash(h);now=int(self.clock())
        if n is None:return {'state':'not-indexed','post_number':None,'checked_at':now}
        self.content._remember(h,raw)
        row=self.reader.read_numbers([n],now)['posts'][0]
        require(row.get('bundle_hash')==h,'v5-canonical-conflict')
        return {'state':row['state'],'post_number':str(n),'checked_at':now}

    def _validate_for_submission(self,r):
        from indexed_authorship_v5 import verify_indexed_bundle
        from authorship_v5 import verify as verify_author
        from public_bundle_v5 import decode
        raw=encode(r['bundle']);now=int(self.clock())
        current=None
        # The legacy preflight only uses issuer history with a count verifier.
        # Hidden-renewal proofs are independently checked by the reader.
        if (self.reader.issuer_views is not None and self.reader.count_native is not None
                and r['bundle']['unsigned']['core']['selection']['followers_threshold'] is not None
                and r['bundle']['unsigned']['evidence']['followers'] is not None):
            try:
                final=self.index.anchor();current=self.reader.issuer_views.current(final);self.index.finish(final)
            except Exception:current=None
        checked=verify_indexed_bundle(raw,sha(raw),self.scope,now,now,self.author.native,
            count_native=self.reader.count_native,issuer_view=current,current_issuer_view=current,
            resolve_history=self.reader.resolve_original)
        ref=checked['thread']
        if ref is not None:
            # New ordinary comments require an independently authenticated root.
            # Readers still retain direct-indexed records with bad relationships.
            original,t=self.reader.resolve_original(ref);v=decode(original,ref['bundle_hash']);u=v['unsigned']
            require(u['core']['post']['kind']=='thread' and t<=now and u['core']['post']['created_at']<=t
                and all(u['core']['context'][k]==self.scope[k] for k in self.scope)
                and verify_author(self.author.native,u,v['authorship']),'v5-root-not-verified')

    def _follower_submission_window(self,r):
        """Local deadline guard; readers still verify actual canonical time."""
        from public_bundle_v5 import unblob
        from policy import strict_json
        from renewal_evidence_v3 import PROFILE
        u=r['bundle']['unsigned']
        if u['core']['selection']['followers_threshold'] is None or u['evidence']['followers'] is None:return
        v=strict_json(unblob(u['evidence']['followers'],'followers'),max_bytes=32768)
        if v.get('profile')!=PROFILE:return
        start,end=v.get('window_start'),v.get('window_end');now=int(self.clock())
        require(type(start) is int and type(end) is int and end-start==60 and start<=now<end-15,
            'follower-publication-window-too-short')

    def check(self,post_id):
        """Read-only network recovery: no signing, keyring, upload or relay call."""
        with self.lock():
            box=self._outbox();r=self._row(box,post_id);r['status']=self._canonical(r)
            self._write('outbox.json',box);return self._projection(r,fresh=True)

    def publish(self,post_id,approve_publication):
        require(approve_publication is True,'consent-required')
        with self.lock():
            box=self._outbox();r=self._row(box,post_id);self._save(box,r)
            r['status']=self._canonical(r);self._write('outbox.json',box)
            if r['status']['state']!='not-indexed':return self._projection(r,fresh=True)
            self._validate_for_submission(r)
            self._follower_submission_window(r)
            receipt=self.content.upload(r['bundle']);h=sha(encode(r['bundle']))
            require(receipt['bundle_hash']==h and self.relay is not None,'v5-relay-unavailable')
            self._follower_submission_window(r)
            r['last_attempt']={'requested_at':int(self.clock())};self._write('outbox.json',box)
            reply=self.relay.submit(h)
            require(type(reply) is dict and set(reply)=={'transaction_hash'},'v5-relay-reply');hash32(reply['transaction_hash'])
            r['last_attempt']['transaction_hash']=reply['transaction_hash'];r['phase']='submitted';self._write('outbox.json',box)
            # A relay's claim of success never establishes acceptance or validity.
            r['status']=self._canonical(r);self._write('outbox.json',box)
            return self._projection(r,fresh=True)

    def export_submission(self,post_id,approve_public_export):
        require(approve_public_export is True,'consent-required')
        with self.lock():
            r=self._row(self._outbox(),post_id);require(r['bundle'] is not None,'v5-bundle-unsaved')
            import base64
            raw=encode(r['bundle']);h=sha(raw)
            return {'profile':'nockapp-public-submission-v5','scope':copy.deepcopy(self.scope),'bundle_hash':h,
                'bundle_base64':base64.b64encode(raw).decode('ascii'),'calldata':submission_data(h),
                'contains_private_key':False,'personal_wallet_required':False}

    def outbox(self,after=0,limit=8):
        require(type(after) is int and 0<=after<=40 and type(limit) is int and 1<=limit<=8,'v5-outbox-page')
        with self.lock():
            entries=self._outbox()['entries'];page=entries[after:after+limit]
            return {'entries':[self._projection(r) for r in page],
                'next_after':after+len(page) if after+len(page)<len(entries) else None}
