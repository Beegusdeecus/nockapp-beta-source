"""Canonical protocol4 reader: always verifies private author, then disclosures.

Shares proven finalized indexing/receipt/numbering logic with protocol3, while
requiring a distinct contract protocol and distinct canonical content profile.
"""
import copy
from authored_bundle_acceptance import check_evidence
from bundle_reader import BundleReader
from policy import Rejected,require
from public_bundle_v4 import decode,commitments


class AuthoredBundleReader(BundleReader):
    protocol_version=4
    accepted_kinds=(0,2)

    def __init__(self,*args,author_native=None,**kwargs):
        self.author_native=author_native
        super().__init__(*args,**kwargs)

    def _bound_content(self,data,header):
        value=decode(data,header['bundle_hash']);bound=commitments(value)
        require(value['context']=={'protocol':4,'application':self.app,'chain_id':self.chain_id,'contract':self.contract,
            'submission_id':header['submission_id']},'authored-bundle-application')
        require(bound['postId']==header['post_id'] and bound['threadId']==header['thread_id']
            and bound['credentialKind']==header['credential_kind'],'authored-bundle-content-binding')
        return value

    def _evidence(self,value,header):
        def pin(native):
            if native is None:return None
            return native.sha256 if type(native.sha256) is str else native.sha256.hex()
        key=(header['bundle_hash'],self.registry.definition,pin(self.author_native),pin(self.count_native),header['accepted_at'])
        if key in self._proof_cache:
            self._proof_cache.move_to_end(key);return copy.deepcopy(self._proof_cache[key])
        checked=check_evidence(value,self.registry.definition,self.author_native,self.count_native,header['accepted_at'])
        self._proof_cache[key]=copy.deepcopy(checked)
        while len(self._proof_cache)>self._proof_cache_entries:self._proof_cache.popitem(last=False)
        return checked

    def _content(self,header,now,current_hash):
        base={**header,'canonical_accepted':True,'post':None,'content_integrity_checked':False,'authorship_checked':False,
            'address_evidence_checked':False,'public_address':None,'credential_evidence_checked':False,'valid_when_published':None}
        fetched=self.store.fetch(header['bundle_hash'])
        if fetched['state']=='content-unavailable':return {**base,'state':'content-unavailable','credential_status':'unavailable'}
        try:
            value=self._bound_content(fetched['data'],header)
            base.update(post=value['post'],selection=value['selection'],content_integrity_checked=True)
            checked=self._evidence(value,header)
            require(all(checked[k]==header[h] for k,h in [('registryHash','registry_hash'),('registrySequence','registry_sequence'),
                ('observedAt','observed_at'),('credentialExpiry','credential_expiry')]),'authored-bundle-evidence-binding')
            kind=header['credential_kind']
            status=('not-requested' if not kind else 'expired' if now>=header['credential_expiry'] else
                'valid-at-current-registry' if current_hash==header['registry_hash'] else 'unknown-after-registry-update')
            return {**base,'state':'finalized','authorship_checked':True,'address_evidence_checked':checked['address_checked'],
                'public_address':checked['public_address'],'valid_when_published':True,'credential_evidence_checked':kind==2,
                'credential_status':status,'disclosed_follower_count':None,'content_source':fetched['source'],'experimental':True}
        except Rejected as error:
            unavailable=error.args==('bundle-verifier-unavailable',)
            return {**base,'state':'evidence-unavailable' if unavailable else 'verification-failed',
                'valid_when_published':None if unavailable else False,'credential_status':'unavailable' if unavailable else 'invalid'}
        except Exception:return {**base,'state':'verification-failed','valid_when_published':False,'credential_status':'invalid'}

    def _row_evidence_checked(self,row):
        return row.get('authorship_checked') is True and (not row.get('selection',{}).get('address')
            or row.get('address_evidence_checked') is True) and (row['credential_kind']==0 or row['credential_evidence_checked'])

    def history_material(self,numbers):
        """Fetch ONLY canonically accepted, independently verified original posts."""
        from public_bundle_v4 import post_intent
        require(type(numbers) is list and 1<=len(numbers)<=16 and len(set(numbers))==len(numbers)
            and all(type(n) is int and 0<n<2**53 for n in numbers),'authored-history-selection')
        final=self._finalized();intents=[];proofs=[];hashes=[]
        for number in numbers:
            header=self._header(number,final);found=self.store.fetch(header['bundle_hash'])
            require(found['state']=='available','authored-history-content-unavailable')
            value=self._bound_content(found['data'],header);checked=self._evidence(value,header)
            require(all(checked[k]==header[h] for k,h in [('registryHash','registry_hash'),('registrySequence','registry_sequence'),
                ('observedAt','observed_at'),('credentialExpiry','credential_expiry')]),'authored-history-evidence-binding')
            intents.append(post_intent(value));proofs.append(copy.deepcopy(value['authorship']));hashes.append(header['bundle_hash'])
        self._finish(final)
        return {'scope':{'protocol':4,'chain_id':self.chain_id,'application':self.app,'contract':self.contract,
            'registry':self.registry.contract,'issuer_definition':self.registry.definition},'numbers':list(numbers),
            'bundle_hashes':hashes,'intents':intents,'post_proofs':proofs,'checkpoint':copy.deepcopy(self.checkpoint)}

    def verify_selected_claim(self,numbers,challenge,proof,now,*,expected_nonce,expected_audience,address_disclosure=None):
        from authorship import nonzero_hex
        from wallet_authorship import history_data,verify_signature
        nonzero_hex(expected_nonce,64);nonzero_hex(expected_audience,64)
        require(type(challenge) is dict and challenge.get('nonce')==expected_nonce
            and challenge.get('audience')==expected_audience,'authored-history-challenge')
        material=self.history_material(numbers)
        require(self.author_native is not None and self.author_native.verify_claim(material['intents'],material['post_proofs'],
            challenge,proof,now),'authored-history-author-rejected')
        account=None
        if challenge['disclose_address']:
            require(type(address_disclosure) is dict and set(address_disclosure)=={'address','signature'},'authored-history-wallet-required')
            data=history_data(material,challenge,proof)
            require(verify_signature(data,address_disclosure['address'],address_disclosure['signature']),'authored-history-wallet-rejected')
            from wallet_authorship import address
            account=address(address_disclosure['address'])
        else:require(address_disclosure is None,'authored-history-address-off')
        return {'protocol':4,'authorization_checked':True,'post_numbers':list(numbers),'bundle_hashes':material['bundle_hashes'],
            'public_address':account,'wallet_claim_endorsement_checked':account is not None,
            'scope':material['scope'],'checked_at':now,'checkpoint':material['checkpoint']}
