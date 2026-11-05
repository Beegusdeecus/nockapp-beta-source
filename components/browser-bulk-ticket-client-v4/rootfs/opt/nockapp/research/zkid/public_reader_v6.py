"""Historical badge reader with version/authority/chain-bound positive caching."""
import hashlib
import cryptography
from pathlib import Path
from wallet import SOURCE_AUTH
from indexed_authorship_v6 import verify_indexed_bundle,PROFILE
from policy import digest,hex_string,require
from public_reader_v5 import PublicDiscussionReader
from public_proof_cache import VerifiedPublicCache


class HistoricalPublicReader(PublicDiscussionReader):
    def __init__(self,index,content,native,*,renewal_native=None,issuer_views=None,issuer_authority,
            legacy_count_native=None,cache_bytes=8*1024*1024,cache_entries=256,result_disk_cache=None):
        hex_string(issuer_authority,64);require(any(bytes.fromhex(issuer_authority)),'historical-issuer-authority')
        root=Path(__file__).resolve().parent
        files=['public_reader_v6.py','public_reader_v5.py','public_proof_cache.py','public_verified_cache.py','bundle_disk_cache.py','wallet.py','indexed_authorship_v6.py',
            'indexed_authorship_v5.py','authorship_v5.py','public_bundle_v5.py','renewal_evidence_v3.py','renewal_policy_v3.py',
            'renewal_native_v3.py','historical_authorship_v5.py','wallet_authorship_v5.py','wallet_authorship.py',
            'count_authorship_v5.py','count_state.py','count_protocol.py','count_policy.py','count_receipts.py','policy.py',
            'permissionless_index.py','base_protocol.py','post_scope.py','authorship.py','domain_pipeline.py','public_issuer_views.py']
        self.verifier_version=digest({'profile':PROFILE,'source_sha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in files},
            'cache_key_transport_sha256':{n:hashlib.sha256((SOURCE_AUTH/n).read_bytes()).hexdigest()
                for n in ('x_keystore.py','x_holder.py','x_policy.py')},'cryptography_version':cryptography.__version__,
            'author_worker':None if native is None else native.sha256,'renewal_worker':None if renewal_native is None else renewal_native.sha256,
            'legacy_count_worker':None if legacy_count_native is None else legacy_count_native.sha256.hex(),
            'issuer_authority':issuer_authority})
        def check(data,h,where,when,now,author,*,count_native=None,issuer_view=None,current_issuer_view=None,resolve_history=None):
            return verify_indexed_bundle(data,h,where,when,now,author,renewal_native=renewal_native,
                issuer_view=issuer_view,resolve_history=resolve_history,legacy_count_native=count_native)
        super().__init__(index,content,native,count_native=legacy_count_native,issuer_views=issuer_views,
            bundle_verifier=check,proof_cache=VerifiedPublicCache(self.verifier_version,max_bytes=cache_bytes,max_entries=cache_entries,
                disk_cache=result_disk_cache),historical_only=True)

    def read_numbers(self,numbers,now,*,_page=None):
        page=super().read_numbers(numbers,now,_page=_page);page['profile']='nockapp-public-page-v6'
        page['verifier_profile']=PROFILE;page['verifier_version']=self.verifier_version
        return page
