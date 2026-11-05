"""Historical badge display policy, over unchanged complete v5 bundle bytes.

Verifier release6 accepts explicitly versioned hidden-date v3 evidence. It never
calls today's issuer state to decide whether a historical badge qualified. Legacy
v5 date-disclosing evidence is optional and remains explicitly labelled legacy.
"""
from indexed_authorship_v5 import verify_indexed_bundle as base_verify
from policy import require,strict_json
from public_bundle_v5 import decode,unblob
import renewal_evidence_v3 as renewal

PROFILE='nockapp-public-verifier-v6'

def verify_indexed_bundle(data,bundle_hash,where,indexed_at,now,native,*,renewal_native=None,
        issuer_view=None,resolve_history=None,legacy_count_native=None):
    result=base_verify(data,bundle_hash,where,indexed_at,now,native,resolve_history=resolve_history)
    result['verifier_profile']=PROFILE
    u=decode(data,bundle_hash)['unsigned']
    if u['core']['selection']['followers_threshold'] is None:return result
    try:
        require(issuer_view is not None,'renewal-issuer-unavailable')
        parsed=strict_json(unblob(u['evidence']['followers'],'followers'),max_bytes=32768)
        if parsed['profile']==renewal.PROFILE:
            require(renewal_native is not None,'renewal-verifier-unavailable')
            checked=renewal.verify(renewal_native,u,issuer_view,indexed_at)
        else:
            import count_authorship_v5 as old
            require(parsed['profile']==old.PROFILE and legacy_count_native is not None,'renewal-evidence-version')
            old.verify(native,legacy_count_native,u,issuer_view,indexed_at,indexed_at,issuer_view)
            checked={'threshold':u['core']['selection']['followers_threshold'],'qualified_when_indexed':True,
                'indexed_at':indexed_at,'credential_profile':'legacy-date-disclosing-count-v2'}
        result['display']['followers']=checked
        result['historical_follower_evidence']=dict(checked)
    except Exception:pass # Independent silent omission; valid text/address/history remain.
    return result
