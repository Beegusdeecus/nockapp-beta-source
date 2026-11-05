"""Hidden six-month validity and strict count, bound to the exact public author.

Only the canonical indexing-time issuer snapshot is trusted. Later revocation,
replacement or expiry does not erase a proof that qualified then. No credential
issuance/renewal/expiry date is returned or placed in the public envelope.
"""
from authorship_v5 import scopes,validate_core
from policy import canonical,require,strict_json
from public_bundle_v5 import blob,unblob
from renewal_native_v3 import public_view
from renewal_policy_v3 import POLICY_HASH
PROFILE='nockapp-hidden-renewal-evidence-v3'

def trust(core,projected,start,end,indexed_at):
    validate_core(core);require(core['selection']['followers_threshold'] is not None,'renewal-not-selected')
    return {'issuer':projected['public'],'policy':POLICY_HASH,'scope':scopes(core)[0]['intent_sha256'],
        'threshold':core['selection']['followers_threshold'],'window_start':start,'window_end':end,
        'registry_sequence':projected['sequence'],'current_sequence':projected['sequence'],'indexed_at':indexed_at}

def present(native,credential,core,author,issuer_view,now):
    t=trust(core,public_view(native,issuer_view),now,now+60,now)
    p=native.call('present',credential=credential,trust=t,expected_author=author['exact'])['presentation']
    return blob(canonical({'profile':PROFILE,'issuer_view':issuer_view,'window_start':now,'window_end':now+60,'presentation':p}),'followers')

def verify(native,unsigned,issuer_view,indexed_at):
    v=strict_json(unblob(unsigned['evidence']['followers'],'followers'),max_bytes=32768)
    require(type(v) is dict and set(v)=={'profile','issuer_view','window_start','window_end','presentation'}
        and v['profile']==PROFILE and v['issuer_view']==issuer_view,'renewal-evidence-authority')
    t=trust(unsigned['core'],public_view(native,issuer_view),v['window_start'],v['window_end'],indexed_at)
    require(native.call('verify',public_input=v['presentation'],trust=t,expected_author=unsigned['author']['exact'])=={'accepted':True},'renewal-evidence-proof')
    return {'threshold':unsigned['core']['selection']['followers_threshold'],'qualified_when_indexed':True,
        'indexed_at':indexed_at,'credential_profile':'nockapp-renewal-count-v3'}
