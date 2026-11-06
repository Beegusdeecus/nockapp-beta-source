"""Same signed hidden scalar in the v5 exact-author point and strict range proof.

The inner pinned primitive retains its v4 schema, under a v5 core-derived scope.
Existing issuance keys/credentials are unchanged. Chain issuer views are supplied
only by the independent reader, never adopted from the bundle itself.
"""
from authorship_v5 import scopes,validate_core,wire_projection
from count_policy import POLICY_HASH
from count_protocol import challenge
from count_state import count_view
from count_receipts import observation
from policy import canonical,require,strict_json
from public_bundle_v5 import blob,unblob
PROFILE='nockapp-followers-evidence-v5'

def trust(c,projected,created_at,when):
    validate_core(c);threshold=c['selection']['followers_threshold'];require(threshold is not None,'v5-followers-not-selected')
    x=c['context'];selected=challenge(wire_projection(c),['account-controlled','followers-more-than'],threshold,
        x['application'],x['chain_id'],x['contract'],projected['sequence'],created_at,x['submission_id'])
    h=scopes(c)[0]['intent_sha256'];selected['scope']=h
    return {'legacy':{'issuer':projected['public'],'policy':POLICY_HASH,'challenge':selected,'current_sequence':projected['sequence'],'now':when},'intent_sha256':h}

def present(native,count_native,credential,c,author_points,issuer_view,now):
    projected=count_view(count_native,issuer_view);t=trust(c,projected,now,now)
    p=native.call('present-count',credential=credential,trust=t,expected_author=author_points['exact'])['presentation']
    return blob(canonical({'profile':PROFILE,'issuer_view':issuer_view,'challenge':t['legacy']['challenge'],'presentation':p}),'followers')

def verify(native,count_native,u,issuer_view,indexed_at,now,current_view):
    raw=unblob(u['evidence']['followers'],'followers');v=strict_json(raw,max_bytes=32768)
    require(set(v)=={'profile','issuer_view','challenge','presentation'} and v['profile']==PROFILE
        and v['issuer_view']==issuer_view,'v5-followers-authority')
    projected=count_view(count_native,issuer_view);t=trust(u['core'],projected,v['challenge']['created_at'],indexed_at)
    require(v['challenge']==t['legacy']['challenge'],'v5-followers-context')
    require(native.call('verify-count',public_input=v['presentation'],trust=t,expected_author=u['author']['exact'])=={'accepted':True},'v5-followers-proof')
    observed,expires,exact=observation(v['presentation']);require(exact is None and observed<=indexed_at<expires,'v5-followers-time')
    return {'valid_when_indexed':True,'eligible_now':now<expires and current_view==issuer_view,
        'threshold':u['core']['selection']['followers_threshold'],'observed_at':observed,'expires_at':expires}
